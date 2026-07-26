//! DERP relay client — connect, authenticate, send/recv relay frames.
//!
//! Wire stack: TCP → TLS (optional) → HTTP/1.1 WS upgrade → binary WS messages.
//! Each WS binary message = one DERP protocol frame.

const std = @import("std");
const key = @import("../key.zig");
const proto = @import("proto.zig");
const handshake = @import("handshake.zig");
const ws = @import("ws.zig");
const tls_wrapper = @import("tls_wrapper.zig");
const relay_server = @import("server.zig");

pub const ClientConfig = struct {
    url: []const u8,
    secret_key: key.SecretKey,
    insecure_skip_verify: bool = false,
    auth_token: ?[]const u8 = null,
};

pub const ClientError = error{
    ConnectionFailed,
    HandshakeFailed,
    AuthDenied,
    ProtocolError,
    FrameTooLarge,
    ConnectionClosed,
    ReadFailed,
    WriteFailed,
    OutOfMemory,
    TlsHandshakeFailed,
};

/// Owns its socket, optional TLS transport, and receive frame buffer.
///
/// A connected Client must remain at a stable address and must not be copied;
/// use it through `*Client` until every concurrent method call has returned.
/// Sends may run concurrently with the single serialized receive stream;
/// concurrent close callers wait for the same completed teardown.
pub const Client = struct {
    stream: std.Io.net.Stream,
    tls_conn: ?*tls_wrapper.TlsClient,
    io: std.Io,
    version: proto.ProtocolVersion,
    secret_key: key.SecretKey,
    local_node_id: key.PublicKey,
    read_buf: [proto.MAX_FRAME_SIZE + 256]u8,
    write_buf: [proto.MAX_FRAME_SIZE + 256]u8,
    frame_buf: []u8,
    ws_decoder: ws.Decoder,
    raw_reader: std.Io.net.Stream.Reader,
    raw_writer: std.Io.net.Stream.Writer,
    write_mu: std.atomic.Mutex = .unlocked,
    read_mu: std.atomic.Mutex = .unlocked,
    closed: std.atomic.Value(bool),
    close_complete: std.atomic.Value(bool),
    active_reads: std.atomic.Value(u32),

    pub fn connectInPlace(self: *Client, io: std.Io, config: ClientConfig) ClientError!void {
        const parsed = parseRelayUrl(config.url) orelse return error.ProtocolError;
        const use_tls = parsed.tls;
        const stream = try connectRelayHost(io, parsed.host, parsed.port);

        // TLS upgrade if wss://
        var tls_conn: ?*tls_wrapper.TlsClient = null;
        if (use_tls) {
            tls_conn = tls_wrapper.TlsClient.connect(std.heap.page_allocator, io, stream, parsed.host, config.insecure_skip_verify) catch {
                stream.close(io);
                return error.TlsHandshakeFailed;
            };
        }

        const frame_buf = std.heap.page_allocator.alloc(u8, proto.MAX_FRAME_SIZE) catch {
            if (tls_conn) |tc| {
                tc.deinit();
            } else {
                stream.close(io);
            }
            return error.OutOfMemory;
        };

        self.* = Client{
            .stream = stream,
            .tls_conn = tls_conn,
            .io = io,
            .version = .v2,
            .secret_key = config.secret_key,
            .local_node_id = config.secret_key.public(),
            .read_buf = undefined,
            .write_buf = undefined,
            .frame_buf = frame_buf,
            .ws_decoder = .{},
            .raw_reader = undefined,
            .raw_writer = undefined,
            .closed = .init(false),
            .close_complete = .init(false),
            .active_reads = .init(0),
        };
        self.rebindIoBuffers();

        errdefer self.close();
        try self.wsUpgrade(parsed.host, parsed.port, config.auth_token);
        try self.challengeHandshake();
    }

    pub fn rebindIoBuffers(self: *Client) void {
        if (self.tls_conn == null) {
            self.raw_reader = self.stream.reader(self.io, &self.read_buf);
            self.raw_writer = self.stream.writer(self.io, &self.write_buf);
        }
    }

    fn getReader(self: *Client) *std.Io.Reader {
        if (self.tls_conn) |tc| return tc.reader();
        return &self.raw_reader.interface;
    }

    fn getWriter(self: *Client) *std.Io.Writer {
        if (self.tls_conn) |tc| return tc.writer();
        return &self.raw_writer.interface;
    }

    pub fn send(self: *Client, msg: proto.ClientToRelayMsg) !void {
        while (!self.write_mu.tryLock()) std.Thread.yield() catch {};
        defer self.write_mu.unlock();
        if (self.closed.load(.acquire)) return error.ConnectionClosed;
        const writer = self.getWriter();
        var frame_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
        var frame_writer = std.Io.Writer.fixed(&frame_buf);
        try proto.encodeClientToRelay(msg, &frame_writer);
        const frame = frame_writer.buffered();
        try ws.writeFrame(self.io, writer, .binary, frame, true);
        try writer.flush();
    }

    /// Returned message slices borrow `frame_buf` and remain valid only until
    /// the next call to `recv` or until `close`.
    pub fn recv(self: *Client) ClientError!proto.RelayToClientMsg {
        if (self.closed.load(.acquire)) return error.ConnectionClosed;
        _ = self.active_reads.fetchAdd(1, .acq_rel);
        defer _ = self.active_reads.fetchSub(1, .acq_rel);
        while (!self.read_mu.tryLock()) std.Thread.yield() catch {};
        defer self.read_mu.unlock();
        // Close may have won between the optimistic check and reader
        // registration. In that case no transport or frame storage is touched.
        if (self.closed.load(.acquire)) return error.ConnectionClosed;
        while (true) {
            const frame = self.readWsFrame() catch |err| switch (err) {
                error.ConnectionClosed, error.EndOfStream => return error.ConnectionClosed,
                error.FrameTooLarge => return error.FrameTooLarge,
                else => return error.ProtocolError,
            };

            if (frame.op == .close) {
                self.echoClose(frame.payload);
                return error.ConnectionClosed;
            }
            if (frame.op == .ping) {
                self.sendWsPong(frame.payload) catch return error.ProtocolError;
                continue;
            }
            if (frame.op == .pong) continue;
            if (frame.op == .text) continue;
            if (frame.op != .binary) return error.ProtocolError;

            const msg = proto.decodeRelayToClient(frame.payload, self.version) catch return error.ProtocolError;
            if (msg == .ping) {
                self.sendPong(msg.ping) catch return error.ProtocolError;
                continue;
            }
            return msg;
        }
    }

    fn readWsFrame(self: *Client) !ws.ReadFrameResult {
        return self.ws_decoder.readFrame(self.getReader(), self.frame_buf, .client);
    }

    fn sendWsPong(self: *Client, payload: []const u8) !void {
        // V3-D: pong must take the same write lock as send() (no bypass).
        while (!self.write_mu.tryLock()) std.Thread.yield() catch {};
        defer self.write_mu.unlock();
        if (self.closed.load(.acquire)) return error.ConnectionClosed;
        const writer = self.getWriter();
        try ws.writeFrame(self.io, writer, .pong, payload, true);
        try writer.flush();
    }

    fn sendPong(self: *Client, data: [8]u8) !void {
        try self.send(.{ .pong = data });
    }

    fn echoClose(self: *Client, payload: []const u8) void {
        while (!self.write_mu.tryLock()) std.Thread.yield() catch {};
        defer self.write_mu.unlock();
        if (self.closed.load(.acquire)) return;
        const writer = self.getWriter();
        ws.writeFrame(self.io, writer, .close, payload, true) catch return;
        writer.flush() catch {};
    }

    fn wsUpgrade(self: *Client, host: []const u8, port: u16, auth_token: ?[]const u8) !void {
        const reader = self.getReader();
        const writer = self.getWriter();

        var key_bytes: [16]u8 = undefined;
        self.io.random(&key_bytes);
        var ws_key_buf: [32]u8 = undefined;
        const ws_key = std.base64.standard.Encoder.encode(&ws_key_buf, &key_bytes);

        try writer.print("GET /relay HTTP/1.1\r\n", .{});
        try writer.print("Host: {s}:{d}\r\n", .{ host, port });
        try writer.writeAll("Upgrade: websocket\r\n");
        try writer.writeAll("Connection: Upgrade\r\n");
        try writer.print("Sec-WebSocket-Key: {s}\r\n", .{ws_key});
        try writer.writeAll("Sec-WebSocket-Version: 13\r\n");
        try writer.print("Sec-WebSocket-Protocol: iroh-relay-v2, iroh-relay-v1\r\n", .{});
        if (auth_token) |tok| {
            if (!isValidHeaderValue(tok)) return error.ProtocolError;
            try writer.print("Authorization: Bearer {s}\r\n", .{tok});
        }
        try writer.writeAll("\r\n");
        try writer.flush();

        // Read response headers
        var expected_accept_buf: [28]u8 = undefined;
        const expected_accept = ws.computeAccept(ws_key, &expected_accept_buf);
        var saw_status_101 = false;
        var saw_upgrade = false;
        var saw_connection_upgrade = false;
        var saw_valid_accept = false;
        var saw_accept_header = false;
        var saw_protocol_header = false;
        var negotiated_version: ?proto.ProtocolVersion = null;
        var line_index: usize = 0;
        var total_header_bytes: usize = 0;
        while (true) {
            var hdr_line: [1024]u8 = undefined;
            var hdr_len: usize = 0;
            var terminated = false;
            while (hdr_len < hdr_line.len) {
                const b = reader.takeByte() catch return error.ConnectionFailed;
                hdr_line[hdr_len] = b;
                hdr_len += 1;
                if (hdr_len >= 2 and hdr_line[hdr_len - 2] == '\r' and hdr_line[hdr_len - 1] == '\n') {
                    terminated = true;
                    break;
                }
            }
            if (!terminated) return error.ProtocolError;
            total_header_bytes += hdr_len;
            if (total_header_bytes > 16 * 1024) return error.ProtocolError;
            if (hdr_len <= 2) break;
            const h = hdr_line[0 .. hdr_len - 2];
            if (line_index == 0) {
                saw_status_101 = validSwitchingProtocolsStatus(h);
                line_index += 1;
                continue;
            }
            line_index += 1;
            if (headerValue(h, "upgrade")) |val| {
                saw_upgrade = saw_upgrade or containsHttpToken(val, "websocket");
            } else if (headerValue(h, "connection")) |val| {
                saw_connection_upgrade = saw_connection_upgrade or containsHttpToken(val, "upgrade");
            } else if (headerValue(h, "sec-websocket-accept")) |val| {
                if (saw_accept_header) return error.ProtocolError;
                saw_accept_header = true;
                saw_valid_accept = std.mem.eql(u8, val, expected_accept);
            } else if (headerValue(h, "sec-websocket-protocol")) |val| {
                if (saw_protocol_header) return error.ProtocolError;
                saw_protocol_header = true;
                negotiated_version = proto.ProtocolVersion.fromString(val);
            }
        }
        if (!saw_status_101 or !saw_upgrade or !saw_connection_upgrade or !saw_valid_accept) {
            return error.ProtocolError;
        }
        self.version = negotiated_version orelse return error.ProtocolError;
    }

    fn challengeHandshake(self: *Client) ClientError!void {
        const writer = self.getWriter();

        // Read ServerChallenge
        const sc_payload = try self.readHandshakeBinary(256);
        const sc = handshake.decodeHandshakeFrame(sc_payload) catch return error.HandshakeFailed;
        if (sc != .server_challenge) return error.HandshakeFailed;

        // Create and send ClientAuth
        const ca = handshake.clientAuthFor(self.secret_key, sc.server_challenge.challenge);
        var auth_buf: [128]u8 = undefined;
        var auth_writer = std.Io.Writer.fixed(&auth_buf);
        handshake.encodeClientAuth(ca, &auth_writer) catch return error.HandshakeFailed;
        ws.writeFrame(self.io, writer, .binary, auth_writer.buffered(), true) catch return error.HandshakeFailed;
        writer.flush() catch return error.HandshakeFailed;

        // Read ServerConfirmsAuth or ServerDeniesAuth
        const result_payload = try self.readHandshakeBinary(1024);
        const result = handshake.decodeHandshakeFrame(result_payload) catch return error.HandshakeFailed;
        switch (result) {
            .server_confirms_auth => return,
            .server_denies_auth => return error.AuthDenied,
            else => return error.HandshakeFailed,
        }
    }

    fn readHandshakeBinary(self: *Client, max_payload: usize) ClientError![]u8 {
        while (true) {
            const frame = self.readWsFrame() catch return error.HandshakeFailed;
            switch (frame.op) {
                .close => {
                    self.echoClose(frame.payload);
                    return error.HandshakeFailed;
                },
                .ping => {
                    self.sendWsPong(frame.payload) catch return error.HandshakeFailed;
                    continue;
                },
                .pong, .text => continue,
                .binary => {
                    if (frame.payload.len > max_payload) return error.HandshakeFailed;
                    return frame.payload;
                },
                else => return error.HandshakeFailed,
            }
        }
    }

    pub fn close(self: *Client) void {
        if (self.closed.swap(true, .acq_rel)) {
            while (!self.close_complete.load(.acquire)) std.Thread.yield() catch {};
            return;
        }
        defer self.close_complete.store(true, .release);

        // Wake a blocked read or write without destroying the TLS state it is
        // still using. The ownership barriers below then make destruction and
        // frame-buffer release safe against concurrent send/recv.
        self.stream.shutdown(self.io, .both) catch {};
        while (!self.write_mu.tryLock()) std.Thread.yield() catch {};
        self.write_mu.unlock();
        while (self.active_reads.load(.acquire) != 0) std.Thread.yield() catch {};
        // Readers may briefly take the write lock to answer ping/close while
        // unwinding. Reacquire only after they quiesce, then hold the lock
        // across final resource destruction.
        while (!self.write_mu.tryLock()) std.Thread.yield() catch {};
        defer self.write_mu.unlock();

        if (self.tls_conn) |tc| {
            tc.deinit();
            self.tls_conn = null;
        } else {
            self.stream.close(self.io);
        }
        if (self.frame_buf.len != 0) {
            std.heap.page_allocator.free(self.frame_buf);
            self.frame_buf = &.{};
        }
        self.secret_key.deinit();
    }

    pub fn nodeId(self: *const Client) key.PublicKey {
        return self.local_node_id;
    }
};

fn connectRelayHost(io: std.Io, host: []const u8, port: u16) ClientError!std.Io.net.Stream {
    if (std.Io.net.IpAddress.parse(host, port)) |addr| {
        return addr.connect(io, .{ .mode = .stream }) catch return error.ConnectionFailed;
    } else |_| {}

    const host_name = std.Io.net.HostName.init(host) catch return error.ProtocolError;
    var results_buf: [16]std.Io.net.HostName.LookupResult = undefined;
    var results: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results_buf);
    std.Io.net.HostName.lookup(host_name, io, &results, .{ .port = port }) catch
        return error.ConnectionFailed;

    while (true) {
        var result: [1]std.Io.net.HostName.LookupResult = undefined;
        const n = results.getUncancelable(io, &result, 0) catch |err| switch (err) {
            error.Closed => break,
        };
        if (n == 0) break;
        switch (result[0]) {
            .address => |addr| {
                if (addr.connect(io, .{ .mode = .stream })) |stream| return stream else |_| {}
            },
            .canonical_name => {},
        }
    }
    return error.ConnectionFailed;
}

fn validSwitchingProtocolsStatus(line: []const u8) bool {
    var fields = std.mem.splitScalar(u8, line, ' ');
    const http_version = fields.next() orelse return false;
    const status = fields.next() orelse return false;
    return std.mem.eql(u8, http_version, "HTTP/1.1") and std.mem.eql(u8, status, "101");
}

fn headerValue(line: []const u8, name: []const u8) ?[]const u8 {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    const field_name = line[0..colon];
    if (field_name.len == 0 or std.mem.indexOfAny(u8, field_name, " \t") != null) return null;
    if (!std.ascii.eqlIgnoreCase(field_name, name)) return null;
    return std.mem.trim(u8, line[colon + 1 ..], " \t");
}

fn containsHttpToken(value: []const u8, token: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |candidate| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, candidate, " \t"), token)) return true;
    }
    return false;
}

fn isValidHeaderValue(value: []const u8) bool {
    for (value) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0x7f or (byte < 0x20 and byte != '\t')) return false;
    }
    return true;
}

const ParsedUrl = struct {
    host: []const u8,
    port: u16,
    tls: bool,
};

fn parseRelayUrl(url: []const u8) ?ParsedUrl {
    const prefix_ws = "ws://";
    const prefix_wss = "wss://";
    var rest: []const u8 = undefined;
    var tls_flag = false;
    if (std.mem.startsWith(u8, url, prefix_ws)) {
        rest = url[prefix_ws.len..];
    } else if (std.mem.startsWith(u8, url, prefix_wss)) {
        rest = url[prefix_wss.len..];
        tls_flag = true;
    } else {
        return null;
    }
    const path_start = std.mem.indexOf(u8, rest, "/") orelse rest.len;
    const host_port = rest[0..path_start];
    if (std.mem.lastIndexOf(u8, host_port, ":")) |colon| {
        const host = host_port[0..colon];
        if (!isValidRelayHost(host)) return null;
        const port_str = host_port[colon + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
        return .{ .host = host, .port = port, .tls = tls_flag };
    }
    return null;
}

fn isValidRelayHost(host: []const u8) bool {
    if (host.len == 0) return false;
    for (host) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return false;
    }
    if (std.Io.net.IpAddress.parse(host, 0)) |_| return true else |_| {}
    _ = std.Io.net.HostName.init(host) catch return false;
    return true;
}

const testing = std.testing;

test "parseRelayUrl basic" {
    const parsed = parseRelayUrl("ws://127.0.0.1:8080") orelse return error.TestFailed;
    try testing.expectEqualStrings("127.0.0.1", parsed.host);
    try testing.expectEqual(@as(u16, 8080), parsed.port);
    try testing.expect(!parsed.tls);
}

test "parseRelayUrl wss" {
    const parsed = parseRelayUrl("wss://relay.example.com:443/relay") orelse return error.TestFailed;
    try testing.expectEqualStrings("relay.example.com", parsed.host);
    try testing.expectEqual(@as(u16, 443), parsed.port);
    try testing.expect(parsed.tls);
}

test "parseRelayUrl rejects non-ws scheme" {
    try testing.expect(parseRelayUrl("http://example.com") == null);
}

test "parseRelayUrl rejects invalid and header-injecting hosts" {
    try testing.expect(parseRelayUrl("ws://:8080/relay") == null);
    try testing.expect(parseRelayUrl("ws://bad_host:8080/relay") == null);
    try testing.expect(parseRelayUrl("ws://relay.example.com\r\nInjected: yes:8080/relay") == null);
    try testing.expect(parseRelayUrl("ws://relay.example.com\x1f:8080/relay") == null);
}

test "websocket upgrade helpers require exact status, headers, and tokens" {
    try testing.expect(validSwitchingProtocolsStatus("HTTP/1.1 101 Switching Protocols"));
    try testing.expect(!validSwitchingProtocolsStatus("HTTP/1.1 200 OK"));
    try testing.expect(!validSwitchingProtocolsStatus("HTTP/1.0 101 Switching Protocols"));
    try testing.expect(containsHttpToken("keep-alive, Upgrade", "upgrade"));
    try testing.expect(!containsHttpToken("not-an-upgrade", "upgrade"));
    try testing.expectEqualStrings("iroh-relay-v2", headerValue("Sec-WebSocket-Protocol: iroh-relay-v2", "sec-websocket-protocol").?);
    try testing.expect(headerValue("Sec-WebSocket-Protocol : iroh-relay-v2", "sec-websocket-protocol") == null);
    try testing.expect(!isValidHeaderValue("token\r\nInjected: yes"));
}

test "Client close zeroizes stored secret without touching caller copy" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();
    var server = try relay_server.Server.init(testing.allocator, io, .{ .bind_host = "127.0.0.1", .bind_port = 0 });
    defer server.deinit();

    var watchdog_done = std.atomic.Value(bool).init(false);
    const watchdog = try std.Thread.spawn(.{}, struct {
        fn run(done: *std.atomic.Value(bool)) void {
            var wd_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
            for (0..100) |_| {
                wd_io.io().sleep(std.Io.Duration.fromMilliseconds(100), .real) catch {};
                if (done.load(.acquire)) return;
            }
            std.debug.panic("relay client zeroize test watchdog timeout", .{});
        }
    }.run, .{&watchdog_done});
    defer {
        watchdog_done.store(true, .release);
        watchdog.join();
    }

    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *relay_server.Server) void {
            srv.acceptOne() catch {};
        }
    }.run, .{&server});
    defer accept_thread.join();

    const seed = [_]u8{0x24} ** 32;
    const caller_secret = key.SecretKey.fromBytes(seed);
    var url_buf: [64]u8 = undefined;
    const relay_url = try std.fmt.bufPrint(&url_buf, "ws://127.0.0.1:{d}/relay", .{server.localAddress().getPort()});

    var client: Client = undefined;
    try client.connectInPlace(io, .{ .url = relay_url, .secret_key = caller_secret });
    try testing.expectEqual(seed, client.secret_key.toBytes());

    // A concurrent close must wake and quiesce the blocked receiver before it
    // destroys TLS/frame storage.
    const recv_thread = try std.Thread.spawn(.{}, struct {
        fn run(c: *Client) void {
            _ = c.recv() catch {};
        }
    }.run, .{&client});
    while (client.active_reads.load(.acquire) == 0) std.Thread.yield() catch {};
    client.close();
    recv_thread.join();
    client.close();

    try testing.expectEqual([_]u8{0} ** 32, client.secret_key.toBytes());
    try testing.expectEqual(seed, caller_secret.toBytes());
}
