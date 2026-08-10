//! TLS wrapper for DERP relay — wraps tls.zig (ianic/tls.zig).
//!
//! Provides TLS client/server streams for wss:// relay connections.
//! tls.zig is a pure Zig TLS 1.2/1.3 library that upgrades a
//! std.Io.net.Stream to a TLS Connection.

const std = @import("std");
pub const tls = @import("tls");

pub const TlsError = error{
    TlsHandshakeFailed,
    CertificateError,
};

/// ALPN protocol token for ACME TLS-ALPN-01 (RFC 8737). A connection that
/// negotiates this is an ACME validation probe, never a relay client — the
/// relay server closes it right after the handshake.
pub const acme_tls_alpn = "acme-tls/1";

/// Result of choosing what to serve for one incoming TLS connection.
pub const ServerHelloSelect = struct {
    /// Cert/key to present. Must stay alive for the duration of the
    /// synchronous handshake (the selector owner's map entries qualify).
    pair: *const tls.config.CertKeyPair,
    /// ALPN protocols to offer, server preference order. Empty = no ALPN.
    alpn_protocols: []const []const u8 = &.{},
};

/// SNI/ALPN-driven certificate selection. `select` is called once per
/// connection BEFORE the handshake with the ClientHello's SNI hostname (null
/// when absent) and ALPN protocol list; returning null refuses the
/// connection (fail closed).
pub const CertSelector = struct {
    context: *anyopaque,
    select_fn: *const fn (context: *anyopaque, sni: ?[]const u8, client_alpns: []const []const u8) ?ServerHelloSelect,

    pub fn select(self: CertSelector, sni: ?[]const u8, client_alpns: []const []const u8) ?ServerHelloSelect {
        return self.select_fn(self.context, sni, client_alpns);
    }
};

/// Parsed fields of a TLS ClientHello. Slices borrow `record`.
pub const ClientHello = struct {
    sni: ?[]const u8 = null,
    alpns: []const []const u8 = &.{},
};

pub const ClientHelloError = error{Malformed};

/// Parses SNI + ALPN from a TLS record carrying (the start of) a ClientHello.
/// `record` is the full record CONTENT (after the 5-byte record header). The
/// ClientHello must fit in this one record — TLS permits handshake
/// fragmentation but no real ACME/relay client fragments the ClientHello;
/// anything else is malformed for our purposes and the caller fails closed.
pub fn parseClientHello(record: []const u8, alpns_buf: [][]const u8) ClientHelloError!ClientHello {
    var r: std.Io.Reader = .fixed(record);
    // Handshake header: type client_hello(1) + uint24 length.
    const hs_type = r.takeByte() catch return error.Malformed;
    if (hs_type != 1) return error.Malformed;
    const hs_len_be = r.takeArray(3) catch return error.Malformed;
    const hs_len: usize = std.mem.readInt(u24, hs_len_be, .big);
    const body = r.take(hs_len) catch return error.Malformed;

    var d: std.Io.Reader = .fixed(body);
    _ = d.takeArray(2) catch return error.Malformed; // legacy_version
    _ = d.takeArray(32) catch return error.Malformed; // random
    const sid_len = d.takeByte() catch return error.Malformed;
    _ = d.take(sid_len) catch return error.Malformed; // legacy_session_id
    const cs_len = d.takeInt(u16, .big) catch return error.Malformed;
    _ = d.take(cs_len) catch return error.Malformed; // cipher_suites
    const comp_len = d.takeByte() catch return error.Malformed;
    _ = d.take(comp_len) catch return error.Malformed; // compression_methods

    var out: ClientHello = .{};
    var alpn_count: usize = 0;

    const ext_total = d.takeInt(u16, .big) catch return error.Malformed;
    const ext_block = d.take(ext_total) catch return error.Malformed;
    var e: std.Io.Reader = .fixed(ext_block);
    while (e.bufferedLen() > 0) {
        const ext_type = e.takeInt(u16, .big) catch return error.Malformed;
        const ext_len = e.takeInt(u16, .big) catch return error.Malformed;
        const ext_data = e.take(ext_len) catch return error.Malformed;
        switch (ext_type) {
            0 => { // server_name
                var s: std.Io.Reader = .fixed(ext_data);
                const list_len = s.takeInt(u16, .big) catch return error.Malformed;
                const list = s.take(list_len) catch return error.Malformed;
                var l: std.Io.Reader = .fixed(list);
                while (l.bufferedLen() > 0) {
                    const name_type = l.takeByte() catch return error.Malformed;
                    const name_len = l.takeInt(u16, .big) catch return error.Malformed;
                    const name = l.take(name_len) catch return error.Malformed;
                    if (name_type == 0) { // host_name; first one wins per RFC 6066
                        out.sni = name;
                        break;
                    }
                }
            },
            16 => { // application_layer_protocol_negotiation
                var s: std.Io.Reader = .fixed(ext_data);
                const list_len = s.takeInt(u16, .big) catch return error.Malformed;
                const list = s.take(list_len) catch return error.Malformed;
                var l: std.Io.Reader = .fixed(list);
                while (l.bufferedLen() > 0) {
                    const proto_len = l.takeByte() catch return error.Malformed;
                    const proto = l.take(proto_len) catch return error.Malformed;
                    if (proto_len == 0) return error.Malformed; // RFC 7301 forbids empty
                    if (alpn_count >= alpns_buf.len) return error.Malformed;
                    alpns_buf[alpn_count] = proto;
                    alpn_count += 1;
                }
            },
            else => {},
        }
    }
    out.alpns = alpns_buf[0..alpn_count];
    return out;
}


fn activeCipherStorage(cipher: *tls.Cipher) []u8 {
    return switch (cipher.*) {
        inline else => |*state| std.mem.asBytes(state),
    };
}

fn zeroizeTrafficKeys(cipher: *tls.Cipher) void {
    // The pinned ianic/tls Connection.close only writes close_notify and has
    // no deinit/secret wipe. Its active cipher payload owns the traffic keys,
    // IVs, and TLS 1.3 traffic secrets, so scrub that payload after all I/O.
    // Keep the union tag intact so repeated teardown remains well-defined.
    std.crypto.secureZero(u8, activeCipherStorage(cipher));
}

/// A TLS client connection wrapping a TCP stream.
pub const TlsClient = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,

    enc_rdbuf: [tls.input_buffer_len]u8,
    enc_wrbuf: [tls.output_buffer_len]u8,
    enc_reader: std.Io.net.Stream.Reader,
    enc_writer: std.Io.net.Stream.Writer,

    tls_conn: tls.Connection,

    tls_rdbuf: [17000]u8,
    tls_wrbuf: [17000]u8,
    cleartext_reader: @TypeOf((@as(*tls.Connection, undefined)).reader(@as([]u8, undefined))),
    cleartext_writer: @TypeOf((@as(*tls.Connection, undefined)).writer(@as([]u8, undefined))),
    closed: bool,

    /// Upgrade a TCP stream to TLS (client side).
    /// `host` is the SNI hostname for certificate verification.
    /// Set `insecure_skip_verify` to true for self-signed certs (testing).
    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: std.Io.net.Stream,
        host: []const u8,
        insecure_skip_verify: bool,
    ) !*TlsClient {
        const self = try allocator.create(TlsClient);
        errdefer allocator.destroy(self);

        var root_ca = std.crypto.Certificate.Bundle.empty;
        defer root_ca.deinit(allocator);
        try root_ca.rescan(allocator, io, std.Io.Clock.real.now(io));

        self.initCommon(allocator, io, stream);

        // rng_impl is stack-local but only borrowed by the synchronous
        // tls.client() handshake below; it never escapes this frame.
        // Note: on handshake failure the CALLER retains stream ownership and
        // closes it (connectInPlace's error path) — no errdefer close here.
        var rng_impl: std.Random.IoSource = .{ .io = io };
        self.tls_conn = tls.client(&self.enc_reader.interface, &self.enc_writer.interface, .{
            .host = host,
            .root_ca = root_ca,
            .insecure_skip_verify = insecure_skip_verify,
            .now = std.Io.Clock.real.now(io),
            .rng = rng_impl.interface(),
        }) catch return error.TlsHandshakeFailed;

        self.initCleartext();
        return self;
    }

    /// Upgrade a TCP stream to TLS (client side) verifying the peer against
    /// `root_ca` — an EXPLICIT trust anchor (e.g. the pinned CA of an ACME
    /// directory), never the system store, never skip-verify.
    pub fn connectWithTrust(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: std.Io.net.Stream,
        host: []const u8,
        root_ca: *const std.crypto.Certificate.Bundle,
    ) !*TlsClient {
        const self = try allocator.create(TlsClient);
        errdefer allocator.destroy(self);

        self.initCommon(allocator, io, stream);

        var rng_impl: std.Random.IoSource = .{ .io = io };
        self.tls_conn = tls.client(&self.enc_reader.interface, &self.enc_writer.interface, .{
            .host = host,
            .root_ca = root_ca.*,
            .insecure_skip_verify = false,
            .now = std.Io.Clock.real.now(io),
            .rng = rng_impl.interface(),
        }) catch return error.TlsHandshakeFailed;

        self.initCleartext();
        return self;
    }

    fn initCommon(
        self: *TlsClient,
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: std.Io.net.Stream,
    ) void {
        self.allocator = allocator;
        self.io = io;
        self.stream = stream;

        self.enc_rdbuf = undefined;
        self.enc_wrbuf = undefined;
        self.enc_reader = self.stream.reader(self.io, &self.enc_rdbuf);
        self.enc_writer = self.stream.writer(self.io, &self.enc_wrbuf);
    }

    fn initCleartext(self: *TlsClient) void {
        self.tls_rdbuf = undefined;
        self.tls_wrbuf = undefined;
        self.cleartext_reader = self.tls_conn.reader(&self.tls_rdbuf);
        self.cleartext_writer = self.tls_conn.writer(&self.tls_wrbuf);
        self.closed = false;
    }


    pub fn reader(self: *TlsClient) *std.Io.Reader {
        return &self.cleartext_reader.interface;
    }

    pub fn writer(self: *TlsClient) *std.Io.Writer {
        return &self.cleartext_writer.interface;
    }

    pub fn close(self: *TlsClient) void {
        if (self.closed) return;
        self.closed = true;
        // A peer that stopped reading must not make close_notify block
        // teardown forever. Shutting the transport first wakes any pending
        // TLS I/O; close() below then performs best-effort TLS cleanup.
        self.stream.shutdown(self.io, .both) catch {};
        self.tls_conn.close() catch {};
        self.stream.close(self.io);
        zeroizeTrafficKeys(&self.tls_conn.cipher);
    }

    pub fn deinit(self: *TlsClient) void {
        self.close();
        self.allocator.destroy(self);
    }
};

/// A TLS server connection wrapping a TCP stream.
pub const TlsServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,

    enc_rdbuf: [tls.input_buffer_len]u8,
    enc_wrbuf: [tls.output_buffer_len]u8,
    enc_reader: std.Io.net.Stream.Reader,
    enc_writer: std.Io.net.Stream.Writer,

    tls_conn: tls.Connection,

    tls_rdbuf: [17000]u8,
    tls_wrbuf: [17000]u8,
    cleartext_reader: @TypeOf((@as(*tls.Connection, undefined)).reader(@as([]u8, undefined))),
    cleartext_writer: @TypeOf((@as(*tls.Connection, undefined)).writer(@as([]u8, undefined))),
    closed: bool,

    /// Upgrade a TCP stream to TLS (server side).
    /// `cert_path` and `key_path` are PEM files for the server certificate.
    pub fn accept(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: std.Io.net.Stream,
        cert_path: []const u8,
        key_path: []const u8,
    ) !*TlsServer {
        const self = try allocator.create(TlsServer);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.io = io;
        self.stream = stream;

        self.enc_rdbuf = undefined;
        self.enc_wrbuf = undefined;
        self.enc_reader = self.stream.reader(self.io, &self.enc_rdbuf);
        self.enc_writer = self.stream.writer(self.io, &self.enc_wrbuf);

        var rng_impl: std.Random.IoSource = .{ .io = io };
        const rng = rng_impl.interface();

        const cwd = std.Io.Dir.cwd();
        // `&auth` is stack-local but only passed into the synchronous tls.server()
        // handshake; tls.zig copies cert material during handshake and does not
        // retain the pointer on the returned Connection (verified L-15 / false positive).
        var auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, cwd, cert_path, key_path);
        defer auth.deinit(allocator);

        self.tls_conn = tls.server(&self.enc_reader.interface, &self.enc_writer.interface, .{
            .auth = &auth,
            .now = std.Io.Clock.real.now(io),
            .rng = rng,
        }) catch return error.TlsHandshakeFailed;

        self.tls_rdbuf = undefined;
        self.tls_wrbuf = undefined;
        self.cleartext_reader = self.tls_conn.reader(&self.tls_rdbuf);
        self.cleartext_writer = self.tls_conn.writer(&self.tls_wrbuf);
        self.closed = false;

        return self;
    }

    /// Upgrade a TCP stream to TLS (server side), choosing the certificate
    /// and ALPN offer per connection from the ClientHello via `selector`.
    /// The selector's null answer refuses the connection (fail closed):
    /// nothing is served for unknown/missing SNI or a mismatched challenge.
    pub fn acceptWithSelector(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: std.Io.net.Stream,
        selector: CertSelector,
    ) !*TlsServer {
        const self = try allocator.create(TlsServer);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.io = io;
        self.stream = stream;

        self.enc_rdbuf = undefined;
        self.enc_wrbuf = undefined;
        self.enc_reader = self.stream.reader(self.io, &self.enc_rdbuf);
        self.enc_writer = self.stream.writer(self.io, &self.enc_wrbuf);

        // Peek the ClientHello record WITHOUT consuming it — the handshake
        // below re-reads the same buffered bytes. The ClientHello is the one
        // always-unencrypted handshake message in TLS 1.2/1.3.
        const header = self.enc_reader.interface.peek(5) catch return error.TlsHandshakeFailed;
        if (header[0] != 22) return error.TlsHandshakeFailed; // record type: handshake
        const record_len = std.mem.readInt(u16, header[3..5], .big);
        // 16645-byte read buffer always covers a max-size record (16389).
        if (5 + @as(usize, record_len) > self.enc_rdbuf.len) return error.TlsHandshakeFailed;
        const record = self.enc_reader.interface.peek(5 + @as(usize, record_len)) catch
            return error.TlsHandshakeFailed;

        var alpns_buf: [8][]const u8 = undefined;
        const hello = parseClientHello(record[5..], &alpns_buf) catch return error.TlsHandshakeFailed;

        const selected = selector.select(hello.sni, hello.alpns) orelse return error.CertificateError;

        var rng_impl: std.Random.IoSource = .{ .io = io };
        const rng = rng_impl.interface();

        // @constCast: tls.zig declares auth as *CertKeyPair but only reads it
        // during the synchronous handshake (the ecdsa_key_pair cache is built
        // at pair init, not here); the selector's pair outlives the handshake.
        self.tls_conn = tls.server(&self.enc_reader.interface, &self.enc_writer.interface, .{
            .auth = @constCast(selected.pair),
            .alpn_protocols = selected.alpn_protocols,
            .now = std.Io.Clock.real.now(io),
            .rng = rng,
        }) catch return error.TlsHandshakeFailed;

        self.tls_rdbuf = undefined;
        self.tls_wrbuf = undefined;
        self.cleartext_reader = self.tls_conn.reader(&self.tls_rdbuf);
        self.cleartext_writer = self.tls_conn.writer(&self.tls_wrbuf);
        self.closed = false;

        return self;
    }

    /// ALPN protocol negotiated during the handshake (null when none). The
    /// relay server uses this to route `acme-tls/1` connections away from
    /// the WebSocket/auth path.
    pub fn alpnProtocol(self: *TlsServer) ?[]const u8 {
        return self.tls_conn.alpn_protocol;
    }

    pub fn reader(self: *TlsServer) *std.Io.Reader {
        return &self.cleartext_reader.interface;
    }

    pub fn writer(self: *TlsServer) *std.Io.Writer {
        return &self.cleartext_writer.interface;
    }

    pub fn close(self: *TlsServer) void {
        if (self.closed) return;
        self.closed = true;
        self.stream.shutdown(self.io, .both) catch {};
        self.tls_conn.close() catch {};
        self.stream.close(self.io);
        zeroizeTrafficKeys(&self.tls_conn.cipher);
    }

    pub fn deinit(self: *TlsServer) void {
        self.close();
        self.allocator.destroy(self);
    }
};

test "traffic cipher zeroization scrubs active storage idempotently" {
    var cipher: tls.Cipher = @unionInit(tls.Cipher, "AES_128_GCM_SHA256", undefined);
    const storage = activeCipherStorage(&cipher);
    @memset(storage, 0xa5);

    zeroizeTrafficKeys(&cipher);
    for (storage) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    zeroizeTrafficKeys(&cipher);
    for (storage) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "acceptWithSelector rejects oversized TLS record without panic" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const AcceptCtx = struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        listener: *std.Io.net.Server,
        result: ?anyerror = null,

        fn rejectSelector(_: *anyopaque, _: ?[]const u8, _: []const []const u8) ?ServerHelloSelect {
            unreachable;
        }

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch |err| {
                self.result = err;
                return;
            };
            defer stream.close(self.io);

            const selector: CertSelector = .{ .context = self, .select_fn = rejectSelector };
            if (TlsServer.acceptWithSelector(self.allocator, self.io, stream, selector)) |server| {
                server.deinit();
                self.result = error.TestUnexpectedSuccess;
            } else |err| {
                self.result = err;
            }
        }
    };

    var ctx: AcceptCtx = .{ .io = io, .allocator = allocator, .listener = &listener };
    const accept_thread = try std.Thread.spawn(.{}, AcceptCtx.run, .{&ctx});

    var client = try listener.socket.address.connect(io, .{ .mode = .stream });
    var client_closed = false;
    defer if (!client_closed) client.close(io);

    var write_buf: [16]u8 = undefined;
    var writer = client.writer(io, &write_buf);
    try writer.interface.writeAll(&[_]u8{ 0x16, 0x03, 0x03, 0x41, 0x01 });
    try writer.interface.flush();
    client.close(io);
    client_closed = true;

    accept_thread.join();
    try std.testing.expect(ctx.result != null);
    try std.testing.expectEqual(error.TlsHandshakeFailed, ctx.result.?);
}

fn buildTestClientHello(buf: []u8, sni: ?[]const u8, alpns: []const []const u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeByte(1) catch unreachable; // handshake type: client_hello
    const len_pos = w.end;
    w.writeInt(u24, 0, .big) catch unreachable; // length, backpatched
    const body_start = w.end;
    w.writeAll(&[_]u8{ 0x03, 0x03 }) catch unreachable; // legacy_version
    w.writeAll(&[_]u8{0x42} ** 32) catch unreachable; // random
    w.writeByte(0) catch unreachable; // session id len
    w.writeInt(u16, 2, .big) catch unreachable;
    w.writeAll(&[_]u8{ 0x13, 0x01 }) catch unreachable; // TLS_AES_128_GCM_SHA256
    w.writeByte(1) catch unreachable;
    w.writeByte(0) catch unreachable; // null compression
    const ext_len_pos = w.end;
    w.writeInt(u16, 0, .big) catch unreachable; // extensions len, backpatched
    const ext_start = w.end;
    if (sni) |host| {
        w.writeInt(u16, 0, .big) catch unreachable; // server_name
        w.writeInt(u16, @intCast(2 + 1 + 2 + host.len), .big) catch unreachable;
        w.writeInt(u16, @intCast(1 + 2 + host.len), .big) catch unreachable; // list len
        w.writeByte(0) catch unreachable; // host_name
        w.writeInt(u16, @intCast(host.len), .big) catch unreachable;
        w.writeAll(host) catch unreachable;
    }
    if (alpns.len > 0) {
        var list_len: usize = 0;
        for (alpns) |p| list_len += 1 + p.len;
        w.writeInt(u16, 16, .big) catch unreachable; // ALPN
        w.writeInt(u16, @intCast(2 + list_len), .big) catch unreachable;
        w.writeInt(u16, @intCast(list_len), .big) catch unreachable;
        for (alpns) |p| {
            w.writeByte(@intCast(p.len)) catch unreachable;
            w.writeAll(p) catch unreachable;
        }
    }
    const ext_total = w.end - ext_start;
    std.mem.writeInt(u16, buf[ext_len_pos..][0..2], @intCast(ext_total), .big);
    const body_total = w.end - body_start;
    std.mem.writeInt(u24, buf[len_pos..][0..3], @intCast(body_total), .big);
    return buf[0..w.end];
}

test "parseClientHello extracts sni and alpn" {
    var buf: [512]u8 = undefined;
    const record = buildTestClientHello(&buf, "relay-a.localhost", &.{ "acme-tls/1", "h2" });
    var alpns_buf: [8][]const u8 = undefined;
    const hello = try parseClientHello(record, &alpns_buf);
    try std.testing.expectEqualStrings("relay-a.localhost", hello.sni.?);
    try std.testing.expectEqual(@as(usize, 2), hello.alpns.len);
    try std.testing.expectEqualStrings("acme-tls/1", hello.alpns[0]);
    try std.testing.expectEqualStrings("h2", hello.alpns[1]);
}

test "parseClientHello tolerates absent sni and alpn" {
    var buf: [512]u8 = undefined;
    const record = buildTestClientHello(&buf, null, &.{});
    var alpns_buf: [8][]const u8 = undefined;
    const hello = try parseClientHello(record, &alpns_buf);
    try std.testing.expect(hello.sni == null);
    try std.testing.expectEqual(@as(usize, 0), hello.alpns.len);
}

test "parseClientHello fails closed on truncation and wrong type" {
    var buf: [512]u8 = undefined;
    const record = buildTestClientHello(&buf, "relay-a.localhost", &.{"acme-tls/1"});
    var alpns_buf: [8][]const u8 = undefined;
    // Truncated mid-extension.
    try std.testing.expectError(error.Malformed, parseClientHello(record[0 .. record.len - 4], &alpns_buf));
    // Not a ClientHello.
    var bad: [512]u8 = undefined;
    @memcpy(bad[0..record.len], record);
    bad[0] = 2;
    try std.testing.expectError(error.Malformed, parseClientHello(bad[0..record.len], &alpns_buf));
}
