//! Generic DNS resolver framework for discovery.
//!
//! Transport-mode surface (UDP / TCP / DoT / DoH) over the frozen DNS wire
//! codec (`dns_wire.zig`) and DoH path (`discovery.resolveDohTxt`). Modes that
//! need live endpoints (DoT, public UDP nameservers) are implemented up to the
//! boundary with honest capability flags.

const std = @import("std");
const root = @import("../root.zig");
const discovery = @import("discovery.zig");
const dns_wire = @import("dns_wire.zig");
const tls_wrapper = @import("../relay/tls_wrapper.zig");

pub const Error = error{
    UnsupportedTransportMode,
    TransportModeMismatch,
    NameserverRequired,
    QueryFailed,
    EmptyAnswer,
    UnexpectedRcode,
    Timeout,
    OutOfMemory,
} || discovery.Error || dns_wire.Error;

/// DNS transport modes matching iroh-dns `DnsProtocol`.
pub const TransportMode = enum {
    udp,
    tcp,
    /// DNS-over-TLS (RFC 7858). Real TLS 1.3 stream via tls_wrapper.TlsClient
    /// with length-prefixed DNS wire framing (same as TCP); exercised against
    /// a loopback TlsServer fixture in tests.
    dot,
    /// DNS-over-HTTPS (RFC 8484). Fully wired via `discovery.resolveDohTxt`.
    doh,

    pub fn name(self: TransportMode) []const u8 {
        return switch (self) {
            .udp => "udp",
            .tcp => "tcp",
            .dot => "dot",
            .doh => "doh",
        };
    }
};

/// Capability matrix: which modes are exerciseable in this build.
pub const ModeCapability = struct {
    mode: TransportMode,
    implemented: bool,
    live_exerciseable: bool,
    notes: []const u8,
};

pub const MODE_CAPABILITIES = [_]ModeCapability{
    .{ .mode = .udp, .implemented = true, .live_exerciseable = true, .notes = "RFC 1035 UDP query against a nameserver or loopback fixture" },
    .{ .mode = .tcp, .implemented = true, .live_exerciseable = true, .notes = "RFC 1035 TCP (length-prefixed) against a nameserver or loopback fixture; honors timeout_ms" },
    .{ .mode = .dot, .implemented = true, .live_exerciseable = true, .notes = "RFC 7858 DoT via TLS 1.3 stream to nameserver:853; length-prefixed DNS wire (same framing as TCP)" },
    .{ .mode = .doh, .implemented = true, .live_exerciseable = true, .notes = "RFC 8484 via discovery.resolveDohTxt / buildDohGetUrl" },
};

pub fn capabilityFor(mode: TransportMode) ModeCapability {
    for (MODE_CAPABILITIES) |cap| {
        if (cap.mode == mode) return cap;
    }
    unreachable;
}

/// Resolver configuration.
pub const DnsResolverConfig = struct {
    mode: TransportMode = .doh,
    /// DoH base URL (e.g. Cloudflare or local fixture).
    doh_url: []const u8 = discovery.DEFAULT_DOH_URL,
    /// DNS origin for `_iroh.<z32>.<origin>` queries.
    dns_origin: []const u8 = discovery.DEFAULT_DNS_ORIGIN,
    /// UDP/TCP/DoT nameserver host:port string (e.g. "127.0.0.1:53").
    nameserver: ?[]const u8 = null,
    /// Optional timeout hint in milliseconds (used by live paths).
    timeout_ms: i64 = 3000,
};

/// Generic DNS resolver: builds queries, dispatches by transport mode, parses
/// TXT answers into EndpointInfo. Does not touch pkarr signing.
pub const DnsResolver = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: DnsResolverConfig,
    /// When set, forces the active mode for mutation tests (detect mode spoofing).
    forced_mode: ?TransportMode = null,
    /// Counters for lifecycle/mutation evidence.
    queries_by_mode: std.EnumArray(TransportMode, usize) = .initFill(0),

    pub fn init(allocator: std.mem.Allocator, io: std.Io, config: DnsResolverConfig) DnsResolver {
        return .{ .allocator = allocator, .io = io, .config = config };
    }

    pub fn activeMode(self: *const DnsResolver) TransportMode {
        return self.forced_mode orelse self.config.mode;
    }

    /// Build the `_iroh.<z32>.<origin>` lookup name for a node.
    pub fn lookupName(self: *const DnsResolver, node_id: root.NodeId) ![]u8 {
        return discovery.txtLookupName(self.allocator, node_id, self.config.dns_origin);
    }

    /// Build a raw DNS TXT query packet for the configured origin.
    pub fn buildQuery(self: *const DnsResolver, node_id: root.NodeId) ![]u8 {
        const name = try self.lookupName(node_id);
        defer self.allocator.free(name);
        return dns_wire.buildTxtQuery(self.allocator, name);
    }

    /// Resolve endpoint info for `node_id` using the active transport mode.
    pub fn resolve(
        self: *DnsResolver,
        http_client: ?*std.http.Client,
        node_id: root.NodeId,
    ) !discovery.EndpointInfo {
        const mode = self.activeMode();
        self.queries_by_mode.set(mode, self.queries_by_mode.get(mode) + 1);

        return switch (mode) {
            .doh => self.resolveDoh(http_client orelse return error.QueryFailed, node_id),
            .udp => self.resolveUdp(node_id),
            .tcp => self.resolveTcp(node_id),
            .dot => self.resolveDot(node_id),
        };
    }

    /// Resolve from a pre-built DNS reply packet (steering / unit path).
    pub fn resolveFromReplyPacket(
        self: *DnsResolver,
        node_id: root.NodeId,
        packet: []const u8,
    ) !discovery.EndpointInfo {
        const query_name = try self.lookupName(node_id);
        defer self.allocator.free(query_name);
        if (packet.len < 12) return error.PacketTooShort;
        const rcode: u4 = @truncate(packet[3] & 0x0f);
        if (rcode != 0) return error.DnsNonZeroRcode;
        const txt_values = try dns_wire.parseTxtAnswers(self.allocator, packet, query_name);
        defer freeTxt(self.allocator, txt_values);
        return discovery.EndpointInfo.fromTxtLookup(self.allocator, query_name, txt_values);
    }

    fn resolveDoh(self: *DnsResolver, client: *std.http.Client, node_id: root.NodeId) !discovery.EndpointInfo {
        return discovery.resolveDohTxt(
            self.allocator,
            client,
            self.config.doh_url,
            node_id,
            self.config.dns_origin,
        );
    }

    /// UDP TXT query against configured nameserver (loopback fixture or real).
    fn resolveUdp(self: *DnsResolver, node_id: root.NodeId) !discovery.EndpointInfo {
        const ns = self.config.nameserver orelse return error.NameserverRequired;
        return resolveDatagramMode(self, ns, node_id);
    }

    fn resolveTcp(self: *DnsResolver, node_id: root.NodeId) !discovery.EndpointInfo {
        const ns = self.config.nameserver orelse return error.NameserverRequired;
        return resolveStreamMode(self, ns, node_id);
    }

    fn resolveDot(self: *DnsResolver, node_id: root.NodeId) !discovery.EndpointInfo {
        // RFC 7858: DNS over TLS — TCP to :853, then TLS, then length-prefixed
        // DNS messages (same framing as RFC 1035 TCP). Refuse silent DoH
        // fallback: a DoT-configured resolver must fail closed if TLS/DNS fails.
        const ns = self.config.nameserver orelse return error.NameserverRequired;
        return resolveDotMode(self, ns, node_id);
    }

    fn resolveDotMode(
        self: *DnsResolver,
        nameserver: []const u8,
        node_id: root.NodeId,
    ) !discovery.EndpointInfo {
        const query = try self.buildQuery(node_id);
        defer self.allocator.free(query);

        const dest = try parseHostPortDefault(nameserver, 853);
        const host_for_sni = hostOf(nameserver);
        var stream = dest.connect(self.io, .{ .mode = .stream }) catch return error.QueryFailed;
        // TlsClient.connect takes ownership of the stream for I/O; on TLS
        // handshake failure we still close the raw stream.
        const tls_client = tls_wrapper.TlsClient.connect(
            self.allocator,
            self.io,
            stream,
            host_for_sni,
            // Loopback / self-signed fixture hosts need skip-verify; public
            // DoT nameservers should pass system roots (insecure=false) once a
            // real hostname is configured. Detect loopback literals.
            isLoopbackHost(host_for_sni),
        ) catch {
            stream.close(self.io);
            return error.QueryFailed;
        };
        defer tls_client.deinit();

        var timed_out = std.atomic.Value(bool).init(false);
        const Watchdog = struct {
            client: *tls_wrapper.TlsClient,
            io: std.Io,
            timeout_ms: u64,
            timed_out: *std.atomic.Value(bool),
            fn run(wd: *@This()) void {
                wd.io.sleep(std.Io.Duration.fromMilliseconds(@intCast(wd.timeout_ms)), .awake) catch {};
                wd.timed_out.store(true, .release);
                wd.client.close();
            }
        };
        var watchdog: Watchdog = .{
            .client = tls_client,
            .io = self.io,
            .timeout_ms = @intCast(@max(self.config.timeout_ms, @as(i64, 1))),
            .timed_out = &timed_out,
        };
        const wd_thread = std.Thread.spawn(.{}, Watchdog.run, .{&watchdog}) catch return error.QueryFailed;
        defer wd_thread.join();

        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(query.len), .big);
        const w = tls_client.writer();
        w.writeAll(&len_buf) catch return mapTimedStreamError(&timed_out);
        w.writeAll(query) catch return mapTimedStreamError(&timed_out);
        w.flush() catch return mapTimedStreamError(&timed_out);

        const r = tls_client.reader();
        var resp_len_raw: [2]u8 = undefined;
        r.readSliceAll(&resp_len_raw) catch return mapTimedStreamError(&timed_out);
        const resp_len = std.mem.readInt(u16, &resp_len_raw, .big);
        if (resp_len > 4096) return error.ResponseTooLarge;
        var packet_buf: [4096]u8 = undefined;
        r.readSliceAll(packet_buf[0..resp_len]) catch return mapTimedStreamError(&timed_out);
        return self.resolveFromReplyPacket(node_id, packet_buf[0..resp_len]);
    }

    fn resolveDatagramMode(
        self: *DnsResolver,
        nameserver: []const u8,
        node_id: root.NodeId,
    ) !discovery.EndpointInfo {
        const query = try self.buildQuery(node_id);
        defer self.allocator.free(query);

        const dest = try parseHostPort(nameserver);
        const local = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
        const socket = try local.bind(self.io, .{ .mode = .dgram, .protocol = .udp });
        defer socket.close(self.io);

        try socket.send(self.io, &dest, query);

        var buf: [4096]u8 = undefined;
        const msg = socket.receiveTimeout(self.io, &buf, .{ .duration = .{
            .raw = .fromMilliseconds(self.config.timeout_ms),
            .clock = .awake,
        } }) catch |err| switch (err) {
            error.Timeout => return error.Timeout,
            else => return error.QueryFailed,
        };
        return self.resolveFromReplyPacket(node_id, msg.data);
    }

    fn resolveStreamMode(
        self: *DnsResolver,
        nameserver: []const u8,
        node_id: root.NodeId,
    ) !discovery.EndpointInfo {
        const query = try self.buildQuery(node_id);
        defer self.allocator.free(query);

        const dest = try parseHostPort(nameserver);
        // Zig 0.16 Threaded Io: ConnectOptions.timeout panics (TODO), and
        // SO_RCVTIMEO + Io.Reader panics on EAGAIN in debug. Enforce timeout_ms
        // with a watchdog that shuts the stream down after the deadline.
        var stream = dest.connect(self.io, .{ .mode = .stream }) catch return error.QueryFailed;
        defer stream.close(self.io);

        var timed_out = std.atomic.Value(bool).init(false);
        const Watchdog = struct {
            stream: *std.Io.net.Stream,
            io: std.Io,
            timeout_ms: u64,
            timed_out: *std.atomic.Value(bool),
            fn run(wd: *@This()) void {
                wd.io.sleep(std.Io.Duration.fromMilliseconds(@intCast(wd.timeout_ms)), .awake) catch {};
                wd.timed_out.store(true, .release);
                wd.stream.shutdown(wd.io, .both) catch {};
            }
        };
        var watchdog: Watchdog = .{
            .stream = &stream,
            .io = self.io,
            .timeout_ms = @intCast(@max(self.config.timeout_ms, @as(i64, 1))),
            .timed_out = &timed_out,
        };
        const wd_thread = std.Thread.spawn(.{}, Watchdog.run, .{&watchdog}) catch return error.QueryFailed;
        defer wd_thread.join();

        // RFC 1035 TCP: 2-byte big-endian length prefix.
        var len_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_buf, @intCast(query.len), .big);
        var write_buf: [4096]u8 = undefined;
        var writer = stream.writer(self.io, &write_buf);
        writer.interface.writeAll(&len_buf) catch return mapTimedStreamError(&timed_out);
        writer.interface.writeAll(query) catch return mapTimedStreamError(&timed_out);
        writer.interface.flush() catch return mapTimedStreamError(&timed_out);

        var read_buf: [4096]u8 = undefined;
        var reader = stream.reader(self.io, &read_buf);
        var resp_len_raw: [2]u8 = undefined;
        reader.interface.readSliceAll(&resp_len_raw) catch return mapTimedStreamError(&timed_out);
        const resp_len = std.mem.readInt(u16, &resp_len_raw, .big);
        if (resp_len > 4096) return error.ResponseTooLarge;
        var packet_buf: [4096]u8 = undefined;
        reader.interface.readSliceAll(packet_buf[0..resp_len]) catch return mapTimedStreamError(&timed_out);
        return self.resolveFromReplyPacket(node_id, packet_buf[0..resp_len]);
    }
};

fn mapTimedStreamError(timed_out: *const std.atomic.Value(bool)) error{ Timeout, QueryFailed } {
    if (timed_out.load(.acquire)) return error.Timeout;
    return error.QueryFailed;
}

fn parseHostPort(hostport: []const u8) !std.Io.net.IpAddress {
    return parseHostPortDefault(hostport, 53);
}

fn parseHostPortDefault(hostport: []const u8, default_port: u16) !std.Io.net.IpAddress {
    // Accept "127.0.0.1:port" or bare host with the mode's default port.
    if (std.mem.lastIndexOfScalar(u8, hostport, ':')) |colon| {
        const host = hostport[0..colon];
        const port = try std.fmt.parseInt(u16, hostport[colon + 1 ..], 10);
        return std.Io.net.IpAddress.parse(host, port);
    }
    return std.Io.net.IpAddress.parse(hostport, default_port);
}

fn hostOf(hostport: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, hostport, ':')) |colon| return hostport[0..colon];
    return hostport;
}

fn isLoopbackHost(host: []const u8) bool {
    return std.mem.eql(u8, host, "127.0.0.1") or
        std.mem.eql(u8, host, "localhost") or
        std.mem.eql(u8, host, "::1");
}

fn freeTxt(allocator: std.mem.Allocator, values: [][]u8) void {
    for (values) |v| allocator.free(v);
    allocator.free(values);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "TransportMode capability matrix covers all four modes" {
    try std.testing.expect(capabilityFor(.udp).implemented);
    try std.testing.expect(capabilityFor(.tcp).implemented);
    try std.testing.expect(capabilityFor(.dot).implemented);
    try std.testing.expect(capabilityFor(.doh).implemented);
    try std.testing.expect(capabilityFor(.doh).live_exerciseable);
    try std.testing.expect(capabilityFor(.dot).live_exerciseable);
}

test "DnsResolver TCP honors timeout_ms against a stalled server" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Bind a TCP listener that accepts then never replies (black-hole after accept).
    const bind_addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try bind_addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const local = server.socket.address;
    var ns_buf: [64]u8 = undefined;
    const ns = try std.fmt.bufPrint(&ns_buf, "127.0.0.1:{d}", .{local.getPort()});

    const AcceptHang = struct {
        server: *std.Io.net.Server,
        io: std.Io,
        fn run(self: *@This()) void {
            const stream = self.server.accept(self.io) catch return;
            // Hold the connection open without reading/writing until the client times out.
            self.io.sleep(std.Io.Duration.fromMilliseconds(2000), .awake) catch {};
            stream.close(self.io);
        }
    };
    var hang: AcceptHang = .{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, AcceptHang.run, .{&hang});
    defer thread.join();

    var resolver = DnsResolver.init(allocator, io, .{
        .mode = .tcp,
        .nameserver = ns,
        .timeout_ms = 200,
    });
    const node_id = root.SecretKey.fromBytes(.{0xA5} ** 32).public();
    const started = std.Io.Clock.Timestamp.now(io, .awake);
    try std.testing.expectError(error.Timeout, resolver.resolve(null, node_id));
    const elapsed_ns = started.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toNanoseconds();
    // Must fail inside a small multiple of timeout_ms, not hang until process kill.
    try std.testing.expect(elapsed_ns < 1500 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), resolver.queries_by_mode.get(.tcp));
}

test "DnsResolver builds query and parses reply without network" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = root.SecretKey.fromBytes(.{0xA1} ** 32);
    const node_id = secret.public();
    const origin = "fixture.iroh-port.local.";

    var resolver = DnsResolver.init(allocator, io, .{
        .mode = .doh,
        .dns_origin = origin,
        .doh_url = "http://127.0.0.1:9/dns-query", // unused in offline path
    });

    const name = try resolver.lookupName(node_id);
    defer allocator.free(name);
    try std.testing.expect(std.mem.startsWith(u8, name, "_iroh."));
    try std.testing.expect(std.mem.endsWith(u8, name, origin) or std.mem.endsWith(u8, name, "fixture.iroh-port.local."));

    const query = try resolver.buildQuery(node_id);
    defer allocator.free(query);
    try std.testing.expect(query.len >= 12);

    const txt_values = [_][]const u8{
        "relay=https://relay.fixture.local./",
        "addr=127.0.0.1:9999",
    };
    const reply = try dns_wire.buildTxtReply(allocator, name, &txt_values, 30);
    defer allocator.free(reply);

    const info = try resolver.resolveFromReplyPacket(node_id, reply);
    defer info.deinit(allocator);
    try std.testing.expect(info.node_id.eql(node_id));
    try std.testing.expectEqualStrings("dns-txt", info.provenance.?);
    try std.testing.expect(info.firstRelayUrl() != null);
    // Offline reply path must not claim a live transport-mode dispatch.
    try std.testing.expectEqual(@as(usize, 0), resolver.queries_by_mode.get(.doh));
}

test "DnsResolver mode counters detect forced-mode mutation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var resolver = DnsResolver.init(allocator, io, .{ .mode = .doh });
    try std.testing.expectEqual(TransportMode.doh, resolver.activeMode());

    // Mutation control: if a caller forced every mode through DoH without
    // recording the requested mode, activeMode would disagree with config.
    resolver.forced_mode = .udp;
    try std.testing.expectEqual(TransportMode.udp, resolver.activeMode());
    try std.testing.expect(resolver.activeMode() != resolver.config.mode);

    resolver.forced_mode = null;
    try std.testing.expectEqual(TransportMode.doh, resolver.activeMode());
}

test "DnsResolver DoT refuses silent DoH fallback" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var resolver = DnsResolver.init(allocator, io, .{
        .mode = .dot,
        .nameserver = "127.0.0.1:1", // nothing listening — DoT path must fail closed
        .timeout_ms = 200,
    });
    const node_id = root.SecretKey.fromBytes(.{0xA2} ** 32).public();
    // Must NOT succeed via DoH; the DoT TLS client path must fail closed.
    try std.testing.expectError(error.QueryFailed, resolver.resolve(null, node_id));
    try std.testing.expectEqual(@as(usize, 1), resolver.queries_by_mode.get(.dot));
    try std.testing.expectEqual(@as(usize, 0), resolver.queries_by_mode.get(.doh));
}

test "DnsResolver UDP without nameserver is NameserverRequired" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var resolver = DnsResolver.init(allocator, io, .{ .mode = .udp });
    const node_id = root.SecretKey.fromBytes(.{0xA3} ** 32).public();
    try std.testing.expectError(error.NameserverRequired, resolver.resolve(null, node_id));
}

test "DnsResolver NXDOMAIN packet is fail-closed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var resolver = DnsResolver.init(allocator, io, .{
        .mode = .doh,
        .dns_origin = "dns.iroh.link.",
    });
    const node_id = root.SecretKey.fromBytes(.{0xA4} ** 32).public();
    var hdr: [12]u8 = .{0} ** 12;
    hdr[3] = 0x03; // RCODE=NXDOMAIN
    try std.testing.expectError(error.DnsNonZeroRcode, resolver.resolveFromReplyPacket(node_id, &hdr));
}

// ---------------------------------------------------------------------------
// Positive loopback transport fixtures (UDP / TCP / DoT)
// ---------------------------------------------------------------------------

const fixture_origin = "fixture.iroh-port.local.";
const fixture_txt = [_][]const u8{
    "relay=https://relay.fixture.local./",
    "addr=127.0.0.1:9999",
};

/// Self-signed loopback PEM material (CN=localhost, 10-year validity,
/// generated 2026-08-02 with openssl for this fixture only). The DoT client
/// skips verification for loopback hosts, so chain trust is irrelevant.
const dot_test_cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBfDCCASOgAwIBAgIUMZ+Q9TexepKcm2WCYZXeXQnXJaMwCgYIKoZIzj0EAwIw
    \\FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgwMjIwNTQ1N1oXDTM2MDczMDIw
    \\NTQ1N1owFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
    \\AQcDQgAEzkC3WBeVPY/SgD9+MCkJsP+uyhaklqpLCvA8xOTuf4CfTEpWnJF6Y/VJ
    \\H9UnsoKUaKBRJ24m8X1dxFT6JTCZeaNTMFEwHQYDVR0OBBYEFJP3JEf83uBiGXhh
    \\Cpqk5F4bIlPFMB8GA1UdIwQYMBaAFJP3JEf83uBiGXhhCpqk5F4bIlPFMA8GA1Ud
    \\EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgKaMmCX61yeRRdGjpLMjvlplw
    \\7IuoW7W5qIYK6OUlWfYCIEd7uu7c777Nzm5tcVd9wo6ESTRz0r9NmXzi93yncj9b
    \\-----END CERTIFICATE-----
    \\
;
const dot_test_key_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgci1DlyJPTKOmuS0x
    \\YWKeo20/Vml6rxgsfok9t4gkksyhRANCAATOQLdYF5U9j9KAP34wKQmw/67KFqSW
    \\qksK8DzE5O5/gJ9MSlackXpj9Ukf1SeygpRooFEnbibxfV3EVPolMJl5
    \\-----END PRIVATE KEY-----
    \\
;

fn buildFixtureReply(
    allocator: std.mem.Allocator,
    resolver: *DnsResolver,
    node_id: root.NodeId,
) ![]u8 {
    const name = try resolver.lookupName(node_id);
    defer allocator.free(name);
    return dns_wire.buildTxtReply(allocator, name, &fixture_txt, 60);
}

fn expectFixtureInfo(info: discovery.EndpointInfo, node_id: root.NodeId) !void {
    try std.testing.expect(info.node_id.eql(node_id));
    try std.testing.expectEqualStrings("dns-txt", info.provenance.?);
    try std.testing.expectEqualStrings("https://relay.fixture.local./", info.firstRelayUrl().?.asString());
    var ip_it = info.ipAddrs();
    try std.testing.expect(ip_it.next() != null);
}

test "DnsResolver UDP resolves TXT from a loopback nameserver fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const node_id = root.SecretKey.fromBytes(.{0xB1} ** 32).public();

    var resolver = DnsResolver.init(allocator, io, .{
        .mode = .udp,
        .dns_origin = fixture_origin,
        .nameserver = "placeholder",
        .timeout_ms = 2000,
    });
    const reply = try buildFixtureReply(allocator, &resolver, node_id);
    defer allocator.free(reply);

    const UdpFixture = struct {
        io: std.Io,
        reply: []const u8,
        port: std.atomic.Value(u16) = .init(0),
        fn run(self: *@This()) void {
            const local = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
            const socket = local.bind(self.io, .{ .mode = .dgram, .protocol = .udp }) catch return;
            defer socket.close(self.io);
            self.port.store(socket.address.getPort(), .release);
            var buf: [4096]u8 = undefined;
            const msg = socket.receive(self.io, &buf) catch return;
            socket.send(self.io, &msg.from, self.reply) catch return;
        }
    };
    var fixture: UdpFixture = .{ .io = io, .reply = reply };
    const thread = try std.Thread.spawn(.{}, UdpFixture.run, .{&fixture});
    defer thread.join();

    var port: u16 = 0;
    while (port == 0) {
        port = fixture.port.load(.acquire);
        if (port == 0) io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
    var ns_buf: [64]u8 = undefined;
    resolver.config.nameserver = try std.fmt.bufPrint(&ns_buf, "127.0.0.1:{d}", .{port});

    const info = try resolver.resolve(null, node_id);
    defer info.deinit(allocator);
    try expectFixtureInfo(info, node_id);
    try std.testing.expectEqual(@as(usize, 1), resolver.queries_by_mode.get(.udp));
}

test "DnsResolver TCP resolves TXT from a loopback nameserver fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const node_id = root.SecretKey.fromBytes(.{0xB2} ** 32).public();

    var resolver = DnsResolver.init(allocator, io, .{
        .mode = .tcp,
        .dns_origin = fixture_origin,
        .timeout_ms = 2000,
    });
    const reply = try buildFixtureReply(allocator, &resolver, node_id);
    defer allocator.free(reply);

    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    const TcpFixture = struct {
        listener: *std.Io.net.Server,
        io: std.Io,
        reply: []const u8,
        fn run(self: *@This()) void {
            var stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            var read_buf: [4096]u8 = undefined;
            var reader = stream.reader(self.io, &read_buf);
            var len_raw: [2]u8 = undefined;
            reader.interface.readSliceAll(&len_raw) catch return;
            const qlen = std.mem.readInt(u16, &len_raw, .big);
            if (qlen > 4096) return;
            var qbuf: [4096]u8 = undefined;
            reader.interface.readSliceAll(qbuf[0..qlen]) catch return;
            var write_buf: [4600]u8 = undefined;
            var writer = stream.writer(self.io, &write_buf);
            var out_len: [2]u8 = undefined;
            std.mem.writeInt(u16, &out_len, @intCast(self.reply.len), .big);
            writer.interface.writeAll(&out_len) catch return;
            writer.interface.writeAll(self.reply) catch return;
            writer.interface.flush() catch return;
        }
    };
    var fixture: TcpFixture = .{ .listener = &listener, .io = io, .reply = reply };
    const thread = try std.Thread.spawn(.{}, TcpFixture.run, .{&fixture});
    defer thread.join();

    var ns_buf: [64]u8 = undefined;
    resolver.config.nameserver = try std.fmt.bufPrint(&ns_buf, "127.0.0.1:{d}", .{port});

    const info = try resolver.resolve(null, node_id);
    defer info.deinit(allocator);
    try expectFixtureInfo(info, node_id);
    try std.testing.expectEqual(@as(usize, 1), resolver.queries_by_mode.get(.tcp));
}

test "DnsResolver DoT resolves TXT over a real TLS loopback fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const node_id = root.SecretKey.fromBytes(.{0xB3} ** 32).public();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "dot-cert.pem", .data = dot_test_cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "dot-key.pem", .data = dot_test_key_pem });
    var base_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(io, &base_buf);
    const base = base_buf[0..base_len];
    const cert_path = try std.fmt.allocPrint(allocator, "{s}/dot-cert.pem", .{base});
    defer allocator.free(cert_path);
    const key_path = try std.fmt.allocPrint(allocator, "{s}/dot-key.pem", .{base});
    defer allocator.free(key_path);

    var resolver = DnsResolver.init(allocator, io, .{
        .mode = .dot,
        .dns_origin = fixture_origin,
        .timeout_ms = 5000,
    });
    const reply = try buildFixtureReply(allocator, &resolver, node_id);
    defer allocator.free(reply);

    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    const DotFixture = struct {
        listener: *std.Io.net.Server,
        io: std.Io,
        allocator: std.mem.Allocator,
        reply: []const u8,
        cert_path: []const u8,
        key_path: []const u8,
        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            const srv = tls_wrapper.TlsServer.accept(self.allocator, self.io, stream, self.cert_path, self.key_path) catch return;
            defer srv.deinit();
            const r = srv.reader();
            var len_raw: [2]u8 = undefined;
            r.readSliceAll(&len_raw) catch return;
            const qlen = std.mem.readInt(u16, &len_raw, .big);
            if (qlen > 4096) return;
            var qbuf: [4096]u8 = undefined;
            r.readSliceAll(qbuf[0..qlen]) catch return;
            const w = srv.writer();
            var out_len: [2]u8 = undefined;
            std.mem.writeInt(u16, &out_len, @intCast(self.reply.len), .big);
            w.writeAll(&out_len) catch return;
            w.writeAll(self.reply) catch return;
            w.flush() catch return;
        }
    };
    var fixture: DotFixture = .{
        .listener = &listener,
        .io = io,
        .allocator = allocator,
        .reply = reply,
        .cert_path = cert_path,
        .key_path = key_path,
    };
    const thread = try std.Thread.spawn(.{}, DotFixture.run, .{&fixture});
    defer thread.join();

    var ns_buf: [64]u8 = undefined;
    resolver.config.nameserver = try std.fmt.bufPrint(&ns_buf, "127.0.0.1:{d}", .{port});

    const info = try resolver.resolve(null, node_id);
    defer info.deinit(allocator);
    try expectFixtureInfo(info, node_id);
    try std.testing.expectEqual(@as(usize, 1), resolver.queries_by_mode.get(.dot));
}
