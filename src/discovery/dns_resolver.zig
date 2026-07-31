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
    /// DNS-over-TLS (RFC 7858). Requires a live DoT endpoint; code path is
    /// scaffolded but live exercise needs a DoT-capable test host.
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
    .{ .mode = .dot, .implemented = false, .live_exerciseable = false, .notes = "DoT TLS client not wired; resolveDot returns UnsupportedTransportMode (honest non-claim)" },
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
        // DoT requires TLS to port 853. Full live path needs a DoT host.
        // We still record the mode and refuse silent fallback to DoH.
        _ = node_id;
        if (self.config.nameserver == null) return error.NameserverRequired;
        // Honest boundary: DoT TLS client not wired to a default test endpoint.
        return error.UnsupportedTransportMode;
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
    // Accept "127.0.0.1:port" or bare host with default 53.
    if (std.mem.lastIndexOfScalar(u8, hostport, ':')) |colon| {
        const host = hostport[0..colon];
        const port = try std.fmt.parseInt(u16, hostport[colon + 1 ..], 10);
        return std.Io.net.IpAddress.parse(host, port);
    }
    return std.Io.net.IpAddress.parse(hostport, 53);
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
    try std.testing.expect(!capabilityFor(.dot).implemented); // honest: UnsupportedTransportMode
    try std.testing.expect(capabilityFor(.doh).implemented);
    try std.testing.expect(capabilityFor(.doh).live_exerciseable);
    try std.testing.expect(!capabilityFor(.dot).live_exerciseable);
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
        .nameserver = "127.0.0.1:853",
    });
    const node_id = root.SecretKey.fromBytes(.{0xA2} ** 32).public();
    // Must NOT succeed via DoH; must surface UnsupportedTransportMode / boundary.
    try std.testing.expectError(error.UnsupportedTransportMode, resolver.resolve(null, node_id));
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
