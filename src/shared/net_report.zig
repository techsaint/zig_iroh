//! Endpoint net report: live home-relay state plus local path facts.
//!
//! The report reflects the CALLING endpoint's network state (upstream
//! `Endpoint::net_report`): the endpoint's configured home relay URL, whether
//! the endpoint currently holds a live home-relay session, and a measured
//! handshake latency against THAT configured relay — never a throwaway relay
//! spun up inside the probe. Local UDP loopback bind facts are collected as
//! observed path facts.
//!
//! `runEndpointReportFull` additionally supports a STUN (RFC 5389) binding
//! probe reporting the server-reflexive address plus a bounded NAT
//! classification, and multi-relay latency probing with a preferred-relay
//! ranking. `runEndpointReport` is the legacy single-relay entry point and
//! delegates with no STUN server and no relay list.

const std = @import("std");
const addr = @import("addr.zig");
const key = @import("key.zig");
const relay_client = @import("relay/client.zig");
const stun = @import("net_report_stun.zig");

const net = std.Io.net;

/// Bounded NAT classification from a single STUN binding probe.
pub const NatClass = enum {
    /// No STUN server was configured, so nothing was probed.
    unknown,
    /// A STUN server was configured but the binding probe timed out or
    /// failed: outbound UDP to that server is blocked (or it is down).
    udp_blocked,
    /// The server-reflexive address equals the probe socket's local address:
    /// no address rewrite was observed on this path.
    no_nat_detected,
    /// The server-reflexive address differs from the probe socket's local
    /// address: a NAT rewrote the source on this path.
    natted,
};

/// Latency probe result for one relay URL.
pub const RelayProbe = struct {
    /// Allocator-owned copy of the probed URL.
    url: []const u8,
    /// Measured handshake latency; null when the relay did not answer.
    latency_us: ?u64,
};

pub const Report = struct {
    /// The endpoint's configured home relay URL; null when the endpoint runs
    /// relay-disabled (or has no resolvable home relay).
    relay_url: ?[]const u8,
    /// The endpoint holds a live home-relay session right now.
    relay_connected: bool,
    /// Measured real relay client handshake latency against the CONFIGURED
    /// home relay; null when no relay is configured or the probe relay is
    /// unreachable from this environment.
    relay_latency_us: ?u64,
    udp_ipv4_loopback: bool,
    udp_ipv6_loopback: bool,
    /// Server-reflexive address from the STUN binding probe; null when no
    /// STUN server was configured or the probe failed.
    stun_srflx: ?net.IpAddress = null,
    /// Bounded NAT classification from the STUN probe (see `NatClass`).
    nat: NatClass = .unknown,
    /// Per-relay latency probes, in the order the URLs were supplied.
    /// Allocator-owned; empty when no relay list was supplied.
    relay_probes: []RelayProbe = &.{},
    /// Allocator-owned URL of the lowest-latency relay in `relay_probes`;
    /// null when no probe answered.
    preferred_relay_url: ?[]const u8 = null,

    pub fn deinit(self: Report, allocator: std.mem.Allocator) void {
        if (self.relay_url) |u| allocator.free(u);
        for (self.relay_probes) |probe| allocator.free(probe.url);
        allocator.free(self.relay_probes);
        if (self.preferred_relay_url) |u| allocator.free(u);
    }
};

/// Inputs for `runEndpointReportFull`.
pub const ReportOptions = struct {
    /// The endpoint's configured home relay URL (see `Report.relay_url`).
    home_relay_url: ?[]const u8 = null,
    relay_connected: bool = false,
    insecure_skip_verify: bool = false,
    /// Optional STUN server address for the RFC 5389 binding probe.
    stun_server: ?net.IpAddress = null,
    /// How long the STUN probe waits for a Binding Response.
    stun_timeout: std.Io.Timeout = .{ .duration = .{
        .raw = .fromMilliseconds(1500),
        .clock = .awake,
    } },
    /// Relay URLs to latency-probe and rank (e.g. the URLs of a
    /// `relay_map.RelayMap`). Probed sequentially.
    relay_urls: []const []const u8 = &.{},
};

/// Build a report for one endpoint from its live relay state. The latency
/// probe dials the endpoint's own configured relay with a throwaway probe
/// identity (so the endpoint's live session is never displaced) and inherits
/// the endpoint's TLS verification posture (`insecure_skip_verify`); a failed
/// probe degrades to `relay_latency_us = null` instead of failing the report.
///
/// Legacy entry point: no STUN server, no multi-relay probe list.
pub fn runEndpointReport(
    allocator: std.mem.Allocator,
    io: std.Io,
    home_relay_url: ?[]const u8,
    relay_connected: bool,
    insecure_skip_verify: bool,
) !Report {
    return runEndpointReportFull(allocator, io, .{
        .home_relay_url = home_relay_url,
        .relay_connected = relay_connected,
        .insecure_skip_verify = insecure_skip_verify,
    });
}

/// Full report composer: everything `runEndpointReport` reports, plus an
/// optional STUN binding probe (`stun_srflx` / `nat`) and optional
/// multi-relay latency probing with preferred-relay ranking
/// (`relay_probes` / `preferred_relay_url`). Individual probe failures
/// degrade to null fields rather than failing the report.
pub fn runEndpointReportFull(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: ReportOptions,
) !Report {
    var report: Report = .{
        .relay_url = null,
        .relay_connected = options.relay_connected,
        .relay_latency_us = null,
        .udp_ipv4_loopback = canBindUdp(io, .{ .ip4 = .loopback(0) }),
        .udp_ipv6_loopback = canBindUdp(io, .{ .ip6 = .loopback(0) }),
    };
    errdefer report.deinit(allocator);

    if (options.home_relay_url) |u| {
        report.relay_url = try allocator.dupe(u8, u);
        report.relay_latency_us = probeRelayLatency(io, u, options.insecure_skip_verify) catch null;
    }

    if (options.stun_server) |server| {
        if (stun.probeBinding(io, server, options.stun_timeout)) |binding| {
            report.stun_srflx = binding.srflx;
            report.nat = classifyNat(binding);
        } else |_| {
            report.nat = .udp_blocked;
        }
    }

    if (options.relay_urls.len > 0) {
        const probes = try allocator.alloc(RelayProbe, options.relay_urls.len);
        // Zero-fill first so errdefer deinit never frees an undefined url.
        @memset(probes, .{ .url = &.{}, .latency_us = null });
        report.relay_probes = probes;
        for (options.relay_urls, probes) |url, *probe| {
            probe.* = .{
                .url = try allocator.dupe(u8, url),
                .latency_us = probeRelayLatency(io, url, options.insecure_skip_verify) catch null,
            };
        }
        // Preferred relay: lowest non-null latency; none answered → null.
        var best: ?usize = null;
        for (probes, 0..) |probe, i| {
            const latency = probe.latency_us orelse continue;
            if (best == null or latency < probes[best.?].latency_us.?) best = i;
        }
        if (best) |i| report.preferred_relay_url = try allocator.dupe(u8, probes[i].url);
    }

    return report;
}

fn classifyNat(binding: stun.BindingResult) NatClass {
    // EXTERNAL BLOCKER: full mapping-BEHAVIOR classification (upstream
    // iroh's "easy/hard" NAT kind — endpoint-independent vs
    // address/port-dependent mapping, RFC 5780-style probes) requires >= 2
    // STUN servers reachable on distinct routes; this environment has no
    // reachable STUN servers at all. Only the bounded single-probe
    // classification below is implemented — do not fake the richer kind.
    if (binding.srflx.eql(&binding.local)) return .no_nat_detected;
    // For non-loopback servers the probe socket binds UNSPECIFIED, and 0.16
    // std exposes no connected-socket getsockname to recover the egress IP
    // the kernel picked, so the IP leg of `local` is unprovable there. Fall
    // back to the port leg: a source rewrite changes the observed port,
    // which is the wire-observable half this probe can check.
    const local_unspecified = switch (binding.local) {
        .ip4 => |ip4| std.mem.eql(u8, &ip4.bytes, &.{ 0, 0, 0, 0 }),
        .ip6 => |ip6| std.mem.eql(u8, &ip6.bytes, &([_]u8{0} ** 16)),
    };
    if (local_unspecified and
        binding.srflx.getPort() == binding.local.getPort()) return .no_nat_detected;
    return .natted;
}

fn probeRelayLatency(io: std.Io, url: []const u8, insecure_skip_verify: bool) !u64 {
    const before = std.Io.Clock.Timestamp.now(io, .awake).raw.toMicroseconds();
    var client: relay_client.Client = undefined;
    try client.connectInPlace(io, .{
        .url = addr.RelayUrl.borrowed(url),
        .secret_key = key.SecretKey.fromBytes([_]u8{0x9a} ** 32),
        .insecure_skip_verify = insecure_skip_verify,
    });
    defer client.close();
    const after = std.Io.Clock.Timestamp.now(io, .awake).raw.toMicroseconds();
    return if (after >= before) @intCast(after - before) else 0;
}

fn canBindUdp(io: std.Io, address: net.IpAddress) bool {
    var bind = address;
    const socket = bind.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch return false;
    socket.close(io);
    return true;
}

test "net_report path summary handles loopback probes" {
    try std.testing.expect(canBindUdp(std.testing.io, .{ .ip4 = .loopback(0) }));
}

test "runEndpointReport without a home relay reports no relay and still collects path facts" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const report = try runEndpointReport(allocator, io, null, false, false);
    defer report.deinit(allocator);
    try std.testing.expect(report.relay_url == null);
    try std.testing.expect(!report.relay_connected);
    try std.testing.expect(report.relay_latency_us == null);
    try std.testing.expect(report.udp_ipv4_loopback);
}

test "runEndpointReport legacy entry leaves STUN and multi-relay facts empty" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const report = try runEndpointReport(allocator, io, null, false, false);
    defer report.deinit(allocator);
    try std.testing.expect(report.stun_srflx == null);
    try std.testing.expect(report.nat == .unknown);
    try std.testing.expectEqual(@as(usize, 0), report.relay_probes.len);
    try std.testing.expect(report.preferred_relay_url == null);
}

test "runEndpointReport probes latency against the configured relay" {
    const relay_server = @import("relay/server.zig");
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try relay_server.Server.init(allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
    });
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *relay_server.Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        accept_thread.join();
    }

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "ws://127.0.0.1:{d}/relay", .{server.localAddress().getPort()});

    // A probe against the CONFIGURED relay measures real latency; a probe
    // against a dead relay degrades to null instead of inventing a number.
    const live = try runEndpointReport(allocator, io, url, true, false);
    defer live.deinit(allocator);
    try std.testing.expectEqualStrings(url, live.relay_url.?);
    try std.testing.expect(live.relay_connected);
    try std.testing.expect(live.relay_latency_us != null);

    const dead = try runEndpointReport(allocator, io, "ws://127.0.0.1:1/relay", false, false);
    defer dead.deinit(allocator);
    try std.testing.expect(dead.relay_latency_us == null);
}

/// Minimal STUN server fixture for the report tests: answers well-formed
/// Binding Requests with a XOR-MAPPED-ADDRESS echoing the transaction id and
/// carrying the sender's observed address.
const StunFixture = struct {
    io: std.Io,
    socket: net.Socket,
    stopped: std.atomic.Value(bool) = .init(false),

    fn run(self: *StunFixture) void {
        defer self.socket.close(self.io);
        var buf: [576]u8 = undefined;
        while (!self.stopped.load(.acquire)) {
            const msg = self.socket.receiveTimeout(self.io, &buf, .{
                .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake },
            }) catch continue;
            if (msg.data.len < stun.header_len) continue;
            if (std.mem.readInt(u16, msg.data[0..2], .big) != 0x0001) continue;
            var resp: [64]u8 = undefined;
            const n = stun.encodeBindingResponse(&resp, msg.data[8..20], msg.from);
            self.socket.send(self.io, &msg.from, resp[0..n]) catch {};
        }
    }
};

test "runEndpointReportFull with a loopback STUN server reports srflx and no_nat_detected" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Bound by the main thread before spawn, so the first probe cannot race
    // the fixture's bind.
    var fixture_bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const fixture_socket = try fixture_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var fixture: StunFixture = .{ .io = io, .socket = fixture_socket };
    const fixture_thread = try std.Thread.spawn(.{}, StunFixture.run, .{&fixture});
    defer {
        fixture.stopped.store(true, .release);
        fixture_thread.join();
    }

    const stun_server: net.IpAddress = .{ .ip4 = .loopback(fixture_socket.address.getPort()) };
    const report = try runEndpointReportFull(allocator, io, .{ .stun_server = stun_server });
    defer report.deinit(allocator);

    // Loopback path: the STUN server observes exactly the probe socket's
    // local address, so the report carries a srflx and classifies no NAT.
    const srflx = report.stun_srflx orelse return error.ExpectedSrflx;
    try std.testing.expectEqual(NatClass.no_nat_detected, report.nat);
    try std.testing.expect(srflx == .ip4);
    try std.testing.expectEqual(@as(u8, 127), srflx.ip4.bytes[0]);
    try std.testing.expect(srflx.getPort() != 0);
}

test "runEndpointReportFull with an unreachable STUN server classifies udp_blocked" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A guaranteed-unused UDP port: bind then close before probing.
    var dead_bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const dead_socket = try dead_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    const dead_port = dead_socket.address.getPort();
    dead_socket.close(io);

    const report = try runEndpointReportFull(allocator, io, .{
        .stun_server = .{ .ip4 = .loopback(dead_port) },
        // Short timeout keeps the suite fast; nothing answers this port.
        .stun_timeout = .{ .duration = .{ .raw = .fromMilliseconds(250), .clock = .awake } },
    });
    defer report.deinit(allocator);

    try std.testing.expect(report.stun_srflx == null);
    try std.testing.expectEqual(NatClass.udp_blocked, report.nat);
}

test "runEndpointReportFull probes and ranks multiple relays" {
    const relay_server = @import("relay/server.zig");
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_a = try relay_server.Server.init(allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
    });
    const accept_thread_a = try std.Thread.spawn(.{}, struct {
        fn run(srv: *relay_server.Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server_a});
    defer {
        server_a.deinit();
        accept_thread_a.join();
    }

    var server_b = try relay_server.Server.init(allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
    });
    const accept_thread_b = try std.Thread.spawn(.{}, struct {
        fn run(srv: *relay_server.Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server_b});
    defer {
        server_b.deinit();
        accept_thread_b.join();
    }

    var url_a_buf: [64]u8 = undefined;
    const url_a = try std.fmt.bufPrint(&url_a_buf, "ws://127.0.0.1:{d}/relay", .{server_a.localAddress().getPort()});
    var url_b_buf: [64]u8 = undefined;
    const url_b = try std.fmt.bufPrint(&url_b_buf, "ws://127.0.0.1:{d}/relay", .{server_b.localAddress().getPort()});
    const url_dead = "ws://127.0.0.1:1/relay";

    const report = try runEndpointReportFull(allocator, io, .{
        .relay_urls = &.{ url_a, url_b, url_dead },
    });
    defer report.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), report.relay_probes.len);
    try std.testing.expectEqualStrings(url_a, report.relay_probes[0].url);
    try std.testing.expectEqualStrings(url_b, report.relay_probes[1].url);
    try std.testing.expectEqualStrings(url_dead, report.relay_probes[2].url);

    // Both live relays answered; the dead URL did not.
    const latency_a = report.relay_probes[0].latency_us orelse return error.ExpectedLatency;
    const latency_b = report.relay_probes[1].latency_us orelse return error.ExpectedLatency;
    try std.testing.expect(report.relay_probes[2].latency_us == null);

    // Preferred is the minimum-latency live relay — never the dead URL.
    const preferred = report.preferred_relay_url orelse return error.ExpectedPreferred;
    const expected = if (latency_a <= latency_b) url_a else url_b;
    try std.testing.expectEqualStrings(expected, preferred);
}
