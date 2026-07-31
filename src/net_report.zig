//! Endpoint net report: live home-relay state plus local path facts.
//!
//! The report reflects the CALLING endpoint's network state (upstream
//! `Endpoint::net_report`): the endpoint's configured home relay URL, whether
//! the endpoint currently holds a live home-relay session, and a measured
//! handshake latency against THAT configured relay — never a throwaway relay
//! spun up inside the probe. Local UDP loopback bind facts are collected as
//! observed path facts.

const std = @import("std");
const addr = @import("addr.zig");
const key = @import("key.zig");
const relay_client = @import("relay/client.zig");

const net = std.Io.net;

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

    pub fn deinit(self: Report, allocator: std.mem.Allocator) void {
        if (self.relay_url) |u| allocator.free(u);
    }
};

/// Build a report for one endpoint from its live relay state. The latency
/// probe dials the endpoint's own configured relay with a throwaway probe
/// identity (so the endpoint's live session is never displaced) and inherits
/// the endpoint's TLS verification posture (`insecure_skip_verify`); a failed
/// probe degrades to `relay_latency_us = null` instead of failing the report.
pub fn runEndpointReport(
    allocator: std.mem.Allocator,
    io: std.Io,
    home_relay_url: ?[]const u8,
    relay_connected: bool,
    insecure_skip_verify: bool,
) !Report {
    var owned_url: ?[]u8 = null;
    errdefer if (owned_url) |u| allocator.free(u);
    if (home_relay_url) |u| owned_url = try allocator.dupe(u8, u);

    var latency: ?u64 = null;
    if (owned_url) |u| {
        latency = probeRelayLatency(io, u, insecure_skip_verify) catch null;
    }

    return .{
        .relay_url = owned_url,
        .relay_connected = relay_connected,
        .relay_latency_us = latency,
        .udp_ipv4_loopback = canBindUdp(io, .{ .ip4 = .loopback(0) }),
        .udp_ipv6_loopback = canBindUdp(io, .{ .ip6 = .loopback(0) }),
    };
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
