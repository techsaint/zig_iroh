//! `zig build discovery-live-canary` — LIVE public canary against the REAL
//! dns.iroh.link infrastructure:
//!
//!   1. PUBLISH a project-owned signed endpoint record to the real pkarr
//!      relay (`https://dns.iroh.link/pkarr/<z32>`) through the production
//!      `discovery.publishPkarrRelay` path.
//!   2. RESOLVE `_iroh.<z32>.dns.iroh.link` TXT via PUBLIC DoH resolvers
//!      (cloudflare-dns.com, dns.google) through the production
//!      `discovery.resolveDohTxt` path.
//!   3. Assert the round-trip: the published relay-url/addr come back
//!      byte-identical from the live DNS answer.
//!
//! Why self-published: the historical static canary
//! `_iroh.dgjpkxyn…dns.iroh.link` is NXDOMAIN upstream — upstream iroh uses
//! that name only in OFFLINE parsing tests (iroh/src/test_utils.rs,
//! iroh-dns/src/endpoint_info.rs), so no live record can ever exist for it.
//! A self-published record on the same real relay+zone is the honest live
//! canary: it exercises exactly the publish → serve → resolve path a real
//! iroh node uses. The static record's status is still probed and REPORTED
//! (non-fatal) so the upstream blocker evidence stays fresh.

const std = @import("std");
const root = @import("zig_iroh");

const discovery = root.discovery;

/// Fixed canary identity — a stable, grep-able `_iroh.<z32>.dns.iroh.link`
/// name owned by this project. The record values are deliberately synthetic
/// (example relay, loopback addr): this is a canary, not a real endpoint.
const canary_secret = root.SecretKey.fromBytes(.{0xCA} ** 32);

const static_canary_z32 = "dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy";

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const out = &stdout_writer.interface;

    const node_id = canary_secret.public();
    try out.print("canary node id: {s}\n", .{node_id.toZ32()});

    var relay_url = try root.RelayUrl.parse(allocator, "https://relay.example/");
    defer relay_url.deinit(allocator);
    const direct = try std.Io.net.IpAddress.parse("127.0.0.1", 4242);
    const info = try discovery.EndpointInfo.fromParts(allocator, node_id, &.{ .{ .relay = relay_url }, .{ .ip = direct } }, null);
    defer info.deinit(allocator);

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    // 1. PUBLISH to the real relay. Fresh monotonic timestamp each run so
    //    the relay accepts the update (older packets are rejected).
    //    `.unfiltered` so the TXT answer carries both relay AND addr values
    //    (the default relay_only is the iroh-parity publish shape).
    try discovery.publishPkarrRelayWithOptions(
        allocator,
        &client,
        discovery.DEFAULT_PKARR_RELAY_URL,
        canary_secret,
        info,
        300,
        discovery.Timestamp.now(),
        .{ .address_filter = .unfiltered },
    );
    try out.print("publish: PUT {s}/{s} accepted\n", .{ discovery.DEFAULT_PKARR_RELAY_URL, node_id.toZ32() });
    try out.flush();

    // 2. RESOLVE through public DoH on the production path. Poll briefly:
    //    the authoritative zone serves the relay's store immediately, but a
    //    resolver may need one retry around propagation/cold cache.
    const doh_endpoints = [_][]const u8{
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
    };
    var resolved_any = false;
    for (doh_endpoints) |doh_url| {
        const resolved = pollResolve(allocator, &client, doh_url, node_id) catch |err| {
            try out.print("resolve: {s} -> error.{s}\n", .{ doh_url, @errorName(err) });
            continue;
        };
        defer resolved.deinit(allocator);
        resolved_any = true;
        try out.print("resolve: {s} -> _iroh.{s}.{s} OK\n", .{ doh_url, node_id.toZ32(), discovery.DEFAULT_DNS_ORIGIN });
        if (!resolved.node_id.eql(node_id)) return error.LiveCanaryNodeIdMismatch;
        const got_relay = resolved.firstRelayUrl() orelse return error.LiveCanaryMissingRelay;
        if (!std.mem.eql(u8, got_relay.asString(), "https://relay.example/")) return error.LiveCanaryRelayMismatch;
        try out.print("  relay={s}\n", .{got_relay.asString()});
        var saw_addr = false;
        var ip_it = resolved.ipAddrs();
        while (ip_it.next()) |address| {
            try out.print("  addr={f}\n", .{address});
            var addr_buf: [64]u8 = undefined;
            const got = std.fmt.bufPrint(&addr_buf, "{f}", .{address}) catch continue;
            if (std.mem.eql(u8, got, "127.0.0.1:4242")) saw_addr = true;
        }
        if (!saw_addr) return error.LiveCanaryAddrMismatch;
    }
    if (!resolved_any) return error.LiveCanaryAllResolversFailed;

    // 3. Static-canary probe — REPORT ONLY. The historical record is
    //    NXDOMAIN upstream; if that ever changes, the gate notes it.
    const static_id = root.PublicKey.fromZ32(static_canary_z32) catch unreachable;
    if (pollResolve(allocator, &client, doh_endpoints[0], static_id)) |static_info| {
        var si = static_info;
        si.deinit(allocator);
        try out.print("static-canary _iroh.{s}.dns.iroh.link: RESOLVES (upstream record now live)\n", .{static_canary_z32});
    } else |err| {
        try out.print("static-canary _iroh.{s}.dns.iroh.link: error.{s} (upstream blocker stands)\n", .{ static_canary_z32, @errorName(err) });
    }

    try out.writeAll("discovery live canary: pass (real dns.iroh.link publish + public DoH resolve)\n");
    try out.flush();
}

/// Resolve with up to 3 attempts, 2s apart, to absorb resolver cold cache.
fn pollResolve(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    doh_url: []const u8,
    node_id: root.NodeId,
) !discovery.EndpointInfo {
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        return discovery.resolveDohTxt(allocator, client, doh_url, node_id, discovery.DEFAULT_DNS_ORIGIN) catch |err| {
            if (attempt >= 2) return err;
            client.io.sleep(std.Io.Duration.fromMilliseconds(2000), .awake) catch {};
            continue;
        };
    }
}
