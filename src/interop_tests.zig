const std = @import("std");
const key = @import("key.zig");
const discovery = @import("discovery/discovery.zig");
const fixtures = @import("blobs/fixtures.zig");
const quic = @import("transport/quic.zig");
const tr = @import("transport.zig");
const bao = @import("blobs/bao.zig");
const lifecycle = @import("interop_lifecycle");

/// CC-i1 readiness state gathered from the Rust peer's stdout lines.
const Cci1Ready = struct {
    allocator: std.mem.Allocator,
    node_id: ?[32]u8 = null,
    bound: ?std.Io.net.IpAddress = null,
    pkarr: ?[]u8 = null,
};

fn cci1Predicate(ctx: *Cci1Ready, line: []const u8) !bool {
    if (std.mem.startsWith(u8, line, "SERVER_NODE_ID: ")) {
        var bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, line["SERVER_NODE_ID: ".len..]);
        ctx.node_id = bytes;
    } else if (std.mem.startsWith(u8, line, "PKARR_HEX: ")) {
        ctx.pkarr = try fixtures.hexToBytesAlloc(ctx.allocator, line["PKARR_HEX: ".len..]);
    } else if (std.mem.startsWith(u8, line, "SERVER_BOUND: ")) {
        ctx.bound = try lifecycle.parseHostPort(line["SERVER_BOUND: ".len..]);
    }
    return ctx.node_id != null and ctx.bound != null;
}

fn expectPkarrMatchesIrohReference(
    allocator: std.mem.Allocator,
    rust_pkarr_bytes: []const u8,
) !void {
    const secret = key.SecretKey.fromBytes(.{0x11} ** 32);
    const direct = try std.Io.net.IpAddress.parse("127.0.0.1", 1234);
    var relay = try tr.RelayUrl.parse(allocator, "https://example.com");
    defer relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{ .{ .relay = relay }, .{ .ip = direct } },
        null,
    );
    defer info.deinit(allocator);

    const rust_packet = try discovery.SignedPacket.fromBytes(allocator, rust_pkarr_bytes);
    defer rust_packet.deinit(allocator);

    const packet = try discovery.SignedPacket.fromEndpointInfoAtWithOptions(
        allocator,
        secret,
        info,
        30,
        rust_packet.timestamp,
        .{ .address_filter = .unfiltered },
    );
    defer packet.deinit(allocator);

    try std.testing.expectEqualSlices(u8, rust_pkarr_bytes, packet.bytes);
}

test "CC-i1: Zig endpoint completes QUIC+TLS handshake with real Rust iroh node" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    // Spawn the Rust interop_peer through the shared lifecycle helper: startup
    // inactivity deadline on the blocking read, group kill + reap, bounded stderr
    // capture (was: an unbounded read that could hang the gate forever — H3).
    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{ "cargo", "run", "--manifest-path", manifest, "--example", "interop_peer" },
    });
    defer peer.deinit();

    var ready: Cci1Ready = .{ .allocator = allocator };
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, cci1Predicate);
    defer if (ready.pkarr) |bytes| allocator.free(bytes);

    try std.testing.expect(ready.pkarr != null);
    try expectPkarrMatchesIrohReference(allocator, ready.pkarr.?);

    const client_key = key.SecretKey.fromBytes([_]u8{0xA1} ** 32);
    const alpn: [:0]const u8 = "iroh-interop-test";
    const client_ep = try quic.Endpoint.init(allocator, io, client_key, alpn);
    defer client_ep.deinit();

    const client_t = client_ep.transport();
    const server_node_id = try key.PublicKey.fromBytes(ready.node_id.?);
    const server_addr = ready.bound.?;

    const client_conn = try client_t.connect(.{
        .id = server_node_id,
        .addrs = &.{.{ .ip = server_addr }},
    });
    defer client_conn.close();

    const client_stream = try client_conn.openBi();
    try client_stream.send.writer().writeAll("ping-interop");
    try client_stream.send.finish();

    var buf: [64]u8 = undefined;
    const m = try client_stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("pong-interop", buf[0..m]);
}

// audit-v4 residual / AO-0067: hostile REAL-Rust-peer wrong-RPK reject at the wire.
// CC-i1 (above) is the positive control (matching pin connects). This negative pins a
// NodeId that does NOT match the peer's actual RPK (SNI + set_cnx_expected_peer via
// beginClientCnx). Production pin path must fail closed → handshake never ready → Timeout.
// Mutation-RED: disable the two pin memcmps in rpk.c → client would accept the honest
// real RPK despite the wrong pin (green→red). Port is dynamic via SERVER_BOUND (testinfra #10).
test "CC-i1-neg: Zig client rejects real Rust peer presenting wrong RPK (client pin)" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{ "cargo", "run", "--manifest-path", manifest, "--example", "interop_peer" },
    });
    defer peer.deinit();

    var ready: Cci1Ready = .{ .allocator = allocator };
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, cci1Predicate);
    defer if (ready.pkarr) |bytes| allocator.free(bytes);

    try std.testing.expect(ready.node_id != null);
    try std.testing.expect(ready.bound != null);

    const client_key = key.SecretKey.fromBytes([_]u8{0xB1} ** 32);
    // Wrong identity: must NOT match the real peer. interop_peer.rs uses fixed
    // server seed [0xB2; 32] — do not reuse that seed as the "wrong" pin.
    const wrong_key = key.SecretKey.fromBytes([_]u8{0xCC} ** 32);
    const alpn: [:0]const u8 = "iroh-interop-test";
    // Short handshake window: pin reject should surface well before the default 15s.
    // 2s leaves room for real-UDP TLS Certificate flight on a cold loopback peer.
    const client_ep = try quic.Endpoint.initOptions(allocator, io, client_key, alpn, .{
        .handshake_timeout_us = 2 * std.time.us_per_s,
    });
    defer client_ep.deinit();

    const server_addr = ready.bound.?;
    const real_id = try key.PublicKey.fromBytes(ready.node_id.?);
    const pin_id = wrong_key.public();
    try std.testing.expect(!real_id.eql(pin_id)); // sanity: pin is actually wrong

    const result = client_ep.transport().connect(.{
        .id = pin_id, // pin Y
        .addrs = &.{.{ .ip = server_addr }}, // address of real peer X
    });
    try std.testing.expectError(error.Timeout, result);
}

test "discovery: pkarr signed packet verifies deterministic local construction" {
    const allocator = std.testing.allocator;
    const secret = key.SecretKey.fromBytes(.{0x11} ** 32);
    const direct = try std.Io.net.IpAddress.parse("127.0.0.1", 1234);
    var relay = try tr.RelayUrl.parse(allocator, "https://example.com");
    defer relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{ .{ .relay = relay }, .{ .ip = direct } },
        null,
    );
    defer info.deinit(allocator);

    const packet = try discovery.SignedPacket.fromEndpointInfoAt(
        allocator,
        secret,
        info,
        30,
        .{ .micros = 42 },
    );
    defer packet.deinit(allocator);

    const reparsed = try discovery.SignedPacket.fromBytes(allocator, packet.bytes);
    defer reparsed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, packet.bytes, reparsed.bytes);
}

test "blobs: bao outboard and root byte-for-byte interop check" {
    const alloc = std.testing.allocator;
    const n = 16385;
    const data = try fixtures.makeTestData(alloc, n);
    defer alloc.free(data);

    const created = try bao.createOutboard(alloc, data);
    defer alloc.free(created.outboard);

    try std.testing.expectEqualStrings(fixtures.golden.hash_16385, &created.root.toHex());

    const expected_out = fixtures.hexToBytes(fixtures.golden.outboard_16385);
    try std.testing.expectEqualSlices(u8, &expected_out, created.outboard);
}
