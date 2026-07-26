//! Bidirectional N3b-5d/5f gate: a real cargo-spawned Rust iroh peer and the
//! greenfield Zig-noq engine each run as client and server. This remains a
//! separate build step from `interop`, which continues to exercise picoquic.

const std = @import("std");
const key = @import("key.zig");
const transport = @import("transport.zig");
const crypto = @import("quic/crypto.zig");
const factory = @import("transport/factory.zig");
const noq_gate = @import("transport/noq_gate.zig");
const noq_ep = @import("transport/transport_noq.zig");
const lifecycle = @import("interop_lifecycle");
const zigtls = if (crypto.zigtls_enabled) @import("zigtls") else struct {};
const rpk = if (crypto.zigtls_enabled) zigtls.tls13.rpk else struct {
    fn encodeEd25519SubjectPublicKeyInfo(_: [32]u8) [44]u8 {
        unreachable;
    }
};

/// Server-mode readiness: the Rust peer prints SERVER_NODE_ID + SERVER_BOUND (the
/// port-0 dynamic-bind contract; the Zig side connects to the PARSED address).
const ServerReady = struct {
    node_id: ?[32]u8 = null,
    bound: ?std.Io.net.IpAddress = null,
};

fn serverPredicate(ctx: *ServerReady, line: []const u8) !bool {
    if (std.mem.startsWith(u8, line, "SERVER_NODE_ID: ")) {
        var bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, line["SERVER_NODE_ID: ".len..]);
        ctx.node_id = bytes;
    } else if (std.mem.startsWith(u8, line, "SERVER_BOUND: ")) {
        ctx.bound = try lifecycle.parseHostPort(line["SERVER_BOUND: ".len..]);
    }
    return ctx.node_id != null and ctx.bound != null;
}

const NoCtx = struct {};

fn clientDialingPredicate(_: *const NoCtx, line: []const u8) !bool {
    return std.mem.eql(u8, line, "CLIENT_DIALING");
}

comptime {
    // Pull the existing server-side fail-closed RPK spoof oracle into this test
    // binary; build.zig selects its 5d-B test alongside both real-peer legs.
    _ = noq_gate;
}

fn requireZigtls() !void {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
}

fn acceptOne(server: factory.AnyEndpoint) transport.Error!transport.Connection {
    return server.transport().accept();
}

fn asNoq(any: factory.AnyEndpoint) *noq_ep.Endpoint {
    return switch (any) {
        .noq => |e| e,
        .picoquic => unreachable,
    };
}

const Established = struct {
    client_conn: transport.Connection,
    server_conn: transport.Connection,
};

fn establish(client_any: factory.AnyEndpoint, server_any: factory.AnyEndpoint, server_pub: key.NodeId) !Established {
    const io = std.testing.io;
    var accept_future = io.async(acceptOne, .{server_any});
    const client_conn = client_any.transport().connect(.{
        .id = server_pub,
        .addrs = &.{.{ .ip = server_any.localAddress() }},
    }) catch |err| {
        _ = accept_future.await(io) catch {};
        return err;
    };
    const server_conn = try accept_future.await(io);
    return .{ .client_conn = client_conn, .server_conn = server_conn };
}

fn pumpUntilServerRejects(server: *noq_ep.Endpoint) transport.Error!void {
    const io = std.testing.io;
    const started_ns = std.Io.Clock.now(.awake, io).nanoseconds;
    const limit_ns: i64 = 10 * std.time.ns_per_s;
    while (true) {
        try server.pumpForTest();
        if (server.serverHandshakeRejected()) return;
        const now_ns = std.Io.Clock.now(.awake, io).nanoseconds;
        if (now_ns - started_ns >= limit_ns) return error.Timeout;
        io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
}

fn waitForRealPeerResumptionTicket(client: *noq_ep.Endpoint, peer: key.NodeId) !void {
    const io = std.testing.io;
    const started_ns = std.Io.Clock.now(.awake, io).nanoseconds;
    const limit_ns: i64 = 10 * std.time.ns_per_s;
    while (true) {
        try client.pumpForTest();
        if (client.hasZigtlsResumptionTicketForTest(peer)) return;
        const now_ns = std.Io.Clock.now(.awake, io).nanoseconds;
        if (now_ns - started_ns >= limit_ns) return error.Timeout;
        io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
}

fn exchangeWithRustServer(conn: transport.Connection) !void {
    const stream = try conn.openBi();
    try stream.send.writer().writeAll("ping-interop");
    try stream.send.finish();
    var buf: [64]u8 = undefined;
    const n = try stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("pong-interop", buf[0..n]);
}

test "5d-A: Zig-noq client completes RPK handshake and echo with real Rust iroh server" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{ "cargo", "run", "--manifest-path", manifest, "--example", "interop_peer" },
    });
    defer peer.deinit();

    var ready: ServerReady = .{};
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, serverPredicate);

    const client_key = key.SecretKey.fromBytes([_]u8{0xA3} ** 32);
    const server_node_id = try key.PublicKey.fromBytes(ready.node_id.?);
    const client = try factory.create(.noq, allocator, io, client_key, "iroh-interop-test", .{});
    defer client.deinit();
    try std.testing.expectEqual(factory.Engine.noq, client.engine());

    const conn = try client.transport().connect(.{
        .id = server_node_id,
        .addrs = &.{.{ .ip = ready.bound.? }},
    });
    defer conn.close();
    try std.testing.expect(conn.remoteNodeId().eql(server_node_id));

    const stream = try conn.openBi();
    try stream.send.writer().writeAll("ping-interop");
    try stream.send.finish();
    var buf: [64]u8 = undefined;
    const n = try stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("pong-interop", buf[0..n]);
}

test "5f-A: real Rust iroh client completes RPK handshake and echo with Zig-noq server" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const server_key = key.SecretKey.fromBytes([_]u8{0xB4} ** 32);
    const rust_client_key = key.SecretKey.fromBytes([_]u8{0xA3} ** 32);

    const server = try factory.create(.noq, allocator, io, server_key, "iroh-interop-test", .{
        .accept_unknown_peer = true,
    });
    defer server.deinit();
    try std.testing.expectEqual(factory.Engine.noq, server.engine());

    var addr_buf: [64]u8 = undefined;
    const local = server.localAddress();
    const server_addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{local.getPort()});
    const server_id_hex = server_key.public().toHex();

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{
            "cargo",
            "run",
            "--manifest-path",
            manifest,
            "--example",
            "interop_peer",
            "--",
            "--client",
            server_addr,
            &server_id_hex,
        },
    });
    defer peer.deinit();

    try peer.waitLines(lifecycle.cargo_startup_window, &NoCtx{}, clientDialingPredicate);

    var accept_future = io.async(acceptOne, .{server});
    const conn = accept_future.await(io) catch |err| {
        std.debug.print("5f Zig server accept failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer conn.close();
    try std.testing.expect(conn.remoteNodeId().eql(rust_client_key.public()));

    const stream = try conn.acceptBi();
    var request: [64]u8 = undefined;
    const n = try stream.recv.reader().readSliceShort(&request);
    try std.testing.expectEqualStrings("ping-from-rust", request[0..n]);
    try stream.send.writer().writeAll("pong-from-zig");
    try stream.send.finish();

    var saw_reply = false;
    peer.armWatchdog(lifecycle.post_startup_window);
    while (try peer.nextLine()) |line| {
        if (std.mem.eql(u8, line, "CLIENT_RECEIVED: pong-from-zig")) saw_reply = true;
    }
    peer.disarmWatchdog();
    try std.testing.expect(saw_reply);
    const term = try peer.waitTerm(lifecycle.post_startup_window);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "F2-positive: real Rust iroh client completes client auth with Zig-noq-zigtls server" {
    try requireZigtls();

    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const server_key = key.SecretKey.fromBytes([_]u8{0xD1} ** 32);
    const rust_client_key = key.SecretKey.fromBytes([_]u8{0xA3} ** 32);

    const server = try factory.create(.noq, allocator, io, server_key, "iroh-interop-test", .{
        .accept_unknown_peer = true,
        .tls_backend = .zigtls,
    });
    defer server.deinit();
    try std.testing.expectEqual(crypto.Backend.zigtls, asNoq(server).tlsBackend());

    var addr_buf: [64]u8 = undefined;
    const local = server.localAddress();
    const server_addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{local.getPort()});
    const server_id_hex = server_key.public().toHex();

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{
            "cargo",
            "run",
            "--manifest-path",
            manifest,
            "--example",
            "interop_peer",
            "--",
            "--client",
            server_addr,
            &server_id_hex,
        },
    });
    defer peer.deinit();

    try peer.waitLines(lifecycle.cargo_startup_window, &NoCtx{}, clientDialingPredicate);

    var accept_future = io.async(acceptOne, .{server});
    const conn = accept_future.await(io) catch |err| {
        std.debug.print("F2 zigtls server accept failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer conn.close();
    try std.testing.expect(conn.remoteNodeId().eql(rust_client_key.public()));

    const stream = try conn.acceptBi();
    var request: [64]u8 = undefined;
    const n = try stream.recv.reader().readSliceShort(&request);
    try std.testing.expectEqualStrings("ping-from-rust", request[0..n]);
    try stream.send.writer().writeAll("pong-from-zig");
    try stream.send.finish();

    var saw_reply = false;
    peer.armWatchdog(lifecycle.post_startup_window);
    while (try peer.nextLine()) |line| {
        if (std.mem.eql(u8, line, "CLIENT_RECEIVED: pong-from-zig")) saw_reply = true;
    }
    peer.disarmWatchdog();
    try std.testing.expect(saw_reply);
    const term = try peer.waitTerm(lifecycle.post_startup_window);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

test "F2-negative: zigtls server rejects Rust client when CertificateRequest has no common signature schemes" {
    try requireZigtls();

    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const server_key = key.SecretKey.fromBytes([_]u8{0xD2} ** 32);

    const server = try factory.create(.noq, allocator, io, server_key, "iroh-interop-test", .{
        .accept_unknown_peer = true,
        .tls_backend = .zigtls,
        .certificate_request_signature_algorithms = &.{0x0403},
    });
    defer server.deinit();
    const server_noq = asNoq(server);
    try std.testing.expectEqual(crypto.Backend.zigtls, server_noq.tlsBackend());

    var addr_buf: [64]u8 = undefined;
    const local = server.localAddress();
    const server_addr = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{local.getPort()});
    const server_id_hex = server_key.public().toHex();

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{
            "cargo",
            "run",
            "--manifest-path",
            manifest,
            "--example",
            "interop_peer",
            "--",
            "--client",
            server_addr,
            &server_id_hex,
        },
    });
    defer peer.deinit();

    var reject_future = io.async(pumpUntilServerRejects, .{server_noq});

    var saw_connected = false;
    var saw_reply = false;
    peer.armWatchdog(lifecycle.post_startup_window);
    while (try peer.nextLine()) |line| {
        if (std.mem.eql(u8, line, "CLIENT_CONNECTED")) saw_connected = true;
        if (std.mem.eql(u8, line, "CLIENT_RECEIVED: pong-from-zig")) saw_reply = true;
    }
    peer.disarmWatchdog();

    try reject_future.await(io);
    const term = try peer.waitTerm(lifecycle.post_startup_window);
    switch (term) {
        .exited => |code| try std.testing.expect(code != 0),
        else => {},
    }
    try std.testing.expect(saw_connected);
    try std.testing.expect(!saw_reply);
    try std.testing.expect(server_noq.serverHandshakeRejected());
    try std.testing.expect(!server_noq.serverHasVerifiedPeer());
}

test "F2-negative: Zig-noq-zigtls client rejects CertificateRequest without offered Ed25519 through NOQ" {
    try requireZigtls();

    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const alpn: [:0]const u8 = "iroh-noq-zigtls-f2-offer";

    const client_key = key.SecretKey.fromBytes([_]u8{0xD3} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xD4} ** 32);

    const server = try factory.create(.noq, allocator, io, server_key, alpn, .{
        .accept_unknown_peer = true,
        .tls_backend = .zigtls,
        .certificate_request_signature_algorithms = &.{0x0403},
    });
    defer server.deinit();
    const server_noq = asNoq(server);
    try std.testing.expectEqual(crypto.Backend.zigtls, server_noq.tlsBackend());

    const client = try factory.create(.noq, allocator, io, client_key, alpn, .{
        .tls_backend = .zigtls,
    });
    defer client.deinit();
    try std.testing.expectEqual(crypto.Backend.zigtls, asNoq(client).tlsBackend());

    var accept_future = io.async(acceptOne, .{server});
    const connect_result = client.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server.localAddress() }},
    });

    if (connect_result) |client_conn| {
        defer client_conn.close();
        if (accept_future.await(io)) |server_conn| {
            server_conn.close();
        } else |_| {}
        return error.TestUnexpectedResult;
    } else |err| switch (err) {
        error.ConnectionLost, error.Timeout => {},
        else => return err,
    }

    if (accept_future.await(io)) |server_conn| {
        server_conn.close();
        return error.TestUnexpectedResult;
    } else |err| switch (err) {
        error.ConnectionLost, error.Timeout => {},
        else => return err,
    }

    try std.testing.expect(!server_noq.serverHasVerifiedPeer());
}

test "SPKI-negative: zigtls server rejects malformed client raw public key certificate" {
    try requireZigtls();

    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const alpn: [:0]const u8 = "iroh-noq-zigtls-spki";

    const client_key = key.SecretKey.fromBytes([_]u8{0xE1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xE2} ** 32);

    const server = try factory.create(.noq, allocator, io, server_key, alpn, .{
        .accept_unknown_peer = true,
        .tls_backend = .zigtls,
    });
    defer server.deinit();
    const server_noq = asNoq(server);
    try std.testing.expectEqual(crypto.Backend.zigtls, server_noq.tlsBackend());

    const honest_client = try factory.create(.noq, allocator, io, client_key, alpn, .{
        .tls_backend = .zigtls,
    });
    defer honest_client.deinit();
    try std.testing.expectEqual(crypto.Backend.zigtls, asNoq(honest_client).tlsBackend());

    const accepted = try establish(honest_client, server, server_key.public());
    try std.testing.expect(accepted.server_conn.remoteNodeId().eql(client_key.public()));
    try std.testing.expect(server_noq.serverHasVerifiedPeer());
    accepted.client_conn.close();
    accepted.server_conn.close();
    try std.testing.expectEqual(@as(usize, 0), server_noq.liveConnectionCount());
    try std.testing.expect(!server_noq.serverHasVerifiedPeer());

    var malformed_spki = rpk.encodeEd25519SubjectPublicKeyInfo(client_key.public().toBytes());
    malformed_spki[0] = 0x31;
    const malformed_client = try factory.create(.noq, allocator, io, client_key, alpn, .{
        .certificate_der_override = malformed_spki[0..],
        .tls_backend = .zigtls,
    });
    defer malformed_client.deinit();
    try std.testing.expectEqual(crypto.Backend.zigtls, asNoq(malformed_client).tlsBackend());

    var reject_future = io.async(pumpUntilServerRejects, .{server_noq});
    const malformed_result = malformed_client.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server.localAddress() }},
    });
    // NOQ client `connect` can return after it has 1-RTT keys, before the
    // server's client-auth verdict. The owning fail-closed signal here is the
    // server-side TLS reject flag plus no published verified peer.
    defer if (malformed_result) |conn| conn.close() else |_| {};
    try reject_future.await(io);
    try std.testing.expect(server_noq.serverHandshakeRejected());
    try std.testing.expect(!server_noq.serverHasVerifiedPeer());
}

// INFORMATIONAL S3 probe — zigtls ClientHello at a real iroh server.
// Pass/fail is diagnostic (wire-compat unknown); do NOT treat as a promotion gate.
// Run via `zig build interop-noq-zigtls` (separate from picotls `interop-noq`).
test "S3-probe: Zig-noq-zigtls client vs real Rust iroh server" {
    try requireZigtls();

    const io = std.testing.io;
    const allocator = std.testing.allocator;

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{ "cargo", "run", "--manifest-path", manifest, "--example", "interop_peer" },
    });
    defer peer.deinit();

    var ready: ServerReady = .{};
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, serverPredicate);

    const client_key = key.SecretKey.fromBytes([_]u8{0xA4} ** 32);
    const server_node_id = try key.PublicKey.fromBytes(ready.node_id.?);
    const client = try factory.create(.noq, allocator, io, client_key, "iroh-interop-test", .{
        .tls_backend = .zigtls,
    });
    defer client.deinit();
    try std.testing.expectEqual(factory.Engine.noq, client.engine());

    const conn = try client.transport().connect(.{
        .id = server_node_id,
        .addrs = &.{.{ .ip = ready.bound.? }},
    });
    defer conn.close();
    try std.testing.expect(conn.remoteNodeId().eql(server_node_id));

    const stream = try conn.openBi();
    try stream.send.writer().writeAll("ping-interop");
    try stream.send.finish();
    var buf: [64]u8 = undefined;
    const n = try stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("pong-interop", buf[0..n]);
}

test "B1-resumption: Zig-noq-zigtls resumes a second connection with real Rust iroh" {
    try requireZigtls();

    const io = std.testing.io;
    const allocator = std.testing.allocator;

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{
            "cargo",
            "run",
            "--locked",
            "--manifest-path",
            manifest,
            "--example",
            "interop_peer",
            "--",
            "--connections",
            "2",
        },
    });
    defer peer.deinit();

    var ready: ServerReady = .{};
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, serverPredicate);

    const server_node_id = try key.PublicKey.fromBytes(ready.node_id.?);
    const client_key = key.SecretKey.fromBytes([_]u8{0xA4} ** 32);
    const client = try factory.create(.noq, allocator, io, client_key, "iroh-interop-test", .{
        .tls_backend = .zigtls,
    });
    defer client.deinit();
    const client_noq = asNoq(client);
    const remote: transport.NodeAddr = .{
        .id = server_node_id,
        .addrs = &.{.{ .ip = ready.bound.? }},
    };

    const first = try client.transport().connect(remote);
    try std.testing.expect(!client_noq.testDriver(.client).?.wasZigtlsResumed());
    try exchangeWithRustServer(first);
    try waitForRealPeerResumptionTicket(client_noq, server_node_id);
    first.close();

    const second = try client.transport().connect(remote);
    try std.testing.expect(client_noq.testDriver(.client).?.wasZigtlsResumed());
    try exchangeWithRustServer(second);
    second.close();

    const term = try peer.waitTerm(lifecycle.post_startup_window);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

// ── audit-v4 real-peer verification (raw-noq hostile peer) ───────────────────
// Peer: cargo example `noq_hostile_peer` (bare noq + embedded RPK, fixed reset_key).
// Closes H1/M1/H3 against a real peer; H5/M3/H2 ride the same peer where expressible.

const HostileReady = struct {
    node_id: ?[32]u8 = null,
    bound: ?std.Io.net.IpAddress = null,
    ready: bool = false,
    reset_armed: bool = false,
    accepted: bool = false,
};

fn hostileServerPredicate(ctx: *HostileReady, line: []const u8) !bool {
    if (std.mem.startsWith(u8, line, "SERVER_NODE_ID: ")) {
        var bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, line["SERVER_NODE_ID: ".len..]);
        ctx.node_id = bytes;
    } else if (std.mem.startsWith(u8, line, "SERVER_BOUND: ")) {
        ctx.bound = try lifecycle.parseHostPort(line["SERVER_BOUND: ".len..]);
    } else if (std.mem.eql(u8, line, "HOSTILE_READY")) {
        ctx.ready = true;
    } else if (std.mem.eql(u8, line, "RESET_ARMED")) {
        ctx.reset_armed = true;
    } else if (std.mem.eql(u8, line, "HOSTILE_ACCEPTED")) {
        ctx.accepted = true;
    }
    return ctx.node_id != null and ctx.bound != null and ctx.ready;
}

fn hostileResetArmedPredicate(ctx: *HostileReady, line: []const u8) !bool {
    if (std.mem.eql(u8, line, "RESET_ARMED")) ctx.reset_armed = true;
    if (std.mem.eql(u8, line, "HOSTILE_ACCEPTED")) ctx.accepted = true;
    return ctx.reset_armed;
}

test "realpeer H1: smoothed RTT not inflated after handshake with raw-noq peer" {
    // After a normal RPK handshake + echo, smoothed RTT must be in a sane LAN
    // range. Without H1 scaling, a peer ack_delay of O(ms) at exponent 3 can
    // leave multi-second inflation; with H1 it tracks real RTT (~sub-second).
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{ "cargo", "run", "--manifest-path", manifest, "--example", "noq_hostile_peer" },
    });
    defer peer.deinit();

    var ready: HostileReady = .{};
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, hostileServerPredicate);

    const client_key = key.SecretKey.fromBytes([_]u8{0xA3} ** 32);
    const server_node_id = try key.PublicKey.fromBytes(ready.node_id.?);
    const client = try factory.create(.noq, allocator, io, client_key, "iroh-interop-test", .{});
    defer client.deinit();
    const client_noq = asNoq(client);

    const conn = try client.transport().connect(.{
        .id = server_node_id,
        .addrs = &.{.{ .ip = ready.bound.? }},
    });
    defer conn.close();

    try exchangeWithRustServer(conn);

    // Pump once so any post-echo ACKs apply RTT samples.
    var pumps: usize = 0;
    while (pumps < 20) : (pumps += 1) {
        try client_noq.pumpForTest();
        io.sleep(std.Io.Duration.fromMilliseconds(5), .awake) catch {};
    }

    const rtt = client_noq.smoothedRttNsForTest(.client) orelse return error.TestUnexpectedResult;
    // LAN loopback handshake RTT should be well under 500ms; initial RTT is 333ms
    // and would stay high only if samples never applied. Upper bound 2s is a
    // generous anti-inflation guard (H1 bug inflated by tens of ms×scale).
    try std.testing.expect(rtt > 0);
    try std.testing.expect(rtt < 2 * std.time.ns_per_s);
    // Peer token was learned via TP (needed by H3 path).
    const drv = client_noq.testDriver(.client) orelse return error.TestUnexpectedResult;
    try std.testing.expect(drv.hasPeerStatelessResetTokenForTest());
}

test "realpeer M1: non-v1 long header inject during live conn does not kill it" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{ "cargo", "run", "--manifest-path", manifest, "--example", "noq_hostile_peer" },
    });
    defer peer.deinit();

    var ready: HostileReady = .{};
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, hostileServerPredicate);

    const client_key = key.SecretKey.fromBytes([_]u8{0xA5} ** 32);
    const server_node_id = try key.PublicKey.fromBytes(ready.node_id.?);
    const client = try factory.create(.noq, allocator, io, client_key, "iroh-interop-test", .{});
    defer client.deinit();
    const client_noq = asNoq(client);

    const conn = try client.transport().connect(.{
        .id = server_node_id,
        .addrs = &.{.{ .ip = ready.bound.? }},
    });
    defer conn.close();
    try exchangeWithRustServer(conn);

    // Craft a minimal non-v1 long-header (version=0x00000002). M1 says skip,
    // do not poison PN space / kill the conn.
    var junk: [32]u8 = undefined;
    @memset(&junk, 0);
    junk[0] = 0xc0; // long header form + fixed bit-ish
    junk[1] = 0x00;
    junk[2] = 0x00;
    junk[3] = 0x00;
    junk[4] = 0x02; // version 2
    junk[5] = 0; // dcid len 0
    junk[6] = 0; // scid len 0
    try client_noq.injectDatagramForTest(.client, &junk);

    // Connection still usable for another echo.
    try exchangeWithRustServer(conn);
    const drv = client_noq.testDriver(.client) orelse return error.TestUnexpectedResult;
    try std.testing.expect(drv.isEstablishedForTest());
}

test "realpeer H3: raw-noq peer induces real RFC 9000 §10.3 reset → Zig drains" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{
            "cargo", "run", "--manifest-path", manifest, "--example", "noq_hostile_peer",
            "--", "--induce-stateless-reset",
        },
    });
    defer peer.deinit();

    var ready: HostileReady = .{};
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, hostileServerPredicate);

    const client_key = key.SecretKey.fromBytes([_]u8{0xA6} ** 32);
    const server_node_id = try key.PublicKey.fromBytes(ready.node_id.?);
    const client = try factory.create(.noq, allocator, io, client_key, "iroh-interop-test", .{});
    defer client.deinit();
    const client_noq = asNoq(client);

    const conn = try client.transport().connect(.{
        .id = server_node_id,
        .addrs = &.{.{ .ip = ready.bound.? }},
    });
    defer conn.close();

    // Kick an exchange so TPs settle and peer may accept a bi before dropping.
    exchangeWithRustServer(conn) catch {};

    // Wait for RESET_ARMED (peer rebuilt Endpoint with same reset_key, no conn state).
    peer.armWatchdog(lifecycle.post_startup_window);
    var armed = false;
    while (try peer.nextLine()) |line| {
        std.debug.print("hostile-peer: {s}\n", .{line});
        if (std.mem.eql(u8, line, "RESET_ARMED")) {
            armed = true;
            break;
        }
    }
    peer.disarmWatchdog();
    if (!armed) {
        std.debug.print("H3: peer exited without RESET_ARMED\n", .{});
    }
    try std.testing.expect(armed);

    // Peer token must have been learned from the handshake TP path.
    const drv = client_noq.testDriver(.client) orelse return error.TestUnexpectedResult;
    try std.testing.expect(drv.hasPeerStatelessResetTokenForTest());

    // Brief pause so the peer's rebind settles, then provoke traffic.
    io.sleep(std.Io.Duration.fromMilliseconds(100), .awake) catch {};

    // noq suppresses resets when the inciting datagram is too small
    // (token 16 + min padding 5). Send a large payload so the peer can reply.
    var big: [1200]u8 = undefined;
    @memset(&big, 0xAB);

    var saw_reset = false;
    var round: usize = 0;
    while (round < 80 and !saw_reset) : (round += 1) {
        if (conn.openBi()) |stream| {
            stream.send.writer().writeAll(&big) catch {};
            stream.send.finish() catch {};
        } else |_| {}
        try client_noq.pumpForTest();
        if (client_noq.isDrainingStatelessResetForTest(.client)) {
            saw_reset = true;
            break;
        }
        io.sleep(std.Io.Duration.fromMilliseconds(25), .awake) catch {};
    }
    try std.testing.expect(saw_reset);
    try std.testing.expect(client_noq.isDrainingStatelessResetForTest(.client));
}

test "realpeer H3 mutation-RED: disable peer-token match misses the real reset" {
    // Deterministic mutation-RED (no race with peer-emitted resets):
    // 1) real-peer handshake → LEARN the peer's TP reset token (not hand-planted)
    // 2) craft an RFC-shape reset with that LEARNED token
    // 3) with match disabled → inject must NOT drain
    // 4) with match re-enabled → inject MUST drain
    // Complements the induce-mode real-wire H3 test above.
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const pkt = @import("quic/packet.zig");

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{ "cargo", "run", "--manifest-path", manifest, "--example", "noq_hostile_peer" },
    });
    defer peer.deinit();

    var ready: HostileReady = .{};
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, hostileServerPredicate);

    const client_key = key.SecretKey.fromBytes([_]u8{0xA7} ** 32);
    const server_node_id = try key.PublicKey.fromBytes(ready.node_id.?);
    const client = try factory.create(.noq, allocator, io, client_key, "iroh-interop-test", .{});
    defer client.deinit();
    const client_noq = asNoq(client);

    const conn = try client.transport().connect(.{
        .id = server_node_id,
        .addrs = &.{.{ .ip = ready.bound.? }},
    });
    defer conn.close();
    try exchangeWithRustServer(conn);

    const drv = client_noq.testDriver(.client) orelse return error.TestUnexpectedResult;
    try std.testing.expect(drv.hasPeerStatelessResetTokenForTest());
    // Capture the LEARNED peer TP token before any mutation.
    const learned = drv.peerStatelessResetTokenForTest() orelse return error.TestUnexpectedResult;

    // Build RFC-shape reset carrying the learned token.
    var reset_pkt: [32]u8 = undefined;
    @memset(&reset_pkt, 0xa5);
    reset_pkt[0] = pkt.fixed_bit;
    @memcpy(reset_pkt[reset_pkt.len - pkt.stateless_reset_token_len ..], &learned);

    // MUTATION: disable match → inject must NOT drain.
    drv.setDisablePeerStatelessResetForTest(true);
    try std.testing.expect(drv.isPeerStatelessResetDisabledForTest());
    try client_noq.injectDatagramForTest(.client, &reset_pkt);
    try std.testing.expect(!client_noq.isDrainingStatelessResetForTest(.client));
    try std.testing.expect(drv.isEstablishedForTest());

    // Re-enable match → same learned-token packet MUST drain (positive control).
    drv.setDisablePeerStatelessResetForTest(false);
    try client_noq.injectDatagramForTest(.client, &reset_pkt);
    try std.testing.expect(client_noq.isDrainingStatelessResetForTest(.client));
}

test "realpeer H5 decode: ACK with 32 ranges accepted (cap is 64)" {
    // Frame-level real-peer-shape assert: build a legal 32-range ACK (above the
    // old 16 cap, under the H5 64 cap) and decode it. The hostile peer cannot
    // force noq to emit >16 ranges on command; the wire-shape acceptance is
    // what H5 changed. (Unit mutation-RED already lives in frame.zig.)
    const frame = @import("quic/frame.zig");
    var ranges: [32]frame.AckGapRange = undefined;
    for (&ranges, 0..) |*r, i| {
        r.* = .{ .gap = 0, .range = @intCast(i % 4) };
    }
    const ack = try frame.Ack.withAdditional(1000, 0, 0, ranges[0..], null);
    try std.testing.expectEqual(@as(u8, 32), ack.additional_len);
    var buf: [1024]u8 = undefined;
    const f: frame.Frame = .{ .ack = ack };
    const enc = try f.encode(&buf);
    const decoded = try frame.decode(enc);
    try std.testing.expect(decoded == .ack);
    try std.testing.expectEqual(@as(u8, 32), decoded.ack.additional_len);
}

test "realpeer H2 forTest: data-space PTO includes max_ack_delay (peer-load ready)" {
    // Confirms the H2 surface the hostile --load peer stresses: PTO with
    // peer max_ack_delay is strictly larger than base PTO. Real-peer load
    // exercise is best-effort via --load; this pins the formula path.
    const loss = @import("quic/loss.zig");
    const rtt = loss.RttEstimator.init(50_000_000); // 50ms
    const base = loss.ptoDelay(rtt, 0, 0);
    const with_mad = loss.ptoDelay(rtt, 0, 25_000_000); // 25ms max_ack_delay
    try std.testing.expect(with_mad > base);
}
