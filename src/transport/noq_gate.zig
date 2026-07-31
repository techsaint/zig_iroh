//! Acceptance gate — Zig-noq ↔ Zig-noq over the REAL UDP socket
//! pump, behind the frozen `transport.zig` vtable, engine selected via the
//! factory. HARNESS-FAKE RESISTANCE: this goes through `net.Socket` + the real
//! noq driver (NOT an in-memory `connection.zig` pair, NOT a mock), and asserts
//! the selected engine is actually `.noq` — otherwise it proves nothing about
//! `transport_noq.zig`.

const std = @import("std");
const tr = @import("../transport.zig");
const key = @import("../key.zig");
const crypto = @import("../quic/crypto.zig");
const quic_token = @import("../quic/token.zig");
const packet = @import("../quic/packet.zig");
const factory = @import("factory.zig");
const noq_ep = @import("transport_noq.zig");
const harness_probes = @import("harness_probes.zig");

fn acceptOne(server: factory.AnyEndpoint) tr.Error!tr.Connection {
    return server.transport().accept();
}

test "5c: Zig-noq <-> Zig-noq real-socket connect+accept, multi-stream echo, close+reclaim" {
    // picotls variant (default noq TLS backend); the zigtls path is covered by
    // noq_zigtls_gate.zig, so mono-noq-zigtls products skip this.
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-5c-gate";

    const client_key = key.SecretKey.fromBytes([_]u8{0x11} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x22} ** 32);

    // Engine-select via the factory. Default is picoquic; here we explicitly
    // select noq. The server pins its RPK verifier to the client's key.
    const server_any = try factory.create(.noq, allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
    });
    defer server_any.deinit();
    const client_any = try factory.create(.noq, allocator, io, client_key, alpn, .{});
    defer client_any.deinit();

    // HARNESS-FAKE RESISTANCE: prove the backend is actually noq.
    try std.testing.expectEqual(factory.Engine.noq, client_any.engine());
    try std.testing.expectEqual(factory.Engine.noq, server_any.engine());
    try std.testing.expectEqual(noq_ep.Engine.noq, noq_ep.Endpoint.engine);

    const server_noq = client_any_noq(server_any);
    const client_noq = client_any_noq(client_any);

    // Handshake needs both sides pumping concurrently → accept on a future.
    var accept_future = io.async(acceptOne, .{server_any});
    const client_conn = client_any.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server_any.localAddress() }},
    }) catch |err| {
        _ = accept_future.await(io) catch {};
        return err;
    };
    const server_conn = try accept_future.await(io);

    // RPK identity: each side's verified remote node id is the peer's key.
    try std.testing.expect(client_conn.remoteNodeId().eql(server_key.public()));
    try std.testing.expect(server_conn.remoteNodeId().eql(client_key.public()));

    // Two concurrent bidi streams, echoed. Single-threaded store-and-forward:
    // each vtable op pumps its own endpoint; the kernel UDP buffer carries bytes
    // between a send on one side and the peer's next pumping read.
    const payloads = [_][]const u8{ "alpha-one", "bravo-two-longer" };
    for (payloads) |text| {
        const c = try client_conn.openBi();
        try c.send.writer().writeAll(text);
        try c.send.finish();

        const s = try server_conn.acceptBi();
        var buf: [64]u8 = undefined;
        const n = try s.recv.reader().readSliceShort(&buf);
        try std.testing.expectEqualStrings(text, buf[0..n]);
        try s.send.writer().writeAll(buf[0..n]);
        try s.send.finish();

        var reply: [64]u8 = undefined;
        const m = try c.recv.reader().readSliceShort(&reply);
        try std.testing.expectEqualStrings(text, reply[0..m]);
    }

    // Clean close: the client emits CONNECTION_CLOSE; the server observes it
    // (enters draining) rather than idle-timing-out. close() also reclaims the
    // client's connection slot (persistent-endpoint discipline).
    try std.testing.expectEqual(@as(usize, 1), client_noq.liveConnectionCount());
    client_conn.close();
    try std.testing.expectEqual(@as(usize, 0), client_noq.liveConnectionCount());

    var observed = false;
    var k: usize = 0;
    while (k < 500 and !observed) : (k += 1) {
        try server_noq.pumpForTest();
        observed = server_noq.serverObservedClose();
    }
    try std.testing.expect(observed);

    // Persistent-endpoint reclaim (XH-regression analog): closing the server
    // connection tears the slot down so a reused endpoint holds no dead conn.
    try std.testing.expectEqual(@as(usize, 1), server_noq.liveConnectionCount());
    server_conn.close();
    try std.testing.expectEqual(@as(usize, 0), server_noq.liveConnectionCount());
}

/// Narrow an AnyEndpoint we know is noq back to the concrete endpoint for the
/// pump/observe test hooks the vtable intentionally does not expose.
fn client_any_noq(any: factory.AnyEndpoint) *noq_ep.Endpoint {
    return switch (any) {
        .noq => |e| e,
        .picoquic => unreachable,
    };
}

/// Receive one datagram (or fail after a bounded number of pump rounds).
fn receiveOne(ep: *noq_ep.Endpoint, rounds: usize) !?[]const u8 {
    var batch: noq_ep.RawReceiveScratch = undefined;
    var i: usize = 0;
    while (i < rounds) : (i += 1) {
        var payloads: [1][]const u8 = undefined;
        var codepoints: [1]?@import("udp_cmsg.zig").EcnCodepoint = undefined;
        const n = ep.receiveRawForTest(&payloads, &codepoints, 20 * std.time.ns_per_ms, &batch) catch |err| switch (err) {
            error.Timeout => return null,
            else => return err,
        };
        if (n == 1) return payloads[0];
    }
    return null;
}

/// Receive until a datagram whose trailing 16 bytes equal `tail` arrives
/// (skipping unrelated conn traffic the raw socket also sees), else null.
fn receiveResetForTest(ep: *noq_ep.Endpoint, tail: [packet.stateless_reset_token_len]u8, rounds: usize) !?[]const u8 {
    var batch: noq_ep.RawReceiveScratch = undefined;
    var i: usize = 0;
    while (i < rounds) : (i += 1) {
        var payloads: [4][]const u8 = undefined;
        var codepoints: [4]?@import("udp_cmsg.zig").EcnCodepoint = undefined;
        const n = ep.receiveRawForTest(&payloads, &codepoints, 20 * std.time.ns_per_ms, &batch) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
        for (payloads[0..n]) |p| {
            if (p.len >= packet.stateless_reset_min_len and
                std.mem.eql(u8, p[p.len - packet.stateless_reset_token_len ..], &tail))
            {
                return p;
            }
        }
    }
    return null;
}

test "E3: stateless reset SEND — HMAC-consistent, rate-limited, pad-below-inciting, unknown-CID-only — real sockets" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-e3-gate";

    const client_key = key.SecretKey.fromBytes([_]u8{0x41} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x42} ** 32);
    const server_any = try factory.create(.noq, allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
    });
    defer server_any.deinit();
    const client_any = try factory.create(.noq, allocator, io, client_key, alpn, .{});
    defer client_any.deinit();
    const server_noq = client_any_noq(server_any);
    const client_noq = client_any_noq(client_any);

    // ── leg A: an unknown-CID short header draws exactly one reset ─────────
    const unknown_cid: [8]u8 = .{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33 };
    const expected_token = quic_token.resetToken(&server_noq.reset_key, try packet.ConnectionId.init(&unknown_cid));
    var dgram_a: [200]u8 = undefined;
    @memset(&dgram_a, 0xA5);
    dgram_a[0] = 0x43; // short-header shape, fixed bit set
    @memcpy(dgram_a[1..9], &unknown_cid);
    try client_noq.sendRawForTest(server_noq.localAddress(), &dgram_a, null, null);
    var pumps: usize = 0;
    while (pumps < 20 and server_noq.stats_stateless_reset_sent == 0) : (pumps += 1) {
        try server_noq.pumpForTest();
    }
    try std.testing.expectEqual(@as(u64, 1), server_noq.stats_stateless_reset_sent);
    const reset = (try receiveResetForTest(client_noq, expected_token, 12)) orelse return error.UnexpectedState;
    // RFC 9000 §10.3 shape: fixed bit set, strictly smaller than inciting,
    // trailing 16 bytes = HMAC(reset_key, unknown_cid).
    try std.testing.expect(reset[0] & 0x40 != 0);
    try std.testing.expect(reset.len < dgram_a.len);
    try std.testing.expect(reset.len >= packet.stateless_reset_min_len);
    try std.testing.expectEqualSlices(u8, &expected_token, reset[reset.len - packet.stateless_reset_token_len ..]);

    // Live connection (also the suppression case's known CID owner).
    const est = try establish(client_any, server_any, server_key.public());
    defer est.client_conn.close();
    defer est.server_conn.close();
    const server_drv = server_noq.testDriver(.server) orelse return error.UnexpectedState;

    // ── consistency leg: the server's advertised reset token derives from
    // the endpoint key exactly as noq ResetToken::new (endpoint.rs:631) ──────
    const expected_conn_token = quic_token.resetToken(&server_noq.reset_key, server_drv.local_cid);
    try std.testing.expectEqualSlices(u8, &expected_conn_token, &server_drv.stateless_reset_token);

    // ── leg B: a datagram to the LIVE conn's CID draws NO reset ────────────
    // (dcidKnown suppression — MECHANICALLY distinct from rate-limit: enforce
    // the >20 ms gap so only CID-knowledge can explain the silence).
    io.sleep(std.Io.Duration.fromMilliseconds(25), .awake) catch {};
    var dgram_b: [200]u8 = undefined;
    @memset(&dgram_b, 0x5A);
    dgram_b[0] = 0x47;
    @memcpy(dgram_b[1..9], server_drv.local_cid.slice());
    try client_noq.sendRawForTest(server_noq.localAddress(), &dgram_b, null, null);
    pumps = 0;
    while (pumps < 20) : (pumps += 1) try server_noq.pumpForTest();
    try std.testing.expectEqual(@as(u64, 1), server_noq.stats_stateless_reset_sent);

    // ── leg C: after the 20 ms window, another unknown CID draws a reset ───
    // (proves leg B's silence was CID-knowledge, not the rate limiter).
    const unknown_cid2: [8]u8 = .{ 0xCA, 0xFE, 0xBA, 0xBE, 0x44, 0x55, 0x66, 0x77 };
    const expected_token2 = quic_token.resetToken(&server_noq.reset_key, try packet.ConnectionId.init(&unknown_cid2));
    var dgram_c: [180]u8 = undefined;
    @memset(&dgram_c, 0xC3);
    dgram_c[0] = 0x45;
    @memcpy(dgram_c[1..9], &unknown_cid2);
    // Push past min_reset_interval with real-time pump rounds.
    pumps = 0;
    while (pumps < 64) : (pumps += 1) {
        try server_noq.pumpForTest();
        try client_noq.pumpForTest();
        io.sleep(std.Io.Duration.fromMilliseconds(2), .awake) catch {};
    }
    try client_noq.sendRawForTest(server_noq.localAddress(), &dgram_c, null, null);
    pumps = 0;
    while (pumps < 20 and server_noq.stats_stateless_reset_sent == 1) : (pumps += 1) {
        try server_noq.pumpForTest();
    }
    try std.testing.expectEqual(@as(u64, 2), server_noq.stats_stateless_reset_sent);
    const reset2 = (try receiveResetForTest(client_noq, expected_token2, 12)) orelse return error.UnexpectedState;
    try std.testing.expect(reset2.len < dgram_c.len);

    // ── leg D: an undersized inciting datagram is not amplified ────────────
    var dgram_d: [20]u8 = undefined;
    @memset(&dgram_d, 0x77);
    dgram_d[0] = 0x41;
    @memcpy(dgram_d[1..9], &unknown_cid2);
    pumps = 0;
    while (pumps < 64) : (pumps += 1) {
        try server_noq.pumpForTest();
        io.sleep(std.Io.Duration.fromMilliseconds(2), .awake) catch {};
    }
    try client_noq.sendRawForTest(server_noq.localAddress(), &dgram_d, null, null);
    pumps = 0;
    while (pumps < 20) : (pumps += 1) try server_noq.pumpForTest();
    try std.testing.expectEqual(@as(u64, 2), server_noq.stats_stateless_reset_sent);
}

test "E5/E7/E8/E9: Retry address validation, sealed NEW_TOKEN, one-time reuse — over the REAL socket pump" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-e5-gate";

    const client_key = key.SecretKey.fromBytes([_]u8{0x31} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x32} ** 32);

    // The server REQUIRES Retry-based address validation (E5); every accepted
    // connection is issued a sealed NEW_TOKEN (E7).
    const server_any = try factory.create(.noq, allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
        .retry = true,
    });
    defer server_any.deinit();
    const client_any = try factory.create(.noq, allocator, io, client_key, alpn, .{});
    defer client_any.deinit();
    const server_noq = client_any_noq(server_any);
    const client_noq = client_any_noq(client_any);

    // ── conn 1: tokenless first flight → Retry → validated retry token ──────
    const first = try establish(client_any, server_any, server_key.public());
    // E5: the server issued exactly one Retry and validated the client's
    // second flight's token — the handshake exists ONLY because it did.
    try std.testing.expectEqual(@as(u64, 1), server_noq.stats_retry_issued);
    try std.testing.expectEqual(@as(u64, 1), server_noq.stats_retry_validated);

    // Echo proves the post-Retry connection is fully operational.
    const c1 = try first.client_conn.openBi();
    try c1.send.writer().writeAll("post-retry");
    try c1.send.finish();
    const s1 = try first.server_conn.acceptBi();
    var buf: [64]u8 = undefined;
    const n1 = try s1.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("post-retry", buf[0..n1]);
    try s1.send.writer().writeAll(buf[0..n1]);
    try s1.send.finish();
    var reply1: [64]u8 = undefined;
    const m1 = try c1.recv.reader().readSliceShort(&reply1);
    try std.testing.expectEqualStrings("post-retry", reply1[0..m1]);

    first.client_conn.close();
    first.server_conn.close();

    // E7: the server's sealed NEW_TOKEN reached the client's cache (E8 store).
    var pumps: usize = 0;
    while (pumps < 200 and client_noq.token_cache.count() == 0) : (pumps += 1) {
        try client_noq.pumpForTest();
        try server_noq.pumpForTest();
    }
    try std.testing.expectEqual(@as(u32, 1), client_noq.token_cache.count());
    // Keep a copy of conn 1's token for the anti-replay leg below.
    var replay_token: []u8 = &.{};
    {
        var it = client_noq.token_cache.iterator();
        if (it.next()) |kv| replay_token = try allocator.dupe(u8, kv.value_ptr.*);
    }
    defer allocator.free(replay_token);
    try std.testing.expect(replay_token.len > 0);

    // ── conn 2: the client presents the stored NEW_TOKEN (E8 take) ─────────
    const second = try establish(client_any, server_any, server_key.public());
    // E9: the token validated → early anti-amplification lift, and NO second
    // Retry was needed.
    try std.testing.expectEqual(@as(u64, 1), server_noq.stats_new_token_validated);
    try std.testing.expectEqual(@as(u64, 1), server_noq.stats_retry_issued);
    // One-time use: the take removed the token from the client cache.
    try std.testing.expectEqual(@as(u32, 0), client_noq.token_cache.count());
    second.client_conn.close();
    second.server_conn.close();

    // ── conn 3: REPLAY the SAME (already-consumed) token ───────────────────
    // The server's anti-replay log must reject it and fall back to a Retry —
    // an always-validate server would never retry here.
    var pumps3: usize = 0;
    while (pumps3 < 200 and client_noq.token_cache.count() == 0) : (pumps3 += 1) {
        try client_noq.pumpForTest();
        try server_noq.pumpForTest();
    }
    // Overwrite the fresh conn-2 token with the replayed conn-1 bytes.
    {
        var it = client_noq.token_cache.iterator();
        while (it.next()) |kv| {
            allocator.free(kv.value_ptr.*);
            kv.value_ptr.* = try allocator.dupe(u8, replay_token);
        }
    }
    const third = try establish(client_any, server_any, server_key.public());
    try std.testing.expectEqual(@as(u64, 2), server_noq.stats_retry_issued);
    try std.testing.expectEqual(@as(u64, 2), server_noq.stats_retry_validated);
    // The replayed NEW_TOKEN must NOT have counted as validated again.
    try std.testing.expectEqual(@as(u64, 1), server_noq.stats_new_token_validated);
    third.client_conn.close();
    third.server_conn.close();
}

/// Establish a Zig-noq ↔ Zig-noq connection over the real socket; returns both
/// live connections (caller closes them).
const Established = struct {
    client_conn: tr.Connection,
    server_conn: tr.Connection,
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

// Reject pump + owning-layer asserts live in harness_probes (S2-A3). This test
// is the converted example that consumes the shared library (frozen
// noq_zigtls_gate.zig keeps its in-file helpers — text-frozen surface).

test "5d-B: server learns a verified peer, mints a fresh CID, and rejects a spoofed RPK" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-5d-gate";
    const client_key = key.SecretKey.fromBytes([_]u8{0x71} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x72} ** 32);

    const server_any = try factory.create(.noq, allocator, io, server_key, alpn, .{
        .accept_unknown_peer = true,
    });
    defer server_any.deinit();
    const honest_client = try factory.create(.noq, allocator, io, client_key, alpn, .{});
    defer honest_client.deinit();
    const server_noq = client_any_noq(server_any);

    const accepted = try establish(honest_client, server_any, server_key.public());
    try std.testing.expect(accepted.server_conn.remoteNodeId().eql(client_key.public()));
    try harness_probes.expectServerAuthAccept(server_noq);
    try std.testing.expect(server_noq.serverUsesFreshLocalCid());
    accepted.client_conn.close();
    accepted.server_conn.close();
    try std.testing.expectEqual(@as(usize, 0), server_noq.liveConnectionCount());

    // The malicious client advertises `spoofed_key` as its raw public key but
    // signs CertificateVerify with `signing_key`. A key-extraction-only server
    // would accept it; the learned verifier must reject before `accept` can
    // expose any remoteNodeId.
    const signing_key = key.SecretKey.fromBytes([_]u8{0x73} ** 32);
    const spoofed_key = key.SecretKey.fromBytes([_]u8{0x74} ** 32);
    const spoof_client = try factory.create(.noq, allocator, io, signing_key, alpn, .{
        .certificate_public_key_override = spoofed_key.public(),
    });
    defer spoof_client.deinit();

    var reject_future = io.async(harness_probes.pumpUntilServerRejects, .{ server_noq, .{} });
    const spoof_result = spoof_client.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server_any.localAddress() }},
    });
    defer if (spoof_result) |conn| conn.close() else |_| {};
    try reject_future.await(io);
    try harness_probes.expectServerAuthReject(server_noq);
}

// GAP-reject-flag-broaden-green (control-oracle-mutation-matrix
// `reject-flag-accessor-iff`): pin BOTH directions of the
// `serverHandshakeRejected()` accessor on real connection paths. The frozen
// zigtls-sec oracle asserts only the reject direction, so the LAND review
// "Extra 2" mutation (accessor always-true for a used server conn) passed the
// whole `test-zigtls-noq` suite silently. The test name extends that step's
// existing filter prefix so this gate bites there AND in `zig build test`.
test "zigtls-sec: live connection rejects forged-RPK iff — reject-flag false on honest, true on spoof" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-zigtls-sec-iff";

    const client_key = key.SecretKey.fromBytes([_]u8{0x81} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x82} ** 32);

    const server_any = try factory.create(.noq, allocator, io, server_key, alpn, .{
        .accept_unknown_peer = true,
        .tls_backend = .zigtls,
    });
    defer server_any.deinit();
    const honest_client = try factory.create(.noq, allocator, io, client_key, alpn, .{
        .tls_backend = .zigtls,
    });
    defer honest_client.deinit();
    const server_noq = client_any_noq(server_any);
    try std.testing.expectEqual(crypto.Backend.zigtls, server_noq.tlsBackend());

    // Honest direction: a completed, verified handshake must NOT set the
    // reject flag (this is the direction the always-true mutation breaks).
    const accepted = try establish(honest_client, server_any, server_key.public());
    try std.testing.expect(accepted.server_conn.remoteNodeId().eql(client_key.public()));
    try harness_probes.expectServerAuthAccept(server_noq);
    try std.testing.expect(!server_noq.serverHandshakeRejected());
    accepted.client_conn.close();
    accepted.server_conn.close();
    try std.testing.expectEqual(@as(usize, 0), server_noq.liveConnectionCount());
    // Reclaiming the slot clears the flag: no tri-state, the accessor is a
    // pure OR over used server conns' rejected bits.
    try std.testing.expect(!server_noq.serverHandshakeRejected());

    // Reject direction: the forged-RPK spoof (same fixture as the frozen
    // zigtls-sec oracle) must set the reject flag and publish no verified peer.
    const signing_key = key.SecretKey.fromBytes([_]u8{0x83} ** 32);
    const spoofed_key = key.SecretKey.fromBytes([_]u8{0x84} ** 32);
    const spoof_client = try factory.create(.noq, allocator, io, signing_key, alpn, .{
        .certificate_public_key_override = spoofed_key.public(),
        .tls_backend = .zigtls,
    });
    defer spoof_client.deinit();

    var reject_future = io.async(harness_probes.pumpUntilServerRejects, .{ server_noq, .{} });
    const spoof_result = spoof_client.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server_any.localAddress() }},
    });
    defer if (spoof_result) |conn| conn.close() else |_| {};
    try reject_future.await(io);
    try harness_probes.expectServerAuthReject(server_noq);
}

test "5e-S3: n0 NAT frame -> magicsock; path selected ONLY after real PATH_CHALLENGE validation" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-5e-s3";
    const client_key = key.SecretKey.fromBytes([_]u8{0x31} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x32} ** 32);

    const server_any = try factory.create(.noq, allocator, io, server_key, alpn, .{ .expected_peer = client_key.public() });
    defer server_any.deinit();
    const client_any = try factory.create(.noq, allocator, io, client_key, alpn, .{});
    defer client_any.deinit();

    const conns = try establish(client_any, server_any, server_key.public());
    const client_noq = client_any_noq(client_any);
    const server_noq = client_any_noq(server_any);

    // Client advertises a direct-path candidate (its own address) via an n0
    // reach_out frame. The server must learn it in magicsock — the frame that the
    // pre-5e driver decoded then DROPPED.
    const cip = client_any.localAddress().ip4;
    client_noq.advertiseReachOut(1, cip.bytes, cip.port);
    var k: usize = 0;
    while (k < 200 and server_noq.magicCandidateCount() == 0) : (k += 1) {
        try client_noq.pumpForTest();
        try server_noq.pumpForTest();
    }
    try std.testing.expectEqual(@as(usize, 1), server_noq.magicCandidateCount());

    // SECURITY: an un-probed / unvalidated candidate is NOT selected.
    try std.testing.expect(server_noq.magicSelectedAddr() == null);

    // Probe with a REAL PATH_CHALLENGE (random token). Still not selected until
    // the peer echoes the token back verbatim.
    server_noq.probeCandidates();
    try std.testing.expect(server_noq.magicSelectedAddr() == null);

    // Drive the challenge/response exchange over the socket; only now does the
    // validated path get selected.
    k = 0;
    while (k < 200 and server_noq.magicSelectedAddr() == null) : (k += 1) {
        try server_noq.pumpForTest();
        try client_noq.pumpForTest();
    }
    const selected = server_noq.magicSelectedAddr() orelse return error.PathNeverValidated;
    try std.testing.expectEqual(cip.port, selected.ip4.port);
    try std.testing.expectEqualSlices(u8, &cip.bytes, &selected.ip4.bytes);

    conns.client_conn.close();
    conns.server_conn.close();
}

/// In-memory loopback relay implementing the engine-agnostic relay vtable — the
/// S4 relay-fallback substrate (stands in for a real DERP relay client).
const LoopbackRelay = struct {
    allocator: std.mem.Allocator,
    queue: std.ArrayList(Msg) = .empty,

    const Msg = struct { src: key.NodeId, dst: key.NodeId, data: []u8 };

    fn deinit(self: *LoopbackRelay) void {
        for (self.queue.items) |m| self.allocator.free(m.data);
        self.queue.deinit(self.allocator);
    }

    fn enqueue(self: *LoopbackRelay, src: key.NodeId, dst: key.NodeId, data: []const u8) tr.Error!void {
        const copy = self.allocator.dupe(u8, data) catch return error.OutOfMemory;
        self.queue.append(self.allocator, .{ .src = src, .dst = dst, .data = copy }) catch return error.OutOfMemory;
    }

    fn dequeue(self: *LoopbackRelay, me: key.NodeId, buf: []u8) tr.Error!?noq_ep.RelayDatagram {
        for (self.queue.items, 0..) |m, i| {
            if (m.dst.eql(me)) {
                const n = @min(buf.len, m.data.len);
                @memcpy(buf[0..n], m.data[0..n]);
                const src = m.src;
                self.allocator.free(m.data);
                _ = self.queue.orderedRemove(i);
                return .{ .src = src, .data = buf[0..n] };
            }
        }
        return null;
    }
};

/// One endpoint's view of the relay (knows its own node id).
const RelayEndpoint = struct {
    relay: *LoopbackRelay,
    me: key.NodeId,

    fn client(self: *RelayEndpoint) noq_ep.RelayClient {
        return .{ .context = self, .vtable = &vtable };
    }
    const vtable: noq_ep.RelayClient.VTable = .{ .send = relaySend, .recv = relayRecv };
    fn relaySend(ctx: *anyopaque, dst: key.NodeId, data: []const u8) tr.Error!void {
        const self: *RelayEndpoint = @ptrCast(@alignCast(ctx));
        return self.relay.enqueue(self.me, dst, data);
    }
    fn relayRecv(ctx: *anyopaque, buf: []u8) tr.Error!?noq_ep.RelayDatagram {
        const self: *RelayEndpoint = @ptrCast(@alignCast(ctx));
        return self.relay.dequeue(self.me, buf);
    }
};

test "passive migration — probe to the new address (1200-padded), verbatim echo switches the path — real sockets" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-h5-gate";

    const client_key = key.SecretKey.fromBytes([_]u8{0x51} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x52} ** 32);
    const spy_key = key.SecretKey.fromBytes([_]u8{0x53} ** 32);

    const server_any = try factory.create(.noq, allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
    });
    defer server_any.deinit();
    const client_any = try factory.create(.noq, allocator, io, client_key, alpn, .{});
    defer client_any.deinit();
    // The "spy" endpoint stands at the address the peer migrates TO.
    const spy_any = try factory.create(.noq, allocator, io, spy_key, alpn, .{});
    defer spy_any.deinit();
    const server_noq = client_any_noq(server_any);
    const client_noq = client_any_noq(client_any);
    const spy_noq = client_any_noq(spy_any);

    const est = try establish(client_any, server_any, server_key.public());
    defer est.client_conn.close();
    defer est.server_conn.close();

    // The peer's packet "arrives" from the spy's address (driving the same
    // production fn the pump calls on a real 4-tuple change).
    try std.testing.expect(server_noq.triggerMigrationForTest(.server, spy_noq.localAddress()));

    // The probe goes to the CANDIDATE (spy), padded to 1200.
    var probe_bytes: ?[]const u8 = null;
    var batch: noq_ep.RawReceiveScratch = undefined;
    var rounds: usize = 0;
    while (rounds < 40 and probe_bytes == null) : (rounds += 1) {
        try server_noq.pumpForTest();
        var payloads: [4][]const u8 = undefined;
        var codepoints: [4]?@import("udp_cmsg.zig").EcnCodepoint = undefined;
        const n = spy_noq.receiveRawForTest(&payloads, &codepoints, 10 * std.time.ns_per_ms, &batch) catch 0;
        for (payloads[0..n]) |p| {
            if (p.len >= 1200) probe_bytes = p;
        }
    }
    const probe = probe_bytes orelse return error.UnexpectedState;
    try std.testing.expect(server_noq.migrationProbePendingForTest(.server));
    // The path has NOT switched pre-validation (anti-spoofing).
    try std.testing.expect(!server_noq.isMigratedToForTest(.server, spy_noq.localAddress()));

    // Production round trip: the probe reaches the peer (via the spy), the
    // peer's engine answers PATH_CHALLENGE with a verbatim PATH_RESPONSE, and
    // the server validates the token and switches the path.
    const probe_copy = try allocator.dupe(u8, probe);
    defer allocator.free(probe_copy);
    try spy_noq.sendRawForTest(client_noq.localAddress(), probe_copy, null, null);
    rounds = 0;
    while (rounds < 60 and !server_noq.isMigratedToForTest(.server, spy_noq.localAddress())) : (rounds += 1) {
        try client_noq.pumpForTest();
        try server_noq.pumpForTest();
    }
    try std.testing.expect(server_noq.isMigratedToForTest(.server, spy_noq.localAddress()));

    // Post-switch, the server's outbound data flows to the new address.
    const c = try est.client_conn.openBi();
    try c.send.writer().writeAll("post-migration");
    try c.send.finish();
    const s = try est.server_conn.acceptBi();
    var buf: [64]u8 = undefined;
    const n = try s.recv.reader().readSliceShort(&buf);
    try s.send.writer().writeAll(buf[0..n]);
    try s.send.finish();
    var got_at_spy = false;
    rounds = 0;
    while (rounds < 40 and !got_at_spy) : (rounds += 1) {
        try server_noq.pumpForTest();
        try client_noq.pumpForTest();
        var payloads: [4][]const u8 = undefined;
        var codepoints: [4]?@import("udp_cmsg.zig").EcnCodepoint = undefined;
        const m = spy_noq.receiveRawForTest(&payloads, &codepoints, 10 * std.time.ns_per_ms, &batch) catch 0;
        if (m > 0) got_at_spy = true;
    }
    try std.testing.expect(got_at_spy);
}

test "5e-S4: relay fallback routes datagrams through the relay client (not the socket)" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-5e-s4";
    const client_key = key.SecretKey.fromBytes([_]u8{0x41} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x42} ** 32);

    const server_any = try factory.create(.noq, allocator, io, server_key, alpn, .{ .expected_peer = client_key.public() });
    defer server_any.deinit();
    const client_any = try factory.create(.noq, allocator, io, client_key, alpn, .{});
    defer client_any.deinit();

    const conns = try establish(client_any, server_any, server_key.public());
    const client_noq = client_any_noq(client_any);
    const server_noq = client_any_noq(server_any);

    // Wire a shared in-memory relay to both endpoints.
    var relay: LoopbackRelay = .{ .allocator = allocator };
    defer relay.deinit();
    var client_relay: RelayEndpoint = .{ .relay = &relay, .me = client_key.public() };
    var server_relay: RelayEndpoint = .{ .relay = &relay, .me = server_key.public() };
    client_noq.setRelay(client_relay.client());
    server_noq.setRelay(server_relay.client());

    // Select the relay path on both sides — subsequent datagrams route through
    // the relay client, NOT the UDP socket.
    client_noq.selectRelay(7);
    server_noq.selectRelay(7);

    // A stream echo now proves the relay actually carried the QUIC datagrams
    // (a no-op relay would stall the transfer).
    const c = try conns.client_conn.openBi();
    try c.send.writer().writeAll("via-relay");
    try c.send.finish();

    const s = try conns.server_conn.acceptBi();
    var buf: [32]u8 = undefined;
    const n = try s.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("via-relay", buf[0..n]);
    try s.send.writer().writeAll(buf[0..n]);
    try s.send.finish();

    var reply: [32]u8 = undefined;
    const m = try c.recv.reader().readSliceShort(&reply);
    try std.testing.expectEqualStrings("via-relay", reply[0..m]);

    conns.client_conn.close();
    conns.server_conn.close();
}
