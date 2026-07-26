//! N3b-5 slice 5c acceptance gate — Zig-noq ↔ Zig-noq over the REAL UDP socket
//! pump, behind the frozen `transport.zig` vtable, engine selected via the
//! factory. HARNESS-FAKE RESISTANCE: this goes through `net.Socket` + the real
//! noq driver (NOT an in-memory `connection.zig` pair, NOT a mock), and asserts
//! the selected engine is actually `.noq` — otherwise it proves nothing about
//! `transport_noq.zig`.

const std = @import("std");
const tr = @import("../transport.zig");
const key = @import("../key.zig");
const crypto = @import("../quic/crypto.zig");
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
