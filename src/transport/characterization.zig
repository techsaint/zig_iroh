//! Characterization suite — picoquic-backend completion's
//! differential oracle (transport-relay-concurrency).
//!
//! Every test pins one OBSERVABLE behavior of the frozen `transport.zig` vtable
//! contract, instantiated against BOTH picoquic backends:
//!
//! - `legacy`     = `quic.zig` — the actually-shipping default. The oracle:
//!                  these tests pin its current-correct behavior.
//! - `greenfield` = `endpoint.zig` — the greenfield edit target. It must MATCH the
//!                  legacy behavior test-for-test.
//!
//! Only wire/peer-visible and vtable-contract behavior is pinned here (GOOD-vs-
//! DRIFT pre-classification): bytes, ordering, FIN/RESET
//! delivery, handshake identity, error classes, handle lifecycle. Incidental
//! INTERNAL shapes (FIN-gated vs incremental reader handoff timing, buffer
//! layout, sweep cadence) are deliberately NOT pinned — the streams/memory
//! work is free to change those, and the change is documented in the notes.
//!
//! OWED-PARITY LIST (greenfield pins registered as milestones land; legacy
//! pins are live NOW and document the contract). Until a milestone closes the
//! gap, the greenfield variant would be red (or would crash the test process —
//! several of these are use-after-free today, not clean errors):
//!
//!   P1 `many sequential bi streams on one connection`  (>16; S8 growable tables)
//!      — FLIPPED GREEN at M1 (the actor model's tables are growable)
//!   P2 `many concurrent uni streams`                   (>16; S8 growable tables)
//!      — FLIPPED GREEN at M1
//!   P3 `unaccepted-then-closed cnxs are reclaimed`     (greenfield reclaim case)
//!      — pending the cnx sweep (streams/memory milestone)
//!   P4 `close is idempotent for copied handles`        — FLIPPED GREEN at M1 (tombstones)
//!   P5 `stream ops after close return NotConnected`    — FLIPPED GREEN at M1
//!   P6 `writer after finish discards`                  — FLIPPED GREEN at M1 (dead writer)
//!
//! Focused build steps (build.zig): `test-transport-char-legacy`,
//! `test-transport-char-greenfield`, `test-transport-char` (both).

const std = @import("std");
const tr = @import("../transport.zig");
const key = @import("../key.zig");
const legacy = @import("quic.zig");
const greenfield = @import("endpoint.zig");

const net = std.Io.net;
const io = std.testing.io;
const allocator = std.testing.allocator;

pub const Backend = enum { legacy, greenfield };

const short_timeout_us: u64 = 500 * std.time.us_per_ms;

fn createEndpoint(comptime backend: Backend, secret: key.SecretKey, alpn: [:0]const u8, handshake_timeout_us: ?u64) !switch (backend) {
    .legacy => *legacy.Endpoint,
    .greenfield => *greenfield.Endpoint,
} {
    const timeout = handshake_timeout_us orelse 15 * std.time.us_per_s;
    return switch (backend) {
        .legacy => legacy.Endpoint.initOptions(allocator, io, secret, alpn, .{ .handshake_timeout_us = timeout }),
        .greenfield => greenfield.Endpoint.initOptions(allocator, io, secret, alpn, .{ .handshake_timeout_us = timeout }),
    };
}

fn acceptConn(t: tr.Transport) tr.Error!tr.Connection {
    return t.accept();
}

fn acceptBiOn(conn: tr.Connection) tr.Error!tr.BiStream {
    return conn.acceptBi();
}

fn acceptUniOn(conn: tr.Connection) tr.Error!tr.RecvStream {
    return conn.acceptUni();
}

fn readAll(reader: *std.Io.Reader, out: *std.ArrayList(u8)) !void {
    var chunk: [16384]u8 = undefined;
    while (true) {
        const n = try reader.readSliceShort(&chunk);
        if (n == 0) return;
        try out.appendSlice(allocator, chunk[0..n]);
    }
}

/// Both endpoints pump while the client dials; returns the established pair.
fn connectPair(client_ep: anytype, server_ep: anytype, server_key: key.SecretKey) !struct { client: tr.Connection, server: tr.Connection } {
    var accept_future = io.async(acceptConn, .{server_ep.transport()});
    errdefer _ = accept_future.cancel(io) catch {};
    const client_conn = try client_ep.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server_ep.localAddress() }},
    });
    errdefer client_conn.close();
    const server_conn = try accept_future.await(io);
    return .{ .client = client_conn, .server = server_conn };
}

// =============================================================================
// Behavior pins (generic over Backend)
// =============================================================================

/// Handshake: both sides learn the peer's verified RPK identity.
fn handshakeIdentities(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0x11} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x12} ** 32);
    const alpn: [:0]const u8 = "iroh-char-handshake";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.client.close();
    defer pair.server.close();

    try std.testing.expect(pair.client.remoteNodeId().eql(server_key.public()));
    try std.testing.expect(pair.server.remoteNodeId().eql(client_key.public()));
}

/// Cross-identity dial (client pins the wrong NodeId) never completes: the
/// handshake is rejected and connect surfaces error.Timeout.
fn crossIdentityRejected(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0x21} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x22} ** 32);
    const wrong_key = key.SecretKey.fromBytes([_]u8{0x23} ** 32);
    const alpn: [:0]const u8 = "iroh-char-cross-id";
    const client_ep = try createEndpoint(backend, client_key, alpn, short_timeout_us);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, short_timeout_us);
    defer server_ep.deinit();

    var accept_future = io.async(acceptConn, .{server_ep.transport()});
    defer _ = accept_future.cancel(io) catch {};

    const result = client_ep.transport().connect(.{
        .id = wrong_key.public(),
        .addrs = &.{.{ .ip = server_ep.localAddress() }},
    });
    try std.testing.expectError(error.Timeout, result);
}

/// Dialing an address where nothing listens surfaces error.Timeout.
fn connectTimeout(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0x31} ** 32);
    const dead_key = key.SecretKey.fromBytes([_]u8{0x32} ** 32);
    const alpn: [:0]const u8 = "iroh-char-timeout";
    const client_ep = try createEndpoint(backend, client_key, alpn, short_timeout_us);
    defer client_ep.deinit();
    // Bind (and immediately drop) a socket to obtain a live-but-unanswered port.
    const probe_ep = try createEndpoint(backend, dead_key, alpn, short_timeout_us);
    const dead_addr = probe_ep.localAddress();
    probe_ep.deinit();

    const result = client_ep.transport().connect(.{
        .id = dead_key.public(),
        .addrs = &.{.{ .ip = dead_addr }},
    });
    try std.testing.expectError(error.Timeout, result);
}

/// Bidirectional echo: openBi, write+finish, acceptBi reads, reply, EOF both ways.
fn biEcho(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0x41} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x42} ** 32);
    const alpn: [:0]const u8 = "iroh-char-bi-echo";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.client.close();
    defer pair.server.close();

    var accept_future = io.async(acceptBiOn, .{pair.server});
    const client_stream = try pair.client.openBi();
    try client_stream.send.writer().writeAll("ping");
    try client_stream.send.finish();
    const server_stream = try accept_future.await(io);

    var received: std.ArrayList(u8) = .empty;
    defer received.deinit(allocator);
    try readAll(server_stream.recv.reader(), &received);
    try std.testing.expectEqualStrings("ping", received.items);

    try server_stream.send.writer().writeAll("pong");
    try server_stream.send.finish();
    var reply: std.ArrayList(u8) = .empty;
    defer reply.deinit(allocator);
    try readAll(client_stream.recv.reader(), &reply);
    try std.testing.expectEqualStrings("pong", reply.items);
}

/// flush() makes buffered bytes visible to the peer WITHOUT FIN: the accept
/// side hands the stream off on data, and the peer can answer before the
/// sender finishes.
fn flushVisibility(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0x51} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x52} ** 32);
    const alpn: [:0]const u8 = "iroh-char-flush";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.client.close();
    defer pair.server.close();

    var accept_future = io.async(acceptBiOn, .{pair.server});
    const client_stream = try pair.client.openBi();
    try client_stream.send.writer().writeAll("part-1;");
    try client_stream.send.flush();

    // Server sees the stream on data (not FIN) and answers first.
    const server_stream = try accept_future.await(io);
    try server_stream.send.writer().writeAll("ack");
    try server_stream.send.finish();

    var reply: std.ArrayList(u8) = .empty;
    defer reply.deinit(allocator);
    try readAll(client_stream.recv.reader(), &reply);
    try std.testing.expectEqualStrings("ack", reply.items);

    // The client can keep writing after a flush; FIN delivers the rest.
    try client_stream.send.writer().writeAll("part-2");
    try client_stream.send.finish();
    var received: std.ArrayList(u8) = .empty;
    defer received.deinit(allocator);
    try readAll(server_stream.recv.reader(), &received);
    try std.testing.expectEqualStrings("part-1;part-2", received.items);
}

/// Unidirectional stream: openUni write+finish, acceptUni reads all, then EOF.
fn uniStream(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0x61} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x62} ** 32);
    const alpn: [:0]const u8 = "iroh-char-uni";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.client.close();
    defer pair.server.close();

    var accept_future = io.async(acceptUniOn, .{pair.server});
    const send = try pair.client.openUni();
    try send.writer().writeAll("one-way");
    try send.finish();
    const recv = try accept_future.await(io);

    var received: std.ArrayList(u8) = .empty;
    defer received.deinit(allocator);
    try readAll(recv.reader(), &received);
    try std.testing.expectEqualStrings("one-way", received.items);
}

/// An empty stream (FIN with zero bytes) is delivered and reads as immediate EOF.
fn uniEmptyFin(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0x71} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x72} ** 32);
    const alpn: [:0]const u8 = "iroh-char-uni-empty";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.client.close();
    defer pair.server.close();

    var accept_future = io.async(acceptUniOn, .{pair.server});
    const send = try pair.client.openUni();
    try send.finish();
    const recv = try accept_future.await(io);

    var buf: [8]u8 = undefined;
    const n = try recv.reader().readSliceShort(&buf);
    try std.testing.expectEqual(@as(usize, 0), n);
}

/// A multi-megabyte transfer in flushed chunks arrives byte-exact.
fn largeTransfer(comptime backend: Backend) !void {
    try chunkedTransfer(backend, 4 * 1024 * 1024);
}

/// Backpressure: a transfer larger than the per-stream initial flow-control
/// credit (16 MiB) must not stall — the receive window slides as the reader
/// consumes (greenfield #6), legacy's 128 MiB credit trivially passes.
fn overWindowTransfer(comptime backend: Backend) !void {
    try chunkedTransfer(backend, 24 * 1024 * 1024);
}

fn chunkedTransfer(comptime backend: Backend, total: usize) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0x81} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x82} ** 32);
    const alpn: [:0]const u8 = "iroh-char-large";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.client.close();
    defer pair.server.close();

    const chunk = 64 * 1024;

    var accept_future = io.async(acceptUniOn, .{pair.server});
    const send = try pair.client.openUni();
    var i: usize = 0;
    var buf: [chunk]u8 = undefined;
    while (i < total) : (i += chunk) {
        for (&buf, 0..) |*byte, j| byte.* = @truncate((i + j) *% 2654435761 >> 13);
        try send.writer().writeAll(&buf);
        try send.flush();
    }
    try send.finish();

    const recv = try accept_future.await(io);
    var received: std.ArrayList(u8) = .empty;
    defer received.deinit(allocator);
    try readAll(recv.reader(), &received);
    try std.testing.expectEqual(total, received.items.len);
    i = 0;
    while (i < total) : (i += chunk) {
        for (&buf, 0..) |*byte, j| byte.* = @truncate((i + j) *% 2654435761 >> 13);
        try std.testing.expectEqualSlices(u8, &buf, received.items[i..][0..chunk]);
    }
}

/// A persistent endpoint pair survives many sequential connect/accept/close cycles.
fn sequentialCnxReuse(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0x91} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x92} ** 32);
    const alpn: [:0]const u8 = "iroh-char-cnx-reuse";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    for (0..12) |_| {
        const pair = try connectPair(client_ep, server_ep, server_key);
        try std.testing.expect(pair.client.remoteNodeId().eql(server_key.public()));
        try std.testing.expect(pair.server.remoteNodeId().eql(client_key.public()));
        pair.client.close();
        pair.server.close();
    }
}

/// A stream reset by the sender before any data surfaces as error.StreamReset
/// on the accept side.
fn resetBeforeData(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0xA1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xA2} ** 32);
    const alpn: [:0]const u8 = "iroh-char-reset";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.client.close();
    defer pair.server.close();

    var accept_future = io.async(acceptUniOn, .{pair.server});
    const send = try pair.client.openUni();
    send.reset();
    try std.testing.expectError(error.StreamReset, accept_future.await(io));
}

/// recv.stop() succeeds and the stopped reader yields immediate EOF.
fn stopSending(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0xB1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xB2} ** 32);
    const alpn: [:0]const u8 = "iroh-char-stop";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.client.close();
    defer pair.server.close();

    var accept_future = io.async(acceptBiOn, .{pair.server});
    const client_stream = try pair.client.openBi();
    try client_stream.send.writer().writeAll("discard-me");
    try client_stream.send.flush();
    const server_stream = try accept_future.await(io);

    try server_stream.recv.stop();
    var buf: [8]u8 = undefined;
    const n = try server_stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqual(@as(usize, 0), n);
}

// =============================================================================
// Owed-parity pins — legacy variants registered NOW (they document the
// contract); greenfield variants register as the greenfield milestones close each gap.
// =============================================================================

/// P1/P2: more than sixteen live streams on one connection (S8 growable tables).
fn manySequentialBiStreams(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0xC1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xC2} ** 32);
    const alpn: [:0]const u8 = "iroh-char-many-bi";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.client.close();
    defer pair.server.close();

    for (0..20) |i| {
        var accept_future = io.async(acceptBiOn, .{pair.server});
        const client_stream = try pair.client.openBi();
        var payload: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&payload, "ping-{d}", .{i});
        try client_stream.send.writer().writeAll(text);
        try client_stream.send.finish();
        const server_stream = try accept_future.await(io);

        var received: std.ArrayList(u8) = .empty;
        defer received.deinit(allocator);
        try readAll(server_stream.recv.reader(), &received);
        try std.testing.expectEqualStrings(text, received.items);
        try server_stream.send.writer().writeAll("pong");
        try server_stream.send.finish();
        var reply: std.ArrayList(u8) = .empty;
        defer reply.deinit(allocator);
        try readAll(client_stream.recv.reader(), &reply);
        try std.testing.expectEqualStrings("pong", reply.items);
    }
}

/// P2: many concurrent uni streams opened before any accept. Endpoint access
/// stays single-driver (ownership precondition): the client opens+finishes all
/// streams up front, then the server accepts them one at a time.
fn manyConcurrentUniStreams(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0xD1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xD2} ** 32);
    const alpn: [:0]const u8 = "iroh-char-many-uni";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.client.close();
    defer pair.server.close();

    const count = 24;
    for (0..count) |i| {
        const send = try pair.client.openUni();
        var payload: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&payload, "uni-{d}", .{i});
        try send.writer().writeAll(text);
        try send.finish();
    }
    for (0..count) |i| {
        const recv = try pair.server.acceptUni();
        var received: std.ArrayList(u8) = .empty;
        defer received.deinit(allocator);
        try readAll(recv.reader(), &received);
        var payload: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&payload, "uni-{d}", .{i});
        try std.testing.expectEqualStrings(text, received.items);
    }
}

/// P3: server cnxs that close before accept are reclaimed, so a persistent
/// endpoint keeps accepting (the greenfield G0/G1 scaffold had
/// no sweep and a cap of 8; the M1 actor's death-sweep + resolveDeadCnxs
/// reclaims them, and the cap is 128).
fn unacceptedClosedCnxReclaim(comptime backend: Backend) !void {
    const Ep = switch (backend) {
        .legacy => legacy.Endpoint,
        .greenfield => greenfield.Endpoint,
    };
    const pump = struct {
        fn run(ep: *Ep, flag: *std.atomic.Value(bool)) void {
            // Legacy pumps by caller convention; the greenfield actor's loop
            // self-pumps, so there is nothing to drive here.
            if (backend == .legacy) {
                while (!flag.load(.acquire)) ep.pollOnce() catch {};
            } else {
                while (!flag.load(.acquire)) std.Io.sleep(io, .fromMilliseconds(1), .awake) catch {};
            }
        }
    };
    const client_key = key.SecretKey.fromBytes([_]u8{0xE1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xE2} ** 32);
    const alpn: [:0]const u8 = "iroh-char-cnx-sweep";
    const client_ep = try createEndpoint(backend, client_key, alpn, 2 * std.time.us_per_s);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, 2 * std.time.us_per_s);
    defer server_ep.deinit();

    var stop = std.atomic.Value(bool).init(false);
    var pump_future = io.async(pump.run, .{ server_ep, &stop });
    defer {
        stop.store(true, .release);
        _ = pump_future.cancel(io);
    }

    // Connect and immediately close without the server ever accepting: 10
    // zombie cycles.
    for (0..10) |_| {
        const conn = try client_ep.transport().connect(.{
            .id = server_key.public(),
            .addrs = &.{.{ .ip = server_ep.localAddress() }},
        });
        conn.close();
    }

    // A final full connect+accept must still succeed.
    stop.store(true, .release);
    pump_future.await(io);
    const pair = try connectPair(client_ep, server_ep, server_key);
    pair.client.close();
    pair.server.close();
}

/// P4: closing a copied Connection handle twice does not crash or double-free.
fn closeIdempotentCopiedHandle(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0xF1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xF2} ** 32);
    const alpn: [:0]const u8 = "iroh-char-close-idem";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.server.close();
    const copied = pair.client;
    pair.client.close();
    copied.close();
}

/// P5: stream operations on a closed connection fail with error.NotConnected.
fn openAfterClose(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0x03} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x04} ** 32);
    const alpn: [:0]const u8 = "iroh-char-open-closed";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.server.close();
    pair.client.close();
    try std.testing.expectError(error.NotConnected, pair.client.openBi());
    try std.testing.expectError(error.NotConnected, pair.client.openUni());
}

/// P6: writing after finish fails closed (WriteFailed via the dead writer) and
/// a second finish is a harmless no-op — not a crash.
fn writerAfterFinish(comptime backend: Backend) !void {
    const client_key = key.SecretKey.fromBytes([_]u8{0x05} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x06} ** 32);
    const alpn: [:0]const u8 = "iroh-char-dead-writer";
    const client_ep = try createEndpoint(backend, client_key, alpn, null);
    defer client_ep.deinit();
    const server_ep = try createEndpoint(backend, server_key, alpn, null);
    defer server_ep.deinit();

    const pair = try connectPair(client_ep, server_ep, server_key);
    defer pair.client.close();
    defer pair.server.close();

    const send = try pair.client.openUni();
    try send.writer().writeAll("real");
    try send.finish();
    // Post-finish writes fail closed; a second finish is a no-op.
    try std.testing.expectError(error.WriteFailed, send.writer().writeAll("ghost"));
    try send.finish();
}

// =============================================================================
// Registrations — `zig build test-transport-char-legacy|greenfield|char`.
// =============================================================================

test "CHAR legacy: handshake identities" {
    try handshakeIdentities(.legacy);
}
test "CHAR greenfield: handshake identities" {
    try handshakeIdentities(.greenfield);
}
test "CHAR legacy: cross-identity dial rejected" {
    try crossIdentityRejected(.legacy);
}
test "CHAR greenfield: cross-identity dial rejected" {
    try crossIdentityRejected(.greenfield);
}
test "CHAR legacy: connect timeout to dead address" {
    try connectTimeout(.legacy);
}
test "CHAR greenfield: connect timeout to dead address" {
    try connectTimeout(.greenfield);
}
test "CHAR legacy: bi echo" {
    try biEcho(.legacy);
}
test "CHAR greenfield: bi echo" {
    try biEcho(.greenfield);
}
test "CHAR legacy: flush visibility mid-stream" {
    try flushVisibility(.legacy);
}
test "CHAR greenfield: flush visibility mid-stream" {
    try flushVisibility(.greenfield);
}
test "CHAR legacy: uni stream" {
    try uniStream(.legacy);
}
test "CHAR greenfield: uni stream" {
    try uniStream(.greenfield);
}
test "CHAR legacy: uni empty FIN" {
    try uniEmptyFin(.legacy);
}
test "CHAR greenfield: uni empty FIN" {
    try uniEmptyFin(.greenfield);
}
test "CHAR legacy: large transfer" {
    try largeTransfer(.legacy);
}
test "CHAR greenfield: large transfer" {
    try largeTransfer(.greenfield);
}
test "CHAR legacy: over-window transfer backpressure" {
    try overWindowTransfer(.legacy);
}
test "CHAR greenfield: over-window transfer backpressure" {
    try overWindowTransfer(.greenfield);
}
test "CHAR legacy: sequential cnx reuse" {
    try sequentialCnxReuse(.legacy);
}
test "CHAR greenfield: sequential cnx reuse" {
    try sequentialCnxReuse(.greenfield);
}
test "CHAR legacy: reset before data" {
    try resetBeforeData(.legacy);
}
test "CHAR greenfield: reset before data" {
    try resetBeforeData(.greenfield);
}
test "CHAR legacy: stop sending" {
    try stopSending(.legacy);
}
test "CHAR greenfield: stop sending" {
    try stopSending(.greenfield);
}

// Owed-parity registrations (see the header list):
//   P1/P2 flip green with the actor model's growable tables (M1);
//   P4/P5/P6 flip green with the actor model's handle tombstones (M1);
//   P3 stays legacy-only until the cnx sweep lands (streams/memory milestone).
test "CHAR legacy: many sequential bi streams on one connection" {
    try manySequentialBiStreams(.legacy);
}
test "CHAR greenfield: many sequential bi streams on one connection" {
    try manySequentialBiStreams(.greenfield);
}
test "CHAR legacy: many concurrent uni streams" {
    try manyConcurrentUniStreams(.legacy);
}
test "CHAR greenfield: many concurrent uni streams" {
    try manyConcurrentUniStreams(.greenfield);
}
test "CHAR legacy: unaccepted-then-closed cnxs reclaimed" {
    try unacceptedClosedCnxReclaim(.legacy);
}
test "CHAR greenfield: unaccepted-then-closed cnxs reclaimed" {
    try unacceptedClosedCnxReclaim(.greenfield);
}
test "CHAR legacy: close idempotent for copied handles" {
    try closeIdempotentCopiedHandle(.legacy);
}
test "CHAR greenfield: close idempotent for copied handles" {
    try closeIdempotentCopiedHandle(.greenfield);
}
test "CHAR legacy: stream ops after close return NotConnected" {
    try openAfterClose(.legacy);
}
test "CHAR greenfield: stream ops after close return NotConnected" {
    try openAfterClose(.greenfield);
}
test "CHAR legacy: writer after finish discards" {
    try writerAfterFinish(.legacy);
}
test "CHAR greenfield: writer after finish discards" {
    try writerAfterFinish(.greenfield);
}
