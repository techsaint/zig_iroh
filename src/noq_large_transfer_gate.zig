//! N-0 noq large-transfer hardening gate (F2 discriminating variants).
//!
//! Enters through the public transport boundary:
//! factory -> `transport.zig` vtable -> `transport_noq.zig` -> real UDP socket
//! pump -> sans-io noq driver. NOT the raw `connection.zig` pair.
//!
//! Variants (plan F2 / CONSOLIDATED — lossless-only is REJECT):
//! - LOSSLESS 64/256 MiB — FC sliding + streaming recvReader
//! - LOSSY — scripted drops, asserts peak_sent > 64 + loss recovery
//! - BDP-THROTTLED — cwnd cap forces `stats_cc_limited > 0` at buildSpacePacket
//! - NEVER-DRAIN — hold read until end; recv buffer stays ≤ advertised window

const std = @import("std");
const tr = @import("transport.zig");
const key = @import("key.zig");
const factory = @import("transport/factory.zig");
const noq_ep = @import("transport/transport_noq.zig");
const quic_conn = @import("quic/connection.zig");

const KiB: usize = 1024;
const MiB: usize = KiB * KiB;
const chunk_len: usize = 32 * KiB;

/// M5 (audit-v4 testinfra): the gate bounds PROGRESS, not only per-op stalls. The
/// transport's stream timeout (180s below) bounds a fully-wedged read/write op;
/// this hard ceiling bounds the whole transfer so a trickle-forever transfer fails
/// too — nothing adapts indefinitely to a deadlock. 900s ≈ 12x the healthy loaded
/// 256 MiB loopback time (~75s), so healthy-but-slow runs keep passing.
const hard_ceiling_ns: i64 = 900 * std.time.ns_per_s;

fn acceptOne(server: factory.AnyEndpoint) tr.Error!tr.Connection {
    return server.transport().accept();
}

fn acceptBi(conn: tr.Connection) tr.Error!tr.BiStream {
    return conn.acceptBi();
}

fn clientAnyNoq(any: factory.AnyEndpoint) *noq_ep.Endpoint {
    return switch (any) {
        .noq => |e| e,
        .picoquic => unreachable,
    };
}

fn fillPattern(buf: []u8, absolute_offset: usize, seed: u8) void {
    for (buf, 0..) |*b, i| {
        const x: u8 = @truncate((absolute_offset + i) *% 31);
        b.* = x +% seed;
    }
}

fn expectPattern(buf: []const u8, absolute_offset: usize, seed: u8) !void {
    for (buf, 0..) |b, i| {
        const x: u8 = @truncate((absolute_offset + i) *% 31);
        try std.testing.expectEqual(x +% seed, b);
    }
}

fn sendPattern(send: tr.SendStream, total: usize, seed: u8) !void {
    const io = std.testing.io;
    const started_ns = std.Io.Clock.now(.awake, io).nanoseconds;
    var scratch: [chunk_len]u8 = undefined;
    var offset: usize = 0;
    while (offset < total) {
        const now_ns = std.Io.Clock.now(.awake, io).nanoseconds;
        if (now_ns - started_ns > hard_ceiling_ns) return error.LargeTransferCeilingExceeded;
        const n = @min(scratch.len, total - offset);
        fillPattern(scratch[0..n], offset, seed);
        try send.writer().writeAll(scratch[0..n]);
        offset += n;
    }
    try send.finish();
}

fn recvPattern(recv: tr.RecvStream, total: usize, seed: u8) !void {
    const io = std.testing.io;
    const started_ns = std.Io.Clock.now(.awake, io).nanoseconds;
    var scratch: [chunk_len]u8 = undefined;
    var offset: usize = 0;
    const reader = recv.reader();
    while (offset < total) {
        const now_ns = std.Io.Clock.now(.awake, io).nanoseconds;
        if (now_ns - started_ns > hard_ceiling_ns) return error.LargeTransferCeilingExceeded;
        const n = try reader.readSliceShort(scratch[0..@min(scratch.len, total - offset)]);
        try std.testing.expect(n > 0);
        try expectPattern(scratch[0..n], offset, seed);
        offset += n;
    }
    try std.testing.expectEqual(@as(usize, 0), try reader.readSliceShort(scratch[0..1]));
}

const Pair = struct {
    client_any: factory.AnyEndpoint,
    server_any: factory.AnyEndpoint,
    client_conn: tr.Connection,
    server_conn: tr.Connection,

    fn deinit(self: *Pair) void {
        self.client_conn.close();
        self.server_conn.close();
        self.client_any.deinit();
        self.server_any.deinit();
    }

    fn clientEp(self: *Pair) *noq_ep.Endpoint {
        return clientAnyNoq(self.client_any);
    }

    fn serverEp(self: *Pair) *noq_ep.Endpoint {
        return clientAnyNoq(self.server_any);
    }
};

fn establish(alpn: [:0]const u8) !Pair {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const client_key = key.SecretKey.fromBytes([_]u8{0x91} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x92} ** 32);

    const server_any = try factory.createForProduct(allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
    });
    errdefer server_any.deinit();
    const client_any = try factory.createForProduct(allocator, io, client_key, alpn, .{});
    errdefer client_any.deinit();

    try std.testing.expectEqual(factory.productEngine(), client_any.engine());
    try std.testing.expectEqual(factory.productEngine(), server_any.engine());
    try std.testing.expectEqual(factory.productTlsBackend(), client_any.tlsBackend());
    try std.testing.expectEqual(factory.productTlsBackend(), server_any.tlsBackend());

    var accept_future = io.async(acceptOne, .{server_any});
    const client_conn = client_any.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server_any.localAddress() }},
    }) catch |err| {
        _ = accept_future.await(io) catch {};
        return err;
    };
    const server_conn = try accept_future.await(io);
    return .{
        .client_any = client_any,
        .server_any = server_any,
        .client_conn = client_conn,
        .server_conn = server_conn,
    };
}

fn runLosslessTransfer(total: usize, seed: u8, alpn: [:0]const u8) !void {
    const io = std.testing.io;
    var pair = try establish(alpn);
    defer pair.deinit();

    // This gate proves COMPLETION + byte-equality without deadlock — it is NOT a latency gate.
    // The transport runs over a REAL loopback UDP socket, which drops packets when the kernel
    // recv buffer overflows under host load; noq recovers correctly but its (un-perf-tuned, M5)
    // congestion controller is conservative, so a 256 MiB transfer under heavy drops can take
    // ~75s. Bounded PROGRESS model (M5, audit-v4 testinfra): the 180s stream timeout bounds a
    // fully-wedged read/write op (a genuine deadlock still fails here), and the hard ceiling
    // (hard_ceiling_ns, checked per chunk in send/recvPattern) bounds total transfer time so a
    // trickle-forever transfer fails as well — nothing adapts indefinitely. The 256 MiB case
    // stays mandatory (no -Dslow opt-out).
    pair.clientEp().setTestStreamTimeout(180 * std.time.ns_per_s);
    pair.serverEp().setTestStreamTimeout(180 * std.time.ns_per_s);

    const client_stream = try pair.client_conn.openBi();
    var send_future = io.async(sendPattern, .{ client_stream.send, total, seed });
    var accept_stream_future = io.async(acceptBi, .{pair.server_conn});

    const server_stream = try accept_stream_future.await(io);
    var recv_future = io.async(recvPattern, .{ server_stream.recv, total, seed });

    errdefer {
        _ = send_future.await(io) catch {};
        _ = recv_future.await(io) catch {};
    }
    try send_future.await(io);
    try recv_future.await(io);
}

/// Drop a sparse burst after the flight has grown past 64 — enough to force
/// retransmit without starving the transfer.
fn lossyDrop(pkt_idx: usize) bool {
    if (pkt_idx < 100) return false;
    // Drop 8 packets in a window, then stop dropping so recovery can finish.
    return pkt_idx >= 100 and pkt_idx < 108;
}

test "N-0 LOSSLESS: noq vtable carries 64MiB and 256MiB without FC deadlock" {
    try runLosslessTransfer(64 * MiB, 0x5a, "iroh-noq-large-64");
    try runLosslessTransfer(256 * MiB, 0xa5, "iroh-noq-large-256");
}

test "N-0 LOSSY: >64-in-flight loss recovery through grown sent tracking" {
    const total: usize = 512 * KiB;
    const seed: u8 = 0x3c;
    const io = std.testing.io;
    var pair = try establish("iroh-noq-large-lossy");
    defer pair.deinit();

    pair.clientEp().setTestDropFilter(lossyDrop);
    pair.clientEp().setTestStreamTimeout(120 * std.time.ns_per_s);
    pair.serverEp().setTestStreamTimeout(120 * std.time.ns_per_s);
    const client_drv = pair.clientEp().testDriver(.client) orelse return error.TestUnexpectedResult;
    client_drv.setTestCwndCap(512 * 1200);

    const client_stream = try pair.client_conn.openBi();
    var send_future = io.async(sendPattern, .{ client_stream.send, total, seed });
    var accept_stream_future = io.async(acceptBi, .{pair.server_conn});
    const server_stream = try accept_stream_future.await(io);
    var recv_future = io.async(recvPattern, .{ server_stream.recv, total, seed });

    const send_res = send_future.await(io);
    const recv_res = recv_future.await(io);
    const stats = pair.clientEp().testHardeningStats(.client) orelse return error.TestUnexpectedResult;
    if (send_res) |_| {} else |err| {
        std.debug.print("LOSSY send failed: {s} peak_sent={d} loss={d} rtx={d} cc_lim={d} tx={d}\n", .{
            @errorName(err), stats.peak_sent, stats.loss_events, stats.retransmits, stats.cc_limited, pair.clientEp().test_tx_count,
        });
        return err;
    }
    if (recv_res) |_| {} else |err| {
        std.debug.print("LOSSY recv failed: {s} peak_sent={d} loss={d} rtx={d} cc_lim={d} tx={d}\n", .{
            @errorName(err), stats.peak_sent, stats.loss_events, stats.retransmits, stats.cc_limited, pair.clientEp().test_tx_count,
        });
        return err;
    }

    try std.testing.expect(stats.peak_sent > 64);
    try std.testing.expect(stats.loss_events > 0 or stats.retransmits > 0);
}

test "N-0 BDP-THROTTLED: cwnd gates at buildSpacePacket (stats_cc_limited > 0)" {
    const total: usize = 4 * MiB;
    const seed: u8 = 0x7e;
    const io = std.testing.io;
    var pair = try establish("iroh-noq-large-bdp");
    defer pair.deinit();

    // Cap effective cwnd to ~8 MSS so a multi-MiB send must hit the CC gate.
    const client_drv = pair.clientEp().testDriver(.client) orelse return error.TestUnexpectedResult;
    client_drv.setTestCwndCap(8 * 1200);

    const client_stream = try pair.client_conn.openBi();
    var send_future = io.async(sendPattern, .{ client_stream.send, total, seed });
    var accept_stream_future = io.async(acceptBi, .{pair.server_conn});
    const server_stream = try accept_stream_future.await(io);
    var recv_future = io.async(recvPattern, .{ server_stream.recv, total, seed });

    errdefer {
        _ = send_future.await(io) catch {};
        _ = recv_future.await(io) catch {};
    }
    try send_future.await(io);
    try recv_future.await(io);

    const stats = pair.clientEp().testHardeningStats(.client) orelse return error.TestUnexpectedResult;
    try std.testing.expect(stats.cc_limited > 0);
}

test "N-0 NEVER-DRAIN: streaming reader keeps recv buffer ≤ advertised window" {
    const total: usize = 2 * MiB;
    const seed: u8 = 0x11;
    const io = std.testing.io;
    var pair = try establish("iroh-noq-large-hold");
    defer pair.deinit();

    const client_stream = try pair.client_conn.openBi();
    // Client-initiated bidi stream 0 on both sides.
    const stream_id: u64 = 0;

    // Start sender (async). It will FC-block once the receive window fills because
    // we deliberately delay the server reader — that is the NEVER-DRAIN condition.
    var send_future = io.async(sendPattern, .{ client_stream.send, total, seed });
    var accept_stream_future = io.async(acceptBi, .{pair.server_conn});
    const server_stream = try accept_stream_future.await(io);

    // Pump SERVER only (client is pumped by sendFinish). Measure recv occupancy
    // while the application has not yet called recv.reader().
    const ceiling = quic_conn.default_initial_max_stream_data + (64 * KiB);
    var peak_buffered: usize = 0;
    var k: usize = 0;
    while (k < 20_000) : (k += 1) {
        try pair.serverEp().pumpForTest();
        if (pair.serverEp().testStreamRecvBuffered(.server, stream_id)) |n| {
            if (n > peak_buffered) peak_buffered = n;
            try std.testing.expect(n <= ceiling);
        }
        if (peak_buffered >= quic_conn.default_initial_max_stream_data / 2) break;
    }
    try std.testing.expect(peak_buffered > 0);
    try std.testing.expect(peak_buffered <= ceiling);

    // Drain — streaming reader advances consumed; transfer must complete byte-equal.
    var recv_future = io.async(recvPattern, .{ server_stream.recv, total, seed });
    errdefer {
        _ = send_future.await(io) catch {};
        _ = recv_future.await(io) catch {};
    }
    try send_future.await(io);
    try recv_future.await(io);
}
