//! tls-zig-native S3 core gate + zigtls SECURITY-PREP live spoof-reject oracle.
//! Zig-noq ↔ Zig-noq over a REAL UDP socket with BOTH endpoints on the
//! experimental `.zigtls` backend. Positive smoke modeled on `noq_gate.zig` 5c;
//! live spoof-reject modeled on `noq_gate.zig` 5d-B. HARNESS-FAKE RESISTANCE:
//! asserts `tlsBackend() == .zigtls` so this cannot silently pass on picotls.
//!
//! Glue-layer asserts (deliberate — do NOT "improve" to a reason code):
//! `serverHandshakeRejected()` + `!serverHasVerifiedPeer()`. The `TlsSession`
//! union flattens every zigtls error to `PicotlsError`, so reason-detail is not
//! assertable here (session-pair layer owns reason checks).

const std = @import("std");
// S6: composition-side zigtls gate (engine + door + tls_backend). Lives under
// engine-noq/harness because it needs the engine endpoint probes; the adapter
// file under tls-zigtls/adapter/ is a path note only (see adapter README comment).
const tr = @import("transport");
const key = @import("shared").key;
const crypto = @import("../crypto.zig");
const factory = tr.factory;
const noq_ep = @import("../transport_noq.zig");

fn acceptOne(server: factory.AnyEndpoint) tr.Error!tr.Connection {
    return server.transport().accept();
}

fn asNoq(any: factory.AnyEndpoint) *noq_ep.Endpoint {
    return any.noqPtr();
}

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

/// Time-bounded reject pump. A fixed iteration cap is too short for zigtls
/// (handshake reaches CertificateVerify after picotls would have already
/// rejected); match the transport handshake deadline instead.
fn pumpUntilServerRejects(server: *noq_ep.Endpoint) tr.Error!void {
    const io = std.testing.io;
    const started_ns = std.Io.Clock.now(.awake, io).nanoseconds;
    // 10s, same order as transport_noq.handshake_timeout_ns. A fixed iteration
    // cap (picotls 5d-B uses 1000) is too short for zigtls — the async pump
    // finishes before CertificateVerify and the server stops receiving while
    // connect alone times out with rejected=false.
    const limit_ns: i64 = 10 * std.time.ns_per_s;
    while (true) {
        try server.pumpForTest();
        if (server.serverHandshakeRejected()) return;
        const now_ns = std.Io.Clock.now(.awake, io).nanoseconds;
        if (now_ns - started_ns >= limit_ns) return error.Timeout;
        io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
}

test "S3: Zig-noq <-> Zig-noq zigtls real-socket 1-RTT+RPK+echo" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-zigtls-s3";

    const client_key = key.SecretKey.fromBytes([_]u8{0xB1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xB2} ** 32);

    const server_any = try factory.create(.noq, allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
        .tls_backend = .zigtls,
    });
    defer server_any.deinit();
    const client_any = try factory.create(.noq, allocator, io, client_key, alpn, .{
        .tls_backend = .zigtls,
    });
    defer client_any.deinit();

    try std.testing.expectEqual(factory.Engine.noq, client_any.engine());
    try std.testing.expectEqual(factory.Engine.noq, server_any.engine());

    const server_noq = asNoq(server_any);
    const client_noq = asNoq(client_any);
    try std.testing.expectEqual(crypto.Backend.zigtls, client_noq.tlsBackend());
    try std.testing.expectEqual(crypto.Backend.zigtls, server_noq.tlsBackend());

    var accept_future = io.async(acceptOne, .{server_any});
    const client_conn = client_any.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server_any.localAddress() }},
    }) catch |err| {
        _ = accept_future.await(io) catch {};
        return err;
    };
    const server_conn = try accept_future.await(io);

    try std.testing.expect(client_conn.remoteNodeId().eql(server_key.public()));
    try std.testing.expect(server_conn.remoteNodeId().eql(client_key.public()));

    const payloads = [_][]const u8{ "zigtls-alpha", "zigtls-bravo-longer" };
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

    try std.testing.expectEqual(@as(usize, 1), server_noq.liveConnectionCount());
    server_conn.close();
    try std.testing.expectEqual(@as(usize, 0), server_noq.liveConnectionCount());
}

// SECURITY-PREP frozen oracle: live connection-glue forged-RPK / wrong-SPKI
// reject on the **server** zigtls verify path (first exercise of that direction).
// Positive-controlled: honest peer PASSES, then spoofed peer is REJECTED on the
// SAME endpoint. Asserts reject FLAG + `!serverHasVerifiedPeer()` — NOT a reason
// (glue union flattens to PicotlsError; mirrors picotls `noq_gate.zig` 5d-B).
test "zigtls-sec: live connection rejects forged-RPK / wrong-SPKI (server verify)" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-zigtls-sec";

    const client_key = key.SecretKey.fromBytes([_]u8{0xC1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xC2} ** 32);

    const server_any = try factory.create(.noq, allocator, io, server_key, alpn, .{
        .accept_unknown_peer = true,
        .tls_backend = .zigtls,
    });
    defer server_any.deinit();
    const honest_client = try factory.create(.noq, allocator, io, client_key, alpn, .{
        .tls_backend = .zigtls,
    });
    defer honest_client.deinit();
    const server_noq = asNoq(server_any);
    try std.testing.expectEqual(crypto.Backend.zigtls, server_noq.tlsBackend());
    try std.testing.expectEqual(crypto.Backend.zigtls, asNoq(honest_client).tlsBackend());

    const accepted = try establish(honest_client, server_any, server_key.public());
    try std.testing.expect(accepted.server_conn.remoteNodeId().eql(client_key.public()));
    try std.testing.expect(server_noq.serverHasVerifiedPeer());
    accepted.client_conn.close();
    accepted.server_conn.close();
    try std.testing.expectEqual(@as(usize, 0), server_noq.liveConnectionCount());
    try std.testing.expect(!server_noq.serverHasVerifiedPeer());

    const signing_key = key.SecretKey.fromBytes([_]u8{0xC3} ** 32);
    const spoofed_key = key.SecretKey.fromBytes([_]u8{0xC4} ** 32);
    const spoof_client = try factory.create(.noq, allocator, io, signing_key, alpn, .{
        .certificate_public_key_override = spoofed_key.public(),
        .tls_backend = .zigtls,
    });
    defer spoof_client.deinit();
    try std.testing.expectEqual(crypto.Backend.zigtls, asNoq(spoof_client).tlsBackend());

    var reject_future = io.async(pumpUntilServerRejects, .{server_noq});
    const spoof_result = spoof_client.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server_any.localAddress() }},
    });
    defer if (spoof_result) |conn| conn.close() else |_| {};
    try reject_future.await(io);
    try std.testing.expect(server_noq.serverHandshakeRejected());
    try std.testing.expect(!server_noq.serverHasVerifiedPeer());
}
