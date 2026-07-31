//! Zig-to-Zig gossip over real QUIC gate (part 3a).
const std = @import("std");
const zig_iroh = @import("zig_iroh");

const transport = zig_iroh.transport;
const factory = zig_iroh.transport_factory;
const product_flags = zig_iroh.product_flags;
const quic_net = zig_iroh.gossip.quic_net;

const TopicId = quic_net.TopicId;
const Node = quic_net.Node;
const alpn: [:0]const u8 = "/iroh-gossip/1";

const hang_ns: u64 = 30 * std.time.ns_per_s;

fn nowNs(io: std.Io) u64 {
    return @intCast(std.Io.Clock.now(.awake, io).nanoseconds);
}

fn assertProductIdentity(node: *const Node) !void {
    if (!node.gossipEnabled()) return error.GossipDisabled;
    if (node.engine() != factory.productEngine()) return error.WrongGossipEngine;
    if (node.tlsBackend() != factory.productTlsBackend()) return error.WrongGossipTls;
}

pub fn main() !void {
    const alloc = std.heap.page_allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    const io = threaded.io();
    const topic: TopicId = .{0x42} ** 32;

    var server = try Node.init(alloc, io, zig_iroh.key.SecretKey.fromBytes(.{0xB2} ** 32), alpn);
    defer server.deinit();
    var client = try Node.init(alloc, io, zig_iroh.key.SecretKey.fromBytes(.{0xA1} ** 32), alpn);
    defer client.deinit();
    try assertProductIdentity(&server);
    try assertProductIdentity(&client);
    std.debug.print("GOSSIP_PRODUCT={s} ENGINE={s} TLS={s} ENABLED={}\n", .{
        product_flags.product_name,
        @tagName(server.engine()),
        @tagName(server.tlsBackend()),
        product_flags.has_gossip,
    });

    const server_addr = server.localAddress();
    try client.registerPeer(server.id, .{
        .id = server.id,
        .addrs = &.{.{ .ip = server_addr }},
    });

    var accept_future = io.async(struct {
        fn run(t: transport.Transport) !transport.Connection {
            return t.accept();
        }
    }.run, .{server.transport});
    _ = try client.connectTo(server.id);
    const server_conn = try accept_future.await(io);
    try server.addConnection(server_conn);

    try server.join(topic, &.{});
    try client.join(topic, &.{server.id});

    const join_start = nowNs(io);
    while (!server.isJoined(topic) or !client.isJoined(topic)) {
        if (nowNs(io) - join_start > hang_ns) return error.HangWatchdog;
        try server.pump();
        try client.pump();
    }

    try server.broadcast(topic, "hello-quic-gossip");
    const recv_start = nowNs(io);
    while (!client.hasReceived(topic, "hello-quic-gossip")) {
        if (nowNs(io) - recv_start > hang_ns) return error.HangWatchdog;
        try server.pump();
        try client.pump();
    }

    std.debug.print("PASS: Zig-to-Zig gossip broadcast over real QUIC\n", .{});

    try server.broadcastNeighbors(topic, "hello-quic-neighbor");
    const neighbor_recv_start = nowNs(io);
    while (!client.hasReceived(topic, "hello-quic-neighbor")) {
        if (nowNs(io) - neighbor_recv_start > hang_ns) return error.HangWatchdog;
        try server.pump();
        try client.pump();
    }

    std.debug.print("PASS: neighbor broadcast over real QUIC driver\n", .{});

    var i: usize = 0;
    while (i < 20) : (i += 1) {
        var buf: [32]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "multi-msg-{}", .{i}) catch unreachable;
        try server.broadcast(topic, msg);
        try server.pump();
        try client.pump();
    }

    const multi_start = nowNs(io);
    while (!client.hasReceived(topic, "multi-msg-0")) {
        if (nowNs(io) - multi_start > hang_ns) return error.HangWatchdog;
        try server.pump();
        try client.pump();
    }

    std.debug.print("PASS: L-8 multi-message (20 broadcasts, no stream exhaustion)\n", .{});

    try server.pump();
    try client.pump();

    std.debug.print("PASS: L-9 driver survives pump cycle after multi-message\n", .{});

    try server.leave(topic);
    const leave_start = nowNs(io);
    while (server.isJoined(topic) or client.isJoined(topic)) {
        if (nowNs(io) - leave_start > hang_ns) return error.HangWatchdog;
        try server.pump();
        try client.pump();
    }

    std.debug.print("PASS: graceful leave drives Quit/Disconnect over real QUIC\n", .{});
}

test "Node.init requires full SecretKey (1-byte seed path gone)" {
    const alloc = std.testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const secret = zig_iroh.key.SecretKey.fromBytes(.{0x5e} ** 32);
    var node = try Node.init(alloc, io, secret, "iroh-vc1-c2");
    defer node.deinit();
    try std.testing.expect(node.id.eql(secret.public()));
}
