//! Runnable gossip example: two local Zig peers join a topic via GossipApi,
//! exchange a message, and print NeighborUp / Received events.
//!
//! Build/run: `zig build gossip-example`
const std = @import("std");
const zig_iroh = @import("zig_iroh");

const transport = zig_iroh.transport;
const api = zig_iroh.gossip.api;

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const io = init.io;

    if (!zig_iroh.product_flags.has_gossip) {
        std.debug.print("gossip disabled for this product\n", .{});
        return error.GossipDisabled;
    }

    const topic: api.TopicId = blk: {
        var t: api.TopicId = undefined;
        @memset(&t, 0);
        @memcpy(t[0..6], "demo42");
        break :blk t;
    };

    var a = try api.GossipApi.builder(alloc, io, zig_iroh.key.SecretKey.fromBytes(.{0xD1} ** 32)).build();
    defer a.deinit();
    var b = try api.GossipApi.builder(alloc, io, zig_iroh.key.SecretKey.fromBytes(.{0xD2} ** 32)).build();
    defer b.deinit();

    try b.registerPeer(a.localId(), .{ .id = a.localId(), .addrs = &.{.{ .ip = a.localAddress() }} });

    var accept = io.async(struct {
        fn run(t: transport.Transport) !transport.Connection {
            return t.accept();
        }
    }.run, .{a.node.transport});
    _ = try b.node.connectTo(a.localId());
    try a.addConnection(try accept.await(io));

    var topic_a = try a.subscribe(topic, &.{});
    var topic_b = try b.subscribe(topic, &.{a.localId()});
    defer topic_a.close() catch {};
    defer topic_b.close() catch {};

    const deadline = std.Io.Clock.now(.awake, io).nanoseconds + 15 * std.time.ns_per_s;
    var got_up = false;
    var got_msg = false;
    while (std.Io.Clock.now(.awake, io).nanoseconds < deadline) {
        try a.pump();
        try b.pump();
        if (try topic_b.receiver().next()) |ev| {
            defer ev.deinit(alloc);
            switch (ev) {
                .neighbor_up => {
                    std.debug.print("event: NeighborUp\n", .{});
                    got_up = true;
                    try topic_a.sender().broadcast("hello from gossip-example");
                },
                .received => |r| {
                    std.debug.print("event: Received '{s}'\n", .{r.content});
                    got_msg = true;
                },
                else => {},
            }
        }
        if (got_up and got_msg) break;
        io.sleep(std.Io.Duration.fromMilliseconds(2), .awake) catch {};
    }
    if (!got_up or !got_msg) return error.ExampleDidNotConverge;
    std.debug.print("PASS: gossip-example exchanged a topic message over real QUIC\n", .{});
}
