//! Router + GossipApi ProtocolHandler composition gate.
//!
//! Proves gossip can be registered alongside another ALPN on RouterBuilder
//! (multi-protocol composition). Does not spawn the accept loop — spawn/shutdown
//! of a live Router is covered by protocol.zig unit tests; this gate locks the
//! gossip handler wiring specifically.
//!
//! Mutation-red control: if protocolHandler() is not registered for
//! `/iroh-gossip/1`, the builder has no gossip ALPN entry and this gate fails.

const std = @import("std");
const zig_iroh = @import("zig_iroh");

const factory = zig_iroh.transport_factory;
const protocol = zig_iroh.protocol;
const api = zig_iroh.gossip.api;
const key = zig_iroh.key;

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    const io = init.io;

    if (!zig_iroh.product_flags.has_gossip) return error.GossipDisabled;

    var gossip = try api.GossipApi.builder(alloc, io, key.SecretKey.fromBytes(.{0xE1} ** 32)).build();
    defer gossip.deinit();

    const echo_alpn = "demo/echo/1";
    const gossip_alpn = api.GOSSIP_ALPN;

    var echo_hits: usize = 0;
    const Echo = struct {
        hits: *usize,
        fn accept(ctx: *anyopaque, connection: zig_iroh.transport.Connection) anyerror!void {
            const hits: *usize = @ptrCast(@alignCast(ctx));
            hits.* += 1;
            connection.close();
        }
        fn handler(self: *@This()) protocol.ProtocolHandler {
            return .{
                .context = self.hits,
                .vtable = &.{ .accept = accept },
            };
        }
    };
    var echo_state: Echo = .{ .hits = &echo_hits };

    const router_ep = try factory.createForProduct(
        alloc,
        io,
        key.SecretKey.fromBytes(.{0xE2} ** 32),
        gossip_alpn,
        .{},
    );
    defer router_ep.deinit();

    var builder = protocol.Router.builder(router_ep, alloc);
    defer builder.deinit();
    _ = try builder.accept(gossip_alpn, gossip.protocolHandler());
    _ = try builder.accept(echo_alpn, echo_state.handler());

    if (builder.handlers.count() != 2) return error.HandlerCount;
    if (builder.handlers.get(gossip_alpn) == null) return error.GossipHandlerMissing;
    if (builder.handlers.get(echo_alpn) == null) return error.EchoHandlerMissing;

    // Gossip actor remains usable after handler registration (composition does
    // not steal ownership of the actor until spawn — we deliberately skip spawn
    // here to keep this gate focused on wiring).
    const topic: api.TopicId = .{0xEE} ** 32;
    var t = try gossip.subscribe(topic, &.{});
    try gossip.pump();
    try t.close();

    std.debug.print("PASS: Router registers gossip ALPN + secondary ALPN (multi-protocol composition)\n", .{});
    std.debug.print("GOSSIP_ALPN={s} ECHO_ALPN={s}\n", .{ gossip_alpn, echo_alpn });
    std.debug.print("PASS: gossip-router-gate\n", .{});
}
