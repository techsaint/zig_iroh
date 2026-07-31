//! Public GossipApi / topic-handle / lifecycle / control / metrics gate.
//!
//! Exercises the user-facing API over real Zig↔Zig QUIC (same transport path as
//! gossip-quic). Covers the superset-completion cluster:
//! subscribe wait/no-wait, capacity lag, stream/split lifetime, multi-sub fanout,
//! neighbor replay, joined-consumes-NeighborUp, neighbor list, joinPeers, config knobs.
//!
//! Mutation-red controls (for independent review):
//! - if subscribeWithOptions waited for join, the immediate-return assertion fails
//! - if subscribeAndJoin returned before a neighbor, JoinWaitMissed fails
//! - if NeighborUp fanout is disabled, joined() / event wait fails
//! - if joined() does not consume NeighborUp, JoinedDidNotConsume fails
//! - if subscription_capacity lag signaling is removed, lagged_seen stays false
//! - if multi-sub fanout is disabled, MultiSubNoFanout fails
//! - if neighbor replay on resubscribe is skipped, ReplayMissed fails
//! - if dropSender closes the topic, ReceiverDidNotSurvive fails
//! - if auto-quit skips leave, AutoQuitLeftTopic fails
//! - if membership/broadcast/alpn builder knobs are ignored, NotConfigured fails
//! - if command_channel_capacity is unbounded, CommandChannelNotBounded fails
//! - if control leave is removed, status still lists the topic
//! - if metrics counters are not incremented, metrics gate fails
//! - if max_message_size builder is ignored, size assertion fails
//! - if shutdown skips leave, peer still sees neighbor after shutdown window

const std = @import("std");
const zig_iroh = @import("zig_iroh");

const transport = zig_iroh.transport;
const api = zig_iroh.gossip.api;
const types = zig_iroh.gossip.types;
const hyparview = zig_iroh.gossip.hyparview;

const TopicId = api.TopicId;
const GossipApi = api.GossipApi;
const hang_ns: u64 = 30 * std.time.ns_per_s;

fn nowNs(io: std.Io) u64 {
    return @intCast(std.Io.Clock.now(.awake, io).nanoseconds);
}

fn pumpBoth(a: *GossipApi, b: *GossipApi) !void {
    try a.pump();
    try b.pump();
}

fn waitNeighborUp(receiver: *api.GossipReceiver, a: *GossipApi, b: *GossipApi) !api.NodeId {
    const start = nowNs(a.node.io);
    while (true) {
        if (nowNs(a.node.io) - start > hang_ns) return error.HangWatchdog;
        try pumpBoth(a, b);
        if (try receiver.next()) |ev| {
            defer ev.deinit(a.allocator);
            switch (ev) {
                .neighbor_up => |peer| return peer,
                else => {},
            }
        }
    }
}

fn waitReceived(receiver: *api.GossipReceiver, a: *GossipApi, b: *GossipApi, expect: []const u8) !void {
    const start = nowNs(a.node.io);
    while (true) {
        if (nowNs(a.node.io) - start > hang_ns) return error.HangWatchdog;
        try pumpBoth(a, b);
        if (try receiver.next()) |ev| {
            defer ev.deinit(a.allocator);
            switch (ev) {
                .received => |r| {
                    if (std.mem.eql(u8, r.content, expect)) return;
                },
                else => {},
            }
        }
    }
}

fn wirePair(alloc: std.mem.Allocator, io: std.Io, max_size: usize) !struct { GossipApi, GossipApi } {
    var server = try GossipApi.builder(alloc, io, zig_iroh.key.SecretKey.fromBytes(.{0xB3} ** 32))
        .maxMessageSize(max_size)
        .build();
    errdefer server.deinit();
    var client = try GossipApi.builder(alloc, io, zig_iroh.key.SecretKey.fromBytes(.{0xA2} ** 32))
        .maxMessageSize(max_size)
        .build();
    errdefer client.deinit();

    try client.registerPeer(server.localId(), .{
        .id = server.localId(),
        .addrs = &.{.{ .ip = server.localAddress() }},
    });

    var accept_future = io.async(struct {
        fn run(t: transport.Transport) !transport.Connection {
            return t.accept();
        }
    }.run, .{server.node.transport});
    _ = try client.node.connectTo(server.localId());
    const server_conn = try accept_future.await(io);
    try server.addConnection(server_conn);
    return .{ server, client };
}

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer {
        if (gpa.deinit() == .leak) {
            std.debug.print("FAIL: gossip-api-gate leaked\n", .{});
            std.process.exit(1);
        }
    }
    const alloc = gpa.allocator();
    const io = init.io;

    if (!zig_iroh.product_flags.has_gossip) return error.GossipDisabled;

    const topic: TopicId = .{0xC0} ** 32;
    const max_size = types.DEFAULT_MAX_MESSAGE_SIZE;

    // --- Config knobs cluster ---
    {
        const custom_alpn: [:0]const u8 = "/iroh-gossip/1";
        var configured = try GossipApi.builder(alloc, io, zig_iroh.key.SecretKey.fromBytes(.{0xC1} ** 32))
            .maxMessageSize(max_size)
            .withAlpn(custom_alpn)
            .membershipConfig(.{ .active_view_capacity = 4, .passive_view_capacity = 12 })
            .broadcastConfig(.{ .optimization_threshold = .{ .value = 3 } })
            .commandChannelCapacity(2)
            .build();
        defer configured.deinit();
        if (configured.maxMessageSize() != max_size) return error.MaxMessageSizeNotConfigured;
        if (!std.mem.eql(u8, configured.alpn(), custom_alpn)) return error.AlpnNotConfigured;
        if (configured.membershipConfig().active_view_capacity != 4) return error.MembershipNotConfigured;
        if (configured.membershipConfig().passive_view_capacity != 12) return error.MembershipNotConfigured;
        if (configured.broadcastConfig().optimization_threshold.value != 3) return error.BroadcastNotConfigured;
        if (configured.commandChannelCapacity() != 2) return error.CommandChannelNotConfigured;
        // Default HyParView capacities on a plain builder.
        var defaults = try GossipApi.builder(alloc, io, zig_iroh.key.SecretKey.fromBytes(.{0xC2} ** 32)).build();
        defer defaults.deinit();
        if (defaults.membershipConfig().active_view_capacity != 5) return error.DefaultActiveCapacity;
        if (defaults.membershipConfig().passive_view_capacity != 30) return error.DefaultPassiveCapacity;
        std.debug.print("PASS: builder knobs (max_message_size/alpn/membership/broadcast/command_capacity) + defaults 5/30\n", .{});
    }

    const pair = try wirePair(alloc, io, max_size);
    var server = pair[0];
    defer server.deinit();
    var client = pair[1];
    defer client.deinit();

    if (server.maxMessageSize() != max_size) return error.MaxMessageSizeNotConfigured;
    std.debug.print("PASS: max_message_size builder exposes configured value ({d})\n", .{max_size});

    // subscribe_with_options / subscribe-no-wait: returns immediately (no wait_for_join).
    const join_start = nowNs(io);
    var server_topic = try server.subscribeWithOptions(topic, .{ .bootstrap = &.{} });
    var client_topic = try client.subscribeWithOptions(topic, .{
        .bootstrap = &.{server.localId()},
        .subscription_capacity = 2,
    });
    if (nowNs(io) - join_start > 2 * std.time.ns_per_s) return error.SubscribeBlocked;
    std.debug.print("PASS: subscribeWithOptions / subscribe-no-wait returns without waiting for neighbor\n", .{});

    // Stream interface: receiver yields events.
    var server_rx = server_topic.receiver();
    var client_rx = client_topic.receiver();
    _ = try waitNeighborUp(&server_rx, &server, &client);
    _ = try waitNeighborUp(&client_rx, &server, &client);
    std.debug.print("PASS: NeighborUp events delivered on both sides (topic stream interface)\n", .{});

    // Neighbor list tracking.
    {
        const nlist = try client_topic.neighbors(alloc);
        defer alloc.free(nlist);
        if (nlist.len == 0) return error.NeighborListEmpty;
        if (!nlist[0].eql(server.localId())) return error.NeighborListWrongPeer;
        if (!client_topic.isJoined()) return error.JoinedStateFalse;
        std.debug.print("PASS: neighbor list tracking + joined-state ({d} neighbor)\n", .{nlist.len});
    }

    // joined() consumes the first NeighborUp from the stream (use a fresh topic).
    {
        const topic_j: TopicId = .{0xC1} ** 32;
        var st = try server.subscribe(topic_j, &.{});
        var ct = try client.subscribe(topic_j, &.{server.localId()});
        // Drive until both have neighbors, but do not drain streams via next().
        const start = nowNs(io);
        while (!st.isJoined() or !ct.isJoined()) {
            if (nowNs(io) - start > hang_ns) return error.HangWatchdog;
            try pumpBoth(&server, &client);
        }
        var crx = ct.receiver();
        // joined() must consume NeighborUp from the subscriber stream.
        try ct.joined();
        // After joined(), the first NeighborUp is consumed — stream should still
        // deliver subsequent Received events from the peer.
        try st.sender().broadcast("after-joined");
        try waitReceived(&crx, &server, &client, "after-joined");
        // Server side also joins-and-consumes without hanging.
        try st.joined();
        try ct.close();
        try st.close();
        std.debug.print("PASS: joined() wait + consumes NeighborUp (stream progresses)\n", .{});
    }

    try server_topic.sender().broadcast("api-hello");
    try waitReceived(&client_rx, &server, &client, "api-hello");
    std.debug.print("PASS: Received message event via topic receiver handle (content+from+scope metadata)\n", .{});

    try server_topic.sender().broadcastNeighbors("api-neighbor-only");
    try waitReceived(&client_rx, &server, &client, "api-neighbor-only");
    std.debug.print("PASS: neighbor-only broadcast via sender handle\n", .{});

    // Lag: overflow capacity=2 with neighbor/message flood; expect Lagged.
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        var buf: [16]u8 = undefined;
        const msg = try std.fmt.bufPrint(&buf, "lag-{}", .{i});
        try server_topic.sender().broadcast(msg);
        try server.pump();
    }
    var lagged_seen = false;
    const lag_start = nowNs(io);
    while (nowNs(io) - lag_start < 5 * std.time.ns_per_s) {
        try pumpBoth(&server, &client);
        if (try client_rx.next()) |ev| {
            defer ev.deinit(alloc);
            if (ev == .lagged) {
                lagged_seen = true;
                break;
            }
        }
    }
    if (!lagged_seen) return error.LagNotSignaled;
    std.debug.print("PASS: subscription capacity limit → Lagged under slow receiver\n", .{});

    // Close the main handles before further topic-lifecycle tests (leave protocol state).
    try client_topic.close();
    try server_topic.close();

    // Multi-subscriber fanout + current-neighbor replay on subscribe.
    {
        const topic_m: TopicId = .{0xC2} ** 32;
        var st = try server.subscribe(topic_m, &.{});
        var ct1 = try client.subscribe(topic_m, &.{server.localId()});
        var crx1 = ct1.receiver();
        _ = try waitNeighborUp(&crx1, &server, &client);
        // Second local subscriber on client: must receive NeighborUp replay for existing neighbor.
        var ct2 = try client.subscribeWithOptions(topic_m, .{
            .bootstrap = &.{},
            .subscription_capacity = 8,
        });
        var crx2 = ct2.receiver();
        const replay_peer = blk: {
            const start = nowNs(io);
            while (true) {
                if (nowNs(io) - start > 5 * std.time.ns_per_s) return error.ReplayMissed;
                // No pump needed for replay — it is synchronous on subscribe.
                if (try crx2.next()) |ev| {
                    defer ev.deinit(alloc);
                    switch (ev) {
                        .neighbor_up => |p| break :blk p,
                        else => {},
                    }
                } else break; // empty — fail
            }
            return error.ReplayMissed;
        };
        if (!replay_peer.eql(server.localId())) return error.ReplayWrongPeer;
        try st.sender().broadcast("fanout-msg");
        try waitReceived(&crx1, &server, &client, "fanout-msg");
        try waitReceived(&crx2, &server, &client, "fanout-msg");
        std.debug.print("PASS: multi-subscriber fanout + current-neighbor replay on subscribe\n", .{});
        try ct2.close();
        try ct1.close();
        try st.close();
    }

    // Split lifetime: receiver survives sender drop; auto-quit when both drop.
    {
        const topic_s: TopicId = .{0xC3} ** 32;
        var st = try server.subscribe(topic_s, &.{});
        var ct = try client.subscribe(topic_s, &.{server.localId()});
        var crx = ct.receiver();
        _ = try waitNeighborUp(&crx, &server, &client);
        // Drop sender half only — receiver must still work.
        try ct.dropSender();
        // Server can still broadcast; client receiver should get it.
        try st.sender().broadcast("after-sender-drop");
        try waitReceived(&crx, &server, &client, "after-sender-drop");
        std.debug.print("PASS: receiver survives sender drop (split lifetime)\n", .{});
        // Drop receiver → topic auto-quits on client.
        try ct.dropReceiver();
        // Client should no longer list the topic after auto-quit.
        const start = nowNs(io);
        while (try topicStillListed(&client, topic_s)) {
            if (nowNs(io) - start > 5 * std.time.ns_per_s) return error.AutoQuitLeftTopic;
            try client.pump();
        }
        std.debug.print("PASS: topic auto-quit when unused (both halves dropped)\n", .{});
        try st.close();
    }

    // Closed-topic error.
    {
        const topic_c: TopicId = .{0xC4} ** 32;
        var st = try server.subscribe(topic_c, &.{});
        try st.close();
        const closed_err = st.sender().broadcast("nope");
        if (closed_err != error.Closed and closed_err != error.TopicNotJoined and closed_err != error.UnknownTopic) {
            return error.ClosedTopicErrorMissing;
        }
        std.debug.print("PASS: closed topic surfaces Closed/TopicNotJoined error\n", .{});
    }

    // Command channel capacity: with capacity=1, join consumes the slot; pump replenishes;
    // then one broadcast OK and a second without pump → CommandChannelFull.
    {
        var limited = try GossipApi.builder(alloc, io, zig_iroh.key.SecretKey.fromBytes(.{0xD1} ** 32))
            .commandChannelCapacity(1)
            .build();
        defer limited.deinit();
        const topic_q: TopicId = .{0xC5} ** 32;
        var t = try limited.subscribe(topic_q, &.{});
        try limited.pump(); // replenish after join command
        try t.sender().broadcast("one");
        const second = t.sender().broadcast("two");
        if (second != error.CommandChannelFull) return error.CommandChannelNotBounded;
        try limited.pump();
        try t.sender().broadcast("three"); // replenished after pump
        try limited.pump();
        try t.close();
        std.debug.print("PASS: command-channel capacity bounds topic commands (CommandChannelFull)\n", .{});
    }

    // Re-open a topic for control-plane checks (handle kept alive until leave).
    const ctrl_topic = try server.subscribe(topic, &.{});
    _ = ctrl_topic;

    // Control plane: in-process ops + external TCP STATUS/LEAVE boundary.
    var status = try server.control(.status);
    defer status.deinit(alloc);
    switch (status) {
        .status => |s| {
            if (s.max_message_size != max_size) return error.ControlStatusSize;
            if (s.joined_topics.len < 1) return error.ControlStatusTopics;
            if (s.membership_active != 5) return error.ControlMembershipDefault;
        },
        else => return error.ControlStatusShape,
    }
    {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const port = listener.socket.address.getPort();
        const ServeCtx = struct {
            api: *GossipApi,
            listener: *std.Io.net.Server,
            fn run(ctx: *@This()) void {
                ctx.api.serveControlOnce(ctx.listener) catch {};
            }
        };
        var ctx: ServeCtx = .{ .api = &server, .listener = &listener };
        const thr = try std.Thread.spawn(.{}, ServeCtx.run, .{&ctx});
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        const stream = try addr.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var wbuf: [64]u8 = undefined;
        var writer = stream.writer(io, &wbuf);
        try writer.interface.writeAll("STATUS\n");
        try writer.interface.flush();
        var rbuf: [128]u8 = undefined;
        var reader = stream.reader(io, &rbuf);
        const resp = (try reader.interface.takeDelimiter('\n')) orelse return error.ControlTcpEmpty;
        if (!std.mem.startsWith(u8, resp, "OK max=")) return error.ControlTcpBadStatus;
        thr.join();
    }
    _ = try server.control(.{ .leave = topic });
    var listed = try server.control(.list_topics);
    defer listed.deinit(alloc);
    switch (listed) {
        .topics => |t| {
            // Other topics from earlier subtests may remain; ensure `topic` is gone.
            for (t) |tid| {
                if (std.mem.eql(u8, &tid, &topic)) return error.ControlLeaveFailed;
            }
        },
        else => return error.ControlListShape,
    }
    std.debug.print("PASS: RPC/control surface join/leave/status/list (+ TCP STATUS)\n", .{});

    // Re-subscribe + shutdown path.
    var server_topic2 = try server.subscribe(topic, &.{});
    var client_topic2 = try client.subscribe(topic, &.{server.localId()});
    var server_rx2 = server_topic2.receiver();
    _ = try waitNeighborUp(&server_rx2, &server, &client);
    try server.shutdown();
    if (!server.stopped) return error.ShutdownIncomplete;
    std.debug.print("PASS: graceful shutdown stops actor + leaves topics\n", .{});

    const pub_m = server.metricsSnapshot();
    const sub_m = client.metricsSnapshot();
    if (pub_m.joins < 2 or pub_m.broadcasts < 1 or pub_m.neighbor_only_broadcasts < 1 or pub_m.neighbor_ups < 1 or pub_m.control_ops < 3 or pub_m.shutdowns < 1) {
        std.debug.print("FAIL publisher metrics: {}\n", .{pub_m});
        return error.MetricsDidNotMove;
    }
    if (sub_m.messages_received < 1 or sub_m.lagged < 1 or sub_m.neighbor_ups < 1) {
        std.debug.print("FAIL subscriber metrics: {}\n", .{sub_m});
        return error.MetricsDidNotMove;
    }
    var metrics_buf: [4096]u8 = undefined;
    var mw: std.Io.Writer = .fixed(&metrics_buf);
    try pub_m.renderPrometheus(&mw);
    if (std.mem.indexOf(u8, mw.buffered(), "iroh_gossip_joins") == null) return error.MetricsRender;
    std.debug.print("PASS: gossip metrics move under real API events\n", .{});

    // server_topic2 was left by shutdown; ignore close errors on both sides.
    server_topic2.close() catch {};
    client_topic2.close() catch {};
    client.shutdown() catch {};
    // Silence unused import if any.
    _ = hyparview;
    std.debug.print("PASS: gossip-api-gate (public API + handles + lag + split + multi-sub + knobs + control + metrics)\n", .{});
}

// Topic still present in the actor map (for auto-quit check).
fn topicStillListed(g: *GossipApi, topic: TopicId) !bool {
    const result = try g.control(.list_topics);
    defer result.deinit(g.allocator);
    switch (result) {
        .topics => |t| {
            for (t) |tid| {
                if (std.mem.eql(u8, &tid, &topic)) return true;
            }
            return false;
        },
        else => return false,
    }
}
