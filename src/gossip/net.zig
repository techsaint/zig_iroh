//! Gossip networking over Tier-0 MockTransport.
const std = @import("std");
const transport = @import("../transport.zig");
const mock = @import("../transport/mock.zig");
const key = @import("../key.zig");
const types = @import("types.zig");
const state = @import("proto/state.zig");
const frame = @import("frame.zig");

pub const GOSSIP_ALPN: []const u8 = "/iroh-gossip/1";
pub const TopicId = types.TopicId;
pub const NodeId = key.NodeId;

pub const StreamHeader = types.StreamHeader;

pub fn encodeTopicMessage(allocator: std.mem.Allocator, msg: types.TopicMessage(NodeId)) ![]u8 {
    return try msg.encode(allocator);
}

pub fn decodeTopicMessage(allocator: std.mem.Allocator, bytes: []const u8) !types.TopicMessage(NodeId) {
    return try types.TopicMessage(NodeId).decode(allocator, bytes);
}

pub fn writeTopicFrame(writer: *std.Io.Writer, allocator: std.mem.Allocator, msg: types.TopicMessage(NodeId)) !void {
    const body = try encodeTopicMessage(allocator, msg);
    defer allocator.free(body);
    try frame.writeFrame(writer, body);
}

pub fn readTopicFrame(reader: *std.Io.Reader, allocator: std.mem.Allocator, max: usize) !types.TopicMessage(NodeId) {
    const body = try frame.readFrame(reader, allocator, max);
    defer allocator.free(body);
    return try decodeTopicMessage(allocator, body);
}

/// Routes messages between N nodes using pairwise MockTransport pairs.
pub const Mesh = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    nodes: std.AutoHashMapUnmanaged(NodeId, *Node),

    pub const Node = struct {
        id: NodeId,
        protocol: state.State(NodeId, std.Random.DefaultPrng),
        mesh: *Mesh,
        time_ns: u64 = 0,
        queue: std.ArrayList(Queued),
        received: std.ArrayList([]const u8),

        const Queued = struct {
            at: u64,
            event: state.InEvent(NodeId),
        };

        pub fn deinit(self: *Node, allocator: std.mem.Allocator) void {
            self.protocol.deinit(allocator);
            self.queue.deinit(allocator);
            for (self.received.items) |content| allocator.free(content);
            self.received.deinit(allocator);
        }

        pub fn join(self: *Node, allocator: std.mem.Allocator, topic: TopicId, bootstrap: []const NodeId) !void {
            const peers = bootstrap;
            _ = peers;
            const out = try self.protocol.handle(allocator, .{ .command = .{ .topic = topic, .command = .{ .join = bootstrap } } }, self.time_ns);
            defer allocator.free(out);
            try self.mesh.dispatch(allocator, self.id, out);
        }

        pub fn broadcast(self: *Node, allocator: std.mem.Allocator, topic: TopicId, content: []const u8) !void {
            const out = try self.protocol.handle(allocator, .{ .command = .{ .topic = topic, .command = .{ .broadcast = .{ .content = content, .scope = .swarm } } } }, self.time_ns);
            defer allocator.free(out);
            try self.mesh.dispatch(allocator, self.id, out);
        }

        fn pushTimer(self: *Node, allocator: std.mem.Allocator, at: u64, event: state.InEvent(NodeId)) !void {
            try self.queue.append(allocator, .{ .at = at, .event = event });
        }

        fn drainDue(self: *Node, allocator: std.mem.Allocator) !void {
            var i: usize = 0;
            while (i < self.queue.items.len) {
                const item = self.queue.items[i];
                if (item.at > self.time_ns) {
                    i += 1;
                    continue;
                }
                _ = self.queue.orderedRemove(i);
                const out = try self.protocol.handle(allocator, item.event, self.time_ns);
                defer allocator.free(out);
                try self.mesh.dispatch(allocator, self.id, out);
            }
        }
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Mesh {
        return .{
            .allocator = allocator,
            .io = io,
            .nodes = .empty,
        };
    }

    pub fn deinit(self: *Mesh) void {
        var nit = self.nodes.iterator();
        while (nit.next()) |e| {
            e.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(e.value_ptr.*);
        }
        self.nodes.deinit(self.allocator);
    }

    pub fn addNode(self: *Mesh, seed: u8) !NodeId {
        const id = key.SecretKey.fromBytes(.{seed} ** 32).public();
        const node = try self.allocator.create(Node);
        const prng = std.Random.DefaultPrng.init(seed);
        node.* = .{
            .id = id,
            .protocol = state.State(NodeId, std.Random.DefaultPrng).init(id, &.{}, .{}, prng),
            .mesh = self,
            .queue = .empty,
            .received = .empty,
        };
        try self.nodes.put(self.allocator, id, node);
        return id;
    }

    fn connectionFor(_: *Mesh, local: NodeId, _: NodeId, pair: *mock.Pair) transport.Connection {
        if (std.mem.eql(u8, &local.toBytes(), &pair.client_id.toBytes())) {
            return pair.client();
        }
        return pair.server();
    }

    fn exchangeTopicMessage(
        self: *Mesh,
        allocator: std.mem.Allocator,
        from: NodeId,
        to: NodeId,
        topic: TopicId,
        body: []const u8,
    ) !types.TopicMessage(NodeId) {
        const client_id, const server_id = canonicalPair(from, to);
        const pair = mock.Pair.init(allocator, self.io, client_id, server_id);
        defer pair.deinit(allocator);

        const send_conn = self.connectionFor(from, to, pair);
        const recv_conn = self.connectionFor(to, from, pair);

        const send = try send_conn.openUni();
        const header = StreamHeader{ .topic_id = topic };
        const header_bytes = try header.encode(allocator);
        defer allocator.free(header_bytes);
        try frame.writeFrame(send.writer(), header_bytes);
        try frame.writeFrame(send.writer(), body);
        try send.finish();

        const recv = try recv_conn.acceptUni();
        const header_frame = try frame.readFrame(recv.reader(), allocator, 4096);
        defer allocator.free(header_frame);
        _ = try StreamHeader.decode(allocator, header_frame);
        const msg_bytes = try frame.readFrame(recv.reader(), allocator, 4096);
        defer allocator.free(msg_bytes);
        return try types.TopicMessage(NodeId).decode(allocator, msg_bytes);
    }

    fn canonicalPair(a: NodeId, b: NodeId) struct { NodeId, NodeId } {
        return if (std.mem.order(u8, &a.toBytes(), &b.toBytes()) == .lt)
            .{ a, b }
        else
            .{ b, a };
    }

    pub fn dispatch(self: *Mesh, allocator: std.mem.Allocator, from: NodeId, events: []const state.OutEvent(NodeId)) !void {
        const Work = struct { from: NodeId, event: state.OutEvent(NodeId) };
        var pending = std.ArrayList(Work).empty;
        defer pending.deinit(allocator);

        for (events) |ev| try pending.append(allocator, .{ .from = from, .event = ev });

        var steps: usize = 0;
        while (pending.items.len > 0) {
            if (steps > 50_000) return error.DispatchStepLimit;
            steps += 1;
            const work = pending.orderedRemove(0);
            switch (work.event) {
                .send_message => |sm| {
                    const body = try sm.message.message.encode(allocator);
                    defer allocator.free(body);
                    var inner = try self.exchangeTopicMessage(allocator, work.from, sm.to, sm.message.topic, body);
                    const wire = types.WireMessage(NodeId){ .topic = sm.message.topic, .message = inner };

                    const recv_node = self.nodes.get(sm.to) orelse {
                        inner.deinit(allocator);
                        sm.message.deinit(allocator);
                        continue;
                    };
                    const out = try recv_node.protocol.handle(allocator, .{ .recv_message = .{ .from = work.from, .message = wire } }, recv_node.time_ns);
                    defer allocator.free(out);
                    for (out) |next| {
                        switch (next) {
                            .emit_event => |em| {
                                if (em.event == .received) {
                                    const owned = try allocator.dupe(u8, em.event.received.content);
                                    try recv_node.received.append(allocator, owned);
                                } else {
                                    try pending.append(allocator, .{ .from = sm.to, .event = next });
                                }
                            },
                            else => try pending.append(allocator, .{ .from = sm.to, .event = next }),
                        }
                    }
                    inner.deinit(allocator);
                    sm.message.deinit(allocator);
                },
                .schedule_timer => |st| {
                    const node = self.nodes.get(work.from) orelse continue;
                    try node.pushTimer(allocator, node.time_ns + st.delay_ns, .{ .timer_expired = st.timer });
                },
                .emit_event => |em| {
                    const node = self.nodes.get(work.from) orelse continue;
                    if (em.event == .received) {
                        const owned = try allocator.dupe(u8, em.event.received.content);
                        try node.received.append(allocator, owned);
                    }
                },
                .disconnect_peer => {},
                .peer_data => {},
            }
        }
    }

    pub fn advance(self: *Mesh, delta_ns: u64) !void {
        var it = self.nodes.iterator();
        while (it.next()) |e| {
            e.value_ptr.*.time_ns += delta_ns;
            try e.value_ptr.*.drainDue(self.allocator);
        }
    }

    pub fn run(self: *Mesh, rounds: usize) !void {
        const step = 50 * std.time.ns_per_ms;
        var r: usize = 0;
        while (r < rounds) : (r += 1) {
            try self.advance(step);
        }
    }
};

test "mesh broadcast reaches all nodes" {
    const alloc = std.testing.allocator;
    var mesh = Mesh.init(alloc, std.testing.io);
    defer mesh.deinit();

    var ids: [4]NodeId = undefined;
    for (0..4) |i| ids[i] = try mesh.addNode(@intCast(i + 10));

    const topic: TopicId = .{0} ** 32;
    try mesh.nodes.getPtr(ids[0]).?.*.join(alloc, topic, &.{});
    try mesh.nodes.getPtr(ids[1]).?.*.join(alloc, topic, &.{ids[0]});
    try mesh.nodes.getPtr(ids[2]).?.*.join(alloc, topic, &.{ids[0]});
    try mesh.nodes.getPtr(ids[3]).?.*.join(alloc, topic, &.{ids[0]});
    try mesh.run(40);

    try mesh.nodes.getPtr(ids[0]).?.*.broadcast(alloc, topic, "hello-mesh");
    try mesh.run(60);

    for (1..4) |i| {
        const node = mesh.nodes.getPtr(ids[i]).?.*;
        try std.testing.expect(node.received.items.len >= 1);
        try std.testing.expectEqualStrings("hello-mesh", node.received.items[0]);
    }
}

test "frame golden vector" {
    const alloc = std.testing.allocator;
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const msg = types.TopicMessage(u32){ .gossip = .prune };
    const body = try msg.encode(alloc);
    defer alloc.free(body);
    try frame.writeFrame(&w, body);
    try std.testing.expectEqualSlices(u8, &@import("fixtures.zig").frame_topic_gossip_prune, w.buffered());
}
