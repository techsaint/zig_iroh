//! In-process discrete event simulation (port of proto/sim.rs).
const std = @import("std");
const state = @import("proto/state.zig");
const topic = @import("proto/topic.zig");
const types = @import("types.zig");

pub const TopicId = state.TopicId;
pub const Config = state.Config;
pub const Command = topic.Command;
pub const Event = topic.Event;
pub const Scope = types.Scope;

pub const LatencyConfig = struct {
    static_ns: u64 = 50 * std.time.ns_per_ms,

    pub fn max(self: LatencyConfig) u64 {
        return self.static_ns;
    }
};

pub const NetworkConfig = struct {
    proto: Config = .{},
    latency: LatencyConfig = .{},
};

const ConnId = struct { a: u32, b: u32 };

const QueueEvent = union(enum) {
    command: struct { topic: TopicId, command: Command(u32) },
    recv_bytes: struct { from: u32, data: []u8 },
    timer_expired: state.Timer(u32),
    peer_disconnected: u32,
};

pub fn Network(comptime Rng: type) type {
    const EventRecord = struct { peer: u32, topic: TopicId, event: Event(u32) };

    return struct {
        start_ns: u64,
        time_ns: u64,
        peers: std.AutoHashMapUnmanaged(u32, state.State(u32, Rng)),
        connections: std.AutoArrayHashMapUnmanaged(ConnId, void),
        events: std.ArrayList(EventRecord),
        latencies: std.AutoHashMapUnmanaged(ConnId, u64),
        rng: *Rng,
        config: NetworkConfig,
        queue: TimedQueue,

        pub fn init(config: NetworkConfig, rng: *Rng) @This() {
            return .{
                .start_ns = 0,
                .time_ns = 0,
                .peers = .empty,
                .connections = .empty,
                .events = .empty,
                .latencies = .empty,
                .rng = rng,
                .config = config,
                .queue = TimedQueue.init(),
            };
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            while (self.queue.pop()) |item| {
                if (item.event == .recv_bytes) allocator.free(item.event.recv_bytes.data);
            }
            var it = self.peers.iterator();
            while (it.next()) |e| e.value_ptr.deinit(allocator);
            self.peers.deinit(allocator);
            self.connections.deinit(allocator);
            self.events.deinit(allocator);
            self.latencies.deinit(allocator);
            self.queue.deinit(allocator);
        }

        pub fn insert(self: *@This(), allocator: std.mem.Allocator, peer_id: u32) !void {
            std.debug.assert(self.peers.get(peer_id) == null);
            const peer_rng = self.derivePeerRng();
            try self.peers.put(allocator, peer_id, state.State(u32, Rng).init(
                peer_id,
                &.{},
                self.config.proto,
                peer_rng,
            ));
        }

        fn derivePeerRng(self: *@This()) Rng {
            if (comptime @hasDecl(Rng, "secret_seed_length")) {
                var child_seed: [Rng.secret_seed_length]u8 = undefined;
                self.rng.random().bytes(&child_seed);
                defer std.crypto.secureZero(u8, &child_seed);
                return Rng.init(child_seed);
            }
            return Rng.init(self.rng.random().int(u64));
        }

        pub fn command(self: *@This(), allocator: std.mem.Allocator, peer: u32, topic_id: TopicId, cmd: Command(u32)) !void {
            try self.queue.insert(allocator, self.time_ns, peer, .{ .command = .{ .topic = topic_id, .command = cmd } });
            try self.tick(allocator);
        }

        pub fn runTrips(self: *@This(), allocator: std.mem.Allocator, n: usize) !void {
            const duration = self.config.latency.max() * @as(u64, @intCast(n));
            try self.runDuration(allocator, duration);
        }

        pub fn runDuration(self: *@This(), allocator: std.mem.Allocator, timeout_ns: u64) !void {
            const end = self.time_ns + timeout_ns;
            var ticks: usize = 0;
            while (self.queue.nextBefore(end)) {
                if (ticks > 10_000) return error.SimulationStepLimit;
                ticks += 1;
                try self.tick(allocator);
            }
            self.time_ns = end;
        }

        fn tick(self: *@This(), allocator: std.mem.Allocator) !void {
            const item = self.queue.pop() orelse return;
            self.time_ns = item.time;
            const peer = item.peer;
            const event = item.event;

            const st = self.peers.getPtr(peer) orelse {
                if (event == .recv_bytes) allocator.free(event.recv_bytes.data);
                return;
            };

            var free_wire: ?types.WireMessage(u32) = null;
            defer if (free_wire) |w| w.deinit(allocator);

            const in_event: state.InEvent(u32) = switch (event) {
                .command => |cmd| .{ .command = .{ .topic = cmd.topic, .command = cmd.command } },
                .timer_expired => |t| .{ .timer_expired = t },
                .peer_disconnected => |p| .{ .peer_disconnected = p },
                .recv_bytes => |rb| blk: {
                    const cid = ConnId{ .a = rb.from, .b = peer };
                    _ = try self.connections.getOrPut(allocator, cid);
                    const wire = try types.WireMessage(u32).decode(allocator, rb.data);
                    free_wire = wire;
                    allocator.free(rb.data);
                    break :blk .{ .recv_message = .{ .from = rb.from, .message = wire } };
                },
            };

            const out = try st.handle(allocator, in_event, self.time_ns);
            defer allocator.free(out);
            var kill = std.ArrayList(struct { u32, u32 }).empty;
            defer kill.deinit(allocator);
            for (out) |ev| {
                switch (ev) {
                    .send_message => |sm| {
                        defer sm.message.deinit(allocator);
                        const latency = try self.latencyBetween(allocator, peer, sm.to);
                        const bytes = try sm.message.encode(allocator);
                        defer allocator.free(bytes);
                        const owned = try allocator.dupe(u8, bytes);
                        try self.queue.insert(allocator, self.time_ns + latency, sm.to, .{
                            .recv_bytes = .{ .from = peer, .data = owned },
                        });
                    },
                    .schedule_timer => |stimer| {
                        try self.queue.insert(allocator, self.time_ns + stimer.delay_ns, peer, .{ .timer_expired = stimer.timer });
                    },
                    .disconnect_peer => |to| try kill.append(allocator, .{ peer, to }),
                    .emit_event => |em| try self.events.append(allocator, .{ .peer = peer, .topic = em.topic, .event = em.event }),
                    .peer_data => {},
                }
            }
            for (kill.items) |pair| try self.killConnection(allocator, pair[0], pair[1]);
        }

        fn latencyBetween(self: *@This(), allocator: std.mem.Allocator, a: u32, b: u32) !u64 {
            const id = ConnId{ .a = a, .b = b };
            const gop = try self.latencies.getOrPut(allocator, id);
            if (!gop.found_existing) gop.value_ptr.* = self.config.latency.static_ns;
            return gop.value_ptr.*;
        }

        fn killConnection(self: *@This(), allocator: std.mem.Allocator, from: u32, to: u32) !void {
            const id = ConnId{ .a = from, .b = to };
            if (self.connections.contains(id)) {
                _ = self.connections.swapRemove(id);
                const latency = try self.latencyBetween(allocator, from, to) + 1000;
                try self.queue.insert(allocator, self.time_ns + latency, to, .{ .peer_disconnected = from });
            }
        }

        pub fn eventsSorted(self: *@This(), allocator: std.mem.Allocator) ![]EventRecord {
            const copy = try allocator.dupe(EventRecord, self.events.items);
            std.sort.block(EventRecord, copy, {}, struct {
                fn less(_: void, x: EventRecord, y: EventRecord) bool {
                    if (x.peer != y.peer) return x.peer < y.peer;
                    if (!std.mem.eql(u8, &x.topic, &y.topic)) return std.mem.order(u8, &x.topic, &y.topic) == .lt;
                    return @intFromEnum(x.event) < @intFromEnum(y.event);
                }
            }.less);
            return copy;
        }

        pub fn drainEvents(self: *@This()) []const EventRecord {
            return self.events.items;
        }

        pub fn clearEvents(self: *@This()) void {
            self.events.clearRetainingCapacity();
        }

        pub fn conns(self: *const @This()) []const ConnId {
            return self.connections.keys();
        }

        pub fn checkSynchronicity(self: *const @This()) bool {
            var ok = true;
            var it = self.peers.iterator();
            while (it.next()) |entry| {
                const peer = entry.key_ptr.*;
                const st = entry.value_ptr;
                var sit = st.states.iterator();
                while (sit.next()) |te| {
                    const topic_id = te.key_ptr.*;
                    const tstate = te.value_ptr;
                    for (tstate.swarm.active_view.keys()) |other| {
                        const other_st = self.peers.get(other) orelse {
                            ok = false;
                            continue;
                        };
                        const other_topic = other_st.states.get(topic_id) orelse {
                            ok = false;
                            continue;
                        };
                        if (!other_topic.swarm.active_view.contains(peer)) ok = false;
                    }
                    for (tstate.gossip.eager_push_peers.keys()) |other| {
                        const other_st = self.peers.get(other) orelse {
                            ok = false;
                            continue;
                        };
                        const other_topic = other_st.states.get(topic_id) orelse {
                            ok = false;
                            continue;
                        };
                        if (!other_topic.gossip.eager_push_peers.contains(peer)) ok = false;
                    }
                }
            }
            return ok;
        }

        pub fn peerState(self: *const @This(), peer: u32, topic_id: TopicId) ?*const topic.State(u32, Rng) {
            const st = self.peers.get(peer) orelse return null;
            return st.state(topic_id);
        }
    };
}

const TimedQueue = struct {
    heap: std.PriorityQueue(TimedItem, void, TimedItem.less),
    seq: u64 = 0,

    fn init() TimedQueue {
        return .{ .heap = std.PriorityQueue(TimedItem, void, TimedItem.less).initContext({}) };
    }

    fn deinit(self: *TimedQueue, allocator: std.mem.Allocator) void {
        self.heap.deinit(allocator);
    }

    fn insert(self: *TimedQueue, allocator: std.mem.Allocator, time: u64, peer: u32, event: QueueEvent) !void {
        const seq = self.seq;
        self.seq += 1;
        try self.heap.push(allocator, .{ .time = time, .seq = seq, .peer = peer, .event = event });
    }

    fn pop(self: *TimedQueue) ?TimedItem {
        return self.heap.pop();
    }

    fn nextBefore(self: *TimedQueue, before: u64) bool {
        const p = self.heap.peek() orelse return false;
        return p.time <= before;
    }
};

const TimedItem = struct {
    time: u64,
    seq: u64,
    peer: u32,
    event: QueueEvent,

    fn less(_: void, a: TimedItem, b: TimedItem) std.math.Order {
        if (a.time != b.time) return if (a.time < b.time) .lt else .gt;
        return if (a.seq < b.seq) .lt else if (a.seq > b.seq) .gt else .eq;
    }
};

test "hyparview_smoke" {
    const alloc = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(0);
    var config = NetworkConfig{};
    config.proto.membership.active_view_capacity = 2;
    var net = Network(std.Random.DefaultPrng).init(config, &rng);
    defer net.deinit(alloc);

    for (0..4) |i| try net.insert(alloc, @intCast(i));
    const t: TopicId = .{0} ** 32;

    try net.command(alloc, 0, t, .{ .join = &[_]u32{ 1, 2 } });
    try net.command(alloc, 1, t, .{ .join = &[_]u32{2} });
    try net.command(alloc, 2, t, .{ .join = &.{} });
    try net.runTrips(alloc, 3);

    const actual = try net.eventsSorted(alloc);
    defer alloc.free(actual);

    try std.testing.expectEqual(@as(usize, 6), actual.len);
    try std.testing.expect(net.checkSynchronicity());
}

test "plumtree_smoke" {
    const alloc = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(0);
    var net = Network(std.Random.DefaultPrng).init(.{}, &rng);
    defer net.deinit(alloc);
    for (0..6) |i| try net.insert(alloc, @intCast(i));
    const t: TopicId = .{0} ** 32;

    try net.command(alloc, 0, t, .{ .join = &.{} });
    try net.command(alloc, 1, t, .{ .join = &[_]u32{0} });
    try net.command(alloc, 2, t, .{ .join = &[_]u32{0} });
    try net.command(alloc, 3, t, .{ .join = &.{} });
    try net.command(alloc, 4, t, .{ .join = &[_]u32{3} });
    try net.command(alloc, 5, t, .{ .join = &[_]u32{3} });
    try net.runTrips(alloc, 4);
    net.clearEvents();
    try std.testing.expect(net.checkSynchronicity());

    try net.command(alloc, 1, t, .{ .broadcast = .{ .content = "hi1", .scope = .swarm } });
    try net.runTrips(alloc, 4);
    var received: usize = 0;
    for (net.drainEvents()) |e| {
        if (e.event == .received) received += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), received);
    net.clearEvents();

    try net.command(alloc, 2, t, .{ .join = &[_]u32{5} });
    try net.runTrips(alloc, 3);
    net.clearEvents();

    try net.command(alloc, 1, t, .{ .broadcast = .{ .content = "hi2", .scope = .swarm } });
    try net.runTrips(alloc, 5);
    received = 0;
    for (net.drainEvents()) |e| {
        if (e.event == .received) received += 1;
    }
    try std.testing.expectEqual(@as(usize, 5), received);
    try std.testing.expect(net.checkSynchronicity());
}

test "quit" {
    const alloc = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(0);
    var config = NetworkConfig{};
    config.proto.membership.active_view_capacity = 2;
    var net = Network(std.Random.DefaultPrng).init(config, &rng);
    defer net.deinit(alloc);
    for (0..4) |i| try net.insert(alloc, @intCast(i));
    const t: TopicId = .{0} ** 32;

    try net.command(alloc, 0, t, .{ .join = &.{} });
    try net.command(alloc, 1, t, .{ .join = &[_]u32{0} });
    try net.command(alloc, 2, t, .{ .join = &[_]u32{1} });
    try net.command(alloc, 3, t, .{ .join = &[_]u32{2} });
    try net.runTrips(alloc, 2);
    try std.testing.expect(net.checkSynchronicity());

    try net.command(alloc, 3, t, .quit);
    try net.runTrips(alloc, 4);
    try std.testing.expect(net.peerState(3, t) == null);
    try std.testing.expect(net.checkSynchronicity());
}

test "L-1: shuffle forward does not double-free nodes" {
    const alloc = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(123);
    var config = NetworkConfig{};
    config.proto.membership.active_view_capacity = 3;
    var net = Network(std.Random.DefaultPrng).init(config, &rng);
    defer net.deinit(alloc);

    for (0..6) |i| try net.insert(alloc, @intCast(i));
    const t: TopicId = .{0xAA} ** 32;

    try net.command(alloc, 0, t, .{ .join = &.{} });
    try net.command(alloc, 1, t, .{ .join = &[_]u32{0} });
    try net.command(alloc, 2, t, .{ .join = &[_]u32{0} });
    try net.command(alloc, 3, t, .{ .join = &[_]u32{1} });
    try net.command(alloc, 4, t, .{ .join = &[_]u32{2} });
    try net.command(alloc, 5, t, .{ .join = &[_]u32{3} });
    try net.runTrips(alloc, 6);

    try std.testing.expect(net.checkSynchronicity());
}
