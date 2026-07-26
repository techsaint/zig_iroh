//! Plumtree epidemic broadcast state machine.
const std = @import("std");
const types = @import("../types.zig");
const util = @import("../util.zig");

pub const MessageId = types.MessageId;
pub const Round = types.Round;
pub const Scope = types.Scope;
pub const DeliveryScope = types.DeliveryScope;
pub const GossipPayload = types.GossipPayload;
pub const PlumtreeMessage = types.PlumtreeMessage;
pub const IHave = types.IHave;
pub const Graft = types.Graft;
pub const messageIdFromContent = types.messageIdFromContent;

pub const Config = struct {
    graft_timeout_1_ns: u64 = 80 * std.time.ns_per_ms,
    graft_timeout_2_ns: u64 = 40 * std.time.ns_per_ms,
    dispatch_timeout_ns: u64 = 5 * std.time.ns_per_ms,
    optimization_threshold: Round = .{ .value = 7 },
    message_cache_retention_ns: u64 = 30 * std.time.ns_per_s,
    message_id_retention_ns: u64 = 90 * std.time.ns_per_s,
    cache_evict_interval_ns: u64 = 1 * std.time.ns_per_s,
};

pub const Timer = union(enum) {
    send_graft: MessageId,
    dispatch_lazy_push,
    evict_cache,
};

pub fn GossipEvent(comptime PI: type) type {
    return struct {
        content: []const u8,
        delivered_from: PI,
        scope: DeliveryScope,
    };
}

pub fn Event(comptime PI: type) type {
    return struct {
        received: GossipEvent(PI),
    };
}

pub fn InEvent(comptime PI: type) type {
    return union(enum) {
        recv_message: struct { from: PI, message: PlumtreeMessage },
        broadcast: struct { content: []const u8, scope: Scope },
        timer_expired: Timer,
        neighbor_up: PI,
        neighbor_down: PI,
    };
}

pub fn OutEvent(comptime PI: type) type {
    return union(enum) {
        send_message: struct { to: PI, message: PlumtreeMessage },
        schedule_timer: struct { delay_ns: u64, timer: Timer },
        emit_event: Event(PI),
    };
}

pub fn State(comptime PI: type) type {
    const PeerSet = util.IndexSet(PI);
    const MissingEntry = struct { peer: PI, round: Round };
    return struct {
        me: PI,
        config: Config,
        eager_push_peers: PeerSet,
        lazy_push_peers: PeerSet,
        lazy_push_queue: std.AutoArrayHashMapUnmanaged(PI, std.ArrayList(IHave)),
        missing_messages: std.AutoHashMapUnmanaged(MessageId, std.ArrayList(MissingEntry)),
        received_messages: util.TimeBoundCache(MessageId, void),
        cache: util.TimeBoundCache(MessageId, GossipPayload),
        graft_timer_scheduled: std.AutoHashMapUnmanaged(MessageId, void),
        dispatch_timer_scheduled: bool = false,
        started: bool = false,
        max_message_size: usize,

        pub fn init(me: PI, config: Config, max_message_size: usize, allocator: std.mem.Allocator) @This() {
            return .{
                .me = me,
                .config = config,
                .eager_push_peers = PeerSet.init(),
                .lazy_push_peers = PeerSet.init(),
                .lazy_push_queue = .empty,
                .missing_messages = .empty,
                .received_messages = util.TimeBoundCache(MessageId, void).initWithAllocator(allocator),
                .cache = util.TimeBoundCache(MessageId, GossipPayload).initWithAllocator(allocator),
                .graft_timer_scheduled = .empty,
                .max_message_size = max_message_size,
            };
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.eager_push_peers.deinit(allocator);
            self.lazy_push_peers.deinit(allocator);
            var qit = self.lazy_push_queue.iterator();
            while (qit.next()) |entry| entry.value_ptr.deinit(allocator);
            self.lazy_push_queue.deinit(allocator);
            var mit = self.missing_messages.iterator();
            while (mit.next()) |entry| entry.value_ptr.deinit(allocator);
            self.missing_messages.deinit(allocator);
            self.cache.deinitValues(allocator);
            self.received_messages.map.deinit(allocator);
            self.received_messages.expiry.deinit();
            self.graft_timer_scheduled.deinit(allocator);
        }

        fn appendSend(allocator: std.mem.Allocator, out: *std.ArrayList(OutEvent(PI)), to: PI, message: PlumtreeMessage) !void {
            out.append(allocator, .{ .send_message = .{ .to = to, .message = message } }) catch |err| {
                var owned = message;
                owned.deinit(allocator);
                return err;
            };
        }

        pub fn cacheLen(self: *const @This()) usize {
            return self.cache.len();
        }

        pub fn handle(self: *@This(), allocator: std.mem.Allocator, event: InEvent(PI), now: u64, out: *std.ArrayList(OutEvent(PI))) !void {
            if (!self.started) {
                self.started = true;
                try self.onEvictCacheTimer(allocator, now, out);
            }
            switch (event) {
                .recv_message => |rm| try self.handleMessage(allocator, rm.from, rm.message, now, out),
                .broadcast => |b| try self.broadcast(allocator, b.content, b.scope, now, out),
                .neighbor_up => |p| try self.onNeighborUp(allocator, p),
                .neighbor_down => |p| try self.onNeighborDown(allocator, p),
                .timer_expired => |t| switch (t) {
                    .dispatch_lazy_push => try self.onDispatchTimer(allocator, out),
                    .send_graft => |id| try self.onSendGraftTimer(allocator, id, out),
                    .evict_cache => try self.onEvictCacheTimer(allocator, now, out),
                },
            }
        }

        fn handleMessage(self: *@This(), allocator: std.mem.Allocator, sender: PI, message: PlumtreeMessage, now: u64, out: *std.ArrayList(OutEvent(PI))) !void {
            switch (message) {
                .gossip => |g| try self.onGossip(allocator, sender, g, now, out),
                .prune => try self.onPrune(allocator, sender),
                .ihave => |list| try self.onIHave(allocator, sender, list, out),
                .graft => |g| try self.onGraft(allocator, sender, g, out),
            }
        }

        fn onDispatchTimer(self: *@This(), allocator: std.mem.Allocator, out: *std.ArrayList(OutEvent(PI))) !void {
            const chunk_size = self.max_message_size - 1 - 2;
            const chunk_len = @max(1, chunk_size / IHave.POSTCARD_MAX_SIZE);
            var keys = try allocator.alloc(PI, self.lazy_push_queue.count());
            defer allocator.free(keys);
            var ki: usize = 0;
            var it = self.lazy_push_queue.iterator();
            while (it.next()) |entry| {
                keys[ki] = entry.key_ptr.*;
                ki += 1;
            }
            for (keys[0..ki]) |peer| {
                const removed = self.lazy_push_queue.fetchSwapRemove(peer) orelse continue;
                var list = removed.value;
                defer list.deinit(allocator);
                var offset: usize = 0;
                while (offset < list.items.len) {
                    const end = @min(offset + chunk_len, list.items.len);
                    const chunk = list.items[offset..end];
                    const chunk_copy = try allocator.dupe(IHave, chunk);
                    try appendSend(allocator, out, peer, .{ .ihave = chunk_copy });
                    offset = end;
                }
            }
            self.dispatch_timer_scheduled = false;
        }

        fn broadcast(self: *@This(), allocator: std.mem.Allocator, content: []const u8, scope: Scope, now: u64, out: *std.ArrayList(OutEvent(PI))) !void {
            const id = messageIdFromContent(content);
            const delivery: DeliveryScope = switch (scope) {
                .neighbors => .neighbors,
                .swarm => .{ .swarm = .{ .value = 0 } },
            };
            const message = GossipPayload{
                .id = id,
                .content = try allocator.dupe(u8, content),
                .scope = delivery,
            };
            defer message.deinit(allocator);
            switch (delivery) {
                .swarm => {
                    try self.received_messages.insert(allocator, id, {}, now + self.config.message_id_retention_ns);
                    const cached = try message.clone(allocator);
                    self.cache.insert(allocator, id, cached, now + self.config.message_cache_retention_ns) catch |err| {
                        cached.deinit(allocator);
                        return err;
                    };
                    try self.lazyPush(allocator, message, self.me, out);
                },
                .neighbors => {},
            }
            try self.eagerPush(allocator, message, self.me, out);
        }

        fn onGossip(self: *@This(), allocator: std.mem.Allocator, sender: PI, message: GossipPayload, now: u64, out: *std.ArrayList(OutEvent(PI))) !void {
            if (!message.validate()) return;
            if (self.received_messages.containsKey(message.id)) {
                try self.addLazy(allocator, sender);
                try appendSend(allocator, out, sender, .prune);
                return;
            }
            switch (message.scope) {
                .swarm => {
                    try self.received_messages.insert(allocator, message.id, {}, now + self.config.message_id_retention_ns);
                    const fwd_msg = message.nextRound(allocator) catch return orelse return;
                    const cached = try fwd_msg.clone(allocator);
                    self.cache.insert(allocator, fwd_msg.id, cached, now + self.config.message_cache_retention_ns) catch |err| {
                        cached.deinit(allocator);
                        return err;
                    };
                    try self.eagerPush(allocator, fwd_msg, sender, out);
                    try self.lazyPush(allocator, fwd_msg, sender, out);
                    _ = self.graft_timer_scheduled.remove(message.id);
                    if (self.missing_messages.fetchRemove(message.id)) |kv| {
                        var list = kv.value;
                        defer list.deinit(allocator);
                        try self.optimizeTree(allocator, sender, fwd_msg, list.items, out);
                    }
                },
                .neighbors => {},
            }
            try out.append(allocator, .{ .emit_event = .{ .received = .{
                .content = message.content,
                .delivered_from = sender,
                .scope = message.scope,
            } } });
        }

        fn optimizeTree(self: *@This(), allocator: std.mem.Allocator, gossip_sender: PI, message: GossipPayload, previous: []const MissingEntry, out: *std.ArrayList(OutEvent(PI))) !void {
            const round = message.round() orelse return;
            var best: ?MissingEntry = null;
            for (previous) |entry| {
                if (best == null or entry.round.value < best.?.round.value) best = entry;
            }
            if (best) |ihave| {
                if (ihave.round.value < round.value and round.value - ihave.round.value >= self.config.optimization_threshold.value) {
                    if (!self.eager_push_peers.contains(ihave.peer)) {
                        try self.addEager(allocator, ihave.peer);
                        try appendSend(allocator, out, ihave.peer, .{
                            .graft = .{ .id = null, .round = ihave.round },
                        });
                    }
                    try self.addLazy(allocator, gossip_sender);
                    try appendSend(allocator, out, gossip_sender, .prune);
                }
            }
        }

        fn onPrune(self: *@This(), allocator: std.mem.Allocator, sender: PI) !void {
            try self.addLazy(allocator, sender);
        }

        fn onIHave(self: *@This(), allocator: std.mem.Allocator, sender: PI, ihaves: []const IHave, out: *std.ArrayList(OutEvent(PI))) !void {
            for (ihaves) |ihave| {
                if (!self.received_messages.containsKey(ihave.id)) {
                    const gop = try self.missing_messages.getOrPut(allocator, ihave.id);
                    if (!gop.found_existing) {
                        gop.value_ptr.* = .empty;
                    }
                    try gop.value_ptr.append(allocator, .{ .peer = sender, .round = ihave.round });
                    const gt = try self.graft_timer_scheduled.getOrPut(allocator, ihave.id);
                    if (!gt.found_existing) {
                        try out.append(allocator, .{ .schedule_timer = .{
                            .delay_ns = self.config.graft_timeout_1_ns,
                            .timer = .{ .send_graft = ihave.id },
                        } });
                    }
                }
            }
        }

        fn onSendGraftTimer(self: *@This(), allocator: std.mem.Allocator, id: MessageId, out: *std.ArrayList(OutEvent(PI))) !void {
            _ = self.graft_timer_scheduled.remove(id);
            if (self.received_messages.containsKey(id)) return;
            if (self.missing_messages.getPtr(id)) |entries| {
                if (entries.items.len > 0) {
                    const entry = entries.orderedRemove(0);
                    try self.addEager(allocator, entry.peer);
                    try appendSend(allocator, out, entry.peer, .{
                        .graft = .{ .id = id, .round = entry.round },
                    });
                    try out.append(allocator, .{ .schedule_timer = .{
                        .delay_ns = self.config.graft_timeout_2_ns,
                        .timer = .{ .send_graft = id },
                    } });
                } else if (self.missing_messages.fetchRemove(id)) |removed| {
                    var empty_entries = removed.value;
                    empty_entries.deinit(allocator);
                }
            }
        }

        fn onGraft(self: *@This(), allocator: std.mem.Allocator, sender: PI, details: Graft, out: *std.ArrayList(OutEvent(PI))) !void {
            try self.addEager(allocator, sender);
            if (details.id) |id| {
                if (self.cache.get(id)) |msg| {
                    const cloned = try msg.clone(allocator);
                    try appendSend(allocator, out, sender, .{ .gossip = cloned });
                }
            }
        }

        fn onNeighborUp(self: *@This(), allocator: std.mem.Allocator, peer: PI) !void {
            try self.addEager(allocator, peer);
        }

        fn peersEqual(a: PI, b: PI) bool {
            if (@typeInfo(PI) == .int) return a == b;
            return a.eql(b);
        }

        fn onNeighborDown(self: *@This(), allocator: std.mem.Allocator, peer: PI) !void {
            var empty_ids = std.ArrayList(MessageId).empty;
            defer empty_ids.deinit(allocator);
            var it = self.missing_messages.iterator();
            while (it.next()) |entry| {
                var i: usize = 0;
                while (i < entry.value_ptr.items.len) {
                    if (peersEqual(entry.value_ptr.items[i].peer, peer)) {
                        _ = entry.value_ptr.orderedRemove(i);
                    } else {
                        i += 1;
                    }
                }
                if (entry.value_ptr.items.len == 0) try empty_ids.append(allocator, entry.key_ptr.*);
            }
            for (empty_ids.items) |id| {
                if (self.missing_messages.fetchRemove(id)) |removed| {
                    var empty_entries = removed.value;
                    empty_entries.deinit(allocator);
                }
            }
            _ = self.eager_push_peers.remove(peer);
            _ = self.lazy_push_peers.remove(peer);
        }

        fn onEvictCacheTimer(self: *@This(), allocator: std.mem.Allocator, now: u64, out: *std.ArrayList(OutEvent(PI))) !void {
            _ = self.cache.expireUntil(allocator, now);
            _ = self.received_messages.expireUntil(allocator, now);
            try out.append(allocator, .{ .schedule_timer = .{
                .delay_ns = self.config.cache_evict_interval_ns,
                .timer = .evict_cache,
            } });
        }

        fn addEager(self: *@This(), allocator: std.mem.Allocator, peer: PI) !void {
            _ = self.lazy_push_peers.remove(peer);
            _ = try self.eager_push_peers.insert(allocator, peer);
        }

        fn addLazy(self: *@This(), allocator: std.mem.Allocator, peer: PI) !void {
            _ = self.eager_push_peers.remove(peer);
            _ = try self.lazy_push_peers.insert(allocator, peer);
        }

        fn peerIsSender(peer: PI, _: PI, sender: PI) bool {
            if (@typeInfo(PI) == .int) return peer == sender;
            return peer.eql(sender);
        }

        fn peerIsSelfOrSender(peer: PI, me: PI, sender: PI) bool {
            if (@typeInfo(PI) == .int) return peer == me or peer == sender;
            return peer.eql(me) or peer.eql(sender);
        }

        fn eagerPush(self: *@This(), allocator: std.mem.Allocator, gossip: GossipPayload, sender: PI, out: *std.ArrayList(OutEvent(PI))) !void {
            for (self.eager_push_peers.keys()) |peer| {
                if (!peerIsSelfOrSender(peer, self.me, sender)) {
                    const cloned = try gossip.clone(allocator);
                    try appendSend(allocator, out, peer, .{ .gossip = cloned });
                }
            }
        }

        fn lazyPush(self: *@This(), allocator: std.mem.Allocator, gossip: GossipPayload, sender: PI, out: *std.ArrayList(OutEvent(PI))) !void {
            const round = gossip.round() orelse return;
            for (self.lazy_push_peers.keys()) |peer| {
                if (peerIsSender(peer, self.me, sender)) continue;
                const gop = try self.lazy_push_queue.getOrPut(allocator, peer);
                if (!gop.found_existing) gop.value_ptr.* = .empty;
                try gop.value_ptr.append(allocator, .{ .id = gossip.id, .round = round });
            }
            if (!self.dispatch_timer_scheduled) {
                try out.append(allocator, .{ .schedule_timer = .{
                    .delay_ns = self.config.dispatch_timeout_ns,
                    .timer = .dispatch_lazy_push,
                } });
                self.dispatch_timer_scheduled = true;
            }
        }
    };
}

test "optimize_tree" {
    const alloc = std.testing.allocator;
    const config = Config{};
    var state = State(u32).init(1, config, 1024, alloc);
    defer state.deinit(alloc);
    const now: u64 = 0;
    var io: std.ArrayList(OutEvent(u32)) = .empty;
    defer io.deinit(alloc);

    const content = "hi";
    const id = messageIdFromContent(content);
    try state.handle(alloc, .{ .recv_message = .{ .from = 2, .message = .{ .ihave = &[_]IHave{.{ .id = id, .round = .{ .value = 2 } }} } } }, now, &io);
    io.clearRetainingCapacity();

    try state.handle(alloc, .{ .recv_message = .{ .from = 3, .message = .{ .gossip = .{
        .id = id,
        .content = content,
        .scope = .{ .swarm = .{ .value = 6 } },
    } } } }, now, &io);
    try std.testing.expectEqual(@as(usize, 2), io.items.len);
    try std.testing.expect(io.items[0] == .schedule_timer);
    try std.testing.expect(io.items[1] == .emit_event);
    io.clearRetainingCapacity();

    const content2 = "hi2";
    const id2 = messageIdFromContent(content2);
    try state.handle(alloc, .{ .recv_message = .{ .from = 2, .message = .{ .ihave = &[_]IHave{.{ .id = id2, .round = .{ .value = 2 } }} } } }, now, &io);
    io.clearRetainingCapacity();

    try state.handle(alloc, .{ .recv_message = .{ .from = 3, .message = .{ .gossip = .{
        .id = id2,
        .content = content2,
        .scope = .{ .swarm = .{ .value = 9 } },
    } } } }, now, &io);
    try std.testing.expectEqual(@as(usize, 3), io.items.len);
    try std.testing.expect(io.items[0] == .send_message);
    try std.testing.expect(io.items[1] == .send_message);
    try std.testing.expect(io.items[2] == .emit_event);
}

test "dispatch lazy push chunks by iroh IHave max size" {
    const alloc = std.testing.allocator;
    var state = State(u32).init(1, .{}, 1023, alloc);
    defer state.deinit(alloc);

    var list = std.ArrayList(IHave).empty;
    errdefer list.deinit(alloc);
    for (0..30) |i| {
        var id = [_]u8{0} ** 32;
        id[31] = @intCast(i);
        try list.append(alloc, .{ .id = id, .round = .{ .value = std.math.maxInt(u16) } });
    }
    try state.lazy_push_queue.put(alloc, 2, list);
    state.dispatch_timer_scheduled = true;

    var io: std.ArrayList(OutEvent(u32)) = .empty;
    defer {
        for (io.items) |event| {
            if (event == .send_message) event.send_message.message.deinit(alloc);
        }
        io.deinit(alloc);
    }

    try state.onDispatchTimer(alloc, &io);
    try std.testing.expectEqual(@as(usize, 2), io.items.len);
    for (io.items) |event| {
        try std.testing.expect(event == .send_message);
        const encoded = try event.send_message.message.encode(alloc);
        defer alloc.free(encoded);
        try std.testing.expect(encoded.len <= state.max_message_size);
    }
}

fn checkGraftAllocationFailures(allocator: std.mem.Allocator) !void {
    var state = State(u32).init(1, .{}, 1024, allocator);
    defer state.deinit(allocator);
    const content = try allocator.dupe(u8, "cached-gossip");
    const id = messageIdFromContent(content);
    const payload = GossipPayload{ .id = id, .content = content, .scope = .{ .swarm = .{ .value = 1 } } };
    state.cache.insert(allocator, id, payload, 100) catch |err| {
        payload.deinit(allocator);
        return err;
    };
    var out = std.ArrayList(OutEvent(u32)).empty;
    defer {
        for (out.items) |event| if (event == .send_message) event.send_message.message.deinit(allocator);
        out.deinit(allocator);
    }
    try state.onGraft(allocator, 2, .{ .id = id, .round = .{ .value = 1 } }, &out);
}

test "outbound gossip ownership is transactional across allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkGraftAllocationFailures, .{});
}

test "neighbors broadcast pushes only eager neighbors" {
    const alloc = std.testing.allocator;
    var state = State(u32).init(1, .{}, 1024, alloc);
    defer state.deinit(alloc);

    try state.addEager(alloc, 2);
    try state.addLazy(alloc, 3);

    var io: std.ArrayList(OutEvent(u32)) = .empty;
    defer {
        for (io.items) |event| {
            if (event == .send_message) event.send_message.message.deinit(alloc);
        }
        io.deinit(alloc);
    }

    try state.broadcast(alloc, "neighbor-only", .neighbors, 0, &io);
    try std.testing.expectEqual(@as(usize, 1), io.items.len);
    const sent = io.items[0].send_message;
    try std.testing.expectEqual(@as(u32, 2), sent.to);
    try std.testing.expect(sent.message == .gossip);
    try std.testing.expect(sent.message.gossip.scope == .neighbors);
    try std.testing.expectEqual(@as(usize, 0), state.cacheLen());
    try std.testing.expectEqual(@as(usize, 0), state.lazy_push_queue.count());
}

test "spoofed_messages_are_ignored" {
    const alloc = std.testing.allocator;
    const config = Config{};
    var state = State(u32).init(1, config, 1024, alloc);
    defer state.deinit(alloc);
    const now: u64 = 0;
    var io: std.ArrayList(OutEvent(u32)) = .empty;
    defer io.deinit(alloc);

    const content = "hello1";
    try state.handle(alloc, .{ .recv_message = .{ .from = 2, .message = .{ .gossip = .{
        .id = messageIdFromContent(content),
        .content = content,
        .scope = .{ .swarm = .{ .value = 1 } },
    } } } }, now, &io);
    try std.testing.expectEqual(@as(usize, 3), io.items.len);
    io.clearRetainingCapacity();

    const bad = "hello2";
    try state.handle(alloc, .{ .recv_message = .{ .from = 2, .message = .{ .gossip = .{
        .id = messageIdFromContent("foo"),
        .content = bad,
        .scope = .{ .swarm = .{ .value = 1 } },
    } } } }, now, &io);
    try std.testing.expectEqual(@as(usize, 0), io.items.len);
}

test "cache_is_evicted" {
    const alloc = std.testing.allocator;
    const config = Config{};
    var state = State(u32).init(1, config, 1024, alloc);
    defer state.deinit(alloc);
    var now: u64 = 0;
    var io: std.ArrayList(OutEvent(u32)) = .empty;
    defer io.deinit(alloc);

    const content = "hello1";
    try state.handle(alloc, .{ .recv_message = .{ .from = 2, .message = .{ .gossip = .{
        .id = messageIdFromContent(content),
        .content = content,
        .scope = .{ .swarm = .{ .value = 1 } },
    } } } }, now, &io);
    try std.testing.expectEqual(@as(usize, 1), state.cacheLen());

    now += std.time.ns_per_s;
    try state.handle(alloc, .{ .timer_expired = .evict_cache }, now, &io);
    try std.testing.expectEqual(@as(usize, 1), state.cacheLen());

    now += config.message_cache_retention_ns;
    try state.handle(alloc, .{ .timer_expired = .evict_cache }, now, &io);
    try std.testing.expectEqual(@as(usize, 0), state.cacheLen());
}
