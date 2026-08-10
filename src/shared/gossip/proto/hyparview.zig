//! HyParView membership protocol state machine.
const std = @import("std");
const types = @import("../types.zig");
const util = @import("../util.zig");

pub const Ttl = types.Ttl;
pub const Priority = types.Priority;
pub const PeerData = types.PeerData;
pub const HyparviewMessage = types.HyparviewMessage;

pub const Config = struct {
    active_view_capacity: usize = 5,
    passive_view_capacity: usize = 30,
    active_random_walk_length: Ttl = .{ .value = 6 },
    passive_random_walk_length: Ttl = .{ .value = 3 },
    shuffle_random_walk_length: Ttl = .{ .value = 6 },
    shuffle_active_view_count: usize = 3,
    shuffle_passive_view_count: usize = 4,
    shuffle_interval_ns: u64 = 60 * std.time.ns_per_s,
    neighbor_request_timeout_ns: u64 = 500 * std.time.ns_per_ms,
};

pub fn Timer(comptime PI: type) type {
    return union(enum) {
        do_shuffle,
        pending_neighbor_request: PI,
    };
}

pub fn Event(comptime PI: type) type {
    return union(enum) {
        neighbor_up: PI,
        neighbor_down: PI,
    };
}

pub fn InEvent(comptime PI: type) type {
    return union(enum) {
        recv_message: struct { from: PI, message: HyparviewMessage(PI) },
        timer_expired: Timer(PI),
        peer_disconnected: PI,
        request_join: PI,
        update_peer_data: ?PeerData,
        quit,
    };
}

pub fn OutEvent(comptime PI: type) type {
    return union(enum) {
        send_message: struct { to: PI, message: HyparviewMessage(PI) },
        schedule_timer: struct { delay_ns: u64, timer: Timer(PI) },
        disconnect_peer: PI,
        emit_event: Event(PI),
        peer_data: struct { peer: PI, data: PeerData },
    };
}

const RemovalReason = union(enum) {
    connection_closed,
    disconnect_received: struct { is_alive: bool },
    random,
};

pub fn State(comptime PI: type, comptime Rng: type) type {
    const IndexSetPI = util.IndexSet(PI);
    return struct {
        me: PI,
        me_data: ?PeerData,
        active_view: IndexSetPI,
        passive_view: IndexSetPI,
        config: Config,
        shuffle_scheduled: bool = false,
        rng: Rng,
        _rand: std.Random = undefined,
        pending_neighbor_requests: std.AutoHashMapUnmanaged(PI, void),
        peer_data: std.AutoHashMapUnmanaged(PI, PeerData),
        alive_disconnect_peers: std.AutoHashMapUnmanaged(PI, void),

        pub fn init(me: PI, me_data: ?PeerData, config: Config, rng: Rng) @This() {
            return .{
                .me = me,
                .me_data = me_data,
                .active_view = IndexSetPI.init(),
                .passive_view = IndexSetPI.init(),
                .config = config,
                .rng = rng,
                .pending_neighbor_requests = .empty,
                .peer_data = .empty,
                .alive_disconnect_peers = .empty,
            };
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            var pit = self.peer_data.iterator();
            while (pit.next()) |entry| {
                allocator.free(entry.value_ptr.*);
            }
            self.active_view.deinit(allocator);
            self.passive_view.deinit(allocator);
            self.pending_neighbor_requests.deinit(allocator);
            self.peer_data.deinit(allocator);
            self.alive_disconnect_peers.deinit(allocator);
        }

        fn randomPtr(self: *@This()) *std.Random {
            self._rand = self.rng.random();
            return &self._rand;
        }

        fn peersEql(a: PI, b: PI) bool {
            if (@typeInfo(PI) == .int) return a == b;
            return a.eql(b);
        }

        pub fn handle(self: *@This(), allocator: std.mem.Allocator, event: InEvent(PI), out: *std.ArrayList(OutEvent(PI))) !void {
            switch (event) {
                .recv_message => |rm| try self.handleMessage(allocator, rm.from, rm.message, out),
                .timer_expired => |t| switch (t) {
                    .do_shuffle => try self.handleShuffleTimer(allocator, out),
                    .pending_neighbor_request => |p| try self.handlePendingNeighborTimer(allocator, p, out),
                },
                .peer_disconnected => |p| try self.handleConnectionClosed(allocator, p, out),
                .request_join => |p| try self.handleJoin(allocator, p, out),
                .update_peer_data => |d| self.me_data = d,
                .quit => try self.handleQuit(allocator, out),
            }
            if (!self.shuffle_scheduled) {
                try out.append(allocator, .{
                    .schedule_timer = .{ .delay_ns = self.config.shuffle_interval_ns, .timer = .do_shuffle },
                });
                self.shuffle_scheduled = true;
            }
        }

        fn handleMessage(self: *@This(), allocator: std.mem.Allocator, from: PI, message: HyparviewMessage(PI), out: *std.ArrayList(OutEvent(PI))) !void {
            const is_disconnect = switch (message) {
                .disconnect => true,
                else => false,
            };
            if (!is_disconnect and !self.active_view.contains(from)) {}
            switch (message) {
                .join => |data| try self.onJoin(allocator, from, data, out),
                .forward_join => |fj| try self.onForwardJoin(allocator, from, fj.peer, fj.ttl, out),
                .shuffle => |s| try self.onShuffle(allocator, from, s.origin, s.nodes, s.ttl, out),
                .shuffle_reply => |sr| try self.onShuffleReply(allocator, sr.nodes, out),
                .neighbor => |n| try self.onNeighbor(allocator, from, n.priority, n.data, out),
                .disconnect => |d| try self.onDisconnect(allocator, from, d.alive, d.respond, out),
            }
            if (!is_disconnect and !self.active_view.contains(from)) {
                try out.append(allocator, .{ .disconnect_peer = from });
            }
        }

        fn cloneData(allocator: std.mem.Allocator, data: ?PeerData) !?PeerData {
            if (data) |d| return try allocator.dupe(u8, d);
            return null;
        }

        fn clonePeerInfo(allocator: std.mem.Allocator, info: types.PeerInfo(PI)) !types.PeerInfo(PI) {
            return .{ .id = info.id, .data = try cloneData(allocator, info.data) };
        }

        fn clonePeerInfoSlice(allocator: std.mem.Allocator, nodes: []const types.PeerInfo(PI)) ![]types.PeerInfo(PI) {
            const out = try allocator.alloc(types.PeerInfo(PI), nodes.len);
            var filled: usize = 0;
            errdefer {
                for (out[0..filled]) |n| if (n.data) |d| allocator.free(d);
                allocator.free(out);
            }
            for (nodes, 0..) |n, i| {
                out[i] = try clonePeerInfo(allocator, n);
                filled = i + 1;
            }
            return out;
        }

        fn appendSend(allocator: std.mem.Allocator, out: *std.ArrayList(OutEvent(PI)), to: PI, message: HyparviewMessage(PI)) !void {
            out.append(allocator, .{ .send_message = .{ .to = to, .message = message } }) catch |err| {
                var owned = message;
                owned.deinit(allocator);
                return err;
            };
        }

        fn handleJoin(self: *@This(), allocator: std.mem.Allocator, peer: PI, out: *std.ArrayList(OutEvent(PI))) !void {
            // Outbound messages own their PeerData; deinit frees it (must not borrow me_data).
            try appendSend(allocator, out, peer, .{ .join = try cloneData(allocator, self.me_data) });
        }

        fn onDisconnect(self: *@This(), allocator: std.mem.Allocator, peer: PI, alive: bool, respond: bool, out: *std.ArrayList(OutEvent(PI))) !void {
            _ = respond;
            _ = self.pending_neighbor_requests.remove(peer);
            if (self.active_view.contains(peer)) {
                try self.removeActive(allocator, peer, .{ .disconnect_received = .{ .is_alive = alive } }, out);
            } else if (alive and self.passive_view.contains(peer)) {
                try self.alive_disconnect_peers.put(allocator, peer, {});
            }
        }

        fn handleConnectionClosed(self: *@This(), allocator: std.mem.Allocator, peer: PI, out: *std.ArrayList(OutEvent(PI))) !void {
            const was_pending = self.pending_neighbor_requests.remove(peer);
            if (self.active_view.contains(peer)) {
                try self.removeActive(allocator, peer, .connection_closed, out);
            } else if (!self.alive_disconnect_peers.remove(peer)) {
                _ = self.passive_view.remove(peer);
                if (self.peer_data.fetchRemove(peer)) |entry| allocator.free(entry.value);
                if (was_pending) try self.refillActiveFromPassive(allocator, &.{}, out);
            }
        }

        fn handleQuit(self: *@This(), allocator: std.mem.Allocator, out: *std.ArrayList(OutEvent(PI))) !void {
            const peers = try allocator.dupe(PI, self.active_view.keys());
            defer allocator.free(peers);
            for (peers) |peer| {
                _ = self.active_view.remove(peer);
                try self.sendDisconnect(allocator, peer, false, out);
            }
        }

        fn sendDisconnect(self: *@This(), allocator: std.mem.Allocator, peer: PI, alive: bool, out: *std.ArrayList(OutEvent(PI))) !void {
            try self.sendShuffleReply(allocator, peer, self.config.shuffle_active_view_count + self.config.shuffle_passive_view_count, out);
            try appendSend(allocator, out, peer, .{ .disconnect = .{ .alive = alive, .respond = false } });
            try out.append(allocator, .{ .disconnect_peer = peer });
        }

        fn onJoin(self: *@This(), allocator: std.mem.Allocator, peer: PI, data: ?PeerData, out: *std.ArrayList(OutEvent(PI))) !void {
            _ = try self.addActive(allocator, peer, data, .high, true, out);
            const ttl = self.config.active_random_walk_length;
            var it = self.active_view.iterWithout(peer);
            while (it.next()) |node| {
                try appendSend(allocator, out, node, .{
                    .forward_join = .{
                        .peer = .{ .id = peer, .data = try cloneData(allocator, data) },
                        .ttl = ttl,
                    },
                });
            }
        }

        fn onForwardJoin(self: *@This(), allocator: std.mem.Allocator, sender: PI, peer: types.PeerInfo(PI), ttl: Ttl, out: *std.ArrayList(OutEvent(PI))) !void {
            const peer_id = peer.id;
            if (self.active_view.contains(peer_id)) {
                try self.insertPeerInfo(allocator, peer, out);
                try self.sendNeighbor(allocator, peer_id, .high, out);
            } else if (ttl.expired() or self.active_view.len() <= 1) {
                try self.insertPeerInfo(allocator, peer, out);
                try self.sendNeighbor(allocator, peer_id, .high, out);
            } else {
                if (ttl.value == self.config.passive_random_walk_length.value) {
                    try self.addPassive(allocator, peer_id, peer.data, out);
                }
                if (!self.active_view.contains(peer_id) and self.pending_neighbor_requests.get(peer_id) == null) {
                    const without = [_]PI{sender};
                    const next = self.active_view.pickRandomWithout(allocator, &without, self.randomPtr()) orelse return;
                    try appendSend(allocator, out, next, .{
                        .forward_join = .{ .peer = try clonePeerInfo(allocator, peer), .ttl = ttl.next() },
                    });
                }
            }
        }

        fn onNeighbor(self: *@This(), allocator: std.mem.Allocator, from: PI, priority: Priority, data: ?PeerData, out: *std.ArrayList(OutEvent(PI))) !void {
            const is_reply = self.pending_neighbor_requests.remove(from);
            const do_reply = !is_reply;
            if (!try self.addActive(allocator, from, data, priority, do_reply, out)) {
                try self.sendDisconnect(allocator, from, true, out);
            }
        }

        fn insertPeerInfo(self: *@This(), allocator: std.mem.Allocator, peer_info: types.PeerInfo(PI), out: *std.ArrayList(OutEvent(PI))) !void {
            if (peer_info.data) |data| {
                const old = self.peer_data.get(peer_info.id);
                const same = if (old) |o| std.mem.eql(u8, o, data) else false;
                if (!same and data.len > 0) {
                    try out.append(allocator, .{ .peer_data = .{ .peer = peer_info.id, .data = data } });
                }
                if (same) return;
                const owned = try allocator.dupe(u8, data);
                errdefer allocator.free(owned);
                try self.peer_data.ensureUnusedCapacity(allocator, 1);
                if (self.peer_data.fetchRemove(peer_info.id)) |entry| {
                    allocator.free(entry.value);
                }
                self.peer_data.putAssumeCapacity(peer_info.id, owned);
            }
        }

        fn onShuffle(self: *@This(), allocator: std.mem.Allocator, from: PI, origin: PI, nodes: []types.PeerInfo(PI), ttl: Ttl, out: *std.ArrayList(OutEvent(PI))) !void {
            if (ttl.expired() or self.active_view.len() <= 1) {
                for (nodes) |node| {
                    try self.addPassive(allocator, node.id, node.data, out);
                }
                try self.sendShuffleReply(allocator, origin, nodes.len, out);
            } else {
                const without = [_]PI{ origin, from };
                if (self.active_view.pickRandomWithout(allocator, &without, self.randomPtr())) |node| {
                    // Deep-copy: inbound `nodes` is freed by recv deinit; outbound also deinit-frees.
                    const owned_nodes = try clonePeerInfoSlice(allocator, nodes);
                    try appendSend(allocator, out, node, .{
                        .shuffle = .{ .origin = origin, .nodes = owned_nodes, .ttl = ttl.next() },
                    });
                }
            }
        }

        fn sendShuffleReply(self: *@This(), allocator: std.mem.Allocator, to: PI, len: usize, out: *std.ArrayList(OutEvent(PI))) !void {
            const passive = try self.passive_view.shuffledAndCapped(allocator, self.randomPtr(), len);
            defer allocator.free(passive);
            var combined: ?[]PI = null;
            defer if (combined) |owned| allocator.free(owned);
            var selected = passive;
            if (passive.len < len) {
                const extra = try self.active_view.shuffledAndCapped(allocator, self.randomPtr(), len - passive.len);
                defer allocator.free(extra);
                combined = try allocator.alloc(PI, passive.len + extra.len);
                @memcpy(combined.?[0..passive.len], passive);
                @memcpy(combined.?[passive.len..], extra);
                selected = combined.?;
            }
            const nodes = try allocator.alloc(types.PeerInfo(PI), selected.len);
            var filled: usize = 0;
            var nodes_owned = true;
            errdefer {
                if (nodes_owned) {
                    for (nodes[0..filled]) |n| if (n.data) |d| allocator.free(d);
                    allocator.free(nodes);
                }
            }
            for (selected, 0..) |id, i| {
                nodes[i] = try self.peerInfoOwned(allocator, id);
                filled = i + 1;
            }
            nodes_owned = false;
            try appendSend(allocator, out, to, .{ .shuffle_reply = .{ .nodes = nodes } });
        }

        fn peerInfoOwned(self: *@This(), allocator: std.mem.Allocator, id: PI) !types.PeerInfo(PI) {
            return .{ .id = id, .data = try cloneData(allocator, self.peer_data.get(id)) };
        }

        fn onShuffleReply(self: *@This(), allocator: std.mem.Allocator, nodes: []types.PeerInfo(PI), out: *std.ArrayList(OutEvent(PI))) !void {
            for (nodes) |node| {
                try self.addPassive(allocator, node.id, node.data, out);
            }
            try self.refillActiveFromPassive(allocator, &.{}, out);
        }

        fn handleShuffleTimer(self: *@This(), allocator: std.mem.Allocator, out: *std.ArrayList(OutEvent(PI))) !void {
            if (self.active_view.pickRandom(self.randomPtr())) |node| {
                const without = [_]PI{node};
                const active = try self.active_view.shuffledWithoutAndCapped(allocator, self.randomPtr(), &without, self.config.shuffle_active_view_count);
                defer allocator.free(active);
                const passive = try self.passive_view.shuffledWithoutAndCapped(allocator, self.randomPtr(), &without, self.config.shuffle_passive_view_count);
                defer allocator.free(passive);
                const total = active.len + passive.len + 1;
                const nodes = try allocator.alloc(types.PeerInfo(PI), total);
                var idx: usize = 0;
                var nodes_owned = true;
                errdefer {
                    if (nodes_owned) {
                        for (nodes[0..idx]) |n| if (n.data) |d| allocator.free(d);
                        allocator.free(nodes);
                    }
                }
                for (active) |id| {
                    nodes[idx] = try self.peerInfoOwned(allocator, id);
                    idx += 1;
                }
                for (passive) |id| {
                    nodes[idx] = try self.peerInfoOwned(allocator, id);
                    idx += 1;
                }
                nodes[idx] = .{ .id = self.me, .data = try cloneData(allocator, self.me_data) };
                idx += 1;
                nodes_owned = false;
                try appendSend(allocator, out, node, .{
                    .shuffle = .{ .origin = self.me, .nodes = nodes, .ttl = self.config.shuffle_random_walk_length },
                });
            }
            try out.append(allocator, .{ .schedule_timer = .{ .delay_ns = self.config.shuffle_interval_ns, .timer = .do_shuffle } });
        }

        fn addPassive(self: *@This(), allocator: std.mem.Allocator, peer: PI, data: ?PeerData, out: *std.ArrayList(OutEvent(PI))) !void {
            try self.insertPeerInfo(allocator, .{ .id = peer, .data = data }, out);
            if (self.active_view.contains(peer) or self.passive_view.contains(peer) or peersEql(peer, self.me)) return;
            if (self.passive_view.len() >= self.config.passive_view_capacity) {
                if (self.passive_view.removeRandom(self.randomPtr())) |evicted| self.freeUnreferencedPeerData(allocator, evicted);
            }
            _ = try self.passive_view.insert(allocator, peer);
        }

        fn freeUnreferencedPeerData(self: *@This(), allocator: std.mem.Allocator, peer: PI) void {
            if (self.active_view.contains(peer) or self.passive_view.contains(peer) or self.pending_neighbor_requests.contains(peer)) return;
            if (self.peer_data.fetchRemove(peer)) |entry| allocator.free(entry.value);
        }

        fn removeActive(self: *@This(), allocator: std.mem.Allocator, peer: PI, reason: RemovalReason, out: *std.ArrayList(OutEvent(PI))) !void {
            if (self.active_view.getIndexOf(peer)) |idx| {
                const removed = try self.removeActiveByIndex(allocator, idx, reason, out);
                if (removed) |p| {
                    const skip = [_]PI{p};
                    try self.refillActiveFromPassive(allocator, &skip, out);
                }
            }
        }

        fn refillActiveFromPassive(self: *@This(), allocator: std.mem.Allocator, skip_peers: []const PI, out: *std.ArrayList(OutEvent(PI))) !void {
            if (self.active_view.len() + self.pending_neighbor_requests.count() >= self.config.active_view_capacity) return;
            var skip = try allocator.alloc(PI, skip_peers.len + self.pending_neighbor_requests.count());
            defer allocator.free(skip);
            @memcpy(skip[0..skip_peers.len], skip_peers);
            var i = skip_peers.len;
            var it = self.pending_neighbor_requests.keyIterator();
            while (it.next()) |k| {
                skip[i] = k.*;
                i += 1;
            }
            if (self.passive_view.pickRandomWithout(allocator, skip[0..i], self.randomPtr())) |node| {
                const priority: Priority = if (self.active_view.isEmpty()) .high else .low;
                try self.sendNeighbor(allocator, node, priority, out);
                try out.append(allocator, .{ .schedule_timer = .{
                    .delay_ns = self.config.neighbor_request_timeout_ns,
                    .timer = .{ .pending_neighbor_request = node },
                } });
            }
        }

        fn handlePendingNeighborTimer(self: *@This(), allocator: std.mem.Allocator, peer: PI, out: *std.ArrayList(OutEvent(PI))) !void {
            if (self.pending_neighbor_requests.remove(peer)) {
                _ = self.passive_view.remove(peer);
                self.freeUnreferencedPeerData(allocator, peer);
                try self.refillActiveFromPassive(allocator, &.{}, out);
            }
        }

        fn removeActiveByIndex(self: *@This(), allocator: std.mem.Allocator, peer_index: usize, reason: RemovalReason, out: *std.ArrayList(OutEvent(PI))) !?PI {
            if (self.active_view.removeIndex(peer_index)) |peer| {
                try out.append(allocator, .{ .emit_event = .{ .neighbor_down = peer } });
                switch (reason) {
                    .random => try self.sendDisconnect(allocator, peer, true, out),
                    .disconnect_received => try out.append(allocator, .{ .disconnect_peer = peer }),
                    .connection_closed => try out.append(allocator, .{ .disconnect_peer = peer }),
                }
                const keep_as_passive = switch (reason) {
                    .connection_closed => self.alive_disconnect_peers.remove(peer),
                    .disconnect_received => |d| d.is_alive,
                    .random => true,
                };
                if (keep_as_passive) {
                    const data = self.peer_data.fetchRemove(peer);
                    defer if (data) |entry| allocator.free(entry.value);
                    try self.addPassive(allocator, peer, if (data) |e| e.value else null, out);
                    if (switch (reason) {
                        .connection_closed => false,
                        else => true,
                    }) {
                        try self.alive_disconnect_peers.put(allocator, peer, {});
                    }
                } else {
                    self.freeUnreferencedPeerData(allocator, peer);
                }
                return peer;
            }
            return null;
        }

        fn freeRandomSlotInActiveView(self: *@This(), allocator: std.mem.Allocator, out: *std.ArrayList(OutEvent(PI))) !void {
            if (self.active_view.pickRandomIndex(self.randomPtr())) |index| {
                _ = try self.removeActiveByIndex(allocator, index, .random, out);
            }
        }

        fn addActive(self: *@This(), allocator: std.mem.Allocator, peer: PI, data: ?PeerData, priority: Priority, reply: bool, out: *std.ArrayList(OutEvent(PI))) !bool {
            if (peersEql(peer, self.me)) return false;
            try self.insertPeerInfo(allocator, .{ .id = peer, .data = data }, out);
            if (self.active_view.contains(peer)) {
                if (reply) try self.sendNeighbor(allocator, peer, priority, out);
                return true;
            }
            const full = self.active_view.len() >= self.config.active_view_capacity;
            switch (priority) {
                .high => {
                    if (full) try self.freeRandomSlotInActiveView(allocator, out);
                    try self.addActiveUnchecked(allocator, peer, priority, reply, out);
                    return true;
                },
                .low => {
                    if (!full) {
                        try self.addActiveUnchecked(allocator, peer, priority, reply, out);
                        return true;
                    }
                    return false;
                },
            }
        }

        fn addActiveUnchecked(self: *@This(), allocator: std.mem.Allocator, peer: PI, priority: Priority, reply: bool, out: *std.ArrayList(OutEvent(PI))) !void {
            if (try self.active_view.insert(allocator, peer)) {
                _ = self.passive_view.remove(peer);
                try out.append(allocator, .{ .emit_event = .{ .neighbor_up = peer } });
                if (reply) try self.sendNeighbor(allocator, peer, priority, out);
            }
        }

        fn sendNeighbor(self: *@This(), allocator: std.mem.Allocator, peer: PI, priority: Priority, out: *std.ArrayList(OutEvent(PI))) !void {
            const gop = try self.pending_neighbor_requests.getOrPut(allocator, peer);
            if (!gop.found_existing) {
                errdefer _ = self.pending_neighbor_requests.remove(peer);
                try appendSend(allocator, out, peer, .{
                    .neighbor = .{ .priority = priority, .data = try cloneData(allocator, self.me_data) },
                });
            }
        }
    };
}

// u32 specialization for tests
pub const U32State = State(u32, std.Random.DefaultPrng);

test "L-10: insertPeerInfo replaces and frees old data" {
    const alloc = std.testing.allocator;
    const rng = std.Random.DefaultPrng.init(42);
    var state = U32State.init(0, null, .{}, rng);
    defer state.deinit(alloc);

    var out = std.ArrayList(OutEvent(u32)).empty;
    defer out.deinit(alloc);

    const data1 = try alloc.dupe(u8, "first-data");
    defer alloc.free(data1);
    try state.insertPeerInfo(alloc, .{ .id = 1, .data = data1 }, &out);
    out.clearRetainingCapacity();

    const data2 = try alloc.dupe(u8, "second-data-longer");
    defer alloc.free(data2);
    try state.insertPeerInfo(alloc, .{ .id = 1, .data = data2 }, &out);
    out.clearRetainingCapacity();

    const data3 = try alloc.dupe(u8, "third");
    defer alloc.free(data3);
    try state.insertPeerInfo(alloc, .{ .id = 1, .data = data3 }, &out);
    out.clearRetainingCapacity();

    const stored = state.peer_data.get(1);
    try std.testing.expect(stored != null);
    try std.testing.expectEqualStrings("third", stored.?);
}

fn deinitTestOutEvents(allocator: std.mem.Allocator, out: *std.ArrayList(OutEvent(u32))) void {
    for (out.items) |event| switch (event) {
        .send_message => |sent| sent.message.deinit(allocator),
        else => {},
    };
    out.deinit(allocator);
}

test "peer disconnect releases retained PeerData" {
    const alloc = std.testing.allocator;
    const rng = std.Random.DefaultPrng.init(43);
    var state = U32State.init(0, null, .{}, rng);
    defer state.deinit(alloc);

    try state.peer_data.put(alloc, 1, try alloc.dupe(u8, "peer-data"));
    _ = try state.passive_view.insert(alloc, 1);
    var out = std.ArrayList(OutEvent(u32)).empty;
    defer deinitTestOutEvents(alloc, &out);

    try state.handle(alloc, .{ .peer_disconnected = 1 }, &out);
    try std.testing.expect(!state.peer_data.contains(1));
}

test "passive view eviction releases unreferenced PeerData" {
    const alloc = std.testing.allocator;
    const rng = std.Random.DefaultPrng.init(48);
    var state = U32State.init(0, null, .{ .passive_view_capacity = 1 }, rng);
    defer state.deinit(alloc);
    var out = std.ArrayList(OutEvent(u32)).empty;
    defer deinitTestOutEvents(alloc, &out);

    try state.addPassive(alloc, 1, "first", &out);
    try state.addPassive(alloc, 2, "second", &out);
    try std.testing.expectEqual(@as(usize, 1), state.passive_view.len());
    try std.testing.expectEqual(@as(usize, 1), state.peer_data.count());
    const retained = state.passive_view.keys()[0];
    try std.testing.expect(state.peer_data.contains(retained));
}

test "active removal transfers PeerData without leaking the old allocation" {
    const alloc = std.testing.allocator;
    const rng = std.Random.DefaultPrng.init(44);
    var state = U32State.init(0, null, .{}, rng);
    defer state.deinit(alloc);

    try state.peer_data.put(alloc, 1, try alloc.dupe(u8, "peer-data"));
    _ = try state.active_view.insert(alloc, 1);
    var out = std.ArrayList(OutEvent(u32)).empty;
    defer deinitTestOutEvents(alloc, &out);

    _ = try state.removeActiveByIndex(alloc, 0, .random, &out);
    try std.testing.expect(state.passive_view.contains(1));
    try std.testing.expectEqualStrings("peer-data", state.peer_data.get(1).?);
}

test "shuffle reply tops up from active view without leaking selection buffers" {
    const alloc = std.testing.allocator;
    const rng = std.Random.DefaultPrng.init(45);
    var state = U32State.init(0, null, .{}, rng);
    defer state.deinit(alloc);

    _ = try state.passive_view.insert(alloc, 1);
    _ = try state.active_view.insert(alloc, 2);
    var out = std.ArrayList(OutEvent(u32)).empty;
    defer deinitTestOutEvents(alloc, &out);

    try state.sendShuffleReply(alloc, 9, 2, &out);
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
}

fn checkJoinAllocationFailures(allocator: std.mem.Allocator) !void {
    const me_data = try allocator.dupe(u8, "owned-peer-data");
    defer allocator.free(me_data);
    const rng = std.Random.DefaultPrng.init(46);
    var state = U32State.init(0, me_data, .{}, rng);
    defer state.deinit(allocator);
    var out = std.ArrayList(OutEvent(u32)).empty;
    defer deinitTestOutEvents(allocator, &out);
    try state.handle(allocator, .{ .request_join = 1 }, &out);
}

test "outbound peer data ownership is transactional across allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkJoinAllocationFailures, .{});
}

fn checkShuffleAllocationFailures(allocator: std.mem.Allocator) !void {
    const me_data = try allocator.dupe(u8, "self-data");
    defer allocator.free(me_data);
    const rng = std.Random.DefaultPrng.init(47);
    var state = U32State.init(0, me_data, .{}, rng);
    defer state.deinit(allocator);
    _ = try state.active_view.insert(allocator, 1);
    _ = try state.passive_view.insert(allocator, 2);
    const active_data = try allocator.dupe(u8, "active-data");
    state.peer_data.put(allocator, 1, active_data) catch |err| {
        allocator.free(active_data);
        return err;
    };
    const passive_data = try allocator.dupe(u8, "passive-data");
    state.peer_data.put(allocator, 2, passive_data) catch |err| {
        allocator.free(passive_data);
        return err;
    };
    var out = std.ArrayList(OutEvent(u32)).empty;
    defer deinitTestOutEvents(allocator, &out);
    try state.sendShuffleReply(allocator, 9, 2, &out);
    try state.handleShuffleTimer(allocator, &out);
}

test "shuffle payload ownership is transactional across allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkShuffleAllocationFailures, .{});
}
