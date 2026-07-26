//! Multi-topic global protocol state.
const std = @import("std");
const types = @import("../types.zig");
const topic = @import("topic.zig");

pub const TopicId = types.TopicId;
pub const TopicMessage = types.TopicMessage;
pub const WireMessage = types.WireMessage;
pub const Config = topic.Config;
pub const Command = topic.Command;
pub const Event = topic.Event;

pub fn Timer(comptime PI: type) type {
    return struct {
        topic: TopicId,
        timer: topic.Timer(PI),
    };
}

pub fn InEvent(comptime PI: type) type {
    return union(enum) {
        recv_message: struct { from: PI, message: WireMessage(PI) },
        command: struct { topic: TopicId, command: Command(PI) },
        timer_expired: Timer(PI),
        peer_disconnected: PI,
        update_peer_data: types.PeerData,
    };
}

pub fn OutEvent(comptime PI: type) type {
    return union(enum) {
        send_message: struct { to: PI, message: WireMessage(PI) },
        emit_event: struct { topic: TopicId, event: Event(PI) },
        schedule_timer: struct { delay_ns: u64, timer: Timer(PI) },
        disconnect_peer: PI,
        peer_data: struct { peer: PI, data: types.PeerData },
    };
}

pub fn State(comptime PI: type, comptime Rng: type) type {
    return struct {
        me: PI,
        me_data: types.PeerData,
        config: Config,
        rng: Rng,
        states: std.AutoHashMapUnmanaged(TopicId, topic.State(PI, Rng)),
        peer_topics: std.AutoHashMapUnmanaged(PI, std.AutoHashMapUnmanaged(TopicId, void)),
        outbox: std.ArrayList(OutEvent(PI)),

        pub fn init(me: PI, me_data: types.PeerData, config: Config, rng: Rng) @This() {
            std.debug.assert(config.max_message_size >= types.MIN_MAX_MESSAGE_SIZE);
            return .{
                .me = me,
                .me_data = me_data,
                .config = config,
                .rng = rng,
                .states = .empty,
                .peer_topics = .empty,
                .outbox = .empty,
            };
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            var it = self.states.iterator();
            while (it.next()) |entry| entry.value_ptr.deinit(allocator);
            self.states.deinit(allocator);
            var pit = self.peer_topics.iterator();
            while (pit.next()) |entry| {
                entry.value_ptr.deinit(allocator);
            }
            self.peer_topics.deinit(allocator);
            self.outbox.deinit(allocator);
        }

        pub fn state(self: *const @This(), topic_id: TopicId) ?*const topic.State(PI, Rng) {
            return self.states.getPtr(topic_id);
        }

        pub fn hasActivePeers(self: *const @This(), topic_id: TopicId) bool {
            const s = self.states.get(topic_id) orelse return false;
            return s.hasActivePeers();
        }

        pub fn handle(self: *@This(), allocator: std.mem.Allocator, event: InEvent(PI), now: u64) ![]OutEvent(PI) {
            self.outbox.clearRetainingCapacity();
            errdefer {
                deinitOutEvents(allocator, self.outbox.items);
                self.outbox.clearRetainingCapacity();
            }
            switch (event) {
                .recv_message => |rm| {
                    try self.handleTopicEvent(allocator, rm.message.topic, .{ .recv_message = .{
                        .from = rm.from,
                        .message = rm.message.message,
                    } }, now, false);
                },
                .command => |cmd| {
                    const is_join = switch (cmd.command) {
                        .join => true,
                        else => false,
                    };
                    if (is_join) {
                        const gop = try self.states.getOrPut(allocator, cmd.topic);
                        if (!gop.found_existing) {
                            gop.value_ptr.* = topic.State(PI, Rng).init(
                                self.me,
                                self.me_data,
                                self.config,
                                self.deriveChildRng(),
                                allocator,
                            );
                        }
                    }
                    const quit = switch (cmd.command) {
                        .quit => true,
                        else => false,
                    };
                    try self.handleTopicEvent(allocator, cmd.topic, .{ .command = cmd.command }, now, false);
                    if (quit) {
                        if (self.states.getPtr(cmd.topic)) |topic_ptr| {
                            topic_ptr.deinit(allocator);
                            _ = self.states.remove(cmd.topic);
                        }
                    }
                },
                .timer_expired => |t| {
                    try self.handleTopicEvent(allocator, t.topic, .{ .timer_expired = t.timer }, now, false);
                },
                .peer_disconnected => |peer| {
                    var topics = std.ArrayList(TopicId).empty;
                    defer topics.deinit(allocator);
                    try topics.ensureTotalCapacity(allocator, self.states.count());
                    var kit = self.states.keyIterator();
                    while (kit.next()) |topic_id| try topics.append(allocator, topic_id.*);
                    for (topics.items) |t| {
                        try self.handleTopicEvent(allocator, t, .{ .peer_disconnected = peer }, now, false);
                    }
                    if (self.peer_topics.fetchRemove(peer)) |entry| {
                        var peer_topic_set = entry.value;
                        peer_topic_set.deinit(allocator);
                    }
                },
                .update_peer_data => |data| {
                    self.me_data = data;
                    var it = self.states.keyIterator();
                    while (it.next()) |topic_id| {
                        try self.handleTopicEvent(allocator, topic_id.*, .{ .update_peer_data = data }, now, false);
                    }
                },
            }
            return try allocator.dupe(OutEvent(PI), self.outbox.items);
        }

        fn handleTopicEvent(
            self: *@This(),
            allocator: std.mem.Allocator,
            topic_id: TopicId,
            event: topic.InEvent(PI),
            now: u64,
            _: bool,
        ) !void {
            const s = self.states.getPtr(topic_id) orelse return;
            switch (event) {
                .recv_message => |rm| {
                    const gop = try self.peer_topics.getOrPut(allocator, rm.from);
                    if (!gop.found_existing) gop.value_ptr.* = .empty;
                    try gop.value_ptr.put(allocator, topic_id, {});
                },
                else => {},
            }
            const out = try s.handle(allocator, event, now);
            defer allocator.free(out);
            var moved: usize = 0;
            defer deinitTopicOutEvents(allocator, out[moved..]);
            while (moved < out.len) {
                try self.handleTopicOut(allocator, topic_id, out[moved]);
                moved += 1;
            }
        }

        fn deriveChildRng(self: *@This()) Rng {
            if (comptime @hasDecl(Rng, "secret_seed_length")) {
                var child_seed: [Rng.secret_seed_length]u8 = undefined;
                self.rng.random().bytes(&child_seed);
                defer std.crypto.secureZero(u8, &child_seed);
                return Rng.init(child_seed);
            }
            return Rng.init(self.rng.random().int(u64));
        }

        fn handleTopicOut(self: *@This(), allocator: std.mem.Allocator, topic_id: TopicId, event: topic.OutEvent(PI)) !void {
            switch (event) {
                .send_message => |sm| {
                    try self.outbox.append(allocator, .{ .send_message = .{
                        .to = sm.to,
                        .message = .{ .topic = topic_id, .message = sm.message },
                    } });
                },
                .emit_event => |ev| try self.outbox.append(allocator, .{ .emit_event = .{ .topic = topic_id, .event = ev } }),
                .schedule_timer => |st| try self.outbox.append(allocator, .{ .schedule_timer = .{
                    .delay_ns = st.delay_ns,
                    .timer = .{ .topic = topic_id, .timer = st.timer },
                } }),
                .disconnect_peer => |peer| {
                    var empty = false;
                    if (self.peer_topics.getPtr(peer)) |set| {
                        _ = set.remove(topic_id);
                        empty = set.count() == 0;
                    }
                    if (empty) {
                        if (self.peer_topics.fetchRemove(peer)) |entry| {
                            var topics = entry.value;
                            topics.deinit(allocator);
                        }
                        try self.outbox.append(allocator, .{ .disconnect_peer = peer });
                    }
                },
                .peer_data => |pd| try self.outbox.append(allocator, .{ .peer_data = .{ .peer = pd.peer, .data = pd.data } }),
            }
        }

        fn deinitTopicOutEvents(allocator: std.mem.Allocator, events: []const topic.OutEvent(PI)) void {
            for (events) |event| switch (event) {
                .send_message => |sent| sent.message.deinit(allocator),
                else => {},
            };
        }

        fn deinitOutEvents(allocator: std.mem.Allocator, events: []const OutEvent(PI)) void {
            for (events) |event| switch (event) {
                .send_message => |sent| sent.message.deinit(allocator),
                else => {},
            };
        }
    };
}
