//! Per-topic state: HyParView + Plumtree wiring.
const std = @import("std");
const types = @import("../types.zig");
const hyparview = @import("hyparview.zig");
const plumtree = @import("plumtree.zig");

pub const TopicMessage = types.TopicMessage;
pub const Scope = types.Scope;
pub const PeerData = types.PeerData;
pub const DEFAULT_MAX_MESSAGE_SIZE = types.DEFAULT_MAX_MESSAGE_SIZE;
pub const MIN_MAX_MESSAGE_SIZE = types.MIN_MAX_MESSAGE_SIZE;

pub const Config = struct {
    membership: hyparview.Config = .{},
    broadcast: plumtree.Config = .{},
    max_message_size: usize = DEFAULT_MAX_MESSAGE_SIZE,
};

pub fn Timer(comptime PI: type) type {
    return union(enum) {
        swarm: hyparview.Timer(PI),
        gossip: plumtree.Timer,
    };
}

pub fn Event(comptime PI: type) type {
    return union(enum) {
        neighbor_up: PI,
        neighbor_down: PI,
        received: plumtree.GossipEvent(PI),
    };
}

pub fn Command(comptime PI: type) type {
    return union(enum) {
        join: []const PI,
        broadcast: struct { content: []const u8, scope: Scope },
        quit,
    };
}

pub fn InEvent(comptime PI: type) type {
    return union(enum) {
        recv_message: struct { from: PI, message: TopicMessage(PI) },
        command: Command(PI),
        timer_expired: Timer(PI),
        peer_disconnected: PI,
        update_peer_data: ?PeerData,
    };
}

pub fn OutEvent(comptime PI: type) type {
    return union(enum) {
        send_message: struct { to: PI, message: TopicMessage(PI) },
        emit_event: Event(PI),
        schedule_timer: struct { delay_ns: u64, timer: Timer(PI) },
        disconnect_peer: PI,
        peer_data: struct { peer: PI, data: PeerData },
    };
}

pub fn State(comptime PI: type, comptime Rng: type) type {
    return struct {
        me: PI,
        swarm: hyparview.State(PI, Rng),
        gossip: plumtree.State(PI),
        outbox: std.ArrayList(OutEvent(PI)),

        pub fn init(me: PI, me_data: ?PeerData, config: Config, rng: Rng, allocator: std.mem.Allocator) @This() {
            std.debug.assert(config.max_message_size >= MIN_MAX_MESSAGE_SIZE);
            const header_size = types.WireMessage(PI).postcardHeaderSize();
            const max_payload = config.max_message_size - header_size;
            return .{
                .me = me,
                .swarm = hyparview.State(PI, Rng).init(me, me_data, config.membership, rng),
                .gossip = plumtree.State(PI).init(me, config.broadcast, max_payload, allocator),
                .outbox = .empty,
            };
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.swarm.deinit(allocator);
            self.gossip.deinit(allocator);
            self.outbox.deinit(allocator);
        }

        pub fn hasActivePeers(self: *const @This()) bool {
            return !self.swarm.active_view.isEmpty();
        }

        pub fn handle(self: *@This(), allocator: std.mem.Allocator, event: InEvent(PI), now: u64) ![]OutEvent(PI) {
            self.outbox.clearRetainingCapacity();
            errdefer {
                deinitOutEvents(allocator, self.outbox.items);
                self.outbox.clearRetainingCapacity();
            }
            var swarm_out: std.ArrayList(hyparview.OutEvent(PI)) = .empty;
            defer {
                deinitSwarmOutEvents(allocator, swarm_out.items);
                swarm_out.deinit(allocator);
            }
            var gossip_out: std.ArrayList(plumtree.OutEvent(PI)) = .empty;
            defer {
                deinitGossipOutEvents(allocator, gossip_out.items);
                gossip_out.deinit(allocator);
            }

            switch (event) {
                .command => |cmd| switch (cmd) {
                    .join => |peers| {
                        for (peers) |peer| {
                            try self.swarm.handle(allocator, .{ .request_join = peer }, &swarm_out);
                        }
                    },
                    .broadcast => |b| {
                        try self.gossip.handle(allocator, .{ .broadcast = .{ .content = b.content, .scope = b.scope } }, now, &gossip_out);
                    },
                    .quit => try self.swarm.handle(allocator, .quit, &swarm_out),
                },
                .recv_message => |rm| switch (rm.message) {
                    .swarm => |m| try self.swarm.handle(allocator, .{ .recv_message = .{ .from = rm.from, .message = m } }, &swarm_out),
                    .gossip => |m| try self.gossip.handle(allocator, .{ .recv_message = .{ .from = rm.from, .message = m } }, now, &gossip_out),
                },
                .timer_expired => |t| switch (t) {
                    .swarm => |st| try self.swarm.handle(allocator, .{ .timer_expired = st }, &swarm_out),
                    .gossip => |gt| try self.gossip.handle(allocator, .{ .timer_expired = gt }, now, &gossip_out),
                },
                .peer_disconnected => |p| {
                    try self.swarm.handle(allocator, .{ .peer_disconnected = p }, &swarm_out);
                    try self.gossip.handle(allocator, .{ .neighbor_down = p }, now, &gossip_out);
                },
                .update_peer_data => |d| try self.swarm.handle(allocator, .{ .update_peer_data = d }, &swarm_out),
            }

            try self.pushSwarm(allocator, &swarm_out);

            for (self.outbox.items) |ev| {
                switch (ev) {
                    .emit_event => |e| switch (e) {
                        .neighbor_up => |peer| {
                            try self.gossip.handle(allocator, .{ .neighbor_up = peer }, now, &gossip_out);
                        },
                        .neighbor_down => |peer| {
                            try self.gossip.handle(allocator, .{ .neighbor_down = peer }, now, &gossip_out);
                        },
                        else => {},
                    },
                    else => {},
                }
            }
            try self.pushGossip(allocator, &gossip_out);

            return try allocator.dupe(OutEvent(PI), self.outbox.items);
        }

        fn pushSwarm(self: *@This(), allocator: std.mem.Allocator, list: *std.ArrayList(hyparview.OutEvent(PI))) !void {
            while (list.items.len > 0) {
                const ev = list.items[0];
                try self.outbox.append(allocator, switch (ev) {
                    .send_message => |sm| OutEvent(PI){ .send_message = .{ .to = sm.to, .message = .{ .swarm = sm.message } } },
                    .schedule_timer => |st| OutEvent(PI){ .schedule_timer = .{ .delay_ns = st.delay_ns, .timer = .{ .swarm = st.timer } } },
                    .disconnect_peer => |p| OutEvent(PI){ .disconnect_peer = p },
                    .emit_event => |e| OutEvent(PI){ .emit_event = switch (e) {
                        .neighbor_up => |p| .{ .neighbor_up = p },
                        .neighbor_down => |p| .{ .neighbor_down = p },
                    } },
                    .peer_data => |pd| OutEvent(PI){ .peer_data = .{ .peer = pd.peer, .data = pd.data } },
                });
                _ = list.orderedRemove(0);
            }
        }

        fn pushGossip(self: *@This(), allocator: std.mem.Allocator, list: *std.ArrayList(plumtree.OutEvent(PI))) !void {
            while (list.items.len > 0) {
                const ev = list.items[0];
                try self.outbox.append(allocator, switch (ev) {
                    .send_message => |sm| OutEvent(PI){ .send_message = .{ .to = sm.to, .message = .{ .gossip = sm.message } } },
                    .schedule_timer => |st| OutEvent(PI){ .schedule_timer = .{ .delay_ns = st.delay_ns, .timer = .{ .gossip = st.timer } } },
                    .emit_event => |e| OutEvent(PI){ .emit_event = .{ .received = e.received } },
                });
                _ = list.orderedRemove(0);
            }
        }

        fn deinitSwarmOutEvents(allocator: std.mem.Allocator, events: []const hyparview.OutEvent(PI)) void {
            for (events) |event| switch (event) {
                .send_message => |sent| sent.message.deinit(allocator),
                else => {},
            };
        }

        fn deinitGossipOutEvents(allocator: std.mem.Allocator, events: []const plumtree.OutEvent(PI)) void {
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
