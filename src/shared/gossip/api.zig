//! Public GossipApi — Zig-idiomatic join/topic/control surface over quic_net.Node.
//!
//! Behavioral targets (feature discovery from iroh-gossip api.rs, not a Rust-shape copy):
//! subscribe with options (immediate return or wait-for-join), per-topic sender/receiver
//! handles with split-lifetime semantics, NeighborUp/Down/Received/Lagged events, bounded
//! subscriber capacity, multi-subscriber fanout + neighbor replay, cooperative actor pump,
//! membership/broadcast/ALPN builder knobs, and a local control-plane.
const std = @import("std");
const key = @import("../key.zig");
const protocol = @import("../protocol.zig");
// Fork-isolation S3: `protocol.zig` moved into shared/, so this file (held
// back in S2 as the last legacy-backed gossip remnant) joins its siblings.
// Only `Connection`/`NodeAddr` are used from the transport surface — they
// arrive through the per-product DOOR module (`transport`), same declarations
// the legacy `transport.zig` re-exports (type identity preserved).
const transport = @import("transport");
const shared_gossip = @import("gossip.zig");
const quic_net = shared_gossip.quic_net;
const metrics_mod = shared_gossip.metrics;
const types = shared_gossip.types;
const hyparview = shared_gossip.hyparview;
const plumtree = shared_gossip.plumtree;
const state_mod = shared_gossip.state;

pub const TopicId = quic_net.TopicId;
pub const NodeId = quic_net.NodeId;
pub const Scope = quic_net.Scope;
pub const Metrics = metrics_mod.Metrics;
pub const GOSSIP_ALPN: [:0]const u8 = "/iroh-gossip/1";
pub const MembershipConfig = hyparview.Config;
pub const BroadcastConfig = plumtree.Config;
pub const ProtocolConfig = state_mod.Config;

pub const Error = error{
    TopicNotJoined,
    TopicAlreadyJoined,
    ActorStopped,
    UnknownTopic,
    InvalidArgument,
    ControlRejected,
    Closed,
    CommandChannelFull,
} || quic_net.Error;

pub const JoinOptions = struct {
    bootstrap: []const NodeId = &.{},
    /// Per-subscriber event capacity. When full, oldest events are dropped
    /// and a Lagged signal is delivered (iroh-gossip JoinOptions.subscription_capacity).
    subscription_capacity: usize = 64,
    /// When true, subscribe blocks (via pump) until at least one neighbor is up.
    wait_for_join: bool = false,

    pub fn withBootstrap(bootstrap: []const NodeId) JoinOptions {
        return .{ .bootstrap = bootstrap };
    }
};

pub const Event = union(enum) {
    neighbor_up: NodeId,
    neighbor_down: NodeId,
    received: struct {
        content: []const u8,
        delivered_from: NodeId,
        scope: types.DeliveryScope,
    },
    lagged,

    pub fn deinit(self: Event, allocator: std.mem.Allocator) void {
        switch (self) {
            .received => |r| allocator.free(r.content),
            else => {},
        }
    }
};

const Subscriber = struct {
    id: u64,
    capacity: usize,
    events: std.ArrayList(Event) = .empty,
    /// Head index into events: pops advance the head instead of shifting the
    /// tail (regression lane-05 H1 — orderedRemove(0) made each pop O(n)).
    /// Invariant: head <= items.len; a fully-drained queue resets to 0.
    head: usize = 0,
    alive: bool = true,

    fn pendingCount(self: *const Subscriber) usize {
        return self.events.items.len - self.head;
    }

    fn deinit(self: *Subscriber, allocator: std.mem.Allocator) void {
        for (self.events.items[self.head..]) |e| e.deinit(allocator);
        self.events.deinit(allocator);
    }

    /// Returns true when this push produced a Lagged signal (capacity exceeded).
    fn push(self: *Subscriber, allocator: std.mem.Allocator, event: Event) !bool {
        if (!self.alive) {
            event.deinit(allocator);
            return false;
        }
        if (self.pendingCount() < self.capacity) {
            try self.events.append(allocator, event);
            return false;
        }
        // Over capacity: drop the incoming event and ensure a single Lagged marker.
        event.deinit(allocator);
        if (self.pendingCount() > 0) {
            switch (self.events.items[self.events.items.len - 1]) {
                .lagged => return true,
                else => {},
            }
            const dropped = self.events.items[self.head];
            self.head += 1;
            dropped.deinit(allocator);
        }
        try self.events.append(allocator, .lagged);
        return true;
    }
};

const TopicState = struct {
    topic: TopicId,
    subscribers: std.ArrayList(Subscriber) = .empty,
    /// Shared topic still joined in the protocol while any local half needs it.
    sender_refs: u32 = 0,
    receiver_refs: u32 = 0,
    closed: bool = false,

    fn deinit(self: *TopicState, allocator: std.mem.Allocator) void {
        for (self.subscribers.items) |*sub| sub.deinit(allocator);
        self.subscribers.deinit(allocator);
    }

    fn liveSubscriberCount(self: *const TopicState) usize {
        var n: usize = 0;
        for (self.subscribers.items) |sub| {
            if (sub.alive) n += 1;
        }
        return n;
    }

    fn unused(self: *const TopicState) bool {
        return self.sender_refs == 0 and self.receiver_refs == 0 and self.liveSubscriberCount() == 0;
    }

    fn findSub(self: *TopicState, id: u64) ?*Subscriber {
        for (self.subscribers.items) |*sub| {
            if (sub.id == id) return sub;
        }
        return null;
    }
};

/// Cooperative production actor: serializes commands onto the Node and fans events
/// to per-topic subscribers. Zig shape is a pump loop (not a Tokio task).
pub const GossipApi = struct {
    allocator: std.mem.Allocator,
    node: quic_net.Node,
    mutex: std.Io.Mutex = .init,
    topics: std.ArrayList(TopicState),
    metrics: Metrics = .{},
    stopped: bool = false,
    next_sub_id: u64 = 1,
    command_channel_capacity: usize,
    /// Set by pump: the last pump observed real work (node activity or user
    /// events drained). The handler loop sleeps only when this is false
    /// (lane-05 H2).
    last_pump_active: bool = false,

    pub const Builder = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        secret: key.SecretKey,
        alpn: [:0]const u8 = GOSSIP_ALPN,
        options: quic_net.Options = .{},

        pub fn maxMessageSize(self: Builder, size: usize) Builder {
            var next = self;
            next.options.protocol.max_message_size = size;
            return next;
        }

        pub fn withAlpn(self: Builder, value: [:0]const u8) Builder {
            var next = self;
            next.alpn = value;
            return next;
        }

        pub fn membershipConfig(self: Builder, config: MembershipConfig) Builder {
            var next = self;
            next.options.protocol.membership = config;
            return next;
        }

        pub fn broadcastConfig(self: Builder, config: BroadcastConfig) Builder {
            var next = self;
            next.options.protocol.broadcast = config;
            return next;
        }

        pub fn commandChannelCapacity(self: Builder, capacity: usize) Builder {
            var next = self;
            next.options.command_channel_capacity = capacity;
            return next;
        }

        pub fn build(self: Builder) !GossipApi {
            const node = try quic_net.Node.initOptions(self.allocator, self.io, self.secret, self.alpn, self.options);
            return .{
                .allocator = self.allocator,
                .node = node,
                .topics = .empty,
                .command_channel_capacity = if (self.options.command_channel_capacity == 0)
                    1
                else
                    self.options.command_channel_capacity,
            };
        }
    };

    pub fn builder(allocator: std.mem.Allocator, io: std.Io, secret: key.SecretKey) Builder {
        return .{ .allocator = allocator, .io = io, .secret = secret };
    }

    pub fn deinit(self: *GossipApi) void {
        self.shutdown() catch {};
        self.lockState();
        for (self.topics.items) |*slot| slot.deinit(self.allocator);
        self.topics.deinit(self.allocator);
        self.unlockState();
        self.node.deinit();
    }

    pub fn maxMessageSize(self: *GossipApi) usize {
        self.lockState();
        defer self.unlockState();
        return self.node.maxMessageSize();
    }

    pub fn localId(self: *GossipApi) NodeId {
        self.lockState();
        defer self.unlockState();
        return self.node.id;
    }

    pub fn localAddress(self: *GossipApi) std.Io.net.IpAddress {
        self.lockState();
        defer self.unlockState();
        return self.node.localAddress();
    }

    pub fn alpn(self: *GossipApi) [:0]const u8 {
        self.lockState();
        defer self.unlockState();
        return self.node.gossipAlpn();
    }

    pub fn membershipConfig(self: *GossipApi) MembershipConfig {
        self.lockState();
        defer self.unlockState();
        return self.node.protocolConfig().membership;
    }

    pub fn broadcastConfig(self: *GossipApi) BroadcastConfig {
        self.lockState();
        defer self.unlockState();
        return self.node.protocolConfig().broadcast;
    }

    pub fn commandChannelCapacity(self: *GossipApi) usize {
        self.lockState();
        defer self.unlockState();
        return self.command_channel_capacity;
    }

    pub fn registerPeer(self: *GossipApi, peer: NodeId, addr: transport.NodeAddr) Error!void {
        self.lockState();
        defer self.unlockState();
        try self.node.registerPeer(peer, addr);
    }

    pub fn addConnection(self: *GossipApi, conn: transport.Connection) Error!void {
        self.lockState();
        defer self.unlockState();
        try self.node.addConnection(conn);
    }

    /// Join without waiting for a neighbor (subscribe_with_opts semantics).
    /// Multiple local subscribers to the same topic share protocol state and receive fanout.
    pub fn subscribeWithOptions(self: *GossipApi, topic: TopicId, opts: JoinOptions) Error!GossipTopic {
        const handle = blk: {
            self.lockState();
            errdefer self.unlockState();
            const handle = try self.subscribeWithOptionsLocked(topic, opts);
            self.unlockState();
            break :blk handle;
        };
        if (opts.wait_for_join) {
            try self.waitAndConsumeJoined(topic, handle.sub_id);
        }
        return handle;
    }

    fn subscribeWithOptionsLocked(self: *GossipApi, topic: TopicId, opts: JoinOptions) Error!GossipTopic {
        if (self.stopped) return error.ActorStopped;
        const capacity = if (opts.subscription_capacity == 0) 1 else opts.subscription_capacity;

        if (self.findTopicPtr(topic)) |ts| {
            if (ts.closed) return error.Closed;
            // Additional local subscriber on an already-joined topic.
            const sub_id = self.next_sub_id;
            self.next_sub_id += 1;
            try ts.subscribers.append(self.allocator, .{
                .id = sub_id,
                .capacity = capacity,
            });
            ts.sender_refs += 1;
            ts.receiver_refs += 1;
            // Replay current neighbors as NeighborUp for the new subscriber.
            try self.replayNeighborsToLocked(ts, sub_id);
            return .{ .api = self, .topic = topic, .sub_id = sub_id };
        }

        try self.node.join(topic, opts.bootstrap);
        self.metrics.joins += 1;
        const sub_id = self.next_sub_id;
        self.next_sub_id += 1;
        try self.topics.append(self.allocator, .{
            .topic = topic,
            .sender_refs = 1,
            .receiver_refs = 1,
        });
        const ts = self.findTopicPtr(topic).?;
        try ts.subscribers.append(self.allocator, .{
            .id = sub_id,
            .capacity = capacity,
        });
        return .{ .api = self, .topic = topic, .sub_id = sub_id };
    }

    pub fn subscribe(self: *GossipApi, topic: TopicId, bootstrap: []const NodeId) Error!GossipTopic {
        return self.subscribeWithOptions(topic, .{ .bootstrap = bootstrap });
    }

    pub fn subscribeAndJoin(self: *GossipApi, topic: TopicId, bootstrap: []const NodeId) Error!GossipTopic {
        return self.subscribeWithOptions(topic, .{ .bootstrap = bootstrap, .wait_for_join = true });
    }

    pub fn pump(self: *GossipApi) Error!void {
        self.lockState();
        defer self.unlockState();
        _ = try self.pumpLocked();
    }

    fn pumpAndReportActive(self: *GossipApi) Error!bool {
        self.lockState();
        defer self.unlockState();
        return self.pumpLocked();
    }

    fn pumpLocked(self: *GossipApi) Error!bool {
        if (self.stopped) return error.ActorStopped;
        try self.node.pump();
        self.metrics.pumps += 1;
        var active = self.node.last_pump_active;
        while (self.node.popUserEvent()) |event| {
            active = true;
            switch (event) {
                .neighbor_up => |nu| {
                    if (self.findTopicPtr(nu.topic)) |ts| {
                        try self.fanout(ts, .{ .neighbor_up = nu.peer });
                    }
                },
                .neighbor_down => |nd| {
                    if (self.findTopicPtr(nd.topic)) |ts| {
                        try self.fanout(ts, .{ .neighbor_down = nd.peer });
                    }
                },
                .received => |r| {
                    defer r.deinit(self.allocator);
                    if (self.findTopicPtr(r.topic)) |ts| {
                        // Fan a private content copy per live subscriber.
                        for (ts.subscribers.items) |*sub| {
                            if (!sub.alive) continue;
                            const owned = try self.allocator.dupe(u8, r.content);
                            errdefer self.allocator.free(owned);
                            if (try sub.push(self.allocator, .{ .received = .{
                                .content = owned,
                                .delivered_from = r.delivered_from,
                                .scope = r.scope,
                            } })) {
                                self.metrics.lagged += 1;
                            } else {
                                self.metrics.messages_received += 1;
                            }
                        }
                    }
                },
            }
        }
        self.last_pump_active = active;
        return active;
    }

    pub fn shutdown(self: *GossipApi) Error!void {
        self.lockState();
        defer self.unlockState();
        try self.shutdownLocked();
    }

    fn shutdownLocked(self: *GossipApi) Error!void {
        if (self.stopped) return;
        try self.node.shutdown();
        self.stopped = true;
        self.metrics.shutdowns += 1;
        for (self.topics.items) |*ts| {
            ts.closed = true;
            ts.sender_refs = 0;
            ts.receiver_refs = 0;
            for (ts.subscribers.items) |*sub| sub.alive = false;
        }
    }

    pub fn metricsSnapshot(self: *GossipApi) Metrics {
        self.lockState();
        defer self.unlockState();
        return self.metrics;
    }

    /// Local control-plane ops (Zig stand-in for iroh-gossip RPC/noq surface).
    pub fn control(self: *GossipApi, op: ControlOp) Error!ControlResult {
        self.lockState();
        defer self.unlockState();
        if (self.stopped) {
            self.metrics.control_errors += 1;
            return error.ActorStopped;
        }
        self.metrics.control_ops += 1;
        switch (op) {
            .join => |j| {
                _ = try self.subscribeWithOptionsLocked(j.topic, .{ .bootstrap = j.bootstrap });
                return .{ .ok = {} };
            },
            .leave => |topic| {
                try self.leaveTopicLocked(topic);
                return .{ .ok = {} };
            },
            .broadcast => |b| {
                try self.broadcastTopicLocked(b.topic, b.content, .swarm);
                return .{ .ok = {} };
            },
            .broadcast_neighbors => |b| {
                try self.broadcastTopicLocked(b.topic, b.content, .neighbors);
                return .{ .ok = {} };
            },
            .status => {
                var topics = try self.allocator.alloc(TopicId, self.topics.items.len);
                for (self.topics.items, 0..) |slot, i| topics[i] = slot.topic;
                return .{ .status = .{
                    .local_id = self.node.id,
                    .joined_topics = topics,
                    .max_message_size = self.node.maxMessageSize(),
                    .stopped = self.stopped,
                    .alpn = self.node.gossipAlpn(),
                    .membership_active = self.node.protocolConfig().membership.active_view_capacity,
                    .membership_passive = self.node.protocolConfig().membership.passive_view_capacity,
                    .command_channel_capacity = self.command_channel_capacity,
                } };
            },
            .list_topics => {
                var topics = try self.allocator.alloc(TopicId, self.topics.items.len);
                for (self.topics.items, 0..) |slot, i| topics[i] = slot.topic;
                return .{ .topics = topics };
            },
        }
    }

    /// ProtocolHandler that feeds accepted Router connections into this actor.
    pub fn protocolHandler(self: *GossipApi) protocol.ProtocolHandler {
        return .{
            .context = self,
            .vtable = &handler_vtable,
        };
    }

    fn handlerAccept(ctx: *anyopaque, connection: transport.Connection) anyerror!void {
        const self: *GossipApi = @ptrCast(@alignCast(ctx));
        try self.addConnection(connection);
        const io = self.ioHandle();
        // Keep the handler thread alive while the actor pumps the connection.
        // The router joins this thread on shutdown; cooperative progress is via pump.
        // Regression lane-05 H2: sleep is bounded by actual work — pump
        // back-to-back while the actor is making progress, back off
        // exponentially (1→32 ms) only while it is idle, instead of waking
        // 1000×/s per accepted connection regardless of activity.
        var idle_streak: u32 = 0;
        while (true) {
            const active = self.pumpAndReportActive() catch |err| switch (err) {
                error.ActorStopped => break,
                else => return err,
            };
            if (active) {
                idle_streak = 0;
                continue;
            }
            idle_streak +|= 1;
            io.sleep(std.Io.Duration.fromMilliseconds(@intCast(GossipApi.idleBackoffMs(idle_streak))), .awake) catch {};
        }
    }

    /// Exponential idle backoff for the handler pump loop: 1 ms initially
    /// (matching the old flat sleep), doubling to a 32 ms cap.
    fn idleBackoffMs(idle_streak: u32) u64 {
        if (idle_streak == 0) return 1;
        const shift: u6 = @intCast(@min(idle_streak - 1, 5));
        return @as(u64, 1) << shift;
    }

    fn handlerShutdown(ctx: *anyopaque) void {
        const self: *GossipApi = @ptrCast(@alignCast(ctx));
        self.shutdown() catch {};
    }

    const handler_vtable: protocol.ProtocolHandler.VTable = .{
        .accept = handlerAccept,
        .shutdown = handlerShutdown,
    };

    fn lockState(self: *GossipApi) void {
        self.mutex.lockUncancelable(self.node.io);
    }

    fn unlockState(self: *GossipApi) void {
        self.mutex.unlock(self.node.io);
    }

    fn ioHandle(self: *GossipApi) std.Io {
        self.lockState();
        defer self.unlockState();
        return self.node.io;
    }

    fn fanout(self: *GossipApi, ts: *TopicState, event: Event) !void {
        // Clone non-owned events for each subscriber (received is handled separately).
        var first = true;
        for (ts.subscribers.items) |*sub| {
            if (!sub.alive) continue;
            const ev: Event = if (first) event else switch (event) {
                .neighbor_up => |p| .{ .neighbor_up = p },
                .neighbor_down => |p| .{ .neighbor_down = p },
                .lagged => .lagged,
                .received => unreachable, // handled in pump
            };
            first = false;
            if (try sub.push(self.allocator, ev)) {
                self.metrics.lagged += 1;
            } else {
                switch (event) {
                    .neighbor_up => self.metrics.neighbor_ups += 1,
                    .neighbor_down => self.metrics.neighbor_downs += 1,
                    else => {},
                }
            }
        }
        if (first) {
            // No live subscribers — drop.
            event.deinit(self.allocator);
        }
    }

    fn replayNeighborsToLocked(self: *GossipApi, ts: *TopicState, sub_id: u64) !void {
        const sub = ts.findSub(sub_id) orelse return;
        const peers = try self.node.listNeighbors(self.allocator, ts.topic);
        defer self.allocator.free(peers);
        for (peers) |peer| {
            if (try sub.push(self.allocator, .{ .neighbor_up = peer })) {
                self.metrics.lagged += 1;
            } else {
                self.metrics.neighbor_ups += 1;
            }
        }
    }

    /// Wait until a neighbor exists and consume the first NeighborUp from the subscriber stream.
    fn waitAndConsumeJoined(self: *GossipApi, topic: TopicId, sub_id: u64) Error!void {
        const io = self.ioHandle();
        const hang_ns: u64 = 30 * std.time.ns_per_s;
        const start: u64 = @intCast(std.Io.Clock.now(.awake, io).nanoseconds);
        while (true) {
            const now: u64 = @intCast(std.Io.Clock.now(.awake, io).nanoseconds);
            if (now - start > hang_ns) return error.HangWatchdog;

            self.lockState();
            defer self.unlockState();
            _ = try self.pumpLocked();
            const ts = self.findTopicPtr(topic) orelse return error.UnknownTopic;
            const sub = ts.findSub(sub_id) orelse return error.UnknownTopic;
            if (!sub.alive) return error.Closed;
            // Scan for NeighborUp without dropping other events permanently.
            var i: usize = sub.head;
            while (i < sub.events.items.len) : (i += 1) {
                switch (sub.events.items[i]) {
                    .neighbor_up => {
                        const ev = sub.events.orderedRemove(i);
                        ev.deinit(self.allocator);
                        return;
                    },
                    else => {},
                }
            }
        }
    }

    fn leaveTopicLocked(self: *GossipApi, topic: TopicId) Error!void {
        const idx = self.findTopicIndex(topic) orelse return error.UnknownTopic;
        try self.node.leave(topic);
        self.metrics.leaves += 1;
        var slot = self.topics.swapRemove(idx);
        slot.closed = true;
        slot.deinit(self.allocator);
    }

    /// Auto-quit protocol topic state when no local sender/receiver still needs it.
    fn maybeAutoQuitLocked(self: *GossipApi, topic: TopicId) Error!void {
        const idx = self.findTopicIndex(topic) orelse return;
        if (!self.topics.items[idx].unused()) return;
        try self.leaveTopicLocked(topic);
    }

    fn broadcastTopicLocked(self: *GossipApi, topic: TopicId, content: []const u8, scope: Scope) Error!void {
        const ts = self.findTopicPtr(topic) orelse return error.TopicNotJoined;
        if (ts.closed) return error.Closed;
        if (ts.sender_refs == 0) return error.Closed;
        try self.node.broadcastScope(topic, content, scope);
        switch (scope) {
            .swarm => self.metrics.broadcasts += 1,
            .neighbors => self.metrics.neighbor_only_broadcasts += 1,
        }
    }

    fn popSubEventLocked(self: *GossipApi, topic: TopicId, sub_id: u64) Error!?Event {
        const ts = self.findTopicPtr(topic) orelse return error.UnknownTopic;
        if (ts.closed) return error.Closed;
        const sub = ts.findSub(sub_id) orelse return error.UnknownTopic;
        if (!sub.alive) return error.Closed;
        if (sub.head >= sub.events.items.len) return null;
        const ev = sub.events.items[sub.head];
        sub.head += 1;
        if (sub.head == sub.events.items.len) {
            // Drained: reset so pushes reuse the capacity.
            sub.events.clearRetainingCapacity();
            sub.head = 0;
        }
        return ev;
    }

    fn joinedTopicHandle(self: *GossipApi, handle: *GossipTopic) Error!void {
        const topic = blk: {
            self.lockState();
            defer self.unlockState();
            if (!handle.receiver_open) return error.Closed;
            const ts = self.findTopicPtr(handle.topic) orelse return error.Closed;
            if (ts.closed) return error.Closed;
            break :blk handle.topic;
        };
        try self.waitAndConsumeJoined(topic, handle.sub_id);
    }

    fn isJoinedTopicHandle(self: *GossipApi, handle: *const GossipTopic) bool {
        self.lockState();
        defer self.unlockState();
        if (self.stopped) return false;
        const ts = self.findTopicPtr(handle.topic) orelse return false;
        if (ts.closed) return false;
        return self.node.isJoined(handle.topic);
    }

    fn neighborsTopicHandle(self: *GossipApi, handle: *const GossipTopic, allocator: std.mem.Allocator) Error![]NodeId {
        self.lockState();
        defer self.unlockState();
        const ts = self.findTopicPtr(handle.topic) orelse return error.Closed;
        if (ts.closed) return error.Closed;
        return self.node.listNeighbors(allocator, handle.topic);
    }

    fn joinPeersTopicHandle(self: *GossipApi, handle: *GossipTopic, peers: []const NodeId) Error!void {
        self.lockState();
        defer self.unlockState();
        const ts = self.findTopicPtr(handle.topic) orelse return error.Closed;
        if (ts.closed) return error.Closed;
        try self.node.joinPeers(handle.topic, peers);
    }

    fn dropSenderHandle(self: *GossipApi, handle: *GossipTopic) Error!void {
        self.lockState();
        defer self.unlockState();
        if (!handle.sender_open) return;
        handle.sender_open = false;
        if (self.findTopicPtr(handle.topic)) |ts| {
            if (ts.sender_refs > 0) ts.sender_refs -= 1;
            try self.maybeAutoQuitLocked(handle.topic);
        }
    }

    fn dropReceiverHandle(self: *GossipApi, handle: *GossipTopic) Error!void {
        self.lockState();
        defer self.unlockState();
        if (!handle.receiver_open) return;
        handle.receiver_open = false;
        if (self.findTopicPtr(handle.topic)) |ts| {
            if (ts.findSub(handle.sub_id)) |sub| sub.alive = false;
            if (ts.receiver_refs > 0) ts.receiver_refs -= 1;
            try self.maybeAutoQuitLocked(handle.topic);
        }
    }

    fn closeTopicHandle(self: *GossipApi, handle: *GossipTopic) Error!void {
        self.lockState();
        defer self.unlockState();

        if (handle.sender_open) {
            handle.sender_open = false;
            if (self.findTopicPtr(handle.topic)) |ts| {
                if (ts.sender_refs > 0) ts.sender_refs -= 1;
            }
        }

        if (handle.receiver_open) {
            handle.receiver_open = false;
            if (self.findTopicPtr(handle.topic)) |ts| {
                if (ts.findSub(handle.sub_id)) |sub| sub.alive = false;
                if (ts.receiver_refs > 0) ts.receiver_refs -= 1;
            }
        }

        try self.maybeAutoQuitLocked(handle.topic);
    }

    fn broadcastHandle(self: *GossipApi, handle: *GossipTopic, content: []const u8, scope: Scope) Error!void {
        self.lockState();
        defer self.unlockState();
        if (!handle.sender_open) return error.Closed;
        try self.broadcastTopicLocked(handle.topic, content, scope);
    }

    fn popHandleEvent(self: *GossipApi, handle: *GossipTopic) Error!?Event {
        self.lockState();
        defer self.unlockState();
        if (!handle.receiver_open) return error.Closed;
        return self.popSubEventLocked(handle.topic, handle.sub_id);
    }

    fn recordControlError(self: *GossipApi) void {
        self.lockState();
        defer self.unlockState();
        self.metrics.control_errors += 1;
    }

    fn findTopic(self: *const GossipApi, topic: TopicId) ?*const TopicState {
        for (self.topics.items) |*slot| {
            if (std.mem.eql(u8, &slot.topic, &topic)) return slot;
        }
        return null;
    }

    fn findTopicPtr(self: *GossipApi, topic: TopicId) ?*TopicState {
        for (self.topics.items) |*slot| {
            if (std.mem.eql(u8, &slot.topic, &topic)) return slot;
        }
        return null;
    }

    fn findTopicIndex(self: *const GossipApi, topic: TopicId) ?usize {
        for (self.topics.items, 0..) |slot, i| {
            if (std.mem.eql(u8, &slot.topic, &topic)) return i;
        }
        return null;
    }

    /// Minimal external control-plane listener (Zig stand-in for iroh-gossip's
    /// irpc-over-noq RPC). Speaks one-shot text commands over TCP:
    ///   STATUS\n → OK max=<n> topics=<k>\n
    ///   LEAVE <64-hex-topic>\n → OK\n / ERR ...\n
    ///   BROADCAST <64-hex-topic> <msg>\n → OK\n / ERR ...\n
    /// Not wire-compatible with Rust irpc (documented design deviation).
    pub fn serveControlOnce(self: *GossipApi, listener: *std.Io.net.Server) !void {
        const io = self.ioHandle();
        const stream = try listener.accept(io);
        defer stream.close(io);
        var rbuf: [512]u8 = undefined;
        var reader = stream.reader(io, &rbuf);
        const raw = (try reader.interface.takeDelimiter('\n')) orelse return error.ControlRejected;
        const line = std.mem.trimEnd(u8, raw, "\r");
        var wbuf: [256]u8 = undefined;
        var writer = stream.writer(io, &wbuf);
        const out = &writer.interface;

        if (std.mem.eql(u8, line, "STATUS")) {
            const result = try self.control(.status);
            defer result.deinit(self.allocator);
            switch (result) {
                .status => |s| try out.print("OK max={d} topics={d}\n", .{ s.max_message_size, s.joined_topics.len }),
                else => try out.writeAll("ERR bad\n"),
            }
        } else if (std.mem.startsWith(u8, line, "LEAVE ")) {
            const hex = line["LEAVE ".len..];
            var topic: TopicId = undefined;
            _ = try std.fmt.hexToBytes(&topic, hex);
            _ = try self.control(.{ .leave = topic });
            try out.writeAll("OK\n");
        } else if (std.mem.startsWith(u8, line, "BROADCAST ")) {
            const rest = line["BROADCAST ".len..];
            if (rest.len < 65) return error.InvalidArgument;
            var topic: TopicId = undefined;
            _ = try std.fmt.hexToBytes(&topic, rest[0..64]);
            const msg = rest[65..];
            _ = try self.control(.{ .broadcast = .{ .topic = topic, .content = msg } });
            try out.writeAll("OK\n");
        } else {
            self.recordControlError();
            try out.writeAll("ERR unknown\n");
        }
        try out.flush();
    }
};

pub const GossipTopic = struct {
    api: *GossipApi,
    topic: TopicId,
    sub_id: u64,
    sender_open: bool = true,
    receiver_open: bool = true,

    pub fn sender(self: *GossipTopic) GossipSender {
        return .{ .topic = self };
    }

    pub fn receiver(self: *GossipTopic) GossipReceiver {
        return .{ .topic = self };
    }

    /// Wait until ≥1 neighbor is connected and consume the first NeighborUp from the stream.
    pub fn joined(self: *GossipTopic) Error!void {
        try self.api.joinedTopicHandle(self);
    }

    /// Whether this topic currently has ≥1 direct neighbor.
    pub fn isJoined(self: *const GossipTopic) bool {
        return self.api.isJoinedTopicHandle(self);
    }

    /// Snapshot of current direct neighbors (caller frees).
    pub fn neighbors(self: *const GossipTopic, allocator: std.mem.Allocator) Error![]NodeId {
        return self.api.neighborsTopicHandle(self, allocator);
    }

    /// After subscribe, join additional bootstrap peers.
    pub fn joinPeers(self: *GossipTopic, peers: []const NodeId) Error!void {
        try self.api.joinPeersTopicHandle(self, peers);
    }

    /// Drop the sender half without closing the topic if a receiver remains.
    pub fn dropSender(self: *GossipTopic) Error!void {
        try self.api.dropSenderHandle(self);
    }

    /// Drop the receiver half without closing the topic if a sender remains.
    pub fn dropReceiver(self: *GossipTopic) Error!void {
        try self.api.dropReceiverHandle(self);
    }

    pub fn close(self: *GossipTopic) Error!void {
        try self.api.closeTopicHandle(self);
    }
};

pub const GossipSender = struct {
    topic: *GossipTopic,

    pub fn broadcast(self: GossipSender, content: []const u8) Error!void {
        try self.topic.api.broadcastHandle(self.topic, content, .swarm);
    }

    pub fn broadcastNeighbors(self: GossipSender, content: []const u8) Error!void {
        try self.topic.api.broadcastHandle(self.topic, content, .neighbors);
    }

    pub fn drop(self: GossipSender) Error!void {
        try self.topic.dropSender();
    }
};

pub const GossipReceiver = struct {
    topic: *GossipTopic,

    pub fn next(self: GossipReceiver) Error!?Event {
        return self.topic.api.popHandleEvent(self.topic);
    }

    pub fn drop(self: GossipReceiver) Error!void {
        try self.topic.dropReceiver();
    }
};

pub const ControlOp = union(enum) {
    join: struct { topic: TopicId, bootstrap: []const NodeId },
    leave: TopicId,
    broadcast: struct { topic: TopicId, content: []const u8 },
    broadcast_neighbors: struct { topic: TopicId, content: []const u8 },
    status,
    list_topics,
};

pub const ControlStatus = struct {
    local_id: NodeId,
    joined_topics: []TopicId,
    max_message_size: usize,
    stopped: bool,
    alpn: [:0]const u8 = GOSSIP_ALPN,
    membership_active: usize = 5,
    membership_passive: usize = 30,
    command_channel_capacity: usize = 128,

    pub fn deinit(self: ControlStatus, allocator: std.mem.Allocator) void {
        allocator.free(self.joined_topics);
    }
};

pub const ControlResult = union(enum) {
    ok,
    status: ControlStatus,
    topics: []TopicId,

    pub fn deinit(self: ControlResult, allocator: std.mem.Allocator) void {
        switch (self) {
            .status => |s| s.deinit(allocator),
            .topics => |t| allocator.free(t),
            .ok => {},
        }
    }
};

test "JoinOptions withBootstrap defaults" {
    const peers = [_]NodeId{key.SecretKey.fromBytes(.{0x11} ** 32).public()};
    const opts = JoinOptions.withBootstrap(&peers);
    try std.testing.expectEqual(@as(usize, 1), opts.bootstrap.len);
    try std.testing.expectEqual(@as(usize, 64), opts.subscription_capacity);
    try std.testing.expect(!opts.wait_for_join);
}

test "Builder configures max message size, alpn, membership, broadcast, command capacity" {
    const secret = key.SecretKey.fromBytes(.{0x61} ** 32);
    const custom_alpn: [:0]const u8 = "/iroh-gossip/test";
    var api = try GossipApi.builder(std.testing.allocator, std.testing.io, secret)
        .maxMessageSize(types.DEFAULT_MAX_MESSAGE_SIZE)
        .withAlpn(custom_alpn)
        .membershipConfig(.{ .active_view_capacity = 3, .passive_view_capacity = 9 })
        .broadcastConfig(.{ .optimization_threshold = .{ .value = 4 } })
        .commandChannelCapacity(7)
        .build();
    defer api.deinit();
    try std.testing.expectEqual(types.DEFAULT_MAX_MESSAGE_SIZE, api.maxMessageSize());
    try std.testing.expectEqualStrings(custom_alpn, api.alpn());
    try std.testing.expectEqual(@as(usize, 3), api.membershipConfig().active_view_capacity);
    try std.testing.expectEqual(@as(usize, 9), api.membershipConfig().passive_view_capacity);
    try std.testing.expectEqual(@as(u16, 4), api.broadcastConfig().optimization_threshold.value);
    try std.testing.expectEqual(@as(usize, 7), api.commandChannelCapacity());
}

test "hyparview default view capacities are active=5 passive=30" {
    const cfg = MembershipConfig{};
    try std.testing.expectEqual(@as(usize, 5), cfg.active_view_capacity);
    try std.testing.expectEqual(@as(usize, 30), cfg.passive_view_capacity);
}

test "ioless protocol state machine is constructible without IO" {
    const alloc = std.testing.allocator;
    const rng = std.Random.DefaultPrng.init(0);
    const me: u32 = 1;
    const me_data: types.PeerData = "";
    var st = state_mod.State(u32, std.Random.DefaultPrng).init(me, me_data, .{}, rng);
    defer st.deinit(alloc);
    const out = try st.handle(alloc, .{ .command = .{ .topic = .{0} ** 32, .command = .{ .join = &.{} } } }, 0);
    defer alloc.free(out);
    try std.testing.expect(st.state(.{0} ** 32) != null);
}

test "Subscriber queue preserves FIFO order and lagged semantics with head-index pops" {
    // Regression lane-05 H1: pops advance a head index instead of orderedRemove(0).
    // Order, capacity, and the single-Lagged-marker behavior must be unchanged.
    const alloc = std.testing.allocator;
    const test_peer = key.SecretKey.fromBytes([_]u8{9} ** 32).public();
    var sub: Subscriber = .{ .id = 1, .capacity = 3 };
    defer sub.deinit(alloc);

    // Pushes take ownership; give each event its own dupe.
    _ = try sub.push(alloc, .{ .received = .{ .content = try alloc.dupe(u8, "a"), .delivered_from = test_peer, .scope = .{ .swarm = .{ .value = 1 } } } });
    _ = try sub.push(alloc, .{ .received = .{ .content = try alloc.dupe(u8, "b"), .delivered_from = test_peer, .scope = .{ .swarm = .{ .value = 1 } } } });
    _ = try sub.push(alloc, .{ .received = .{ .content = try alloc.dupe(u8, "c"), .delivered_from = test_peer, .scope = .{ .swarm = .{ .value = 1 } } } });
    try std.testing.expectEqual(@as(usize, 3), sub.pendingCount());

    // Fourth push exceeds capacity: oldest ("a") dropped, single lagged marker.
    const lagged = try sub.push(alloc, .{ .received = .{ .content = try alloc.dupe(u8, "d"), .delivered_from = test_peer, .scope = .{ .swarm = .{ .value = 1 } } } });
    try std.testing.expect(lagged);
    try std.testing.expectEqual(@as(usize, 3), sub.pendingCount());
    // Fifth push: last event is already .lagged — no second marker.
    const lagged2 = try sub.push(alloc, .{ .received = .{ .content = try alloc.dupe(u8, "e"), .delivered_from = test_peer, .scope = .{ .swarm = .{ .value = 1 } } } });
    try std.testing.expect(lagged2);
    try std.testing.expectEqual(@as(usize, 3), sub.pendingCount());

    // FIFO order across the head-index pops: b, c, lagged.
    const first = sub.events.items[sub.head];
    try std.testing.expectEqualStrings("b", first.received.content);
    const second = sub.events.items[sub.head + 1];
    try std.testing.expectEqualStrings("c", second.received.content);
    const third = sub.events.items[sub.head + 2];
    try std.testing.expect(third == .lagged);
}

test "idleBackoffMs starts at 1 ms and caps at 32 ms" {
    try std.testing.expectEqual(@as(u64, 1), GossipApi.idleBackoffMs(0));
    try std.testing.expectEqual(@as(u64, 1), GossipApi.idleBackoffMs(1));
    try std.testing.expectEqual(@as(u64, 2), GossipApi.idleBackoffMs(2));
    try std.testing.expectEqual(@as(u64, 4), GossipApi.idleBackoffMs(3));
    try std.testing.expectEqual(@as(u64, 32), GossipApi.idleBackoffMs(6));
    try std.testing.expectEqual(@as(u64, 32), GossipApi.idleBackoffMs(1000));
}
