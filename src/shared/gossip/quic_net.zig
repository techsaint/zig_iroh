//! QUIC-backed gossip network driver over real transport.Connection uni-streams.
const std = @import("std");
// Fork-isolation S2: the transport surface + engine-select factory arrive
// through the named DOOR module (legacy-backed until the S6/S7 cutover).
const transport = @import("transport");
const factory = @import("transport").factory;
const product_flags = @import("../product_flags.zig");
const key = @import("../key.zig");
const types = @import("types.zig");
const state = @import("proto/state.zig");
const frame = @import("frame.zig");
const util = @import("util.zig");
const net = @import("net.zig");
const postcard = @import("postcard.zig");

const GOSSIP_ALPN: [:0]const u8 = "/iroh-gossip/1";
const GossipPrng = std.Random.ChaCha;
pub const TopicId = types.TopicId;
pub const NodeId = key.NodeId;
pub const Scope = types.Scope;
pub const StreamHeader = types.StreamHeader;

pub const Error = error{
    PeerAddrUnknown,
    HangWatchdog,
    PumpLimit,
    InvalidConfiguration,
    CommandChannelFull,
    PendingDialQueueFull,
} || transport.Error || frame.Error || postcard.Error || std.mem.Allocator.Error;

const hang_watchdog_ns: u64 = 30 * std.time.ns_per_s;

pub const Received = struct {
    topic: TopicId,
    content: []const u8,
    delivered_from: NodeId,
    scope: types.DeliveryScope,

    pub fn deinit(self: Received, allocator: std.mem.Allocator) void {
        allocator.free(self.content);
    }
};

/// Peer-observable topic events surfaced for the public GossipApi event stream.
/// Distinct from the protocol-internal topic.Event — this queue is the user-facing
/// fanout (NeighborUp/Down/Received). Lag signaling is owned by the API layer's
/// per-subscriber capacity, not this global inbox.
pub const UserEvent = union(enum) {
    neighbor_up: struct { topic: TopicId, peer: NodeId },
    neighbor_down: struct { topic: TopicId, peer: NodeId },
    received: Received,

    pub fn deinit(self: UserEvent, allocator: std.mem.Allocator) void {
        switch (self) {
            .received => |r| r.deinit(allocator),
            else => {},
        }
    }
};

pub const Options = struct {
    protocol: state.Config = .{},
    endpoint: factory.Options = .{},
    max_received_messages: usize = 2048,
    max_user_events: usize = 4096,
    max_inbox_messages: usize = 1024,
    /// Bound on protocol command-style dispatches that may queue while a dial is in flight
    /// (Zig stand-in for iroh-gossip's actor command-channel capacity).
    command_channel_capacity: usize = 128,
    max_pending_dial_messages: usize = 64,
    max_inbound_frames_per_peer_per_pump: usize = 64,
    inbound_chunk_buffer_size: usize = 16 * 1024,
    max_learned_peers: usize = 4096,
    learned_peer_retention_ns: u64 = 5 * 60 * std.time.ns_per_s,
    learned_peer_eviction_interval_ns: u64 = 30 * std.time.ns_per_s,
};

const InboundStreamKey = struct {
    peer: NodeId,
    stream_id: u64,
};

const OutboundStreamKey = struct {
    peer: NodeId,
    topic: TopicId,
};

const ConnectionOrigin = enum { dialed, accepted };

const PeerConnection = struct {
    connection: transport.Connection,
    origin: ConnectionOrigin,
};

const InboundStreamState = struct {
    topic: ?TopicId = null,
    buffer: std.ArrayList(u8) = .empty,

    fn deinit(self: *InboundStreamState, allocator: std.mem.Allocator) void {
        self.buffer.deinit(allocator);
        self.* = .{};
    }
};

const FrameSlice = struct {
    body: []const u8,
    total_len: usize,
};

fn readFrameSlice(bytes: []const u8, limit: usize) Error!?FrameSlice {
    if (bytes.len < 4) return null;
    const len: usize = @intCast(std.mem.readInt(u32, bytes[0..4], .big));
    if (len > limit) return error.MessageTooLarge;
    if (bytes.len - 4 < len) return null;
    return .{
        .body = bytes[4..][0..len],
        .total_len = 4 + len,
    };
}

fn encodePeerData(allocator: std.mem.Allocator, direct_address: std.Io.net.IpAddress) ![]u8 {
    var writer = postcard.Writer.init(allocator);
    defer writer.deinit(allocator);

    // Rust AddrInfo { relay_url: None, direct_addresses: { direct_address } }.
    try writer.writeByte(allocator, 0);
    try writer.writeVarintUsize(allocator, 1);
    switch (direct_address) {
        .ip4 => |address| {
            try writer.writeEnumDiscriminant(allocator, 0);
            try writer.writeFixed(allocator, &address.bytes);
            try writer.writeVarintU16(allocator, address.port);
        },
        .ip6 => |address| {
            try writer.writeEnumDiscriminant(allocator, 1);
            try writer.writeFixed(allocator, &address.bytes);
            try writer.writeVarintU16(allocator, address.port);
        },
    }
    return allocator.dupe(u8, writer.written());
}

fn decodePeerData(allocator: std.mem.Allocator, peer: NodeId, data: []const u8) !transport.NodeAddr {
    if (data.len == 0) return transport.NodeAddr.new(peer);

    var reader = postcard.Reader.init(data);
    var addrs = std.ArrayList(transport.TransportAddr).empty;
    defer {
        for (addrs.items) |address| address.deinit(allocator);
        addrs.deinit(allocator);
    }

    switch (try reader.readByte()) {
        0 => {},
        1 => {
            const text = try reader.readBytes(allocator);
            defer allocator.free(text);
            const relay = try transport.RelayUrl.parse(allocator, text);
            errdefer relay.deinit(allocator);
            try addrs.append(allocator, .{ .relay = relay });
        },
        else => return error.InvalidOptionTag,
    }

    const direct_count = try reader.readVarintUsize();
    for (0..direct_count) |_| {
        const address: std.Io.net.IpAddress = switch (try reader.readEnumDiscriminant()) {
            0 => .{ .ip4 = .{
                .bytes = try reader.readFixed(4),
                .port = try reader.readVarintU16(),
            } },
            1 => .{ .ip6 = .{
                .bytes = try reader.readFixed(16),
                .port = try reader.readVarintU16(),
            } },
            else => return error.InvalidOptionTag,
        };
        try addrs.append(allocator, .{ .ip = address });
    }
    return transport.NodeAddr.fromParts(allocator, peer, addrs.items);
}

pub const Node = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: factory.AnyEndpoint,
    transport: transport.Transport,
    id: NodeId,
    protocol: state.State(NodeId, GossipPrng),
    peer_data: []u8,
    max_message_size: usize,
    max_received_messages: usize,
    max_user_events: usize,
    dropped_received_messages: usize = 0,
    dropped_user_events: usize = 0,
    max_inbox_messages: usize,
    command_channel_capacity: usize,
    max_pending_dial_messages: usize,
    /// Commands accepted since the last pump (Zig stand-in for a bounded actor channel).
    commands_since_pump: usize = 0,
    /// Set by pump: the last pump observed real work (accepted connection,
    /// inbound frames, fired timer, or a non-empty inbox). Lets cooperative
    /// pump loops sleep only when the actor is genuinely idle (lane-05 H2).
    last_pump_active: bool = false,
    max_inbound_frames_per_peer_per_pump: usize,
    max_learned_peers: usize,
    learned_peer_retention_ns: u64,
    learned_peer_eviction_interval_ns: u64,
    next_learned_peer_eviction_ns: u64 = 0,
    alpn: [:0]const u8,

    connections: std.AutoHashMapUnmanaged(NodeId, PeerConnection),
    peer_addrs: std.AutoHashMapUnmanaged(NodeId, transport.NodeAddr),
    learned_peer_updates: std.AutoHashMapUnmanaged(NodeId, u64),
    dialing: std.AutoHashMapUnmanaged(NodeId, void),
    pending_dial: std.AutoHashMapUnmanaged(NodeId, std.ArrayList(types.WireMessage(NodeId))),
    inbound_streams: std.AutoHashMapUnmanaged(InboundStreamKey, InboundStreamState),
    outbound_streams: std.AutoHashMapUnmanaged(OutboundStreamKey, transport.SendStream),
    inbound_chunk_buffer: []u8,

    inbox: std.ArrayList(state.InEvent(NodeId)),
    timers: util.TimerMap(state.Timer(NodeId)),
    neighbors: std.AutoHashMapUnmanaged(TopicId, std.AutoHashMapUnmanaged(NodeId, void)),
    received: std.ArrayList(Received),
    user_events: std.ArrayList(UserEvent),
    /// Head indices for the two FIFO queues above: pops advance the head
    /// instead of shifting the tail (regression lane-05 H1 — orderedRemove(0)
    /// made every pop O(n) under backlog). Invariant: head <= items.len; a
    /// fully-drained queue resets to head 0 with items cleared.
    received_head: usize = 0,
    user_events_head: usize = 0,

    start_ns: u64,

    /// Construct a gossip Node with a full 32-byte secret (RPK auth root).
    /// A 1-byte seed is intentionally rejected — that collapsed the identity
    /// space to 256 keys.
    pub fn init(allocator: std.mem.Allocator, io: std.Io, secret: key.SecretKey, alpn: [:0]const u8) !Node {
        return initOptions(allocator, io, secret, alpn, .{});
    }

    pub fn initOptions(allocator: std.mem.Allocator, io: std.Io, secret: key.SecretKey, alpn: [:0]const u8, options: Options) !Node {
        if (options.protocol.max_message_size < types.MIN_MAX_MESSAGE_SIZE) return error.InvalidConfiguration;
        if (options.inbound_chunk_buffer_size == 0) return error.InvalidConfiguration;
        var endpoint_options = options.endpoint;
        endpoint_options.accept_unknown_peer = true;
        const endpoint = try factory.createForProduct(allocator, io, secret, alpn, endpoint_options);
        errdefer endpoint.deinit();
        const peer_data = try encodePeerData(allocator, endpoint.localAddress());
        errdefer allocator.free(peer_data);
        const inbound_chunk_buffer = try allocator.alloc(u8, options.inbound_chunk_buffer_size);
        errdefer allocator.free(inbound_chunk_buffer);
        // Membership randomness is independent of long-term identity key material.
        var seed_bytes: [GossipPrng.secret_seed_length]u8 = undefined;
        io.random(&seed_bytes);
        defer std.crypto.secureZero(u8, &seed_bytes);
        const prng = GossipPrng.init(seed_bytes);
        return .{
            .allocator = allocator,
            .io = io,
            .endpoint = endpoint,
            .transport = endpoint.transport(),
            .id = secret.public(),
            .protocol = state.State(NodeId, GossipPrng).init(
                secret.public(),
                peer_data,
                options.protocol,
                prng,
            ),
            .peer_data = peer_data,
            .max_message_size = options.protocol.max_message_size,
            .max_user_events = options.max_user_events,
            .max_received_messages = options.max_received_messages,
            .max_inbox_messages = options.max_inbox_messages,
            .command_channel_capacity = if (options.command_channel_capacity == 0) 1 else options.command_channel_capacity,
            .max_pending_dial_messages = options.max_pending_dial_messages,
            .max_inbound_frames_per_peer_per_pump = options.max_inbound_frames_per_peer_per_pump,
            .max_learned_peers = options.max_learned_peers,
            .learned_peer_retention_ns = options.learned_peer_retention_ns,
            .learned_peer_eviction_interval_ns = options.learned_peer_eviction_interval_ns,
            .alpn = alpn,
            .connections = .empty,
            .peer_addrs = .empty,
            .learned_peer_updates = .empty,
            .dialing = .empty,
            .pending_dial = .empty,
            .inbound_streams = .empty,
            .outbound_streams = .empty,
            .inbound_chunk_buffer = inbound_chunk_buffer,
            .inbox = .empty,
            .timers = util.TimerMap(state.Timer(NodeId)).init(allocator),
            .neighbors = .empty,
            .received = .empty,
            .user_events = .empty,
            .start_ns = @intCast(std.Io.Clock.now(.awake, io).nanoseconds),
        };
    }

    pub fn deinit(self: *Node) void {
        self.shutdown() catch {};
        var cit = self.connections.iterator();
        while (cit.next()) |e| e.value_ptr.connection.close();
        self.connections.deinit(self.allocator);
        var pit = self.peer_addrs.iterator();
        while (pit.next()) |e| e.value_ptr.deinit(self.allocator);
        self.peer_addrs.deinit(self.allocator);
        self.learned_peer_updates.deinit(self.allocator);
        self.dialing.deinit(self.allocator);
        var pdit = self.pending_dial.iterator();
        while (pdit.next()) |e| {
            for (e.value_ptr.items) |msg| msg.deinit(self.allocator);
            e.value_ptr.deinit(self.allocator);
        }
        self.pending_dial.deinit(self.allocator);
        var iit = self.inbound_streams.iterator();
        while (iit.next()) |e| e.value_ptr.deinit(self.allocator);
        self.inbound_streams.deinit(self.allocator);
        var oit = self.outbound_streams.iterator();
        while (oit.next()) |e| e.value_ptr.finish() catch {};
        self.outbound_streams.deinit(self.allocator);
        self.allocator.free(self.inbound_chunk_buffer);
        for (self.inbox.items) |event| self.deinitInEvent(event);
        self.inbox.deinit(self.allocator);
        self.timers.deinit();
        var nit = self.neighbors.iterator();
        while (nit.next()) |e| e.value_ptr.deinit(self.allocator);
        self.neighbors.deinit(self.allocator);
        for (self.received.items[self.received_head..]) |received| received.deinit(self.allocator);
        self.received.deinit(self.allocator);
        for (self.user_events.items[self.user_events_head..]) |event| event.deinit(self.allocator);
        self.user_events.deinit(self.allocator);
        self.protocol.deinit(self.allocator);
        self.allocator.free(self.peer_data);
        self.endpoint.deinit();
    }

    pub fn gossipAlpn(self: *const Node) [:0]const u8 {
        return self.alpn;
    }

    pub fn protocolConfig(self: *const Node) state.Config {
        return self.protocol.config;
    }

    pub fn commandChannelCapacity(self: *const Node) usize {
        return self.command_channel_capacity;
    }

    pub fn localAddress(self: *const Node) std.Io.net.IpAddress {
        return self.endpoint.localAddress();
    }

    pub fn engine(self: *const Node) factory.Engine {
        return self.endpoint.engine();
    }

    pub fn tlsBackend(self: *const Node) factory.TlsBackend {
        return self.endpoint.tlsBackend();
    }

    pub fn productName(_: *const Node) []const u8 {
        return product_flags.product_name;
    }

    pub fn gossipEnabled(_: *const Node) bool {
        return product_flags.has_gossip;
    }

    pub fn registerPeer(self: *Node, peer: NodeId, addr: transport.NodeAddr) Error!void {
        var stored = addr.clone(self.allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.NotConnected,
        };
        errdefer stored.deinit(self.allocator);
        stored.id = peer;
        const gop = try self.peer_addrs.getOrPut(self.allocator, peer);
        if (gop.found_existing) {
            gop.value_ptr.deinit(self.allocator);
        }
        gop.value_ptr.* = stored;
        _ = self.learned_peer_updates.remove(peer);
    }

    fn learnPeer(self: *Node, peer: NodeId, learned: transport.NodeAddr, now: u64) Error!void {
        if (self.peer_addrs.getPtr(peer)) |existing| {
            // Manual registrations are authoritative. Keeping learned addresses in
            // the same record would make untrusted additions permanent because
            // manual records are intentionally excluded from learned expiry.
            const updated = self.learned_peer_updates.getPtr(peer) orelse return;
            const combined = try self.allocator.alloc(transport.TransportAddr, existing.addrs.len + learned.addrs.len);
            defer self.allocator.free(combined);
            var count: usize = existing.addrs.len;
            @memcpy(combined[0..count], existing.addrs);
            @memcpy(combined[count..][0..learned.addrs.len], learned.addrs);
            count += learned.addrs.len;
            const merged = transport.NodeAddr.fromParts(self.allocator, peer, combined[0..count]) catch return error.OutOfMemory;
            existing.deinit(self.allocator);
            existing.* = merged;
            updated.* = now;
            return;
        }

        if (self.max_learned_peers == 0) return;
        self.evictLearnedPeers(now, true);
        try self.peer_addrs.ensureUnusedCapacity(self.allocator, 1);
        try self.learned_peer_updates.ensureUnusedCapacity(self.allocator, 1);
        var stored = learned.clone(self.allocator) catch return error.OutOfMemory;
        errdefer stored.deinit(self.allocator);
        stored.id = peer;
        self.peer_addrs.putAssumeCapacity(peer, stored);
        self.learned_peer_updates.putAssumeCapacity(peer, now);
    }

    fn evictLearnedPeers(self: *Node, now: u64, enforce_limit: bool) void {
        while (true) {
            var candidate: ?NodeId = null;
            var oldest_update: u64 = std.math.maxInt(u64);
            var it = self.learned_peer_updates.iterator();
            while (it.next()) |entry| {
                const age = now -| entry.value_ptr.*;
                if (age > self.learned_peer_retention_ns) {
                    candidate = entry.key_ptr.*;
                    break;
                }
                if (enforce_limit and entry.value_ptr.* < oldest_update) {
                    candidate = entry.key_ptr.*;
                    oldest_update = entry.value_ptr.*;
                }
            }
            const over_limit = enforce_limit and self.learned_peer_updates.count() >= self.max_learned_peers;
            if (candidate == null or (!over_limit and oldest_update != std.math.maxInt(u64))) break;
            const peer = candidate.?;
            _ = self.learned_peer_updates.remove(peer);
            if (self.peer_addrs.fetchRemove(peer)) |removed| {
                var expired = removed.value;
                expired.deinit(self.allocator);
            }
            if (!over_limit) continue;
        }
    }

    pub fn addConnection(self: *Node, conn: transport.Connection) Error!void {
        return self.addConnectionWithOrigin(conn, .accepted);
    }

    fn addConnectionWithOrigin(self: *Node, conn: transport.Connection, origin: ConnectionOrigin) Error!void {
        const peer = conn.remoteNodeId();
        errdefer conn.close();
        if (self.connections.get(peer)) |existing| {
            const local_bytes = self.id.toBytes();
            const peer_bytes = peer.toBytes();
            const preferred: ConnectionOrigin = if (std.mem.order(u8, &local_bytes, &peer_bytes) == .lt) .dialed else .accepted;
            if (existing.origin == preferred or origin != preferred) {
                conn.close();
                return;
            }
            self.closePeer(peer);
        }
        try self.connections.put(self.allocator, peer, .{ .connection = conn, .origin = origin });
    }

    fn pollTransport(self: *Node) Error!void {
        const maybe = self.endpoint.tryAcceptReady() catch |err| switch (err) {
            error.ConnectionLost, error.NotConnected, error.StreamReset => null,
            else => return err,
        };
        if (maybe) |conn| {
            self.last_pump_active = true;
            try self.addConnection(conn);
        }
        try self.pollInbound();
    }

    fn pollInbound(self: *Node) Error!void {
        var lost_peers = std.ArrayList(NodeId).empty;
        defer lost_peers.deinit(self.allocator);

        var it = self.connections.iterator();
        while (it.next()) |entry| {
            var frames_processed: usize = 0;
            while (frames_processed < self.max_inbound_frames_per_peer_per_pump) {
                if (self.endpoint.connectionIsClosed(entry.value_ptr.connection)) {
                    try lost_peers.append(self.allocator, entry.key_ptr.*);
                    break;
                }
                const maybe_inbound_event = self.endpoint.nextInboundUniEvent(entry.value_ptr.connection, self.inbound_chunk_buffer) catch |err| switch (err) {
                    error.ConnectionLost, error.NotConnected => {
                        try lost_peers.append(self.allocator, entry.key_ptr.*);
                        break;
                    },
                    else => return err,
                };
                const inbound_event = maybe_inbound_event orelse {
                    if (self.endpoint.connectionIsClosed(entry.value_ptr.connection)) {
                        try lost_peers.append(self.allocator, entry.key_ptr.*);
                    }
                    break;
                };
                self.last_pump_active = true;
                const chunk = switch (inbound_event) {
                    .chunk => |chunk| chunk,
                    .reset => |stream_id| {
                        self.removeInboundStream(.{ .peer = entry.key_ptr.*, .stream_id = stream_id });
                        continue;
                    },
                };
                const inbox_before = self.inbox.items.len;
                const decoded = self.handleInboundChunk(
                    entry.key_ptr.*,
                    chunk.stream_id,
                    chunk.bytes,
                    chunk.fin,
                    self.max_inbound_frames_per_peer_per_pump - frames_processed,
                ) catch |decode_err| {
                    if (decode_err == error.OutOfMemory) return decode_err;
                    // A bad frame must not abort the whole-node pump.
                    self.removeInboundStream(.{ .peer = entry.key_ptr.*, .stream_id = chunk.stream_id });
                    break;
                };
                frames_processed += decoded;
                if (self.inbox.items.len == inbox_before and chunk.bytes.len == 0) break;
            }
        }

        try self.inbox.ensureUnusedCapacity(self.allocator, lost_peers.items.len);
        for (lost_peers.items) |peer| {
            if (!self.connections.contains(peer)) continue;
            self.closePeer(peer);
            self.inbox.appendAssumeCapacity(.{ .peer_disconnected = peer });
        }
    }

    fn removeInboundStream(self: *Node, key_for_lookup: InboundStreamKey) void {
        if (self.inbound_streams.fetchRemove(key_for_lookup)) |entry| {
            var inbound = entry.value;
            inbound.deinit(self.allocator);
        }
    }

    fn handleInboundChunk(self: *Node, from: NodeId, stream_id: u64, bytes: []const u8, fin: bool, max_frames: usize) Error!usize {
        const key_for_lookup = InboundStreamKey{ .peer = from, .stream_id = stream_id };
        const gop = try self.inbound_streams.getOrPut(self.allocator, key_for_lookup);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        if (bytes.len > 0) try gop.value_ptr.buffer.appendSlice(self.allocator, bytes);

        var consumed: usize = 0;
        var rest = gop.value_ptr.buffer.items;
        if (gop.value_ptr.topic == null) {
            const header_frame = (try readFrameSlice(rest, self.max_message_size)) orelse {
                if (fin) return error.EndOfStream;
                return 0;
            };
            const header = try StreamHeader.decode(self.allocator, header_frame.body);
            gop.value_ptr.topic = header.topic_id;
            consumed += header_frame.total_len;
            rest = rest[header_frame.total_len..];
        }

        const topic = gop.value_ptr.topic.?;
        var decoded_frames: usize = 0;
        while (true) {
            if (decoded_frames >= max_frames or self.inbox.items.len >= self.max_inbox_messages) break;
            const msg_frame = (try readFrameSlice(rest, self.max_message_size)) orelse {
                if (fin) {
                    if (rest.len != 0) return error.EndOfStream;
                }
                break;
            };
            {
                const inner = try types.TopicMessage(NodeId).decode(self.allocator, msg_frame.body);
                errdefer inner.deinit(self.allocator);
                const wire = types.WireMessage(NodeId){ .topic = topic, .message = inner };
                try self.inbox.append(self.allocator, .{ .recv_message = .{ .from = from, .message = wire } });
            }
            decoded_frames += 1;
            consumed += msg_frame.total_len;
            rest = rest[msg_frame.total_len..];
        }
        if (consumed > 0) {
            const remaining = gop.value_ptr.buffer.items[consumed..];
            std.mem.copyForwards(u8, gop.value_ptr.buffer.items[0..remaining.len], remaining);
            gop.value_ptr.buffer.shrinkRetainingCapacity(remaining.len);
        }
        if (gop.value_ptr.buffer.items.len > self.max_message_size + 4) {
            if ((try readFrameSlice(gop.value_ptr.buffer.items, self.max_message_size)) == null) {
                return error.MessageTooLarge;
            }
        }
        if (fin and gop.value_ptr.buffer.items.len == 0) {
            self.removeInboundStream(key_for_lookup);
        }
        return decoded_frames;
    }

    /// Establish a Node-owned connection. The concrete handle is deliberately
    /// not exposed because closing an alias would invalidate Node-owned topic streams.
    pub fn connectTo(self: *Node, peer: NodeId) Error!void {
        _ = try self.ensureConnection(peer);
    }

    fn ensureConnection(self: *Node, peer: NodeId) Error!transport.Connection {
        if (self.connections.get(peer)) |conn| {
            if (!self.endpoint.connectionIsClosed(conn.connection)) return conn.connection;
            self.closePeer(peer);
        }
        const addr = self.peer_addrs.get(peer) orelse return error.PeerAddrUnknown;
        try self.dialing.put(self.allocator, peer, {});
        defer _ = self.dialing.remove(peer);
        const conn = try self.transport.connect(addr);
        try self.addConnectionWithOrigin(conn, .dialed);
        try self.flushPendingDial(peer);
        return conn;
    }

    pub fn join(self: *Node, topic: TopicId, bootstrap: []const NodeId) Error!void {
        for (bootstrap) |peer| {
            if (self.peer_addrs.contains(peer)) {
                _ = self.ensureConnection(peer) catch {};
            }
        }
        try self.dispatchCommand(.{ .command = .{ .topic = topic, .command = .{ .join = bootstrap } } });
    }

    /// Post-subscribe bootstrap: tell an already-joined topic to connect additional peers.
    pub fn joinPeers(self: *Node, topic: TopicId, peers: []const NodeId) Error!void {
        if (self.protocol.state(topic) == null) return error.InvalidConfiguration;
        try self.join(topic, peers);
    }

    pub fn broadcast(self: *Node, topic: TopicId, content: []const u8) Error!void {
        try self.broadcastScope(topic, content, .swarm);
    }

    pub fn broadcastNeighbors(self: *Node, topic: TopicId, content: []const u8) Error!void {
        try self.broadcastScope(topic, content, .neighbors);
    }

    pub fn broadcastScope(self: *Node, topic: TopicId, content: []const u8, scope: Scope) Error!void {
        try self.dispatchCommand(.{ .command = .{ .topic = topic, .command = .{ .broadcast = .{
            .content = content,
            .scope = scope,
        } } } });
    }

    pub fn leave(self: *Node, topic: TopicId) Error!void {
        defer if (self.protocol.state(topic) == null) self.clearTopicNeighbors(topic);
        // Quit/leave is a lifecycle path and must not be blocked by the command-channel
        // bound (auto-quit after half-drop must always succeed).
        try self.dispatch(.{ .command = .{ .topic = topic, .command = .quit } });
    }

    /// Snapshot the current direct-neighbor set for a topic (caller frees).
    pub fn listNeighbors(self: *const Node, allocator: std.mem.Allocator, topic: TopicId) Error![]NodeId {
        const set = self.neighbors.get(topic) orelse {
            return try allocator.alloc(NodeId, 0);
        };
        var out = try allocator.alloc(NodeId, set.count());
        var i: usize = 0;
        var it = set.keyIterator();
        while (it.next()) |peer| {
            out[i] = peer.*;
            i += 1;
        }
        return out;
    }

    pub fn neighborCount(self: *const Node, topic: TopicId) usize {
        const set = self.neighbors.get(topic) orelse return 0;
        return set.count();
    }

    pub fn shutdown(self: *Node) Error!void {
        var topics = std.ArrayList(TopicId).empty;
        defer topics.deinit(self.allocator);

        var it = self.protocol.states.keyIterator();
        while (it.next()) |topic_id| try topics.append(self.allocator, topic_id.*);
        for (topics.items) |topic| try self.leave(topic);

        var peers = std.ArrayList(NodeId).empty;
        defer peers.deinit(self.allocator);
        try peers.ensureTotalCapacity(self.allocator, self.connections.count());
        var peer_it = self.connections.keyIterator();
        while (peer_it.next()) |peer| peers.appendAssumeCapacity(peer.*);
        for (peers.items) |peer| self.closePeer(peer);
    }

    fn clearTopicNeighbors(self: *Node, topic: TopicId) void {
        if (self.neighbors.fetchRemove(topic)) |entry| {
            var set = entry.value;
            set.deinit(self.allocator);
        }
    }

    fn deinitInEvent(self: *Node, event: state.InEvent(NodeId)) void {
        switch (event) {
            .recv_message => |rm| rm.message.deinit(self.allocator),
            else => {},
        }
    }

    fn nowNs(self: *const Node) u64 {
        return @as(u64, @intCast(std.Io.Clock.now(.awake, self.io).nanoseconds)) -| self.start_ns;
    }

    pub fn pump(self: *Node) Error!void {
        self.commands_since_pump = 0;
        self.last_pump_active = false;
        try self.pollTransport();
        const now = self.nowNs();
        if (now >= self.next_learned_peer_eviction_ns) {
            self.evictLearnedPeers(now, false);
            self.next_learned_peer_eviction_ns = now +| self.learned_peer_eviction_interval_ns;
        }
        while (self.timers.popBefore(now)) |entry| {
            self.last_pump_active = true;
            const out = try self.protocol.handle(self.allocator, .{ .timer_expired = entry.item }, now);
            defer self.allocator.free(out);
            try self.handleOut(out);
        }
        var batch: std.ArrayList(state.InEvent(NodeId)) = .empty;
        std.mem.swap(std.ArrayList(state.InEvent(NodeId)), &batch, &self.inbox);
        defer batch.deinit(self.allocator);
        if (batch.items.len > 0) self.last_pump_active = true;
        var handled: usize = 0;
        defer for (batch.items[handled..]) |event| self.deinitInEvent(event);
        while (handled < batch.items.len) {
            const event = batch.items[handled];
            handled += 1;
            defer self.deinitInEvent(event);
            const out = try self.protocol.handle(self.allocator, event, now);
            defer self.allocator.free(out);
            try self.handleOut(out);
        }
    }

    fn dispatch(self: *Node, event: state.InEvent(NodeId)) Error!void {
        const now = self.nowNs();
        const out = try self.protocol.handle(self.allocator, event, now);
        defer self.allocator.free(out);
        try self.handleOut(out);
    }

    /// Dispatch a user/protocol command under the command-channel capacity bound.
    /// Capacity is replenished on each `pump` (cooperative actor channel).
    fn dispatchCommand(self: *Node, event: state.InEvent(NodeId)) Error!void {
        if (self.commands_since_pump >= self.command_channel_capacity) return error.CommandChannelFull;
        self.commands_since_pump += 1;
        try self.dispatch(event);
    }

    fn handleOut(self: *Node, events: []const state.OutEvent(NodeId)) Error!void {
        const now = self.nowNs();
        var pending = std.ArrayList(state.OutEvent(NodeId)).empty;
        defer pending.deinit(self.allocator);
        var copied = false;
        errdefer if (!copied) self.deinitOutEvents(events);
        try pending.appendSlice(self.allocator, events);
        copied = true;
        var head: usize = 0;
        errdefer self.deinitOutEvents(pending.items[head..]);

        var steps: usize = 0;
        // Head-index pop (lane-05 H1): consume from the front without shifting
        // the tail; the errdefer below only owns the unconsumed suffix.
        while (head < pending.items.len) {
            if (steps > 10_000) return error.PumpLimit;
            steps += 1;
            const ev = pending.items[head];
            head += 1;
            switch (ev) {
                .send_message => |sm| {
                    // sendWire takes ownership of sm.message on every path (queue, send, or error).
                    self.sendWire(sm.to, sm.message) catch |err| {
                        if (err == error.OutOfMemory) return err;
                        if (err == error.PendingDialQueueFull) continue;
                        self.closePeer(sm.to);
                        const failure_events = try self.protocol.handle(self.allocator, .{ .peer_disconnected = sm.to }, now);
                        defer self.allocator.free(failure_events);
                        var moved = false;
                        defer if (!moved) self.deinitOutEvents(failure_events);
                        try pending.appendSlice(self.allocator, failure_events);
                        moved = true;
                        continue;
                    };
                    try self.pollTransport();
                },
                .schedule_timer => |st| try self.timers.insert(now + st.delay_ns, st.timer),
                .emit_event => |em| {
                    switch (em.event) {
                        .neighbor_up => |peer| {
                            const gop = try self.neighbors.getOrPut(self.allocator, em.topic);
                            if (!gop.found_existing) gop.value_ptr.* = .empty;
                            try gop.value_ptr.put(self.allocator, peer, {});
                            try self.pushUserEvent(.{ .neighbor_up = .{ .topic = em.topic, .peer = peer } });
                        },
                        .neighbor_down => |peer| {
                            if (self.neighbors.getPtr(em.topic)) |set| _ = set.remove(peer);
                            try self.pushUserEvent(.{ .neighbor_down = .{ .topic = em.topic, .peer = peer } });
                        },
                        .received => |msg| {
                            const owned = try self.allocator.dupe(u8, msg.content);
                            errdefer self.allocator.free(owned);
                            if (self.received.items.len - self.received_head < self.max_received_messages) {
                                try self.received.ensureUnusedCapacity(self.allocator, 1);
                            } else if (self.received.items.len - self.received_head > 0) {
                                // Drop the oldest pending message (head-index pop —
                                // items.len is unchanged, so reserve for the append).
                                const dropped = self.received.items[self.received_head];
                                self.received_head += 1;
                                dropped.deinit(self.allocator);
                                self.dropped_received_messages += 1;
                                try self.received.ensureUnusedCapacity(self.allocator, 1);
                            } else {
                                self.dropped_received_messages += 1;
                                self.allocator.free(owned);
                                continue;
                            }
                            const received = Received{
                                .topic = em.topic,
                                .content = owned,
                                .delivered_from = msg.delivered_from,
                                .scope = msg.scope,
                            };
                            self.received.appendAssumeCapacity(received);
                            // Fan a separate owned copy into the user-event stream so
                            // popReceived and popUserEvent remain independent consumers.
                            const event_owned = try self.allocator.dupe(u8, received.content);
                            errdefer self.allocator.free(event_owned);
                            try self.pushUserEvent(.{ .received = .{
                                .topic = received.topic,
                                .content = event_owned,
                                .delivered_from = received.delivered_from,
                                .scope = received.scope,
                            } });
                        },
                    }
                },
                .disconnect_peer => |peer| self.closePeer(peer),
                .peer_data => |peer_data| {
                    var learned = decodePeerData(self.allocator, peer_data.peer, peer_data.data) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => continue,
                    };
                    defer learned.deinit(self.allocator);
                    try self.learnPeer(peer_data.peer, learned, now);
                },
            }
            while (self.timers.popBefore(now)) |entry| {
                const more = try self.protocol.handle(self.allocator, .{ .timer_expired = entry.item }, now);
                defer self.allocator.free(more);
                var moved = false;
                defer if (!moved) self.deinitOutEvents(more);
                try pending.appendSlice(self.allocator, more);
                moved = true;
            }
        }
    }

    fn deinitOutEvents(self: *Node, events: []const state.OutEvent(NodeId)) void {
        for (events) |event| switch (event) {
            .send_message => |sent| sent.message.deinit(self.allocator),
            else => {},
        };
    }

    fn closePeer(self: *Node, peer: NodeId) void {
        while (true) {
            var remove_key: ?OutboundStreamKey = null;
            var cache_it = self.outbound_streams.keyIterator();
            while (cache_it.next()) |stream_key| {
                if (stream_key.peer.eql(peer)) {
                    remove_key = stream_key.*;
                    break;
                }
            }
            if (remove_key) |stream_key| {
                if (self.outbound_streams.fetchRemove(stream_key)) |entry| entry.value.reset();
            } else break;
        }
        while (true) {
            var remove_key: ?InboundStreamKey = null;
            var cache_it = self.inbound_streams.keyIterator();
            while (cache_it.next()) |stream_key| {
                if (stream_key.peer.eql(peer)) {
                    remove_key = stream_key.*;
                    break;
                }
            }
            if (remove_key) |stream_key| {
                self.removeInboundStream(stream_key);
            } else break;
        }
        if (self.connections.fetchRemove(peer)) |entry| entry.value.connection.close();
    }

    /// Takes ownership of `wire` on every path (successful send, pending queue, or error).
    fn sendWire(self: *Node, to: NodeId, wire: types.WireMessage(NodeId)) Error!void {
        // Already connected → write immediately.
        if (self.connections.get(to)) |pc| {
            if (!self.endpoint.connectionIsClosed(pc.connection)) {
                return self.writeWireOnConnection(to, wire);
            }
            self.closePeer(to);
        }
        // No live connection: queue while dial starts (pending-dial message queue).
        try self.enqueuePendingDial(to, wire);
        if (self.dialing.contains(to)) return;
        // Kick the dial; ensureConnection flushes the pending queue on success.
        _ = self.ensureConnection(to) catch |err| {
            // Leave queued messages for a later successful dial, unless fatal.
            if (err == error.OutOfMemory) return err;
            if (err == error.PeerAddrUnknown) {
                self.dropPendingDial(to);
                return err;
            }
            return;
        };
    }

    fn writeWireOnConnection(self: *Node, to: NodeId, wire: types.WireMessage(NodeId)) Error!void {
        defer wire.deinit(self.allocator);
        const stream_key = OutboundStreamKey{ .peer = to, .topic = wire.topic };
        const gop = try self.outbound_streams.getOrPut(self.allocator, stream_key);
        var stream_ready = gop.found_existing;
        errdefer if (self.outbound_streams.fetchRemove(stream_key)) |entry| {
            if (stream_ready) entry.value.reset();
        };
        if (!gop.found_existing) {
            const conn = self.connections.get(to) orelse return error.PeerAddrUnknown;
            const stream = try conn.connection.openUni();
            gop.value_ptr.* = stream;
            stream_ready = true;
            const header = StreamHeader{ .topic_id = wire.topic };
            const header_bytes = try header.encode(self.allocator);
            defer self.allocator.free(header_bytes);
            try frame.writeFrameLimited(stream.writer(), header_bytes, self.max_message_size);
        }
        const stream = gop.value_ptr.*;
        const body = try wire.message.encode(self.allocator);
        defer self.allocator.free(body);
        try frame.writeFrameLimited(stream.writer(), body, self.max_message_size);
        if (wire.message.isDisconnect()) {
            try stream.finish();
            _ = self.outbound_streams.remove(stream_key);
        } else {
            try stream.flush();
        }
    }

    fn enqueuePendingDial(self: *Node, to: NodeId, wire: types.WireMessage(NodeId)) Error!void {
        errdefer wire.deinit(self.allocator);
        const gop = try self.pending_dial.getOrPut(self.allocator, to);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        if (gop.value_ptr.items.len >= self.max_pending_dial_messages) {
            return error.PendingDialQueueFull;
        }
        try gop.value_ptr.append(self.allocator, wire);
    }

    fn dropPendingDial(self: *Node, to: NodeId) void {
        if (self.pending_dial.fetchRemove(to)) |entry| {
            var list = entry.value;
            for (list.items) |msg| msg.deinit(self.allocator);
            list.deinit(self.allocator);
        }
    }

    fn flushPendingDial(self: *Node, to: NodeId) Error!void {
        const entry = self.pending_dial.fetchRemove(to) orelse return;
        var list = entry.value;
        var head: usize = 0;
        defer {
            // Only the unconsumed suffix is still ours to release.
            for (list.items[head..]) |msg| msg.deinit(self.allocator);
            list.deinit(self.allocator);
        }
        while (head < list.items.len) {
            const msg = list.items[head];
            head += 1;
            // Connected path: writeWireOnConnection takes ownership.
            self.writeWireOnConnection(to, msg) catch |err| {
                if (err == error.OutOfMemory) return err;
                return;
            };
        }
    }

    pub fn isJoined(self: *const Node, topic: TopicId) bool {
        const set = self.neighbors.get(topic) orelse return false;
        return set.count() > 0;
    }

    pub fn hasReceived(self: *const Node, topic: TopicId, content: []const u8) bool {
        for (self.received.items[self.received_head..]) |r| {
            if (std.mem.eql(u8, &r.topic, &topic) and std.mem.eql(u8, r.content, content)) return true;
        }
        return false;
    }

    pub fn popReceived(self: *Node) ?Received {
        if (self.received_head >= self.received.items.len) return null;
        const r = self.received.items[self.received_head];
        self.received_head += 1;
        if (self.received_head == self.received.items.len) {
            // Drained: reset so pushes reuse the capacity.
            self.received.clearRetainingCapacity();
            self.received_head = 0;
        }
        return r;
    }

    pub fn maxMessageSize(self: *const Node) usize {
        return self.max_message_size;
    }

    pub fn droppedReceivedCount(self: *const Node) usize {
        return self.dropped_received_messages;
    }

    pub fn droppedUserEventCount(self: *const Node) usize {
        return self.dropped_user_events;
    }

    pub fn popUserEvent(self: *Node) ?UserEvent {
        if (self.user_events_head >= self.user_events.items.len) return null;
        const ev = self.user_events.items[self.user_events_head];
        self.user_events_head += 1;
        if (self.user_events_head == self.user_events.items.len) {
            self.user_events.clearRetainingCapacity();
            self.user_events_head = 0;
        }
        return ev;
    }

    fn pushUserEvent(self: *Node, event: UserEvent) Error!void {
        const pending_count = self.user_events.items.len - self.user_events_head;
        if (pending_count < self.max_user_events) {
            try self.user_events.ensureUnusedCapacity(self.allocator, 1);
        } else if (pending_count > 0) {
            // Drop the oldest pending event (head-index pop — items.len is
            // unchanged, so reserve for the append).
            const dropped = self.user_events.items[self.user_events_head];
            self.user_events_head += 1;
            dropped.deinit(self.allocator);
            self.dropped_user_events += 1;
            try self.user_events.ensureUnusedCapacity(self.allocator, 1);
        } else {
            event.deinit(self.allocator);
            self.dropped_user_events += 1;
            return;
        }
        self.user_events.appendAssumeCapacity(event);
    }

    pub fn runUntilJoined(self: *Node, topic: TopicId) Error!void {
        const deadline = self.nowNs() + hang_watchdog_ns;
        while (!self.isJoined(topic)) {
            if (self.nowNs() > deadline) return error.HangWatchdog;
            try self.pump();
        }
    }

    pub fn runUntilReceived(self: *Node, topic: TopicId, content: []const u8) Error!void {
        const deadline = self.nowNs() + hang_watchdog_ns;
        while (!self.hasReceived(topic, content)) {
            if (self.nowNs() > deadline) return error.HangWatchdog;
            try self.pump();
        }
    }
};

test "Rust AddrInfo peer data encodes and decodes direct IPv4" {
    const allocator = std.testing.allocator;
    const direct: std.Io.net.IpAddress = .{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 1 },
        .port = 1234,
    } };
    const encoded = try encodePeerData(allocator, direct);
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 0, 127, 0, 0, 1, 0xd2, 0x09 }, encoded);

    const peer = key.SecretKey.fromBytes(.{0x51} ** 32).public();
    var decoded = try decodePeerData(allocator, peer, encoded);
    defer decoded.deinit(allocator);
    try std.testing.expect(decoded.id.eql(peer));
    try std.testing.expectEqual(direct, decoded.firstIpAddr().?);
}

test "malformed peer data releases partial relay address" {
    const allocator = std.testing.allocator;
    const peer = key.SecretKey.fromBytes(.{0x52} ** 32).public();
    // Some relay URL followed by a direct-address count with a truncated entry.
    try std.testing.expectError(
        error.EndOfStream,
        decodePeerData(allocator, peer, &.{ 1, 9, 'h', 't', 't', 'p', ':', '/', '/', 'x', '/', 1, 0 }),
    );
}

test "Node rejects unsafe message and inbound chunk buffer limits" {
    const secret = key.SecretKey.fromBytes(.{0x53} ** 32);
    try std.testing.expectError(error.InvalidConfiguration, Node.initOptions(
        std.testing.allocator,
        std.testing.io,
        secret,
        GOSSIP_ALPN,
        .{ .protocol = .{ .max_message_size = types.MIN_MAX_MESSAGE_SIZE - 1 } },
    ));
    try std.testing.expectError(error.InvalidConfiguration, Node.initOptions(
        std.testing.allocator,
        std.testing.io,
        secret,
        GOSSIP_ALPN,
        .{ .inbound_chunk_buffer_size = 0 },
    ));
}
