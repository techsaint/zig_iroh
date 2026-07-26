//! QUIC-backed gossip network driver over real transport.Connection uni-streams.
const std = @import("std");
const transport = @import("../transport.zig");
const factory = @import("../transport/factory.zig");
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

pub const Options = struct {
    protocol: state.Config = .{},
    endpoint: factory.Options = .{},
    max_received_messages: usize = 2048,
    max_inbox_messages: usize = 1024,
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
    dropped_received_messages: usize = 0,
    max_inbox_messages: usize,
    max_inbound_frames_per_peer_per_pump: usize,
    max_learned_peers: usize,
    learned_peer_retention_ns: u64,
    learned_peer_eviction_interval_ns: u64,
    next_learned_peer_eviction_ns: u64 = 0,

    connections: std.AutoHashMapUnmanaged(NodeId, PeerConnection),
    peer_addrs: std.AutoHashMapUnmanaged(NodeId, transport.NodeAddr),
    learned_peer_updates: std.AutoHashMapUnmanaged(NodeId, u64),
    inbound_streams: std.AutoHashMapUnmanaged(InboundStreamKey, InboundStreamState),
    outbound_streams: std.AutoHashMapUnmanaged(OutboundStreamKey, transport.SendStream),
    inbound_chunk_buffer: []u8,

    inbox: std.ArrayList(state.InEvent(NodeId)),
    timers: util.TimerMap(state.Timer(NodeId)),
    neighbors: std.AutoHashMapUnmanaged(TopicId, std.AutoHashMapUnmanaged(NodeId, void)),
    received: std.ArrayList(Received),

    start_ns: u64,

    /// Construct a gossip Node with a full 32-byte secret (RPK auth root).
    /// A 1-byte seed is intentionally rejected — that collapsed the identity
    /// space to 256 keys (VC-1 C2 / V3-B).
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
            .max_received_messages = options.max_received_messages,
            .max_inbox_messages = options.max_inbox_messages,
            .max_inbound_frames_per_peer_per_pump = options.max_inbound_frames_per_peer_per_pump,
            .max_learned_peers = options.max_learned_peers,
            .learned_peer_retention_ns = options.learned_peer_retention_ns,
            .learned_peer_eviction_interval_ns = options.learned_peer_eviction_interval_ns,
            .connections = .empty,
            .peer_addrs = .empty,
            .learned_peer_updates = .empty,
            .inbound_streams = .empty,
            .outbound_streams = .empty,
            .inbound_chunk_buffer = inbound_chunk_buffer,
            .inbox = .empty,
            .timers = util.TimerMap(state.Timer(NodeId)).init(allocator),
            .neighbors = .empty,
            .received = .empty,
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
        for (self.received.items) |received| received.deinit(self.allocator);
        self.received.deinit(self.allocator);
        self.protocol.deinit(self.allocator);
        self.allocator.free(self.peer_data);
        self.endpoint.deinit();
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
        if (maybe) |conn| try self.addConnection(conn);
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
                    // V3-C: a bad frame must not abort the whole-node pump (L-9 residue).
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
        const conn = try self.transport.connect(addr);
        try self.addConnectionWithOrigin(conn, .dialed);
        return conn;
    }

    pub fn join(self: *Node, topic: TopicId, bootstrap: []const NodeId) Error!void {
        for (bootstrap) |peer| {
            if (self.peer_addrs.contains(peer)) {
                _ = self.ensureConnection(peer) catch {};
            }
        }
        try self.dispatch(.{ .command = .{ .topic = topic, .command = .{ .join = bootstrap } } });
    }

    pub fn broadcast(self: *Node, topic: TopicId, content: []const u8) Error!void {
        try self.broadcastScope(topic, content, .swarm);
    }

    pub fn broadcastNeighbors(self: *Node, topic: TopicId, content: []const u8) Error!void {
        try self.broadcastScope(topic, content, .neighbors);
    }

    pub fn broadcastScope(self: *Node, topic: TopicId, content: []const u8, scope: Scope) Error!void {
        try self.dispatch(.{ .command = .{ .topic = topic, .command = .{ .broadcast = .{
            .content = content,
            .scope = scope,
        } } } });
    }

    pub fn leave(self: *Node, topic: TopicId) Error!void {
        defer if (self.protocol.state(topic) == null) self.clearTopicNeighbors(topic);
        try self.dispatch(.{ .command = .{ .topic = topic, .command = .quit } });
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
        try self.pollTransport();
        const now = self.nowNs();
        if (now >= self.next_learned_peer_eviction_ns) {
            self.evictLearnedPeers(now, false);
            self.next_learned_peer_eviction_ns = now +| self.learned_peer_eviction_interval_ns;
        }
        while (self.timers.popBefore(now)) |entry| {
            const out = try self.protocol.handle(self.allocator, .{ .timer_expired = entry.item }, now);
            defer self.allocator.free(out);
            try self.handleOut(out);
        }
        var batch: std.ArrayList(state.InEvent(NodeId)) = .empty;
        std.mem.swap(std.ArrayList(state.InEvent(NodeId)), &batch, &self.inbox);
        defer batch.deinit(self.allocator);
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

    fn handleOut(self: *Node, events: []const state.OutEvent(NodeId)) Error!void {
        const now = self.nowNs();
        var pending = std.ArrayList(state.OutEvent(NodeId)).empty;
        defer pending.deinit(self.allocator);
        var copied = false;
        errdefer if (!copied) self.deinitOutEvents(events);
        try pending.appendSlice(self.allocator, events);
        copied = true;
        errdefer self.deinitOutEvents(pending.items);

        var steps: usize = 0;
        while (pending.items.len > 0) {
            if (steps > 10_000) return error.PumpLimit;
            steps += 1;
            const ev = pending.orderedRemove(0);
            switch (ev) {
                .send_message => |sm| {
                    defer sm.message.deinit(self.allocator);
                    self.sendWire(sm.to, sm.message) catch |err| {
                        if (err == error.OutOfMemory) return err;
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
                        },
                        .neighbor_down => |peer| {
                            if (self.neighbors.getPtr(em.topic)) |set| _ = set.remove(peer);
                        },
                        .received => |msg| {
                            const owned = try self.allocator.dupe(u8, msg.content);
                            errdefer self.allocator.free(owned);
                            if (self.received.items.len < self.max_received_messages) {
                                try self.received.ensureUnusedCapacity(self.allocator, 1);
                            } else if (self.received.items.len > 0) {
                                const dropped = self.received.orderedRemove(0);
                                dropped.deinit(self.allocator);
                                self.dropped_received_messages += 1;
                            } else {
                                self.dropped_received_messages += 1;
                                self.allocator.free(owned);
                                continue;
                            }
                            self.received.appendAssumeCapacity(.{
                                .topic = em.topic,
                                .content = owned,
                                .delivered_from = msg.delivered_from,
                                .scope = msg.scope,
                            });
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

    fn sendWire(self: *Node, to: NodeId, wire: types.WireMessage(NodeId)) Error!void {
        const stream_key = OutboundStreamKey{ .peer = to, .topic = wire.topic };
        const gop = try self.outbound_streams.getOrPut(self.allocator, stream_key);
        var stream_ready = gop.found_existing;
        errdefer if (self.outbound_streams.fetchRemove(stream_key)) |entry| {
            if (stream_ready) entry.value.reset();
        };
        if (!gop.found_existing) {
            const conn = try self.ensureConnection(to);
            const stream = try conn.openUni();
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

    pub fn isJoined(self: *const Node, topic: TopicId) bool {
        const set = self.neighbors.get(topic) orelse return false;
        return set.count() > 0;
    }

    pub fn hasReceived(self: *const Node, topic: TopicId, content: []const u8) bool {
        for (self.received.items) |r| {
            if (std.mem.eql(u8, &r.topic, &topic) and std.mem.eql(u8, r.content, content)) return true;
        }
        return false;
    }

    pub fn popReceived(self: *Node) ?Received {
        if (self.received.items.len == 0) return null;
        return self.received.orderedRemove(0);
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
