//! Wire types: TopicId, MessageId, nested message enums.
const std = @import("std");
const postcard = @import("postcard.zig");
const fixtures = @import("fixtures.zig");

pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 4096;
pub const MIN_MAX_MESSAGE_SIZE: usize = 512;

pub const TopicId = [32]u8;
pub const MessageId = [32]u8;

pub fn messageIdFromContent(content: []const u8) MessageId {
    var digest: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(content, &digest, .{});
    return digest;
}

pub const PeerData = []const u8;

pub fn PeerInfo(comptime PI: type) type {
    return struct {
        id: PI,
        data: ?PeerData,
    };
}

pub const Ttl = struct {
    value: u16,

    pub fn expired(self: Ttl) bool {
        return self.value == 0;
    }

    pub fn next(self: Ttl) Ttl {
        return .{ .value = if (self.value == 0) 0 else self.value - 1 };
    }
};

pub const Round = struct {
    value: u16,

    pub fn next(self: Round) Round {
        // A remote max-round message must not trap a safety build.
        return .{ .value = self.value +| 1 };
    }
};

pub const Priority = enum { high, low };

pub const DeliveryScope = union(enum) {
    swarm: Round,
    neighbors,
};

pub const Scope = enum { swarm, neighbors };

fn peerToBytes(peer: anytype) [32]u8 {
    const PI = @TypeOf(peer);
    if (@hasDecl(PI, "toBytes")) return peer.toBytes();
    return peer;
}

pub fn encodePeer(w: *postcard.Writer, allocator: std.mem.Allocator, peer: anytype) postcard.Error!void {
    const PI = @TypeOf(peer);
    if (PI == u32) {
        try w.writeVarintU32(allocator, peer);
    } else {
        try w.writeFixed32(allocator, peerToBytes(peer));
    }
}

pub fn decodePeer(r: *postcard.Reader, comptime PI: type, allocator: std.mem.Allocator) postcard.Error!PI {
    _ = allocator;
    if (PI == u32) {
        return try r.readVarintU32();
    } else if (@hasDecl(PI, "fromBytes")) {
        return PI.fromBytes(try r.readFixed32()) catch return error.EndOfStream;
    } else if (PI == TopicId or PI == MessageId) {
        return try r.readFixed32();
    } else {
        @compileError("unsupported peer type");
    }
}

fn encodePeerData(w: *postcard.Writer, allocator: std.mem.Allocator, data: PeerData) postcard.Error!void {
    try w.writeBytes(allocator, data);
}

fn decodePeerData(r: *postcard.Reader, allocator: std.mem.Allocator) postcard.Error!PeerData {
    return try r.readBytes(allocator);
}

fn encodeOptionPeerData(w: *postcard.Writer, allocator: std.mem.Allocator, data: ?PeerData) postcard.Error!void {
    try w.writeOption(allocator, PeerData, data, encodePeerData);
}

fn decodeOptionPeerData(r: *postcard.Reader, allocator: std.mem.Allocator) postcard.Error!?PeerData {
    return try r.readOption(PeerData, decodePeerData, allocator);
}

fn encodeMessageIdOption(w: *postcard.Writer, allocator: std.mem.Allocator, id: MessageId) postcard.Error!void {
    try w.writeFixed32(allocator, id);
}

pub fn HyparviewMessage(comptime PI: type) type {
    return union(enum) {
        join: ?PeerData,
        forward_join: struct {
            peer: PeerInfo(PI),
            ttl: Ttl,
        },
        shuffle: struct {
            origin: PI,
            nodes: []PeerInfo(PI),
            ttl: Ttl,
        },
        shuffle_reply: struct {
            nodes: []PeerInfo(PI),
        },
        neighbor: struct {
            priority: Priority,
            data: ?PeerData,
        },
        disconnect: struct {
            alive: bool,
            respond: bool,
        },

        pub fn encode(self: HyparviewMessage(PI), allocator: std.mem.Allocator) ![]u8 {
            var w = postcard.Writer.init(allocator);
            defer w.deinit(allocator);
            try self.encodeInto(&w, allocator);
            return try allocator.dupe(u8, w.written());
        }

        pub fn deinit(self: HyparviewMessage(PI), allocator: std.mem.Allocator) void {
            switch (self) {
                .join => |data| if (data) |d| allocator.free(d),
                .forward_join => |fj| if (fj.peer.data) |d| allocator.free(d),
                .shuffle => |s| {
                    for (s.nodes) |n| if (n.data) |d| allocator.free(d);
                    allocator.free(s.nodes);
                },
                .shuffle_reply => |sr| {
                    for (sr.nodes) |n| if (n.data) |d| allocator.free(d);
                    allocator.free(sr.nodes);
                },
                .neighbor => |n| if (n.data) |d| allocator.free(d),
                .disconnect => {},
            }
        }

        pub fn encodeInto(self: HyparviewMessage(PI), w: *postcard.Writer, allocator: std.mem.Allocator) !void {
            switch (self) {
                .join => |data| {
                    try w.writeEnumDiscriminant(allocator, 0);
                    try encodeOptionPeerData(w, allocator, data);
                },
                .forward_join => |fj| {
                    try w.writeEnumDiscriminant(allocator, 1);
                    try encodePeer(w, allocator, fj.peer.id);
                    try encodeOptionPeerData(w, allocator, fj.peer.data);
                    try w.writeVarintU16(allocator, fj.ttl.value);
                },
                .shuffle => |s| {
                    try w.writeEnumDiscriminant(allocator, 2);
                    try encodePeer(w, allocator, s.origin);
                    try w.writeVarintUsize(allocator, s.nodes.len);
                    for (s.nodes) |n| {
                        try encodePeer(w, allocator, n.id);
                        try encodeOptionPeerData(w, allocator, n.data);
                    }
                    try w.writeVarintU16(allocator, s.ttl.value);
                },
                .shuffle_reply => |sr| {
                    try w.writeEnumDiscriminant(allocator, 3);
                    try w.writeVarintUsize(allocator, sr.nodes.len);
                    for (sr.nodes) |n| {
                        try encodePeer(w, allocator, n.id);
                        try encodeOptionPeerData(w, allocator, n.data);
                    }
                },
                .neighbor => |n| {
                    try w.writeEnumDiscriminant(allocator, 4);
                    try w.writeEnumDiscriminant(allocator, switch (n.priority) {
                        .high => 0,
                        .low => 1,
                    });
                    try encodeOptionPeerData(w, allocator, n.data);
                },
                .disconnect => |d| {
                    try w.writeEnumDiscriminant(allocator, 5);
                    try w.writeBool(allocator, d.alive);
                    try w.writeBool(allocator, d.respond);
                },
            }
        }

        pub fn decode(allocator: std.mem.Allocator, data: []const u8) !HyparviewMessage(PI) {
            var r = postcard.Reader.init(data);
            return try decodeFrom(&r, allocator);
        }

        pub fn decodeFrom(r: *postcard.Reader, allocator: std.mem.Allocator) !HyparviewMessage(PI) {
            return switch (try r.readEnumDiscriminant()) {
                0 => .{ .join = try decodeOptionPeerData(r, allocator) },
                1 => blk: {
                    const id = try decodePeer(r, PI, allocator);
                    const data = try decodeOptionPeerData(r, allocator);
                    errdefer if (data) |owned| allocator.free(owned);
                    const ttl: u16 = try r.readVarintU16();
                    break :blk .{ .forward_join = .{
                        .peer = .{ .id = id, .data = data },
                        .ttl = .{ .value = ttl },
                    } };
                },
                2 => blk: {
                    const origin = try decodePeer(r, PI, allocator);
                    const count = try r.readVarintUsize();
                    if (count > r.remaining().len) return error.EndOfStream;
                    const nodes = try allocator.alloc(PeerInfo(PI), count);
                    var initialized: usize = 0;
                    errdefer {
                        for (nodes[0..initialized]) |node| if (node.data) |owned| allocator.free(owned);
                        allocator.free(nodes);
                    }
                    for (nodes) |*n| {
                        n.id = try decodePeer(r, PI, allocator);
                        n.data = try decodeOptionPeerData(r, allocator);
                        initialized += 1;
                    }
                    const ttl: u16 = try r.readVarintU16();
                    break :blk .{ .shuffle = .{ .origin = origin, .nodes = nodes, .ttl = .{ .value = ttl } } };
                },
                3 => blk: {
                    const count = try r.readVarintUsize();
                    if (count > r.remaining().len) return error.EndOfStream;
                    const nodes = try allocator.alloc(PeerInfo(PI), count);
                    var initialized: usize = 0;
                    errdefer {
                        for (nodes[0..initialized]) |node| if (node.data) |owned| allocator.free(owned);
                        allocator.free(nodes);
                    }
                    for (nodes) |*n| {
                        n.id = try decodePeer(r, PI, allocator);
                        n.data = try decodeOptionPeerData(r, allocator);
                        initialized += 1;
                    }
                    break :blk .{ .shuffle_reply = .{ .nodes = nodes } };
                },
                4 => blk: {
                    const pri = try r.readEnumDiscriminant();
                    break :blk .{ .neighbor = .{
                        .priority = switch (pri) {
                            0 => .high,
                            1 => .low,
                            else => return error.InvalidOptionTag,
                        },
                        .data = try decodeOptionPeerData(r, allocator),
                    } };
                },
                5 => blk: {
                    const alive = try r.readBool();
                    const respond = try r.readBool();
                    break :blk .{ .disconnect = .{ .alive = alive, .respond = respond } };
                },
                else => return error.InvalidOptionTag,
            };
        }
    };
}

pub const IHave = struct {
    pub const POSTCARD_MAX_SIZE: usize = 35;

    id: MessageId,
    round: Round,
};

pub const Graft = struct {
    id: ?MessageId,
    round: Round,
};

pub const GossipPayload = struct {
    id: MessageId,
    content: []const u8,
    scope: DeliveryScope,

    pub fn clone(self: GossipPayload, allocator: std.mem.Allocator) !GossipPayload {
        return .{
            .id = self.id,
            .content = try allocator.dupe(u8, self.content),
            .scope = self.scope,
        };
    }

    pub fn deinit(self: GossipPayload, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.content));
    }

    pub fn validate(self: GossipPayload) bool {
        return std.mem.eql(u8, &self.id, &messageIdFromContent(self.content));
    }

    pub fn round(self: GossipPayload) ?Round {
        return switch (self.scope) {
            .swarm => |r| r,
            .neighbors => null,
        };
    }

    pub fn nextRound(self: GossipPayload, allocator: std.mem.Allocator) !?GossipPayload {
        _ = allocator;
        return switch (self.scope) {
            .neighbors => null,
            .swarm => |r| .{
                .id = self.id,
                .content = self.content,
                .scope = .{ .swarm = r.next() },
            },
        };
    }
};

pub const PlumtreeMessage = union(enum) {
    gossip: GossipPayload,
    prune,
    graft: Graft,
    ihave: []const IHave,

    pub fn encode(self: PlumtreeMessage, allocator: std.mem.Allocator) ![]u8 {
        var w = postcard.Writer.init(allocator);
        defer w.deinit(allocator);
        try self.encodeInto(&w, allocator);
        return try allocator.dupe(u8, w.written());
    }

    pub fn deinit(self: PlumtreeMessage, allocator: std.mem.Allocator) void {
        switch (self) {
            .gossip => |g| g.deinit(allocator),
            .ihave => |list| allocator.free(list),
            else => {},
        }
    }

    pub fn encodeInto(self: PlumtreeMessage, w: *postcard.Writer, allocator: std.mem.Allocator) !void {
        switch (self) {
            .gossip => |g| {
                try w.writeEnumDiscriminant(allocator, 0);
                try w.writeFixed32(allocator, g.id);
                try w.writeBytes(allocator, g.content);
                switch (g.scope) {
                    .swarm => |r| {
                        try w.writeEnumDiscriminant(allocator, 0);
                        try w.writeVarintU16(allocator, r.value);
                    },
                    .neighbors => try w.writeEnumDiscriminant(allocator, 1),
                }
            },
            .prune => try w.writeEnumDiscriminant(allocator, 1),
            .graft => |gr| {
                try w.writeEnumDiscriminant(allocator, 2);
                try w.writeOption(allocator, MessageId, gr.id, encodeMessageIdOption);
                try w.writeVarintU16(allocator, gr.round.value);
            },
            .ihave => |list| {
                try w.writeEnumDiscriminant(allocator, 3);
                try w.writeVarintUsize(allocator, list.len);
                for (list) |item| {
                    try w.writeFixed32(allocator, item.id);
                    try w.writeVarintU16(allocator, item.round.value);
                }
            },
        }
    }

    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !PlumtreeMessage {
        var r = postcard.Reader.init(data);
        return try decodeFrom(&r, allocator);
    }

    pub fn decodeFrom(r: *postcard.Reader, allocator: std.mem.Allocator) !PlumtreeMessage {
        return switch (try r.readEnumDiscriminant()) {
            0 => blk: {
                const id = try r.readFixed32();
                const content = try r.readBytes(allocator);
                errdefer allocator.free(content);
                const scope_tag = try r.readEnumDiscriminant();
                const scope: DeliveryScope = switch (scope_tag) {
                    0 => .{ .swarm = .{ .value = try r.readVarintU16() } },
                    1 => .neighbors,
                    else => return error.InvalidOptionTag,
                };
                break :blk .{ .gossip = .{ .id = id, .content = content, .scope = scope } };
            },
            1 => .prune,
            2 => blk: {
                const has_id = try r.readByte();
                const id: ?MessageId = if (has_id == 1) try r.readFixed32() else if (has_id == 0) null else return error.InvalidOptionTag;
                const round: u16 = try r.readVarintU16();
                break :blk .{ .graft = .{ .id = id, .round = .{ .value = round } } };
            },
            3 => blk: {
                const count = try r.readVarintUsize();
                if (count > r.remaining().len / 33) return error.EndOfStream;
                const list = try allocator.alloc(IHave, count);
                errdefer allocator.free(list);
                for (list) |*item| {
                    item.id = try r.readFixed32();
                    item.round = .{ .value = try r.readVarintU16() };
                }
                break :blk .{ .ihave = list };
            },
            else => return error.InvalidOptionTag,
        };
    }
};

pub fn TopicMessage(comptime PI: type) type {
    return union(enum) {
        swarm: HyparviewMessage(PI),
        gossip: PlumtreeMessage,

        pub fn encode(self: TopicMessage(PI), allocator: std.mem.Allocator) ![]u8 {
            var w = postcard.Writer.init(allocator);
            defer w.deinit(allocator);
            try self.encodeInto(&w, allocator);
            return try allocator.dupe(u8, w.written());
        }

        pub fn deinit(self: TopicMessage(PI), allocator: std.mem.Allocator) void {
            switch (self) {
                .swarm => |m| m.deinit(allocator),
                .gossip => |m| m.deinit(allocator),
            }
        }

        pub fn encodeInto(self: TopicMessage(PI), w: *postcard.Writer, allocator: std.mem.Allocator) !void {
            switch (self) {
                .swarm => |m| {
                    try w.writeEnumDiscriminant(allocator, 0);
                    try m.encodeInto(w, allocator);
                },
                .gossip => |m| {
                    try w.writeEnumDiscriminant(allocator, 1);
                    try m.encodeInto(w, allocator);
                },
            }
        }

        pub fn decode(allocator: std.mem.Allocator, data: []const u8) !TopicMessage(PI) {
            var r = postcard.Reader.init(data);
            return try decodeFrom(&r, allocator);
        }

        pub fn decodeFrom(r: *postcard.Reader, allocator: std.mem.Allocator) !TopicMessage(PI) {
            return switch (try r.readEnumDiscriminant()) {
                0 => .{ .swarm = try HyparviewMessage(PI).decodeFrom(r, allocator) },
                1 => .{ .gossip = try PlumtreeMessage.decodeFrom(r, allocator) },
                else => return error.InvalidOptionTag,
            };
        }

        pub fn isDisconnect(self: TopicMessage(PI)) bool {
            return switch (self) {
                .swarm => |m| switch (m) {
                    .disconnect => true,
                    else => false,
                },
                else => false,
            };
        }
    };
}

pub fn WireMessage(comptime PI: type) type {
    return struct {
        topic: TopicId,
        message: TopicMessage(PI),

        pub fn postcardHeaderSize() usize {
            // topic[32] + TopicMessage enum discriminant; the nested message
            // discriminant is accounted for by each message encoder.
            return 33;
        }

        pub fn encode(self: WireMessage(PI), allocator: std.mem.Allocator) ![]u8 {
            var w = postcard.Writer.init(allocator);
            defer w.deinit(allocator);
            try w.writeFixed32(allocator, self.topic);
            try self.message.encodeInto(&w, allocator);
            return try allocator.dupe(u8, w.written());
        }

        pub fn deinit(self: WireMessage(PI), allocator: std.mem.Allocator) void {
            self.message.deinit(allocator);
        }

        pub fn decode(allocator: std.mem.Allocator, data: []const u8) !WireMessage(PI) {
            var r = postcard.Reader.init(data);
            const topic = try r.readFixed32();
            const message = try TopicMessage(PI).decodeFrom(&r, allocator);
            return .{ .topic = topic, .message = message };
        }
    };
}

pub const StreamHeader = struct {
    topic_id: TopicId,

    pub fn encode(self: StreamHeader, allocator: std.mem.Allocator) ![]u8 {
        var w = postcard.Writer.init(allocator);
        defer w.deinit(allocator);
        try w.writeFixed32(allocator, self.topic_id);
        return try allocator.dupe(u8, w.written());
    }

    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !StreamHeader {
        _ = allocator;
        var r = postcard.Reader.init(data);
        return .{ .topic_id = try r.readFixed32() };
    }
};

test "blake3 golden vectors" {
    try std.testing.expectEqualSlices(u8, &fixtures.blake3_hi, &messageIdFromContent("hi"));
    try std.testing.expectEqualSlices(u8, &fixtures.blake3_hi2, &messageIdFromContent("hi2"));
}

test "delivery round saturates at the wire maximum" {
    try std.testing.expectEqual(std.math.maxInt(u16), (Round{ .value = std.math.maxInt(u16) }).next().value);
}

test "golden wire bytes" {
    const alloc = std.testing.allocator;
    const prune = TopicMessage(u32){ .gossip = .prune };
    const encoded = try prune.encode(alloc);
    defer alloc.free(encoded);
    try std.testing.expectEqualSlices(u8, &fixtures.topic_gossip_prune, encoded);

    const ihave_list = [_]IHave{.{ .id = fixtures.blake3_hi, .round = .{ .value = 2 } }};
    const ihave = PlumtreeMessage{ .ihave = &ihave_list };
    const ihave_bytes = try ihave.encode(alloc);
    defer alloc.free(ihave_bytes);
    try std.testing.expectEqualSlices(u8, &fixtures.plumtree_ihave_hi_r2, ihave_bytes);

    const gossip = PlumtreeMessage{ .gossip = .{
        .id = fixtures.blake3_hi2,
        .content = "hi2",
        .scope = .{ .swarm = .{ .value = 9 } },
    } };
    const gossip_bytes = try gossip.encode(alloc);
    defer alloc.free(gossip_bytes);
    try std.testing.expectEqualSlices(u8, &fixtures.plumtree_gossip_hi2_swarm9, gossip_bytes);

    const disc = HyparviewMessage(u32){ .disconnect = .{ .alive = true, .respond = false } };
    const disc_bytes = try disc.encode(alloc);
    defer alloc.free(disc_bytes);
    try std.testing.expectEqualSlices(u8, &fixtures.hyparview_disconnect_alive, disc_bytes);

    const hdr = WireMessage(u32).postcardHeaderSize();
    try std.testing.expectEqual(fixtures.postcard_header_size, hdr);
}

test "enum round-trip" {
    const alloc = std.testing.allocator;
    const ihave_case_list = [_]IHave{.{ .id = fixtures.blake3_hi, .round = .{ .value = 2 } }};
    const cases = [_]TopicMessage(u32){
        .{ .gossip = .prune },
        .{ .gossip = .{ .ihave = &ihave_case_list } },
        .{ .gossip = .{ .gossip = .{
            .id = fixtures.blake3_hi2,
            .content = "hi2",
            .scope = .{ .swarm = .{ .value = 9 } },
        } } },
        .{ .swarm = .{ .disconnect = .{ .alive = true, .respond = false } } },
    };
    for (cases) |msg| {
        const bytes = try msg.encode(alloc);
        defer alloc.free(bytes);
        const decoded = try TopicMessage(u32).decode(alloc, bytes);
        defer switch (decoded) {
            .gossip => |g| switch (g) {
                .gossip => |payload| alloc.free(payload.content),
                .ihave => |list| alloc.free(list),
                else => {},
            },
            .swarm => |m| m.deinit(alloc),
        };
        switch (msg) {
            .gossip => |g| switch (decoded) {
                .gossip => |dg| try std.testing.expect(@intFromEnum(g) == @intFromEnum(dg)),
                else => try std.testing.expect(false),
            },
            .swarm => |s| switch (decoded) {
                .swarm => |ds| switch (s) {
                    .disconnect => |d| switch (ds) {
                        .disconnect => |dd| {
                            try std.testing.expect(d.alive == dd.alive);
                            try std.testing.expect(d.respond == dd.respond);
                        },
                        else => try std.testing.expect(false),
                    },
                    else => {},
                },
                else => try std.testing.expect(false),
            },
        }
    }
}

test "L-7: HyparviewMessage deinit frees all PeerData" {
    const alloc = std.testing.allocator;

    {
        const msg = HyparviewMessage(u32){ .join = try alloc.dupe(u8, "peer-data") };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        msg.deinit(alloc);
        const decoded = try HyparviewMessage(u32).decode(alloc, encoded);
        decoded.deinit(alloc);
    }

    {
        const msg = HyparviewMessage(u32){ .forward_join = .{
            .peer = .{ .id = 42, .data = try alloc.dupe(u8, "fj-data") },
            .ttl = .{ .value = 5 },
        } };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        msg.deinit(alloc);
        const decoded = try HyparviewMessage(u32).decode(alloc, encoded);
        decoded.deinit(alloc);
    }

    {
        const nodes = try alloc.alloc(PeerInfo(u32), 2);
        nodes[0] = .{ .id = 1, .data = try alloc.dupe(u8, "node1") };
        nodes[1] = .{ .id = 2, .data = try alloc.dupe(u8, "node2") };
        const msg = HyparviewMessage(u32){ .shuffle = .{
            .origin = 0,
            .nodes = nodes,
            .ttl = .{ .value = 3 },
        } };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        msg.deinit(alloc);
        const decoded = try HyparviewMessage(u32).decode(alloc, encoded);
        decoded.deinit(alloc);
    }

    {
        const nodes = try alloc.alloc(PeerInfo(u32), 1);
        nodes[0] = .{ .id = 99, .data = try alloc.dupe(u8, "sr-data") };
        const msg = HyparviewMessage(u32){ .shuffle_reply = .{ .nodes = nodes } };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        msg.deinit(alloc);
        const decoded = try HyparviewMessage(u32).decode(alloc, encoded);
        decoded.deinit(alloc);
    }

    {
        const msg = HyparviewMessage(u32){ .neighbor = .{
            .priority = .high,
            .data = try alloc.dupe(u8, "neighbor-data"),
        } };
        const encoded = try msg.encode(alloc);
        defer alloc.free(encoded);
        msg.deinit(alloc);
        const decoded = try HyparviewMessage(u32).decode(alloc, encoded);
        decoded.deinit(alloc);
    }
}

test "malformed allocating messages release partial decode state" {
    const alloc = std.testing.allocator;

    // Shuffle: one complete allocating peer followed by a truncated peer.
    try std.testing.expectError(
        error.EndOfStream,
        HyparviewMessage(u32).decode(alloc, &.{ 2, 0, 2, 1, 1, 3, 'o', 'n', 'e', 2 }),
    );

    // Gossip: content is allocated before the invalid scope discriminant.
    var malformed_gossip: [38]u8 = undefined;
    malformed_gossip[0] = 0;
    @memset(malformed_gossip[1..33], 0);
    malformed_gossip[33] = 3;
    @memcpy(malformed_gossip[34..37], "bad");
    malformed_gossip[37] = 2;
    try std.testing.expectError(error.InvalidOptionTag, PlumtreeMessage.decode(alloc, &malformed_gossip));
}

test "malformed vector counts are bounded before allocation" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.EndOfStream, HyparviewMessage(u32).decode(alloc, &.{ 2, 0, 127 }));
    try std.testing.expectError(error.EndOfStream, HyparviewMessage(u32).decode(alloc, &.{ 3, 127 }));
    try std.testing.expectError(error.EndOfStream, PlumtreeMessage.decode(alloc, &.{ 3, 127 }));
}

test "neighbor rejects unknown priority discriminants" {
    try std.testing.expectError(
        error.InvalidOptionTag,
        HyparviewMessage(u32).decode(std.testing.allocator, &.{ 4, 2, 0 }),
    );
}
