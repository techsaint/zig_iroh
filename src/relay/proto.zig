//! DERP wire protocol codec — byte-compatible with iroh's relay framing.
//!
//! Each WebSocket binary message carries exactly one protocol frame.
//! Layout: `[FrameType: QUIC varint][payload bytes...]`
//!
//! Tags 0..13 are single-byte varints. Payloads are raw bytes (big-endian
//! integers, no trailing length — parser reads to end of WS payload).
//!
//! Reference: `original/iroh/iroh-relay/src/protos/common.rs` (FrameType enum)
//!            `original/iroh/iroh-relay/src/protos/relay.rs` (data frames)

const std = @import("std");
const key = @import("../key.zig");

/// Maximum datagram payload size (64 KiB).
pub const MAX_PACKET_SIZE: usize = 64 * 1024;
/// Maximum encoded relay frame: an 8-byte QUIC varint tag plus the bounded
/// post-tag payload. Keeping receive buffers at the actual wire limit avoids
/// a 1 MiB allocation per pre-authentication reader and writer.
pub const MAX_FRAME_SIZE: usize = MAX_PACKET_SIZE + 8;

/// Protocol version negotiation (iroh-relay-v1 / iroh-relay-v2).
pub const ProtocolVersion = enum(u8) {
    v1 = 1,
    v2 = 2,

    pub fn fromString(s: []const u8) ?ProtocolVersion {
        if (std.mem.eql(u8, s, "iroh-relay-v1")) return .v1;
        if (std.mem.eql(u8, s, "iroh-relay-v2")) return .v2;
        return null;
    }

    pub fn toString(self: ProtocolVersion) []const u8 {
        return switch (self) {
            .v1 => "iroh-relay-v1",
            .v2 => "iroh-relay-v2",
        };
    }

    /// The preferred/default version.
    pub const preferred: ProtocolVersion = .v2;
};

/// DERP frame type tags (tags 0..13).
/// Reference: `original/iroh/iroh-relay/src/protos/common.rs:18-65`
pub const FrameType = enum(u6) {
    server_challenge = 0,
    client_auth = 1,
    server_confirms_auth = 2,
    server_denies_auth = 3,
    client_to_relay_datagram = 4,
    client_to_relay_datagram_batch = 5,
    relay_to_client_datagram = 6,
    relay_to_client_datagram_batch = 7,
    endpoint_gone = 8,
    ping = 9,
    pong = 10,
    health = 11,
    restarting = 12,
    status = 13,

    /// Whether this frame type is valid for a given protocol version.
    pub fn validForVersion(self: FrameType, ver: ProtocolVersion) bool {
        return switch (self) {
            .health => ver == .v1,
            .status => ver == .v2,
            else => true,
        };
    }
};

/// QUIC varint encoding/decoding.
///
/// Tags 0..13 are < 64, so they encode as a single byte equal to the tag.
/// The parser must handle multi-byte varints but can reject them for valid frames.
pub fn writeVarint(val: u64, writer: *std.Io.Writer) !void {
    if (val < 64) {
        try writer.writeByte(@intCast(val));
    } else if (val < (1 << 14)) {
        try writer.writeByte(@intCast(0x40 | (val >> 8)));
        try writer.writeByte(@intCast(val & 0xFF));
    } else if (val < (1 << 30)) {
        try writer.writeInt(u32, @intCast(0x80000000 | val), .big);
    } else {
        try writer.writeInt(u64, 0xC000000000000000 | val, .big);
    }
}

pub fn readVarint(reader: *std.Io.Reader) !u64 {
    const first = try reader.takeByte();
    const prefix = first >> 6;
    switch (prefix) {
        0b00 => return first,
        0b01 => {
            const second = try reader.takeByte();
            return (@as(u64, first & 0x3F) << 8) | second;
        },
        0b10 => {
            var buf: [3]u8 = undefined;
            try reader.readSliceAll(&buf);
            return (@as(u64, first & 0x3F) << 24) |
                (@as(u64, buf[0]) << 16) |
                (@as(u64, buf[1]) << 8) |
                buf[2];
        },
        0b11 => {
            var buf: [7]u8 = undefined;
            try reader.readSliceAll(&buf);
            return (@as(u64, first & 0x3F) << 56) |
                (@as(u64, buf[0]) << 48) |
                (@as(u64, buf[1]) << 40) |
                (@as(u64, buf[2]) << 32) |
                (@as(u64, buf[3]) << 24) |
                (@as(u64, buf[4]) << 16) |
                (@as(u64, buf[5]) << 8) |
                buf[6];
        },
        else => unreachable,
    }
}

/// ECN codepoint.
pub const Ecn = enum(u2) {
    not_ect = 0,
    ect1 = 1,
    ect0 = 2,
    ce = 3,
};

/// Shared datagram body (used by tags 4/5/6/7).
/// Reference: `original/iroh/iroh-relay/src/protos/relay.rs:252-292`
pub const Datagrams = struct {
    ecn: Ecn,
    /// Present only for Batch variants (tags 5, 7).
    segment_size: ?u16,
    /// The datagram payload (or concatenated segments for batch).
    contents: []const u8,
};

/// Client → relay messages.
pub const ClientToRelayMsg = union(enum) {
    /// Tag 4: single datagram to `dst`.
    datagram: struct {
        dst: key.PublicKey,
        datagrams: Datagrams,
    },
    /// Tag 5: batch datagram to `dst`.
    datagram_batch: struct {
        dst: key.PublicKey,
        datagrams: Datagrams,
    },
    /// Tag 9: ping (8 bytes opaque).
    ping: [8]u8,
    /// Tag 10: pong (8 bytes opaque).
    pong: [8]u8,
};

/// Relay → client messages.
pub const RelayToClientMsg = union(enum) {
    /// Tag 6: single datagram from `src`.
    datagram: struct {
        src: key.PublicKey,
        datagrams: Datagrams,
    },
    /// Tag 7: batch datagram from `src`.
    datagram_batch: struct {
        src: key.PublicKey,
        datagrams: Datagrams,
    },
    /// Tag 8: endpoint gone.
    endpoint_gone: key.PublicKey,
    /// Tag 9: ping (server keepalive).
    ping: [8]u8,
    /// Tag 10: pong (response to server ping).
    pong: [8]u8,
    /// Tag 11: health (V1 only).
    health: []const u8,
    /// Tag 12: restarting.
    restarting: Restarting,
    /// Tag 13: status (V2 only).
    status: Status,
};

pub const Restarting = struct {
    reconnect_in: u32,
    try_for: u32,
};

pub const Status = enum(u8) {
    healthy = 0,
    same_endpoint_id_connected = 1,
    _,
};

// --- Encoding ---------------------------------------------------------------

/// Encode a `ClientToRelayMsg` into a single WS binary frame.
pub fn encodeClientToRelay(msg: ClientToRelayMsg, writer: *std.Io.Writer) !void {
    try validateClientToRelay(msg);
    switch (msg) {
        .datagram => |d| {
            try writeVarint(@intFromEnum(FrameType.client_to_relay_datagram), writer);
            try writer.writeAll(&d.dst.bytes);
            try encodeDatagrams(d.datagrams, false, writer);
        },
        .datagram_batch => |d| {
            try writeVarint(@intFromEnum(FrameType.client_to_relay_datagram_batch), writer);
            try writer.writeAll(&d.dst.bytes);
            try encodeDatagrams(d.datagrams, true, writer);
        },
        .ping => |p| {
            try writeVarint(@intFromEnum(FrameType.ping), writer);
            try writer.writeAll(&p);
        },
        .pong => |p| {
            try writeVarint(@intFromEnum(FrameType.pong), writer);
            try writer.writeAll(&p);
        },
    }
}

/// Encode a `RelayToClientMsg` into a single WS binary frame.
pub fn encodeRelayToClient(msg: RelayToClientMsg, writer: *std.Io.Writer) !void {
    try validateRelayToClient(msg);
    switch (msg) {
        .datagram => |d| {
            try writeVarint(@intFromEnum(FrameType.relay_to_client_datagram), writer);
            try writer.writeAll(&d.src.bytes);
            try encodeDatagrams(d.datagrams, false, writer);
        },
        .datagram_batch => |d| {
            try writeVarint(@intFromEnum(FrameType.relay_to_client_datagram_batch), writer);
            try writer.writeAll(&d.src.bytes);
            try encodeDatagrams(d.datagrams, true, writer);
        },
        .endpoint_gone => |pk| {
            try writeVarint(@intFromEnum(FrameType.endpoint_gone), writer);
            try writer.writeAll(&pk.bytes);
        },
        .ping => |p| {
            try writeVarint(@intFromEnum(FrameType.ping), writer);
            try writer.writeAll(&p);
        },
        .pong => |p| {
            try writeVarint(@intFromEnum(FrameType.pong), writer);
            try writer.writeAll(&p);
        },
        .health => |s| {
            try writeVarint(@intFromEnum(FrameType.health), writer);
            try writer.writeAll(s);
        },
        .restarting => |r| {
            try writeVarint(@intFromEnum(FrameType.restarting), writer);
            try writer.writeInt(u32, r.reconnect_in, .big);
            try writer.writeInt(u32, r.try_for, .big);
        },
        .status => |s| {
            try writeVarint(@intFromEnum(FrameType.status), writer);
            try writer.writeByte(@intFromEnum(s));
        },
    }
}

fn validateClientToRelay(msg: ClientToRelayMsg) !void {
    switch (msg) {
        .datagram => |d| try validateDatagrams(d.datagrams, false),
        .datagram_batch => |d| try validateDatagrams(d.datagrams, true),
        .ping, .pong => {},
    }
}

fn validateRelayToClient(msg: RelayToClientMsg) !void {
    switch (msg) {
        .datagram => |d| try validateDatagrams(d.datagrams, false),
        .datagram_batch => |d| try validateDatagrams(d.datagrams, true),
        .health => |problem| {
            // iroh models this as a String and rejects invalid UTF-8 on decode.
            if (!std.unicode.utf8ValidateSlice(problem)) return error.InvalidUtf8;
            if (problem.len > MAX_PACKET_SIZE - 1) return error.PacketTooLarge;
        },
        .endpoint_gone, .ping, .pong, .restarting, .status => {},
    }
}

fn validateDatagrams(d: Datagrams, is_batch: bool) !void {
    if (d.contents.len == 0) return error.EmptyPacket;

    // Rust's production sinks bound the entire encoded message, including the
    // one-byte tag, endpoint id, ECN byte, and optional segment size.
    const frame_overhead: usize = if (is_batch) 1 + 32 + 1 + 2 else 1 + 32 + 1;
    if (d.contents.len > MAX_PACKET_SIZE - frame_overhead) return error.PacketTooLarge;

    if (is_batch) {
        const seg = d.segment_size orelse return error.MissingSegmentSize;
        if (seg == 0) return error.InvalidSegmentSize;
    } else if (d.segment_size != null) {
        return error.UnexpectedSegmentSize;
    }
}

fn encodeDatagrams(d: Datagrams, is_batch: bool, writer: *std.Io.Writer) !void {
    try writer.writeByte(@intFromEnum(d.ecn));
    if (is_batch) {
        const seg = d.segment_size orelse return error.MissingSegmentSize;
        if (seg == 0) return error.InvalidSegmentSize;
        if (seg > MAX_PACKET_SIZE) return error.PacketTooLarge;
        try writer.writeInt(u16, seg, .big);
    } else if (d.contents.len > MAX_PACKET_SIZE) {
        return error.PacketTooLarge;
    }
    try writer.writeAll(d.contents);
}

// --- Decoding ---------------------------------------------------------------

/// Decode a `ClientToRelayMsg` from a raw frame buffer (tag already consumed or
/// included — this function expects the FULL frame bytes including the tag byte).
pub fn decodeClientToRelay(buf: []const u8, version: ProtocolVersion) !ClientToRelayMsg {
    const parsed = try parseFrame(buf, version);
    const ft = parsed.frame_type;
    const payload = parsed.payload;
    return switch (ft) {
        .client_to_relay_datagram => {
            if (payload.len < 33) return error.FrameTooShort;
            const dst = try key.PublicKey.fromBytes(payload[0..32].*);
            const datagrams = try decodeDatagrams(payload[32..], false);
            return .{ .datagram = .{ .dst = dst, .datagrams = datagrams } };
        },
        .client_to_relay_datagram_batch => {
            if (payload.len < 35) return error.FrameTooShort;
            const dst = try key.PublicKey.fromBytes(payload[0..32].*);
            const datagrams = try decodeDatagrams(payload[32..], true);
            return .{ .datagram_batch = .{ .dst = dst, .datagrams = datagrams } };
        },
        .ping => {
            if (payload.len != 8) return error.InvalidFrameLength;
            var p: [8]u8 = undefined;
            @memcpy(&p, payload);
            return .{ .ping = p };
        },
        .pong => {
            if (payload.len != 8) return error.InvalidFrameLength;
            var p: [8]u8 = undefined;
            @memcpy(&p, payload);
            return .{ .pong = p };
        },
        else => error.UnexpectedFrameType,
    };
}

/// Decode a `RelayToClientMsg` from a raw frame buffer (including tag byte).
pub fn decodeRelayToClient(buf: []const u8, version: ProtocolVersion) !RelayToClientMsg {
    const parsed = try parseFrame(buf, version);
    const ft = parsed.frame_type;
    const payload = parsed.payload;
    return switch (ft) {
        .relay_to_client_datagram => {
            if (payload.len < 33) return error.FrameTooShort;
            const src = try key.PublicKey.fromBytes(payload[0..32].*);
            const datagrams = try decodeDatagrams(payload[32..], false);
            return .{ .datagram = .{ .src = src, .datagrams = datagrams } };
        },
        .relay_to_client_datagram_batch => {
            if (payload.len < 35) return error.FrameTooShort;
            const src = try key.PublicKey.fromBytes(payload[0..32].*);
            const datagrams = try decodeDatagrams(payload[32..], true);
            return .{ .datagram_batch = .{ .src = src, .datagrams = datagrams } };
        },
        .endpoint_gone => {
            if (payload.len != 32) return error.InvalidFrameLength;
            const pk = try key.PublicKey.fromBytes(payload[0..32].*);
            return .{ .endpoint_gone = pk };
        },
        .ping => {
            if (payload.len != 8) return error.InvalidFrameLength;
            var p: [8]u8 = undefined;
            @memcpy(&p, payload);
            return .{ .ping = p };
        },
        .pong => {
            if (payload.len != 8) return error.InvalidFrameLength;
            var p: [8]u8 = undefined;
            @memcpy(&p, payload);
            return .{ .pong = p };
        },
        .health => {
            if (!std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
            return .{ .health = payload };
        },
        .restarting => {
            if (payload.len != 8) return error.InvalidFrameLength;
            return .{ .restarting = .{
                .reconnect_in = std.mem.readInt(u32, payload[0..4], .big),
                .try_for = std.mem.readInt(u32, payload[4..8], .big),
            } };
        },
        .status => {
            if (payload.len < 1) return error.FrameTooShort;
            return .{ .status = @enumFromInt(payload[0]) };
        },
        else => error.UnexpectedFrameType,
    };
}

fn decodeDatagrams(buf: []const u8, is_batch: bool) !Datagrams {
    if (buf.len < 1) return error.FrameTooShort;
    // Rust's EcnCodepoint::from_bits ignores reserved high bits.
    const ecn: Ecn = @enumFromInt(buf[0] & 0x03);
    var offset: usize = 1;
    var segment_size: ?u16 = null;
    if (is_batch) {
        if (buf.len < 3) return error.FrameTooShort;
        const seg = std.mem.readInt(u16, buf[1..3], .big);
        // Rust decodes zero through NonZeroU16::new into None while retaining
        // the batch frame tag; preserve that accepted wire behavior.
        segment_size = if (seg == 0) null else seg;
        offset = 3;
    } else if (buf.len - 1 > MAX_PACKET_SIZE) {
        return error.PacketTooLarge;
    }
    return .{
        .ecn = ecn,
        .segment_size = segment_size,
        .contents = buf[offset..],
    };
}

const ParsedFrame = struct {
    frame_type: FrameType,
    payload: []const u8,
};

fn parseFrame(buf: []const u8, version: ProtocolVersion) !ParsedFrame {
    if (buf.len == 0) return error.EmptyFrame;

    var reader = std.Io.Reader.fixed(buf);
    const tag_val = try readVarint(&reader);
    if (tag_val > 13) return error.UnknownFrameType;
    const frame_type: FrameType = @enumFromInt(@as(u6, @intCast(tag_val)));
    if (!frame_type.validForVersion(version)) return error.InvalidFrameForVersion;

    const payload = buf[reader.seek..];
    if (payload.len > MAX_PACKET_SIZE) return error.FrameTooLarge;
    return .{ .frame_type = frame_type, .payload = payload };
}

// --- Tests ------------------------------------------------------------------

const testing = std.testing;

// The test public key from the snapshot vectors:
// client_key = SecretKey::from_bytes(&[42u8; 32])
// public key = 197f6b23e16c8532c6abc838facd5ea7 89be0c76b2920334 039bfa8b3d368d61
const TEST_PUB_BYTES: [32]u8 = .{
    0x19, 0x7f, 0x6b, 0x23, 0xe1, 0x6c, 0x85, 0x32,
    0xc6, 0xab, 0xc8, 0x38, 0xfa, 0xcd, 0x5e, 0xa7,
    0x89, 0xbe, 0x0c, 0x76, 0xb2, 0x92, 0x03, 0x34,
    0x03, 0x9b, 0xfa, 0x8b, 0x3d, 0x36, 0x8d, 0x61,
};

fn testPub() key.PublicKey {
    return key.PublicKey{ .bytes = TEST_PUB_BYTES };
}

const PING_42: [8]u8 = .{42} ** 8;

// --- Server→client snapshot vectors ---
// Reference: `protos/relay.rs:596-681`

test "Health frame matches iroh snapshot" {
    // Health{"Hello? Yes this is dog."} = 0b 48656c6c6f3f...
    const msg = RelayToClientMsg{ .health = "Hello? Yes this is dog." };
    var buf: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeRelayToClient(msg, &writer);
    const encoded = writer.buffered();
    try testing.expectEqual(@as(usize, 24), encoded.len);
    try testing.expectEqual(@as(u8, 0x0b), encoded[0]);
    try testing.expectEqualStrings("Hello? Yes this is dog.", encoded[1..]);
}

test "EndpointGone frame matches iroh snapshot" {
    const msg = RelayToClientMsg{ .endpoint_gone = testPub() };
    var buf: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeRelayToClient(msg, &writer);
    const encoded = writer.buffered();
    try testing.expectEqual(@as(usize, 33), encoded.len);
    try testing.expectEqual(@as(u8, 0x08), encoded[0]);
    try testing.expectEqualSlices(u8, &TEST_PUB_BYTES, encoded[1..33]);
}

test "Ping [42;8] matches iroh snapshot" {
    const msg = RelayToClientMsg{ .ping = PING_42 };
    var buf: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeRelayToClient(msg, &writer);
    const encoded = writer.buffered();
    try testing.expectEqual(@as(usize, 9), encoded.len);
    try testing.expectEqual(@as(u8, 0x09), encoded[0]);
    try testing.expectEqualSlices(u8, &PING_42, encoded[1..9]);
}

test "Pong [42;8] matches iroh snapshot" {
    const msg = RelayToClientMsg{ .pong = PING_42 };
    var buf: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeRelayToClient(msg, &writer);
    const encoded = writer.buffered();
    try testing.expectEqual(@as(usize, 9), encoded.len);
    try testing.expectEqual(@as(u8, 0x0a), encoded[0]);
    try testing.expectEqualSlices(u8, &PING_42, encoded[1..9]);
}

test "RelayToClient Batch datagram matches iroh snapshot" {
    // Tag 07, 32-byte pubkey, ecn=3(Ce), seg_size=6, contents="Hello World!"
    const msg = RelayToClientMsg{ .datagram_batch = .{
        .src = testPub(),
        .datagrams = .{
            .ecn = .ce,
            .segment_size = 6,
            .contents = "Hello World!",
        },
    } };
    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeRelayToClient(msg, &writer);
    const encoded = writer.buffered();

    // Expected: 07 <32B pub> 03 0006 48656c6c6f20576f726c6421
    try testing.expectEqual(@as(u8, 0x07), encoded[0]);
    try testing.expectEqualSlices(u8, &TEST_PUB_BYTES, encoded[1..33]);
    try testing.expectEqual(@as(u8, 0x03), encoded[33]); // ECN = Ce
    try testing.expectEqual(@as(u8, 0x00), encoded[34]); // seg_size hi
    try testing.expectEqual(@as(u8, 0x06), encoded[35]); // seg_size lo
    try testing.expectEqualStrings("Hello World!", encoded[36..]);
}

test "RelayToClient single datagram matches iroh snapshot" {
    // Tag 06, 32-byte pubkey, ecn=3(Ce), no segment_size, contents="Hello World!"
    const msg = RelayToClientMsg{ .datagram = .{
        .src = testPub(),
        .datagrams = .{
            .ecn = .ce,
            .segment_size = null,
            .contents = "Hello World!",
        },
    } };
    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeRelayToClient(msg, &writer);
    const encoded = writer.buffered();

    // Expected: 06 <32B pub> 03 48656c6c6f20576f726c6421
    try testing.expectEqual(@as(u8, 0x06), encoded[0]);
    try testing.expectEqualSlices(u8, &TEST_PUB_BYTES, encoded[1..33]);
    try testing.expectEqual(@as(u8, 0x03), encoded[33]); // ECN = Ce
    try testing.expectEqualStrings("Hello World!", encoded[34..]);
}

test "Restarting matches iroh snapshot" {
    // Tag 0c, reconnect_in=10ms, try_for=20ms
    const msg = RelayToClientMsg{ .restarting = .{ .reconnect_in = 10, .try_for = 20 } };
    var buf: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeRelayToClient(msg, &writer);
    const encoded = writer.buffered();

    // Expected: 0c 0000000a 00000014
    try testing.expectEqualSlices(u8, &[_]u8{ 0x0c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x14 }, encoded);
}

test "Status(SameEndpointIdConnected) matches iroh snapshot" {
    // Tag 0d, value 01
    const msg = RelayToClientMsg{ .status = .same_endpoint_id_connected };
    var buf: [8]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeRelayToClient(msg, &writer);
    const encoded = writer.buffered();

    try testing.expectEqualSlices(u8, &[_]u8{ 0x0d, 0x01 }, encoded);
}

// --- Client→server snapshot vectors ---
// Reference: `protos/relay.rs:684-743`

test "ClientToRelay Ping [42;8] matches iroh snapshot" {
    const msg = ClientToRelayMsg{ .ping = PING_42 };
    var buf: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeClientToRelay(msg, &writer);
    const encoded = writer.buffered();
    try testing.expectEqual(@as(usize, 9), encoded.len);
    try testing.expectEqual(@as(u8, 0x09), encoded[0]);
    try testing.expectEqualSlices(u8, &PING_42, encoded[1..9]);
}

test "ClientToRelay Pong [42;8] matches iroh snapshot" {
    const msg = ClientToRelayMsg{ .pong = PING_42 };
    var buf: [16]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeClientToRelay(msg, &writer);
    const encoded = writer.buffered();
    try testing.expectEqual(@as(usize, 9), encoded.len);
    try testing.expectEqual(@as(u8, 0x0a), encoded[0]);
    try testing.expectEqualSlices(u8, &PING_42, encoded[1..9]);
}

test "ClientToRelay Batch datagram matches iroh snapshot" {
    // Tag 05, <32B pub> 03 0006 48656c6c6f20576f726c6421
    const msg = ClientToRelayMsg{ .datagram_batch = .{
        .dst = testPub(),
        .datagrams = .{
            .ecn = .ce,
            .segment_size = 6,
            .contents = "Hello World!",
        },
    } };
    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeClientToRelay(msg, &writer);
    const encoded = writer.buffered();

    try testing.expectEqual(@as(u8, 0x05), encoded[0]);
    try testing.expectEqualSlices(u8, &TEST_PUB_BYTES, encoded[1..33]);
    try testing.expectEqual(@as(u8, 0x03), encoded[33]);
    try testing.expectEqual(@as(u8, 0x00), encoded[34]);
    try testing.expectEqual(@as(u8, 0x06), encoded[35]);
    try testing.expectEqualStrings("Hello World!", encoded[36..]);
}

test "ClientToRelay single datagram matches iroh snapshot" {
    // Tag 04, <32B pub> 03 48656c6c6f20576f726c6421
    const msg = ClientToRelayMsg{ .datagram = .{
        .dst = testPub(),
        .datagrams = .{
            .ecn = .ce,
            .segment_size = null,
            .contents = "Hello World!",
        },
    } };
    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeClientToRelay(msg, &writer);
    const encoded = writer.buffered();

    try testing.expectEqual(@as(u8, 0x04), encoded[0]);
    try testing.expectEqualSlices(u8, &TEST_PUB_BYTES, encoded[1..33]);
    try testing.expectEqual(@as(u8, 0x03), encoded[33]);
    try testing.expectEqualStrings("Hello World!", encoded[34..]);
}

// --- Round-trip encode/decode tests ---

test "round-trip: RelayToClient datagram" {
    const msg = RelayToClientMsg{ .datagram = .{
        .src = testPub(),
        .datagrams = .{ .ecn = .ect1, .segment_size = null, .contents = "test payload" },
    } };
    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeRelayToClient(msg, &writer);
    const encoded = writer.buffered();

    const decoded = try decodeRelayToClient(encoded, .v2);
    try testing.expect(decoded == .datagram);
    try testing.expect(decoded.datagram.src.eql(testPub()));
    try testing.expectEqual(Ecn.ect1, decoded.datagram.datagrams.ecn);
    try testing.expectEqual(@as(?u16, null), decoded.datagram.datagrams.segment_size);
    try testing.expectEqualStrings("test payload", decoded.datagram.datagrams.contents);
}

test "round-trip: ClientToRelay batch datagram" {
    const msg = ClientToRelayMsg{ .datagram_batch = .{
        .dst = testPub(),
        .datagrams = .{ .ecn = .ce, .segment_size = 5, .contents = "abcde12345" },
    } };
    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeClientToRelay(msg, &writer);
    const encoded = writer.buffered();

    const decoded = try decodeClientToRelay(encoded, .v2);
    try testing.expect(decoded == .datagram_batch);
    try testing.expect(decoded.datagram_batch.dst.eql(testPub()));
    try testing.expectEqual(Ecn.ce, decoded.datagram_batch.datagrams.ecn);
    try testing.expectEqual(@as(?u16, 5), decoded.datagram_batch.datagrams.segment_size);
    try testing.expectEqualStrings("abcde12345", decoded.datagram_batch.datagrams.contents);
}

test "V1/V2 gating: Health invalid in V2" {
    const decoded = decodeRelayToClient(&[_]u8{0x0b} ++ "hello", .v2);
    try testing.expectError(error.InvalidFrameForVersion, decoded);
}

test "V1/V2 gating: Status invalid in V1" {
    const decoded = decodeRelayToClient(&[_]u8{ 0x0d, 0x00 }, .v1);
    try testing.expectError(error.InvalidFrameForVersion, decoded);
}

test "datagram decode masks reserved ECN high bits like Rust" {
    const frame = [_]u8{0x04} ++ TEST_PUB_BYTES ++ [_]u8{0x04};
    const decoded = try decodeClientToRelay(&frame, .v1);
    try testing.expectEqual(Ecn.not_ect, decoded.datagram.datagrams.ecn);
}

test "batch zero segment decodes as none and single encode rejects segment metadata" {
    const batch = [_]u8{0x05} ++ TEST_PUB_BYTES ++ [_]u8{ 0x01, 0x00, 0x00, 0x2a };
    const decoded = try decodeClientToRelay(&batch, .v2);
    try testing.expect(decoded == .datagram_batch);
    try testing.expectEqual(@as(?u16, null), decoded.datagram_batch.datagrams.segment_size);
    try testing.expectEqualStrings("*", decoded.datagram_batch.datagrams.contents);

    var out: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out);
    try testing.expectError(error.UnexpectedSegmentSize, encodeClientToRelay(.{ .datagram = .{
        .dst = testPub(),
        .datagrams = .{ .ecn = .ect0, .segment_size = 1, .contents = "x" },
    } }, &writer));
    try testing.expectEqual(@as(usize, 0), writer.buffered().len);
}

test "known frame tags decode from every QUIC varint width" {
    const tag_encodings = [_][]const u8{
        "\x09",
        "\x40\x09",
        "\x80\x00\x00\x09",
        "\xc0\x00\x00\x00\x00\x00\x00\x09",
    };

    for (tag_encodings) |tag| {
        var frame: [16]u8 = undefined;
        @memcpy(frame[0..tag.len], tag);
        @memcpy(frame[tag.len..][0..PING_42.len], &PING_42);
        const encoded = frame[0 .. tag.len + PING_42.len];

        const client_msg = try decodeClientToRelay(encoded, .v2);
        try testing.expect(client_msg == .ping);
        try testing.expectEqual(PING_42, client_msg.ping);

        const relay_msg = try decodeRelayToClient(encoded, .v2);
        try testing.expect(relay_msg == .ping);
        try testing.expectEqual(PING_42, relay_msg.ping);
    }
}

test "inbound frame content is capped after the varint tag" {
    const frame = try testing.allocator.alloc(u8, MAX_PACKET_SIZE + 2);
    defer testing.allocator.free(frame);
    frame[0] = @intFromEnum(FrameType.health);
    @memset(frame[1..], 'a');

    const at_limit = try decodeRelayToClient(frame[0 .. MAX_PACKET_SIZE + 1], .v1);
    try testing.expect(at_limit == .health);
    try testing.expectEqual(@as(usize, MAX_PACKET_SIZE), at_limit.health.len);
    try testing.expectError(error.FrameTooLarge, decodeRelayToClient(frame, .v1));
}

test "inbound datagram batch cannot retain more than 64 KiB" {
    const frame = try testing.allocator.alloc(u8, MAX_PACKET_SIZE + 2);
    defer testing.allocator.free(frame);
    frame[0] = @intFromEnum(FrameType.relay_to_client_datagram_batch);
    @memset(frame[1..], 0);

    try testing.expectError(error.FrameTooLarge, decodeRelayToClient(frame, .v2));
}

test "outbound datagram frames enforce full encoded limit and nonempty contents" {
    const single_overhead: usize = 1 + 32 + 1;
    const max_single_contents = MAX_PACKET_SIZE - single_overhead;
    const single_contents = try testing.allocator.alloc(u8, max_single_contents + 1);
    defer testing.allocator.free(single_contents);
    @memset(single_contents, 0x5a);

    const encoded = try testing.allocator.alloc(u8, MAX_PACKET_SIZE);
    defer testing.allocator.free(encoded);
    var writer = std.Io.Writer.fixed(encoded);
    try encodeClientToRelay(.{ .datagram = .{
        .dst = testPub(),
        .datagrams = .{ .ecn = .not_ect, .segment_size = null, .contents = single_contents[0..max_single_contents] },
    } }, &writer);
    try testing.expectEqual(@as(usize, MAX_PACKET_SIZE), writer.buffered().len);

    var reject_buf: [1]u8 = undefined;
    var reject_writer = std.Io.Writer.fixed(&reject_buf);
    try testing.expectError(error.PacketTooLarge, encodeClientToRelay(.{ .datagram = .{
        .dst = testPub(),
        .datagrams = .{ .ecn = .not_ect, .segment_size = null, .contents = single_contents },
    } }, &reject_writer));

    reject_writer = std.Io.Writer.fixed(&reject_buf);
    try testing.expectError(error.EmptyPacket, encodeClientToRelay(.{ .datagram = .{
        .dst = testPub(),
        .datagrams = .{ .ecn = .not_ect, .segment_size = null, .contents = "" },
    } }, &reject_writer));

    const batch_overhead: usize = 1 + 32 + 1 + 2;
    const max_batch_contents = MAX_PACKET_SIZE - batch_overhead;
    writer = std.Io.Writer.fixed(encoded);
    try encodeRelayToClient(.{ .datagram_batch = .{
        .src = testPub(),
        .datagrams = .{ .ecn = .ect0, .segment_size = 1200, .contents = single_contents[0..max_batch_contents] },
    } }, &writer);
    try testing.expectEqual(@as(usize, MAX_PACKET_SIZE), writer.buffered().len);

    reject_writer = std.Io.Writer.fixed(&reject_buf);
    try testing.expectError(error.PacketTooLarge, encodeRelayToClient(.{ .datagram_batch = .{
        .src = testPub(),
        .datagrams = .{ .ecn = .ect0, .segment_size = 1200, .contents = single_contents[0 .. max_batch_contents + 1] },
    } }, &reject_writer));
}

test "fixed-width relay payloads require exact lengths" {
    const ping_short = [_]u8{0x09} ++ [_]u8{0x2a} ** 7;
    try testing.expectError(error.InvalidFrameLength, decodeClientToRelay(&ping_short, .v2));
    try testing.expectError(error.InvalidFrameLength, decodeRelayToClient(&ping_short, .v2));

    const ping_extra = [_]u8{0x09} ++ PING_42 ++ [_]u8{0x00};
    try testing.expectError(error.InvalidFrameLength, decodeClientToRelay(&ping_extra, .v2));
    try testing.expectError(error.InvalidFrameLength, decodeRelayToClient(&ping_extra, .v2));

    const pong_short = [_]u8{0x0a} ++ [_]u8{0x2a} ** 7;
    try testing.expectError(error.InvalidFrameLength, decodeClientToRelay(&pong_short, .v2));
    try testing.expectError(error.InvalidFrameLength, decodeRelayToClient(&pong_short, .v2));

    const pong_extra = [_]u8{0x0a} ++ PING_42 ++ [_]u8{0x00};
    try testing.expectError(error.InvalidFrameLength, decodeClientToRelay(&pong_extra, .v2));
    try testing.expectError(error.InvalidFrameLength, decodeRelayToClient(&pong_extra, .v2));

    var endpoint_short: [32]u8 = undefined;
    endpoint_short[0] = 0x08;
    @memcpy(endpoint_short[1..], TEST_PUB_BYTES[0..31]);
    try testing.expectError(error.InvalidFrameLength, decodeRelayToClient(&endpoint_short, .v2));

    const endpoint_extra = [_]u8{0x08} ++ TEST_PUB_BYTES ++ [_]u8{0x00};
    try testing.expectError(error.InvalidFrameLength, decodeRelayToClient(&endpoint_extra, .v2));

    const restarting_short = [_]u8{ 0x0c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00 };
    try testing.expectError(error.InvalidFrameLength, decodeRelayToClient(&restarting_short, .v2));

    const restarting_extra = [_]u8{ 0x0c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x14, 0x00 };
    try testing.expectError(error.InvalidFrameLength, decodeRelayToClient(&restarting_extra, .v2));
}

test "Health requires UTF-8 on decode and encode" {
    const invalid_health = [_]u8{ 0x0b, 0xff };
    try testing.expectError(error.InvalidUtf8, decodeRelayToClient(&invalid_health, .v1));

    var buf: [8]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try testing.expectError(error.InvalidUtf8, encodeRelayToClient(.{ .health = "\xff" }, &writer));

    const health = try testing.allocator.alloc(u8, MAX_PACKET_SIZE);
    defer testing.allocator.free(health);
    @memset(health, 'a');
    const encoded = try testing.allocator.alloc(u8, MAX_PACKET_SIZE);
    defer testing.allocator.free(encoded);
    writer = std.Io.Writer.fixed(encoded);
    try encodeRelayToClient(.{ .health = health[0 .. MAX_PACKET_SIZE - 1] }, &writer);
    try testing.expectEqual(@as(usize, MAX_PACKET_SIZE), writer.buffered().len);

    writer = std.Io.Writer.fixed(&buf);
    try testing.expectError(error.PacketTooLarge, encodeRelayToClient(.{ .health = health }, &writer));
}
