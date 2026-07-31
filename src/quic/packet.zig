const std = @import("std");
const coding = @import("coding.zig");
const varint = @import("varint.zig");

pub const Error = error{
    ConnectionIdTooLong,
    FixedBitUnset,
    ShortHeaderUnsupported,
    NonInitialUnsupported,
    PacketTooShort,
    MalformedConnectionId,
    NoSpaceLeft,
    InvalidPacketNumberLength,
    UnsupportedVersion,
    VersionNegotiationMalformed,
};

pub const max_cid_size: usize = 20;
pub const long_header_form: u8 = 0x80;
pub const fixed_bit: u8 = 0x40;
pub const spin_bit: u8 = 0x20;
pub const key_phase_bit: u8 = 0x04;

pub const LongType = enum {
    initial,
    zero_rtt,
    handshake,
    retry,
};

pub const PacketNumber = struct {
    value: u32,
    len: u8,

    pub fn tag(self: PacketNumber) u8 {
        return self.len - 1;
    }

    /// Truncate a full PN for the wire (RFC 9000 §17.1 length selection, simplified).
    pub fn truncate(full_pn: u64, largest_acked: u64) PacketNumber {
        // Prefer the shortest length that still lets expand recover `full_pn`
        // given expected ≈ largest_acked + 1.
        var len: u8 = 1;
        while (len <= 4) : (len += 1) {
            const truncated: PacketNumber = .{
                .value = truncateValue(full_pn, len),
                .len = len,
            };
            if (expand(truncated, largest_acked +% 1) == full_pn) return truncated;
        }
        return .{ .value = @truncate(full_pn), .len = 4 };
    }

    pub fn expand(truncated: PacketNumber, expected: u64) u64 {
        const pn_nbits: u6 = @intCast(truncated.len * 8);
        const pn_win: u64 = @as(u64, 1) << pn_nbits;
        const pn_hwin = pn_win / 2;
        const pn_mask = pn_win - 1;
        const candidate = (expected & ~pn_mask) | @as(u64, truncated.value);
        if (candidate +% pn_hwin <= expected) {
            return candidate +% pn_win;
        }
        if (candidate > expected +% pn_hwin and candidate >= pn_win) {
            return candidate -% pn_win;
        }
        return candidate;
    }

    fn truncateValue(full_pn: u64, len: u8) u32 {
        const mask: u64 = (@as(u64, 1) << @intCast(len * 8)) - 1;
        return @intCast(full_pn & mask);
    }
};

pub const ConnectionId = struct {
    bytes: [max_cid_size]u8 = .{0} ** max_cid_size,
    len: u8 = 0,

    pub fn init(bytes: []const u8) !ConnectionId {
        if (bytes.len > max_cid_size) return error.ConnectionIdTooLong;
        var self: ConnectionId = .{ .len = @intCast(bytes.len) };
        @memcpy(self.bytes[0..bytes.len], bytes);
        return self;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn encodeLong(self: ConnectionId, out: []u8, index: *usize) !void {
        try coding.writeU8(self.len, out, index);
        try coding.writeBytes(self.slice(), out, index);
    }
};

pub const InitialHeader = struct {
    version: u32,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    token: []const u8 = "",
    packet_number: PacketNumber,
    payload_len: usize = 0,

    pub fn encode(self: InitialHeader, out: []u8) ![]u8 {
        var index: usize = 0;
        try coding.writeU8(long_header_form | fixed_bit | self.packet_number.tag(), out, &index);
        try coding.writeU32(self.version, out, &index);
        try self.dst_cid.encodeLong(out, &index);
        try self.src_cid.encodeLong(out, &index);
        try varint.encodeAppend(self.token.len, out, &index);
        try coding.writeBytes(self.token, out, &index);
        try varint.encodeAppend(self.payload_len + self.packet_number.len, out, &index);
        try writePacketNumber(self.packet_number, out, &index);
        return out[0..index];
    }
};

pub const ProtectedHeader = union(enum) {
    initial: struct {
        version: u32,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        token: []const u8,
        len: u64,
    },
};

pub const ProtectedLongHeader = struct {
    long_type: LongType,
    version: u32,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    /// Only Initial carries a token field; 0-RTT and Handshake leave this empty.
    token: []const u8 = "",
    /// Length field value: packet number + protected payload + AEAD tag.
    len: u64,
    /// Offset of the protected packet number bytes.
    pn_offset: usize,
    /// End of this packet inside a possibly coalesced datagram.
    packet_end: usize,
};

/// Decode the visible long-header skeleton before header protection is removed.
///
/// This supports packet-number-bearing long headers: Initial, 0-RTT, and
/// Handshake. Retry is deliberately excluded because it has no Length or packet
/// number field and is parsed by `parseRetry`.
/// `accept_greased`: fixed-bit-0 packets are legal when the greasing of the
/// QUIC bit is in play (RFC 9000 §15 + the grease_quic_bit TP, F12) — noq
/// passes its endpoint grease config into the parser the same way.
pub fn decodeProtectedLongHeader(bytes: []const u8, accept_greased: bool) !ProtectedLongHeader {
    var cursor: coding.Cursor = .{ .bytes = bytes };
    const first = try cursor.readU8();
    if (first & fixed_bit == 0 and !accept_greased) return error.FixedBitUnset;
    if (first & long_header_form == 0) return error.ShortHeaderUnsupported;

    const version = try cursor.readU32();
    const dst_cid = try readLongCid(&cursor);
    const src_cid = try readLongCid(&cursor);
    const long_type = longTypeFromFirst(first);
    if (long_type == .retry) return error.NonInitialUnsupported;

    const token = if (long_type == .initial) blk: {
        const token_len = try varint.decodeConsume(cursor.bytes, &cursor.index);
        break :blk try cursor.readSlice(@intCast(token_len));
    } else "";
    const len = try varint.decodeConsume(cursor.bytes, &cursor.index);
    if (len > std.math.maxInt(usize)) return error.PacketTooShort;
    const body_len: usize = @intCast(len);
    if (cursor.remaining() < body_len) return error.PacketTooShort;
    const pn_offset = cursor.index;
    return .{
        .long_type = long_type,
        .version = version,
        .dst_cid = dst_cid,
        .src_cid = src_cid,
        .token = token,
        .len = len,
        .pn_offset = pn_offset,
        .packet_end = pn_offset + body_len,
    };
}

pub fn decodeProtectedHeader(bytes: []const u8, accept_greased: bool) !ProtectedHeader {
    const decoded = try decodeProtectedLongHeader(bytes, accept_greased);
    if (decoded.long_type != .initial) return error.NonInitialUnsupported;
    return .{ .initial = .{
        .version = decoded.version,
        .dst_cid = decoded.dst_cid,
        .src_cid = decoded.src_cid,
        .token = decoded.token,
        .len = decoded.len,
    } };
}

fn longTypeFromFirst(first: u8) LongType {
    return switch ((first & 0x30) >> 4) {
        0 => .initial,
        1 => .zero_rtt,
        2 => .handshake,
        3 => .retry,
        else => unreachable,
    };
}

fn readLongCid(cursor: *coding.Cursor) !ConnectionId {
    const len = try cursor.readU8();
    if (len > max_cid_size) return error.MalformedConnectionId;
    const bytes = try cursor.readSlice(len);
    return ConnectionId.init(bytes);
}

pub const version_negotiation: u32 = 0;

/// Cap on parsed supported-version list entries (RFC 9000 §6 VN payload).
pub const max_vn_versions: usize = 16;

pub const VersionNegotiation = struct {
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    supported_versions_buf: [max_vn_versions]u32 = undefined,
    supported_versions_len: usize = 0,

    pub fn supportedVersions(self: *const VersionNegotiation) []const u32 {
        return self.supported_versions_buf[0..self.supported_versions_len];
    }
};

/// Build a RFC 9000 §6 Version Negotiation packet (long header, version=0).
/// `first_grease` carries the low 7 bits of the first byte: noq greases them
/// (`rng | 0x40`, endpoint.rs:186) so receivers cannot ossify them.
pub fn buildVersionNegotiation(
    allocator: std.mem.Allocator,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    first_grease: u8,
    supported_versions: []const u32,
) ![]u8 {
    const size = 1 + 4 + 1 + dst_cid.len + 1 + src_cid.len + supported_versions.len * 4;
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    var index: usize = 0;
    try coding.writeU8(long_header_form | (first_grease & 0x7f), out, &index);
    try coding.writeU32(version_negotiation, out, &index);
    try dst_cid.encodeLong(out, &index);
    try src_cid.encodeLong(out, &index);
    for (supported_versions) |ver| {
        try coding.writeU32(ver, out, &index);
    }
    return out;
}

pub fn parseVersionNegotiation(bytes: []const u8) !VersionNegotiation {
    if (bytes.len < 7) return error.PacketTooShort;
    // RFC 9000 §6: the first byte's low 7 bits are unused and greased by
    // senders, so only the long-header bit is meaningful (mirrors noq
    // packet.rs:660-667 under the default grease_quic_bit = true).
    if ((bytes[0] & long_header_form) == 0) return error.VersionNegotiationMalformed;
    var cursor: coding.Cursor = .{ .bytes = bytes };
    _ = try cursor.readU8();
    const version = try cursor.readU32();
    if (version != version_negotiation) return error.VersionNegotiationMalformed;
    const dst_cid = try readLongCid(&cursor);
    const src_cid = try readLongCid(&cursor);
    if ((cursor.remaining() % 4) != 0) return error.VersionNegotiationMalformed;
    const count = cursor.remaining() / 4;
    if (count > max_vn_versions) return error.VersionNegotiationMalformed;
    var parsed: VersionNegotiation = .{
        .dst_cid = dst_cid,
        .src_cid = src_cid,
        .supported_versions_len = count,
    };
    var i: usize = 0;
    while (i < count) : (i += 1) {
        parsed.supported_versions_buf[i] = try cursor.readU32();
    }
    return parsed;
}

/// Build a RFC 9000 Retry long-header packet (type Retry, no PN/payload length).
pub fn buildRetry(
    allocator: std.mem.Allocator,
    version: u32,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    token: []const u8,
    integrity_tag: [16]u8,
) ![]u8 {
    const size = 1 + 4 + 1 + dst_cid.len + 1 + src_cid.len + token.len + 16;
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    var index: usize = 0;
    try coding.writeU8(long_header_form | fixed_bit | 0x30, out, &index);
    try coding.writeU32(version, out, &index);
    try dst_cid.encodeLong(out, &index);
    try src_cid.encodeLong(out, &index);
    try coding.writeBytes(token, out, &index);
    try coding.writeBytes(&integrity_tag, out, &index);
    return out;
}

pub const RetryPacket = struct {
    version: u32,
    dst_cid: ConnectionId,
    src_cid: ConnectionId,
    token: []const u8,
    integrity_tag: [16]u8,
};

pub fn parseRetry(bytes: []const u8) !RetryPacket {
    if (bytes.len < 1 + 4 + 1 + 1 + 16) return error.PacketTooShort;
    var cursor: coding.Cursor = .{ .bytes = bytes };
    const first = try cursor.readU8();
    if ((first & long_header_form) == 0 or (first & fixed_bit) == 0) return error.FixedBitUnset;
    if (((first & 0x30) >> 4) != 3) return error.NonInitialUnsupported;
    const version = try cursor.readU32();
    const dst_cid = try readLongCid(&cursor);
    const src_cid = try readLongCid(&cursor);
    if (cursor.remaining() < 16) return error.PacketTooShort;
    const token_len = cursor.remaining() - 16;
    const token = try cursor.readSlice(token_len);
    var tag: [16]u8 = undefined;
    @memcpy(&tag, try cursor.readSlice(16));
    return .{
        .version = version,
        .dst_cid = dst_cid,
        .src_cid = src_cid,
        .token = token,
        .integrity_tag = tag,
    };
}

pub const stateless_reset_token_len: usize = 16;
pub const stateless_reset_min_len: usize = 21;

/// Build a stateless reset datagram (≥21 bytes, token in the last 16 bytes).
pub fn generateStatelessReset(token: [stateless_reset_token_len]u8, random_tail: []const u8) ![]u8 {
    const total = @max(stateless_reset_min_len, random_tail.len + stateless_reset_token_len);
    var out = try std.heap.page_allocator.alloc(u8, total);
    errdefer std.heap.page_allocator.free(out);
    const prefix_len = total - stateless_reset_token_len;
    if (random_tail.len >= prefix_len) {
        @memcpy(out[0..prefix_len], random_tail[0..prefix_len]);
    } else {
        @memcpy(out[0..random_tail.len], random_tail);
        var i: usize = random_tail.len;
        while (i < prefix_len) : (i += 1) out[i] = @truncate(i *% 0x9e);
    }
    // Ensure first byte does not look like a valid QUIC header (clear long/short form bits).
    out[0] &= 0x3f;
    @memcpy(out[prefix_len..], &token);
    return out;
}

/// True when `datagram` ends with `token` and is at least 21 bytes (RFC 9000 §10.3).
pub fn detectStatelessReset(datagram: []const u8, token: [stateless_reset_token_len]u8) bool {
    if (datagram.len < stateless_reset_min_len) return false;
    const tail = datagram[datagram.len - stateless_reset_token_len ..][0..stateless_reset_token_len].*;
    return std.mem.eql(u8, &tail, &token);
}

pub fn writePacketNumber(packet_number: PacketNumber, out: []u8, index: *usize) !void {
    switch (packet_number.len) {
        1 => try coding.writeU8(@intCast(packet_number.value), out, index),
        2 => try coding.writeU16(@intCast(packet_number.value), out, index),
        3 => {
            if (out.len - index.* < 3) return error.NoSpaceLeft;
            out[index.*] = @intCast((packet_number.value >> 16) & 0xff);
            out[index.* + 1] = @intCast((packet_number.value >> 8) & 0xff);
            out[index.* + 2] = @intCast(packet_number.value & 0xff);
            index.* += 3;
        },
        4 => try coding.writeU32(packet_number.value, out, index),
        else => return error.InvalidPacketNumberLength,
    }
}

/// Short-header (1-RTT) skeleton: first byte + DCID + PN (no payload).
pub const ShortHeader = struct {
    key_phase: bool = false,
    spin: bool = false,
    dst_cid: ConnectionId,
    packet_number: PacketNumber,

    pub fn encode(self: ShortHeader, out: []u8) ![]u8 {
        var index: usize = 0;
        var first: u8 = fixed_bit | self.packet_number.tag();
        if (self.key_phase) first |= key_phase_bit;
        if (self.spin) first |= spin_bit;
        try coding.writeU8(first, out, &index);
        try coding.writeBytes(self.dst_cid.slice(), out, &index);
        try writePacketNumber(self.packet_number, out, &index);
        return out[0..index];
    }

    pub fn pnOffset(self: ShortHeader) usize {
        return 1 + self.dst_cid.len;
    }
};

test "packet number truncate/expand recovers full pn" {
    const full: u64 = 0x105;
    const truncated = PacketNumber.truncate(full, 0x100);
    try std.testing.expectEqual(full, PacketNumber.expand(truncated, 0x101));
}

test "noq initial protected header round trips invariant fields" {
    const dst = try ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0 });
    const src = try ConnectionId.init(&.{ 0x11, 0x22, 0x33, 0x44 });
    var buf: [64]u8 = undefined;
    const encoded = try (InitialHeader{
        .version = 1,
        .dst_cid = dst,
        .src_cid = src,
        .packet_number = .{ .value = 0x7f, .len = 1 },
    }).encode(&buf);

    const decoded = try decodeProtectedHeader(encoded, false);
    try std.testing.expectEqual(@as(u32, 1), decoded.initial.version);
    try std.testing.expectEqualSlices(u8, dst.slice(), decoded.initial.dst_cid.slice());
    try std.testing.expectEqualSlices(u8, src.slice(), decoded.initial.src_cid.slice());
    try std.testing.expectEqual(@as(u64, 1), decoded.initial.len);
}

test "0-RTT protected long header skeleton decodes without token" {
    const dst = try ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0 });
    const src = try ConnectionId.init(&.{ 0x11, 0x22 });
    const body_len: usize = 18; // two PN bytes + protected payload/tag bytes

    var buf: [64]u8 = undefined;
    var index: usize = 0;
    try coding.writeU8(long_header_form | fixed_bit | 0x10 | 0x01, &buf, &index);
    try coding.writeU32(1, &buf, &index);
    try dst.encodeLong(&buf, &index);
    try src.encodeLong(&buf, &index);
    try varint.encodeAppend(body_len, &buf, &index);
    const expected_pn_offset = index;
    @memset(buf[index..][0..body_len], 0);
    index += body_len;

    const decoded = try decodeProtectedLongHeader(buf[0..index], false);
    try std.testing.expectEqual(LongType.zero_rtt, decoded.long_type);
    try std.testing.expectEqual(@as(u32, 1), decoded.version);
    try std.testing.expectEqualSlices(u8, dst.slice(), decoded.dst_cid.slice());
    try std.testing.expectEqualSlices(u8, src.slice(), decoded.src_cid.slice());
    try std.testing.expectEqual(@as(usize, 0), decoded.token.len);
    try std.testing.expectEqual(@as(u64, body_len), decoded.len);
    try std.testing.expectEqual(expected_pn_offset, decoded.pn_offset);
    try std.testing.expectEqual(index, decoded.packet_end);

    // Keep the legacy endpoint-facing wrapper Initial-only until connection
    // routing grows explicit 0-RTT integration.
    try std.testing.expectError(error.NonInitialUnsupported, decodeProtectedHeader(buf[0..index], false));
}

test "N-3 version negotiation build/parse roundtrip" {
    const allocator = std.testing.allocator;
    const dst = try ConnectionId.init(&.{ 0xde, 0xad });
    const src = try ConnectionId.init(&.{ 0xbe, 0xef });
    const supported = [_]u32{ 1, 0x6b3343cf };
    const built = try buildVersionNegotiation(allocator, dst, src, fixed_bit, &supported);
    defer allocator.free(built);
    // Long-header bit set; greased low bits (fixed bit) pass through.
    try std.testing.expectEqual(@as(u8, 0xc0), built[0]);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, built[1..5], .big));
    const parsed = try parseVersionNegotiation(built);
    try std.testing.expectEqualSlices(u8, dst.slice(), parsed.dst_cid.slice());
    try std.testing.expectEqualSlices(u8, src.slice(), parsed.src_cid.slice());
    try std.testing.expectEqual(@as(usize, 2), parsed.supportedVersions().len);
    try std.testing.expectEqual(@as(u32, 1), parsed.supportedVersions()[0]);
    // RFC 9000 §6: first-byte low 7 bits are unused/greased — any value with
    // the long-header bit set must parse (noq grease_quic_bit default true).
    built[0] = long_header_form | 0x2a;
    try std.testing.expect((try parseVersionNegotiation(built)).supportedVersions().len == 2);
}

test "N-3 stateless reset generate/detect" {
    const token: [16]u8 = .{0x42} ** 16;
    const tail = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const pkt = try generateStatelessReset(token, &tail);
    defer std.heap.page_allocator.free(pkt);
    try std.testing.expect(pkt.len >= 21);
    try std.testing.expect(detectStatelessReset(pkt, token));
    try std.testing.expect(!detectStatelessReset(pkt[0 .. pkt.len - 1], token));
}
