//! Assemble a QUIC packet: short/long header + frames + packet protection (N3b-2 / N3b-2.5).

const std = @import("std");
const coding = @import("coding.zig");
const frame = @import("frame.zig");
const packet = @import("packet.zig");
const packet_crypto = @import("packet_crypto.zig");
const spaces = @import("spaces.zig");
const varint = @import("varint.zig");

pub const Error = error{
    NoSpaceLeft,
    EmptyPacket,
    FrameEncodeFailed,
    VarIntTooLarge,
} || packet_crypto.Error || packet.Error;

pub const BuiltPacket = struct {
    /// Full protected datagram bytes (owned slice into `buf`).
    bytes: []u8,
    header_len: usize,
    pn_offset: usize,
    packet_number: u64,
    packet_number_len: u8,
};

/// Build a 1-RTT short-header packet with a fixed frame set, protect it, and
/// return the on-wire bytes in `buf`.
pub fn buildOneRtt(
    buf: []u8,
    dst_cid: packet.ConnectionId,
    packet_number: u64,
    key_phase: bool,
    frames: []const frame.Frame,
    keys: packet_crypto.PacketKeys,
    min_datagram_size: usize,
) Error!BuiltPacket {
    if (frames.len == 0) return error.EmptyPacket;

    // Encode header without PN length bits finalized until we know PN encoding.
    var pn_space: spaces.PacketNumberSpace = .{};
    // Use largest_acked=0 so truncate uses full value with minimal length for small PNs.
    const pn = pn_space.truncateForSend(packet_number);

    var index: usize = 0;
    const first: u8 = packet.fixed_bit |
        (if (key_phase) packet.key_phase_bit else 0) |
        pn.tag();
    try writeU8(buf, &index, first);
    try writeBytes(buf, &index, dst_cid.slice());
    const pn_offset = index;
    try packet.writePacketNumber(pn, buf, &index);
    const header_len = index;

    // Frames
    for (frames) |f| {
        const encoded = f.encode(buf[index..]) catch return error.FrameEncodeFailed;
        index += encoded.len;
    }

    // Pad so HP sample window fits: need pn_offset + 4 + 16 bytes total length
    // after AEAD tag is appended.
    const min_len = @max(min_datagram_size, pn_offset + 4 + packet_crypto.sample_size + packet_crypto.tag_len);
    while (index + packet_crypto.tag_len < min_len) {
        try writeU8(buf, &index, 0x00); // PADDING frames
    }

    // Reserve tag
    if (index + packet_crypto.tag_len > buf.len) return error.NoSpaceLeft;
    @memset(buf[index .. index + packet_crypto.tag_len], 0);
    index += packet_crypto.tag_len;

    const packet_bytes = buf[0..index];
    try packet_crypto.encryptPayload(packet_bytes, header_len, packet_number, keys);
    try packet_crypto.encryptHeaderWithKeys(packet_bytes, pn_offset, keys);

    return .{
        .bytes = packet_bytes,
        .header_len = header_len,
        .pn_offset = pn_offset,
        .packet_number = packet_number,
        .packet_number_len = pn.len,
    };
}

/// Unprotect a 1-RTT short-header packet built with known keys (oracle/test path).
pub fn unprotectOneRtt(
    packet_bytes: []u8,
    dst_cid_len: usize,
    packet_number: u64,
    keys: packet_crypto.PacketKeys,
) Error!struct { header_len: usize, pn_offset: usize } {
    // short: first(1) + dcid + pn
    const pn_offset = 1 + dst_cid_len;
    try packet_crypto.decryptHeaderWithKeys(packet_bytes, pn_offset, keys);
    const pn_len: usize = @as(usize, packet_bytes[0] & 0x03) + 1;
    const header_len = pn_offset + pn_len;
    try packet_crypto.decryptPayload(packet_bytes, header_len, packet_number, keys);
    return .{ .header_len = header_len, .pn_offset = pn_offset };
}

/// Build a packet-number-bearing long-header packet, protect it, return on-wire bytes.
///
/// `long_type` is `packet.LongType.initial`, `.zero_rtt`, or `.handshake`.
/// Retry has no Length/PN field and is built by `packet.buildRetry`.
/// For Initial, `token` is included; for 0-RTT/Handshake it is ignored.
pub fn buildLongHeader(
    buf: []u8,
    long_type: packet.LongType,
    version: u32,
    dst_cid: packet.ConnectionId,
    src_cid: packet.ConnectionId,
    token: []const u8,
    packet_number: u64,
    frames: []const frame.Frame,
    keys: packet_crypto.PacketKeys,
    min_datagram_size: usize,
) Error!BuiltPacket {
    if (frames.len == 0) return error.EmptyPacket;
    if (long_type == .retry) return error.FrameEncodeFailed;

    var pn_space: spaces.PacketNumberSpace = .{};
    const pn = pn_space.truncateForSend(packet_number);

    // Pass 1: encode frames into a scratch area at the end of buf to know payload size.
    var frame_bytes: [2048]u8 = undefined;
    var frame_len: usize = 0;
    for (frames) |f| {
        const encoded = f.encode(frame_bytes[frame_len..]) catch return error.FrameEncodeFailed;
        frame_len += encoded.len;
    }

    // Length field covers PN + payload + AEAD tag. Pad so HP sample fits after protect:
    // total packet length >= pn_offset + 4 + sample + 0 (sample is in ciphertext after PN).
    // We don't know pn_offset until header is sized; compute header skeleton size first.
    const type_bits: u8 = switch (long_type) {
        .initial => 0x00,
        .zero_rtt => 0x10,
        .handshake => 0x20,
        .retry => 0x30,
    };
    const first_plain: u8 = packet.long_header_form | packet.fixed_bit | type_bits | pn.tag();

    // header_without_len_pn = first(1) + version(4) + dcid + scid + [token for initial]
    var prefix: usize = 1 + 4 + 1 + dst_cid.len + 1 + src_cid.len;
    if (long_type == .initial) {
        // token length varint + token
        var tok_len_buf: [8]u8 = undefined;
        const tok_len_enc = varint.encode(token.len, &tok_len_buf) catch return error.NoSpaceLeft;
        prefix += tok_len_enc + token.len;
    }

    // length varint encodes (pn.len + payload_plain + tag). Size of the length field itself
    // depends on the value — use two-byte varint when needed by picking payload pad.
    // Iterate pad until min HP sample constraint is satisfied.
    var pad: usize = 0;
    var length_value: u64 = undefined;
    var length_field_len: usize = undefined;
    var pn_offset: usize = undefined;
    var header_len: usize = undefined;
    var total_len: usize = undefined;
    while (true) {
        const payload_plain = frame_len + pad;
        length_value = pn.len + payload_plain + packet_crypto.tag_len;
        var len_buf: [8]u8 = undefined;
        length_field_len = varint.encode(length_value, &len_buf) catch return error.NoSpaceLeft;
        pn_offset = prefix + length_field_len;
        header_len = pn_offset + pn.len;
        total_len = header_len + payload_plain + packet_crypto.tag_len;
        // After protect: need sample at pn_offset+4 of size 16 within packet.
        const min_len = @max(min_datagram_size, pn_offset + 4 + packet_crypto.sample_size);
        if (total_len >= min_len) break;
        pad += 1;
        if (pad > buf.len) return error.NoSpaceLeft;
    }

    if (total_len > buf.len) return error.NoSpaceLeft;

    // Write header
    var index: usize = 0;
    try writeU8(buf, &index, first_plain);
    try writeU32(buf, &index, version);
    try writeU8(buf, &index, dst_cid.len);
    try writeBytes(buf, &index, dst_cid.slice());
    try writeU8(buf, &index, src_cid.len);
    try writeBytes(buf, &index, src_cid.slice());
    if (long_type == .initial) {
        try varint.encodeAppend(token.len, buf, &index);
        try writeBytes(buf, &index, token);
    }
    try varint.encodeAppend(length_value, buf, &index);
    std.debug.assert(index == pn_offset);
    try packet.writePacketNumber(pn, buf, &index);
    std.debug.assert(index == header_len);

    // Frames + padding
    @memcpy(buf[index..][0..frame_len], frame_bytes[0..frame_len]);
    index += frame_len;
    @memset(buf[index .. index + pad], 0);
    index += pad;

    // AEAD tag slot
    @memset(buf[index .. index + packet_crypto.tag_len], 0);
    index += packet_crypto.tag_len;
    std.debug.assert(index == total_len);

    const packet_bytes = buf[0..total_len];
    try packet_crypto.encryptPayload(packet_bytes, header_len, packet_number, keys);
    try packet_crypto.encryptHeaderWithKeys(packet_bytes, pn_offset, keys);

    return .{
        .bytes = packet_bytes,
        .header_len = header_len,
        .pn_offset = pn_offset,
        .packet_number = packet_number,
        .packet_number_len = pn.len,
    };
}

/// Unprotect a long-header Initial/Handshake packet with known keys (oracle/test path).
/// Caller supplies `pn_offset` (from build) or compute via header parse after HP is removed —
/// this helper takes the protected packet and known layout offsets from build.
pub fn unprotectLongHeader(
    packet_bytes: []u8,
    pn_offset: usize,
    packet_number: u64,
    keys: packet_crypto.PacketKeys,
) Error!struct { header_len: usize } {
    try packet_crypto.decryptHeaderWithKeys(packet_bytes, pn_offset, keys);
    const pn_len: usize = @as(usize, packet_bytes[0] & 0x03) + 1;
    const header_len = pn_offset + pn_len;
    try packet_crypto.decryptPayload(packet_bytes, header_len, packet_number, keys);
    return .{ .header_len = header_len };
}

fn writeU8(buf: []u8, index: *usize, value: u8) Error!void {
    if (index.* >= buf.len) return error.NoSpaceLeft;
    buf[index.*] = value;
    index.* += 1;
}

fn writeU32(buf: []u8, index: *usize, value: u32) Error!void {
    if (index.* + 4 > buf.len) return error.NoSpaceLeft;
    std.mem.writeInt(u32, buf[index.*..][0..4], value, .big);
    index.* += 4;
}

fn writeBytes(buf: []u8, index: *usize, bytes: []const u8) Error!void {
    if (index.* + bytes.len > buf.len) return error.NoSpaceLeft;
    @memcpy(buf[index.*..][0..bytes.len], bytes);
    index.* += bytes.len;
}

test "buildOneRtt ping protects and unprotects" {
    const dst = try packet.ConnectionId.init(&.{ 0xde, 0xad, 0xbe, 0xef });
    const keys = packet_crypto.PacketKeys.init(
        .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
        .{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b },
        .{ 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f },
    );
    var buf: [256]u8 = undefined;
    const frames = [_]frame.Frame{.ping};
    const built = try buildOneRtt(&buf, dst, 0x2a, false, &frames, keys, 0);

    // Must differ from plaintext ping alone
    try std.testing.expect(built.bytes.len > 1);

    var copy: [256]u8 = undefined;
    @memcpy(copy[0..built.bytes.len], built.bytes);
    _ = try unprotectOneRtt(copy[0..built.bytes.len], dst.len, 0x2a, keys);

    // After unprotect, find ping frame (0x01) in payload (skip padding zeros).
    const payload = copy[built.header_len .. built.bytes.len - packet_crypto.tag_len];
    var found_ping = false;
    for (payload) |b| {
        if (b == 0x01) {
            found_ping = true;
            break;
        }
        if (b != 0x00) break;
    }
    try std.testing.expect(found_ping);
}

test "buildLongHeader pads a client Initial to the QUIC minimum" {
    const dst = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const src = try packet.ConnectionId.init(&.{ 0x43, 0xb0 });
    const keys = packet_crypto.PacketKeys.init(
        .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
        .{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b },
        .{ 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f },
    );
    var buf: [1400]u8 = undefined;
    const frames = [_]frame.Frame{.ping};
    const built = try buildLongHeader(&buf, .initial, 1, dst, src, "", 0, &frames, keys, 1200);
    try std.testing.expect((built.bytes[0] & 0x80) != 0);
    try std.testing.expectEqual(@as(usize, 1200), built.bytes.len);

    var copy: [1400]u8 = undefined;
    @memcpy(copy[0..built.bytes.len], built.bytes);
    _ = try unprotectLongHeader(copy[0..built.bytes.len], built.pn_offset, 0, keys);
    const payload = copy[built.header_len .. built.bytes.len - packet_crypto.tag_len];
    var found_ping = false;
    for (payload) |b| {
        if (b == 0x01) {
            found_ping = true;
            break;
        }
        if (b != 0x00) break;
    }
    try std.testing.expect(found_ping);
}

test "buildLongHeader supports 0-RTT packet protection" {
    const dst = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0 });
    const src = try packet.ConnectionId.init(&.{ 0x43, 0xb0 });
    const keys = packet_crypto.PacketKeys.init(
        .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
        .{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b },
        .{ 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f },
    );
    var buf: [256]u8 = undefined;
    const frames = [_]frame.Frame{.{ .stream = .{ .id = 0, .data = "early" } }};
    const built = try buildLongHeader(&buf, .zero_rtt, 1, dst, src, "", 7, &frames, keys, 0);

    try std.testing.expectEqual(@as(u8, 0x10), built.bytes[0] & 0x30);
    const header = try packet.decodeProtectedLongHeader(built.bytes);
    try std.testing.expectEqual(packet.LongType.zero_rtt, header.long_type);
    try std.testing.expectEqual(@as(usize, 0), header.token.len);
    try std.testing.expectEqual(built.pn_offset, header.pn_offset);
    try std.testing.expectEqual(built.bytes.len, header.packet_end);

    var copy: [256]u8 = undefined;
    @memcpy(copy[0..built.bytes.len], built.bytes);
    _ = try unprotectLongHeader(copy[0..built.bytes.len], built.pn_offset, 7, keys);
    const payload = copy[built.header_len .. built.bytes.len - packet_crypto.tag_len];
    var cursor: coding.Cursor = .{ .bytes = payload };
    const decoded = try frame.decodeAt(&cursor);
    try std.testing.expect(decoded == .stream);
    try std.testing.expectEqual(@as(u64, 0), decoded.stream.id);
    try std.testing.expectEqualSlices(u8, "early", decoded.stream.data);
    while (cursor.remaining() > 0) {
        try std.testing.expectEqual(@as(u8, 0), payload[cursor.index]);
        cursor.index += 1;
    }
}
