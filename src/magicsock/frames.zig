//! noq/iroh custom QUIC frame codec used by magicsock path discovery.

const std = @import("std");

pub const FrameType = enum(u64) {
    observed_ipv4_addr = 0x9f81a6,
    observed_ipv6_addr = 0x9f81a7,
    add_ipv4_address = 0x3d7f90,
    add_ipv6_address = 0x3d7f91,
    reach_out_at_ipv4 = 0x3d7f92,
    reach_out_at_ipv6 = 0x3d7f93,
    remove_address = 0x3d7f94,
};

pub const Ipv6AddressFrame = struct {
    frame_type: FrameType,
    seq: u64,
    ip: [16]u8,
    port: u16,
};

pub const Frame = union(enum) {
    ipv4_address: Ipv4AddressFrame,
    ipv6_address: Ipv6AddressFrame,
    remove_address: RemoveAddress,

    pub fn frameType(self: Frame) FrameType {
        return switch (self) {
            .ipv4_address => |f| f.frame_type,
            .ipv6_address => |f| f.frame_type,
            .remove_address => .remove_address,
        };
    }
};

pub const Ipv4AddressFrame = struct {
    frame_type: FrameType,
    seq: u64,
    ip: [4]u8,
    port: u16,

    pub fn encode(self: Ipv4AddressFrame, out: []u8) ![]u8 {
        var index: usize = 0;
        try writeVarInt(@intFromEnum(self.frame_type), out, &index);
        try writeVarInt(self.seq, out, &index);
        if (out.len - index < 6) return error.NoSpaceLeft;
        @memcpy(out[index..][0..4], &self.ip);
        index += 4;
        std.mem.writeInt(u16, out[index..][0..2], self.port, .big);
        index += 2;
        return out[0..index];
    }
};

pub const RemoveAddress = struct {
    seq: u64,

    pub fn encode(self: RemoveAddress, out: []u8) ![]u8 {
        var index: usize = 0;
        try writeVarInt(@intFromEnum(FrameType.remove_address), out, &index);
        try writeVarInt(self.seq, out, &index);
        return out[0..index];
    }
};

fn writeVarInt(value: u64, out: []u8, index: *usize) !void {
    if (value < (1 << 6)) {
        if (out.len - index.* < 1) return error.NoSpaceLeft;
        out[index.*] = @intCast(value);
        index.* += 1;
    } else if (value < (1 << 14)) {
        if (out.len - index.* < 2) return error.NoSpaceLeft;
        std.mem.writeInt(u16, out[index.*..][0..2], @as(u16, @intCast(value)) | 0x4000, .big);
        index.* += 2;
    } else if (value < (1 << 30)) {
        if (out.len - index.* < 4) return error.NoSpaceLeft;
        std.mem.writeInt(u32, out[index.*..][0..4], @as(u32, @intCast(value)) | 0x80000000, .big);
        index.* += 4;
    } else if (value < (1 << 62)) {
        if (out.len - index.* < 8) return error.NoSpaceLeft;
        std.mem.writeInt(u64, out[index.*..][0..8], value | 0xc000000000000000, .big);
        index.* += 8;
    } else {
        return error.VarIntTooLarge;
    }
}

pub fn decode(bytes: []const u8) !Frame {
    var index: usize = 0;
    const raw_frame_type = try readVarInt(bytes, &index);
    const frame_type = std.enums.fromInt(FrameType, raw_frame_type) orelse return error.UnknownFrameType;
    return switch (frame_type) {
        .add_ipv4_address, .reach_out_at_ipv4, .observed_ipv4_addr => .{ .ipv4_address = .{
            .frame_type = frame_type,
            .seq = try readVarInt(bytes, &index),
            .ip = try readArray(4, bytes, &index),
            .port = try readU16(bytes, &index),
        } },
        .add_ipv6_address, .reach_out_at_ipv6, .observed_ipv6_addr => .{ .ipv6_address = .{
            .frame_type = frame_type,
            .seq = try readVarInt(bytes, &index),
            .ip = try readArray(16, bytes, &index),
            .port = try readU16(bytes, &index),
        } },
        .remove_address => .{ .remove_address = .{ .seq = try readVarInt(bytes, &index) } },
    };
}

fn readVarInt(bytes: []const u8, index: *usize) !u64 {
    if (index.* >= bytes.len) return error.TruncatedFrame;
    const first = bytes[index.*];
    const tag = first >> 6;
    const len: usize = switch (tag) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (bytes.len - index.* < len) return error.TruncatedFrame;
    const value: u64 = switch (len) {
        1 => first & 0x3f,
        2 => std.mem.readInt(u16, bytes[index.*..][0..2], .big) & 0x3fff,
        4 => std.mem.readInt(u32, bytes[index.*..][0..4], .big) & 0x3fffffff,
        8 => std.mem.readInt(u64, bytes[index.*..][0..8], .big) & 0x3fffffffffffffff,
        else => unreachable,
    };
    index.* += len;
    return value;
}

fn readArray(comptime len: usize, bytes: []const u8, index: *usize) ![len]u8 {
    if (bytes.len - index.* < len) return error.TruncatedFrame;
    const out = bytes[index.*..][0..len].*;
    index.* += len;
    return out;
}

fn readU16(bytes: []const u8, index: *usize) !u16 {
    if (bytes.len - index.* < 2) return error.TruncatedFrame;
    const value = std.mem.readInt(u16, bytes[index.*..][0..2], .big);
    index.* += 2;
    return value;
}

test "S3 codec encodes iroh/noq IPv4 custom frames byte-for-byte" {
    var buf: [32]u8 = undefined;

    const add = try (Ipv4AddressFrame{
        .frame_type = .add_ipv4_address,
        .seq = 1,
        .ip = .{ 192, 0, 2, 1 },
        .port = 4242,
    }).encode(&buf);
    try std.testing.expectEqualSlices(u8, &.{ 0x80, 0x3d, 0x7f, 0x90, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x10, 0x92 }, add);

    const reach = try (Ipv4AddressFrame{
        .frame_type = .reach_out_at_ipv4,
        .seq = 2,
        .ip = .{ 127, 0, 0, 1 },
        .port = 9999,
    }).encode(&buf);
    try std.testing.expectEqualSlices(u8, &.{ 0x80, 0x3d, 0x7f, 0x92, 0x02, 0x7f, 0x00, 0x00, 0x01, 0x27, 0x0f }, reach);

    const observed = try (Ipv4AddressFrame{
        .frame_type = .observed_ipv4_addr,
        .seq = 5,
        .ip = .{ 203, 0, 113, 10 },
        .port = 4444,
    }).encode(&buf);
    try std.testing.expectEqualSlices(u8, &.{ 0x80, 0x9f, 0x81, 0xa6, 0x05, 0xcb, 0x00, 0x71, 0x0a, 0x11, 0x5c }, observed);

    const remove = try (RemoveAddress{ .seq = 7 }).encode(&buf);
    try std.testing.expectEqualSlices(u8, &.{ 0x80, 0x3d, 0x7f, 0x94, 0x07 }, remove);
}

test "S3 codec decodes received iroh/noq custom frames" {
    const add = try decode(&.{ 0x80, 0x3d, 0x7f, 0x90, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x10, 0x92 });
    try std.testing.expectEqual(FrameType.add_ipv4_address, add.frameType());
    try std.testing.expectEqual(@as(u64, 1), add.ipv4_address.seq);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, &add.ipv4_address.ip);
    try std.testing.expectEqual(@as(u16, 4242), add.ipv4_address.port);

    const remove = try decode(&.{ 0x80, 0x3d, 0x7f, 0x94, 0x07 });
    try std.testing.expectEqual(FrameType.remove_address, remove.frameType());
    try std.testing.expectEqual(@as(u64, 7), remove.remove_address.seq);
}
