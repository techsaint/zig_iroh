const std = @import("std");

pub const max_value: u64 = (@as(u64, 1) << 62) - 1;
pub const max_size: usize = 8;

pub const Decode = struct {
    value: u64,
    len: usize,
};

pub fn size(value: u64) !usize {
    if (value < (@as(u64, 1) << 6)) return 1;
    if (value < (@as(u64, 1) << 14)) return 2;
    if (value < (@as(u64, 1) << 30)) return 4;
    if (value < (@as(u64, 1) << 62)) return 8;
    return error.VarIntTooLarge;
}

pub fn encode(value: u64, out: []u8) !usize {
    if (value < (@as(u64, 1) << 6)) {
        if (out.len < 1) return error.NoSpaceLeft;
        out[0] = @intCast(value);
        return 1;
    }
    if (value < (@as(u64, 1) << 14)) {
        if (out.len < 2) return error.NoSpaceLeft;
        std.mem.writeInt(u16, out[0..2], @as(u16, @intCast(value)) | 0x4000, .big);
        return 2;
    }
    if (value < (@as(u64, 1) << 30)) {
        if (out.len < 4) return error.NoSpaceLeft;
        std.mem.writeInt(u32, out[0..4], @as(u32, @intCast(value)) | 0x80000000, .big);
        return 4;
    }
    if (value < (@as(u64, 1) << 62)) {
        if (out.len < 8) return error.NoSpaceLeft;
        std.mem.writeInt(u64, out[0..8], value | 0xc000000000000000, .big);
        return 8;
    }
    return error.VarIntTooLarge;
}

pub fn encodeAppend(value: u64, out: []u8, index: *usize) !void {
    const n = try encode(value, out[index.*..]);
    index.* += n;
}

pub fn decode(bytes: []const u8) !Decode {
    if (bytes.len == 0) return error.TruncatedVarInt;
    const tag = bytes[0] >> 6;
    const len: usize = switch (tag) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (bytes.len < len) return error.TruncatedVarInt;
    const value: u64 = switch (len) {
        1 => bytes[0] & 0x3f,
        2 => std.mem.readInt(u16, bytes[0..2], .big) & 0x3fff,
        4 => std.mem.readInt(u32, bytes[0..4], .big) & 0x3fffffff,
        8 => std.mem.readInt(u64, bytes[0..8], .big) & 0x3fffffffffffffff,
        else => unreachable,
    };
    return .{ .value = value, .len = len };
}

pub fn decodeConsume(bytes: []const u8, index: *usize) !u64 {
    const decoded = try decode(bytes[index.*..]);
    index.* += decoded.len;
    return decoded.value;
}

test "noq varint canonical lengths" {
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try encode(63, &buf));
    try std.testing.expectEqualSlices(u8, &.{0x3f}, buf[0..1]);
    try std.testing.expectEqual(@as(usize, 2), try encode(64, &buf));
    try std.testing.expectEqualSlices(u8, &.{ 0x40, 0x40 }, buf[0..2]);
    try std.testing.expectEqual(@as(usize, 4), try encode(16384, &buf));
    try std.testing.expectEqualSlices(u8, &.{ 0x80, 0x00, 0x40, 0x00 }, buf[0..4]);
    try std.testing.expectEqual(@as(usize, 8), try encode(@as(u64, 1) << 30, &buf));
    try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 }, buf[0..8]);

    const decoded = try decode(buf[0..8]);
    try std.testing.expectEqual(@as(u64, 1) << 30, decoded.value);
    try std.testing.expectEqual(@as(usize, 8), decoded.len);
}
