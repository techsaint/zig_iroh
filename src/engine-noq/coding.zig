const std = @import("std");

pub const Cursor = struct {
    bytes: []const u8,
    index: usize = 0,

    pub fn remaining(self: Cursor) usize {
        return self.bytes.len - self.index;
    }

    pub fn readU8(self: *Cursor) !u8 {
        if (self.remaining() < 1) return error.UnexpectedEnd;
        const value = self.bytes[self.index];
        self.index += 1;
        return value;
    }

    pub fn readU16(self: *Cursor) !u16 {
        if (self.remaining() < 2) return error.UnexpectedEnd;
        const value = std.mem.readInt(u16, self.bytes[self.index..][0..2], .big);
        self.index += 2;
        return value;
    }

    pub fn readU32(self: *Cursor) !u32 {
        if (self.remaining() < 4) return error.UnexpectedEnd;
        const value = std.mem.readInt(u32, self.bytes[self.index..][0..4], .big);
        self.index += 4;
        return value;
    }

    pub fn readArray(self: *Cursor, comptime len: usize) ![len]u8 {
        if (self.remaining() < len) return error.UnexpectedEnd;
        const value = self.bytes[self.index..][0..len].*;
        self.index += len;
        return value;
    }

    pub fn readSlice(self: *Cursor, len: usize) ![]const u8 {
        if (self.remaining() < len) return error.UnexpectedEnd;
        const value = self.bytes[self.index .. self.index + len];
        self.index += len;
        return value;
    }

    pub fn skip(self: *Cursor, len: usize) !void {
        if (self.remaining() < len) return error.UnexpectedEnd;
        self.index += len;
    }
};

pub fn writeU8(value: u8, out: []u8, index: *usize) !void {
    if (out.len - index.* < 1) return error.NoSpaceLeft;
    out[index.*] = value;
    index.* += 1;
}

pub fn writeU16(value: u16, out: []u8, index: *usize) !void {
    if (out.len - index.* < 2) return error.NoSpaceLeft;
    std.mem.writeInt(u16, out[index.*..][0..2], value, .big);
    index.* += 2;
}

pub fn writeU32(value: u32, out: []u8, index: *usize) !void {
    if (out.len - index.* < 4) return error.NoSpaceLeft;
    std.mem.writeInt(u32, out[index.*..][0..4], value, .big);
    index.* += 4;
}

pub fn writeBytes(bytes: []const u8, out: []u8, index: *usize) !void {
    if (out.len - index.* < bytes.len) return error.NoSpaceLeft;
    @memcpy(out[index.*..][0..bytes.len], bytes);
    index.* += bytes.len;
}
