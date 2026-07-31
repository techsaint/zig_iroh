//! Minimal postcard 1.x codec for iroh-gossip wire types.
const std = @import("std");

pub const Error = error{
    EndOfStream,
    VarintOverflow,
    InvalidOptionTag,
    InvalidBool,
    OutOfMemory,
};

pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    pub fn remaining(self: *const Reader) []const u8 {
        return self.data[self.pos..];
    }

    pub fn readByte(self: *Reader) Error!u8 {
        if (self.pos >= self.data.len) return error.EndOfStream;
        const b = self.data[self.pos];
        self.pos += 1;
        return b;
    }

    pub fn readVarintU64(self: *Reader) Error!u64 {
        var result: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            const b = try self.readByte();
            const low: u64 = b & 0x7f;
            // Match blobs/postcard: check before shift so u6/u7 never wraps on the 10th byte.
            if (shift >= 64) return error.VarintOverflow;
            if (shift == 63 and low > 1) return error.VarintOverflow;
            result |= low << @intCast(shift);
            if (b & 0x80 == 0) return result;
            if (shift >= 63) return error.VarintOverflow;
            shift += 7;
        }
    }

    pub fn readVarintU32(self: *Reader) Error!u32 {
        const v = try self.readVarintU64();
        if (v > std.math.maxInt(u32)) return error.VarintOverflow;
        return @intCast(v);
    }

    pub fn readVarintU16(self: *Reader) Error!u16 {
        const v = try self.readVarintU64();
        if (v > std.math.maxInt(u16)) return error.VarintOverflow;
        return @intCast(v);
    }

    pub fn readVarintUsize(self: *Reader) Error!usize {
        const v = try self.readVarintU64();
        if (v > std.math.maxInt(usize)) return error.VarintOverflow;
        return @intCast(v);
    }

    pub fn readFixed32(self: *Reader) Error![32]u8 {
        return self.readFixed(32);
    }

    pub fn readFixed(self: *Reader, comptime len: usize) Error![len]u8 {
        if (len > self.data.len - self.pos) return error.EndOfStream;
        var out: [len]u8 = undefined;
        @memcpy(&out, self.data[self.pos..][0..len]);
        self.pos += len;
        return out;
    }

    pub fn readBool(self: *Reader) Error!bool {
        const b = try self.readByte();
        return switch (b) {
            0 => false,
            1 => true,
            else => error.InvalidBool,
        };
    }

    pub fn readBytes(self: *Reader, allocator: std.mem.Allocator) Error![]u8 {
        const len = try self.readVarintUsize();
        if (len > self.data.len - self.pos) return error.EndOfStream;
        const slice = self.data[self.pos..][0..len];
        self.pos += len;
        return try allocator.dupe(u8, slice);
    }

    pub fn readOption(
        self: *Reader,
        comptime T: type,
        decode: *const fn (*Reader, std.mem.Allocator) Error!T,
        allocator: std.mem.Allocator,
    ) Error!?T {
        const tag = try self.readByte();
        return switch (tag) {
            0 => null,
            1 => try decode(self, allocator),
            else => error.InvalidOptionTag,
        };
    }

    pub fn readEnumDiscriminant(self: *Reader) Error!u32 {
        return try self.readVarintU32();
    }
};

pub const Writer = struct {
    list: std.ArrayList(u8),

    pub fn init(_: std.mem.Allocator) Writer {
        return .{ .list = .empty };
    }

    pub fn deinit(self: *Writer, allocator: std.mem.Allocator) void {
        self.list.deinit(allocator);
    }

    pub fn written(self: *const Writer) []const u8 {
        return self.list.items;
    }

    pub fn writeByte(self: *Writer, allocator: std.mem.Allocator, byte: u8) Error!void {
        try self.list.append(allocator, byte);
    }

    pub fn writeVarintU64(self: *Writer, allocator: std.mem.Allocator, value: u64) Error!void {
        var v = value;
        while (true) {
            var byte: u8 = @truncate(v & 0x7f);
            v >>= 7;
            if (v != 0) byte |= 0x80;
            try self.writeByte(allocator, byte);
            if (v == 0) return;
        }
    }

    pub fn writeVarintU32(self: *Writer, allocator: std.mem.Allocator, value: u32) Error!void {
        try self.writeVarintU64(allocator, value);
    }

    pub fn writeVarintU16(self: *Writer, allocator: std.mem.Allocator, value: u16) Error!void {
        try self.writeVarintU64(allocator, value);
    }

    pub fn writeVarintUsize(self: *Writer, allocator: std.mem.Allocator, value: usize) Error!void {
        try self.writeVarintU64(allocator, @intCast(value));
    }

    pub fn writeFixed32(self: *Writer, allocator: std.mem.Allocator, bytes: [32]u8) Error!void {
        try self.writeFixed(allocator, &bytes);
    }

    pub fn writeFixed(self: *Writer, allocator: std.mem.Allocator, bytes: []const u8) Error!void {
        try self.list.appendSlice(allocator, bytes);
    }

    pub fn writeBool(self: *Writer, allocator: std.mem.Allocator, value: bool) Error!void {
        try self.writeByte(allocator, if (value) 1 else 0);
    }

    pub fn writeBytes(self: *Writer, allocator: std.mem.Allocator, bytes: []const u8) Error!void {
        try self.writeVarintUsize(allocator, bytes.len);
        try self.list.appendSlice(allocator, bytes);
    }

    pub fn writeOption(
        self: *Writer,
        allocator: std.mem.Allocator,
        comptime T: type,
        value: ?T,
        encode: *const fn (*Writer, std.mem.Allocator, T) Error!void,
    ) Error!void {
        if (value) |v| {
            try self.writeByte(allocator, 1);
            try encode(self, allocator, v);
        } else {
            try self.writeByte(allocator, 0);
        }
    }

    pub fn writeEnumDiscriminant(self: *Writer, allocator: std.mem.Allocator, tag: u32) Error!void {
        try self.writeVarintU32(allocator, tag);
    }
};

test "varint round-trip" {
    const alloc = std.testing.allocator;
    const values = [_]u64{ 0, 1, 127, 128, 300, 16384 };
    for (values) |v| {
        var w = Writer.init(alloc);
        defer w.deinit(alloc);
        try w.writeVarintU64(alloc, v);
        var r = Reader.init(w.written());
        try std.testing.expectEqual(v, try r.readVarintU64());
    }
}

test "LEB128 overlong varint rejects without shift overflow" {
    // 10 continuation bytes would wrap a u6 shift before the old >=64 check.
    const overlong = [_]u8{0x80} ** 10;
    var r = Reader.init(&overlong);
    try std.testing.expectError(error.VarintOverflow, r.readVarintU64());
}

test "readBytes rejects length that would wrap pos+len" {
    const alloc = std.testing.allocator;
    // varint length = maxInt(usize) via many 0xff bytes is impractical; use a
    // short buffer with a length larger than remaining bytes.
    const input = [_]u8{ 0x05, 0x00, 0x00 }; // len=5, only 2 payload bytes
    var r = Reader.init(&input);
    try std.testing.expectError(error.EndOfStream, r.readBytes(alloc));
}

test "option round-trip" {
    const alloc = std.testing.allocator;
    var w = Writer.init(alloc);
    defer w.deinit(alloc);
    try w.writeOption(alloc, u16, @as(?u16, null), encodeVarintU16);
    try w.writeOption(alloc, u16, @as(?u16, 42), encodeVarintU16);
    var r = Reader.init(w.written());
    try std.testing.expect((try r.readOption(u16, decodeVarintU16, alloc)) == null);
    try std.testing.expectEqual(@as(u16, 42), (try r.readOption(u16, decodeVarintU16, alloc)).?);
}

fn encodeVarintU16(w: *Writer, a: std.mem.Allocator, v: u16) Error!void {
    try w.writeVarintU16(a, v);
}
fn decodeVarintU16(r: *Reader, _: std.mem.Allocator) Error!u16 {
    return try r.readVarintU16();
}
