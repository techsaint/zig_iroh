//! Minimal postcard codec for the subset iroh-blobs uses.
//!
//! Wire: unsigned LEB128 varints (7 data bits/byte, MSB = continuation),
//! fixed `[u8; N]` as N raw bytes, enum discriminant as varint(u32).

const std = @import("std");

pub const Error = error{
    EndOfStream,
    VarintOverflow,
    OutOfMemory,
    ReadFailed,
    WriteFailed,
};

pub fn writeU64(w: *std.Io.Writer, value: u64) Error!void {
    var v = value;
    while (true) {
        const byte: u8 = @truncate(v & 0x7f);
        v >>= 7;
        if (v == 0) {
            try w.writeAll(&[_]u8{byte});
            return;
        }
        try w.writeAll(&[_]u8{byte | 0x80});
    }
}

pub fn readU64(r: *std.Io.Reader) Error!u64 {
    var result: u64 = 0;
    var shift: u7 = 0;
    while (true) {
        const byte = try r.takeByte();
        const low: u64 = byte & 0x7f;
        if (shift >= 64) return error.VarintOverflow;
        if (shift == 63 and low > 1) return error.VarintOverflow;
        result |= low << @intCast(shift);
        if (byte & 0x80 == 0) return result;
        if (shift >= 63) return error.VarintOverflow;
        shift += 7;
    }
}

pub fn writeU32(w: *std.Io.Writer, value: u32) Error!void {
    try writeU64(w, value);
}

pub fn readU32(r: *std.Io.Reader) Error!u32 {
    const v = try readU64(r);
    if (v > std.math.maxInt(u32)) return error.VarintOverflow;
    return @intCast(v);
}

pub fn writeSliceHeader(w: *std.Io.Writer, len: usize) Error!void {
    try writeU64(w, len);
}

pub fn readSliceHeader(r: *std.Io.Reader) Error!usize {
    const v = try readU64(r);
    return std.math.cast(usize, v) orelse error.VarintOverflow;
}

test "LEB128 round-trip" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeU64(&w, 10000);
    try std.testing.expectEqual(@as(usize, 2), w.end);
    var r: std.Io.Reader = .fixed(buf[0..w.end]);
    try std.testing.expectEqual(@as(u64, 10000), try readU64(&r));
}

test "LEB128 overlong varint rejects without shift overflow" {
    var r: std.Io.Reader = .fixed(&[_]u8{
        0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 0x80,
        0x00,
    });
    try std.testing.expectError(error.VarintOverflow, readU64(&r));
}
