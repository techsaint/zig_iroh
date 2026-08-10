//! BE u32 length prefix + postcard body over std.Io.
const std = @import("std");

pub const Error = error{
    EndOfStream,
    MessageTooLarge,
    OutOfMemory,
    ReadFailed,
    WriteFailed,
};

pub fn writeFrame(writer: *std.Io.Writer, body: []const u8) Error!void {
    try writeFrameLimited(writer, body, std.math.maxInt(u32));
}

pub fn writeFrameLimited(writer: *std.Io.Writer, body: []const u8, max_message_size: usize) Error!void {
    // Rust iroh-gossip reserves the configured limit itself and rejects a
    // serialized body whose length is equal to the limit.
    if (body.len >= max_message_size or body.len > std.math.maxInt(u32)) return error.MessageTooLarge;
    var hdr: [4]u8 = undefined;
    std.mem.writeInt(u32, &hdr, @intCast(body.len), .big);
    try writer.writeAll(&hdr);
    try writer.writeAll(body);
    try writer.flush();
}

fn readExact(reader: *std.Io.Reader, buf: []u8) Error!void {
    var off: usize = 0;
    while (off < buf.len) {
        const n = try reader.readSliceShort(buf[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
}

pub fn readFrame(
    reader: *std.Io.Reader,
    allocator: std.mem.Allocator,
    max_message_size: usize,
) Error![]u8 {
    var hdr: [4]u8 = undefined;
    try readExact(reader, &hdr);
    const len: usize = @intCast(std.mem.readInt(u32, &hdr, .big));
    if (len > max_message_size) return error.MessageTooLarge;
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    try readExact(reader, buf);
    return buf;
}

test "frame round-trip" {
    const alloc = std.testing.allocator;
    var out_buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buf);
    try writeFrame(&w, &[_]u8{ 0x01, 0x01 });
    const written = w.buffered();
    try std.testing.expectEqual(@as(usize, 6), written.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 2, 0x01, 0x01 }, written);

    var r: std.Io.Reader = .fixed(written);
    const body = try readFrame(&r, alloc, 4096);
    defer alloc.free(body);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x01 }, body);
}

test "F2: writeFrameLimited rejects oversize bodies before writing" {
    var out_buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buf);

    try std.testing.expectError(error.MessageTooLarge, writeFrameLimited(&w, &[_]u8{ 1, 2, 3 }, 2));
    try std.testing.expectEqual(@as(usize, 0), w.buffered().len);
}

test "writeFrameLimited matches Rust's exclusive maximum" {
    var out_buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buf);

    try std.testing.expectError(error.MessageTooLarge, writeFrameLimited(&w, &[_]u8{ 1, 2 }, 2));
    try std.testing.expectEqual(@as(usize, 0), w.buffered().len);
}
