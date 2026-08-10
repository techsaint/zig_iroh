//! Seekable readers over complete blobs.
//!
//! MemReader serves an owned copy of in-memory bytes; FsReader streams from
//! the durable content file with positional reads (the blob stays on disk).
//! Both are opened only for complete entries and verify content against the
//! content-addressed hash at open, so a reader never serves bytes that do
//! not match the hash it was opened with.

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const types = @import("types.zig");

pub const Error = types.Error;

pub const MemReader = struct {
    allocator: std.mem.Allocator,
    data: []u8,
    pos: usize,

    pub fn size(self: *const MemReader) u64 {
        return self.data.len;
    }

    pub fn position(self: *const MemReader) u64 {
        return self.pos;
    }

    /// Read up to `buf.len` bytes from the current position; returns the
    /// number of bytes read (0 at end).
    pub fn read(self: *MemReader, buf: []u8) usize {
        const n = @min(buf.len, self.data.len - self.pos);
        @memcpy(buf[0..n], self.data[self.pos .. self.pos + n]);
        self.pos += n;
        return n;
    }

    pub fn seekTo(self: *MemReader, offset: u64) Error!void {
        if (offset > self.data.len) return error.NotFound;
        self.pos = @intCast(offset);
    }

    /// Read from the current position to the end.
    pub fn readToEnd(self: *MemReader, allocator: std.mem.Allocator) Error![]u8 {
        const out = allocator.dupe(u8, self.data[self.pos..]) catch return error.OutOfMemory;
        self.pos = self.data.len;
        return out;
    }

    pub fn close(self: *MemReader) void {
        self.allocator.free(self.data);
        self.* = undefined;
    }
};

pub const FsReader = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    blob_size: u64,
    pos: u64,

    pub fn size(self: *const FsReader) u64 {
        return self.blob_size;
    }

    pub fn position(self: *const FsReader) u64 {
        return self.pos;
    }

    /// Read up to `buf.len` bytes from the current position; returns the
    /// number of bytes read (0 at end).
    pub fn read(self: *FsReader, buf: []u8) Error!usize {
        if (self.pos >= self.blob_size) return 0;
        const want: usize = @intCast(@min(buf.len, self.blob_size - self.pos));
        const n = self.file.readPositionalAll(self.io, buf[0..want], self.pos) catch return error.Io;
        self.pos += n;
        return n;
    }

    pub fn seekTo(self: *FsReader, offset: u64) Error!void {
        if (offset > self.blob_size) return error.NotFound;
        self.pos = offset;
    }

    /// Read from the current position to the end.
    pub fn readToEnd(self: *FsReader, allocator: std.mem.Allocator) Error![]u8 {
        const remaining: usize = @intCast(self.blob_size - self.pos);
        const out = allocator.alloc(u8, remaining) catch return error.OutOfMemory;
        errdefer allocator.free(out);
        var off: usize = 0;
        while (off < remaining) {
            const n = try self.read(out[off..]);
            if (n == 0) return error.Io;
            off += n;
        }
        return out;
    }

    pub fn close(self: *FsReader) void {
        self.file.close(self.io);
        self.* = undefined;
    }
};

test "mem reader reads, seeks, and bounds" {
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    var store = MemStore.init(alloc);
    defer store.deinit();

    const hash = try store.addBytes("reader-seek-content");
    var reader = try store.openReader(alloc, hash);
    defer reader.close();

    try std.testing.expectEqual(@as(u64, "reader-seek-content".len), reader.size());
    var buf: [6]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 6), reader.read(&buf));
    try std.testing.expectEqualStrings("reader", buf[0..6]);

    try reader.seekTo(7);
    try std.testing.expectEqual(@as(u64, 7), reader.position());
    try std.testing.expectEqual(@as(usize, 6), reader.read(&buf));
    try std.testing.expectEqualStrings("seek-c", buf[0..6]);

    try reader.seekTo(0);
    const all = try reader.readToEnd(alloc);
    defer alloc.free(all);
    try std.testing.expectEqualStrings("reader-seek-content", all);

    try std.testing.expectError(error.NotFound, reader.seekTo(1000));
    try std.testing.expectEqual(error.NotFound, store.openReader(alloc, Hash.of("absent")));
}

test "fs reader streams from disk with seek and verifies at open" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const path = try std.fmt.allocPrint(allocator, "zig-cache/tmp/blobs-fs-reader-{d}", .{nonce});
    defer allocator.free(path);
    defer std.Io.Dir.cwd().deleteTree(io, path) catch {};

    var store = try @import("fs_store.zig").FsStore.open(allocator, io, path);
    defer store.deinit();

    const content = "durable-reader-bytes";
    const hash = try store.addBytes(content);
    var reader = try store.openReader(allocator, hash);
    try std.testing.expectEqual(@as(u64, content.len), reader.size());

    var buf: [7]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 7), try reader.read(&buf));
    try std.testing.expectEqualStrings("durable", buf[0..7]);
    try reader.seekTo(8);
    const rest = try reader.readToEnd(allocator);
    defer allocator.free(rest);
    try std.testing.expectEqualStrings("reader-bytes", rest);
    try std.testing.expectEqual(@as(usize, 0), try reader.read(&buf));
    reader.close();

    // Tampered content is rejected at open and counted as an integrity error.
    const hex = hash.toHex();
    const blob_path = try std.fmt.allocPrint(allocator, "{s}/blobs/{s}", .{ path, &hex });
    defer allocator.free(blob_path);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = blob_path, .data = "tampered-reader!!" });
    try std.testing.expectError(error.HashMismatch, store.openReader(allocator, hash));
    try std.testing.expectEqual(@as(u64, 1), store.metrics().integrity_errors);
}
