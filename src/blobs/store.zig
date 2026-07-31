//! In-memory Blob Store — add/get/export/list + embedded Tags.
//!
//! Behaviour contract: iroh-blobs/tests/blobs.rs::blobs_smoke_mem
//! (local MemStore only; no FsStore/RPC in this slice).

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const tags_mod = @import("tags.zig");
const types = @import("types.zig");

pub const Tags = tags_mod.Tags;
pub const BlobFormat = types.BlobFormat;
pub const HashAndFormat = types.HashAndFormat;
pub const TagInfo = types.TagInfo;
pub const Error = types.Error || error{HashMismatch};

const BlobEntry = struct {
    data: []u8,
};

pub const MemStore = struct {
    allocator: std.mem.Allocator,
    blobs: std.AutoHashMapUnmanaged([32]u8, BlobEntry) = .empty,
    tags_inner: Tags,

    pub fn init(allocator: std.mem.Allocator) MemStore {
        return .{
            .allocator = allocator,
            .tags_inner = Tags.init(allocator),
        };
    }

    pub fn deinit(self: *MemStore) void {
        var it = self.blobs.iterator();
        while (it.next()) |e| self.allocator.free(e.value_ptr.data);
        self.blobs.deinit(self.allocator);
        self.tags_inner.deinit();
        self.* = undefined;
    }

    pub fn shutdown(self: *MemStore) void {
        _ = self;
    }

    pub fn tags(self: *MemStore) *Tags {
        return &self.tags_inner;
    }

    pub fn addBytes(self: *MemStore, data: []const u8) Error!Hash {
        const hash = Hash.of(data);
        if (self.blobs.contains(hash.bytes)) return hash;
        const owned = self.allocator.dupe(u8, data) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        self.blobs.put(self.allocator, hash.bytes, .{ .data = owned }) catch return error.OutOfMemory;
        return hash;
    }

    pub fn getBytes(self: *const MemStore, allocator: std.mem.Allocator, hash: Hash) Error![]u8 {
        const entry = self.blobs.get(hash.bytes) orelse return error.NotFound;
        return allocator.dupe(u8, entry.data) catch return error.OutOfMemory;
    }

    pub fn addPath(self: *MemStore, io: std.Io, path: []const u8) Error!Hash {
        const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return error.Io;
        defer file.close(io);
        const stat = file.stat(io) catch return error.Io;
        const size: usize = @intCast(stat.size);
        const buf = self.allocator.alloc(u8, size) catch return error.OutOfMemory;
        defer self.allocator.free(buf);
        var reader_buf: [4096]u8 = undefined;
        var file_reader = file.reader(io, &reader_buf);
        const r = &file_reader.interface;
        r.readSliceAll(buf) catch return error.Io;
        return self.addBytes(buf);
    }

    pub fn exportPath(self: *const MemStore, io: std.Io, hash: Hash, path: []const u8) Error!void {
        const entry = self.blobs.get(hash.bytes) orelse return error.NotFound;
        const file = std.Io.Dir.cwd().createFile(io, path, .{}) catch return error.Io;
        defer file.close(io);
        var writer_buf: [4096]u8 = undefined;
        var file_writer = file.writer(io, &writer_buf);
        const w = &file_writer.interface;
        w.writeAll(entry.data) catch return error.Io;
        w.flush() catch return error.Io;
    }

    pub fn listHashes(self: *const MemStore, allocator: std.mem.Allocator) Error![]Hash {
        var out: std.ArrayList(Hash) = .empty;
        errdefer out.deinit(allocator);
        var it = self.blobs.keyIterator();
        while (it.next()) |k| {
            out.append(allocator, Hash.fromBytes(k.*)) catch return error.OutOfMemory;
        }
        return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
    }
};

test "blobs smoke mem" {
    const alloc = std.testing.allocator;
    var store = MemStore.init(alloc);
    defer store.deinit();

    const expected = "hello";
    const hash = try store.addBytes(expected);
    try std.testing.expect(hash.eql(Hash.of(expected)));
    {
        const actual = try store.getBytes(alloc, hash);
        defer alloc.free(actual);
        try std.testing.expectEqualStrings(expected, actual);
    }

    _ = try store.addBytes("somestuffinafile");
    const big = try alloc.alloc(u8, 1024 * 1024);
    defer alloc.free(big);
    @memset(big, 0);
    const big_hash = try store.addBytes(big);
    try std.testing.expect(big_hash.eql(Hash.of(big)));

    const hashes = try store.listHashes(alloc);
    defer alloc.free(hashes);
    try std.testing.expectEqual(@as(usize, 3), hashes.len);
}
