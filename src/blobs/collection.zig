//! iroh collection metadata and link splitting.
//!
//! Mirrors `iroh-blobs/src/format/collection.rs` for the S7 subset.

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const hashseq = @import("hashseq.zig");
const postcard = @import("postcard.zig");

pub const HEADER = "CollectionV0.".*;

pub const Error = postcard.Error || error{
    InvalidHeader,
    InvalidUtf8,
    EndOfStream,
    OutOfMemory,
    WriteFailed,
};

pub const CollectionMeta = struct {
    names: []const []const u8,

    pub fn encode(self: CollectionMeta, w: *std.Io.Writer) Error!void {
        for (self.names) |name| {
            if (!std.unicode.utf8ValidateSlice(name)) return error.InvalidUtf8;
        }
        try w.writeAll(&HEADER);
        try postcard.writeSliceHeader(w, self.names.len);
        for (self.names) |name| {
            try postcard.writeSliceHeader(w, name.len);
            try w.writeAll(name);
        }
    }

    pub fn decode(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!CollectionMeta {
        var header: [HEADER.len]u8 = undefined;
        const hn = try r.readSliceShort(&header);
        if (hn != HEADER.len) return error.EndOfStream;
        if (!std.mem.eql(u8, &header, &HEADER)) return error.InvalidHeader;

        const len = try postcard.readSliceHeader(r);
        const names = try allocator.alloc([]u8, len);
        var filled: usize = 0;
        errdefer {
            for (names[0..filled]) |name| allocator.free(name);
            allocator.free(names);
        }
        for (names) |*slot| {
            const name_len = try postcard.readSliceHeader(r);
            const name = try allocator.alloc(u8, name_len);
            errdefer allocator.free(name);
            const n = try r.readSliceShort(name);
            if (n != name_len) return error.EndOfStream;
            if (!std.unicode.utf8ValidateSlice(name)) return error.InvalidUtf8;
            slot.* = name;
            filled += 1;
        }
        return .{ .names = names };
    }

    pub fn deinit(self: CollectionMeta, allocator: std.mem.Allocator) void {
        for (self.names) |name| allocator.free(@constCast(name));
        allocator.free(@constCast(self.names));
    }
};

pub const Collection = struct {
    blobs: []const Entry,

    pub const Entry = struct {
        name: []const u8,
        hash: Hash,
    };

    pub fn links(self: Collection, allocator: std.mem.Allocator) ![]Hash {
        const out = try allocator.alloc(Hash, self.blobs.len);
        for (self.blobs, 0..) |entry, i| out[i] = entry.hash;
        return out;
    }

    pub fn names(self: Collection, allocator: std.mem.Allocator) ![][]u8 {
        const out = try allocator.alloc([]u8, self.blobs.len);
        var filled: usize = 0;
        errdefer {
            for (out[0..filled]) |name| allocator.free(name);
            allocator.free(out);
        }
        for (self.blobs, 0..) |entry, i| {
            out[i] = try allocator.dupe(u8, entry.name);
            filled += 1;
        }
        return out;
    }

    pub fn fromParts(allocator: std.mem.Allocator, links_in: []const Hash, meta: CollectionMeta) !Collection {
        if (links_in.len != meta.names.len) return error.LengthMismatch;
        const len = links_in.len;
        const blobs = try allocator.alloc(Entry, len);
        var filled: usize = 0;
        errdefer {
            for (blobs[0..filled]) |entry| allocator.free(@constCast(entry.name));
            allocator.free(blobs);
        }
        for (0..len) |i| {
            blobs[i] = .{ .name = try allocator.dupe(u8, meta.names[i]), .hash = links_in[i] };
            filled += 1;
        }
        return .{ .blobs = blobs };
    }

    pub fn deinit(self: Collection, allocator: std.mem.Allocator) void {
        for (self.blobs) |entry| allocator.free(@constCast(entry.name));
        allocator.free(@constCast(self.blobs));
    }

    pub const Blobs = struct {
        meta_bytes: []u8,
        links_bytes: []const u8,

        pub fn deinit(self: *Blobs, allocator: std.mem.Allocator) void {
            allocator.free(self.meta_bytes);
            allocator.free(@constCast(self.links_bytes));
        }
    };

    pub fn toBlobs(self: Collection, allocator: std.mem.Allocator) !Blobs {
        const names_out = try self.names(allocator);
        defer {
            for (names_out) |name| allocator.free(name);
            allocator.free(names_out);
        }

        const meta_bytes = try encodeMetaAlloc(allocator, .{ .names = names_out });
        errdefer allocator.free(meta_bytes);

        const child_links = try self.links(allocator);
        defer allocator.free(child_links);
        const link_hashes = try allocator.alloc(Hash, child_links.len + 1);
        defer allocator.free(link_hashes);
        link_hashes[0] = Hash.of(meta_bytes);
        @memcpy(link_hashes[1..], child_links);

        const seq = try hashseq.HashSeq.fromHashes(allocator, link_hashes);
        return .{ .meta_bytes = meta_bytes, .links_bytes = seq.bytes };
    }
};

pub fn encodeMetaAlloc(allocator: std.mem.Allocator, meta: CollectionMeta) ![]u8 {
    var size: usize = HEADER.len + lebLen(meta.names.len);
    for (meta.names) |name| size += lebLen(name.len) + name.len;
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    var w: std.Io.Writer = .fixed(out);
    try meta.encode(&w);
    return out[0..w.end];
}

fn lebLen(value: usize) usize {
    var v = value;
    var len: usize = 1;
    while (v >= 0x80) : (len += 1) v >>= 7;
    return len;
}

fn hexToBytes(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    var out: [hex_str.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

test "CollectionMeta header is CollectionV0 dot" {
    try std.testing.expectEqual(@as(usize, 13), HEADER.len);
    try std.testing.expectEqualSlices(u8, "CollectionV0.", &HEADER);
}

test "CollectionMeta wire vector format/collection.rs:79-86,118" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try (CollectionMeta{ .names = &.{ "test", "a", "b" } }).encode(&w);
    const expected = hexToBytes("436F6C6C656374696F6E56302E03047465737401610162");
    try std.testing.expectEqualSlices(u8, &expected, w.buffer[0..w.end]);
}

test "CollectionMeta decode round-trip" {
    const alloc = std.testing.allocator;
    const bytes = hexToBytes("436F6C6C656374696F6E56302E03047465737401610162");
    var r: std.Io.Reader = .fixed(&bytes);
    const meta = try CollectionMeta.decode(alloc, &r);
    defer meta.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 3), meta.names.len);
    try std.testing.expectEqualStrings("test", meta.names[0]);
    try std.testing.expectEqualStrings("a", meta.names[1]);
    try std.testing.expectEqualStrings("b", meta.names[2]);
}

test "CollectionMeta rejects invalid UTF-8 without emitting partial metadata" {
    const invalid_name = &[_]u8{0xff};
    var out: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try std.testing.expectError(error.InvalidUtf8, (CollectionMeta{ .names = &.{invalid_name} }).encode(&w));
    try std.testing.expectEqual(@as(usize, 0), w.end);

    var encoded: [HEADER.len + 3]u8 = undefined;
    @memcpy(encoded[0..HEADER.len], &HEADER);
    encoded[HEADER.len..].* = .{ 1, 1, 0xff };
    var r: std.Io.Reader = .fixed(&encoded);
    try std.testing.expectError(error.InvalidUtf8, CollectionMeta.decode(std.testing.allocator, &r));
}

test "Collection fromParts rejects link and name length mismatch" {
    const h0 = Hash.of("0");
    const h1 = Hash.of("1");
    try std.testing.expectError(
        error.LengthMismatch,
        Collection.fromParts(std.testing.allocator, &.{h0}, .{ .names = &.{ "0", "1" } }),
    );
    try std.testing.expectError(
        error.LengthMismatch,
        Collection.fromParts(std.testing.allocator, &.{ h0, h1 }, .{ .names = &.{"0"} }),
    );
}

test "Collection toBlobs puts meta hash first" {
    const alloc = std.testing.allocator;
    const h0 = Hash.of("child0");
    const h1 = Hash.of("child1");
    const entries = &[_]Collection.Entry{
        .{ .name = "blob0", .hash = h0 },
        .{ .name = "blob1", .hash = h1 },
    };
    var blobs = try (Collection{ .blobs = entries }).toBlobs(alloc);
    defer blobs.deinit(alloc);
    const seq = try hashseq.HashSeq.fromBytes(blobs.links_bytes);
    try std.testing.expectEqual(@as(usize, 3), seq.len());
    try std.testing.expect(seq.get(0).?.eql(Hash.of(blobs.meta_bytes)));
    try std.testing.expect(seq.get(1).?.eql(h0));
    try std.testing.expect(seq.get(2).?.eql(h1));
}
