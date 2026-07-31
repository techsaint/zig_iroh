//! Public Tags API smoke — MemStore.tags equivalent of tags_smoke_mem.
//! Receipt source for oracle row `blobs_tags_api`.

const std = @import("std");
const zig_iroh = @import("zig_iroh");

const Hash = zig_iroh.Hash;
const MemStore = zig_iroh.blobs.store.MemStore;
const HashAndFormat = zig_iroh.blobs.store.HashAndFormat;
const TagInfo = zig_iroh.blobs.store.TagInfo;

const pass_marker = "PASS: Zig blobs Tags API smoke (set/list/range/prefix/delete/rename)";

fn freeList(allocator: std.mem.Allocator, list: []TagInfo) void {
    for (list) |t| t.deinit(allocator);
    allocator.free(list);
}

fn expectNames(list: []const TagInfo, names: []const []const u8) !void {
    if (list.len != names.len) return error.ListLen;
    for (list, names) |t, n| {
        if (!std.mem.eql(u8, t.name, n)) return error.NameMismatch;
    }
}

fn setRaw(tags: anytype, names: []const []const u8) !void {
    for (names) |n| try tags.setRaw(n, Hash.of(n));
}

fn successor(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = try allocator.alloc(u8, s.len + 1);
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return buf;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var store = MemStore.init(allocator);
    defer store.deinit();
    const tags = store.tags();

    try setRaw(tags, &.{ "a", "b", "c", "d", "e" });
    {
        const list = try tags.list(allocator);
        defer freeList(allocator, list);
        try expectNames(list, &.{ "a", "b", "c", "d", "e" });
    }
    {
        const list = try tags.listRange(allocator, "b", "d");
        defer freeList(allocator, list);
        try expectNames(list, &.{ "b", "c" });
    }
    {
        const list = try tags.listRange(allocator, "b", null);
        defer freeList(allocator, list);
        try expectNames(list, &.{ "b", "c", "d", "e" });
    }
    {
        const list = try tags.listRange(allocator, null, "d");
        defer freeList(allocator, list);
        try expectNames(list, &.{ "a", "b", "c" });
    }
    {
        const end = try successor(allocator, "d");
        defer allocator.free(end);
        const list = try tags.listRange(allocator, null, end);
        defer freeList(allocator, list);
        try expectNames(list, &.{ "a", "b", "c", "d" });
    }

    _ = tags.deleteRange("b", null);
    {
        const list = try tags.list(allocator);
        defer freeList(allocator, list);
        try expectNames(list, &.{"a"});
    }
    {
        const end = try successor(allocator, "a");
        defer allocator.free(end);
        _ = tags.deleteRange(null, end);
    }
    {
        const list = try tags.list(allocator);
        defer freeList(allocator, list);
        try expectNames(list, &.{});
    }

    try setRaw(tags, &.{ "a", "aa", "aaa", "aab", "b" });
    {
        const list = try tags.listPrefix(allocator, "aa");
        defer freeList(allocator, list);
        try expectNames(list, &.{ "aa", "aaa", "aab" });
    }
    _ = try tags.deletePrefix("aa");
    {
        const list = try tags.list(allocator);
        defer freeList(allocator, list);
        try expectNames(list, &.{ "a", "b" });
    }
    _ = try tags.deletePrefix("");
    {
        const list = try tags.list(allocator);
        defer freeList(allocator, list);
        try expectNames(list, &.{});
    }

    try setRaw(tags, &.{ "a", "b", "c" });
    if (tags.get("b") == null) return error.GetMissing;
    if (!tags.delete("b")) return error.DeleteFailed;
    {
        const list = try tags.list(allocator);
        defer freeList(allocator, list);
        try expectNames(list, &.{ "a", "c" });
    }
    if (tags.get("b") != null) return error.GetStillPresent;
    tags.deleteAll();

    try tags.set("a", HashAndFormat.hashSeq(Hash.of("a")));
    try tags.set("b", HashAndFormat.raw(Hash.of("b")));
    {
        const list = try tags.listHashSeq(allocator);
        defer freeList(allocator, list);
        if (list.len != 1 or !std.mem.eql(u8, list[0].name, "a") or list[0].format != .hash_seq)
            return error.HashSeqList;
    }

    tags.deleteAll();
    try tags.setRaw("c", Hash.of("c"));
    try tags.rename("c", "f");
    {
        const list = try tags.list(allocator);
        defer freeList(allocator, list);
        if (list.len != 1 or !std.mem.eql(u8, list[0].name, "f") or !list[0].hash.eql(Hash.of("c")))
            return error.Rename;
    }
    tags.rename("y", "z") catch |err| switch (err) {
        error.RenameMissing => {},
        else => return err,
    };

    std.debug.print("{s}\n", .{pass_marker});
}
