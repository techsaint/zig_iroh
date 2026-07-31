//! In-memory Tags API — lex-ordered tag names, bytewise ranges/prefixes.
//!
//! Behaviour contract: iroh-blobs/tests/tags.rs::tags_smoke (Mem).

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const types = @import("types.zig");

pub const BlobFormat = types.BlobFormat;
pub const HashAndFormat = types.HashAndFormat;
pub const TagInfo = types.TagInfo;
pub const Error = types.Error;

const Entry = struct {
    name: []u8,
    hash: Hash,
    format: BlobFormat,
};

pub const Tags = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,

    pub fn init(allocator: std.mem.Allocator) Tags {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Tags) void {
        for (self.entries.items) |e| self.allocator.free(e.name);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn set(self: *Tags, name: []const u8, value: HashAndFormat) Error!void {
        const owned = self.allocator.dupe(u8, name) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        if (self.findIndex(name)) |idx| {
            self.allocator.free(self.entries.items[idx].name);
            self.entries.items[idx] = .{ .name = owned, .hash = value.hash, .format = value.format };
            return;
        }
        const idx = self.lowerBound(name);
        self.entries.insert(self.allocator, idx, .{
            .name = owned,
            .hash = value.hash,
            .format = value.format,
        }) catch return error.OutOfMemory;
    }

    pub fn setRaw(self: *Tags, name: []const u8, hash: Hash) Error!void {
        try self.set(name, HashAndFormat.raw(hash));
    }

    pub fn get(self: *const Tags, name: []const u8) ?TagInfo {
        const idx = self.findIndex(name) orelse return null;
        const e = self.entries.items[idx];
        return .{ .name = e.name, .hash = e.hash, .format = e.format };
    }

    pub fn list(self: *const Tags, allocator: std.mem.Allocator) Error![]TagInfo {
        return self.listFiltered(allocator, null, null, false, null);
    }

    /// Inclusive lower / exclusive upper (bytewise), matching Rust RangeBounds.
    pub fn listRange(
        self: *const Tags,
        allocator: std.mem.Allocator,
        start: ?[]const u8,
        end_exclusive: ?[]const u8,
    ) Error![]TagInfo {
        return self.listFiltered(allocator, start, end_exclusive, false, null);
    }

    pub fn listPrefix(self: *const Tags, allocator: std.mem.Allocator, prefix: []const u8) Error![]TagInfo {
        const end = try nextPrefix(allocator, prefix);
        defer if (end) |e| allocator.free(e);
        return self.listFiltered(allocator, prefix, end, false, null);
    }

    pub fn listHashSeq(self: *const Tags, allocator: std.mem.Allocator) Error![]TagInfo {
        return self.listFiltered(allocator, null, null, false, .hash_seq);
    }

    pub fn delete(self: *Tags, name: []const u8) bool {
        const idx = self.findIndex(name) orelse return false;
        self.allocator.free(self.entries.items[idx].name);
        _ = self.entries.orderedRemove(idx);
        return true;
    }

    pub fn deleteRange(self: *Tags, start: ?[]const u8, end_exclusive: ?[]const u8) usize {
        return self.deleteFiltered(start, end_exclusive, null);
    }

    pub fn deletePrefix(self: *Tags, prefix: []const u8) Error!usize {
        const end = try nextPrefix(self.allocator, prefix);
        defer if (end) |e| self.allocator.free(e);
        return self.deleteFiltered(prefix, end, null);
    }

    pub fn deleteAll(self: *Tags) void {
        for (self.entries.items) |e| self.allocator.free(e.name);
        self.entries.clearRetainingCapacity();
    }

    pub fn rename(self: *Tags, from: []const u8, to: []const u8) Error!void {
        const idx = self.findIndex(from) orelse return error.RenameMissing;
        const hash = self.entries.items[idx].hash;
        const format = self.entries.items[idx].format;
        _ = self.delete(from);
        try self.set(to, .{ .hash = hash, .format = format });
    }

    fn listFiltered(
        self: *const Tags,
        allocator: std.mem.Allocator,
        start: ?[]const u8,
        end_exclusive: ?[]const u8,
        _: bool,
        format_only: ?BlobFormat,
    ) Error![]TagInfo {
        var out: std.ArrayList(TagInfo) = .empty;
        errdefer {
            for (out.items) |t| t.deinit(allocator);
            out.deinit(allocator);
        }
        for (self.entries.items) |e| {
            if (start) |s| {
                if (std.mem.order(u8, e.name, s) == .lt) continue;
            }
            if (end_exclusive) |end| {
                if (std.mem.order(u8, e.name, end) != .lt) continue;
            }
            if (format_only) |fmt| {
                if (e.format != fmt) continue;
            }
            const name = allocator.dupe(u8, e.name) catch return error.OutOfMemory;
            out.append(allocator, .{ .name = name, .hash = e.hash, .format = e.format }) catch {
                allocator.free(name);
                return error.OutOfMemory;
            };
        }
        return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
    }

    fn deleteFiltered(
        self: *Tags,
        start: ?[]const u8,
        end_exclusive: ?[]const u8,
        format_only: ?BlobFormat,
    ) usize {
        var removed: usize = 0;
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const e = self.entries.items[i];
            const in_range = blk: {
                if (start) |s| {
                    if (std.mem.order(u8, e.name, s) == .lt) break :blk false;
                }
                if (end_exclusive) |end| {
                    if (std.mem.order(u8, e.name, end) != .lt) break :blk false;
                }
                if (format_only) |fmt| {
                    if (e.format != fmt) break :blk false;
                }
                break :blk true;
            };
            if (in_range) {
                self.allocator.free(e.name);
                _ = self.entries.orderedRemove(i);
                removed += 1;
            } else {
                i += 1;
            }
        }
        return removed;
    }

    fn findIndex(self: *const Tags, name: []const u8) ?usize {
        const idx = self.lowerBound(name);
        if (idx < self.entries.items.len and std.mem.eql(u8, self.entries.items[idx].name, name))
            return idx;
        return null;
    }

    fn lowerBound(self: *const Tags, name: []const u8) usize {
        var lo: usize = 0;
        var hi: usize = self.entries.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (std.mem.order(u8, self.entries.items[mid].name, name) == .lt) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }
};

/// Bytewise successor prefix bound: first string that does not start with `prefix`.
/// Returns null when no finite upper bound exists (all-0xff prefix).
fn nextPrefix(allocator: std.mem.Allocator, prefix: []const u8) Error!?[]u8 {
    if (prefix.len == 0) return null;
    var buf = allocator.dupe(u8, prefix) catch return error.OutOfMemory;
    errdefer allocator.free(buf);
    var i = buf.len;
    while (i > 0) {
        i -= 1;
        if (buf[i] != 0xff) {
            buf[i] += 1;
            const trimmed = allocator.realloc(buf, i + 1) catch {
                // keep full buffer with incremented byte; still a valid exclusive bound
                return buf;
            };
            return trimmed;
        }
    }
    allocator.free(buf);
    return null;
}

test "tags smoke mem" {
    const alloc = std.testing.allocator;
    var tags = Tags.init(alloc);
    defer tags.deinit();

    const names = [_][]const u8{ "a", "b", "c", "d", "e" };
    for (names) |n| try tags.setRaw(n, Hash.of(n));

    {
        const list = try tags.list(alloc);
        defer freeTagInfos(alloc, list);
        try expectNames(list, &names);
    }
    {
        const list = try tags.listRange(alloc, "b", "d");
        defer freeTagInfos(alloc, list);
        try expectNames(list, &.{ "b", "c" });
    }
    {
        const list = try tags.listRange(alloc, "b", null);
        defer freeTagInfos(alloc, list);
        try expectNames(list, &.{ "b", "c", "d", "e" });
    }
    {
        const list = try tags.listRange(alloc, null, "d");
        defer freeTagInfos(alloc, list);
        try expectNames(list, &.{ "a", "b", "c" });
    }
    // Inclusive upper "d" ≈ exclusive successor of "d"
    {
        const end = try successor(alloc, "d");
        defer alloc.free(end);
        const list = try tags.listRange(alloc, null, end);
        defer freeTagInfos(alloc, list);
        try expectNames(list, &.{ "a", "b", "c", "d" });
    }

    _ = tags.deleteRange("b", null);
    {
        const list = try tags.list(alloc);
        defer freeTagInfos(alloc, list);
        try expectNames(list, &.{"a"});
    }
    {
        const end = try successor(alloc, "a");
        defer alloc.free(end);
        _ = tags.deleteRange(null, end);
    }
    {
        const list = try tags.list(alloc);
        defer freeTagInfos(alloc, list);
        try expectNames(list, &.{});
    }

    for ([_][]const u8{ "a", "aa", "aaa", "aab", "b" }) |n| try tags.setRaw(n, Hash.of(n));
    {
        const list = try tags.listPrefix(alloc, "aa");
        defer freeTagInfos(alloc, list);
        try expectNames(list, &.{ "aa", "aaa", "aab" });
    }
    _ = try tags.deletePrefix("aa");
    {
        const list = try tags.list(alloc);
        defer freeTagInfos(alloc, list);
        try expectNames(list, &.{ "a", "b" });
    }
    _ = try tags.deletePrefix("");
    {
        const list = try tags.list(alloc);
        defer freeTagInfos(alloc, list);
        try expectNames(list, &.{});
    }

    for ([_][]const u8{ "a", "b", "c" }) |n| try tags.setRaw(n, Hash.of(n));
    try std.testing.expect(tags.get("b") != null);
    try std.testing.expect(tags.delete("b"));
    {
        const list = try tags.list(alloc);
        defer freeTagInfos(alloc, list);
        try expectNames(list, &.{ "a", "c" });
    }
    try std.testing.expect(tags.get("b") == null);
    tags.deleteAll();

    try tags.set("a", HashAndFormat.hashSeq(Hash.of("a")));
    try tags.set("b", HashAndFormat.raw(Hash.of("b")));
    {
        const list = try tags.listHashSeq(alloc);
        defer freeTagInfos(alloc, list);
        try std.testing.expectEqual(@as(usize, 1), list.len);
        try std.testing.expectEqualStrings("a", list[0].name);
        try std.testing.expect(list[0].format == .hash_seq);
    }

    tags.deleteAll();
    try tags.setRaw("c", Hash.of("c"));
    try tags.rename("c", "f");
    {
        const list = try tags.list(alloc);
        defer freeTagInfos(alloc, list);
        try std.testing.expectEqual(@as(usize, 1), list.len);
        try std.testing.expectEqualStrings("f", list[0].name);
        try std.testing.expect(list[0].hash.eql(Hash.of("c")));
    }
    try std.testing.expectError(error.RenameMissing, tags.rename("y", "z"));
}

fn successor(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var buf = try allocator.alloc(u8, s.len + 1);
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return buf;
}

fn freeTagInfos(allocator: std.mem.Allocator, list: []TagInfo) void {
    for (list) |t| t.deinit(allocator);
    allocator.free(list);
}

fn expectNames(list: []const TagInfo, names: []const []const u8) !void {
    try std.testing.expectEqual(names.len, list.len);
    for (list, names) |t, n| try std.testing.expectEqualStrings(n, t.name);
}
