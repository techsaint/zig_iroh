//! RangeSpec + ChunkRangesSeq postcard codec.
//!
//! Mirrors `iroh-blobs/src/protocol/range_spec.rs`.

const std = @import("std");
const postcard = @import("postcard.zig");

pub const Error = postcard.Error || error{
    InvalidRangeSpec,
    InvalidChunkRangesSeq,
    ReadFailed,
    WriteFailed,
};

/// Alternating span widths starting deselected (postcard `Vec<u64>`).
pub const RangeSpec = struct {
    /// Element 0 = deselected span from chunk 0; then toggle selected/deselected.
    /// Odd length => final selected span is open-ended.
    widths: []const u64,

    const empty_widths: [0]u64 = .{};
    pub const empty: RangeSpec = .{ .widths = &empty_widths };

    pub fn all() RangeSpec {
        return .{ .widths = all_widths };
    }

    pub fn verifiedSize() RangeSpec {
        return .{ .widths = verified_size_widths };
    }

    pub fn encode(self: RangeSpec, w: *std.Io.Writer) Error!void {
        try postcard.writeSliceHeader(w, self.widths.len);
        for (self.widths) |width| try postcard.writeU64(w, width);
    }

    pub fn decode(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!RangeSpec {
        const len = try postcard.readSliceHeader(r);
        const widths = try allocator.alloc(u64, len);
        errdefer allocator.free(widths);
        for (widths) |*slot| slot.* = try postcard.readU64(r);
        return .{ .widths = widths };
    }

    pub fn deinit(self: RangeSpec, allocator: std.mem.Allocator) void {
        // Static constants (empty/all/verifiedSize/file_empty) must not be freed.
        if (isStaticWidths(self.widths)) return;
        allocator.free(@constCast(self.widths));
    }

    /// A half-open chunk index range.
    pub const ChunkRange = struct {
        start: u64,
        end: ?u64, // null = open-ended (infinity)
    };

    pub fn toChunkRanges(self: RangeSpec, allocator: std.mem.Allocator) Error![]ChunkRange {
        // Match Rust `RangeSpec::to_chunk_ranges`: for each width, record while ON,
        // then advance, then toggle. Open-ended if still ON after the last width.
        var ranges: std.ArrayList(ChunkRange) = .empty;
        errdefer ranges.deinit(allocator);

        var current: u64 = 0;
        var on = false;
        for (self.widths) |width| {
            const next = std.math.add(u64, current, width) catch return error.InvalidRangeSpec;
            if (on and current != next) {
                if (ranges.items.len > 0 and ranges.items[ranges.items.len - 1].end == current) {
                    ranges.items[ranges.items.len - 1].end = next;
                } else {
                    try ranges.append(allocator, .{ .start = current, .end = next });
                }
            }
            current = next;
            on = !on;
        }
        if (on) {
            if (ranges.items.len > 0 and ranges.items[ranges.items.len - 1].end == current) {
                ranges.items[ranges.items.len - 1].end = null;
            } else {
                try ranges.append(allocator, .{ .start = current, .end = null });
            }
        }
        return try ranges.toOwnedSlice(allocator);
    }

    pub fn fromChunkRanges(allocator: std.mem.Allocator, ranges: []const ChunkRange) Error!RangeSpec {
        if (ranges.len == 0) return empty;

        var widths: std.ArrayList(u64) = .empty;
        errdefer widths.deinit(allocator);

        var chunk: u64 = 0;
        for (ranges) |range| {
            if (range.start < chunk) return error.InvalidRangeSpec;
            // Deselected gap (may be 0 when adjacent selected ranges — merge by
            // extending the previous selected width instead of emitting 0,0).
            const gap = range.start - chunk;
            if (range.end) |end| {
                if (end < range.start) return error.InvalidRangeSpec;
                if (end == range.start) continue;
                if (gap == 0 and widths.items.len >= 1 and widths.items.len % 2 == 0) {
                    // Adjacent to previous selected span: extend it.
                    widths.items[widths.items.len - 1] += end - range.start;
                } else {
                    try widths.append(allocator, gap);
                    try widths.append(allocator, end - range.start);
                }
                chunk = end;
            } else {
                // Open-ended selected from range.start (odd-length widths).
                if (gap == 0 and widths.items.len >= 1 and widths.items.len % 2 == 0) {
                    // Drop the closing of previous finite select — reopen it.
                    _ = widths.pop();
                } else {
                    try widths.append(allocator, gap);
                }
                const out = try widths.toOwnedSlice(allocator);
                return .{ .widths = out };
            }
        }
        if (widths.items.len == 0) return empty;
        const out = try widths.toOwnedSlice(allocator);
        return .{ .widths = out };
    }
};

pub const ChunkRangesSeq = struct {
    /// `(offset, RangeSpec)` — wire stores offset deltas + RLE on identical specs.
    entries: []const Entry,

    pub const Entry = struct {
        offset: u64,
        spec: RangeSpec,
    };

    pub fn empty() ChunkRangesSeq {
        return .{ .entries = &empty_entries };
    }

    pub fn all() ChunkRangesSeq {
        return .{ .entries = all_entries };
    }

    /// Single blob: root only, finite sequence.
    pub fn singleBlob() ChunkRangesSeq {
        return .{ .entries = single_blob_entries };
    }

    pub fn encode(self: ChunkRangesSeq, w: *std.Io.Writer) Error!void {
        try postcard.writeSliceHeader(w, self.entries.len);
        var prev_offset: u64 = 0;
        for (self.entries) |entry| {
            const delta = entry.offset -% prev_offset;
            try postcard.writeU64(w, delta);
            try entry.spec.encode(w);
            prev_offset = entry.offset;
        }
    }

    pub fn decode(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!ChunkRangesSeq {
        const len = try postcard.readSliceHeader(r);
        const entries = try allocator.alloc(Entry, len);
        var filled: usize = 0;
        errdefer {
            for (entries[0..filled]) |entry| entry.spec.deinit(allocator);
            allocator.free(entries);
        }
        var prev_offset: u64 = 0;
        for (entries) |*entry| {
            const delta = try postcard.readU64(r);
            entry.offset = std.math.add(u64, prev_offset, delta) catch return error.InvalidChunkRangesSeq;
            prev_offset = entry.offset;
            entry.spec = try RangeSpec.decode(allocator, r);
            filled += 1;
        }
        return .{ .entries = entries };
    }

    pub fn deinit(self: ChunkRangesSeq, allocator: std.mem.Allocator) void {
        for (self.entries) |entry| entry.spec.deinit(allocator);
        allocator.free(@constCast(self.entries));
    }

    pub fn isBlob(self: ChunkRangesSeq) bool {
        return self.entries.len == 2 and
            self.entries[0].offset == 0 and
            self.entries[1].offset == 1 and
            self.entries[1].spec.widths.len == 0;
    }
};

const all_widths = &[_]u64{0};
const verified_size_widths = &[_]u64{std.math.maxInt(u64)};
const file_empty_widths: [0]u64 = .{};
const empty_entries: [0]ChunkRangesSeq.Entry = .{};
const all_entries = &[_]ChunkRangesSeq.Entry{
    .{ .offset = 0, .spec = .{ .widths = all_widths } },
};
const single_blob_entries = &[_]ChunkRangesSeq.Entry{
    .{ .offset = 0, .spec = .{ .widths = all_widths } },
    .{ .offset = 1, .spec = .{ .widths = &file_empty_widths } },
};

fn isStaticWidths(widths: []const u64) bool {
    // Only known static constants — an allocated empty decode must still free.
    return widths.ptr == all_widths.ptr or
        widths.ptr == verified_size_widths.ptr or
        widths.ptr == @as([*]const u64, @ptrCast(&file_empty_widths)) or
        widths.ptr == @as([*]const u64, @ptrCast(&RangeSpec.empty_widths));
}

fn hexToBytes(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    var out: [hex_str.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

fn expectWire(comptime hex_str: []const u8, spec: RangeSpec) !void {
    const expected = hexToBytes(hex_str);
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try spec.encode(&w);
    try std.testing.expectEqual(expected.len, w.end);
    try std.testing.expectEqualSlices(u8, &expected, w.buffer[0..w.end]);
}

fn expectWireSeq(comptime hex_str: []const u8, spec: ChunkRangesSeq) !void {
    const expected = hexToBytes(hex_str);
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try spec.encode(&w);
    try std.testing.expectEqual(expected.len, w.end);
    try std.testing.expectEqualSlices(u8, &expected, w.buffer[0..w.end]);
}

test "RangeSpec wire vectors §2a" {
    const widths64 = &[_]u64{64};
    const widths10000 = &[_]u64{10000};
    const widths0_64 = &[_]u64{ 0, 64 };
    const widths_multi = &[_]u64{ 1, 2, 6, 4 };
    try expectWire("00", RangeSpec.empty);
    try expectWire("0100", RangeSpec.all());
    try expectWire("0140", .{ .widths = widths64 });
    try expectWire("01904E", .{ .widths = widths10000 });
    try expectWire("020040", .{ .widths = widths0_64 });
    try expectWire("0401020604", .{ .widths = widths_multi });
}

test "ChunkRangesSeq wire vectors §2b" {
    const widths_1_2 = &[_]u64{ 1, 2 };
    const widths_7_6 = &[_]u64{ 7, 6 };
    try expectWireSeq("00", ChunkRangesSeq.empty());
    try expectWireSeq("01000100", ChunkRangesSeq.all());
    try expectWireSeq(
        "0300020102010207060100",
        .{ .entries = &[_]ChunkRangesSeq.Entry{
            .{ .offset = 0, .spec = .{ .widths = widths_1_2 } },
            .{ .offset = 1, .spec = .{ .widths = widths_7_6 } },
            .{ .offset = 2, .spec = RangeSpec.empty },
        } },
    );
    const bytes_020301070100 = hexToBytes("020301070100");
    var r2: std.Io.Reader = .fixed(&bytes_020301070100);
    const seq2 = try ChunkRangesSeq.decode(std.testing.allocator, &r2);
    defer seq2.deinit(std.testing.allocator);
    try expectWireSeq("020301070100", seq2);
}

test "RangeSpec decode round-trip" {
    const alloc = std.testing.allocator;
    const cases = [_][]const u8{ "00", "0100", "0140", "01904E", "020040", "0401020604" };
    inline for (cases) |hex| {
        const bytes = hexToBytes(hex);
        var r: std.Io.Reader = .fixed(&bytes);
        const spec = try RangeSpec.decode(alloc, &r);
        defer spec.deinit(alloc);
        var buf: [32]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try spec.encode(&w);
        try std.testing.expectEqualSlices(u8, &bytes, w.buffer[0..w.end]);
    }
}

test "ChunkRangesSeq decode round-trip" {
    const alloc = std.testing.allocator;
    const cases = [_][]const u8{ "00", "01000100", "0300020102010207060100", "020301070100" };
    inline for (cases) |hex| {
        const bytes = hexToBytes(hex);
        var r: std.Io.Reader = .fixed(&bytes);
        const seq = try ChunkRangesSeq.decode(alloc, &r);
        defer seq.deinit(alloc);
        var buf: [64]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try seq.encode(&w);
        try std.testing.expectEqualSlices(u8, &bytes, w.buffer[0..w.end]);
    }
}

test "ChunkRangesSeq decode cleans up partial entries and rejects offset overflow" {
    const truncated = [_]u8{ 2, 0, 1, 0, 1 };
    var truncated_reader: std.Io.Reader = .fixed(&truncated);
    try std.testing.expectError(
        error.EndOfStream,
        ChunkRangesSeq.decode(std.testing.allocator, &truncated_reader),
    );

    var encoded: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&encoded);
    try postcard.writeSliceHeader(&w, 2);
    try postcard.writeU64(&w, std.math.maxInt(u64));
    try RangeSpec.empty.encode(&w);
    try postcard.writeU64(&w, 1);
    try RangeSpec.empty.encode(&w);
    var overflow_reader: std.Io.Reader = .fixed(w.buffer[0..w.end]);
    try std.testing.expectError(
        error.InvalidChunkRangesSeq,
        ChunkRangesSeq.decode(std.testing.allocator, &overflow_reader),
    );
}

test "single blob ranges" {
    try expectWireSeq("020001000100", ChunkRangesSeq.singleBlob());
    try std.testing.expect(ChunkRangesSeq.singleBlob().isBlob());
}

test "toChunkRanges matches Rust toggle-after-record semantics" {
    const alloc = std.testing.allocator;
    // all = [0] → open selected from 0
    {
        const ranges = try RangeSpec.all().toChunkRanges(alloc);
        defer alloc.free(ranges);
        try std.testing.expectEqual(@as(usize, 1), ranges.len);
        try std.testing.expectEqual(@as(u64, 0), ranges[0].start);
        try std.testing.expect(ranges[0].end == null);
    }
    // [2,3] → deselected 0..2, selected 2..5
    {
        const spec = RangeSpec{ .widths = &[_]u64{ 2, 3 } };
        const ranges = try spec.toChunkRanges(alloc);
        defer alloc.free(ranges);
        try std.testing.expectEqual(@as(usize, 1), ranges.len);
        try std.testing.expectEqual(@as(u64, 2), ranges[0].start);
        try std.testing.expectEqual(@as(?u64, 5), ranges[0].end);
    }
    // round-trip
    {
        const original = [_]RangeSpec.ChunkRange{ .{ .start = 2, .end = 5 }, .{ .start = 10, .end = 12 } };
        const spec = try RangeSpec.fromChunkRanges(alloc, &original);
        defer spec.deinit(alloc);
        const back = try spec.toChunkRanges(alloc);
        defer alloc.free(back);
        try std.testing.expectEqual(@as(usize, 2), back.len);
        try std.testing.expectEqual(@as(u64, 2), back[0].start);
        try std.testing.expectEqual(@as(?u64, 5), back[0].end);
        try std.testing.expectEqual(@as(u64, 10), back[1].start);
        try std.testing.expectEqual(@as(?u64, 12), back[1].end);
    }
}

test "toChunkRanges rejects width overflow" {
    const spec = RangeSpec{ .widths = &.{ std.math.maxInt(u64), 1 } };
    try std.testing.expectError(error.InvalidRangeSpec, spec.toChunkRanges(std.testing.allocator));
}

test "toChunkRanges preserves set semantics for zero widths" {
    const alloc = std.testing.allocator;
    inline for ([_][]const u64{ &.{ 0, 0 }, &.{ 1, 0 } }) |widths| {
        const empty_ranges = try (RangeSpec{ .widths = widths }).toChunkRanges(alloc);
        defer alloc.free(empty_ranges);
        try std.testing.expectEqual(@as(usize, 0), empty_ranges.len);
    }

    const adjacent = try (RangeSpec{ .widths = &.{ 0, 1, 0, 1 } }).toChunkRanges(alloc);
    defer alloc.free(adjacent);
    try std.testing.expectEqual(@as(usize, 1), adjacent.len);
    try std.testing.expectEqual(@as(u64, 0), adjacent[0].start);
    try std.testing.expectEqual(@as(?u64, 2), adjacent[0].end);

    const reopened = try (RangeSpec{ .widths = &.{ 0, 1, 0 } }).toChunkRanges(alloc);
    defer alloc.free(reopened);
    try std.testing.expectEqual(@as(usize, 1), reopened.len);
    try std.testing.expectEqual(@as(u64, 0), reopened[0].start);
    try std.testing.expect(reopened[0].end == null);
}

test "fromChunkRanges drops zero-length selections" {
    const spec = try RangeSpec.fromChunkRanges(std.testing.allocator, &.{
        .{ .start = 1, .end = 1 },
        .{ .start = 2, .end = 2 },
    });
    try std.testing.expectEqual(@as(usize, 0), spec.widths.len);
}
