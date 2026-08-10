//! n0-flavored bao verified streaming (16 KiB chunk groups, 1024-byte chunks).

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const hazmat = @import("blake3_hazmat.zig");
const fixtures = @import("fixtures.zig");

pub const CHUNK_LEN: usize = 1024;
pub const IROH_BLOCK_CHUNK_LOG: u8 = 4;
pub const MAX_DECODED_BLOB_BYTES: u64 = 64 * 1024 * 1024;

const MAX_BAO_STACK_DEPTH: usize = 64;

pub const Error = error{
    EndOfStream,
    ParentHashMismatch,
    LeafHashMismatch,
    RootHashMismatch,
    BlobTooLarge,
    BaoStackOverflow,
    OutOfMemory,
    ReadFailed,
    WriteFailed,
};

pub const ChunkRanges = struct {
    boundaries: []const u64,

    pub fn all() ChunkRanges {
        return .{ .boundaries = &.{0} };
    }

    pub fn empty() ChunkRanges {
        return .{ .boundaries = &.{} };
    }

    pub fn is_all(self: ChunkRanges) bool {
        return self.boundaries.len == 1 and self.boundaries[0] == 0;
    }

    pub fn is_empty(self: ChunkRanges) bool {
        return self.boundaries.len == 0;
    }

    fn split(self: ChunkRanges, allocator: std.mem.Allocator, mid: u64) Error!struct { OwnedChunkRanges, OwnedChunkRanges } {
        if (self.is_all() and mid > 0) {
            return .{
                .{ .ranges = ChunkRanges.all(), .storage = null },
                .{ .ranges = ChunkRanges.all(), .storage = null },
            };
        }
        var left_count: usize = 0;
        var right_count: usize = 0;
        for (self.boundaries) |b| {
            if (b < mid) {
                left_count += 1;
            } else {
                right_count += 1;
            }
        }
        const left_storage = try allocator.alloc(u64, left_count);
        errdefer allocator.free(left_storage);
        const right_storage = try allocator.alloc(u64, right_count);
        errdefer allocator.free(right_storage);

        var li: usize = 0;
        var ri: usize = 0;
        for (self.boundaries) |b| {
            if (b < mid) {
                left_storage[li] = b;
                li += 1;
            } else {
                right_storage[ri] = b;
                ri += 1;
            }
        }

        var left: OwnedChunkRanges = .{
            .ranges = .{ .boundaries = left_storage[0..li] },
            .storage = left_storage,
        };
        var right: OwnedChunkRanges = .{
            .ranges = .{ .boundaries = right_storage[0..ri] },
            .storage = right_storage,
        };
        if (left.ranges.boundaries.len == 1 and left.ranges.boundaries[0] == 0) {
            left.ranges = ChunkRanges.all();
            allocator.free(left.storage.?);
            left.storage = null;
        }
        if (right.ranges.boundaries.len == 1 and right.ranges.boundaries[0] <= mid) {
            right.ranges = ChunkRanges.all();
            allocator.free(right.storage.?);
            right.storage = null;
        }
        return .{ left, right };
    }
};

/// A `ChunkRanges` value that may own its boundary storage. Used by the range
/// iterator so that partitioned ranges remain valid after the iterator moves
/// on to the next stack frame.
const OwnedChunkRanges = struct {
    ranges: ChunkRanges,
    storage: ?[]u64,

    fn deinit(self: OwnedChunkRanges, allocator: std.mem.Allocator) void {
        if (self.storage) |storage| allocator.free(storage);
    }
};

const CanonicalRanges = struct {
    ranges: ChunkRanges,
    storage: ?[]u64 = null,

    fn deinit(self: *CanonicalRanges, allocator: std.mem.Allocator) void {
        if (self.storage) |storage| allocator.free(storage);
        self.* = undefined;
    }
};

/// Match bao-tree's size-aware range truncation. A selection wholly beyond the
/// tree means "the last chunk", which is how iroh requests a size proof.
fn canonicalizeRanges(allocator: std.mem.Allocator, ranges: ChunkRanges, size: u64) Error!CanonicalRanges {
    const boundaries = ranges.boundaries;
    if (boundaries.len == 0) return .{ .ranges = ranges };

    const last_chunk = chunkCountForSize(size) -| 1;
    var low: usize = 0;
    var high: usize = boundaries.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        if (boundaries[mid] < last_chunk) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    const insertion = low;
    const found = insertion < boundaries.len and boundaries[insertion] == last_chunk;
    const truncated_len = if (found) blk: {
        if (insertion % 2 == 0) break :blk insertion + 1;
        break :blk if (boundaries.len == insertion + 1) insertion + 1 else insertion;
    } else if (insertion % 2 == 0)
        (if (boundaries.len == insertion) insertion else insertion + 1)
    else
        insertion;

    const truncated = boundaries[0..truncated_len];
    if (truncated.len == 0 or truncated.len % 2 == 0 or truncated[truncated.len - 1] <= last_chunk) {
        return .{ .ranges = .{ .boundaries = truncated } };
    }

    const storage = try allocator.dupe(u64, truncated);
    storage[storage.len - 1] = last_chunk;
    return .{ .ranges = .{ .boundaries = storage }, .storage = storage };
}

const ChunkNum = struct {
    v: u64,

    fn bytes(self: ChunkNum) u64 {
        return self.v * CHUNK_LEN;
    }
};

const TreeNode = struct {
    v: u64,
};

// trailing_ones for TreeNode encoding
fn trailingOnes(x: u64) u32 {
    if (x == 0) return 0;
    return @intCast(@ctz(~x));
}

fn treeNodeLevel(node: TreeNode) u32 {
    return trailingOnes(node.v);
}

fn treeNodeIsLeaf(node: TreeNode) bool {
    return (node.v & 1) == 0;
}

fn treeNodeHalfSpan(node: TreeNode) u64 {
    return @as(u64, 1) << treeNodeLevel(node);
}

fn treeNodeMid(node: TreeNode) ChunkNum {
    return .{ .v = node.v + 1 };
}

fn treeNodeSubtractBlockSize(node: TreeNode, n: u8) TreeNode {
    const shifted = ~((~node.v) << @as(u6, @intCast(n)));
    return .{ .v = shifted };
}

fn treeNodeAddBlockSize(node: TreeNode, n: u8) ?TreeNode {
    const mask = (@as(u64, 1) << @as(u6, @intCast(n))) - 1;
    if ((node.v & mask) != mask) return null;
    return .{ .v = node.v >> @as(u6, @intCast(n)) };
}

fn treeNodeCountBelow(node: TreeNode) u64 {
    const x = node.v + 1;
    const lowest_bit = x & (~x + 1);
    return lowest_bit * 2 - 2;
}

fn treeNodeNextLeftAncestor0(node: TreeNode) ?u64 {
    const x = node.v + 1;
    const without_lowest = x & (x - 1);
    if (without_lowest == 0) return null;
    return without_lowest - 1;
}

fn treeNodePostOrderOffset(node: TreeNode) u64 {
    const below_me = treeNodeCountBelow(node);
    const next_left = treeNodeNextLeftAncestor0(node);
    if (next_left) |nla| {
        return below_me + nla + 1 - @popCount(nla + 1);
    }
    return below_me;
}

fn treeNodeRightCount(node: TreeNode) u32 {
    return @popCount(node.v + 1) - 1;
}

fn treeNodeLeftChild(node: TreeNode) ?TreeNode {
    const lvl = treeNodeLevel(node);
    if (lvl == 0) return null;
    const offset = @as(u64, 1) << @as(u6, @intCast(lvl - 1));
    return .{ .v = node.v - offset };
}

fn treeNodeRightChild(node: TreeNode) ?TreeNode {
    const lvl = treeNodeLevel(node);
    if (lvl == 0) return null;
    const offset = @as(u64, 1) << @as(u6, @intCast(lvl - 1));
    return .{ .v = node.v + offset };
}

fn treeNodeRightDescendant(node: TreeNode, len: TreeNode) ?TreeNode {
    var n = treeNodeRightChild(node) orelse return null;
    while (n.v >= len.v) {
        n = treeNodeLeftChild(n) orelse return null;
    }
    return n;
}

fn treeNodeRestrictedParent(node: TreeNode, len: TreeNode) ?TreeNode {
    var curr = node;
    while (treeNodeParent(curr)) |parent| {
        if (parent.v < len.v) return parent;
        curr = parent;
    }
    return null;
}

fn treeNodeParent(node: TreeNode) ?TreeNode {
    const lvl = treeNodeLevel(node);
    if (lvl == 63) return null;
    const span = @as(u64, 1) << @as(u6, @intCast(lvl));
    const offset = node.v;
    if ((offset & (span * 2)) == 0) {
        return .{ .v = offset + span };
    }
    return .{ .v = offset - span };
}

fn treeNodeChunkRange(node: TreeNode) struct { start: u64, end: u64 } {
    const lvl = treeNodeLevel(node);
    const span = @as(u64, 1) << @as(u6, @intCast(lvl));
    const mid = node.v + 1;
    return .{ .start = mid - span, .end = mid + span };
}

const BaoTree = struct {
    size: u64,
    block_size_log: u8,

    fn shifted(self: BaoTree) struct { root: TreeNode, filled: TreeNode } {
        const shift: u6 = @intCast(10 + self.block_size_log);
        const mask = (@as(u64, 1) << shift) - 1;
        const full_blocks = self.size >> shift;
        const open_block: u64 = if ((self.size & mask) != 0) 1 else 0;
        const block_count = @max(full_blocks + open_block, 1);
        const n = (block_count + 1) / 2;
        const root = nextPowerOfTwo(n) - 1;
        const filled = n + if (n > 0) n - 1 else 0;
        return .{ .root = .{ .v = root }, .filled = .{ .v = filled } };
    }

    fn chunkGroupBytes(self: BaoTree) usize {
        return CHUNK_LEN << self.block_size_log;
    }

    fn outboardSize(self: BaoTree) u64 {
        return (self.blocks() - 1) * 64;
    }

    fn blocks(self: BaoTree) u64 {
        const shift: u6 = @intCast(10 + self.block_size_log);
        const mask = (@as(u64, 1) << shift) - 1;
        const full_blocks = self.size >> shift;
        const open_block: u64 = if ((self.size & mask) != 0) 1 else 0;
        return @max(full_blocks + open_block, 1);
    }

    fn leafByteRanges3(self: BaoTree, node: TreeNode) struct { u64, u64, u64 } {
        const range = treeNodeChunkRange(node);
        const start = range.start * CHUNK_LEN;
        const end = range.end * CHUNK_LEN;
        const mid = treeNodeMid(node).v * CHUNK_LEN;
        return .{ start, @min(mid, self.size), @min(end, self.size) };
    }

    fn splitRanges(_: BaoTree, allocator: std.mem.Allocator, ranges: ChunkRanges, node: TreeNode) Error!struct { OwnedChunkRanges, OwnedChunkRanges } {
        const mid = treeNodeMid(node);
        return ranges.split(allocator, mid.v);
    }

    fn postOrderOffset(self: BaoTree, node: TreeNode) ?u64 {
        const shifted_node = treeNodeAddBlockSize(node, self.block_size_log) orelse return null;
        const range = treeNodeChunkRange(node);
        const end_bytes = range.end * CHUNK_LEN;
        if (end_bytes <= self.size) {
            return treeNodePostOrderOffset(shifted_node);
        }
        const mid_bytes = treeNodeMid(node).v * CHUNK_LEN;
        if (treeNodeIsLeaf(shifted_node) and mid_bytes >= self.size) {
            return null;
        }
        const pairs = self.blocks() - 1;
        const rc = treeNodeRightCount(shifted_node);
        return pairs - (rc + 1);
    }

    fn loadOutboardPair(self: BaoTree, node: TreeNode, outboard: []const u8) Error!?struct { [32]u8, [32]u8 } {
        const offset = self.postOrderOffset(node) orelse return null;
        const start = offset * 64;
        if (start + 64 > outboard.len) return error.EndOfStream;
        var left: [32]u8 = undefined;
        var right: [32]u8 = undefined;
        @memcpy(&left, outboard[start .. start + 32]);
        @memcpy(&right, outboard[start + 32 .. start + 64]);
        return .{ left, right };
    }
};

fn nextPowerOfTwo(x: u64) u64 {
    if (x <= 1) return 1;
    return @as(u64, 1) << (@as(u6, @intCast(64 - @clz(x - 1))));
}

const BaoChunkKind = enum {
    parent,
    leaf,
};

const RangeState = enum {
    empty,
    partial,
    full,
};

fn chunkCountForSize(size: u64) u64 {
    return size / CHUNK_LEN + @as(u64, if (size % CHUNK_LEN != 0) 1 else 0);
}

fn chunkCountForLen(len: usize) u64 {
    return chunkCountForSize(@intCast(len));
}

fn selectedState(ranges: ChunkRanges, start_chunk: u64, end_chunk: u64) RangeState {
    if (start_chunk >= end_chunk) return if (ranges.is_empty()) .empty else .full;
    if (ranges.is_all()) return .full;
    if (ranges.is_empty()) return .empty;

    var covered_until = start_chunk;
    var saw_intersection = false;
    var i: usize = 0;
    while (i < ranges.boundaries.len) : (i += 2) {
        const selected_start = ranges.boundaries[i];
        const selected_end = if (i + 1 < ranges.boundaries.len) ranges.boundaries[i + 1] else std.math.maxInt(u64);
        if (selected_end <= start_chunk) continue;
        if (selected_start >= end_chunk) break;
        saw_intersection = true;
        if (selected_start > covered_until) return .partial;
        covered_until = @max(covered_until, @min(selected_end, end_chunk));
        if (covered_until >= end_chunk) return .full;
    }
    return if (saw_intersection) .partial else .empty;
}

const BaoChunk = struct {
    kind: BaoChunkKind,
    is_root: bool,
    start_chunk: u64,
    size: usize,
    node: TreeNode,
    left: bool,
    right: bool,
};

const PostOrderNodeIter = struct {
    len: TreeNode,
    curr: TreeNode,
    prev: enum { parent, left, right, done },

    fn new(root: TreeNode, len: TreeNode) PostOrderNodeIter {
        return .{ .len = len, .curr = root, .prev = .parent };
    }

    fn goUp(self: *PostOrderNodeIter, curr: TreeNode) void {
        const prev = curr;
        if (treeNodeRestrictedParent(curr, self.len)) |parent| {
            self.curr = parent;
            self.prev = if (prev.v < parent.v) .left else .right;
        } else {
            self.curr = curr;
            self.prev = .done;
        }
    }

    fn next(self: *PostOrderNodeIter) ?TreeNode {
        while (true) {
            const curr = self.curr;
            switch (self.prev) {
                .parent => {
                    if (treeNodeLeftChild(curr)) |child| {
                        self.curr = child;
                        self.prev = .parent;
                    } else {
                        self.goUp(curr);
                        return curr;
                    }
                },
                .left => {
                    self.curr = treeNodeRightDescendant(curr, self.len) orelse return null;
                    self.prev = .parent;
                },
                .right => {
                    self.goUp(curr);
                    return curr;
                },
                .done => return null,
            }
        }
    }
};

const PostOrderChunkIter = struct {
    tree: BaoTree,
    inner: PostOrderNodeIter,
    shifted_root: TreeNode,
    stack: [4]BaoChunk,
    stack_len: usize,

    fn new(tree: BaoTree) PostOrderChunkIter {
        const shifted = tree.shifted();
        return .{
            .tree = tree,
            .inner = PostOrderNodeIter.new(shifted.root, shifted.filled),
            .shifted_root = shifted.root,
            .stack = undefined,
            .stack_len = 0,
        };
    }

    fn next(self: *PostOrderChunkIter) ?BaoChunk {
        if (self.stack_len > 0) {
            self.stack_len -= 1;
            return self.stack[self.stack_len];
        }
        const shifted = self.inner.next() orelse return null;
        const is_root = shifted.v == self.shifted_root.v;
        const node = treeNodeSubtractBlockSize(shifted, self.tree.block_size_log);
        if (treeNodeIsLeaf(shifted)) {
            const ranges3 = self.tree.leafByteRanges3(node);
            const s = ranges3[0];
            const m = ranges3[1];
            const e = ranges3[2];
            const l_start = treeNodeChunkRange(node).start;
            const r_start = l_start + (@as(u64, 1) << @as(u6, @intCast(self.tree.block_size_log)));
            const is_half_leaf = m == e;
            if (!is_half_leaf) {
                self.stack[self.stack_len] = .{
                    .kind = .parent,
                    .is_root = is_root,
                    .start_chunk = 0,
                    .size = 64,
                    .node = node,
                    .left = true,
                    .right = true,
                };
                self.stack_len += 1;
                self.stack[self.stack_len] = .{
                    .kind = .leaf,
                    .is_root = false,
                    .start_chunk = r_start,
                    .size = @intCast(e - m),
                    .node = node,
                    .left = false,
                    .right = false,
                };
                self.stack_len += 1;
            }
            return .{
                .kind = .leaf,
                .is_root = is_root and is_half_leaf,
                .start_chunk = l_start,
                .size = @intCast(m - s),
                .node = node,
                .left = false,
                .right = false,
            };
        }
        self.stack[self.stack_len] = .{
            .kind = .parent,
            .is_root = is_root,
            .start_chunk = 0,
            .size = 64,
            .node = node,
            .left = true,
            .right = true,
        };
        self.stack_len += 1;
        return self.next();
    }
};

pub const OutboardResult = struct {
    root: Hash,
    outboard: []u8,
};

pub fn createOutboard(allocator: std.mem.Allocator, data: []const u8) Error!OutboardResult {
    const tree = BaoTree{ .size = data.len, .block_size_log = IROH_BLOCK_CHUNK_LOG };
    const out_len = tree.outboardSize();
    if (out_len == 0) {
        var chunk_iter = PostOrderChunkIter.new(tree);
        while (chunk_iter.next()) |chunk| {
            if (chunk.kind != .leaf) continue;
            const off = chunk.start_chunk * CHUNK_LEN;
            _ = hazmat.hashSubtree(chunk.start_chunk, data[off .. off + chunk.size], chunk.is_root);
        }
        return .{ .root = Hash.of(data), .outboard = &.{} };
    }
    const outboard = try allocator.alloc(u8, out_len);
    errdefer allocator.free(outboard);

    var hash_stack: [MAX_BAO_STACK_DEPTH][32]u8 = undefined;
    var hash_stack_len: usize = 0;
    var out_pos: usize = 0;

    var chunk_iter = PostOrderChunkIter.new(tree);
    while (chunk_iter.next()) |chunk| {
        switch (chunk.kind) {
            .parent => {
                const right = hash_stack_len - 1;
                const left = right - 1;
                const r_hash = hash_stack[right];
                const l_hash = hash_stack[left];
                @memcpy(outboard[out_pos .. out_pos + 32], &l_hash);
                @memcpy(outboard[out_pos + 32 .. out_pos + 64], &r_hash);
                out_pos += 64;
                hash_stack[left] = hazmat.parentCv(l_hash, r_hash, chunk.is_root);
                hash_stack_len = left + 1;
            },
            .leaf => {
                const off = chunk.start_chunk * CHUNK_LEN;
                if (off + chunk.size > data.len) return error.EndOfStream;
                const leaf_data = data[off .. off + chunk.size];
                if (hash_stack_len >= hash_stack.len) return error.BaoStackOverflow;
                hash_stack[hash_stack_len] = hazmat.hashSubtree(chunk.start_chunk, leaf_data, chunk.is_root);
                hash_stack_len += 1;
            },
        }
    }

    std.debug.assert(hash_stack_len == 1);
    return .{
        .root = Hash.of(data),
        .outboard = outboard,
    };
}

fn encodeSelectedRec(
    allocator: std.mem.Allocator,
    start_chunk: u64,
    data: []const u8,
    is_root: bool,
    ranges: ChunkRanges,
    min_level: u32,
    emit_data: bool,
    out: *std.ArrayList(u8),
) Error![32]u8 {
    const chunks_raw = chunkCountForLen(data.len);
    const state = selectedState(ranges, start_chunk, start_chunk + chunks_raw);
    if (data.len <= CHUNK_LEN) {
        if (emit_data and state != .empty) {
            try out.appendSlice(allocator, data);
        }
        return hazmat.hashSubtree(start_chunk, data, is_root);
    }
    const chunks = nextPowerOfTwo(chunks_raw);
    const level = @ctz(chunks) - 1;
    const mid = chunks / 2;
    const mid_bytes = mid * CHUNK_LEN;
    const mid_chunk = start_chunk + mid;
    const full = state == .full;
    const emit_parent = state != .empty and (!full or level >= min_level);
    const hash_offset = if (emit_parent) blk: {
        try out.appendSlice(allocator, &[_]u8{0xFF} ** 64);
        break :blk out.items.len - 64;
    } else null;
    const left = try encodeSelectedRec(allocator, start_chunk, data[0..mid_bytes], false, ranges, min_level, emit_data, out);
    const right = try encodeSelectedRec(allocator, mid_chunk, data[mid_bytes..], false, ranges, min_level, emit_data, out);
    if (hash_offset) |o| {
        @memcpy(out.items[o .. o + 32], &left);
        @memcpy(out.items[o + 32 .. o + 64], &right);
    }
    return hazmat.parentCv(left, right, is_root);
}

pub fn encodeRanges(allocator: std.mem.Allocator, data: []const u8, ranges: ChunkRanges) Error![]u8 {
    var canonical = try canonicalizeRanges(allocator, ranges, data.len);
    defer canonical.deinit(allocator);
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    _ = try encodeSelectedRec(allocator, 0, data, true, canonical.ranges, IROH_BLOCK_CHUNK_LOG, true, &list);
    return try list.toOwnedSlice(allocator);
}

fn decodeSelectedRec(
    reader: *std.Io.Reader,
    expected_hash: ?[32]u8,
    start_chunk: u64,
    size: usize,
    is_root: bool,
    ranges: ChunkRanges,
    min_level: u32,
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
) Error![32]u8 {
    const chunks_raw = chunkCountForLen(size);
    const state = selectedState(ranges, start_chunk, start_chunk + chunks_raw);
    if (state == .empty) return expected_hash orelse error.EndOfStream;

    if (size <= CHUNK_LEN) {
        var buf: [CHUNK_LEN]u8 = undefined;
        const n = try reader.readSliceShort(buf[0..size]);
        if (n != size) return error.EndOfStream;
        const actual = hazmat.hashSubtree(start_chunk, buf[0..n], is_root);
        if (expected_hash) |expected| {
            if (!std.mem.eql(u8, &expected, &actual)) return error.LeafHashMismatch;
        }
        try out.appendSlice(allocator, buf[0..n]);
        return actual;
    }

    const chunks = nextPowerOfTwo(chunks_raw);
    const level = @ctz(chunks) - 1;
    const mid = chunks / 2;
    const mid_bytes = mid * CHUNK_LEN;
    const mid_chunk = start_chunk + mid;
    const full = state == .full;
    const emit_parent = !full or level >= min_level;

    var left_expected: ?[32]u8 = null;
    var right_expected: ?[32]u8 = null;
    if (emit_parent) {
        var parent_buf: [64]u8 = undefined;
        const n = try reader.readSliceShort(&parent_buf);
        if (n != 64) return error.EndOfStream;
        var l_hash: [32]u8 = undefined;
        var r_hash: [32]u8 = undefined;
        @memcpy(&l_hash, parent_buf[0..32]);
        @memcpy(&r_hash, parent_buf[32..64]);
        const actual = hazmat.parentCv(l_hash, r_hash, is_root);
        if (expected_hash) |expected| {
            if (!std.mem.eql(u8, &expected, &actual)) return error.ParentHashMismatch;
        }
        left_expected = l_hash;
        right_expected = r_hash;
    }

    const left = try decodeSelectedRec(reader, left_expected, start_chunk, mid_bytes, false, ranges, min_level, out, allocator);
    const right = try decodeSelectedRec(reader, right_expected, mid_chunk, size - mid_bytes, false, ranges, min_level, out, allocator);
    const actual = hazmat.parentCv(left, right, is_root);
    if (!emit_parent) {
        if (expected_hash) |expected| {
            if (!std.mem.eql(u8, &expected, &actual)) return error.LeafHashMismatch;
        }
    }
    return actual;
}

pub fn encodeAll(allocator: std.mem.Allocator, data: []const u8, outboard: []const u8) Error![]u8 {
    const tree = BaoTree{ .size = data.len, .block_size_log = IROH_BLOCK_CHUNK_LOG };
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    var iter = ResponseIter.new(allocator, tree, ChunkRanges.all());
    defer iter.deinit();
    while (try iter.next()) |chunk| {
        switch (chunk.kind) {
            .parent => {
                const pair = try tree.loadOutboardPair(chunk.node, outboard) orelse return error.EndOfStream;
                try list.appendSlice(allocator, &pair[0]);
                try list.appendSlice(allocator, &pair[1]);
            },
            .leaf => {
                const off = chunk.start_chunk * CHUNK_LEN;
                try list.appendSlice(allocator, data[off .. off + chunk.size]);
            },
        }
    }
    return try list.toOwnedSlice(allocator);
}

const ResponseIter = struct {
    allocator: std.mem.Allocator,
    tree: BaoTree,
    min_full_level: u8,
    shifted_root: TreeNode,
    shifted_filled: TreeNode,
    stack: [MAX_BAO_STACK_DEPTH]struct { TreeNode, OwnedChunkRanges },
    stack_len: usize,
    buffer: [2]BaoChunk,
    buffer_len: usize,

    fn new(allocator: std.mem.Allocator, tree: BaoTree, ranges: ChunkRanges) ResponseIter {
        const shifted = tree.shifted();
        var self: ResponseIter = .{
            .allocator = allocator,
            .tree = tree,
            .min_full_level = IROH_BLOCK_CHUNK_LOG,
            .shifted_root = shifted.root,
            .shifted_filled = shifted.filled,
            .stack = undefined,
            .stack_len = 0,
            .buffer = undefined,
            .buffer_len = 0,
        };
        self.stack[0] = .{ shifted.root, .{ .ranges = ranges, .storage = null } };
        self.stack_len = 1;
        return self;
    }

    fn deinit(self: *ResponseIter) void {
        while (self.stack_len > 0) {
            self.stack_len -= 1;
            self.stack[self.stack_len][1].deinit(self.allocator);
        }
    }

    fn pushChild(self: *ResponseIter, node: TreeNode, owned: OwnedChunkRanges) Error!void {
        if (self.stack_len >= self.stack.len) {
            owned.deinit(self.allocator);
            return error.BaoStackOverflow;
        }
        self.stack[self.stack_len] = .{ node, owned };
        self.stack_len += 1;
    }

    fn next(self: *ResponseIter) Error!?BaoChunk {
        if (self.buffer_len > 0) {
            self.buffer_len -= 1;
            return self.buffer[self.buffer_len];
        }
        if (self.stack_len == 0) return null;
        self.stack_len -= 1;
        var owned = self.stack[self.stack_len][1];
        defer owned.deinit(self.allocator);
        const ranges = owned.ranges;
        if (ranges.is_empty()) return try self.next();

        const shifted = self.stack[self.stack_len][0];
        const node = treeNodeSubtractBlockSize(shifted, self.tree.block_size_log);
        const ranges_is_all = ranges.is_all();
        const below = treeNodeLevel(node) < self.min_full_level;
        const query_leaf = ranges_is_all and below;

        const is_root = shifted.v == self.shifted_root.v;
        const chunk_range = treeNodeChunkRange(node);
        const byte_range = struct {
            fn br(t: BaoTree, n: TreeNode) struct { u64, u64 } {
                const r = treeNodeChunkRange(n);
                return .{ r.start * CHUNK_LEN, @min(r.end * CHUNK_LEN, t.size) };
            }
        }.br(self.tree, node);
        const size: usize = @intCast(byte_range[1] - byte_range[0]);

        if (query_leaf) {
            return .{
                .kind = .leaf,
                .is_root = is_root,
                .start_chunk = chunk_range.start,
                .size = size,
                .node = node,
                .left = false,
                .right = false,
            };
        } else if (!treeNodeIsLeaf(shifted)) {
            const lr = try self.tree.splitRanges(self.allocator, ranges, node);

            var r_child: ?TreeNode = null;
            var l_child: ?TreeNode = null;
            if (!lr[1].ranges.is_empty()) {
                r_child = treeNodeRightDescendant(shifted, self.shifted_filled);
                if (r_child == null) {
                    lr[0].deinit(self.allocator);
                    lr[1].deinit(self.allocator);
                    return null;
                }
            }
            if (!lr[0].ranges.is_empty()) {
                l_child = treeNodeLeftChild(shifted);
                if (l_child == null) {
                    lr[0].deinit(self.allocator);
                    lr[1].deinit(self.allocator);
                    return null;
                }
            }
            if (r_child) |r| try self.pushChild(r, lr[1]) else lr[1].deinit(self.allocator);
            if (l_child) |l| try self.pushChild(l, lr[0]) else lr[0].deinit(self.allocator);

            return .{
                .kind = .parent,
                .is_root = is_root,
                .start_chunk = 0,
                .size = 64,
                .node = node,
                .left = !lr[0].ranges.is_empty(),
                .right = !lr[1].ranges.is_empty(),
            };
        } else {
            const mid = treeNodeMid(node).v * CHUNK_LEN;
            if (mid >= self.tree.size) {
                return .{
                    .kind = .leaf,
                    .is_root = is_root,
                    .start_chunk = chunk_range.start,
                    .size = size,
                    .node = node,
                    .left = false,
                    .right = false,
                };
            }
            const lr = try self.tree.splitRanges(self.allocator, ranges, node);
            var buf_len: usize = 0;
            if (!lr[1].ranges.is_empty()) {
                const right_size: usize = @intCast(byte_range[1] - mid);
                self.buffer[buf_len] = .{
                    .kind = .leaf,
                    .is_root = false,
                    .start_chunk = treeNodeMid(node).v,
                    .size = right_size,
                    .node = node,
                    .left = false,
                    .right = false,
                };
                buf_len += 1;
            }
            if (!lr[0].ranges.is_empty()) {
                const left_size: usize = @intCast(mid - byte_range[0]);
                self.buffer[buf_len] = .{
                    .kind = .leaf,
                    .is_root = false,
                    .start_chunk = chunk_range.start,
                    .size = left_size,
                    .node = node,
                    .left = false,
                    .right = false,
                };
                buf_len += 1;
            }
            lr[0].deinit(self.allocator);
            lr[1].deinit(self.allocator);
            self.buffer_len = buf_len;
            return .{
                .kind = .parent,
                .is_root = is_root,
                .start_chunk = 0,
                .size = 64,
                .node = node,
                .left = !lr[0].ranges.is_empty(),
                .right = !lr[1].ranges.is_empty(),
            };
        }
    }
};

/// The number of 16 KiB blocks covering `size` (at least one), matching the
/// outboard's granularity: an outboard holds `blocks - 1` parent pairs.
pub fn blockCount(size: u64) u64 {
    const full = size / (CHUNK_LEN << IROH_BLOCK_CHUNK_LOG);
    const open: u64 = if (size % (CHUNK_LEN << IROH_BLOCK_CHUNK_LOG) != 0) 1 else 0;
    return @max(full + open, 1);
}

pub fn decodeVerified(
    allocator: std.mem.Allocator,
    root_hash: Hash,
    size: u64,
    reader: *std.Io.Reader,
) Error![]u8 {
    return decodeVerifiedRanges(allocator, root_hash, size, reader, ChunkRanges.all());
}

pub fn decodeVerifiedRanges(
    allocator: std.mem.Allocator,
    root_hash: Hash,
    size: u64,
    reader: *std.Io.Reader,
    ranges: ChunkRanges,
) Error![]u8 {
    if (size > MAX_DECODED_BLOB_BYTES) return error.BlobTooLarge;
    const data_len = std.math.cast(usize, size) orelse return error.BlobTooLarge;
    var canonical = try canonicalizeRanges(allocator, ranges, size);
    defer canonical.deinit(allocator);
    var data: std.ArrayList(u8) = .empty;
    errdefer data.deinit(allocator);

    _ = try decodeSelectedRec(reader, root_hash.bytes, 0, data_len, true, canonical.ranges, IROH_BLOCK_CHUNK_LOG, &data, allocator);
    return try data.toOwnedSlice(allocator);
}

test "golden outboard and wire vectors" {
    const alloc = std.testing.allocator;
    for ([_]usize{ 0, 1024, 16384, 16385 }) |n| {
        const data = if (n == 0) "" else try fixtures.makeTestData(alloc, n);
        defer if (n > 0) alloc.free(data);

        const created = try createOutboard(alloc, data);
        defer if (created.outboard.len > 0) alloc.free(created.outboard);

        const expected_hex = switch (n) {
            0 => fixtures.golden.hash_empty,
            1024 => fixtures.golden.hash_1024,
            16384 => fixtures.golden.hash_16384,
            16385 => fixtures.golden.hash_16385,
            else => unreachable,
        };
        try std.testing.expectEqualStrings(expected_hex, &created.root.toHex());

        const expected_out_len: usize = if (n > 16384) 64 else 0;
        try std.testing.expectEqual(expected_out_len, created.outboard.len);
        if (n == 16385) {
            const expected_out = fixtures.hexToBytes(fixtures.golden.outboard_16385);
            try std.testing.expectEqualSlices(u8, &expected_out, created.outboard);
        }

        const wire = try encodeAll(alloc, data, created.outboard);
        defer alloc.free(wire);

        if (n == 16385) {
            try std.testing.expectEqual(@as(usize, 16449), wire.len);
            try std.testing.expectEqualSlices(u8, created.outboard, wire[0..64]);
            try std.testing.expectEqualSlices(u8, data, wire[64..]);
        }

        var r: std.Io.Reader = .fixed(wire);
        const decoded = try decodeVerified(alloc, created.root, n, &r);
        defer alloc.free(decoded);
        try std.testing.expectEqualSlices(u8, data, decoded);
    }
}

test "corrupt byte detected in first 16KiB" {
    const alloc = std.testing.allocator;
    const n = 16385;
    const data = try fixtures.makeTestData(alloc, n);
    defer alloc.free(data);
    const created = try createOutboard(alloc, data);
    defer alloc.free(created.outboard);
    const wire = try encodeAll(alloc, data, created.outboard);
    defer alloc.free(wire);
    wire[64 + 100] ^= 0x01;
    var r: std.Io.Reader = .fixed(wire);
    const res = decodeVerified(alloc, created.root, n, &r);
    try std.testing.expectError(error.LeafHashMismatch, res);
}

test "selected ranges encode and decode to concatenated requested chunks" {
    const alloc = std.testing.allocator;
    const data = try fixtures.makeTestData(alloc, 65_537);
    defer alloc.free(data);
    const created = try createOutboard(alloc, data);
    defer alloc.free(created.outboard);

    const ranges = ChunkRanges{ .boundaries = &[_]u64{ 1, 3, 5, 6 } };
    const wire = try encodeRanges(alloc, data, ranges);
    defer alloc.free(wire);

    var r: std.Io.Reader = .fixed(wire);
    const decoded = try decodeVerifiedRanges(alloc, created.root, data.len, &r, ranges);
    defer alloc.free(decoded);

    const first = data[1 * CHUNK_LEN .. 3 * CHUNK_LEN];
    const second = data[5 * CHUNK_LEN .. 6 * CHUNK_LEN];
    try std.testing.expectEqual(first.len + second.len, decoded.len);
    try std.testing.expectEqualSlices(u8, first, decoded[0..first.len]);
    try std.testing.expectEqualSlices(u8, second, decoded[first.len..]);
}

test "ChunkRanges.split partitions arbitrary boundary slices without stack overflow" {
    const alloc = std.testing.allocator;
    const boundaries = try alloc.alloc(u64, 6);
    defer alloc.free(boundaries);
    @memcpy(boundaries, &[_]u64{ 1, 3, 5, 7, 9, 11 });
    const ranges = ChunkRanges{ .boundaries = boundaries };
    const lr = try ranges.split(alloc, 6);
    defer lr[0].deinit(alloc);
    defer lr[1].deinit(alloc);
    try std.testing.expectEqualSlices(u64, &[_]u64{ 1, 3, 5 }, lr[0].ranges.boundaries);
    try std.testing.expectEqualSlices(u64, &[_]u64{ 7, 9, 11 }, lr[1].ranges.boundaries);
}

test "ChunkRanges.split preserves all() and empty() without allocation" {
    const alloc = std.testing.allocator;
    const all_lr = try (ChunkRanges.all()).split(alloc, 10);
    try std.testing.expect(all_lr[0].ranges.is_all());
    try std.testing.expect(all_lr[1].ranges.is_all());
    try std.testing.expect(all_lr[0].storage == null);
    try std.testing.expect(all_lr[1].storage == null);

    const empty_lr = try (ChunkRanges.empty()).split(alloc, 10);
    try std.testing.expect(empty_lr[0].ranges.is_empty());
    try std.testing.expect(empty_lr[1].ranges.is_empty());
}

test "verified-size sentinel canonicalizes to the final chunk" {
    const alloc = std.testing.allocator;
    const sentinel = ChunkRanges{ .boundaries = &.{std.math.maxInt(u64)} };
    for ([_]usize{ 1, 1024, 1025, 16384, 16385, 65_537 }) |size| {
        const data = try fixtures.makeTestData(alloc, size);
        defer alloc.free(data);
        const created = try createOutboard(alloc, data);
        defer if (created.outboard.len > 0) alloc.free(created.outboard);

        const last_chunk = chunkCountForLen(data.len) - 1;
        const explicit = ChunkRanges{ .boundaries = &.{last_chunk} };
        const sentinel_wire = try encodeRanges(alloc, data, sentinel);
        defer alloc.free(sentinel_wire);
        const explicit_wire = try encodeRanges(alloc, data, explicit);
        defer alloc.free(explicit_wire);
        try std.testing.expectEqualSlices(u8, explicit_wire, sentinel_wire);

        var r: std.Io.Reader = .fixed(sentinel_wire);
        const decoded = try decodeVerifiedRanges(alloc, created.root, data.len, &r, sentinel);
        defer alloc.free(decoded);
        const last_offset: usize = @intCast(last_chunk * CHUNK_LEN);
        try std.testing.expectEqualSlices(u8, data[last_offset..], decoded);
    }
}

test "verified-size sentinel requires Bao proof bytes" {
    const alloc = std.testing.allocator;
    const data = try fixtures.makeTestData(alloc, 16_385);
    defer alloc.free(data);
    const root = Hash.of(data);
    const sentinel = ChunkRanges{ .boundaries = &.{std.math.maxInt(u64)} };
    var empty_reader: std.Io.Reader = .fixed(&.{});
    try std.testing.expectError(
        error.EndOfStream,
        decodeVerifiedRanges(alloc, root, data.len, &empty_reader, sentinel),
    );
}

test "range beyond the tree composes with an earlier selection" {
    const alloc = std.testing.allocator;
    const data = try fixtures.makeTestData(alloc, 65_537);
    defer alloc.free(data);
    const created = try createOutboard(alloc, data);
    defer alloc.free(created.outboard);
    const ranges = ChunkRanges{ .boundaries = &.{ 0, 1, std.math.maxInt(u64) } };

    const wire = try encodeRanges(alloc, data, ranges);
    defer alloc.free(wire);
    var r: std.Io.Reader = .fixed(wire);
    const decoded = try decodeVerifiedRanges(alloc, created.root, data.len, &r, ranges);
    defer alloc.free(decoded);

    const last_chunk = chunkCountForLen(data.len) - 1;
    const last_offset: usize = @intCast(last_chunk * CHUNK_LEN);
    try std.testing.expectEqual(CHUNK_LEN + data.len - last_offset, decoded.len);
    try std.testing.expectEqualSlices(u8, data[0..CHUNK_LEN], decoded[0..CHUNK_LEN]);
    try std.testing.expectEqualSlices(u8, data[last_offset..], decoded[CHUNK_LEN..]);
}
