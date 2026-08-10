//! Partial BAO entries: verified-range ingestion, chunk bitfields,
//! partial-to-complete transition, and export/import of partial state.
//!
//! A partial entry holds the root hash, the blob size, the BAO outboard,
//! a presence bitfield over the 1 KiB chunks, and a sparse data buffer.
//! Inserted ranges are verified against the root hash before they are
//! placed (bao.decodeVerifiedRanges); when every chunk is present the entry
//! transitions to a complete blob after a final full-content hash check.
//!
//! Trust boundary for import: imported state is structurally validated and
//! its outboard is bound to the root hash (the root parent pair must
//! recombine to the root); a fully-present import is additionally
//! full-hash-checked at import. Imported chunk bytes that are not yet
//! complete are held as unverified sparse data — they can NEVER become a
//! corrupt complete blob, because the partial-to-complete transition
//! re-checks the full content hash, and every later range insertion is
//! wire-verified against the root. A forged import is therefore at worst
//! garbage that fails completion, matching the store's read-time integrity
//! model (fs_store getBytes/openReader verify content against the hash).

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const bao = @import("bao.zig");
const hazmat = @import("blake3_hazmat.zig");
const types = @import("types.zig");

pub const CHUNK_LEN: usize = bao.CHUNK_LEN;
pub const Error = types.Error;

const export_magic = "ZBPS1";

pub const Bitfield = struct {
    words: []u64,
    chunk_count: u64,

    pub fn init(allocator: std.mem.Allocator, chunk_count: u64) Error!Bitfield {
        const word_count = (chunk_count + 63) / 64;
        const n: usize = @intCast(word_count);
        const words = allocator.alloc(u64, n) catch return error.OutOfMemory;
        @memset(words, 0);
        return .{ .words = words, .chunk_count = chunk_count };
    }

    pub fn deinit(self: *Bitfield, allocator: std.mem.Allocator) void {
        allocator.free(self.words);
        self.* = undefined;
    }

    pub fn set(self: *Bitfield, chunk: u64) void {
        if (chunk >= self.chunk_count) return;
        const word: usize = @intCast(chunk / 64);
        self.words[word] |= @as(u64, 1) << @intCast(chunk % 64);
    }

    pub fn isSet(self: *const Bitfield, chunk: u64) bool {
        if (chunk >= self.chunk_count) return false;
        const word: usize = @intCast(chunk / 64);
        return (self.words[word] & (@as(u64, 1) << @intCast(chunk % 64))) != 0;
    }

    pub fn allSet(self: *const Bitfield) bool {
        // Only real chunk bits count — padding bits beyond chunk_count must
        // never forge completion (a forged import can set padding and clear a
        // real chunk while keeping a whole-word popcount equal to chunk_count).
        var chunk: u64 = 0;
        while (chunk < self.chunk_count) : (chunk += 1) {
            if (!self.isSet(chunk)) return false;
        }
        return true;
    }

    pub fn countSet(self: *const Bitfield) u64 {
        var count: u64 = 0;
        var chunk: u64 = 0;
        while (chunk < self.chunk_count) : (chunk += 1) {
            if (self.isSet(chunk)) count += 1;
        }
        return count;
    }

    /// True when any bit past `chunk_count` is set in the word backing store.
    fn hasPaddingBits(self: *const Bitfield) bool {
        if (self.chunk_count == 0) {
            for (self.words) |word| if (word != 0) return true;
            return false;
        }
        const last_chunk = self.chunk_count - 1;
        const last_word: usize = @intCast(last_chunk / 64);
        const used_in_last: u32 = @intCast((last_chunk % 64) + 1); // 1..=64
        // Mask of valid bits in the final word; anything above is padding.
        // When used_in_last == 64 the whole word is real chunks (no padding).
        if (used_in_last < 64) {
            const valid_mask: u64 = (@as(u64, 1) << @intCast(used_in_last)) - 1;
            if ((self.words[last_word] & ~valid_mask) != 0) return true;
        }
        var w: usize = last_word + 1;
        while (w < self.words.len) : (w += 1) {
            if (self.words[w] != 0) return true;
        }
        return false;
    }

    /// Serialize little-endian words (persistence + export).
    pub fn toBytes(self: *const Bitfield, allocator: std.mem.Allocator) Error![]u8 {
        const out = allocator.alloc(u8, self.words.len * 8) catch return error.OutOfMemory;
        for (self.words, 0..) |word, i| {
            std.mem.writeInt(u64, out[i * 8 ..][0..8], word, .little);
        }
        return out;
    }

    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8, chunk_count: u64) Error!Bitfield {
        const word_count = (chunk_count + 63) / 64;
        if (bytes.len != word_count * 8) return error.InvalidState;
        var self = try init(allocator, chunk_count);
        errdefer self.deinit(allocator);
        for (self.words, 0..) |_, i| {
            self.words[i] = std.mem.readInt(u64, bytes[i * 8 ..][0..8], .little);
        }
        // Reject ANY padding bit: they are never produced by `set`, and a
        // popcount-only check misses the forge where padding is set and a real
        // chunk bit is clear while countSet still equals chunk_count.
        if (self.hasPaddingBits()) return error.InvalidState;
        return self;
    }

    /// Boundaries of the present ranges, as [start, end) chunk pairs.
    pub fn presentBoundaries(self: *const Bitfield, allocator: std.mem.Allocator) Error![]u64 {
        return self.rangeBoundaries(allocator, true);
    }

    /// Boundaries of the missing ranges, as [start, end) chunk pairs.
    pub fn missingBoundaries(self: *const Bitfield, allocator: std.mem.Allocator) Error![]u64 {
        return self.rangeBoundaries(allocator, false);
    }

    fn rangeBoundaries(self: *const Bitfield, allocator: std.mem.Allocator, want_set: bool) Error![]u64 {
        var out: std.ArrayList(u64) = .empty;
        errdefer out.deinit(allocator);
        var i: u64 = 0;
        while (i < self.chunk_count) {
            if (self.isSet(i) == want_set) {
                const start = i;
                while (i < self.chunk_count and self.isSet(i) == want_set) i += 1;
                out.append(allocator, start) catch return error.OutOfMemory;
                out.append(allocator, i) catch return error.OutOfMemory;
            } else {
                i += 1;
            }
        }
        return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
    }
};

pub const PartialEntry = struct {
    allocator: std.mem.Allocator,
    hash: Hash,
    size: u64,
    outboard: []u8,
    data: []u8,
    bitfield: Bitfield,

    /// Create an empty partial entry. `outboard` is copied; the caller
    /// keeps ownership of the passed slice.
    pub fn create(allocator: std.mem.Allocator, hash: Hash, size: u64, outboard: []const u8) Error!PartialEntry {
        if (size == 0) return error.InvalidState; // empty blobs are complete by construction
        // Same product ceiling as bao decode / FsStore.loadPartials (64 MiB).
        if (size > bao.MAX_DECODED_BLOB_BYTES) return error.BlobTooLarge;
        const outboard_owned = allocator.dupe(u8, outboard) catch return error.OutOfMemory;
        errdefer allocator.free(outboard_owned);
        const size_usize = std.math.cast(usize, size) orelse return error.InvalidState;
        const data = allocator.alloc(u8, size_usize) catch return error.OutOfMemory;
        errdefer allocator.free(data);
        @memset(data, 0);
        var bitfield = try Bitfield.init(allocator, chunkCount(size));
        errdefer bitfield.deinit(allocator);
        return .{
            .allocator = allocator,
            .hash = hash,
            .size = size,
            .outboard = outboard_owned,
            .data = data,
            .bitfield = bitfield,
        };
    }

    pub fn deinit(self: *PartialEntry) void {
        self.bitfield.deinit(self.allocator);
        self.allocator.free(self.data);
        self.allocator.free(self.outboard);
        self.* = undefined;
    }

    pub fn chunkCount(size: u64) u64 {
        return size / CHUNK_LEN + @as(u64, if (size % CHUNK_LEN != 0) 1 else 0);
    }

    pub fn isComplete(self: *const PartialEntry) bool {
        return self.bitfield.allSet();
    }

    /// Bytes present so far (for BlobStatus.partial reporting).
    pub fn presentBytes(self: *const PartialEntry) u64 {
        const full_chunks = self.bitfield.countSet();
        const last = chunkCount(self.size) - 1;
        var bytes = full_chunks * CHUNK_LEN;
        if (self.bitfield.isSet(last)) {
            const last_len = self.size - last * CHUNK_LEN;
            bytes -= CHUNK_LEN - last_len;
        }
        return bytes;
    }

    /// Verify an encoded range (wire bytes as produced by bao.encodeRanges /
    /// encodeRangesFromOutboard) against the root hash, then place its leaf
    /// chunks into the sparse buffer and mark them present.
    pub fn insertEncoded(self: *PartialEntry, encoded: []const u8, ranges: bao.ChunkRanges) Error!void {
        const decoded = blk: {
            var r: std.Io.Reader = .fixed(encoded);
            break :blk bao.decodeVerifiedRanges(self.allocator, self.hash, self.size, &r, ranges) catch
                return error.HashMismatch;
        };
        defer self.allocator.free(decoded);
        try self.placeDecoded(decoded, ranges);
    }

    /// Place already-verified chunk bytes (e.g. from a trusted local source)
    /// and mark the chunks present. The caller asserts verification.
    pub fn placeDecoded(self: *PartialEntry, decoded: []const u8, ranges: bao.ChunkRanges) Error!void {
        var off: usize = 0;
        var i: usize = 0;
        if (ranges.boundaries.len % 2 != 0) return error.InvalidState;
        while (i + 1 < ranges.boundaries.len) : (i += 2) {
            const start = ranges.boundaries[i];
            const end = @min(ranges.boundaries[i + 1], chunkCount(self.size));
            var chunk = start;
            while (chunk < end) : (chunk += 1) {
                const chunk_start = chunk * CHUNK_LEN;
                const len: usize = @intCast(@min(CHUNK_LEN, self.size - chunk_start));
                if (off + len > decoded.len) return error.InvalidState;
                @memcpy(self.data[chunk_start..][0..len], decoded[off..][0..len]);
                self.bitfield.set(chunk);
                off += len;
            }
        }
    }

    /// Transition to complete: requires every chunk present, then re-checks
    /// the full content against the root hash. Returns an owned copy of the
    /// complete blob bytes.
    pub fn finish(self: *const PartialEntry, allocator: std.mem.Allocator) Error![]u8 {
        if (!self.isComplete()) return error.Incomplete;
        if (!Hash.of(self.data).eql(self.hash)) return error.HashMismatch;
        return allocator.dupe(u8, self.data) catch return error.OutOfMemory;
    }

    /// Serialize this partial state for transfer/resume:
    /// magic | hash | size | outboard | chunk_count | bitfield | present data.
    pub fn exportState(self: *const PartialEntry, allocator: std.mem.Allocator) Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        out.appendSlice(allocator, export_magic) catch return error.OutOfMemory;
        out.appendSlice(allocator, &self.hash.bytes) catch return error.OutOfMemory;
        var num: [8]u8 = undefined;
        std.mem.writeInt(u64, &num, self.size, .little);
        out.appendSlice(allocator, &num) catch return error.OutOfMemory;
        std.mem.writeInt(u64, &num, self.outboard.len, .little);
        out.appendSlice(allocator, &num) catch return error.OutOfMemory;
        out.appendSlice(allocator, self.outboard) catch return error.OutOfMemory;
        std.mem.writeInt(u64, &num, self.bitfield.chunk_count, .little);
        out.appendSlice(allocator, &num) catch return error.OutOfMemory;
        const bits = try self.bitfield.toBytes(allocator);
        defer allocator.free(bits);
        out.appendSlice(allocator, bits) catch return error.OutOfMemory;
        // Present chunk data, in chunk order (reconstructed via the bitfield).
        var chunk: u64 = 0;
        while (chunk < self.bitfield.chunk_count) : (chunk += 1) {
            if (!self.bitfield.isSet(chunk)) continue;
            const chunk_start = chunk * CHUNK_LEN;
            const len: usize = @intCast(@min(CHUNK_LEN, self.size - chunk_start));
            out.appendSlice(allocator, self.data[chunk_start..][0..len]) catch return error.OutOfMemory;
        }
        return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
    }

    /// Parse + verify exported partial state. The outboard is bound to the
    /// root hash (its root parent pair must recombine to the root), a
    /// fully-present entry is full-hash-checked here, and any remaining
    /// present bytes are held as unverified sparse data that completion
    /// will re-check (see the module-level trust-boundary note).
    pub fn importState(allocator: std.mem.Allocator, bytes: []const u8) Error!PartialEntry {
        var off: usize = 0;
        if (bytes.len < export_magic.len + 32 + 8 + 8 + 8) return error.InvalidState;
        if (!std.mem.eql(u8, bytes[0..export_magic.len], export_magic)) return error.InvalidState;
        off = export_magic.len;

        var hash_bytes: [32]u8 = undefined;
        @memcpy(&hash_bytes, bytes[off .. off + 32]);
        off += 32;
        const size = std.mem.readInt(u64, bytes[off..][0..8], .little);
        off += 8;
        if (size == 0) return error.InvalidState;
        // Reject before bitfield/data/outboard allocs (F28). Aligns with
        // bao.MAX_DECODED_BLOB_BYTES and FsStore.loadPartials' 64 MiB ceiling.
        if (size > bao.MAX_DECODED_BLOB_BYTES) return error.BlobTooLarge;
        const outboard_len = std.math.cast(usize, std.mem.readInt(u64, bytes[off..][0..8], .little)) orelse
            return error.InvalidState;
        off += 8;
        if (off + outboard_len + 8 > bytes.len) return error.InvalidState;
        const outboard = bytes[off .. off + outboard_len];
        off += outboard_len;
        const chunk_count = std.mem.readInt(u64, bytes[off..][0..8], .little);
        off += 8;
        if (chunk_count != chunkCount(size)) return error.InvalidState;

        // Bind the outboard to the root hash: it must hold exactly one pair
        // per internal block-tree node, and the postorder-final (root) pair
        // must recombine to the root hash.
        const blocks = bao.blockCount(size);
        if (outboard.len != (blocks -| 1) * 64) return error.InvalidState;
        if (blocks > 1) {
            const root_pair = outboard[outboard.len - 64 ..];
            var left: [32]u8 = undefined;
            var right: [32]u8 = undefined;
            @memcpy(&left, root_pair[0..32]);
            @memcpy(&right, root_pair[32..64]);
            const recomputed = hazmat.parentCv(left, right, true);
            if (!std.mem.eql(u8, &recomputed, &hash_bytes)) return error.HashMismatch;
        }

        // Own bitfield + sparse data + outboard under one cleanup path (F22):
        // a terminal outboard-dupe OOM must free the earlier allocations.
        var bitfield = try Bitfield.fromBytes(allocator, bytes[off .. off + @as(usize, @intCast((chunk_count + 63) / 64)) * 8], chunk_count);
        errdefer bitfield.deinit(allocator);
        off += @as(usize, @intCast((chunk_count + 63) / 64)) * 8;

        // Reconstruct the sparse buffer from the present chunk data.
        const size_usize = std.math.cast(usize, size) orelse return error.InvalidState;
        const data = allocator.alloc(u8, size_usize) catch return error.OutOfMemory;
        errdefer allocator.free(data);
        @memset(data, 0);
        var chunk: u64 = 0;
        while (chunk < chunk_count) : (chunk += 1) {
            if (!bitfield.isSet(chunk)) continue;
            const chunk_start = chunk * CHUNK_LEN;
            const len: usize = @intCast(@min(CHUNK_LEN, size - chunk_start));
            if (off + len > bytes.len) return error.InvalidState;
            @memcpy(data[chunk_start..][0..len], bytes[off..][0..len]);
            off += len;
        }
        if (off != bytes.len) return error.InvalidState;

        // A fully-present import is verified NOW; a partial one is verified
        // at the partial-to-complete transition (full content hash).
        if (bitfield.allSet() and !Hash.of(data).eql(Hash.fromBytes(hash_bytes))) {
            return error.HashMismatch;
        }

        const outboard_owned = allocator.dupe(u8, outboard) catch return error.OutOfMemory;
        return .{
            .allocator = allocator,
            .hash = Hash.fromBytes(hash_bytes),
            .size = size,
            .outboard = outboard_owned,
            .data = data,
            .bitfield = bitfield,
        };
    }
};

test "bitfield set/count/ranges round-trip" {
    const alloc = std.testing.allocator;
    var bf = try Bitfield.init(alloc, 130);
    defer bf.deinit(alloc);
    try std.testing.expectEqual(@as(u64, 0), bf.countSet());
    bf.set(0);
    bf.set(1);
    bf.set(64);
    bf.set(129);
    try std.testing.expectEqual(@as(u64, 4), bf.countSet());
    try std.testing.expect(!bf.allSet());

    const present = try bf.presentBoundaries(alloc);
    defer alloc.free(present);
    try std.testing.expectEqualSlices(u64, &.{ 0, 2, 64, 65, 129, 130 }, present);

    const missing = try bf.missingBoundaries(alloc);
    defer alloc.free(missing);
    try std.testing.expectEqualSlices(u64, &.{ 2, 64, 65, 129 }, missing);

    const bytes = try bf.toBytes(alloc);
    defer alloc.free(bytes);
    var restored = try Bitfield.fromBytes(alloc, bytes, 130);
    defer restored.deinit(alloc);
    try std.testing.expectEqual(@as(u64, 4), restored.countSet());
    try std.testing.expect(restored.isSet(129));
    try std.testing.expect(!restored.isSet(128));
}

test "partial entry verifies ranges, tracks presence, and transitions" {
    const alloc = std.testing.allocator;
    const fixtures = @import("fixtures.zig");

    const n: usize = 65_537; // two 16 KiB block groups + a tail chunk
    const data = try fixtures.makeTestData(alloc, n);
    defer alloc.free(data);
    const created = try bao.createOutboard(alloc, data);
    defer alloc.free(created.outboard);

    var entry = try PartialEntry.create(alloc, created.root, n, created.outboard);
    defer entry.deinit();
    try std.testing.expectEqual(@as(u64, 65), PartialEntry.chunkCount(n));
    try std.testing.expect(!entry.isComplete());
    try std.testing.expectEqual(@as(u64, 0), entry.presentBytes());

    // Insert chunks [1,3) — verified against the root via the wire encoding.
    {
        const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 1, 3 } });
        defer alloc.free(wire);
        try entry.insertEncoded(wire, .{ .boundaries = &.{ 1, 3 } });
    }
    try std.testing.expectEqual(@as(u64, 2), entry.bitfield.countSet());
    try std.testing.expectEqual(@as(u64, 2 * CHUNK_LEN), entry.presentBytes());

    // A corrupted range is rejected and leaves no trace.
    {
        const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 5, 6 } });
        defer alloc.free(wire);
        wire[wire.len - 1] ^= 0xFF;
        try std.testing.expectError(
            error.HashMismatch,
            entry.insertEncoded(wire, .{ .boundaries = &.{ 5, 6 } }),
        );
    }
    try std.testing.expectEqual(@as(u64, 2), entry.bitfield.countSet());

    // Finish before complete is an error.
    try std.testing.expectError(error.Incomplete, entry.finish(alloc));

    // Insert everything else; the entry completes and the bytes match.
    {
        const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 0, 1, 3, 65 } });
        defer alloc.free(wire);
        try entry.insertEncoded(wire, .{ .boundaries = &.{ 0, 1, 3, 65 } });
    }
    try std.testing.expect(entry.isComplete());
    const finished = try entry.finish(alloc);
    defer alloc.free(finished);
    try std.testing.expectEqualSlices(u8, data, finished);
}

test "partial state export/import re-verifies and resumes" {
    const alloc = std.testing.allocator;
    const fixtures = @import("fixtures.zig");

    const n: usize = 65_537;
    const data = try fixtures.makeTestData(alloc, n);
    defer alloc.free(data);
    const created = try bao.createOutboard(alloc, data);
    defer alloc.free(created.outboard);

    var entry = try PartialEntry.create(alloc, created.root, n, created.outboard);
    defer entry.deinit();
    {
        const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 1, 3 } });
        defer alloc.free(wire);
        try entry.insertEncoded(wire, .{ .boundaries = &.{ 1, 3 } });
    }

    const state = try entry.exportState(alloc);
    defer alloc.free(state);

    var imported = try PartialEntry.importState(alloc, state);
    defer imported.deinit();
    try std.testing.expect(imported.hash.eql(created.root));
    try std.testing.expectEqual(n, imported.size);
    try std.testing.expectEqual(@as(u64, 2), imported.bitfield.countSet());
    try std.testing.expectEqualSlices(u8, entry.data, imported.data);

    // Resume: complete the imported entry from the remaining ranges.
    {
        const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 0, 1, 3, 65 } });
        defer alloc.free(wire);
        try imported.insertEncoded(wire, .{ .boundaries = &.{ 0, 1, 3, 65 } });
    }
    const finished = try imported.finish(alloc);
    defer alloc.free(finished);
    try std.testing.expectEqualSlices(u8, data, finished);

    // A forged outboard breaks the outboard-to-root binding at import.
    // (state layout: magic 5 | hash 32 | size 8 | outboard_len 8 | outboard…)
    var forged_outboard = try alloc.dupe(u8, state);
    defer alloc.free(forged_outboard);
    forged_outboard[5 + 32 + 8 + 8 + 255] ^= 0xFF; // last byte of the root pair
    try std.testing.expectError(error.HashMismatch, PartialEntry.importState(alloc, forged_outboard));

    // Forged present-data in a PARTIAL import cannot poison completion: the
    // entry imports (structurally valid) but the transition rejects it.
    var forged_data = try alloc.dupe(u8, state);
    defer alloc.free(forged_data);
    forged_data[forged_data.len - 1] ^= 0xFF; // last present chunk byte
    var poisoned = try PartialEntry.importState(alloc, forged_data);
    defer poisoned.deinit();
    {
        // Fill everything EXCEPT the forged chunks (already marked present);
        // the inserts never overwrite them, so completion must fail.
        const wire_a = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 0, 1 } });
        defer alloc.free(wire_a);
        try poisoned.insertEncoded(wire_a, .{ .boundaries = &.{ 0, 1 } });
        const wire_b = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 3, 65 } });
        defer alloc.free(wire_b);
        try poisoned.insertEncoded(wire_b, .{ .boundaries = &.{ 3, 65 } });
    }
    try std.testing.expect(poisoned.isComplete());
    try std.testing.expectError(error.HashMismatch, poisoned.finish(alloc));
}

test "F01 bitfield padding bits cannot forge allSet or fromBytes" {
    const alloc = std.testing.allocator;
    // 65 chunks → 2 words; bits 65..127 in word 1 are padding.
    var bf = try Bitfield.init(alloc, 65);
    defer bf.deinit(alloc);

    // Set every real chunk bit.
    var c: u64 = 0;
    while (c < 65) : (c += 1) bf.set(c);
    try std.testing.expect(bf.allSet());
    try std.testing.expectEqual(@as(u64, 65), bf.countSet());

    // Forge: clear one real chunk bit and set a padding bit so a whole-word
    // popcount would still equal chunk_count.
    bf.words[0] &= ~@as(u64, 1); // clear chunk 0
    bf.words[1] |= @as(u64, 1) << 1; // set padding bit 65 (chunk index 65)
    try std.testing.expect(!bf.isSet(0));
    try std.testing.expect(!bf.allSet());
    try std.testing.expectEqual(@as(u64, 64), bf.countSet());

    const forged_bytes = try bf.toBytes(alloc);
    defer alloc.free(forged_bytes);
    try std.testing.expectError(error.InvalidState, Bitfield.fromBytes(alloc, forged_bytes, 65));

    // finish() full-content re-hash remains the second integrity backstop:
    // even a fully-present bitfield still re-hashes data before publishing.
    const data = try @import("fixtures.zig").makeTestData(alloc, 65 * CHUNK_LEN);
    defer alloc.free(data);
    const created = try bao.createOutboard(alloc, data);
    defer alloc.free(created.outboard);
    var entry = try PartialEntry.create(alloc, created.root, data.len, created.outboard);
    defer entry.deinit();
    // Mark complete via legitimate inserts, then confirm finish re-hash path.
    {
        const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 0, 65 } });
        defer alloc.free(wire);
        try entry.insertEncoded(wire, .{ .boundaries = &.{ 0, 65 } });
    }
    try std.testing.expect(entry.isComplete());
    const finished = try entry.finish(alloc);
    defer alloc.free(finished);
    try std.testing.expectEqualSlices(u8, data, finished);
}

test "F22 importState OOM on final outboard dupe frees data and bitfield" {
    const alloc = std.testing.allocator;
    const fixtures = @import("fixtures.zig");
    const FailingAllocator = std.testing.FailingAllocator;

    // Large enough that data + bitfield are real heap allocs (not empty).
    const n: usize = 65_537;
    const data = try fixtures.makeTestData(alloc, n);
    defer alloc.free(data);
    const created = try bao.createOutboard(alloc, data);
    defer alloc.free(created.outboard);

    var seed = try PartialEntry.create(alloc, created.root, n, created.outboard);
    defer seed.deinit();
    {
        const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 1, 3 } });
        defer alloc.free(wire);
        try seed.insertEncoded(wire, .{ .boundaries = &.{ 1, 3 } });
    }
    const state = try seed.exportState(alloc);
    defer alloc.free(state);

    // Count allocations on the successful import path; the final alloc is the
    // outboard dupe (after bitfield words + sparse data).
    var counter = FailingAllocator.init(alloc, .{});
    var probe = try PartialEntry.importState(counter.allocator(), state);
    const k = counter.alloc_index;
    probe.deinit();
    try std.testing.expect(k >= 3); // bitfield + data + outboard

    // Fail exactly the final dupe. testing.allocator leak detection is the
    // F22 gate: data + bitfield must not survive the OOM return.
    var fail_state = FailingAllocator.init(alloc, .{ .fail_index = k - 1 });
    try std.testing.expectError(
        error.OutOfMemory,
        PartialEntry.importState(fail_state.allocator(), state),
    );
    try std.testing.expect(fail_state.has_induced_failure);
    try std.testing.expectEqual(k - 1, fail_state.alloc_index);
}

test "F28 importState and create reject size above MAX_DECODED_BLOB_BYTES before alloc" {
    const alloc = std.testing.allocator;
    const FailingAllocator = std.testing.FailingAllocator;

    // Craft a minimal header with an oversized size. Rejection must happen
    // before bitfield/data allocation (no multi-GB alloc attempt).
    var header: [5 + 32 + 8 + 8 + 8]u8 = undefined;
    @memcpy(header[0..5], "ZBPS1");
    @memset(header[5 .. 5 + 32], 0xab);
    std.mem.writeInt(u64, header[5 + 32 ..][0..8], bao.MAX_DECODED_BLOB_BYTES + 1, .little);
    std.mem.writeInt(u64, header[5 + 32 + 8 ..][0..8], 0, .little); // outboard_len
    std.mem.writeInt(u64, header[5 + 32 + 8 + 8 ..][0..8], 0, .little); // chunk_count

    var counter = FailingAllocator.init(alloc, .{});
    try std.testing.expectError(
        error.BlobTooLarge,
        PartialEntry.importState(counter.allocator(), &header),
    );
    try std.testing.expectEqual(@as(usize, 0), counter.allocated_bytes);

    try std.testing.expectError(
        error.BlobTooLarge,
        PartialEntry.create(alloc, Hash.fromBytes([_]u8{0} ** 32), bao.MAX_DECODED_BLOB_BYTES + 1, &.{}),
    );
}
