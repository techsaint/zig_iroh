//! Temporary ref-counted protections and batch lifetime protection.
//!
//! A temporary tag shields a hash from GC while an in-flight operation
//! (download, import, batch) holds it; releasing the last guard unshields
//! the hash. A batch extends that shield over every blob added through it
//! until the caller commits. Behaviour contract:
//! iroh-blobs/src/store/gc.rs temp-tag protection +
//! iroh-blobs/src/api/blobs.rs batch lifetime.

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const types = @import("types.zig");

pub const BlobFormat = types.BlobFormat;
pub const Error = types.Error;

/// A live temporary protection on one hash. The guard borrows the store;
/// it must not outlive it. `release` is idempotent — double-release is a
/// no-op, matching drop-once-then-forget call sites.
pub fn TempTagGuard(comptime Store: type) type {
    return struct {
        const Self = @This();
        store: *Store,
        hash: Hash,
        alive: bool,

        pub fn release(self: *Self) void {
            if (!self.alive) return;
            self.alive = false;
            self.store.releaseTempTag(self.hash);
        }

        pub fn hashOf(self: *const Self) Hash {
            return self.hash;
        }
    };
}

/// Lifetime protection for a group of blobs added together. Every hash added
/// through the batch gains a temporary tag; `commit` ends the batch's
/// protection and hands the hash list to the caller (who is then responsible
/// for any durable reference, e.g. a named tag). `deinit` without commit
/// drops the protection without handing anything back.
pub fn Batch(comptime Store: type) type {
    return struct {
        const Self = @This();
        store: *Store,
        hashes: std.ArrayList(Hash) = .empty,
        committed: bool = false,

        pub fn addBytes(self: *Self, data: []const u8) Error!Hash {
            return self.addBytesFormatted(data, .raw);
        }

        /// Like `addBytes`, but the batch temp-tag uses `format` so hash_seq
        /// collections expand children under GC for the whole batch window (F26).
        pub fn addBytesFormatted(self: *Self, data: []const u8, format: BlobFormat) Error!Hash {
            const hash = try self.store.addBytes(data);
            try self.protect(hash, format);
            return hash;
        }

        pub fn addPath(self: *Self, io: std.Io, path: []const u8) Error!Hash {
            const hash = try self.store.addPath(io, path);
            try self.protect(hash, .raw);
            return hash;
        }

        /// The number of distinct hashes this batch currently protects.
        pub fn len(self: *const Self) usize {
            return self.hashes.items.len;
        }

        /// End the batch's protection and return the protected hash list.
        pub fn commit(self: *Self) Error![]Hash {
            std.debug.assert(!self.committed);
            self.committed = true;
            const owned = self.hashes.toOwnedSlice(self.store.allocator) catch return error.OutOfMemory;
            for (owned) |hash| self.store.releaseTempTag(hash);
            return owned;
        }

        pub fn deinit(self: *Self) void {
            self.releaseAll();
            self.hashes.deinit(self.store.allocator);
            self.* = undefined;
        }

        fn protect(self: *Self, hash: Hash, format: BlobFormat) Error!void {
            for (self.hashes.items) |existing| {
                if (existing.eql(hash)) return;
            }
            _ = try self.store.tempTag(hash, format);
            // F06: if the batch cannot record the hash, roll back the temp-tag
            // so deinit/GC do not leak an untracked pin forever.
            self.hashes.append(self.store.allocator, hash) catch {
                self.store.releaseTempTag(hash);
                return error.OutOfMemory;
            };
        }

        fn releaseAll(self: *Self) void {
            for (self.hashes.items) |hash| self.store.releaseTempTag(hash);
            self.hashes.clearRetainingCapacity();
        }
    };
}

test "F25 tempTag raw then hash_seq promotes format so GC keeps children" {
    // Pre-fix: found_existing only bumped count; format stayed .raw → GC
    // expanded no children and reclaimed them under a live "hash_seq" pin.
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    const hashseq = @import("hashseq.zig");
    const gc = @import("gc.zig");
    var store = MemStore.init(alloc);
    defer store.deinit();

    const child_a = try store.addBytes("f25-child-a");
    const child_b = try store.addBytes("f25-child-b");
    var seq = try hashseq.HashSeq.fromHashes(alloc, &.{ child_a, child_b });
    defer seq.deinit(alloc);
    const collection = try store.addBytes(seq.bytes);
    _ = try store.addBytes("f25-garbage");

    var raw_guard = try store.tempTag(collection, .raw);
    defer raw_guard.release();
    var seq_guard = try store.tempTag(collection, .hash_seq);
    defer seq_guard.release();

    const outcome = try gc.gcRun(MemStore, &store, alloc);
    try std.testing.expectEqual(@as(u64, 3), outcome.kept);
    try std.testing.expectEqual(@as(u64, 1), outcome.reclaimed);
    switch (try store.status(child_a)) {
        .complete => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try store.status(child_b)) {
        .complete => {},
        else => return error.TestUnexpectedResult,
    }
}

test "F26 batch addBytesFormatted hash_seq protects collection children until commit" {
    // Pre-fix: Batch.protect always temp-tagged .raw, so children of a
    // collection added in-batch were reclaimable for the whole batch window.
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    const hashseq = @import("hashseq.zig");
    const gc = @import("gc.zig");
    var store = MemStore.init(alloc);
    defer store.deinit();

    const child_a = try store.addBytes("f26-child-a");
    const child_b = try store.addBytes("f26-child-b");
    var seq = try hashseq.HashSeq.fromHashes(alloc, &.{ child_a, child_b });
    defer seq.deinit(alloc);
    _ = try store.addBytes("f26-garbage");

    var batch = store.batch();
    defer batch.deinit();
    _ = try batch.addBytesFormatted(seq.bytes, .hash_seq);

    const during = try gc.gcRun(MemStore, &store, alloc);
    try std.testing.expectEqual(@as(u64, 3), during.kept);
    try std.testing.expectEqual(@as(u64, 1), during.reclaimed);
    switch (try store.status(child_a)) {
        .complete => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try store.status(child_b)) {
        .complete => {},
        else => return error.TestUnexpectedResult,
    }
}

test "F06 Batch.protect OOM after tempTag rolls back the untracked pin" {
    // Pre-fix: tempTag succeeded then hashes.append OOM left a pin that
    // Batch.deinit could not release (hash never recorded).
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    const FailingAllocator = std.testing.FailingAllocator;

    const payload = "f06-oom-protect";
    var counter = FailingAllocator.init(alloc, .{});
    {
        var store = MemStore.init(counter.allocator());
        defer store.deinit();
        _ = try store.addBytes(payload);
        const base = counter.alloc_index;
        var batch = store.batch();
        defer batch.deinit();
        _ = try batch.addBytes(payload);
        // Last allocation in the protect path is hashes.append.
        try std.testing.expect(counter.alloc_index > base);
    }
    const fail_at = counter.alloc_index - 1;

    var fail_state = FailingAllocator.init(alloc, .{ .fail_index = fail_at });
    var store = MemStore.init(fail_state.allocator());
    defer store.deinit();
    _ = try store.addBytes(payload);
    try std.testing.expectEqual(@as(usize, 0), store.tempTagCount());

    var batch = store.batch();
    defer batch.deinit();
    try std.testing.expectError(error.OutOfMemory, batch.addBytes(payload));
    try std.testing.expect(fail_state.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), store.tempTagCount());
    try std.testing.expectEqual(@as(usize, 0), batch.len());
}

test "temp tag guard is ref-counted and idempotently released" {
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    var store = MemStore.init(alloc);
    defer store.deinit();

    const hash = try store.addBytes("shielded");
    var g1 = try store.tempTag(hash, .raw);
    var g2 = try store.tempTag(hash, .raw);
    try std.testing.expectEqual(@as(usize, 1), store.tempTagCount());

    g1.release();
    try std.testing.expectEqual(@as(usize, 1), store.tempTagCount());
    g2.release();
    g2.release(); // idempotent
    try std.testing.expectEqual(@as(usize, 0), store.tempTagCount());
}

test "batch protects additions until commit" {
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    const gc = @import("gc.zig");
    var store = MemStore.init(alloc);
    defer store.deinit();

    var batch = store.batch();
    const h1 = try batch.addBytes("batch-one");
    const h2 = try batch.addBytes("batch-two");
    try std.testing.expectEqual(@as(usize, 2), batch.len());

    const during = try gc.gcRun(MemStore, &store, alloc);
    try std.testing.expectEqual(@as(u64, 2), during.kept);
    try std.testing.expectEqual(@as(u64, 0), during.reclaimed);

    const committed = try batch.commit();
    defer alloc.free(committed);
    batch.deinit();
    try std.testing.expectEqual(@as(usize, 2), committed.len);
    try std.testing.expect(committed[0].eql(h1) and committed[1].eql(h2));

    // Protection ended with the batch: untagged blobs are collectable.
    const after = try gc.gcRun(MemStore, &store, alloc);
    try std.testing.expectEqual(@as(u64, 0), after.kept);
    try std.testing.expectEqual(@as(u64, 2), after.reclaimed);
}

test "FsStore temp tag guard is ref-counted and batch protects until commit" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    const FsStore = @import("fs_store.zig").FsStore;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const path = try std.fmt.allocPrint(alloc, "zig-cache/tmp/blobs-fs-temp-tag-{d}", .{nonce});
    defer alloc.free(path);
    defer std.Io.Dir.cwd().deleteTree(io, path) catch {};

    var store = try FsStore.open(alloc, io, path);
    defer store.deinit();

    const hash = try store.addBytes("fs-shielded");
    var g1 = try store.tempTag(hash, .raw);
    var g2 = try store.tempTag(hash, .raw);
    try std.testing.expectEqual(@as(usize, 1), store.tempTagCount());
    g1.release();
    try std.testing.expectEqual(@as(usize, 1), store.tempTagCount());
    g2.release();
    g2.release();
    try std.testing.expectEqual(@as(usize, 0), store.tempTagCount());

    var batch = store.batch();
    const h1 = try batch.addBytes("fs-batch-one");
    const h2 = try batch.addBytes("fs-batch-two");
    try std.testing.expectEqual(@as(usize, 2), batch.len());
    try std.testing.expectEqual(@as(usize, 2), store.tempTagCount());

    const during = try store.gc();
    try std.testing.expectEqual(@as(u64, 2), during.kept);
    try std.testing.expectEqual(@as(u64, 1), during.reclaimed); // untagged "fs-shielded"

    const committed = try batch.commit();
    defer alloc.free(committed);
    batch.deinit();
    try std.testing.expectEqual(@as(usize, 2), committed.len);
    try std.testing.expect(committed[0].eql(h1) and committed[1].eql(h2));
    try std.testing.expectEqual(@as(usize, 0), store.tempTagCount());

    const after = try store.gc();
    try std.testing.expectEqual(@as(u64, 0), after.kept);
    try std.testing.expectEqual(@as(u64, 2), after.reclaimed);
}
