//! Tag-aware garbage collection for blob stores.
//!
//! Mark-and-sweep over the store's complete entries: a hash is protected
//! when a named tag or a live temporary tag references it, and hash-seq
//! formatted protections extend to their child hashes. Everything else is
//! reclaimed. Behaviour contract: iroh-blobs/src/store/gc.rs
//! (reachability-driven collection; periodic scheduling is a caller concern).

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const hashseq = @import("hashseq.zig");
const types = @import("types.zig");

pub const BlobFormat = types.BlobFormat;
pub const Error = types.Error;

pub const GcOutcome = struct {
    kept: u64,
    reclaimed: u64,
};

pub const ProtectSet = std.AutoHashMapUnmanaged([32]u8, void);

/// Add `hash` to the protected set; when `format` is hash_seq, fetch the
/// blob and protect each child hash it names. Missing children are protected
/// anyway — protecting an absent hash is a no-op at sweep time.
pub fn protectWithChildren(
    comptime Store: type,
    store: *Store,
    allocator: std.mem.Allocator,
    protect: *ProtectSet,
    hash: Hash,
    format: BlobFormat,
) Error!void {
    try protect.put(allocator, hash.bytes, {});
    if (format != .hash_seq) return;
    const data = store.getBytes(allocator, hash) catch |err| switch (err) {
        error.NotFound => return,
        else => |e| return e,
    };
    defer allocator.free(data);
    // Fail-closed (F10): a malformed hash_seq must not look like a successful
    // GC that only protected the root — surface the error so gcRun aborts
    // before the reclaim sweep.
    const seq = hashseq.HashSeq.fromBytes(data) catch return error.InvalidState;
    var i: usize = 0;
    while (seq.get(i)) |child| : (i += 1) {
        try protect.put(allocator, child.bytes, {});
    }
}

/// Run one GC round over a store. The store contract is the same one the
/// `Blobs` facade uses (tags/listHashes/remove/getBytes) plus an optional
/// `tempTagEntries` iterator for live temporary protections and an optional
/// `sweepUnprotectedPartials` hook for partial-entry backends.
pub fn gcRun(comptime Store: type, store: *Store, allocator: std.mem.Allocator) Error!GcOutcome {
    var protect: ProtectSet = .empty;
    defer protect.deinit(allocator);

    const tag_list = try store.tags().list(allocator);
    defer {
        for (tag_list) |tag| tag.deinit(allocator);
        allocator.free(tag_list);
    }
    for (tag_list) |tag| {
        try protectWithChildren(Store, store, allocator, &protect, tag.hash, tag.format);
    }

    if (comptime @hasDecl(Store, "tempTagEntries")) {
        var it = store.tempTagEntries();
        while (it.next()) |entry| {
            try protectWithChildren(
                Store,
                store,
                allocator,
                &protect,
                Hash.fromBytes(entry.key_ptr.*),
                entry.value_ptr.format,
            );
        }
    }

    var outcome: GcOutcome = .{ .kept = 0, .reclaimed = 0 };
    const hashes = try store.listHashes(allocator);
    defer allocator.free(hashes);
    for (hashes) |hash| {
        if (protect.contains(hash.bytes)) {
            outcome.kept += 1;
            continue;
        }
        if (try store.remove(hash)) outcome.reclaimed += 1;
    }

    if (comptime @hasDecl(Store, "sweepUnprotectedPartials")) {
        outcome.reclaimed += try store.sweepUnprotectedPartials(&protect);
    }

    return outcome;
}

test "gc reclaims untagged blobs and keeps tagged ones" {
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    var store = MemStore.init(alloc);
    defer store.deinit();

    const tagged = try store.addBytes("kept-by-tag");
    _ = try store.addBytes("garbage");
    try store.tags().setRaw("keep", tagged);

    const outcome = try gcRun(MemStore, &store, alloc);
    try std.testing.expectEqual(@as(u64, 1), outcome.kept);
    try std.testing.expectEqual(@as(u64, 1), outcome.reclaimed);

    const hashes = try store.listHashes(alloc);
    defer alloc.free(hashes);
    try std.testing.expectEqual(@as(usize, 1), hashes.len);
    try std.testing.expect(hashes[0].eql(tagged));
}

test "gc protects hash-seq children of tagged collections" {
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    var store = MemStore.init(alloc);
    defer store.deinit();

    const child_a = try store.addBytes("child-a");
    const child_b = try store.addBytes("child-b");
    var seq = try hashseq.HashSeq.fromHashes(alloc, &.{ child_a, child_b });
    defer seq.deinit(alloc);
    const collection = try store.addBytes(seq.bytes);
    try store.tags().set("collection", .{ .hash = collection, .format = .hash_seq });
    _ = try store.addBytes("garbage");

    const outcome = try gcRun(MemStore, &store, alloc);
    try std.testing.expectEqual(@as(u64, 3), outcome.kept);
    try std.testing.expectEqual(@as(u64, 1), outcome.reclaimed);
    const kept = try store.listHashes(alloc);
    defer alloc.free(kept);
    try std.testing.expectEqual(@as(usize, 3), kept.len);
}

test "gc sweeps unprotected partial entries and keeps temp-tagged ones" {
    const alloc = std.testing.allocator;
    const bao = @import("bao.zig");
    const fixtures = @import("fixtures.zig");
    const MemStore = @import("store.zig").MemStore;
    var store = MemStore.init(alloc);
    defer store.deinit();

    const data = try fixtures.makeTestData(alloc, 16_385);
    defer alloc.free(data);
    const created = try bao.createOutboard(alloc, data);
    defer alloc.free(created.outboard);

    _ = try store.partialCreate(created.root, data.len, created.outboard);
    const first = try gcRun(MemStore, &store, alloc);
    try std.testing.expectEqual(@as(u64, 1), first.reclaimed);
    try std.testing.expect(store.partialEntry(created.root) == null);

    // A temp-tagged partial survives the round.
    _ = try store.partialCreate(created.root, data.len, created.outboard);
    var guard = try store.tempTag(created.root, .raw);
    const second = try gcRun(MemStore, &store, alloc);
    try std.testing.expectEqual(@as(u64, 0), second.reclaimed);
    try std.testing.expect(store.partialEntry(created.root) != null);
    guard.release();
    const third = try gcRun(MemStore, &store, alloc);
    try std.testing.expectEqual(@as(u64, 1), third.reclaimed);
}

test "F10 GC fails closed on malformed hash_seq instead of reclaiming children" {
    // Pre-fix: HashSeq.fromBytes errors were swallowed after protecting only
    // the root; gcRun reported success while deleting the children.
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    var store = MemStore.init(alloc);
    defer store.deinit();

    const child_a = try store.addBytes("f10-child-a");
    const child_b = try store.addBytes("f10-child-b");
    // 33 bytes → not 32-aligned → InvalidHashSeq.
    var malformed: [33]u8 = undefined;
    @memset(&malformed, 0xAB);
    @memcpy(malformed[0..32], &child_a.bytes);
    const broken_root = try store.addBytes(&malformed);
    try store.tags().set("broken-collection", .{ .hash = broken_root, .format = .hash_seq });

    try std.testing.expectError(error.InvalidState, gcRun(MemStore, &store, alloc));
    switch (try store.status(child_a)) {
        .complete => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try store.status(child_b)) {
        .complete => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try store.status(broken_root)) {
        .complete => {},
        else => return error.TestUnexpectedResult,
    }
}

test "gc keeps temp-tagged blobs until the guard releases" {
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    var store = MemStore.init(alloc);
    defer store.deinit();

    const in_flight = try store.addBytes("in-flight-download");
    var guard = try store.tempTag(in_flight, .raw);

    const first = try gcRun(MemStore, &store, alloc);
    try std.testing.expectEqual(@as(u64, 1), first.kept);
    try std.testing.expectEqual(@as(u64, 0), first.reclaimed);

    guard.release();
    const second = try gcRun(MemStore, &store, alloc);
    try std.testing.expectEqual(@as(u64, 0), second.kept);
    try std.testing.expectEqual(@as(u64, 1), second.reclaimed);
}
