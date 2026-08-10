//! Multi-source download orchestration.
//!
//! The Downloader queues blob requests, coalesces duplicate requests for the
//! same hash, skips blobs the store already has, and drives each remaining
//! hash through the source list in order (failover) until one serves bytes
//! that verify against the requested hash. Verified bytes land in the store
//! through the normal content-addressed add path; bytes that fail the hash
//! check are never stored. Sources are an injection seam — the orchestration
//! (dedup, failover, verified landing) is what this component owns.
//! Behaviour contract: iroh-blobs/src/api/downloader.rs
//! (request queue + dedup + multi-source), with the network binding left to
//! the concrete Source implementation.

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const types = @import("types.zig");

pub const Error = types.Error;

pub const SourceError = error{
    FetchFailed,
    OutOfMemory,
};

/// A place the downloader can obtain blob bytes from. `fetch` returns
/// caller-owned bytes; the downloader verifies them against the requested
/// hash before storing, so a misbehaving source cannot poison the store.
pub const Source = struct {
    ptr: *anyopaque,
    vtable: *const Vtable,

    pub const Vtable = struct {
        name: *const fn (ptr: *anyopaque) []const u8,
        has: *const fn (ptr: *anyopaque, hash: Hash) bool,
        fetch: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator, hash: Hash) SourceError![]u8,
    };

    pub fn name(self: Source) []const u8 {
        return self.vtable.name(self.ptr);
    }

    pub fn has(self: Source, hash: Hash) bool {
        return self.vtable.has(self.ptr, hash);
    }

    pub fn fetch(self: Source, allocator: std.mem.Allocator, hash: Hash) SourceError![]u8 {
        return self.vtable.fetch(self.ptr, allocator, hash);
    }
};

pub const Stats = struct {
    requested: u64 = 0,
    deduplicated: u64 = 0,
    already_present: u64 = 0,
    fetched: u64 = 0,
    failed: u64 = 0,
};

pub fn Downloader(comptime Store: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        store: *Store,
        sources: []const Source,
        queue: std.ArrayList(Hash) = .empty,
        queued: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
        stats: Stats = .{},

        pub fn init(allocator: std.mem.Allocator, store: *Store, sources: []const Source) Self {
            return .{ .allocator = allocator, .store = store, .sources = sources };
        }

        pub fn deinit(self: *Self) void {
            self.queue.deinit(self.allocator);
            self.queued.deinit(self.allocator);
            self.* = undefined;
        }

        /// Queue a hash for download. Duplicate requests coalesce into the
        /// pending/queued entry; hashes already complete in the store are
        /// counted and skipped.
        pub fn queueRequest(self: *Self, hash: Hash) Error!void {
            self.stats.requested += 1;
            switch (try self.store.status(hash)) {
                .complete => {
                    self.stats.already_present += 1;
                    return;
                },
                else => {},
            }
            if (self.queued.contains(hash.bytes)) {
                self.stats.deduplicated += 1;
                return;
            }
            // Put the dedup key first so a queue-append OOM cannot leave a
            // queued entry without a map slot (or the reverse).
            self.queued.put(self.allocator, hash.bytes, {}) catch return error.OutOfMemory;
            errdefer _ = self.queued.remove(hash.bytes);
            self.queue.append(self.allocator, hash) catch return error.OutOfMemory;
        }

        /// Number of hashes waiting to be fetched.
        pub fn pending(self: *const Self) usize {
            return self.queue.items.len;
        }

        /// Drain the queue: for each hash, try the sources in order until one
        /// serves bytes that verify against the hash, then store them.
        pub fn run(self: *Self) Error!void {
            while (self.queue.items.len > 0) {
                const hash = self.queue.orderedRemove(0);
                _ = self.queued.remove(hash.bytes);
                self.fetchOne(hash);
            }
        }

        fn fetchOne(self: *Self, hash: Hash) void {
            for (self.sources) |source| {
                if (!source.has(hash)) continue;
                const data = source.fetch(self.allocator, hash) catch continue;
                defer self.allocator.free(data);
                if (!Hash.of(data).eql(hash)) continue; // never store unverified bytes
                // Store OOM is not a clean success — count failed (F07).
                _ = self.store.addBytes(data) catch {
                    self.stats.failed += 1;
                    return;
                };
                self.stats.fetched += 1;
                return;
            }
            self.stats.failed += 1;
        }
    };
}

const TestSource = struct {
    const Self = @This();
    allocator: std.mem.Allocator,
    label: []const u8,
    blobs: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty,
    fetch_count: u64 = 0,
    fail_fetches: bool = false,
    corrupt_fetches: bool = false,

    fn deinit(self: *Self) void {
        var it = self.blobs.iterator();
        while (it.next()) |e| self.allocator.free(e.value_ptr.*);
        self.blobs.deinit(self.allocator);
    }

    fn put(self: *Self, data: []const u8) !void {
        const owned = try self.allocator.dupe(u8, data);
        try self.blobs.put(self.allocator, Hash.of(data).bytes, owned);
    }

    fn source(self: *Self) Source {
        return .{ .ptr = self, .vtable = &.{
            .name = nameImpl,
            .has = hasImpl,
            .fetch = fetchImpl,
        } };
    }

    fn nameImpl(ptr: *anyopaque) []const u8 {
        return @as(*Self, @ptrCast(@alignCast(ptr))).label;
    }

    fn hasImpl(ptr: *anyopaque, hash: Hash) bool {
        return @as(*Self, @ptrCast(@alignCast(ptr))).blobs.contains(hash.bytes);
    }

    fn fetchImpl(ptr: *anyopaque, allocator: std.mem.Allocator, hash: Hash) SourceError![]u8 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.fetch_count += 1;
        if (self.fail_fetches) return error.FetchFailed;
        const data = self.blobs.get(hash.bytes) orelse return error.FetchFailed;
        const out = allocator.dupe(u8, data) catch return error.OutOfMemory;
        if (self.corrupt_fetches) out[0] += 1;
        return out;
    }
};

test "downloader dedups concurrent requests into one fetch" {
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    var store = MemStore.init(alloc);
    defer store.deinit();

    var src: TestSource = .{ .allocator = alloc, .label = "a" };
    defer src.deinit();
    try src.put("download-me");
    const hash = Hash.of("download-me");

    var dl = Downloader(MemStore).init(alloc, &store, &.{src.source()});
    defer dl.deinit();
    try dl.queueRequest(hash);
    try dl.queueRequest(hash);
    try dl.queueRequest(hash);
    try std.testing.expectEqual(@as(u64, 3), dl.stats.requested);
    try std.testing.expectEqual(@as(u64, 2), dl.stats.deduplicated);
    try std.testing.expectEqual(@as(usize, 1), dl.pending());

    try dl.run();
    try std.testing.expectEqual(@as(u64, 1), src.fetch_count);
    try std.testing.expectEqual(@as(u64, 1), dl.stats.fetched);
    const got = try store.getBytes(alloc, hash);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("download-me", got);
}

test "downloader fails over sources and skips absent ones" {
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    var store = MemStore.init(alloc);
    defer store.deinit();

    var broken: TestSource = .{ .allocator = alloc, .label = "broken", .fail_fetches = true };
    defer broken.deinit();
    var silent: TestSource = .{ .allocator = alloc, .label = "silent" };
    defer silent.deinit();
    var good: TestSource = .{ .allocator = alloc, .label = "good" };
    defer good.deinit();

    try broken.put("failover-blob"); // has it, but fetches fail
    try good.put("failover-blob");
    const hash = Hash.of("failover-blob");

    var dl = Downloader(MemStore).init(alloc, &store, &.{ broken.source(), silent.source(), good.source() });
    defer dl.deinit();
    try dl.queueRequest(hash);
    try dl.run();

    try std.testing.expectEqual(@as(u64, 1), broken.fetch_count); // tried, failed
    try std.testing.expectEqual(@as(u64, 0), silent.fetch_count); // never had it
    try std.testing.expectEqual(@as(u64, 1), good.fetch_count); // served it
    try std.testing.expectEqual(@as(u64, 1), dl.stats.fetched);
    try std.testing.expectEqual(@as(u64, 0), dl.stats.failed);
}

test "downloader never stores bytes that fail the hash check" {
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    var store = MemStore.init(alloc);
    defer store.deinit();

    var corrupt: TestSource = .{ .allocator = alloc, .label = "corrupt", .corrupt_fetches = true };
    defer corrupt.deinit();
    try corrupt.put("poison-blob");
    const hash = Hash.of("poison-blob");

    var dl = Downloader(MemStore).init(alloc, &store, &.{corrupt.source()});
    defer dl.deinit();
    try dl.queueRequest(hash);
    try dl.run();

    try std.testing.expectEqual(@as(u64, 1), dl.stats.failed);
    try std.testing.expectEqual(@as(u64, 0), dl.stats.fetched);
    switch (try store.status(hash)) {
        .not_found => {},
        else => return error.TestUnexpectedResult,
    }
}

test "downloader skips hashes already present in the store" {
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    var store = MemStore.init(alloc);
    defer store.deinit();
    const hash = try store.addBytes("already-here");

    var src: TestSource = .{ .allocator = alloc, .label = "a" };
    defer src.deinit();
    try src.put("already-here");

    var dl = Downloader(MemStore).init(alloc, &store, &.{src.source()});
    defer dl.deinit();
    try dl.queueRequest(hash);
    try dl.run();
    try std.testing.expectEqual(@as(u64, 1), dl.stats.already_present);
    try std.testing.expectEqual(@as(u64, 0), src.fetch_count);
}

test "F07 addBytes OOM increments failed and does not count fetched" {
    const alloc = std.testing.allocator;
    const MemStore = @import("store.zig").MemStore;
    const FailingAllocator = std.testing.FailingAllocator;

    // Store allocator fails on the first alloc (addBytes dupe). Downloader
    // queue/fetch use the testing allocator, so only the store landing fails.
    var fail_store = FailingAllocator.init(alloc, .{ .fail_index = 0 });
    var store = MemStore.init(fail_store.allocator());
    defer store.deinit();

    var src: TestSource = .{ .allocator = alloc, .label = "a" };
    defer src.deinit();
    try src.put("oom-landing");
    const hash = Hash.of("oom-landing");

    var dl = Downloader(MemStore).init(alloc, &store, &.{src.source()});
    defer dl.deinit();
    try dl.queueRequest(hash);
    try dl.run();

    try std.testing.expectEqual(@as(u64, 1), src.fetch_count);
    try std.testing.expectEqual(@as(u64, 0), dl.stats.fetched);
    try std.testing.expectEqual(@as(u64, 1), dl.stats.failed);
}
