//! In-memory Blob Store — add/get/export/list + embedded Tags.
//!
//! Behaviour contract: iroh-blobs/tests/blobs.rs::blobs_smoke_mem
//! (local MemStore only; no FsStore/RPC in this slice).

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const api = @import("api.zig");
const gc_mod = @import("gc.zig");
const metrics_mod = @import("metrics.zig");
const partial_mod = @import("partial.zig");
const reader_mod = @import("reader.zig");
const tags_mod = @import("tags.zig");
const temp_tag = @import("temp_tag.zig");
const types = @import("types.zig");

pub const Tags = tags_mod.Tags;
pub const BlobFormat = types.BlobFormat;
pub const HashAndFormat = types.HashAndFormat;
pub const TagInfo = types.TagInfo;
pub const BlobStatus = types.BlobStatus;
pub const Error = types.Error;
pub const TempTagGuard = temp_tag.TempTagGuard(MemStore);
pub const Batch = temp_tag.Batch(MemStore);
pub const GcOutcome = gc_mod.GcOutcome;

const BlobEntry = struct {
    data: []u8,
};

pub const TempTagEntry = struct {
    count: u64,
    format: BlobFormat,
};

const TempTagMap = std.AutoHashMapUnmanaged([32]u8, TempTagEntry);

pub const MemStore = struct {
    pub const Reader = reader_mod.MemReader;
    pub const PartialEntry = partial_mod.PartialEntry;

    allocator: std.mem.Allocator,
    entries: std.AutoHashMapUnmanaged([32]u8, BlobEntry) = .empty,
    partials: std.AutoHashMapUnmanaged([32]u8, *PartialEntry) = .empty,
    tags_inner: Tags,
    temp_tags: TempTagMap = .empty,
    metrics_inner: metrics_mod.Metrics = .{},
    closed: bool = false,

    pub fn init(allocator: std.mem.Allocator) MemStore {
        return .{
            .allocator = allocator,
            .tags_inner = Tags.init(allocator),
        };
    }

    pub fn deinit(self: *MemStore) void {
        var it = self.entries.iterator();
        while (it.next()) |e| self.allocator.free(e.value_ptr.data);
        self.entries.deinit(self.allocator);
        var pit = self.partials.iterator();
        while (pit.next()) |e| {
            e.value_ptr.*.deinit();
            self.allocator.destroy(e.value_ptr.*);
        }
        self.partials.deinit(self.allocator);
        self.temp_tags.deinit(self.allocator);
        self.tags_inner.deinit();
        self.* = undefined;
    }

    pub fn shutdown(self: *MemStore) Error!void {
        self.closed = true;
    }

    pub fn waitIdle(self: *MemStore) Error!void {
        try self.ensureOpen();
    }

    pub fn blobs(self: *MemStore) api.Blobs(MemStore) {
        return .{ .backend = self };
    }

    pub fn tags(self: *MemStore) *Tags {
        return &self.tags_inner;
    }

    pub fn metrics(self: *const MemStore) metrics_mod.Snapshot {
        return self.metrics_inner.snapshot();
    }

    /// Take a temporary ref-counted protection on `hash`. GC keeps a
    /// temp-tagged hash until the last guard releases it.
    ///
    /// Format is the OR of all live pins: any `.hash_seq` pin promotes the
    /// entry so GC expands children for the whole remaining lifetime (never
    /// silently drop a stronger format — F25).
    pub fn tempTag(self: *MemStore, hash: Hash, format: BlobFormat) Error!TempTagGuard {
        try self.ensureOpen();
        const gop = self.temp_tags.getOrPut(self.allocator, hash.bytes) catch return error.OutOfMemory;
        if (gop.found_existing) {
            gop.value_ptr.count += 1;
            if (format == .hash_seq) gop.value_ptr.format = .hash_seq;
        } else {
            gop.value_ptr.* = .{ .count = 1, .format = format };
        }
        return .{ .store = self, .hash = hash, .alive = true };
    }

    pub fn releaseTempTag(self: *MemStore, hash: Hash) void {
        const entry = self.temp_tags.getPtr(hash.bytes) orelse return;
        entry.count -= 1;
        if (entry.count == 0) _ = self.temp_tags.remove(hash.bytes);
    }

    /// The number of distinct hashes currently temp-tagged (GC introspection).
    pub fn tempTagCount(self: *const MemStore) usize {
        return self.temp_tags.count();
    }

    pub fn tempTagEntries(self: *MemStore) TempTagMap.Iterator {
        return self.temp_tags.iterator();
    }

    /// Start a batch: every blob added through it is temp-tag protected until
    /// the batch commits or is deinitialized.
    pub fn batch(self: *MemStore) Batch {
        return .{ .store = self };
    }

    /// Run one tag-aware GC round: reclaim complete entries not reachable
    /// from a named tag or a live temp tag (hash-seq children included).
    pub fn gc(self: *MemStore) Error!GcOutcome {
        try self.ensureOpen();
        return gc_mod.gcRun(MemStore, self, self.allocator);
    }

    pub fn addBytes(self: *MemStore, data: []const u8) Error!Hash {
        try self.ensureOpen();
        const hash = Hash.of(data);
        if (self.entries.contains(hash.bytes)) {
            self.metrics_inner.recordAdd(data.len);
            return hash;
        }
        const owned = self.allocator.dupe(u8, data) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        self.entries.put(self.allocator, hash.bytes, .{ .data = owned }) catch return error.OutOfMemory;
        self.metrics_inner.recordAdd(data.len);
        return hash;
    }

    pub fn getBytes(self: *MemStore, allocator: std.mem.Allocator, hash: Hash) Error![]u8 {
        try self.ensureOpen();
        const entry = self.entries.get(hash.bytes) orelse {
            _ = self.metrics_inner.not_found.fetchAdd(1, .monotonic);
            return error.NotFound;
        };
        const data = allocator.dupe(u8, entry.data) catch return error.OutOfMemory;
        self.metrics_inner.recordGet(data.len);
        return data;
    }

    pub fn addPath(self: *MemStore, io: std.Io, path: []const u8) Error!Hash {
        try self.ensureOpen();
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

    /// Import a file, streaming `ImportProgress` events to `on_event` as bytes
    /// land. `context` is passed through unchanged on every event.
    pub fn addPathWithProgress(
        self: *MemStore,
        io: std.Io,
        path: []const u8,
        context: anytype,
        on_event: *const fn (@TypeOf(context), types.ImportProgress) void,
    ) Error!Hash {
        try self.ensureOpen();
        const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return error.Io;
        defer file.close(io);
        const stat = file.stat(io) catch return error.Io;
        const size: usize = @intCast(stat.size);
        on_event(context, .{ .found = .{ .size = size } });

        const buf = self.allocator.alloc(u8, size) catch return error.OutOfMemory;
        defer self.allocator.free(buf);
        var reader_buf: [4096]u8 = undefined;
        var file_reader = file.reader(io, &reader_buf);
        const r = &file_reader.interface;
        var done: usize = 0;
        while (done < size) {
            const n = r.readSliceShort(buf[done..]) catch return error.Io;
            if (n == 0) return error.Io;
            done += n;
            on_event(context, .{ .progress = .{ .bytes_done = done } });
        }
        const hash = try self.addBytes(buf);
        on_event(context, .{ .done = .{ .hash = hash } });
        return hash;
    }

    /// Open a seekable reader over a complete blob's bytes.
    pub fn openReader(self: *MemStore, allocator: std.mem.Allocator, hash: Hash) Error!reader_mod.MemReader {
        try self.ensureOpen();
        const entry = self.entries.get(hash.bytes) orelse return error.NotFound;
        const owned = allocator.dupe(u8, entry.data) catch return error.OutOfMemory;
        return .{ .allocator = allocator, .data = owned, .pos = 0 };
    }

    /// Create an empty partial entry for an in-flight download.
    pub fn partialCreate(self: *MemStore, hash: Hash, size: u64, outboard: []const u8) Error!*PartialEntry {
        try self.ensureOpen();
        const entry = self.allocator.create(PartialEntry) catch return error.OutOfMemory;
        var created = false;
        errdefer {
            if (created) entry.deinit();
            self.allocator.destroy(entry);
        }
        entry.* = try PartialEntry.create(self.allocator, hash, size, outboard);
        created = true;
        const gop = self.partials.getOrPut(self.allocator, hash.bytes) catch return error.OutOfMemory;
        if (gop.found_existing) {
            gop.value_ptr.*.deinit();
            self.allocator.destroy(gop.value_ptr.*);
        }
        gop.value_ptr.* = entry;
        return entry;
    }

    /// Import serialized partial state (see PartialEntry.exportState) and
    /// register it, replacing any existing entry for the same hash.
    pub fn partialImport(self: *MemStore, state: []const u8) Error!*PartialEntry {
        try self.ensureOpen();
        const entry = self.allocator.create(PartialEntry) catch return error.OutOfMemory;
        var created = false;
        errdefer {
            if (created) entry.deinit();
            self.allocator.destroy(entry);
        }
        entry.* = try PartialEntry.importState(self.allocator, state);
        created = true;
        const gop = self.partials.getOrPut(self.allocator, entry.hash.bytes) catch return error.OutOfMemory;
        if (gop.found_existing) {
            gop.value_ptr.*.deinit();
            self.allocator.destroy(gop.value_ptr.*);
        }
        gop.value_ptr.* = entry;
        return entry;
    }

    pub fn partialEntry(self: *MemStore, hash: Hash) ?*PartialEntry {
        return self.partials.get(hash.bytes);
    }

    /// Export the partial state for a hash (transfer/resume).
    pub fn partialExport(self: *MemStore, allocator: std.mem.Allocator, hash: Hash) Error![]u8 {
        try self.ensureOpen();
        const entry = self.partials.get(hash.bytes) orelse return error.NotFound;
        return entry.exportState(allocator);
    }

    /// Partial-to-complete transition: requires the entry to be complete,
    /// re-checks the full content hash, publishes the blob, and drops the
    /// partial entry.
    pub fn partialComplete(self: *MemStore, hash: Hash) Error!Hash {
        try self.ensureOpen();
        const entry = self.partials.get(hash.bytes) orelse return error.NotFound;
        const data = try entry.finish(self.allocator);
        defer self.allocator.free(data);
        const complete = try self.addBytes(data);
        self.destroyPartial(hash);
        return complete;
    }

    /// GC hook: reclaim partial entries with no protection.
    pub fn sweepUnprotectedPartials(self: *MemStore, protect: *const gc_mod.ProtectSet) Error!u64 {
        var doomed: std.ArrayList([32]u8) = .empty;
        defer doomed.deinit(self.allocator);
        var it = self.partials.iterator();
        while (it.next()) |e| {
            if (!protect.contains(e.key_ptr.*)) {
                doomed.append(self.allocator, e.key_ptr.*) catch return error.OutOfMemory;
            }
        }
        for (doomed.items) |key| self.destroyPartial(Hash.fromBytes(key));
        return @intCast(doomed.items.len);
    }

    fn destroyPartial(self: *MemStore, hash: Hash) void {
        const entry = self.partials.fetchRemove(hash.bytes) orelse return;
        entry.value.deinit();
        self.allocator.destroy(entry.value);
    }

    pub fn exportPath(self: *MemStore, io: std.Io, hash: Hash, path: []const u8) Error!void {
        try self.ensureOpen();
        const entry = self.entries.get(hash.bytes) orelse return error.NotFound;
        const file = std.Io.Dir.cwd().createFile(io, path, .{}) catch return error.Io;
        defer file.close(io);
        var writer_buf: [4096]u8 = undefined;
        var file_writer = file.writer(io, &writer_buf);
        const w = &file_writer.interface;
        w.writeAll(entry.data) catch return error.Io;
        w.flush() catch return error.Io;
    }

    pub fn listHashes(self: *MemStore, allocator: std.mem.Allocator) Error![]Hash {
        try self.ensureOpen();
        var out: std.ArrayList(Hash) = .empty;
        errdefer out.deinit(allocator);
        var it = self.entries.keyIterator();
        while (it.next()) |k| {
            out.append(allocator, Hash.fromBytes(k.*)) catch return error.OutOfMemory;
        }
        return out.toOwnedSlice(allocator) catch return error.OutOfMemory;
    }

    pub fn status(self: *MemStore, hash: Hash) Error!BlobStatus {
        try self.ensureOpen();
        if (self.entries.get(hash.bytes)) |entry| {
            return .{ .complete = entry.data.len };
        }
        if (self.partials.get(hash.bytes)) |partial| {
            return .{ .partial = partial.presentBytes() };
        }
        return .not_found;
    }

    pub fn remove(self: *MemStore, hash: Hash) Error!bool {
        try self.ensureOpen();
        const removed = self.entries.fetchRemove(hash.bytes) orelse return false;
        self.allocator.free(removed.value.data);
        _ = self.metrics_inner.removed.fetchAdd(1, .monotonic);
        return true;
    }

    fn ensureOpen(self: *const MemStore) Error!void {
        if (self.closed) return error.Closed;
    }
};

test "mem store addPathWithProgress emits found/progress/done" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    var store = MemStore.init(alloc);
    defer store.deinit();

    const tmp_root = "zig-cache/tmp-blobs-mem-progress";
    try std.Io.Dir.cwd().createDirPath(io, tmp_root);
    defer std.Io.Dir.cwd().deleteTree(io, tmp_root) catch {};
    const import_path = tmp_root ++ "/raw-progress-import";
    const content = "raw-mem-store-progress";
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = import_path, .data = content });

    const ProgressLog = struct {
        const Event = types.ImportProgress;
        allocator: std.mem.Allocator,
        events: std.ArrayList(Event) = .empty,
        fn callback(ctx: *@This(), event: Event) void {
            ctx.events.append(ctx.allocator, event) catch unreachable;
        }
    };
    var log: ProgressLog = .{ .allocator = alloc };
    defer log.events.deinit(alloc);

    const hash = try store.addPathWithProgress(io, import_path, &log, ProgressLog.callback);
    try std.testing.expect(hash.eql(Hash.of(content)));
    if (log.events.items.len < 3) return error.TestUnexpectedResult;
    switch (log.events.items[0]) {
        .found => |f| try std.testing.expectEqual(@as(u64, content.len), f.size),
        else => return error.TestUnexpectedResult,
    }
    var last_done: u64 = 0;
    for (log.events.items[1 .. log.events.items.len - 1]) |event| {
        switch (event) {
            .progress => |p| {
                try std.testing.expect(p.bytes_done > last_done and p.bytes_done <= content.len);
                last_done = p.bytes_done;
            },
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqual(@as(u64, content.len), last_done);
    switch (log.events.items[log.events.items.len - 1]) {
        .done => |d| try std.testing.expect(d.hash.eql(hash)),
        else => return error.TestUnexpectedResult,
    }
}

test "mem store partialExport/partialImport round-trips and resumes" {
    const alloc = std.testing.allocator;
    const bao = @import("bao.zig");
    const fixtures = @import("fixtures.zig");

    const n: usize = 65_537;
    const data = try fixtures.makeTestData(alloc, n);
    defer alloc.free(data);
    const created = try bao.createOutboard(alloc, data);
    defer alloc.free(created.outboard);

    var store = MemStore.init(alloc);
    defer store.deinit();
    const entry = try store.partialCreate(created.root, n, created.outboard);
    {
        const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 1, 3 } });
        defer alloc.free(wire);
        try entry.insertEncoded(wire, .{ .boundaries = &.{ 1, 3 } });
    }
    const state = try store.partialExport(alloc, created.root);
    defer alloc.free(state);

    var store2 = MemStore.init(alloc);
    defer store2.deinit();
    const imported = try store2.partialImport(state);
    try std.testing.expect(imported.hash.eql(created.root));
    try std.testing.expectEqual(@as(u64, 2), imported.bitfield.countSet());
    {
        const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 0, 1, 3, 65 } });
        defer alloc.free(wire);
        try imported.insertEncoded(wire, .{ .boundaries = &.{ 0, 1, 3, 65 } });
    }
    const complete = try store2.partialComplete(created.root);
    try std.testing.expect(complete.eql(created.root));
    const got = try store2.getBytes(alloc, created.root);
    defer alloc.free(got);
    try std.testing.expectEqualSlices(u8, data, got);
}

test "mem store partial entry lifecycle to complete" {
    const alloc = std.testing.allocator;
    const bao = @import("bao.zig");
    const fixtures = @import("fixtures.zig");

    var store = MemStore.init(alloc);
    defer store.deinit();

    const n: usize = 65_537;
    const data = try fixtures.makeTestData(alloc, n);
    defer alloc.free(data);
    const created = try bao.createOutboard(alloc, data);
    defer alloc.free(created.outboard);

    const entry = try store.partialCreate(created.root, n, created.outboard);
    switch (try store.status(created.root)) {
        .partial => |present| try std.testing.expectEqual(@as(u64, 0), present),
        else => return error.TestUnexpectedResult,
    }

    {
        const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 0, 32 } });
        defer alloc.free(wire);
        try entry.insertEncoded(wire, .{ .boundaries = &.{ 0, 32 } });
    }
    switch (try store.status(created.root)) {
        .partial => |present| try std.testing.expectEqual(@as(u64, 32 * bao.CHUNK_LEN), present),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectError(error.Incomplete, store.partialComplete(created.root));

    {
        const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 32, 65 } });
        defer alloc.free(wire);
        try entry.insertEncoded(wire, .{ .boundaries = &.{ 32, 65 } });
    }
    const complete = try store.partialComplete(created.root);
    try std.testing.expect(complete.eql(created.root));
    try std.testing.expect(store.partialEntry(created.root) == null);

    const got = try store.getBytes(alloc, created.root);
    defer alloc.free(got);
    try std.testing.expectEqualSlices(u8, data, got);
    switch (try store.status(created.root)) {
        .complete => |size| try std.testing.expectEqual(@as(u64, n), size),
        else => return error.TestUnexpectedResult,
    }
}

test "F02 partialCreate replace destroys old PartialEntry shell" {
    const alloc = std.testing.allocator;
    const bao = @import("bao.zig");
    const fixtures = @import("fixtures.zig");

    var store = MemStore.init(alloc);
    defer store.deinit();

    const n: usize = 2048;
    const data = try fixtures.makeTestData(alloc, n);
    defer alloc.free(data);
    const created = try bao.createOutboard(alloc, data);
    defer alloc.free(created.outboard);

    const first = try store.partialCreate(created.root, n, created.outboard);
    try std.testing.expect(store.partialEntry(created.root) == first);
    const second = try store.partialCreate(created.root, n, created.outboard);
    try std.testing.expect(store.partialEntry(created.root) == second);
    try std.testing.expect(first != second);
    // testing allocator leak check on defer store.deinit() is the F02 gate.
}

test "F03 partial{Create,Import} OOM at getOrPut frees entry internals" {
    const alloc = std.testing.allocator;
    const bao = @import("bao.zig");
    const fixtures = @import("fixtures.zig");
    const FailingAllocator = std.testing.FailingAllocator;

    const n: usize = 4096;
    const data = try fixtures.makeTestData(alloc, n);
    defer alloc.free(data);
    const created = try bao.createOutboard(alloc, data);
    defer alloc.free(created.outboard);

    // The F03 leak window is NOT the first OOM. The first allocation to fail
    // aborts *inside* PartialEntry.create (or the shell create), which unwinds
    // its own allocations cleanly — no leak, so a test that stops at the first
    // OOM proves nothing (it passes on pre-fix code). The real window is the
    // narrow one where BOTH the shell create AND PartialEntry.create fully
    // succeed and only the store-map `getOrPut` registration fails. There the
    // pre-fix errdefer destroy'd the shell but never `deinit`'d the entry, so
    // the just-built internals (outboard dup + sparse data buffer + bitfield
    // words) leaked. The fixed errdefer runs `entry.deinit()` first.
    //
    // To land precisely on that window we let every allocation up to and
    // including PartialEntry.create succeed, then fail the very next one (the
    // getOrPut into the still-empty `partials` map). The exact count of
    // pre-getOrPut allocations is computed by replaying shell +
    // PartialEntry.{create,importState} against a counting allocator, so this
    // stays correct if the internal allocation shape ever changes.

    // --- partialCreate registration window ---
    {
        // Count allocations for the shell + PartialEntry.create (no getOrPut).
        var counter = FailingAllocator.init(alloc, .{}); // never fails
        const cnt = counter.allocator();
        const probe = try cnt.create(MemStore.PartialEntry);
        probe.* = try MemStore.PartialEntry.create(cnt, created.root, n, created.outboard);
        const k = counter.alloc_index; // shell + create internals
        probe.deinit();
        cnt.destroy(probe);
        try std.testing.expect(k >= 2); // at least the shell + one internal alloc

        // Fail exactly the getOrPut allocation (0-based index k): indices
        // 0..k-1 (shell + create internals) all succeed, index k fails.
        var fail_state = FailingAllocator.init(alloc, .{ .fail_index = k });
        var store = MemStore.init(fail_state.allocator());
        defer store.deinit();
        try std.testing.expectError(
            error.OutOfMemory,
            store.partialCreate(created.root, n, created.outboard),
        );
        // Prove we hit the intended window and not an earlier abort: the
        // induced failure fired, and exactly k allocations succeeded first
        // (create fully completed). A create-internal abort would leave
        // alloc_index < k.
        try std.testing.expect(fail_state.has_induced_failure);
        try std.testing.expectEqual(k, fail_state.alloc_index);
        // Registration was rolled back — no entry survives in the map.
        try std.testing.expect(store.partialEntry(created.root) == null);
        // The backing std.testing.allocator's leak detector is the F03 gate:
        // pre-fix, the entry internals leak here and this test FAILS.
    }

    // --- partialImport registration window (twin errdefer) ---
    {
        // A valid exported state to import (fresh entry, no chunks present).
        var seed = try MemStore.PartialEntry.create(alloc, created.root, n, created.outboard);
        defer seed.deinit();
        const state = try seed.exportState(alloc);
        defer alloc.free(state);

        var counter = FailingAllocator.init(alloc, .{});
        const cnt = counter.allocator();
        const probe = try cnt.create(MemStore.PartialEntry);
        probe.* = try MemStore.PartialEntry.importState(cnt, state);
        const k = counter.alloc_index;
        probe.deinit();
        cnt.destroy(probe);
        try std.testing.expect(k >= 2);

        var fail_state = FailingAllocator.init(alloc, .{ .fail_index = k });
        var store = MemStore.init(fail_state.allocator());
        defer store.deinit();
        try std.testing.expectError(error.OutOfMemory, store.partialImport(state));
        try std.testing.expect(fail_state.has_induced_failure);
        try std.testing.expectEqual(k, fail_state.alloc_index);
        try std.testing.expect(store.partialEntry(created.root) == null);
    }
}

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
