//! Backend-generic public Blobs API.

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const temp_tag = @import("temp_tag.zig");
const types = @import("types.zig");

pub const BlobStatus = types.BlobStatus;
pub const BlobFormat = types.BlobFormat;
pub const Error = types.Error;

/// A zero-allocation facade over any backend implementing the Store contract.
/// The concrete backend remains visible at comptime while callers use one API.
pub fn Blobs(comptime Backend: type) type {
    return struct {
        backend: *Backend,

        pub fn addBytes(self: @This(), data: []const u8) Error!Hash {
            return self.backend.addBytes(data);
        }

        pub fn getBytes(self: @This(), allocator: std.mem.Allocator, hash: Hash) Error![]u8 {
            return self.backend.getBytes(allocator, hash);
        }

        pub fn addPath(self: @This(), io: std.Io, path: []const u8) Error!Hash {
            return self.backend.addPath(io, path);
        }

        pub fn exportPath(self: @This(), io: std.Io, hash: Hash, path: []const u8) Error!void {
            return self.backend.exportPath(io, hash, path);
        }

        pub fn listHashes(self: @This(), allocator: std.mem.Allocator) Error![]Hash {
            return self.backend.listHashes(allocator);
        }

        pub fn status(self: @This(), hash: Hash) Error!BlobStatus {
            return self.backend.status(hash);
        }

        pub fn remove(self: @This(), hash: Hash) Error!bool {
            return self.backend.remove(hash);
        }

        /// Take a temporary ref-counted GC protection on `hash`.
        pub fn tempTag(self: @This(), hash: Hash, format: BlobFormat) Error!temp_tag.TempTagGuard(Backend) {
            return self.backend.tempTag(hash, format);
        }

        /// Start a batch: blobs added through it stay GC-protected until it
        /// commits or is deinitialized.
        pub fn batch(self: @This()) temp_tag.Batch(Backend) {
            return self.backend.batch();
        }

        /// Import a file, streaming `ImportProgress` events to `on_event`.
        pub fn addPathWithProgress(
            self: @This(),
            io: std.Io,
            path: []const u8,
            context: anytype,
            on_event: *const fn (@TypeOf(context), types.ImportProgress) void,
        ) Error!Hash {
            return self.backend.addPathWithProgress(io, path, context, on_event);
        }

        /// Open a seekable reader over a complete blob. The concrete reader
        /// type is the backend's (`Backend.Reader`).
        pub fn openReader(self: @This(), allocator: std.mem.Allocator, hash: Hash) Error!Backend.Reader {
            return self.backend.openReader(allocator, hash);
        }

        /// Create an empty partial entry for an in-flight download.
        pub fn partialCreate(self: @This(), hash: Hash, size: u64, outboard: []const u8) Error!*Backend.PartialEntry {
            return self.backend.partialCreate(hash, size, outboard);
        }

        /// Import serialized partial state (verified on parse).
        pub fn partialImport(self: @This(), state: []const u8) Error!*Backend.PartialEntry {
            return self.backend.partialImport(state);
        }

        /// Export the partial state for a hash (transfer/resume).
        pub fn partialExport(self: @This(), allocator: std.mem.Allocator, hash: Hash) Error![]u8 {
            return self.backend.partialExport(allocator, hash);
        }

        /// Partial-to-complete transition (requires a complete entry).
        pub fn partialComplete(self: @This(), hash: Hash) Error!Hash {
            return self.backend.partialComplete(hash);
        }
    };
}

const ProgressLog = struct {
    const Event = types.ImportProgress;
    allocator: std.mem.Allocator,
    events: std.ArrayList(Event) = .empty,

    fn append(self: *ProgressLog, event: Event) void {
        self.events.append(self.allocator, event) catch unreachable;
    }

    fn callback(ctx: *ProgressLog, event: Event) void {
        ctx.append(event);
    }
};

test "facade import progress streams found/progress/done and reader seeks" {
    const MemStore = @import("store.zig").MemStore;
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var store = MemStore.init(alloc);
    defer store.deinit();
    const blobs = store.blobs();

    const tmp_root = "zig-cache/tmp-blobs-api-progress";
    try std.Io.Dir.cwd().createDirPath(io, tmp_root);
    defer std.Io.Dir.cwd().deleteTree(io, tmp_root) catch {};
    const import_path = tmp_root ++ "/progress-import";
    const content = "progress-streamed-content";
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = import_path, .data = content });

    var log: ProgressLog = .{ .allocator = alloc };
    defer log.events.deinit(alloc);
    const hash = try blobs.addPathWithProgress(io, import_path, &log, ProgressLog.callback);
    if (!hash.eql(Hash.of(content))) return error.HashMismatch;

    // found(size) first, done(hash) last, progress monotonic in between.
    if (log.events.items.len < 3) return error.TestUnexpectedResult;
    switch (log.events.items[0]) {
        .found => |f| if (f.size != content.len) return error.TestUnexpectedResult,
        else => return error.TestUnexpectedResult,
    }
    var last_done: u64 = 0;
    for (log.events.items[1 .. log.events.items.len - 1]) |event| {
        switch (event) {
            .progress => |p| {
                if (p.bytes_done <= last_done or p.bytes_done > content.len) return error.TestUnexpectedResult;
                last_done = p.bytes_done;
            },
            else => return error.TestUnexpectedResult,
        }
    }
    if (last_done != content.len) return error.TestUnexpectedResult;
    switch (log.events.items[log.events.items.len - 1]) {
        .done => |d| if (!d.hash.eql(hash)) return error.TestUnexpectedResult,
        else => return error.TestUnexpectedResult,
    }

    // Facade reader over the imported blob.
    var reader = try blobs.openReader(alloc, hash);
    defer reader.close();
    try reader.seekTo(9);
    const tail = try reader.readToEnd(alloc);
    defer alloc.free(tail);
    try std.testing.expectEqualStrings("streamed-content", tail);
}

test "facade temp tag and batch delegate to the backend" {
    const MemStore = @import("store.zig").MemStore;
    const alloc = std.testing.allocator;
    var store = MemStore.init(alloc);
    defer store.deinit();
    const blobs = store.blobs();

    const hash = try blobs.addBytes("facade-protected");
    var guard = try blobs.tempTag(hash, .raw);
    try std.testing.expectEqual(@as(usize, 1), store.tempTagCount());
    guard.release();
    try std.testing.expectEqual(@as(usize, 0), store.tempTagCount());

    var b = blobs.batch();
    _ = try b.addBytes("facade-batch");
    try std.testing.expectEqual(@as(usize, 1), store.tempTagCount());
    const committed = try b.commit();
    defer alloc.free(committed);
    b.deinit();
    try std.testing.expectEqual(@as(usize, 1), committed.len);
}

test "facade-over-Fs temp tag, batch, and import progress" {
    const FsStore = @import("fs_store.zig").FsStore;
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const root = try std.fmt.allocPrint(alloc, "zig-cache/tmp/blobs-api-fs-facade-{d}", .{nonce});
    defer alloc.free(root);
    defer std.Io.Dir.cwd().deleteTree(io, root) catch {};

    var store = try FsStore.open(alloc, io, root);
    defer store.deinit();
    const blobs = store.blobs();

    const hash = try blobs.addBytes("fs-facade-protected");
    var guard = try blobs.tempTag(hash, .raw);
    try std.testing.expectEqual(@as(usize, 1), store.tempTagCount());
    guard.release();
    try std.testing.expectEqual(@as(usize, 0), store.tempTagCount());

    var b = blobs.batch();
    _ = try b.addBytes("fs-facade-batch");
    try std.testing.expectEqual(@as(usize, 1), store.tempTagCount());
    const committed = try b.commit();
    defer alloc.free(committed);
    b.deinit();
    try std.testing.expectEqual(@as(usize, 1), committed.len);
    try std.testing.expectEqual(@as(usize, 0), store.tempTagCount());

    const import_path = try std.fmt.allocPrint(alloc, "{s}/progress-import", .{root});
    defer alloc.free(import_path);
    const content = "fs-facade-progress-content";
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = import_path, .data = content });

    var log: ProgressLog = .{ .allocator = alloc };
    defer log.events.deinit(alloc);
    const progress_hash = try blobs.addPathWithProgress(io, import_path, &log, ProgressLog.callback);
    if (!progress_hash.eql(Hash.of(content))) return error.HashMismatch;
    if (log.events.items.len < 3) return error.TestUnexpectedResult;
    switch (log.events.items[0]) {
        .found => |f| if (f.size != content.len) return error.TestUnexpectedResult,
        else => return error.TestUnexpectedResult,
    }
    var last_done: u64 = 0;
    for (log.events.items[1 .. log.events.items.len - 1]) |event| {
        switch (event) {
            .progress => |p| {
                if (p.bytes_done <= last_done or p.bytes_done > content.len) return error.TestUnexpectedResult;
                last_done = p.bytes_done;
            },
            else => return error.TestUnexpectedResult,
        }
    }
    if (last_done != content.len) return error.TestUnexpectedResult;
    switch (log.events.items[log.events.items.len - 1]) {
        .done => |d| if (!d.hash.eql(progress_hash)) return error.TestUnexpectedResult,
        else => return error.TestUnexpectedResult,
    }
}

test "facade partialExport/partialImport round-trips on MemStore and FsStore" {
    const MemStore = @import("store.zig").MemStore;
    const FsStore = @import("fs_store.zig").FsStore;
    const bao = @import("bao.zig");
    const fixtures = @import("fixtures.zig");
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    const n: usize = 65_537;
    const data = try fixtures.makeTestData(alloc, n);
    defer alloc.free(data);
    const created = try bao.createOutboard(alloc, data);
    defer alloc.free(created.outboard);

    // MemStore via public Blobs facade.
    {
        var store = MemStore.init(alloc);
        defer store.deinit();
        const blobs = store.blobs();
        const entry = try blobs.partialCreate(created.root, n, created.outboard);
        {
            const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 1, 3 } });
            defer alloc.free(wire);
            try entry.insertEncoded(wire, .{ .boundaries = &.{ 1, 3 } });
        }
        const state = try blobs.partialExport(alloc, created.root);
        defer alloc.free(state);

        var store2 = MemStore.init(alloc);
        defer store2.deinit();
        const blobs2 = store2.blobs();
        const imported = try blobs2.partialImport(state);
        try std.testing.expectEqual(@as(u64, 2), imported.bitfield.countSet());
        {
            const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 0, 1, 3, 65 } });
            defer alloc.free(wire);
            try imported.insertEncoded(wire, .{ .boundaries = &.{ 0, 1, 3, 65 } });
        }
        const complete = try blobs2.partialComplete(created.root);
        try std.testing.expect(complete.eql(created.root));
        const got = try blobs2.getBytes(alloc, created.root);
        defer alloc.free(got);
        try std.testing.expectEqualSlices(u8, data, got);
    }

    // FsStore via public Blobs facade (export -> import on a fresh root).
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const root_a = try std.fmt.allocPrint(alloc, "zig-cache/tmp/blobs-api-fs-partial-a-{d}", .{nonce});
    defer alloc.free(root_a);
    defer std.Io.Dir.cwd().deleteTree(io, root_a) catch {};
    const root_b = try std.fmt.allocPrint(alloc, "zig-cache/tmp/blobs-api-fs-partial-b-{d}", .{nonce});
    defer alloc.free(root_b);
    defer std.Io.Dir.cwd().deleteTree(io, root_b) catch {};

    const state = blk: {
        var store = try FsStore.open(alloc, io, root_a);
        defer store.deinit();
        const blobs = store.blobs();
        const entry = try blobs.partialCreate(created.root, n, created.outboard);
        {
            const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 1, 3 } });
            defer alloc.free(wire);
            try entry.insertEncoded(wire, .{ .boundaries = &.{ 1, 3 } });
        }
        try store.partialPersist(created.root);
        break :blk try blobs.partialExport(alloc, created.root);
    };
    defer alloc.free(state);

    {
        var store = try FsStore.open(alloc, io, root_b);
        defer store.deinit();
        const blobs = store.blobs();
        const imported = try blobs.partialImport(state);
        try std.testing.expectEqual(@as(u64, 2), imported.bitfield.countSet());
        {
            const wire = try bao.encodeRanges(alloc, data, .{ .boundaries = &.{ 0, 1, 3, 65 } });
            defer alloc.free(wire);
            try imported.insertEncoded(wire, .{ .boundaries = &.{ 0, 1, 3, 65 } });
        }
        const complete = try blobs.partialComplete(created.root);
        try std.testing.expect(complete.eql(created.root));
        const got = try blobs.getBytes(alloc, created.root);
        defer alloc.free(got);
        try std.testing.expectEqualSlices(u8, data, got);
    }
}
