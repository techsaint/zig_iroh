//! Durable filesystem blob store.
//!
//! Complete blobs are content-addressed files published atomically. Named tags
//! use a small versioned manifest committed on `sync`/`shutdown`. This is a
//! Zig-native persistence backend; redb's private table layout is not part of
//! the peer-observable contract.

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
pub const BlobStatus = types.BlobStatus;
pub const Error = types.Error;
pub const TempTagGuard = temp_tag.TempTagGuard(FsStore);
pub const Batch = temp_tag.Batch(FsStore);
pub const GcOutcome = gc_mod.GcOutcome;

const tags_magic = "ZBTS1";
const max_tags_manifest = 16 * 1024 * 1024;

pub const TempTagEntry = struct {
    count: u64,
    format: BlobFormat,
};

const TempTagMap = std.AutoHashMapUnmanaged([32]u8, TempTagEntry);

pub const FsStore = struct {
    pub const Reader = reader_mod.FsReader;
    pub const PartialEntry = partial_mod.PartialEntry;

    allocator: std.mem.Allocator,
    io: std.Io,
    root_path: []u8,
    blobs_path: []u8,
    tags_path: []u8,
    partial_path: []u8,
    tags_inner: Tags,
    partials: std.AutoHashMapUnmanaged([32]u8, *PartialEntry) = .empty,
    temp_tags: TempTagMap = .empty,
    metrics_inner: metrics_mod.Metrics = .{},
    closed: bool = false,

    pub fn open(allocator: std.mem.Allocator, io: std.Io, root_path: []const u8) Error!FsStore {
        const owned_root = allocator.dupe(u8, root_path) catch return error.OutOfMemory;
        errdefer allocator.free(owned_root);
        const blobs_path = std.fmt.allocPrint(allocator, "{s}/blobs", .{root_path}) catch return error.OutOfMemory;
        errdefer allocator.free(blobs_path);
        const tags_path = std.fmt.allocPrint(allocator, "{s}/tags.bin", .{root_path}) catch return error.OutOfMemory;
        errdefer allocator.free(tags_path);
        const partial_path = std.fmt.allocPrint(allocator, "{s}/partial", .{root_path}) catch return error.OutOfMemory;
        errdefer allocator.free(partial_path);

        std.Io.Dir.cwd().createDirPath(io, root_path) catch return error.Io;
        std.Io.Dir.cwd().createDirPath(io, blobs_path) catch return error.Io;
        std.Io.Dir.cwd().createDirPath(io, partial_path) catch return error.Io;

        var tags_inner = Tags.init(allocator);
        errdefer tags_inner.deinit();
        var store: FsStore = .{
            .allocator = allocator,
            .io = io,
            .root_path = owned_root,
            .blobs_path = blobs_path,
            .tags_path = tags_path,
            .partial_path = partial_path,
            .tags_inner = tags_inner,
        };
        try store.loadTags();
        try store.loadPartials();
        return store;
    }

    pub fn deinit(self: *FsStore) void {
        var pit = self.partials.iterator();
        while (pit.next()) |e| {
            e.value_ptr.*.deinit();
            self.allocator.destroy(e.value_ptr.*);
        }
        self.partials.deinit(self.allocator);
        self.temp_tags.deinit(self.allocator);
        self.tags_inner.deinit();
        self.allocator.free(self.partial_path);
        self.allocator.free(self.tags_path);
        self.allocator.free(self.blobs_path);
        self.allocator.free(self.root_path);
        self.* = undefined;
    }

    pub fn blobs(self: *FsStore) api.Blobs(FsStore) {
        return .{ .backend = self };
    }

    pub fn tags(self: *FsStore) *Tags {
        return &self.tags_inner;
    }

    pub fn metrics(self: *const FsStore) metrics_mod.Snapshot {
        return self.metrics_inner.snapshot();
    }

    /// Take a temporary ref-counted protection on `hash`. Temporary tags are
    /// in-memory only (a restart drops them), matching the reachability model
    /// where durable protection is the named-tag manifest.
    /// Format is the OR of all live pins: any `.hash_seq` pin promotes the
    /// entry so GC expands children for the whole remaining lifetime (F25).
    pub fn tempTag(self: *FsStore, hash: Hash, format: BlobFormat) Error!TempTagGuard {
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

    pub fn releaseTempTag(self: *FsStore, hash: Hash) void {
        const entry = self.temp_tags.getPtr(hash.bytes) orelse return;
        entry.count -= 1;
        if (entry.count == 0) _ = self.temp_tags.remove(hash.bytes);
    }

    /// The number of distinct hashes currently temp-tagged (GC introspection).
    pub fn tempTagCount(self: *const FsStore) usize {
        return self.temp_tags.count();
    }

    pub fn tempTagEntries(self: *FsStore) TempTagMap.Iterator {
        return self.temp_tags.iterator();
    }

    /// Start a batch: every blob added through it is temp-tag protected until
    /// the batch commits or is deinitialized.
    pub fn batch(self: *FsStore) Batch {
        return .{ .store = self };
    }

    /// Run one tag-aware GC round over the durable store.
    pub fn gc(self: *FsStore) Error!GcOutcome {
        try self.ensureOpen();
        return gc_mod.gcRun(FsStore, self, self.allocator);
    }

    pub fn waitIdle(self: *FsStore) Error!void {
        try self.ensureOpen();
    }

    pub fn sync(self: *FsStore) Error!void {
        try self.ensureOpen();
        try self.persistTags();
        try self.persistPartials();
    }

    pub fn shutdown(self: *FsStore) Error!void {
        if (self.closed) return;
        try self.persistTags();
        try self.persistPartials();
        self.closed = true;
    }

    pub fn addBytes(self: *FsStore, data: []const u8) Error!Hash {
        try self.ensureOpen();
        const hash = Hash.of(data);
        const path = try self.blobPath(hash);
        defer self.allocator.free(path);
        try self.writeAtomic(path, data);
        self.metrics_inner.recordAdd(data.len);
        return hash;
    }

    pub fn getBytes(self: *FsStore, allocator: std.mem.Allocator, hash: Hash) Error![]u8 {
        try self.ensureOpen();
        const path = try self.blobPath(hash);
        defer self.allocator.free(path);
        const data = readFileAlloc(allocator, self.io, path) catch |err| {
            if (err == error.NotFound) _ = self.metrics_inner.not_found.fetchAdd(1, .monotonic);
            return err;
        };
        errdefer allocator.free(data);
        if (!Hash.of(data).eql(hash)) {
            _ = self.metrics_inner.integrity_errors.fetchAdd(1, .monotonic);
            return error.HashMismatch;
        }
        self.metrics_inner.recordGet(data.len);
        return data;
    }

    pub fn addPath(self: *FsStore, io: std.Io, path: []const u8) Error!Hash {
        try self.ensureOpen();
        const data = try readFileAlloc(self.allocator, io, path);
        defer self.allocator.free(data);
        return self.addBytes(data);
    }

    /// Import a file, streaming `ImportProgress` events to `on_event` as
    /// bytes land. `context` is passed through unchanged on every event.
    pub fn addPathWithProgress(
        self: *FsStore,
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

    /// Open a seekable reader over a complete blob. The content is verified
    /// against the content-addressed hash at open; reads stream from the
    /// durable file via positional reads.
    pub fn openReader(self: *FsStore, allocator: std.mem.Allocator, hash: Hash) Error!reader_mod.FsReader {
        try self.ensureOpen();
        const path = try self.blobPath(hash);
        defer self.allocator.free(path);
        const data = readFileAlloc(allocator, self.io, path) catch |err| {
            if (err == error.NotFound) _ = self.metrics_inner.not_found.fetchAdd(1, .monotonic);
            return err;
        };
        defer allocator.free(data);
        if (!Hash.of(data).eql(hash)) {
            _ = self.metrics_inner.integrity_errors.fetchAdd(1, .monotonic);
            return error.HashMismatch;
        }
        const file = std.Io.Dir.cwd().openFile(self.io, path, .{}) catch return error.Io;
        return .{
            .allocator = allocator,
            .io = self.io,
            .file = file,
            .blob_size = data.len,
            .pos = 0,
        };
    }

    pub fn exportPath(self: *FsStore, io: std.Io, hash: Hash, path: []const u8) Error!void {
        const data = try self.getBytes(self.allocator, hash);
        defer self.allocator.free(data);
        const file = std.Io.Dir.cwd().createFile(io, path, .{}) catch return error.Io;
        defer file.close(io);
        var writer_buffer: [4096]u8 = undefined;
        var writer = file.writer(io, &writer_buffer);
        writer.interface.writeAll(data) catch return error.Io;
        writer.interface.flush() catch return error.Io;
    }

    pub fn listHashes(self: *FsStore, allocator: std.mem.Allocator) Error![]Hash {
        try self.ensureOpen();
        var dir = std.Io.Dir.cwd().openDir(self.io, self.blobs_path, .{ .iterate = true }) catch return error.Io;
        defer dir.close(self.io);

        var hashes: std.ArrayList(Hash) = .empty;
        errdefer hashes.deinit(allocator);
        var iterator = dir.iterate();
        while (iterator.next(self.io) catch return error.Io) |entry| {
            if (entry.kind != .file or entry.name.len != 64) continue;
            const hash = Hash.fromHex(entry.name) catch continue;
            hashes.append(allocator, hash) catch return error.OutOfMemory;
        }
        return hashes.toOwnedSlice(allocator) catch return error.OutOfMemory;
    }

    pub fn status(self: *FsStore, hash: Hash) Error!BlobStatus {
        try self.ensureOpen();
        const path = try self.blobPath(hash);
        defer self.allocator.free(path);
        const stat = std.Io.Dir.cwd().statFile(self.io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                if (self.partials.get(hash.bytes)) |partial| {
                    return .{ .partial = partial.presentBytes() };
                }
                return .not_found;
            },
            else => return error.Io,
        };
        return .{ .complete = stat.size };
    }

    pub fn remove(self: *FsStore, hash: Hash) Error!bool {
        try self.ensureOpen();
        const path = try self.blobPath(hash);
        defer self.allocator.free(path);
        std.Io.Dir.cwd().deleteFile(self.io, path) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return error.Io,
        };
        _ = self.metrics_inner.removed.fetchAdd(1, .monotonic);
        return true;
    }

    /// Create an empty partial entry for an in-flight download and persist it.
    pub fn partialCreate(self: *FsStore, hash: Hash, size: u64, outboard: []const u8) Error!*PartialEntry {
        try self.ensureOpen();
        const entry = self.allocator.create(PartialEntry) catch return error.OutOfMemory;
        // Ownership phases: shell-only → internals live → map owns entry.
        // After map install, persist failure must remove from the map (not just
        // free) so deinit cannot double-free.
        var phase: enum { shell, internals, mapped } = .shell;
        errdefer switch (phase) {
            .shell => self.allocator.destroy(entry),
            .internals => {
                entry.deinit();
                self.allocator.destroy(entry);
            },
            .mapped => {
                _ = self.partials.fetchRemove(hash.bytes);
                entry.deinit();
                self.allocator.destroy(entry);
            },
        };
        entry.* = try PartialEntry.create(self.allocator, hash, size, outboard);
        phase = .internals;
        const gop = self.partials.getOrPut(self.allocator, hash.bytes) catch return error.OutOfMemory;
        if (gop.found_existing) {
            gop.value_ptr.*.deinit();
            self.allocator.destroy(gop.value_ptr.*);
        }
        gop.value_ptr.* = entry;
        phase = .mapped;
        try self.persistPartial(entry);
        return entry;
    }

    /// Import serialized partial state (verified on parse) and persist it,
    /// replacing any existing entry for the same hash.
    pub fn partialImport(self: *FsStore, state: []const u8) Error!*PartialEntry {
        try self.ensureOpen();
        const entry = self.allocator.create(PartialEntry) catch return error.OutOfMemory;
        var phase: enum { shell, internals, mapped } = .shell;
        errdefer switch (phase) {
            .shell => self.allocator.destroy(entry),
            .internals => {
                entry.deinit();
                self.allocator.destroy(entry);
            },
            .mapped => {
                _ = self.partials.fetchRemove(entry.hash.bytes);
                entry.deinit();
                self.allocator.destroy(entry);
            },
        };
        entry.* = try PartialEntry.importState(self.allocator, state);
        phase = .internals;
        const gop = self.partials.getOrPut(self.allocator, entry.hash.bytes) catch return error.OutOfMemory;
        if (gop.found_existing) {
            gop.value_ptr.*.deinit();
            self.allocator.destroy(gop.value_ptr.*);
        }
        gop.value_ptr.* = entry;
        phase = .mapped;
        try self.persistPartial(entry);
        return entry;
    }

    pub fn partialEntry(self: *FsStore, hash: Hash) ?*PartialEntry {
        return self.partials.get(hash.bytes);
    }

    /// Export the partial state for a hash (transfer/resume).
    pub fn partialExport(self: *FsStore, allocator: std.mem.Allocator, hash: Hash) Error![]u8 {
        try self.ensureOpen();
        const entry = self.partials.get(hash.bytes) orelse return error.NotFound;
        return entry.exportState(allocator);
    }

    /// Persist one partial entry's current state to its durable file. Call
    /// after mutating an entry obtained from `partialEntry` (inserts are
    /// made on the entry directly); `sync`/`shutdown` persist all entries.
    pub fn partialPersist(self: *FsStore, hash: Hash) Error!void {
        try self.ensureOpen();
        const entry = self.partials.get(hash.bytes) orelse return error.NotFound;
        try self.persistPartial(entry);
    }

    /// Partial-to-complete transition: requires the entry to be complete,
    /// re-checks the full content hash, atomically publishes the blob, and
    /// deletes the durable partial state.
    pub fn partialComplete(self: *FsStore, hash: Hash) Error!Hash {
        try self.ensureOpen();
        const entry = self.partials.get(hash.bytes) orelse return error.NotFound;
        const data = try entry.finish(self.allocator);
        defer self.allocator.free(data);
        const complete = try self.addBytes(data);
        try self.destroyPartial(hash);
        return complete;
    }

    /// GC hook: reclaim partial entries with no protection (state files too).
    pub fn sweepUnprotectedPartials(self: *FsStore, protect: *const gc_mod.ProtectSet) Error!u64 {
        var doomed: std.ArrayList([32]u8) = .empty;
        defer doomed.deinit(self.allocator);
        var it = self.partials.iterator();
        while (it.next()) |e| {
            if (!protect.contains(e.key_ptr.*)) {
                doomed.append(self.allocator, e.key_ptr.*) catch return error.OutOfMemory;
            }
        }
        for (doomed.items) |key| try self.destroyPartial(Hash.fromBytes(key));
        return @intCast(doomed.items.len);
    }

    fn ensureOpen(self: *const FsStore) Error!void {
        if (self.closed) return error.Closed;
    }

    fn blobPath(self: *const FsStore, hash: Hash) Error![]u8 {
        const hex = hash.toHex();
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.blobs_path, &hex }) catch error.OutOfMemory;
    }

    fn partialStatePath(self: *const FsStore, hash: Hash) Error![]u8 {
        const hex = hash.toHex();
        return std.fmt.allocPrint(self.allocator, "{s}/{s}.state", .{ self.partial_path, &hex }) catch error.OutOfMemory;
    }

    fn persistPartial(self: *FsStore, entry: *PartialEntry) Error!void {
        const state = try entry.exportState(self.allocator);
        defer self.allocator.free(state);
        const path = try self.partialStatePath(entry.hash);
        defer self.allocator.free(path);
        try self.writeAtomic(path, state);
    }

    fn persistPartials(self: *FsStore) Error!void {
        var it = self.partials.iterator();
        while (it.next()) |e| try self.persistPartial(e.value_ptr.*);
    }

    /// Reconstruct durable partial entries on open. Each state file is
    /// re-verified during import; a corrupt file is counted as an integrity
    /// error and removed so it cannot poison later opens.
    fn loadPartials(self: *FsStore) Error!void {
        var dir = std.Io.Dir.cwd().openDir(self.io, self.partial_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return error.Io,
        };
        defer dir.close(self.io);
        var iterator = dir.iterate();
        while (iterator.next(self.io) catch return error.Io) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".state")) continue;
            const path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.partial_path, entry.name }) catch
                return error.OutOfMemory;
            defer self.allocator.free(path);
            const state = std.Io.Dir.cwd().readFileAlloc(self.io, path, self.allocator, .limited(64 * 1024 * 1024)) catch
                continue;
            defer self.allocator.free(state);
            const parsed = PartialEntry.importState(self.allocator, state) catch {
                _ = self.metrics_inner.integrity_errors.fetchAdd(1, .monotonic);
                std.Io.Dir.cwd().deleteFile(self.io, path) catch {};
                continue;
            };
            const slot = self.allocator.create(PartialEntry) catch {
                var p = parsed;
                p.deinit();
                return error.OutOfMemory;
            };
            slot.* = parsed;
            const gop = self.partials.getOrPut(self.allocator, parsed.hash.bytes) catch {
                slot.deinit();
                self.allocator.destroy(slot);
                return error.OutOfMemory;
            };
            if (gop.found_existing) {
                gop.value_ptr.*.deinit();
                self.allocator.destroy(gop.value_ptr.*);
            }
            gop.value_ptr.* = slot;
        }
    }

    fn destroyPartial(self: *FsStore, hash: Hash) Error!void {
        const path = try self.partialStatePath(hash);
        defer self.allocator.free(path);
        std.Io.Dir.cwd().deleteFile(self.io, path) catch {};
        const entry = self.partials.fetchRemove(hash.bytes) orelse return;
        entry.value.deinit();
        self.allocator.destroy(entry.value);
    }

    fn writeAtomic(self: *FsStore, path: []const u8, data: []const u8) Error!void {
        var atomic_file = std.Io.Dir.cwd().createFileAtomic(self.io, path, .{
            .make_path = true,
            .replace = true,
        }) catch return error.Io;
        defer atomic_file.deinit(self.io);

        var writer_buffer: [4096]u8 = undefined;
        var writer = atomic_file.file.writer(self.io, &writer_buffer);
        writer.interface.writeAll(data) catch return error.Io;
        writer.interface.flush() catch return error.Io;
        atomic_file.file.sync(self.io) catch return error.Io;
        atomic_file.replace(self.io) catch return error.Io;
    }

    fn persistTags(self: *FsStore) Error!void {
        const entries = try self.tags_inner.list(self.allocator);
        defer freeTagInfos(self.allocator, entries);
        if (entries.len > std.math.maxInt(u32)) return error.CorruptStore;

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        encoded.appendSlice(self.allocator, tags_magic) catch return error.OutOfMemory;
        try appendU32(&encoded, self.allocator, @intCast(entries.len));
        for (entries) |entry| {
            if (entry.name.len > std.math.maxInt(u32)) return error.CorruptStore;
            try appendU32(&encoded, self.allocator, @intCast(entry.name.len));
            encoded.appendSlice(self.allocator, entry.name) catch return error.OutOfMemory;
            encoded.append(self.allocator, @intFromEnum(entry.format)) catch return error.OutOfMemory;
            encoded.appendSlice(self.allocator, &entry.hash.bytes) catch return error.OutOfMemory;
        }
        if (encoded.items.len > max_tags_manifest) return error.CorruptStore;
        try self.writeAtomic(self.tags_path, encoded.items);
    }

    fn loadTags(self: *FsStore) Error!void {
        const encoded = std.Io.Dir.cwd().readFileAlloc(
            self.io,
            self.tags_path,
            self.allocator,
            .limited(max_tags_manifest),
        ) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return error.Io,
        };
        defer self.allocator.free(encoded);
        if (encoded.len < tags_magic.len + 4 or !std.mem.eql(u8, encoded[0..tags_magic.len], tags_magic))
            return error.CorruptStore;

        var offset: usize = tags_magic.len;
        const count = try takeU32(encoded, &offset);
        for (0..count) |_| {
            const name_len = try takeU32(encoded, &offset);
            const name_end = std.math.add(usize, offset, name_len) catch return error.CorruptStore;
            if (name_end + 1 + 32 > encoded.len) return error.CorruptStore;
            const name = encoded[offset..name_end];
            offset = name_end;
            const format: BlobFormat = switch (encoded[offset]) {
                0 => .raw,
                1 => .hash_seq,
                else => return error.CorruptStore,
            };
            offset += 1;
            var hash_bytes: [32]u8 = undefined;
            @memcpy(&hash_bytes, encoded[offset .. offset + 32]);
            offset += 32;
            try self.tags_inner.set(name, .{ .hash = .fromBytes(hash_bytes), .format = format });
        }
        if (offset != encoded.len) return error.CorruptStore;
    }
};

fn readFileAlloc(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error![]u8 {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.NotFound,
        else => return error.Io,
    };
    defer file.close(io);
    const stat = file.stat(io) catch return error.Io;
    const size = std.math.cast(usize, stat.size) orelse return error.Io;
    const data = allocator.alloc(u8, size) catch return error.OutOfMemory;
    errdefer allocator.free(data);
    var reader_buffer: [4096]u8 = undefined;
    var reader = file.reader(io, &reader_buffer);
    reader.interface.readSliceAll(data) catch return error.Io;
    return data;
}

fn appendU32(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) Error!void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    out.appendSlice(allocator, &bytes) catch return error.OutOfMemory;
}

fn takeU32(encoded: []const u8, offset: *usize) Error!u32 {
    if (offset.* + 4 > encoded.len) return error.CorruptStore;
    const value = std.mem.readInt(u32, encoded[offset.*..][0..4], .little);
    offset.* += 4;
    return value;
}

fn freeTagInfos(allocator: std.mem.Allocator, entries: []types.TagInfo) void {
    for (entries) |entry| entry.deinit(allocator);
    allocator.free(entries);
}

test "FsStore persists complete blobs and named tags across reopen" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const path = try std.fmt.allocPrint(allocator, "zig-cache/tmp/blobs-fs-store-{d}", .{nonce});
    defer allocator.free(path);
    defer std.Io.Dir.cwd().deleteTree(io, path) catch {};

    const data = "durable blob bytes";
    const hash = Hash.of(data);
    {
        var store = try FsStore.open(allocator, io, path);
        defer store.deinit();
        const blobs_api = store.blobs();
        try std.testing.expect((try blobs_api.addBytes(data)).eql(hash));
        try store.tags().setRaw("pinned", hash);
        try store.shutdown();
    }
    {
        var store = try FsStore.open(allocator, io, path);
        defer store.deinit();
        const blobs_api = store.blobs();
        switch (try blobs_api.status(hash)) {
            .complete => |size| try std.testing.expectEqual(@as(u64, data.len), size),
            else => return error.TestUnexpectedResult,
        }
        const actual = try blobs_api.getBytes(allocator, hash);
        defer allocator.free(actual);
        try std.testing.expectEqualStrings(data, actual);
        const tag = store.tags().get("pinned") orelse return error.TestUnexpectedResult;
        try std.testing.expect(tag.hash.eql(hash));
    }
}

test "FsStore gc reclaims untagged content files and keeps tagged ones" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const path = try std.fmt.allocPrint(allocator, "zig-cache/tmp/blobs-fs-gc-{d}", .{nonce});
    defer allocator.free(path);
    defer std.Io.Dir.cwd().deleteTree(io, path) catch {};

    var store = try FsStore.open(allocator, io, path);
    defer store.deinit();

    const kept_hash = try store.addBytes("kept-on-disk");
    const garbage_hash = try store.addBytes("garbage-on-disk");
    try store.tags().setRaw("kept", kept_hash);

    const outcome = try store.gc();
    try std.testing.expectEqual(@as(u64, 1), outcome.kept);
    try std.testing.expectEqual(@as(u64, 1), outcome.reclaimed);

    // The reclaimed content file is actually gone from the blobs directory.
    const hex = garbage_hash.toHex();
    const blob_path = try std.fmt.allocPrint(allocator, "{s}/blobs/{s}", .{ path, &hex });
    defer allocator.free(blob_path);
    const stat = std.Io.Dir.cwd().statFile(io, blob_path, .{});
    try std.testing.expectError(error.FileNotFound, stat);

    const kept = try store.getBytes(allocator, kept_hash);
    defer allocator.free(kept);
    try std.testing.expectEqualStrings("kept-on-disk", kept);
}

test "FsStore durable partial entry survives reopen and completes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const bao = @import("bao.zig");
    const fixtures = @import("fixtures.zig");
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const path = try std.fmt.allocPrint(allocator, "zig-cache/tmp/blobs-fs-partial-{d}", .{nonce});
    defer allocator.free(path);
    defer std.Io.Dir.cwd().deleteTree(io, path) catch {};

    const n: usize = 65_537;
    const data = try fixtures.makeTestData(allocator, n);
    defer allocator.free(data);
    const created = try bao.createOutboard(allocator, data);
    defer allocator.free(created.outboard);

    // First session: create the partial, insert half, persist, shut down.
    {
        var store = try FsStore.open(allocator, io, path);
        defer store.deinit();
        const entry = try store.partialCreate(created.root, n, created.outboard);
        const wire = try bao.encodeRanges(allocator, data, .{ .boundaries = &.{ 0, 32 } });
        defer allocator.free(wire);
        try entry.insertEncoded(wire, .{ .boundaries = &.{ 0, 32 } });
        try store.partialPersist(created.root);
        try store.shutdown();
    }

    // Second session: the partial reconstructs from disk and resumes.
    {
        var store = try FsStore.open(allocator, io, path);
        defer store.deinit();
        const entry = store.partialEntry(created.root) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(u64, 32), entry.bitfield.countSet());
        switch (try store.status(created.root)) {
            .partial => |present| try std.testing.expectEqual(@as(u64, 32 * bao.CHUNK_LEN), present),
            else => return error.TestUnexpectedResult,
        }

        const wire = try bao.encodeRanges(allocator, data, .{ .boundaries = &.{ 32, 65 } });
        defer allocator.free(wire);
        try entry.insertEncoded(wire, .{ .boundaries = &.{ 32, 65 } });

        const complete = try store.partialComplete(created.root);
        try std.testing.expect(complete.eql(created.root));
        try std.testing.expect(store.partialEntry(created.root) == null);

        const got = try store.getBytes(allocator, created.root);
        defer allocator.free(got);
        try std.testing.expectEqualSlices(u8, data, got);
    }

    // Third session: the completed blob persisted; no partial remains.
    {
        var store = try FsStore.open(allocator, io, path);
        defer store.deinit();
        try std.testing.expect(store.partialEntry(created.root) == null);
        const got = try store.getBytes(allocator, created.root);
        defer allocator.free(got);
        try std.testing.expectEqualSlices(u8, data, got);
    }
}

test "FsStore rejects corrupted content-addressed data" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const path = try std.fmt.allocPrint(allocator, "zig-cache/tmp/blobs-fs-corrupt-{d}", .{nonce});
    defer allocator.free(path);
    defer std.Io.Dir.cwd().deleteTree(io, path) catch {};

    const hash = Hash.of("original");
    {
        var store = try FsStore.open(allocator, io, path);
        defer store.deinit();
        _ = try store.addBytes("original");
        try store.shutdown();
    }
    const hex = hash.toHex();
    const blob_path = try std.fmt.allocPrint(allocator, "{s}/blobs/{s}", .{ path, &hex });
    defer allocator.free(blob_path);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = blob_path, .data = "tampered" });

    var store = try FsStore.open(allocator, io, path);
    defer store.deinit();
    try std.testing.expectError(error.HashMismatch, store.getBytes(allocator, hash));
}

test "FsStore addPathWithProgress emits found/progress/done" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const path = try std.fmt.allocPrint(allocator, "zig-cache/tmp/blobs-fs-progress-{d}", .{nonce});
    defer allocator.free(path);
    defer std.Io.Dir.cwd().deleteTree(io, path) catch {};

    var store = try FsStore.open(allocator, io, path);
    defer store.deinit();

    const import_path = try std.fmt.allocPrint(allocator, "{s}/raw-progress-import", .{path});
    defer allocator.free(import_path);
    const content = "raw-fs-store-progress";
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = import_path, .data = content });

    const ProgressLog = struct {
        const Event = types.ImportProgress;
        allocator: std.mem.Allocator,
        events: std.ArrayList(Event) = .empty,
        fn callback(ctx: *@This(), event: Event) void {
            ctx.events.append(ctx.allocator, event) catch unreachable;
        }
    };
    var log: ProgressLog = .{ .allocator = allocator };
    defer log.events.deinit(allocator);

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

test "FsStore partialExport/partialImport round-trips and resumes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const bao = @import("bao.zig");
    const fixtures = @import("fixtures.zig");
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const root_a = try std.fmt.allocPrint(allocator, "zig-cache/tmp/blobs-fs-partial-export-a-{d}", .{nonce});
    defer allocator.free(root_a);
    defer std.Io.Dir.cwd().deleteTree(io, root_a) catch {};
    const root_b = try std.fmt.allocPrint(allocator, "zig-cache/tmp/blobs-fs-partial-export-b-{d}", .{nonce});
    defer allocator.free(root_b);
    defer std.Io.Dir.cwd().deleteTree(io, root_b) catch {};

    const n: usize = 65_537;
    const data = try fixtures.makeTestData(allocator, n);
    defer allocator.free(data);
    const created = try bao.createOutboard(allocator, data);
    defer allocator.free(created.outboard);

    const state = blk: {
        var store = try FsStore.open(allocator, io, root_a);
        defer store.deinit();
        const entry = try store.partialCreate(created.root, n, created.outboard);
        {
            const wire = try bao.encodeRanges(allocator, data, .{ .boundaries = &.{ 1, 3 } });
            defer allocator.free(wire);
            try entry.insertEncoded(wire, .{ .boundaries = &.{ 1, 3 } });
        }
        try store.partialPersist(created.root);
        break :blk try store.partialExport(allocator, created.root);
    };
    defer allocator.free(state);

    {
        var store = try FsStore.open(allocator, io, root_b);
        defer store.deinit();
        const imported = try store.partialImport(state);
        try std.testing.expect(imported.hash.eql(created.root));
        try std.testing.expectEqual(@as(u64, 2), imported.bitfield.countSet());
        {
            const wire = try bao.encodeRanges(allocator, data, .{ .boundaries = &.{ 0, 1, 3, 65 } });
            defer allocator.free(wire);
            try imported.insertEncoded(wire, .{ .boundaries = &.{ 0, 1, 3, 65 } });
        }
        const complete = try store.partialComplete(created.root);
        try std.testing.expect(complete.eql(created.root));
        const got = try store.getBytes(allocator, created.root);
        defer allocator.free(got);
        try std.testing.expectEqualSlices(u8, data, got);
    }
}

test "FsStore deletes corrupt durable partial state and counts integrity errors" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const bao = @import("bao.zig");
    const fixtures = @import("fixtures.zig");
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const path = try std.fmt.allocPrint(allocator, "zig-cache/tmp/blobs-fs-corrupt-state-{d}", .{nonce});
    defer allocator.free(path);
    defer std.Io.Dir.cwd().deleteTree(io, path) catch {};

    const n: usize = 65_537;
    const data = try fixtures.makeTestData(allocator, n);
    defer allocator.free(data);
    const created = try bao.createOutboard(allocator, data);
    defer allocator.free(created.outboard);

    {
        var store = try FsStore.open(allocator, io, path);
        defer store.deinit();
        const entry = try store.partialCreate(created.root, n, created.outboard);
        {
            const wire = try bao.encodeRanges(allocator, data, .{ .boundaries = &.{ 0, 32 } });
            defer allocator.free(wire);
            try entry.insertEncoded(wire, .{ .boundaries = &.{ 0, 32 } });
        }
        try store.partialPersist(created.root);
        try store.shutdown();
    }

    const hex = created.root.toHex();
    const state_path = try std.fmt.allocPrint(allocator, "{s}/partial/{s}.state", .{ path, &hex });
    defer allocator.free(state_path);
    // Corrupt after a durable write so reopen must hit loadPartials' verify path.
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = state_path, .data = "not-a-valid-partial-state" });

    {
        var store = try FsStore.open(allocator, io, path);
        defer store.deinit();
        try std.testing.expect(store.partialEntry(created.root) == null);
        try std.testing.expectEqual(@as(u64, 1), store.metrics().integrity_errors);
    }

    // Quarantine = delete: the corrupt file must not remain to poison later opens.
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, state_path, .{}));
    {
        var store = try FsStore.open(allocator, io, path);
        defer store.deinit();
        try std.testing.expect(store.partialEntry(created.root) == null);
        try std.testing.expectEqual(@as(u64, 0), store.metrics().integrity_errors);
    }
}
