//! Public Store API smoke — shared MemStore/FsStore behavior and durability.
//! Receipt source for oracle row `blobs_store_api`.
//!
//! Coverage: add/get/path-import-export/list/reopen/metrics on both backends,
//! plus the gate-coverage closures from blobs-parity-round-2: miss, removal,
//! and integrity-failure counters asserted on real store behavior, `remove()`
//! exercised on MemStore AND FsStore, and addPath/exportPath/listHashes/
//! status/remove driven through the backend-generic `Blobs` FACADE (not just
//! the underlying store).

const std = @import("std");
const zig_iroh = @import("zig_iroh");

const Hash = zig_iroh.Hash;
const FsStore = zig_iroh.blobs.FsStore;
const MemStore = zig_iroh.blobs.store.MemStore;
const bao = zig_iroh.blobs.bao;
const fixtures = zig_iroh.blobs.fixtures;

const pass_marker = "PASS: Zig blobs Store API smoke (Mem/Fs add/get/export/list/reopen/metrics/miss/remove/integrity/facade/partial)";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var store = MemStore.init(allocator);
    defer store.deinit();

    // add/get bytes
    const hello_hash = blk: {
        const expected = "hello";
        const hash = try store.addBytes(expected);
        if (!hash.eql(Hash.of(expected))) return error.HashMismatch;
        const actual = try store.getBytes(allocator, hash);
        defer allocator.free(actual);
        if (!std.mem.eql(u8, actual, expected)) return error.BytesMismatch;
        break :blk hash;
    };

    // path import + export
    const tmp_root = "zig-cache/tmp-blobs-store-api-smoke";
    try std.Io.Dir.cwd().createDirPath(io, tmp_root);
    defer std.Io.Dir.cwd().deleteTree(io, tmp_root) catch {};

    var path_buf: [256]u8 = undefined;
    const temp1 = try std.fmt.bufPrint(&path_buf, "{s}/test1", .{tmp_root});
    {
        const f = try std.Io.Dir.cwd().createFile(io, temp1, .{});
        defer f.close(io);
        var wb: [64]u8 = undefined;
        var fw = f.writer(io, &wb);
        try fw.interface.writeAll("somestuffinafile");
        try fw.interface.flush();
    }
    const file_hash = try store.addPath(io, temp1);
    if (!file_hash.eql(Hash.of("somestuffinafile"))) return error.PathHashMismatch;

    var path2_buf: [256]u8 = undefined;
    const temp2 = try std.fmt.bufPrint(&path2_buf, "{s}/test2", .{tmp_root});
    try store.exportPath(io, file_hash, temp2);
    {
        const f = try std.Io.Dir.cwd().openFile(io, temp2, .{});
        defer f.close(io);
        var rb: [64]u8 = undefined;
        var fr = f.reader(io, &rb);
        const got = try fr.interface.takeArray(16);
        if (!std.mem.eql(u8, got, "somestuffinafile")) return error.ExportMismatch;
    }

    // large blob (progress stream in Rust = final hash only for us)
    {
        const big = try allocator.alloc(u8, 1024 * 1024);
        defer allocator.free(big);
        @memset(big, 0);
        var path3_buf: [256]u8 = undefined;
        const temp3 = try std.fmt.bufPrint(&path3_buf, "{s}/test3", .{tmp_root});
        {
            const f = try std.Io.Dir.cwd().createFile(io, temp3, .{});
            defer f.close(io);
            var wb: [4096]u8 = undefined;
            var fw = f.writer(io, &wb);
            try fw.interface.writeAll(big);
            try fw.interface.flush();
        }
        const big_hash = try store.addPath(io, temp3);
        if (!big_hash.eql(Hash.of(big))) return error.LargeHashMismatch;
    }

    const hashes = try store.listHashes(allocator);
    defer allocator.free(hashes);
    if (hashes.len != 3) return error.ListCount;

    const mem_metrics = store.metrics();
    if (mem_metrics.add_operations != 3 or mem_metrics.get_operations != 1)
        return error.MemMetrics;

    // Gate-coverage closure 1 (blobs-metrics): a real MISS moves not_found.
    const absent_hash = Hash.of("never-added");
    const miss_result = store.getBytes(allocator, absent_hash);
    if (miss_result != error.NotFound) return error.MemMissNotCounted;
    if (store.metrics().not_found != 1) return error.MemMissNotCounted;

    // Gate-coverage closure 2 (blobs-store-api): remove() on MemStore —
    // first removal succeeds and moves the removed counter, second reports
    // false, and the bytes are actually gone.
    if (!try store.remove(hello_hash)) return error.MemRemoveFailed;
    if (store.metrics().removed != 1) return error.MemRemoveNotCounted;
    if (try store.remove(hello_hash)) return error.MemRemoveDouble;
    const gone = store.getBytes(allocator, hello_hash);
    if (gone != error.NotFound) return error.MemRemoveNotApplied;
    if (store.metrics().not_found != 2) return error.MemMissNotCounted;

    // Gate-coverage closure 3 (blobs-blobs-api): drive the FACADE, not the
    // raw store — addPath / exportPath / listHashes / status / remove.
    const mem_facade = store.blobs();
    var path4_buf: [256]u8 = undefined;
    const temp4 = try std.fmt.bufPrint(&path4_buf, "{s}/test4", .{tmp_root});
    {
        const f = try std.Io.Dir.cwd().createFile(io, temp4, .{});
        defer f.close(io);
        var wb: [64]u8 = undefined;
        var fw = f.writer(io, &wb);
        try fw.interface.writeAll("facade-import");
        try fw.interface.flush();
    }
    const facade_hash = try mem_facade.addPath(io, temp4);
    if (!facade_hash.eql(Hash.of("facade-import"))) return error.FacadeAddPath;
    var path5_buf: [256]u8 = undefined;
    const temp5 = try std.fmt.bufPrint(&path5_buf, "{s}/test5", .{tmp_root});
    try mem_facade.exportPath(io, facade_hash, temp5);
    {
        const exported = try std.Io.Dir.cwd().readFileAlloc(io, temp5, allocator, .limited(1024));
        defer allocator.free(exported);
        if (!std.mem.eql(u8, exported, "facade-import")) return error.FacadeExportPath;
    }
    switch (try mem_facade.status(facade_hash)) {
        .complete => |size| if (size != "facade-import".len) return error.FacadeStatus,
        else => return error.FacadeStatus,
    }
    const facade_hashes = try mem_facade.listHashes(allocator);
    defer allocator.free(facade_hashes);
    if (facade_hashes.len != 3) return error.FacadeListHashes; // test1, big, facade-import
    if (!try mem_facade.remove(facade_hash)) return error.FacadeRemove;
    switch (try mem_facade.status(facade_hash)) {
        .not_found => {},
        else => return error.FacadeRemoveNotApplied,
    }

    try store.shutdown();

    // The same public Blobs surface over the durable backend must survive a
    // clean shutdown/reopen with named tags intact.
    const fs_root = try std.fmt.allocPrint(allocator, "{s}/fs-store", .{tmp_root});
    defer allocator.free(fs_root);
    const durable_data = "persistent-store-smoke";
    const durable_hash = Hash.of(durable_data);
    {
        var fs_store = try FsStore.open(allocator, io, fs_root);
        defer fs_store.deinit();
        const blobs = fs_store.blobs();
        if (!(try blobs.addBytes(durable_data)).eql(durable_hash)) return error.FsHashMismatch;
        try fs_store.tags().setRaw("durable", durable_hash);
        try fs_store.waitIdle();
        try fs_store.shutdown();
    }
    {
        var fs_store = try FsStore.open(allocator, io, fs_root);
        defer fs_store.deinit();
        const blobs = fs_store.blobs();
        const reopened = try blobs.getBytes(allocator, durable_hash);
        defer allocator.free(reopened);
        if (!std.mem.eql(u8, reopened, durable_data)) return error.FsReopenMismatch;
        const tag = fs_store.tags().get("durable") orelse return error.FsTagMissing;
        if (!tag.hash.eql(durable_hash)) return error.FsTagMismatch;
        const fs_metrics = fs_store.metrics();
        if (fs_metrics.get_operations != 1 or fs_metrics.bytes_read != durable_data.len)
            return error.FsMetrics;

        // Gate-coverage closure 1 on FsStore: a real MISS moves not_found.
        const fs_miss = blobs.getBytes(allocator, absent_hash);
        if (fs_miss != error.NotFound) return error.FsMissNotCounted;
        if (fs_store.metrics().not_found != 1) return error.FsMissNotCounted;

        // Gate-coverage closure 3 on FsStore: facade addPath/exportPath/
        // listHashes/status/remove over the durable backend.
        var fs_path_buf: [256]u8 = undefined;
        const fs_import = try std.fmt.bufPrint(&fs_path_buf, "{s}/fs-import", .{tmp_root});
        {
            const f = try std.Io.Dir.cwd().createFile(io, fs_import, .{});
            defer f.close(io);
            var wb: [64]u8 = undefined;
            var fw = f.writer(io, &wb);
            try fw.interface.writeAll("fs-facade-import");
            try fw.interface.flush();
        }
        const fs_facade_hash = try blobs.addPath(io, fs_import);
        if (!fs_facade_hash.eql(Hash.of("fs-facade-import"))) return error.FsFacadeAddPath;
        const fs_export = try std.fmt.bufPrint(&fs_path_buf, "{s}/fs-export", .{tmp_root});
        try blobs.exportPath(io, fs_facade_hash, fs_export);
        {
            const exported = try std.Io.Dir.cwd().readFileAlloc(io, fs_export, allocator, .limited(1024));
            defer allocator.free(exported);
            if (!std.mem.eql(u8, exported, "fs-facade-import")) return error.FsFacadeExportPath;
        }
        switch (try blobs.status(fs_facade_hash)) {
            .complete => |size| if (size != "fs-facade-import".len) return error.FsFacadeStatus,
            else => return error.FsFacadeStatus,
        }
        const fs_hashes = try blobs.listHashes(allocator);
        defer allocator.free(fs_hashes);
        if (fs_hashes.len != 2) return error.FsFacadeListHashes; // durable + fs-facade-import

        // Gate-coverage closure 2 on FsStore: remove() deletes the content
        // file, reports false on repeat, and moves the removed counter.
        if (!try blobs.remove(durable_hash)) return error.FsRemoveFailed;
        if (fs_store.metrics().removed != 1) return error.FsRemoveNotCounted;
        if (try blobs.remove(durable_hash)) return error.FsRemoveDouble;
        switch (try blobs.status(durable_hash)) {
            .not_found => {},
            else => return error.FsRemoveNotApplied,
        }

        // Gate-coverage closure 1 on FsStore: a REAL integrity failure
        // (tampered content-addressed file) moves integrity_errors.
        const integrity_data = "integrity-check";
        const integrity_hash = try blobs.addBytes(integrity_data);
        const hex = integrity_hash.toHex();
        var blob_path_buf: [512]u8 = undefined;
        const blob_path = try std.fmt.bufPrint(&blob_path_buf, "{s}/blobs/{s}", .{ fs_root, &hex });
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = blob_path, .data = "tampered-bytes!" });
        const corrupt = blobs.getBytes(allocator, integrity_hash);
        if (corrupt != error.HashMismatch) return error.FsIntegrityNotDetected;
        if (fs_store.metrics().integrity_errors != 1) return error.FsIntegrityNotCounted;
    }

    // Partial BAO entries: verified-range ingestion, partial status, and the
    // partial-to-complete transition — on the memory backend.
    {
        var mem = MemStore.init(allocator);
        defer mem.deinit();
        const partial_data = try fixtures.makeTestData(allocator, 65_537);
        defer allocator.free(partial_data);
        const outboarded = try bao.createOutboard(allocator, partial_data);
        defer allocator.free(outboarded.outboard);

        const entry = try mem.partialCreate(outboarded.root, partial_data.len, outboarded.outboard);
        {
            const wire = try bao.encodeRanges(allocator, partial_data, .{ .boundaries = &.{ 0, 32 } });
            defer allocator.free(wire);
            try entry.insertEncoded(wire, .{ .boundaries = &.{ 0, 32 } });
        }
        switch (try mem.status(outboarded.root)) {
            .partial => |present| if (present != 32 * bao.CHUNK_LEN) return error.MemPartialStatus,
            else => return error.MemPartialStatus,
        }
        {
            const wire = try bao.encodeRanges(allocator, partial_data, .{ .boundaries = &.{ 32, 65 } });
            defer allocator.free(wire);
            try entry.insertEncoded(wire, .{ .boundaries = &.{ 32, 65 } });
        }
        const completed = try mem.partialComplete(outboarded.root);
        if (!completed.eql(outboarded.root)) return error.MemPartialComplete;
        const got = try mem.getBytes(allocator, outboarded.root);
        defer allocator.free(got);
        if (!std.mem.eql(u8, got, partial_data)) return error.MemPartialBytes;
    }

    // Durable partial state: a partial entry persists across shutdown/reopen
    // and resumes to completion on the filesystem backend.
    {
        const fs_partial_root = try std.fmt.allocPrint(allocator, "{s}/fs-partial", .{tmp_root});
        defer allocator.free(fs_partial_root);
        const partial_data = try fixtures.makeTestData(allocator, 65_537);
        defer allocator.free(partial_data);
        const outboarded = try bao.createOutboard(allocator, partial_data);
        defer allocator.free(outboarded.outboard);

        {
            var fs = try FsStore.open(allocator, io, fs_partial_root);
            defer fs.deinit();
            const entry = try fs.partialCreate(outboarded.root, partial_data.len, outboarded.outboard);
            const wire = try bao.encodeRanges(allocator, partial_data, .{ .boundaries = &.{ 0, 32 } });
            defer allocator.free(wire);
            try entry.insertEncoded(wire, .{ .boundaries = &.{ 0, 32 } });
            try fs.partialPersist(outboarded.root);
            try fs.shutdown();
        }
        {
            var fs = try FsStore.open(allocator, io, fs_partial_root);
            defer fs.deinit();
            const entry = fs.partialEntry(outboarded.root) orelse return error.FsPartialNotDurable;
            const wire = try bao.encodeRanges(allocator, partial_data, .{ .boundaries = &.{ 32, 65 } });
            defer allocator.free(wire);
            try entry.insertEncoded(wire, .{ .boundaries = &.{ 32, 65 } });
            const completed = try fs.partialComplete(outboarded.root);
            if (!completed.eql(outboarded.root)) return error.FsPartialComplete;
            const got = try fs.getBytes(allocator, outboarded.root);
            defer allocator.free(got);
            if (!std.mem.eql(u8, got, partial_data)) return error.FsPartialBytes;
        }
    }

    std.debug.print("{s}\n", .{pass_marker});
}
