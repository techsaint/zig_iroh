//! Public Store API smoke — MemStore equivalent of blobs_smoke_mem.
//! Receipt source for oracle row `blobs_store_api`.

const std = @import("std");
const zig_iroh = @import("zig_iroh");

const Hash = zig_iroh.Hash;
const MemStore = zig_iroh.blobs.store.MemStore;

const pass_marker = "PASS: Zig blobs MemStore API smoke (add/get/export/list)";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var store = MemStore.init(allocator);
    defer store.deinit();

    // add/get bytes
    {
        const expected = "hello";
        const hash = try store.addBytes(expected);
        if (!hash.eql(Hash.of(expected))) return error.HashMismatch;
        const actual = try store.getBytes(allocator, hash);
        defer allocator.free(actual);
        if (!std.mem.eql(u8, actual, expected)) return error.BytesMismatch;
    }

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

    store.shutdown();
    std.debug.print("{s}\n", .{pass_marker});
}
