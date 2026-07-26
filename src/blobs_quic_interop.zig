const std = @import("std");
const key = @import("key.zig");
const transport = @import("transport.zig");
const factory = @import("transport/factory.zig");
const Hash = @import("hash.zig").Hash;
const get = @import("blobs/get.zig");
const fixtures = @import("blobs/fixtures.zig");

const testing = std.testing;

test "blobs over real QUIC: single blob get with bao verification" {
    const allocator = testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_key = key.SecretKey.fromBytes([_]u8{0xA1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xB2} ** 32);
    const alpn: [:0]const u8 = "iroh-blobs-quic-interop";

    const client_ep = try factory.createForProduct(allocator, io, client_key, alpn, .{});
    defer client_ep.deinit();
    const server_ep = try factory.createForProduct(allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
    });
    defer server_ep.deinit();

    const client_t = client_ep.transport();
    const server_t = server_ep.transport();

    var accept_future = io.async(struct {
        fn run(t: transport.Transport) !transport.Connection {
            return t.accept();
        }
    }.run, .{server_t});

    const server_addr = server_ep.localAddress();
    const client_conn = try client_t.connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server_addr }},
    });
    defer client_conn.close();
    const server_conn = try accept_future.await(io);
    defer server_conn.close();

    const blob_size: usize = 16385;
    const data = try fixtures.makeTestData(allocator, blob_size);
    defer allocator.free(data);
    const hash = Hash.of(data);

    var server_done = std.atomic.Value(bool).init(false);
    var serve_future = io.async(struct {
        fn run(allocator_inner: std.mem.Allocator, conn: transport.Connection, server: factory.AnyEndpoint, h: Hash, d: []const u8, done: *std.atomic.Value(bool)) !void {
            try get.serveBlob(allocator_inner, conn, h, d);
            while (!done.load(.acquire)) {
                try server.pollOnce();
            }
        }
    }.run, .{ allocator, server_conn, server_ep, hash, data, &server_done });
    errdefer {
        server_done.store(true, .release);
        _ = serve_future.await(io) catch {};
    }

    const got = try get.getBlob(allocator, client_conn, hash, hash);
    defer allocator.free(got);

    server_done.store(true, .release);
    _ = try serve_future.await(io);
    try testing.expectEqualSlices(u8, data, got);
}

test "blobs over real QUIC: hashseq multi-blob get with bao verification" {
    const allocator = testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_key = key.SecretKey.fromBytes([_]u8{0xC3} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xD4} ** 32);
    const alpn: [:0]const u8 = "iroh-blobs-quic-hs";

    const client_ep = try factory.createForProduct(allocator, io, client_key, alpn, .{});
    defer client_ep.deinit();
    const server_ep = try factory.createForProduct(allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
    });
    defer server_ep.deinit();

    const client_t = client_ep.transport();
    const server_t = server_ep.transport();

    var accept_future = io.async(struct {
        fn run(t: transport.Transport) !transport.Connection {
            return t.accept();
        }
    }.run, .{server_t});

    const server_addr = server_ep.localAddress();
    const client_conn = try client_t.connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server_addr }},
    });
    defer client_conn.close();
    const server_conn = try accept_future.await(io);
    defer server_conn.close();

    const child0 = try fixtures.makeTestData(allocator, 512);
    defer allocator.free(child0);
    const child1 = try fixtures.makeTestData(allocator, 1024);
    defer allocator.free(child1);
    const h0 = Hash.of(child0);
    const h1 = Hash.of(child1);
    const hashseq_mod = @import("blobs/hashseq.zig");
    var seq = try hashseq_mod.HashSeq.fromHashes(allocator, &.{ h0, h1 });
    defer seq.deinit(allocator);
    const seq_hash = Hash.of(seq.bytes);

    var server_done = std.atomic.Value(bool).init(false);
    var serve_future = io.async(struct {
        fn run(
            allocator_inner: std.mem.Allocator,
            conn: transport.Connection,
            server: factory.AnyEndpoint,
            seq_bytes: []const u8,
            c0: []const u8,
            c1: []const u8,
            done: *std.atomic.Value(bool),
        ) !void {
            const child_data: []const []const u8 = &.{ c0, c1 };
            try get.serveAll(allocator_inner, conn, seq_bytes, child_data);
            while (!done.load(.acquire)) {
                try server.pollOnce();
            }
        }
    }.run, .{ allocator, server_conn, server_ep, seq.bytes, child0, child1, &server_done });
    errdefer {
        server_done.store(true, .release);
        _ = serve_future.await(io) catch {};
    }

    const result = try get.getAll(allocator, client_conn, seq_hash, &.{ h0, h1 });
    defer {
        allocator.free(result.hash_seq);
        for (result.children) |c| allocator.free(c);
        allocator.free(result.children);
    }

    try testing.expectEqualSlices(u8, seq.bytes, result.hash_seq);
    try testing.expectEqualSlices(u8, child0, result.children[0]);
    try testing.expectEqualSlices(u8, child1, result.children[1]);

    server_done.store(true, .release);
    _ = try serve_future.await(io);
}
