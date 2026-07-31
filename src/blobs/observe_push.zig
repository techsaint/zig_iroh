//! Observe and Push protocol handlers over the transport seam.

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const transport = @import("../transport.zig");
const bao = @import("bao.zig");
const fixtures = @import("fixtures.zig");
const get = @import("get.zig");
const protocol = @import("protocol.zig");

pub const Error = get.Error || error{UnsupportedRanges};

pub const ObserveStream = struct {
    recv: transport.RecvStream,

    pub fn next(self: ObserveStream, allocator: std.mem.Allocator) Error!protocol.ObserveItem {
        return protocol.ObserveItem.decodeFrame(allocator, self.recv.reader());
    }

    pub fn close(self: *ObserveStream) void {
        self.recv.stop() catch {};
    }

    pub fn deinit(self: *ObserveStream) void {
        self.close();
    }
};

pub const PushedBlob = struct {
    hash: Hash,
    data: []u8,

    pub fn deinit(self: PushedBlob, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

/// Start observing a blob. The returned stream yields the provider's initial
/// bitfield followed by incremental updates.
pub fn observe(conn: transport.Connection, request: protocol.ObserveRequest) Error!ObserveStream {
    const bi = try conn.openBi();
    errdefer bi.recv.stop() catch {};
    errdefer bi.send.reset();
    // Match getBlob: encode into a fixed buffer then writeAll. Encoding
    // directly into the stream Writer left the observe request unflushed on
    // the noq adapter (get/push worked; observe timed out reading).
    var req_buf: [256]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try request.encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();
    return .{ .recv = bi.recv };
}

/// Serve a bounded sequence of Observe updates. Storage-backed providers call
/// this with the initial bitfield and each subsequent diff they receive.
pub fn serveObserve(
    allocator: std.mem.Allocator,
    conn: transport.Connection,
    expected_hash: Hash,
    updates: []const protocol.ObserveItem,
) Error!void {
    const bi = try conn.acceptBi();
    errdefer bi.recv.stop() catch {};
    errdefer bi.send.reset();

    const request_reader = bi.recv.reader();
    const request = try protocol.ObserveRequest.decode(allocator, request_reader);
    defer request.deinit(allocator);
    try expectEnd(request_reader);
    try bi.recv.stop();
    if (!request.hash.eql(expected_hash)) return error.HashMismatch;

    for (updates) |update| try update.encodeFrame(bi.send.writer());
    try bi.send.finish();
}

/// Push a complete raw blob using iroh's tag-8 length-prefixed request framing
/// followed by the same verified Bao stream used by Get responses.
pub fn pushBlob(
    allocator: std.mem.Allocator,
    conn: transport.Connection,
    hash: Hash,
    data: []const u8,
) Error!void {
    if (!Hash.of(data).eql(hash)) return error.HashMismatch;
    const bi = try conn.openBi();
    errdefer bi.recv.stop() catch {};
    errdefer bi.send.reset();
    try bi.recv.stop();

    try protocol.PushRequest.blob(hash).encode(bi.send.writer());
    try get.writeBlobResponse(allocator, bi.send.writer(), hash, data, bao.ChunkRanges.all());
    try bi.send.finish();
}

/// Accept and verify one complete raw-blob Push. BL3 storage can consume the
/// returned bytes without changing this wire/transport boundary.
pub fn receivePushBlob(allocator: std.mem.Allocator, conn: transport.Connection) Error!PushedBlob {
    const bi = try conn.acceptBi();
    errdefer bi.recv.stop() catch {};
    errdefer bi.send.reset();
    const request_reader = bi.recv.reader();
    const request = try protocol.PushRequest.decode(allocator, request_reader);
    defer request.deinit(allocator);
    if (!isCompleteRootPush(request)) return error.UnsupportedRanges;

    var size_buf: [8]u8 = undefined;
    const size_len = try request_reader.readSliceShort(&size_buf);
    if (size_len != size_buf.len) return error.EndOfStream;
    const size = std.mem.readInt(u64, &size_buf, .little);
    const data = try bao.decodeVerified(allocator, request.hash, size, request_reader);
    errdefer allocator.free(data);
    try expectEnd(request_reader);
    bi.send.finish() catch |err| switch (err) {
        // The Push sender stops this unused direction immediately.
        error.StreamReset => {},
        else => |other| return other,
    };
    try bi.recv.stop();
    return .{ .hash = request.hash, .data = data };
}

fn isCompleteRootPush(request: protocol.PushRequest) bool {
    const entries = request.ranges.entries;
    return entries.len == 2 and
        entries[0].offset == 0 and
        std.mem.eql(u64, entries[0].spec.widths, &.{0}) and
        entries[1].offset == 1 and
        entries[1].spec.widths.len == 0;
}

fn expectEnd(reader: *std.Io.Reader) Error!void {
    _ = reader.takeByte() catch |err| switch (err) {
        error.EndOfStream => return,
        else => return err,
    };
    return error.UnexpectedData;
}

fn testId(seed: u8) @import("../key.zig").NodeId {
    return @import("../key.zig").SecretKey.fromBytes(.{seed} ** 32).public();
}

test "Observe request and multiple response items round-trip" {
    const allocator = std.testing.allocator;
    const pair = @import("../transport/mock.zig").Pair.init(
        allocator,
        std.testing.io,
        testId(1),
        testId(2),
    );
    defer pair.deinit(allocator);

    const data = try fixtures.makeTestData(allocator, 65_537);
    defer allocator.free(data);
    const hash = Hash.of(data);
    var stream = try observe(pair.client(), protocol.ObserveRequest.all(hash));
    defer stream.deinit();

    const updates = [_]protocol.ObserveItem{
        .{ .size = 0, .ranges = bao.ChunkRanges.empty() },
        .{ .size = @intCast(data.len), .ranges = bao.ChunkRanges.all() },
    };
    try serveObserve(allocator, pair.server(), hash, &updates);

    const initial = try stream.next(allocator);
    defer initial.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), initial.size);
    try std.testing.expect(initial.ranges.is_empty());

    const complete = try stream.next(allocator);
    defer complete.deinit(allocator);
    try std.testing.expectEqual(@as(u64, data.len), complete.size);
    try std.testing.expect(complete.ranges.is_all());
}

test "Observe streams valid custom ranges larger than 128 bytes" {
    const allocator = std.testing.allocator;
    const pair = @import("../transport/mock.zig").Pair.init(
        allocator,
        std.testing.io,
        testId(7),
        testId(8),
    );
    defer pair.deinit(allocator);

    const widths = [_]u64{1} ** 160;
    const hash = Hash.of("large-observe-range");
    const request: protocol.ObserveRequest = .{ .hash = hash, .ranges = .{ .widths = &widths } };
    var encoded: [256]u8 = undefined;
    var encoded_writer: std.Io.Writer = .fixed(&encoded);
    try request.encode(&encoded_writer);
    try std.testing.expect(encoded_writer.end > 128);
    try std.testing.expect(encoded_writer.end < protocol.MAX_MESSAGE_SIZE);

    var stream = try observe(pair.client(), request);
    defer stream.deinit();
    try serveObserve(allocator, pair.server(), hash, &.{});
}

test "Observe close stops only its receive direction" {
    const allocator = std.testing.allocator;
    const pair = @import("../transport/mock.zig").Pair.init(
        allocator,
        std.testing.io,
        testId(9),
        testId(10),
    );
    defer pair.deinit(allocator);

    var stream = try observe(pair.client(), protocol.ObserveRequest.all(Hash.of("close-observe")));
    stream.close();
    stream.close();

    const lifecycle = pair.lifecycle();
    try std.testing.expect(lifecycle.client_send_finished);
    try std.testing.expect(lifecycle.client_recv_stopped);
    try std.testing.expect(pair.client().remoteNodeId().eql(testId(10)));
}

test "Observe preflight failure resets both stream directions" {
    const allocator = std.testing.allocator;
    const pair = @import("../transport/mock.zig").Pair.init(
        allocator,
        std.testing.io,
        testId(11),
        testId(12),
    );
    defer pair.deinit(allocator);

    const widths = try allocator.alloc(u64, protocol.MAX_MESSAGE_SIZE);
    defer allocator.free(widths);
    @memset(widths, 1);
    const request: protocol.ObserveRequest = .{
        .hash = Hash.of("oversized-observe"),
        .ranges = .{ .widths = widths },
    };
    try std.testing.expectError(error.MessageTooLarge, observe(pair.client(), request));

    const lifecycle = pair.lifecycle();
    try std.testing.expect(lifecycle.client_send_reset);
    try std.testing.expect(lifecycle.client_recv_stopped);
}

test "Push raw blob round-trip verifies Bao and content hash" {
    const allocator = std.testing.allocator;
    const pair = @import("../transport/mock.zig").Pair.init(
        allocator,
        std.testing.io,
        testId(3),
        testId(4),
    );
    defer pair.deinit(allocator);

    const data = try fixtures.makeTestData(allocator, 32_769);
    defer allocator.free(data);
    const hash = Hash.of(data);

    try pushBlob(allocator, pair.client(), hash, data);
    const after_send = pair.lifecycle();
    try std.testing.expect(after_send.client_send_finished);
    try std.testing.expect(after_send.client_recv_stopped);
    try std.testing.expect(!after_send.server_send_finished);

    const pushed = try receivePushBlob(allocator, pair.server());
    defer pushed.deinit(allocator);
    try std.testing.expect(pushed.hash.eql(hash));
    try std.testing.expectEqualSlices(u8, data, pushed.data);
    const after_receive = pair.lifecycle();
    try std.testing.expect(after_receive.server_send_finished);
    try std.testing.expect(after_receive.server_recv_stopped);
}

test "Push rejects partial root ranges and resets the unused response" {
    const allocator = std.testing.allocator;
    const pair = @import("../transport/mock.zig").Pair.init(
        allocator,
        std.testing.io,
        testId(13),
        testId(14),
    );
    defer pair.deinit(allocator);

    const partial_widths = &[_]u64{ 0, 1 };
    const entries = &[_]@import("range_spec.zig").ChunkRangesSeq.Entry{
        .{ .offset = 0, .spec = .{ .widths = partial_widths } },
        .{ .offset = 1, .spec = .empty },
    };
    const request = protocol.PushRequest.new(
        Hash.of("partial-root"),
        .{ .entries = entries },
    );
    const bi = try pair.client().openBi();
    try request.encode(bi.send.writer());
    try bi.send.finish();

    try std.testing.expectError(error.UnsupportedRanges, receivePushBlob(allocator, pair.server()));
    const lifecycle = pair.lifecycle();
    try std.testing.expect(lifecycle.server_send_reset);
    try std.testing.expect(lifecycle.server_recv_stopped);
}

test "Push rejects caller bytes that do not match the request hash" {
    const allocator = std.testing.allocator;
    const pair = @import("../transport/mock.zig").Pair.init(
        allocator,
        std.testing.io,
        testId(5),
        testId(6),
    );
    defer pair.deinit(allocator);

    const data = try fixtures.makeTestData(allocator, 1024);
    defer allocator.free(data);
    var wrong_hash_bytes = Hash.of(data).bytes;
    wrong_hash_bytes[0] ^= 1;
    try std.testing.expectError(
        error.HashMismatch,
        pushBlob(allocator, pair.client(), Hash.fromBytes(wrong_hash_bytes), data),
    );
}
