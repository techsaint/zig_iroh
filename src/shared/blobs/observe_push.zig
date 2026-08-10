//! Observe and Push protocol handlers over the transport seam.

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const transport = @import("transport");
const bao = @import("bao.zig");
const fixtures = @import("fixtures.zig");
const get = @import("get.zig");
const protocol = @import("protocol.zig");
const provider_policy = @import("provider_policy.zig");

pub const Policy = provider_policy.Policy;

pub const Error = get.Error || provider_policy.PolicyError || error{UnsupportedRanges};

pub fn ObserveStreamT(comptime Recv: type) type {
    return struct {
        recv: Recv,

        pub fn next(self: @This(), allocator: std.mem.Allocator) Error!protocol.ObserveItem {
            return protocol.ObserveItem.decodeFrame(allocator, self.recv.reader());
        }

        pub fn close(self: *@This()) void {
            self.recv.stop() catch {};
        }

        pub fn deinit(self: *@This()) void {
            self.close();
        }
    };
}
pub const ObserveStream = ObserveStreamT(transport.RecvStream);

pub const PushedBlob = struct {
    hash: Hash,
    data: []u8,

    pub fn deinit(self: PushedBlob, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

fn RecvStreamOf(comptime Conn: type) type {
    const BiType = @typeInfo(@typeInfo(@TypeOf(Conn.openBi)).@"fn".return_type.?).error_union.payload;
    return @typeInfo(BiType).@"struct".fields[1].type;
}

/// Start observing a blob. The returned stream yields the provider's initial
/// bitfield followed by incremental updates.
pub fn observe(
    allocator: std.mem.Allocator,
    conn: anytype,
    request: protocol.ObserveRequest,
) Error!ObserveStreamT(RecvStreamOf(@TypeOf(conn))) {
    const bi = try conn.openBi();
    errdefer bi.recv.stop() catch {};
    errdefer bi.send.reset();

    // Keep the encode-then-write path required by the noq adapter, but size it
    // from the actual postcard output instead of imposing an arbitrary 256 B
    // limit. The counting pass enforces the protocol's real 1 MiB bound before
    // allocation, so a caller cannot turn a large range list into unbounded
    // memory growth.
    var count_buffer: [256]u8 = undefined;
    var counter: std.Io.Writer.Discarding = .init(&count_buffer);
    try request.encode(&counter.writer);
    const encoded_len = counter.fullCount();
    if (encoded_len > protocol.MAX_MESSAGE_SIZE) return error.MessageTooLarge;
    var req_w = std.Io.Writer.Allocating.initCapacity(allocator, @intCast(encoded_len)) catch
        return error.WriteFailed;
    defer req_w.deinit();
    try request.encode(&req_w.writer);
    try bi.send.writer().writeAll(req_w.writer.buffered());
    try bi.send.finish();
    return .{ .recv = bi.recv };
}

/// Serve a bounded sequence of Observe updates. Storage-backed providers call
/// this with the initial bitfield and each subsequent diff they receive.
/// Compatibility wrapper (`Policy.allow_all`) — production hosts should use
/// `provider.Provider` (push-deny by default).
pub fn serveObserve(
    allocator: std.mem.Allocator,
    conn: anytype,
    expected_hash: Hash,
    updates: []const protocol.ObserveItem,
) Error!void {
    return serveObserveWithPolicy(allocator, conn, expected_hash, updates, Policy.allow_all);
}

pub fn serveObserveWithPolicy(
    allocator: std.mem.Allocator,
    conn: anytype,
    expected_hash: Hash,
    updates: []const protocol.ObserveItem,
    policy: Policy,
) Error!void {
    const bi = try conn.acceptBi();
    errdefer bi.recv.stop() catch {};
    errdefer bi.send.reset();
    try provider_policy.gateBi(policy, .observe, bi);

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
    conn: anytype,
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
/// Uses `Policy.allow_all` so existing interop/tests keep accepting push.
/// Production hosts should use `provider.Provider` (push-deny by default).
pub fn receivePushBlob(allocator: std.mem.Allocator, conn: anytype) Error!PushedBlob {
    return receivePushBlobWithPolicy(allocator, conn, Policy.allow_all);
}

/// Accept a push under an explicit policy. `Policy.default` refuses push.
pub fn receivePushBlobWithPolicy(
    allocator: std.mem.Allocator,
    conn: anytype,
    policy: Policy,
) Error!PushedBlob {
    const bi = try conn.acceptBi();
    errdefer bi.recv.stop() catch {};
    errdefer bi.send.reset();
    try provider_policy.gateBi(policy, .push, bi);
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
    var stream = try observe(allocator, pair.client(), protocol.ObserveRequest.all(hash));
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

test "Observe streams valid custom ranges larger than the old 256-byte ceiling" {
    const allocator = std.testing.allocator;
    const pair = @import("../transport/mock.zig").Pair.init(
        allocator,
        std.testing.io,
        testId(7),
        testId(8),
    );
    defer pair.deinit(allocator);

    const widths = [_]u64{1} ** 4000;
    const hash = Hash.of("large-observe-range");
    const request: protocol.ObserveRequest = .{ .hash = hash, .ranges = .{ .widths = &widths } };
    var counter_buffer: [32]u8 = undefined;
    var counter: std.Io.Writer.Discarding = .init(&counter_buffer);
    try request.encode(&counter.writer);
    try std.testing.expect(counter.fullCount() > 256);
    try std.testing.expect(counter.fullCount() < protocol.MAX_MESSAGE_SIZE);

    var stream = try observe(allocator, pair.client(), request);
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

    var stream = try observe(allocator, pair.client(), protocol.ObserveRequest.all(Hash.of("close-observe")));
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
    try std.testing.expectError(error.MessageTooLarge, observe(allocator, pair.client(), request));

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

test "default policy refuses push (peer-visible permission reset)" {
    const allocator = std.testing.allocator;
    const pair = @import("../transport/mock.zig").Pair.init(
        allocator,
        std.testing.io,
        testId(20),
        testId(21),
    );
    defer pair.deinit(allocator);

    const data = try fixtures.makeTestData(allocator, 2048);
    defer allocator.free(data);
    const hash = Hash.of(data);

    try pushBlob(allocator, pair.client(), hash, data);
    try std.testing.expectError(
        error.PermissionDenied,
        receivePushBlobWithPolicy(allocator, pair.server(), Policy.default),
    );
    const life = pair.lifecycle();
    try std.testing.expect(life.server_send_reset);
    try std.testing.expectEqual(@as(?u64, protocol.ERR_PERMISSION), life.server_send_reset_code);
    try std.testing.expect(life.server_recv_stopped);
}

test "allow_all policy accepts push unchanged" {
    const allocator = std.testing.allocator;
    const pair = @import("../transport/mock.zig").Pair.init(
        allocator,
        std.testing.io,
        testId(22),
        testId(23),
    );
    defer pair.deinit(allocator);

    const data = try fixtures.makeTestData(allocator, 1024);
    defer allocator.free(data);
    const hash = Hash.of(data);

    try pushBlob(allocator, pair.client(), hash, data);
    const pushed = try receivePushBlobWithPolicy(allocator, pair.server(), Policy.allow_all);
    defer pushed.deinit(allocator);
    try std.testing.expect(pushed.hash.eql(hash));
    try std.testing.expectEqualSlices(u8, data, pushed.data);
}

test "policy deny aborts observe without updates" {
    const allocator = std.testing.allocator;
    const pair = @import("../transport/mock.zig").Pair.init(
        allocator,
        std.testing.io,
        testId(24),
        testId(25),
    );
    defer pair.deinit(allocator);

    const hash = Hash.of("observe-deny");
    var stream = try observe(allocator, pair.client(), protocol.ObserveRequest.all(hash));
    defer stream.deinit();

    const deny = Policy{ .observe = .deny };
    try std.testing.expectError(
        error.PermissionDenied,
        serveObserveWithPolicy(allocator, pair.server(), hash, &.{}, deny),
    );
    const life = pair.lifecycle();
    try std.testing.expect(life.server_send_reset);
    try std.testing.expectEqual(@as(?u64, protocol.ERR_PERMISSION), life.server_send_reset_code);
}
