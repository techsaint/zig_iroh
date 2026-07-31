//! Get protocol over MockTransport.

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const transport = @import("../transport.zig");
const mock = @import("../transport/mock.zig");
const key = @import("../key.zig");
const protocol = @import("protocol.zig");
const bao = @import("bao.zig");
const hashseq = @import("hashseq.zig");
const range_spec = @import("range_spec.zig");

pub const Error = protocol.Error || bao.Error || hashseq.Error || transport.Error || error{
    HashMismatch,
    UnexpectedData,
    TooManyHashes,
    LengthMismatch,
};

const OwnedBaoRanges = struct {
    ranges: bao.ChunkRanges,
    boundaries: []u64,

    fn deinit(self: OwnedBaoRanges, allocator: std.mem.Allocator) void {
        allocator.free(self.boundaries);
    }
};

fn testId(seed: u8) key.NodeId {
    return key.SecretKey.fromBytes(.{seed} ** 32).public();
}

fn rangeSpecToBaoRanges(allocator: std.mem.Allocator, spec: range_spec.RangeSpec) Error!OwnedBaoRanges {
    const chunk_ranges = try spec.toChunkRanges(allocator);
    defer allocator.free(chunk_ranges);

    var boundaries: std.ArrayList(u64) = .empty;
    errdefer boundaries.deinit(allocator);
    for (chunk_ranges) |range| {
        try boundaries.append(allocator, range.start);
        if (range.end) |end| {
            try boundaries.append(allocator, end);
        } else break;
    }
    const owned = try boundaries.toOwnedSlice(allocator);
    return .{ .ranges = .{ .boundaries = owned }, .boundaries = owned };
}

fn rangeAt(allocator: std.mem.Allocator, seq: range_spec.ChunkRangesSeq, index: u64) Error!OwnedBaoRanges {
    var spec = range_spec.RangeSpec.empty;
    for (seq.entries) |entry| {
        if (entry.offset > index) break;
        spec = entry.spec;
    }
    return rangeSpecToBaoRanges(allocator, spec);
}

fn getManyAllRanges(entries: *[2]range_spec.ChunkRangesSeq.Entry, hashes_len: usize) Error!range_spec.ChunkRangesSeq {
    const end = std.math.cast(u64, hashes_len) orelse return error.TooManyHashes;
    entries.* = .{
        .{ .offset = 0, .spec = range_spec.RangeSpec.all() },
        .{ .offset = end, .spec = range_spec.RangeSpec.empty },
    };
    return .{ .entries = entries };
}

fn validatedHashSeq(bytes: []const u8, child_hashes: []const Hash) Error!hashseq.HashSeq {
    const seq = try hashseq.HashSeq.fromBytes(bytes);
    if (seq.len() != child_hashes.len) return error.LengthMismatch;
    for (child_hashes, 0..) |child_hash, i| {
        const authenticated = seq.get(i) orelse return error.LengthMismatch;
        if (!authenticated.eql(child_hash)) return error.HashMismatch;
    }
    return seq;
}

fn expectRequestEnd(reader: *std.Io.Reader) Error!void {
    _ = reader.takeByte() catch |err| switch (err) {
        error.EndOfStream => return,
        else => return err,
    };
    return error.UnexpectedData;
}

pub fn writeBlobResponse(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    requested_hash: Hash,
    data: []const u8,
    ranges: bao.ChunkRanges,
) Error!void {
    if (ranges.is_empty()) return;
    if (!Hash.of(data).eql(requested_hash)) return error.HashMismatch;

    const wire = if (ranges.is_all()) blk: {
        const created = try bao.createOutboard(allocator, data);
        defer if (created.outboard.len > 0) allocator.free(created.outboard);
        break :blk try bao.encodeAll(allocator, data, created.outboard);
    } else try bao.encodeRanges(allocator, data, ranges);
    defer allocator.free(wire);

    var size_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &size_buf, data.len, .little);
    try writer.writeAll(&size_buf);
    try writer.writeAll(wire);
}

/// Client: request a single blob and return verified bytes.
/// `hash` is both the requested identity and the verification root — they must match.
pub fn getBlob(allocator: std.mem.Allocator, conn: transport.Connection, hash: Hash, expected_hash: Hash) Error![]u8 {
    if (!hash.eql(expected_hash)) return error.HashMismatch;
    const bi = try conn.openBi();
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try protocol.GetRequest.blob(hash).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    var size_buf: [8]u8 = undefined;
    const sn = try bi.recv.reader().readSliceShort(&size_buf);
    if (sn != 8) return error.EndOfStream;
    const size = std.mem.readInt(u64, &size_buf, .little);

    return try bao.decodeVerified(allocator, expected_hash, size, bi.recv.reader());
}

/// Client: request a single blob sub-range and return concatenated verified bytes.
pub fn getBlobRanges(
    allocator: std.mem.Allocator,
    conn: transport.Connection,
    hash: Hash,
    expected_hash: Hash,
    ranges: range_spec.RangeSpec,
) Error![]u8 {
    if (!hash.eql(expected_hash)) return error.HashMismatch;
    const bi = try conn.openBi();
    var range_entries = [_]range_spec.ChunkRangesSeq.Entry{
        .{ .offset = 0, .spec = ranges },
        .{ .offset = 1, .spec = range_spec.RangeSpec.empty },
    };
    const req = protocol.GetRequest{ .hash = hash, .ranges = .{ .entries = &range_entries } };
    const req_storage = try allocator.alloc(u8, 64 + ranges.widths.len * 10);
    defer allocator.free(req_storage);
    var req_w: std.Io.Writer = .fixed(req_storage);
    try req.encode(&req_w);
    try bi.send.writer().writeAll(req_storage[0..req_w.end]);
    try bi.send.finish();

    var size_buf: [8]u8 = undefined;
    const sn = try bi.recv.reader().readSliceShort(&size_buf);
    if (sn != 8) return error.EndOfStream;
    const size = std.mem.readInt(u64, &size_buf, .little);

    const owned_ranges = try rangeSpecToBaoRanges(allocator, ranges);
    defer owned_ranges.deinit(allocator);
    return try bao.decodeVerifiedRanges(allocator, expected_hash, size, bi.recv.reader(), owned_ranges.ranges);
}

/// Provider: serve one blob (8-byte LE size + bao stream).
pub fn serveBlob(allocator: std.mem.Allocator, conn: transport.Connection, hash: Hash, data: []const u8) Error!void {
    const bi = try conn.acceptBi();
    errdefer bi.send.reset();
    const req_reader = bi.recv.reader();
    const req = try protocol.GetRequest.decode(allocator, req_reader);
    defer req.ranges.deinit(allocator);
    try expectRequestEnd(req_reader);
    if (!req.hash.eql(hash)) return error.HashMismatch;

    const ranges = try rangeAt(allocator, req.ranges, 0);
    defer ranges.deinit(allocator);
    try writeBlobResponse(allocator, bi.send.writer(), req.hash, data, ranges.ranges);
    try bi.send.finish();
}

/// Client: get hashseq root then each child blob listed in the sequence.
pub fn getAll(allocator: std.mem.Allocator, conn: transport.Connection, hash_seq_hash: Hash, child_hashes: []const Hash) Error!struct {
    hash_seq: []u8,
    children: [][]u8,
} {
    const bi = try conn.openBi();
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try protocol.GetRequest.all(hash_seq_hash).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    var size_buf: [8]u8 = undefined;
    const reader = bi.recv.reader();

    const sn = try reader.readSliceShort(&size_buf);
    if (sn != 8) return error.EndOfStream;
    const root_size = std.mem.readInt(u64, &size_buf, .little);
    const hash_seq = try bao.decodeVerified(allocator, hash_seq_hash, root_size, reader);
    errdefer allocator.free(hash_seq);

    const seq = try validatedHashSeq(hash_seq, child_hashes);

    const children = try allocator.alloc([]u8, child_hashes.len);
    var filled: usize = 0;
    errdefer {
        for (children[0..filled]) |c| allocator.free(c);
        allocator.free(children);
    }
    for (child_hashes, 0..) |_, i| {
        const cn = try reader.readSliceShort(&size_buf);
        if (cn != 8) return error.EndOfStream;
        const child_size = std.mem.readInt(u64, &size_buf, .little);
        const child_hash = seq.get(i) orelse return error.LengthMismatch;
        children[i] = try bao.decodeVerified(allocator, child_hash, child_size, reader);
        filled = i + 1;
    }

    return .{ .hash_seq = hash_seq, .children = children };
}

/// Provider: serve hashseq root + each child blob for GetRequest::all.
pub fn serveAll(
    allocator: std.mem.Allocator,
    conn: transport.Connection,
    hash_seq_bytes: []const u8,
    child_data: []const []const u8,
) Error!void {
    const bi = try conn.acceptBi();
    errdefer bi.send.reset();
    const req_reader = bi.recv.reader();
    const req = try protocol.GetRequest.decode(allocator, req_reader);
    defer req.ranges.deinit(allocator);
    try expectRequestEnd(req_reader);
    if (!req.hash.eql(Hash.of(hash_seq_bytes))) return error.HashMismatch;
    const seq = try hashseq.HashSeq.fromBytes(hash_seq_bytes);
    // Reject truncated OR over-long child lists (was `>` only — allowed truncated serve).
    if (child_data.len != seq.len()) return error.LengthMismatch;
    for (child_data, 0..) |data, i| {
        const expected = seq.get(i) orelse return error.LengthMismatch;
        if (!Hash.of(data).eql(expected)) return error.HashMismatch;
    }

    const root_ranges = try rangeAt(allocator, req.ranges, 0);
    defer root_ranges.deinit(allocator);
    try writeBlobResponse(allocator, bi.send.writer(), req.hash, hash_seq_bytes, root_ranges.ranges);

    for (child_data, 0..) |data, i| {
        const child_hash = seq.get(i) orelse return error.LengthMismatch;
        const child_ranges = try rangeAt(allocator, req.ranges, i + 1);
        defer child_ranges.deinit(allocator);
        try writeBlobResponse(allocator, bi.send.writer(), child_hash, data, child_ranges.ranges);
    }
    try bi.send.finish();
}

/// Client: request multiple raw blobs by sending their hashes directly.
pub fn getMany(allocator: std.mem.Allocator, conn: transport.Connection, hashes: []const Hash) Error![][]u8 {
    const bi = try conn.openBi();
    const req_buf = try allocator.alloc(u8, 1 + 10 + hashes.len * 32 + 64);
    defer allocator.free(req_buf);
    var req_w: std.Io.Writer = .fixed(req_buf);
    var range_entries: [2]range_spec.ChunkRangesSeq.Entry = undefined;
    try (protocol.GetManyRequest{ .hashes = hashes, .ranges = try getManyAllRanges(&range_entries, hashes.len) }).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    const children = try allocator.alloc([]u8, hashes.len);
    var filled: usize = 0;
    errdefer {
        for (children[0..filled]) |child| allocator.free(child);
        allocator.free(children);
    }

    var size_buf: [8]u8 = undefined;
    const reader = bi.recv.reader();
    for (hashes, 0..) |hash, i| {
        const sn = try reader.readSliceShort(&size_buf);
        if (sn != 8) return error.EndOfStream;
        const size = std.mem.readInt(u64, &size_buf, .little);
        children[i] = try bao.decodeVerified(allocator, hash, size, reader);
        filled = i + 1;
    }
    return children;
}

/// Provider: serve each requested GetMany child in request order.
pub fn serveMany(allocator: std.mem.Allocator, conn: transport.Connection, child_data: []const []const u8) Error!void {
    const bi = try conn.acceptBi();
    errdefer bi.send.reset();
    const req_reader = bi.recv.reader();
    const req = try protocol.GetManyRequest.decode(allocator, req_reader);
    defer req.deinit(allocator);
    try expectRequestEnd(req_reader);
    if (req.hashes.len != child_data.len) return error.LengthMismatch;

    for (child_data, 0..) |data, i| {
        const ranges = try rangeAt(allocator, req.ranges, i);
        defer ranges.deinit(allocator);
        try writeBlobResponse(allocator, bi.send.writer(), req.hashes[i], data, ranges.ranges);
    }
    try bi.send.finish();
}

test "single blob get round-trip" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(1), testId(2));
    defer pair.deinit(alloc);

    const data = try @import("fixtures.zig").makeTestData(alloc, 16385);
    defer alloc.free(data);
    const hash = Hash.of(data);

    const bi = try pair.client().openBi();
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try protocol.GetRequest.blob(hash).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    try serveBlob(alloc, pair.server(), hash, data);

    var size_buf: [8]u8 = undefined;
    const sn = try bi.recv.reader().readSliceShort(&size_buf);
    if (sn != 8) return error.EndOfStream;
    const size = std.mem.readInt(u64, &size_buf, .little);
    const got = try bao.decodeVerified(alloc, hash, size, bi.recv.reader());
    defer alloc.free(got);
    try std.testing.expectEqualSlices(u8, data, got);
}

test "single blob range get returns requested verified chunk bytes" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(7), testId(8));
    defer pair.deinit(alloc);

    const data = try @import("fixtures.zig").makeTestData(alloc, 65_537);
    defer alloc.free(data);
    const hash = Hash.of(data);

    const spec = try range_spec.RangeSpec.fromChunkRanges(alloc, &.{
        .{ .start = 1, .end = 3 },
        .{ .start = 5, .end = 6 },
    });
    defer spec.deinit(alloc);

    const bi = try pair.client().openBi();
    var range_entries = [_]range_spec.ChunkRangesSeq.Entry{
        .{ .offset = 0, .spec = spec },
        .{ .offset = 1, .spec = range_spec.RangeSpec.empty },
    };
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try (protocol.GetRequest{ .hash = hash, .ranges = .{ .entries = &range_entries } }).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    try serveBlob(alloc, pair.server(), hash, data);

    var size_buf: [8]u8 = undefined;
    const sn = try bi.recv.reader().readSliceShort(&size_buf);
    if (sn != 8) return error.EndOfStream;
    const size = std.mem.readInt(u64, &size_buf, .little);

    const ranges = try rangeSpecToBaoRanges(alloc, spec);
    defer ranges.deinit(alloc);
    const got = try bao.decodeVerifiedRanges(alloc, hash, size, bi.recv.reader(), ranges.ranges);
    defer alloc.free(got);

    const first = data[1 * bao.CHUNK_LEN .. 3 * bao.CHUNK_LEN];
    const second = data[5 * bao.CHUNK_LEN .. 6 * bao.CHUNK_LEN];
    try std.testing.expectEqual(first.len + second.len, got.len);
    try std.testing.expectEqualSlices(u8, first, got[0..first.len]);
    try std.testing.expectEqualSlices(u8, second, got[first.len..]);
}

test "verified-size range returns the authenticated final chunk" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(19), testId(20));
    defer pair.deinit(alloc);

    const data = try @import("fixtures.zig").makeTestData(alloc, 65_537);
    defer alloc.free(data);
    const hash = Hash.of(data);
    const spec = range_spec.RangeSpec.verifiedSize();

    const bi = try pair.client().openBi();
    var range_entries = [_]range_spec.ChunkRangesSeq.Entry{
        .{ .offset = 0, .spec = spec },
        .{ .offset = 1, .spec = range_spec.RangeSpec.empty },
    };
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try (protocol.GetRequest{ .hash = hash, .ranges = .{ .entries = &range_entries } }).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    try serveBlob(alloc, pair.server(), hash, data);

    var size_buf: [8]u8 = undefined;
    const sn = try bi.recv.reader().readSliceShort(&size_buf);
    if (sn != 8) return error.EndOfStream;
    const size = std.mem.readInt(u64, &size_buf, .little);
    const ranges = try rangeSpecToBaoRanges(alloc, spec);
    defer ranges.deinit(alloc);
    const got = try bao.decodeVerifiedRanges(alloc, hash, size, bi.recv.reader(), ranges.ranges);
    defer alloc.free(got);

    try std.testing.expectEqualSlices(u8, data[64 * bao.CHUNK_LEN ..], got);
}

test "zero-width selected spans stay empty at the Bao bridge" {
    const alloc = std.testing.allocator;
    inline for ([_][]const u64{ &.{ 0, 0 }, &.{ 1, 0 } }) |widths| {
        const ranges = try rangeSpecToBaoRanges(alloc, .{ .widths = widths });
        defer ranges.deinit(alloc);
        try std.testing.expect(ranges.ranges.is_empty());

        const wire = try bao.encodeRanges(alloc, "two chunks" ** 200, ranges.ranges);
        defer alloc.free(wire);
        try std.testing.expectEqual(@as(usize, 0), wire.len);
    }
}

test "serveBlob rejects caller bytes that do not match requested hash" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(9), testId(10));
    defer pair.deinit(alloc);

    const data = try @import("fixtures.zig").makeTestData(alloc, 2048);
    defer alloc.free(data);
    const other = try @import("fixtures.zig").makeTestData(alloc, 2049);
    defer alloc.free(other);
    const hash = Hash.of(data);

    const bi = try pair.client().openBi();
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try protocol.GetRequest.blob(hash).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    try std.testing.expectError(error.HashMismatch, serveBlob(alloc, pair.server(), hash, other));
}

test "serveBlob rejects trailing request bytes" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(11), testId(12));
    defer pair.deinit(alloc);

    const data = "requested blob";
    const hash = Hash.of(data);
    const bi = try pair.client().openBi();
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try protocol.GetRequest.blob(hash).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.writer().writeByte(0xff);
    try bi.send.finish();

    try std.testing.expectError(error.UnexpectedData, serveBlob(alloc, pair.server(), hash, data));
}

test "hashseq multi-blob get" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(3), testId(4));
    defer pair.deinit(alloc);

    const child0 = try @import("fixtures.zig").makeTestData(alloc, 512);
    defer alloc.free(child0);
    const child1 = try @import("fixtures.zig").makeTestData(alloc, 1024);
    defer alloc.free(child1);
    const h0 = Hash.of(child0);
    const h1 = Hash.of(child1);
    var seq = try hashseq.HashSeq.fromHashes(alloc, &.{ h0, h1 });
    defer seq.deinit(alloc);
    const seq_hash = Hash.of(seq.bytes);

    const bi = try pair.client().openBi();
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try protocol.GetRequest.all(seq_hash).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    try serveAll(alloc, pair.server(), seq.bytes, &.{ child0, child1 });

    var size_buf: [8]u8 = undefined;
    const reader = bi.recv.reader();
    const sn = try reader.readSliceShort(&size_buf);
    if (sn != 8) return error.EndOfStream;
    const root_size = std.mem.readInt(u64, &size_buf, .little);
    const hash_seq = try bao.decodeVerified(alloc, seq_hash, root_size, reader);
    const children = try alloc.alloc([]u8, 2);
    errdefer {
        alloc.free(hash_seq);
        for (children) |c| alloc.free(c);
        alloc.free(children);
    }
    for (0..2) |i| {
        const cn = try reader.readSliceShort(&size_buf);
        if (cn != 8) return error.EndOfStream;
        const child_size = std.mem.readInt(u64, &size_buf, .little);
        children[i] = try bao.decodeVerified(alloc, (if (i == 0) h0 else h1), child_size, reader);
    }
    defer {
        alloc.free(hash_seq);
        for (children) |c| alloc.free(c);
        alloc.free(children);
    }
    try std.testing.expectEqualSlices(u8, seq.bytes, hash_seq);
    try std.testing.expectEqualSlices(u8, child0, children[0]);
    try std.testing.expectEqualSlices(u8, child1, children[1]);
}

test "getAll binds caller child hashes to authenticated hash sequence" {
    const alloc = std.testing.allocator;
    const h0 = Hash.of("child0");
    const h1 = Hash.of("child1");
    var seq = try hashseq.HashSeq.fromHashes(alloc, &.{ h0, h1 });
    defer seq.deinit(alloc);

    const validated = try validatedHashSeq(seq.bytes, &.{ h0, h1 });
    try std.testing.expectEqual(@as(usize, 2), validated.len());
    try std.testing.expectError(error.LengthMismatch, validatedHashSeq(seq.bytes, &.{h0}));
    try std.testing.expectError(error.HashMismatch, validatedHashSeq(seq.bytes, &.{ h0, Hash.of("other") }));

    const malformed = [_]u8{0} ** 33;
    try std.testing.expectError(error.InvalidHashSeq, validatedHashSeq(&malformed, &.{h0}));
}

test "getAll rejects a caller-selected child outside the authenticated sequence" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(13), testId(14));
    defer pair.deinit(alloc);

    const linked_hash = Hash.of("linked child");
    const attacker_data = "attacker-selected child";
    const attacker_hash = Hash.of(attacker_data);
    var seq = try hashseq.HashSeq.fromHashes(alloc, &.{linked_hash});
    defer seq.deinit(alloc);

    const response = try pair.server().openBi();
    try writeBlobResponse(alloc, response.send.writer(), Hash.of(seq.bytes), seq.bytes, bao.ChunkRanges.all());
    try writeBlobResponse(alloc, response.send.writer(), attacker_hash, attacker_data, bao.ChunkRanges.all());
    try response.send.finish();

    try std.testing.expectError(
        error.HashMismatch,
        getAll(alloc, pair.client(), Hash.of(seq.bytes), &.{attacker_hash}),
    );
}

test "getAll rejects malformed verified hash sequence" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(15), testId(16));
    defer pair.deinit(alloc);

    const malformed = [_]u8{0} ** 33;
    const response = try pair.server().openBi();
    try writeBlobResponse(alloc, response.send.writer(), Hash.of(&malformed), &malformed, bao.ChunkRanges.all());
    try response.send.finish();

    try std.testing.expectError(
        error.InvalidHashSeq,
        getAll(alloc, pair.client(), Hash.of(&malformed), &.{Hash.of("ignored")}),
    );
}

test "getAll frees earlier children when a later child fails verification" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(17), testId(18));
    defer pair.deinit(alloc);

    const child0 = "first child";
    const child1 = "second child";
    const corrupt = "not the second child";
    const h0 = Hash.of(child0);
    const h1 = Hash.of(child1);
    var seq = try hashseq.HashSeq.fromHashes(alloc, &.{ h0, h1 });
    defer seq.deinit(alloc);

    const response = try pair.server().openBi();
    try writeBlobResponse(alloc, response.send.writer(), Hash.of(seq.bytes), seq.bytes, bao.ChunkRanges.all());
    try writeBlobResponse(alloc, response.send.writer(), h0, child0, bao.ChunkRanges.all());
    try writeBlobResponse(alloc, response.send.writer(), Hash.of(corrupt), corrupt, bao.ChunkRanges.all());
    try response.send.finish();

    try std.testing.expectError(
        error.LeafHashMismatch,
        getAll(alloc, pair.client(), Hash.of(seq.bytes), &.{ h0, h1 }),
    );
}

test "get many round-trip" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(5), testId(6));
    defer pair.deinit(alloc);

    const child0 = try @import("fixtures.zig").makeTestData(alloc, 257);
    defer alloc.free(child0);
    const child1 = try @import("fixtures.zig").makeTestData(alloc, 8193);
    defer alloc.free(child1);
    const hashes = &[_]Hash{ Hash.of(child0), Hash.of(child1) };

    const bi = try pair.client().openBi();
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    var range_entries: [2]range_spec.ChunkRangesSeq.Entry = undefined;
    try (protocol.GetManyRequest{ .hashes = hashes, .ranges = try getManyAllRanges(&range_entries, hashes.len) }).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    try serveMany(alloc, pair.server(), &.{ child0, child1 });

    var size_buf: [8]u8 = undefined;
    const reader = bi.recv.reader();
    const sn0 = try reader.readSliceShort(&size_buf);
    if (sn0 != 8) return error.EndOfStream;
    const size0 = std.mem.readInt(u64, &size_buf, .little);
    const got0 = try bao.decodeVerified(alloc, hashes[0], size0, reader);
    defer alloc.free(got0);

    const sn1 = try reader.readSliceShort(&size_buf);
    if (sn1 != 8) return error.EndOfStream;
    const size1 = std.mem.readInt(u64, &size_buf, .little);
    const got1 = try bao.decodeVerified(alloc, hashes[1], size1, reader);
    defer alloc.free(got1);

    try std.testing.expectEqualSlices(u8, child0, got0);
    try std.testing.expectEqualSlices(u8, child1, got1);
}
