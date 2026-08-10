//! Get protocol over MockTransport.

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const transport = @import("transport");
const mock = @import("../transport/mock.zig");
const key = @import("../key.zig");
const protocol = @import("protocol.zig");
const bao = @import("bao.zig");
const hashseq = @import("hashseq.zig");
const range_spec = @import("range_spec.zig");
const provider_policy = @import("provider_policy.zig");

pub const Policy = provider_policy.Policy;

pub const Error = protocol.Error || bao.Error || hashseq.Error || transport.Error || provider_policy.PolicyError || error{
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

/// Read one provider blob frame (8-byte LE size + bao body) and verify.
/// Caller must only invoke this when the selected ranges are non-empty — empty
/// selections emit no frame (see `writeBlobResponse` / iroh `iter_non_empty`).
fn readVerifiedBlobFrame(
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    expected_hash: Hash,
    ranges: bao.ChunkRanges,
) Error![]u8 {
    var size_buf: [8]u8 = undefined;
    const sn = try reader.readSliceShort(&size_buf);
    if (sn != 8) return error.EndOfStream;
    const size = std.mem.readInt(u64, &size_buf, .little);
    return try bao.decodeVerifiedRanges(allocator, expected_hash, size, reader, ranges);
}

pub fn writeBlobResponse(
    allocator: std.mem.Allocator,
    writer: *std.Io.Writer,
    requested_hash: Hash,
    data: []const u8,
    ranges: bao.ChunkRanges,
) Error!void {
    // Match iroh-blobs provider (`handle_get`/`handle_get_many`): empty per-blob
    // ranges emit NO size header and NO body. Clients iterate non-empty ranges
    // only (`iter_non_empty_infinite`), so a size-header-with-empty-body would
    // desync against real peers. Do not invent a third wire behavior.
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
pub fn getBlob(allocator: std.mem.Allocator, conn: anytype, hash: Hash, expected_hash: Hash) Error![]u8 {
    if (!hash.eql(expected_hash)) return error.HashMismatch;
    const bi = try conn.openBi();
    errdefer bi.recv.stop() catch {};
    errdefer bi.send.reset();
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try protocol.GetRequest.blob(hash).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    return try readVerifiedBlobFrame(allocator, bi.recv.reader(), expected_hash, bao.ChunkRanges.all());
}

/// Client: request a single blob sub-range and return concatenated verified bytes.
///
/// Empty selections (`RangeSpec.empty` or zero-width spans that become empty at
/// the bao bridge) match provider `writeBlobResponse` / iroh `iter_non_empty`:
/// no size header is written, so this returns an empty owned slice **without**
/// opening a frame read (and without dialing a bi-stream).
pub fn getBlobRanges(
    allocator: std.mem.Allocator,
    conn: anytype,
    hash: Hash,
    expected_hash: Hash,
    ranges: range_spec.RangeSpec,
) Error![]u8 {
    if (!hash.eql(expected_hash)) return error.HashMismatch;

    const owned_ranges = try rangeSpecToBaoRanges(allocator, ranges);
    defer owned_ranges.deinit(allocator);
    // F24: empty → no wire frame. Do not readSliceShort(8); that hangs/desyncs
    // against a correct F05 provider that omits the size header entirely.
    if (owned_ranges.ranges.is_empty()) return try allocator.alloc(u8, 0);

    const bi = try conn.openBi();
    errdefer bi.recv.stop() catch {};
    errdefer bi.send.reset();
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

    return try readVerifiedBlobFrame(allocator, bi.recv.reader(), expected_hash, owned_ranges.ranges);
}

/// Provider: serve one blob (8-byte LE size + bao stream).
/// Uses `Policy.allow_all` so existing callers keep today's serve behavior.
/// Production hosts should use `provider.Provider` (push-deny by default).
pub fn serveBlob(allocator: std.mem.Allocator, conn: anytype, hash: Hash, data: []const u8) Error!void {
    return serveBlobWithPolicy(allocator, conn, hash, data, Policy.allow_all);
}

/// Provider: serve one blob under an explicit policy.
pub fn serveBlobWithPolicy(
    allocator: std.mem.Allocator,
    conn: anytype,
    hash: Hash,
    data: []const u8,
    policy: Policy,
) Error!void {
    const bi = try conn.acceptBi();
    errdefer bi.send.reset();
    try provider_policy.gateBi(policy, .get, bi);
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

pub const GetAllResult = struct {
    hash_seq: []u8,
    children: [][]u8,
};

/// Client: get hashseq root then each child blob listed in the sequence.
pub fn getAll(allocator: std.mem.Allocator, conn: anytype, hash_seq_hash: Hash, child_hashes: []const Hash) Error!GetAllResult {
    return getAllRanges(allocator, conn, hash_seq_hash, child_hashes, range_spec.ChunkRangesSeq.all());
}

/// Client: GetRequest::all with an explicit `ChunkRangesSeq`.
///
/// Empty per-blob range slots produce **no** size header on the wire (provider
/// `writeBlobResponse` / iroh `iter_non_empty_infinite`). This reader advances
/// only for non-empty slots; empty child slots return an empty owned slice.
/// Root (index 0) must be non-empty so the authenticated hash sequence can be
/// verified against `child_hashes`.
pub fn getAllRanges(
    allocator: std.mem.Allocator,
    conn: anytype,
    hash_seq_hash: Hash,
    child_hashes: []const Hash,
    ranges: range_spec.ChunkRangesSeq,
) Error!GetAllResult {
    const bi = try conn.openBi();
    errdefer bi.recv.stop() catch {};
    errdefer bi.send.reset();
    const req_storage = try allocator.alloc(u8, 64 + ranges.entries.len * 24);
    defer allocator.free(req_storage);
    var req_w: std.Io.Writer = .fixed(req_storage);
    try (protocol.GetRequest{ .hash = hash_seq_hash, .ranges = ranges }).encode(&req_w);
    try bi.send.writer().writeAll(req_storage[0..req_w.end]);
    try bi.send.finish();

    const reader = bi.recv.reader();

    const root_ranges = try rangeAt(allocator, ranges, 0);
    defer root_ranges.deinit(allocator);
    if (root_ranges.ranges.is_empty()) return error.UnexpectedData;
    const hash_seq = try readVerifiedBlobFrame(allocator, reader, hash_seq_hash, root_ranges.ranges);
    errdefer allocator.free(hash_seq);

    const seq = try validatedHashSeq(hash_seq, child_hashes);

    const children = try allocator.alloc([]u8, child_hashes.len);
    var filled: usize = 0;
    errdefer {
        for (children[0..filled]) |c| allocator.free(c);
        allocator.free(children);
    }
    for (child_hashes, 0..) |_, i| {
        const child_ranges = try rangeAt(allocator, ranges, i + 1);
        defer child_ranges.deinit(allocator);
        if (child_ranges.ranges.is_empty()) {
            // F32: match provider empty skip — no frame to read.
            children[i] = try allocator.alloc(u8, 0);
            filled = i + 1;
            continue;
        }
        const child_hash = seq.get(i) orelse return error.LengthMismatch;
        children[i] = try readVerifiedBlobFrame(allocator, reader, child_hash, child_ranges.ranges);
        filled = i + 1;
    }

    return .{ .hash_seq = hash_seq, .children = children };
}

/// Provider: serve hashseq root + each child blob for GetRequest::all.
/// Compatibility wrapper (`Policy.allow_all`) — production hosts should use
/// `provider.Provider` (push-deny by default).
pub fn serveAll(
    allocator: std.mem.Allocator,
    conn: anytype,
    hash_seq_bytes: []const u8,
    child_data: []const []const u8,
) Error!void {
    return serveAllWithPolicy(allocator, conn, hash_seq_bytes, child_data, Policy.allow_all);
}

pub fn serveAllWithPolicy(
    allocator: std.mem.Allocator,
    conn: anytype,
    hash_seq_bytes: []const u8,
    child_data: []const []const u8,
    policy: Policy,
) Error!void {
    const bi = try conn.acceptBi();
    errdefer bi.send.reset();
    try provider_policy.gateBi(policy, .get, bi);
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
pub fn getMany(allocator: std.mem.Allocator, conn: anytype, hashes: []const Hash) Error![][]u8 {
    var range_entries: [2]range_spec.ChunkRangesSeq.Entry = undefined;
    return getManyRanges(allocator, conn, hashes, try getManyAllRanges(&range_entries, hashes.len));
}

/// Client: GetMany with an explicit `ChunkRangesSeq`.
///
/// Empty per-hash range slots produce **no** size header (provider F05 /
/// iroh `iter_non_empty`). Those slots return an empty owned slice without a
/// size-header read so subsequent non-empty children stay frame-aligned.
pub fn getManyRanges(
    allocator: std.mem.Allocator,
    conn: anytype,
    hashes: []const Hash,
    ranges: range_spec.ChunkRangesSeq,
) Error![][]u8 {
    const bi = try conn.openBi();
    errdefer bi.recv.stop() catch {};
    errdefer bi.send.reset();
    const req_buf = try allocator.alloc(u8, 1 + 10 + hashes.len * 32 + 64 + ranges.entries.len * 24);
    defer allocator.free(req_buf);
    var req_w: std.Io.Writer = .fixed(req_buf);
    try (protocol.GetManyRequest{ .hashes = hashes, .ranges = ranges }).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    const children = try allocator.alloc([]u8, hashes.len);
    var filled: usize = 0;
    errdefer {
        for (children[0..filled]) |child| allocator.free(child);
        allocator.free(children);
    }

    const reader = bi.recv.reader();
    for (hashes, 0..) |hash, i| {
        const child_ranges = try rangeAt(allocator, ranges, i);
        defer child_ranges.deinit(allocator);
        if (child_ranges.ranges.is_empty()) {
            // F32: match provider empty skip — no frame to read.
            children[i] = try allocator.alloc(u8, 0);
            filled = i + 1;
            continue;
        }
        children[i] = try readVerifiedBlobFrame(allocator, reader, hash, child_ranges.ranges);
        filled = i + 1;
    }
    return children;
}

/// Provider: serve each requested GetMany child in request order.
/// Compatibility wrapper (`Policy.allow_all`) — production hosts should use
/// `provider.Provider` (push-deny by default).
pub fn serveMany(allocator: std.mem.Allocator, conn: anytype, child_data: []const []const u8) Error!void {
    return serveManyWithPolicy(allocator, conn, child_data, Policy.allow_all);
}

pub fn serveManyWithPolicy(
    allocator: std.mem.Allocator,
    conn: anytype,
    child_data: []const []const u8,
    policy: Policy,
) Error!void {
    const bi = try conn.acceptBi();
    errdefer bi.send.reset();
    try provider_policy.gateBi(policy, .get_many, bi);
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

test "F04 getBlob error path resets send and stops recv" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(21), testId(22));
    defer pair.deinit(alloc);

    // No provider response: client openBi + write succeeds, then size read hits EndOfStream.
    const want = Hash.of("missing blob");
    try std.testing.expectError(error.EndOfStream, getBlob(alloc, pair.client(), want, want));

    const life = pair.lifecycle();
    try std.testing.expect(life.client_send_reset);
    try std.testing.expect(life.client_recv_stopped);
}

test "F04 getAll error path resets send and stops recv" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(23), testId(24));
    defer pair.deinit(alloc);

    const root = Hash.of("missing hashseq");
    try std.testing.expectError(
        error.EndOfStream,
        getAll(alloc, pair.client(), root, &.{Hash.of("child")}),
    );
    const life = pair.lifecycle();
    try std.testing.expect(life.client_send_reset);
    try std.testing.expect(life.client_recv_stopped);
}

test "F04 getMany error path resets send and stops recv" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(25), testId(26));
    defer pair.deinit(alloc);

    try std.testing.expectError(
        error.EndOfStream,
        getMany(alloc, pair.client(), &.{Hash.of("a")}),
    );
    const life = pair.lifecycle();
    try std.testing.expect(life.client_send_reset);
    try std.testing.expect(life.client_recv_stopped);
}

test "F05 empty per-blob ranges omit size header; next child frames stay aligned" {
    // Wire determination (iroh-blobs provider.rs handle_get / handle_get_many):
    // empty ChunkRanges are skipped entirely — no 8-byte LE size, no bao body.
    // Clients use iter_non_empty_infinite, so they never read a frame for empty
    // slots. Emitting a size header with empty body would desync against real
    // peers; skipping is the matched behavior.
    const alloc = std.testing.allocator;

    const child0 = try @import("fixtures.zig").makeTestData(alloc, 512);
    defer alloc.free(child0);
    const child1 = try @import("fixtures.zig").makeTestData(alloc, 1024);
    defer alloc.free(child1);
    const h0 = Hash.of(child0);
    const h1 = Hash.of(child1);
    var seq = try hashseq.HashSeq.fromHashes(alloc, &.{ h0, h1 });
    defer seq.deinit(alloc);
    const seq_hash = Hash.of(seq.bytes);

    var out_buf: std.Io.Writer.Allocating = .init(alloc);
    defer out_buf.deinit();
    const w = &out_buf.writer;

    // Root (hashseq) full, child0 empty (deselected), child1 full.
    try writeBlobResponse(alloc, w, seq_hash, seq.bytes, bao.ChunkRanges.all());
    try writeBlobResponse(alloc, w, h0, child0, bao.ChunkRanges.empty());
    try writeBlobResponse(alloc, w, h1, child1, bao.ChunkRanges.all());

    const bytes = out_buf.written();
    var r: std.Io.Reader = .fixed(bytes);

    // Frame 0: root size + bao
    var size_buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 8), try r.readSliceShort(&size_buf));
    const root_size = std.mem.readInt(u64, &size_buf, .little);
    const got_seq = try bao.decodeVerified(alloc, seq_hash, root_size, &r);
    defer alloc.free(got_seq);
    try std.testing.expectEqualSlices(u8, seq.bytes, got_seq);

    // No frame for deselected child0: next 8 bytes are child1's size, not
    // child0's. A pre-fix client that always read N child frames would treat
    // child1's size as child0's and bao-verify against the wrong root.
    try std.testing.expectEqual(@as(usize, 8), try r.readSliceShort(&size_buf));
    const child1_size = std.mem.readInt(u64, &size_buf, .little);
    try std.testing.expectEqual(@as(u64, child1.len), child1_size);
    const got1 = try bao.decodeVerified(alloc, h1, child1_size, &r);
    defer alloc.free(got1);
    try std.testing.expectEqualSlices(u8, child1, got1);

    // Stream exhausted — no trailing phantom frame for the empty child.
    try std.testing.expectEqual(@as(usize, 0), try r.readSliceShort(&size_buf));
}

test "F05 serveMany skips empty selected ranges without desyncing next child" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(27), testId(28));
    defer pair.deinit(alloc);

    const child0 = try @import("fixtures.zig").makeTestData(alloc, 300);
    defer alloc.free(child0);
    const child1 = try @import("fixtures.zig").makeTestData(alloc, 700);
    defer alloc.free(child1);
    const hashes = &[_]Hash{ Hash.of(child0), Hash.of(child1) };

    // Request: child0 empty, child1 all — wire-legal ChunkRangesSeq.
    const bi = try pair.client().openBi();
    var req_buf: [256]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    var range_entries = [_]range_spec.ChunkRangesSeq.Entry{
        .{ .offset = 0, .spec = range_spec.RangeSpec.empty },
        .{ .offset = 1, .spec = range_spec.RangeSpec.all() },
        .{ .offset = 2, .spec = range_spec.RangeSpec.empty },
    };
    try (protocol.GetManyRequest{ .hashes = hashes, .ranges = .{ .entries = &range_entries } }).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    try serveMany(alloc, pair.server(), &.{ child0, child1 });

    var size_buf: [8]u8 = undefined;
    const reader = bi.recv.reader();
    // Only child1 produces a frame.
    const sn = try reader.readSliceShort(&size_buf);
    try std.testing.expectEqual(@as(usize, 8), sn);
    const size1 = std.mem.readInt(u64, &size_buf, .little);
    const got1 = try bao.decodeVerified(alloc, hashes[1], size1, reader);
    defer alloc.free(got1);
    try std.testing.expectEqualSlices(u8, child1, got1);
    try std.testing.expectEqual(@as(usize, 0), try reader.readSliceShort(&size_buf));
}

test "F24 getBlobRanges empty RangeSpec returns empty without frame read" {
    // Pre-fix always readSliceShort(8) after openBi; with no provider frame that
    // is EndOfStream / hang. Post-fix short-circuits on empty bao ranges and
    // never opens a frame read — matches provider F05 (no size header).
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(29), testId(30));
    defer pair.deinit(alloc);

    const hash = Hash.of("ignored when ranges empty");
    // No provider response at all.
    const got = try getBlobRanges(alloc, pair.client(), hash, hash, range_spec.RangeSpec.empty);
    defer alloc.free(got);
    try std.testing.expectEqual(@as(usize, 0), got.len);

    // Zero-width selection that becomes empty at the bao bridge (same contract).
    const zero_width = range_spec.RangeSpec{ .widths = &.{ 0, 0 } };
    const got_zw = try getBlobRanges(alloc, pair.client(), hash, hash, zero_width);
    defer alloc.free(got_zw);
    try std.testing.expectEqual(@as(usize, 0), got_zw.len);
}

test "F32 getManyRanges skips empty child frames against F05 provider" {
    // Provider writeBlobResponse omits frames for empty ranges (F05). Pre-fix
    // clients that always read N size headers bao-verify child1 as child0.
    // getManyRanges advances only non-empty slots (iroh iter_non_empty).
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(31), testId(32));
    defer pair.deinit(alloc);

    const child0 = try @import("fixtures.zig").makeTestData(alloc, 300);
    defer alloc.free(child0);
    const child1 = try @import("fixtures.zig").makeTestData(alloc, 700);
    defer alloc.free(child1);
    const hashes = &[_]Hash{ Hash.of(child0), Hash.of(child1) };

    var range_entries = [_]range_spec.ChunkRangesSeq.Entry{
        .{ .offset = 0, .spec = range_spec.RangeSpec.empty },
        .{ .offset = 1, .spec = range_spec.RangeSpec.all() },
        .{ .offset = 2, .spec = range_spec.RangeSpec.empty },
    };
    const ranges: range_spec.ChunkRangesSeq = .{ .entries = &range_entries };

    // Pre-stage the F05 provider wire (mock is write-then-read, not concurrent).
    const response = try pair.server().openBi();
    try writeBlobResponse(alloc, response.send.writer(), hashes[0], child0, bao.ChunkRanges.empty());
    try writeBlobResponse(alloc, response.send.writer(), hashes[1], child1, bao.ChunkRanges.all());
    try response.send.finish();

    const got = try getManyRanges(alloc, pair.client(), hashes, ranges);
    defer {
        for (got) |c| alloc.free(c);
        alloc.free(got);
    }
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqual(@as(usize, 0), got[0].len);
    try std.testing.expectEqualSlices(u8, child1, got[1]);
}

test "F32 getAllRanges skips empty child frames against F05 provider" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(33), testId(34));
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

    // Root all, child0 empty, child1 all — wire-legal; provider skips child0 frame.
    var range_entries = [_]range_spec.ChunkRangesSeq.Entry{
        .{ .offset = 0, .spec = range_spec.RangeSpec.all() },
        .{ .offset = 1, .spec = range_spec.RangeSpec.empty },
        .{ .offset = 2, .spec = range_spec.RangeSpec.all() },
        .{ .offset = 3, .spec = range_spec.RangeSpec.empty },
    };
    const ranges: range_spec.ChunkRangesSeq = .{ .entries = &range_entries };

    const response = try pair.server().openBi();
    try writeBlobResponse(alloc, response.send.writer(), seq_hash, seq.bytes, bao.ChunkRanges.all());
    try writeBlobResponse(alloc, response.send.writer(), h0, child0, bao.ChunkRanges.empty());
    try writeBlobResponse(alloc, response.send.writer(), h1, child1, bao.ChunkRanges.all());
    try response.send.finish();

    const got = try getAllRanges(alloc, pair.client(), seq_hash, &.{ h0, h1 }, ranges);
    defer {
        alloc.free(got.hash_seq);
        for (got.children) |c| alloc.free(c);
        alloc.free(got.children);
    }
    try std.testing.expectEqualSlices(u8, seq.bytes, got.hash_seq);
    try std.testing.expectEqual(@as(usize, 0), got.children[0].len);
    try std.testing.expectEqualSlices(u8, child1, got.children[1]);
}

test "policy deny aborts get without response body (peer-visible reset)" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(40), testId(41));
    defer pair.deinit(alloc);

    const data = try @import("fixtures.zig").makeTestData(alloc, 1024);
    defer alloc.free(data);
    const hash = Hash.of(data);

    const bi = try pair.client().openBi();
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try protocol.GetRequest.blob(hash).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    const deny = Policy{ .get = .deny };
    try std.testing.expectError(error.PermissionDenied, serveBlobWithPolicy(alloc, pair.server(), hash, data, deny));

    const life = pair.lifecycle();
    try std.testing.expect(life.server_send_reset);
    try std.testing.expectEqual(@as(?u64, protocol.ERR_PERMISSION), life.server_send_reset_code);
    try std.testing.expect(life.server_recv_stopped);
    // No finished response body for the client to consume.
    try std.testing.expect(!life.server_send_finished);
}

test "policy allow get serves byte-identical to unpolicy path" {
    const alloc = std.testing.allocator;
    const data = try @import("fixtures.zig").makeTestData(alloc, 4096);
    defer alloc.free(data);
    const hash = Hash.of(data);

    const pair_a = mock.Pair.init(alloc, std.testing.io, testId(42), testId(43));
    defer pair_a.deinit(alloc);
    const pair_b = mock.Pair.init(alloc, std.testing.io, testId(44), testId(45));
    defer pair_b.deinit(alloc);

    // Client A: legacy serveBlob (allow_all)
    {
        const bi = try pair_a.client().openBi();
        var req_buf: [128]u8 = undefined;
        var req_w: std.Io.Writer = .fixed(&req_buf);
        try protocol.GetRequest.blob(hash).encode(&req_w);
        try bi.send.writer().writeAll(req_buf[0..req_w.end]);
        try bi.send.finish();
        try serveBlob(alloc, pair_a.server(), hash, data);
    }
    // Client B: explicit allow policy
    {
        const bi = try pair_b.client().openBi();
        var req_buf: [128]u8 = undefined;
        var req_w: std.Io.Writer = .fixed(&req_buf);
        try protocol.GetRequest.blob(hash).encode(&req_w);
        try bi.send.writer().writeAll(req_buf[0..req_w.end]);
        try bi.send.finish();
        try serveBlobWithPolicy(alloc, pair_b.server(), hash, data, Policy.allow_all);
    }

    const wire_a = pair_a.b2a.sink.written();
    const wire_b = pair_b.b2a.sink.written();
    try std.testing.expectEqualSlices(u8, wire_a, wire_b);
}

test "policy intercept can deny get_many with rate_limited code" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(46), testId(47));
    defer pair.deinit(alloc);

    const child = try @import("fixtures.zig").makeTestData(alloc, 256);
    defer alloc.free(child);
    const hash = Hash.of(child);

    const bi = try pair.client().openBi();
    var range_entries: [2]range_spec.ChunkRangesSeq.Entry = undefined;
    const ranges = try getManyAllRanges(&range_entries, 1);
    const req_buf = try alloc.alloc(u8, 256);
    defer alloc.free(req_buf);
    var req_w: std.Io.Writer = .fixed(req_buf);
    try (protocol.GetManyRequest{ .hashes = &.{hash}, .ranges = ranges }).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    const Hook = struct {
        fn on(_: ?*anyopaque, _: provider_policy.RequestKind) provider_policy.Decision {
            return .{ .deny = .rate_limited };
        }
    };
    const policy = Policy{
        .get_many = .intercept,
        .on_request = Hook.on,
    };
    try std.testing.expectError(
        error.RateLimited,
        serveManyWithPolicy(alloc, pair.server(), &.{child}, policy),
    );
    const life = pair.lifecycle();
    try std.testing.expect(life.server_send_reset);
    try std.testing.expectEqual(@as(?u64, protocol.ERR_LIMIT), life.server_send_reset_code);
}

test "policy notify on get serves and records hook call" {
    const alloc = std.testing.allocator;
    const pair = mock.Pair.init(alloc, std.testing.io, testId(48), testId(49));
    defer pair.deinit(alloc);

    const data = try @import("fixtures.zig").makeTestData(alloc, 512);
    defer alloc.free(data);
    const hash = Hash.of(data);

    const bi = try pair.client().openBi();
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try protocol.GetRequest.blob(hash).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    var called: usize = 0;
    const Hook = struct {
        fn on(ctx: ?*anyopaque, kind: provider_policy.RequestKind) provider_policy.Decision {
            const c: *usize = @ptrCast(@alignCast(ctx.?));
            c.* += 1;
            std.debug.assert(kind == .get);
            return .{ .deny = .permission }; // notify must ignore deny
        }
    };
    const policy = Policy{
        .get = .notify,
        .hook_ctx = &called,
        .on_request = Hook.on,
    };
    try serveBlobWithPolicy(alloc, pair.server(), hash, data, policy);
    try std.testing.expectEqual(@as(usize, 1), called);
    try std.testing.expect(pair.lifecycle().server_send_finished);
}
