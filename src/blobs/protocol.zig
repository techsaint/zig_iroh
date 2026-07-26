//! Blobs request framing (postcard).
//!
//! Mirrors the request and observation framing in
//! `original/iroh-blobs/src/protocol.rs`.

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const bao = @import("bao.zig");
const range_spec = @import("range_spec.zig");
const postcard = @import("postcard.zig");

pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

pub const Error = postcard.Error || range_spec.Error || error{
    UnknownRequestType,
    MessageTooLarge,
    TrailingFrameData,
    ReadFailed,
    WriteFailed,
};

pub const RequestType = enum(u8) {
    get = 0,
    observe = 1,
    push = 8,
    get_many = 9,
    _,
};

pub const GetRequest = struct {
    hash: Hash,
    ranges: range_spec.ChunkRangesSeq,

    pub fn blob(hash: Hash) GetRequest {
        return .{ .hash = hash, .ranges = range_spec.ChunkRangesSeq.singleBlob() };
    }

    pub fn all(hash: Hash) GetRequest {
        return .{ .hash = hash, .ranges = range_spec.ChunkRangesSeq.all() };
    }

    pub fn encode(self: GetRequest, w: *std.Io.Writer) Error!void {
        try w.writeByte(@intFromEnum(RequestType.get));
        try w.writeAll(&self.hash.bytes);
        try self.ranges.encode(w);
    }

    pub fn decode(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!GetRequest {
        var limit_buf: [1]u8 = undefined;
        var limited = r.limited(.limited(MAX_MESSAGE_SIZE), &limit_buf);
        return decodeLimited(allocator, &limited.interface);
    }

    fn decodeLimited(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!GetRequest {
        const tag = try r.takeByte();
        if (tag != @intFromEnum(RequestType.get)) return error.UnknownRequestType;
        var hash_bytes: [32]u8 = undefined;
        const n = try r.readSliceShort(&hash_bytes);
        if (n != 32) return error.EndOfStream;
        const ranges = try decodeChunkRangesSeq(allocator, r, false);
        return .{ .hash = Hash.fromBytes(hash_bytes), .ranges = ranges };
    }
};

/// The postcard representation of `bao_tree::ChunkRanges`: sorted range-set
/// boundaries encoded as a sequence of `u64` values.
pub const ChunkRanges = bao.ChunkRanges;

pub const ObserveRequest = struct {
    hash: Hash,
    ranges: range_spec.RangeSpec,
    owns_ranges: bool = false,

    pub fn new(hash: Hash) ObserveRequest {
        return .{ .hash = hash, .ranges = range_spec.RangeSpec.all() };
    }

    pub fn all(hash: Hash) ObserveRequest {
        return .new(hash);
    }

    pub fn encode(self: ObserveRequest, w: *std.Io.Writer) Error!void {
        _ = try encodedBodySize(self);
        try w.writeByte(@intFromEnum(RequestType.observe));
        try self.encodeBody(w);
    }

    fn encodeBody(self: ObserveRequest, w: *std.Io.Writer) Error!void {
        try w.writeAll(&self.hash.bytes);
        try self.ranges.encode(w);
    }

    pub fn decode(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!ObserveRequest {
        const tag = try r.takeByte();
        if (tag != @intFromEnum(RequestType.observe)) return error.UnknownRequestType;

        const body = r.allocRemaining(allocator, .limited(MAX_MESSAGE_SIZE + 1)) catch |err| switch (err) {
            error.StreamTooLong => return error.MessageTooLarge,
            else => |other| return other,
        };
        defer allocator.free(body);
        if (body.len > MAX_MESSAGE_SIZE) return error.MessageTooLarge;

        var body_reader: std.Io.Reader = .fixed(body);
        const request = try decodeBody(allocator, &body_reader);
        errdefer request.deinit(allocator);
        if (body_reader.bufferedLen() != 0) return error.TrailingFrameData;
        return request;
    }

    fn decodeBody(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!ObserveRequest {
        var hash_bytes: [32]u8 = undefined;
        const n = try r.readSliceShort(&hash_bytes);
        if (n != hash_bytes.len) return error.EndOfStream;
        const ranges = try decodeRangeSpec(allocator, r, true);
        return .{ .hash = Hash.fromBytes(hash_bytes), .ranges = ranges, .owns_ranges = true };
    }

    pub fn deinit(self: ObserveRequest, allocator: std.mem.Allocator) void {
        if (self.owns_ranges) self.ranges.deinit(allocator);
    }
};

pub const PushRequest = struct {
    hash: Hash,
    ranges: range_spec.ChunkRangesSeq,
    owns_ranges: bool = false,

    pub fn new(hash: Hash, ranges: range_spec.ChunkRangesSeq) PushRequest {
        return .{ .hash = hash, .ranges = ranges };
    }

    pub fn blob(hash: Hash) PushRequest {
        return .new(hash, range_spec.ChunkRangesSeq.singleBlob());
    }

    pub fn encode(self: PushRequest, w: *std.Io.Writer) Error!void {
        const size = try encodedBodySize(self);
        try w.writeByte(@intFromEnum(RequestType.push));
        try postcard.writeSliceHeader(w, size);
        try self.encodeBody(w);
    }

    fn encodeBody(self: PushRequest, w: *std.Io.Writer) Error!void {
        try w.writeAll(&self.hash.bytes);
        try self.ranges.encode(w);
    }

    pub fn decode(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!PushRequest {
        const tag = try r.takeByte();
        if (tag != @intFromEnum(RequestType.push)) return error.UnknownRequestType;

        const body = try readLengthPrefixedBody(allocator, r);
        defer allocator.free(body);
        var body_reader: std.Io.Reader = .fixed(body);
        const request = try decodeBody(allocator, &body_reader);
        errdefer request.deinit(allocator);
        if (body_reader.bufferedLen() != 0) return error.TrailingFrameData;
        return request;
    }

    fn decodeBody(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!PushRequest {
        var hash_bytes: [32]u8 = undefined;
        const n = try r.readSliceShort(&hash_bytes);
        if (n != hash_bytes.len) return error.EndOfStream;
        const ranges = try decodeChunkRangesSeq(allocator, r, true);
        return .{ .hash = Hash.fromBytes(hash_bytes), .ranges = ranges, .owns_ranges = true };
    }

    pub fn deinit(self: PushRequest, allocator: std.mem.Allocator) void {
        if (self.owns_ranges) self.ranges.deinit(allocator);
    }
};

pub const ObserveItem = struct {
    size: u64,
    ranges: ChunkRanges,
    owns_ranges: bool = false,

    pub fn encodeFrame(self: ObserveItem, w: *std.Io.Writer) Error!void {
        try encodeLengthPrefixedBody(self, w);
    }

    fn encodeBody(self: ObserveItem, w: *std.Io.Writer) Error!void {
        try postcard.writeU64(w, self.size);
        try encodeChunkRanges(self.ranges, w);
    }

    pub fn decodeFrame(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!ObserveItem {
        const body = try readLengthPrefixedBody(allocator, r);
        defer allocator.free(body);
        var body_reader: std.Io.Reader = .fixed(body);

        const size = try postcard.readU64(&body_reader);
        const ranges = try decodeChunkRanges(allocator, &body_reader);
        const owns_ranges = chunkRangesAreOwned(ranges);
        errdefer if (owns_ranges) allocator.free(@constCast(ranges.boundaries));
        if (body_reader.bufferedLen() != 0) return error.TrailingFrameData;
        return .{ .size = size, .ranges = ranges, .owns_ranges = owns_ranges };
    }

    pub fn deinit(self: ObserveItem, allocator: std.mem.Allocator) void {
        if (self.owns_ranges) allocator.free(@constCast(self.ranges.boundaries));
    }
};

pub const GetManyRequest = struct {
    hashes: []const Hash,
    ranges: range_spec.ChunkRangesSeq,

    pub fn encode(self: GetManyRequest, w: *std.Io.Writer) Error!void {
        try w.writeByte(@intFromEnum(RequestType.get_many));
        try postcard.writeSliceHeader(w, self.hashes.len);
        for (self.hashes) |hash| try w.writeAll(&hash.bytes);
        try self.ranges.encode(w);
    }

    pub fn decode(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!GetManyRequest {
        var limit_buf: [1]u8 = undefined;
        var limited = r.limited(.limited(MAX_MESSAGE_SIZE), &limit_buf);
        return decodeLimited(allocator, &limited.interface);
    }

    fn decodeLimited(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!GetManyRequest {
        const tag = try r.takeByte();
        if (tag != @intFromEnum(RequestType.get_many)) return error.UnknownRequestType;
        const len = try postcard.readSliceHeader(r);
        if (len > maxHashCountInMessage()) return error.MessageTooLarge;
        const hashes = try allocator.alloc(Hash, len);
        errdefer allocator.free(hashes);
        for (hashes) |*hash| {
            var hash_bytes: [32]u8 = undefined;
            const n = try r.readSliceShort(&hash_bytes);
            if (n != 32) return error.EndOfStream;
            hash.* = Hash.fromBytes(hash_bytes);
        }
        const ranges = try decodeChunkRangesSeq(allocator, r, false);
        return .{ .hashes = hashes, .ranges = ranges };
    }

    pub fn deinit(self: GetManyRequest, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.hashes));
        self.ranges.deinit(allocator);
    }
};

/// Read the 1-byte discriminant then decode the body for Get.
pub fn readRequest(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!GetRequest {
    return GetRequest.decode(allocator, r);
}

fn encodedBodySize(value: anytype) Error!usize {
    var count_buf: [64]u8 = undefined;
    var counter: std.Io.Writer.Discarding = .init(&count_buf);
    try value.encodeBody(&counter.writer);
    const size = counter.fullCount();
    if (size > MAX_MESSAGE_SIZE) return error.MessageTooLarge;
    return @intCast(size);
}

fn encodeLengthPrefixedBody(value: anytype, w: *std.Io.Writer) Error!void {
    const size = try encodedBodySize(value);
    try postcard.writeSliceHeader(w, size);
    try value.encodeBody(w);
}

fn readLengthPrefixedBody(allocator: std.mem.Allocator, r: *std.Io.Reader) Error![]u8 {
    const len = try postcard.readSliceHeader(r);
    if (len > MAX_MESSAGE_SIZE) return error.MessageTooLarge;
    return try r.readAlloc(allocator, len);
}

fn encodeChunkRanges(ranges: ChunkRanges, w: *std.Io.Writer) Error!void {
    try postcard.writeSliceHeader(w, ranges.boundaries.len);
    for (ranges.boundaries) |boundary| try postcard.writeU64(w, boundary);
}

fn decodeChunkRanges(allocator: std.mem.Allocator, r: *std.Io.Reader) Error!ChunkRanges {
    const len = try postcard.readSliceHeader(r);
    if (len > MAX_MESSAGE_SIZE) return error.MessageTooLarge;
    // Every encoded boundary occupies at least one byte. This reader is a
    // fixed frame, so reject impossible counts before allocating.
    if (len > r.bufferedLen()) return error.EndOfStream;

    const boundaries = try allocator.alloc(u64, len);
    errdefer allocator.free(boundaries);
    for (boundaries) |*boundary| boundary.* = try postcard.readU64(r);

    // `range_collections::RangeSet` normalizes its serde input this way.
    std.mem.sort(u64, boundaries, {}, std.sort.asc(u64));
    var unique_len: usize = 0;
    for (boundaries) |boundary| {
        if (unique_len == 0 or boundaries[unique_len - 1] != boundary) {
            boundaries[unique_len] = boundary;
            unique_len += 1;
        }
    }

    if (unique_len == 0) {
        allocator.free(boundaries);
        return ChunkRanges.empty();
    }
    if (unique_len == 1 and boundaries[0] == 0) {
        allocator.free(boundaries);
        return ChunkRanges.all();
    }
    if (unique_len == boundaries.len) return .{ .boundaries = boundaries };

    const normalized = try allocator.dupe(u64, boundaries[0..unique_len]);
    allocator.free(boundaries);
    return .{ .boundaries = normalized };
}

fn chunkRangesAreOwned(ranges: ChunkRanges) bool {
    const empty = ChunkRanges.empty();
    const all = ChunkRanges.all();
    return ranges.boundaries.ptr != empty.boundaries.ptr and
        ranges.boundaries.ptr != all.boundaries.ptr;
}

fn maxHashCountInMessage() usize {
    return (MAX_MESSAGE_SIZE - 1) / 32;
}

fn decodeRangeSpec(
    allocator: std.mem.Allocator,
    r: *std.Io.Reader,
    fixed_frame: bool,
) Error!range_spec.RangeSpec {
    const len = try postcard.readSliceHeader(r);
    if (len > MAX_MESSAGE_SIZE) return error.MessageTooLarge;
    // Each postcard u64 needs at least one byte. Fixed Observe/Push bodies are
    // fully buffered, so reject impossible counts before allocating len * 8.
    if (fixed_frame and len > r.bufferedLen()) return error.EndOfStream;
    const widths = try allocator.alloc(u64, len);
    errdefer allocator.free(widths);
    for (widths) |*slot| slot.* = try postcard.readU64(r);
    return .{ .widths = widths };
}

fn decodeChunkRangesSeq(
    allocator: std.mem.Allocator,
    r: *std.Io.Reader,
    fixed_frame: bool,
) Error!range_spec.ChunkRangesSeq {
    const len = try postcard.readSliceHeader(r);
    if (len > MAX_MESSAGE_SIZE / 2) return error.MessageTooLarge;
    // Each entry needs at least one delta byte and one RangeSpec length byte.
    if (fixed_frame and len > r.bufferedLen() / 2) return error.EndOfStream;
    const entries = try allocator.alloc(range_spec.ChunkRangesSeq.Entry, len);
    var filled: usize = 0;
    errdefer {
        for (entries[0..filled]) |entry| entry.spec.deinit(allocator);
        allocator.free(entries);
    }

    var prev_offset: u64 = 0;
    for (entries) |*entry| {
        const delta = try postcard.readU64(r);
        entry.offset = std.math.add(u64, prev_offset, delta) catch return error.MessageTooLarge;
        prev_offset = entry.offset;
        entry.spec = try decodeRangeSpec(allocator, r, fixed_frame);
        filled += 1;
    }
    return .{ .entries = entries };
}

fn hexToBytes(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    var out: [hex_str.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

test "GetRequest wire vectors §2c (0xda hash)" {
    var hash_bytes: [32]u8 = undefined;
    @memset(&hash_bytes, 0xda);
    const hash = Hash.fromBytes(hash_bytes);

    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try GetRequest.blob(hash).encode(&w);
    const expected_blob = hexToBytes(
        "00dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada020001000100",
    );
    try std.testing.expectEqual(expected_blob.len, w.end);
    try std.testing.expectEqualSlices(u8, &expected_blob, w.buffer[0..w.end]);

    w = .fixed(&buf);
    try GetRequest.all(hash).encode(&w);
    const expected_all = hexToBytes(
        "00dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada01000100",
    );
    try std.testing.expectEqual(expected_all.len, w.end);
    try std.testing.expectEqualSlices(u8, &expected_all, w.buffer[0..w.end]);
}

test "GetRequest decode round-trip" {
    const alloc = std.testing.allocator;
    var hash_bytes: [32]u8 = undefined;
    @memset(&hash_bytes, 0xda);

    inline for ([_][]const u8{
        "00dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada020001000100",
        "00dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada01000100",
    }) |hex| {
        const bytes = hexToBytes(hex);
        var r: std.Io.Reader = .fixed(&bytes);
        const req = try GetRequest.decode(alloc, &r);
        defer req.ranges.deinit(alloc);
        var out: [64]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        try req.encode(&w);
        try std.testing.expectEqualSlices(u8, &bytes, w.buffer[0..w.end]);
    }
}

test "request discriminant is exactly one byte" {
    // Rust reads RequestType as a single byte before postcard-decoding the body;
    // an overlong integer encoding must not be accepted as Get.
    const overlong_get = [_]u8{ 0x80, 0x00 };
    var r: std.Io.Reader = .fixed(&overlong_get);
    try std.testing.expectError(error.UnknownRequestType, GetRequest.decode(std.testing.allocator, &r));
}

test "GetManyRequest wire vector §7 (0xda,0xdb hashes)" {
    var hash0_bytes: [32]u8 = undefined;
    var hash1_bytes: [32]u8 = undefined;
    @memset(&hash0_bytes, 0xda);
    @memset(&hash1_bytes, 0xdb);
    const hashes = &[_]Hash{ Hash.fromBytes(hash0_bytes), Hash.fromBytes(hash1_bytes) };
    const ranges = range_spec.ChunkRangesSeq{ .entries = &[_]range_spec.ChunkRangesSeq.Entry{
        .{ .offset = 0, .spec = range_spec.RangeSpec.all() },
        .{ .offset = hashes.len, .spec = range_spec.RangeSpec.empty },
    } };

    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try (GetManyRequest{ .hashes = hashes, .ranges = ranges }).encode(&w);
    const expected = hexToBytes(
        "0902" ++
            "dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada" ++
            "dbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdb" ++
            "020001000200",
    );
    try std.testing.expectEqual(expected.len, w.end);
    try std.testing.expectEqualSlices(u8, &expected, w.buffer[0..w.end]);
}

test "GetManyRequest decode round-trip" {
    const alloc = std.testing.allocator;
    const bytes = hexToBytes(
        "0902" ++
            "dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada" ++
            "dbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdb" ++
            "020001000200",
    );
    var r: std.Io.Reader = .fixed(&bytes);
    const req = try GetManyRequest.decode(alloc, &r);
    defer req.deinit(alloc);
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try req.encode(&w);
    try std.testing.expectEqualSlices(u8, &bytes, w.buffer[0..w.end]);
}

test "RequestType discriminant is 1 byte" {
    try std.testing.expectEqual(@as(usize, 1), @sizeOf(RequestType));
}

test "GetManyRequest rejects oversized declared hash count" {
    var buf: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try postcard.writeU32(&w, @intFromEnum(RequestType.get_many));
    try postcard.writeSliceHeader(&w, maxHashCountInMessage() + 1);

    var r: std.Io.Reader = .fixed(w.buffer[0..w.end]);
    try std.testing.expectError(error.MessageTooLarge, GetManyRequest.decode(std.testing.allocator, &r));
}

test "ObserveRequest is tag plus postcard body to EOF" {
    var hash_bytes: [32]u8 = undefined;
    @memset(&hash_bytes, 0xda);

    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try ObserveRequest.new(Hash.fromBytes(hash_bytes)).encode(&w);
    const expected = hexToBytes(
        "01dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada0100",
    );
    try std.testing.expectEqualSlices(u8, &expected, w.buffer[0..w.end]);

    var r: std.Io.Reader = .fixed(&expected);
    const request = try ObserveRequest.decode(std.testing.allocator, &r);
    defer request.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &hash_bytes, &request.hash.bytes);
    try std.testing.expectEqualSlices(u64, &.{0}, request.ranges.widths);
}

test "PushRequest is tag plus length-prefixed GetRequest body" {
    var hash_bytes: [32]u8 = undefined;
    @memset(&hash_bytes, 0xda);
    const request = PushRequest.new(Hash.fromBytes(hash_bytes), range_spec.ChunkRangesSeq.singleBlob());

    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try request.encode(&w);
    const expected = hexToBytes(
        "0826dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada020001000100",
    );
    try std.testing.expectEqualSlices(u8, &expected, w.buffer[0..w.end]);

    var r: std.Io.Reader = .fixed(&expected);
    const decoded = try PushRequest.decode(std.testing.allocator, &r);
    defer decoded.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &hash_bytes, &decoded.hash.bytes);
    try std.testing.expect(decoded.ranges.isBlob());
}

test "ObserveItem frame encodes size and ChunkRanges boundaries" {
    const item = ObserveItem{
        .size = 10_000,
        .ranges = .{ .boundaries = &.{ 0, 5, 8 } },
    };
    var buf: [32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try item.encodeFrame(&w);
    const expected = hexToBytes("06904e03000508");
    try std.testing.expectEqualSlices(u8, &expected, w.buffer[0..w.end]);

    var r: std.Io.Reader = .fixed(&expected);
    const decoded = try ObserveItem.decodeFrame(std.testing.allocator, &r);
    defer decoded.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 10_000), decoded.size);
    try std.testing.expectEqualSlices(u64, &.{ 0, 5, 8 }, decoded.ranges.boundaries);
    try std.testing.expect(!decoded.ranges.is_empty());
    try std.testing.expect(!decoded.ranges.is_all());
}

test "ObserveItem normalizes Rust RangeSet boundaries and owns decoded storage" {
    const encoded = hexToBytes("050003020202");
    var r: std.Io.Reader = .fixed(&encoded);
    const decoded = try ObserveItem.decodeFrame(std.testing.allocator, &r);
    defer decoded.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u64, &.{2}, decoded.ranges.boundaries);

    const empty_item = ObserveItem{ .size = 0, .ranges = ChunkRanges.empty() };
    empty_item.deinit(std.testing.allocator);
    const all_item = ObserveItem{ .size = 0, .ranges = ChunkRanges.all() };
    all_item.deinit(std.testing.allocator);

    const borrowed_boundaries = [_]u64{ 2, 4 };
    const borrowed_item = ObserveItem{
        .size = 1024,
        .ranges = .{ .boundaries = &borrowed_boundaries },
    };
    borrowed_item.deinit(std.testing.allocator);
}

test "constructed Observe and Push requests retain borrowed ranges" {
    const hash = Hash.of("borrowed-request-ranges");
    const observe = ObserveRequest{
        .hash = hash,
        .ranges = .{ .widths = &.{ 1, 2, 3 } },
    };
    observe.deinit(std.testing.allocator);

    const push = PushRequest.blob(hash);
    push.deinit(std.testing.allocator);
}

test "Observe and Push reject unknown request tags" {
    var observe_reader: std.Io.Reader = .fixed(&.{0xff});
    try std.testing.expectError(
        error.UnknownRequestType,
        ObserveRequest.decode(std.testing.allocator, &observe_reader),
    );

    var push_reader: std.Io.Reader = .fixed(&.{0xff});
    try std.testing.expectError(
        error.UnknownRequestType,
        PushRequest.decode(std.testing.allocator, &push_reader),
    );
}

test "Observe Push and ObserveItem reject truncated frames" {
    var observe_bytes: [32]u8 = undefined;
    observe_bytes[0] = @intFromEnum(RequestType.observe);
    @memset(observe_bytes[1..], 0xda);
    var observe_reader: std.Io.Reader = .fixed(&observe_bytes);
    try std.testing.expectError(
        error.EndOfStream,
        ObserveRequest.decode(std.testing.allocator, &observe_reader),
    );

    var push_reader: std.Io.Reader = .fixed(&.{ @intFromEnum(RequestType.push), 2, 0xda });
    try std.testing.expectError(
        error.EndOfStream,
        PushRequest.decode(std.testing.allocator, &push_reader),
    );

    var item_reader: std.Io.Reader = .fixed(&.{ 2, 0 });
    try std.testing.expectError(
        error.EndOfStream,
        ObserveItem.decodeFrame(std.testing.allocator, &item_reader),
    );
}

test "Observe Push and ObserveItem reject oversized bodies" {
    var observe_buf: [48]u8 = undefined;
    var observe_writer: std.Io.Writer = .fixed(&observe_buf);
    try observe_writer.writeByte(@intFromEnum(RequestType.observe));
    try observe_writer.splatByteAll(0xda, 32);
    try postcard.writeSliceHeader(&observe_writer, MAX_MESSAGE_SIZE + 1);
    var observe_reader: std.Io.Reader = .fixed(observe_writer.buffer[0..observe_writer.end]);
    try std.testing.expectError(
        error.MessageTooLarge,
        ObserveRequest.decode(std.testing.allocator, &observe_reader),
    );

    var frame_buf: [16]u8 = undefined;
    var frame_writer: std.Io.Writer = .fixed(&frame_buf);
    try frame_writer.writeByte(@intFromEnum(RequestType.push));
    try postcard.writeSliceHeader(&frame_writer, MAX_MESSAGE_SIZE + 1);
    var push_reader: std.Io.Reader = .fixed(frame_writer.buffer[0..frame_writer.end]);
    try std.testing.expectError(
        error.MessageTooLarge,
        PushRequest.decode(std.testing.allocator, &push_reader),
    );

    var item_writer: std.Io.Writer = .fixed(&frame_buf);
    try postcard.writeSliceHeader(&item_writer, MAX_MESSAGE_SIZE + 1);
    var item_reader: std.Io.Reader = .fixed(item_writer.buffer[0..item_writer.end]);
    try std.testing.expectError(
        error.MessageTooLarge,
        ObserveItem.decodeFrame(std.testing.allocator, &item_reader),
    );
}

test "fixed Observe and Push frames reject impossible counts before allocation" {
    var observe_buf: [48]u8 = undefined;
    var observe_writer: std.Io.Writer = .fixed(&observe_buf);
    try observe_writer.writeByte(@intFromEnum(RequestType.observe));
    try observe_writer.splatByteAll(0xda, 32);
    try postcard.writeSliceHeader(&observe_writer, MAX_MESSAGE_SIZE);
    var observe_reader: std.Io.Reader = .fixed(observe_writer.buffer[0..observe_writer.end]);
    var observe_backing: [256]u8 = undefined;
    var observe_fba = std.heap.FixedBufferAllocator.init(&observe_backing);
    try std.testing.expectError(
        error.EndOfStream,
        ObserveRequest.decode(observe_fba.allocator(), &observe_reader),
    );

    var push_body_buf: [48]u8 = undefined;
    var push_body_writer: std.Io.Writer = .fixed(&push_body_buf);
    try push_body_writer.splatByteAll(0xda, 32);
    try postcard.writeSliceHeader(&push_body_writer, MAX_MESSAGE_SIZE / 2);

    var push_buf: [64]u8 = undefined;
    var push_writer: std.Io.Writer = .fixed(&push_buf);
    try push_writer.writeByte(@intFromEnum(RequestType.push));
    try postcard.writeSliceHeader(&push_writer, push_body_writer.end);
    try push_writer.writeAll(push_body_writer.buffered());
    var push_reader: std.Io.Reader = .fixed(push_writer.buffered());
    var push_backing: [256]u8 = undefined;
    var push_fba = std.heap.FixedBufferAllocator.init(&push_backing);
    try std.testing.expectError(
        error.EndOfStream,
        PushRequest.decode(push_fba.allocator(), &push_reader),
    );
}
