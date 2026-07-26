//! Concatenated 32-byte hashes (iroh `HashSeq`).

const std = @import("std");
const Hash = @import("../hash.zig").Hash;

pub const Error = error{InvalidHashSeq};

pub const HashSeq = struct {
    bytes: []const u8,
    owned: bool = false,

    /// Validate borrowed bytes as a sequence of complete 32-byte hashes.
    pub fn fromBytes(bytes: []const u8) Error!HashSeq {
        if (bytes.len % 32 != 0) return error.InvalidHashSeq;
        return .{ .bytes = bytes };
    }

    pub fn fromHashes(allocator: std.mem.Allocator, hashes: []const Hash) !HashSeq {
        const bytes_len = try std.math.mul(usize, hashes.len, 32);
        const bytes = try allocator.alloc(u8, bytes_len);
        for (hashes, 0..) |h, i| @memcpy(bytes[i * 32 ..][0..32], &h.bytes);
        return .{ .bytes = bytes, .owned = true };
    }

    pub fn len(self: HashSeq) usize {
        return self.bytes.len / 32;
    }

    pub fn get(self: HashSeq, i: usize) ?Hash {
        if (i >= self.len()) return null;
        var out: [32]u8 = undefined;
        @memcpy(&out, self.bytes[i * 32 ..][0..32]);
        return Hash.fromBytes(out);
    }

    pub fn deinit(self: *HashSeq, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(@constCast(self.bytes));
        self.* = undefined;
    }
};

test "HashSeq get slices 32-byte chunks" {
    const alloc = std.testing.allocator;
    const h0 = Hash.of("a");
    const h1 = Hash.of("b");
    var seq = try HashSeq.fromHashes(alloc, &.{ h0, h1 });
    defer seq.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), seq.len());
    try std.testing.expect(seq.get(0).?.eql(h0));
    try std.testing.expect(seq.get(1).?.eql(h1));
    try std.testing.expect(seq.get(2) == null);
}

test "HashSeq validates complete hash bytes" {
    inline for ([_]usize{ 0, 32, 64 }) |len| {
        const valid = [_]u8{0} ** len;
        var seq = try HashSeq.fromBytes(&valid);
        try std.testing.expectEqual(len / 32, seq.len());
        seq.deinit(std.testing.allocator);
    }
    inline for ([_]usize{ 1, 31, 33, 63, 65 }) |len| {
        const invalid = [_]u8{0} ** len;
        try std.testing.expectError(error.InvalidHashSeq, HashSeq.fromBytes(&invalid));
    }
}
