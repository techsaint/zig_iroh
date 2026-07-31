//! Shared blobs Store/Tags value types (wire-identity via Hash; local API only).

const std = @import("std");
const Hash = @import("../hash.zig").Hash;

pub const BlobFormat = enum {
    raw,
    hash_seq,
};

pub const HashAndFormat = struct {
    hash: Hash,
    format: BlobFormat = .raw,

    pub fn raw(hash: Hash) HashAndFormat {
        return .{ .hash = hash, .format = .raw };
    }

    pub fn hashSeq(hash: Hash) HashAndFormat {
        return .{ .hash = hash, .format = .hash_seq };
    }
};

pub const TagInfo = struct {
    name: []const u8,
    hash: Hash,
    format: BlobFormat = .raw,

    pub fn deinit(self: TagInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};

pub const Error = error{
    NotFound,
    RenameMissing,
    OutOfMemory,
    Io,
};
