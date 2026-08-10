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

pub const BlobStatus = union(enum) {
    not_found,
    partial: ?u64,
    complete: u64,
};

/// Import progress events, emitted while a file is streamed into a store.
/// Behaviour contract: iroh-blobs/src/api/blobs.rs ImportProgress
/// (found / progress / done), delivered here through a caller callback.
pub const ImportProgress = union(enum) {
    found: struct { size: u64 },
    progress: struct { bytes_done: u64 },
    done: struct { hash: Hash },
};

pub const Error = error{
    NotFound,
    RenameMissing,
    OutOfMemory,
    Io,
    HashMismatch,
    CorruptStore,
    Closed,
    Incomplete,
    InvalidState,
    BlobTooLarge,
};
