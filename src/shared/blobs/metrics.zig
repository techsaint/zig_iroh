//! Active blobs subsystem counters.

const std = @import("std");

pub const Snapshot = struct {
    add_operations: u64,
    get_operations: u64,
    bytes_added: u64,
    bytes_read: u64,
    not_found: u64,
    removed: u64,
    integrity_errors: u64,
};

pub const Metrics = struct {
    add_operations: std.atomic.Value(u64) = .init(0),
    get_operations: std.atomic.Value(u64) = .init(0),
    bytes_added: std.atomic.Value(u64) = .init(0),
    bytes_read: std.atomic.Value(u64) = .init(0),
    not_found: std.atomic.Value(u64) = .init(0),
    removed: std.atomic.Value(u64) = .init(0),
    integrity_errors: std.atomic.Value(u64) = .init(0),

    pub fn recordAdd(self: *Metrics, bytes: usize) void {
        _ = self.add_operations.fetchAdd(1, .monotonic);
        _ = self.bytes_added.fetchAdd(@intCast(bytes), .monotonic);
    }

    pub fn recordGet(self: *Metrics, bytes: usize) void {
        _ = self.get_operations.fetchAdd(1, .monotonic);
        _ = self.bytes_read.fetchAdd(@intCast(bytes), .monotonic);
    }

    pub fn snapshot(self: *const Metrics) Snapshot {
        return .{
            .add_operations = self.add_operations.load(.monotonic),
            .get_operations = self.get_operations.load(.monotonic),
            .bytes_added = self.bytes_added.load(.monotonic),
            .bytes_read = self.bytes_read.load(.monotonic),
            .not_found = self.not_found.load(.monotonic),
            .removed = self.removed.load(.monotonic),
            .integrity_errors = self.integrity_errors.load(.monotonic),
        };
    }
};

test "metrics snapshot reports active counters" {
    var metrics: Metrics = .{};
    metrics.recordAdd(4);
    metrics.recordGet(3);
    _ = metrics.not_found.fetchAdd(1, .monotonic);
    const snapshot = metrics.snapshot();
    try std.testing.expectEqual(@as(u64, 1), snapshot.add_operations);
    try std.testing.expectEqual(@as(u64, 1), snapshot.get_operations);
    try std.testing.expectEqual(@as(u64, 4), snapshot.bytes_added);
    try std.testing.expectEqual(@as(u64, 3), snapshot.bytes_read);
    try std.testing.expectEqual(@as(u64, 1), snapshot.not_found);
}
