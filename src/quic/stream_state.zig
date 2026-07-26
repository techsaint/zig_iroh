//! Stream send/recv state extracted from connection.zig (N1 reorientation).
//! Pure stream half-state — no Connection coupling. Connection remains the
//! orchestrator for open/limit/FC/events.

const std = @import("std");
const crypto = @import("crypto.zig");

pub const max_streams: usize = 32;
pub const max_stream_data: usize = 4096;
pub const max_recv_pending_bytes: usize = 4 * 1024 * 1024;
pub const max_recv_pending_segments: usize = 4096;

pub const StreamDir = enum { bidi, uni };

/// A single (offset,len,fin) chunk queued for (re)transmission on a stream.
pub const Chunk = struct { offset: u64, len: u64, fin: bool };

/// One out-of-order received segment awaiting an earlier gap to fill. Segment
/// bytes live in the owning StreamRecv's shared pending_storage arena.
const RecvSegment = struct {
    offset: u64,
    storage_start: usize,
    len: usize,
};

fn recvSegmentOrder(_: void, a: RecvSegment, b: RecvSegment) std.math.Order {
    const by_offset = std.math.order(a.offset, b.offset);
    if (by_offset != .eq) return by_offset;
    return std.math.order(a.len, b.len);
}

fn recvSegmentHeapLessThan(_: void, a: RecvSegment, b: RecvSegment) bool {
    return recvSegmentOrder({}, a, b) == .lt;
}

fn recvSegmentStorageLessThan(_: void, a: RecvSegment, b: RecvSegment) bool {
    return a.storage_start < b.storage_start;
}

const RecvPending = std.PriorityQueue(RecvSegment, void, recvSegmentOrder);

/// Send half of one stream.
pub const StreamSend = struct {
    buf: std.ArrayList(u8) = .empty, // retained bytes beginning at buf_offset
    buf_offset: u64 = 0,
    send_next: u64 = 0, // next fresh offset to transmit
    fin: bool = false, // finish() requested
    fin_sent: bool = false, // FIN has been put on the wire at least once
    buffer_released: bool = false,
    max_data: u64 = 0, // peer's advertised per-stream window (send limit)
    reset_code: ?u64 = null, // reset() requested → send RESET_STREAM
    reset_final_size: ?u64 = null,
    reset_sent: bool = false,
    rtx: std.Deque(Chunk) = .empty, // lost chunks pending resend (before fresh data)
    blocked_at: u64 = 0, // last window we already emitted STREAM_DATA_BLOCKED for

    pub fn deinit(self: *StreamSend, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
        self.rtx.deinit(allocator);
    }

    pub fn endOffset(self: *const StreamSend) u64 {
        return self.buf_offset + @as(u64, @intCast(self.buf.items.len));
    }

    pub fn sliceAt(self: *const StreamSend, offset: u64, len: usize) []const u8 {
        std.debug.assert(offset >= self.buf_offset);
        const start: usize = @intCast(offset - self.buf_offset);
        std.debug.assert(start + len <= self.buf.items.len);
        return self.buf.items[start .. start + len];
    }

    /// Discard an ACK-safe absolute-offset prefix. Compaction is geometric:
    /// defer copying until the dead prefix is at least as large as the live
    /// suffix, so continuously ACKed streams copy each byte only O(1) times.
    pub fn reclaimBefore(self: *StreamSend, allocator: std.mem.Allocator, offset: u64) void {
        const end = self.endOffset();
        const safe_offset = @min(offset, self.send_next);
        const clamped = @min(@max(safe_offset, self.buf_offset), end);
        const discard: usize = @intCast(clamped - self.buf_offset);
        if (discard == 0) return;
        const retained = self.buf.items.len - discard;
        if (discard < retained) return;
        if (retained == 0) {
            self.buf.clearAndFree(allocator);
        } else {
            std.mem.copyForwards(u8, self.buf.items[0..retained], self.buf.items[discard..]);
            self.buf.shrinkAndFree(allocator, retained);
        }
        self.buf_offset = clamped;
    }
};

/// Receive half of one stream (in-order reassembly by offset).
pub const StreamRecv = struct {
    data: std.ArrayList(u8) = .empty, // contiguous bytes from base_offset
    base_offset: u64 = 0,
    // Min-offset heap: each future segment is visited only when it can extend
    // the contiguous prefix, avoiding repeated full pending-list scans.
    pending: RecvPending = .empty,
    // Shared ownership for all pending segment bytes. Dead prefixes are
    // compacted geometrically, eliminating one allocation per receive gap.
    pending_storage: std.ArrayList(u8) = .empty,
    pending_bytes: usize = 0,
    highest_offset: u64 = 0, // max offset+len ever seen (for FC accounting)
    fin_offset: ?u64 = null, // final size once FIN observed
    fin_delivered: bool = false, // FIN reached contiguously + surfaced
    reset_code: ?u64 = null, // RESET_STREAM received
    stop_code: ?u64 = null, // stop() requested -> send STOP_SENDING
    stop_sent: bool = false,
    max_data: u64 = 0, // our advertised per-stream window (receive limit)
    consumed: u64 = 0, // bytes delivered to the application

    pub fn deinit(self: *StreamRecv, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
        self.pending_storage.deinit(allocator);
        self.pending.deinit(allocator);
    }

    /// Ingest one STREAM frame chunk. Returns the count of NEW contiguous bytes
    /// appended (for connection-level delivery accounting). `error.FinalSizeError`
    /// / overflow are caught by the caller as a protocol violation.
    pub fn ingest(self: *StreamRecv, allocator: std.mem.Allocator, offset: u64, bytes: []const u8, fin: bool) !usize {
        const end = std.math.add(u64, offset, @intCast(bytes.len)) catch return error.StreamTooLarge;
        if (self.fin_offset) |fo| {
            if (end > fo) return error.FinalSizeError;
        }
        if (fin) {
            if (self.fin_offset) |fo| {
                if (fo != end) return error.FinalSizeError;
            } else {
                if (self.highest_offset > end) return error.FinalSizeError;
            }
        }
        const before = self.data.items.len;
        const cur = self.contiguousEnd();
        if (offset > cur) {
            // Empty frames carry no gap data; FIN is represented by fin_offset.
            if (bytes.len == 0) {
                if (fin and self.fin_offset == null) self.fin_offset = end;
                if (end > self.highest_offset) self.highest_offset = end;
                return 0;
            }
            // Out of order — buffer a copy.
            if (self.pending.count() >= max_recv_pending_segments) return error.NoSpaceLeft;
            const new_pending_bytes = std.math.add(usize, self.pending_bytes, bytes.len) catch return error.NoSpaceLeft;
            if (new_pending_bytes > max_recv_pending_bytes) return error.NoSpaceLeft;
            const storage_after = std.math.add(usize, self.pending_storage.items.len, bytes.len) catch max_recv_pending_bytes + 1;
            if (storage_after > max_recv_pending_bytes) self.compactPendingStorage();

            // Reserve every fallible resource before transferring ownership.
            // A failed reserve can change capacity but not logical state.
            try self.pending.ensureUnusedCapacity(allocator, 1);
            try self.pending_storage.ensureUnusedCapacity(allocator, bytes.len);
            const seg: RecvSegment = .{
                .offset = offset,
                .storage_start = self.pending_storage.items.len,
                .len = bytes.len,
            };
            try self.pending.push(allocator, seg); // capacity already reserved
            self.pending_storage.appendSliceAssumeCapacity(bytes);
            if (fin and self.fin_offset == null) self.fin_offset = end;
            if (end > self.highest_offset) self.highest_offset = end;
            self.pending_bytes = new_pending_bytes;
        } else if (end > cur) {
            const skip: usize = @intCast(cur - offset);
            const reserve = std.math.add(usize, bytes.len - skip, self.pending_bytes) catch return error.NoSpaceLeft;
            try self.data.ensureUnusedCapacity(allocator, reserve);
            if (fin and self.fin_offset == null) self.fin_offset = end;
            if (end > self.highest_offset) self.highest_offset = end;
            self.data.appendSliceAssumeCapacity(bytes[skip..]);
            self.absorbPending();
        } else {
            if (fin and self.fin_offset == null) self.fin_offset = end;
            if (end > self.highest_offset) self.highest_offset = end;
        }
        return self.data.items.len - before;
    }

    pub fn absorbPending(self: *StreamRecv) void {
        while (self.pending.peek()) |head| {
            const cur = self.contiguousEnd();
            if (head.offset > cur) break;

            const seg = self.pending.pop().?;
            const seg_end = seg.offset + @as(u64, @intCast(seg.len));
            self.pending_bytes -= seg.len;
            if (seg_end <= cur) continue; // fully duplicate

            const skip: usize = @intCast(cur - seg.offset);
            const stored = self.pending_storage.items[seg.storage_start..][0..seg.len];
            self.data.appendSliceAssumeCapacity(stored[skip..]);
        }

        if (self.pending.count() == 0) {
            self.pending_storage.clearRetainingCapacity();
            return;
        }
        const dead_bytes = self.pending_storage.items.len - self.pending_bytes;
        if (dead_bytes >= self.pending_bytes) self.compactPendingStorage();
    }

    /// Remove dead arena ranges without allocating. Sorting by storage offset
    /// makes forward copies overlap-safe; sorting by heap priority afterwards
    /// restores a valid min-heap (a fully sorted array satisfies heap order).
    pub fn compactPendingStorage(self: *StreamRecv) void {
        if (self.pending.count() == 0) {
            self.pending_storage.clearRetainingCapacity();
            return;
        }
        if (self.pending_storage.items.len == self.pending_bytes) return;

        std.mem.sort(RecvSegment, self.pending.items, {}, recvSegmentStorageLessThan);
        var next_start: usize = 0;
        for (self.pending.items) |*seg| {
            const old_start = seg.storage_start;
            if (old_start != next_start) {
                std.mem.copyForwards(
                    u8,
                    self.pending_storage.items[next_start..][0..seg.len],
                    self.pending_storage.items[old_start..][0..seg.len],
                );
            }
            seg.storage_start = next_start;
            next_start += seg.len;
        }
        std.debug.assert(next_start == self.pending_bytes);
        self.pending_storage.shrinkRetainingCapacity(next_start);
        std.mem.sort(RecvSegment, self.pending.items, {}, recvSegmentHeapLessThan);
    }

    pub fn pendingCount(self: *const StreamRecv) usize {
        return self.pending.count();
    }

    pub fn contiguousEnd(self: *const StreamRecv) u64 {
        return self.base_offset + self.data.items.len;
    }

    pub fn pruneConsumed(self: *StreamRecv) void {
        if (self.consumed <= self.base_offset) return;
        const drop_u64 = @min(self.consumed - self.base_offset, self.data.items.len);
        const drop: usize = @intCast(drop_u64);
        if (drop == 0) return;
        const keep = self.data.items.len - drop;
        std.mem.copyForwards(u8, self.data.items[0..keep], self.data.items[drop..]);
        self.data.shrinkRetainingCapacity(keep);
        self.base_offset += drop;
    }

    /// True once all data through FIN has been reassembled contiguously.
    pub fn finReached(self: *const StreamRecv) bool {
        return if (self.fin_offset) |fo| self.contiguousEnd() >= fo else false;
    }
};

/// One live stream (bidi carries both halves; uni carries the relevant half).
pub const StreamEntry = struct {
    id: u64 = 0,
    dir: StreamDir = .bidi,
    used: bool = false,
    opened_emitted: bool = false,
    send: StreamSend = .{},
    recv: StreamRecv = .{},
};

// RFC 9000 §2.1 stream-id bit layout.
pub fn streamIsUni(id: u64) bool {
    return (id & 0x02) != 0;
}
pub fn streamInitiator(id: u64) crypto.Role {
    return if ((id & 0x01) == 0) .client else .server;
}
