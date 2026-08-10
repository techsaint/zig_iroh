//! The relay-datagram seam: ONE engine-neutral handle every QUIC engine and
//! every relay front-end shares.
//!
//! `Client` is the whole contract — send a QUIC packet to a peer NodeId, poll
//! the next relay datagram addressed to us. `transport/endpoint.zig` (picoquic)
//! and `transport/transport_noq.zig` (noq) both consume this exact type, and
//! `endpoint_relay.HomeRelay` produces it. Adapters over the DERP
//! `relay/client.zig` live here too so no engine owns a private copy.

const std = @import("std");
const key = @import("../key.zig");
// Only `tr.Error` is used here, from the neutral contract rather than the
// product door. That keeps this file independently analyzable while engine
// implementations reference `Client` in their signatures.
const tr = @import("../transport_contract.zig");
const relay_client = @import("../relay/client.zig");
const relay_proto = @import("../relay/proto.zig");

// The concrete DERP adapters below retain this historic module facade while
// engines and the product factory share the one neutral contract identity.
pub const Datagram = tr.RelayDatagram;
pub const Client = tr.RelayClient;

pub const Disabled = struct {
    pub fn init() Disabled {
        return .{};
    }

    pub fn available(_: Disabled) bool {
        return false;
    }
};

/// Synchronous DERP adapter: every `recv` pulls one frame straight off the
/// relay client. A batch frame carries GSO-style concatenated segments and this
/// adapter has no pending queue, so it surfaces the first segment only — use
/// `QueuedRelayClient` when batches must survive intact.
pub const DerpClient = struct {
    client: *relay_client.Client,

    pub fn datagrams(self: *DerpClient) Client {
        return .{ .context = self, .vtable = &derp_vtable };
    }
};

const derp_vtable: Client.VTable = .{ .send = derpSend, .recv = derpRecv };

fn derpSend(ctx: *anyopaque, dst: key.NodeId, data: []const u8) tr.Error!void {
    const adapter: *DerpClient = @ptrCast(@alignCast(ctx));
    adapter.client.send(.{ .datagram = .{
        .dst = dst,
        .datagrams = .{ .ecn = .not_ect, .segment_size = null, .contents = data },
    } }) catch return error.ConnectionLost;
}

fn derpRecv(ctx: *anyopaque, buffer: []u8) tr.Error!?Datagram {
    const adapter: *DerpClient = @ptrCast(@alignCast(ctx));
    const msg = adapter.client.recv() catch return error.ConnectionLost;
    switch (msg) {
        .datagram => |d| {
            if (d.datagrams.contents.len > buffer.len) return error.ConnectionLost;
            @memcpy(buffer[0..d.datagrams.contents.len], d.datagrams.contents);
            return .{ .src = d.src, .data = buffer[0..d.datagrams.contents.len] };
        },
        .datagram_batch => |d| {
            const contents = d.datagrams.contents;
            const seg_len: usize = if (d.datagrams.segment_size) |s| @as(usize, s) else contents.len;
            const take = @min(seg_len, contents.len);
            if (take > buffer.len) return error.ConnectionLost;
            @memcpy(buffer[0..take], contents[0..take]);
            return .{ .src = d.src, .data = buffer[0..take] };
        },
        .endpoint_gone => return error.ConnectionLost,
        else => return null,
    }
}

/// Bounded relay receive adapter with owned queue entries.
///
/// The value may be returned and moved before `startReceiver`, but from that call
/// until `stopReceiver` returns it must remain at one stable address: both the
/// receiver thread and `datagrams()` vtable retain its pointer. All users of a
/// previously returned `Client` must be quiesced before `stopReceiver`; that call
/// joins the receiver and releases the queue storage. The client and allocator
/// must also remain valid through `stopReceiver`.
pub const QueuedRelayClient = struct {
    // Match iroh's relay receive channel depth. Queue entries are heap-backed so
    // this does not put a 1 MiB+ fixed array in every adapter value.
    const max_queue = 512;
    const max_datagram = 2048;

    const Queued = struct {
        src: key.NodeId,
        segment_size: ?u16,
        offset: usize = 0,
        bytes: []u8,
    };

    client: *relay_client.Client,
    allocator: std.mem.Allocator,
    mu: std.atomic.Mutex = .unlocked,
    queue: ?[]Queued = null,
    head: usize = 0,
    len: usize = 0,
    thread: ?std.Thread = null,
    receiver_ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    sent_via_client: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    received_via_client: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    /// Historical compatibility aggregate: logical datagrams rejected for any
    /// reason, not only queue-capacity overflow. Consult the reason counters below
    /// to distinguish capacity, validation, and allocation failures. A dropped
    /// batch contributes its number of logical datagrams to every applicable count.
    dropped_by_overflow: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    dropped_by_queue_full: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    dropped_by_oversize_or_invalid: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    dropped_by_allocation_failure: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    queue_high_water_depth: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    pub fn init(client: *relay_client.Client) QueuedRelayClient {
        return initWithAllocator(std.heap.page_allocator, client);
    }

    pub fn initWithAllocator(allocator: std.mem.Allocator, client: *relay_client.Client) QueuedRelayClient {
        return .{ .client = client, .allocator = allocator };
    }

    fn initForTest(allocator: std.mem.Allocator) !QueuedRelayClient {
        var self: QueuedRelayClient = .{ .client = undefined, .allocator = allocator };
        try self.allocateQueue();
        return self;
    }

    fn allocateQueue(self: *QueuedRelayClient) !void {
        std.debug.assert(self.queue == null);
        self.queue = try self.allocator.alloc(Queued, max_queue);
    }

    fn deinitQueue(self: *QueuedRelayClient) void {
        std.debug.assert(self.thread == null);
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();

        const queue = self.queue orelse return;
        for (0..self.len) |i| {
            const index = (self.head + i) % queue.len;
            self.allocator.free(queue[index].bytes);
        }
        self.allocator.free(queue);
        self.queue = null;
        self.head = 0;
        self.len = 0;
    }

    pub fn datagrams(self: *QueuedRelayClient) Client {
        return .{ .context = self, .vtable = &queued_vtable };
    }

    /// Starts the sole queue producer and pins this value at its current address.
    pub fn startReceiver(self: *QueuedRelayClient) !void {
        std.debug.assert(self.thread == null);
        try self.allocateQueue();
        errdefer self.deinitQueue();
        self.receiver_ready.store(false, .release);
        const thread = try std.Thread.spawn(.{}, receiverThread, .{self});
        self.thread = thread;
        while (!self.receiver_ready.load(.acquire)) std.Thread.yield() catch {};
    }

    /// Stops and joins the producer, then releases all pending queue entries.
    /// Callers must first quiesce every consumer of the `datagrams()` handle.
    pub fn stopReceiver(self: *QueuedRelayClient) void {
        self.client.stream.shutdown(self.client.io, .both) catch {};
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        self.deinitQueue();
    }

    fn receiverThread(self: *QueuedRelayClient) void {
        self.receiver_ready.store(true, .release);
        while (true) {
            const msg = self.client.recv() catch return;
            switch (msg) {
                .datagram => |d| self.enqueue(d.src, d.datagrams.contents),
                .datagram_batch => |d| self.enqueueBatch(d.src, d.datagrams),
                .endpoint_gone => return,
                else => {},
            }
        }
    }

    fn send(self: *QueuedRelayClient, dst: key.NodeId, data: []const u8) tr.Error!void {
        self.client.send(.{ .datagram = .{
            .dst = dst,
            .datagrams = .{ .ecn = .not_ect, .segment_size = null, .contents = data },
        } }) catch return error.ConnectionLost;
        _ = self.sent_via_client.fetchAdd(1, .monotonic);
    }

    fn recv(self: *QueuedRelayClient, buffer: []u8) tr.Error!?Datagram {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        if (self.len == 0) return null;
        const queue = self.queue orelse return error.ConnectionLost;
        const item = &queue[self.head];
        const remaining = item.bytes[item.offset..];
        const take = if (item.segment_size) |segment_size|
            @min(@as(usize, segment_size), remaining.len)
        else
            remaining.len;
        if (take > buffer.len) return error.ConnectionLost;

        const src = item.src;
        @memcpy(buffer[0..take], remaining[0..take]);
        item.offset += take;
        if (item.offset == item.bytes.len) {
            self.allocator.free(item.bytes);
            self.head = (self.head + 1) % queue.len;
            self.len -= 1;
        }
        return .{ .src = src, .data = buffer[0..take] };
    }

    fn enqueue(self: *QueuedRelayClient, src: key.NodeId, data: []const u8) void {
        self.enqueueDatagrams(src, null, data);
    }

    fn enqueueDatagrams(self: *QueuedRelayClient, src: key.NodeId, segment_size: ?u16, data: []const u8) void {
        const datagram_count = datagramCount(data.len, segment_size);
        if (segment_size) |segment| {
            if (segment == 0 or data.len == 0 or segment > max_datagram) {
                self.recordDrop(datagram_count, .oversize_or_invalid);
                return;
            }
        } else if (data.len > max_datagram) {
            self.recordDrop(datagram_count, .oversize_or_invalid);
            return;
        }

        // The relay client receive buffer is borrowed until its next recv, so an
        // accepted item must be copied. Check capacity first: a full bounded queue
        // drops the newest whole entry without allocating, matching Rust's
        // `try_send` behavior and keeping the reason counter deterministic under
        // allocator pressure.
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        const queue_before_alloc = self.queue orelse {
            self.mu.unlock();
            self.recordDrop(datagram_count, .allocation_failure);
            return;
        };
        if (self.len >= queue_before_alloc.len) {
            self.mu.unlock();
            self.recordDrop(datagram_count, .queue_full);
            return;
        }
        self.mu.unlock();

        const owned = self.allocator.dupe(u8, data) catch {
            self.recordDrop(datagram_count, .allocation_failure);
            return;
        };

        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        const queue = self.queue orelse {
            self.allocator.free(owned);
            self.recordDrop(datagram_count, .allocation_failure);
            return;
        };
        if (self.len >= queue.len) {
            self.allocator.free(owned);
            self.recordDrop(datagram_count, .queue_full);
            return;
        }

        const index = (self.head + self.len) % queue.len;
        queue[index] = .{
            .src = src,
            .segment_size = segment_size,
            .bytes = owned,
        };
        self.len += 1;
        _ = self.received_via_client.fetchAdd(datagram_count, .monotonic);
        if (self.len > self.queue_high_water_depth.load(.monotonic)) {
            self.queue_high_water_depth.store(self.len, .monotonic);
        }
    }

    /// Queue a whole batch as one logical item, splitting only as `recv` drains it.
    fn enqueueBatch(self: *QueuedRelayClient, src: key.NodeId, d: relay_proto.Datagrams) void {
        const seg = d.segment_size orelse {
            self.enqueue(src, d.contents);
            return;
        };
        self.enqueueDatagrams(src, seg, d.contents);
    }

    const DropReason = enum {
        queue_full,
        oversize_or_invalid,
        allocation_failure,
    };

    fn recordDrop(self: *QueuedRelayClient, count: usize, reason: DropReason) void {
        _ = self.dropped_by_overflow.fetchAdd(count, .monotonic);
        switch (reason) {
            .queue_full => _ = self.dropped_by_queue_full.fetchAdd(count, .monotonic),
            .oversize_or_invalid => _ = self.dropped_by_oversize_or_invalid.fetchAdd(count, .monotonic),
            .allocation_failure => _ = self.dropped_by_allocation_failure.fetchAdd(count, .monotonic),
        }
    }

    fn datagramCount(data_len: usize, segment_size: ?u16) usize {
        const segment = segment_size orelse return 1;
        if (segment == 0 or data_len == 0) return 1;
        return (data_len - 1) / @as(usize, segment) + 1;
    }
};

fn queuedSend(ctx: *anyopaque, dst: key.NodeId, data: []const u8) tr.Error!void {
    const queued: *QueuedRelayClient = @ptrCast(@alignCast(ctx));
    return queued.send(dst, data);
}

fn queuedRecv(ctx: *anyopaque, buffer: []u8) tr.Error!?Datagram {
    const queued: *QueuedRelayClient = @ptrCast(@alignCast(ctx));
    return queued.recv(buffer);
}

const queued_vtable: Client.VTable = .{ .send = queuedSend, .recv = queuedRecv };

test "F1: queued relay overflow drops newest before allocation and preserves backlog" {
    const src = key.SecretKey.fromBytes([_]u8{21} ** 32).public();
    var failing_state = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var queue = try QueuedRelayClient.initForTest(failing_state.allocator());
    defer queue.deinitQueue();
    const payload = "relay-datagram";

    for (0..QueuedRelayClient.max_queue) |_| {
        queue.enqueue(src, payload);
    }
    failing_state.fail_index = failing_state.alloc_index;
    queue.enqueueBatch(src, .{
        .ecn = .not_ect,
        .segment_size = 4,
        .contents = "dropped-newest",
    });

    try std.testing.expectEqual(@as(usize, QueuedRelayClient.max_queue), queue.len);
    try std.testing.expectEqual(@as(usize, QueuedRelayClient.max_queue), queue.received_via_client.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 4), queue.dropped_by_overflow.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 4), queue.dropped_by_queue_full.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), queue.dropped_by_oversize_or_invalid.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), queue.dropped_by_allocation_failure.load(.monotonic));
    try std.testing.expectEqual(@as(usize, QueuedRelayClient.max_queue), queue.queue_high_water_depth.load(.monotonic));
    try std.testing.expect(!failing_state.has_induced_failure);

    var recv_buf: [QueuedRelayClient.max_datagram]u8 = undefined;
    var drained: usize = 0;
    while (try queue.recv(&recv_buf)) |msg| {
        try std.testing.expect(msg.src.eql(src));
        try std.testing.expectEqualStrings(payload, msg.data);
        drained += 1;
    }
    try std.testing.expectEqual(@as(usize, QueuedRelayClient.max_queue), drained);
    try std.testing.expectEqual(@as(usize, 0), queue.len);

    failing_state.fail_index = std.math.maxInt(usize);
    queue.enqueue(src, "still-usable");
    const after_overflow = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("still-usable", after_overflow.data);
    try std.testing.expectEqual(@as(usize, 0), queue.len);

    queue.deinitQueue();
    try std.testing.expectEqual(failing_state.allocated_bytes, failing_state.freed_bytes);
}

test "F1: queued relay batch occupies one slot and drains segments in order" {
    const src = key.SecretKey.fromBytes([_]u8{22} ** 32).public();
    var queue = try QueuedRelayClient.initForTest(std.testing.allocator);
    defer queue.deinitQueue();

    queue.enqueueBatch(src, .{
        .ecn = .not_ect,
        .segment_size = 4,
        .contents = "aaaabbbbcc",
    });
    queue.enqueue(src, "after-batch");
    try std.testing.expectEqual(@as(usize, 2), queue.len);
    try std.testing.expectEqual(@as(usize, 4), queue.received_via_client.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 2), queue.queue_high_water_depth.load(.monotonic));

    var recv_buf: [QueuedRelayClient.max_datagram]u8 = undefined;
    const first = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("aaaa", first.data);
    try std.testing.expectEqual(@as(usize, 2), queue.len);
    const second = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("bbbb", second.data);
    try std.testing.expectEqual(@as(usize, 2), queue.len);
    const third = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("cc", third.data);
    try std.testing.expectEqual(@as(usize, 1), queue.len);
    const after_batch = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("after-batch", after_batch.data);
    try std.testing.expectEqual(@as(usize, 0), queue.len);
    try std.testing.expect((try queue.recv(&recv_buf)) == null);
}

test "F1: queued relay reports capacity and invalid drops separately" {
    const src = key.SecretKey.fromBytes([_]u8{23} ** 32).public();
    var queue = try QueuedRelayClient.initForTest(std.testing.allocator);
    defer queue.deinitQueue();

    var oversize: [QueuedRelayClient.max_datagram + 1]u8 = undefined;
    @memset(&oversize, 0x5a);
    queue.enqueue(src, &oversize);
    queue.enqueueBatch(src, .{
        .ecn = .not_ect,
        .segment_size = 0,
        .contents = "invalid-batch",
    });

    try std.testing.expectEqual(@as(usize, 2), queue.dropped_by_overflow.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), queue.dropped_by_queue_full.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 2), queue.dropped_by_oversize_or_invalid.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), queue.dropped_by_allocation_failure.load(.monotonic));

    // Leave owned items queued for deinitQueue so the testing allocator proves cleanup.
    queue.enqueue(src, "cleanup-single");
    queue.enqueueBatch(src, .{
        .ecn = .not_ect,
        .segment_size = 4,
        .contents = "cleanup-batch",
    });
    try std.testing.expectEqual(@as(usize, 2), queue.len);
}

test "F1: queued relay allocation failure drops transactionally and remains usable" {
    const src = key.SecretKey.fromBytes([_]u8{24} ** 32).public();
    var failing_state = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    const failing_allocator = failing_state.allocator();
    var queue = try QueuedRelayClient.initForTest(failing_allocator);
    defer queue.deinitQueue();

    queue.enqueue(src, "allocation-fails");
    try std.testing.expectEqual(@as(usize, 0), queue.len);
    try std.testing.expectEqual(@as(usize, 1), queue.dropped_by_overflow.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 1), queue.dropped_by_allocation_failure.load(.monotonic));

    failing_state.fail_index = std.math.maxInt(usize);
    queue.enqueue(src, "usable-after-oom");
    var recv_buf: [QueuedRelayClient.max_datagram]u8 = undefined;
    const received = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("usable-after-oom", received.data);
    try std.testing.expectEqual(@as(usize, 0), queue.len);

    queue.deinitQueue();
    try std.testing.expectEqual(failing_state.allocated_bytes, failing_state.freed_bytes);
}
