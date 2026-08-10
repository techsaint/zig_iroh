//! Batched UDP pump helpers for the greenfield transport endpoint.
//!
//! Also owns the Linux event-driven wait helpers (`waitReadable` / `ppoll`)
//! used by both the legacy (`quic.zig`) and G2 (`endpoint.zig`) receive loops
//! to kill the zero-timeout poll storm.

const std = @import("std");
const builtin = @import("builtin");
const c = @import("../connection/c.zig").c;

const net = std.Io.net;
const posix = std.posix;

pub const outgoing_batch_size = 8;
pub const incoming_batch_size = 8;
pub const incoming_datagram_size = 2048;

/// Cap for a single blocking wait (matches the historical `wait_timeout` of 1 ms
/// so `checkWaiters` cadence is unchanged).
pub const max_wait_ns: u64 = 1 * std.time.ns_per_ms;

pub const wait_timeout: std.Io.Timeout = .{ .duration = .{
    .raw = .fromMilliseconds(1),
    .clock = .awake,
} };

pub const drain_timeout: std.Io.Timeout = .{ .duration = .{
    .raw = .fromNanoseconds(0),
    .clock = .awake,
} };

pub const OutgoingBatch = struct {
    packets: [outgoing_batch_size][c.PICOQUIC_MAX_PACKET_SIZE]u8 = undefined,
    destinations: [outgoing_batch_size]net.IpAddress = undefined,
    messages: [outgoing_batch_size]net.OutgoingMessage = undefined,
    count: usize = 0,

    pub fn isFull(self: *const OutgoingBatch) bool {
        return self.count == outgoing_batch_size;
    }

    pub fn append(self: *OutgoingBatch, destination: net.IpAddress, bytes: []const u8) void {
        std.debug.assert(self.count < outgoing_batch_size);
        std.debug.assert(bytes.len <= c.PICOQUIC_MAX_PACKET_SIZE);
        const index = self.count;
        self.destinations[index] = destination;
        @memcpy(self.packets[index][0..bytes.len], bytes);
        self.messages[index] = .{
            .address = &self.destinations[index],
            .data_ptr = self.packets[index][0..bytes.len].ptr,
            .data_len = bytes.len,
        };
        self.count += 1;
    }

    pub fn slice(self: *OutgoingBatch) []net.OutgoingMessage {
        return self.messages[0..self.count];
    }
};

pub const IncomingBatch = struct {
    messages: [incoming_batch_size]net.IncomingMessage = undefined,
    data: [incoming_batch_size * incoming_datagram_size]u8 = undefined,

    pub fn init(self: *IncomingBatch) void {
        for (&self.messages) |*message| message.* = net.IncomingMessage.init;
    }
};

/// Linux-gated blocking wait on one or more pollfds with nanosecond timeout.
/// Returns the number of ready descriptors (0 on timeout).
/// Portable fallback uses `poll` with millisecond rounding.
pub fn waitReadable(fds: []posix.pollfd, timeout_ns: u64) !usize {
    if (fds.len == 0) return 0;
    if (builtin.os.tag == .linux) {
        const ts = posix.timespec{
            .sec = @intCast(timeout_ns / std.time.ns_per_s),
            .nsec = @intCast(timeout_ns % std.time.ns_per_s),
        };
        while (true) {
            return posix.ppoll(fds, &ts, null) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => |e| return e,
            };
        }
    } else {
        const ms_u64 = timeout_ns / std.time.ns_per_ms;
        const ms: i32 = if (ms_u64 > std.math.maxInt(i32))
            std.math.maxInt(i32)
        else
            @intCast(ms_u64);
        return posix.poll(fds, ms);
    }
}

/// Result of waiting on the UDP socket and optional command-wake fd.
pub const SocketWakeResult = struct {
    socket_ready: bool = false,
    wake_ready: bool = false,
};

/// `ppoll` the UDP socket and optional wake fd. On timeout both flags are false.
pub fn waitSocketOrWake(
    socket_fd: posix.fd_t,
    wake_fd: ?posix.fd_t,
    timeout_ns: u64,
) !SocketWakeResult {
    var fds_buf: [2]posix.pollfd = undefined;
    var n: usize = 1;
    fds_buf[0] = .{
        .fd = socket_fd,
        .events = posix.POLL.IN,
        .revents = 0,
    };
    if (wake_fd) |wfd| {
        fds_buf[1] = .{
            .fd = wfd,
            .events = posix.POLL.IN,
            .revents = 0,
        };
        n = 2;
    }
    const ready = try waitReadable(fds_buf[0..n], timeout_ns);
    if (ready == 0) return .{};
    return .{
        .socket_ready = (fds_buf[0].revents & (posix.POLL.IN | posix.POLL.ERR | posix.POLL.HUP)) != 0,
        .wake_ready = n > 1 and (fds_buf[1].revents & (posix.POLL.IN | posix.POLL.ERR | posix.POLL.HUP)) != 0,
    };
}

/// Cap picoquic's next-wake delay (µs) to `max_wait_ns`. Returns null when the
/// delay is ≤ 0 (outgoing/timer work pending — caller must not block).
pub fn waitNsFromWakeDelayUs(wake_delay_us: i64) ?u64 {
    if (wake_delay_us <= 0) return null;
    const capped_us: u64 = @intCast(@min(wake_delay_us, @as(i64, @intCast(max_wait_ns / std.time.ns_per_us))));
    return capped_us * std.time.ns_per_us;
}

/// Create a non-blocking cloexec eventfd for command wakeups (Linux only).
pub fn createWakeFd() !posix.fd_t {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const rc = std.os.linux.eventfd(0, std.os.linux.EFD.CLOEXEC | std.os.linux.EFD.NONBLOCK);
    switch (std.os.linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        else => return error.SystemResources,
    }
}

/// Write 8 bytes to the wake fd (lost-wakeup safe: multiple writes coalesce).
pub fn signalWake(wake_fd: posix.fd_t) void {
    if (builtin.os.tag != .linux) return;
    const one: u64 = 1;
    _ = std.os.linux.write(wake_fd, std.mem.asBytes(&one), 8);
}

/// Drain the eventfd counter so subsequent ppolls block again.
pub fn drainWake(wake_fd: posix.fd_t) void {
    if (builtin.os.tag != .linux) return;
    var buf: u64 = 0;
    while (true) {
        const rc = std.os.linux.read(wake_fd, std.mem.asBytes(&buf), 8);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => continue,
            .AGAIN => return,
            else => return,
        }
    }
}

pub fn closeWakeFd(wake_fd: posix.fd_t) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.close(wake_fd);
    }
}

// ── Linux recvmmsg batch for G2 IncomingBatch ───────────────────────────────

/// Non-blocking `recvmmsg` into an `IncomingBatch`. Returns datagram count (0 on EAGAIN).
/// Fills `batch.messages[0..count]` with `from` + `data` slices into `batch.data`.
/// `parseFrom` converts a filled sockaddr storage blob into an `IpAddress`.
pub fn recvmmsgDontWait(
    handle: posix.socket_t,
    batch: *IncomingBatch,
    parseFrom: *const fn (*const c.struct_sockaddr_storage) error{ConnectionLost}!net.IpAddress,
) error{ConnectionLost}!usize {
    if (builtin.os.tag != .linux) return error.ConnectionLost;

    var messages: [incoming_batch_size]std.os.linux.mmsghdr = undefined;
    var iovecs: [incoming_batch_size]posix.iovec = undefined;
    var addrs: [incoming_batch_size]c.struct_sockaddr_storage = undefined;

    for (0..incoming_batch_size) |i| {
        const data_off = i * incoming_datagram_size;
        iovecs[i] = .{
            .base = batch.data[data_off..][0..incoming_datagram_size].ptr,
            .len = incoming_datagram_size,
        };
        messages[i] = .{
            .hdr = .{
                .name = @ptrCast(&addrs[i]),
                .namelen = @intCast(@sizeOf(c.struct_sockaddr_storage)),
                .iov = iovecs[i..][0..1].ptr,
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            },
            .len = 0,
        };
    }

    while (true) {
        const rc = std.os.linux.recvmmsg(
            handle,
            &messages,
            @intCast(incoming_batch_size),
            std.os.linux.MSG.DONTWAIT,
            null,
        );
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                const count: usize = @intCast(rc);
                for (0..count) |i| {
                    const msg = messages[i];
                    if ((msg.hdr.flags & (std.os.linux.MSG.TRUNC | std.os.linux.MSG.CTRUNC)) != 0)
                        return error.ConnectionLost;
                    const data_len: usize = @intCast(msg.len);
                    if (data_len > incoming_datagram_size) return error.ConnectionLost;
                    const data_off = i * incoming_datagram_size;
                    const from = try parseFrom(&addrs[i]);
                    batch.messages[i] = .{
                        .from = from,
                        .data = batch.data[data_off..][0..data_len],
                        .control = &.{},
                        .flags = std.mem.zeroes(net.IncomingMessage.Flags),
                    };
                }
                return count;
            },
            .INTR => continue,
            .AGAIN => return 0,
            else => return error.ConnectionLost,
        }
    }
}

test "waitNsFromWakeDelayUs: no block when delay <= 0" {
    try std.testing.expect(waitNsFromWakeDelayUs(0) == null);
    try std.testing.expect(waitNsFromWakeDelayUs(-1) == null);
    try std.testing.expectEqual(@as(u64, 500 * std.time.ns_per_us), waitNsFromWakeDelayUs(500).?);
    try std.testing.expectEqual(max_wait_ns, waitNsFromWakeDelayUs(10 * std.time.us_per_ms).?);
}

test "waitReadable: timeout returns 0" {
    if (builtin.os.tag != .linux) return;
    // An unconnected pipe read end never becomes readable without a writer.
    var pair: [2]i32 = undefined;
    switch (std.os.linux.errno(std.os.linux.pipe2(&pair, .{}))) {
        .SUCCESS => {},
        else => return error.SkipZigTest,
    }
    defer {
        _ = std.os.linux.close(pair[0]);
        _ = std.os.linux.close(pair[1]);
    }
    var pollfds = [_]posix.pollfd{.{
        .fd = pair[0],
        .events = posix.POLL.IN,
        .revents = 0,
    }};
    const n = try waitReadable(&pollfds, 100 * std.time.ns_per_us);
    try std.testing.expectEqual(@as(usize, 0), n);
}
