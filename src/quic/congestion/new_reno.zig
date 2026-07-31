//! NewReno congestion controller (RFC 9002 baseline).
const std = @import("std");
const congestion = @import("../congestion.zig");

const Instant = congestion.Instant;
const base = congestion.base_datagram_size;

pub const NewReno = struct {
    window: u64,
    ssthresh: u64,
    recovery_start_time: Instant,
    current_mtu: u64,
    bytes_acked: u64,
    initial_window: u64,
    loss_reduction_factor: f32,
    smoothed_rtt_ns: i64 = 30_000_000,
    pacing_rate: ?u64 = null,

    pub fn init(now: Instant, mtu: u16) NewReno {
        const m = @as(u64, mtu);
        const iw = std.math.clamp(14720, 2 * base, 10 * base);
        var self = NewReno{
            .window = iw,
            .ssthresh = std.math.maxInt(u64),
            .recovery_start_time = now,
            .current_mtu = m,
            .bytes_acked = 0,
            .initial_window = iw,
            .loss_reduction_factor = 0.5,
        };
        self.recomputePacing();
        return self;
    }

    fn minimumWindow(self: *const NewReno) u64 {
        return 2 * self.current_mtu;
    }

    fn recomputePacing(self: *NewReno) void {
        const rtt = @max(self.smoothed_rtt_ns, 1_000_000);
        const rate = self.window * std.time.ns_per_s / @as(u64, @intCast(rtt));
        self.pacing_rate = if (rate > 0) rate else null;
    }

    fn onAck(self: *NewReno, _: Instant, sent: Instant, bytes: u64, _: u64, app_limited: bool, rtt: congestion.RttSample) void {
        if (rtt.smoothed_ns > 0) self.smoothed_rtt_ns = rtt.smoothed_ns;
        if (app_limited or sent <= self.recovery_start_time) return;
        if (self.window < self.ssthresh) {
            self.window += bytes;
            if (self.window >= self.ssthresh) {
                self.bytes_acked = self.window - self.ssthresh;
            }
        } else {
            self.bytes_acked += bytes;
            if (self.bytes_acked >= self.window) {
                self.bytes_acked -= self.window;
                self.window += self.current_mtu;
            }
        }
        self.recomputePacing();
    }

    fn onCongestionEvent(self: *NewReno, now: Instant, sent: Instant, is_persistent: bool, _: bool, _: u64, _: u64) void {
        if (sent <= self.recovery_start_time) return;
        self.recovery_start_time = now;
        self.window = @max(@as(u64, @intFromFloat(@as(f64, @floatFromInt(self.window)) * self.loss_reduction_factor)), self.minimumWindow());
        self.ssthresh = self.window;
        if (is_persistent) self.window = self.minimumWindow();
        self.recomputePacing();
    }
};

fn vOnSent(_: *anyopaque, _: Instant, _: u64, _: u64) void {}
fn vOnPacketSent(_: *anyopaque, _: Instant, _: u16, _: u64) void {}
fn vOnAck(ptr: *anyopaque, now: Instant, sent: Instant, bytes: u64, pn: u64, app_limited: bool, rtt: congestion.RttSample) void {
    @as(*NewReno, @ptrCast(@alignCast(ptr))).onAck(now, sent, bytes, pn, app_limited, rtt);
}
fn vOnEndAcks(_: *anyopaque, _: Instant, _: u64, _: bool, _: ?u64) void {}
fn vOnCongestion(ptr: *anyopaque, now: Instant, sent: Instant, pers: bool, ecn: bool, lost: u64, lpn: u64) void {
    @as(*NewReno, @ptrCast(@alignCast(ptr))).onCongestionEvent(now, sent, pers, ecn, lost, lpn);
}
fn vOnPacketLost(_: *anyopaque, _: u16, _: u64, _: Instant) void {}
fn vOnSpurious(_: *anyopaque) void {}
fn vOnMtu(ptr: *anyopaque, new_mtu: u16) void {
    const self: *NewReno = @ptrCast(@alignCast(ptr));
    self.current_mtu = new_mtu;
    self.window = @max(self.window, self.minimumWindow());
}
fn vWindow(ptr: *anyopaque) u64 {
    return @as(*NewReno, @ptrCast(@alignCast(ptr))).window;
}
fn vPacing(ptr: *anyopaque) ?u64 {
    return @as(*NewReno, @ptrCast(@alignCast(ptr))).pacing_rate;
}
fn vQuantum(ptr: *anyopaque) ?u64 {
    const self: *NewReno = @ptrCast(@alignCast(ptr));
    return self.current_mtu;
}
fn vDestroy(ptr: *anyopaque, allocator: std.mem.Allocator) void {
    allocator.destroy(@as(*NewReno, @ptrCast(@alignCast(ptr))));
}

const vtable = congestion.Controller.VTable{
    .on_sent = vOnSent,
    .on_packet_sent = vOnPacketSent,
    .on_ack = vOnAck,
    .on_end_acks = vOnEndAcks,
    .on_congestion_event = vOnCongestion,
    .on_packet_lost = vOnPacketLost,
    .on_spurious_congestion_event = vOnSpurious,
    .on_mtu_update = vOnMtu,
    .window = vWindow,
    .pacing_rate = vPacing,
    .send_quantum = vQuantum,
    .destroy = vDestroy,
};

pub fn create(allocator: std.mem.Allocator, now: Instant, mtu: u16) !congestion.Controller {
    const self = try allocator.create(NewReno);
    self.* = NewReno.init(now, mtu);
    return .{ .ptr = self, .vtable = &vtable };
}

test "NewReno slow-start then congestion reduction" {
    const allocator = std.testing.allocator;
    var cc = try create(allocator, 0, 1200);
    defer cc.destroy(allocator);
    const rtt = congestion.RttSample{ .latest_ns = 50_000_000, .smoothed_ns = 50_000_000, .min_ns = 40_000_000, .var_ns = 10_000_000 };
    const start_w = cc.window();
    // ACK after recovery_start — grows in slow start
    cc.onAck(1_000_000_000, 500_000_000, 1200, 1, false, rtt);
    try std.testing.expect(cc.window() > start_w);
    // Congestion event halves window
    const before = cc.window();
    cc.onCongestionEvent(2_000_000_000, 1_500_000_000, false, false, 1200, 2);
    try std.testing.expect(cc.window() <= before);
    try std.testing.expect(cc.window() >= 2 * 1200);
}
