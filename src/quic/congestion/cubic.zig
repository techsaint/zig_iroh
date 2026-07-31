//! CUBIC congestion controller (RFC 8312 / iroh default).
const std = @import("std");
const congestion = @import("../congestion.zig");

const Instant = congestion.Instant;
const base = congestion.base_datagram_size;
const beta: f64 = 0.7;
const c_const: f64 = 0.4;

pub const Cubic = struct {
    window: u64,
    ssthresh: u64,
    recovery_start_time: ?Instant,
    current_mtu: u64,
    w_max: f64,
    k: f64,
    cwnd_inc: u64,
    initial_window: u64,
    smoothed_rtt_ns: i64 = 30_000_000,
    pacing_rate: ?u64 = null,
    /// G15 (noq `pre_congestion_state`, cubic.rs:201-204): snapshot taken
    /// before each non-ECN congestion event so a spurious event can be undone.
    pre_congestion_state: ?StateSnapshot = null,

    const StateSnapshot = struct {
        window: u64,
        ssthresh: u64,
        recovery_start_time: ?Instant,
        w_max: f64,
        k: f64,
        cwnd_inc: u64,
    };

    fn snapshot(self: *const Cubic) StateSnapshot {
        return .{
            .window = self.window,
            .ssthresh = self.ssthresh,
            .recovery_start_time = self.recovery_start_time,
            .w_max = self.w_max,
            .k = self.k,
            .cwnd_inc = self.cwnd_inc,
        };
    }

    pub fn init(_: Instant, mtu: u16) Cubic {
        const iw = std.math.clamp(14720, 2 * base, 10 * base);
        var self = Cubic{
            .window = iw,
            .ssthresh = std.math.maxInt(u64),
            .recovery_start_time = null,
            .current_mtu = mtu,
            .w_max = @floatFromInt(iw),
            .k = 0,
            .cwnd_inc = 0,
            .initial_window = iw,
        };
        self.recomputePacing();
        return self;
    }

    fn minimumWindow(self: *const Cubic) u64 {
        return 2 * self.current_mtu;
    }

    pub fn recomputePacing(self: *Cubic) void {
        const rtt = @max(self.smoothed_rtt_ns, 1_000_000);
        const rate = self.window * std.time.ns_per_s / @as(u64, @intCast(rtt));
        self.pacing_rate = if (rate > 0) rate else null;
    }

    fn onAck(self: *Cubic, now: Instant, sent: Instant, bytes: u64, _: u64, app_limited: bool, rtt: congestion.RttSample) void {
        if (rtt.smoothed_ns > 0) self.smoothed_rtt_ns = rtt.smoothed_ns;
        if (app_limited) return;
        if (self.recovery_start_time) |rs| {
            if (sent <= rs) return;
        }
        if (self.window < self.ssthresh) {
            self.window += bytes;
            self.recomputePacing();
            return;
        }
        // Congestion avoidance: cubic target
        const t_s = @as(f64, @floatFromInt(now - (self.recovery_start_time orelse now))) / 1e9;
        const rtt_s = @max(@as(f64, @floatFromInt(rtt.get())) / 1e9, 0.001);
        const w_max_pkts = self.w_max / @as(f64, @floatFromInt(self.current_mtu));
        const w_cubic = (c_const * std.math.pow(f64, t_s - self.k, 3) + w_max_pkts) * @as(f64, @floatFromInt(self.current_mtu));
        const w_est = (w_max_pkts * beta + 3.0 * (1.0 - beta) / (1.0 + beta) * (t_s / rtt_s)) * @as(f64, @floatFromInt(self.current_mtu));
        const target = @max(w_cubic, w_est);
        if (target > @as(f64, @floatFromInt(self.window))) {
            self.cwnd_inc += @intFromFloat(target - @as(f64, @floatFromInt(self.window)));
            if (self.cwnd_inc >= self.window) {
                self.window += self.current_mtu;
                self.cwnd_inc = 0;
            }
        }
        self.recomputePacing();
    }

    fn onCongestionEvent(self: *Cubic, now: Instant, sent: Instant, is_persistent: bool, is_ecn: bool, _: u64, _: u64) void {
        if (self.recovery_start_time) |rs| {
            if (sent <= rs) return;
        }
        // G15 (noq cubic.rs:201-204): save state in case this event ends up
        // being spurious.
        if (!is_ecn) self.pre_congestion_state = self.snapshot();
        self.recovery_start_time = now;
        self.w_max = @floatFromInt(self.window);
        const w_max_pkts = self.w_max / @as(f64, @floatFromInt(self.current_mtu));
        self.k = std.math.cbrt(w_max_pkts * (1.0 - beta) / c_const);
        self.window = @max(@as(u64, @intFromFloat(@as(f64, @floatFromInt(self.window)) * beta)), self.minimumWindow());
        self.ssthresh = self.window;
        self.cwnd_inc = 0;
        if (is_persistent) {
            // G16 (noq cubic.rs:226-238, "4.7 Timeout"): fresh slow start —
            // recovery ends, ssthresh re-derives from the reduced window and
            // cwnd collapses to the minimum.
            self.recovery_start_time = null;
            self.w_max = @floatFromInt(self.window);
            self.ssthresh = @max(@as(u64, @intFromFloat(@as(f64, @floatFromInt(self.window)) * beta)), self.minimumWindow());
            self.window = self.minimumWindow();
        }
        self.recomputePacing();
    }

    /// G15 (noq cubic.rs:242-248): undo a congestion event that turned out
    /// spurious — restore the pre-event state when the event actually
    /// shrank the window.
    fn onSpuriousCongestionEvent(self: *Cubic) void {
        if (self.pre_congestion_state) |prior| {
            self.pre_congestion_state = null;
            if (self.window < prior.window) {
                self.window = prior.window;
                self.ssthresh = prior.ssthresh;
                self.recovery_start_time = prior.recovery_start_time;
                self.w_max = prior.w_max;
                self.k = prior.k;
                self.cwnd_inc = prior.cwnd_inc;
                self.recomputePacing();
            }
        }
    }
};

fn vOnSent(_: *anyopaque, _: Instant, _: u64, _: u64) void {}
fn vOnPacketSent(_: *anyopaque, _: Instant, _: u16, _: u64) void {}
fn vOnAck(ptr: *anyopaque, now: Instant, sent: Instant, bytes: u64, pn: u64, app_limited: bool, rtt: congestion.RttSample) void {
    @as(*Cubic, @ptrCast(@alignCast(ptr))).onAck(now, sent, bytes, pn, app_limited, rtt);
}
fn vOnEndAcks(_: *anyopaque, _: Instant, _: u64, _: bool, _: ?u64) void {}
fn vOnCongestion(ptr: *anyopaque, now: Instant, sent: Instant, pers: bool, ecn: bool, lost: u64, lpn: u64) void {
    @as(*Cubic, @ptrCast(@alignCast(ptr))).onCongestionEvent(now, sent, pers, ecn, lost, lpn);
}
fn vOnPacketLost(_: *anyopaque, _: u16, _: u64, _: Instant) void {}
fn vOnSpurious(ptr: *anyopaque) void {
    @as(*Cubic, @ptrCast(@alignCast(ptr))).onSpuriousCongestionEvent();
}
fn vOnMtu(ptr: *anyopaque, new_mtu: u16) void {
    const self: *Cubic = @ptrCast(@alignCast(ptr));
    self.current_mtu = new_mtu;
    self.window = @max(self.window, self.minimumWindow());
}
fn vWindow(ptr: *anyopaque) u64 {
    return @as(*Cubic, @ptrCast(@alignCast(ptr))).window;
}
fn vPacing(ptr: *anyopaque) ?u64 {
    return @as(*Cubic, @ptrCast(@alignCast(ptr))).pacing_rate;
}
fn vQuantum(ptr: *anyopaque) ?u64 {
    const self: *Cubic = @ptrCast(@alignCast(ptr));
    return self.current_mtu;
}
fn vDestroy(ptr: *anyopaque, allocator: std.mem.Allocator) void {
    allocator.destroy(@as(*Cubic, @ptrCast(@alignCast(ptr))));
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
    const self = try allocator.create(Cubic);
    self.* = Cubic.init(now, mtu);
    return .{ .ptr = self, .vtable = &vtable };
}

test "Cubic window grows in slow start and reduces on loss" {
    const allocator = std.testing.allocator;
    var cc = try create(allocator, 0, 1200);
    defer cc.destroy(allocator);
    const rtt = congestion.RttSample{ .latest_ns = 30_000_000, .smoothed_ns = 30_000_000, .min_ns = 25_000_000, .var_ns = 5_000_000 };
    const start = cc.window();
    cc.onAck(100_000_000, 50_000_000, 2400, 1, false, rtt);
    try std.testing.expect(cc.window() > start);
    const before = cc.window();
    cc.onCongestionEvent(200_000_000, 150_000_000, false, false, 1200, 2);
    try std.testing.expect(cc.window() < before);
}
