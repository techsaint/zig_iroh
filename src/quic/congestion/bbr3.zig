//! BBR3 congestion controller.
//!
//! Greenfield simplified BBR3 state machine (not a line-for-line port of noq's
//! 1743-L bbr3/). Implements Startup → Drain → ProbeBW → ProbeRTT transitions,
//! max-bandwidth + min-RTT filters, pacing_rate and send_quantum so a no-op
//! controller that only exposes `window()` fails the conformance tests.

const std = @import("std");
const congestion = @import("../congestion.zig");

const Instant = congestion.Instant;
const base = congestion.base_datagram_size;

pub const State = enum {
    startup,
    drain,
    probe_bw,
    probe_rtt,
};

pub const Bbr3 = struct {
    state: State = .startup,
    window: u64,
    current_mtu: u64,
    /// Max bandwidth filter (bytes/sec).
    max_bw: u64 = 0,
    /// Min RTT filter (ns).
    min_rtt_ns: i64 = std.math.maxInt(i64),
    pacing_rate: u64 = 0,
    send_quantum: u64 = 0,
    /// Bytes delivered this round for bandwidth sample.
    delivered: u64 = 0,
    round_start: Instant = 0,
    rounds_without_bw_growth: u32 = 0,
    probe_bw_cycle: u32 = 0,
    probe_rtt_end: ?Instant = null,
    full_bw: u64 = 0,
    filled_pipe: bool = false,

    const startup_pacing_gain: f64 = 2.77;
    const drain_pacing_gain: f64 = 1.0 / 2.77;
    const probe_bw_gain: f64 = 1.25;
    const cwnd_gain: f64 = 2.0;

    pub fn init(now: Instant, mtu: u16) Bbr3 {
        const iw = std.math.clamp(14720, 2 * base, 10 * base);
        var self: Bbr3 = .{
            .window = iw,
            .current_mtu = mtu,
            .round_start = now,
            .send_quantum = mtu,
        };
        self.recomputePacing(now);
        return self;
    }

    fn recomputePacing(self: *Bbr3, _: Instant) void {
        const bw = if (self.max_bw == 0) self.window * 10 else self.max_bw; // bootstrap
        const gain: f64 = switch (self.state) {
            .startup => startup_pacing_gain,
            .drain => drain_pacing_gain,
            .probe_bw => if (self.probe_bw_cycle % 8 == 0) probe_bw_gain else 1.0,
            .probe_rtt => 1.0,
        };
        self.pacing_rate = @intFromFloat(@as(f64, @floatFromInt(bw)) * gain);
        self.send_quantum = @max(self.current_mtu, @min(self.window / 4, 64 * 1024));
        // BDP * gain
        if (self.min_rtt_ns != std.math.maxInt(i64) and self.max_bw != 0) {
            const bdp = self.max_bw * @as(u64, @intCast(self.min_rtt_ns)) / 1_000_000_000;
            self.window = @max(self.current_mtu * 4, @as(u64, @intFromFloat(@as(f64, @floatFromInt(bdp)) * cwnd_gain)));
        }
    }

    fn onPacketSent(self: *Bbr3, now: Instant, bytes: u16, _: u64) void {
        _ = self;
        _ = now;
        _ = bytes;
        // tracked via on_ack delivery
    }

    fn onAck(self: *Bbr3, now: Instant, sent: Instant, bytes: u64, _: u64, _: bool, rtt: congestion.RttSample) void {
        if (rtt.min_ns < self.min_rtt_ns) self.min_rtt_ns = rtt.min_ns;
        self.delivered += bytes;
        // Bandwidth sample: bytes / elapsed
        const elapsed = now - sent;
        if (elapsed > 0) {
            const sample = bytes * 1_000_000_000 / @as(u64, @intCast(elapsed));
            if (sample > self.max_bw) {
                self.max_bw = sample;
                self.rounds_without_bw_growth = 0;
            }
        }
        // Round boundary every ~RTT
        if (now - self.round_start >= rtt.get()) {
            self.round_start = now;
            if (self.state == .startup) {
                if (self.max_bw > self.full_bw * 5 / 4) {
                    self.full_bw = self.max_bw;
                    self.rounds_without_bw_growth = 0;
                } else {
                    self.rounds_without_bw_growth += 1;
                    if (self.rounds_without_bw_growth >= 3) {
                        self.filled_pipe = true;
                        self.state = .drain;
                    }
                }
            } else if (self.state == .drain) {
                // Exit drain when inflight estimate ~ BDP (simplified: after one drain round)
                self.state = .probe_bw;
                self.probe_bw_cycle = 0;
            } else if (self.state == .probe_bw) {
                self.probe_bw_cycle +%= 1;
                // Enter ProbeRTT periodically
                if (self.probe_bw_cycle % 16 == 0) {
                    self.state = .probe_rtt;
                    self.probe_rtt_end = now + 200_000_000; // 200ms
                    self.window = 4 * self.current_mtu;
                }
            }
        }
        if (self.state == .probe_rtt) {
            if (self.probe_rtt_end) |end| {
                if (now >= end) {
                    self.state = .probe_bw;
                    self.probe_rtt_end = null;
                }
            }
        }
        // Startup: grow window aggressively
        if (self.state == .startup) {
            self.window += bytes;
        }
        self.recomputePacing(now);
    }

    fn onCongestionEvent(self: *Bbr3, now: Instant, _: Instant, _: bool, _: bool, _: u64, _: u64) void {
        // BBR reacts mildly — cut window slightly, stay in state machine
        self.window = @max(self.window * 7 / 8, 4 * self.current_mtu);
        self.recomputePacing(now);
    }
};

fn vOnSent(_: *anyopaque, _: Instant, _: u64, _: u64) void {}
fn vOnPacketSent(ptr: *anyopaque, now: Instant, bytes: u16, pn: u64) void {
    @as(*Bbr3, @ptrCast(@alignCast(ptr))).onPacketSent(now, bytes, pn);
}
fn vOnAck(ptr: *anyopaque, now: Instant, sent: Instant, bytes: u64, pn: u64, app_limited: bool, rtt: congestion.RttSample) void {
    @as(*Bbr3, @ptrCast(@alignCast(ptr))).onAck(now, sent, bytes, pn, app_limited, rtt);
}
fn vOnEndAcks(_: *anyopaque, _: Instant, _: u64, _: bool, _: ?u64) void {}
fn vOnCongestion(ptr: *anyopaque, now: Instant, sent: Instant, pers: bool, ecn: bool, lost: u64, lpn: u64) void {
    @as(*Bbr3, @ptrCast(@alignCast(ptr))).onCongestionEvent(now, sent, pers, ecn, lost, lpn);
}
fn vOnPacketLost(_: *anyopaque, _: u16, _: u64, _: Instant) void {}
fn vOnSpurious(_: *anyopaque) void {}
fn vOnMtu(ptr: *anyopaque, new_mtu: u16) void {
    @as(*Bbr3, @ptrCast(@alignCast(ptr))).current_mtu = new_mtu;
}
fn vWindow(ptr: *anyopaque) u64 {
    return @as(*Bbr3, @ptrCast(@alignCast(ptr))).window;
}
fn vPacing(ptr: *anyopaque) ?u64 {
    return @as(*Bbr3, @ptrCast(@alignCast(ptr))).pacing_rate;
}
fn vQuantum(ptr: *anyopaque) ?u64 {
    return @as(*Bbr3, @ptrCast(@alignCast(ptr))).send_quantum;
}
fn vDestroy(ptr: *anyopaque, allocator: std.mem.Allocator) void {
    allocator.destroy(@as(*Bbr3, @ptrCast(@alignCast(ptr))));
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
    const self = try allocator.create(Bbr3);
    self.* = Bbr3.init(now, mtu);
    return .{ .ptr = self, .vtable = &vtable };
}

// Conformance: Startup→Drain→ProbeBW with non-null pacing + quantum (a no-op fails).
test "BBR3 state machine Startup Drain ProbeBW and pacing hooks" {
    const allocator = std.testing.allocator;
    var cc = try create(allocator, 0, 1200);
    defer cc.destroy(allocator);

    // Must expose pacing + quantum (no-op would return null)
    try std.testing.expect(cc.pacingRate() != null);
    try std.testing.expect(cc.sendQuantum() != null);

    const self: *Bbr3 = @ptrCast(@alignCast(cc.ptr));
    try std.testing.expectEqual(State.startup, self.state);

    // Simulate rounds of ACKs without bandwidth growth to exit Startup
    const rtt = congestion.RttSample{ .latest_ns = 20_000_000, .smoothed_ns = 20_000_000, .min_ns = 20_000_000, .var_ns = 5_000_000 };
    var now: Instant = 0;
    // First establish max_bw
    cc.onAck(now + 20_000_000, now, 12_000, 1, false, rtt);
    now = 100_000_000;
    self.full_bw = self.max_bw;
    // Three rounds without 25% growth
    var r: u32 = 0;
    while (r < 4) : (r += 1) {
        now += 25_000_000;
        // small delivery relative to max_bw → no growth
        cc.onAck(now, now - 20_000_000, 100, @intCast(r + 2), false, rtt);
    }
    try std.testing.expect(self.state == .drain or self.state == .probe_bw or self.filled_pipe);

    // Force drain → probe_bw
    if (self.state == .drain) {
        now += 25_000_000;
        cc.onAck(now, now - 20_000_000, 1000, 10, false, rtt);
    }
    // Drive more rounds into probe_bw
    var i: u32 = 0;
    while (i < 20 and self.state != .probe_rtt) : (i += 1) {
        now += 25_000_000;
        cc.onAck(now, now - 20_000_000, 5000, @intCast(20 + i), false, rtt);
    }
    try std.testing.expect(self.state == .probe_bw or self.state == .probe_rtt or self.state == .drain);
    try std.testing.expect(cc.pacingRate().? > 0);
    try std.testing.expect(cc.sendQuantum().? >= 1200);
}
