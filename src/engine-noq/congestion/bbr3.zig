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
        // u128 intermediate on the bootstrap path too: a saturated window
        // (see below) would otherwise overflow window * 10 (lane-02 H3).
        const bw: u64 = if (self.max_bw == 0)
            @intCast(@min(@as(u128, self.window) * 10, std.math.maxInt(u64)))
        else
            self.max_bw;
        const gain: f64 = switch (self.state) {
            .startup => startup_pacing_gain,
            .drain => drain_pacing_gain,
            .probe_bw => if (self.probe_bw_cycle % 8 == 0) probe_bw_gain else 1.0,
            .probe_rtt => 1.0,
        };
        // lossyCast clamps to u64 range: bw * 2.77 can exceed u64 max after a
        // saturated bandwidth sample, where @intFromFloat would trip safety UB.
        self.pacing_rate = std.math.lossyCast(u64, @as(f64, @floatFromInt(bw)) * gain);
        self.send_quantum = @max(self.current_mtu, @min(self.window / 4, 64 * 1024));
        // BDP * gain — u128 intermediate: max_bw * min_rtt_ns overflows u64 on
        // very high-BDP paths (regression lane-02 H3); saturate instead of
        // panicking (safe builds) or wrapping (release). cwnd_gain == 2.0, so
        // the gain multiply is exact in integers.
        if (self.min_rtt_ns != std.math.maxInt(i64) and self.max_bw != 0) {
            const bdp = @as(u128, self.max_bw) * @as(u128, @intCast(self.min_rtt_ns)) / 1_000_000_000;
            const target = @min(bdp * 2, @as(u128, std.math.maxInt(u64)));
            self.window = @max(self.current_mtu * 4, @as(u64, @intCast(target)));
        }
    }

    fn onPacketSent(self: *Bbr3, now: Instant, bytes: u16, _: u64) void {
        _ = self;
        _ = now;
        _ = bytes;
        // tracked via on_ack delivery
    }

    fn onAck(self: *Bbr3, now: Instant, sent: Instant, bytes: u64, _: u64, app_limited: bool, rtt: congestion.RttSample) void {
        // Always refresh RTT/delivery samples so min_rtt stays accurate, but
        // suppress window/bandwidth *growth* while the application is limited
        // (same contract as NewReno/Cubic — J9).
        if (rtt.min_ns < self.min_rtt_ns) self.min_rtt_ns = rtt.min_ns;
        if (app_limited) {
            self.recomputePacing(now);
            return;
        }
        self.delivered += bytes;
        // Bandwidth sample: bytes / elapsed — u128 intermediate, same
        // overflow class as the BDP path (lane-02 H3).
        const elapsed = now - sent;
        if (elapsed > 0) {
            const sample: u64 = @intCast(@min(
                @as(u128, bytes) * 1_000_000_000 / @as(u128, @intCast(elapsed)),
                std.math.maxInt(u64),
            ));
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

test "BBR3 BDP and bandwidth-sample arithmetic saturate instead of overflowing u64" {
    const allocator = std.testing.allocator;
    var cc = try create(allocator, 0, 1200);
    defer cc.destroy(allocator);
    const self: *Bbr3 = @ptrCast(@alignCast(cc.ptr));
    // Pathological high-BDP path: max_bw * min_rtt_ns overflows u64 without
    // widening (regression lane-02 H3) — safe build panics, release wraps the
    // window toward zero.
    self.max_bw = std.math.maxInt(u64) / 10;
    self.min_rtt_ns = 60_000_000_000; // 60 s
    self.recomputePacing(0);
    // Window saturates to u64 max (BDP * 2 clamped), never wraps below the
    // 4-MTU floor.
    try std.testing.expectEqual(std.math.maxInt(u64), cc.window());
    // Pacing rate is clamped to u64 range, not @intFromFloat safety UB.
    try std.testing.expect(cc.pacingRate().? > 0);
    // Bandwidth-sample path: huge delivery over a tiny elapsed interval.
    self.state = .probe_bw;
    self.window = 12_000;
    const rtt = congestion.RttSample{ .latest_ns = 20_000_000, .smoothed_ns = 20_000_000, .min_ns = 20_000_000, .var_ns = 5_000_000 };
    cc.onAck(1, 0, std.math.maxInt(u64) / 1000, 1, false, rtt);
    try std.testing.expectEqual(std.math.maxInt(u64), self.max_bw);
    try std.testing.expect(cc.pacingRate().? > 0);
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

test "J9: BBR3 suppresses window growth while app-limited" {
    const allocator = std.testing.allocator;
    var cc = try create(allocator, 0, 1200);
    defer cc.destroy(allocator);
    const self: *Bbr3 = @ptrCast(@alignCast(cc.ptr));
    const rtt = congestion.RttSample{ .latest_ns = 20_000_000, .smoothed_ns = 20_000_000, .min_ns = 20_000_000, .var_ns = 5_000_000 };

    // Establish a baseline window with a normal ACK.
    cc.onAck(20_000_000, 0, 12_000, 1, false, rtt);
    const window_after_growth = self.window;
    try std.testing.expect(window_after_growth > 0);

    // App-limited ACKs must not grow the window further (J9).
    cc.onAck(40_000_000, 20_000_000, 12_000, 2, true, rtt);
    cc.onAck(60_000_000, 40_000_000, 12_000, 3, true, rtt);
    try std.testing.expectEqual(window_after_growth, self.window);
}
