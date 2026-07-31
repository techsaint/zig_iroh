//! Loss detection, PTO, and RTT estimation (RFC 9002).
const std = @import("std");
const connection = @import("connection.zig");
const congestion = @import("congestion.zig");
const spaces = @import("spaces.zig");
const varint = @import("varint.zig");

pub const Instant = i64;
pub const timer_granularity_ns: i64 = 1_000_000; // 1ms
pub const packet_threshold: u64 = 3;
pub const time_threshold_num: i64 = 9;
pub const time_threshold_den: i64 = 8;
pub const persistent_congestion_threshold: i64 = 3; // * (smoothed_rtt + max_ack_delay)

// G14 (noq connection/mod.rs:7552-7573): PTO backoff caps.
/// noq MAX_BACKOFF_EXPONENT — prevents overflow in 2^pto_count.
pub const max_backoff_exponent: u32 = 16;
/// noq MAX_PTO_INTERVAL — the normal cap on the interval between two
/// successive tail-loss probes.
pub const max_pto_interval_ns: i64 = 2_000_000_000; // 2s
/// noq MIN_IDLE_FOR_FAST_PTO — idle timeouts at or below this switch to the
/// shorter probe-interval cap so retransmits get plenty of chances first.
pub const min_idle_for_fast_pto_ns: i64 = 25_000_000_000; // 25s
/// noq MAX_PTO_FAST_INTERVAL.
pub const max_pto_fast_interval_ns: i64 = 1_000_000_000; // 1s
/// noq SLOW_RTT_THRESHOLD — above this RTT, 1.5·RTT exceeds the 2s cap and
/// the cap becomes 1.5·RTT instead of flooding a slow pipe with probes.
pub const slow_rtt_threshold_ns: i64 = @divTrunc(max_pto_interval_ns * 2, 3);

pub const RttEstimator = struct {
    latest: i64,
    smoothed: ?i64 = null,
    var_rtt: i64,
    min_rtt: i64,

    pub fn init(initial_rtt: i64) RttEstimator {
        return .{
            .latest = initial_rtt,
            .var_rtt = @divTrunc(initial_rtt, 2),
            .min_rtt = initial_rtt,
        };
    }

    pub fn get(self: RttEstimator) i64 {
        return self.smoothed orelse self.latest;
    }

    pub fn conservative(self: RttEstimator) i64 {
        return @max(self.get(), self.latest);
    }

    /// RFC 9002 §6.2.1 base term: smoothed_rtt + max(4·rttvar, kGranularity).
    /// Callers add the Application Data `max_ack_delay` term themselves when
    /// computing a data-space PTO (see `ptoDelay`).
    pub fn ptoBase(self: RttEstimator) i64 {
        return self.get() + @max(4 * self.var_rtt, timer_granularity_ns);
    }

    pub fn update(self: *RttEstimator, ack_delay: i64, rtt: i64) void {
        self.latest = rtt;
        self.min_rtt = @min(self.min_rtt, self.latest);
        if (self.smoothed) |smoothed| {
            const adjusted = if (self.min_rtt + ack_delay <= self.latest)
                self.latest - ack_delay
            else
                self.latest;
            const var_sample = if (smoothed > adjusted) smoothed - adjusted else adjusted - smoothed;
            self.var_rtt = @divTrunc(3 * self.var_rtt + var_sample, 4);
            self.smoothed = @divTrunc(7 * smoothed + adjusted, 8);
        } else {
            self.smoothed = self.latest;
            self.var_rtt = @divTrunc(self.latest, 2);
            self.min_rtt = self.latest;
        }
    }

    pub fn sample(self: RttEstimator) congestion.RttSample {
        return .{
            .latest_ns = self.latest,
            .smoothed_ns = self.get(),
            .min_ns = self.min_rtt,
            .var_ns = self.var_rtt,
        };
    }
};

pub const LossEvent = struct {
    packet_number: u64,
    space: spaces.SpaceId,
    size: u16,
    path_generation: u64,
    time_sent: Instant,
};

/// noq `first_packet_after_rtt_sample` (paths.rs:216): the first packet sent
/// after the first RTT sample was taken. Persistent congestion may only START
/// strictly after it (RFC 9002 §7.6.1 / noq mod.rs:3328-3334).
pub const FirstAfterRttSample = struct {
    space: spaces.SpaceId,
    pn: u64,

    /// Lexicographic (space kind, pn) compare — noq's tuple `x < (kind, packet)`.
    pub fn precedes(self: FirstAfterRttSample, space: spaces.SpaceId, pn: u64) bool {
        const a = @intFromEnum(self.space);
        const b = @intFromEnum(space);
        if (a != b) return a < b;
        return self.pn < pn;
    }
};

pub const DetectLossResult = struct {
    count: usize,
    /// G16 (noq detect_lost_packets, mod.rs:3292-3347): every ack-eliciting
    /// packet sent in a span longer than `threshold · (pto_base + max_ack_delay)`
    /// before the newest loss was declared lost, with no acked packet in
    /// between. Only meaningful because this detector is invoked due-to-ACK
    /// (noq's `due_to_ack` gate, mod.rs:3320).
    in_persistent_congestion: bool,
};

/// Detect packets lost by packet threshold and/or time threshold (RFC 9002 §6.1).
/// `max_ack_delay_ns` is the DATA-space max_ack_delay (PTO computation for the
/// persistent-congestion period always includes it, RFC 9001 §7.6.1 /
/// noq mod.rs:3294-3297). `mtu_probe_pn` mirrors noq's exclusion of a lost MTU
/// probe from loss/PC accounting (mod.rs:3313-3316).
pub fn detectLostPackets(
    sent: []const connection.SentPacket,
    now: Instant,
    largest_acked: u64,
    space: spaces.SpaceId,
    rtt: RttEstimator,
    max_ack_delay_ns: i64,
    first_after_sample: ?FirstAfterRttSample,
    mtu_probe_pn: ?u64,
    out: []LossEvent,
) DetectLossResult {
    const loss_delay = @max(@divTrunc(rtt.conservative() * time_threshold_num, time_threshold_den), timer_granularity_ns);
    // G16: the persistent-congestion period (noq mod.rs:3292-3297) — the
    // data-space PTO (max_ack_delay included) × the configured threshold.
    const congestion_period = (rtt.ptoBase() + @max(max_ack_delay_ns, 0)) * persistent_congestion_threshold;
    var pc_start: ?Instant = null;
    var in_persistent_congestion = false;
    var prev_packet: ?u64 = null;
    var n: usize = 0;
    for (sent) |sp| {
        if (sp.space != space) continue;
        if (sp.packet_number > largest_acked) continue;
        // noq mod.rs:3304-3307: an intervening packet was acknowledged → the
        // congestion span is broken.
        if (prev_packet == null or sp.packet_number != prev_packet.? +% 1) pc_start = null;
        const by_packet = largest_acked >= sp.packet_number + packet_threshold;
        const by_time = now - sp.time_sent >= loss_delay;
        if (by_packet or by_time) {
            if (n < out.len) {
                out[n] = .{
                    .packet_number = sp.packet_number,
                    .space = sp.space,
                    .size = sp.size,
                    .path_generation = sp.path_generation,
                    .time_sent = sp.time_sent,
                };
                n += 1;
            }
            // noq mod.rs:3313-3316: a lost MTU probe is reported (the caller
            // runs the probe-loss path) but never enters congestion/PC
            // accounting.
            const is_mtu_probe = if (mtu_probe_pn) |probe| probe == sp.packet_number else false;
            // noq mod.rs:3318-3337: only ack-eliciting losses open or
            // extend the span; two such losses more than
            // congestion_period apart prove persistent congestion.
            if (!is_mtu_probe and sp.ack_eliciting) {
                if (pc_start) |start| {
                    if (sp.time_sent - start > congestion_period) in_persistent_congestion = true;
                } else if (first_after_sample != null and
                    first_after_sample.?.precedes(space, sp.packet_number))
                {
                    pc_start = sp.time_sent;
                }
            }
        } else {
            // Not yet lost: breaks the span (noq mod.rs:3344-3346).
            pc_start = null;
        }
        prev_packet = sp.packet_number;
    }
    return .{ .count = n, .in_persistent_congestion = in_persistent_congestion };
}

/// G14: noq's max_interval selection (pto_time_and_space, mod.rs:3553-3565):
/// 1.5·RTT on slow links, 1s when the idle timeout is short, else 2s. noq
/// takes `path.idle_timeout.or(conn.idle_timeout)`; this stack has one
/// connection-wide idle timeout.
pub fn ptoMaxInterval(rtt: RttEstimator, idle_timeout_ns: ?i64) i64 {
    if (rtt.get() > slow_rtt_threshold_ns) return @divTrunc(rtt.get() * 3, 2);
    if (idle_timeout_ns) |idle| {
        if (idle <= min_idle_for_fast_pto_ns) return max_pto_fast_interval_ns;
    }
    return max_pto_interval_ns;
}

/// PTO duration (RFC 9002 §6.2.1 + noq pto_time_and_space, mod.rs:3609-3623):
/// (pto_base + max_ack_delay) · 2^pto_count, but capped so the INCREMENT over
/// the previous step never exceeds `max_interval` — noq iterates the probes
/// (`duration = min(pto_base·2^i, duration + max_interval)`) rather than
/// clamping the final value, so a long backoff still probes every
/// max_interval. `max_ack_delay` MUST be 0 for Initial/Handshake spaces.
pub fn ptoDelay(rtt: RttEstimator, pto_count: u32, max_ack_delay_ns: i64, max_interval: i64) i64 {
    const pto_base = rtt.ptoBase() + @max(max_ack_delay_ns, 0);
    var duration = pto_base;
    var i: u32 = 1;
    while (i <= pto_count) : (i += 1) {
        const shift: u6 = @intCast(@min(i, max_backoff_exponent));
        const exponential = pto_base *| (@as(i64, 1) << shift);
        duration = @min(exponential, duration +| max_interval);
    }
    return duration;
}

/// G14: the anti-amplification-deadlock PTO duration (noq mod.rs:3580-3584):
/// a plain pto_base · 2^min(pto_count,16), hard-capped at max_interval (NOT
/// the iterative cap — noq computes this branch without the probe loop).
pub fn ptoDelayAntiDeadlock(rtt: RttEstimator, pto_count: u32, max_interval: i64) i64 {
    const shift: u6 = @intCast(@min(pto_count, max_backoff_exponent));
    return @min(rtt.ptoBase() *| (@as(i64, 1) << shift), max_interval);
}

/// G16: the persistent-congestion verdict is computed inside
/// `detectLostPackets` (noq detect_lost_packets, mod.rs:3262-3358) — the
/// earlier standalone span helper was dead code and has been superseded by
/// the detector's per-packet span walk.

/// Wire CC-gate #7: only feed CC when sent.path_generation matches path generation.
pub fn shouldFeedCc(sent_path_generation: u64, path_generation: u64) bool {
    return sent_path_generation == path_generation;
}

/// PendingAcks: track received PNs for multi-range ACK generation.
pub const PendingAcks = struct {
    pub const max_blocks: usize = 64;
    /// Half-open ranges [start, end), stored largest-first.
    starts: [max_blocks]u64 = undefined,
    ends: [max_blocks]u64 = undefined,
    len: usize = 0,
    largest: ?u64 = null,
    /// When the largest tracked PN was received — the basis of the ACK Delay
    /// field (noq PendingAcks::largest_packet, spaces.rs:1115-1116 +
    /// ack_delay:1170-1172; updated in insert_one:1277-1279).
    largest_recv_time_ns: ?Instant = null,

    pub fn onRecv(self: *PendingAcks, pn: u64) void {
        self.onRecvAt(pn, 0);
    }

    pub fn onRecvAt(self: *PendingAcks, pn: u64, now: Instant) void {
        if (pn > varint.max_value) return;
        if (self.largest == null or pn > self.largest.?) {
            self.largest = pn;
            self.largest_recv_time_ns = now;
        }
        // Duplicate?
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            if (pn >= self.starts[i] and pn < self.ends[i]) return;
        }

        // Keep ranges largest-first as they are inserted. The previous path
        // appended, bubble-sorted, then sorted again while merging: O(n^2) work
        // per new packet at the 64-range cap. One ordered insertion plus a
        // single merge pass is O(n) and preserves the same ACK-range invariant.
        var insert_at: usize = 0;
        while (insert_at < self.len and self.starts[insert_at] > pn) : (insert_at += 1) {}
        const next = pn + 1;
        const joins_higher = insert_at > 0 and next == self.starts[insert_at - 1];
        const joins_lower = insert_at < self.len and pn == self.ends[insert_at];
        if (joins_higher and joins_lower) {
            // Bridge two existing ranges without allocating a 65th slot.
            const higher = insert_at - 1;
            self.starts[higher] = self.starts[insert_at];
            self.removeAt(insert_at);
            return;
        }
        if (joins_higher) {
            self.starts[insert_at - 1] = pn;
            return;
        }
        if (joins_lower) {
            self.ends[insert_at] = next;
            return;
        }
        if (self.len >= max_blocks) {
            // Full and older than every tracked range: it would immediately be
            // the range dropped by the largest-first retention policy.
            if (insert_at == self.len) return;
            // Otherwise drop the current lowest range to make room.
            self.len -= 1;
        }
        i = self.len;
        while (i > insert_at) : (i -= 1) {
            self.starts[i] = self.starts[i - 1];
            self.ends[i] = self.ends[i - 1];
        }
        self.starts[insert_at] = pn;
        self.ends[insert_at] = next;
        self.len += 1;
        self.mergeAdjacent();
    }

    fn removeAt(self: *PendingAcks, index: usize) void {
        var i = index;
        while (i + 1 < self.len) : (i += 1) {
            self.starts[i] = self.starts[i + 1];
            self.ends[i] = self.ends[i + 1];
        }
        self.len -= 1;
    }

    fn mergeAdjacent(self: *PendingAcks) void {
        var i: usize = 0;
        while (i + 1 < self.len) {
            // ranges are largest-first; merge if adjacent/overlapping
            // [s0,e0) and [s1,e1) with s0 >= s1
            if (self.starts[i] <= self.ends[i + 1]) {
                self.starts[i] = @min(self.starts[i], self.starts[i + 1]);
                self.ends[i] = @max(self.ends[i], self.ends[i + 1]);
                // remove i+1
                self.removeAt(i + 1);
            } else {
                i += 1;
            }
        }
    }

    /// Build frame.Ack from ranges (largest-first).
    pub fn toAckFrame(self: *const PendingAcks, ack_delay: u64) ?@import("frame.zig").Ack {
        if (self.len == 0 or self.largest == null) return null;
        const largest = self.largest.?;
        const first = self.ends[0] - self.starts[0]; // size
        var ack = @import("frame.zig").Ack{
            .largest_acked = largest,
            .ack_delay = ack_delay,
            .first_range = first - 1,
        };
        var i: usize = 1;
        while (i < self.len and ack.additional_len < @import("frame.zig").max_ack_additional) : (i += 1) {
            const prev_start = self.starts[i - 1];
            const gap = prev_start - self.ends[i] - 1;
            const range = self.ends[i] - self.starts[i] - 1;
            ack.additional_buf[ack.additional_len] = .{ .gap = gap, .range = range };
            ack.additional_len += 1;
        }
        return ack;
    }
};

/// u128 sliding window dedup (WINDOW_SIZE ≈ 129) — reject already-seen PNs.
pub const Dedup = struct {
    pub const window_size: u64 = 129;
    largest: ?u64 = null,
    bits: u128 = 0,

    /// noq Dedup::smallest_missing_in_interval (spaces.rs:941-991): the
    /// smallest PN in the OPEN interval (lower_bound, upper_bound) that was
    /// never recorded, or null if the interval is fully received. Packets
    /// aged out of the window are considered received, same as noq's clamp
    /// (spaces.rs:957-960).
    pub fn smallestMissingInInterval(self: *const Dedup, lower_bound: u64, upper_bound: u64) ?u64 {
        if (upper_bound <= lower_bound + 1) return null; // empty open interval
        const largest = self.largest orelse return lower_bound + 1;
        var pn = lower_bound + 1;
        while (pn < upper_bound) : (pn += 1) {
            if (pn == largest) continue; // the largest is tracked by definition
            if (pn > largest) return pn; // above the window: never recorded
            const bit = largest - pn;
            if (bit >= 128) continue; // aged out of the window: considered received
            if (self.bits & (@as(u128, 1) << @as(u7, @intCast(bit))) == 0) return pn;
        }
        return null;
    }

    /// noq Dedup::missing_in_interval (spaces.rs:994-997): true when any PN in
    /// the OPEN interval (lower_bound, upper_bound) was never recorded.
    pub fn missingInInterval(self: *const Dedup, lower_bound: u64, upper_bound: u64) bool {
        return self.smallestMissingInInterval(lower_bound, upper_bound) != null;
    }

    pub fn checkAndInsert(self: *Dedup, pn: u64) bool {
        // returns true if NEW (accept), false if duplicate
        if (self.largest) |lg| {
            if (pn <= lg and lg - pn >= window_size) return false; // too old
            if (pn <= lg) {
                const bit: u7 = @intCast(lg - pn);
                if (bit < 128 and (self.bits & (@as(u128, 1) << bit)) != 0) return false;
                if (bit < 128) self.bits |= @as(u128, 1) << bit;
                return true;
            }
            // pn > largest: shift window
            const shift: u64 = pn - lg;
            if (shift >= 128) {
                self.bits = 1; // only pn set at bit 0 after rebase conceptually
            } else {
                self.bits <<= @intCast(shift);
                self.bits |= 1;
            }
            self.largest = pn;
            return true;
        }
        self.largest = pn;
        self.bits = 1;
        return true;
    }
};

test "RTT estimator RFC6298 update" {
    var rtt = RttEstimator.init(100_000_000);
    try std.testing.expectEqual(@as(i64, 100_000_000), rtt.get());
    rtt.update(0, 80_000_000);
    try std.testing.expectEqual(@as(i64, 80_000_000), rtt.get());
    rtt.update(0, 100_000_000);
    try std.testing.expect(rtt.get() > 80_000_000);
    try std.testing.expect(rtt.ptoBase() > rtt.get());
}

test "loss detection packet threshold" {
    const sent = [_]connection.SentPacket{
        .{ .path_generation = 0, .time_sent = 0, .size = 100, .ack_eliciting = true, .packet_number = 1, .space = .data },
        .{ .path_generation = 0, .time_sent = 0, .size = 100, .ack_eliciting = true, .packet_number = 2, .space = .data },
        .{ .path_generation = 0, .time_sent = 0, .size = 100, .ack_eliciting = true, .packet_number = 3, .space = .data },
        .{ .path_generation = 0, .time_sent = 0, .size = 100, .ack_eliciting = true, .packet_number = 10, .space = .data },
    };
    const rtt = RttEstimator.init(50_000_000);
    var out: [8]LossEvent = undefined;
    const res = detectLostPackets(&sent, 1_000_000_000, 10, .data, rtt, 0, null, null, &out);
    try std.testing.expect(res.count >= 3);
}

test "loss detection time threshold" {
    const rtt = RttEstimator.init(100_000_000); // 100ms
    const loss_delay = @max(@divTrunc(rtt.conservative() * time_threshold_num, time_threshold_den), timer_granularity_ns);
    const sent = [_]connection.SentPacket{
        .{ .path_generation = 0, .time_sent = 0, .size = 100, .ack_eliciting = true, .packet_number = 1, .space = .data },
    };
    var out: [4]LossEvent = undefined;
    // Not lost yet
    try std.testing.expectEqual(@as(usize, 0), detectLostPackets(&sent, loss_delay - 1, 1, .data, rtt, 0, null, null, &out).count);
    // Lost by time (largest_acked=1, packet_threshold not met for by_packet alone when gap < 3)
    // by_packet: largest_acked >= pn+3 → 1 >= 4? false. by_time: true
    try std.testing.expectEqual(@as(usize, 1), detectLostPackets(&sent, loss_delay, 1, .data, rtt, 0, null, null, &out).count);
}

test "PTO exponential backoff" {
    const rtt = RttEstimator.init(50_000_000);
    const d0 = ptoDelay(rtt, 0, 0, max_pto_interval_ns);
    const d1 = ptoDelay(rtt, 1, 0, max_pto_interval_ns);
    const d2 = ptoDelay(rtt, 2, 0, max_pto_interval_ns);
    // max_ack_delay is added before the 2^pto_count expansion.
    const with_mad = ptoDelay(rtt, 0, 25_000_000, max_pto_interval_ns);
    try std.testing.expectEqual(d0 + 25_000_000, with_mad);
    const with_mad_backoff = ptoDelay(rtt, 1, 25_000_000, max_pto_interval_ns);
    try std.testing.expectEqual(with_mad * 2, with_mad_backoff);
    try std.testing.expectEqual(d0 * 2, d1);
    try std.testing.expectEqual(d0 * 4, d2);
}

test "G14 PTO backoff is capped at max_interval per probe step" {
    const rtt = RttEstimator.init(50_000_000);
    const base = rtt.ptoBase(); // 150ms
    // Far into backoff the naive exponential would dwarf the cap.
    const d10 = ptoDelay(rtt, 10, 0, max_pto_interval_ns);
    try std.testing.expect(d10 < base * (@as(i64, 1) << 10));
    // noq's iterative cap (mod.rs:3614-3621): each step is
    // min(base·2^i, prev_step + max_interval) — pinned exactly.
    try std.testing.expectEqual(@as(i64, 14_400_000_000), d10);
    // The cap binds exactly from the step where base·2^i overtakes
    // prev + max_interval (here step 5).
    try std.testing.expectEqual(ptoDelay(rtt, 4, 0, max_pto_interval_ns) + max_pto_interval_ns, ptoDelay(rtt, 5, 0, max_pto_interval_ns));
    // Successive probes are never more than max_interval apart.
    var i: u32 = 5;
    while (i < 12) : (i += 1) {
        try std.testing.expect(ptoDelay(rtt, i + 1, 0, max_pto_interval_ns) <= ptoDelay(rtt, i, 0, max_pto_interval_ns) + max_pto_interval_ns);
    }
}

test "G14 ptoMaxInterval mirrors noq's slow-link / short-idle selection" {
    const fast = RttEstimator.init(50_000_000);
    // Normal link, long/absent idle timeout → 2s cap.
    try std.testing.expectEqual(max_pto_interval_ns, ptoMaxInterval(fast, null));
    try std.testing.expectEqual(max_pto_interval_ns, ptoMaxInterval(fast, 30_000_000_000));
    // Short idle timeout → 1s cap.
    try std.testing.expectEqual(max_pto_fast_interval_ns, ptoMaxInterval(fast, 25_000_000_000));
    // Slow link (RTT > 4/3 s) → 1.5·RTT.
    const slow = RttEstimator.init(2_000_000_000);
    try std.testing.expectEqual(@as(i64, 3_000_000_000), ptoMaxInterval(slow, null));
}

test "G14 anti-deadlock PTO is a hard-capped plain exponential" {
    const rtt = RttEstimator.init(50_000_000);
    const base = rtt.ptoBase();
    try std.testing.expectEqual(base * 4, ptoDelayAntiDeadlock(rtt, 2, max_pto_interval_ns));
    try std.testing.expectEqual(max_pto_interval_ns, ptoDelayAntiDeadlock(rtt, 10, max_pto_interval_ns));
}

fn sentPn(pn: u64, time_sent: Instant) connection.SentPacket {
    return .{ .path_generation = 0, .time_sent = time_sent, .size = 1200, .ack_eliciting = true, .packet_number = pn, .space = .data };
}

test "G16 persistent congestion: a lost span over 3·PTO collapses, acks break it" {
    const rtt = RttEstimator.init(100_000_000); // ptoBase = 300ms → period = 900ms
    const first: FirstAfterRttSample = .{ .space = .data, .pn = 0 };
    var out: [16]LossEvent = undefined;
    // Packets 0..=8 sent 300ms apart (span 2.4s), all old enough to be lost
    // by time; largest_acked = 8. The unbroken lost span exceeds 900ms.
    var sent: [9]connection.SentPacket = undefined;
    for (&sent, 0..) |*sp, i| sp.* = sentPn(@intCast(i), @as(i64, @intCast(i)) * 300_000_000);
    const now: i64 = 2_600_000_000;
    const res = detectLostPackets(&sent, now, 8, .data, rtt, 0, first, null, &out);
    try std.testing.expect(res.count >= 1);
    try std.testing.expect(res.in_persistent_congestion);
    // Same traffic with an acknowledged hole (pn 4 absent) breaks the span:
    // each side then spans ≤ 900ms → no verdict (noq mod.rs:3304-3307).
    var sent2: [8]connection.SentPacket = undefined;
    var w: usize = 0;
    for (sent) |sp| {
        if (sp.packet_number == 4) continue;
        sent2[w] = sp;
        w += 1;
    }
    const res2 = detectLostPackets(&sent2, now, 8, .data, rtt, 0, first, null, &out);
    try std.testing.expect(!res2.in_persistent_congestion);
    // Without a first RTT sample the span can never open (noq mod.rs:3328-3334).
    const res3 = detectLostPackets(&sent, now, 8, .data, rtt, 0, null, null, &out);
    try std.testing.expect(!res3.in_persistent_congestion);
}

test "path_generation CC-gate #7" {
    try std.testing.expect(shouldFeedCc(3, 3));
    try std.testing.expect(!shouldFeedCc(2, 3));
}

test "PendingAcks multi-range" {
    var pa: PendingAcks = .{};
    pa.onRecv(1);
    pa.onRecv(2);
    pa.onRecv(5);
    pa.onRecv(6);
    pa.onRecv(7);
    try std.testing.expect(pa.len >= 2);
    const ack = pa.toAckFrame(0).?;
    try std.testing.expectEqual(@as(u64, 7), ack.largest_acked);
}

test "PendingAcks ordered insertion merges out-of-order packet numbers" {
    var pa: PendingAcks = .{};
    for ([_]u64{ 5, 1, 3, 2, 4 }) |pn| pa.onRecv(pn);
    try std.testing.expectEqual(@as(usize, 1), pa.len);
    try std.testing.expectEqual(@as(u64, 1), pa.starts[0]);
    try std.testing.expectEqual(@as(u64, 6), pa.ends[0]);
    const ack = pa.toAckFrame(0).?;
    try std.testing.expectEqual(@as(u64, 5), ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 4), ack.first_range);
}

test "PendingAcks full range set retains the largest packet numbers" {
    var pa: PendingAcks = .{};
    var pn: u64 = 0;
    while (pn < PendingAcks.max_blocks * 2) : (pn += 2) pa.onRecv(pn);
    try std.testing.expectEqual(PendingAcks.max_blocks, pa.len);
    pa.onRecv(10_000);
    try std.testing.expectEqual(PendingAcks.max_blocks, pa.len);
    try std.testing.expectEqual(@as(u64, 10_000), pa.starts[0]);
    pa.onRecv(1);
    try std.testing.expectEqual(PendingAcks.max_blocks, pa.len);
    try std.testing.expectEqual(@as(u64, 10_000), pa.starts[0]);
}

test "PendingAcks full range set bridges without evicting either neighbor" {
    var pa: PendingAcks = .{};
    var pn: u64 = 0;
    while (pn < PendingAcks.max_blocks * 2) : (pn += 2) pa.onRecv(pn);
    pa.onRecv(1);
    try std.testing.expectEqual(PendingAcks.max_blocks - 1, pa.len);
    try std.testing.expectEqual(@as(u64, 0), pa.starts[pa.len - 1]);
    try std.testing.expectEqual(@as(u64, 3), pa.ends[pa.len - 1]);

    var top: PendingAcks = .{};
    pn = 0;
    while (pn < PendingAcks.max_blocks * 2) : (pn += 2) top.onRecv(pn);
    top.onRecv(125);
    const ack = top.toAckFrame(0).?;
    try std.testing.expect(ackContainsForTest(ack, 124));
    try std.testing.expect(ackContainsForTest(ack, 125));
    try std.testing.expect(ackContainsForTest(ack, 126));
}

test "PendingAcks full range set extends high and low without eviction" {
    var high: PendingAcks = .{};
    var pn: u64 = 0;
    while (pn < PendingAcks.max_blocks * 3) : (pn += 3) high.onRecv(pn);
    high.onRecv(1);
    try std.testing.expectEqual(PendingAcks.max_blocks, high.len);
    try std.testing.expectEqual(@as(u64, 0), high.starts[high.len - 1]);
    try std.testing.expectEqual(@as(u64, 2), high.ends[high.len - 1]);

    var low: PendingAcks = .{};
    pn = 2;
    while (pn < 2 + PendingAcks.max_blocks * 3) : (pn += 3) low.onRecv(pn);
    low.onRecv(1);
    try std.testing.expectEqual(PendingAcks.max_blocks, low.len);
    try std.testing.expectEqual(@as(u64, 1), low.starts[low.len - 1]);
    try std.testing.expectEqual(@as(u64, 3), low.ends[low.len - 1]);
}

test "PendingAcks ignores packet numbers above the QUIC limit" {
    var pa: PendingAcks = .{};
    pa.onRecv(varint.max_value);
    try std.testing.expectEqual(@as(usize, 1), pa.len);
    try std.testing.expectEqual(varint.max_value + 1, pa.ends[0]);
    pa.onRecv(varint.max_value + 1);
    try std.testing.expectEqual(@as(usize, 1), pa.len);
    try std.testing.expectEqual(varint.max_value, pa.largest.?);
    const ack = pa.toAckFrame(0).?;
    try std.testing.expectEqual(varint.max_value, ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 0), ack.first_range);
}

fn ackContainsForTest(a: @import("frame.zig").Ack, pn: u64) bool {
    var high = a.largest_acked;
    var low = high - a.first_range;
    if (pn >= low and pn <= high) return true;
    for (a.additional()) |range| {
        if (low < range.gap + 2) return false;
        high = low - range.gap - 2;
        if (high < range.range) return false;
        low = high - range.range;
        if (pn >= low and pn <= high) return true;
    }
    return false;
}

test "Dedup rejects duplicates" {
    var d: Dedup = .{};
    try std.testing.expect(d.checkAndInsert(5));
    try std.testing.expect(!d.checkAndInsert(5));
    try std.testing.expect(d.checkAndInsert(6));
}

test "G11 Dedup missingInInterval mirrors noq missing_in_interval" {
    var d: Dedup = .{};
    // Received 0..=9 except holes at 4 and 7, then 100.
    var pn: u64 = 0;
    while (pn < 10) : (pn += 1) {
        if (pn == 4 or pn == 7) continue;
        _ = d.checkAndInsert(pn);
    }
    _ = d.checkAndInsert(100);
    // The open interval of consecutive packets is empty → nothing missing.
    try std.testing.expect(!d.missingInInterval(8, 9));
    // Holes inside the open interval are detected.
    try std.testing.expect(d.missingInInterval(6, 9)); // 7
    try std.testing.expect(d.missingInInterval(3, 6)); // 4
    // Fully-received interval.
    try std.testing.expect(!d.missingInInterval(0, 3));
    // The never-received 10..99 are in-window → missing.
    try std.testing.expect(d.missingInInterval(9, 100));
    // Aged-out packets (bit ≥ 128) are considered received (noq clamp,
    // spaces.rs:957-960).
    _ = d.checkAndInsert(300);
    try std.testing.expect(!d.missingInInterval(150, 170));
    // …while an in-window hole is still detected after the shift.
    try std.testing.expect(d.missingInInterval(250, 290));
}

test "G4 Dedup smallestMissingInInterval mirrors noq smallest_missing_in_interval" {
    var d: Dedup = .{};
    // Received 0..=9 except holes at 4 and 7, then 100.
    var pn: u64 = 0;
    while (pn < 10) : (pn += 1) {
        if (pn == 4 or pn == 7) continue;
        _ = d.checkAndInsert(pn);
    }
    _ = d.checkAndInsert(100);
    // Empty open interval → null.
    try std.testing.expect(d.smallestMissingInInterval(8, 9) == null);
    // The SMALLEST missing PN is returned, not just presence.
    try std.testing.expectEqual(@as(?u64, 7), d.smallestMissingInInterval(6, 9));
    try std.testing.expectEqual(@as(?u64, 4), d.smallestMissingInInterval(3, 9));
    try std.testing.expect(d.smallestMissingInInterval(0, 3) == null);
    // Never-received in-window run: the first of it.
    try std.testing.expectEqual(@as(?u64, 10), d.smallestMissingInInterval(9, 100));
    // Aged-out packets are considered received (noq clamp, spaces.rs:957-960).
    _ = d.checkAndInsert(300);
    try std.testing.expect(d.smallestMissingInInterval(150, 170) == null);
}

test "Dedup old-packet check does not overflow near max pn" {
    var d: Dedup = .{};
    const max = std.math.maxInt(u64);
    try std.testing.expect(d.checkAndInsert(max));
    try std.testing.expect(!d.checkAndInsert(max - Dedup.window_size));
}
