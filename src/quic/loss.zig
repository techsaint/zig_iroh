//! Loss detection, PTO, and RTT estimation (RFC 9002) — N3b-4.
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

/// Detect packets lost by packet threshold and/or time threshold (RFC 9002 §6.1).
pub fn detectLostPackets(
    sent: []const connection.SentPacket,
    now: Instant,
    largest_acked: u64,
    space: spaces.SpaceId,
    rtt: RttEstimator,
    out: []LossEvent,
) usize {
    const loss_delay = @max(@divTrunc(rtt.conservative() * time_threshold_num, time_threshold_den), timer_granularity_ns);
    var n: usize = 0;
    for (sent) |sp| {
        if (sp.space != space) continue;
        if (sp.packet_number > largest_acked) continue;
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
        }
    }
    return n;
}

/// PTO duration (RFC 9002 §6.2.1): (pto_base + max_ack_delay) · 2^pto_count.
/// `max_ack_delay` is nanoseconds and MUST be 0 for Initial/Handshake spaces;
/// for Application Data it is the peer's max_ack_delay (transport param / ACK_FREQUENCY).
pub fn ptoDelay(rtt: RttEstimator, pto_count: u32, max_ack_delay_ns: i64) i64 {
    var delay = rtt.ptoBase() + @max(max_ack_delay_ns, 0);
    var i: u32 = 0;
    while (i < pto_count) : (i += 1) {
        delay *%= 2;
    }
    return delay;
}

/// Persistent congestion if the lost period spans ≥ threshold * (srtt + max_ack_delay).
pub fn isPersistentCongestion(
    first_lost_sent: Instant,
    last_lost_sent: Instant,
    rtt: RttEstimator,
    max_ack_delay: i64,
) bool {
    const duration = last_lost_sent - first_lost_sent;
    const thresh = persistent_congestion_threshold * (rtt.get() + max_ack_delay);
    return duration >= thresh;
}

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

    pub fn onRecv(self: *PendingAcks, pn: u64) void {
        if (pn > varint.max_value) return;
        if (self.largest == null or pn > self.largest.?) self.largest = pn;
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
    const n = detectLostPackets(&sent, 1_000_000_000, 10, .data, rtt, &out);
    try std.testing.expect(n >= 3);
}

test "loss detection time threshold" {
    const rtt = RttEstimator.init(100_000_000); // 100ms
    const loss_delay = @max(@divTrunc(rtt.conservative() * time_threshold_num, time_threshold_den), timer_granularity_ns);
    const sent = [_]connection.SentPacket{
        .{ .path_generation = 0, .time_sent = 0, .size = 100, .ack_eliciting = true, .packet_number = 1, .space = .data },
    };
    var out: [4]LossEvent = undefined;
    // Not lost yet
    try std.testing.expectEqual(@as(usize, 0), detectLostPackets(&sent, loss_delay - 1, 1, .data, rtt, &out));
    // Lost by time (largest_acked=1, packet_threshold not met for by_packet alone when gap < 3)
    // by_packet: largest_acked >= pn+3 → 1 >= 4? false. by_time: true
    try std.testing.expectEqual(@as(usize, 1), detectLostPackets(&sent, loss_delay, 1, .data, rtt, &out));
}

test "PTO exponential backoff" {
    const rtt = RttEstimator.init(50_000_000);
    const d0 = ptoDelay(rtt, 0, 0);
    const d1 = ptoDelay(rtt, 1, 0);
    const d2 = ptoDelay(rtt, 2, 0);
    // audit-v4 H2: max_ack_delay is added before the 2^pto_count expansion.
    const with_mad = ptoDelay(rtt, 0, 25_000_000);
    try std.testing.expectEqual(d0 + 25_000_000, with_mad);
    const with_mad_backoff = ptoDelay(rtt, 1, 25_000_000);
    try std.testing.expectEqual(with_mad * 2, with_mad_backoff);
    try std.testing.expectEqual(d0 * 2, d1);
    try std.testing.expectEqual(d0 * 4, d2);
}

test "persistent congestion threshold" {
    const rtt = RttEstimator.init(100_000_000);
    try std.testing.expect(isPersistentCongestion(0, 400_000_000, rtt, 0));
    try std.testing.expect(!isPersistentCongestion(0, 100_000_000, rtt, 0));
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

test "Dedup old-packet check does not overflow near max pn" {
    var d: Dedup = .{};
    const max = std.math.maxInt(u64);
    try std.testing.expect(d.checkAndInsert(max));
    try std.testing.expect(!d.checkAndInsert(max - Dedup.window_size));
}
