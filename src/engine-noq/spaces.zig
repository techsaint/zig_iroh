//! Packet-number spaces for the noq Zig surface.
//!
//! Scope fence: SpaceId × per-space PN allocate/reconstruct only — enough for the
//! packet-layer wire oracle. PendingAcks / loss / canSend stay with later slices
//! (later work).

const std = @import("std");
const packet = @import("packet.zig");

pub const SpaceId = enum(u2) {
    initial = 0,
    handshake = 1,
    data = 2,

    pub fn encryptionLevel(self: SpaceId) EncryptionLevel {
        return switch (self) {
            .initial => .initial,
            .handshake => .handshake,
            .data => .one_rtt,
        };
    }
};

pub const EncryptionLevel = enum {
    initial,
    handshake,
    zero_rtt,
    one_rtt,
};

/// Optimistic-ACK defense (RFC 9000 §21.4 "Optimistic ACK Attack"; noq
/// `PacketNumberFilter`, connection/spaces.rs:1329-1373). Used in the Data
/// space only: one randomly chosen outgoing packet number per exponentially
/// growing window is never sent; an ACK covering it proves the peer is ACKing
/// packets it never received → PROTOCOL_VIOLATION ("unsent packet acked").
pub const PacketNumberFilter = struct {
    /// Next outgoing packet number to skip.
    next_skipped: u64,
    /// Most recently skipped packet number (the one `checkAck` guards).
    prev_skipped: ?u64 = null,
    /// Next skip is drawn from 2^exponent..2^(exponent+1); starts at 6 (0..64).
    exponent: u6 = 6,

    pub fn new(rng: std.Random) PacketNumberFilter {
        return .{ .next_skipped = rng.uintLessThan(u64, 64) };
    }

    /// noq `skip_pn`: whether to skip `n` (true) and schedule the next skip.
    pub fn skipPn(self: *PacketNumberFilter, n: u64, rng: std.Random) bool {
        if (n != self.next_skipped) return false;
        self.prev_skipped = self.next_skipped;
        const lo = @as(u64, 1) << self.exponent;
        const next_exp = self.exponent +| 1;
        const hi = if (next_exp >= 63) std.math.maxInt(u64) else @as(u64, 1) << next_exp;
        self.next_skipped = if (hi > lo)
            lo + rng.uintLessThan(u64, hi - lo)
        else
            std.math.maxInt(u64);
        self.exponent = next_exp;
        return true;
    }
};

/// Per-space packet-number state (u64 counter + largest received for reconstruction).
pub const PacketNumberSpace = struct {
    next_pn: u64 = 0,
    largest_acked: ?u64 = null,
    largest_received: ?u64 = null,
    /// Data space only (noq spaces.rs:306-309); `null` for Initial/Handshake.
    pn_filter: ?PacketNumberFilter = null,

    pub fn getTxNumber(self: *PacketNumberSpace) u64 {
        const pn = self.next_pn;
        self.next_pn += 1;
        return pn;
    }

    /// Truncate `full_pn` for the wire given the peer's largest acked (or 0).
    pub fn truncateForSend(self: *const PacketNumberSpace, full_pn: u64) packet.PacketNumber {
        const largest = self.largest_acked orelse 0;
        return packet.PacketNumber.truncate(full_pn, largest);
    }

    pub fn reconstruct(self: *PacketNumberSpace, truncated: packet.PacketNumber) u64 {
        const expected = (self.largest_received orelse 0) +% 1;
        const full = packet.PacketNumber.expand(truncated, expected);
        if (self.largest_received == null or full > self.largest_received.?) {
            self.largest_received = full;
        }
        return full;
    }

    pub fn onAck(self: *PacketNumberSpace, pn: u64) void {
        if (self.largest_acked == null or pn > self.largest_acked.?) {
            self.largest_acked = pn;
        }
    }
};

/// The three QUIC packet spaces (Initial / Handshake / Data).
pub const Spaces = struct {
    spaces: [3]PacketNumberSpace = .{ .{}, .{}, .{} },

    pub fn get(self: *Spaces, id: SpaceId) *PacketNumberSpace {
        return &self.spaces[@intFromEnum(id)];
    }

    pub fn getConst(self: *const Spaces, id: SpaceId) *const PacketNumberSpace {
        return &self.spaces[@intFromEnum(id)];
    }
};

test "PN truncate/expand round-trips near largest acked" {
    var space: PacketNumberSpace = .{ .largest_acked = 0x100 };
    const full: u64 = 0x105;
    const truncated = space.truncateForSend(full);
    try std.testing.expect(truncated.len >= 1 and truncated.len <= 4);
    var recv: PacketNumberSpace = .{ .largest_received = 0x100 };
    try std.testing.expectEqual(full, recv.reconstruct(truncated));
}

test "spaces allocate monotonic tx numbers per space" {
    var spaces: Spaces = .{};
    try std.testing.expectEqual(@as(u64, 0), spaces.get(.data).getTxNumber());
    try std.testing.expectEqual(@as(u64, 1), spaces.get(.data).getTxNumber());
    try std.testing.expectEqual(@as(u64, 0), spaces.get(.initial).getTxNumber());
}

test "A17 PacketNumberFilter: skips the scheduled PN, then an exponential window" {
    var prng = std.Random.DefaultPrng.init(0xA17);
    const rng = prng.random();
    var f = PacketNumberFilter.new(rng);
    // First skipped PN is in 0..64 (noq: exponent starts at 6).
    try std.testing.expect(f.next_skipped < 64);
    // PNs other than the scheduled one are used.
    try std.testing.expect(!f.skipPn(f.next_skipped + 1000, rng));
    try std.testing.expect(f.prev_skipped == null);
    // The scheduled PN is skipped; the next one lands in [64, 128).
    const skipped = f.next_skipped;
    try std.testing.expect(f.skipPn(skipped, rng));
    try std.testing.expectEqual(skipped, f.prev_skipped.?);
    try std.testing.expect(f.next_skipped >= 64 and f.next_skipped < 128);
}
