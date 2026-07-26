//! Packet-number spaces for the noq Zig surface (N3b-2).
//!
//! Scope fence: SpaceId × per-space PN allocate/reconstruct only — enough for the
//! packet-layer wire oracle. PendingAcks / loss / canSend stay with later slices
//! (glm52 N3b-3/N3b-4).

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

/// Per-space packet-number state (u64 counter + largest received for reconstruction).
pub const PacketNumberSpace = struct {
    next_pn: u64 = 0,
    largest_acked: ?u64 = null,
    largest_received: ?u64 = null,

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
