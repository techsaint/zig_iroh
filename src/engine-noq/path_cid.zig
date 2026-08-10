//! Path challenge / CID slot / n0 NAT address types (N1 reorientation).
//! Extracted from connection.zig — no Connection poll/tx logic lives here.

const packet = @import("packet.zig");

pub const max_path_tokens: usize = 8;
/// noq parity: `CidQueue::LEN` is 5 — the engine holds (and therefore
/// advertises) that many local CIDs (E13).
pub const max_local_cid_slots: usize = 5;

pub const NatKind = enum { observed, add, reach_out, remove };

/// A decoded n0 NAT-traversal address frame, surfaced to the transport's
/// magicsock layer (RFC-less n0 custom frames; decoded in `frame.zig`).
pub const NatAddress = struct {
    kind: NatKind,
    seq: u64 = 0,
    ip: [4]u8 = .{ 0, 0, 0, 0 },
    /// H7: set for the IPv6 frame variants (ip is then meaningless).
    ip6: ?[16]u8 = null,
    port: u16 = 0,
};

pub const LocalCidSlot = struct {
    sequence: u64 = 0,
    cid: packet.ConnectionId = .{},
    reset_token: [packet.stateless_reset_token_len]u8 = .{0} ** packet.stateless_reset_token_len,
    retired: bool = false,
};

pub const RemoteCidSlot = struct {
    sequence: u64 = 0,
    cid: packet.ConnectionId = .{},
    reset_token: [packet.stateless_reset_token_len]u8 = .{0} ** packet.stateless_reset_token_len,
    retired: bool = false,
};
