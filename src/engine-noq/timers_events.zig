//! Connection timers + event surface (N1 reorientation).
//! Extracted from connection.zig. Event.stream_data borrows StreamRecv buffer
//! slices — see N8 / characterization tests: do not hold across prune/ingest.

const stream_state = @import("stream_state.zig");
const path_cid = @import("path_cid.zig");

pub const Instant = i64; // nanoseconds, injected by the pump

pub const CloseInfo = struct {
    is_local: bool = false,
    reason: []const u8 = "closed",
};

pub const State = union(enum) {
    handshake,
    established,
    closed: CloseInfo,
    draining: CloseInfo,
    drained: CloseInfo,
};

pub const Event = union(enum) {
    handshake_data,
    connected,
    /// Peer opened a new stream (first data arrived on an id we had not seen).
    stream_opened: struct { id: u64, dir: stream_state.StreamDir },
    /// BORROW: `data` points into the stream receive buffer and is invalidated
    /// by `StreamRecv.pruneConsumed` / further ingest compaction. The shipping
    /// transport ignores this payload and re-reads via `readStreamInto`.
    stream_data: struct { id: u64, data: []const u8, fin: bool },
    stream_reset: struct { id: u64, code: u64 },
    stop_sending: struct { id: u64, code: u64 },
    /// A PATH_CHALLENGE we sent was echoed back (path validated, RFC 9000 §8.2).
    path_validated: [8]u8,
    /// An n0 NAT-traversal address frame surfaced for magicsock (5e).
    nat_address: path_cid.NatAddress,
    connection_lost: CloseInfo,
};

/// Conn-wide timer table shape (#9). Full PTO/loss arming is handled separately; close and
/// both independent key-discard lifecycles use connection-wide `3 × max_pto`.
pub const TimerTable = struct {
    /// Connection-wide absolute deadlines, if armed.
    close_deadline: ?Instant = null,
    handshake_key_discard_deadline: ?Instant = null,
    previous_key_discard_deadline: ?Instant = null,
    /// PATH_CHALLENGE retransmission (RFC 9000 §8.2.4 PTO backoff).
    path_challenge_deadline: ?Instant = null,
    path_challenge_attempts: u8 = 0,
    /// G19: cached max PTO across paths, REFRESHED from the live RTT estimator
    /// on every RTT sample (`Connection.refreshTimerPtoBase`, noq
    /// `max_pto_for_space(highest_space)`, mod.rs:3711-3727 — pto_base +
    /// data-space max_ack_delay once 1-RTT keys exist). Backs the close/drain
    /// and previous-key-discard deadlines. The 1s default equals noq's
    /// initial-RTT-derived PTO (333ms initial RTT, config/transport.rs:564).
    /// Tests may still poke this field directly for determinism.
    max_pto_ns: i64 = 1_000_000_000, // 1s default until RTT samples exist
    /// G19: same refresh but WITHOUT the max_ack_delay term — backs the
    /// handshake-key-discard deadline (noq set_key_discard_timer with the
    /// Handshake space, mod.rs:3175-3194 + 3808, whose pto() adds no
    /// max_ack_delay, mod.rs:3733-3743).
    max_pto_handshake_ns: i64 = 1_000_000_000,

    pub fn armClose(self: *TimerTable, now: Instant) void {
        self.close_deadline = now + 3 * self.max_pto_ns;
    }

    pub fn armHandshakeKeyDiscard(self: *TimerTable, now: Instant) void {
        self.handshake_key_discard_deadline = now + 3 * self.max_pto_handshake_ns;
    }

    pub fn armPreviousKeyDiscard(self: *TimerTable, now: Instant) void {
        self.previous_key_discard_deadline = now + 3 * self.max_pto_ns;
    }
};
