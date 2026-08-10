//! Sans-io QUIC connection driver.
//!
//! Greenfield idiomatic Zig — not a line-for-line port of noq's 7797-L `mod.rs`.
//! Scope: complete a 1-RTT handshake over loopback (CRYPTO + ACK +
//! HandshakeDone + one STREAM), carrying `path_generation` on every SentPacket
//! (#7) and establishing the timer-table shape (#9).
//!
//! Full loss/ACK bookkeeping / CC are handled separately.
//!
//! N1 reorientation (module-reorientation / reorient-noq): stream half-state,
//! path/CID/NAT types, and timers+events live in sibling modules
//! (`stream_state.zig`, `path_cid.zig`, `timers_events.zig`). This file is the
//! orchestrator + public re-export surface. `tx_build` stays here (integration
//! point — not a peer module).

const std = @import("std");
const crypto = @import("crypto.zig");
// S6: Session is the selected backend's uniform surface; A5 keeps the historical
// Connection method names (popZigtlsNewSessionTicket / wasZigtlsResumed).
const crypto_zigtls = if (crypto.zigtls_enabled) @import("crypto_zigtls.zig") else struct {};
const endpoint = @import("endpoint.zig");
const frame = @import("frame.zig");
const initial_keys = @import("initial_keys.zig");
const quic_token = @import("token.zig");
const key = @import("shared").key;
const tls_name = @import("shared").tls_name;
const packet = @import("packet.zig");
const packet_builder = @import("packet_builder.zig");
const packet_crypto = @import("packet_crypto.zig");
const spaces = @import("spaces.zig");
const varint = @import("varint.zig");
const coding = @import("coding.zig");
const congestion = @import("congestion.zig");
const loss = @import("loss.zig");
const transport_parameters = @import("transport_parameters.zig");
const cubic_cc = @import("congestion/cubic.zig");
const new_reno_cc = @import("congestion/new_reno.zig");

const stream_state = @import("stream_state.zig");
const path_cid = @import("path_cid.zig");
const timers_events = @import("timers_events.zig");
/// Socket-ABI types only (the ECN codepoint enum). The driver stays sans-io:
/// it never calls into the socket layer, it just names the codepoint it wants.
const udp_cmsg = @import("shared").udp_cmsg;

pub const Error = error{
    NoSpaceLeft,
    EmptyPacket,
    FrameEncodeFailed,
    NotHandshake,
    AlreadyClosed,
    MissingKeys,
    DecryptFailed,
    UnexpectedState,
    StreamTooLarge,
    StreamLimit,
    OutOfCryptoOrder,
    UnexpectedEnd,
    TruncatedVarInt,
    TrailingFrameBytes,
    InvalidFrameType,
    TooManyAckRanges,
    UnsupportedFrameType,
    AntiAmplificationLimit,
    DatagramTooLarge,
    DatagramUnavailable,
    KeyUpdateOrderViolation,
    ReservedBitsSet,
    KeyBudgetExhausted,
} || crypto.Error || packet.Error || packet_crypto.Error || packet_builder.Error || std.mem.Allocator.Error;

// ── Re-exports (public API stable; types live in extracted modules) ─────────
pub const Instant = timers_events.Instant;
pub const State = timers_events.State;
pub const CloseInfo = timers_events.CloseInfo;
pub const Event = timers_events.Event;
pub const TimerTable = timers_events.TimerTable;

pub const NatKind = path_cid.NatKind;
pub const NatAddress = path_cid.NatAddress;
pub const LocalCidSlot = path_cid.LocalCidSlot;
pub const RemoteCidSlot = path_cid.RemoteCidSlot;
pub const max_path_tokens = path_cid.max_path_tokens;
pub const max_local_cid_slots = path_cid.max_local_cid_slots;

pub const StreamDir = stream_state.StreamDir;
pub const Chunk = stream_state.Chunk;
pub const StreamSend = stream_state.StreamSend;
pub const StreamRecv = stream_state.StreamRecv;
pub const StreamEntry = stream_state.StreamEntry;
pub const max_streams = stream_state.max_streams;
pub const max_stream_data = stream_state.max_stream_data;
pub const max_recv_pending_bytes = stream_state.max_recv_pending_bytes;
pub const max_recv_pending_segments = stream_state.max_recv_pending_segments;
const streamIsUni = stream_state.streamIsUni;
const streamInitiator = stream_state.streamInitiator;

/// Retransmittable content of a sent packet — enough to rebuild it after
/// `loss.detectLostPackets` flags the packet lost (F2: real retransmit).
pub const FrameRef = union(enum) {
    crypto: struct { space: spaces.SpaceId, offset: u64, len: u64 },
    stream: struct { id: u64, offset: u64, len: u64, fin: bool },
    reset_stream: struct { id: u64 },
    stop_sending: struct { id: u64 },
};

pub const max_content: usize = 8;

/// One buffered out-of-order CRYPTO range (A9, noq's crypto_stream assembler).
/// `data` is owned by the connection allocator; segments in a space's pending
/// list are non-overlapping and their aggregate is bounded by `max_crypto_buf`
/// (enforced in `ingestCrypto` before insert).
pub const CryptoSegment = struct {
    offset: u64,
    data: []u8,
};

/// Destination is implied by the pair harness for the single-path pair harness.
///
/// The driver is sans-io: it decides *what* to put on the wire, including the
/// per-datagram metadata a UDP socket needs, and the transport translates that
/// into syscalls. `ecn` and `segment_size` are that metadata.
pub const Transmit = struct {
    bytes: []u8,
    /// ECN codepoint to stamp on the IP header, or `null` for Not-ECT. The
    /// driver marks ECT(0) while ECN validation is live and clears it the
    /// moment the path is judged to bleach or mangle the bits (RFC 9000 §13.4.2).
    ecn: ?udp_cmsg.EcnCodepoint = null,
    /// When set, `bytes` is a run of `segment_size`-byte datagrams (the last
    /// may be shorter) to hand the kernel in one GSO `sendmsg`. `null` means a
    /// single datagram.
    segment_size: ?u16 = null,
    /// Opaque destination hint copied from a `challengePathTo` probe — the
    /// transport maps it to the migration-candidate address. `null` = the
    /// conn's current path.
    dest_hint: ?u64 = null,
    /// When set, the source address this send must leave from
    /// (`IP_PKTINFO`/`IPV6_PKTINFO`, `Transmit.src_ip`). A wildcard/multi-homed
    /// endpoint otherwise lets the kernel choose the source. `null` = kernel
    /// picks (single-homed endpoints never set this).
    src_ip: ?std.Io.net.IpAddress = null,
};

/// G15: a packet declared lost, kept for spurious-loss detection (noq
/// `LostPacket`, spaces.rs — time_sent only; the frames are already requeued).
pub const LostPacket = struct {
    packet_number: u64,
    time_sent: Instant,
};

/// Load-bearing sent-packet record (#7 path_generation carried now for congestion-control validation).
pub const SentPacket = struct {
    path_generation: u64,
    time_sent: Instant,
    size: u16,
    ack_eliciting: bool,
    app_limited: bool = false,
    packet_number: u64,
    space: spaces.SpaceId,
    loss_reported: bool = false,
    /// Sent as a 0-RTT long-header packet (client). A server 0-RTT rejection
    /// re-offers every such packet's frames under 1-RTT (noq
    /// `retransmit_all_for_0rtt`, mod.rs:4682-4710).
    zero_rtt: bool = false,
    /// This packet went out with an ECT codepoint on the IP header. Needed to
    /// tell "the peer echoed nothing because we marked nothing" apart from
    /// "the peer echoed nothing because the path bleached our marks".
    ecn_marked: bool = false,
    /// Retransmittable frames this packet carried (crypto + stream). Control
    /// frames are regenerated from state, so they are not tracked here.
    content: [max_content]FrameRef = undefined,
    content_len: u8 = 0,
};

/// ECN validation state (RFC 9000 §13.4.2). `disabled` is terminal: once a path
/// is caught bleaching or mangling the codepoint we never re-enable, because a
/// path that mangles ECN once will do it again and a false CE costs throughput.
pub const EcnState = enum { testing, capable, disabled };

// ── DPLPMTUD (RFC 8899) ─────────────────────────────────────────────────────

/// The UDP payload size every QUIC path is required to support (RFC 9000 §14).
/// PMTUD never probes below this and a black hole falls back exactly to it.
pub const min_mtu: u16 = 1200;
/// Stop the binary search once the remaining interval is smaller than this —
/// further probes cost more than the bytes they would win.
pub const mtu_minimum_change: u16 = 20;
/// How long PMTUD stays parked after a black hole before re-probing.
pub const mtu_black_hole_cooldown_ns: i64 = 60 * std.time.ns_per_s;
/// Suspicious loss bursts required before we believe in a black hole. Matching
/// upstream's constant keeps our false-positive rate comparable on a shared path.
pub const mtu_black_hole_threshold: usize = 3;

/// Binary search for the path MTU (RFC 8899 §5.3; upstream `mtud.rs:288-353`).
///
/// The interval is `(lower_bound, upper_bound]`: `lower_bound` is a size we
/// have confirmed works, `upper_bound` the largest we still believe possible.
/// Each probe halves it. A probe ACK raises the floor; a probe loss lowers the
/// ceiling below the size that failed.
pub const MtuSearch = struct {
    lower_bound: u16,
    upper_bound: u16,
    /// The size of the most recent probe — what an ACK/loss verdict applies to.
    last_probed: u16,
    /// Consecutive losses at `last_probed`. A probe is a single unreliable
    /// datagram, so one loss is weak evidence; we retry before shrinking.
    lost_probe_count: u8 = 0,

    pub const max_probe_retries: u8 = 3;

    pub fn init(lower: u16, upper: u16) MtuSearch {
        const lo = @min(lower, upper);
        return .{ .lower_bound = lo, .upper_bound = @max(lo, upper), .last_probed = lo };
    }

    /// Next size to probe, or `null` when the search has converged.
    ///
    /// `last_probe_succeeded` folds the previous verdict into the interval
    /// before choosing, so callers never mutate the bounds themselves.
    pub fn nextProbe(self: *MtuSearch, last_probe_succeeded: bool) ?u16 {
        if (last_probe_succeeded) {
            self.lower_bound = @max(self.lower_bound, self.last_probed);
        } else if (self.last_probed > self.lower_bound) {
            self.upper_bound = self.last_probed - 1;
        }
        self.lost_probe_count = 0;
        if (self.upper_bound <= self.lower_bound) return null;

        const midpoint: u16 = @intCast((@as(u32, self.lower_bound) + @as(u32, self.upper_bound)) / 2);
        const delta = if (midpoint > self.last_probed) midpoint - self.last_probed else self.last_probed - midpoint;
        if (delta < mtu_minimum_change) {
            // The midpoint is no longer worth probing. The upper bound itself
            // may still be, though — otherwise a search that converged just
            // below it would never actually reach it.
            if (self.upper_bound -| self.last_probed >= mtu_minimum_change) {
                self.last_probed = self.upper_bound;
                return self.upper_bound;
            }
            return null;
        }
        self.last_probed = midpoint;
        return midpoint;
    }
};

/// MTU black-hole detector.
///
/// An **idiomatic adaptation** of upstream's `BlackHoleDetector`
/// (`mtud.rs:356-384`, `:443-452`) — same wire-observable outcome (fall back to
/// `min_mtu` on a path that persistently swallows big packets), expressed in
/// Zig's grain rather than transliterated. Where upstream keeps a heap-allocated
/// `Vec<LossBurst>`, this keeps a fixed-size ring, because the threshold is a
/// compile-time constant and a connection must not allocate on the loss path.
///
/// The heuristic, unchanged:
///
///  1. **Burst grouping.** Consecutive packet numbers declared lost together
///     were probably lost for the same reason, so they are aggregated into one
///     burst (`open_last_pn` tracks the run; a gap closes it).
///  2. **Suspicion.** A burst is suspicious only if *every* packet in it was
///     larger than `min_mtu` — i.e. the whole burst could be explained by the
///     path having shrunk. One small packet in the burst exonerates it.
///  3. **De-suspicion by ACK.** Acknowledging a packet at least as large as a
///     burst's smallest member proves the path still carries that size, so the
///     burst is retroactively cleared (`onAcked`).
///  4. **Threshold + cooldown.** More than `mtu_black_hole_threshold`
///     surviving suspicious bursts is enough evidence; the caller drops to
///     `min_mtu` and parks PMTUD for a cooldown.
pub const MtuBlackHole = struct {
    /// Smallest packet size in each surviving suspicious burst.
    suspicious: [mtu_black_hole_threshold + 1]u16 = undefined,
    suspicious_len: usize = 0,
    /// The burst currently being aggregated, if any.
    open_smallest: u16 = 0,
    /// Packet number of the most recent loss folded into the open burst. The
    /// next loss continues the burst iff it is exactly `open_last_pn + 1`.
    open_last_pn: u64 = 0,
    open: bool = false,
    /// Largest packet size acknowledged more recently than any surviving
    /// suspicious burst. Bursts smaller than this cannot be MTU-related.
    acked_mtu: u16 = min_mtu,

    /// A non-probe packet was declared lost.
    pub fn onLost(self: *MtuBlackHole, pn: u64, size: u16) void {
        if (self.open and pn != self.open_last_pn +% 1) self.closeBurst();
        if (self.open) {
            self.open_smallest = @min(self.open_smallest, size);
            self.open_last_pn = pn;
        } else {
            self.open = true;
            self.open_smallest = size;
            self.open_last_pn = pn;
        }
    }

    /// A packet was acknowledged. A delivery at least this large exonerates
    /// every suspicious burst whose smallest member was no bigger — the path
    /// demonstrably still carries that size.
    pub fn onAcked(self: *MtuBlackHole, size: u16) void {
        if (size <= self.acked_mtu) return;
        self.acked_mtu = size;
        var write: usize = 0;
        var read: usize = 0;
        while (read < self.suspicious_len) : (read += 1) {
            if (self.suspicious[read] > size) {
                self.suspicious[write] = self.suspicious[read];
                write += 1;
            }
        }
        self.suspicious_len = write;
    }

    /// An MTU probe was acknowledged: the larger size works, so nothing older
    /// is evidence of a black hole.
    pub fn onProbeAcked(self: *MtuBlackHole, size: u16) void {
        self.suspicious_len = 0;
        self.open = false;
        self.acked_mtu = @max(self.acked_mtu, size);
    }

    /// Call once per loss-detection round, after every `onLost`. True means the
    /// evidence is sufficient; the detector resets so one black hole is
    /// reported once.
    pub fn detected(self: *MtuBlackHole) bool {
        self.closeBurst();
        if (self.suspicious_len <= mtu_black_hole_threshold) return false;
        self.reset();
        return true;
    }

    pub fn reset(self: *MtuBlackHole) void {
        self.suspicious_len = 0;
        self.open = false;
        self.acked_mtu = min_mtu;
    }

    /// Finish the open burst and record it if it is suspicious.
    fn closeBurst(self: *MtuBlackHole) void {
        if (!self.open) return;
        const smallest = self.open_smallest;
        self.open = false;
        // A burst containing a packet no larger than the guaranteed-supported
        // size cannot be explained by an MTU reduction.
        if (smallest <= min_mtu) return;
        // Nor can one smaller than a size we have since seen delivered.
        if (smallest <= self.acked_mtu) return;

        // A suspicious burst invalidates the acked evidence that preceded it:
        // we no longer know the path carries `acked_mtu`. Conservative, and
        // erring toward a false positive is safe (we only lose some MTU).
        self.acked_mtu = min_mtu;

        if (self.suspicious_len < self.suspicious.len) {
            self.suspicious[self.suspicious_len] = smallest;
            self.suspicious_len += 1;
            return;
        }
        // Ring is full: keep the most suspicious (largest smallest-member)
        // bursts, since those are the ones an MTU reduction best explains.
        var min_i: usize = 0;
        for (self.suspicious[0..self.suspicious_len], 0..) |s, i| {
            if (s < self.suspicious[min_i]) min_i = i;
        }
        if (smallest > self.suspicious[min_i]) self.suspicious[min_i] = smallest;
    }
};

pub const max_tracked_sent_packets: usize = 131_072;
pub const max_loss_batch: usize = 1024;
pub const max_crypto_buf: usize = 16 * 1024;
/// Largest UDP datagram the engine builds or accepts (F19).
/// Single source of truth: `shared/limits.zig`.
pub const max_datagram: usize = @import("shared").limits.max_datagram;

/// Timer granularity in MICROSECONDS, advertised as `min_ack_delay`
/// (draft-ietf-quic-ack-frequency §10.1). Matches noq's TIMER_GRANULARITY
/// (`Duration::from_millis(1)` → 1000 µs), which noq emits unconditionally.
pub const timer_granularity_us: u64 = 1000;

/// Default advertised `max_datagram_frame_size` (RFC 9221). 1200 is the RFC 9000
/// §14.1 minimum-datagram floor, so a peer honoring it can always carry one
/// unreliable datagram in a conforming packet.
pub const default_max_datagram_frame_size: u64 = 1200;
/// Bound on queued outgoing DATAGRAM payload bytes. Matches noq's default
/// `datagram_send_buffer_size` (noq-proto config/transport.rs:577); like noq's
/// `Connection::send_datagram` (`Datagrams::send` with drop=true), a send that
/// would exceed the bound discards the oldest queued datagrams first.
pub const datagram_send_buffer_size: usize = 1024 * 1024;
/// RFC 9000 §14.1: every client Initial datagram is at least 1200 bytes.
const min_client_initial_datagram_size: usize = 1200;
/// A3 (noq `MIN_PACKET_SPACE`, connection/mod.rs:7575-7590): minimal remaining
/// datagram room that allows coalescing one more packet — the largest
/// Handshake/0-RTT header (1 + 4 + 1 + 20 + 1 + 20 + 4 + 4 = 55) plus 32.
const min_packet_space: usize = 87;
/// Slack subtracted from the remaining datagram room to bound a coalesced
/// followup packet's payload budget: long header + PN + AEAD tag with margin.
const packet_header_reserve: usize = 80;
// QUIC transport error codes (RFC 9000 §20.1).
pub const err_no_error: u64 = 0x00;
pub const err_flow_control: u64 = 0x03;
pub const err_stream_limit: u64 = 0x04;
pub const err_stream_state: u64 = 0x05;
pub const err_final_size: u64 = 0x06;
pub const err_frame_encoding: u64 = 0x07;
pub const err_transport_parameter: u64 = 0x08;
pub const err_protocol_violation: u64 = 0x0a;
pub const err_crypto_buffer_exceeded: u64 = 0x0d;
pub const err_key_update: u64 = 0x0e;
pub const err_aead_limit_reached: u64 = 0x0f;
/// RFC 9000 §20.1: CRYPTO_ERROR base — a TLS alert maps to 0x0100 + alert
/// code (noq `TransportErrorCode::crypto`, crypto/rustls.rs:100-104).
pub const err_crypto_error_base: u64 = 0x0100;
/// RFC 9000 §10.2.3: an application close signaled in an Initial/Handshake
/// packet is rewritten to a transport close with this code (noq
/// `TransportError::APPLICATION_ERROR`, transport_error.rs:157).
pub const err_application_error: u64 = 0x0c;
/// Default flow-control windows we advertise (receive side).
pub const default_initial_max_data: u64 = 1 << 20;
pub const default_initial_max_stream_data: u64 = 256 * 1024;
pub const default_initial_max_streams: u64 = 16;
pub const default_max_idle_timeout_ms: u64 = 30_000;
/// G18: iroh's HEARTBEAT_INTERVAL (iroh socket.rs:109) — the
/// keep-alive interval iroh configures on every connection
/// (endpoint/quic.rs:156). transport_noq sets this on its drivers; the
/// bare Connection default stays disabled (noq's `None`).
pub const default_keep_alive_interval_ns: i64 = 5 * std.time.ns_per_s;
/// Initial plaintext we pack into one 1-RTT data packet's frame region.
///
/// This keeps the first post-handshake data packets below the base 1200-byte
/// QUIC datagram size. Once MTU probing raises `self.mtu`, the packet builder
/// can use the confirmed path headroom.
const base_data_payload_budget: usize = 1100;
const data_payload_headroom: usize = 96;

// S6: the 2-arm TlsSession union collapses to the selected backend's Session.
// Behavior-preserving by construction — mono products only ever had one live arm.
const TlsSession = crypto.Session;

/// Pre-S6 TlsSession.zigtls arm mapped every non-OOM engine error onto
/// `error.PicotlsError` so Connection.Error stayed closed. The union collapse
/// must keep that map at the engine boundary (adapter methods keep their
/// richer sets for direct unit tests).
fn mapTlsSessionErr(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => if (comptime crypto.zigtls_enabled) error.PicotlsError else @errorCast(err),
    };
}

fn tlsStart(tls: *TlsSession, allocator: std.mem.Allocator) Error!crypto.HandshakeOutput {
    if (comptime crypto.zigtls_enabled) {
        return tls.start(allocator) catch |err| return mapTlsSessionErr(err);
    } else {
        return tls.start(allocator);
    }
}

fn tlsHandleMessage(
    tls: *TlsSession,
    allocator: std.mem.Allocator,
    epoch: crypto.Epoch,
    input: []const u8,
) Error!crypto.HandshakeOutput {
    if (comptime crypto.zigtls_enabled) {
        return tls.handleMessage(allocator, epoch, input) catch |err| return mapTlsSessionErr(err);
    } else {
        return tls.handleMessage(allocator, epoch, input);
    }
}

pub const Connection = struct {
    allocator: std.mem.Allocator,
    role: crypto.Role,
    state: State = .handshake,
    tls: *TlsSession,

    local_cid: packet.ConnectionId,
    remote_cid: packet.ConnectionId,
    /// Client's original DCID (used for Initial key derivation on both sides).
    initial_dcid: packet.ConnectionId,

    path_generation: u64 = 0,
    timers: TimerTable = .{},
    spaces_state: spaces.Spaces = .{},

    // Per-space keys (write = local send, read = peer send).
    write_keys: [3]?packet_crypto.PacketKeys = .{ null, null, null },
    read_keys: [3]?packet_crypto.PacketKeys = .{ null, null, null },

    // 0-RTT keys (RFC 9001 §5): SEPARATE from the three spaces — 0-RTT
    // packets use the Application Data packet-number space but early-epoch
    // keys. Client: early WRITE keys encrypt 0-RTT flights before 1-RTT;
    // server: early READ keys decrypt accepted 0-RTT.
    zero_rtt_write_keys: ?packet_crypto.PacketKeys = null,
    zero_rtt_read_keys: ?packet_crypto.PacketKeys = null,
    /// Client offered 0-RTT (early write keys were installed from TLS).
    zero_rtt_offered: bool = false,
    /// The 0-RTT offer was/will be ACCEPTED: client learned it from the
    /// server's EncryptedExtensions; server sets it when it installs early
    /// read keys (the TLS engine only derives them on an accepted offer).
    zero_rtt_accepted: bool = false,
    /// Client: a rejected offer was already reconciled (one-shot guard for
    /// the re-offer machinery — noq retransmits every 0-RTT packet's frames).
    zero_rtt_rejected: bool = false,
    /// Client applied remembered transport parameters from the resumption
    /// ticket for its 0-RTT flight (RFC 9001 §4.6). The real handshake TPs
    /// still apply later and must not shrink the remembered max_* values
    /// (RFC 9000 §7.4.1 — TRANSPORT_PARAMETER_ERROR otherwise).
    zero_rtt_peer_params: bool = false,
    zero_rtt_remembered: ?transport_parameters.TransportParameters = null,
    /// AEAD budget counter for early-key packets (noq `sent_with_zero_rtt`,
    /// packet_crypto.rs:90) — 0-RTT keys can never rotate, so exhaustion
    /// stops 0-RTT sends instead of triggering a key update.
    sent_with_zero_rtt: u64 = 0,
    /// Datagrams dropped because inbound 0-RTT was not accepted (evidence).
    stats_zero_rtt_dropped: u64 = 0,
    /// Server: 0-RTT packets accepted + early bytes delivered (evidence).
    stats_zero_rtt_accepted_packets: u64 = 0,
    stats_zero_rtt_payload_bytes: u64 = 0,
    /// Client: 0-RTT packets sent (evidence).
    stats_zero_rtt_packets_sent: u64 = 0,

    // Outbound CRYPTO per epoch (initial / handshake / app). Kept in full (not
    // cleared after send) so lost CRYPTO can be re-sent by offset (real retransmit).
    crypto_out: [3]std.ArrayList(u8) = .{ .empty, .empty, .empty },
    crypto_sent: [3]u64 = .{ 0, 0, 0 }, // high-water offset already put on the wire
    crypto_rtx: [3]std.Deque(Chunk) = .{ .empty, .empty, .empty }, // lost crypto chunks
    crypto_in_offset: [3]u64 = .{ 0, 0, 0 },
    /// A9: out-of-order CRYPTO reassembly per space (noq's per-space
    /// `crypto_stream` assembler, connection/mod.rs read_crypto). Segments
    /// past the contiguous `crypto_in_offset` high-water wait here until the
    /// gap fills; the unreassembled span is bounded by `max_crypto_buf`
    /// (noq `crypto_buffer_size`, 16 KiB default).
    crypto_in_pending: [3]std.ArrayList(CryptoSegment) = .{ .empty, .empty, .empty },

    /// A5: most recent ack-eliciting send per space, persisting after the
    /// packet is ACKed (noq `time_of_last_ack_eliciting_packet`). The
    /// anti-deadlock PTO bases its deadline on this once nothing is in flight.
    last_ack_eliciting_sent: [3]?Instant = .{ null, null, null },
    /// In-flight ack-eliciting inventory for O(1) PTO arming. `ptoDeadline` is
    /// on every `pollTimeout`/`pollTransmit` path; rescanning `sent` was 21% of
    /// responder CPU with a large in-flight list.
    pto_inflight_count: [3]u32 = .{ 0, 0, 0 },
    pto_inflight_latest: [3]?Instant = .{ null, null, null },
    /// A5: one queued anti-deadlock PING probe per space (noq `pending_ping`
    /// fallback of `queue_tail_loss_probe`).
    pending_ping: [3]bool = .{ false, false, false },

    // ACK state: per-space received-PN tracker (multi-range) + send flag.
    pending_acks: [3]loss.PendingAcks = .{ .{}, .{}, .{} },
    needs_ack: [3]bool = .{ false, false, false },
    dedup: [3]loss.Dedup = .{ .{}, .{}, .{} },

    sent: std.ArrayList(SentPacket) = .empty,

    // ── Stream layer (5b) ────────────────────────────────────────────────────
    streams: [max_streams]StreamEntry = [_]StreamEntry{.{}} ** max_streams,
    /// Next locally-initiated stream counters (id = counter*4 + role/dir base).
    next_bidi: u64 = 0,
    next_uni: u64 = 0,

    // Flow control. `send_*` = the peer's advertised limits we obey; `recv_*` =
    // the limits we advertise + enforce (a memory-safety boundary).
    send_max_data: u64 = 0,
    send_data_total: u64 = 0,
    recv_max_data: u64 = default_initial_max_data,
    recv_data_total: u64 = 0,
    recv_abandoned_total: u64 = 0,
    data_blocked_at: u64 = 0,
    recv_max_streams_bidi: u64 = default_initial_max_streams,
    recv_max_streams_uni: u64 = default_initial_max_streams,
    streams_blocked_bidi_pending: ?u64 = null,
    streams_blocked_uni_pending: ?u64 = null,
    streams_blocked_bidi_sent_at: ?u64 = null,
    streams_blocked_uni_sent_at: ?u64 = null,
    local_params: transport_parameters.TransportParameters = .{},
    peer_params: transport_parameters.TransportParameters = .{},
    peer_params_applied: bool = false,
    idle_timeout_ns: ?i64 = null,
    idle_deadline: ?Instant = null,
    /// G18-idle (RFC 9000 §10.1, noq `permit_idle_reset`, paths.rs + packet_builder.rs:303-318):
    /// a SEND may restart the idle timer only if no ack-eliciting packet has
    /// been sent since the last received-and-processed packet. Set on every
    /// received datagram that restarts the timer; consumed by the first
    /// ack-eliciting transmit. Without the gate our own keep-alive PINGs
    /// re-arm the deadline forever and a silent/dead peer is never
    /// idle-timed-out.
    permit_idle_reset: bool = true,

    // Close.
    close_frame: ?frame.ConnectionClose = null,
    close_sent: bool = false,
    /// Per-space record of a close armament: bit `si` is set once the close
    /// has ridden in space `si` since the last (re-)arm (B2, noq
    /// connection/mod.rs:1678-1693 — "send a close frame in every possible
    /// space"). Needed because one `pollTransmit` returns ONE datagram, so a
    /// 1200-padded client Initial close defers the Handshake close to the
    /// next call (noq would put both in one multi-datagram Transmit).
    close_sent_mask: u3 = 0,
    /// B4 (noq connection/mod.rs:5540-5543): a peer's Data-space close moved
    /// us to draining and we owe exactly ONE NO_ERROR CONNECTION_CLOSE back.
    drain_close_pending: bool = false,
    /// First authenticated Handshake packet seen (noq `on_path_validated`,
    /// connection/mod.rs:4657 — both roles validate the peer's address when a
    /// Handshake packet authenticates). Gates the B3 closed-state re-arm.
    /// Deliberately separate from `path_validated_any`, which also feeds the
    /// anti-amplification limit and follows RFC 9000 §8 timing instead.
    peer_handshake_authed: bool = false,

    // Path validation (5e, RFC 9000 §8.2). `challenge_pending` = tokens queued to
    // send once; `challenge_await` = sent, awaiting a matching PATH_RESPONSE;
    // `response_tx` = responses we owe for received PATH_CHALLENGEs; `validated` =
    // tokens confirmed (challenge echoed back verbatim). A path is validated ONLY
    // by a matching response — never by merely receiving a datagram (anti-spoofing
    // / anti-amplification).
    challenge_pending: [max_path_tokens][8]u8 = undefined,
    challenge_pending_hints: [max_path_tokens]?u64 = undefined,
    challenge_pending_len: usize = 0,
    challenge_await: [max_path_tokens][8]u8 = undefined,
    /// Parallel destination hints for outstanding challenges, so a hinted
    /// probe keeps its destination across retransmission re-drives.
    challenge_await_hints: [max_path_tokens]?u64 = undefined,
    challenge_await_len: usize = 0,
    response_tx: [max_path_tokens][8]u8 = undefined,
    response_tx_len: usize = 0,
    validated: [max_path_tokens][8]u8 = undefined,
    validated_len: usize = 0,
    path_validated_any: bool = false,
    bytes_received: u64 = 0,
    bytes_sent_unvalidated: u64 = 0,
    /// Authenticated packets processed (noq total_authed_packets) — the only
    /// honest "the peer proved keys" signal for migration gating and the A11
    /// forged-Version-Negotiation defense.
    total_authed_packets: u64 = 0,

    stateless_reset_token: [packet.stateless_reset_token_len]u8 = .{0} ** packet.stateless_reset_token_len,
    /// E3: the owning endpoint's reset HMAC key (bytes + len), when wired —
    /// per-CID reset tokens derive from it (noq ResetToken::new).
    reset_key: ?struct { [64]u8, usize } = null,
    peer_stateless_reset_token: ?[packet.stateless_reset_token_len]u8 = null,
    /// Test-only: when true, `matchesPeerStatelessReset` always returns false
    /// (mutation-RED disable-point for real-peer stateless-reset tests).
    test_disable_peer_stateless_reset: bool = false,

    local_cids: [max_local_cid_slots]LocalCidSlot = [_]LocalCidSlot{.{}} ** max_local_cid_slots,
    local_cid_len: usize = 0,
    next_cid_sequence: u64 = 1,
    pending_new_cid: bool = false,
    pending_new_cid_buf: [packet.max_cid_size]u8 = undefined,
    pending_new_cid_len: u8 = 0,
    pending_new_cid_reset: [packet.stateless_reset_token_len]u8 = .{0} ** packet.stateless_reset_token_len,
    pending_new_cid_seq: u64 = 0,
    pending_new_cid_retire: u64 = 0,
    remote_cids: [max_local_cid_slots]RemoteCidSlot = [_]RemoteCidSlot{.{}} ** max_local_cid_slots,
    remote_cid_len: usize = 0,

    crypto_1rtt: packet_crypto.CryptoState = .{},
    write_key_phase: bool = false,
    /// A locally initiated update cannot repeat until the peer authenticates a
    /// packet in the new phase.
    write_update_pending: bool = false,
    /// A peer-initiated update is acknowledged by our first packet in the new
    /// phase. A second peer update before then is a KEY_UPDATE_ERROR.
    remote_update_unacked: bool = false,
    key_update_count: u64 = 0,
    /// A16: packets encrypted with the current keys, per space (noq
    /// `CryptoSpace::sent_with_keys`, connection/packet_crypto.rs:466). The
    /// Data-space counter resets on every key update.
    sent_with_keys: [3]u64 = .{ 0, 0, 0 },
    /// A16: packets allowed in the current Data key phase before an automatic
    /// key update (noq `CryptoState::key_phase_size`, packet_crypto.rs:105).
    key_phase_size: u64 = 0,
    /// A16: total packets that failed authentication (noq
    /// `Connection::authentication_failures`, connection/mod.rs:214).
    authentication_failures: u64 = 0,
    app_write_secret: [64]u8 = undefined,
    app_write_secret_len: usize = 0,
    app_read_secret: [64]u8 = undefined,
    app_read_secret_len: usize = 0,

    peer_ack_eliciting_pending: u64 = 0,

    mtu_probe_queue: [4]u16 = undefined,
    mtu_probe_queue_len: usize = 0,
    mtu_probes_scheduled: bool = false,

    initial_token: []u8 = &.{},
    stored_new_token: []u8 = &.{},
    new_token_pending: bool = false,
    /// E7: the sealed NEW_TOKEN bytes to send post-handshake (transport-issued,
    /// bound to the peer's address + issuance time). The engine never invents
    /// token bytes — a server without an override sends no NEW_TOKEN.
    new_token_override: []u8 = &.{},
    retry_secret_key: [32]u8 = undefined,

    datagram_out: std.Deque([]u8) = .empty,
    /// Sum of payload bytes currently queued in `datagram_out`; kept in sync by
    /// `sendDatagram` / `takeDatagramOut` so the send-buffer bound is O(1).
    datagram_out_total: usize = 0,
    datagram_in: std.Deque([]u8) = .empty,

    peer_ack_eliciting_threshold: ?u64 = null,
    peer_ack_max_ack_delay: ?u64 = null,
    /// G11 (noq PendingAcks::reordering_threshold, spaces.rs:1103, default 1
    /// at :1130): the peer's requested response to out-of-order packets, from
    /// ACK_FREQUENCY (set_ack_frequency_params, spaces.rs:1139-1142). Stored
    /// here; SEAM-G4 (delayed-ACK cadence) consumes it in the out-of-order
    /// immediate-ACK decision — see the G11 note in processPayload.
    peer_reordering_threshold: u64 = 1,
    /// Largest ack-eliciting PN received per space (noq
    /// PendingAcks::largest_ack_eliciting_packet, spaces.rs:1118-1119) —
    /// G11 plumbing for the same SEAM-G4 decision.
    largest_ack_eliciting_recv: [3]?u64 = .{ null, null, null },
    /// Largest PN we have reported as acknowledged in an emitted ACK frame
    /// (noq PendingAcks::largest_acked, spaces.rs:1120, updated in
    /// acks_sent:1270). G4: input to the draft-§6.1 reordering_threshold > 1
    /// branch of is_out_of_order (spaces.rs:1232-1248).
    largest_acked_sent: [3]?u64 = .{ null, null, null },
    ack_frequency_pending: bool = false,
    /// Next outgoing ACK_FREQUENCY sequence number (noq
    /// AckFrequencyState::next_outgoing_sequence_number, ack_frequency.rs:15,
    /// starts at VarInt(0); next_sequence_number:70-76).
    ack_frequency_seq: u64 = 0,
    /// G10 (noq AckFrequencyState::in_flight_ack_frequency_frame,
    /// ack_frequency.rs:14): PN + requested value of the ACK_FREQUENCY frame
    /// we sent that the peer has not acknowledged yet.
    ack_freq_in_flight_pn: ?u64 = null,
    ack_freq_in_flight_value_us: u64 = 0,
    /// G10 (noq AckFrequencyState::peer_max_ack_delay, ack_frequency.rs:16):
    /// the max_ack_delay the peer is currently using, as far as we know —
    /// its transport-parameter value until an ACK_FREQUENCY we sent is
    /// acknowledged (on_acked, ack_frequency.rs:107-116). Microseconds.
    ack_freq_peer_max_delay_us: u64 = 25_000, // default TP max_ack_delay 25 ms
    /// G13 (noq PacketNumberSpace::pending_immediate_ack, spaces.rs:274):
    /// an IMMEDIATE_ACK frame owed in the Data space — queued by tail-loss
    /// probes and MTU probes (mod.rs:1540-1546, 1822-1827).
    pending_immediate_ack: bool = false,
    /// Delayed-ACK deadline per space (RFC 9000 §13.2.1): when an ack-eliciting
    /// packet arrives but the ACK is not sent immediately (the threshold has
    /// not been reached), we still owe the peer an ACK within `max_ack_delay`.
    /// Without this timer a below-threshold ACK could be deferred indefinitely,
    /// stalling the peer's RTT sampling and loss recovery.
    ack_deadline: [3]?Instant = .{ null, null, null },
    /// Count of ACKs emitted because the delayed-ACK timer expired.
    stats_delayed_ack_timeouts: u64 = 0,

    mtu: u16 = 1200,
    probe_mtu: ?u16 = null,
    probe_pn: ?u64 = null,
    /// DPLPMTUD binary search over [min_mtu, upper_bound]. `null` once the
    /// search has converged (or a black hole parked it).
    mtu_search: ?MtuSearch = null,
    /// Black-hole detector state (see `MtuBlackHole`).
    mtu_black_hole: MtuBlackHole = .{},
    /// While set, PMTUD is parked: a black hole was detected and we stay at
    /// `min_mtu` until this instant, then re-arm the search (Rust's
    /// `Phase::Complete(next_mtud_activation)`, `mtud.rs:271-274`).
    mtu_search_resume_at: ?Instant = null,
    /// Count of black holes detected (structured evidence for the oracle —
    /// a reason-string match would not survive a refactor).
    stats_mtu_black_holes: u64 = 0,
    /// Count of MTU probes that were ACKed, raising the path MTU.
    stats_mtu_probes_acked: u64 = 0,

    next_send_at: Instant = 0,
    test_pacing_rate: ?u64 = null,
    pacing_tokens: u64 = 0,
    pacing_last_refill_at: ?Instant = null,
    pace_content_blocked: bool = false,

    /// ECN counters for the codepoints we have RECEIVED, echoed back to the
    /// peer in ACK_ECN (RFC 9000 §13.4.1).
    ecn_counts: frame.EcnCounts = .{},
    /// ECN codepoints we have SENT, used to validate the peer's ACK_ECN echo.
    ecn_sent: frame.EcnCounts = .{},
    /// Largest ACK_ECN counters the peer has reported, for the monotonicity +
    /// bleach checks in `validatePeerEcn`.
    ecn_peer_seen: frame.EcnCounts = .{},
    /// ECN state machine (RFC 9000 §13.4.2). Starts `testing`: we mark ECT(0)
    /// and watch the peer's ACK_ECN echo. Confirmed on a valid echo; disabled
    /// permanently the first time the path is caught bleaching or mangling.
    ecn_state: EcnState = .testing,
    /// Structured evidence: CE codepoints ingested from real IP header bits at
    /// the socket receive path. The oracle's ECN row keys on this, NOT on a
    /// reason string, so a stub cannot fake it.
    stats_ecn_recv_marked: u64 = 0,
    /// ECT(0)/ECT(1) codepoints ingested from real IP header bits.
    stats_ecn_recv_ect: u64 = 0,
    /// Congestion events driven by a VALIDATED peer CE increase.
    stats_ecn_congestion_events: u64 = 0,
    /// Test-only: stamp this codepoint instead of ECT(0). Lets a loopback test
    /// exercise CE ingestion, which no loopback router will ever apply.
    test_ecn_override: ?udp_cmsg.EcnCodepoint = null,

    // Outbound n0 NAT-traversal address frames queued by the magicsock layer.
    nat_out: [max_path_tokens]NatAddress = undefined,
    nat_out_len: usize = 0,

    // Loss / RTT (RFC 9002) — drives real retransmission.
    rtt: loss.RttEstimator = loss.RttEstimator.init(333_000_000),
    pto_count: u32 = 0,
    /// G15 (noq `lost_packets` per space, mod.rs:3074-3100): PNs declared lost
    /// whose frames were already retransmitted, kept so a later ACK covering
    /// them can detect a spurious congestion event. Drained once they are
    /// older than 2·pto_base (noq `drain_lost_packets`, mod.rs:3103-3113).
    lost_packets: [3]std.ArrayList(LostPacket) = .{ .empty, .empty, .empty },
    /// G16 (noq `first_packet_after_rtt_sample`, paths.rs:216): set when the
    /// first RTT sample lands; persistent congestion may only start at a
    /// packet sent strictly after it.
    first_pn_after_rtt_sample: ?loss.FirstAfterRttSample = null,
    /// Count of spurious congestion events detected (G15).
    stats_spurious_congestion_events: u64 = 0,
    /// Count of ACKs delivered to congestion control with app_limited=true (J9).
    stats_app_limited_acks: u64 = 0,
    /// G18 (noq `TransportConfig::keep_alive_interval` + `ConnTimer::KeepAlive`,
    /// config/transport.rs:50, timer.rs:27): emit a PING when the connection
    /// would otherwise be idle past this interval. null = disabled (noq
    /// default; iroh sets its 5s heartbeat).
    keep_alive_interval_ns: ?i64 = null,
    keep_alive_deadline: ?Instant = null,
    cc: ?congestion.Controller = null,
    congestion_kind: congestion.Kind = .cubic,
    bytes_in_flight: u64 = 0,
    /// Count of times stream data was ready but congestion window blocked
    /// packet construction.
    stats_cc_limited: u64 = 0,
    /// Peak `sent.items.len` observed (proves >64-in-flight tracking for LOSSY gate).
    stats_peak_sent: u64 = 0,
    /// Test-only BDP throttle: caps the effective cwnd consulted at buildSpacePacket.
    /// `null` = production (uncapped). Used by the BDP-THROTTLED large-transfer variant.
    test_cwnd_cap: ?u64 = null,
    /// Count of chunks re-queued by any retransmit path.
    stats_retransmits: u64 = 0,
    /// Count of packets flagged lost BY loss.detectLostPackets in the driver
    /// (proves the F2 production loss-detection path fired).
    stats_loss_events: u64 = 0,
    /// Count of PTO-driven probe retransmits (RFC 9002 §6.2 backstop).
    stats_pto_events: u64 = 0,
    /// A3: packets appended behind a long-header packet into the same UDP
    /// datagram (noq `poll_transmit_path_space` coalesce, mod.rs:1739-1758).
    stats_coalesced_packets: u64 = 0,
    /// A3: followup packets that did not fit the open datagram and were
    /// stashed for the next `pollTransmit` (budget caps should make this ~0).
    stats_coalesce_stashed: u64 = 0,

    handshake_done_sent: bool = false,
    handshake_done_received: bool = false,
    handshake_confirmed: bool = false,
    /// The noq HandshakeDataReady contract — the event fires exactly once.
    handshake_data_sent: bool = false,
    /// E6: a Retry was already consumed — a second one is silently discarded
    /// (RFC 9000 §17.2.5: a client accepts at most one Retry per attempt).
    retry_consumed: bool = false,
    /// E6/F5: the Retry SCID the client adopted, for TP retry_scid comparison.
    retry_src_cid: ?packet.ConnectionId = null,
    /// Highest OBSERVED_ADDR sequence accepted so far (stale/equal reports
    /// are dropped, noq update_observed_addr_report).
    last_observed_seq: ?u64 = null,
    /// F5: the FIRST remote CID ever adopted (Retry consume or the first
    /// authenticated server Initial, whichever came first — noq's
    /// `original_remote_cid`). Pinned: later adoptions update `remote_cid`
    /// but never this, which is what makes a CID-desync detectable.
    initial_remote_cid: ?packet.ConnectionId = null,

    events: std.Deque(Event) = .empty,
    tx_scratch: [max_datagram]u8 = undefined,
    /// A3 send-side coalescing: the datagram under assembly in `pollTransmit`.
    tx_coalesce: [max_datagram]u8 = undefined,
    /// A3 safety net: a followup packet that was sealed and tracked but did
    /// not fit the datagram in flight. Delivered before anything new is built.
    stash_buf: [max_datagram]u8 = undefined,
    stash_len: usize = 0,
    stash_ecn: ?udp_cmsg.EcnCodepoint = null,

    now: Instant = 0,
    /// CSPRNG for security tokens (reset / NEW_TOKEN / CIDs). ChaCha8 seeded
    /// from caller-supplied entropy — never a non-crypto PRNG.
    rng: std.Random.DefaultCsprng,

    pub const CreateOptions = struct {
        /// E5: the client's ORIGINAL DCID when the accept path validated a Retry
        /// (emitted as `original_destination_connection_id`); keys still derive
        /// from `initial_dcid` (the current flight's DCID).
        orig_dst_cid: ?packet.ConnectionId = null,
        /// E5/F6: the Retry SCID the server issued (emitted as
        /// `retry_source_connection_id`). Server role only.
        retry_src_cid: ?packet.ConnectionId = null,
        /// E8: a stored NEW_TOKEN token to present in the first Initial (RFC
        /// 9000 §8.1.3 — one-time use; the caller's store already took it).
        initial_token: []const u8 = "",
        /// E3: the owning endpoint's stateless-reset HMAC key. When set, the
        /// connection's reset tokens (TP + every NEW_CONNECTION_ID) are
        /// HMAC-derived per noq ResetToken::new — the same derivation the
        /// endpoint uses for resets it sends, so a peer can recognize them.
        reset_key: ?[]const u8 = null,
        /// F13: the address-discovery role to advertise (draft-seemann QAD,
        /// TP 0x9f81a176). Null = feature off (no frames may be sent either
        /// direction, matching noq's absent-role default).
        observed_addr_role: ?transport_parameters.ObservedAddrRole = null,
        /// J2: congestion controller selection. Cubic remains the iroh/noq
        /// default, but the driver no longer hardcodes it.
        congestion_kind: congestion.Kind = .cubic,
    };

    pub fn create(
        allocator: std.mem.Allocator,
        config: crypto.Config,
        local_cid: packet.ConnectionId,
        remote_cid: packet.ConnectionId,
        initial_dcid: packet.ConnectionId,
        /// 32-byte secret seed for the connection CSPRNG (production: fill via
        /// `std.Io.random`; tests may use a deterministic pattern).
        seed: [std.Random.DefaultCsprng.secret_seed_length]u8,
        opts: CreateOptions,
    ) !*Connection {
        const self = try allocator.create(Connection);
        errdefer allocator.destroy(self);

        // Advertise flow-control params (F1). The caller may pass explicit
        // transport_params; otherwise advertise our defaults so a real peer
        // (quinn) will echo + open streams. Decode what we advertise so the
        // receive-side windows we ENFORCE match what we told the peer.
        var cfg = config;
        var params_scratch: [256]u8 = undefined;
        var local_params: transport_parameters.TransportParameters = undefined;
        var reset_token: [packet.stateless_reset_token_len]u8 = undefined;
        var rng = std.Random.DefaultCsprng.init(seed);
        rng.fill(&reset_token);
        // E3: endpoint-keyed derivation (noq ResetToken::new) when wired.
        if (opts.reset_key) |rk| reset_token = quic_token.resetToken(rk, local_cid);
        if (cfg.transport_params) |tp| {
            local_params = transport_parameters.decode(tp) catch .{};
        } else {
            local_params = .{
                .max_idle_timeout = default_max_idle_timeout_ms,
                .initial_max_data = default_initial_max_data,
                .initial_max_stream_data_bidi_local = default_initial_max_stream_data,
                .initial_max_stream_data_bidi_remote = default_initial_max_stream_data,
                .initial_max_stream_data_uni = default_initial_max_stream_data,
                .initial_max_streams_bidi = default_initial_max_streams,
                .initial_max_streams_uni = default_initial_max_streams,
                .initial_source_connection_id = local_cid,
            };
        }
        // initial_source_connection_id is always our local CID (RFC 9000
        // §18.2), overriding caller-supplied params — the peer's CID
        // authentication (F5) rejects a handshake whose iscid is absent/wrong.
        local_params.initial_source_connection_id = local_cid;
        // E13: advertise exactly the CID inventory the engine can hold
        // (max_local_cid_slots = 5 = noq's CidQueue::LEN).
        local_params.active_connection_id_limit = max_local_cid_slots;
        // F12: grease_quic_bit is noq's default (config/mod.rs:66) — we
        // advertise it and therefore accept fixed-bit-0 from greasing peers.
        local_params.grease_quic_bit = true;
        // F2: one greased reserved TP (31N+27) per connection (noq
        // ReservedTransportParameter::random — anti-ossification).
        local_params.grease = .random(rng.random());
        // F13: the QAD role, when the caller negotiates address discovery.
        if (opts.observed_addr_role) |role| local_params.observed_addr_role = role;
        // Never advertise a QUIC datagram size larger than this driver's fixed
        // receive/decrypt scratch space. Real peers otherwise legitimately send
        // packets we cannot open after the handshake.
        local_params.max_udp_payload_size = @min(local_params.max_udp_payload_size, max_datagram);
        // noq parity: `min_ack_delay` (µs) is emitted unconditionally by noq at
        // its 1 ms timer granularity; our pump timer shares that granularity.
        // An explicit value in caller-supplied params is honored.
        if (local_params.min_ack_delay == null) local_params.min_ack_delay = timer_granularity_us;
        // RFC 9221 unreliable datagrams: advertise a frame size, capped at our
        // default so a caller cannot ask for more than a conforming packet holds.
        local_params.max_datagram_frame_size = if (local_params.max_datagram_frame_size) |value|
            @min(value, default_max_datagram_frame_size)
        else
            default_max_datagram_frame_size;
        // RFC 9000 §18.2: `stateless_reset_token` is a server-only transport
        // parameter. A client MUST NOT send it — quinn rejects with
        // TRANSPORT_PARAMETER_ERROR("illegal value") (the interop-noq regression).
        // We still keep a local reset token for NEW_CONNECTION_ID / inbound-reset
        // detection; only the handshake TP advertisement is role-gated.
        local_params.stateless_reset_token = if (config.role == .server) reset_token else null;
        // A server must authenticate the client's original destination CID in
        // its transport parameters (RFC 9000 section 18.2). Real QUIC clients
        // reject the handshake when this is absent even if in-memory peers do not.
        // E5: after a validated Retry that CID is the token's, not the current
        // flight's (which is the Retry SCID the keys derive from).
        local_params.original_destination_connection_id = if (config.role == .server) (opts.orig_dst_cid orelse initial_dcid) else null;
        // F6: after issuing a Retry the server authenticates the Retry SCID.
        local_params.retry_source_connection_id = if (config.role == .server) opts.retry_src_cid else null;
        // F2: the handshake TP block goes out in a shuffled write order (noq
        // `write_order: Some(shuffled)`); the canonical encode stays for the
        // byte fixtures. A test-only adversarial override ships verbatim bytes.
        cfg.transport_params = if (cfg.adversarial_transport_params) |adv|
            adv
        else
            local_params.encodeShuffled(&params_scratch, rng.random()) catch null;
        if (cfg.alpn == null) cfg.alpn = "iroh-interop-test";

        // S6: direct Session.create — backend is product-selected at comptime.
        // Runtime cfg.backend is still validated against the compiled backend.
        // Error codes match pre-S6 TlsSession union arms (vwsmsltl):
        //   .zigtls requested when zigtls is compiled out → ZigtlsDisabled
        //   .picotls requested when picotls is compiled out → PicotlsError
        if (comptime crypto.picotls_enabled) {
            if (cfg.backend != .picotls) return error.ZigtlsDisabled;
        } else if (comptime crypto.zigtls_enabled) {
            if (cfg.backend != .zigtls) return error.PicotlsError;
        }
        var tls = try TlsSession.create(allocator, cfg);
        errdefer tls.destroy();
        const cc = try congestion.create(allocator, opts.congestion_kind, 0, @intCast(max_datagram));
        errdefer cc.destroy(allocator);
        self.* = .{
            .allocator = allocator,
            .role = config.role,
            .tls = tls,
            .local_cid = local_cid,
            .remote_cid = remote_cid,
            .initial_dcid = initial_dcid,
            .local_params = local_params,
            .recv_max_data = local_params.initial_max_data,
            .recv_max_streams_bidi = local_params.initial_max_streams_bidi,
            .recv_max_streams_uni = local_params.initial_max_streams_uni,
            .cc = cc,
            .congestion_kind = opts.congestion_kind,
            .idle_timeout_ns = idleTimeoutNs(local_params.max_idle_timeout),
            .rng = rng,
            .stateless_reset_token = reset_token,
            .reset_key = if (opts.reset_key) |rk| blk: {
                var stored: [64]u8 = undefined;
                const n = @min(rk.len, stored.len);
                @memcpy(stored[0..n], rk[0..n]);
                break :blk .{ stored, n };
            } else null,
        };
        self.rng.fill(&self.retry_secret_key);
        // F5: the server's iscid reference pins at create (noq's
        // original_remote_cid = the CID first learned for the peer) — the
        // client pins later, at the first authenticated server Initial.
        if (config.role == .server) self.initial_remote_cid = remote_cid;
        // E8: a stored NEW_TOKEN token the client presents in its first Initial.
        if (opts.initial_token.len != 0) {
            self.initial_token = try allocator.dupe(u8, opts.initial_token);
        }
        // A16 (noq `CryptoState::new`, connection/packet_crypto.rs:130-136): a
        // small random initial key phase size ensures peers that don't handle
        // key updates fail sooner rather than later. It's okay for both peers
        // to do this — the first to update resets the other's phase size.
        self.key_phase_size = self.rng.random().intRangeLessThan(u64, 10, 1000);
        self.local_cids[0] = .{
            .sequence = 0,
            .cid = local_cid,
            .reset_token = self.stateless_reset_token,
        };
        self.local_cid_len = 1;
        self.ack_frequency_pending = true;
        // A17: optimistic-ACK defense — skip random PNs in the Data space only
        // (noq PacketNumberSpace::new, spaces.rs:302-310).
        self.spaces_state.get(.data).pn_filter = spaces.PacketNumberFilter.new(self.rng.random());
        // Install Initial keys (RFC 9001 §5.2) from the client DCID.
        const secrets = initial_keys.deriveInitialSecrets(initial_dcid.slice());
        const client_k = packet_crypto.keysFromTrafficSecret(&secrets.client);
        const server_k = packet_crypto.keysFromTrafficSecret(&secrets.server);
        switch (config.role) {
            .client => {
                self.write_keys[@intFromEnum(spaces.SpaceId.initial)] = client_k;
                self.read_keys[@intFromEnum(spaces.SpaceId.initial)] = server_k;
            },
            .server => {
                self.write_keys[@intFromEnum(spaces.SpaceId.initial)] = server_k;
                self.read_keys[@intFromEnum(spaces.SpaceId.initial)] = client_k;
            },
        }
        return self;
    }

    pub fn destroy(self: *Connection) void {
        self.scrubSecrets();
        self.tls.destroy();
        if (self.cc) |cc| cc.destroy(self.allocator);
        for (&self.crypto_out) |*buf| buf.deinit(self.allocator);
        for (&self.crypto_rtx) |*buf| buf.deinit(self.allocator);
        for (&self.crypto_in_pending) |*pending| {
            for (pending.items) |seg| self.allocator.free(seg.data);
            pending.deinit(self.allocator);
        }
        for (&self.streams) |*s| {
            if (s.used) {
                s.send.deinit(self.allocator);
                s.recv.deinit(self.allocator);
            }
        }
        self.sent.deinit(self.allocator);
        for (&self.lost_packets) |*lp| lp.deinit(self.allocator);
        self.events.deinit(self.allocator);
        var datagram_out_it = self.datagram_out.iterator();
        while (datagram_out_it.next()) |d| self.allocator.free(d);
        self.datagram_out.deinit(self.allocator);
        var datagram_in_it = self.datagram_in.iterator();
        while (datagram_in_it.next()) |d| self.allocator.free(d);
        self.datagram_in.deinit(self.allocator);
        if (self.initial_token.len != 0) self.allocator.free(self.initial_token);
        if (self.stored_new_token.len != 0) self.allocator.free(self.stored_new_token);
        if (self.new_token_override.len != 0) self.allocator.free(self.new_token_override);
        self.allocator.destroy(self);
    }

    fn zeroPacketKeys(self: *Connection) void {
        for (&self.write_keys) |*slot| zeroPacketKeySlot(slot);
        for (&self.read_keys) |*slot| zeroPacketKeySlot(slot);
    }

    /// Zero every connection-owned secret before free. Uses secureZero so the
    /// compiler cannot elide the wipe. TLS-owned material is scrubbed by
    /// `self.tls.destroy()` separately.
    fn scrubSecrets(self: *Connection) void {
        self.zeroPacketKeys();
        zeroPacketKeySlot(&self.crypto_1rtt.current);
        zeroPacketKeySlot(&self.crypto_1rtt.prev);
        zeroPacketKeySlot(&self.crypto_1rtt.next);
        std.crypto.secureZero(u8, self.app_write_secret[0..]);
        std.crypto.secureZero(u8, self.app_read_secret[0..]);
        self.app_write_secret_len = 0;
        self.app_read_secret_len = 0;
        std.crypto.secureZero(u8, self.retry_secret_key[0..]);
        if (self.reset_key) |*rk| std.crypto.secureZero(u8, rk[0][0..rk[1]]);
    }

    fn zeroPacketKeySlot(slot: *?packet_crypto.PacketKeys) void {
        if (slot.*) |*keys| {
            std.crypto.secureZero(u8, keys.aead_key[0..]);
            std.crypto.secureZero(u8, keys.iv[0..]);
            std.crypto.secureZero(u8, keys.hp_key[0..]);
            std.crypto.secureZero(u8, std.mem.asBytes(&keys.hp_ctx));
        }
        slot.* = null;
    }

    /// RFC 9001 §4.9.1/§4.9.2 event-driven key discard. noq drops a space's
    /// keys on handshake-progress events (first Handshake packet sent/received,
    /// confirmation, HANDSHAKE_DONE), not on a wall-clock timer; the 3×PTO
    /// timer stays armed as the backstop for abandoned handshakes.
    fn discardSpaceKeys(self: *Connection, space: spaces.SpaceId) void {
        const si = @intFromEnum(space);
        zeroPacketKeySlot(&self.write_keys[si]);
        zeroPacketKeySlot(&self.read_keys[si]);
        // noq discard_space (connection/mod.rs:4131-4156): the space's
        // outstanding sent-records leave loss tracking with the keys — their
        // content is never retransmitted into a dead space.
        var i: usize = 0;
        while (i < self.sent.items.len) {
            const sp = self.sent.items[i];
            if (sp.space == space) {
                self.notePacketLeftFlight(sp);
                _ = self.sent.orderedRemove(i);
            } else {
                i += 1;
            }
        }
        // Inventory must be empty for the discarded space even if a non-ack-
        // eliciting residual was present (counts only track ack-eliciting).
        self.clearPtoInflightSpace(space);
        self.needs_ack[si] = false;
        self.ack_deadline[si] = null;
    }

    /// Client kicks off ClientHello into Initial CRYPTO.
    pub fn startClient(self: *Connection) !void {
        if (self.role != .client) return error.UnexpectedState;
        var out = try tlsStart(self.tls, self.allocator);
        defer out.deinit();
        try self.queueTlsOutput(out);
    }

    pub fn pollTimeout(self: *const Connection) ?Instant {
        var next: ?Instant = null;
        if (self.idle_deadline) |d| next = minOpt(next, d);
        if (self.keep_alive_deadline) |d| next = minOpt(next, d);
        if (self.timers.close_deadline) |d| next = minOpt(next, d);
        if (self.timers.handshake_key_discard_deadline) |d| next = minOpt(next, d);
        if (self.timers.previous_key_discard_deadline) |d| next = minOpt(next, d);
        if (self.timers.path_challenge_deadline) |d| next = minOpt(next, d);
        if (self.ptoDeadline()) |d| next = minOpt(next, d);
        // RFC 9000 §13.2.1: a deferred ACK still has a deadline, and the pump
        // must wake for it or the peer's RTT sampling stalls.
        if (self.ackDeadline()) |d| next = minOpt(next, d);
        if (self.next_send_at > self.now and self.hasPacedOutbound()) {
            next = minOpt(next, self.next_send_at);
        }
        return next;
    }

    /// noq `peer_completed_handshake_address_validation` (mod.rs:3656-3670):
    /// servers (and closed connections) are always validated; a client is
    /// validated once any Handshake/Data packet of ours was ACKed, or we hold
    /// 1-RTT keys while the handshake keys are gone (HANDSHAKE_DONE seen).
    fn peerCompletedHandshakeAddressValidation(self: *const Connection) bool {
        if (self.role == .server) return true;
        switch (self.state) {
            .closed, .draining, .drained => return true,
            else => {},
        }
        if (self.spaces_state.getConst(.handshake).largest_acked != null) return true;
        if (self.spaces_state.getConst(.data).largest_acked != null) return true;
        const hs = @intFromEnum(spaces.SpaceId.handshake);
        const dt = @intFromEnum(spaces.SpaceId.data);
        if (self.write_keys[dt] != null and self.write_keys[hs] == null) return true;
        return false;
    }

    /// A5 (noq `pto_time_and_space`, mod.rs:3570-3587): the space the
    /// anti-amplification-deadlock PTO probes in — Handshake once we hold
    /// handshake write keys, else Initial. `null` unless we are a client whose
    /// address the server has not yet validated.
    fn antiDeadlockSpace(self: *const Connection) ?spaces.SpaceId {
        if (self.role != .client) return null;
        if (self.peerCompletedHandshakeAddressValidation()) return null;
        if (self.write_keys[@intFromEnum(spaces.SpaceId.handshake)] != null) return .handshake;
        return .initial;
    }

    /// G14: noq's max_interval selection for the PTO backoff cap
    /// (pto_time_and_space, mod.rs:3553-3565).
    fn ptoMaxIntervalNs(self: *const Connection) i64 {
        return loss.ptoMaxInterval(self.rtt, self.idle_timeout_ns);
    }

    /// PTO deadline (RFC 9002 §6.2.1): last ack-eliciting send + backoff, if any
    /// ack-eliciting packet is still outstanding. Application-data outstanding
    /// includes the peer's max_ack_delay term. G14: the backoff is capped at
    /// noq's max_interval per probe step, and the Application Data space only
    /// arms a PTO once the handshake is confirmed (RFC 9002 §6.2.1-7 /
    /// noq mod.rs:3592-3597).
    fn ptoDeadline(self: *const Connection) ?Instant {
        // O(1) hot path: inventory maintained by trackSent / rebuildPtoInflight.
        // Full `sent` scan was 21% of responder CPU when called every poll.
        var last: ?Instant = null;
        var data_outstanding = false;
        if (self.sent.items.len != 0) {
            // Lazy repair: tests that mutate `sent` without trackSent leave
            // counts at 0 while packets remain — rebuild once, then O(1).
            if (self.pto_inflight_count[0] + self.pto_inflight_count[1] + self.pto_inflight_count[2] == 0) {
                @constCast(self).rebuildPtoInflight();
            }
            for ([3]spaces.SpaceId{ .initial, .handshake, .data }) |space| {
                if (space == .data and !self.handshake_confirmed) continue;
                const si = @intFromEnum(space);
                if (self.pto_inflight_count[si] == 0) continue;
                if (self.pto_inflight_latest[si]) |t| {
                    last = if (last) |l| @max(l, t) else t;
                    if (space == .data) data_outstanding = true;
                }
            }
        }
        const t = last orelse {
            // A5: with zero ack-eliciting in flight pre-validation the PTO is
            // still armed (RFC 9000 §8.1 anti-amplification deadlock guard),
            // based on the last ack-eliciting packet we sent in the probe
            // space so re-arming cannot slide the deadline forward forever.
            const space = self.antiDeadlockSpace() orelse return null;
            const base = self.last_ack_eliciting_sent[@intFromEnum(space)] orelse
                self.last_ack_eliciting_sent[@intFromEnum(spaces.SpaceId.initial)] orelse
                return null;
            return base + loss.ptoDelayAntiDeadlock(self.rtt, self.pto_count, self.ptoMaxIntervalNs());
        };
        const mad: i64 = if (data_outstanding) self.peerMaxAckDelayNs() else 0;
        return t + loss.ptoDelay(self.rtt, self.pto_count, mad, self.ptoMaxIntervalNs());
    }

    fn notePtoInflightAdd(self: *Connection, sp: SentPacket) void {
        if (!sp.ack_eliciting) return;
        const si = @intFromEnum(sp.space);
        self.pto_inflight_count[si] +|= 1;
        self.pto_inflight_latest[si] = if (self.pto_inflight_latest[si]) |l|
            @max(l, sp.time_sent)
        else
            sp.time_sent;
    }

    /// Full rebuild of the PTO in-flight inventory from `sent`. Called after
    /// bulk removal (ACK/PTO/space discard) so `ptoDeadline` stays O(1) and
    /// correct even when tests append to `sent` without `trackSent`.
    fn rebuildPtoInflight(self: *Connection) void {
        self.pto_inflight_count = .{ 0, 0, 0 };
        self.pto_inflight_latest = .{ null, null, null };
        for (self.sent.items) |sp| {
            if (!sp.ack_eliciting) continue;
            const si = @intFromEnum(sp.space);
            self.pto_inflight_count[si] +|= 1;
            self.pto_inflight_latest[si] = if (self.pto_inflight_latest[si]) |l|
                @max(l, sp.time_sent)
            else
                sp.time_sent;
        }
    }

    fn clearPtoInflightSpace(self: *Connection, space: spaces.SpaceId) void {
        const si = @intFromEnum(space);
        self.pto_inflight_count[si] = 0;
        self.pto_inflight_latest[si] = null;
    }

    /// Peer max_ack_delay in nanoseconds (RFC 9000 §18.2 / ACK_FREQUENCY override).
    fn peerMaxAckDelayNs(self: *const Connection) i64 {
        // ACK_FREQUENCY `request_max_ack_delay` is microseconds when set.
        if (self.peer_ack_max_ack_delay) |us| {
            const ns = std.math.mul(u64, us, 1000) catch return std.math.maxInt(i64);
            return @intCast(@min(ns, @as(u64, @intCast(std.math.maxInt(i64)))));
        }
        // Transport-parameter `max_ack_delay` is milliseconds (default 25).
        const ns = std.math.mul(u64, self.peer_params.max_ack_delay, 1_000_000) catch return std.math.maxInt(i64);
        return @intCast(@min(ns, @as(u64, @intCast(std.math.maxInt(i64)))));
    }

    /// Scale a wire ACK Delay field to nanoseconds and cap by max_ack_delay
    /// (RFC 9000 §19.3 / RFC 9002 §5). Non-data spaces use delay 0.
    fn scaledAckDelayNs(self: *const Connection, space: spaces.SpaceId, wire_ack_delay: u64) i64 {
        if (space != .data) return 0;
        // Wire unit is microseconds · 2^ack_delay_exponent. Cap exponent at 20
        // (RFC 9000 §18.2 illegal if >20); use saturating mul for overflow.
        const exp: u6 = @intCast(@min(self.peer_params.ack_delay_exponent, 20));
        const scale: u64 = @as(u64, 1) << exp;
        const shifted = std.math.mul(u64, wire_ack_delay, scale) catch std.math.maxInt(u64);
        const delay_ns_u = std.math.mul(u64, shifted, 1000) catch std.math.maxInt(u64);
        const delay_ns: i64 = @intCast(@min(delay_ns_u, @as(u64, @intCast(std.math.maxInt(i64)))));
        return @min(delay_ns, self.peerMaxAckDelayNs());
    }

    pub fn poll(self: *Connection) ?Event {
        return self.events.popFront();
    }

    /// A5: historical Connection method name kept (forwards to Session.popNewSessionTicket).
    pub fn popZigtlsNewSessionTicket(self: *Connection) if (crypto.zigtls_enabled) ?crypto.Types.NewSessionTicketInfo else ?void {
        if (comptime crypto.zigtls_enabled) {
            return self.tls.popNewSessionTicket();
        } else {
            return null;
        }
    }

    /// A5: historical Connection method name kept (forwards to Session.wasResumed).
    pub fn wasZigtlsResumed(self: *const Connection) bool {
        return self.tls.wasResumed();
    }

    /// Discard queued events (used by drivers/tests that poll state directly).
    pub fn drainEvents(self: *Connection) void {
        while (self.events.popFront() != null) {}
    }

    pub fn handleTimeout(self: *Connection, now: Instant) void {
        self.now = now;
        if (self.idle_deadline) |d| {
            if (now >= d and self.state != .closed and self.state != .draining and self.state != .drained) {
                self.state = .{ .draining = .{ .is_local = false, .reason = "idle-timeout" } };
                self.timers.armClose(now);
                self.events.pushBack(self.allocator, .{ .connection_lost = .{ .is_local = false, .reason = "idle-timeout" } }) catch {};
                return;
            }
        }
        if (self.timers.close_deadline) |d| {
            if (now >= d and (self.state == .closed or self.state == .draining)) {
                self.state = .{ .drained = .{ .is_local = true } };
            }
        }
        if (self.timers.handshake_key_discard_deadline) |d| {
            if (now >= d) {
                const hs = @intFromEnum(spaces.SpaceId.handshake);
                // noq discards client Handshake keys only on HANDSHAKE_DONE
                // (connection/mod.rs:5262): zeroing them while our own
                // handshake flight is unsent, lost-awaiting-retransmit, or
                // unacked strands the handshake permanently — the peer never
                // receives our Finished and the connection idles out. The arm
                // fires at `established` (TLS complete), which for a client
                // can precede the Finished's first transmission, so the fire
                // must wait out an outstanding flight: re-arm instead.
                const flight_outstanding =
                    self.crypto_out[hs].items.len > self.crypto_sent[hs] or
                    self.crypto_rtx[hs].len > 0 or
                    self.pto_inflight_count[hs] > 0;
                if (flight_outstanding) {
                    self.timers.armHandshakeKeyDiscard(now);
                } else {
                    const initial = @intFromEnum(spaces.SpaceId.initial);
                    const handshake = @intFromEnum(spaces.SpaceId.handshake);
                    zeroPacketKeySlot(&self.write_keys[initial]);
                    zeroPacketKeySlot(&self.read_keys[initial]);
                    zeroPacketKeySlot(&self.write_keys[handshake]);
                    zeroPacketKeySlot(&self.read_keys[handshake]);
                    self.timers.handshake_key_discard_deadline = null;
                }
            }
        }
        if (self.timers.previous_key_discard_deadline) |d| {
            if (now >= d) {
                zeroPacketKeySlot(&self.crypto_1rtt.prev);
                self.timers.previous_key_discard_deadline = null;
            }
        }
        // PATH_CHALLENGE retransmission with PTO backoff (RFC 9000 §8.2.4).
        if (self.timers.path_challenge_deadline) |d| {
            if (now >= d) {
                const max_challenge_attempts: u8 = 5;
                if (self.challenge_await_len == 0 or self.timers.path_challenge_attempts >= max_challenge_attempts) {
                    // The path probe is declared dead: stop re-driving AND
                    // retire the outstanding tokens — a late response to a dead
                    // probe must not validate (noq resets challenge state on
                    // validation failure), and future probes must be possible.
                    self.timers.path_challenge_deadline = null;
                    self.timers.path_challenge_attempts = 0;
                    self.challenge_await_len = 0;
                } else {
                    self.timers.path_challenge_attempts += 1;
                    var i: usize = 0;
                    while (i < self.challenge_await_len) : (i += 1) {
                        if (self.challenge_pending_len < max_path_tokens) {
                            self.challenge_pending[self.challenge_pending_len] = self.challenge_await[i];
                            self.challenge_pending_hints[self.challenge_pending_len] = self.challenge_await_hints[i];
                            self.challenge_pending_len += 1;
                        }
                    }
                    self.timers.path_challenge_deadline = now + loss.ptoDelay(self.rtt, self.timers.path_challenge_attempts, 0, self.ptoMaxIntervalNs());
                }
            }
        }
        // G18 (noq ConnTimer::KeepAlive → Connection::ping, mod.rs:2439-2441):
        // the interval elapsed with no authenticated packet from the peer —
        // keep the connection alive with a data-space PING. Like noq the
        // timer is one-shot: it re-arms on the next authenticated packet
        // (reset_keep_alive, mod.rs:3863-3880).
        if (self.keep_alive_deadline) |d| {
            if (now >= d) {
                self.keep_alive_deadline = null;
                if (self.state == .established) {
                    self.pending_ping[@intFromEnum(spaces.SpaceId.data)] = true;
                }
            }
        }
        // Delayed-ACK expiry (RFC 9000 §13.2.1): an ACK deferred below the
        // ack-eliciting threshold still owes the peer a response within
        // `max_ack_delay`.
        self.handleAckTimeout(now);
        // PTO backstop (RFC 9002 §6.2): when data is outstanding and no ACKs are
        // arriving, probe by re-queuing the oldest outstanding packet's frames.
        if (self.ptoDeadline()) |d| {
            if (now >= d) self.onPtoExpiry();
        }
    }

    fn onPtoExpiry(self: *Connection) void {
        // G14 (noq on_loss_detection_timeout, mod.rs:3230-3244): a
        // conventional PTO queues TWO probe packets; only the
        // anti-amplification-deadlock PTO (zero ack-eliciting in flight
        // pre-validation, handled below) sends one. Mirror by re-queuing the
        // TWO oldest outstanding ack-eliciting packets' frames. The data
        // space is skipped pre-handshake-confirm exactly like the arming
        // gate in ptoDeadline (RFC 9002 §6.2.1-7).
        var picks: [2]?usize = .{ null, null };
        for (self.sent.items, 0..) |sp, i| {
            if (!sp.ack_eliciting) continue;
            if (sp.space == .data and !self.handshake_confirmed) continue;
            if (picks[0] == null or sp.time_sent < self.sent.items[picks[0].?].time_sent) {
                picks[1] = picks[0];
                picks[0] = i;
            } else if (picks[1] == null or sp.time_sent < self.sent.items[picks[1].?].time_sent) {
                picks[1] = i;
            }
        }
        if (picks[0] != null) {
            // Remove the HIGHER index first so orderedRemove keeps the other
            // pick valid.
            const ordered: [2]?usize = if (picks[1] != null and picks[1].? > picks[0].?)
                .{ picks[1], picks[0] }
            else
                picks;
            var any_data = false;
            var any_empty = false;
            for (ordered) |maybe_i| {
                const i = maybe_i orelse continue;
                const sp = self.sent.items[i];
                const requeued_all = self.requeueContent(sp);
                self.stats_pto_events += 1;
                if (requeued_all) {
                    self.notePacketLeftFlight(sp);
                    _ = self.sent.orderedRemove(i);
                }
                if (sp.space == .data) any_data = true;
                if (sp.content_len == 0) any_empty = true;
            }
            self.rebuildPtoInflight();
            self.reclaimResetStreams();
            self.pto_count +|= 1;
            // G13 (noq queue_tail_loss_probe with request_immediate_ack =
            // `space == Data && peer_supports_ack_frequency`, mod.rs:1539-1546):
            // a data-space tail-loss probe asks for an un-delayed ACK. noq's
            // peer-supports check is the min_ack_delay TP — F11 (not landed);
            // this stack treats ack-frequency as always-on (it emits
            // ACK_FREQUENCY and honors IMMEDIATE_ACK unconditionally).
            if (any_data) self.pending_immediate_ack = true;
            // A5 (noq queue_tail_loss_probe, spaces.rs:114-138): a PTO whose
            // retransmission came up EMPTY (a contentless PING probe has no
            // retransmittable frames) falls back to a fresh PING while the
            // anti-deadlock guard is active — otherwise a lost probe
            // re-deadlocks the handshake.
            if (any_empty) {
                if (self.antiDeadlockSpace()) |space| {
                    const si = @intFromEnum(space);
                    const has_pending = self.crypto_rtx[si].len > 0 or
                        self.crypto_out[si].items.len > self.crypto_sent[si];
                    if (!has_pending) self.pending_ping[si] = true;
                }
            }
            return;
        }
        // A5 (noq on_loss_detection_timeout mod.rs:3231-3243 +
        // queue_tail_loss_probe spaces.rs:97-138): a PTO with ZERO ack-eliciting
        // in flight pre-validation is the handshake anti-amplification
        // deadlock guard — send exactly ONE probe. noq prefers pending data,
        // then retransmits, and only makes up a PING when nothing else exists.
        const space = self.antiDeadlockSpace() orelse return;
        const si = @intFromEnum(space);
        const has_pending = self.crypto_rtx[si].len > 0 or
            self.crypto_out[si].items.len > self.crypto_sent[si];
        if (!has_pending) self.pending_ping[si] = true;
        self.stats_pto_events += 1;
        self.pto_count +|= 1;
    }

    /// The ALPN the TLS handshake selected for this connection. Backs the
    /// wire-neutral `transport.Connection.alpn()` seam the multi-ALPN Router
    /// dispatches on (`src/shared/protocol.zig`).
    pub fn negotiatedProtocol(self: *Connection) ?[]const u8 {
        return self.tls.negotiatedProtocol();
    }

    /// RFC 9001 §7.5 / RFC 5705 exporter: derive keying material from
    /// this connection's TLS session. Both peers derive identical bytes for
    /// identical label/context — this is the surface iroh's endpoint depends
    /// on (`noq::Connection::export_keying_material`).
    pub fn exportKeyingMaterial(self: *Connection, label: [:0]const u8, context_value: []const u8, out: []u8) !void {
        if (self.state != .established and !self.handshake_confirmed) return error.IncompleteHandshake;
        return self.tls.exportSecret(label, context_value, out);
    }

    pub fn close(self: *Connection, now: Instant) void {
        self.closeWith(now, .{ .error_code = 0, .reason = "closed", .is_app = true });
    }

    /// Close emitting an explicit CONNECTION_CLOSE frame the peer will observe.
    pub fn closeWith(self: *Connection, now: Instant, cc: frame.ConnectionClose) void {
        self.now = now;
        switch (self.state) {
            .closed, .draining, .drained => return,
            else => {},
        }
        self.state = .{ .closed = .{ .is_local = true, .reason = cc.reason } };
        self.close_frame = cc;
        self.close_sent = false;
        self.close_sent_mask = 0;
        self.timers.armClose(now);
        self.events.pushBack(self.allocator, .{ .connection_lost = .{ .is_local = true, .reason = cc.reason } }) catch {};
    }

    /// Drive one outbound datagram (if anything to send). Returns a slice into
    /// `tx_coalesce` (or the stash for a carried-over followup packet).
    ///
    /// A3 send-side coalescing (noq `poll_transmit_on_path` /
    /// `poll_transmit_path_space`, connection/mod.rs:1292-1373, 1407-1802):
    /// spaces ascend Initial → Handshake → Data; after a long-header packet,
    /// the next space's packet is appended to the same UDP datagram while the
    /// noq predicate holds (mod.rs:1739-1747): long header (always true for
    /// Initial/Handshake), remaining datagram room > MIN_PACKET_SPACE, the
    /// current space fully drained, and the next space able to send. The
    /// RFC 9000 §14.1 ≥1200 floor for a datagram carrying a client Initial is
    /// carried forward (`pad_to`) and applied to the LAST packet's min size,
    /// exactly like noq's `PadDatagram::ToMinMtu` (mod.rs:1603-1608).
    pub fn pollTransmit(self: *Connection, now: Instant) Error!?Transmit {
        self.now = now;
        self.handleTimeout(now);
        if (self.state == .drained) return null;

        // A stashed followup is already sealed and tracked as sent: it must be
        // the next thing on the wire before any new packet is built.
        if (self.stash_len > 0) {
            const tx: Transmit = .{ .bytes = self.stash_buf[0..self.stash_len], .ecn = self.stash_ecn };
            self.stash_len = 0;
            return tx;
        }

        var total: usize = 0; // bytes accumulated in tx_coalesce
        var pad_to: usize = 0; // RFC 9000 §14.1 floor for this datagram
        var ecn: ?udp_cmsg.EcnCodepoint = null;
        var have_packet = false;

        var space: spaces.SpaceId = .initial;
        spaces: while (true) {
            var wire_cap: usize = max_datagram;
            var initial_pad: usize = 0;
            var initial_requires_pad = false;
            var extra_min_size: usize = 0;
            if (space == .initial) {
                // RFC 9000 §14.1 / noq PadDatagram::ToMinMtu: client Initial
                // datagrams always carry the 1200 floor; server Initial
                // datagrams carry it when the Initial packet is ack-eliciting
                // (CRYPTO or a loss-probe PING). Decide the coalescing pad split
                // BEFORE the Initial is sealed — an unpadded Initial is only
                // legal when the Handshake followup is guaranteed to be built
                // and to carry the 1200 pad.
                initial_requires_pad = self.initialDatagramRequiresPadding();
                initial_pad = if (initial_requires_pad) min_client_initial_datagram_size else 0;
                if (initial_requires_pad and self.canCoalesceInitialIntoHandshake()) initial_pad = 0;
            } else if (have_packet) {
                // Followup attempt into the open datagram.
                const cap = self.datagramCoalesceCap();
                if (cap -| total <= min_packet_space) break :spaces;
                if (self.sent.items.len + 1 >= max_tracked_sent_packets) break :spaces;
                wire_cap = (cap - total) -| packet_header_reserve;
                extra_min_size = pad_to -| total;
            }
            if (space == .data) {
                // Data space runs once 1-RTT keys exist: established
                // (streams/control) or while emitting a pending
                // CONNECTION_CLOSE after a local close or a peer's close.
                // 0-RTT is the pre-1-RTT exception (RFC 9001 §5): a client
                // with a live early WRITE key offers stream/datagram data in
                // 0-RTT long-header packets (noq has_0rtt + is_0rtt sends).
                if (!(self.state == .established or self.handshake_confirmed or self.close_frame != null or self.drain_close_pending or self.zeroRttSendActive())) break :spaces;
                // A destination-hinted probe rides STANDALONE — mixing it
                // with same-connection frames would send them to the wrong
                // address. Defer it until the next datagram if a long-header
                // packet already occupies this one.
                if (have_packet) {
                    for (self.challenge_pending_hints[0..self.challenge_pending_len]) |hint| {
                        if (hint != null) break :spaces;
                    }
                } else if (!self.zeroRttSendActive()) {
                    if (self.takeHintedProbe()) |probe| {
                        const data_si = @intFromEnum(spaces.SpaceId.data);
                        const keys = self.write_keys[data_si] orelse return null;
                        const probe_frames = [_]frame.Frame{.{ .path_challenge = probe.token }};
                        var probe_content: [max_content]FrameRef = undefined;
                        const pn = self.spaces_state.get(.data).getTxNumber();
                        var tx = try self.finishPacket(.data, keys, &probe_frames, &probe_content, 0, true, pn, min_client_initial_datagram_size, 0, 0, false);
                        tx.dest_hint = probe.hint;
                        return tx;
                    }
                }
                // MTU probes fly solo: a probe's whole point is its exact
                // padded size, which a coalesced datagram would corrupt.
                if (have_packet and self.probe_mtu != null) break :spaces;
                const pacing = self.dataPacingRate();
                if (pacing) |rate| {
                    if (rate > 0) {
                        if (self.next_send_at == 0) self.resetPacingBudget();
                        self.refillPacingTokens(self.now, rate);
                        // Pace STREAM/CRYPTO bytes only. Control frames (ACK,
                        // NEW_TOKEN, PATH_*, NAT, ...) can still be built below.
                        if (self.hasPacedOutbound()) {
                            if (self.congestionSendWindow() == 0) self.stats_cc_limited += 1;
                            self.pace_content_blocked = !self.hasPacingBudgetForContent();
                        }
                        defer self.pace_content_blocked = false;
                    }
                }
            }

            const tx = (try self.buildSpacePacket(space, wire_cap, initial_pad, extra_min_size)) orelse {
                // Nothing sendable in this space. If nothing has been built
                // yet, fall through to the next space (today's behavior).
                // A null followup always leaves pad satisfied: pad_to > 0
                // only for a client-Initial datagram, whose Handshake
                // followup is guaranteed by canCoalesceInitialIntoHandshake.
                if (!have_packet and space != .data) {
                    space = if (space == .initial) .handshake else .data;
                    continue :spaces;
                }
                break :spaces;
            };

            if (!have_packet) {
                have_packet = true;
                if (space == .initial and initial_requires_pad) pad_to = min_client_initial_datagram_size;
                @memcpy(self.tx_coalesce[0..tx.bytes.len], tx.bytes);
                total = tx.bytes.len;
                ecn = tx.ecn;
                // A short-header (1-RTT) packet carries no Length field:
                // nothing may follow it in a datagram.
                if (space == .data) break :spaces;
            } else {
                if (total + tx.bytes.len <= max_datagram) {
                    @memcpy(self.tx_coalesce[total..][0..tx.bytes.len], tx.bytes);
                    total += tx.bytes.len;
                    ecn = tx.ecn;
                    self.stats_coalesced_packets += 1;
                } else {
                    // Sealed and tracked but over the datagram cap: stash it
                    // for the next call rather than exceed max_datagram.
                    @memcpy(self.stash_buf[0..tx.bytes.len], tx.bytes);
                    self.stash_len = tx.bytes.len;
                    self.stash_ecn = tx.ecn;
                    self.stats_coalesce_stashed += 1;
                    break :spaces;
                }
                if (space == .data) break :spaces;
            }
            // Coalesce onward only if this space is fully drained (noq
            // `space_can_send(current).is_empty()`, mod.rs:1743-1745). A close
            // is exempt: it rides in EVERY keyed space (B2, noq returns
            // WrotePacket unconditionally at mod.rs:1690-1693), so a
            // not-yet-drained space must not strand the next space's close.
            const closing = self.state == .closed or self.state == .draining;
            if (!closing and !self.longSpaceDrained(space)) break :spaces;
            space = if (space == .initial) .handshake else .data;
        }

        if (!have_packet) return null;
        // The §14.1 floor is structural (see the null-followup comment above);
        // a miss here is a bug in the coalescing predicate, not valid output.
        std.debug.assert(total >= pad_to);
        return .{ .bytes = self.tx_coalesce[0..total], .ecn = ecn };
    }

    /// noq `TransmitBuf::segment_size` for the coalescing decision: the
    /// current path MTU, bounded by the scratch size. During the handshake
    /// (where coalescing happens) this is min_mtu until PMTUD raises it.
    fn datagramCoalesceCap(self: *const Connection) usize {
        return @min(@as(usize, self.mtu), max_datagram);
    }

    /// Post-build check mirroring noq's `space_can_send(current).is_empty()`
    /// coalesce precondition: true when an Initial/Handshake build has drained
    /// every frame source of `space` (ACK obligation discharged, no crypto
    // bytes left unsent or queued for retransmit, no pending PING probe).
    fn longSpaceDrained(self: *const Connection, space: spaces.SpaceId) bool {
        const si = @intFromEnum(space);
        if (self.needs_ack[si] and self.pending_acks[si].toAckFrame(0) != null) return false;
        if (self.crypto_rtx[si].len > 0) return false;
        if (self.crypto_out[si].items.len > @as(usize, @intCast(self.crypto_sent[si]))) return false;
        if (self.pending_ping[si]) return false;
        return true;
    }

    fn initialDatagramRequiresPadding(self: *const Connection) bool {
        if (self.role == .client) return true;
        if (self.state == .closed or self.state == .draining) return false;
        const si = @intFromEnum(spaces.SpaceId.initial);
        if (self.crypto_rtx[si].len > 0) return true;
        if (self.crypto_out[si].items.len > @as(usize, @intCast(self.crypto_sent[si]))) return true;
        if (self.pending_ping[si]) return true;
        return false;
    }

    /// Exact simulation of the frame sources `buildSpacePacket` can emit for a
    /// long-header (Initial/Handshake) space — ACK, CRYPTO (rtx then fresh),
    /// PING — with the builder's own budget accounting. `drained` is the
    /// post-build counterpart of `longSpaceDrained`, computed without
    /// mutating any send cursor.
    const LongSpaceSim = struct { frame_bytes: usize, drained: bool };
    fn simLongSpace(self: *const Connection, space: spaces.SpaceId) LongSpaceSim {
        const si = @intFromEnum(space);
        var budget: usize = base_data_payload_budget;
        var frame_bytes: usize = 0;
        var n: usize = 0; // frames used (builder cap: frames[16])
        var cn: usize = 0; // content entries (builder cap: max_content)
        var drained = true;

        if (self.needs_ack[si]) {
            // G5: simulate with the REAL ack_delay so the varint size in the
            // budget math matches what emitOwedAck will actually encode.
            if (self.pending_acks[si].toAckFrame(self.wireAckDelay(si))) |ack_base| {
                var ack = ack_base;
                const ecn_nonempty = self.ecn_counts.ect0 != 0 or self.ecn_counts.ect1 != 0 or self.ecn_counts.ce != 0;
                if (ecn_nonempty) ack.ecn = self.ecn_counts;
                const f: frame.Frame = .{ .ack = ack };
                frame_bytes += f.encodedLen();
                budget -|= f.encodedLen();
                n += 1;
            }
        }

        var it = self.crypto_rtx[si].iterator();
        while (it.next()) |chunk| {
            if (!(n < 16 and cn < max_content and budget > 64)) {
                drained = false;
                break;
            }
            const take: usize = @intCast(@min(chunk.len, budget - 32));
            frame_bytes += take + 8; // builder debits len + 8 per CRYPTO frame
            budget -|= take + 8;
            n += 1;
            cn += 1;
            if (take < chunk.len) {
                drained = false;
                break;
            }
        }

        const sent_hw: usize = @intCast(self.crypto_sent[si]);
        const avail = self.crypto_out[si].items.len -| sent_hw;
        if (avail > 0) {
            if (n < 16 and cn < max_content and budget > 64) {
                const take = @min(avail, budget - 32);
                frame_bytes += take + 8;
                budget -|= take + 8;
                n += 1;
                if (take < avail) drained = false;
            } else {
                drained = false;
            }
        }

        if (self.pending_ping[si]) {
            if (n < 16) {
                frame_bytes += 1;
            } else {
                drained = false;
            }
        }
        return .{ .frame_bytes = frame_bytes, .drained = drained };
    }

    /// noq coalesce predicate (mod.rs:1739-1747) specialized for the one hop
    /// where the §14.1 pad must move off the first packet: client
    /// Initial → Handshake. Every condition that could make the Handshake
    /// build return null is checked here, so that building the Initial
    /// unpadded is guaranteed safe:
    ///   - Handshake keys exist, AEAD budget remains, sent-record slots remain;
    ///   - the Initial build will fully drain its space (else noq would not
    ///     coalesce either — the Initial is then built padded, as before);
    ///   - the Initial leaves enough of the 1200 floor for the Handshake
    ///     packet (its CRYPTO emit needs budget > 64 after the header);
    ///   - the Handshake space has at least one frame to send.
    /// The client is never anti-amplification limited, so that exit cannot
    /// fire. A prediction miss would ship a sub-1200 client-Initial datagram;
    /// `pollTransmit` asserts the floor before returning.
    fn canCoalesceInitialIntoHandshake(self: *Connection) bool {
        const hi = @intFromEnum(spaces.SpaceId.handshake);
        if (self.write_keys[hi] == null) return false;
        if (self.remainingPacketBudget(.handshake) == 0) return false;
        if (self.sent.items.len + 2 > max_tracked_sent_packets) return false;
        const sim_i = self.simLongSpace(.initial);
        if (!sim_i.drained) return false;
        // The Handshake followup's budget is (1200 - actual Initial wire -
        // header reserve); its CRYPTO emit needs budget > 64. 128 leaves
        // generous margin over 64 + the few bytes the wire estimate can
        // undershoot (CID lengths, varint sizes).
        const initial_wire_max = sim_i.frame_bytes + packet_header_reserve;
        if (initial_wire_max + packet_header_reserve + 128 > min_client_initial_datagram_size) return false;
        const sim_h = self.simLongSpace(.handshake);
        if (sim_h.frame_bytes == 0) return false;
        return true;
    }

    fn dataPacingRate(self: *const Connection) ?u64 {
        return self.test_pacing_rate orelse if (self.cc) |cc| cc.pacingRate() else null;
    }

    fn resetPacingBudget(self: *Connection) void {
        self.pacing_tokens = 0;
        self.pacing_last_refill_at = null;
    }

    fn refillPacingTokens(self: *Connection, now: Instant, rate: u64) void {
        const capacity = self.pacingCapacity();
        if (capacity == 0) {
            self.pacing_tokens = 0;
            self.pacing_last_refill_at = now;
            self.next_send_at = now + 1;
            return;
        }

        if (self.pacing_last_refill_at) |last| {
            if (now > last) {
                const elapsed: u64 = @intCast(now - last);
                const added_raw = (@as(u128, elapsed) * @as(u128, rate)) / @as(u128, std.time.ns_per_s);
                const added: u64 = if (added_raw > std.math.maxInt(u64)) std.math.maxInt(u64) else @intCast(added_raw);
                self.pacing_tokens = @min(capacity, self.pacing_tokens +| added);
                self.pacing_last_refill_at = now;
            }
        } else {
            self.pacing_tokens = capacity;
            self.pacing_last_refill_at = now;
        }
        if (self.pacing_tokens > capacity) self.pacing_tokens = capacity;
        self.updatePacingDeadline(rate);
    }

    /// noq pacing.rs burst geometry: the pacer emits a burst of `capacity`
    /// bytes per interval — TARGET_BURST_INTERVAL worth of the congestion
    /// window, clamped to [MIN_BURST_SIZE, MAX_BURST_SIZE] MTU and bounded by
    /// MAX_BURST_INTERVAL worth of the window.
    const pacing_target_burst_interval_ns: u128 = 2 * std.time.ns_per_ms;
    const pacing_max_burst_interval_ns: u128 = 10 * std.time.ns_per_ms;
    const pacing_min_burst_size: u64 = 10; // MTU units (noq MIN_BURST_SIZE)
    const pacing_max_burst_size: u64 = 256; // MTU units (noq MAX_BURST_SIZE)

    fn pacingCapacity(self: *Connection) u64 {
        const room = self.congestionSendWindow();
        if (room == 0) return 0;

        const mtu = @as(u64, self.mtu);
        var capacity = mtu;
        if (self.cc) |cc| {
            if (cc.sendQuantum()) |quantum| {
                if (quantum > capacity) capacity = quantum;
            }
        }
        const effective_window = if (self.test_cwnd_cap) |cap| cap else if (self.cc) |cc| cc.window() else mtu * 10;
        // noq optimal_capacity (pacing.rs:168-187). The pre-fix port
        // hard-capped the burst at min(window/4, 10 MTU): on a low-RTT path
        // that throttles every pacing release to ~10 packets, so in-flight
        // tracking never grows past a few bursts even when the congestion
        // window is hundreds of KB — the N-0 LOSSY peak_sent <= 64 stall.
        const rtt_ns: u128 = @intCast(@max(self.rtt.get(), 1));
        const window: u128 = effective_window;
        const target_raw: u64 = @intCast(@min(window * pacing_target_burst_interval_ns / rtt_ns, std.math.maxInt(u64)));
        const target = std.math.clamp(target_raw, pacing_min_burst_size * mtu, pacing_max_burst_size * mtu);
        const max_capacity: u64 = @intCast(@min(window * pacing_max_burst_interval_ns / rtt_ns, std.math.maxInt(u64)));
        const burst = @min(@max(max_capacity, mtu), target);
        capacity = @max(capacity, burst);
        return @min(capacity, room);
    }

    fn pacingMinSendBytes(self: *Connection) u64 {
        const room = self.congestionSendWindow();
        if (room == 0) return std.math.maxInt(u64);
        return @min(@as(u64, self.mtu), room);
    }

    fn hasPacingBudgetForContent(self: *Connection) bool {
        return self.pacing_tokens >= self.pacingMinSendBytes();
    }

    fn pacingDelayForBytes(bytes: u64, rate: u64) i64 {
        const numerator = @as(u128, bytes) * @as(u128, std.time.ns_per_s) + @as(u128, rate - 1);
        const raw = numerator / @as(u128, rate);
        const bounded = @min(raw, @as(u128, @intCast(std.math.maxInt(i64))));
        return @max(@as(i64, @intCast(bounded)), 1);
    }

    fn updatePacingDeadline(self: *Connection, rate: u64) void {
        const min_send = self.pacingMinSendBytes();
        if (min_send == std.math.maxInt(u64)) {
            self.next_send_at = self.now + 1;
            return;
        }
        if (self.pacing_tokens >= min_send) {
            self.next_send_at = if (self.now == 0) 1 else self.now;
            return;
        }
        self.next_send_at = self.now + pacingDelayForBytes(min_send - self.pacing_tokens, rate);
    }

    fn debitPacingBytes(self: *Connection, bytes: u64, rate: u64) void {
        self.pacing_tokens -|= bytes;
        self.updatePacingDeadline(rate);
    }

    fn hasPacedOutbound(self: *const Connection) bool {
        for (&self.streams) |*s| {
            if (!s.used) continue;
            if (s.send.rtx.len > 0) return true;
            if (s.send.endOffset() > s.send.send_next) return true;
        }
        var si: usize = 0;
        while (si < self.crypto_out.len) : (si += 1) {
            if (self.crypto_rtx[si].len > 0) return true;
            if (self.crypto_out[si].items.len > @as(usize, @intCast(self.crypto_sent[si]))) return true;
        }
        return false;
    }

    pub fn statelessResetToken(self: *const Connection) [packet.stateless_reset_token_len]u8 {
        return self.stateless_reset_token;
    }

    /// Local CIDs that have been committed to an outbound
    /// NEW_CONNECTION_ID frame. The transport must register each one with its
    /// datagram router before publishing the frame on the wire.
    pub fn localConnectionId(self: *const Connection, index: usize) ?packet.ConnectionId {
        if (index >= self.local_cid_len) return null;
        return self.local_cids[index].cid;
    }

    fn datagramFrameSize(payload_len: usize, with_length: bool) ?usize {
        const len_len = if (with_length) varint.size(@intCast(payload_len)) catch return null else 0;
        return std.math.add(usize, 1 + len_len, payload_len) catch null;
    }

    fn datagramPayloadMax(frame_limit: u64) ?usize {
        if (frame_limit == 0) return null;
        var candidate: usize = @intCast(@min(frame_limit -| 1, @as(u64, max_datagram)));
        while (true) {
            const frame_size = datagramFrameSize(candidate, true) orelse return null;
            if (frame_size <= frame_limit) return candidate;
            if (candidate == 0) return null;
            candidate -= 1;
        }
    }

    pub fn sendDatagram(self: *Connection, bytes: []const u8) Error!void {
        const max = self.maxDatagramSize() orelse return error.DatagramUnavailable;
        if (bytes.len > max) return error.DatagramTooLarge;
        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        // noq `Datagrams::send` with drop=true (`make_space_for`,
        // connection/datagrams.rs:143-151): bound the outgoing queue to
        // `datagram_send_buffer_size` payload bytes, discarding oldest first.
        while (self.datagram_out_total + copy.len > datagram_send_buffer_size) {
            const stale = self.takeDatagramOut() orelse break;
            self.allocator.free(stale);
        }
        try self.datagram_out.pushBack(self.allocator, copy);
        self.datagram_out_total += copy.len;
    }

    /// Pop the oldest queued outgoing datagram, debiting the send-buffer total.
    fn takeDatagramOut(self: *Connection) ?[]u8 {
        const d = self.datagram_out.popFront() orelse return null;
        self.datagram_out_total -= d.len;
        return d;
    }

    pub fn recvDatagram(self: *Connection) ?[]u8 {
        return self.datagram_in.popFront();
    }

    pub fn maxDatagramSize(self: *const Connection) ?usize {
        const peer_limit = self.peer_params.max_datagram_frame_size orelse return null;
        const local_limit = self.local_params.max_datagram_frame_size orelse return null;
        return datagramPayloadMax(@min(peer_limit, local_limit));
    }

    /// E12: fill the local CID inventory up to the peer's advertised
    /// `active_connection_id_limit` (capped at our slot count). noq issues
    /// `issue_first_cids` after the handshake and replaces on retire.
    fn maybeIssueCids(self: *Connection) Error!void {
        if (self.state != .established and !self.handshake_confirmed) return;
        if (!self.peer_params_applied) return;
        const target: usize = @intCast(@min(self.peer_params.active_connection_id_limit, max_local_cid_slots));
        const in_flight: usize = if (self.pending_new_cid) 1 else 0;
        if (self.local_cid_len + in_flight < target) try self.queueNewConnectionId();
    }

    pub fn queueNewConnectionId(self: *Connection) Error!void {
        if (self.pending_new_cid) return;
        if (self.local_cid_len >= max_local_cid_slots) return;
        var cid_bytes: [packet.max_cid_size]u8 = undefined;
        self.rng.fill(&cid_bytes);
        const cid_len: u8 = 8;
        self.pending_new_cid_len = cid_len;
        @memcpy(self.pending_new_cid_buf[0..cid_len], cid_bytes[0..cid_len]);
        if (self.reset_key) |rk| {
            // E3: endpoint-keyed token (noq endpoint.rs:642).
            const new_cid = packet.ConnectionId.init(self.pending_new_cid_buf[0..cid_len]) catch unreachable;
            self.pending_new_cid_reset = quic_token.resetToken(rk[0][0..rk[1]], new_cid);
        } else {
            self.rng.fill(&self.pending_new_cid_reset);
        }
        self.pending_new_cid_seq = self.next_cid_sequence;
        self.pending_new_cid_retire = if (self.next_cid_sequence > 0) self.next_cid_sequence - 1 else 0;
        self.next_cid_sequence += 1;
        self.pending_new_cid = true;
    }

    pub fn initiateKeyUpdate(self: *Connection) Error!void {
        if (self.state != .established or self.write_update_pending or self.crypto_1rtt.prev != null) {
            return error.UnexpectedState;
        }
        try self.advanceWriteKeys();
        self.write_update_pending = true;
    }

    fn advanceWriteKeys(self: *Connection) Error!void {
        const data_idx = @intFromEnum(spaces.SpaceId.data);
        const current_write = self.write_keys[data_idx] orelse return error.MissingKeys;
        const secret = try self.applicationWriteSecret();
        const next_secret = packet_crypto.nextTrafficSecret(secret);
        const next_keys = packet_crypto.keysFromKeyUpdate(&next_secret, current_write.hp_key);
        self.write_key_phase = !self.write_key_phase;
        self.write_keys[data_idx] = next_keys;
        @memcpy(self.app_write_secret[0..next_secret.len], &next_secret);
        self.app_write_secret_len = next_secret.len;
        self.key_update_count += 1;
        // A16 (noq `update_keys`, connection/packet_crypto.rs:407-409): the new
        // phase gets a fresh budget of confidentiality_limit − margin packets.
        self.sent_with_keys[data_idx] = 0;
        self.key_phase_size = packet_crypto.confidentiality_limit -| packet_crypto.key_update_margin;
    }

    /// Test helper: HKDF-derive and install next keys (same path as initiateKeyUpdate).
    pub fn installNextKeys(self: *Connection) Error!void {
        try self.initiateKeyUpdate();
    }

    fn applicationWriteSecret(self: *Connection) Error![]const u8 {
        if (self.app_write_secret_len != 0) return self.app_write_secret[0..self.app_write_secret_len];
        const sec = try self.tls.trafficSecret(.write, .application);
        @memcpy(self.app_write_secret[0..sec.len], sec.slice());
        self.app_write_secret_len = sec.len;
        return self.app_write_secret[0..self.app_write_secret_len];
    }

    fn applicationReadSecret(self: *Connection) Error![]const u8 {
        if (self.app_read_secret_len != 0) return self.app_read_secret[0..self.app_read_secret_len];
        const sec = try self.tls.trafficSecret(.read, .application);
        @memcpy(self.app_read_secret[0..sec.len], sec.slice());
        self.app_read_secret_len = sec.len;
        return self.app_read_secret[0..self.app_read_secret_len];
    }

    fn ensureReadKeysForPhase(self: *Connection, packet_key_phase: bool) Error!void {
        if (packet_key_phase == self.crypto_1rtt.key_phase) return;
        if (self.crypto_1rtt.next != null) return;
        const current_read = self.crypto_1rtt.current orelse return error.MissingKeys;
        const secret = try self.applicationReadSecret();
        const next_secret = packet_crypto.nextTrafficSecret(secret);
        self.crypto_1rtt.next = packet_crypto.keysFromKeyUpdate(&next_secret, current_read.hp_key);
    }

    fn commitReadKeyUpdate(self: *Connection, used_phase: packet_crypto.KeyPhase) Error!void {
        if (used_phase != .next) return;
        const confirms_local_update = self.write_update_pending;
        if (!confirms_local_update and self.remote_update_unacked) {
            self.protocolClose(err_key_update);
            return error.UnexpectedState;
        }
        const next = self.crypto_1rtt.next orelse return;
        self.crypto_1rtt.prev = self.crypto_1rtt.current;
        self.crypto_1rtt.current = next;
        self.crypto_1rtt.next = null;
        self.crypto_1rtt.key_phase = !self.crypto_1rtt.key_phase;
        self.read_keys[@intFromEnum(spaces.SpaceId.data)] = next;
        if (self.app_read_secret_len != 0) {
            const next_secret = packet_crypto.nextTrafficSecret(self.app_read_secret[0..self.app_read_secret_len]);
            @memcpy(self.app_read_secret[0..next_secret.len], &next_secret);
            self.app_read_secret_len = next_secret.len;
        }
        self.timers.armPreviousKeyDiscard(self.now);
        if (confirms_local_update) {
            self.write_update_pending = false;
        } else {
            // RFC 9001 §6: respond to a peer-initiated update by advancing our
            // sending keys before the next packet.
            if (self.write_key_phase != self.crypto_1rtt.key_phase) try self.advanceWriteKeys();
            self.remote_update_unacked = true;
        }
    }

    pub fn issueRetry(
        self: *Connection,
        original_dcid: packet.ConnectionId,
        client_scid: packet.ConnectionId,
        token_buf: []u8,
    ) Error![]u8 {
        if (self.role != .server) return error.UnexpectedState;
        self.rng.fill(token_buf[0..16]);
        @memcpy(token_buf[16 .. 16 + original_dcid.len], original_dcid.slice());
        const token = token_buf[0 .. 16 + original_dcid.len];
        const tmp = try packet.buildRetry(self.allocator, 1, client_scid, original_dcid, token, .{0} ** 16);
        defer self.allocator.free(tmp);
        const tag = try initial_keys.retryIntegrityTag(self.allocator, original_dcid.slice(), tmp[0 .. tmp.len - 16]);
        return try packet.buildRetry(self.allocator, 1, client_scid, original_dcid, token, tag);
    }

    /// Consume a Retry packet (E6 — the noq Header::Retry arm,
    /// connection/mod.rs:4540-4641): verify the integrity tag, adopt the Retry
    /// SCID, re-derive Initial keys FROM THE RETRY SCID (RFC 9000 §7.3.1:
    /// changing the DCID changes the Initial keys), reset the Initial PN
    /// space, and re-queue the ClientHello so the next Initial carries the
    /// token on the wire.
    pub fn consumeRetry(self: *Connection, datagram: []const u8) Error!void {
        if (self.role != .client) return error.UnexpectedState;
        const retry = try packet.parseRetry(datagram);
        if (retry.version != 1) return error.UnsupportedVersion;
        const prefix = try self.allocator.dupe(u8, datagram[0 .. datagram.len - 16]);
        defer self.allocator.free(prefix);
        const expected_tag = try initial_keys.retryIntegrityTag(self.allocator, self.initial_dcid.slice(), prefix);
        if (!std.mem.eql(u8, &expected_tag, &retry.integrity_tag)) return error.AuthenticationFailed;
        if (retry.token.len == 0) return error.EmptyPacket;
        // Dupe before free — an alloc failure must not leave a dangling slice.
        const new_token = try self.allocator.dupe(u8, retry.token);
        if (self.initial_token.len != 0) self.allocator.free(self.initial_token);
        self.initial_token = new_token;
        self.retry_consumed = true;
        self.retry_src_cid = retry.src_cid;
        // NOTE: initial_remote_cid (the F5 iscid pin) is NOT set here — noq's
        // original_remote_cid updates only at the FIRST authenticated server
        // Initial, which is what the server's iscid then authenticates.
        self.remote_cid = retry.src_cid;
        // Key re-derivation from the RETRY SCID (not the original DCID) —
        // a stateless server derives Initial keys from the second Initial's
        // DCID, so both sides land on the same secret only via this CID.
        const secrets = initial_keys.deriveInitialSecrets(retry.src_cid.slice());
        const client_k = packet_crypto.keysFromTrafficSecret(&secrets.client);
        const server_k = packet_crypto.keysFromTrafficSecret(&secrets.server);
        self.write_keys[@intFromEnum(spaces.SpaceId.initial)] = client_k;
        self.read_keys[@intFromEnum(spaces.SpaceId.initial)] = server_k;
        // Reset the Initial space: outstanding sent-records leave flight (the
        // old flight is dead), the ClientHello is re-queued from offset 0, and
        // receive-side dedup/ACK state is fresh — while the SEND PN continues
        // (noq preserves next_packet_number across the reset).
        const initial_si = @intFromEnum(spaces.SpaceId.initial);
        var i: usize = 0;
        while (i < self.sent.items.len) {
            const sp = self.sent.items[i];
            if (sp.space == .initial) {
                self.notePacketLeftFlight(sp);
                _ = self.sent.orderedRemove(i);
            } else {
                i += 1;
            }
        }
        self.clearPtoInflightSpace(.initial);
        self.crypto_sent[initial_si] = 0;
        while (self.crypto_rtx[initial_si].popFront()) |_| {}
        self.needs_ack[initial_si] = false;
        self.ack_deadline[initial_si] = null;
        const pn_space = self.spaces_state.get(.initial);
        const next_pn = pn_space.next_pn;
        pn_space.* = .{ .next_pn = next_pn };
        self.dedup[initial_si] = .{};
        self.pending_acks[initial_si] = .{};
    }

    pub fn storedNewToken(self: *const Connection) ?[]const u8 {
        if (self.stored_new_token.len == 0) return null;
        return self.stored_new_token;
    }

    /// E7: install the sealed NEW_TOKEN bytes (the transport owns token
    /// issuance; the engine dupes). Arms the post-handshake emission.
    pub fn setNewTokenOverride(self: *Connection, bytes: []const u8) Error!void {
        // Dupe before free — an alloc failure must not leave a dangling slice.
        const copy = try self.allocator.dupe(u8, bytes);
        if (self.new_token_override.len != 0) self.allocator.free(self.new_token_override);
        self.new_token_override = copy;
    }

    /// Largest UDP payload we can put on the wire: the peer's advertised limit,
    /// clamped to the send scratch buffer (padding beyond it is `NoSpaceLeft`).
    fn mtuUpperBound(self: *const Connection) u16 {
        const peer_limit = self.peer_params.max_udp_payload_size;
        const local_limit = self.local_params.max_udp_payload_size;
        return @intCast(@min(@min(peer_limit, local_limit), max_datagram));
    }

    fn scheduleMtuProbes(self: *Connection) void {
        if (self.mtu_probes_scheduled) return;
        self.mtu_probes_scheduled = true;
        self.startMtuSearch();
    }

    /// (Re-)arm the DPLPMTUD binary search from the currently confirmed MTU.
    fn startMtuSearch(self: *Connection) void {
        const upper = self.mtuUpperBound();
        const lower = @max(self.mtu, min_mtu);
        if (upper <= lower or upper - lower < mtu_minimum_change) {
            // Nothing worth searching for on this path.
            self.mtu_search = null;
            return;
        }
        var search: MtuSearch = .init(lower, upper);
        // Seed the queue with the first midpoint; `maybeStartMtuProbe` promotes
        // queued sizes into `probe_mtu` once the handshake allows probing.
        if (search.nextProbe(true)) |target| self.enqueueMtuProbe(target);
        self.mtu_search = search;
    }

    fn enqueueMtuProbe(self: *Connection, target: u16) void {
        if (target <= self.mtu) return;
        if (target > self.mtuUpperBound()) return;
        if (self.mtu_probe_queue_len >= self.mtu_probe_queue.len) return;
        self.mtu_probe_queue[self.mtu_probe_queue_len] = target;
        self.mtu_probe_queue_len += 1;
    }

    fn maybeStartMtuProbe(self: *Connection) void {
        if (self.probe_mtu != null) return;
        if (!self.handshake_confirmed and self.state != .established) return;
        // A black hole parks probing until the cooldown elapses; re-arm the
        // search on the far side rather than leaving PMTUD dead for the
        // connection's lifetime (the path may have been transiently broken).
        if (self.mtu_search_resume_at) |resume_at| {
            if (self.now < resume_at) return;
            self.mtu_search_resume_at = null;
            self.startMtuSearch();
        }
        if (self.mtu_probe_queue_len == 0) return;
        self.probe_mtu = self.mtu_probe_queue[0];
        self.mtu_probe_queue_len -= 1;
        var i: usize = 0;
        while (i < self.mtu_probe_queue_len) : (i += 1) {
            self.mtu_probe_queue[i] = self.mtu_probe_queue[i + 1];
        }
    }

    fn dataPayloadBudget(self: *const Connection) usize {
        const confirmed = @as(usize, self.mtu) -| data_payload_headroom;
        const max_confirmed = max_datagram - data_payload_headroom;
        return @max(base_data_payload_budget, @min(confirmed, max_confirmed));
    }

    fn onMtuProbeAcked(self: *Connection) void {
        if (self.probe_mtu) |new_mtu| {
            self.mtu = new_mtu;
            self.stats_mtu_probes_acked += 1;
            if (self.cc) |cc| cc.onMtuUpdate(new_mtu);
            // A delivery at this size is the strongest possible evidence the
            // path is not black-holing, so clear accumulated suspicion.
            self.mtu_black_hole.onProbeAcked(new_mtu);
            // Advance the binary search: the probed size worked, so raise the floor.
            if (self.mtu_search) |*search| {
                if (search.nextProbe(true)) |target| {
                    self.enqueueMtuProbe(target);
                } else {
                    self.mtu_search = null;
                }
            }
        }
        self.probe_mtu = null;
        self.probe_pn = null;
        self.maybeStartMtuProbe();
    }

    fn onMtuProbeLost(self: *Connection) void {
        const lost_target = self.probe_mtu;
        self.probe_mtu = null;
        self.probe_pn = null;
        // A probe loss must NOT count toward the black-hole detector: probes are
        // deliberately oversized and their loss is the expected outcome of a
        // successful search, not evidence the path shrank.
        const search = &(self.mtu_search orelse return);
        if (lost_target == null) return;
        search.lost_probe_count +|= 1;
        if (search.lost_probe_count < MtuSearch.max_probe_retries) {
            // One lost datagram is weak evidence. Retry the same size before
            // concluding the path cannot carry it.
            self.enqueueMtuProbe(lost_target.?);
            return;
        }
        if (search.nextProbe(false)) |target| {
            self.enqueueMtuProbe(target);
        } else {
            self.mtu_search = null;
        }
    }

    /// Drop to the guaranteed-supported size and park PMTUD for a cooldown.
    ///
    /// This is the wire-observable outcome the black-hole detector exists to
    /// produce: a path that persistently swallows big packets stops receiving
    /// them (upstream `mtud.rs:271-274`).
    fn onMtuBlackHole(self: *Connection) void {
        self.stats_mtu_black_holes += 1;
        if (self.mtu > min_mtu) {
            self.mtu = min_mtu;
            if (self.cc) |cc| cc.onMtuUpdate(min_mtu);
        }
        self.probe_mtu = null;
        self.probe_pn = null;
        self.mtu_probe_queue_len = 0;
        self.mtu_search = null;
        self.mtu_search_resume_at = self.now + mtu_black_hole_cooldown_ns;
    }

    /// Test/oracle hook: the confirmed path MTU.
    pub fn pathMtuForTest(self: *const Connection) u16 {
        return self.mtu;
    }

    /// Test/oracle hook: black holes detected (STRUCTURED evidence — the oracle
    /// keys the PMTUD row on this counter, not on a reason string).
    pub fn mtuBlackHolesForTest(self: *const Connection) u64 {
        return self.stats_mtu_black_holes;
    }

    /// Test/oracle hook: MTU probes that were acknowledged (search progress).
    pub fn mtuProbesAckedForTest(self: *const Connection) u64 {
        return self.stats_mtu_probes_acked;
    }

    /// Test/oracle hook: selected congestion controller kind (J2).
    pub fn congestionKindForTest(self: *const Connection) congestion.Kind {
        return self.congestion_kind;
    }

    /// Test/oracle hook: ACKs delivered to congestion control with app_limited=true (J9).
    pub fn appLimitedAcksForTest(self: *const Connection) u64 {
        return self.stats_app_limited_acks;
    }

    /// Test/oracle hook: receive bytes abandoned by reset/stop handling (D12).
    pub fn abandonedRecvBytesForTest(self: *const Connection) u64 {
        return self.recv_abandoned_total;
    }

    /// Test/oracle hook: current congestion window.
    pub fn congestionWindowForTest(self: *const Connection) u64 {
        return if (self.cc) |cc| cc.window() else 0;
    }

    pub fn bytesInFlightForTest(self: *const Connection) u64 {
        return self.bytes_in_flight;
    }

    pub fn spuriousCongestionEventsForTest(self: *const Connection) u64 {
        return self.stats_spurious_congestion_events;
    }

    /// Test hook: is the DPLPMTUD binary search currently armed?
    pub fn mtuSearchActiveForTest(self: *const Connection) bool {
        return self.mtu_search != null;
    }

    /// Test/oracle hook: reset PMTUD to a known starting point and arm the
    /// binary search from `start_mtu`.
    pub fn restartMtuSearchForTest(self: *Connection, start_mtu: u16) void {
        self.mtu = start_mtu;
        self.mtu_probes_scheduled = false;
        self.mtu_probe_queue_len = 0;
        self.probe_mtu = null;
        self.probe_pn = null;
        self.mtu_search = null;
        self.mtu_search_resume_at = null;
        self.mtu_black_hole = .{};
        self.stats_mtu_black_holes = 0;
        self.stats_mtu_probes_acked = 0;
        self.scheduleMtuProbes();
    }

    /// Test/oracle hook: advance the DPLPMTUD search by one probe.
    ///
    /// Starts the next probe, then applies the verdict `link_mtu` implies: a
    /// probe the link can carry is acknowledged (raising the MTU), one it
    /// cannot is lost (lowering the ceiling). Returns the size probed, or
    /// `null` once the search has converged.
    ///
    /// This drives the SAME `onMtuProbeAcked` / `onMtuProbeLost` production
    /// paths the real ACK/loss handlers call — it only supplies the link's
    /// verdict, which on a simulated link is the harness's job anyway.
    pub fn stepMtuSearchForTest(self: *Connection, link_mtu: u16) ?u16 {
        self.maybeStartMtuProbe();
        const target = self.probe_mtu orelse return null;
        const pn = self.spaces_state.getConst(.data).next_pn;
        self.probe_pn = pn;
        self.spaces_state.get(.data).next_pn = pn + 1;
        if (target <= link_mtu) {
            self.onMtuProbeAcked();
        } else {
            self.onMtuProbeLost();
        }
        return target;
    }

    /// Test/oracle hook: report one lost non-probe packet to the black-hole
    /// detector.
    ///
    /// Reporting and the verdict are SEPARATE, mirroring production: a loss
    /// round reports every lost packet and only then asks for a verdict
    /// (`detectAndRequeueLosses`). Interleaving them would close each burst
    /// after a single packet and destroy the burst grouping the heuristic
    /// depends on — so callers must report a whole round, then call
    /// `checkBlackHoleForTest`.
    pub fn reportLostForBlackHoleTest(self: *Connection, pn: u64, size: u16) void {
        self.mtu_black_hole.onLost(pn, size);
    }

    /// Test/oracle hook: end-of-round verdict. Returns true if a black hole was
    /// detected, having applied the min_mtu fallback.
    pub fn checkBlackHoleForTest(self: *Connection) bool {
        if (!self.mtu_black_hole.detected()) return false;
        self.onMtuBlackHole();
        return true;
    }

    /// Test/oracle hook: report an acknowledged packet size to the detector
    /// (a delivery at this size exonerates smaller suspicious bursts).
    pub fn reportAckedForBlackHoleTest(self: *Connection, size: u16) void {
        self.mtu_black_hole.onAcked(size);
    }

    /// Test/oracle hook: reset black-hole state and pin the MTU.
    pub fn resetBlackHoleForTest(self: *Connection, mtu_value: u16) void {
        self.mtu = mtu_value;
        self.mtu_search = null;
        self.mtu_search_resume_at = null;
        self.mtu_black_hole = .{};
        self.stats_mtu_black_holes = 0;
    }

    pub fn queueMtuProbe(self: *Connection, size: u16) void {
        self.probe_mtu = size;
    }

    pub fn noteEcn(self: *Connection, ect0: u64, ect1: u64, ce: u64) void {
        self.ecn_counts.ect0 += ect0;
        self.ecn_counts.ect1 += ect1;
        self.ecn_counts.ce += ce;
    }

    // ── ECN (RFC 9000 §13.4) ────────────────────────────────────────────────

    /// Ingest the ECN codepoint read off a REAL inbound IP header.
    ///
    /// This is the production receive path: `transport_noq`'s pump decodes the
    /// `IP_TOS`/`IPV6_TCLASS` cmsg (`transport/udp_cmsg.zig`) and calls this
    /// once per datagram. It is deliberately distinct from `noteEcn`, which the
    /// deterministic pair harness uses to *simulate* marking — the oracle keys
    /// its ECN row on `stats_ecn_recv_marked`, which only this function
    /// increments, so a simulated mark can never masquerade as a real one.
    pub fn ingestReceivedEcn(self: *Connection, codepoint: udp_cmsg.EcnCodepoint) void {
        switch (codepoint) {
            .ect0 => {
                self.ecn_counts.ect0 += 1;
                self.stats_ecn_recv_ect += 1;
            },
            .ect1 => {
                self.ecn_counts.ect1 += 1;
                self.stats_ecn_recv_ect += 1;
            },
            .ce => {
                self.ecn_counts.ce += 1;
                self.stats_ecn_recv_marked += 1;
                // RFC 9000 §13.2.1: a CE mark must be reported promptly, so the
                // sender can react within an RTT. Ack immediately rather than
                // waiting for the threshold or the delayed-ACK timer.
                self.needs_ack[@intFromEnum(spaces.SpaceId.data)] = true;
            },
        }
    }

    /// The codepoint to stamp on the next outgoing datagram, or `null` for
    /// Not-ECT once validation has failed.
    fn outgoingEcn(self: *const Connection) ?udp_cmsg.EcnCodepoint {
        if (self.ecn_state == .disabled) return null;
        if (self.test_ecn_override) |cp| return cp;
        // RFC 9000 §13.4.2 says to mark ECT(0) while testing AND after
        // confirmation; only a validation failure stops the marking.
        return .ect0;
    }

    /// Test hook: stamp a specific codepoint instead of ECT(0).
    ///
    /// On a loopback path there is no router to apply CE, so a test that needs
    /// to observe CE ingestion marks it at the sender. The bits still traverse
    /// a real IP header and are still decoded from a real cmsg by the receiver
    /// — only the *source* of the mark differs from production, which is
    /// exactly the part a loopback cannot supply.
    pub fn setEcnOverrideForTest(self: *Connection, codepoint: ?udp_cmsg.EcnCodepoint) void {
        self.test_ecn_override = codepoint;
    }

    /// Validate the peer's ACK_ECN echo against what we actually sent
    /// (RFC 9000 §13.4.2.1) and drive congestion response on a real CE increase.
    ///
    /// Three failure modes disable ECN permanently:
    ///   * **bleaching** — the peer acknowledges ack-eliciting packets we marked
    ///     but reports no ECN counters at all, so something on the path stripped
    ///     the bits;
    ///   * **regression** — a counter went backwards, which is impossible for a
    ///     conformant peer and means the feedback cannot be trusted;
    ///   * **over-count** — the peer claims more marked packets than we sent,
    ///     so a middlebox is re-marking (or the peer is lying) and a CE-driven
    ///     window reduction would be attacker-controlled.
    ///
    /// G9 note: marking covers ALL spaces (noq build_transmit), but the
    /// validation feedback loop deliberately keys on the Data space only —
    /// Initial/Handshake ACKs frequently carry no ECN block, and noq's
    /// disable-on-any-silent-ACK (mod.rs:3062-3067) would kill marking at the
    /// first handshake ACK against peers that don't report ECN there.
    fn validatePeerEcn(self: *Connection, space: spaces.SpaceId, a: frame.Ack, newly_acked_marked: u64) void {
        if (self.ecn_state == .disabled) return;
        // Validation runs on the data space only (see the doc comment).
        if (space != .data) return;

        const reported = a.ecn orelse {
            // No ECN block. Only conclusive once the peer has acknowledged
            // packets we marked — before that, silence is just an early ACK.
            if (newly_acked_marked > 0 and self.ecn_state == .capable) self.disableEcn();
            return;
        };

        const prev = self.ecn_peer_seen;
        if (reported.ect0 < prev.ect0 or reported.ect1 < prev.ect1 or reported.ce < prev.ce) {
            self.disableEcn();
            return;
        }
        // We only ever send ECT(0), so the peer cannot legitimately have seen
        // more ECT(0)+CE than we sent, nor any ECT(1) at all.
        const total_marked = reported.ect0 +| reported.ce;
        if (total_marked > self.ecn_sent.ect0 or reported.ect1 != 0) {
            self.disableEcn();
            return;
        }

        const ce_increase = reported.ce - prev.ce;
        self.ecn_peer_seen = reported;
        self.ecn_state = .capable;

        if (ce_increase > 0) {
            // A VALIDATED CE increase is congestion signal, equivalent in
            // strength to a loss but without the retransmit (RFC 9002 §7).
            self.stats_ecn_congestion_events +|= ce_increase;
            if (self.cc) |cc| {
                cc.onCongestionEvent(self.now, self.now, false, true, 0, a.largest_acked);
            }
        }
    }

    fn disableEcn(self: *Connection) void {
        self.ecn_state = .disabled;
        self.ecn_peer_seen = .{};
    }

    /// Test/oracle hook: CE codepoints ingested from REAL IP header bits.
    /// A simulated mark via `noteEcn` does NOT move this counter.
    pub fn ecnRecvMarkedForTest(self: *const Connection) u64 {
        return self.stats_ecn_recv_marked;
    }

    /// Test/oracle hook: ECT codepoints ingested from real IP header bits.
    pub fn ecnRecvEctForTest(self: *const Connection) u64 {
        return self.stats_ecn_recv_ect;
    }

    /// Test/oracle hook: congestion events driven by a validated peer CE increase.
    pub fn ecnCongestionEventsForTest(self: *const Connection) u64 {
        return self.stats_ecn_congestion_events;
    }

    /// Test/oracle hook: the ECN validation state machine's current state.
    pub fn ecnStateForTest(self: *const Connection) EcnState {
        return self.ecn_state;
    }

    /// Test/oracle hook: ECN counters we have RECEIVED (echoed in ACK_ECN).
    pub fn ecnCountsForTest(self: *const Connection) frame.EcnCounts {
        return self.ecn_counts;
    }

    /// Test/oracle hook: ECT(0) datagrams we have SENT.
    pub fn ecnSentForTest(self: *const Connection) frame.EcnCounts {
        return self.ecn_sent;
    }

    /// Test hook (mutation-RED): force ECN off so a gate that claims to prove
    /// the ECN path must actually fail when it is disabled.
    pub fn setEcnDisabledForTest(self: *Connection, disabled: bool) void {
        self.ecn_state = if (disabled) .disabled else .testing;
    }

    pub fn setTestPacingRate(self: *Connection, rate: ?u64) void {
        self.test_pacing_rate = rate;
    }

    /// Test hook: smoothed RTT in nanoseconds (RFC 9002 estimator). Used by
    /// real-peer RTT tests to assert ACK-delay scaling does not inflate RTT.
    pub fn smoothedRttNsForTest(self: *const Connection) i64 {
        return self.rtt.get();
    }

    /// Test hook: latest sample RTT in nanoseconds.
    pub fn latestRttNsForTest(self: *const Connection) i64 {
        return self.rtt.latest;
    }

    /// Test hook: whether a non-zero peer TP/NEW_CONNECTION_ID reset token is installed.
    pub fn hasPeerStatelessResetTokenForTest(self: *const Connection) bool {
        if (self.peer_stateless_reset_token) |token| {
            for (token) |b| if (b != 0) return true;
        }
        var i: usize = 0;
        while (i < self.remote_cid_len) : (i += 1) {
            if (self.remote_cids[i].retired) continue;
            for (self.remote_cids[i].reset_token) |b| if (b != 0) return true;
        }
        return false;
    }

    /// Test hook: the peer TP `stateless_reset_token` learned at handshake, if any.
    pub fn peerStatelessResetTokenForTest(self: *const Connection) ?[packet.stateless_reset_token_len]u8 {
        return self.peer_stateless_reset_token;
    }

    /// Test hook (mutation-RED): clear learned peer reset tokens so
    /// `matchesPeerStatelessReset` cannot fire. A real peer reset must then
    /// fail to drain — proving detection depends on the peer-token path.
    pub fn clearPeerStatelessResetTokensForTest(self: *Connection) void {
        self.peer_stateless_reset_token = null;
        var i: usize = 0;
        while (i < self.remote_cid_len) : (i += 1) {
            self.remote_cids[i].reset_token = .{0} ** packet.stateless_reset_token_len;
        }
    }

    /// Test hook (mutation-RED): hard-disable peer reset matching.
    pub fn setDisablePeerStatelessResetForTest(self: *Connection, disable: bool) void {
        self.test_disable_peer_stateless_reset = disable;
    }

    pub fn isPeerStatelessResetDisabledForTest(self: *const Connection) bool {
        return self.test_disable_peer_stateless_reset;
    }

    /// Test hook: true when the connection is draining due to a peer stateless reset.
    pub fn isDrainingStatelessResetForTest(self: *const Connection) bool {
        return switch (self.state) {
            .draining => |info| std.mem.eql(u8, info.reason, "stateless-reset"),
            else => false,
        };
    }

    /// Test hook: true when the connection is still established.
    pub fn isEstablishedForTest(self: *const Connection) bool {
        return self.state == .established;
    }

    /// B7: true once the drain window (3×PTO close timer, noq
    /// connection/mod.rs:6597-6603) fully elapsed and the connection went
    /// drained (mod.rs:2736-2739). The transport defers slot teardown until
    /// then so straggler packets re-draw the close (mod.rs:4439-4471)
    /// instead of falling off the CID router to a stateless reset.
    pub fn isDrained(self: *const Connection) bool {
        return self.state == .drained;
    }

    /// Apply a peer-issued stateless reset observed on an unroutable datagram
    /// (transport demux path). Same transition as the in-handleDatagram check.
    pub fn notePeerStatelessReset(self: *Connection, now: Instant) Error!void {
        self.now = now;
        self.state = .{ .draining = .{ .is_local = false, .reason = "stateless-reset" } };
        self.timers.armClose(now);
        try self.events.pushBack(self.allocator, .{ .connection_lost = .{ .is_local = false, .reason = "stateless-reset" } });
    }

    /// Ingest one unprotected-path datagram (already demuxed to this connection).
    pub fn handleDatagram(self: *Connection, now: Instant, datagram: []const u8) Error!void {
        self.now = now;
        self.bytes_received += datagram.len;
        // Empty check BEFORE datagram[0] — zero-length must not OOB.
        if (datagram.len == 0) return;
        // Stateless reset (RFC 9000 §10.3): compare the trailing 16 bytes against
        // the *peer*'s tokens (TP + NEW_CONNECTION_ID). Real resets set the fixed
        // bit; do not gate on our own token or on fixed-bit-clear.
        if (self.matchesPeerStatelessReset(datagram)) {
            self.state = .{ .draining = .{ .is_local = false, .reason = "stateless-reset" } };
            self.timers.armClose(now);
            try self.events.pushBack(self.allocator, .{ .connection_lost = .{ .is_local = false, .reason = "stateless-reset" } });
            return;
        }
        self.armIdle(now);
        // G18-idle: a received datagram restarts the idle timer AND permits the
        // next ack-eliciting send to restart it once (RFC 9000 §10.1, noq
        // on_packet_authenticated → permit_idle_reset).
        self.permit_idle_reset = true;
        // Coalesced packets: walk long-header packets then a trailing short-header.
        var offset: usize = 0;
        while (offset < datagram.len) {
            if ((datagram[offset] & packet.long_header_form) != 0) {
                const consumed = try self.handleLongPacket(datagram[offset..]);
                if (consumed == 0) break;
                offset += consumed;
            } else {
                try self.handleShortPacket(datagram[offset..]);
                break;
            }
        }
    }

    // ── Stream API (5b) ──────────────────────────────────────────────────────

    /// Allocate a new locally-initiated stream id (RFC 9000 §2.1) and register it.
    pub fn openStream(self: *Connection, dir: StreamDir) Error!u64 {
        self.applyPeerParams();
        const role_bit: u64 = if (self.role == .client) 0 else 1;
        const id = switch (dir) {
            .bidi => blk: {
                const n = self.next_bidi;
                if (self.peer_params_applied and n >= self.peer_params.initial_max_streams_bidi) {
                    self.queueStreamsBlocked(.bidi, self.peer_params.initial_max_streams_bidi);
                    return error.StreamLimit;
                }
                self.next_bidi += 1;
                break :blk n * 4 + role_bit;
            },
            .uni => blk: {
                const n = self.next_uni;
                if (self.peer_params_applied and n >= self.peer_params.initial_max_streams_uni) {
                    self.queueStreamsBlocked(.uni, self.peer_params.initial_max_streams_uni);
                    return error.StreamLimit;
                }
                self.next_uni += 1;
                break :blk n * 4 + 2 + role_bit;
            },
        };
        const e = try self.getOrCreateStream(id);
        e.send.max_data = self.peerSendWindow(id, dir);
        return id;
    }

    /// Queue bytes to send on a stream. `fin` marks the last write.
    pub fn writeStream(self: *Connection, id: u64, data: []const u8, fin: bool) Error!void {
        const e = try self.getOrCreateStream(id);
        try e.send.buf.appendSlice(self.allocator, data);
        if (fin) e.send.fin = true;
    }

    /// Abort the sending half of a stream (RESET_STREAM).
    pub fn resetStream(self: *Connection, id: u64, code: u64) Error!void {
        if (code > varint.max_value) return error.FrameEncodeFailed;
        const e = try self.getOrCreateStream(id);
        if (e.send.reset_code == null) {
            e.send.reset_code = code;
            e.send.reset_final_size = e.send.send_next;
            e.send.send_next = e.send.endOffset();
            e.send.rtx.deinit(self.allocator);
            e.send.rtx = .empty;
            self.reclaimResetStreamData(e);
        }
    }

    /// Stop accepting data on a receive stream (STOP_SENDING).
    pub fn stopStream(self: *Connection, id: u64, code: u64) Error!void {
        if (code > varint.max_value) return error.FrameEncodeFailed;
        const e = try self.getOrCreateStream(id);
        if (e.recv.stop_code == null) {
            self.creditAbandonedRecv(e);
            e.recv.stop_code = code;
        }
    }

    /// Reassembled, in-order received bytes not yet consumed; advances `consumed`.
    /// Draining grants more receive-window (queues MAX_STREAM_DATA / MAX_DATA).
    pub fn readStream(self: *Connection, id: u64) []const u8 {
        const e = self.findStream(id) orelse return &.{};
        if (e.recv.consumed < e.recv.base_offset) e.recv.consumed = e.recv.base_offset;
        const from: usize = @intCast(e.recv.consumed - e.recv.base_offset);
        const out = e.recv.data.items[from..];
        e.recv.consumed = e.recv.contiguousEnd();
        return out;
    }

    /// Copy received bytes into caller storage and advance flow-control credit.
    /// Unlike `streamRecvBytes`, this is the production streaming read path and
    /// prunes consumed contiguous bytes so large transfers do not accumulate in
    /// the connection receive buffer.
    pub fn readStreamInto(self: *Connection, id: u64, out: []u8) usize {
        const e = self.findStream(id) orelse return 0;
        if (out.len == 0) return 0;
        if (e.recv.consumed < e.recv.base_offset) e.recv.consumed = e.recv.base_offset;
        const from: usize = @intCast(e.recv.consumed - e.recv.base_offset);
        if (from >= e.recv.data.items.len) return 0;
        const n = @min(out.len, e.recv.data.items.len - from);
        @memcpy(out[0..n], e.recv.data.items[from .. from + n]);
        e.recv.consumed += n;
        e.recv.pruneConsumed();
        return n;
    }

    pub fn streamRecvBytes(self: *Connection, id: u64) []const u8 {
        const e = self.findStream(id) orelse return &.{};
        return e.recv.data.items;
    }

    pub fn streamRecvBufferedLen(self: *Connection, id: u64) usize {
        const e = self.findStream(id) orelse return 0;
        if (e.recv.consumed < e.recv.base_offset) return e.recv.data.items.len;
        const from: usize = @intCast(e.recv.consumed - e.recv.base_offset);
        return if (from < e.recv.data.items.len) e.recv.data.items.len - from else 0;
    }

    pub fn streamRecvFin(self: *Connection, id: u64) bool {
        const e = self.findStream(id) orelse return false;
        return e.recv.finReached();
    }

    pub fn streamSendComplete(self: *Connection, id: u64) bool {
        const e = self.findStream(id) orelse return true;
        if (e.send.buffer_released) return true;
        const final_len = e.send.endOffset();
        return e.send.fin and e.send.send_next == final_len and e.send.fin_sent;
    }

    /// True when the local send direction is aborted (our reset(), or a peer
    /// STOP_SENDING that forces an implicit RESET_STREAM reply). Distinct from
    /// a peer RESET_STREAM on the recv direction — those are independent per
    /// RFC 9000 §3 and must not gate sendFinish/write.
    pub fn streamSendReset(self: *Connection, id: u64) bool {
        const e = self.findStream(id) orelse return false;
        return e.send.reset_code != null;
    }

    pub fn streamSendResetCode(self: *Connection, id: u64) ?u64 {
        const e = self.findStream(id) orelse return null;
        return e.send.reset_code;
    }

    pub fn streamRecvResetCode(self: *Connection, id: u64) ?u64 {
        const e = self.findStream(id) orelse return null;
        return e.recv.reset_code;
    }

    pub fn releaseStreamSendBuffer(self: *Connection, id: u64) void {
        const e = self.findStream(id) orelse return;
        if (e.send.buffer_released) return;
        if (!self.streamSendComplete(id)) return;
        if (e.send.rtx.len != 0) return;
        for (self.sent.items) |sp| {
            var i: usize = 0;
            while (i < sp.content_len) : (i += 1) {
                switch (sp.content[i]) {
                    .stream => |st| if (st.id == id) return,
                    else => {},
                }
            }
        }
        e.send.buf.deinit(self.allocator);
        e.send.buf = .empty;
        e.send.buffer_released = true;
    }

    pub fn streamSendBlocked(self: *Connection, id: u64) bool {
        const e = self.findStream(id) orelse return false;
        const pending = e.send.endOffset() > e.send.send_next;
        return pending and self.streamSendWindow(e) == 0;
    }

    fn creditAbandonedRecv(self: *Connection, e: *StreamEntry) void {
        const finalish = e.recv.fin_offset orelse e.recv.highest_offset;
        if (finalish <= e.recv.consumed) return;
        self.recv_abandoned_total +|= finalish - e.recv.consumed;
        e.recv.consumed = finalish;
        e.recv.pruneConsumed();
    }

    /// Retained send storage, excluding already-reclaimed absolute prefixes.
    pub fn streamSendBufferedLen(self: *Connection, id: u64) usize {
        const e = self.findStream(id) orelse return 0;
        return e.send.buf.items.len;
    }

    // ── Path validation API (5e, RFC 9000 §8.2) ─────────────────────────────

    /// Queue a PATH_CHALLENGE carrying `token`; a matching PATH_RESPONSE marks
    /// the path validated. The caller supplies a random, unguessable token.
    pub fn challengePath(self: *Connection, token: [8]u8) void {
        self.challengePathTo(token, null);
    }

    /// Queue a PATH_CHALLENGE bound to a transport-owned destination hint
    /// (a migration candidate). The emitting packet carries the hint in
    /// `Transmit.dest_hint`; the transport maps it to the real address.
    pub fn challengePathTo(self: *Connection, token: [8]u8, dest_hint: ?u64) void {
        if (self.challenge_pending_len >= max_path_tokens) return;
        self.challenge_pending[self.challenge_pending_len] = token;
        self.challenge_pending_hints[self.challenge_pending_len] = dest_hint;
        self.challenge_pending_len += 1;
    }

    /// Is `token` already outstanding (sent at least once, awaiting a response)?
    fn challengeAwaited(self: *const Connection, token: [8]u8) bool {
        for (self.challenge_await[0..self.challenge_await_len]) |t| {
            if (std.mem.eql(u8, &t, &token)) return true;
        }
        return false;
    }

    /// Take the first destination-hinted probe off the pending queue.
    /// Unhinted probes keep flowing through the normal challenge path.
    fn takeHintedProbe(self: *Connection) ?struct { token: [8]u8, hint: u64 } {
        var i: usize = 0;
        while (i < self.challenge_pending_len) : (i += 1) {
            if (self.challenge_pending_hints[i]) |hint| {
                const token = self.challenge_pending[i];
                std.mem.copyForwards([8]u8, self.challenge_pending[i .. self.challenge_pending_len - 1], self.challenge_pending[i + 1 .. self.challenge_pending_len]);
                std.mem.copyForwards(?u64, self.challenge_pending_hints[i .. self.challenge_pending_len - 1], self.challenge_pending_hints[i + 1 .. self.challenge_pending_len]);
                self.challenge_pending_len -= 1;
                // Outstanding-tracking + the retransmission clock, same as the
                // normal challenge path (armed for NEW challenges only).
                const new_challenge = !self.challengeAwaited(token);
                if (self.challenge_await_len < max_path_tokens) {
                    self.challenge_await[self.challenge_await_len] = token;
                    self.challenge_await_hints[self.challenge_await_len] = hint;
                    self.challenge_await_len += 1;
                }
                if (self.timers.path_challenge_deadline == null and new_challenge) {
                    self.timers.path_challenge_deadline = self.now + loss.ptoDelay(self.rtt, 0, 0, self.ptoMaxIntervalNs());
                    self.timers.path_challenge_attempts = 0;
                }
                return .{ .token = token, .hint = hint };
            }
        }
        return null;
    }

    /// Queue an n0 NAT-traversal address frame for transmission (magicsock).
    /// F13: does our role let us SEND reports (send_only/both)?
    fn roleSends(role: ?transport_parameters.ObservedAddrRole) bool {
        return role == .send_only or role == .both;
    }

    /// F13: does the role ask for reports (receive_only/both)?
    fn roleReceives(role: ?transport_parameters.ObservedAddrRole) bool {
        return role == .receive_only or role == .both;
    }

    pub fn advertiseAddress(self: *Connection, a: NatAddress) void {
        if (self.nat_out_len >= max_path_tokens) return;
        self.nat_out[self.nat_out_len] = a;
        self.nat_out_len += 1;
    }

    /// F13: an OBSERVED_ADDR report may only be SENT when we advertised a
    /// sending role AND the peer advertised a receiving one
    /// (draft-seemann-quic-address-discovery; noq should_report).
    fn observedAddrSendNegotiated(self: *const Connection) bool {
        return roleSends(self.local_params.observed_addr_role) and
            roleReceives(self.peer_params.observed_addr_role);
    }

    /// F13: an incoming OBSERVED_ADDR is legal only when the peer advertised
    /// send AND we advertised receive; anything else is PROTOCOL_VIOLATION
    /// (noq connection/mod.rs "received OBSERVED_ADDRESS when not negotiated").
    fn observedAddrRecvNegotiated(self: *const Connection) bool {
        return roleSends(self.peer_params.observed_addr_role) and
            roleReceives(self.local_params.observed_addr_role);
    }

    /// True once `token` (a token we challenged with) has been echoed back.
    pub fn pathValidated(self: *const Connection, token: [8]u8) bool {
        for (self.validated[0..self.validated_len]) |v| {
            if (std.mem.eql(u8, &v, &token)) return true;
        }
        return false;
    }

    fn queuePathResponse(self: *Connection, token: [8]u8) void {
        for (self.response_tx[0..self.response_tx_len]) |r| {
            if (std.mem.eql(u8, &r, &token)) return; // already owed
        }
        if (self.response_tx_len >= max_path_tokens) return;
        self.response_tx[self.response_tx_len] = token;
        self.response_tx_len += 1;
    }

    fn isPathValidated(self: *const Connection) bool {
        if (self.path_validated_any) return true;
        if (self.state == .established or self.handshake_confirmed) return true;
        if (self.role == .server and self.validated_len > 0) return true;
        return false;
    }

    fn markPathValidated(self: *Connection) void {
        self.path_validated_any = true;
    }

    /// E5/E9: the accept path validated this address out-of-band (a Retry or
    /// NEW_TOKEN token) — the anti-amplification cap lifts immediately
    /// (noq IncomingToken::validated).
    pub fn markTokenValidated(self: *Connection) void {
        self.markPathValidated();
    }

    fn onPathResponse(self: *Connection, token: [8]u8) Error!void {
        // Match against an outstanding (already-sent) challenge — an unsolicited
        // or mismatched response validates NOTHING (anti-spoofing).
        var i: usize = 0;
        while (i < self.challenge_await_len) : (i += 1) {
            if (std.mem.eql(u8, &self.challenge_await[i], &token)) {
                if (self.validated_len < max_path_tokens) {
                    self.validated[self.validated_len] = token;
                    self.validated_len += 1;
                }
                std.mem.copyForwards([8]u8, self.challenge_await[i .. self.challenge_await_len - 1], self.challenge_await[i + 1 .. self.challenge_await_len]);
                std.mem.copyForwards(?u64, self.challenge_await_hints[i .. self.challenge_await_len - 1], self.challenge_await_hints[i + 1 .. self.challenge_await_len]);
                self.challenge_await_len -= 1;
                self.markPathValidated();
                // A validated challenge stops the retransmission clock.
                if (self.challenge_await_len == 0) {
                    self.timers.path_challenge_deadline = null;
                    self.timers.path_challenge_attempts = 0;
                }
                try self.events.pushBack(self.allocator, .{ .path_validated = token });
                return;
            }
        }
    }

    // ── internals ──────────────────────────────────────────────────────────

    fn findStream(self: *Connection, id: u64) ?*StreamEntry {
        for (&self.streams) |*s| {
            if (s.used and s.id == id) return s;
        }
        return null;
    }

    fn getOrCreateStream(self: *Connection, id: u64) Error!*StreamEntry {
        if (self.findStream(id)) |e| return e;
        const dir: StreamDir = if (streamIsUni(id)) .uni else .bidi;
        if (streamInitiator(id) != self.role and !self.peerStreamWithinLimit(id, dir)) {
            self.protocolClose(err_stream_limit);
            return error.StreamLimit;
        }
        for (&self.streams) |*s| {
            if (!s.used) {
                s.* = .{
                    .id = id,
                    .dir = dir,
                    .used = true,
                };
                s.send.max_data = self.peerSendWindow(id, s.dir);
                s.recv.max_data = self.recvStreamWindow(id, s.dir);
                return s;
            }
        }
        return error.StreamTooLarge;
    }

    fn peerStreamWithinLimit(self: *const Connection, id: u64, dir: StreamDir) bool {
        const ordinal = id / 4 + 1;
        const limit = if (dir == .bidi) self.local_params.initial_max_streams_bidi else self.local_params.initial_max_streams_uni;
        return ordinal <= limit;
    }

    /// Our send window on a stream = the peer's advertised per-stream limit.
    fn peerSendWindow(self: *Connection, id: u64, dir: StreamDir) u64 {
        // 0-RTT: the remembered transport parameters (RFC 9001 §4.6) seed the
        // send windows before the real handshake TPs land; `peer_params` holds
        // them when zero_rtt_peer_params is set.
        if (!self.peer_params_applied and !self.zero_rtt_peer_params) return 0;
        if (dir == .uni) return self.peer_params.initial_max_stream_data_uni;
        // bidi: locally-initiated uses peer's *_bidi_remote; remote-initiated uses *_bidi_local.
        return if (streamInitiator(id) == self.role)
            self.peer_params.initial_max_stream_data_bidi_remote
        else
            self.peer_params.initial_max_stream_data_bidi_local;
    }

    /// The receive window we advertise for a stream (matches what we told the peer).
    fn recvStreamWindow(self: *Connection, id: u64, dir: StreamDir) u64 {
        if (dir == .uni) return self.local_params.initial_max_stream_data_uni;
        return if (streamInitiator(id) == self.role)
            self.local_params.initial_max_stream_data_bidi_local
        else
            self.local_params.initial_max_stream_data_bidi_remote;
    }

    fn streamSendWindow(self: *Connection, e: *StreamEntry) u64 {
        const stream_room = if (e.send.max_data > e.send.send_next) e.send.max_data - e.send.send_next else 0;
        const conn_room = if (self.send_max_data > self.send_data_total) self.send_max_data - self.send_data_total else 0;
        return @min(stream_room, conn_room);
    }

    fn streamSendRoom(_: *const Connection, e: *const StreamEntry) u64 {
        return if (e.send.max_data > e.send.send_next) e.send.max_data - e.send.send_next else 0;
    }

    fn connectionSendRoom(self: *const Connection) u64 {
        return if (self.send_max_data > self.send_data_total) self.send_max_data - self.send_data_total else 0;
    }

    fn queueStreamsBlocked(self: *Connection, dir: StreamDir, limit: u64) void {
        switch (dir) {
            .bidi => {
                if (self.streams_blocked_bidi_sent_at != limit) self.streams_blocked_bidi_pending = limit;
            },
            .uni => {
                if (self.streams_blocked_uni_sent_at != limit) self.streams_blocked_uni_pending = limit;
            },
        }
    }

    fn retiredStreamGrantCap(_: *const Connection) u64 {
        return @as(u64, @intCast(max_streams));
    }

    fn peerStreamRetirable(self: *const Connection, e: *const StreamEntry) bool {
        if (streamInitiator(e.id) == self.role) return false;
        const recv_done = e.recv.reset_code != null or
            (e.recv.fin_offset != null and e.recv.consumed >= e.recv.fin_offset.?);
        if (!recv_done) return false;
        if (e.dir == .uni) return true;
        if (e.send.reset_code != null) return true;
        return e.send.fin and e.send.fin_sent and e.send.send_next == e.send.endOffset();
    }

    fn retirablePeerStreamsForMaxStreams(self: *const Connection, dir: StreamDir) u64 {
        var count: u64 = 0;
        for (&self.streams) |*s| {
            if (!s.used or s.dir != dir or s.max_streams_retired or !self.peerStreamRetirable(s)) continue;
            count += 1;
        }
        return count;
    }

    fn markPeerStreamsRetiredForMaxStreams(self: *Connection, dir: StreamDir, count: u64) void {
        var remaining = count;
        for (&self.streams) |*s| {
            if (remaining == 0) break;
            if (!s.used or s.dir != dir or s.max_streams_retired or !self.peerStreamRetirable(s)) continue;
            s.max_streams_retired = true;
            remaining -= 1;
        }
    }

    fn appendMaxStreamsRegrants(self: *Connection, frames: []frame.Frame, n: *usize, ack_eliciting: *bool) void {
        const grant_cap = self.retiredStreamGrantCap();
        if (n.* < frames.len and self.recv_max_streams_bidi < grant_cap) {
            const retired = @min(
                self.retirablePeerStreamsForMaxStreams(.bidi),
                grant_cap - self.recv_max_streams_bidi,
            );
            if (retired > 0) {
                self.recv_max_streams_bidi += retired;
                frames[n.*] = .{ .max_streams_bidi = self.recv_max_streams_bidi };
                n.* += 1;
                ack_eliciting.* = true;
                self.markPeerStreamsRetiredForMaxStreams(.bidi, retired);
            }
        }
        if (n.* < frames.len and self.recv_max_streams_uni < grant_cap) {
            const retired = @min(
                self.retirablePeerStreamsForMaxStreams(.uni),
                grant_cap - self.recv_max_streams_uni,
            );
            if (retired > 0) {
                self.recv_max_streams_uni += retired;
                frames[n.*] = .{ .max_streams_uni = self.recv_max_streams_uni };
                n.* += 1;
                ack_eliciting.* = true;
                self.markPeerStreamsRetiredForMaxStreams(.uni, retired);
            }
        }
    }

    fn appLimitedAfterTransmit(self: *const Connection) bool {
        if (self.datagram_out.len > 0) return false;
        if (self.pending_new_cid or self.new_token_pending or self.pending_immediate_ack) return false;
        if (self.challenge_pending_len > 0 or self.response_tx_len > 0 or self.nat_out_len > 0) return false;
        for (self.crypto_rtx) |rtx| if (rtx.len > 0) return false;
        inline for (0..3) |si| {
            if (self.crypto_out[si].items.len > @as(usize, @intCast(self.crypto_sent[si]))) return false;
        }
        for (self.streams) |s| {
            if (!s.used) continue;
            if (s.send.reset_code != null and !s.send.reset_sent) return false;
            if (s.recv.stop_code != null and !s.recv.stop_sent) return false;
            if (s.send.rtx.len > 0) return false;
            if (s.send.endOffset() > s.send.send_next) return false;
            if (s.send.fin and !s.send.fin_sent) return false;
        }
        return true;
    }

    fn armIdle(self: *Connection, now: Instant) void {
        const timeout = self.idle_timeout_ns orelse return;
        self.idle_deadline = now +| timeout;
    }

    /// F5 (RFC 9000 §7.3, noq handle_peer_params): authenticate the peer's
    /// transport-parameter CIDs against the handshake's CIDs. iscid MUST equal
    /// the FIRST CID we pinned for the peer; a client additionally
    /// authenticates odcid (its original DCID) and retry_scid (exactly the
    /// Retry it consumed — present iff one was, else absent).
    fn verifyPeerCids(self: *const Connection, decoded: transport_parameters.TransportParameters) bool {
        const pinned_remote = self.initial_remote_cid orelse self.remote_cid;
        if (decoded.initial_source_connection_id == null or
            !std.mem.eql(u8, decoded.initial_source_connection_id.?.slice(), pinned_remote.slice()))
        {
            return false;
        }
        if (self.role != .client) return true;
        if (decoded.original_destination_connection_id == null or
            !std.mem.eql(u8, decoded.original_destination_connection_id.?.slice(), self.initial_dcid.slice()))
        {
            return false;
        }
        if (self.retry_src_cid) |mine| {
            if (decoded.retry_source_connection_id == null or
                !std.mem.eql(u8, decoded.retry_source_connection_id.?.slice(), mine.slice()))
            {
                return false;
            }
        } else if (decoded.retry_source_connection_id != null) {
            return false;
        }
        return true;
    }

    /// F17: the four server-only transport parameters (RFC 9000 §18.2 /
    /// noq TransportParameters::read): original_destination_connection_id,
    /// retry_source_connection_id, preferred_address, stateless_reset_token.
    fn serverOnlyParamsPresent(decoded: transport_parameters.TransportParameters) bool {
        return decoded.original_destination_connection_id != null or
            decoded.retry_source_connection_id != null or
            decoded.preferred_address != null or
            decoded.stateless_reset_token != null;
    }

    /// G18 (noq `Connection::reset_keep_alive`, mod.rs:3863-3880): every
    /// authenticated packet pushes the keep-alive deadline out; only an
    /// established connection with a configured interval arms it. noq resets
    /// on RECEIVE only (on_packet_authenticated, mod.rs:3764) — a one-way
    /// sender still pings, which is the intended liveness signal.
    fn resetKeepAlive(self: *Connection) void {
        if (self.state != .established) return;
        if (self.keep_alive_interval_ns) |interval| {
            if (interval <= 0) return; // unset/zero disables (noq Option<Duration>)
            self.keep_alive_deadline = self.now +| interval;
        }
    }

    /// G18: configure the keep-alive interval (nanoseconds). null or <= 0
    /// disables — noq's `keep_alive_interval: Option<Duration>` semantics.
    pub fn setKeepAliveIntervalNs(self: *Connection, interval_ns: ?i64) void {
        self.keep_alive_interval_ns = if (interval_ns) |i| (if (i > 0) i else null) else null;
        if (self.keep_alive_interval_ns == null) self.keep_alive_deadline = null;
    }

    /// G19 (noq `pto` / `max_pto_for_space`, mod.rs:3711-3743): refresh the
    /// cached PTO bases the connection-wide 3×PTO deadlines (close/drain,
    /// handshake-key discard, previous-key discard) are armed from, so they
    /// track the live RTT estimator instead of a fixed constant. Called when
    /// an RTT sample lands and when the peer's max_ack_delay becomes known.
    /// The pre-RTT default (1s) matches noq's initial-RTT-derived PTO
    /// (333ms + max(4·166.5ms, 1ms) ≈ 1s, config/transport.rs:564).
    fn refreshTimerPtoBase(self: *Connection) void {
        self.timers.max_pto_handshake_ns = self.rtt.ptoBase();
        // Close and previous-key discard are data-space timers once 1-RTT
        // keys exist (noq set_close_timer uses highest_space,
        // mod.rs:6598-6606; set_key_discard_timer takes the triggering
        // space, mod.rs:3175-3194).
        const mad: i64 = if (self.write_keys[@intFromEnum(spaces.SpaceId.data)] != null)
            self.peerMaxAckDelayNs()
        else
            0;
        self.timers.max_pto_ns = self.rtt.ptoBase() +| mad;
    }

    fn applyPeerParams(self: *Connection) void {
        if (self.peer_params_applied) return;
        const tp = self.tls.peerTransportParams() orelse return;
        // A malformed TP block is a hard failure, not a silent skip (RFC 9000
        // §7.4: TRANSPORT_PARAMETER_ERROR).
        const decoded = transport_parameters.decode(tp) catch {
            self.protocolClose(err_transport_parameter);
            return;
        };
        // F17 (RFC 9000 §7.4, noq TransportParameters::read side check):
        // server-only parameters from a CLIENT are a TRANSPORT_PARAMETER_ERROR.
        if (self.role == .server and serverOnlyParamsPresent(decoded)) {
            self.protocolClose(err_transport_parameter);
            return;
        }
        // RFC 9000 §7.4.1 (0-RTT): the real handshake parameters MUST NOT
        // shrink what the client's flight relied on from the remembered
        // values — the server already honored them, and a downgrade here
        // retroactively violates flow control.
        if (self.zero_rtt_peer_params) {
            const remembered = self.zero_rtt_remembered.?;
            if (decoded.initial_max_data < remembered.initial_max_data or
                decoded.initial_max_streams_bidi < remembered.initial_max_streams_bidi or
                decoded.initial_max_streams_uni < remembered.initial_max_streams_uni or
                decoded.initial_max_stream_data_bidi_local < remembered.initial_max_stream_data_bidi_local or
                decoded.initial_max_stream_data_bidi_remote < remembered.initial_max_stream_data_bidi_remote or
                decoded.initial_max_stream_data_uni < remembered.initial_max_stream_data_uni)
            {
                self.protocolClose(err_transport_parameter);
                return;
            }
        }
        // RFC 9000 §7.3 CID authentication (noq handle_peer_params — F5).
        if (!self.verifyPeerCids(decoded)) {
            self.protocolClose(err_transport_parameter);
            return;
        }
        // F8 (noq set_peer_params): a server's preferred_address installs its
        // CID + stateless-reset token into the peer-CID inventory so a later
        // migration can address it.
        if (self.role == .client) {
            if (decoded.preferred_address) |addr| {
                if (self.remote_cid_len < max_local_cid_slots) {
                    self.remote_cids[self.remote_cid_len] = .{
                        .sequence = @intCast(self.remote_cid_len + 1),
                        .cid = addr.connection_id,
                        .reset_token = addr.stateless_reset_token,
                    };
                    self.remote_cid_len += 1;
                }
            }
        }
        self.peer_params = decoded;
        self.peer_params_applied = true;
        // G10 (noq mod.rs:6660): the max_ack_delay the peer is presumed to be
        // using starts at its transport-parameter value.
        self.ack_freq_peer_max_delay_us = std.math.mul(u64, self.peer_params.max_ack_delay, 1000) catch std.math.maxInt(u64);
        self.send_max_data = self.peer_params.initial_max_data;
        self.idle_timeout_ns = effectiveIdleTimeoutNs(self.local_params.max_idle_timeout, self.peer_params.max_idle_timeout);
        if (self.peer_params.stateless_reset_token) |token| {
            self.peer_stateless_reset_token = token;
        }
        self.armIdle(self.now);
        self.refreshTimerPtoBase(); // G19: peer max_ack_delay is now known
        // Backfill send windows on any streams opened before params arrived.
        for (&self.streams) |*s| {
            if (s.used and s.send.max_data == 0) {
                s.send.max_data = self.peerSendWindow(s.id, s.dir);
            }
        }
    }

    fn queueTlsOutput(self: *Connection, out: crypto.HandshakeOutput) !void {
        const epochs = [_]crypto.Epoch{ .initial, .handshake, .application };
        for (epochs) |epoch| {
            const slice = out.epochSlice(epoch);
            if (slice.len == 0) continue;
            const space = epochToSpace(epoch);
            try self.crypto_out[@intFromEnum(space)].appendSlice(self.allocator, slice);
        }
        try self.installKeysFromTls();
    }

    fn installKeysFromTls(self: *Connection) !void {
        // Handshake write/read
        if (self.write_keys[@intFromEnum(spaces.SpaceId.handshake)] == null) {
            if (self.tls.trafficSecret(.write, .handshake)) |sec| {
                self.write_keys[@intFromEnum(spaces.SpaceId.handshake)] = packet_crypto.keysFromTrafficSecret(sec.slice());
            } else |_| {}
        }
        if (self.read_keys[@intFromEnum(spaces.SpaceId.handshake)] == null) {
            if (self.tls.trafficSecret(.read, .handshake)) |sec| {
                self.read_keys[@intFromEnum(spaces.SpaceId.handshake)] = packet_crypto.keysFromTrafficSecret(sec.slice());
            } else |_| {}
        }
        // 0-RTT (RFC 9001 §5): the CLIENT installs early WRITE keys the moment
        // the TLS session offers early data (before any server flight), so the
        // first pollTransmit after the ClientHello can already carry 0-RTT
        // data; the remembered transport parameters come with them (RFC 9001
        // §4.6). The SERVER installs early READ keys only when the engine
        // accepted the offer — zigtls derives `zero_rtt_read` exclusively on
        // an accepted ClientHello (replay-filter-fresh ticket), so key
        // presence IS the acceptance signal.
        if (self.role == .client and self.zero_rtt_write_keys == null and
            self.write_keys[@intFromEnum(spaces.SpaceId.data)] == null)
        {
            if (self.tls.trafficSecret(.write, .zero_rtt)) |sec| {
                self.zero_rtt_write_keys = packet_crypto.keysFromTrafficSecret(sec.slice());
                self.zero_rtt_offered = true;
                self.initZeroRttClient();
            } else |_| {}
        }
        if (self.role == .server and self.zero_rtt_read_keys == null) {
            if (self.tls.trafficSecret(.read, .zero_rtt)) |sec| {
                self.zero_rtt_read_keys = packet_crypto.keysFromTrafficSecret(sec.slice());
                self.zero_rtt_accepted = true;
            } else |_| {}
        }
        // Application (1-RTT)
        if (self.write_keys[@intFromEnum(spaces.SpaceId.data)] == null) {
            if (self.tls.trafficSecret(.write, .application)) |sec| {
                self.write_keys[@intFromEnum(spaces.SpaceId.data)] = packet_crypto.keysFromTrafficSecret(sec.slice());
                @memcpy(self.app_write_secret[0..sec.len], sec.slice());
                self.app_write_secret_len = sec.len;
                // noq upgrade_crypto (mod.rs:4124-4128): once 1-RTT write keys
                // exist the client's 0-RTT keys are dead weight — discard them
                // so nothing else can encrypt early packets.
                if (self.role == .client) self.zero_rtt_write_keys = null;
            } else |_| {}
        }
        if (self.read_keys[@intFromEnum(spaces.SpaceId.data)] == null) {
            if (self.tls.trafficSecret(.read, .application)) |sec| {
                self.read_keys[@intFromEnum(spaces.SpaceId.data)] = packet_crypto.keysFromTrafficSecret(sec.slice());
                @memcpy(self.app_read_secret[0..sec.len], sec.slice());
                self.app_read_secret_len = sec.len;
            } else |_| {}
        }

        // Reconcile the client's 0-RTT offer once TLS is complete: the
        // EncryptedExtensions verdict is long settled by then (RFC 8446
        // §4.2.10). A REJECTED offer re-offers all early flight frames under
        // 1-RTT (noq `streams.zero_rtt_rejected`, mod.rs:4682-4710).
        if (self.role == .client and self.zero_rtt_offered and
            !self.zero_rtt_accepted and !self.zero_rtt_rejected and self.tls.isComplete())
        {
            if (self.tls.earlyDataAccepted()) {
                self.zero_rtt_accepted = true;
            } else {
                self.zero_rtt_rejected = true;
                self.onZeroRttRejected();
            }
        }
        // RFC 9001 §4.9.2: the server discards 0-RTT read keys once the
        // handshake completes — every later packet is 1-RTT by construction,
        // and a slow stray 0-RTT flight must not decrypt anymore.
        if (self.role == .server and self.tls.isComplete()) {
            self.zero_rtt_read_keys = null;
        }

        if (self.tls.isComplete() and self.state == .handshake) {
            // Move to established once we have 1-RTT keys and TLS complete.
            if (self.write_keys[@intFromEnum(spaces.SpaceId.data)] != null) {
                self.state = .established;
                self.next_send_at = self.now;
                self.markPathValidated();
                self.applyPeerParams();
                // CID authentication (F5) may have closed the connection —
                // never announce a connected event for it.
                if (self.state != .established) return;
                self.scheduleMtuProbes();
                if (self.role == .server and self.new_token_override.len != 0) self.new_token_pending = true;
                // E12: fill our CID inventory to the peer's advertised limit.
                try self.maybeIssueCids();
                try self.events.pushBack(self.allocator, .connected);
                self.timers.armHandshakeKeyDiscard(self.now);
                // RFC 9001 §4.9.2: the server discards Handshake keys at
                // handshake confirmation (noq connection/mod.rs:4717-4721).
                if (self.role == .server) {
                    // The SERVER confirms the handshake once it holds both
                    // Application-Data keys (RFC 9001 §4.9.2). The client
                    // confirms later, on HANDSHAKE_DONE (frame path). Without
                    // this the data-space PTO is never armed server-side
                    // (ptoDeadline/onPtoExpiry gate on handshake_confirmed), so
                    // a lost flight or ACK gap on the anchor/responder path has
                    // no PTO backstop and stalls until the 5 s keep-alive PING
                    // — the noq-zigtls responder bimodal stall.
                    if (self.read_keys[@intFromEnum(spaces.SpaceId.data)] != null) {
                        self.handshake_confirmed = true;
                    }
                    self.discardSpaceKeys(.handshake);
                }
            }
        }
        if (self.read_keys[@intFromEnum(spaces.SpaceId.data)]) |keys| {
            self.crypto_1rtt.current = keys;
        }
    }

    /// noq `init_0rtt` (mod.rs:3973-4007): the client restores REMEMBERED
    /// transport parameters from the resumption ticket so its 0-RTT flight
    /// knows the send windows before the handshake completes (RFC 9001 §4.6).
    /// Values an attacker or a stale ticket might forge away from this
    /// connection — CID authentication material, preferred address, reset
    /// token, ACK shaping — are stripped first (noq sanitizes the same set).
    fn initZeroRttClient(self: *Connection) void {
        const tp = self.tls.resumptionTransportParams() orelse return;
        const decoded = transport_parameters.decode(tp) catch return;
        var p = decoded;
        p.initial_source_connection_id = null;
        p.original_destination_connection_id = null;
        p.retry_source_connection_id = null;
        p.preferred_address = null;
        p.stateless_reset_token = null;
        p.min_ack_delay = null;
        p.initial_max_path_id = null;
        p.ack_delay_exponent = 3; // RFC 9000 §18: not remembered (noq resets)
        p.max_ack_delay = 25;
        self.peer_params = p;
        self.send_max_data = p.initial_max_data;
        self.zero_rtt_remembered = p;
        self.zero_rtt_peer_params = true;
    }

    /// noq 0-RTT REJECTION (mod.rs:4682-4710): every frame that rode a 0-RTT
    /// packet is re-offered under 1-RTT. Sent 0-RTT packets leave flight
    /// accounting WITHOUT a congestion penalty (noq remove_in_flight — a
    /// rejection is not loss), and their retransmittable content requeues so
    /// the established data space retransmits it. Pending frames that were
    /// never built need nothing: the builder regenerates them from stream
    /// state. Runs at most once (guarded by zero_rtt_rejected).
    fn onZeroRttRejected(self: *Connection) void {
        self.zero_rtt_write_keys = null;
        const old_len = self.sent.items.len;
        var read: usize = 0;
        var write_i: usize = 0;
        while (read < old_len) : (read += 1) {
            const sp = self.sent.items[read];
            if (sp.zero_rtt) {
                if (self.requeueContent(sp)) {
                    self.notePacketLeftFlight(sp);
                    continue;
                }
                // Allocation failure requeueing: retain this record and every
                // later one so the ranges stay pinned (detectAndRequeueLosses
                // discipline).
                while (read < old_len) : (read += 1) {
                    if (write_i != read) self.sent.items[write_i] = self.sent.items[read];
                    write_i += 1;
                }
                break;
            }
            if (write_i != read) self.sent.items[write_i] = sp;
            write_i += 1;
        }
        self.sent.shrinkRetainingCapacity(write_i);
        self.rebuildPtoInflight();
    }

    /// True while this client may still emit 0-RTT packets: an offer is live
    /// (early write keys present) and 1-RTT keys have not replaced them.
    pub fn zeroRttSendActive(self: *const Connection) bool {
        return self.role == .client and
            self.zero_rtt_offered and
            !self.zero_rtt_rejected and
            self.zero_rtt_write_keys != null and
            self.write_keys[@intFromEnum(spaces.SpaceId.data)] == null;
    }

    /// Server-side 0-RTT ACCEPTANCE: the ClientHello's offer cleared the replay
    /// filter and early read keys are installed. The transport's 0-RTT early
    /// accept hands the connection off on this signal (noq `accepted_0rtt`).
    pub fn zeroRttAcceptedServer(self: *const Connection) bool {
        return self.role == .server and self.zero_rtt_accepted;
    }

    /// Client-side verdict once the handshake completes: did the server take
    /// the 0-RTT offer (EncryptedExtensions early_data) or reject it.
    pub fn zeroRttAcceptedClient(self: *const Connection) bool {
        return self.role == .client and self.zero_rtt_accepted;
    }

    /// 0-RTT evidence counters for the oracle (never reason strings).
    pub fn zeroRttStats(self: *const Connection) struct {
        offered: bool,
        accepted: bool,
        packets_sent: u64,
        packets_accepted: u64,
        payload_bytes_received: u64,
        dropped: u64,
    } {
        return .{
            .offered = self.zero_rtt_offered,
            .accepted = self.zero_rtt_accepted,
            .packets_sent = self.stats_zero_rtt_packets_sent,
            .packets_accepted = self.stats_zero_rtt_accepted_packets,
            .payload_bytes_received = self.stats_zero_rtt_payload_bytes,
            .dropped = self.stats_zero_rtt_dropped,
        };
    }

    /// Allocate the next outgoing packet number for `space`. In the Data space
    /// the PacketNumberFilter may skip the scheduled PN (A17, noq
    /// `get_tx_number`, spaces.rs:364-380); the skipped PN is never sent.
    fn allocTxNumber(self: *Connection, space: spaces.SpaceId) u64 {
        const pns = self.spaces_state.get(space);
        var pn = pns.getTxNumber();
        if (pns.pn_filter) |*f| {
            if (f.skipPn(pn, self.rng.random())) pn = pns.getTxNumber();
        }
        return pn;
    }

    /// A16 (noq `CryptoState::remaining_packet_budget`,
    /// connection/packet_crypto.rs:433-442): packets that may still be sent
    /// before the AEAD confidentiality limit at this space. For Data the
    /// effective limit is the minimum of the AEAD limit and the current
    /// key-phase size; other spaces use the raw AEAD limit.
    fn remainingPacketBudget(self: *const Connection, space: spaces.SpaceId) u64 {
        const sent = self.sent_with_keys[@intFromEnum(space)];
        const limit = if (space == .data)
            @min(self.key_phase_size, packet_crypto.confidentiality_limit)
        else
            packet_crypto.confidentiality_limit;
        return limit -| sent;
    }

    /// Highest packet space with outbound keys — noq's `highest_space`
    /// analogue for clearing the close-pending flag (mod.rs:1673-1677).
    fn highestKeyedWriteSpace(self: *const Connection) spaces.SpaceId {
        if (self.write_keys[@intFromEnum(spaces.SpaceId.data)] != null) return .data;
        if (self.write_keys[@intFromEnum(spaces.SpaceId.handshake)] != null) return .handshake;
        return .initial;
    }

    /// B2/B4 (noq connection/mod.rs:1613-1693): the CONNECTION_CLOSE a closing
    /// or draining connection must still emit in `space`, or null when this
    /// space owes nothing. A close rides in EVERY space that currently has
    /// keys (the caller's keys lookup gates that), once per armament, until
    /// the highest keyed space has carried it. Application closes below the
    /// Data space cannot be expressed on the wire (RFC 9000 §10.2.3) and are
    /// rewritten to a transport APPLICATION_ERROR close (noq mod.rs:1654-1663);
    /// a draining peer-close answer is always a NO_ERROR transport close
    /// (noq mod.rs:1664).
    fn pendingCloseForSpace(self: *const Connection, space: spaces.SpaceId) ?frame.ConnectionClose {
        const bit: u3 = @as(u3, 1) << @intCast(@intFromEnum(space));
        if (self.state == .closed) {
            const cc = self.close_frame orelse return null;
            if (self.close_sent or (self.close_sent_mask & bit) != 0) return null;
            if (space == .data or !cc.is_app) return cc;
            return .{ .error_code = err_application_error, .reason = "", .is_app = false };
        }
        if (self.state == .draining) {
            if (!self.drain_close_pending or (self.close_sent_mask & bit) != 0) return null;
            return .{ .error_code = err_no_error, .reason = "", .is_app = false };
        }
        return null;
    }

    /// B3 (noq connection/mod.rs:4463-4470): the closed-state close re-arm
    /// fires only for a peer on a validated path. noq checks
    /// `path.data.validated && path.network_path == network_path`; this
    /// connection is single-path without remote-address tracking, so the
    /// equivalent is "the peer's address was validated at any point": path
    /// validation proper, handshake confirmation, or a first authenticated
    /// Handshake packet (noq's `on_path_validated` timing, mod.rs:4657).
    fn closeRearmRemoteValidated(self: *const Connection) bool {
        return self.isPathValidated() or self.peer_handshake_authed;
    }

    /// G5 (noq populate_ack_frame, connection/mod.rs:6576-6579): the outgoing
    /// ACK Delay field is (now − time the largest acked PN was received) in
    /// microseconds, right-shifted by the ack_delay_exponent WE advertise
    /// (noq uses its non-configurable default 3, flagged with a TODO — ours
    /// comes from local_params, default also 3). Encoded for every space;
    /// the receiver ignores it outside 1-RTT (noq mod.rs:3005-3007, mirrored
    /// by `scaledAckDelayNs`).
    fn wireAckDelay(self: *const Connection, si: usize) u64 {
        const recv_at = self.pending_acks[si].largest_recv_time_ns orelse return 0;
        const delta_ns = @max(self.now - recv_at, 0);
        const delay_micros: u64 = @intCast(@divTrunc(delta_ns, 1000));
        const exp: u6 = @intCast(@min(self.local_params.ack_delay_exponent, 20));
        return delay_micros >> exp;
    }

    /// Emit the space's owed ACK (multi-range + ECN, RFC 9000 §19.3) into
    /// `frames[n]` and clear the obligation. Returns the encoded size so the
    /// caller can debit its budget; 0 when nothing was owed.
    fn emitOwedAck(self: *Connection, si: usize, frames: *[16]frame.Frame, n: *usize) usize {
        if (!self.needs_ack[si]) return 0;
        const ack_base = self.pending_acks[si].toAckFrame(self.wireAckDelay(si)) orelse return 0;
        var ack = ack_base;
        const ecn_nonempty = self.ecn_counts.ect0 != 0 or self.ecn_counts.ect1 != 0 or self.ecn_counts.ce != 0;
        if (ecn_nonempty) ack.ecn = self.ecn_counts;
        frames[n.*] = .{ .ack = ack };
        n.* += 1;
        self.needs_ack[si] = false;
        // The obligation is discharged; a later deferred ACK re-arms.
        self.ack_deadline[si] = null;
        // G4 (noq PendingAcks::acks_sent, spaces.rs:1256-1271): once an ACK
        // goes out, the threshold count restarts and the largest PN this ACK
        // reports is recorded for the draft-§6.1 out-of-order branch (noq
        // assumes the ACK covers everything received — spaces.rs:1257-1265).
        // The pending count is a Data-space-only counter (the threshold
        // cadence applies there only), so only a Data ACK restarts it.
        if (si == @intFromEnum(spaces.SpaceId.data)) self.peer_ack_eliciting_pending = 0;
        self.largest_acked_sent[si] = self.largest_ack_eliciting_recv[si];
        return frames[n.* - 1].encodedLen();
    }

    fn buildSpacePacket(self: *Connection, space: spaces.SpaceId, wire_cap: usize, initial_pad: usize, extra_min_size: usize) Error!?Transmit {
        if (space == .data) self.maybeStartMtuProbe();
        // A pre-established client with a live 0-RTT offer builds a 0-RTT
        // long-header packet from the data space (early WRITE keys, data-space
        // PNs — RFC 9001 §5). 1-RTT packets use the space keys as before.
        const building_zero_rtt = space == .data and self.zeroRttSendActive() and self.state != .established;
        const keys = if (building_zero_rtt)
            (self.zero_rtt_write_keys orelse return null)
        else
            (self.write_keys[@intFromEnum(space)] orelse return null);
        // Packet assembly mutates send cursors and retransmit queues. Reserve
        // the sent-record slot before any such mutation so allocation failure
        // cannot leave bytes neither tracked nor queued for retransmission.
        if (self.sent.items.len >= max_tracked_sent_packets) return error.NoSpaceLeft;
        try self.sent.ensureUnusedCapacity(self.allocator, 1);
        const si = @intFromEnum(space);
        var frames: [16]frame.Frame = undefined;
        var n: usize = 0;
        var content: [max_content]FrameRef = undefined;
        var cn: usize = 0;
        var ack_eliciting = false;
        var budget: usize = if (space == .data) self.dataPayloadBudget() else base_data_payload_budget;
        // A3: a coalesced followup packet is bounded to the room left in the
        // datagram. max_datagram (the first-packet value) never binds.
        budget = @min(budget, wire_cap);
        var datagram_wire: ?[]const u8 = null;
        var stream_payload_bytes: usize = 0;
        var paced_payload_bytes: usize = 0;
        var ack_freq_sent_us: ?u64 = null;
        const pace_content_blocked = space == .data and self.pace_content_blocked;
        if (space == .data and !pace_content_blocked and self.hasPacedOutbound()) {
            const pacing_budget: usize = @intCast(@min(self.pacing_tokens, @as(u64, @intCast(budget))));
            budget = @min(budget, pacing_budget);
        }
        var reset_commits = [_]bool{false} ** max_streams;
        var pad_to_min_mtu = false;

        // B2/B4 (noq connection/mod.rs:1613-1693): a closing or draining
        // connection emits ONLY close packets — the space's owed ACKs first
        // (noq populates ACKs before the close, mod.rs:1615-1638), then the
        // CONNECTION_CLOSE, nothing else. noq's poll_transmit sends nothing at
        // all in Closed/Draining unless a close is pending (mod.rs:1039-1047),
        // so a space without a pending close produces no packet here either.
        if (self.state == .closed or self.state == .draining) {
            const cc = self.pendingCloseForSpace(space) orelse return null;
            const ack_len = self.emitOwedAck(si, &frames, &n);
            // B9 (noq CloseEncoder, frame.rs:936-947): the reason phrase is
            // truncated to fit THIS packet's remaining frame budget (noq's
            // `frame_space_remaining` at mod.rs:1667-1669) rather than
            // overflowing the packet or failing the encode.
            var cc_bounded = cc;
            cc_bounded.reason = frame.truncatedCloseReason(cc, budget -| ack_len);
            frames[n] = .{ .connection_close = cc_bounded };
            n += 1;
            ack_eliciting = true;
            // noq pads a client Initial close's datagram to the 1200 floor
            // (PadDatagram::ToMinMtu, mod.rs:1603-1608) — the Initial close
            // then fills its own datagram and any Handshake close goes out in
            // the next one. A server Initial close is NOT padded (noq's
            // SendableFrames::is_ack_eliciting is false for close-only).
            const close_pad = if (space == .initial and self.role == .client) min_client_initial_datagram_size else initial_pad;
            const pn = self.allocTxNumber(space);
            const tx = self.finishPacket(space, keys, frames[0..n], &content, cn, ack_eliciting, pn, extra_min_size, 0, close_pad, false) catch |err| switch (err) {
                error.KeyBudgetExhausted => return null,
                else => |e| return e,
            };
            self.close_sent_mask |= @as(u3, 1) << @intCast(si);
            // The close is fully sent once the HIGHEST keyed space carried it
            // (noq clears connection_close_pending at highest_space,
            // mod.rs:1673-1677); lower spaces already rode along this pass.
            if (space == self.highestKeyedWriteSpace()) {
                if (self.state == .closed) {
                    self.close_sent = true;
                } else {
                    self.drain_close_pending = false;
                }
            }
            return tx;
        }

        // ACK (multi-range, RFC 9000 §19.3) from the per-space receive tracker.
        // RFC 9000 §12.4: ACK MUST NOT ride a 0-RTT packet.
        if (self.needs_ack[si] and !building_zero_rtt) {
            const ack_len = self.emitOwedAck(si, &frames, &n);
            if (ack_len > 0) {
                // Debit the ACK's wire size from this packet's budget. The ACK
                // is the one frame emitted unconditionally, without a budget
                // check; a large multi-range ACK (up to max_ack_additional
                // ranges under loss) plus a budget-filling STREAM frame
                // otherwise overflows tx_scratch — the encode failure surfaced
                // as pollTransmit → pumpOutgoing → ConnectionLost and killed
                // sustained-transfer responders under loss (run
                // 20260726T023440Z: 64 MiB echo vs Rust requester, 0/5).
                budget -|= ack_len;
            }
        }

        // CRYPTO: retransmit lost chunks first, then fresh unsent bytes.
        // RFC 9001 §8.3: CRYPTO frames MUST NOT be sent in 0-RTT packets.
        if (!pace_content_blocked and !building_zero_rtt) {
            const cbuf = &self.crypto_out[si];
            const rtx = &self.crypto_rtx[si];
            while (rtx.len > 0 and n < frames.len and cn < max_content and budget > 64) {
                const ch = rtx.popFront().?;
                const off: usize = @intCast(ch.offset);
                const len: usize = @intCast(@min(ch.len, budget - 32));
                frames[n] = .{ .crypto = .{ .offset = ch.offset, .data = cbuf.items[off .. off + len] } };
                content[cn] = .{ .crypto = .{ .space = space, .offset = ch.offset, .len = len } };
                n += 1;
                cn += 1;
                paced_payload_bytes += len;
                ack_eliciting = true;
                budget -|= len + 8;
                if (len < ch.len) rtx.pushBackAssumeCapacity(.{ .offset = ch.offset + len, .len = ch.len - len, .fin = false });
            }
            const sent_hw: usize = @intCast(self.crypto_sent[si]);
            if (cbuf.items.len > sent_hw and n < frames.len and cn < max_content and budget > 64) {
                const avail = cbuf.items.len - sent_hw;
                const len = @min(avail, budget - 32);
                frames[n] = .{ .crypto = .{ .offset = self.crypto_sent[si], .data = cbuf.items[sent_hw .. sent_hw + len] } };
                content[cn] = .{ .crypto = .{ .space = space, .offset = self.crypto_sent[si], .len = len } };
                n += 1;
                cn += 1;
                paced_payload_bytes += len;
                ack_eliciting = true;
                budget -|= len + 8;
                self.crypto_sent[si] = @intCast(sent_hw + len);
            }
        }

        // A5 anti-deadlock PTO probe (noq `queue_tail_loss_probe` PING
        // fallback): queued by onPtoExpiry when PTO fired with nothing
        // outstanding and nothing pending to send.
        if (self.pending_ping[si] and n < frames.len) {
            frames[n] = .ping;
            n += 1;
            ack_eliciting = true;
            self.pending_ping[si] = false;
        }

        if (space == .data and (self.state == .established or building_zero_rtt)) {
            // NEW_CONNECTION_ID when queued.
            if (!building_zero_rtt and self.pending_new_cid and n < frames.len) {
                frames[n] = .{ .new_connection_id = .{
                    .sequence = self.pending_new_cid_seq,
                    .retire_prior_to = self.pending_new_cid_retire,
                    .connection_id = self.pending_new_cid_buf[0..self.pending_new_cid_len],
                    .reset_token = self.pending_new_cid_reset,
                } };
                n += 1;
                ack_eliciting = true;
            }

            // NEW_TOKEN once after handshake (address validation). E7: only the
            // transport-issued sealed token is ever sent — never invented bytes.
            // RFC 9000 §12.4: NEW_TOKEN MUST NOT ride a 0-RTT packet.
            if (!building_zero_rtt and self.new_token_pending and self.new_token_override.len != 0 and n < frames.len) {
                frames[n] = .{ .new_token = .{ .token = self.new_token_override } };
                n += 1;
                ack_eliciting = true;
                self.new_token_pending = false;
            }

            // ACK_FREQUENCY (RFC 9368): once after handshake, then re-sent
            // when the RTT-derived candidate diverges enough from the value
            // in force (G10, noq should_send_ack_frequency — the schedule is
            // evaluated on every poll like noq's poll_transmit,
            // mod.rs:1054-1066). `request_max_ack_delay` is MICROSECONDS; the
            // transport-parameter `max_ack_delay` is MILLISECONDS. Quinn
            // rejects values below its timer granularity (~1 ms) with
            // PROTOCOL_VIOLATION ("less than min_ack_delay") — the post-TP
            // interop-noq failure mode; the candidate's 25 ms floor keeps us
            // clear of it.
            if (!building_zero_rtt and self.shouldSendAckFrequency()) self.ack_frequency_pending = true;
            if (!building_zero_rtt and self.ack_frequency_pending and n < frames.len) {
                const requested_us = self.candidateAckFreqDelayUs();
                frames[n] = .{ .ack_frequency = .{
                    .sequence_number = self.ack_frequency_seq,
                    .ack_eliciting_threshold = 2,
                    .request_max_ack_delay = requested_us,
                    .reordering_threshold = 1,
                } };
                n += 1;
                ack_eliciting = true;
                self.ack_frequency_pending = false;
                self.ack_frequency_seq += 1;
                // The PN is allocated below; record the in-flight request
                // there (noq ack_frequency_sent, ack_frequency.rs:98-105).
                ack_freq_sent_us = requested_us;
            }

            // G13 (noq poll_transmit_path_space, mod.rs:6090-6100): an owed
            // IMMEDIATE_ACK rides the next Data packet — queued by tail-loss
            // and MTU probes. Data space only (noq debug_assert,
            // mod.rs:6093-6096; the frame is illegal elsewhere anyway).
            if (!building_zero_rtt and self.pending_immediate_ack and n < frames.len) {
                frames[n] = .immediate_ack;
                n += 1;
                ack_eliciting = true;
                self.pending_immediate_ack = false;
            }

            // Outbound DATAGRAM frames.
            if (self.datagram_out.len > 0 and n < frames.len and budget > 64) {
                const d = self.datagram_out.front().?;
                datagram_wire = d;
                // Always length-bearing: a terminal no-LEN DATAGRAM (0x30) would consume
                // packet padding zeros as application data once decode is cursor-based.
                frames[n] = .{ .datagram = .{ .data = d, .with_length = true } };
                n += 1;
                ack_eliciting = true;
                budget -|= d.len + 8;
            }

            // HandshakeDone (server).
            if (self.role == .server and !self.handshake_done_sent) {
                frames[n] = .handshake_done;
                n += 1;
                ack_eliciting = true;
                self.handshake_done_sent = true;
            }

            // STREAMS_BLOCKED when a caller hit the peer's advertised stream limit.
            if (self.streams_blocked_bidi_pending) |limit| {
                if (n < frames.len) {
                    frames[n] = .{ .streams_blocked_bidi = limit };
                    n += 1;
                    ack_eliciting = true;
                    self.streams_blocked_bidi_sent_at = limit;
                    self.streams_blocked_bidi_pending = null;
                }
            }
            if (self.streams_blocked_uni_pending) |limit| {
                if (n < frames.len) {
                    frames[n] = .{ .streams_blocked_uni = limit };
                    n += 1;
                    ack_eliciting = true;
                    self.streams_blocked_uni_sent_at = limit;
                    self.streams_blocked_uni_pending = null;
                }
            }

            // MAX_STREAMS regrant when peer-initiated streams reach a retired state.
            self.appendMaxStreamsRegrants(&frames, &n, &ack_eliciting);

            // Connection-level window grant (MAX_DATA) as the app consumes data.
            var total_consumed: u64 = 0;
            for (&self.streams) |*s| {
                if (s.used) total_consumed += s.recv.consumed;
            }
            const desired_conn = total_consumed + self.local_params.initial_max_data;
            if (desired_conn > self.recv_max_data and n < frames.len) {
                self.recv_max_data = desired_conn;
                frames[n] = .{ .max_data = desired_conn };
                n += 1;
                ack_eliciting = true;
            }
            // PATH_RESPONSE (echo owed challenges) then PATH_CHALLENGE (probe).
            // Datagrams carrying either are padded to 1200 (RFC 9000 §8.2.1
            // / noq require_padding) — a path probe must be a full-size probe.
            // RFC 9000 §12.4: PATH_CHALLENGE/PATH_RESPONSE MUST NOT ride 0-RTT.
            while (!building_zero_rtt and self.response_tx_len > 0 and n < frames.len) {
                frames[n] = .{ .path_response = self.response_tx[0] };
                n += 1;
                ack_eliciting = true;
                pad_to_min_mtu = true;
                std.mem.copyForwards([8]u8, self.response_tx[0 .. self.response_tx_len - 1], self.response_tx[1..self.response_tx_len]);
                self.response_tx_len -= 1;
            }
            // n0 NAT-traversal address advertisements (magicsock). Never in
            // 0-RTT: they are address-discovery frames negotiated post-handshake.
            while (!building_zero_rtt and self.nat_out_len > 0 and n < frames.len) {
                const a = self.nat_out[0];
                // F13: an OBSERVED_ADDR frame may only leave when the roles
                // negotiated it (we send, the peer receives) — the n0 NAT
                // frames are separately negotiated by their own TP.
                if (a.kind == .observed and !self.observedAddrSendNegotiated()) {
                    std.mem.copyForwards(NatAddress, self.nat_out[0 .. self.nat_out_len - 1], self.nat_out[1..self.nat_out_len]);
                    self.nat_out_len -= 1;
                    continue;
                }
                frames[n] = switch (a.kind) {
                    .observed => .{ .observed_ipv4_addr = .{ .seq = a.seq, .ip = a.ip, .port = a.port } },
                    .add => .{ .add_ipv4_address = .{ .seq = a.seq, .ip = a.ip, .port = a.port } },
                    .reach_out => .{ .reach_out_at_ipv4 = .{ .seq = a.seq, .ip = a.ip, .port = a.port } },
                    .remove => .{ .remove_address = a.seq },
                };
                n += 1;
                ack_eliciting = true;
                std.mem.copyForwards(NatAddress, self.nat_out[0 .. self.nat_out_len - 1], self.nat_out[1..self.nat_out_len]);
                self.nat_out_len -= 1;
            }

            while (!building_zero_rtt and self.challenge_pending_len > 0 and n < frames.len) {
                const token = self.challenge_pending[0];
                const hint = self.challenge_pending_hints[0]; // capture BEFORE the shift
                frames[n] = .{ .path_challenge = token };
                n += 1;
                ack_eliciting = true;
                pad_to_min_mtu = true;
                std.mem.copyForwards([8]u8, self.challenge_pending[0 .. self.challenge_pending_len - 1], self.challenge_pending[1..self.challenge_pending_len]);
                std.mem.copyForwards(?u64, self.challenge_pending_hints[0 .. self.challenge_pending_len - 1], self.challenge_pending_hints[1..self.challenge_pending_len]);
                self.challenge_pending_len -= 1;
                const new_challenge = !self.challengeAwaited(token);
                if (self.challenge_await_len < max_path_tokens) {
                    self.challenge_await[self.challenge_await_len] = token;
                    self.challenge_await_hints[self.challenge_await_len] = hint;
                    self.challenge_await_len += 1;
                }
                // A NEW challenge arms the retransmission clock; a re-drive
                // of an already-outstanding token never resets it (the timeout
                // handler owns backoff, and a dead-probe clear must stick).
                if (self.timers.path_challenge_deadline == null and new_challenge) {
                    self.timers.path_challenge_deadline = self.now + loss.ptoDelay(self.rtt, 0, 0, self.ptoMaxIntervalNs());
                    self.timers.path_challenge_attempts = 0;
                }
            }

            // Per-stream control + data.
            var idx: usize = 0;
            while (idx < self.streams.len and n + 1 < frames.len and cn < max_content) : (idx += 1) {
                const e = &self.streams[idx];
                if (!e.used) continue;

                // RESET_STREAM.
                if (e.send.reset_code) |code| {
                    if (!e.send.reset_sent) {
                        frames[n] = .{ .reset_stream = .{ .stream_id = e.id, .app_error_code = code, .final_size = e.send.reset_final_size.? } };
                        content[cn] = .{ .reset_stream = .{ .id = e.id } };
                        n += 1;
                        cn += 1;
                        ack_eliciting = true;
                        reset_commits[idx] = true;
                    }
                    continue; // no data after reset
                }

                // STOP_SENDING.
                if (e.recv.stop_code) |code| {
                    if (!e.recv.stop_sent and n < frames.len and cn < max_content) {
                        frames[n] = .{ .stop_sending = .{ .stream_id = e.id, .app_error_code = code } };
                        content[cn] = .{ .stop_sending = .{ .id = e.id } };
                        n += 1;
                        cn += 1;
                        ack_eliciting = true;
                        e.recv.stop_sent = true;
                    }
                }

                // MAX_STREAM_DATA grant: advertise consumed + window as the app drains.
                const desired = e.recv.consumed + self.recvStreamWindow(e.id, e.dir);
                if (desired > e.recv.max_data and n < frames.len) {
                    e.recv.max_data = desired;
                    frames[n] = .{ .max_stream_data = .{ .stream_id = e.id, .max_data = desired } };
                    n += 1;
                    ack_eliciting = true;
                }

                // Retransmit lost stream chunks first.
                while (!pace_content_blocked and e.send.rtx.len > 0 and n < frames.len and cn < max_content and budget > 64) {
                    const cc_room = self.congestionSendWindow();
                    if (cc_room == 0) {
                        self.stats_cc_limited += 1;
                        break;
                    }
                    const ch = e.send.rtx.popFront().?;
                    std.debug.assert(ch.offset >= e.send.buf_offset);
                    std.debug.assert(ch.offset + ch.len <= e.send.endOffset());
                    const take = @min(@as(usize, @intCast(ch.len)), @as(usize, @intCast(@min(cc_room, @as(u64, @intCast(budget - 32))))));
                    const fin = ch.fin and take == ch.len;
                    frames[n] = .{ .stream = .{ .id = e.id, .offset = ch.offset, .fin = fin, .data = e.send.sliceAt(ch.offset, take) } };
                    content[cn] = .{ .stream = .{ .id = e.id, .offset = ch.offset, .len = take, .fin = fin } };
                    n += 1;
                    cn += 1;
                    stream_payload_bytes += take;
                    paced_payload_bytes += take;
                    ack_eliciting = true;
                    budget -|= take + 8;
                    if (take < ch.len) e.send.rtx.pushBackAssumeCapacity(.{ .offset = ch.offset + take, .len = ch.len - take, .fin = ch.fin });
                }

                // Fresh stream data, bounded by flow control.
                const send_end = e.send.endOffset();
                const pending: usize = @intCast(send_end - @min(e.send.send_next, send_end));
                if (!pace_content_blocked and pending > 0 and n < frames.len and cn < max_content and budget > 64) {
                    const stream_room = self.streamSendRoom(e);
                    const conn_room = self.connectionSendRoom();
                    const flow_window = @min(stream_room, conn_room);
                    if (flow_window == 0) {
                        // Flow-control blocked → signal once per blocking window.
                        if (conn_room == 0 and self.data_blocked_at != self.send_max_data) {
                            frames[n] = .{ .data_blocked = self.send_max_data };
                            n += 1;
                            ack_eliciting = true;
                            self.data_blocked_at = self.send_max_data;
                        } else if (stream_room == 0 and e.send.blocked_at != e.send.max_data) {
                            frames[n] = .{ .stream_data_blocked = .{ .stream_id = e.id, .max_data = e.send.max_data } };
                            n += 1;
                            ack_eliciting = true;
                            e.send.blocked_at = e.send.max_data;
                        }
                    } else {
                        const cc_room = self.congestionSendWindow();
                        if (cc_room == 0) {
                            self.stats_cc_limited += 1;
                            continue;
                        }
                        const window = @min(flow_window, cc_room);
                        const take = @min(pending, @as(usize, @intCast(@min(window, @as(u64, @intCast(budget - 32))))));
                        const fin = e.send.fin and e.send.send_next + take == send_end;
                        frames[n] = .{ .stream = .{ .id = e.id, .offset = e.send.send_next, .fin = fin, .data = e.send.sliceAt(e.send.send_next, take) } };
                        content[cn] = .{ .stream = .{ .id = e.id, .offset = e.send.send_next, .len = take, .fin = fin } };
                        n += 1;
                        cn += 1;
                        stream_payload_bytes += take;
                        paced_payload_bytes += take;
                        ack_eliciting = true;
                        budget -|= take + 8;
                        e.send.send_next += take;
                        self.send_data_total += take;
                        if (fin) e.send.fin_sent = true;
                    }
                } else if (e.send.fin and !e.send.fin_sent and pending == 0 and n < frames.len and cn < max_content) {
                    // Empty tail FIN (all bytes already sent, FIN not yet).
                    const off = e.send.endOffset();
                    frames[n] = .{ .stream = .{ .id = e.id, .offset = off, .fin = true, .data = &.{} } };
                    content[cn] = .{ .stream = .{ .id = e.id, .offset = off, .len = 0, .fin = true } };
                    n += 1;
                    cn += 1;
                    ack_eliciting = true;
                    e.send.fin_sent = true;
                }
            }
        }

        // Idle MTU probe: PING-only padded packet when no other data frames queued.
        // At most one probe in flight (`probe_pn != null`). Re-emitting on every
        // pollTransmit while probe_mtu is set makes pumpOnce's drain loop spin
        // forever (ACK ↔ PING ping-pong with a new PN each iteration).
        if (space == .data and self.state == .established and n == 0) {
            if (self.probe_mtu) |target| {
                if (self.probe_pn == null) {
                    if (target > max_datagram) {
                        // Cannot pad beyond tx_scratch — drop this probe size.
                        self.probe_mtu = null;
                        return null;
                    }
                    frames[n] = .ping;
                    n += 1;
                    // G13 (noq poll_transmit_mtu_probe, mod.rs:1822-1827): an
                    // MTU probe asks for an un-delayed ACK via IMMEDIATE_ACK
                    // (noq gates on peer_supports_ack_frequency — the
                    // min_ack_delay TP, F11, not landed; always-on here).
                    frames[n] = .immediate_ack;
                    n += 1;
                    ack_eliciting = true;
                    const pn = self.allocTxNumber(space);
                    return self.finishPacket(space, keys, frames[0..n], &content, cn, ack_eliciting, pn, target, 0, initial_pad, false) catch |err| switch (err) {
                        error.AntiAmplificationLimit, error.NoSpaceLeft, error.KeyBudgetExhausted => {
                            self.probe_mtu = null;
                            self.probe_pn = null;
                            return null;
                        },
                        else => |e| return e,
                    };
                }
            }
        }

        if (n == 0) return null;

        const pn = self.allocTxNumber(space);
        var min_size: usize = 0;
        // A datagram carrying PATH_CHALLENGE/RESPONSE pads to 1200.
        if (pad_to_min_mtu) min_size = min_client_initial_datagram_size;
        if (space == .data and ack_eliciting and stream_payload_bytes > 0) {
            if (self.probe_mtu) |target| {
                if (target > max_datagram) {
                    self.probe_mtu = null;
                } else if (stream_payload_bytes * 2 >= target and self.congestionSendWindow() >= target) {
                    min_size = @intCast(target);
                }
            }
        }
        const tx = self.finishPacket(space, keys, frames[0..n], &content, cn, ack_eliciting, pn, @max(min_size, extra_min_size), paced_payload_bytes, initial_pad, building_zero_rtt) catch |err| switch (err) {
            error.AntiAmplificationLimit, error.KeyBudgetExhausted => return null,
            else => |e| return e,
        };
        // RFC 9001 §4.9.1: a client discards its Initial keys once its first
        // Handshake packet is on the wire (noq connection/mod.rs:1576-1583).
        if (space == .handshake and self.role == .client) self.discardSpaceKeys(.initial);
        // G10 (noq ack_frequency_sent, ack_frequency.rs:98-105): the request
        // is in flight until this packet is acknowledged (onAckFrequencyAcked).
        if (ack_freq_sent_us) |requested_us| {
            self.ack_freq_in_flight_pn = pn;
            self.ack_freq_in_flight_value_us = requested_us;
        }
        for (reset_commits, 0..) |commit, stream_i| {
            if (commit) self.streams[stream_i].send.reset_sent = true;
        }
        if (datagram_wire) |owned| {
            _ = self.takeDatagramOut();
            self.allocator.free(owned);
        }
        return tx;
    }

    fn finishPacket(
        self: *Connection,
        space: spaces.SpaceId,
        keys_in: packet_crypto.PacketKeys,
        frames: []const frame.Frame,
        content: *const [max_content]FrameRef,
        cn: usize,
        ack_eliciting: bool,
        pn: u64,
        min_datagram_size: usize,
        paced_payload_bytes: usize,
        /// A3: packet-level floor for an Initial — the client's 1200 when the
        /// Initial closes its own datagram, 0 when pollTransmit proved a
        /// Handshake followup will carry the datagram floor instead.
        initial_pad: usize,
        /// Build a 0-RTT LONG-HEADER packet instead of a 1-RTT short-header
        /// one (data space only; early keys are passed in `keys_in`).
        zero_rtt: bool,
    ) Error!Transmit {
        var keys = keys_in;
        // A16 AEAD confidentiality budget (noq `PacketBuilder::new`,
        // connection/packet_builder.rs:60-87). Checked here, where a packet is
        // certain to be emitted — buildSpacePacket is speculative and may
        // assemble zero frames, in which case noq builds nothing at all.
        const remaining_budget = if (zero_rtt)
            (packet_crypto.confidentiality_limit -| self.sent_with_zero_rtt)
        else
            self.remainingPacketBudget(space);
        if (zero_rtt) {
            // Early keys never rotate (RFC 9001 §6): budget exhaustion simply
            // stops 0-RTT sends; 1-RTT takes over once established.
            if (remaining_budget == 0) return error.KeyBudgetExhausted;
        } else if (space == .data) {
            // 1-RTT keys can be rotated, so exhaustion triggers a key update.
            // Like noq's force_key_update this is a no-op when an update is
            // already in flight or the connection is not yet established.
            if (remaining_budget == 0) {
                self.initiateKeyUpdate() catch {};
                keys = self.write_keys[@intFromEnum(space)] orelse return error.MissingKeys;
            }
        } else {
            // Initial/Handshake have a fixed key budget: send the last
            // permitted packet with a graceful close, then refuse to send.
            if (remaining_budget == 0) {
                // noq `Connection::kill`: local termination with no
                // CONNECTION_CLOSE — sending one would itself exceed the limit.
                self.state = .{ .draining = .{ .is_local = true, .reason = "aead-limit-reached" } };
                self.timers.armClose(self.now);
                try self.events.pushBack(self.allocator, .{ .connection_lost = .{ .is_local = true, .reason = "aead-limit-reached" } });
                return error.KeyBudgetExhausted;
            } else if (remaining_budget == 1) {
                self.protocolClose(err_aead_limit_reached);
            }
        }
        const key_phase = if (space == .data and !zero_rtt) self.write_key_phase else false;
        const built = switch (space) {
            // The Initial carries the token the client holds: a Retry token
            // after consumeRetry (E6) or a stored NEW_TOKEN token at connect
            // (E8). Empty before any token exists (RFC 9000 §8.1).
            .initial => try packet_builder.buildLongHeader(&self.tx_scratch, .initial, 1, self.remote_cid, self.local_cid, self.initial_token, pn, frames, keys, @max(initial_pad, min_datagram_size)),
            // min_datagram_size carries the A3 datagram floor when this
            // Handshake packet is the last one of a coalesced client flight.
            .handshake => try packet_builder.buildLongHeader(&self.tx_scratch, .handshake, 1, self.remote_cid, self.local_cid, "", pn, frames, keys, min_datagram_size),
            // 0-RTT rides a long header (long_kind 1) under EARLY keys with a
            // Data-space packet number (RFC 9001 §5 / RFC 9000 §12.2.4).
            .data => if (zero_rtt)
                try packet_builder.buildLongHeader(&self.tx_scratch, .zero_rtt, 1, self.remote_cid, self.local_cid, "", pn, frames, keys, min_datagram_size)
            else
                try packet_builder.buildOneRtt(&self.tx_scratch, self.remote_cid, pn, key_phase, frames, keys, min_datagram_size),
        };
        // A16 (noq `inc_sent_with_keys`, packet_builder.rs:363): every
        // encrypted packet spends one unit of the key's confidentiality budget
        // (0-RTT spends the separate early-key budget, noq sent_with_zero_rtt).
        if (zero_rtt) self.sent_with_zero_rtt +|= 1 else self.sent_with_keys[@intFromEnum(space)] +|= 1;
        if (zero_rtt) self.stats_zero_rtt_packets_sent += 1;
        if (self.role == .server and !self.isPathValidated()) {
            const limit = self.bytes_received * 3;
            if (self.bytes_sent_unvalidated + built.bytes.len > limit) return error.AntiAmplificationLimit;
            self.bytes_sent_unvalidated += built.bytes.len;
        }
        if (self.probe_mtu != null and min_datagram_size > 0) self.probe_pn = pn;
        // G9 (noq build_transmit, mod.rs:1251-1257): EVERY space's packets
        // are marked ECT(0) while ECN is enabled — `sending_ecn` starts true
        // (paths.rs:304) and noq's ecn selection has no space check. The
        // validation feedback loop (validatePeerEcn) still keys on the Data
        // space only, so a handshake-space ACK without an ECN block cannot
        // disable marking.
        const ecn: ?udp_cmsg.EcnCodepoint = self.outgoingEcn();
        if (ecn) |cp| switch (cp) {
            .ect0 => self.ecn_sent.ect0 += 1,
            .ect1 => self.ecn_sent.ect1 += 1,
            .ce => self.ecn_sent.ce += 1,
        };
        var sp: SentPacket = .{
            .path_generation = self.path_generation,
            .time_sent = self.now,
            .size = @intCast(built.bytes.len),
            .ack_eliciting = ack_eliciting,
            .app_limited = space == .data and self.appLimitedAfterTransmit(),
            .packet_number = pn,
            .space = space,
            .content_len = @intCast(cn),
            .ecn_marked = ecn != null,
            .zero_rtt = zero_rtt,
        };
        var i: usize = 0;
        while (i < cn) : (i += 1) sp.content[i] = content[i];
        self.trackSent(sp);
        if (self.pending_new_cid and space == .data) {
            const cid = try packet.ConnectionId.init(self.pending_new_cid_buf[0..self.pending_new_cid_len]);
            if (self.local_cid_len < max_local_cid_slots) {
                self.local_cids[self.local_cid_len] = .{
                    .sequence = self.pending_new_cid_seq,
                    .cid = cid,
                    .reset_token = self.pending_new_cid_reset,
                };
                self.local_cid_len += 1;
            }
            self.pending_new_cid = false;
            // E12: keep the inventory filled to the peer's limit.
            try self.maybeIssueCids();
        }
        if (space == .data and self.remote_update_unacked and key_phase == self.crypto_1rtt.key_phase) {
            self.remote_update_unacked = false;
        }
        if (self.probe_mtu != null and space == .data) {
            // probe_pn set above; cleared when ACKed in onAck
        }
        const pacing = self.dataPacingRate();
        if (pacing) |rate| {
            // Pace packets that carry STREAM/CRYPTO bytes. Control-only frames
            // (ACK/PING/NEW_TOKEN/PATH/NAT) do not consume the token budget.
            if (rate > 0 and paced_payload_bytes > 0) {
                if (self.pacing_last_refill_at == null) self.refillPacingTokens(self.now, rate);
                self.debitPacingBytes(sp.size, rate);
            }
        }
        // RFC 9000 §10.1 (noq packet_builder.rs:303-318): a send restarts the
        // idle timer only for the FIRST ack-eliciting packet since the last
        // received-and-processed packet. Unconditional arming here lets our
        // own keep-alive PINGs and PTO probes extend a silent peer's lease
        // forever: the connection never idle-times-out and the caller waits
        // out the full stream timeout instead (the AnchorAckTimeout signature
        // observed under UDP drop stress).
        if (ack_eliciting) {
            if (self.permit_idle_reset) self.armIdle(self.now);
            self.permit_idle_reset = false;
        }
        return .{ .bytes = built.bytes, .ecn = ecn };
    }

    fn trackSent(self: *Connection, sp: SentPacket) void {
        std.debug.assert(self.sent.items.len < max_tracked_sent_packets);
        self.sent.appendAssumeCapacity(sp);
        if (self.sent.items.len > self.stats_peak_sent) self.stats_peak_sent = self.sent.items.len;
        if (sp.ack_eliciting) {
            self.bytes_in_flight +|= sp.size;
            self.last_ack_eliciting_sent[@intFromEnum(sp.space)] = sp.time_sent;
            self.notePtoInflightAdd(sp);
            if (self.cc) |cc| {
                cc.onPacketSent(self.now, sp.size, sp.packet_number);
                cc.onSent(self.now, sp.size, sp.packet_number);
            }
        }
    }

    fn notePacketLeftFlight(self: *Connection, sp: SentPacket) void {
        if (!sp.ack_eliciting) return;
        self.bytes_in_flight -|= sp.size;
        // PTO inventory is rebuilt after bulk removals (onAck / PTO / space
        // discard). Count is adjusted lazily via rebuildPtoInflight.
    }

    fn congestionSendWindow(self: *Connection) u64 {
        const cc = self.cc orelse return std.math.maxInt(u64);
        var window = cc.window();
        if (self.test_cwnd_cap) |cap| window = @min(window, cap);
        if (window <= self.bytes_in_flight) return 0;
        return window - self.bytes_in_flight;
    }

    /// Test hook: cap effective cwnd (simulates a low-BDP path so `stats_cc_limited` fires).
    pub fn setTestCwndCap(self: *Connection, cap: ?u64) void {
        self.test_cwnd_cap = cap;
    }

    /// Test hook: park DPLPMTUD at the initial MTU (simulates an Ethernet-like
    /// path). Without it a loopback pair legitimately converges to
    /// `max_datagram` (8192), and a packet-count-based gate loses its scenario:
    /// a 512 KiB transfer becomes ~66 packets, so neither the scripted-loss
    /// packet window nor a >64-in-flight burst can ever occur.
    pub fn testDisablePmtud(self: *Connection) void {
        self.mtu_probes_scheduled = true; // scheduleMtuProbes never re-arms
        self.mtu_search = null;
        self.mtu_probe_queue_len = 0;
        self.probe_mtu = null;
        self.mtu_search_resume_at = null;
    }

    fn onPacketAcked(self: *Connection, sp: SentPacket) void {
        // A delivery of this size proves the path still carries it, which
        // exonerates suspicious loss bursts of smaller packets. This runs for
        // every acked packet, not just ack-eliciting ones, because delivery is
        // delivery as far as the path MTU is concerned.
        if (sp.space == .data) self.mtu_black_hole.onAcked(sp.size);
        if (!sp.ack_eliciting) return;
        self.notePacketLeftFlight(sp);
        if (self.cc) |cc| {
            if (sp.app_limited) self.stats_app_limited_acks +|= 1;
            cc.onAck(self.now, sp.time_sent, sp.size, sp.packet_number, sp.app_limited, self.rtt.sample());
        }
    }

    fn onPacketLost(self: *Connection, sp: SentPacket) void {
        if (self.probe_pn) |probe| {
            if (probe == sp.packet_number) {
                // Probe losses are expected during a search and are deliberately
                // excluded from black-hole evidence.
                self.onMtuProbeLost();
                if (!sp.ack_eliciting) return;
                self.notePacketLeftFlight(sp);
                return;
            }
        }
        // Feed the black-hole detector before the CC callbacks so a burst that
        // triggers detection is grouped with its neighbours by packet number.
        if (sp.space == .data) self.mtu_black_hole.onLost(sp.packet_number, sp.size);
        if (!sp.ack_eliciting) return;
        self.notePacketLeftFlight(sp);
        // G16: the congestion EVENT is raised once per loss batch by
        // detectAndRequeueLosses (noq handle_lost_packets, mod.rs:3486-3495);
        // only the per-packet hook fires here (noq mod.rs:3462).
        if (self.cc) |cc| cc.onPacketLost(sp.size, sp.packet_number, self.now);
    }

    fn handleLongPacket(self: *Connection, data: []const u8) Error!usize {
        if (data.len < 7) return 0;
        const first = data[0];
        const long_kind = (first & 0x30) >> 4;
        if (long_kind == 3) {
            // Retry packet (RFC 9000 §17.2.5). A client consumes it per the
            // noq Header::Retry arm; a SERVER receiving one is a protocol
            // violation (noq mod.rs:4546-4549).
            if (self.role == .server) {
                self.protocolClose(err_protocol_violation);
                return error.UnexpectedState;
            }
            // Silent discards (noq mod.rs:4558-4570): at most one Retry per
            // attempt, none after any server packet was already processed,
            // none with an empty token, none with a bad integrity tag. Any
            // parse/verify failure inside consumeRetry is also a silent drop.
            const already_processed = self.retry_consumed or
                self.spaces_state.getConst(.initial).largest_received != null;
            if (!already_processed and data.len > 16) {
                self.consumeRetry(data) catch {};
            }
            return data.len;
        }
        // RFC 9001 §5: a 0-RTT packet (long_kind 1) belongs to the
        // Application Data packet-number space but decrypts with EARLY read
        // keys — tracked separately from the space keys.
        const is_zero_rtt = long_kind == 1;
        const space: spaces.SpaceId = switch (long_kind) {
            0 => .initial,
            2 => .handshake,
            1 => .data,
            else => return 0,
        };

        // Parse unprotected-header skeleton to find length / pn_offset.
        var cursor: coding.Cursor = .{ .bytes = data };
        _ = try cursor.readU8(); // first
        const version = try cursor.readU32();
        // A11: a Version Negotiation packet (version == 0) is unauthenticated
        // and carries no Length field — handle it and stop walking the
        // datagram (return 0 consumed breaks the coalesced-packet loop).
        if (version == packet.version_negotiation) return self.handleVersionNegotiation(data);
        // M1: only QUIC v1 is processed. Unknown versions skip (return 0) rather
        // than wasting an AEAD attempt and erroring the whole coalesced datagram.
        if (version != 1) return 0;
        const dcid_len = try cursor.readU8();
        _ = try cursor.readSlice(dcid_len);
        const scid_len = try cursor.readU8();
        const source_cid = try packet.ConnectionId.init(try cursor.readSlice(scid_len));
        if (space == .initial) {
            const token_len = try varint.decodeConsume(data, &cursor.index);
            _ = try cursor.readSlice(@intCast(token_len));
        }
        const length = try varint.decodeConsume(data, &cursor.index);
        const pn_offset = cursor.index;
        const packet_end = pn_offset + @as(usize, @intCast(length));
        // Keys for this space may already be discarded (RFC 9000 §4.10 —
        // e.g. a multi-space close datagram arriving after key discard). noq
        // drops such a packet individually and CONTINUES the datagram
        // (handle_coalesced decodes per packet, mod.rs:4158-4191), so a close
        // coalesced into a later space still lands. A truncated remainder
        // stops the walk silently, like noq's "malformed header" return. No
        // AEAD attempt happens, so this is not an authentication failure.
        //
        // 0-RTT: a packet whose early keys were never installed (the offer was
        // rejected) or already discarded is the same — a silent per-packet
        // drop that keeps the coalesced walk alive (RFC 9001 §5.7). The drop
        // is counted so VERIFY can distinguish "rejected" from "lost in a
        // drop arm that predates this code".
        const keys = (if (is_zero_rtt) self.zero_rtt_read_keys else self.read_keys[@intFromEnum(space)]) orelse {
            if (packet_end > data.len) return 0;
            if (is_zero_rtt) self.stats_zero_rtt_dropped += 1;
            return packet_end;
        };
        if (packet_end > data.len) return error.DecryptFailed;

        var pkt_buf: [max_datagram]u8 = undefined;
        if (packet_end > pkt_buf.len) return error.NoSpaceLeft;
        @memcpy(pkt_buf[0..packet_end], data[0..packet_end]);

        // Decrypt header to learn PN length, then payload.
        packet_crypto.decryptHeaderWithKeys(pkt_buf[0..packet_end], pn_offset, keys) catch |err| {
            self.noteAuthenticationFailure();
            return err;
        };
        const pn_len: usize = @as(usize, pkt_buf[0] & 0x03) + 1;
        const header_len = pn_offset + pn_len;
        // Reconstruct full PN (simplified: small PNs at start of connection).
        var pn_val: u64 = 0;
        var i: usize = 0;
        while (i < pn_len) : (i += 1) {
            pn_val = (pn_val << 8) | pkt_buf[pn_offset + i];
        }
        // Save/restore around reconstruct+decrypt: reconstruct() commits
        // largest_received before the AEAD attempt, so a crafted truncated PN
        // that reconstructs large would poison the space if the payload then
        // fails to decrypt (mirrors the short-header discipline below).
        const pn_space = self.spaces_state.get(space);
        const saved_largest = pn_space.largest_received;
        const full_pn = pn_space.reconstruct(.{
            .value = @truncate(pn_val),
            .len = @intCast(pn_len),
        });
        packet_crypto.decryptPayload(pkt_buf[0..packet_end], header_len, full_pn, keys) catch |err| {
            pn_space.largest_received = saved_largest;
            self.noteAuthenticationFailure();
            return err;
        };
        // A15 (RFC 9000 §17.2): reserved bits must be zero. Checked only after
        // the packet authenticates — mirrors noq packet_crypto.rs:248, so an
        // unauthenticated forgery still fails AEAD silently instead of closing.
        if (!packet_crypto.reservedBitsValid(pkt_buf[0])) {
            self.protocolClose(err_protocol_violation);
            return error.ReservedBitsSet;
        }

        const payload = pkt_buf[header_len .. packet_end - packet_crypto.tag_len];
        self.total_authed_packets +|= 1;
        self.resetKeepAlive(); // G18 (noq on_packet_authenticated, mod.rs:3764)
        // A first authenticated Handshake packet validates the peer's address
        // (noq `on_path_validated`, mod.rs:4657 — both roles). Gates B3's
        // closed-state close re-arm.
        if (space == .handshake) self.peer_handshake_authed = true;
        try self.processPayload(space, full_pn, payload, is_zero_rtt);

        if (is_zero_rtt) {
            // Evidence: the server decrypted AND processed a real 0-RTT packet
            // under early keys (the oracle counters key on these).
            self.stats_zero_rtt_accepted_packets += 1;
            self.stats_zero_rtt_payload_bytes += payload.len;
        }

        // RFC 9001 §4.9.1: a server discards its Initial keys once an
        // authenticated Handshake packet arrives (noq connection/mod.rs:3800-3805).
        if (space == .handshake and self.role == .server) self.discardSpaceKeys(.initial);
        // A client's Initial is addressed to its chosen temporary DCID. Once an
        // authenticated server Initial arrives, every later client packet must
        // instead target the server-selected SCID (RFC 9000 §7.2). The old
        // in-memory pair harness patched this externally; real peers do not.
        if (self.role == .client and space == .initial) {
            if (self.initial_remote_cid == null) self.initial_remote_cid = source_cid;
            self.remote_cid = source_cid;
        }
        return packet_end;
    }

    /// A11 (noq connection/mod.rs:4787-4803): client reaction to a Version
    /// Negotiation packet. VN is unauthenticated, so this is never a protocol
    /// close — either ignore it (forgery defense) or terminate locally with
    /// VersionMismatch surfaced as connection_lost.
    fn handleVersionNegotiation(self: *Connection, data: []const u8) Error!usize {
        // Servers never act on VN.
        if (self.role != .client) return 0;
        const vn = packet.parseVersionNegotiation(data) catch return 0;
        // Once more than one packet has authenticated, the peer demonstrably
        // speaks our version — the VN must be forged.
        if (self.total_authed_packets > 1) return 0;
        // A VN listing a version we support is ignored (RFC 9000 §6.2).
        for (vn.supportedVersions()) |v| {
            if (v == 1) return 0;
        }
        // Local termination, matching noq's move_to_draining(VersionMismatch):
        // no CONNECTION_CLOSE is sent for an unauthenticated packet.
        self.state = .{ .draining = .{ .is_local = true, .reason = "version-mismatch" } };
        self.timers.armClose(self.now);
        try self.events.pushBack(self.allocator, .{ .connection_lost = .{ .is_local = true, .reason = "version-mismatch" } });
        return 0;
    }

    fn handleShortPacket(self: *Connection, data: []const u8) Error!void {
        if (data.len > max_datagram) return error.NoSpaceLeft;
        // M3: derive pn_offset from the DCID that actually matches a local CID
        // slot (not only the current `local_cid` length). After NEW_CONNECTION_ID
        // a peer may address a different-length CID we issued.
        const pn_offset = self.shortHeaderPnOffset(data) orelse return error.DecryptFailed;

        // Peer may have updated: pre-derive `next` read keys when missing so HP
        // can open the new key phase (header protection uses the packet's keys).
        if (self.crypto_1rtt.current) |current_read| {
            if (self.crypto_1rtt.next == null) {
                if (self.applicationReadSecret()) |secret| {
                    const next_secret = packet_crypto.nextTrafficSecret(secret);
                    self.crypto_1rtt.next = packet_crypto.keysFromKeyUpdate(&next_secret, current_read.hp_key);
                } else |_| {}
            }
        }

        const candidates = [_]packet_crypto.KeyPhase{ .current, .next, .prev };
        var last_err: Error = error.MissingKeys;
        const space = self.spaces_state.get(.data);
        const saved_largest = space.largest_received;
        for (candidates) |phase| {
            const keys = self.crypto_1rtt.select(phase) catch |err| {
                last_err = err;
                continue;
            };
            var trial: [max_datagram]u8 = undefined;
            @memcpy(trial[0..data.len], data);
            packet_crypto.decryptHeaderWithKeys(trial[0..data.len], pn_offset, keys) catch |err| {
                last_err = err;
                continue;
            };
            const packet_key_phase = (trial[0] & 0x04) != 0;
            const phase_matches = switch (phase) {
                .current => packet_key_phase == self.crypto_1rtt.key_phase,
                .next, .prev => packet_key_phase != self.crypto_1rtt.key_phase,
            };
            if (!phase_matches) {
                last_err = error.InvalidKeyPhase;
                continue;
            }
            const pn_len: usize = @as(usize, trial[0] & 0x03) + 1;
            const header_len = pn_offset + pn_len;
            if (header_len + packet_crypto.tag_len > data.len) {
                last_err = error.DecryptFailed;
                continue;
            }
            var pn_val: u64 = 0;
            var i: usize = 0;
            while (i < pn_len) : (i += 1) {
                pn_val = (pn_val << 8) | trial[pn_offset + i];
            }
            // Expand without mutating largest_received — a failed trial under the
            // wrong HP key must not poison PN reconstruction for later candidates.
            const truncated: packet.PacketNumber = .{
                .value = @truncate(pn_val),
                .len = @intCast(pn_len),
            };
            const expected = (saved_largest orelse 0) +% 1;
            const full_pn = packet.PacketNumber.expand(truncated, expected);
            packet_crypto.decryptPayload(trial[0..data.len], header_len, full_pn, keys) catch |err| {
                last_err = err;
                continue;
            };
            // A15: authenticated, so reserved bits must be zero (RFC 9000
            // §17.3; noq packet_crypto.rs:248). Fatal, not a candidate miss.
            if (!packet_crypto.reservedBitsValid(trial[0])) {
                self.protocolClose(err_protocol_violation);
                return error.ReservedBitsSet;
            }
            if (saved_largest == null or full_pn > saved_largest.?) {
                space.largest_received = full_pn;
            }
            // RFC 9001 §6: an incoming key update is INVALID when its
            // packet number does not exceed the last received one — a replayed
            // or reordered update closes KEY_UPDATE_ERROR rather than
            // committing (noq connection/packet_crypto.rs:260-272).
            if (phase == .next and saved_largest != null and full_pn <= saved_largest.?) {
                self.protocolClose(err_key_update);
                return error.KeyUpdateOrderViolation;
            }
            try self.commitReadKeyUpdate(phase);
            const payload = trial[header_len .. data.len - packet_crypto.tag_len];
            self.total_authed_packets +|= 1;
            self.resetKeepAlive(); // G18 (noq on_packet_authenticated, mod.rs:3764)
            try self.processPayload(.data, full_pn, payload, false);

            return;
        }
        space.largest_received = saved_largest;

        // Fallback when crypto_1rtt slots are empty (early 1-RTT): use read_keys.
        if (self.crypto_1rtt.current == null) {
            const keys = self.read_keys[@intFromEnum(spaces.SpaceId.data)] orelse return error.MissingKeys;
            var pkt_buf: [max_datagram]u8 = undefined;
            @memcpy(pkt_buf[0..data.len], data);
            packet_crypto.decryptHeaderWithKeys(pkt_buf[0..data.len], pn_offset, keys) catch |err| {
                self.noteAuthenticationFailure();
                return err;
            };
            const pn_len: usize = @as(usize, pkt_buf[0] & 0x03) + 1;
            const header_len = pn_offset + pn_len;
            var pn_val: u64 = 0;
            var i: usize = 0;
            while (i < pn_len) : (i += 1) {
                pn_val = (pn_val << 8) | pkt_buf[pn_offset + i];
            }
            // Same save/restore as the long-header path: a failed AEAD attempt
            // in this early-1-RTT fallback must not poison the data space.
            const saved_largest_fallback = space.largest_received;
            const full_pn = space.reconstruct(.{
                .value = @truncate(pn_val),
                .len = @intCast(pn_len),
            });
            packet_crypto.decryptPayload(pkt_buf[0..data.len], header_len, full_pn, keys) catch |err| {
                space.largest_received = saved_largest_fallback;
                self.noteAuthenticationFailure();
                return err;
            };
            // A15: same reserved-bits check as the main 1-RTT candidate path.
            if (!packet_crypto.reservedBitsValid(pkt_buf[0])) {
                self.protocolClose(err_protocol_violation);
                return error.ReservedBitsSet;
            }
            const payload = pkt_buf[header_len .. data.len - packet_crypto.tag_len];
            self.total_authed_packets +|= 1;
            self.resetKeepAlive(); // G18 (noq on_packet_authenticated, mod.rs:3764)
            try self.processPayload(.data, full_pn, payload, false);

            return;
        }
        // A16: no candidate key phase authenticated the packet — a drop that
        // counts toward the AEAD integrity limit (noq mod.rs:4269-4280).
        self.noteAuthenticationFailure();
        return last_err;
    }

    /// A8 (RFC 9000 §12.5 Table 3): Initial and Handshake packets may carry
    /// only PADDING, PING, ACK, CRYPTO, and CONNECTION_CLOSE; anything else is
    /// a PROTOCOL_VIOLATION. PADDING never reaches the frame loop (skipped
    /// pre-decode), so it is legal everywhere implicitly. This mirrors noq's
    /// `process_early_payload` (connection/mod.rs ~4836-4872): its catch-all
    /// match arm rejects everything outside that set, and its `is_1rtt()`
    /// check additionally rejects the multipath/QAD extension frames — which
    /// pins HANDSHAKE_DONE, the RFC 9368 frames (ACK_FREQUENCY, IMMEDIATE_ACK),
    /// and the iroh address frames (observed_*/add_*/reach_out_*/
    /// remove_address) to 1-RTT only, same as this allow-list.
    fn frameLegalInSpace(tag: std.meta.Tag(frame.Frame), space: spaces.SpaceId) bool {
        return switch (space) {
            .data => true,
            .initial, .handshake => switch (tag) {
                .ping, .ack, .crypto, .connection_close => true,
                else => false,
            },
        };
    }

    /// noq process_payload is_0rtt arm (mod.rs:4926-4941): CRYPTO frames and
    /// the QAD/multipath 1-RTT-only frames are illegal in a 0-RTT packet (RFC
    /// 9001 §8.3); an application CONNECTION_CLOSE additionally cannot be
    /// expressed before the handshake completes (checked at the payload arm,
    /// which sees the `is_app` flag). Everything else rides the ordinary data
    /// space handling.
    fn frameLegalInZeroRtt(decoded: frame.Frame) bool {
        return switch (decoded) {
            .crypto => false,
            .connection_close => |cc| !cc.is_app,
            .observed_ipv4_addr, .observed_ipv6_addr, .add_ipv4_address, .add_ipv6_address, .reach_out_at_ipv4, .reach_out_at_ipv6, .remove_address => false,
            .path_ack, .path_abandon, .path_status_backup, .path_status_available, .path_new_connection_id, .path_retire_connection_id, .max_path_id, .paths_blocked, .path_cids_blocked => false,
            else => true,
        };
    }

    fn processPayload(self: *Connection, space: spaces.SpaceId, pn: u64, payload: []const u8, is_zero_rtt: bool) Error!void {
        const si = @intFromEnum(space);
        // B3 (noq connection/mod.rs:4329-4332): a duplicate is discarded
        // BEFORE the closed-state re-arm below — it does not owe a close.
        if (!self.dedup[si].checkAndInsert(pn)) return;
        self.pending_acks[si].onRecvAt(pn, self.now);
        // G3 (noq frame.rs Iter::new:1502-1510, reached from process_payload /
        // process_early_payload after the PN is already tracked; RFC 9000
        // §12.4): a packet whose payload contains no frames at all is a
        // PROTOCOL_VIOLATION. noq's predicate is literal emptiness — a
        // padding-only payload is NOT a violation (PADDING is a frame the
        // iterator yields and skips).
        if (payload.len == 0) {
            self.protocolClose(err_protocol_violation);
            return error.EmptyPacket;
        }

        var cursor: coding.Cursor = .{ .bytes = payload };
        var ack_eliciting = false;
        var force_ack = false;
        while (cursor.remaining() > 0) {
            // PADDING is a single 0x00 byte; skip runs without decodeAt.
            if (cursor.bytes[cursor.index] == 0x00) {
                cursor.index += 1;
                continue;
            }
            const decoded_frame = frame.decodeAt(&cursor) catch {
                self.protocolClose(err_frame_encoding);
                return error.FrameEncodeFailed;
            };
            // A8 (RFC 9000 §12.5): a frame that is illegal in this packet's
            // space is a PROTOCOL_VIOLATION (noq process_early_payload).
            if (!frameLegalInSpace(std.meta.activeTag(decoded_frame), space)) {
                self.protocolClose(err_protocol_violation);
                return;
            }
            // 0-RTT packet frame filter (noq process_payload is_0rtt arm).
            if (is_zero_rtt and !frameLegalInZeroRtt(decoded_frame)) {
                self.protocolClose(err_protocol_violation);
                return;
            }
            switch (decoded_frame) {
                .ping => ack_eliciting = true,
                .immediate_ack => {
                    ack_eliciting = true;
                    force_ack = true;
                },
                .handshake_done => {
                    // A7 (RFC 9000 §19.20; noq connection/mod.rs ~5255):
                    // HANDSHAKE_DONE is sent by the server only — a server
                    // receiving one from its client is a PROTOCOL_VIOLATION.
                    if (self.role == .server) {
                        self.protocolClose(err_protocol_violation);
                        return;
                    }
                    ack_eliciting = true;
                    self.handshake_done_received = true;
                    self.handshake_confirmed = true;
                    // RFC 9001 §4.9.2: the client discards Handshake keys on
                    // HANDSHAKE_DONE receipt (noq connection/mod.rs:5255-5265).
                    self.discardSpaceKeys(.handshake);
                },
                .crypto => |c| {
                    ack_eliciting = true;
                    try self.ingestCrypto(space, c);
                },
                .ack => |a| self.onAck(space, a),
                .stream => |s| {
                    ack_eliciting = true;
                    try self.handleStreamFrame(s);
                },
                .reset_stream => |r| {
                    ack_eliciting = true;
                    if ((streamIsUni(r.stream_id) and streamInitiator(r.stream_id) == self.role) or
                        (streamInitiator(r.stream_id) == self.role and self.findStream(r.stream_id) == null))
                    {
                        self.protocolClose(err_stream_state);
                        return;
                    }
                    const e = self.findStream(r.stream_id) orelse try self.getOrCreateStream(r.stream_id);
                    if (r.final_size > e.recv.max_data) return self.protocolClose(err_flow_control);
                    if (e.recv.highest_offset > r.final_size or
                        (e.recv.fin_offset != null and e.recv.fin_offset.? != r.final_size))
                    {
                        self.protocolClose(err_final_size);
                        return;
                    }
                    if (r.final_size > e.recv.highest_offset) {
                        const delta = r.final_size - e.recv.highest_offset;
                        const next_total = std.math.add(u64, self.recv_data_total, delta) catch {
                            return self.protocolClose(err_flow_control);
                        };
                        if (next_total > self.recv_max_data) return self.protocolClose(err_flow_control);
                        self.recv_data_total = next_total;
                        e.recv.highest_offset = r.final_size;
                    }
                    e.recv.fin_offset = r.final_size;
                    if (e.recv.reset_code == null) {
                        self.creditAbandonedRecv(e);
                        e.recv.reset_code = r.app_error_code;
                        try self.events.pushBack(self.allocator, .{ .stream_reset = .{ .id = r.stream_id, .code = r.app_error_code } });
                    }
                },
                .stop_sending => |s| {
                    ack_eliciting = true;
                    if ((streamIsUni(s.stream_id) and streamInitiator(s.stream_id) != self.role) or
                        (streamInitiator(s.stream_id) == self.role and self.findStream(s.stream_id) == null))
                    {
                        self.protocolClose(err_stream_state);
                        return;
                    }
                    try self.resetStream(s.stream_id, s.app_error_code);
                    try self.events.pushBack(self.allocator, .{ .stop_sending = .{ .id = s.stream_id, .code = s.app_error_code } });
                },
                .max_data => |m| {
                    // F1 fix: no longer a dead decode — grant more connection send window.
                    ack_eliciting = true;
                    if (m > self.send_max_data) self.send_max_data = m;
                },
                .max_stream_data => |m| {
                    ack_eliciting = true;
                    const e = try self.getOrCreateStream(m.stream_id);
                    if (m.max_data > e.send.max_data) e.send.max_data = m.max_data;
                },
                .max_streams_bidi => |m| {
                    ack_eliciting = true;
                    if (m > self.peer_params.initial_max_streams_bidi) self.peer_params.initial_max_streams_bidi = m;
                },
                .max_streams_uni => |m| {
                    ack_eliciting = true;
                    if (m > self.peer_params.initial_max_streams_uni) self.peer_params.initial_max_streams_uni = m;
                },
                .data_blocked, .stream_data_blocked, .streams_blocked_bidi, .streams_blocked_uni => ack_eliciting = true,
                .connection_close => |cc| {
                    // Peer closed: enter draining, surface once. Not ack-eliciting (RFC 9000 §13.2.1).
                    switch (self.state) {
                        .draining, .drained => {},
                        else => {
                            // noq answers a peer close with ONE NO_ERROR
                            // CONNECTION_CLOSE (B4, mod.rs:5540-5543) — but
                            // only when it still owes a close: an endpoint
                            // whose own close is already fully sent drains
                            // silently (mod.rs:4529-4532), and a close
                            // arriving in an Initial/Handshake packet moves
                            // noq to draining without queuing a response at
                            // all (process_early_payload, mod.rs:4856-4859).
                            const owe_no_error_close = space == .data and
                                !(self.state == .closed and self.close_sent);
                            self.state = .{ .draining = .{ .is_local = false, .reason = "peer-close" } };
                            self.timers.armClose(self.now);
                            if (owe_no_error_close) {
                                self.drain_close_pending = true;
                                self.close_sent_mask = 0;
                            }
                            try self.events.pushBack(self.allocator, .{ .connection_lost = .{ .is_local = false, .reason = if (cc.reason.len > 0) "peer-close" else "peer-close" } });
                        },
                    }
                },
                .path_challenge => |data| {
                    // RFC 9000 §8.2.2: echo the challenge in a PATH_RESPONSE.
                    ack_eliciting = true;
                    self.queuePathResponse(data);
                },
                .path_response => |data| {
                    // RFC 9000 §8.2.3: a path is validated ONLY when our own
                    // challenge token comes back verbatim.
                    ack_eliciting = true;
                    try self.onPathResponse(data);
                },
                .observed_ipv4_addr => |a| {
                    ack_eliciting = true;
                    // F13: an unnegotiated OBSERVED_ADDR is a connection error
                    // (noq: "received OBSERVED_ADDRESS frame when not negotiated").
                    if (!self.observedAddrRecvNegotiated()) {
                        self.protocolClose(err_protocol_violation);
                        return;
                    }
                    // Seq-gating — only a strictly newer report surfaces
                    // (noq update_observed_addr_report drops stale/equal).
                    if (self.last_observed_seq != null and a.seq <= self.last_observed_seq.?) continue;
                    self.last_observed_seq = a.seq;
                    try self.events.pushBack(self.allocator, .{ .nat_address = .{ .kind = .observed, .seq = a.seq, .ip = a.ip, .port = a.port } });
                },
                // The v6 report decodes + surfaces (was a FRAME_ENCODING_ERROR
                // close — the QAD-over-IPv6 floor gap from independent review).
                .observed_ipv6_addr => |a| {
                    ack_eliciting = true;
                    if (!self.observedAddrRecvNegotiated()) {
                        self.protocolClose(err_protocol_violation);
                        return;
                    }
                    if (self.last_observed_seq != null and a.seq <= self.last_observed_seq.?) continue;
                    self.last_observed_seq = a.seq;
                    try self.events.pushBack(self.allocator, .{ .nat_address = .{ .kind = .observed, .seq = a.seq, .ip6 = a.ip, .port = a.port } });
                },
                .add_ipv4_address => |a| {
                    ack_eliciting = true;
                    try self.events.pushBack(self.allocator, .{ .nat_address = .{ .kind = .add, .seq = a.seq, .ip = a.ip, .port = a.port } });
                },
                // V6 frames surface as v6 events — the connection no longer
                // closes on them (a v6 NAT-traversing iroh peer stays up).
                .add_ipv6_address => |a| {
                    ack_eliciting = true;
                    try self.events.pushBack(self.allocator, .{ .nat_address = .{ .kind = .add, .seq = a.seq, .ip6 = a.ip, .port = a.port } });
                },
                .reach_out_at_ipv4 => |a| {
                    ack_eliciting = true;
                    try self.events.pushBack(self.allocator, .{ .nat_address = .{ .kind = .reach_out, .seq = a.seq, .ip = a.ip, .port = a.port } });
                },
                .reach_out_at_ipv6 => |a| {
                    ack_eliciting = true;
                    try self.events.pushBack(self.allocator, .{ .nat_address = .{ .kind = .reach_out, .seq = a.seq, .ip6 = a.ip, .port = a.port } });
                },
                .remove_address => |seq| {
                    ack_eliciting = true;
                    try self.events.pushBack(self.allocator, .{ .nat_address = .{ .kind = .remove, .seq = seq } });
                },
                .new_connection_id => |n| {
                    ack_eliciting = true;
                    try self.acceptNewConnectionId(n);
                },
                .retire_connection_id => |r| {
                    ack_eliciting = true;
                    // The peer retired one of OUR cids (RFC 9000 §19.16):
                    // mark the LOCAL slot and replace it — not a remote slot.
                    try self.retireLocalConnectionId(r.sequence);
                },
                .new_token => |t| {
                    ack_eliciting = true;
                    if (self.stored_new_token.len != 0) self.allocator.free(self.stored_new_token);
                    self.stored_new_token = try self.allocator.dupe(u8, t.token);
                },
                .ack_frequency => |a| {
                    ack_eliciting = true;
                    self.peer_ack_eliciting_threshold = a.ack_eliciting_threshold;
                    self.peer_ack_max_ack_delay = a.request_max_ack_delay;
                    // G11 (noq set_ack_frequency_params, spaces.rs:1139-1142).
                    self.peer_reordering_threshold = a.reordering_threshold;
                },
                .datagram => |d| {
                    ack_eliciting = true;
                    const local_limit = self.local_params.max_datagram_frame_size orelse {
                        self.protocolClose(err_protocol_violation);
                        return;
                    };
                    const frame_size = datagramFrameSize(d.data.len, d.with_length) orelse {
                        self.protocolClose(err_frame_encoding);
                        return;
                    };
                    if (@as(u64, @intCast(frame_size)) > local_limit) {
                        self.protocolClose(err_protocol_violation);
                        return;
                    }
                    const copy = try self.allocator.dupe(u8, d.data);
                    try self.datagram_in.pushBack(self.allocator, copy);
                },
                // I3: the multipath family. These frames are legal in the data
                // space (frameLegalInSpace admits them) and MUST NOT close the
                // connection as UnsupportedFrameType. Full multipath path
                // semantics are project-scope-limited, so a recognized frame is
                // treated as ack-eliciting and otherwise ignored — the peer's
                // path-state machinery sees the ACK and stays up rather than
                // tearing the connection down on a frame we decoded correctly.
                .path_ack,
                .path_abandon,
                .path_status_backup,
                .path_status_available,
                .path_new_connection_id,
                .path_retire_connection_id,
                .max_path_id,
                .paths_blocked,
                .path_cids_blocked,
                => ack_eliciting = true,
            }
        }
        if (ack_eliciting) {
            // G4 (noq PendingAcks::packet_received, spaces.rs:1178-1214): the
            // largest ack-eliciting PN is tracked per space and the PREVIOUS
            // value feeds is_out_of_order (spaces.rs:1190, 1219) — capture it
            // BEFORE the update, like noq does.
            const prev_largest_ack_eliciting = self.largest_ack_eliciting_recv[si] orelse 0;
            if (self.largest_ack_eliciting_recv[si] == null or pn > self.largest_ack_eliciting_recv[si].?) {
                self.largest_ack_eliciting_recv[si] = pn;
            }
            if (space != .data) {
                // noq process_early_payload (mod.rs:4869-4874): in the Initial
                // and Handshake spaces ACKs are sent immediately, always.
                self.needs_ack[si] = true;
            } else {
                // Data space (noq packet_received, spaces.rs:1198-1213): an
                // ACK is due immediately when the peer's IMMEDIATE_ACK asked
                // for it, when the count since the last ACK exceeds the
                // ack-eliciting threshold (noq default 1 — "every other
                // ack-eliciting packet", config doc transport.rs:725 — peer's
                // ACK_FREQUENCY overrides, set_ack_frequency_params
                // spaces.rs:1139-1142), or when the packet is out-of-order
                // under the peer's reordering threshold (is_out_of_order,
                // spaces.rs:1216-1251).
                const threshold = self.peer_ack_eliciting_threshold orelse 1;
                self.peer_ack_eliciting_pending += 1;
                if (force_ack or
                    self.peer_ack_eliciting_pending > threshold or
                    self.isOutOfOrder(si, pn, prev_largest_ack_eliciting))
                {
                    self.needs_ack[si] = true;
                } else {
                    // Below the threshold and in-order: the ACK is deferred,
                    // but RFC 9000 §13.2.1 caps that deferral at
                    // `max_ack_delay`. Arm the timer (leaving an already-armed,
                    // earlier deadline alone — the obligation dates from the
                    // FIRST unacked packet; noq arms only when no timer is
                    // running and no ACK is already due, spaces.rs:1208-1211).
                    self.armAckTimer(si);
                }
            }
            if (self.needs_ack[si]) self.ack_deadline[si] = null;
        }
        // B3 (noq connection/mod.rs:4439-4471, evaluated with the POST-packet
        // state at the end of handle_packet): while closed, re-arm exactly ONE
        // CONNECTION_CLOSE per further packet from the peer — but only a
        // packet that (a) authenticated (we are past AEAD in
        // handleLongPacket/handleShortPacket; an unauthenticated datagram
        // never reaches here), (b) is not a duplicate (dedup at the top), and
        // (c) arrived from the validated remote (RFC 9000 §10.2.1
        // amplification defense — an unvalidated remote gets silence). A peer
        // close that moved us to draining leaves the state non-closed, so it
        // does NOT re-arm (noq mod.rs:4529-4532).
        if (self.state == .closed and self.close_frame != null and self.closeRearmRemoteValidated()) {
            self.close_sent = false;
            self.close_sent_mask = 0;
        }
    }

    /// G10 (noq AckFrequencyState::candidate_max_ack_delay,
    /// ack_frequency.rs:40-53): the max_ack_delay to request of the peer.
    /// The requested base is OUR configured max_ack_delay (Zig has no
    /// AckFrequencyConfig; the value the pre-G10 static emission already
    /// requested, local_params.max_ack_delay, plays that role), clamped to at
    /// most max(current RTT, 25 ms) (MIN_AUTOMATIC_ACK_DELAY,
    /// ack_frequency.rs:157-159). noq's lower clamp is the peer's
    /// min_ack_delay transport parameter — that TP is F11 (not landed), so
    /// the lower bound is 0 here.
    fn candidateAckFreqDelayUs(self: *const Connection) u64 {
        const base = std.math.mul(u64, self.local_params.max_ack_delay, 1000) catch std.math.maxInt(u64);
        const rtt_us: u64 = @intCast(@max(@divTrunc(self.rtt.get(), 1000), 0));
        return @min(base, @max(rtt_us, 25_000));
    }

    /// G10 (noq AckFrequencyState::should_send_ack_frequency,
    /// ack_frequency.rs:79-95): always send at startup; afterwards re-send
    /// when the RTT-derived candidate diverges from the value currently in
    /// force (the in-flight request if one is unacknowledged, else the last
    /// acknowledged one) by more than MAX_RTT_ERROR = 0.2
    /// (ack_frequency.rs:154) — in integer form, |desired − current| · 5 >
    /// current.
    fn shouldSendAckFrequency(self: *const Connection) bool {
        if (self.ack_frequency_seq == 0) return true;
        const current = if (self.ack_freq_in_flight_pn != null)
            self.ack_freq_in_flight_value_us
        else
            self.ack_freq_peer_max_delay_us;
        const desired = self.candidateAckFreqDelayUs();
        const diff = if (desired > current) desired - current else current - desired;
        return diff *| 5 > current;
    }

    /// G10 (noq AckFrequencyState::on_acked, ack_frequency.rs:107-116): once
    /// the packet carrying an ACK_FREQUENCY frame is acknowledged, the
    /// requested value is the one the peer is presumed to be using.
    fn onAckFrequencyAcked(self: *Connection, space: spaces.SpaceId, a: frame.Ack) void {
        const pn = self.ack_freq_in_flight_pn orelse return;
        if (space != .data) return;
        if (!ackContains(a, pn)) return;
        self.ack_freq_peer_max_delay_us = self.ack_freq_in_flight_value_us;
        self.ack_freq_in_flight_pn = null;
    }

    /// Arm the delayed-ACK deadline for `si` if it is not already armed.
    fn armAckTimer(self: *Connection, si: usize) void {
        if (self.ack_deadline[si] != null) return;
        self.ack_deadline[si] = self.now + self.localMaxAckDelayNs();
    }

    /// G4 (noq PendingAcks::is_out_of_order, spaces.rs:1216-1251): does this
    /// packet's arrival warrant an immediate ACK under the peer's requested
    /// reordering threshold?
    /// * 0: never (peer opted out);
    /// * 1: RFC 9000 §13.2.1 — below the previous largest ack-eliciting PN,
    ///   or a hole between it and this packet (noq's default and the behavior
    ///   when the extension is unused, config doc transport.rs:752-754);
    /// * >1: ACK-frequency draft §6.1 — an ACK is due when it would let the
    ///   sender newly declare a packet lost, i.e. the run of unreported
    ///   missing packets below the largest unacked reaches the threshold.
    fn isOutOfOrder(self: *const Connection, si: usize, pn: u64, prev_largest_ack_eliciting: u64) bool {
        switch (self.peer_reordering_threshold) {
            0 => return false,
            1 => return pn < prev_largest_ack_eliciting or
                self.dedup[si].missingInInterval(prev_largest_ack_eliciting, pn),
            else => {
                const rt = self.peer_reordering_threshold;
                const largest_acked = self.largest_acked_sent[si] orelse return false;
                const largest_unacked = self.largest_ack_eliciting_recv[si] orelse return false;
                if (rt > largest_acked) return false;
                // The largest PN that could be declared lost without a new
                // ACK being sent (spaces.rs:1242).
                const largest_reported = largest_acked - rt + 1;
                const smallest_missing_unreported = self.dedup[si].smallestMissingInInterval(largest_reported, largest_unacked) orelse return false;
                return largest_unacked - smallest_missing_unreported >= rt;
            },
        }
    }

    /// The `max_ack_delay` WE advertised — the bound the peer is entitled to
    /// hold us to (as opposed to `peerMaxAckDelayNs`, which bounds the peer).
    fn localMaxAckDelayNs(self: *const Connection) i64 {
        const ns = std.math.mul(u64, self.local_params.max_ack_delay, std.time.ns_per_ms) catch
            return std.math.maxInt(i64);
        return @intCast(@min(ns, @as(u64, @intCast(std.math.maxInt(i64)))));
    }

    /// Earliest armed delayed-ACK deadline across spaces, if any.
    fn ackDeadline(self: *const Connection) ?Instant {
        var next: ?Instant = null;
        for (self.ack_deadline) |slot| {
            if (slot) |d| next = minOpt(next, d);
        }
        return next;
    }

    /// Fire any expired delayed-ACK timers, converting the deferred obligation
    /// into a real pending ACK the next `pollTransmit` will emit.
    /// (noq on_max_ack_delay_timeout, spaces.rs:1148-1150 — the threshold
    /// count itself is only restarted when the ACK is actually emitted,
    /// acks_sent:1267, mirrored in emitOwedAck.)
    fn handleAckTimeout(self: *Connection, now: Instant) void {
        for (&self.ack_deadline, 0..) |*deadline, si| {
            const d = deadline.* orelse continue;
            if (now < d) continue;
            deadline.* = null;
            self.needs_ack[si] = true;
            self.stats_delayed_ack_timeouts += 1;
        }
    }

    /// Test/oracle hook: ACKs emitted because the delayed-ACK timer expired.
    pub fn delayedAckTimeoutsForTest(self: *const Connection) u64 {
        return self.stats_delayed_ack_timeouts;
    }

    /// Test hook: the armed delayed-ACK deadline for a space, if any.
    pub fn ackDeadlineForTest(self: *const Connection, space: spaces.SpaceId) ?Instant {
        return self.ack_deadline[@intFromEnum(space)];
    }

    fn acceptNewConnectionId(self: *Connection, n: frame.NewConnectionId) Error!void {
        if (self.remote_cid_len >= max_local_cid_slots) return;
        const cid = try packet.ConnectionId.init(n.connection_id);
        self.remote_cids[self.remote_cid_len] = .{
            .sequence = n.sequence,
            .cid = cid,
            .reset_token = n.reset_token,
        };
        self.remote_cid_len += 1;
        var i: usize = 0;
        while (i < self.remote_cid_len) : (i += 1) {
            if (self.remote_cids[i].sequence < n.retire_prior_to) {
                self.remote_cids[i].retired = true;
            }
        }
        // E12 (noq CidQueue::insert + ::active): adopt the newest non-retired
        // peer-issued CID as our transmit destination — the "server adopts
        // client-issued CID" half of the machinery.
        if (self.activeRemoteCid()) |active| self.remote_cid = active;
    }

    /// The newest non-retired peer-issued CID, if any — noq CidQueue::active.
    fn activeRemoteCid(self: *const Connection) ?packet.ConnectionId {
        var best: ?packet.ConnectionId = null;
        var best_seq: u64 = 0;
        for (&self.remote_cids, 0..) |*slot, i| {
            if (i >= self.remote_cid_len) break;
            if (slot.retired) continue;
            if (best == null or slot.sequence >= best_seq) {
                best = slot.cid;
                best_seq = slot.sequence;
            }
        }
        return best;
    }

    fn retireRemoteConnectionId(self: *Connection, sequence: u64) void {
        for (&self.remote_cids, 0..) |*slot, i| {
            if (i < self.remote_cid_len and slot.sequence == sequence) slot.retired = true;
        }
        if (self.activeRemoteCid()) |active| self.remote_cid = active;
    }

    /// E12: the peer retired one of OUR CIDs (RETIRE_CONNECTION_ID) — mark the
    /// local slot and issue a replacement to keep the inventory at the peer's
    /// limit (noq issue_first_cids on retire).
    fn retireLocalConnectionId(self: *Connection, sequence: u64) Error!void {
        for (&self.local_cids, 0..) |*slot, i| {
            if (i < self.local_cid_len and slot.sequence == sequence) slot.retired = true;
        }
        try self.maybeIssueCids();
    }

    /// Receive one STREAM frame: enforce flow control (memory-safety boundary),
    /// reassemble in order, and surface a stream event.
    fn handleStreamFrame(self: *Connection, s: frame.Stream) Error!void {
        const e = try self.getOrCreateStream(s.id);
        if (!e.opened_emitted) {
            e.opened_emitted = true;
            try self.events.pushBack(self.allocator, .{ .stream_opened = .{ .id = s.id, .dir = e.dir } });
        }
        const end = std.math.add(u64, s.offset, @intCast(s.data.len)) catch {
            return self.protocolClose(err_final_size);
        };
        // Stream-level flow control: reject data past the advertised window.
        if (end > e.recv.max_data) return self.protocolClose(err_flow_control);
        if (e.recv.reset_code != null) {
            const final_size = e.recv.fin_offset orelse return self.protocolClose(err_final_size);
            if (end > final_size or (s.fin and end != final_size)) return self.protocolClose(err_final_size);
            return;
        }
        // Connection-level flow control on newly-advanced offset.
        const old_high = e.recv.highest_offset;
        var recv_next_total: ?u64 = null;
        if (end > old_high) {
            const delta = end - old_high;
            const next_total = std.math.add(u64, self.recv_data_total, delta) catch {
                return self.protocolClose(err_flow_control);
            };
            if (next_total > self.recv_max_data) return self.protocolClose(err_flow_control);
            recv_next_total = next_total;
        }
        const added = e.recv.ingest(self.allocator, s.offset, s.data, s.fin) catch |err| switch (err) {
            error.FinalSizeError => return self.protocolClose(err_final_size),
            else => |e2| return e2,
        };
        if (recv_next_total) |next_total| self.recv_data_total = next_total;
        if (added > 0 or s.fin) {
            const new_slice = e.recv.data.items[e.recv.data.items.len - added ..];
            try self.events.pushBack(self.allocator, .{ .stream_data = .{
                .id = s.id,
                .data = new_slice,
                .fin = e.recv.finReached(),
            } });
        }
    }

    /// A16 (noq connection/mod.rs:4269-4280): a packet that fails to
    /// authenticate is dropped and counted; past the AEAD integrity limit the
    /// connection is abandoned with AEAD_LIMIT_REACHED. Like noq this is a
    /// cumulative connection-lifetime counter, never reset on success.
    fn noteAuthenticationFailure(self: *Connection) void {
        self.authentication_failures +|= 1;
        if (self.authentication_failures > packet_crypto.integrity_limit) {
            self.protocolClose(err_aead_limit_reached);
        }
    }

    fn protocolClose(self: *Connection, code: u64) void {
        self.closeWith(self.now, .{ .error_code = code, .frame_type = 0, .reason = "", .is_app = false });
    }

    fn onAck(self: *Connection, space: spaces.SpaceId, a: frame.Ack) void {
        // RFC 9000 §13.2.4: an ACK of a PN we never sent is a PROTOCOL_VIOLATION.
        const next_pn = self.spaces_state.getConst(space).next_pn;
        if (a.largest_acked >= next_pn) {
            self.protocolClose(err_protocol_violation);
            return;
        }
        // A17 (noq PacketNumberFilter::check_ack, spaces.rs:393-402, called per
        // ACK range at mod.rs:2950): an ACK covering the PN we deliberately
        // skipped is an optimistic-ACK attack → PROTOCOL_VIOLATION.
        if (self.spaces_state.getConst(space).pn_filter) |*f| {
            if (f.prev_skipped) |skipped| {
                if (ackContains(a, skipped)) {
                    self.protocolClose(err_protocol_violation);
                    return;
                }
            }
        }
        // G15 (noq detect_spurious_loss, mod.rs:3074-3100, called at
        // mod.rs:2940 BEFORE the newly-acked walk): an ACK that covers PNs we
        // previously declared lost exonerates them; when it empties the lost
        // set the earlier congestion event was spurious and the congestion
        // controller restores its pre-event state.
        if (self.detectSpuriousLoss(space, a)) {
            self.stats_spurious_congestion_events +|= 1;
            if (self.cc) |cc| cc.onSpuriousCongestionEvent();
        }
        // Remove newly-acked packets (no retransmit) + sample RTT from the largest.
        var largest_time: ?Instant = null;
        var largest_acked_seen: ?u64 = null;
        var acked_app_limited = false;
        var newly_acked_marked: u64 = 0;
        var reclaim_streams = [_]bool{false} ** max_streams;
        var reclaim_safe: [max_streams]u64 = undefined;
        for (&self.streams, 0..) |*stream, stream_i| reclaim_safe[stream_i] = stream.send.send_next;
        const old_len = self.sent.items.len;
        var read: usize = 0;
        var write: usize = 0;
        while (read < old_len) : (read += 1) {
            const sp = self.sent.items[read];
            if (sp.space == space and ackContains(a, sp.packet_number)) {
                self.markAckedStreams(sp, &reclaim_streams);
                if (sp.packet_number == a.largest_acked) largest_time = sp.time_sent;
                largest_acked_seen = if (largest_acked_seen) |pn| @max(pn, sp.packet_number) else sp.packet_number;
                acked_app_limited = acked_app_limited or sp.app_limited;
                if (sp.ecn_marked) newly_acked_marked += 1;
                self.onPacketAcked(sp);
                continue;
            }
            self.noteOutstandingStreamMin(sp, &reclaim_safe);
            if (write != read) self.sent.items[write] = sp;
            write += 1;
        }
        self.sent.shrinkRetainingCapacity(write);
        self.rebuildPtoInflight();
        if (largest_time) |t| {
            const sample = self.now - t;
            // RFC 9002 §5: scale wire ack_delay by 2^ack_delay_exponent and cap
            // by max_ack_delay before feeding the RTT estimator.
            if (sample > 0) {
                const had_sample = self.rtt.smoothed != null;
                self.rtt.update(self.scaledAckDelayNs(space, a.ack_delay), sample);
                if (!had_sample) {
                    // G16 (noq mod.rs:3022-3025): remember the first packet
                    // sent after the first RTT sample — persistent congestion
                    // may only start strictly after it.
                    self.first_pn_after_rtt_sample = .{
                        .space = space,
                        .pn = self.spaces_state.getConst(space).next_pn,
                    };
                }
                // G19: the 3×PTO deadlines (close, key discards) track the
                // live RTT estimator.
                self.refreshTimerPtoBase();
            }
            self.pto_count = 0; // ack received → reset PTO backoff (RFC 9002 §6.2.1)
        }
        if (self.probe_pn) |probe| {
            if (ackContains(a, probe)) self.onMtuProbeAcked();
        }
        self.onAckFrequencyAcked(space, a);
        // RFC 9000 §13.4.2.1: validate the peer's ECN echo before letting it
        // drive congestion control, so a bleaching or lying path cannot shrink
        // our window. Runs before `onEndAcks` so the CC sees the full round.
        self.validatePeerEcn(space, a, newly_acked_marked);
        if (self.cc) |cc| cc.onEndAcks(self.now, self.bytes_in_flight, acked_app_limited, largest_acked_seen);
        _ = self.spaces_state.get(space).onAck(a.largest_acked);
        // F2: real retransmission — losses are detected BY loss.detectLostPackets
        // in the driver and their frames re-queued for the next pollTransmit.
        self.detectAndRequeueLosses(space);
        self.reclaimResetStreams();
        self.reclaimAckedStreamData(&reclaim_streams, &reclaim_safe);
    }

    fn markAckedStreams(self: *Connection, sp: SentPacket, marked: *[max_streams]bool) void {
        var content_i: usize = 0;
        while (content_i < sp.content_len) : (content_i += 1) {
            switch (sp.content[content_i]) {
                .stream => |st| for (&self.streams, 0..) |*e, stream_i| {
                    if (e.used and e.id == st.id) {
                        marked[stream_i] = true;
                        break;
                    }
                },
                .reset_stream => {},
                .stop_sending => {},
                else => {},
            }
        }
    }

    fn noteOutstandingStreamMin(self: *Connection, sp: SentPacket, safe_before: *[max_streams]u64) void {
        var content_i: usize = 0;
        while (content_i < sp.content_len) : (content_i += 1) {
            switch (sp.content[content_i]) {
                .stream => |st| for (&self.streams, 0..) |*e, stream_i| {
                    if (e.used and e.id == st.id) {
                        safe_before[stream_i] = @min(safe_before[stream_i], st.offset);
                        break;
                    }
                },
                else => {},
            }
        }
    }

    /// Release send-buffer prefixes that are no longer referenced by any
    /// outstanding packet or retransmission queue. All offsets stay absolute;
    /// `StreamSend.buf_offset` only changes the retained storage window.
    fn reclaimAckedStreamData(
        self: *Connection,
        marked: *const [max_streams]bool,
        safe_watermarks: *const [max_streams]u64,
    ) void {
        for (&self.streams, 0..) |*e, stream_i| {
            if (!marked[stream_i] or !e.used or e.send.buffer_released or e.send.buf.items.len == 0) continue;
            // Avoid an outstanding-history scan when even the optimistic
            // watermark (`send_next`) cannot trigger geometric compaction.
            const optimistic_discard: usize = @intCast(e.send.send_next - e.send.buf_offset);
            const optimistic_retained = e.send.buf.items.len - @min(optimistic_discard, e.send.buf.items.len);
            if (optimistic_discard < optimistic_retained) continue;
            var safe_before = safe_watermarks[stream_i];
            var rtx_it = e.send.rtx.iterator();
            while (rtx_it.next()) |chunk| safe_before = @min(safe_before, chunk.offset);
            e.send.reclaimBefore(self.allocator, safe_before);
        }
    }

    fn reclaimResetStreamData(self: *Connection, e: *StreamEntry) void {
        if (e.send.reset_code == null or e.send.buf.items.len == 0) return;
        var safe_before = e.send.endOffset();
        for (self.sent.items) |sp| {
            var content_i: usize = 0;
            while (content_i < sp.content_len) : (content_i += 1) {
                switch (sp.content[content_i]) {
                    .stream => |st| if (st.id == e.id) {
                        safe_before = @min(safe_before, st.offset);
                    },
                    else => {},
                }
            }
        }
        e.send.reclaimBefore(self.allocator, safe_before);
    }

    fn reclaimResetStreams(self: *Connection) void {
        for (&self.streams) |*e| self.reclaimResetStreamData(e);
    }

    /// G15 (noq detect_spurious_loss, mod.rs:3074-3100): drop every lost PN
    /// this ACK covers; returns true when the ACK acknowledged ALL deemed-lost
    /// packets of the space, proving a past congestion event was spurious.
    /// The retransmitted frames are NOT un-queued (noq doesn't either) — only
    /// the congestion controller state is restored by the caller.
    fn detectSpuriousLoss(self: *Connection, space: spaces.SpaceId, a: frame.Ack) bool {
        const lost = &self.lost_packets[@intFromEnum(space)];
        if (lost.items.len == 0) return false;
        var write: usize = 0;
        for (lost.items) |lp| {
            if (!ackContains(a, lp.packet_number)) {
                lost.items[write] = lp;
                write += 1;
            }
        }
        lost.shrinkRetainingCapacity(write);
        // We cannot conclude while losses remain; future ACKs might still
        // indicate the spurious loss detection (noq mod.rs:3095-3099).
        return lost.items.len == 0;
    }

    /// G15 (noq drain_lost_packets, mod.rs:3103-3113): forget lost packets old
    /// enough that their ACK would plausibly never arrive — "sent earlier
    /// than 2 probe timeouts ago" (criterion copied from msquic).
    fn drainLostPackets(self: *Connection, space: spaces.SpaceId) void {
        const two_pto = 2 * self.rtt.ptoBase();
        const lost = &self.lost_packets[@intFromEnum(space)];
        var write: usize = 0;
        for (lost.items) |lp| {
            if (self.now - lp.time_sent <= two_pto) {
                lost.items[write] = lp;
                write += 1;
            }
        }
        lost.shrinkRetainingCapacity(write);
    }

    fn detectAndRequeueLosses(self: *Connection, space: spaces.SpaceId) void {
        const largest = (self.spaces_state.getConst(space).largest_acked) orelse return;
        self.drainLostPackets(space);
        var out: [max_loss_batch]loss.LossEvent = undefined;
        const res = loss.detectLostPackets(
            self.sent.items,
            self.now,
            largest,
            space,
            self.rtt,
            self.peerMaxAckDelayNs(),
            self.first_pn_after_rtt_sample,
            self.probe_pn,
            &out,
        );
        const nlost = res.count;
        if (nlost == 0) return;
        const old_bytes_in_flight = self.bytes_in_flight;
        var size_of_lost_packets: u64 = 0;
        var largest_lost_pn: ?u64 = null;
        var largest_lost_sent: Instant = 0;
        const old_len = self.sent.items.len;
        var read: usize = 0;
        var write: usize = 0;
        var loss_index: usize = 0;
        while (read < old_len) : (read += 1) {
            var sp = self.sent.items[read];
            const lost = loss_index < nlost and
                sp.space == out[loss_index].space and
                sp.packet_number == out[loss_index].packet_number;
            if (lost) {
                loss_index += 1;
                if (!sp.loss_reported) {
                    self.stats_loss_events +|= 1; // flagged by loss.detectLostPackets
                    sp.loss_reported = true;
                }
                if (self.requeueContent(sp)) {
                    self.onPacketLost(sp);
                    // noq mod.rs:3313-3316: a lost MTU probe runs only the
                    // probe-loss path — no lost_packets entry, no congestion
                    // accounting.
                    const is_probe = if (self.probe_pn) |probe| probe == sp.packet_number else false;
                    if (!is_probe) {
                        // G15: remember the loss so a later ACK covering it can
                        // exonerate the congestion event (noq handle_lost_packets
                        // lost_packets.insert, mod.rs:3463-3468).
                        self.lost_packets[@intFromEnum(space)].append(self.allocator, .{
                            .packet_number = sp.packet_number,
                            .time_sent = sp.time_sent,
                        }) catch {};
                        size_of_lost_packets += sp.size;
                        if (largest_lost_pn == null or sp.packet_number > largest_lost_pn.?) {
                            largest_lost_pn = sp.packet_number;
                            largest_lost_sent = sp.time_sent;
                        }
                    }
                    continue;
                }
                // Allocation failure on the oldest selected loss: retain it and
                // every later record in order. Let the next detection retry the
                // same prefix instead of allowing later loss callbacks to pass it.
                self.sent.items[write] = sp;
                write += 1;
                read += 1;
                while (read < old_len) : (read += 1) {
                    if (write != read) self.sent.items[write] = self.sent.items[read];
                    write += 1;
                }
                break;
            }
            if (write != read) self.sent.items[write] = sp;
            write += 1;
        }
        self.sent.shrinkRetainingCapacity(write);
        self.rebuildPtoInflight();

        // G16 (noq handle_lost_packets, mod.rs:3428-3437 +
        // 3486-3495): ONE congestion event per loss batch, carrying the
        // persistent-congestion verdict the detector computed. "Don't apply
        // congestion penalty for lost ack-only packets": noq's
        // lost_ack_eliciting is bytes_in_flight having shrunk.
        if (largest_lost_pn) |largest_pn| {
            if (self.bytes_in_flight != old_bytes_in_flight) {
                if (self.cc) |cc| {
                    cc.onCongestionEvent(self.now, largest_lost_sent, res.in_persistent_congestion, false, size_of_lost_packets, largest_pn);
                }
            }
        }

        // Every loss in this round has been reported; the open burst is now
        // complete, so ask the detector for a verdict (upstream calls
        // `black_hole_detected` at exactly this point, `mtud.rs:139`).
        if (space == .data and self.mtu_black_hole.detected()) self.onMtuBlackHole();
    }

    /// Returns false if any allocation failed. The caller must retain `sp` in
    /// that case so its absolute ranges continue to pin the send buffer.
    fn requeueContent(self: *Connection, sp: SentPacket) bool {
        var crypto_counts = [_]usize{0} ** 3;
        var stream_counts = [_]usize{0} ** max_streams;
        var i: usize = 0;
        while (i < sp.content_len) : (i += 1) {
            switch (sp.content[i]) {
                .crypto => |cr| crypto_counts[@intFromEnum(cr.space)] += 1,
                .stream => |st| for (&self.streams, 0..) |*e, stream_i| {
                    if (e.used and e.id == st.id) {
                        if (e.send.reset_code == null) stream_counts[stream_i] += 1;
                        break;
                    }
                },
                .reset_stream => {},
                .stop_sending => {},
            }
        }
        for (&self.crypto_rtx, crypto_counts) |*rtx, count| {
            if (count != 0) rtx.ensureUnusedCapacity(self.allocator, count) catch return false;
        }
        for (&self.streams, stream_counts) |*e, count| {
            if (count != 0) e.send.rtx.ensureUnusedCapacity(self.allocator, count) catch return false;
        }

        i = 0;
        while (i < sp.content_len) : (i += 1) {
            switch (sp.content[i]) {
                .crypto => |cr| {
                    self.crypto_rtx[@intFromEnum(cr.space)].pushBackAssumeCapacity(.{ .offset = cr.offset, .len = cr.len, .fin = false });
                    self.stats_retransmits +|= 1;
                },
                .stream => |st| {
                    if (self.findStream(st.id)) |e| {
                        if (e.send.reset_code != null) continue;
                        e.send.rtx.pushBackAssumeCapacity(.{ .offset = st.offset, .len = st.len, .fin = st.fin });
                        self.stats_retransmits +|= 1;
                    }
                },
                .reset_stream => |reset| {
                    if (self.findStream(reset.id)) |e| e.send.reset_sent = false;
                    self.stats_retransmits +|= 1;
                },
                .stop_sending => |stop| {
                    if (self.findStream(stop.id)) |e| e.recv.stop_sent = false;
                    self.stats_retransmits +|= 1;
                },
            }
        }
        return true;
    }

    /// A9 (noq `read_crypto`, connection/mod.rs:4016-4023): the CRYPTO level we
    /// currently expect. Data once the handshake completes; otherwise the
    /// highest level we hold read keys for (a server with 1-RTT keys still
    /// expects Handshake CRYPTO until the handshake completes).
    fn expectedCryptoSpace(self: *const Connection) spaces.SpaceId {
        if (self.state != .handshake) return .data;
        if (self.read_keys[@intFromEnum(spaces.SpaceId.handshake)] == null) return .initial;
        return .handshake;
    }

    fn ingestCrypto(self: *Connection, space: spaces.SpaceId, c: frame.Crypto) Error!void {
        const si = @intFromEnum(space);
        const consumed = self.crypto_in_offset[si];
        const end = c.offset + c.data.len;

        // A9 wrong-level (noq read_crypto, mod.rs:4031-4041): NEW data (end
        // past the consumed high-water) arriving at a level below the expected
        // one is a PROTOCOL_VIOLATION. Retransmits of already-consumed bytes
        // at an old level are tolerated, exactly like noq.
        if (@intFromEnum(space) < @intFromEnum(self.expectedCryptoSpace()) and end > consumed) {
            return self.protocolClose(err_protocol_violation);
        }

        // A9 buffer bound (noq read_crypto, mod.rs:4043-4049): the
        // unreassembled span (frame end minus contiguous bytes consumed,
        // saturating like noq) may not exceed the crypto buffer — noq's
        // `crypto_buffer_size` default 16 KiB, already our `max_crypto_buf`.
        if (end -| consumed > max_crypto_buf) {
            return self.protocolClose(err_crypto_buffer_exceeded);
        }

        if (end <= consumed) return; // pure retransmit of consumed bytes

        if (c.offset > consumed) {
            // Out of order: buffer the unconsumed bytes until the gap fills.
            try self.insertCryptoPending(si, c.offset, c.data);
            return;
        }

        // In-order (possibly with an already-consumed prefix): feed the suffix,
        // then drain whatever the newly-filled gap unblocks.
        const skip: usize = @intCast(consumed - c.offset);
        const data = c.data[skip..];
        try self.feedTls(space, data);
        self.crypto_in_offset[si] = consumed + data.len;
        try self.drainCryptoPending(space);
    }

    /// Buffer `data` (at absolute stream `offset`, all past the consumed
    /// high-water) for later reassembly, trimming any byte ranges already
    /// buffered so the pending list stays non-overlapping (noq assembler
    /// defragment) and bounded by the `max_crypto_buf` span check above.
    fn insertCryptoPending(self: *Connection, si: usize, offset: u64, data: []const u8) Error!void {
        const list = &self.crypto_in_pending[si];
        // Evict anything a slow drain left fully below the high-water.
        var i: usize = 0;
        while (i < list.items.len) {
            const seg = list.items[i];
            if (seg.offset + seg.data.len <= self.crypto_in_offset[si]) {
                self.allocator.free(seg.data);
                _ = list.orderedRemove(i);
            } else {
                i += 1;
            }
        }
        var cursor = offset;
        const end = offset + data.len;
        while (cursor < end) {
            // Skip ranges an existing segment already covers.
            var covered = false;
            var nearest_start: u64 = end;
            for (list.items) |seg| {
                const seg_end = seg.offset + seg.data.len;
                if (seg.offset <= cursor and cursor < seg_end) {
                    cursor = seg_end;
                    covered = true;
                    break;
                }
                if (seg.offset > cursor and seg.offset < nearest_start) nearest_start = seg.offset;
            }
            if (covered) continue;
            const len: usize = @intCast(nearest_start - cursor);
            const copy = try self.allocator.dupe(u8, data[cursor - offset ..][0..len]);
            try list.append(self.allocator, .{ .offset = cursor, .data = copy });
            cursor = nearest_start;
        }
    }

    /// Feed TLS every pending segment now contiguous with the consumed
    /// high-water (noq's `while let Some(chunk) = crypto_stream.read(..)`).
    fn drainCryptoPending(self: *Connection, space: spaces.SpaceId) Error!void {
        const si = @intFromEnum(space);
        const list = &self.crypto_in_pending[si];
        while (true) {
            const consumed = self.crypto_in_offset[si];
            var found: ?usize = null;
            for (list.items, 0..) |seg, i| {
                if (seg.offset <= consumed and consumed < seg.offset + seg.data.len) {
                    found = i;
                    break;
                }
            }
            const i = found orelse return;
            const seg = list.items[i];
            const skip: usize = @intCast(consumed - seg.offset);
            const data = seg.data[skip..];
            try self.feedTls(space, data);
            self.crypto_in_offset[si] = consumed + data.len;
            self.allocator.free(seg.data);
            _ = list.orderedRemove(i);
        }
    }

    fn feedTls(self: *Connection, space: spaces.SpaceId, data: []const u8) Error!void {
        const epoch: crypto.Epoch = switch (space) {
            .initial => .initial,
            .handshake => .handshake,
            .data => .application,
        };
        var out = tlsHandleMessage(self.tls, self.allocator, epoch, data) catch |err| {
            // B8 (noq crypto/rustls.rs:98-108): a TLS failure carrying an
            // alert becomes a CRYPTO_ERROR (0x0100 + alert) transport close;
            // a TLS failure without an alert is a PROTOCOL_VIOLATION (noq's
            // non-alert branch, rustls.rs:106). The close rides in every
            // keyed space via the B2 machinery; the error still propagates
            // so the transport marks the entry rejected (Gate B shape).
            if (err == error.PicotlsError) {
                const code = if (self.tls.lastAlertCode()) |alert|
                    err_crypto_error_base + @as(u64, alert)
                else
                    err_protocol_violation;
                self.protocolClose(code);
            }
            return err;
        };
        defer out.deinit();
        // noq HandshakeDataReady (crypto/rustls.rs:111-123): fire exactly once,
        // when ALPN or the peer's SNI first becomes readable — or at handshake
        // completion when neither exists. Not per CRYPTO feed. Pushed
        // BEFORE queueTlsOutput: installKeysFromTls (called there) pushes
        // `.connected` on completion, and the handshake_data event must precede
        // connected on the wire-facing event stream (C22 ordering contract).
        if (!self.handshake_data_sent and
            (self.tls.negotiatedProtocol() != null or self.tls.serverName() != null or self.tls.isComplete()))
        {
            self.handshake_data_sent = true;
            try self.events.pushBack(self.allocator, .handshake_data);
        }
        try self.queueTlsOutput(out);
    }

    /// True when `datagram` ends with a peer-issued stateless-reset token
    /// (transport-parameter token or any non-retired remote NEW_CONNECTION_ID token).
    /// Public so the transport demux can check unroutable short-headers (RFC 9000
    /// §10.3: reset detection is not CID-demuxed — the unit path feeds handleDatagram
    /// directly, but real UDP ingress routes by DCID first).
    pub fn matchesPeerStatelessReset(self: *const Connection, datagram: []const u8) bool {
        if (self.test_disable_peer_stateless_reset) return false;
        if (datagram.len < packet.stateless_reset_min_len) return false;
        if (self.peer_stateless_reset_token) |token| {
            if (packet.detectStatelessReset(datagram, token)) return true;
        }
        var i: usize = 0;
        while (i < self.remote_cid_len) : (i += 1) {
            if (self.remote_cids[i].retired) continue;
            if (packet.detectStatelessReset(datagram, self.remote_cids[i].reset_token)) return true;
        }
        return false;
    }

    /// Locate the short-header packet-number offset by matching the DCID against
    /// the local CID registry (including CIDs issued via NEW_CONNECTION_ID).
    fn shortHeaderPnOffset(self: *const Connection, data: []const u8) ?usize {
        if (data.len < 2) return null;
        var best: ?usize = null;
        var i: usize = 0;
        while (i < self.local_cid_len) : (i += 1) {
            if (self.local_cids[i].retired) continue;
            const cid = self.local_cids[i].cid;
            if (cid.len == 0) continue;
            if (data.len < 1 + cid.len) continue;
            if (std.mem.eql(u8, data[1 .. 1 + cid.len], cid.slice())) {
                const off = 1 + cid.len;
                if (best == null or off > best.?) best = off;
            }
        }
        // Fall back to the primary local_cid (always registered at create).
        if (best == null and self.local_cid.len > 0 and data.len >= 1 + self.local_cid.len) {
            if (std.mem.eql(u8, data[1 .. 1 + self.local_cid.len], self.local_cid.slice())) {
                return 1 + self.local_cid.len;
            }
        }
        return best;
    }
};

/// Is `pn` covered by any range of ACK frame `a`? (RFC 9000 §19.3.1 range walk.)
fn ackContains(a: frame.Ack, pn: u64) bool {
    var high = a.largest_acked;
    var low = if (a.first_range <= high) high - a.first_range else 0;
    if (pn >= low and pn <= high) return true;
    for (a.additional()) |r| {
        // Next range's largest = previous smallest - gap - 2.
        const step = r.gap + 2;
        if (low < step) return false;
        high = low - step;
        low = if (r.range <= high) high - r.range else 0;
        if (pn >= low and pn <= high) return true;
    }
    return false;
}

fn epochToSpace(epoch: crypto.Epoch) spaces.SpaceId {
    return switch (epoch) {
        .initial => .initial,
        .zero_rtt => .data, // treat as data for buffer purposes
        .handshake => .handshake,
        .application => .data,
    };
}

fn minOpt(a: ?Instant, b: Instant) Instant {
    return if (a) |v| @min(v, b) else b;
}

fn idleTimeoutNs(ms: u64) ?i64 {
    if (ms == 0) return null;
    const ns = std.math.mul(u64, ms, std.time.ns_per_ms) catch std.math.maxInt(i64);
    return @intCast(@min(ns, @as(u64, @intCast(std.math.maxInt(i64)))));
}

fn effectiveIdleTimeoutNs(local_ms: u64, peer_ms: u64) ?i64 {
    const ms = if (local_ms == 0)
        peer_ms
    else if (peer_ms == 0)
        local_ms
    else
        @min(local_ms, peer_ms);
    return idleTimeoutNs(ms);
}

// ── Pair harness (5b Zig↔Zig loopback gate) ────────────────────────────────

const TestPair = struct {
    client: *Connection,
    server: *Connection,

    fn deinit(self: *TestPair) void {
        self.client.destroy();
        self.server.destroy();
    }
};

/// Build a client+server driver pair. `server_params` optionally overrides the
/// server's advertised flow-control windows (used by the FC gate).
fn makePair(allocator: std.mem.Allocator, server_params: ?[]const u8) !TestPair {
    // Default to picotls; a product with picotls compiled out (noq-zigtls) runs
    // these backend-agnostic driver tests under zigtls instead.
    const backend: crypto.Backend = if (crypto.picotls_enabled) .picotls else .zigtls;
    return makePairBackend(allocator, backend, server_params);
}

/// Deterministic 32-byte CSPRNG seed for tests (expands a u64 into the ChaCha seed).
fn testCsprngSeed(tag: u64) [std.Random.DefaultCsprng.secret_seed_length]u8 {
    var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = .{0} ** std.Random.DefaultCsprng.secret_seed_length;
    std.mem.writeInt(u64, seed[0..8], tag, .little);
    // Mix the tag across the rest so the CSPRNG key is not sparse.
    var i: usize = 8;
    while (i + 8 <= seed.len) : (i += 8) {
        std.mem.writeInt(u64, seed[i..][0..8], tag *% (@as(u64, @intCast(i)) +% 0x9e37_79b9_7f4a_7c15), .little);
    }
    return seed;
}

fn makePairBackend(allocator: std.mem.Allocator, backend: crypto.Backend, server_params: ?[]const u8) !TestPair {
    const client_key = key.SecretKey.fromBytes(.{0x11} ** 32);
    const server_key = key.SecretKey.fromBytes(.{0x22} ** 32);
    const client_cid = try packet.ConnectionId.init(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });
    const server_cid = try packet.ConnectionId.init(&.{ 0x51, 0x52, 0x53, 0x54 });
    const initial_dcid = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const server_name = tls_name.serverName(server_key.public());

    const client = try Connection.create(allocator, .{
        .backend = backend,
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .server_name = &server_name,
    }, client_cid, initial_dcid, initial_dcid, testCsprngSeed(0xC0FFEE), .{});
    errdefer client.destroy();

    const server = try Connection.create(allocator, .{
        .backend = backend,
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = client_key.public(),
        .require_client_authentication = true,
        .transport_params = server_params,
    }, server_cid, client_cid, initial_dcid, testCsprngSeed(0xBADC0DE), .{});
    errdefer server.destroy();

    return .{ .client = client, .server = server };
}

/// makePair with an explicit congestion controller kind on both ends (the
/// pair builders above are pinned to the cubic default).
fn makePairCongestionKind(allocator: std.mem.Allocator, kind: congestion.Kind) !TestPair {
    const backend: crypto.Backend = if (crypto.picotls_enabled) .picotls else .zigtls;
    const client_key = key.SecretKey.fromBytes(.{0x41} ** 32);
    const server_key = key.SecretKey.fromBytes(.{0x42} ** 32);
    const client_cid = try packet.ConnectionId.init(&.{ 0x61, 0x62, 0x63, 0x64 });
    const server_cid = try packet.ConnectionId.init(&.{ 0x71, 0x72, 0x73, 0x74 });
    const initial_dcid = try packet.ConnectionId.init(&.{ 0x93, 0xa4, 0xb8, 0xc0, 0x4e, 0x61, 0x67, 0x18 });
    const server_name = tls_name.serverName(server_key.public());

    const client = try Connection.create(allocator, .{
        .backend = backend,
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .server_name = &server_name,
    }, client_cid, initial_dcid, initial_dcid, testCsprngSeed(0x0A11CE), .{
        .congestion_kind = kind,
    });
    errdefer client.destroy();

    const server = try Connection.create(allocator, .{
        .backend = backend,
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = client_key.public(),
        .require_client_authentication = true,
    }, server_cid, client_cid, initial_dcid, testCsprngSeed(0x0BE11A), .{
        .congestion_kind = kind,
    });
    errdefer server.destroy();

    return .{ .client = client, .server = server };
}

test "destroy scrubSecrets zeros connection-owned secret inventory" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // Post-handshake secrets should be live.
    try std.testing.expect(pair.client.app_write_secret_len > 0 or pair.client.crypto_1rtt.current != null);
    // Seed retry key to a known non-zero pattern so the wipe is observable.
    @memset(&pair.client.retry_secret_key, 0xa5);
    pair.client.scrubSecrets();
    try std.testing.expectEqual(@as(usize, 0), pair.client.app_write_secret_len);
    try std.testing.expectEqual(@as(usize, 0), pair.client.app_read_secret_len);
    try std.testing.expect(pair.client.crypto_1rtt.current == null);
    try std.testing.expect(pair.client.crypto_1rtt.prev == null);
    try std.testing.expect(pair.client.crypto_1rtt.next == null);
    try std.testing.expectEqual([_]u8{0} ** 64, pair.client.app_write_secret);
    try std.testing.expectEqual([_]u8{0} ** 64, pair.client.app_read_secret);
    try std.testing.expectEqual([_]u8{0} ** 32, pair.client.retry_secret_key);
    for (pair.client.write_keys) |slot| try std.testing.expect(slot == null);
    for (pair.client.read_keys) |slot| try std.testing.expect(slot == null);
}

test "handleDatagram empty input is a no-op (no OOB)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // Must not panic / OOB on zero-length; armIdle is skipped for empty.
    try pair.client.handleDatagram(1_000_000, &.{});
    try std.testing.expect(pair.client.state == .established);
}

test "N-2 idle timeout surfaces connection_lost" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();

    const timeout = idleTimeoutNs(default_max_idle_timeout_ms).?;
    pair.client.armIdle(0);
    pair.client.handleTimeout(timeout + 1);
    try std.testing.expect(pair.client.state == .draining);
    const ev = pair.client.poll().?;
    try std.testing.expect(std.meta.activeTag(ev) == .connection_lost);
    try std.testing.expectEqualStrings("idle-timeout", ev.connection_lost.reason);
}

test "G18-idle: silent peer is idle-timed-out despite our keep-alive/PTO sends" {
    // RFC 9000 §10.1 (noq permit_idle_reset, packet_builder.rs:303-318): a
    // SEND restarts the idle timer only for the first ack-eliciting packet
    // after a received packet. Without that gate, an endpoint with an
    // unacked flight keeps emitting PTO probes (≤2 s apart) and re-arming its
    // own idle deadline on every one of them, so a gone peer is NEVER
    // idle-timed-out and the caller burns the full stream timeout instead of
    // a bounded connection_lost — the bench signature is AnchorAckTimeout
    // (60 s wait) under UDP drop stress rather than AnchorAckConnectionLost.
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);
    const s = pair.server;
    // Transport wiring: the endpoint arms the 5 s keep-alive interval.
    s.setKeepAliveIntervalNs(default_keep_alive_interval_ns);

    // One unacked data flight toward a peer that then goes silent: the
    // stream payload emits, is never delivered, and PTO probes chase it.
    const sid = try s.openStream(.bidi);
    try s.writeStream(sid, "silent-peer-flake-tail", false);

    const idle_ns = idleTimeoutNs(default_max_idle_timeout_ms).?;
    const silence_start = s.now;
    var now = silence_start;
    var sends: usize = 0;
    var lost_at: ?Instant = null;
    const horizon = idle_ns + 10 * std.time.ns_per_s;
    while (now - silence_start < horizon) : (now += 100 * std.time.ns_per_ms) {
        s.handleTimeout(now);
        s.next_send_at = 0; // pacing must not hold probes back in the harness
        while (try s.pollTransmit(now)) |_| {
            // Every datagram is emitted into the void: the silent peer never
            // receives, never ACKs, never sends.
            sends += 1;
        }
        if (s.state == .draining or s.state == .closed or s.state == .drained) {
            lost_at = now;
            break;
        }
    }
    // We DID keep sending (data + PTO probes + keep-alive) while the peer was
    // silent — yet the idle deadline fired instead of being re-armed forever.
    try std.testing.expect(sends >= 3);
    try std.testing.expect(lost_at != null);
    try std.testing.expect(lost_at.? - silence_start <= idle_ns + std.time.ns_per_s);
    var saw_idle_lost = false;
    while (s.poll()) |ev| {
        if (std.meta.activeTag(ev) == .connection_lost and
            std.mem.eql(u8, ev.connection_lost.reason, "idle-timeout")) saw_idle_lost = true;
    }
    try std.testing.expect(saw_idle_lost);
}

test "event queue preserves FIFO order across deque wraparound" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.drainEvents();

    for (0..40) |id| {
        try pair.client.events.pushBack(std.testing.allocator, .{
            .stream_reset = .{ .id = id, .code = id + 100 },
        });
    }
    for (0..20) |expected| {
        const event = pair.client.poll() orelse return error.UnexpectedState;
        switch (event) {
            .stream_reset => |reset| {
                try std.testing.expectEqual(@as(u64, expected), reset.id);
                try std.testing.expectEqual(@as(u64, expected + 100), reset.code);
            },
            else => return error.UnexpectedState,
        }
    }
    for (40..60) |id| {
        try pair.client.events.pushBack(std.testing.allocator, .{
            .stream_reset = .{ .id = id, .code = id + 100 },
        });
    }
    for (20..60) |expected| {
        const event = pair.client.poll() orelse return error.UnexpectedState;
        switch (event) {
            .stream_reset => |reset| {
                try std.testing.expectEqual(@as(u64, expected), reset.id);
                try std.testing.expectEqual(@as(u64, expected + 100), reset.code);
            },
            else => return error.UnexpectedState,
        }
    }
    try std.testing.expect(pair.client.poll() == null);
}

test "N-3 stream limits enforce local opens and peer-created ids" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();

    pair.client.peer_params_applied = true;
    pair.client.peer_params.initial_max_streams_bidi = 1;
    _ = try pair.client.openStream(.bidi);
    try std.testing.expectError(error.StreamLimit, pair.client.openStream(.bidi));

    pair.server.local_params.initial_max_streams_bidi = 1;
    _ = try pair.server.getOrCreateStream(0);
    try std.testing.expectError(error.StreamLimit, pair.server.getOrCreateStream(4));
}

fn pumpOnce(pair: *TestPair, now: Instant, pkt_idx: *usize, drop: ?*const fn (usize, bool) bool) !void {
    // Timers first (PTO/close) — real pumps arm/fire timeouts each round.
    pair.client.handleTimeout(now);
    pair.server.handleTimeout(now);
    while (try pair.client.pollTransmit(now)) |tx| {
        pkt_idx.* += 1;
        const d = if (drop) |f| f(pkt_idx.*, true) else false;
        if (!d) try pair.server.handleDatagram(now, tx.bytes);
    }
    while (try pair.server.pollTransmit(now)) |tx| {
        pkt_idx.* += 1;
        const d = if (drop) |f| f(pkt_idx.*, false) else false;
        if (!d) try pair.client.handleDatagram(now, tx.bytes);
    }
    pair.client.drainEvents();
    pair.server.drainEvents();
}

fn establishPair(pair: *TestPair) !void {
    try pair.client.startClient();
    var now: Instant = 0;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    while (rounds < 32 and !(pair.client.state == .established and pair.server.state == .established)) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(pair, now, &pkt_idx, null);
    }
    try std.testing.expect(pair.client.state == .established);
    try std.testing.expect(pair.server.state == .established);
}

/// G4: with noq's delayed-ACK cadence (data-space ACKs deferred below the
/// threshold until `max_ack_delay`) the establishment flow can end with a
/// deferred ACK on either side and the peer's last flight still outstanding.
/// Tests whose premise is "only MY synthetic packet is in flight" (PTO /
/// loss pokes) must flush first: advance past max_ack_delay and pump once so
/// the delayed-ACK timer fires exactly like a real event loop would drive it.
fn flushDeferredAcks(pair: *TestPair) !void {
    var idx: usize = 0;
    try pumpOnce(pair, pair.client.now + 30_000_000, &idx, null);
}

test "large multi-range ACK is budgeted: ACK + full stream frame fits one datagram" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);

    // Heavy loss/reordering on the server's receive tracker → many disjoint
    // ranges → a large multi-range ACK (up to the additional-range cap).
    const si = @intFromEnum(spaces.SpaceId.data);
    var pn: u64 = 0;
    while (pn <= 2 * (frame.max_ack_additional + 4)) : (pn += 2) {
        pair.server.pending_acks[si].onRecv(pn);
    }
    pair.server.needs_ack[si] = true;
    const ack = pair.server.pending_acks[si].toAckFrame(0).?;
    try std.testing.expect(ack.additional_len >= 32);

    // Queue more than one datagram's worth of stream data so packet assembly
    // wants to fill the budget with STREAM bytes behind the large ACK.
    var payload: [4096]u8 = undefined;
    @memset(&payload, 0x5A);
    const sid = try pair.server.openStream(.bidi);
    try pair.server.writeStream(sid, &payload, false);

    // Every datagram must encode and fit: pre-fix the unbudgeted ACK let a
    // budget-filling STREAM frame overflow tx_scratch → FrameEncodeFailed →
    // pollTransmit error → connection torn down under loss.
    var now: Instant = 100_000_000;
    var emitted: usize = 0;
    while (emitted < 16) : (emitted += 1) {
        const tx = (try pair.server.pollTransmit(now)) orelse break;
        try std.testing.expect(tx.bytes.len <= max_datagram);
        now += 1_000_000;
    }
    try std.testing.expect(emitted > 0);
}

test "S3-diag: zigtls Connection TestPair establish + stream echo" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    var pair = try makePairBackend(std.testing.allocator, .zigtls, null);
    defer pair.deinit();
    try establishPair(&pair);
    const client_tp = pair.client.tls.peerTransportParams();
    const server_tp = pair.server.tls.peerTransportParams();
    try std.testing.expect(client_tp != null);
    try std.testing.expect(server_tp != null);
    _ = transport_parameters.decode(client_tp.?) catch return error.ClientPeerTpDecodeFailed;
    _ = transport_parameters.decode(server_tp.?) catch return error.ServerPeerTpDecodeFailed;
    try std.testing.expect(pair.client.peer_params_applied);
    try std.testing.expect(pair.server.peer_params_applied);
    const sid = try pair.client.openStream(.bidi);
    try pair.client.writeStream(sid, "zigtls-diag", true);
    var now: Instant = 0;
    var pkt_idx: usize = 0;
    var got = false;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
        if (pair.server.streamRecvFin(sid)) {
            try std.testing.expectEqualStrings("zigtls-diag", pair.server.streamRecvBytes(sid));
            try pair.server.writeStream(sid, pair.server.streamRecvBytes(sid), true);
            got = true;
            break;
        }
    }
    try std.testing.expect(got);
    rounds = 0;
    while (rounds < 32 and !pair.client.streamRecvFin(sid)) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expectEqualStrings("zigtls-diag", pair.client.streamRecvBytes(sid));
}

test "N-3 anti-amplification server caps pre-validation sends at 3x received" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();
    var now: Instant = 1_000_000;
    var pkt_idx: usize = 0;
    try pumpOnce(&pair, now, &pkt_idx, null);
    try std.testing.expect(!pair.server.path_validated_any);
    try std.testing.expect(pair.server.validated_len == 0);
    try std.testing.expect(pair.server.state != .established);
    const received = pair.server.bytes_received;
    try std.testing.expect(received > 0);
    var sent: u64 = 0;
    var rounds: usize = 0;
    while (rounds < 48) : (rounds += 1) {
        if (try pair.server.pollTransmit(now)) |tx| {
            sent += tx.bytes.len;
            try pair.client.handleDatagram(now, tx.bytes);
        }
        now += 1_000_000;
        if (pair.server.state == .established) break;
    }
    try std.testing.expect(sent <= received * 3);
}

test "N-3 datagram send recv through TestPair" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try pair.client.sendDatagram("hello-dgram");
    var now: Instant = 0;
    var pkt_idx: usize = 0;
    var got: ?[]u8 = null;
    var rounds: usize = 0;
    while (rounds < 16) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
        got = pair.server.recvDatagram();
        if (got != null) break;
    }
    const payload = got orelse return error.UnexpectedState;
    defer std.testing.allocator.free(payload);
    try std.testing.expectEqualSlices(u8, "hello-dgram", payload);
}

test "outbound datagram queue preserves FIFO order across deque wraparound" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.peer_params.max_datagram_frame_size = default_max_datagram_frame_size;

    for (0..40) |value| {
        try pair.client.sendDatagram(&.{@intCast(value)});
    }
    for (0..20) |expected| {
        const payload = pair.client.takeDatagramOut() orelse return error.UnexpectedState;
        const value = payload[0];
        std.testing.allocator.free(payload);
        try std.testing.expectEqual(@as(u8, @intCast(expected)), value);
    }
    for (40..60) |value| {
        try pair.client.sendDatagram(&.{@intCast(value)});
    }
    for (20..60) |expected| {
        const payload = pair.client.takeDatagramOut() orelse return error.UnexpectedState;
        const value = payload[0];
        std.testing.allocator.free(payload);
        try std.testing.expectEqual(@as(u8, @intCast(expected)), value);
    }
    try std.testing.expectEqual(@as(usize, 0), pair.client.datagram_out.len);
    try std.testing.expectEqual(@as(usize, 0), pair.client.datagram_out_total);
}

test "outbound datagram queue drops oldest past the send-buffer bound" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.peer_params.max_datagram_frame_size = default_max_datagram_frame_size;

    // 1197-byte payloads (the max at the default frame size): 876 fill the
    // 1 MiB noq send buffer exactly (876*1197 = 1_048_572 <= 1_048_576).
    const payload_len = 1197;
    const fitting = datagram_send_buffer_size / payload_len;
    var buf: [payload_len]u8 = undefined;
    const sent = fitting + 3;
    for (0..sent) |i| {
        @memset(&buf, 0);
        std.mem.writeInt(u32, buf[0..4], @intCast(i), .little);
        try pair.client.sendDatagram(&buf);
    }
    // The bound held: nothing queued past the buffer, oldest dropped first,
    // and the retained suffix keeps FIFO order.
    try std.testing.expect(pair.client.datagram_out_total <= datagram_send_buffer_size);
    try std.testing.expectEqual(fitting, pair.client.datagram_out.len);
    for (sent - fitting..sent) |expected| {
        const payload = pair.client.takeDatagramOut() orelse return error.UnexpectedState;
        defer std.testing.allocator.free(payload);
        try std.testing.expectEqual(@as(u32, @intCast(expected)), std.mem.readInt(u32, payload[0..4], .little));
    }
    try std.testing.expectEqual(@as(usize, 0), pair.client.datagram_out_total);
}

test "DATAGRAM max size reports payload bytes after frame overhead" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.peer_params.max_datagram_frame_size = default_max_datagram_frame_size;

    const max = pair.client.maxDatagramSize() orelse return error.UnexpectedState;
    try std.testing.expectEqual(@as(usize, 1197), max);

    var ok: [1197]u8 = undefined;
    @memset(&ok, 0xab);
    try pair.client.sendDatagram(&ok);
    var too_big: [1198]u8 = undefined;
    @memset(&too_big, 0xcd);
    try std.testing.expectError(error.DatagramTooLarge, pair.client.sendDatagram(&too_big));

    const queued = pair.client.takeDatagramOut() orelse return error.UnexpectedState;
    defer std.testing.allocator.free(queued);
    try std.testing.expectEqual(@as(usize, ok.len), queued.len);
    try std.testing.expectEqual(@as(usize, 0), pair.client.datagram_out_total);
}

test "stream send buffer reclaims absolute-offset prefixes geometrically" {
    var send: StreamSend = .{};
    defer send.deinit(std.testing.allocator);
    const bytes = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    try send.buf.appendSlice(std.testing.allocator, &bytes);
    send.send_next = bytes.len;

    send.reclaimBefore(std.testing.allocator, 4);
    try std.testing.expectEqual(@as(u64, 0), send.buf_offset);
    try std.testing.expectEqual(@as(usize, bytes.len), send.buf.items.len);

    send.reclaimBefore(std.testing.allocator, 8);
    try std.testing.expectEqual(@as(u64, 8), send.buf_offset);
    try std.testing.expectEqualSlices(u8, bytes[8..], send.buf.items);
    try std.testing.expectEqualSlices(u8, bytes[10..14], send.sliceAt(10, 4));

    try send.buf.appendSlice(std.testing.allocator, &.{ 16, 17, 18, 19 });
    try std.testing.expectEqual(@as(u64, 20), send.endOffset());
    send.reclaimBefore(std.testing.allocator, 16);
    try std.testing.expectEqual(@as(u64, 16), send.buf_offset);
    try std.testing.expectEqualSlices(u8, &.{ 16, 17, 18, 19 }, send.buf.items);
    send.send_next = 20;
    send.reclaimBefore(std.testing.allocator, 20);
    try std.testing.expectEqual(@as(u64, 20), send.buf_offset);
    try std.testing.expectEqual(@as(usize, 0), send.buf.items.len);
    try std.testing.expectEqual(@as(usize, 0), send.buf.capacity);
}

test "stream receive rejects data beyond an established final size" {
    var recv: StreamRecv = .{};
    defer recv.deinit(std.testing.allocator);
    _ = try recv.ingest(std.testing.allocator, 0, "done", true);
    try std.testing.expectError(error.FinalSizeError, recv.ingest(std.testing.allocator, 4, "x", false));
    try std.testing.expectEqual(@as(u64, 4), recv.highest_offset);
}

test "stream receive rejects a FIN below previously observed data" {
    var recv: StreamRecv = .{};
    defer recv.deinit(std.testing.allocator);
    _ = try recv.ingest(std.testing.allocator, 8, "late", false);
    try std.testing.expectError(error.FinalSizeError, recv.ingest(std.testing.allocator, 0, "done", true));
    try std.testing.expect(recv.fin_offset == null);
    try std.testing.expectEqual(@as(u64, 12), recv.highest_offset);
}

test "stream receive does not allocate metadata for empty out-of-order frames" {
    var recv: StreamRecv = .{};
    defer recv.deinit(std.testing.allocator);
    for (0..max_recv_pending_segments + 32) |_| {
        _ = try recv.ingest(std.testing.allocator, 100, &.{}, false);
    }
    try std.testing.expectEqual(@as(usize, 0), recv.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), recv.pending_bytes);
}

test "stream receive caps pending segment metadata transactionally" {
    var recv: StreamRecv = .{};
    defer recv.deinit(std.testing.allocator);
    for (0..max_recv_pending_segments) |i| {
        _ = try recv.ingest(std.testing.allocator, 10_000 + i * 2, &.{0xaa}, false);
    }
    const high_before = recv.highest_offset;
    try std.testing.expectError(error.NoSpaceLeft, recv.ingest(std.testing.allocator, high_before + 2, &.{0xbb}, false));
    try std.testing.expectEqual(high_before, recv.highest_offset);
    try std.testing.expectEqual(max_recv_pending_segments, recv.pendingCount());
}

fn checkPendingIngestAllocationFailures(allocator: std.mem.Allocator) !void {
    var recv: StreamRecv = .{};
    defer recv.deinit(allocator);
    _ = try recv.ingest(allocator, 10, "gap", false);
    try std.testing.expectEqual(@as(usize, 1), recv.pendingCount());
    try std.testing.expectEqualStrings("gap", recv.pending_storage.items);
}

test "stream receive pending ownership is transactional across allocation failures" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkPendingIngestAllocationFailures,
        .{},
    );
}

test "stream receive absorbs reverse-order gaps without rescanning" {
    var recv: StreamRecv = .{};
    defer recv.deinit(std.testing.allocator);
    _ = try recv.ingest(std.testing.allocator, 3, "d", true);
    _ = try recv.ingest(std.testing.allocator, 2, "c", false);
    _ = try recv.ingest(std.testing.allocator, 1, "b", false);
    try std.testing.expectEqual(@as(usize, 3), recv.pendingCount());

    const added = try recv.ingest(std.testing.allocator, 0, "a", false);
    try std.testing.expectEqual(@as(usize, 4), added);
    try std.testing.expectEqualStrings("abcd", recv.data.items);
    try std.testing.expectEqual(@as(usize, 0), recv.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), recv.pending_bytes);
    try std.testing.expect(recv.finReached());
}

test "stream receive compacts shared pending storage after a partial absorb" {
    var recv: StreamRecv = .{};
    defer recv.deinit(std.testing.allocator);
    _ = try recv.ingest(std.testing.allocator, 3, "d", false);
    _ = try recv.ingest(std.testing.allocator, 4, "e", false);
    _ = try recv.ingest(std.testing.allocator, 10, "k", true);
    try std.testing.expectEqual(@as(usize, 3), recv.pending_storage.items.len);

    _ = try recv.ingest(std.testing.allocator, 0, "abcd", false);
    try std.testing.expectEqualStrings("abcde", recv.data.items);
    try std.testing.expectEqual(@as(usize, 1), recv.pendingCount());
    try std.testing.expectEqual(@as(usize, 1), recv.pending_bytes);
    try std.testing.expectEqualStrings("k", recv.pending_storage.items);
    try std.testing.expectEqual(@as(usize, 0), recv.pending.peek().?.storage_start);

    _ = try recv.ingest(std.testing.allocator, 5, "fghij", false);
    try std.testing.expectEqualStrings("abcdefghijk", recv.data.items);
    try std.testing.expectEqual(@as(usize, 0), recv.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), recv.pending_storage.items.len);
    try std.testing.expect(recv.finReached());
}

test "stream reset validates its code and releases an unsent tail" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    const stream = try pair.client.getOrCreateStream(0);
    try pair.client.writeStream(stream.id, "reset-me", false);
    try std.testing.expectError(error.FrameEncodeFailed, pair.client.resetStream(stream.id, varint.max_value + 1));
    try std.testing.expect(stream.send.reset_code == null);

    try pair.client.resetStream(stream.id, 42);
    try std.testing.expectEqual(@as(u64, 0), stream.send.reset_final_size.?);
    try std.testing.expectEqual(@as(u64, 8), stream.send.buf_offset);
    try std.testing.expectEqual(@as(usize, 0), stream.send.buf.items.len);
    try std.testing.expectEqual(@as(usize, 0), stream.send.rtx.len);
}

test "STOP_SENDING crosses the wire and resets the peer send half" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);

    const id = try pair.client.openStream(.bidi);
    try pair.client.writeStream(id, "discard-me", false);
    var now: Instant = 10_000_000;
    var pkt_idx: usize = 0;
    try pumpOnce(&pair, now, &pkt_idx, null);
    try std.testing.expect(pair.server.findStream(id) != null);

    try pair.server.stopStream(id, 0);
    var rounds: usize = 0;
    while (rounds < 8 and pair.client.findStream(id).?.send.reset_code == null) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expectEqual(@as(u64, 0), pair.client.findStream(id).?.send.reset_code.?);
}

test "stream data after RESET_STREAM is final-size checked then discarded" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    const stream = try pair.server.getOrCreateStream(0);
    stream.recv.max_data = 16;
    stream.recv.reset_code = 9;
    stream.recv.fin_offset = 4;
    stream.recv.highest_offset = 4;
    pair.server.recv_data_total = 4;

    try pair.server.handleStreamFrame(.{ .id = 0, .offset = 0, .data = "late", .fin = false });
    try std.testing.expectEqual(@as(usize, 0), stream.recv.data.items.len);
    try std.testing.expectEqual(@as(u64, 4), pair.server.recv_data_total);

    try pair.server.handleStreamFrame(.{ .id = 0, .offset = 4, .data = "x", .fin = false });
    try std.testing.expect(pair.server.close_frame != null);
    try std.testing.expectEqual(err_final_size, pair.server.close_frame.?.error_code);
}

test "stream send reclamation retains outstanding and retransmit ranges" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.sent.clearRetainingCapacity();

    const stream = try pair.client.getOrCreateStream(0);
    try stream.send.buf.appendSlice(std.testing.allocator, "abcdefghijklmnop");
    stream.send.send_next = 16;
    var outstanding: SentPacket = .{
        .path_generation = 0,
        .time_sent = 0,
        .size = 8,
        .ack_eliciting = true,
        .packet_number = 1,
        .space = .data,
        .content_len = 1,
    };
    outstanding.content[0] = .{ .stream = .{ .id = stream.id, .offset = 8, .len = 4, .fin = false } };
    try pair.client.sent.append(std.testing.allocator, outstanding);
    try stream.send.rtx.pushBack(std.testing.allocator, .{ .offset = 12, .len = 4, .fin = false });
    var marked = [_]bool{false} ** max_streams;
    var safe = [_]u64{0} ** max_streams;
    marked[0] = true;
    safe[0] = 8;

    pair.client.reclaimAckedStreamData(&marked, &safe);
    try std.testing.expectEqual(@as(u64, 8), stream.send.buf_offset);
    try std.testing.expectEqualSlices(u8, "ijklmnop", stream.send.buf.items);

    _ = pair.client.sent.swapRemove(0);
    safe[0] = 16;
    pair.client.reclaimAckedStreamData(&marked, &safe);
    try std.testing.expectEqual(@as(u64, 12), stream.send.buf_offset);
    try std.testing.expectEqualSlices(u8, "mnop", stream.send.buf.items);

    _ = stream.send.rtx.popFront();
    pair.client.reclaimAckedStreamData(&marked, &safe);
    try std.testing.expectEqual(@as(u64, 16), stream.send.buf_offset);
    try std.testing.expectEqual(@as(usize, 0), stream.send.buf.items.len);
}

test "onAck reclaims stream storage only after every absolute range is acknowledged" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.sent.clearRetainingCapacity();

    const stream = try pair.client.getOrCreateStream(0);
    try stream.send.buf.appendSlice(std.testing.allocator, "abcdefghijklmnop");
    stream.send.send_next = 16;
    stream.send.fin = true;
    stream.send.fin_sent = true;
    for (0..2) |i| {
        var sp: SentPacket = .{
            .path_generation = 0,
            .time_sent = 0,
            .size = 8,
            .ack_eliciting = false,
            .packet_number = i + 1,
            .space = .data,
            .content_len = 1,
        };
        sp.content[0] = .{ .stream = .{
            .id = stream.id,
            .offset = i * 8,
            .len = 8,
            .fin = i == 1,
        } };
        try pair.client.sent.append(std.testing.allocator, sp);
    }
    // M7: next_pn must be past any PN we claim to have sent.
    pair.client.spaces_state.get(.data).next_pn = 3;

    pair.client.onAck(.data, .{ .largest_acked = 2, .ack_delay = 0, .first_range = 0 });
    try std.testing.expectEqual(@as(u64, 0), stream.send.buf_offset);
    try std.testing.expectEqualSlices(u8, "abcdefghijklmnop", stream.send.buf.items);
    try std.testing.expectEqual(@as(usize, 1), pair.client.sent.items.len);
    try std.testing.expectEqual(@as(u64, 1), pair.client.sent.items[0].packet_number);

    pair.client.onAck(.data, .{ .largest_acked = 1, .ack_delay = 0, .first_range = 0 });
    try std.testing.expectEqual(@as(u64, 16), stream.send.buf_offset);
    try std.testing.expectEqual(@as(usize, 0), stream.send.buf.items.len);
    try std.testing.expect(pair.client.streamSendComplete(stream.id));
}

test "onAck stable compaction preserves unacknowledged packet order" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.sent.clearRetainingCapacity();

    for (10..15) |pn| {
        try pair.client.sent.append(std.testing.allocator, .{
            .path_generation = 0,
            .time_sent = 0,
            .size = 1,
            .ack_eliciting = false,
            .packet_number = pn,
            .space = .data,
        });
    }
    pair.client.spaces_state.get(.data).next_pn = 15; // past synthetic sent PNs (M7)
    const ack = try frame.Ack.withAdditional(12, 0, 0, &.{.{ .gap = 0, .range = 0 }}, null);
    pair.client.onAck(.data, ack);
    try std.testing.expectEqual(@as(usize, 3), pair.client.sent.items.len);
    try std.testing.expectEqual(@as(u64, 11), pair.client.sent.items[0].packet_number);
    try std.testing.expectEqual(@as(u64, 13), pair.client.sent.items[1].packet_number);
    try std.testing.expectEqual(@as(u64, 14), pair.client.sent.items[2].packet_number);
}

test "empty DATAGRAM stays empty through packet padding" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try pair.client.sendDatagram(&.{});
    var now: Instant = 0;
    var pkt_idx: usize = 0;
    var got: ?[]u8 = null;
    var rounds: usize = 0;
    while (rounds < 16) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
        got = pair.server.recvDatagram();
        if (got != null) break;
    }
    const payload = got orelse return error.UnexpectedState;
    defer std.testing.allocator.free(payload);
    try std.testing.expectEqual(@as(usize, 0), payload.len);
}

test "sender emits length-bearing empty DATAGRAM (0x31) on the wire frame" {
    // Byte-level on the *frame* the sender constructs (before AEAD). With
    // with_length=true, encode is type 0x31 + length 0 — not terminal 0x30.
    var buf: [8]u8 = undefined;
    const f: frame.Frame = .{ .datagram = .{ .data = &.{}, .with_length = true } };
    const enc = try f.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x31), enc[0]);
    try std.testing.expectEqual(@as(u8, 0x00), enc[1]);
}

test "processPayload decodes packed multi-frame payload once each" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    // Length-bearing DATAGRAM + PING + length-bearing DATAGRAM in one payload.
    var buf: [128]u8 = undefined;
    var index: usize = 0;
    const d1 = try (frame.Frame{ .datagram = .{ .data = "aa", .with_length = true } }).encode(buf[index..]);
    index += d1.len;
    const ping_f: frame.Frame = .ping;
    const p = try ping_f.encode(buf[index..]);
    index += p.len;
    const d2 = try (frame.Frame{ .datagram = .{ .data = "bb", .with_length = true } }).encode(buf[index..]);
    index += d2.len;
    try pair.client.processPayload(.data, 9001, buf[0..index], false);
    const a = pair.client.recvDatagram() orelse return error.UnexpectedState;
    defer std.testing.allocator.free(a);
    const b = pair.client.recvDatagram() orelse return error.UnexpectedState;
    defer std.testing.allocator.free(b);
    try std.testing.expectEqualSlices(u8, "aa", a);
    try std.testing.expectEqualSlices(u8, "bb", b);
    // No third datagram (padding / leftover not absorbed).
    try std.testing.expect(pair.client.recvDatagram() == null);
}

test "inbound DATAGRAM without local support protocol-closes" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.local_params.max_datagram_frame_size = null;

    var buf: [16]u8 = undefined;
    const enc = try (frame.Frame{ .datagram = .{ .data = "x", .with_length = true } }).encode(&buf);
    try pair.client.processPayload(.data, 9004, enc, false);

    const close_frame = pair.client.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_protocol_violation, close_frame.error_code);
    try std.testing.expect(pair.client.recvDatagram() == null);
}

test "inbound DATAGRAM over local frame limit protocol-closes" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.local_params.max_datagram_frame_size = 2;

    var buf: [16]u8 = undefined;
    const enc = try (frame.Frame{ .datagram = .{ .data = "x", .with_length = true } }).encode(&buf);
    try pair.client.processPayload(.data, 9005, enc, false);

    const close_frame = pair.client.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_protocol_violation, close_frame.error_code);
    try std.testing.expect(pair.client.recvDatagram() == null);
}

// ── Group A legality rows (noq parity): A7 role check, A8 per-space legality ─

test "A7: HANDSHAKE_DONE from a client protocol-closes the server" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();

    var buf: [8]u8 = undefined;
    const enc = try (frame.Frame{ .handshake_done = {} }).encode(&buf);
    try pair.server.processPayload(.data, 9101, enc, false);

    const close_frame = pair.server.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_protocol_violation, close_frame.error_code);
}

test "A7: HANDSHAKE_DONE from the server confirms the client handshake (control)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();

    var buf: [8]u8 = undefined;
    const enc = try (frame.Frame{ .handshake_done = {} }).encode(&buf);
    try pair.client.processPayload(.data, 9102, enc, false);

    try std.testing.expect(pair.client.close_frame == null);
    try std.testing.expect(pair.client.handshake_confirmed);
}

/// A8 gate driver: inject one encoded frame into a fresh server's
/// processPayload in `space` and require a PROTOCOL_VIOLATION close.
fn expectIllegalFrameInSpace(space: spaces.SpaceId, f: frame.Frame, pn: u64) !void {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    var buf: [64]u8 = undefined;
    const enc = try f.encode(&buf);
    try pair.server.processPayload(space, pn, enc, false);
    const close_frame = pair.server.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_protocol_violation, close_frame.error_code);
}

test "A8: 1-RTT-only frames protocol-close in Initial and Handshake spaces" {
    // RFC 9000 §12.5: STREAM is 1-RTT-only, in both early spaces.
    try expectIllegalFrameInSpace(.initial, .{ .stream = .{ .id = 0, .data = "x" } }, 9111);
    try expectIllegalFrameInSpace(.handshake, .{ .stream = .{ .id = 0, .data = "x" } }, 9112);
    // HANDSHAKE_DONE is 1-RTT-only (RFC 9000 §19.20).
    try expectIllegalFrameInSpace(.initial, .handshake_done, 9113);
    try expectIllegalFrameInSpace(.handshake, .handshake_done, 9114);
    // RFC 9221 DATAGRAM is 1-RTT-only.
    try expectIllegalFrameInSpace(.initial, .{ .datagram = .{ .data = "x", .with_length = true } }, 9115);
    // RFC 9368 ACK_FREQUENCY is 1-RTT-only.
    try expectIllegalFrameInSpace(.handshake, .{ .ack_frequency = .{
        .sequence_number = 0,
        .ack_eliciting_threshold = 1,
        .request_max_ack_delay = 1,
        .reordering_threshold = 1,
    } }, 9116);
    // iroh address-discovery extension frames are 1-RTT-only (noq is_qad_frame).
    try expectIllegalFrameInSpace(.initial, .{ .add_ipv4_address = .{
        .seq = 0,
        .ip = .{ 127, 0, 0, 1 },
        .port = 4433,
    } }, 9117);
}

test "A8: allow-list frames stay legal in every space (control)" {
    // PING is the side-effect-free member of the Initial/Handshake allow-list
    // (ACK needs sent-PN state, CRYPTO a live TLS session); it must NOT close
    // in any space. The same allow-list admits ACK/CRYPTO/CONNECTION_CLOSE.
    for ([_]spaces.SpaceId{ .initial, .handshake, .data }, 0..) |space, i| {
        var pair = try makePair(std.testing.allocator, null);
        defer pair.deinit();
        var buf: [8]u8 = undefined;
        const enc = try (frame.Frame{ .ping = {} }).encode(&buf);
        try pair.server.processPayload(space, 9121 + @as(u64, @intCast(i)), enc, false);
        try std.testing.expect(pair.server.close_frame == null);
    }
    // And a frame rejected in the early spaces above stays legal in Data.
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    var buf: [64]u8 = undefined;
    const enc = try (frame.Frame{ .ack_frequency = .{
        .sequence_number = 0,
        .ack_eliciting_threshold = 1,
        .request_max_ack_delay = 1,
        .reordering_threshold = 1,
    } }).encode(&buf);
    try pair.server.processPayload(.data, 9131, enc, false);
    try std.testing.expect(pair.server.close_frame == null);
}

test "processPayload malformed frame maps to FrameEncodeFailed and protocolClose" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try std.testing.expectError(error.FrameEncodeFailed, pair.client.processPayload(.data, 9002, &.{0xff}, false));
    const close_frame = pair.client.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_frame_encoding, close_frame.error_code);
}

test "crafted ACK with underflowing ranges protocol-closes FRAME_ENCODING_ERROR" {
    // noq read_ack_blocks (frame.rs:1760-1792): first_range > largest_acked is
    // IterErr::Malformed at decode; the Zig decode must reject before
    // ackContains' clamping ever sees it.
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    // largest=3, delay=0, count=0, first_range=4 → underflow.
    try std.testing.expectError(
        error.FrameEncodeFailed,
        pair.client.processPayload(.data, 9201, &.{ 0x02, 0x03, 0x00, 0x00, 0x04 }, false),
    );
    const close_frame = pair.client.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_frame_encoding, close_frame.error_code);

    // Additional-block gap underflow: largest=5, first_range=1, gap=4.
    var pair2 = try makePair(std.testing.allocator, null);
    defer pair2.deinit();
    try std.testing.expectError(
        error.FrameEncodeFailed,
        pair2.client.processPayload(.data, 9202, &.{ 0x02, 0x05, 0x00, 0x01, 0x01, 0x04, 0x00 }, false),
    );
    const close_frame2 = pair2.client.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_frame_encoding, close_frame2.error_code);
}

test "G3: empty packet payload is a PROTOCOL_VIOLATION (noq Iter::new)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try std.testing.expectError(error.EmptyPacket, pair.client.processPayload(.data, 9301, &.{}, false));
    const close_frame = pair.client.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_protocol_violation, close_frame.error_code);
}

test "G3: padding-only payload is NOT a violation (control)" {
    // noq Iter::new rejects only literal emptiness; PADDING is a frame the
    // iterator yields and skips (frame.rs:1503-1510, 1535-1536).
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.processPayload(.data, 9302, &.{ 0x00, 0x00, 0x00 }, false);
    try std.testing.expect(pair.client.close_frame == null);
}

test "G5: outgoing ACK Delay encodes (now - largest recv time) >> our exponent" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const si = @intFromEnum(spaces.SpaceId.data);
    var buf: [8]u8 = undefined;
    const enc = try (frame.Frame{ .ping = {} }).encode(&buf);
    // Deterministic cadence: no peer-requested ack-eliciting threshold.
    pair.server.peer_ack_eliciting_threshold = null;
    // noq populate_ack_frame (mod.rs:6576-6579): delay_micros >> exponent,
    // exponent = OUR advertised ack_delay_exponent (default 3).
    pair.server.now = 10_000_000_000;
    try pair.server.processPayload(.data, 9401, enc, false);
    pair.server.now += 24_000_000; // +24 ms
    var frames: [16]frame.Frame = undefined;
    var n: usize = 0;
    _ = pair.server.emitOwedAck(si, &frames, &n);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u64, 24_000 >> 3), frames[0].ack.ack_delay);

    // noq nuance (mod.rs:6576-6585): the delay is computed for EVERY space —
    // Initial/Handshake ACKs carry it too; only the DECODE side zeroes it
    // (mod.rs:3005-3007, mirrored by scaledAckDelayNs).
    const si_h = @intFromEnum(spaces.SpaceId.handshake);
    pair.server.now = 10_000_000_000;
    try pair.server.processPayload(.handshake, 9402, enc, false);
    pair.server.now += 8_000_000; // +8 ms
    n = 0;
    _ = pair.server.emitOwedAck(si_h, &frames, &n);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u64, 8_000 >> 3), frames[0].ack.ack_delay);
}

test "G5: OUR advertised ack_delay_exponent scales the field (control)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const si = @intFromEnum(spaces.SpaceId.data);
    var buf: [8]u8 = undefined;
    const enc = try (frame.Frame{ .ping = {} }).encode(&buf);
    // We advertised exponent 2: 24 ms → 24_000 µs >> 2.
    pair.server.local_params.ack_delay_exponent = 2;
    pair.server.peer_ack_eliciting_threshold = null;
    pair.server.now = 10_000_000_000;
    try pair.server.processPayload(.data, 9411, enc, false);
    pair.server.now += 24_000_000;
    var frames: [16]frame.Frame = undefined;
    var n: usize = 0;
    _ = pair.server.emitOwedAck(si, &frames, &n);
    try std.testing.expectEqual(@as(u64, 24_000 >> 2), frames[0].ack.ack_delay);
}

test "G11: ACK_FREQUENCY reordering_threshold is stored (noq set_ack_frequency_params)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    var buf: [64]u8 = undefined;
    // The default is 1 (spaces.rs:1130), so 0 and 7 both prove the field landed.
    for ([_]u64{ 0, 7 }, 0..) |reorder, i| {
        const af_enc = try (frame.Frame{ .ack_frequency = .{
            .sequence_number = @intCast(i + 1),
            .ack_eliciting_threshold = 100,
            .request_max_ack_delay = 40,
            .reordering_threshold = reorder,
        } }).encode(&buf);
        try pair.client.processPayload(.data, 9600 + @as(u64, @intCast(i)), af_enc, false);
        try std.testing.expectEqual(reorder, pair.client.peer_reordering_threshold);
    }
}

test "G11: largest ack-eliciting PN is tracked per space (is_out_of_order plumbing)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const si = @intFromEnum(spaces.SpaceId.data);
    var buf: [64]u8 = undefined;
    const ping_enc = try (frame.Frame{ .ping = {} }).encode(&buf);
    var pn = pair.client.dedup[si].largest.? + 1;
    // An ack-eliciting frame advances the tracker (noq spaces.rs:1191-1194).
    try pair.client.processPayload(.data, pn, ping_enc, false);
    try std.testing.expectEqual(pn, pair.client.largest_ack_eliciting_recv[si].?);
    // A non-ack-eliciting packet does NOT (noq spaces.rs:1184-1187: only the
    // ack-eliciting path updates largest_ack_eliciting_packet). PADDING-only
    // is not ack-eliciting (RFC 9000 §13.2.1).
    pn += 1;
    try pair.client.processPayload(.data, pn, &.{ 0x00, 0x00 }, false);
    try std.testing.expectEqual(pn - 1, pair.client.largest_ack_eliciting_recv[si].?);
}

test "length-bearing DATAGRAM does not absorb following padding as data" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    // 0x31 len=1 payload=0xaa then padding zeros — padding must not join the datagram.
    const wire = [_]u8{ 0x31, 0x01, 0xaa, 0x00, 0x00, 0x00 };
    try pair.client.processPayload(.data, 9003, &wire, false);
    const got = pair.client.recvDatagram() orelse return error.UnexpectedState;
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualSlices(u8, &.{0xaa}, got);
    try std.testing.expect(pair.client.recvDatagram() == null);
}

test "N-3 ACK_FREQUENCY applied on receive" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    var buf: [64]u8 = undefined;
    const af: frame.Frame = .{ .ack_frequency = .{
        .sequence_number = 9,
        .ack_eliciting_threshold = 5,
        .request_max_ack_delay = 40,
        .reordering_threshold = 2,
    } };
    const enc = try af.encode(&buf);
    try pair.client.processPayload(.data, 999, enc, false);
    try std.testing.expectEqual(@as(?u64, 5), pair.client.peer_ack_eliciting_threshold);
    try std.testing.expectEqual(@as(?u64, 40), pair.client.peer_ack_max_ack_delay);
}

test "N-3 CID queue emits NEW_CONNECTION_ID and peer accepts" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try pair.server.queueNewConnectionId();
    var now: Instant = 0;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    while (rounds < 16 and pair.client.remote_cid_len == 0) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expect(pair.client.remote_cid_len > 0);
    pair.client.retireRemoteConnectionId(pair.client.remote_cids[0].sequence);
    try std.testing.expect(pair.client.remote_cids[0].retired);
}

test "E12/E13: CID inventory auto-fills to the peer's advertised limit, in sequence" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // Both sides advertise 5 (= max_local_cid_slots = noq CidQueue::LEN), so
    // each inventory auto-fills to 5 as NEW_CONNECTION_ID frames trickle out.
    var now: Instant = pair.client.now;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    while (rounds < 24 and (pair.client.local_cid_len < max_local_cid_slots or pair.server.local_cid_len < max_local_cid_slots)) : (rounds += 1) {
        now += 1_000_000;
        pair.client.next_send_at = 0;
        pair.server.next_send_at = 0;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expectEqual(max_local_cid_slots, pair.client.local_cid_len);
    try std.testing.expectEqual(max_local_cid_slots, pair.server.local_cid_len);
    // Sequences 0..4 in order; seq 0 is the create-time CID (4 bytes in this
    // pair), the issued replacements are 8 bytes; none retired.
    for ([_]*Connection{ pair.client, pair.server }) |conn| {
        var seq: u64 = 0;
        while (seq < max_local_cid_slots) : (seq += 1) {
            const idx: usize = @intCast(seq);
            try std.testing.expectEqual(seq, conn.local_cids[idx].sequence);
            try std.testing.expectEqual(if (seq == 0) conn.local_cid.len else 8, conn.local_cids[idx].cid.len);
            try std.testing.expect(!conn.local_cids[idx].retired);
        }
        // The advertisement on the wire said exactly the slot count.
        try std.testing.expectEqual(@as(u64, max_local_cid_slots), conn.local_params.active_connection_id_limit);
    }
    // A manual queue is a no-op once the inventory is full.
    try pair.server.queueNewConnectionId();
    try std.testing.expect(!pair.server.pending_new_cid);

    // E12 adoption: each side's transmit destination follows the peer's
    // newest issued CID (noq CidQueue::active).
    const server_issued = pair.server.local_cids[max_local_cid_slots - 1].cid;
    const client_issued = pair.client.local_cids[max_local_cid_slots - 1].cid;
    try std.testing.expectEqualSlices(u8, server_issued.slice(), pair.client.remote_cid.slice());
    try std.testing.expectEqualSlices(u8, client_issued.slice(), pair.server.remote_cid.slice());
}

test "N-3 key update HKDF-derived keys decrypt on peer" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.client.mtu_probe_queue_len = 0;
    pair.client.probe_mtu = null;
    pair.client.probe_pn = null;
    pair.server.mtu_probe_queue_len = 0;
    pair.server.probe_mtu = null;
    pair.server.probe_pn = null;
    pair.server.peer_ack_eliciting_threshold = 1;
    const data_idx = @intFromEnum(spaces.SpaceId.data);
    const client_before = pair.client.write_keys[data_idx].?;
    const server_before = pair.server.crypto_1rtt.current.?;
    const update_count = pair.client.key_update_count;
    try pair.client.initiateKeyUpdate();
    try std.testing.expect(pair.client.write_key_phase);
    try std.testing.expectEqual(update_count + 1, pair.client.key_update_count);
    const client_after = pair.client.write_keys[data_idx].?;
    try std.testing.expect(!std.mem.eql(u8, &client_before.aead_key, &client_after.aead_key));
    try std.testing.expect(!std.mem.eql(u8, &client_before.iv, &client_after.iv));
    try std.testing.expectEqualSlices(u8, &client_before.hp_key, &client_after.hp_key);
    const s = try pair.client.openStream(.bidi);
    try pair.client.writeStream(s, "ku", true);
    var now: Instant = pair.client.now;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    while (rounds < 16 and !pair.server.streamRecvFin(s)) : (rounds += 1) {
        now += 1_000_000;
        pair.client.next_send_at = 0;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expectEqualStrings("ku", pair.server.streamRecvBytes(s));
    try std.testing.expect(pair.server.streamRecvFin(s));
    const server_after = pair.server.crypto_1rtt.current.?;
    try std.testing.expect(!std.mem.eql(u8, &server_before.aead_key, &server_after.aead_key));
    try std.testing.expect(!std.mem.eql(u8, &server_before.iv, &server_after.iv));
    try std.testing.expectEqualSlices(u8, &server_before.hp_key, &server_after.hp_key);
    try std.testing.expectEqualDeep(server_after, pair.server.read_keys[data_idx].?);
    try std.testing.expect(pair.server.crypto_1rtt.next == null);
}

test "key update rejects overlap then permits a confirmed retired successor" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const handshake_discard_at = pair.client.timers.handshake_key_discard_deadline orelse return error.UnexpectedState;
    pair.client.mtu_probe_queue_len = 0;
    pair.client.probe_mtu = null;
    pair.client.probe_pn = null;
    pair.server.mtu_probe_queue_len = 0;
    pair.server.probe_mtu = null;
    pair.server.probe_pn = null;
    pair.server.peer_ack_eliciting_threshold = 1;

    try pair.client.initiateKeyUpdate();
    try std.testing.expectError(error.UnexpectedState, pair.client.initiateKeyUpdate());
    const stream_id = try pair.client.openStream(.bidi);
    try pair.client.writeStream(stream_id, "first-update", true);
    var now = pair.client.now;
    var packet_index: usize = 0;
    var rounds: usize = 0;
    while (rounds < 32 and pair.client.write_update_pending) : (rounds += 1) {
        now += 1_000_000;
        pair.client.next_send_at = 0;
        pair.server.next_send_at = 0;
        try pumpOnce(&pair, now, &packet_index, null);
    }
    try std.testing.expect(!pair.client.write_update_pending);
    try std.testing.expect(pair.client.crypto_1rtt.prev != null);
    try std.testing.expectError(error.UnexpectedState, pair.client.initiateKeyUpdate());

    const previous_discard_at = pair.client.timers.previous_key_discard_deadline orelse return error.UnexpectedState;
    try std.testing.expectEqual(handshake_discard_at, pair.client.timers.handshake_key_discard_deadline.?);
    try std.testing.expect(previous_discard_at > handshake_discard_at);

    pair.client.handleTimeout(handshake_discard_at + 1);
    try std.testing.expect(pair.client.write_keys[@intFromEnum(spaces.SpaceId.initial)] == null);
    try std.testing.expect(pair.client.read_keys[@intFromEnum(spaces.SpaceId.initial)] == null);
    try std.testing.expect(pair.client.write_keys[@intFromEnum(spaces.SpaceId.handshake)] == null);
    try std.testing.expect(pair.client.read_keys[@intFromEnum(spaces.SpaceId.handshake)] == null);
    try std.testing.expect(pair.client.crypto_1rtt.prev != null);
    try std.testing.expectEqual(previous_discard_at, pair.client.timers.previous_key_discard_deadline.?);

    pair.client.handleTimeout(previous_discard_at + 1);
    try std.testing.expect(pair.client.crypto_1rtt.prev == null);
    try pair.client.initiateKeyUpdate();
    try std.testing.expect(pair.client.write_update_pending);
}

test "RFC 9001 §4.9 key discards fire on handshake progress events, not the timer" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();

    const initial_si = @intFromEnum(spaces.SpaceId.initial);
    const hs_si = @intFromEnum(spaces.SpaceId.handshake);

    // Drive the handshake one pump at a time and pin the RFC events directly:
    // the client must have discarded Initial keys by the time its FIRST
    // Handshake packet is on the wire; the server by the time its FIRST
    // Handshake packet has been received. Both observations are race-free
    // (PN counters only move when the event has definitely happened).
    var client_send_discard_proven = false;
    var server_recv_discard_proven = false;
    var now: Instant = 0;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    while (rounds < 32 and !(pair.client.state == .established and pair.server.state == .established)) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
        if (!client_send_discard_proven and pair.client.spaces_state.getConst(.handshake).next_pn > 0) {
            try std.testing.expect(pair.client.write_keys[initial_si] == null);
            try std.testing.expect(pair.client.read_keys[initial_si] == null);
            client_send_discard_proven = true;
        }
        if (!server_recv_discard_proven and pair.server.spaces_state.getConst(.handshake).largest_received != null) {
            try std.testing.expect(pair.server.write_keys[initial_si] == null);
            try std.testing.expect(pair.server.read_keys[initial_si] == null);
            server_recv_discard_proven = true;
        }
    }
    try std.testing.expect(pair.client.state == .established);
    try std.testing.expect(pair.server.state == .established);
    try std.testing.expect(client_send_discard_proven);
    try std.testing.expect(server_recv_discard_proven);

    // Server Handshake keys are discarded at handshake confirmation.
    try std.testing.expect(pair.server.write_keys[hs_si] == null);
    try std.testing.expect(pair.server.read_keys[hs_si] == null);

    // The 3×PTO backstop timer is still armed and NOT yet due — proof the
    // discards above were event-driven (the timer cannot have produced them).
    const deadline = pair.client.timers.handshake_key_discard_deadline orelse return error.UnexpectedState;
    try std.testing.expect(now < deadline);

    // Client Handshake keys drop on HANDSHAKE_DONE receipt.
    rounds = 0;
    while (rounds < 32 and !pair.client.handshake_done_received) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expect(pair.client.handshake_done_received);
    try std.testing.expect(pair.client.write_keys[hs_si] == null);
    try std.testing.expect(pair.client.read_keys[hs_si] == null);

    // Wire-observable leg: a late Initial replayed to the server under the
    // ORIGINAL initial keys is not processed — the keys are gone.
    const replay_baseline = pair.server.spaces_state.getConst(.initial).largest_received;
    const replay_keys = initial_keys.clientKeys(pair.server.initial_dcid.slice());
    var buf: [1500]u8 = undefined;
    const frames = [_]frame.Frame{.ping};
    const built = try packet_builder.buildLongHeader(&buf, .initial, 1, pair.server.local_cid, pair.client.local_cid, "", 99, &frames, replay_keys, 1200);
    try pair.server.handleDatagram(now + 1_000_000, built.bytes);
    try std.testing.expectEqual(replay_baseline, pair.server.spaces_state.getConst(.initial).largest_received);

    // The connection is still healthy: a stream echo completes after discard.
    const sid = try pair.client.openStream(.bidi);
    try pair.client.writeStream(sid, "post-discard", true);
    rounds = 0;
    while (rounds < 16 and !pair.server.streamRecvFin(sid)) : (rounds += 1) {
        now += 1_000_000;
        pair.client.next_send_at = 0;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expectEqualStrings("post-discard", pair.server.streamRecvBytes(sid));
}

test "a reordered/replayed key update (PN not greater than last received) closes KEY_UPDATE_ERROR" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.client.mtu_probe_queue_len = 0;
    pair.client.probe_mtu = null;
    pair.client.probe_pn = null;
    pair.server.mtu_probe_queue_len = 0;
    pair.server.probe_mtu = null;
    pair.server.probe_pn = null;

    // Drive one ordinary exchange so the server has data-space receive history.
    const sid = try pair.client.openStream(.bidi);
    try pair.client.writeStream(sid, "before-forge", true);
    var now: Instant = pair.client.now;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    while (rounds < 16 and !pair.server.streamRecvFin(sid)) : (rounds += 1) {
        now += 1_000_000;
        pair.client.next_send_at = 0;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    const last_rx = pair.server.spaces_state.getConst(.data).largest_received orelse return error.UnexpectedState;

    // Forge a key update the server will accept cryptographically (derived
    // exactly as its own next read keys) but whose PN does NOT exceed the last
    // received one. RFC 9001 §6: invalid update → KEY_UPDATE_ERROR close.
    const read_secret = pair.server.app_read_secret[0..pair.server.app_read_secret_len];
    const next_secret = packet_crypto.nextTrafficSecret(read_secret);
    const forged_keys = packet_crypto.keysFromKeyUpdate(&next_secret, pair.server.crypto_1rtt.current.?.hp_key);
    var buf: [1500]u8 = undefined;
    const frames = [_]frame.Frame{.ping};
    const forged_phase = !pair.server.crypto_1rtt.key_phase;
    const built = try packet_builder.buildOneRtt(&buf, pair.server.local_cid, last_rx, forged_phase, &frames, forged_keys, 0);

    try std.testing.expectError(error.KeyUpdateOrderViolation, pair.server.handleDatagram(now + 1_000_000, built.bytes));
    try std.testing.expect(pair.server.state == .closed);
    try std.testing.expectEqual(err_key_update, pair.server.close_frame.?.error_code);

    // The client side of the same connection is unaffected; and a LEGITIMATE
    // update still commits on a fresh pair (ordering check must not fire).
    var pair2 = try makePair(std.testing.allocator, null);
    defer pair2.deinit();
    try establishPair(&pair2);
    pair2.client.mtu_probe_queue_len = 0;
    pair2.client.probe_mtu = null;
    pair2.client.probe_pn = null;
    pair2.server.mtu_probe_queue_len = 0;
    pair2.server.probe_mtu = null;
    pair2.server.probe_pn = null;
    try pair2.client.initiateKeyUpdate();
    const s2 = try pair2.client.openStream(.bidi);
    try pair2.client.writeStream(s2, "legit-update", true);
    now = pair2.client.now;
    pkt_idx = 0;
    rounds = 0;
    while (rounds < 16 and !pair2.server.streamRecvFin(s2)) : (rounds += 1) {
        now += 1_000_000;
        pair2.client.next_send_at = 0;
        pair2.server.next_send_at = 0;
        try pumpOnce(&pair2, now, &pkt_idx, null);
    }
    try std.testing.expectEqualStrings("legit-update", pair2.server.streamRecvBytes(s2));
    try std.testing.expect(pair2.server.state == .established);
}

test "TLS exporter at the Connection surface — both peers derive identical keying material" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);

    var client_out: [64]u8 = undefined;
    var server_out: [64]u8 = undefined;
    try pair.client.exportKeyingMaterial("noq-c14-test", "ctx", &client_out);
    try pair.server.exportKeyingMaterial("noq-c14-test", "ctx", &server_out);
    // RFC 5705: same label+context on both peers of the same session yields
    // identical pseudorandom bytes.
    try std.testing.expectEqualSlices(u8, &client_out, &server_out);
    // Not the all-zero failure mode of an unwritten buffer.
    try std.testing.expect(!std.mem.allEqual(u8, &client_out, 0));

    // The label binds the output: a different label MUST derive different
    // bytes (a passthrough that drops the label goes RED here).
    var other_out: [64]u8 = undefined;
    try pair.client.exportKeyingMaterial("noq-c14-other", "ctx", &other_out);
    try std.testing.expect(!std.mem.eql(u8, &client_out, &other_out));

    // Pre-establishment the surface is closed.
    var early = try makePair(std.testing.allocator, null);
    defer early.deinit();
    var buf: [16]u8 = undefined;
    try std.testing.expectError(error.IncompleteHandshake, early.client.exportKeyingMaterial("l", "c", &buf));
}

test "handshake_data event fires exactly once, mid-handshake, with ALPN readable (noq HandshakeDataReady contract)" {
    const backend: crypto.Backend = if (crypto.picotls_enabled) .picotls else .zigtls;
    const client_key = key.SecretKey.fromBytes(.{0x31} ** 32);
    const server_key = key.SecretKey.fromBytes(.{0x32} ** 32);
    const client_cid = try packet.ConnectionId.init(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });
    const server_cid = try packet.ConnectionId.init(&.{ 0x51, 0x52, 0x53, 0x54 });
    const initial_dcid = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const server_name = tls_name.serverName(server_key.public());

    const client = try Connection.create(std.testing.allocator, .{
        .backend = backend,
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .server_name = &server_name,
        .alpn = "noq-c22-alpn",
    }, client_cid, initial_dcid, initial_dcid, testCsprngSeed(0xC22C), .{});
    defer client.destroy();
    const server = try Connection.create(std.testing.allocator, .{
        .backend = backend,
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = client_key.public(),
        .require_client_authentication = true,
        .alpn = "noq-c22-alpn",
    }, server_cid, client_cid, initial_dcid, testCsprngSeed(0xC225), .{});
    defer server.destroy();

    try client.startClient();
    var client_event_count: usize = 0;
    var client_alpn_at_event: ?[]const u8 = null;
    var server_event_count: usize = 0;
    var server_alpn_at_event: ?[]const u8 = null;
    var connected_before_event = false;
    var now: Instant = 0;
    var rounds: usize = 0;
    while (rounds < 64 and !(client.state == .established and server.state == .established)) : (rounds += 1) {
        now += 1_000_000;
        client.handleTimeout(now);
        server.handleTimeout(now);
        while (try client.pollTransmit(now)) |tx| try server.handleDatagram(now, tx.bytes);
        while (try server.pollTransmit(now)) |tx| try client.handleDatagram(now, tx.bytes);
        // Drain events by hand so the ordering is observable (pumpOnce would
        // swallow them).
        while (client.poll()) |ev| {
            switch (ev) {
                .handshake_data => {
                    client_event_count += 1;
                    client_alpn_at_event = client.negotiatedProtocol();
                },
                .connected => {
                    if (client_event_count == 0) connected_before_event = true;
                },
                else => {},
            }
        }
        while (server.poll()) |ev| {
            switch (ev) {
                .handshake_data => {
                    server_event_count += 1;
                    // The server learns ALPN+SNI from the ClientHello — the
                    // event must land strictly mid-handshake here.
                    try std.testing.expect(server.state == .handshake);
                    server_alpn_at_event = server.negotiatedProtocol();
                },
                else => {},
            }
        }
    }
    try std.testing.expect(client.state == .established);
    try std.testing.expect(server.state == .established);
    try std.testing.expectEqual(@as(usize, 1), client_event_count);
    try std.testing.expectEqual(@as(usize, 1), server_event_count);
    try std.testing.expect(!connected_before_event);
    try std.testing.expectEqualStrings("noq-c22-alpn", client_alpn_at_event.?);
    try std.testing.expectEqualStrings("noq-c22-alpn", server_alpn_at_event.?);
}

test "peer-initiated key update advances write keys before response" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.client.mtu = min_mtu;
    pair.client.mtu_search = null;
    pair.client.mtu_probe_queue_len = 0;
    pair.client.probe_mtu = null;
    pair.client.probe_pn = null;
    pair.server.mtu = min_mtu;
    pair.server.mtu_search = null;
    pair.server.mtu_probe_queue_len = 0;
    pair.server.probe_mtu = null;
    pair.server.probe_pn = null;
    pair.client.peer_ack_eliciting_threshold = 1;

    try pair.server.initiateKeyUpdate();
    const stream_id = try pair.server.openStream(.bidi);
    try pair.server.writeStream(stream_id, "remote-update", true);
    const before = pair.client.write_keys[@intFromEnum(spaces.SpaceId.data)].?;
    pair.server.next_send_at = 0;
    const now = pair.server.now + 1;
    const tx = (try pair.server.pollTransmit(now)) orelse return error.UnexpectedState;
    try pair.client.handleDatagram(now, tx.bytes);

    try std.testing.expect(pair.client.write_key_phase);
    try std.testing.expect(pair.client.remote_update_unacked);
    const after = pair.client.write_keys[@intFromEnum(spaces.SpaceId.data)].?;
    try std.testing.expect(!std.mem.eql(u8, &before.aead_key, &after.aead_key));
    pair.client.next_send_at = 0;
    _ = (try pair.client.pollTransmit(now + 1)) orelse return error.UnexpectedState;
    try std.testing.expect(!pair.client.remote_update_unacked);
}

test "A16 auto key update fires at key-phase budget exhaustion and peer decrypts across the roll" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.client.mtu_probe_queue_len = 0;
    pair.client.probe_mtu = null;
    pair.client.probe_pn = null;
    pair.server.mtu_probe_queue_len = 0;
    pair.server.probe_mtu = null;
    pair.server.probe_pn = null;
    pair.server.peer_ack_eliciting_threshold = 1;

    // noq packet_crypto.rs:136: the first key phase ends after 10..1000
    // packets so peers that cannot handle key updates fail fast.
    try std.testing.expect(pair.client.key_phase_size >= 10 and pair.client.key_phase_size < 1000);

    const data_idx = @intFromEnum(spaces.SpaceId.data);
    // Determinism: pin the server away from its own auto-update for the rest
    // of the test (its random first-phase budget may have fired during the
    // handshake) and drop any fully-confirmed update leftover so the client
    // may initiate — noq force_key_update is likewise a no-op while
    // prev_crypto exists.
    pair.server.key_phase_size = packet_crypto.confidentiality_limit;
    pair.server.sent_with_keys[data_idx] = 0;
    pair.client.crypto_1rtt.prev = null;
    pair.client.write_update_pending = false;
    pair.server.crypto_1rtt.prev = null;
    pair.server.write_update_pending = false;

    const phase_before = pair.client.write_key_phase;
    const server_phase_before = pair.server.crypto_1rtt.key_phase;
    const updates_before = pair.client.key_update_count;
    const keys_before = pair.client.write_keys[data_idx].?;
    // Drive the send counter to one packet below budget exhaustion; the next
    // packets cross the boundary and must roll the write phase automatically
    // (noq PacketBuilder::new → force_key_update, packet_builder.rs:71-76).
    pair.client.sent_with_keys[data_idx] = pair.client.key_phase_size -| 1;

    const sid = try pair.client.openStream(.bidi);
    var now: Instant = pair.client.now;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    var rolled = false;
    while (rounds < 32 and !rolled) : (rounds += 1) {
        try pair.client.writeStream(sid, "x", false);
        now += 1_000_000;
        pair.client.next_send_at = 0;
        try pumpOnce(&pair, now, &pkt_idx, null);
        rolled = pair.client.write_key_phase != phase_before;
    }
    try std.testing.expect(rolled);
    try std.testing.expectEqual(updates_before + 1, pair.client.key_update_count);
    const keys_after = pair.client.write_keys[data_idx].?;
    try std.testing.expect(!std.mem.eql(u8, &keys_before.aead_key, &keys_after.aead_key));
    // The new phase gets the full confidentiality budget minus the margin and
    // the counter restarts from zero (noq update_keys, packet_crypto.rs:407-409).
    try std.testing.expectEqual(packet_crypto.confidentiality_limit - packet_crypto.key_update_margin, pair.client.key_phase_size);
    try std.testing.expect(pair.client.sent_with_keys[data_idx] < 100);

    // The peer followed the roll and still decrypts: its read phase flipped
    // and its current read keys are the client's new write keys.
    try std.testing.expect(pair.server.crypto_1rtt.key_phase != server_phase_before);
    try std.testing.expectEqualSlices(u8, &keys_after.aead_key, &pair.server.crypto_1rtt.current.?.aead_key);
    try pair.client.writeStream(sid, "", true);
    rounds = 0;
    while (rounds < 32 and !pair.server.streamRecvFin(sid)) : (rounds += 1) {
        now += 1_000_000;
        pair.client.next_send_at = 0;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expect(pair.server.streamRecvFin(sid));
}

test "A16 initial space at the confidentiality limit refuses to send (kill, no close frame)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();
    pair.client.sent_with_keys[@intFromEnum(spaces.SpaceId.initial)] = packet_crypto.confidentiality_limit;
    // noq packet_builder.rs:79-82: budget 0 on a fixed-key space kills the
    // connection locally — no CONNECTION_CLOSE would itself exceed the limit.
    const tx = try pair.client.pollTransmit(1_000_000);
    try std.testing.expect(tx == null);
    try std.testing.expect(pair.client.state == .draining);
    try std.testing.expect(pair.client.close_frame == null);
    const ev = pair.client.poll() orelse return error.UnexpectedState;
    try std.testing.expect(std.meta.activeTag(ev) == .connection_lost);
    try std.testing.expectEqualStrings("aead-limit-reached", ev.connection_lost.reason);
}

test "A16 last initial packet before the limit closes gracefully with AEAD_LIMIT_REACHED" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();
    pair.client.sent_with_keys[@intFromEnum(spaces.SpaceId.initial)] = packet_crypto.confidentiality_limit - 1;
    // noq packet_builder.rs:83-86: the final permitted packet is still sent,
    // alongside a graceful AEAD_LIMIT_REACHED close.
    const tx = try pair.client.pollTransmit(1_000_000);
    try std.testing.expect(tx != null);
    try std.testing.expectEqual(packet_crypto.confidentiality_limit, pair.client.sent_with_keys[@intFromEnum(spaces.SpaceId.initial)]);
    try std.testing.expect(pair.client.state == .closed);
    const cc = pair.client.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_aead_limit_reached, cc.error_code);
}

test "A16 forged 1-RTT packets past the integrity limit close AEAD_LIMIT_REACHED" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const server = pair.server;
    const data_idx = @intFromEnum(spaces.SpaceId.data);
    const read_keys = server.read_keys[data_idx].?;
    const failures_before = server.authentication_failures;

    // A keyless forgery: valid header-protection envelope, corrupted AEAD tag.
    const poison_pn: u64 = (server.spaces_state.getConst(.data).largest_received orelse 0) + 100;
    var buf: [1500]u8 = undefined;
    const frames = [_]frame.Frame{.ping};
    const built = try packet_builder.buildOneRtt(&buf, server.local_cid, poison_pn, server.crypto_1rtt.key_phase, &frames, read_keys, 0);
    built.bytes[built.bytes.len - 1] ^= 0xff;

    // Below the limit (noq mod.rs:4271-4279): dropped per-packet, counted, no
    // close — the connection keeps working.
    _ = server.handleDatagram(server.now, built.bytes) catch {};
    try std.testing.expectEqual(failures_before + 1, server.authentication_failures);
    try std.testing.expect(server.state == .established);
    try std.testing.expect(server.close_frame == null);

    // Past the limit the connection is abandoned with AEAD_LIMIT_REACHED.
    server.authentication_failures = packet_crypto.integrity_limit;
    _ = server.handleDatagram(server.now, built.bytes) catch {};
    try std.testing.expectEqual(packet_crypto.integrity_limit + 1, server.authentication_failures);
    try std.testing.expect(server.state == .closed);
    const cc = server.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_aead_limit_reached, cc.error_code);
}

test "N-3 ACK_FREQUENCY threshold delays ACK until third eliciting packet" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // G4 scenario-premise correction (was threshold 3 + PNs 100-102 out of
    // the blue). noq fires when the count EXCEEDS the threshold
    // (packet_received, spaces.rs:1199-1201: `count > threshold` — config doc
    // "more than this number", transport.rs:721-725), so "ACK on the third"
    // is threshold TWO under noq semantics; threshold 3 would defer to the
    // fourth. And PNs far above the establishment watermark are out-of-order
    // traffic under noq's is_out_of_order (immediate ACK) — the tracker is
    // pinned so the injected run is genuinely in-order, which is what this
    // test claims to exercise.
    const si = @intFromEnum(spaces.SpaceId.data);
    pair.server.peer_ack_eliciting_threshold = 2;
    pair.server.peer_ack_eliciting_pending = 0;
    pair.server.largest_ack_eliciting_recv[si] = 99;
    var buf: [64]u8 = undefined;
    const ping: frame.Frame = .ping;
    const enc = try ping.encode(&buf);
    try pair.server.processPayload(.data, 100, enc, false);
    try std.testing.expect(!pair.server.needs_ack[@intFromEnum(spaces.SpaceId.data)]);
    try pair.server.processPayload(.data, 101, enc, false);
    try std.testing.expect(!pair.server.needs_ack[@intFromEnum(spaces.SpaceId.data)]);
    try pair.server.processPayload(.data, 102, enc, false);
    try std.testing.expect(pair.server.needs_ack[@intFromEnum(spaces.SpaceId.data)]);
}

test "N-3 stateless reset token transport parameter roundtrip" {
    var token: [packet.stateless_reset_token_len]u8 = undefined;
    @memset(&token, 0xAB);
    var buf: [128]u8 = undefined;
    const encoded = try (transport_parameters.TransportParameters{
        .initial_max_data = 4096,
        .stateless_reset_token = token,
    }).encode(&buf);
    const decoded = try transport_parameters.decode(encoded);
    try std.testing.expect(decoded.stateless_reset_token != null);
    try std.testing.expectEqualSlices(u8, &token, &decoded.stateless_reset_token.?);
}

test "N-3 connection advertises nonzero stateless reset token" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    // RFC 9000 §18.2: clients MUST NOT advertise the TP; servers MUST.
    try std.testing.expect(pair.client.local_params.stateless_reset_token == null);
    try std.testing.expect(pair.server.local_params.stateless_reset_token != null);
    // Both sides still own a local reset token for NEW_CONNECTION_ID / inbound-reset.
    var nonzero_client = false;
    for (pair.client.stateless_reset_token) |b| {
        if (b != 0) nonzero_client = true;
    }
    try std.testing.expect(nonzero_client);
    var nonzero_server = false;
    for (pair.server.stateless_reset_token) |b| {
        if (b != 0) nonzero_server = true;
    }
    try std.testing.expect(nonzero_server);
    try std.testing.expectEqualSlices(u8, &pair.server.stateless_reset_token, &pair.server.local_params.stateless_reset_token.?);
    try std.testing.expectEqual(@as(u64, max_datagram), pair.client.local_params.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, max_datagram), pair.server.local_params.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, default_max_datagram_frame_size), pair.client.local_params.max_datagram_frame_size.?);
    try std.testing.expectEqual(@as(u64, default_max_datagram_frame_size), pair.server.local_params.max_datagram_frame_size.?);
}

test "N-3 mtu probe two-step raise 1200 to 1400" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // Handshake may already have run the auto-scheduled probes — reset so this
    // test owns the two-step raise path.
    pair.client.mtu = 1200;
    pair.client.mtu_probes_scheduled = false;
    pair.client.mtu_probe_queue_len = 0;
    pair.client.probe_mtu = null;
    pair.client.probe_pn = null;
    try std.testing.expectEqual(@as(u16, 1200), pair.client.mtu);
    pair.client.scheduleMtuProbes();
    pair.client.maybeStartMtuProbe();
    const first_probe = pair.client.probe_mtu orelse return error.UnexpectedState;
    pair.client.probe_pn = 10;
    pair.client.spaces_state.get(.data).next_pn = 12; // synthetic probe PNs are "sent"
    pair.client.onAck(.data, .{ .largest_acked = 10, .ack_delay = 0, .first_range = 0 });
    try std.testing.expectEqual(first_probe, pair.client.mtu);
    pair.client.maybeStartMtuProbe();
    const second_probe = pair.client.probe_mtu orelse return error.UnexpectedState;
    try std.testing.expect(second_probe > first_probe);
    pair.client.probe_pn = 11;
    pair.client.onAck(.data, .{ .largest_acked = 11, .ack_delay = 0, .first_range = 0 });
    try std.testing.expectEqual(second_probe, pair.client.mtu);
}

// ── DPLPMTUD binary search ──────────────────────────────────────────────────

test "MtuSearch halves the interval and converges" {
    var search: MtuSearch = .init(1200, 1452);
    // First probe is the midpoint of (1200, 1452].
    const first = search.nextProbe(true) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 1326), first);

    // Success raises the floor; the next probe is above it.
    const second = search.nextProbe(true) orelse return error.TestUnexpectedResult;
    try std.testing.expect(second > first);
    try std.testing.expectEqual(@as(u16, 1326), search.lower_bound);

    // The search must terminate rather than probe forever.
    var guard: usize = 0;
    while (search.nextProbe(true)) |_| {
        guard += 1;
        try std.testing.expect(guard < 32);
    }
}

test "MtuSearch lowers the ceiling below a size that failed" {
    var search: MtuSearch = .init(1200, 1452);
    const first = search.nextProbe(true) orelse return error.TestUnexpectedResult;
    // A failure means `first` is unreachable: the ceiling drops below it.
    const second = search.nextProbe(false) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(first - 1, search.upper_bound);
    try std.testing.expect(second < first);
    try std.testing.expect(second >= search.lower_bound);
}

test "MtuSearch probes the upper bound rather than converging just below it" {
    // A search whose midpoint is within `mtu_minimum_change` of the last probe
    // would otherwise stop and never reach a reachable upper bound.
    var search: MtuSearch = .init(1400, 1452);
    var last: u16 = 1400;
    var reached_upper = false;
    var guard: usize = 0;
    while (search.nextProbe(true)) |probe| {
        last = probe;
        if (probe == 1452) reached_upper = true;
        guard += 1;
        try std.testing.expect(guard < 32);
    }
    try std.testing.expect(reached_upper);
    try std.testing.expectEqual(@as(u16, 1452), last);
}

test "MtuSearch on a degenerate interval yields nothing" {
    var search: MtuSearch = .init(1200, 1200);
    try std.testing.expect(search.nextProbe(true) == null);
    // An inverted interval must be normalized, not wrap.
    const inverted: MtuSearch = .init(1452, 1200);
    try std.testing.expect(inverted.lower_bound <= inverted.upper_bound);
}

// ── MTU black-hole detector ─────────────────────────────────────────────────
//
// The detector is judged on BEHAVIOR (does a persistent big-packet-loss path
// end up at min_mtu?), not on resemblance to upstream's field names. These
// tests assert the heuristic's decisions, which is the part a peer can observe
// the consequences of.

test "black hole: enough suspicious bursts of large packets trips detection" {
    var d: MtuBlackHole = .{};
    // Each burst is a run of consecutive PNs, all larger than min_mtu, with a
    // PN gap between bursts so they group separately.
    var pn: u64 = 0;
    for (0..mtu_black_hole_threshold + 1) |_| {
        d.onLost(pn, 1400);
        d.onLost(pn + 1, 1400);
        pn += 10; // gap → new burst
    }
    try std.testing.expect(d.detected());
    // Detection resets, so one black hole is reported once.
    try std.testing.expect(!d.detected());
}

test "black hole: a burst containing a small packet is not suspicious" {
    var d: MtuBlackHole = .{};
    var pn: u64 = 0;
    for (0..mtu_black_hole_threshold + 2) |_| {
        d.onLost(pn, 1400);
        // A packet at or below min_mtu was lost too, so the burst is explained
        // by ordinary congestion, not by a shrunken path.
        d.onLost(pn + 1, min_mtu);
        pn += 10;
    }
    try std.testing.expect(!d.detected());
}

test "black hole: consecutive packet numbers group into ONE burst" {
    var d: MtuBlackHole = .{};
    // A single long run of consecutive losses is one burst, not many — so it
    // cannot by itself cross the threshold.
    for (0..(mtu_black_hole_threshold + 2) * 4) |i| d.onLost(@intCast(i), 1400);
    try std.testing.expect(!d.detected());
}

test "black hole: acking a large packet de-suspicions smaller bursts" {
    var d: MtuBlackHole = .{};
    var pn: u64 = 0;
    for (0..mtu_black_hole_threshold + 1) |_| {
        d.onLost(pn, 1300);
        pn += 10;
    }
    // A 1350-byte delivery proves the path still carries more than 1300, so
    // every 1300-byte burst is retroactively exonerated.
    d.onAcked(1350);
    try std.testing.expect(!d.detected());
}

test "black hole: acking a SMALLER packet does not exonerate larger bursts" {
    var d: MtuBlackHole = .{};
    var pn: u64 = 0;
    for (0..mtu_black_hole_threshold + 1) |_| {
        d.onLost(pn, 1400);
        pn += 10;
    }
    // 1250 < 1400, so it says nothing about whether 1400 still fits.
    d.onAcked(1250);
    try std.testing.expect(d.detected());
}

test "black hole: a probe ACK clears all accumulated suspicion" {
    var d: MtuBlackHole = .{};
    var pn: u64 = 0;
    for (0..mtu_black_hole_threshold + 1) |_| {
        d.onLost(pn, 1400);
        pn += 10;
    }
    d.onProbeAcked(1452);
    try std.testing.expect(!d.detected());
}

test "black hole: the suspicious ring is bounded and keeps the worst bursts" {
    var d: MtuBlackHole = .{};
    var pn: u64 = 0;
    // Far more bursts than the ring holds — memory must stay fixed.
    for (0..64) |i| {
        d.onLost(pn, @intCast(1250 + i));
        pn += 10;
    }
    try std.testing.expect(d.suspicious_len <= d.suspicious.len);
}

test "black hole drives the connection back to min_mtu and parks PMTUD" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);

    const c = pair.client;
    c.mtu = 1400;
    c.mtu_search = .init(1400, 1452);
    c.mtu_search_resume_at = null;
    c.stats_mtu_black_holes = 0;
    c.mtu_black_hole = .{};

    // Feed the detector a persistent big-packet-loss pattern, then let the
    // connection act on the verdict.
    var pn: u64 = 0;
    for (0..mtu_black_hole_threshold + 1) |_| {
        c.mtu_black_hole.onLost(pn, 1400);
        c.mtu_black_hole.onLost(pn + 1, 1400);
        pn += 10;
    }
    try std.testing.expect(c.mtu_black_hole.detected());
    c.onMtuBlackHole();

    // THE wire-observable outcome: we stop sending packets the path swallows.
    try std.testing.expectEqual(min_mtu, c.mtu);
    try std.testing.expectEqual(@as(u64, 1), c.mtuBlackHolesForTest());
    // PMTUD is parked, not dead: probing resumes after the cooldown.
    try std.testing.expect(c.mtu_search_resume_at != null);
    try std.testing.expect(!c.mtuSearchActiveForTest());
    try std.testing.expectEqual(@as(usize, 0), c.mtu_probe_queue_len);

    const resume_at = c.mtu_search_resume_at.?;
    // Before the cooldown elapses, no probe starts.
    c.now = resume_at - 1;
    c.maybeStartMtuProbe();
    try std.testing.expect(c.probe_mtu == null);
    try std.testing.expect(!c.mtuSearchActiveForTest());
    // After it, the search re-arms on its own — PMTUD was parked, not killed.
    c.now = resume_at;
    c.maybeStartMtuProbe();
    try std.testing.expect(c.mtuSearchActiveForTest());
    try std.testing.expect(c.mtu_search_resume_at == null);
}

test "MTU probe losses are excluded from black-hole evidence" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const c = pair.client;
    c.mtu = 1200;
    c.mtu_black_hole = .{};

    // A probe is deliberately oversized; losing it is the EXPECTED outcome of a
    // successful search, so it must not count as black-hole evidence — or every
    // normal search would end in a spurious fallback.
    var i: u64 = 0;
    while (i < (mtu_black_hole_threshold + 2) * 2) : (i += 1) {
        c.probe_pn = i;
        c.probe_mtu = 1452;
        c.onPacketLost(.{
            .path_generation = 0,
            .time_sent = 0,
            .size = 1452,
            .ack_eliciting = true,
            .packet_number = i,
            .space = .data,
        });
    }
    try std.testing.expect(!c.mtu_black_hole.detected());
    try std.testing.expectEqual(@as(u64, 0), c.mtuBlackHolesForTest());
}

test "PMTUD binary search raises the MTU across successive probe ACKs" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const c = pair.client;
    c.mtu = 1200;
    c.mtu_probes_scheduled = false;
    c.mtu_probe_queue_len = 0;
    c.probe_mtu = null;
    c.probe_pn = null;
    c.mtu_search = null;
    c.scheduleMtuProbes();

    var pn: u64 = 100;
    var raises: usize = 0;
    var guard: usize = 0;
    while (guard < 32) : (guard += 1) {
        c.maybeStartMtuProbe();
        const target = c.probe_mtu orelse break;
        c.probe_pn = pn;
        c.spaces_state.get(.data).next_pn = pn + 1;
        const before = c.mtu;
        c.onAck(.data, .{ .largest_acked = pn, .ack_delay = 0, .first_range = 0 });
        try std.testing.expectEqual(target, c.mtu);
        if (c.mtu > before) raises += 1;
        pn += 1;
    }
    // Several successive probes were acknowledged, each raising the path MTU —
    // that is the binary search working, not a single fixed two-step raise.
    try std.testing.expect(raises >= 2);
    try std.testing.expect(c.mtu > 1200);
    try std.testing.expect(c.mtuProbesAckedForTest() >= raises);
}

// ── ECN ─────────────────────────────────────────────────────────────────────

test "ECN: real IP-bit ingest moves the real counter, noteEcn does not" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    const c = pair.client;

    // The simulated path bumps the ACK_ECN counters but NOT the real-ingest
    // evidence. This split is what stops the oracle passing on a simulation.
    c.noteEcn(0, 0, 5);
    try std.testing.expectEqual(@as(u64, 5), c.ecnCountsForTest().ce);
    try std.testing.expectEqual(@as(u64, 0), c.ecnRecvMarkedForTest());

    c.ingestReceivedEcn(.ce);
    try std.testing.expectEqual(@as(u64, 6), c.ecnCountsForTest().ce);
    try std.testing.expectEqual(@as(u64, 1), c.ecnRecvMarkedForTest());

    c.ingestReceivedEcn(.ect0);
    try std.testing.expectEqual(@as(u64, 1), c.ecnCountsForTest().ect0);
    try std.testing.expectEqual(@as(u64, 1), c.ecnRecvEctForTest());
}

test "ECN: a received CE forces an immediate ACK (RFC 9000 §13.2.1)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    const c = pair.client;
    const si = @intFromEnum(spaces.SpaceId.data);
    c.needs_ack[si] = false;
    // Congestion feedback is useless if it is deferred.
    c.ingestReceivedEcn(.ce);
    try std.testing.expect(c.needs_ack[si]);

    c.needs_ack[si] = false;
    c.ingestReceivedEcn(.ect0);
    try std.testing.expect(!c.needs_ack[si]);
}

test "ECN: a validated peer CE increase drives a congestion event" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const c = pair.client;
    c.ecn_state = .testing;
    c.ecn_peer_seen = .{};
    c.ecn_sent = .{ .ect0 = 10 };
    c.stats_ecn_congestion_events = 0;
    c.spaces_state.get(.data).next_pn = 100;

    c.onAck(.data, .{
        .largest_acked = 1,
        .ack_delay = 0,
        .first_range = 0,
        .ecn = .{ .ect0 = 5, .ect1 = 0, .ce = 2 },
    });
    try std.testing.expectEqual(EcnState.capable, c.ecnStateForTest());
    try std.testing.expectEqual(@as(u64, 2), c.ecnCongestionEventsForTest());

    // No further increase → no further congestion event.
    c.onAck(.data, .{
        .largest_acked = 2,
        .ack_delay = 0,
        .first_range = 0,
        .ecn = .{ .ect0 = 5, .ect1 = 0, .ce = 2 },
    });
    try std.testing.expectEqual(@as(u64, 2), c.ecnCongestionEventsForTest());
}

test "ECN: a lying peer cannot manufacture congestion" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const c = pair.client;
    c.ecn_state = .testing;
    c.ecn_peer_seen = .{};
    // We sent 3 marked packets; a peer claiming 100 CE is re-marking or lying.
    // Honoring it would hand an attacker our congestion window.
    c.ecn_sent = .{ .ect0 = 3 };
    c.stats_ecn_congestion_events = 0;
    c.spaces_state.get(.data).next_pn = 100;

    c.onAck(.data, .{
        .largest_acked = 1,
        .ack_delay = 0,
        .first_range = 0,
        .ecn = .{ .ect0 = 0, .ect1 = 0, .ce = 100 },
    });
    try std.testing.expectEqual(EcnState.disabled, c.ecnStateForTest());
    try std.testing.expectEqual(@as(u64, 0), c.ecnCongestionEventsForTest());
}

test "ECN: counter regression and unexpected ECT(1) disable validation" {
    inline for (.{ "regress", "ect1" }) |mode| {
        var pair = try makePair(std.testing.allocator, null);
        defer pair.deinit();
        try establishPair(&pair);
        const c = pair.client;
        c.ecn_state = .capable;
        c.ecn_sent = .{ .ect0 = 50 };
        c.ecn_peer_seen = .{ .ect0 = 10, .ect1 = 0, .ce = 3 };
        c.spaces_state.get(.data).next_pn = 100;

        const reported: frame.EcnCounts = if (comptime std.mem.eql(u8, mode, "regress"))
            // Counters are monotonic for a conformant peer.
            .{ .ect0 = 4, .ect1 = 0, .ce = 3 }
        else
            // We never send ECT(1), so the peer cannot have seen any.
            .{ .ect0 = 12, .ect1 = 1, .ce = 3 };

        c.onAck(.data, .{ .largest_acked = 1, .ack_delay = 0, .first_range = 0, .ecn = reported });
        try std.testing.expectEqual(EcnState.disabled, c.ecnStateForTest());
    }
}

test "ECN: a bleaching path disables marking" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const c = pair.client;
    // Already confirmed working, then the echo stops: something on the path is
    // now stripping the bits.
    c.ecn_state = .capable;
    c.ecn_sent = .{ .ect0 = 10 };
    c.ecn_peer_seen = .{ .ect0 = 5, .ect1 = 0, .ce = 0 };
    c.spaces_state.get(.data).next_pn = 100;
    c.sent.clearRetainingCapacity();
    try c.sent.append(std.testing.allocator, .{
        .path_generation = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .packet_number = 1,
        .space = .data,
        .ecn_marked = true,
    });

    c.onAck(.data, .{ .largest_acked = 1, .ack_delay = 0, .first_range = 0 });
    try std.testing.expectEqual(EcnState.disabled, c.ecnStateForTest());
    // And once disabled, we stop marking: Not-ECT from here on.
    try std.testing.expect(c.outgoingEcn() == null);
}

test "ECN: disabled state stops stamping the codepoint on transmits" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const c = pair.client;
    try std.testing.expect(c.outgoingEcn() != null);

    const sid = try c.openStream(.bidi);
    try c.writeStream(sid, "ecn-marked", false);
    c.next_send_at = 0;
    const marked = (try c.pollTransmit(c.now)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(udp_cmsg.EcnCodepoint.ect0, marked.ecn.?);

    c.setEcnDisabledForTest(true);
    try c.writeStream(sid, "ecn-bleached", true);
    c.next_send_at = 0;
    const unmarked = (try c.pollTransmit(c.now + 1)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(unmarked.ecn == null);
}

test "G9: Initial and Handshake packets leave with ECT(0) (noq build_transmit)" {
    // PREMISE CORRECTION: this gate replaces "ECN: Initial and Handshake
    // packets are never marked", whose predicate contradicted noq —
    // build_transmit (mod.rs:1251-1257) marks EVERY transmit ECT(0) while
    // sending_ecn (paths.rs:304: starts true), with no space check. The old
    // test pinned a deliberate pre-G9 divergence ("a bleached handshake is
    // not recoverable"); G9 is the row that removes the divergence, so the
    // gate now pins noq's behavior.
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();
    const initial = (try pair.client.pollTransmit(1_000_000)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(udp_cmsg.EcnCodepoint.ect0, initial.ecn.?);
    try std.testing.expect(pair.client.ecnSentForTest().ect0 > 0);

    // Server first flight: Initial+Handshake coalesced into ONE datagram
    // (A3), whose transmit metadata carries the single TOS for both.
    try pair.server.handleDatagram(1_000_000, initial.bytes);
    const flight = (try pair.server.pollTransmit(1_000_000)) orelse return error.TestUnexpectedResult;
    const w = try walkCoalesced(flight.bytes);
    try std.testing.expectEqual(@as(usize, 1), w.initial);
    try std.testing.expectEqual(@as(usize, 1), w.handshake);
    try std.testing.expectEqual(udp_cmsg.EcnCodepoint.ect0, flight.ecn.?);
    try std.testing.expect(pair.server.ecnSentForTest().ect0 > 0);
}

// ── delayed ACK ─────────────────────────────────────────────────────────────

test "delayed ACK: a below-threshold ACK is deferred but bounded by max_ack_delay" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const s = pair.server;
    const si = @intFromEnum(spaces.SpaceId.data);

    s.peer_ack_eliciting_threshold = 3;
    s.peer_ack_eliciting_pending = 0;
    s.needs_ack[si] = false;
    s.ack_deadline[si] = null;
    s.stats_delayed_ack_timeouts = 0;
    s.now = 1_000_000;
    // G4 scenario-premise correction: pin the tracker so PN 5000 is IN-ORDER
    // (noq is_out_of_order would force an immediate ACK on a gapped PN).
    s.largest_ack_eliciting_recv[si] = 4999;

    // One ack-eliciting packet, below the threshold: the ACK is deferred, but
    // the timer must be armed or the peer waits forever.
    var buf: [8]u8 = undefined;
    const ping_frame: frame.Frame = .ping;
    const ping = try ping_frame.encode(&buf);
    try s.processPayload(.data, 5000, ping, false);
    try std.testing.expect(!s.needs_ack[si]);
    const deadline = s.ackDeadlineForTest(.data) orelse return error.TestUnexpectedResult;
    try std.testing.expect(deadline > s.now);

    // The deadline must be visible to the pump's timeout computation.
    const timeout = s.pollTimeout() orelse return error.TestUnexpectedResult;
    try std.testing.expect(timeout <= deadline);

    // Before it expires, still deferred.
    s.handleTimeout(deadline - 1);
    try std.testing.expect(!s.needs_ack[si]);

    // At the deadline the ACK becomes owed.
    s.handleTimeout(deadline);
    try std.testing.expect(s.needs_ack[si]);
    try std.testing.expectEqual(@as(u64, 1), s.delayedAckTimeoutsForTest());
    try std.testing.expect(s.ackDeadlineForTest(.data) == null);
}

test "delayed ACK: reaching the threshold acks immediately and disarms the timer" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const s = pair.server;
    const si = @intFromEnum(spaces.SpaceId.data);
    // G4 scenario-premise correction (was threshold 2): noq fires when the
    // count EXCEEDS the threshold (spaces.rs:1199-1201), so "second packet
    // ACKs immediately" is threshold ONE under noq semantics. The tracker is
    // pinned so the injected PNs are in-order (a gapped PN is out-of-order
    // traffic under is_out_of_order and would ACK immediately for a
    // different reason than the one this test claims to exercise).
    s.peer_ack_eliciting_threshold = 1;
    s.peer_ack_eliciting_pending = 0;
    s.needs_ack[si] = false;
    s.ack_deadline[si] = null;
    s.stats_delayed_ack_timeouts = 0;
    s.largest_ack_eliciting_recv[si] = 5999;

    var buf: [8]u8 = undefined;
    const ping_frame: frame.Frame = .ping;
    const ping = try ping_frame.encode(&buf);
    try s.processPayload(.data, 6000, ping, false);
    try std.testing.expect(s.ackDeadlineForTest(.data) != null);

    try s.processPayload(.data, 6001, ping, false);
    try std.testing.expect(s.needs_ack[si]);
    // The timer is redundant once the ACK is owed.
    try std.testing.expect(s.ackDeadlineForTest(.data) == null);
    try std.testing.expectEqual(@as(u64, 0), s.delayedAckTimeoutsForTest());
}

test "delayed ACK: emitting the ACK clears the deadline" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const s = pair.server;
    const si = @intFromEnum(spaces.SpaceId.data);
    s.peer_ack_eliciting_threshold = 5;
    s.peer_ack_eliciting_pending = 0;
    s.needs_ack[si] = false;
    s.ack_deadline[si] = null;
    // G4 scenario-premise correction: pin the tracker so PN 7000 is IN-ORDER
    // (a gapped PN is out-of-order under noq's is_out_of_order → immediate
    // ACK, which is not what this test exercises).
    s.largest_ack_eliciting_recv[si] = 6999;

    var buf: [8]u8 = undefined;
    const ping_frame: frame.Frame = .ping;
    const ping = try ping_frame.encode(&buf);
    try s.processPayload(.data, 7000, ping, false);
    const deadline = s.ackDeadlineForTest(.data) orelse return error.TestUnexpectedResult;

    s.handleTimeout(deadline);
    s.next_send_at = 0;
    _ = (try s.pollTransmit(deadline)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(!s.needs_ack[si]);
    try std.testing.expect(s.ackDeadlineForTest(.data) == null);
}

test "N-3 data packet can carry MTU probe" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.client.mtu = 1200;
    pair.client.mtu_probe_queue_len = 0;
    pair.client.probe_mtu = 1280;
    pair.client.probe_pn = null;
    const before_budget = pair.client.dataPayloadBudget();
    const sid = try pair.client.openStream(.bidi);
    try pair.client.writeStream(sid, &[_]u8{0xaa} ** 2048, false);
    const now = pair.client.now;
    pair.client.next_send_at = 0;
    const tx = (try pair.client.pollTransmit(now)) orelse return error.UnexpectedState;
    try std.testing.expect(tx.bytes.len >= 1280);
    const probe = pair.client.probe_pn orelse return error.UnexpectedState;
    pair.client.onAck(.data, .{ .largest_acked = probe, .ack_delay = 0, .first_range = 0 });
    try std.testing.expectEqual(@as(u16, 1280), pair.client.mtu);
    try std.testing.expect(pair.client.dataPayloadBudget() > before_budget);
}

test "N-3 lost mtu probe does not raise mtu" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const start = pair.client.mtu;
    pair.client.probe_mtu = start + 200;
    pair.client.probe_pn = 42;
    pair.client.onMtuProbeLost();
    try std.testing.expectEqual(start, pair.client.mtu);
    try std.testing.expect(pair.client.probe_mtu == null);
}

test "N-3 Cubic pacing rate nonzero after handshake" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const cc = pair.client.cc orelse return error.UnexpectedState;
    try std.testing.expect(cc.pacingRate() != null);
    try std.testing.expect(cc.pacingRate().? > 0);
}

test "N-3 Cubic pacing permits a bounded initial burst under tiny RTT" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.client.rtt = loss.RttEstimator.init(1_000_000_000);
    if (pair.client.cc) |cc| {
        const cubic_ptr: *cubic_cc.Cubic = @ptrCast(@alignCast(cc.ptr));
        cubic_ptr.window = 2600;
        cubic_ptr.smoothed_rtt_ns = 1_000_000_000;
        cubic_ptr.recomputePacing();
    }
    const s = try pair.client.openStream(.bidi);
    try pair.client.writeStream(s, &[_]u8{0} ** 3600, true);
    // Anchor on the connection clock — establishPair advances `now` far past a
    // literal 1ms epoch, so a stale next_send_at would block the first send.
    const t0: Instant = pair.client.now;
    pair.client.next_send_at = 0;
    const first = (try pair.client.pollTransmit(t0)) orelse return error.UnexpectedState;
    try pair.server.handleDatagram(t0, first.bytes);
    const second = (try pair.client.pollTransmit(t0 + 500_000_000)) orelse return error.UnexpectedState;
    try std.testing.expect(second.bytes.len > 0);

    var sent: usize = 2;
    while (try pair.client.pollTransmit(t0 + 500_000_000)) |tx| {
        try std.testing.expect(tx.bytes.len > 0);
        sent += 1;
        if (sent > 4) return error.UnexpectedState;
    }
    try std.testing.expect(sent > 1);
}

test "N-3 NewReno pacing refills and schedules at the 1.25x window rate" {
    // Wire-observable send-rate schedule under NewReno: the connection
    // consumes cc.pacingRate() as the pacer refill rate (dataPacingRate ->
    // refillPacingTokens / updatePacingDeadline), which must reproduce iroh's
    // `window * 1.25 * elapsed_rtts` refill (noq pacing.rs:131) and the
    // matching `/ 5 * 4` delay scaling (pacing.rs:152) — NOT BBR3's separate
    // ProbeBW gain.
    var pair = try makePairCongestionKind(std.testing.allocator, .new_reno);
    defer pair.deinit();
    try establishPair(&pair);
    // Drain the handshake flight so it does not shrink the send window: the
    // pacer caps every refill at congestionSendWindow() = window - in_flight
    // (pacing.rs optimal_capacity is bounded the same way), and the refill
    // assertions below need the FULL window as headroom.
    try flushDeferredAcks(&pair);
    try std.testing.expectEqual(@as(u64, 0), pair.client.bytes_in_flight);
    // The flush's pump can advance MTU discovery; pin the baseline MTU so the
    // delay assertions below have a fixed min_send.
    pair.client.mtu = min_mtu;
    const cc = pair.client.cc orelse return error.UnexpectedState;
    const nr: *new_reno_cc.NewReno = @ptrCast(@alignCast(cc.ptr));
    // Pin a known window + RTT schedule on the controller.
    nr.window = 1_000_000;
    nr.smoothed_rtt_ns = 50_000_000; // 50 ms
    nr.recomputePacing();
    // The connection's actual rate source: 5/4 of the bare window rate
    // (1e6 bytes / 50 ms = 20e6 bytes/s -> 25e6 bytes/s).
    const rate = pair.client.dataPacingRate() orelse return error.UnexpectedState;
    try std.testing.expectEqual(@as(u64, 25_000_000), rate);

    const t0: Instant = pair.client.now;
    // Refill schedule: drain the bucket, advance 400 us — at the 25e6 rate
    // that is exactly 10_000 bytes, under the burst-bucket cap so the refill
    // is uncapped and tracks the RATE. The pre-fix 1.0x rate refilled only
    // 8_000 in the same interval (window * 1.25 * elapsed_rtts vs the bare
    // window rate).
    pair.client.pacing_tokens = 0;
    pair.client.pacing_last_refill_at = t0;
    pair.client.refillPacingTokens(t0 + 400_000, rate);
    try std.testing.expectEqual(@as(u64, 10_000), pair.client.pacing_tokens);

    // Delay schedule: an empty bucket must hold the next data send for
    // ceil(min_send / rate) = 1200 * 1e9 / 25e6 = 48_000 ns — 4/5 of the
    // pre-fix 1.0x-rate delay (60_000 ns), the pacing.rs:152 `/ 5 * 4`
    // scaling. next_send_at is what arms the send timer, so this is the
    // wire-observable send time.
    pair.client.pacing_tokens = 0;
    pair.client.updatePacingDeadline(rate);
    try std.testing.expectEqual(@as(u64, 1200), pair.client.pacingMinSendBytes());
    try std.testing.expectEqual(t0 + 48_000, pair.client.next_send_at);
}

test "N-3 NewReno pacing tracks the halved window after a loss event" {
    // Loss scenario: a congestion event halves the NewReno window and the
    // pacing/refill schedule must follow at 5/4 of the REDUCED window rate —
    // under-pacing after loss would confound real-network throughput.
    const allocator = std.testing.allocator;
    var cc = try new_reno_cc.create(allocator, 0, 1200);
    defer cc.destroy(allocator);
    const nr: *new_reno_cc.NewReno = @ptrCast(@alignCast(cc.ptr));
    nr.window = 1_000_000;
    nr.smoothed_rtt_ns = 50_000_000;
    nr.recomputePacing();
    try std.testing.expectEqual(@as(?u64, 25_000_000), cc.pacingRate());
    cc.onCongestionEvent(2_000_000_000, 1_500_000_000, false, false, 1200, 2);
    try std.testing.expectEqual(@as(u64, 500_000), cc.window());
    try std.testing.expectEqual(@as(?u64, 12_500_000), cc.pacingRate());
}

test "N-3 Retry roundtrip changes client token" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    var token_buf: [32]u8 = undefined;
    const retry_pkt = try pair.server.issueRetry(pair.client.initial_dcid, pair.client.local_cid, &token_buf);
    defer std.testing.allocator.free(retry_pkt);
    try pair.client.consumeRetry(retry_pkt);
    try std.testing.expect(pair.client.initial_token.len > 0);
}

test "N-3 NEW_TOKEN received and stored" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    var buf: [64]u8 = undefined;
    const nt: frame.Frame = .{ .new_token = .{ .token = "resume-addr-token" } };
    const enc = try nt.encode(&buf);
    try pair.client.processPayload(.data, 500, enc, false);
    try std.testing.expectEqualStrings("resume-addr-token", pair.client.storedNewToken().?);
}

test "N-3 mtu probe ack raises mtu" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const start_mtu = pair.client.mtu;
    pair.client.mtu_probe_queue_len = 0;
    pair.client.mtu_search = null;
    pair.client.probe_mtu = start_mtu + 200;
    pair.client.probe_pn = 7;
    pair.client.spaces_state.get(.data).next_pn = @max(pair.client.spaces_state.get(.data).next_pn, 8);
    pair.client.onAck(.data, .{
        .largest_acked = 7,
        .ack_delay = 0,
        .first_range = 0,
    });
    try std.testing.expectEqual(@as(u16, start_mtu + 200), pair.client.mtu);
    try std.testing.expect(pair.client.probe_mtu == null);
}

test "N-3 pacing permits bounded burst under tiny rate" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.client.setTestPacingRate(1200);
    pair.client.setTestCwndCap(2600);
    const s = try pair.client.openStream(.bidi);
    try pair.client.writeStream(s, &[_]u8{0} ** 3600, true);
    const t0: Instant = pair.client.now;
    pair.client.next_send_at = 0;
    const first = (try pair.client.pollTransmit(t0)) orelse return error.UnexpectedState;
    try pair.server.handleDatagram(t0, first.bytes);
    const second = (try pair.client.pollTransmit(t0 + 1)) orelse return error.UnexpectedState;
    try std.testing.expect(second.bytes.len > 0);

    var sent: usize = 2;
    while (try pair.client.pollTransmit(t0 + 1)) |tx| {
        try std.testing.expect(tx.bytes.len > 0);
        sent += 1;
        if (sent > 4) return error.UnexpectedState;
    }
    try std.testing.expect(sent > 1);
}

test "N-3 pacing debt does not block queued data-space control" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.client.setTestPacingRate(1200);
    const s = try pair.client.openStream(.bidi);
    try pair.client.writeStream(s, &[_]u8{0} ** 2048, false);
    try pair.client.queueNewConnectionId();

    const t0: Instant = pair.client.now;
    pair.client.pacing_tokens = 0;
    pair.client.pacing_last_refill_at = t0;
    pair.client.next_send_at = t0 + std.time.ns_per_s;

    const control = (try pair.client.pollTransmit(t0 + 1)) orelse return error.UnexpectedState;
    try std.testing.expect(control.bytes.len > 0);
    try std.testing.expectEqual(@as(u64, 0), pair.client.pacing_tokens);
}

test "N-3 ACK with ecn counts roundtrips" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.server.noteEcn(3, 1, 2);
    pair.server.needs_ack[@intFromEnum(spaces.SpaceId.data)] = true;
    var pkt_idx: usize = 0;
    try pumpOnce(&pair, 1_000_000, &pkt_idx, null);
    try std.testing.expect(pair.server.ecn_counts.ect0 == 3);
    try std.testing.expect(pair.server.ecn_counts.ce == 2);
}

test "N-3 stateless reset detected on connection" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // Detection uses the PEER's token (server's advertised reset token for the
    // client), not our own. RFC 9000 §10.3 resets look like short headers with
    // the fixed bit SET — encode that shape as external truth (do not mirror
    // our generator's fixed-bit-clear quirk).
    const peer_token = pair.client.peer_stateless_reset_token orelse
        pair.server.statelessResetToken();
    // Ensure peer token is installed (handshake TP path).
    pair.client.peer_stateless_reset_token = peer_token;
    var reset_pkt: [32]u8 = undefined;
    @memset(&reset_pkt, 0xa5);
    reset_pkt[0] = packet.fixed_bit; // RFC shape: fixed bit SET
    @memcpy(reset_pkt[reset_pkt.len - packet.stateless_reset_token_len ..], &peer_token);
    try pair.client.handleDatagram(1_000_000, &reset_pkt);
    try std.testing.expect(pair.client.state == .draining);
}

test "5d: client adopts the server SCID from an authenticated Initial" {
    const allocator = std.testing.allocator;
    var pair = try makePair(allocator, null);
    defer pair.deinit();

    try pair.client.startClient();
    var packet_index: usize = 0;
    try pumpOnce(&pair, 1, &packet_index, null);
    try std.testing.expectEqualSlices(u8, pair.server.local_cid.slice(), pair.client.remote_cid.slice());
}

test "5b: multi-stream bidi echo + independent FIN + CONNECTION_CLOSE" {
    const allocator = std.testing.allocator;
    var pair = try makePair(allocator, null);
    defer pair.deinit();
    const client = pair.client;
    const server = pair.server;

    try client.startClient();

    var now: Instant = 0;
    var pkt_idx: usize = 0;
    // Drive the handshake to established.
    var rounds: usize = 0;
    while (rounds < 32 and !(client.state == .established and server.state == .established)) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expect(client.state == .established);
    try std.testing.expect(server.state == .established);

    // Client opens two concurrent bidi streams with distinct data + FIN.
    const s1 = try client.openStream(.bidi);
    const s2 = try client.openStream(.bidi);
    try client.writeStream(s1, "alpha-one", true);
    try client.writeStream(s2, "bravo-two-longer", true);

    // Server echoes each fully-received stream back on the same id.
    var echoed1 = false;
    var echoed2 = false;
    rounds = 0;
    while (rounds < 64) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
        if (!echoed1 and server.streamRecvFin(s1)) {
            try server.writeStream(s1, server.streamRecvBytes(s1), true);
            echoed1 = true;
        }
        if (!echoed2 and server.streamRecvFin(s2)) {
            try server.writeStream(s2, server.streamRecvBytes(s2), true);
            echoed2 = true;
        }
        if (client.streamRecvFin(s1) and client.streamRecvFin(s2)) break;
    }

    // In-order reassembly + independent FIN, both directions.
    try std.testing.expectEqualSlices(u8, "alpha-one", server.streamRecvBytes(s1));
    try std.testing.expectEqualSlices(u8, "bravo-two-longer", server.streamRecvBytes(s2));
    try std.testing.expect(server.streamRecvFin(s1));
    try std.testing.expect(server.streamRecvFin(s2));
    try std.testing.expectEqualSlices(u8, "alpha-one", client.streamRecvBytes(s1));
    try std.testing.expectEqualSlices(u8, "bravo-two-longer", client.streamRecvBytes(s2));
    try std.testing.expect(client.streamRecvFin(s1));
    try std.testing.expect(client.streamRecvFin(s2));

    // Clean CONNECTION_CLOSE observed by the peer (not idle timeout).
    client.close(now);
    rounds = 0;
    while (rounds < 8 and server.state != .draining) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    // Once the peer's data-space close arrives, both sides enter draining;
    // the local close was already sent and is not answered again.
    try std.testing.expect(client.state == .draining);
    try std.testing.expect(server.state == .draining);

    _ = endpoint.Side.client;
}

test "5e: path validated ONLY by a matching PATH_RESPONSE (real challenge, no spoof)" {
    const allocator = std.testing.allocator;
    var pair = try makePair(allocator, null);
    defer pair.deinit();
    const client = pair.client;
    const server = pair.server;
    try client.startClient();

    var now: Instant = 0;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    while (rounds < 32 and !(client.state == .established and server.state == .established)) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expect(client.state == .established);
    try std.testing.expect(server.state == .established);

    const token: [8]u8 = .{ 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18 };
    const never_challenged: [8]u8 = .{ 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22 };

    // Anti-spoof: an unsolicited PATH_RESPONSE (token we never challenged with)
    // validates NOTHING.
    try client.onPathResponse(never_challenged);
    try std.testing.expect(!client.pathValidated(never_challenged));

    // Issue a real challenge; it is NOT validated until the peer echoes it.
    client.challengePath(token);
    try std.testing.expect(!client.pathValidated(token));

    // Drive the exchange: client PATH_CHALLENGE -> server PATH_RESPONSE(token) ->
    // client validates. The token is random + echoed verbatim (real validation).
    rounds = 0;
    while (rounds < 8 and !client.pathValidated(token)) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expect(client.pathValidated(token));

    // A token that was never challenged is still not validated after the exchange.
    try std.testing.expect(!client.pathValidated(never_challenged));
}

test "5b: flow control blocks then unblocks on MAX_STREAM_DATA" {
    const allocator = std.testing.allocator;
    // Server advertises a TINY per-stream window (4 bytes) for client-initiated
    // bidi streams, so the client stalls after 4 bytes until granted more.
    var params_buf: [128]u8 = undefined;
    const server_params = try (transport_parameters.TransportParameters{
        .initial_max_data = 1_000_000,
        .initial_max_stream_data_bidi_local = 4,
        .initial_max_stream_data_bidi_remote = 4,
        .initial_max_stream_data_uni = 4,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 8,
    }).encode(&params_buf);

    var pair = try makePair(allocator, server_params);
    defer pair.deinit();
    const client = pair.client;
    const server = pair.server;
    try client.startClient();

    var now: Instant = 0;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    while (rounds < 32 and !(client.state == .established and server.state == .established)) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expect(client.state == .established);

    const s = try client.openStream(.bidi);
    try client.writeStream(s, "0123456789", true); // 10 bytes vs a 4-byte window

    // Pump a few rounds WITHOUT the server consuming — client must stall at 4.
    rounds = 0;
    while (rounds < 8) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expectEqual(@as(usize, 4), server.streamRecvBytes(s).len);
    try std.testing.expect(client.streamSendBlocked(s));

    // Server consumes → grants MAX_STREAM_DATA on the next flight → client resumes.
    rounds = 0;
    while (rounds < 32) : (rounds += 1) {
        _ = server.readStream(s); // drain → schedules window grant
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
        if (server.streamRecvFin(s)) break;
    }
    try std.testing.expectEqualSlices(u8, "0123456789", server.streamRecvBytes(s));
    try std.testing.expect(server.streamRecvFin(s));
    try std.testing.expect(!client.streamSendBlocked(s));
}

test "5b: empty stream emits FIN without a data frame" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);

    const stream_id = try pair.client.openStream(.bidi);
    try pair.client.writeStream(stream_id, &.{}, true);
    var now: Instant = pair.client.now;
    var packet_index: usize = 0;
    var rounds: usize = 0;
    while (rounds < 16 and !pair.server.streamRecvFin(stream_id)) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &packet_index, null);
    }
    try std.testing.expect(pair.server.streamRecvFin(stream_id));
    try std.testing.expectEqual(@as(usize, 0), pair.server.streamRecvBytes(stream_id).len);
}

test "5b: empty FIN defers when packet content slots are saturated" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.client.mtu_probe_queue_len = 0;
    pair.client.probe_mtu = null;
    pair.client.probe_pn = null;

    const stream_id = try pair.client.openStream(.bidi);
    try pair.client.writeStream(stream_id, "12345678", false);
    const stream = pair.client.findStream(stream_id).?;
    stream.send.send_next = stream.send.endOffset();
    stream.send.fin = true;
    try stream.send.rtx.ensureUnusedCapacity(std.testing.allocator, max_content);
    for (0..max_content) |offset| {
        stream.send.rtx.pushBackAssumeCapacity(.{ .offset = offset, .len = 1, .fin = false });
    }

    pair.client.next_send_at = 0;
    const now = pair.client.now + 1_000_000;
    _ = (try pair.client.pollTransmit(now)) orelse return error.UnexpectedState;
    try std.testing.expect(!stream.send.fin_sent);
    try std.testing.expectEqual(@as(usize, 0), stream.send.rtx.len);

    pair.client.next_send_at = 0;
    _ = (try pair.client.pollTransmit(now + 1)) orelse return error.UnexpectedState;
    try std.testing.expect(stream.send.fin_sent);
}

test "5b: empty FIN retransmits after PTO" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair); // G4: drain establishment ACK state (see helper)
    pair.client.mtu_probe_queue_len = 0;
    pair.client.probe_mtu = null;
    pair.client.probe_pn = null;
    pair.server.mtu_probe_queue_len = 0;
    pair.server.probe_mtu = null;
    pair.server.probe_pn = null;

    const stream_id = try pair.client.openStream(.bidi);
    try pair.client.writeStream(stream_id, &.{}, true);
    const sent_at = pair.client.now + 1_000_000;
    pair.client.next_send_at = 0;
    _ = (try pair.client.pollTransmit(sent_at)) orelse return error.UnexpectedState; // deliberately dropped

    const expiry = pair.client.ptoDeadline().?;
    pair.client.handleTimeout(expiry);
    try std.testing.expect(pair.client.stats_pto_events > 0);
    pair.client.next_send_at = 0;
    const retry = (try pair.client.pollTransmit(expiry + 1)) orelse return error.UnexpectedState;
    try pair.server.handleDatagram(expiry + 1, retry.bytes);
    try std.testing.expect(pair.server.streamRecvFin(stream_id));
}

test "5b: RESET_STREAM retransmits after PTO with its absolute final size" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair); // G4: drain establishment ACK state (see helper)
    pair.client.mtu_probe_queue_len = 0;
    pair.client.probe_mtu = null;
    pair.client.probe_pn = null;
    pair.server.mtu_probe_queue_len = 0;
    pair.server.probe_mtu = null;
    pair.server.probe_pn = null;

    const stream_id = try pair.client.openStream(.bidi);
    try pair.client.resetStream(stream_id, 77);
    const stream = pair.client.findStream(stream_id).?;
    const sent_at = pair.client.now + 1_000_000;
    pair.client.next_send_at = 0;
    _ = (try pair.client.pollTransmit(sent_at)) orelse return error.UnexpectedState; // deliberately dropped
    try std.testing.expect(stream.send.reset_sent);

    const expiry = pair.client.ptoDeadline().?;
    pair.client.handleTimeout(expiry);
    try std.testing.expect(!stream.send.reset_sent);
    pair.client.next_send_at = 0;
    const retry = (try pair.client.pollTransmit(expiry + 1)) orelse return error.UnexpectedState;
    try pair.server.handleDatagram(expiry + 1, retry.bytes);
    const received = pair.server.findStream(stream_id) orelse return error.UnexpectedState;
    try std.testing.expectEqual(@as(?u64, 77), received.recv.reset_code);
    try std.testing.expectEqual(@as(?u64, 0), received.recv.fin_offset);
}

// Zig↔Zig completes-under-loss (5b gate, F2): scripted drops; the transfer
// completes with retransmission driven BY loss.detectLostPackets IN THE DRIVER —
// NO harness poke, NO test-only flag flip. The old `stream_out_sent` hack is gone.
test "5b: completes under loss via real loss-driven retransmit (NewReno + Cubic)" {
    const kinds = [_]congestion.Kind{ .new_reno, .cubic };
    for (kinds) |kind| try pairUnderLoss(kind);
}

fn dropPattern(idx: usize, from_client: bool) bool {
    // Drop ~1 in 4 CLIENT→SERVER packets after the handshake's first flights,
    // so the server is genuinely missing data and completion REQUIRES a real
    // loss-driven retransmit (not merely dropped ACKs).
    return from_client and idx > 8 and (idx % 4 == 0);
}

fn pairUnderLoss(kind: congestion.Kind) !void {
    const allocator = std.testing.allocator;
    var pair = try makePair(allocator, null);
    defer pair.deinit();
    const client = pair.client;
    const server = pair.server;

    // Exercise the CC seam alongside (window must stay positive).
    var client_cc = try congestion.create(allocator, kind, 0, 1200);
    defer client_cc.destroy(allocator);

    try client.startClient();
    // Payload written INCREMENTALLY (below) so sustained traffic keeps acks
    // flowing — a lost packet is exposed by later acked packets and caught by
    // loss.detectLostPackets (packet threshold), not just the PTO backstop.
    var payload: [18_000]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i & 0xff);
    const chunk_len: usize = 240;

    var now: Instant = 0;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    var s: u64 = undefined;
    var opened = false;
    var written: usize = 0;
    var got = false;
    while (rounds < 800) : (rounds += 1) {
        now += 25_000_000; // 25ms/round — time-threshold backstop crosses ~375ms
        if (!opened and client.state == .established) {
            // Isolate the loss gate from auto-scheduled MTU PING probes so
            // pkt_idx drops land on STREAM packets and loss.detectLostPackets fires.
            client.mtu_probe_queue_len = 0;
            client.probe_mtu = null;
            client.probe_pn = null;
            server.mtu_probe_queue_len = 0;
            server.probe_mtu = null;
            server.probe_pn = null;
            s = try client.openStream(.bidi);
            opened = true;
        }
        if (opened and written < payload.len) {
            const end = @min(written + chunk_len, payload.len);
            try client.writeStream(s, payload[written..end], end == payload.len);
            written = end;
        }
        try pumpOnce(&pair, now, &pkt_idx, dropPattern);
        client_cc.onAck(now, now - 1_000_000, 1200, @intCast(rounds), false, .{
            .latest_ns = 20_000_000,
            .smoothed_ns = 20_000_000,
            .min_ns = 15_000_000,
            .var_ns = 5_000_000,
        });
        try std.testing.expect(client_cc.window() > 0);
        if (opened and written == payload.len and server.streamRecvFin(s) and server.streamRecvBytes(s).len == payload.len) {
            got = true;
            break;
        }
    }
    try std.testing.expect(got);
    try std.testing.expectEqualSlices(u8, &payload, server.streamRecvBytes(s));
    // F2: prove the transfer's recovery was DRIVEN by loss.detectLostPackets in
    // the driver (the production path), not a harness poke or flag flip.
    try std.testing.expect(client.stats_loss_events > 0);
    try std.testing.expect(client.stats_retransmits > 0);
    try std.testing.expect(client.state == .established);
    try std.testing.expect(server.state == .established);
}

// ---------------------------------------------------------------------------
// N-3 adversarial (stateful): fixture-driven guards that a byte corpus cannot reach.
// ---------------------------------------------------------------------------

test "N-3-adversarial key-phase fail-closed after update with no prev/next" {
    // Direct CryptoState path (same as connection.crypto_1rtt): phase flip without
    // next/prev keys must not pick a silent default.
    const state: packet_crypto.CryptoState = .{
        .current = packet_crypto.PacketKeys.init(.{0xab} ** 16, .{0xcd} ** 12, .{0xef} ** 16),
        .key_phase = false,
    };
    try std.testing.expectError(error.InvalidKeyPhase, state.selectForIncoming(true));
}

test "N-3-adversarial CID slots cap rejects excess NEW_CONNECTION_ID without crash" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // Flood remote CID slots past max_local_cid_slots — must not OOB/panic.
    var i: u64 = 0;
    while (i < max_local_cid_slots + 8) : (i += 1) {
        var cid_bytes: [4]u8 = .{ 0x10, 0x20, 0x30, @truncate(i) };
        var buf: [64]u8 = undefined;
        const f: frame.Frame = .{ .new_connection_id = .{
            .sequence = i + 1,
            .retire_prior_to = 0,
            .connection_id = &cid_bytes,
            .reset_token = .{@as(u8, @truncate(i))} ** 16,
        } };
        const enc = try f.encode(&buf);
        try pair.client.processPayload(.data, 1000 + i, enc, false);
    }
    try std.testing.expect(pair.client.remote_cid_len <= max_local_cid_slots);
    try std.testing.expect(pair.client.state == .established);
}

test "N-3-adversarial retire_prior_to marks lower sequences retired" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // Install two remote CIDs, then one with retire_prior_to that retires them.
    const cid_a = [_]u8{ 0xaa, 0x01 };
    const cid_b = [_]u8{ 0xbb, 0x02 };
    const cid_c = [_]u8{ 0xcc, 0x03 };
    var buf: [96]u8 = undefined;
    const f1: frame.Frame = .{ .new_connection_id = .{
        .sequence = 1,
        .retire_prior_to = 0,
        .connection_id = &cid_a,
        .reset_token = .{0x11} ** 16,
    } };
    try pair.client.processPayload(.data, 2001, try f1.encode(&buf), false);
    const f2: frame.Frame = .{ .new_connection_id = .{
        .sequence = 2,
        .retire_prior_to = 0,
        .connection_id = &cid_b,
        .reset_token = .{0x22} ** 16,
    } };
    try pair.client.processPayload(.data, 2002, try f2.encode(&buf), false);
    const f3: frame.Frame = .{ .new_connection_id = .{
        .sequence = 3,
        .retire_prior_to = 2,
        .connection_id = &cid_c,
        .reset_token = .{0x33} ** 16,
    } };
    try pair.client.processPayload(.data, 2003, try f3.encode(&buf), false);
    var retired_low: usize = 0;
    var i: usize = 0;
    while (i < pair.client.remote_cid_len) : (i += 1) {
        if (pair.client.remote_cids[i].sequence < 2 and pair.client.remote_cids[i].retired) retired_low += 1;
    }
    try std.testing.expect(retired_low >= 1);
}

test "N-3-adversarial anti-amplification blocks send when nothing received" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    // Server has received 0 bytes and path not validated → pollTransmit must not
    // emit unlimited data (anti-amp).
    try std.testing.expectEqual(@as(u64, 0), pair.server.bytes_received);
    try std.testing.expect(!pair.server.path_validated_any);
    // Force something to send: queue a PATH_CHALLENGE response or CRYPTO via
    // startClient on client only, then try many server pollTransmit.
    // With zero received, any non-empty build hits AntiAmplificationLimit → null.
    var rounds: usize = 0;
    var sent: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        if (try pair.server.pollTransmit(1_000_000 + @as(i64, @intCast(rounds)))) |tx| {
            sent += tx.bytes.len;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), sent);
}

test "N-3-adversarial long-header AEAD failure does not poison PN space" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();
    var now: Instant = 0;
    var pkt_idx: usize = 0;
    try pumpOnce(&pair, now, &pkt_idx, null);
    // Baseline: the client's first Initial (PN 0) arrived.
    const saved = pair.server.spaces_state.getConst(.initial).largest_received;
    try std.testing.expect(saved != null);

    // Craft an Initial whose truncated PN reconstructs far ahead, then corrupt
    // the AEAD tag (a keyless attacker cannot do better). The decrypt must fail
    // AND the reconstruct inside handleLongPacket must not stick.
    const client_initial_keys = initial_keys.clientKeys(pair.server.initial_dcid.slice());
    const poison_pn: u64 = saved.? + 100;
    var buf: [1500]u8 = undefined;
    const frames = [_]frame.Frame{.ping};
    const built = try packet_builder.buildLongHeader(&buf, .initial, 1, pair.server.local_cid, pair.client.local_cid, "", poison_pn, &frames, client_initial_keys, 0);
    built.bytes[built.bytes.len - 1] ^= 0xff; // corrupt the AEAD tag
    try std.testing.expectError(error.AuthenticationFailed, pair.server.handleDatagram(now, built.bytes));
    try std.testing.expectEqual(saved, pair.server.spaces_state.getConst(.initial).largest_received);

    // The connection is still healthy: the handshake completes.
    var rounds: usize = 0;
    while (rounds < 32 and !(pair.client.state == .established and pair.server.state == .established)) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expect(pair.client.state == .established);
    try std.testing.expect(pair.server.state == .established);
}

test "N-3-adversarial early-1RTT fallback AEAD failure does not poison data PN space" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const data_idx = @intFromEnum(spaces.SpaceId.data);
    const server = pair.server;
    const read_keys = server.read_keys[data_idx].?;

    // Force the early-1-RTT fallback branch: 1-RTT read keys present but the
    // crypto_1rtt slots are empty (the transient state before they populate).
    const saved_crypto = server.crypto_1rtt;
    server.crypto_1rtt = .{};
    const saved = server.spaces_state.getConst(.data).largest_received;

    const poison_pn: u64 = (saved orelse 0) + 100;
    var buf: [1500]u8 = undefined;
    const frames = [_]frame.Frame{.ping};
    const built = try packet_builder.buildOneRtt(&buf, server.local_cid, poison_pn, saved_crypto.key_phase, &frames, read_keys, 0);
    built.bytes[built.bytes.len - 1] ^= 0xff; // corrupt the AEAD tag
    try std.testing.expectError(error.AuthenticationFailed, server.handleDatagram(server.now, built.bytes));
    try std.testing.expectEqual(saved, server.spaces_state.getConst(.data).largest_received);

    // Restore and prove the data path still works end to end.
    server.crypto_1rtt = saved_crypto;
    const sid = try pair.client.openStream(.bidi);
    try pair.client.writeStream(sid, "post-attack", true);
    var now: Instant = pair.client.now;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    while (rounds < 32 and !server.streamRecvFin(sid)) : (rounds += 1) {
        now += 1_000_000;
        pair.client.next_send_at = 0;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expectEqualStrings("post-attack", server.streamRecvBytes(sid));
}

test "A15: reserved bits set on an authenticated Initial protocol-closes" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();
    const now: Instant = 0;
    var pkt_idx: usize = 0;
    try pumpOnce(&pair, now, &pkt_idx, null);
    const saved = pair.server.spaces_state.getConst(.initial).largest_received;
    try std.testing.expect(saved != null);

    // Build a REAL Initial with the client initial keys, unprotect it, set the
    // long-header reserved bits (0x0c) on the plaintext first byte, and
    // re-protect so the AEAD tag authenticates the tampered header. Only an
    // authenticated packet may close; unauthenticated garbage must keep
    // failing AEAD silently (noq checks reserved bits after decrypt).
    const client_initial_keys = initial_keys.clientKeys(pair.server.initial_dcid.slice());
    const pn: u64 = saved.? + 1;
    var buf: [1500]u8 = undefined;
    const frames = [_]frame.Frame{.ping};
    const built = try packet_builder.buildLongHeader(&buf, .initial, 1, pair.server.local_cid, pair.client.local_cid, "", pn, &frames, client_initial_keys, 0);
    try packet_crypto.decryptHeaderWithKeys(built.bytes, built.pn_offset, client_initial_keys);
    try packet_crypto.decryptPayload(built.bytes, built.header_len, pn, client_initial_keys);
    try std.testing.expect(packet_crypto.reservedBitsValid(built.bytes[0]));
    built.bytes[0] |= 0x0c;
    try packet_crypto.encryptPayload(built.bytes, built.header_len, pn, client_initial_keys);
    try packet_crypto.encryptHeaderWithKeys(built.bytes, built.pn_offset, client_initial_keys);

    try std.testing.expectError(error.ReservedBitsSet, pair.server.handleDatagram(now, built.bytes));
    const close_frame = pair.server.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_protocol_violation, close_frame.error_code);
}

test "A15: reserved bits set on an authenticated 1-RTT packet protocol-closes" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const server = pair.server;
    const read_keys = server.crypto_1rtt.current.?;
    const saved = server.spaces_state.getConst(.data).largest_received;
    const pn: u64 = (saved orelse 0) + 1;

    var buf: [1500]u8 = undefined;
    const frames = [_]frame.Frame{.ping};
    const built = try packet_builder.buildOneRtt(&buf, server.local_cid, pn, server.crypto_1rtt.key_phase, &frames, read_keys, 0);
    try packet_crypto.decryptHeaderWithKeys(built.bytes, built.pn_offset, read_keys);
    try packet_crypto.decryptPayload(built.bytes, built.header_len, pn, read_keys);
    try std.testing.expect(packet_crypto.reservedBitsValid(built.bytes[0]));
    built.bytes[0] |= 0x18; // short-header reserved bits
    try packet_crypto.encryptPayload(built.bytes, built.header_len, pn, read_keys);
    try packet_crypto.encryptHeaderWithKeys(built.bytes, built.pn_offset, read_keys);

    try std.testing.expectError(error.ReservedBitsSet, server.handleDatagram(server.now, built.bytes));
    const close_frame = server.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_protocol_violation, close_frame.error_code);
}

test "N-3-adversarial consumeRetry rejects forged integrity tag" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    var token_buf: [32]u8 = undefined;
    const retry_pkt = try pair.server.issueRetry(pair.client.initial_dcid, pair.client.local_cid, &token_buf);
    defer std.testing.allocator.free(retry_pkt);
    // Corrupt the integrity tag (last 16 bytes).
    const corrupted = try std.testing.allocator.dupe(u8, retry_pkt);
    defer std.testing.allocator.free(corrupted);
    corrupted[corrupted.len - 1] ^= 0xff;
    try std.testing.expectError(error.AuthenticationFailed, pair.client.consumeRetry(corrupted));
}

test "N-3-adversarial consumeRetry rejects truncated/malformed bytes" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try std.testing.expectError(error.PacketTooShort, pair.client.consumeRetry(&.{}));
    try std.testing.expectError(error.PacketTooShort, pair.client.consumeRetry(&.{ 0xf0, 0x00 }));
    // Short header is not a Retry.
    const short = [_]u8{ 0x40, 0x01, 0x02, 0x03 };
    _ = pair.client.consumeRetry(&short) catch {};
}

/// Build a Retry packet by hand with a FRESH server CID as the Retry SCID —
/// the shape a real server issues (endpoint.rs:753-790), so the client must
/// re-key its Initials from a CID that differs from the original DCID.
fn craftRetry(
    allocator: std.mem.Allocator,
    original_dcid: packet.ConnectionId,
    client_scid: packet.ConnectionId,
    retry_scid: packet.ConnectionId,
    token: []const u8,
) ![]u8 {
    const tmp = try packet.buildRetry(allocator, 1, client_scid, retry_scid, token, .{0} ** 16);
    defer allocator.free(tmp);
    const tag = try initial_keys.retryIntegrityTag(allocator, original_dcid.slice(), tmp[0 .. tmp.len - 16]);
    return packet.buildRetry(allocator, 1, client_scid, retry_scid, token, tag);
}

test "E6: wire Retry — client re-keys from the Retry SCID, carries the token, and re-sends the ClientHello" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();

    // First flight: the client's Initial goes out tokenless.
    var now: Instant = 0;
    const first = (try pair.client.pollTransmit(now)) orelse return error.UnexpectedState;
    const first_hdr = try packet.decodeProtectedLongHeader(first.bytes, false);
    try std.testing.expectEqual(@as(usize, 0), first_hdr.token.len);
    try std.testing.expect(pair.client.crypto_sent[@intFromEnum(spaces.SpaceId.initial)] > 0);

    // A Retry arrives from the wire with a FRESH Retry SCID.
    const retry_scid = try packet.ConnectionId.init(&.{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 });
    const retry_pkt = try craftRetry(std.testing.allocator, pair.client.initial_dcid, pair.client.local_cid, retry_scid, "wire-token-16-bytes!");
    defer std.testing.allocator.free(retry_pkt);
    now += 1_000;
    try pair.client.handleDatagram(now, retry_pkt);
    try std.testing.expect(pair.client.retry_consumed);
    try std.testing.expectEqualSlices(u8, retry_scid.slice(), pair.client.remote_cid.slice());

    // The second flight: token on the wire, DCID = Retry SCID, CH re-sent
    // from offset 0, PN continuity (the reset must not restart the space).
    const second = (try pair.client.pollTransmit(now + 1)) orelse return error.UnexpectedState;
    const second_hdr = try packet.decodeProtectedLongHeader(second.bytes, false);
    try std.testing.expectEqualSlices(u8, "wire-token-16-bytes!", second_hdr.token);
    try std.testing.expectEqualSlices(u8, retry_scid.slice(), second_hdr.dst_cid.slice());

    // Decrypt the second Initial under keys derived from the RETRY SCID —
    // the exact thing a stateless noq server does (endpoint derives Initial
    // keys from the incoming Initial's DCID).
    const retry_secrets = initial_keys.deriveInitialSecrets(retry_scid.slice());
    const client_initial_keys = packet_crypto.keysFromTrafficSecret(&retry_secrets.client);
    var pkt_buf: [1500]u8 = undefined;
    @memcpy(pkt_buf[0..second.bytes.len], second.bytes);
    const pn_offset = second_hdr.pn_offset;
    try packet_crypto.decryptHeaderWithKeys(pkt_buf[0..second.bytes.len], pn_offset, client_initial_keys);
    const pn_len: usize = @as(usize, pkt_buf[0] & 0x03) + 1;
    const header_len = pn_offset + pn_len;
    var pn_val: u64 = 0;
    for (0..pn_len) |i| pn_val = (pn_val << 8) | pkt_buf[pn_offset + i];
    // PN continuity: the first flight was PN 0; the second flight continues.
    try std.testing.expectEqual(@as(u64, 1), pn_val);
    try packet_crypto.decryptPayload(pkt_buf[0..second.bytes.len], header_len, pn_val, client_initial_keys);
    // ...and NOT under keys derived from the ORIGINAL DCID: the payload AEAD
    // must reject them (wrong-secret negative control).
    const orig_secrets = initial_keys.deriveInitialSecrets(pair.client.initial_dcid.slice());
    const orig_keys = packet_crypto.keysFromTrafficSecret(&orig_secrets.client);
    var pkt_buf2: [1500]u8 = undefined;
    @memcpy(pkt_buf2[0..second.bytes.len], second.bytes);
    packet_crypto.decryptHeaderWithKeys(pkt_buf2[0..second.bytes.len], pn_offset, orig_keys) catch {};
    try std.testing.expectError(error.AuthenticationFailed, packet_crypto.decryptPayload(pkt_buf2[0..second.bytes.len], header_len, pn_val, orig_keys));

    // A SECOND Retry is silently discarded (at most one per attempt).
    const retry_pkt2 = try craftRetry(std.testing.allocator, pair.client.initial_dcid, pair.client.local_cid, retry_scid, "other-token-16byte");
    defer std.testing.allocator.free(retry_pkt2);
    now += 1_000;
    try pair.client.handleDatagram(now, retry_pkt2);
    try std.testing.expectEqualSlices(u8, "wire-token-16-bytes!", pair.client.initial_token);

    // A forged-tag Retry is silently discarded, connection unharmed.
    const forged = try std.testing.allocator.dupe(u8, retry_pkt2);
    defer std.testing.allocator.free(forged);
    forged[forged.len - 1] ^= 0xff;
    try pair.client.handleDatagram(now + 1, forged);
    try std.testing.expectEqualSlices(u8, "wire-token-16-bytes!", pair.client.initial_token);
    try std.testing.expect(pair.client.state == .handshake);
}

test "F5: a server minted from a DIFFERENT first flight than the client's is rejected (TP CID desync)" {
    const backend: crypto.Backend = if (crypto.picotls_enabled) .picotls else .zigtls;
    const client_key = key.SecretKey.fromBytes(.{0x41} ** 32);
    const server_a_key = key.SecretKey.fromBytes(.{0x42} ** 32);
    const client_cid = try packet.ConnectionId.init(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });
    const initial_dcid = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const server_name = tls_name.serverName(server_a_key.public());

    const client = try Connection.create(std.testing.allocator, .{
        .backend = backend,
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_a_key.public(),
        .server_name = &server_name,
    }, client_cid, initial_dcid, initial_dcid, testCsprngSeed(0xF501), .{});
    defer client.destroy();
    try client.startClient();

    // Flight 1 out; the client consumes a Retry toward Retry SCID R1.
    var now: Instant = 0;
    _ = (try client.pollTransmit(now)) orelse return error.UnexpectedState;
    const retry_scid_r1 = try packet.ConnectionId.init(&.{ 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8 });
    const retry_pkt = try craftRetry(std.testing.allocator, initial_dcid, client_cid, retry_scid_r1, "redirect-16-bytes");
    defer std.testing.allocator.free(retry_pkt);
    now += 1_000;
    try client.handleDatagram(now, retry_pkt);
    try std.testing.expectEqualSlices(u8, retry_scid_r1.slice(), client.remote_cid.slice());

    // The answering server fronts the SAME identity (A's key) but minted with
    // NO Retry context at all: its odcid will be R1 (this flight's DCID — NOT
    // the client's original X) and it sends no retry_scid. Both are REAL,
    // production-emitted TPs; the client's Retry context disagrees with them.
    // Keys derive from R1 on both sides, so only TP CID authentication (F5)
    // can catch the desync.
    const server_b_cid = try packet.ConnectionId.init(&.{ 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8 });
    const server_b = try Connection.create(std.testing.allocator, .{
        .backend = backend,
        .role = .server,
        .secret_key = server_a_key,
        .peer_public_key = client_key.public(),
        .require_client_authentication = true,
    }, server_b_cid, client_cid, retry_scid_r1, testCsprngSeed(0xF502), .{});
    defer server_b.destroy();

    const second = (try client.pollTransmit(now + 1)) orelse return error.UnexpectedState;
    now += 1_000;
    try server_b.handleDatagram(now, second.bytes);
    var rounds: usize = 0;
    while (rounds < 16) : (rounds += 1) {
        now += 1_000;
        while (try server_b.pollTransmit(now)) |tx| {
            client.handleDatagram(now + 1, tx.bytes) catch {};
        }
        if (client.state == .closed) break;
        while (try client.pollTransmit(now + 2)) |tx| {
            server_b.handleDatagram(now + 3, tx.bytes) catch {};
        }
        if (client.state == .closed) break;
    }
    try std.testing.expect(client.state == .closed);
    try std.testing.expectEqual(err_transport_parameter, client.close_frame.?.error_code);
    // The connection was NOT announced: no .connected event may survive.
    while (client.poll()) |ev| {
        try std.testing.expect(ev != .connected);
    }
}

test "F12: grease_quic_bit is advertised and fixed-bit-0 packets are accepted at the demux" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);

    // Both sides advertise the grease TP (noq default-on anti-ossification).
    try std.testing.expect(pair.client.local_params.grease_quic_bit);
    try std.testing.expect(pair.server.local_params.grease_quic_bit);
    try std.testing.expect(pair.client.peer_params.grease_quic_bit);
    try std.testing.expect(pair.server.peer_params.grease_quic_bit);

    // A greased (fixed-bit-0) Initial must parse at the demux — a greasing
    // noq peer's packets may not be dropped (F12's interop gap).
    const dcid = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    var buf: [64]u8 = .{0} ** 64;
    var index: usize = 0;
    try coding.writeU8(packet.long_header_form, &buf, &index); // fixed bit CLEAR
    try coding.writeU32(1, &buf, &index);
    try dcid.encodeLong(&buf, &index);
    try dcid.encodeLong(&buf, &index);
    try varint.encodeAppend(0, &buf, &index); // token len
    try varint.encodeAppend(20, &buf, &index); // length (covered by the zero tail)
    _ = try packet.decodeProtectedLongHeader(&buf, true);
    try std.testing.expectError(error.FixedBitUnset, packet.decodeProtectedLongHeader(&buf, false));
}

test "F17: server-only transport parameters from a client close TRANSPORT_PARAMETER_ERROR" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const cid = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });

    // Each server-only parameter, encoded → decoded → the PRODUCTION check
    // applyPeerParams gates on (called directly at the documented seam).
    for ([_]transport_parameters.TransportParameters{
        .{ .original_destination_connection_id = cid },
        .{ .retry_source_connection_id = cid },
        .{ .stateless_reset_token = [_]u8{0x5A} ** packet.stateless_reset_token_len },
        .{ .preferred_address = .{
            .ipv4 = .{ 127, 0, 0, 1 },
            .port_v4 = 4433,
            .ipv6 = ([_]u8{0} ** 15) ++ [_]u8{1},
            .port_v6 = 4434,
            .connection_id = cid,
            .stateless_reset_token = [_]u8{0x5A} ** packet.stateless_reset_token_len,
        } },
    }) |bad| {
        var buf: [256]u8 = undefined;
        const encoded = try (transport_parameters.TransportParameters{
            .initial_max_data = bad.initial_max_data,
            .original_destination_connection_id = bad.original_destination_connection_id,
            .retry_source_connection_id = bad.retry_source_connection_id,
            .stateless_reset_token = bad.stateless_reset_token,
            .preferred_address = bad.preferred_address,
        }).encode(&buf);
        const decoded = try transport_parameters.decode(encoded);
        try std.testing.expect(Connection.serverOnlyParamsPresent(decoded));
    }
    // A clean client TP block (none of the four) is not flagged.
    var clean_buf: [128]u8 = undefined;
    const clean = try transport_parameters.decode(try (transport_parameters.TransportParameters{
        .initial_max_data = 1024,
        .max_idle_timeout = 30_000,
        .initial_source_connection_id = cid,
    }).encode(&clean_buf));
    try std.testing.expect(!Connection.serverOnlyParamsPresent(clean));
    // And the honest pair's server-side view stays healthy (regression control).
    try std.testing.expect(pair.server.state == .established);

    // INTEGRATION leg (the review's F17-wiring finding): a client whose TP
    // block carries a server-only parameter drives the SERVER to close the
    // handshake with TRANSPORT_PARAMETER_ERROR — through the production
    // applyPeerParams call site, not just the predicate.
    const backend: crypto.Backend = if (crypto.picotls_enabled) .picotls else .zigtls;
    const client_key = key.SecretKey.fromBytes(.{0x71} ** 32);
    const server_key = key.SecretKey.fromBytes(.{0x72} ** 32);
    const client_cid = try packet.ConnectionId.init(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });
    const server_cid = try packet.ConnectionId.init(&.{ 0x51, 0x52, 0x53, 0x54 });
    const initial_dcid = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const server_name = tls_name.serverName(server_key.public());

    // Poison the client's emitted TP block with a server-only parameter via
    // the adversarial override seam (the production TLS ships it verbatim).
    var bad_buf: [256]u8 = undefined;
    const bad_bytes = try (transport_parameters.TransportParameters{
        .max_idle_timeout = 30_000,
        .initial_max_data = 1 << 20,
        .initial_source_connection_id = client_cid,
        .original_destination_connection_id = initial_dcid, // server-only!
    }).encode(&bad_buf);
    const client = try Connection.create(std.testing.allocator, .{
        .backend = backend,
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .server_name = &server_name,
        .adversarial_transport_params = bad_bytes,
    }, client_cid, initial_dcid, initial_dcid, testCsprngSeed(0xF17C), .{});
    defer client.destroy();
    const server = try Connection.create(std.testing.allocator, .{
        .backend = backend,
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = client_key.public(),
        .require_client_authentication = true,
    }, server_cid, client_cid, initial_dcid, testCsprngSeed(0xF175), .{});
    defer server.destroy();

    var pair2: TestPair = .{ .client = client, .server = server };
    try client.startClient();
    var now: Instant = 0;
    var rounds: usize = 0;
    while (rounds < 32 and server.state != .closed) : (rounds += 1) {
        now += 1_000_000;
        client.handleTimeout(now);
        server.handleTimeout(now);
        while (try client.pollTransmit(now)) |tx| {
            server.handleDatagram(now, tx.bytes) catch {};
        }
        while (try server.pollTransmit(now)) |tx| {
            client.handleDatagram(now, tx.bytes) catch {};
        }
        if (server.state == .established) break;
    }
    try std.testing.expect(server.state == .closed);
    try std.testing.expectEqual(err_transport_parameter, server.close_frame.?.error_code);
    _ = &pair2;
}

test "F13: OBSERVED_ADDR frames flow only within the negotiated roles" {
    const backend: crypto.Backend = if (crypto.picotls_enabled) .picotls else .zigtls;
    const client_key = key.SecretKey.fromBytes(.{0x51} ** 32);
    const server_key = key.SecretKey.fromBytes(.{0x52} ** 32);
    const client_cid = try packet.ConnectionId.init(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });
    const server_cid = try packet.ConnectionId.init(&.{ 0x51, 0x52, 0x53, 0x54 });
    const initial_dcid = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const server_name = tls_name.serverName(server_key.public());

    // QAD pair: the server reports (send_only), the client wants reports
    // (receive_only) — the draft-seemann negotiation.
    const client = try Connection.create(std.testing.allocator, .{
        .backend = backend,
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .server_name = &server_name,
    }, client_cid, initial_dcid, initial_dcid, testCsprngSeed(0xF13C), .{ .observed_addr_role = .receive_only });
    defer client.destroy();
    const server = try Connection.create(std.testing.allocator, .{
        .backend = backend,
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = client_key.public(),
        .require_client_authentication = true,
    }, server_cid, client_cid, initial_dcid, testCsprngSeed(0xF135), .{ .observed_addr_role = .send_only });
    defer server.destroy();

    var pair: TestPair = .{ .client = client, .server = server };
    try establishPair(&pair);
    try std.testing.expectEqual(transport_parameters.ObservedAddrRole.receive_only, client.local_params.observed_addr_role.?);
    try std.testing.expectEqual(transport_parameters.ObservedAddrRole.send_only, server.local_params.observed_addr_role.?);

    // Negotiated: server → client report flows (event surfaces).
    server.advertiseAddress(.{ .kind = .observed, .seq = 7, .ip = .{ 127, 0, 0, 9 }, .port = 7777 });
    var now: Instant = pair.client.now;
    var rounds: usize = 0;
    var got_report = false;
    while (rounds < 16 and !got_report) : (rounds += 1) {
        now += 1_000_000;
        pair.server.next_send_at = 0;
        pair.client.next_send_at = 0;
        while (try pair.server.pollTransmit(now)) |tx| try pair.client.handleDatagram(now, tx.bytes);
        while (try pair.client.pollTransmit(now)) |tx| try pair.server.handleDatagram(now, tx.bytes);
        while (pair.client.poll()) |ev| {
            switch (ev) {
                .nat_address => |a| {
                    if (a.kind == .observed and a.seq == 7) got_report = true;
                },
                else => {},
            }
        }
        server.drainEvents();
    }
    try std.testing.expect(got_report);

    // Reverse direction is NOT negotiated (client is receive_only): the
    // client's advertiseAddress must not reach the wire.
    client.advertiseAddress(.{ .kind = .observed, .seq = 8, .ip = .{ 127, 0, 0, 8 }, .port = 8888 });
    rounds = 0;
    while (rounds < 12) : (rounds += 1) {
        now += 1_000_000;
        pair.client.next_send_at = 0;
        while (try pair.client.pollTransmit(now)) |tx| try pair.server.handleDatagram(now, tx.bytes);
    }
    try std.testing.expect(server.state == .established);
    while (server.poll()) |ev| {
        try std.testing.expect(ev != .nat_address);
    }

    // An unnegotiated inbound OBSERVED_ADDR closes PROTOCOL_VIOLATION (the
    // fresh pair's roles are both absent).
    var plain = try makePair(std.testing.allocator, null);
    defer plain.deinit();
    try establishPair(&plain);
    var buf: [16]u8 = undefined;
    const f: frame.Frame = .{ .observed_ipv4_addr = .{ .seq = 1, .ip = .{ 127, 0, 0, 1 }, .port = 1 } };
    try plain.client.processPayload(.data, 9001, try f.encode(&buf), false);
    try std.testing.expect(plain.client.state == .closed);
    try std.testing.expectEqual(err_protocol_violation, plain.client.close_frame.?.error_code);
}

test "F8/F9/F11: preferred_address adoption is live, disable_active_migration decodes, min_ack_delay is emitted" {
    const pref_cid = try packet.ConnectionId.init(&.{ 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8 });
    const pref_token = [_]u8{0x77} ** packet.stateless_reset_token_len;
    // The server's TP block (caller-supplied path) carries preferred_address +
    // disable_active_migration onto the wire.
    var tp_buf: [256]u8 = undefined;
    const server_params = try (transport_parameters.TransportParameters{
        .max_idle_timeout = default_max_idle_timeout_ms,
        .initial_max_data = default_initial_max_data,
        .initial_max_stream_data_bidi_local = default_initial_max_stream_data,
        .initial_max_stream_data_bidi_remote = default_initial_max_stream_data,
        .initial_max_stream_data_uni = default_initial_max_stream_data,
        .initial_max_streams_bidi = default_initial_max_streams,
        .initial_max_streams_uni = default_initial_max_streams,
        .preferred_address = .{
            .ipv4 = .{ 192, 0, 2, 1 },
            .port_v4 = 4433,
            .ipv6 = ([_]u8{0} ** 15) ++ [_]u8{1},
            .port_v6 = 4434,
            .connection_id = pref_cid,
            .stateless_reset_token = pref_token,
        },
        .disable_active_migration = true,
    }).encode(&tp_buf);

    var pair = try makePair(std.testing.allocator, server_params);
    defer pair.deinit();
    try establishPair(&pair);

    // F8: the offered CID + reset token landed in the client's inventory
    // (retirement by the server's later NEW_CONNECTION_ID churn is the
    // standard lifecycle, not an install failure).
    var found = false;
    for (pair.client.remote_cids[0..pair.client.remote_cid_len]) |slot| {
        if (std.mem.eql(u8, slot.cid.slice(), pref_cid.slice())) {
            try std.testing.expectEqualSlices(u8, &pref_token, &slot.reset_token);
            found = true;
        }
    }
    try std.testing.expect(found);
    // F9: the flag decodes (Zig has no active migration to suppress — the
    // future migration code must consult peer_params.disable_active_migration).
    try std.testing.expect(pair.client.peer_params.disable_active_migration);
    // F11: min_ack_delay rides both directions (noq ack-frequency support).
    try std.testing.expectEqual(timer_granularity_us, pair.client.local_params.min_ack_delay.?);
    try std.testing.expect(pair.client.peer_params.min_ack_delay != null);
    try std.testing.expect(pair.server.peer_params.min_ack_delay != null);
}

test "PATH_CHALLENGE datagrams are padded to 1200 and re-driven with PTO backoff until validated" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);

    // A datagram carrying PATH_CHALLENGE is padded to 1200.
    pair.client.challengePath(.{ 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8 });
    var now: Instant = pair.client.now + 1_000_000;
    pair.client.next_send_at = 0;
    const probe = (try pair.client.pollTransmit(now)) orelse return error.UnexpectedState;
    try std.testing.expectEqual(@as(usize, min_client_initial_datagram_size), probe.bytes.len);

    // The server echoes a PATH_RESPONSE — also padded to 1200.
    try pair.server.handleDatagram(now, probe.bytes);
    now += 1_000_000;
    pair.server.next_send_at = 0;
    const echo = (try pair.server.pollTransmit(now)) orelse return error.UnexpectedState;
    try std.testing.expectEqual(@as(usize, min_client_initial_datagram_size), echo.bytes.len);
    try pair.client.handleDatagram(now, echo.bytes);
    try std.testing.expect(pair.client.pathValidated(.{ 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8 }));

    // An unanswered challenge is re-driven with PTO backoff, then stops.
    pair.server.challengePath(.{ 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8 });
    // Emit the first challenge (arms the retransmission clock).
    now += 1_000_000;
    pair.server.next_send_at = 0;
    _ = (try pair.server.pollTransmit(now)) orelse return error.UnexpectedState;
    try std.testing.expect(pair.server.timers.path_challenge_deadline != null);
    var redrives: usize = 0;
    var last_interval: i64 = 0;
    var backoff_grew = false;
    var attempt: usize = 0;
    while (attempt < 6) : (attempt += 1) {
        const d = pair.server.timers.path_challenge_deadline orelse break;
        const interval = d - now;
        if (last_interval != 0 and interval > last_interval) backoff_grew = true;
        last_interval = interval;
        // Drive to just past the deadline WITHOUT letting the client answer.
        now = d + 1;
        pair.server.handleTimeout(now);
        // The production re-drive: the unanswered challenge is re-queued.
        if (pair.server.challenge_pending_len > 0) {
            redrives += 1;
            pair.server.next_send_at = 0;
            _ = try pair.server.pollTransmit(now);
        }
    }
    try std.testing.expect(redrives >= 2);
    try std.testing.expect(backoff_grew);
    // After the attempt cap the clock stops (probe declared dead).
    try std.testing.expect(pair.server.timers.path_challenge_deadline == null);
    // The connection itself is unharmed (dead probe ≠ dead connection).
    try std.testing.expect(pair.server.state == .established);
}

test "IPv6 n0 NAT frames decode + surface (no UnsupportedFrameType close), codec round-trips" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);

    // Codec round-trip: v6 add/reach_out encode → decode → re-encode equal.
    var buf: [64]u8 = undefined;
    const v6ip = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ ([_]u8{0} ** 11) ++ [_]u8{1};
    const add6: frame.Frame = .{ .add_ipv6_address = .{ .seq = 9, .ip = v6ip, .port = 4433 } };
    const reach6: frame.Frame = .{ .reach_out_at_ipv6 = .{ .seq = 10, .ip = v6ip, .port = 4434 } };
    for ([_]frame.Frame{ add6, reach6 }) |f| {
        const encoded = try f.encode(&buf);
        var check: [64]u8 = undefined;
        const decoded = try frame.decode(encoded);
        try std.testing.expectEqualSlices(u8, encoded, try decoded.encode(&check));
        try std.testing.expectEqual(f.frameType(), decoded.frameType());
    }

    // On the wire: a v6 ADD_ADDRESS surfaces as a v6 event — no connection
    // close (the previous behavior closed on UnsupportedFrameType).
    const f: frame.Frame = .{ .add_ipv6_address = .{ .seq = 3, .ip = v6ip, .port = 4433 } };
    try pair.client.processPayload(.data, 9201, try f.encode(&buf), false);
    try std.testing.expect(pair.client.state == .established);
    var got6 = false;
    while (pair.client.poll()) |ev| {
        switch (ev) {
            .nat_address => |a| {
                if (a.kind == .add and a.seq == 3) {
                    try std.testing.expectEqualSlices(u8, &v6ip, &a.ip6.?);
                    try std.testing.expectEqual(@as(u16, 4433), a.port);
                    got6 = true;
                }
            },
            else => {},
        }
    }
    try std.testing.expect(got6);
    const r: frame.Frame = .{ .reach_out_at_ipv6 = .{ .seq = 4, .ip = v6ip, .port = 4434 } };
    try pair.client.processPayload(.data, 9202, try r.encode(&buf), false);
    try std.testing.expect(pair.client.state == .established);
}

test "OBSERVED_ADDR reports are seq-gated (stale and duplicate reports drop)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // QAD roles negotiated by hand for the gate (receive on the client side).
    pair.client.local_params.observed_addr_role = .receive_only;
    pair.server.local_params.observed_addr_role = .send_only;
    pair.client.peer_params.observed_addr_role = .send_only;

    var buf: [16]u8 = undefined;
    const f5: frame.Frame = .{ .observed_ipv4_addr = .{ .seq = 5, .ip = .{ 127, 0, 0, 1 }, .port = 1 } };
    const f3: frame.Frame = .{ .observed_ipv4_addr = .{ .seq = 3, .ip = .{ 127, 0, 0, 2 }, .port = 2 } };
    const f5b: frame.Frame = .{ .observed_ipv4_addr = .{ .seq = 5, .ip = .{ 127, 0, 0, 3 }, .port = 3 } };
    const f6: frame.Frame = .{ .observed_ipv4_addr = .{ .seq = 6, .ip = .{ 127, 0, 0, 4 }, .port = 4 } };

    try pair.client.processPayload(.data, 9101, try f5.encode(&buf), false);
    try pair.client.processPayload(.data, 9102, try f3.encode(&buf), false); // older: drop
    try pair.client.processPayload(.data, 9103, try f5b.encode(&buf), false); // equal: drop
    try pair.client.processPayload(.data, 9104, try f6.encode(&buf), false); // newer: surface

    var seen: usize = 0;
    var last_seq: u64 = 0;
    while (pair.client.poll()) |ev| {
        switch (ev) {
            .nat_address => |a| {
                if (a.kind == .observed) {
                    seen += 1;
                    last_seq = a.seq;
                }
            },
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 2), seen);
    try std.testing.expectEqual(@as(u64, 6), last_seq);
    try std.testing.expectEqual(@as(u64, 6), pair.client.last_observed_seq.?);
}

test "F5 arms: verifyPeerCids accepts exactly the handshake's CIDs (iscid / odcid / retry_scid)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const client = pair.client;
    const correct_iscid = pair.server.local_cid;

    // The honest handshake's TPs authenticate (regression control).
    try std.testing.expect(client.verifyPeerCids(.{
        .initial_source_connection_id = correct_iscid,
        .original_destination_connection_id = client.initial_dcid,
    }));
    // iscid wrong or absent → reject (the desync the RFC defends against).
    try std.testing.expect(!client.verifyPeerCids(.{
        .initial_source_connection_id = client.local_cid,
        .original_destination_connection_id = client.initial_dcid,
    }));
    try std.testing.expect(!client.verifyPeerCids(.{
        .original_destination_connection_id = client.initial_dcid,
    }));
    // odcid wrong or absent → reject (client-side, RFC 9000 §7.3).
    try std.testing.expect(!client.verifyPeerCids(.{
        .initial_source_connection_id = correct_iscid,
        .original_destination_connection_id = client.local_cid,
    }));
    try std.testing.expect(!client.verifyPeerCids(.{
        .initial_source_connection_id = correct_iscid,
    }));
    // retry_scid present without a consumed Retry → reject.
    try std.testing.expect(!client.verifyPeerCids(.{
        .initial_source_connection_id = correct_iscid,
        .original_destination_connection_id = client.initial_dcid,
        .retry_source_connection_id = client.local_cid,
    }));

    // A client that DID consume a Retry: retry_scid must match exactly.
    var pair2 = try makePair(std.testing.allocator, null);
    defer pair2.deinit();
    try pair2.client.startClient();
    const retry_scid = try packet.ConnectionId.init(&.{ 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8 });
    const retry_pkt = try craftRetry(std.testing.allocator, pair2.client.initial_dcid, pair2.client.local_cid, retry_scid, "retry-token-16byt");
    defer std.testing.allocator.free(retry_pkt);
    try pair2.client.consumeRetry(retry_pkt);
    // The first answering server Initial pins the server's CID (noq's
    // original_remote_cid assignment) — simulate that sequencing here.
    pair2.client.initial_remote_cid = pair2.server.local_cid;
    try std.testing.expect(pair2.client.verifyPeerCids(.{
        .initial_source_connection_id = pair2.server.local_cid,
        .original_destination_connection_id = pair2.client.initial_dcid,
        .retry_source_connection_id = retry_scid,
    }));
    try std.testing.expect(!pair2.client.verifyPeerCids(.{
        .initial_source_connection_id = pair2.server.local_cid,
        .original_destination_connection_id = pair2.client.initial_dcid,
    }));
    try std.testing.expect(!pair2.client.verifyPeerCids(.{
        .initial_source_connection_id = pair2.server.local_cid,
        .original_destination_connection_id = pair2.client.initial_dcid,
        .retry_source_connection_id = pair2.client.local_cid,
    }));

    // Server role: iscid is checked too (the client's own SCID).
    try std.testing.expect(pair.server.verifyPeerCids(.{
        .initial_source_connection_id = pair.client.local_cid,
    }));
    try std.testing.expect(!pair.server.verifyPeerCids(.{
        .initial_source_connection_id = pair.server.local_cid,
    }));
}

test "N-3-adversarial stateless reset wrong token does not drain" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    var wrong: [packet.stateless_reset_token_len]u8 = undefined;
    @memset(&wrong, 0x5a);
    // Ensure it differs from the real token.
    if (std.mem.eql(u8, &wrong, &pair.client.statelessResetToken())) wrong[0] ^= 0xff;
    const reset_pkt = try packet.generateStatelessReset(wrong, &.{ 0x01, 0x02, 0x03, 0x04, 0x05 });
    defer std.heap.page_allocator.free(reset_pkt);
    // Wrong token: detectStatelessReset is false; may fall into short-packet decrypt
    // and return DecryptFailed — still MUST NOT enter draining (token mismatch).
    _ = pair.client.handleDatagram(1_000_000, reset_pkt) catch {};
    try std.testing.expect(pair.client.state == .established);
}

test "N-3-adversarial forged stateless reset with real token drains (positive control)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // Must use the PEER token; our own token is never the detection key.
    const peer_token = pair.server.statelessResetToken();
    pair.client.peer_stateless_reset_token = peer_token;
    var reset_pkt: [32]u8 = undefined;
    @memset(&reset_pkt, 0xde);
    reset_pkt[0] = packet.fixed_bit;
    @memcpy(reset_pkt[reset_pkt.len - packet.stateless_reset_token_len ..], &peer_token);
    try pair.client.handleDatagram(2_000_000, &reset_pkt);
    try std.testing.expect(pair.client.state == .draining);
}

test "N-3-adversarial RETIRE_CONNECTION_ID unknown sequence is a no-op not a crash" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    var buf: [16]u8 = undefined;
    const f: frame.Frame = .{ .retire_connection_id = .{ .sequence = 0xffff_ffff } };
    try pair.client.processPayload(.data, 3001, try f.encode(&buf), false);
    try std.testing.expect(pair.client.state == .established);
}

// ── N2 characterization (reorient-noq): pin footguns the interop net misses ──
// draining → drained is gated by TimerTable.armClose (= now + 3×max_pto_ns).
// Existing N-2 only asserts the idle→draining edge + connection_lost event.
test "N2 char: draining advances to drained at close_deadline (3×max_pto)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();

    // Shrink PTO so the close timer is deterministic without sleeping.
    pair.client.timers.max_pto_ns = 1_000_000; // 1 ms
    const idle = idleTimeoutNs(default_max_idle_timeout_ms).?;
    pair.client.armIdle(0);
    pair.client.handleTimeout(idle + 1);
    try std.testing.expect(pair.client.state == .draining);
    const close_at = pair.client.timers.close_deadline.?;
    try std.testing.expectEqual(idle + 1 + 3 * pair.client.timers.max_pto_ns, close_at);

    // One tick before close: still draining; transmit may still run close path.
    pair.client.handleTimeout(close_at - 1);
    try std.testing.expect(pair.client.state == .draining);

    pair.client.handleTimeout(close_at);
    try std.testing.expect(pair.client.state == .drained);
    // drained: no further transmits.
    try std.testing.expect(try pair.client.pollTransmit(close_at) == null);
}

// Event.stream_data.data borrows into StreamRecv.data. After pruneConsumed
// (the production readStreamInto path), that slice is not a stable view of
// the original payload. Shipping transport_noq ignores stream_data and re-reads
// via readStreamInto — this pins the footgun so a future "hold the event"
// consumer cannot silently regress.
test "N2 char: Event.stream_data borrow is invalidated by pruneConsumed" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.server.drainEvents();

    const e = try pair.server.getOrCreateStream(0);
    e.recv.max_data = 1 << 20;
    const payload = "ABCDEFGHIJKLMNOP"; // 16 bytes
    const added = try e.recv.ingest(std.testing.allocator, 0, payload, false);
    try std.testing.expectEqual(@as(usize, 16), added);
    // Mirror connection.onStream emission: slice into the contiguous recv buffer.
    const new_slice = e.recv.data.items[e.recv.data.items.len - added ..];
    try pair.server.events.pushBack(std.testing.allocator, .{ .stream_data = .{
        .id = 0,
        .data = new_slice,
        .fin = false,
    } });
    const ev = pair.server.poll().?;
    try std.testing.expect(std.meta.activeTag(ev) == .stream_data);
    const held = ev.stream_data.data;
    try std.testing.expectEqualStrings(payload, held);

    // Production read path: copy out + prune consumed prefix.
    var out: [8]u8 = undefined;
    const n = pair.server.readStreamInto(0, &out);
    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqualStrings("ABCDEFGH", out[0..n]);

    // After prune, the held event slice must not be treated as still equal to
    // the original payload (buffer contents relocated / shortened).
    const still_matches = held.len == payload.len and std.mem.eql(u8, held, payload);
    try std.testing.expect(!still_matches);
}

// ── Noq+discovery hardening mutation-RED unit tests ────────────────

test "ack_delay is scaled by 2^ack_delay_exponent and capped" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    // Peer advertises exponent 3 (default) and max_ack_delay 25 ms.
    pair.client.peer_params.ack_delay_exponent = 3;
    pair.client.peer_params.max_ack_delay = 25;
    pair.client.peer_params_applied = true;
    // Wire delay = 1000 → 1000 << 3 = 8000 µs = 8_000_000 ns (under 25 ms cap).
    const scaled = pair.client.scaledAckDelayNs(.data, 1000);
    try std.testing.expectEqual(@as(i64, 8_000_000), scaled);
    // Cap: huge wire delay must not exceed max_ack_delay (25 ms = 25_000_000 ns).
    const capped = pair.client.scaledAckDelayNs(.data, 1 << 20);
    try std.testing.expectEqual(@as(i64, 25_000_000), capped);
    // Non-data spaces ignore wire delay (RFC 9002 §5).
    try std.testing.expectEqual(@as(i64, 0), pair.client.scaledAckDelayNs(.initial, 1000));
    try std.testing.expectEqual(@as(i64, 0), pair.client.scaledAckDelayNs(.handshake, 1000));
}

test "data-space PTO includes peer max_ack_delay" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.peer_params.max_ack_delay = 25; // ms
    pair.client.peer_params_applied = true;
    pair.client.rtt = loss.RttEstimator.init(100_000_000); // 100 ms
    // G14: a data-space PTO only arms once the handshake is confirmed.
    pair.client.handshake_confirmed = true;
    // Seed one outstanding data-space ack-eliciting packet.
    try pair.client.sent.append(std.testing.allocator, .{
        .path_generation = 0,
        .time_sent = 0,
        .size = 100,
        .ack_eliciting = true,
        .packet_number = 0,
        .space = .data,
    });
    const deadline = pair.client.ptoDeadline().?;
    const cap = pair.client.ptoMaxIntervalNs();
    const without_mad = loss.ptoDelay(pair.client.rtt, 0, 0, cap);
    const with_mad = loss.ptoDelay(pair.client.rtt, 0, pair.client.peerMaxAckDelayNs(), cap);
    try std.testing.expect(with_mad > without_mad);
    try std.testing.expectEqual(with_mad, deadline);
}

test "own-token reset is ignored; peer-token RFC-shape drains" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // Own token + fixed bit clear (old buggy detector shape) must NOT drain.
    // May fail short-header decrypt (unknown DCID) — that is fine; state stays established.
    const own = pair.client.statelessResetToken();
    var own_pkt: [32]u8 = undefined;
    @memset(&own_pkt, 0x11);
    own_pkt[0] = 0; // fixed bit clear
    @memcpy(own_pkt[own_pkt.len - 16 ..], &own);
    _ = pair.client.handleDatagram(1_000_000, &own_pkt) catch {};
    try std.testing.expect(pair.client.state == .established);

    // Peer token + fixed bit SET (RFC shape) drains.
    const peer = pair.server.statelessResetToken();
    pair.client.peer_stateless_reset_token = peer;
    var peer_pkt: [32]u8 = undefined;
    @memset(&peer_pkt, 0x22);
    peer_pkt[0] = packet.fixed_bit;
    @memcpy(peer_pkt[peer_pkt.len - 16 ..], &peer);
    try pair.client.handleDatagram(2_000_000, &peer_pkt);
    try std.testing.expect(pair.client.state == .draining);
}

test "connection CSPRNG is DefaultCsprng not Pcg" {
    // Type-level pin: field is DefaultCsprng. A revert to Pcg fails to compile
    // this assertion's type check.
    const T = @TypeOf(@as(Connection, undefined).rng);
    try std.testing.expect(T == std.Random.DefaultCsprng);
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    // Tokens are non-zero with high probability under a real CSPRNG stream.
    var nonzero: usize = 0;
    for (pair.server.statelessResetToken()) |b| {
        if (b != 0) nonzero += 1;
    }
    try std.testing.expect(nonzero > 0);
}

test "long-header non-v1 is skipped without erroring the connection" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // Long header, version 0xdeadbeef, minimal skeleton — must not crash/close.
    var bogus: [20]u8 = .{0} ** 20;
    bogus[0] = packet.long_header_form | packet.fixed_bit; // Initial-ish
    std.mem.writeInt(u32, bogus[1..5], 0xdeadbeef, .big);
    bogus[5] = 0; // dcid len
    bogus[6] = 0; // scid len
    // token len + length varints = 0
    try pair.client.handleDatagram(1_000_000, &bogus);
    try std.testing.expect(pair.client.state == .established);
}

test "shortHeaderPnOffset matches rotated local CID length" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    // Primary local CID is 4 bytes (makePair).
    try std.testing.expectEqual(@as(u8, 4), pair.server.local_cid.len);
    // Inject an 8-byte rotated local CID into the registry.
    const rotated = try packet.ConnectionId.init(&.{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 });
    pair.server.local_cids[pair.server.local_cid_len] = .{
        .sequence = 1,
        .cid = rotated,
        .reset_token = .{0xab} ** 16,
    };
    pair.server.local_cid_len += 1;
    var dgram: [20]u8 = .{0} ** 20;
    dgram[0] = packet.fixed_bit;
    @memcpy(dgram[1..9], rotated.slice());
    const off = pair.server.shortHeaderPnOffset(&dgram).?;
    try std.testing.expectEqual(@as(usize, 1 + 8), off);
    // Mismatching DCID returns null.
    dgram[1] ^= 0xff;
    try std.testing.expect(pair.server.shortHeaderPnOffset(&dgram) == null);
}

test "ACK of never-sent PN is PROTOCOL_VIOLATION" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // next_pn for data is some small value after handshake; ACK a huge PN.
    const next = pair.client.spaces_state.getConst(.data).next_pn;
    pair.client.onAck(.data, .{
        .largest_acked = next + 1000,
        .ack_delay = 0,
        .first_range = 0,
    });
    try std.testing.expect(pair.client.close_frame != null);
    try std.testing.expectEqual(err_protocol_violation, pair.client.close_frame.?.error_code);
}

// ── A9: CRYPTO reassembly (noq read_crypto, connection/mod.rs:4009-4059) ────

fn dropServerFlight(_: usize, from_client: bool) bool {
    return !from_client;
}

test "A9: out-of-order CRYPTO is buffered and reassembled in order" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();
    // Deliver the client's Initial but drop the server's flight, so the
    // server's Initial CRYPTO (ServerHello) exists only in server.crypto_out.
    const now: Instant = 1_000_000;
    var pkt_idx: usize = 0;
    try pumpOnce(&pair, now, &pkt_idx, dropServerFlight);
    const si = @intFromEnum(spaces.SpaceId.initial);
    const bytes = pair.server.crypto_out[si].items;
    try std.testing.expect(bytes.len > 4);
    // Split near the end: zigtls requires at least one complete TLS handshake
    // message in the first feedTls call, so the head must be large enough to
    // contain the full ServerHello. A 4-byte tail still proves reassembly.
    const split = bytes.len - 4;
    var buf: [4096]u8 = undefined;

    // Tail first (out of order): buffered, nothing fed to TLS.
    const tail = frame.Frame{ .crypto = .{ .offset = split, .data = bytes[split..] } };
    try pair.client.processPayload(.initial, 100, try tail.encode(&buf), false);
    try std.testing.expectEqual(@as(u64, 0), pair.client.crypto_in_offset[si]);
    try std.testing.expectEqual(@as(usize, 1), pair.client.crypto_in_pending[si].items.len);

    // Duplicate tail: tolerated, no buffer growth (defrag trim).
    try pair.client.processPayload(.initial, 101, try tail.encode(&buf), false);
    try std.testing.expectEqual(@as(u64, 0), pair.client.crypto_in_offset[si]);
    try std.testing.expectEqual(@as(usize, 1), pair.client.crypto_in_pending[si].items.len);

    // Head: feeds the head, then drains the buffered tail contiguously.
    const head = frame.Frame{ .crypto = .{ .offset = 0, .data = bytes[0..split] } };
    try pair.client.processPayload(.initial, 102, try head.encode(&buf), false);
    try std.testing.expectEqual(@as(u64, bytes.len), pair.client.crypto_in_offset[si]);
    try std.testing.expectEqual(@as(usize, 0), pair.client.crypto_in_pending[si].items.len);
    // Real evidence the bytes reached TLS: consuming the ServerHello installs
    // the handshake keys (client can now read/write the Handshake space).
    try std.testing.expect(pair.client.read_keys[@intFromEnum(spaces.SpaceId.handshake)] != null);
    try std.testing.expect(pair.client.write_keys[@intFromEnum(spaces.SpaceId.handshake)] != null);
}

test "A9: CRYPTO past the 16 KiB buffer bound is CRYPTO_BUFFER_EXCEEDED" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();
    const si = @intFromEnum(spaces.SpaceId.initial);
    var buf: [64]u8 = undefined;

    // At the bound (end - consumed == max_crypto_buf): accepted and buffered.
    const at_bound = frame.Frame{ .crypto = .{ .offset = max_crypto_buf - 1, .data = "x" } };
    try pair.client.processPayload(.initial, 100, try at_bound.encode(&buf), false);
    try std.testing.expect(pair.client.close_frame == null);
    try std.testing.expectEqual(@as(usize, 1), pair.client.crypto_in_pending[si].items.len);

    // Past the bound: CRYPTO_BUFFER_EXCEEDED (RFC 9000 §20.1 code 0x0d).
    const past = frame.Frame{ .crypto = .{ .offset = max_crypto_buf + 1, .data = "x" } };
    try pair.client.processPayload(.initial, 101, try past.encode(&buf), false);
    try std.testing.expect(pair.client.close_frame != null);
    try std.testing.expectEqual(err_crypto_buffer_exceeded, pair.client.close_frame.?.error_code);
}

test "A9: new CRYPTO data at a stale level is PROTOCOL_VIOLATION" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const si = @intFromEnum(spaces.SpaceId.initial);
    var buf: [64]u8 = undefined;

    // Retransmit of already-consumed Initial bytes on an established
    // connection: tolerated (noq only rejects NEW data at a stale level).
    const old = frame.Frame{ .crypto = .{ .offset = 0, .data = pair.server.crypto_out[si].items[0..1] } };
    try pair.client.processPayload(.initial, 9000, try old.encode(&buf), false);
    try std.testing.expect(pair.client.close_frame == null);

    // New Initial-space data once the handshake completed (expected level is
    // Data): PROTOCOL_VIOLATION.
    const consumed = pair.client.crypto_in_offset[si];
    const stale = frame.Frame{ .crypto = .{ .offset = consumed, .data = "zz" } };
    try pair.client.processPayload(.initial, 9001, try stale.encode(&buf), false);
    try std.testing.expect(pair.client.close_frame != null);
    try std.testing.expectEqual(err_protocol_violation, pair.client.close_frame.?.error_code);
}

// ── A5: handshake anti-deadlock PTO probe (noq mod.rs:3210-3243 + spaces.rs:97) ──

test "A5: client with zero in-flight pre-validation sends one PING probe on PTO" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();
    const si = @intFromEnum(spaces.SpaceId.initial);

    // Client sends its Initial (ack-eliciting, in flight).
    const t0: Instant = 1_000_000;
    const tx = (try pair.client.pollTransmit(t0)).?;
    try std.testing.expect(tx.bytes.len >= min_client_initial_datagram_size);
    try std.testing.expectEqual(@as(usize, 1), pair.client.sent.items.len);

    // The server ACKs that Initial (via the real ACK path) but then goes
    // silent — nothing outstanding, handshake not validated: the deadlock
    // shape RFC 9000 §8.1 / noq pto_time_and_space guards against.
    pair.client.onAck(.initial, .{ .largest_acked = 0, .ack_delay = 0, .first_range = 0 });
    try std.testing.expectEqual(@as(usize, 0), pair.client.sent.items.len);

    // The PTO stays armed even with zero in flight (server never arms it).
    const deadline = pair.client.ptoDeadline() orelse return error.UnexpectedState;
    try std.testing.expect(deadline > t0);
    try std.testing.expect(pair.server.ptoDeadline() == null);

    // PTO fires → exactly one ack-eliciting probe is emitted: an Initial
    // packet carrying a PING (no retransmittable content).
    pair.client.handleTimeout(deadline);
    const probe = (try pair.client.pollTransmit(deadline)).?;
    try std.testing.expect(probe.bytes.len >= min_client_initial_datagram_size);
    try std.testing.expectEqual(@as(usize, 1), pair.client.sent.items.len);
    const sent = pair.client.sent.items[0];
    try std.testing.expect(sent.ack_eliciting);
    try std.testing.expectEqual(spaces.SpaceId.initial, sent.space);
    try std.testing.expectEqual(@as(u8, 0), sent.content_len); // PING carries no content
    try std.testing.expectEqual(@as(u64, 1), pair.client.stats_pto_events);
    try std.testing.expectEqual(@as(u32, 1), pair.client.pto_count);

    // One probe per PTO: nothing more until the next (backed-off) PTO fires.
    try std.testing.expect(pair.client.pending_ping[si] == false);
    const deadline2 = pair.client.ptoDeadline() orelse return error.UnexpectedState;
    try std.testing.expect(deadline2 > deadline);
    pair.client.handleTimeout(deadline2);
    _ = (try pair.client.pollTransmit(deadline2)).?;
    try std.testing.expectEqual(@as(u64, 2), pair.client.stats_pto_events);
}

test "A5: established client with nothing outstanding does not arm anti-deadlock PTO" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    // Validated + established: the anti-deadlock arm is off on both roles
    // (any ptoDeadline still armed is the normal outstanding-packet PTO).
    try std.testing.expect(pair.client.antiDeadlockSpace() == null);
    try std.testing.expect(pair.server.antiDeadlockSpace() == null);
}

// ── A17: optimistic-ACK defense (noq PacketNumberFilter, spaces.rs:1329-1373) ──

test "A17: Data space skips a random PN; ACK of the skipped PN is PROTOCOL_VIOLATION" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const client = pair.client;

    // The filter is armed on the Data space only (noq spaces.rs:306-309).
    try std.testing.expect(client.spaces_state.getConst(.data).pn_filter != null);
    try std.testing.expect(client.spaces_state.getConst(.initial).pn_filter == null);
    try std.testing.expect(client.spaces_state.getConst(.handshake).pn_filter == null);

    // Force the next allocation to be the scheduled skip (deterministic).
    const pns = client.spaces_state.get(.data);
    const skipped = pns.next_pn;
    pns.pn_filter.?.next_skipped = skipped;

    // Wire-observable: the allocated PN jumps over the skipped one — the peer
    // sees a packet-number gap, exactly like noq.
    const used = client.allocTxNumber(.data);
    try std.testing.expectEqual(skipped + 1, used);
    try std.testing.expectEqual(skipped + 2, client.spaces_state.getConst(.data).next_pn);
    try std.testing.expectEqual(skipped, client.spaces_state.getConst(.data).pn_filter.?.prev_skipped.?);

    // Legitimate ACK covering only the packet actually "sent": accepted.
    client.onAck(.data, .{ .largest_acked = used, .ack_delay = 0, .first_range = 0 });
    try std.testing.expect(client.close_frame == null);

    // ACK whose range also covers the skipped/unsent PN: optimistic-ACK
    // attack → PROTOCOL_VIOLATION ("unsent packet acked").
    client.onAck(.data, .{ .largest_acked = used, .ack_delay = 0, .first_range = 1 });
    try std.testing.expect(client.close_frame != null);
    try std.testing.expectEqual(err_protocol_violation, client.close_frame.?.error_code);
}

test "A11: client terminates version-mismatch on VN without a supported version" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    // Fresh client: nothing authenticated yet, handshake in flight.
    try std.testing.expect(pair.client.state == .handshake);

    const vn = try packet.buildVersionNegotiation(
        std.testing.allocator,
        pair.client.local_cid,
        try packet.ConnectionId.init(&.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }),
        packet.fixed_bit,
        &.{0x0a1a2a3a}, // grease only — no version we support
    );
    defer std.testing.allocator.free(vn);

    try pair.client.handleDatagram(1_000_000, vn);
    // Local termination (noq VersionMismatch → draining), NOT a protocol close.
    try std.testing.expect(pair.client.state == .draining);
    try std.testing.expect(pair.client.close_frame == null);
    const ev = pair.client.poll().?;
    try std.testing.expect(std.meta.activeTag(ev) == .connection_lost);
    try std.testing.expectEqualStrings("version-mismatch", ev.connection_lost.reason);
    try std.testing.expect(ev.connection_lost.is_local);
}

test "A11: client ignores VN listing version 1; server ignores VN entirely" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.drainEvents();

    const vn = try packet.buildVersionNegotiation(
        std.testing.allocator,
        pair.client.local_cid,
        try packet.ConnectionId.init(&.{ 0x11, 0x12 }),
        packet.fixed_bit,
        &.{ 0x0a1a2a3a, 1 }, // grease + a version we support → forgery, ignore
    );
    defer std.testing.allocator.free(vn);

    try pair.client.handleDatagram(1_000_000, vn);
    try std.testing.expect(pair.client.state == .handshake);
    try std.testing.expect(pair.client.poll() == null);

    try pair.server.handleDatagram(1_000_000, vn);
    try std.testing.expect(pair.server.state == .handshake);
}

test "A11: client ignores forged VN after authenticating packets" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.client.drainEvents();
    try std.testing.expect(pair.client.total_authed_packets > 1);

    const vn = try packet.buildVersionNegotiation(
        std.testing.allocator,
        pair.client.local_cid,
        try packet.ConnectionId.init(&.{ 0x21, 0x22 }),
        packet.fixed_bit,
        &.{0x0a1a2a3a}, // no supported version, but forged post-handshake
    );
    defer std.testing.allocator.free(vn);

    try pair.client.handleDatagram(1_000_000, vn);
    try std.testing.expect(pair.client.state == .established);
    try std.testing.expect(pair.client.poll() == null);
}

// ── A3: send-side datagram coalescing (noq poll_transmit_path_space, mod.rs:1739-1758) ──

const CoalesceWalk = struct {
    initial: usize = 0,
    handshake: usize = 0,
    short: usize = 0,
    packets: usize = 0,
};

/// Walk a (possibly coalesced) datagram the same way `handleDatagram` does:
/// long-header packets delimited by their own Length fields, then one
/// trailing short-header packet running to the end of the datagram.
fn walkCoalesced(d: []const u8) !CoalesceWalk {
    var w: CoalesceWalk = .{};
    var off: usize = 0;
    while (off < d.len) {
        if ((d[off] & packet.long_header_form) != 0) {
            const ph = try packet.decodeProtectedLongHeader(d[off..], true);
            switch (ph.long_type) {
                .initial => w.initial += 1,
                .handshake => w.handshake += 1,
                else => {},
            }
            w.packets += 1;
            off += ph.packet_end;
        } else {
            w.short += 1;
            w.packets += 1;
            break;
        }
    }
    return w;
}

test "A3: server first flight coalesces Initial+Handshake into one datagram, peer still establishes" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();

    // Client Initial → server.
    var now: Instant = 1_000_000;
    while (try pair.client.pollTransmit(now)) |tx| try pair.server.handleDatagram(now, tx.bytes);

    // The server's first datagram must carry both long-header spaces (noq
    // handshake flights are one datagram per space-prefix, mod.rs:1739-1758).
    const first = (try pair.server.pollTransmit(now)).?;
    try std.testing.expectEqual(min_client_initial_datagram_size, first.bytes.len);
    const w = try walkCoalesced(first.bytes);
    try std.testing.expectEqual(@as(usize, 1), w.initial);
    try std.testing.expectEqual(@as(usize, 1), w.handshake);
    try std.testing.expectEqual(@as(usize, 2), w.packets);
    try std.testing.expect(pair.server.stats_coalesced_packets > 0);
    try pair.client.handleDatagram(now, first.bytes);

    // The rest of the handshake completes over coalesced flights, proving the
    // receive path and the send path interoperate end to end.
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    while (rounds < 32 and !(pair.client.state == .established and pair.server.state == .established)) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expect(pair.client.state == .established);
    try std.testing.expect(pair.server.state == .established);
    // The handshake exercised coalescing on both directions' flights and
    // never needed the stash safety net.
    try std.testing.expect(pair.client.stats_coalesced_packets > 0);
    try std.testing.expectEqual(@as(u64, 0), pair.client.stats_coalesce_stashed);
    try std.testing.expectEqual(@as(u64, 0), pair.server.stats_coalesce_stashed);
}

test "A3: client flight after server Initial is one 1200-byte Initial+Handshake datagram" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();

    var now: Instant = 1_000_000;
    while (try pair.client.pollTransmit(now)) |tx| try pair.server.handleDatagram(now, tx.bytes);
    while (try pair.server.pollTransmit(now)) |tx| try pair.client.handleDatagram(now, tx.bytes);

    // RFC 9000 §14.1 via noq's PadDatagram::ToMinMtu (mod.rs:1603-1608): the
    // datagram floor is carried to the LAST packet, so the coalesced datagram
    // is exactly 1200 — a padded-first-packet implementation would exceed it.
    const tx = (try pair.client.pollTransmit(now)).?;
    try std.testing.expectEqual(min_client_initial_datagram_size, tx.bytes.len);
    const w = try walkCoalesced(tx.bytes);
    try std.testing.expectEqual(@as(usize, 1), w.initial);
    try std.testing.expectEqual(@as(usize, 1), w.handshake);
    try std.testing.expectEqual(@as(usize, 2), w.packets);

    // Feed it: the server must accept the coalesced flight and both sides
    // must still establish.
    try pair.server.handleDatagram(now, tx.bytes);
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    while (rounds < 32 and !(pair.client.state == .established and pair.server.state == .established)) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expect(pair.client.state == .established);
    try std.testing.expect(pair.server.state == .established);
}

test "A3: no coalescing means a lone client Initial keeps its own 1200 pad (control)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();

    // First flight: no Handshake keys yet, so no coalescing is possible and
    // the Initial datagram must be padded by itself, exactly as before A3.
    const tx = (try pair.client.pollTransmit(1_000_000)).?;
    try std.testing.expectEqual(min_client_initial_datagram_size, tx.bytes.len);
    const w = try walkCoalesced(tx.bytes);
    try std.testing.expectEqual(@as(usize, 1), w.initial);
    try std.testing.expectEqual(@as(usize, 1), w.packets);
}

// ── Group B: close/drain parity (noq connection/mod.rs:1613-1693, 4439-4471, 5540-5543) ──

/// A CONNECTION_CLOSE frame scanned off the wire, with the reason copied out
/// (the decode buffer is stack-local to the scanner).
const ScannedClose = struct {
    error_code: u64,
    is_app: bool,
    reason_buf: [max_datagram]u8,
    reason_len: usize,

    fn reason(self: *const ScannedClose) []const u8 {
        return self.reason_buf[0..self.reason_len];
    }
};

/// Decrypt every packet of `space` inside a (possibly coalesced) datagram
/// built by `conn` and return the first CONNECTION_CLOSE frame found.
/// Test-only scanner: uses the sender's own write keys (AEAD is symmetric)
/// and the minimal-length PNs the builders emit for small packet numbers.
fn closeFrameInSpace(conn: *Connection, d: []const u8, space: spaces.SpaceId) !?ScannedClose {
    var off: usize = 0;
    while (off < d.len) {
        var pkt_space: spaces.SpaceId = undefined;
        var pkt: []const u8 = undefined;
        var pn_offset: usize = undefined;
        if ((d[off] & packet.long_header_form) != 0) {
            const ph = try packet.decodeProtectedLongHeader(d[off..], true);
            pkt_space = switch (ph.long_type) {
                .initial => .initial,
                .handshake => .handshake,
                else => .data,
            };
            pkt = d[off .. off + ph.packet_end];
            pn_offset = ph.pn_offset;
            off += ph.packet_end;
        } else {
            pkt_space = .data;
            pkt = d[off..];
            pn_offset = 1 + conn.remote_cid.len;
            off = d.len;
        }
        if (pkt_space != space) continue;
        const keys = conn.write_keys[@intFromEnum(pkt_space)] orelse return error.UnexpectedState;
        var buf: [max_datagram]u8 = undefined;
        @memcpy(buf[0..pkt.len], pkt);
        try packet_crypto.decryptHeaderWithKeys(buf[0..pkt.len], pn_offset, keys);
        const pn_len: usize = @as(usize, buf[0] & 0x03) + 1;
        const header_len = pn_offset + pn_len;
        var pn_val: u64 = 0;
        var i: usize = 0;
        while (i < pn_len) : (i += 1) pn_val = (pn_val << 8) | buf[pn_offset + i];
        try packet_crypto.decryptPayload(buf[0..pkt.len], header_len, pn_val, keys);
        const payload = buf[header_len .. pkt.len - packet_crypto.tag_len];
        var cursor: coding.Cursor = .{ .bytes = payload };
        while (cursor.remaining() > 0) {
            if (cursor.bytes[cursor.index] == 0x00) {
                cursor.index += 1;
                continue;
            }
            const f = frame.decodeAt(&cursor) catch return error.UnexpectedState;
            switch (f) {
                .connection_close => |cc| {
                    var scanned: ScannedClose = .{
                        .error_code = cc.error_code,
                        .is_app = cc.is_app,
                        .reason_buf = .{0} ** max_datagram,
                        .reason_len = @min(cc.reason.len, max_datagram),
                    };
                    @memcpy(scanned.reason_buf[0..scanned.reason_len], cc.reason[0..scanned.reason_len]);
                    return scanned;
                },
                else => {},
            }
        }
    }
    return null;
}

test "B2: handshake-time close rides in every keyed space with APPLICATION_ERROR rewrite" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();

    // Drive only the client's first flight: the server then holds
    // Initial+Handshake write keys (and 0.5-RTT Data keys) while still in the
    // handshake state — the key shape of a TLS-failure / protocol-violation
    // close before the handshake completes.
    const now: Instant = 1_000_000;
    while (try pair.client.pollTransmit(now)) |tx| try pair.server.handleDatagram(now, tx.bytes);
    const initial_si = @intFromEnum(spaces.SpaceId.initial);
    const handshake_si = @intFromEnum(spaces.SpaceId.handshake);
    try std.testing.expect(pair.server.write_keys[initial_si] != null);
    try std.testing.expect(pair.server.write_keys[handshake_si] != null);
    try std.testing.expect(pair.server.state == .handshake);

    // Application close during the handshake. noq (mod.rs:1613-1693) emits
    // the close in EVERY space with keys; below the Data space an app close is
    // rewritten to transport APPLICATION_ERROR (mod.rs:1654-1663).
    pair.server.close(now);
    var initial_cc: ?ScannedClose = null;
    var handshake_cc: ?ScannedClose = null;
    var data_cc: ?ScannedClose = null;
    var first_walk: ?CoalesceWalk = null;
    var first_len: usize = 0;
    while (try pair.server.pollTransmit(now)) |tx| {
        if (first_walk == null) {
            first_walk = try walkCoalesced(tx.bytes);
            first_len = tx.bytes.len;
        }
        if (try closeFrameInSpace(pair.server, tx.bytes, .initial)) |cc| initial_cc = cc;
        if (try closeFrameInSpace(pair.server, tx.bytes, .handshake)) |cc| handshake_cc = cc;
        if (try closeFrameInSpace(pair.server, tx.bytes, .data)) |cc| data_cc = cc;
    }
    // A close reached EVERY keyed space — pre-B2 the data-only builder sent
    // nothing at all before 1-RTT keys were used.
    const ic = initial_cc orelse return error.UnexpectedState;
    const hc = handshake_cc orelse return error.UnexpectedState;
    // Rewritten: transport close (0x1c), code APPLICATION_ERROR (0x0c), empty
    // reason — not the app close's own code/reason.
    try std.testing.expect(!ic.is_app);
    try std.testing.expectEqual(err_application_error, ic.error_code);
    try std.testing.expectEqual(@as(usize, 0), ic.reason_len);
    try std.testing.expect(!hc.is_app);
    try std.testing.expectEqual(err_application_error, hc.error_code);
    // The Data space carries the real application close.
    const dc = data_cc orelse return error.UnexpectedState;
    try std.testing.expect(dc.is_app);
    try std.testing.expectEqual(@as(u64, 0), dc.error_code);
    // Server Initial close is NOT padded (noq's SendableFrames::is_ack_eliciting
    // is false for a close-only packet), so all three spaces coalesce into one
    // small datagram.
    const w = first_walk.?;
    try std.testing.expectEqual(@as(usize, 1), w.initial);
    try std.testing.expectEqual(@as(usize, 1), w.handshake);
    try std.testing.expectEqual(@as(usize, 1), w.short);
    try std.testing.expect(first_len < min_client_initial_datagram_size);
    // Highest keyed space carried it: the armament is complete and the
    // connection goes silent (noq mod.rs:1039-1047).
    try std.testing.expect(pair.server.close_sent);
    try std.testing.expect((try pair.server.pollTransmit(now)) == null);
}

test "B2: established client close uses its remaining Data-space key" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const now: Instant = pair.client.now + 1_000_000;

    // Established close: Initial/Handshake write keys are still held (the
    // discard timer has not fired), so the close rides in all three spaces
    // (B2). The client Initial close pads its own datagram to the §14.1 floor
    // (noq PadDatagram::ToMinMtu, mod.rs:1603-1608).
    pair.client.close(now);
    var initial_cc: ?ScannedClose = null;
    var handshake_cc: ?ScannedClose = null;
    var data_cc: ?ScannedClose = null;
    while (try pair.client.pollTransmit(now)) |tx| {
        if (try closeFrameInSpace(pair.client, tx.bytes, .initial)) |cc| initial_cc = cc;
        if (try closeFrameInSpace(pair.client, tx.bytes, .handshake)) |cc| handshake_cc = cc;
        if (try closeFrameInSpace(pair.client, tx.bytes, .data)) |cc| data_cc = cc;
    }
    // RFC 9001 §4.9.1 has already discarded the client's Initial keys, and
    // the handshake-key discard timer has fired during establishment. The
    // close is therefore emitted solely in the remaining Data space.
    try std.testing.expect(initial_cc == null);
    try std.testing.expect(handshake_cc == null);
    // The Data space carries the real application close (noq
    // mod.rs:1658: `space_id == SpaceId::Data || reason.is_transport_layer()`).
    const dc = data_cc orelse return error.UnexpectedState;
    try std.testing.expect(dc.is_app);
    try std.testing.expectEqual(@as(u64, 0), dc.error_code);
    try std.testing.expectEqualStrings("closed", dc.reason());
    try std.testing.expect(pair.client.close_sent);
    try std.testing.expect((try pair.client.pollTransmit(now)) == null);
}

test "B2: established Data-space close reaches a peer after long-header key discard" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const now: Instant = pair.server.now + 1_000_000;

    // The receiver has discarded Initial/Handshake read keys (RFC 9000 §4.10
    // timing, forced here). noq drops such packets individually and continues
    // the datagram (handle_coalesced, mod.rs:4158-4191) — the trailing Data
    // close must still land.
    Connection.zeroPacketKeySlot(&pair.client.read_keys[@intFromEnum(spaces.SpaceId.initial)]);
    Connection.zeroPacketKeySlot(&pair.client.read_keys[@intFromEnum(spaces.SpaceId.handshake)]);
    // Keep the whole close armament in ONE datagram (the MTU probe otherwise
    // flies solo and the Data close gets its own datagram, which would not
    // exercise the keyless-skip at all).
    pair.server.probe_mtu = null;
    pair.server.mtu_probe_queue_len = 0;

    pair.server.close(now);
    var initial_cc: ?ScannedClose = null;
    var handshake_cc: ?ScannedClose = null;
    var data_cc: ?ScannedClose = null;
    while (try pair.server.pollTransmit(now)) |tx| {
        // One datagram per pollTransmit call: a close for a space whose peer
        // keys are gone is skipped by the receiver, the rest still land.
        if (try closeFrameInSpace(pair.server, tx.bytes, .initial)) |cc| initial_cc = cc;
        if (try closeFrameInSpace(pair.server, tx.bytes, .handshake)) |cc| handshake_cc = cc;
        if (try closeFrameInSpace(pair.server, tx.bytes, .data)) |cc| data_cc = cc;
        try pair.client.handleDatagram(now, tx.bytes);
    }
    // Both endpoints discarded long-header keys during establishment, so the
    // pending close rides solely in Data and still reaches the peer.
    try std.testing.expect(initial_cc == null);
    try std.testing.expect(handshake_cc == null);
    try std.testing.expect(data_cc != null);
    try std.testing.expect(pair.client.state == .draining);
}

test "B3: closed re-arm ignores garbage and unvalidated remotes, fires for validated peers" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const client = pair.client;
    const server = pair.server;
    const now: Instant = client.now + 1_000_000;
    const data_si = @intFromEnum(spaces.SpaceId.data);

    // Client closes; the close armament completes (highest keyed space = Data).
    client.close(now);
    while (try client.pollTransmit(now)) |tx| try server.handleDatagram(now, tx.bytes);
    try std.testing.expect(client.state == .closed);
    try std.testing.expect(client.close_sent);

    // (a) An unauthenticated datagram must NOT re-arm (pre-B3 the re-arm sat
    // at the top of handleDatagram and any garbage reflected a close).
    const read_keys = client.read_keys[data_si].?;
    const poison_pn: u64 = (client.spaces_state.getConst(.data).largest_received orelse 0) + 100;
    var forge_buf: [1500]u8 = undefined;
    const ping_frames = [_]frame.Frame{.ping};
    const forged = try packet_builder.buildOneRtt(&forge_buf, client.local_cid, poison_pn, client.crypto_1rtt.key_phase, &ping_frames, read_keys, 0);
    forged.bytes[forged.bytes.len - 1] ^= 0xff;
    _ = client.handleDatagram(now, forged.bytes) catch {};
    try std.testing.expect(client.close_sent);
    try std.testing.expect((try client.pollTransmit(now)) == null);

    // (b) One VALID authenticated packet from the validated peer re-arms
    // exactly one close armament (noq mod.rs:4439-4471).
    const good_pn: u64 = (client.spaces_state.getConst(.data).largest_received orelse 0) + 1;
    var good_buf: [1500]u8 = undefined;
    const good = try packet_builder.buildOneRtt(&good_buf, client.local_cid, good_pn, client.crypto_1rtt.key_phase, &ping_frames, read_keys, 0);
    try client.handleDatagram(now, good.bytes);
    try std.testing.expect(!client.close_sent);
    var reemitted = false;
    while (try client.pollTransmit(now)) |tx| {
        if (try closeFrameInSpace(client, tx.bytes, .data)) |cc| {
            reemitted = true;
            try std.testing.expect(cc.is_app);
        }
    }
    try std.testing.expect(reemitted);
    try std.testing.expect(client.close_sent);
    try std.testing.expect((try client.pollTransmit(now)) == null);

    // (c) A duplicate packet does NOT re-arm (noq mod.rs:4329-4332 returns
    // before its re-arm): feed the same valid packet again.
    try client.handleDatagram(now, good.bytes);
    try std.testing.expect(client.close_sent);
    try std.testing.expect((try client.pollTransmit(now)) == null);
}

test "B3: pre-validation server stays silent; first handshake packet validates the remote" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();
    const now: Instant = 1_000_000;

    // Full flight exchange short of establishment: the client can build a
    // coalesced [Initial ACK][Handshake CRYPTO] datagram, but the server has
    // not yet seen any client Handshake packet.
    while (try pair.client.pollTransmit(now)) |tx| try pair.server.handleDatagram(now, tx.bytes);
    while (try pair.server.pollTransmit(now)) |tx| try pair.client.handleDatagram(now, tx.bytes);
    const flight = (try pair.client.pollTransmit(now)).?;
    var flight_buf: [max_datagram]u8 = undefined;
    @memcpy(flight_buf[0..flight.bytes.len], flight.bytes);
    const flight_bytes = flight_buf[0..flight.bytes.len];
    const ph = try packet.decodeProtectedLongHeader(flight_bytes, true);
    const initial_part = flight_bytes[0..ph.packet_end];
    const handshake_part = flight_bytes[ph.packet_end..];
    try std.testing.expect(handshake_part.len > 0);

    // The server closes; its close armament completes. The client must NOT
    // learn of it (drop the close datagrams).
    pair.server.close(now);
    while (try pair.server.pollTransmit(now)) |_| {}
    try std.testing.expect(pair.server.close_sent);
    try std.testing.expect(!pair.server.closeRearmRemoteValidated());

    // A fresh, authenticated Initial from the still-UNVALIDATED remote: no
    // re-arm, silence (RFC 9000 §10.2.1; noq mod.rs:4463-4470).
    try pair.server.handleDatagram(now, initial_part);
    try std.testing.expect((try pair.server.pollTransmit(now)) == null);

    // Garbage in the Handshake space (valid envelope, corrupted AEAD tag):
    // no re-arm either — it never authenticates.
    const handshake_si = @intFromEnum(spaces.SpaceId.handshake);
    const hs_read = pair.server.read_keys[handshake_si].?;
    var forge_buf: [1500]u8 = undefined;
    const ping_frames = [_]frame.Frame{.ping};
    const forged = try packet_builder.buildLongHeader(&forge_buf, .handshake, 1, pair.server.local_cid, pair.client.local_cid, "", 100, &ping_frames, hs_read, 0);
    forged.bytes[forged.bytes.len - 1] ^= 0xff;
    _ = pair.server.handleDatagram(now, forged.bytes) catch {};
    try std.testing.expect((try pair.server.pollTransmit(now)) == null);

    // The first authenticated HANDSHAKE packet validates the remote (noq
    // on_path_validated, mod.rs:4657) and re-arms one close armament.
    try pair.server.handleDatagram(now, handshake_part);
    try std.testing.expect(pair.server.peer_handshake_authed);
    try std.testing.expect(!pair.server.close_sent);
    var reemitted = false;
    while (try pair.server.pollTransmit(now)) |tx| {
        if (try closeFrameInSpace(pair.server, tx.bytes, .handshake)) |_| reemitted = true;
    }
    try std.testing.expect(reemitted);
    try std.testing.expect(pair.server.close_sent);
}

test "B4: draining answers a peer's Data-space close with exactly one NO_ERROR close" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const now: Instant = pair.client.now + 1_000_000;

    // The closer holds ONLY 1-RTT keys (the post-key-discard shape noq is in
    // after handshake confirmation), so its close arrives in the Data space —
    // the only space whose close queues a NO_ERROR answer (noq mod.rs:5540-5543;
    // a handshake-space close drains silently, mod.rs:4856-4859).
    Connection.zeroPacketKeySlot(&pair.client.write_keys[@intFromEnum(spaces.SpaceId.initial)]);
    Connection.zeroPacketKeySlot(&pair.client.write_keys[@intFromEnum(spaces.SpaceId.handshake)]);
    pair.client.close(now);
    while (try pair.client.pollTransmit(now)) |tx| try pair.server.handleDatagram(now, tx.bytes);
    try std.testing.expect(pair.server.state == .draining);
    try std.testing.expect(pair.server.drain_close_pending);

    // Exactly one NO_ERROR transport close back, then silence (noq clears
    // connection_close_pending at the highest space, mod.rs:1673-1677).
    var no_error_seen = false;
    while (try pair.server.pollTransmit(now)) |tx| {
        if (try closeFrameInSpace(pair.server, tx.bytes, .data)) |cc| {
            no_error_seen = true;
            try std.testing.expect(!cc.is_app);
            try std.testing.expectEqual(err_no_error, cc.error_code);
            try std.testing.expectEqual(@as(usize, 0), cc.reason_len);
        }
        // The closed peer absorbs the answer: already fully-closed, it moves
        // to draining WITHOUT answering the answer (noq mod.rs:4529-4532).
        try pair.client.handleDatagram(now, tx.bytes);
    }
    try std.testing.expect(no_error_seen);
    try std.testing.expect(!pair.server.drain_close_pending);
    try std.testing.expect((try pair.server.pollTransmit(now)) == null);
    try std.testing.expect(pair.client.state == .draining);
    try std.testing.expect((try pair.client.pollTransmit(now)) == null);
}

test "B9: CONNECTION_CLOSE reason truncated to the packet budget (noq CloseEncoder)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);

    // Pin the MTU low so the packet budget is small enough to force truncation
    // (establishPair's direct link lets PMTUD converge to max_datagram).
    pair.client.mtu = min_mtu;
    pair.client.mtu_search = null;

    // A reason far larger than one 1-RTT packet's frame budget: without
    // noq's CloseEncoder bound the encode overflows tx_scratch and the close
    // packet cannot be built at all.
    var reason_buf: [3000]u8 = undefined;
    @memset(&reason_buf, 'x');
    const now: Instant = 300_000_000;
    pair.client.closeWith(now, .{ .error_code = 0, .reason = &reason_buf, .is_app = true });

    var saw_close = false;
    while (try pair.client.pollTransmit(now)) |tx| {
        try std.testing.expect(tx.bytes.len <= max_datagram);
        // The emitted datagram parses (the scanner decrypts and frame-decodes
        // it) and the wire reason is the budget-bounded prefix, not the full
        // 3000 bytes.
        if (try closeFrameInSpace(pair.client, tx.bytes, .data)) |cc| {
            saw_close = true;
            try std.testing.expect(cc.reason_len < reason_buf.len);
            try std.testing.expect(cc.reason_len > 0);
            try std.testing.expectEqualSlices(u8, reason_buf[0..cc.reason_len], cc.reason());
        }
    }
    try std.testing.expect(saw_close);
}

// ── B8: TLS alert → CRYPTO_ERROR (noq crypto/rustls.rs:98-108) ─────────────

/// Drive the client's first flight into the server, then inject garbage
/// Handshake-level CRYPTO (an unknown TLS handshake message type) in place of
/// the client's second flight. The server's TLS stack must reject it with an
/// alert, the connection must close with CRYPTO_ERROR (0x0100 + alert), and
/// the peer must observe exactly that code on the wire.
fn expectCryptoErrorClose(pair: *TestPair) !void {
    try pair.client.startClient();
    const now: Instant = 1_000_000;
    // One full round: the client's first flight to the server, the server's
    // answer back to the client — the client then holds every read key the
    // server's multi-space close can arrive under.
    var pkt_idx: usize = 0;
    try pumpOnce(pair, now, &pkt_idx, null);
    try std.testing.expect(pair.server.state == .handshake);

    // Corrupt the client's second flight in flight: 0xff is not a TLS
    // handshake message type — any conforming stack alerts on it.
    const garbage = [_]u8{ 0xff, 0x00, 0x00, 0x00 };
    try std.testing.expectError(
        error.PicotlsError,
        pair.server.ingestCrypto(.handshake, .{ .offset = 0, .data = &garbage }),
    );

    // noq rustls.rs:98-108: alert → TransportErrorCode::crypto(alert) =
    // 0x0100 + alert; the close is queued in every keyed space (B2).
    try std.testing.expect(pair.server.state == .closed);
    const cc = pair.server.close_frame.?;
    try std.testing.expect(!cc.is_app);
    try std.testing.expect(cc.error_code >= err_crypto_error_base and
        cc.error_code <= err_crypto_error_base + 0xff);

    // The peer observes exactly that code on the wire, then drains.
    var observed: ?u64 = null;
    while (try pair.server.pollTransmit(now)) |tx| {
        inline for (.{ spaces.SpaceId.initial, spaces.SpaceId.handshake, spaces.SpaceId.data }) |sp| {
            if (try closeFrameInSpace(pair.server, tx.bytes, sp)) |sc| observed = sc.error_code;
        }
        try pair.client.handleDatagram(now, tx.bytes);
    }
    const code = observed orelse return error.ExpectedCloseOnWire;
    try std.testing.expect(code >= err_crypto_error_base and code <= err_crypto_error_base + 0xff);
    try std.testing.expect(pair.client.state == .draining);
}

test "B8: TLS alert maps to CRYPTO_ERROR (0x1xx) close the peer observes" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try expectCryptoErrorClose(&pair);
}

test "B8: TLS alert maps to CRYPTO_ERROR under the zigtls backend" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    var pair = try makePairBackend(std.testing.allocator, .zigtls, null);
    defer pair.deinit();
    try expectCryptoErrorClose(&pair);
}

// ── G4: delayed-ACK cadence (noq PendingAcks::packet_received / is_out_of_order) ──

test "G4: default cadence defers the first in-order packet, ACKs the second" {
    // noq packet_received (spaces.rs:1198-1201): default ack_eliciting
    // threshold is 1 (spaces.rs:1129) and the immediate condition is
    // `count > threshold` — "every other ack-eliciting packet" (config doc,
    // transport.rs:725).
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const s = pair.server;
    const si = @intFromEnum(spaces.SpaceId.data);
    s.needs_ack[si] = false;
    s.ack_deadline[si] = null;
    s.peer_ack_eliciting_pending = 0;
    s.peer_ack_eliciting_threshold = null; // extension unused → noq default 1
    s.largest_ack_eliciting_recv[si] = 4999; // injected run is in-order

    var buf: [8]u8 = undefined;
    const ping = try (frame.Frame{ .ping = {} }).encode(&buf);
    try s.processPayload(.data, 5000, ping, false);
    try std.testing.expect(!s.needs_ack[si]);
    try std.testing.expect(s.ackDeadlineForTest(.data) != null); // bounded deferral
    try s.processPayload(.data, 5001, ping, false);
    try std.testing.expect(s.needs_ack[si]);
    try std.testing.expect(s.ackDeadlineForTest(.data) == null);
}

test "G4: out-of-order packet forces an immediate ACK below the threshold" {
    // noq is_out_of_order, reordering_threshold == 1 branch (spaces.rs:1224-1228):
    // a hole in (prev_largest, pn) → immediate ACK, threshold count irrelevant.
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const s = pair.server;
    const si = @intFromEnum(spaces.SpaceId.data);
    s.needs_ack[si] = false;
    s.ack_deadline[si] = null;
    s.peer_ack_eliciting_pending = 0;
    s.peer_ack_eliciting_threshold = 100; // threshold alone would defer for ages
    s.largest_ack_eliciting_recv[si] = 4999;

    var buf: [8]u8 = undefined;
    const ping = try (frame.Frame{ .ping = {} }).encode(&buf);
    try s.processPayload(.data, 5001, ping, false); // 5000 never arrives
    try std.testing.expect(s.needs_ack[si]);
    // And the same for a BELOW-previous-largest arrival (spaces.rs:1226).
    s.needs_ack[si] = false;
    s.peer_ack_eliciting_pending = 0;
    try s.processPayload(.data, 5000, ping, false); // fills the hole, behind the tracker
    try std.testing.expect(s.needs_ack[si]);
}

test "G4: reordering_threshold 0 disables the out-of-order immediate ACK" {
    // noq is_out_of_order, threshold 0 branch (spaces.rs:1223): never.
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const s = pair.server;
    const si = @intFromEnum(spaces.SpaceId.data);
    s.needs_ack[si] = false;
    s.ack_deadline[si] = null;
    s.peer_ack_eliciting_pending = 0;
    s.peer_ack_eliciting_threshold = 100;
    s.peer_reordering_threshold = 0;
    s.largest_ack_eliciting_recv[si] = 4999;

    var buf: [8]u8 = undefined;
    const ping = try (frame.Frame{ .ping = {} }).encode(&buf);
    try s.processPayload(.data, 5001, ping, false); // gapped, but the peer opted out
    try std.testing.expect(!s.needs_ack[si]);
    try std.testing.expect(s.ackDeadlineForTest(.data) != null);
}

test "G4: draft-§6.1 reordering_threshold > 1 uses the largest_acked tracker" {
    // noq is_out_of_order, threshold > 1 branch (spaces.rs:1229-1249): with
    // reordering_threshold 3 and largest_acked 100 (largest_reported = 98), a
    // hole at 101 triggers the immediate ACK only once the largest unacked is
    // 3 ahead of it — 102/103 defer, 104 fires.
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const s = pair.server;
    const si = @intFromEnum(spaces.SpaceId.data);
    s.needs_ack[si] = false;
    s.peer_ack_eliciting_pending = 0;
    s.peer_ack_eliciting_threshold = 1000; // take the count branch out of play
    s.peer_reordering_threshold = 3;
    s.largest_acked_sent[si] = 100;
    s.largest_ack_eliciting_recv[si] = 100;
    // Seed the dedup window with 98..100 received (the interval bounds are
    // assumed received, spaces.rs:948-952).
    _ = s.dedup[si].checkAndInsert(98);
    _ = s.dedup[si].checkAndInsert(99);
    _ = s.dedup[si].checkAndInsert(100);

    var buf: [8]u8 = undefined;
    const ping = try (frame.Frame{ .ping = {} }).encode(&buf);
    try s.processPayload(.data, 102, ping, false); // hole at 101; 102-101 = 1 < 3
    try std.testing.expect(!s.needs_ack[si]);
    try s.processPayload(.data, 103, ping, false); // 103-101 = 2 < 3
    try std.testing.expect(!s.needs_ack[si]);
    try s.processPayload(.data, 104, ping, false); // 104-101 = 3 >= 3 → immediate
    try std.testing.expect(s.needs_ack[si]);
}

test "G4: emitting the ACK restarts the threshold count and records largest_acked (noq acks_sent)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const s = pair.server;
    const si = @intFromEnum(spaces.SpaceId.data);
    s.peer_ack_eliciting_pending = 0;
    s.peer_reordering_threshold = 1;
    s.largest_ack_eliciting_recv[si] = 4999;
    var buf: [8]u8 = undefined;
    const ping = try (frame.Frame{ .ping = {} }).encode(&buf);
    try s.processPayload(.data, 5001, ping, false); // out-of-order → immediate
    try std.testing.expect(s.needs_ack[si]);
    var frames: [16]frame.Frame = undefined;
    var n: usize = 0;
    _ = s.emitOwedAck(si, &frames, &n);
    try std.testing.expectEqual(@as(usize, 1), n);
    // noq acks_sent (spaces.rs:1266-1270): count restarts, largest_acked
    // becomes the largest ack-eliciting PN the ACK reports.
    try std.testing.expectEqual(@as(u64, 0), s.peer_ack_eliciting_pending);
    try std.testing.expectEqual(@as(?u64, 5001), s.largest_acked_sent[si]);
}

// ── G10: ACK_FREQUENCY emission policy (noq AckFrequencyState) ───────────────

/// Decrypt a lone 1-RTT transmit with the sender's own write keys and decode
/// its frames (padding skipped), the way processPayload does.
fn decodeDataFrames(conn: *Connection, tx_bytes: []const u8, out: *[32]frame.Frame) !usize {
    const keys = conn.write_keys[@intFromEnum(spaces.SpaceId.data)].?;
    const pn = conn.spaces_state.getConst(.data).next_pn - 1;
    var buf: [max_datagram]u8 = undefined;
    @memcpy(buf[0..tx_bytes.len], tx_bytes);
    const hdr = try packet_builder.unprotectOneRtt(buf[0..tx_bytes.len], conn.remote_cid.len, pn, keys);
    var cursor: coding.Cursor = .{ .bytes = buf[hdr.header_len .. tx_bytes.len - packet_crypto.tag_len] };
    var n: usize = 0;
    while (cursor.remaining() > 0) {
        if (cursor.bytes[cursor.index] == 0x00) {
            cursor.index += 1;
            continue;
        }
        out[n] = try frame.decodeAt(&cursor);
        n += 1;
    }
    return n;
}

fn findAckFrequency(frames: []const frame.Frame) ?frame.AckFrequency {
    for (frames) |f| switch (f) {
        .ack_frequency => |af| return af,
        else => {},
    };
    return null;
}

fn findDataBlocked(frames: []const frame.Frame) ?u64 {
    for (frames) |f| switch (f) {
        .data_blocked => |value| return value,
        else => {},
    };
    return null;
}

fn findStreamsBlockedBidi(frames: []const frame.Frame) ?u64 {
    for (frames) |f| switch (f) {
        .streams_blocked_bidi => |value| return value,
        else => {},
    };
    return null;
}

fn findMaxStreamsUni(frames: []const frame.Frame) ?u64 {
    for (frames) |f| switch (f) {
        .max_streams_uni => |value| return value,
        else => {},
    };
    return null;
}

fn findMaxData(frames: []const frame.Frame) ?u64 {
    for (frames) |f| switch (f) {
        .max_data => |value| return value,
        else => {},
    };
    return null;
}

test "J2: Connection.create honors configured congestion controller" {
    const allocator = std.testing.allocator;
    const backend: crypto.Backend = if (crypto.picotls_enabled) .picotls else .zigtls;
    const client_key = key.SecretKey.fromBytes(.{0x31} ** 32);
    const server_key = key.SecretKey.fromBytes(.{0x32} ** 32);
    const local_cid = try packet.ConnectionId.init(&.{ 0x31, 0x32, 0x33, 0x34 });
    const remote_cid = try packet.ConnectionId.init(&.{ 0x35, 0x36, 0x37, 0x38 });
    const server_name = tls_name.serverName(server_key.public());

    const conn = try Connection.create(allocator, .{
        .backend = backend,
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .server_name = &server_name,
    }, local_cid, remote_cid, remote_cid, testCsprngSeed(0x1234), .{
        .congestion_kind = .new_reno,
    });
    defer conn.destroy();

    try std.testing.expectEqual(congestion.Kind.new_reno, conn.congestionKindForTest());
}

test "J9: app-limited sent packets reach congestion ACK hooks" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);

    const stream_id = try pair.client.openStream(.bidi);
    try pair.client.writeStream(stream_id, "j9", true);
    pair.client.next_send_at = 0;
    _ = (try pair.client.pollTransmit(pair.client.now + 1)) orelse return error.TestUnexpectedResult;
    const sent = pair.client.sent.items[pair.client.sent.items.len - 1];
    try std.testing.expect(sent.app_limited);

    pair.client.onAck(.data, .{ .largest_acked = sent.packet_number, .ack_delay = 0, .first_range = 0 });
    try std.testing.expect(pair.client.appLimitedAcksForTest() > 0);
}

test "D11: connection-window stalls emit DATA_BLOCKED" {
    var params_buf: [128]u8 = undefined;
    const server_params = try (transport_parameters.TransportParameters{
        .initial_max_data = 4,
        .initial_max_stream_data_bidi_local = 1_000,
        .initial_max_stream_data_bidi_remote = 1_000,
        .initial_max_stream_data_uni = 1_000,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 8,
    }).encode(&params_buf);
    var pair = try makePair(std.testing.allocator, server_params);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);

    const stream_id = try pair.client.openStream(.bidi);
    try pair.client.writeStream(stream_id, "0123456789", true);
    const now = pair.client.now + 1;
    pair.client.next_send_at = 0;
    const first = (try pair.client.pollTransmit(now)) orelse return error.TestUnexpectedResult;
    try pair.server.handleDatagram(now, first.bytes);

    pair.client.next_send_at = 0;
    const blocked = (try pair.client.pollTransmit(now + 1)) orelse return error.TestUnexpectedResult;
    var frames: [32]frame.Frame = undefined;
    const n = try decodeDataFrames(pair.client, blocked.bytes, &frames);
    try std.testing.expectEqual(@as(u64, 4), findDataBlocked(frames[0..n]).?);
}

test "D11: stream-open stalls emit STREAMS_BLOCKED" {
    var params_buf: [128]u8 = undefined;
    const server_params = try (transport_parameters.TransportParameters{
        .initial_max_data = 1_000,
        .initial_max_stream_data_bidi_local = 1_000,
        .initial_max_stream_data_bidi_remote = 1_000,
        .initial_max_stream_data_uni = 1_000,
        .initial_max_streams_bidi = 1,
        .initial_max_streams_uni = 8,
    }).encode(&params_buf);
    var pair = try makePair(std.testing.allocator, server_params);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);

    _ = try pair.client.openStream(.bidi);
    try std.testing.expectError(error.StreamLimit, pair.client.openStream(.bidi));
    pair.client.next_send_at = 0;
    const tx = (try pair.client.pollTransmit(pair.client.now + 1)) orelse return error.TestUnexpectedResult;
    var frames: [32]frame.Frame = undefined;
    const n = try decodeDataFrames(pair.client, tx.bytes, &frames);
    try std.testing.expectEqual(@as(u64, 1), findStreamsBlockedBidi(frames[0..n]).?);
}

test "D10: retired peer uni streams emit MAX_STREAMS regrant" {
    var params_buf: [128]u8 = undefined;
    const server_params = try (transport_parameters.TransportParameters{
        .initial_max_data = 1_000,
        .initial_max_stream_data_bidi_local = 1_000,
        .initial_max_stream_data_bidi_remote = 1_000,
        .initial_max_stream_data_uni = 1_000,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 1,
    }).encode(&params_buf);
    var pair = try makePair(std.testing.allocator, server_params);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);

    const stream_id = try pair.client.openStream(.uni);
    try pair.client.writeStream(stream_id, "u", true);
    const now = pair.client.now + 1;
    pair.client.next_send_at = 0;
    const client_tx = (try pair.client.pollTransmit(now)) orelse return error.TestUnexpectedResult;
    try pair.server.handleDatagram(now, client_tx.bytes);
    try std.testing.expectEqualStrings("u", pair.server.readStream(stream_id));

    pair.server.next_send_at = 0;
    const regrant_tx = (try pair.server.pollTransmit(now + 1)) orelse return error.TestUnexpectedResult;
    var frames: [32]frame.Frame = undefined;
    const n = try decodeDataFrames(pair.server, regrant_tx.bytes, &frames);
    try std.testing.expectEqual(@as(u64, 2), findMaxStreamsUni(frames[0..n]).?);
}

test "D10: MAX_STREAMS retirement retries when the frame budget is full" {
    var params_buf: [128]u8 = undefined;
    const server_params = try (transport_parameters.TransportParameters{
        .initial_max_data = 1_000,
        .initial_max_stream_data_bidi_local = 1_000,
        .initial_max_stream_data_bidi_remote = 1_000,
        .initial_max_stream_data_uni = 1_000,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 1,
    }).encode(&params_buf);
    var pair = try makePair(std.testing.allocator, server_params);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);

    const stream_id = try pair.client.openStream(.uni);
    try pair.client.writeStream(stream_id, "u", true);
    const now = pair.client.now + 1;
    pair.client.next_send_at = 0;
    const client_tx = (try pair.client.pollTransmit(now)) orelse return error.TestUnexpectedResult;
    try pair.server.handleDatagram(now, client_tx.bytes);
    try std.testing.expectEqualStrings("u", pair.server.readStream(stream_id));

    var no_room: [0]frame.Frame = .{};
    var n: usize = 0;
    var ack_eliciting = false;
    pair.server.appendMaxStreamsRegrants(no_room[0..], &n, &ack_eliciting);
    try std.testing.expectEqual(@as(usize, 0), n);
    try std.testing.expect(!ack_eliciting);
    try std.testing.expectEqual(@as(u64, 1), pair.server.recv_max_streams_uni);
    try std.testing.expect(!pair.server.findStream(stream_id).?.max_streams_retired);

    var frames: [2]frame.Frame = undefined;
    n = 0;
    pair.server.appendMaxStreamsRegrants(&frames, &n, &ack_eliciting);
    try std.testing.expect(ack_eliciting);
    try std.testing.expectEqual(@as(u64, 2), findMaxStreamsUni(frames[0..n]).?);
    try std.testing.expect(pair.server.findStream(stream_id).?.max_streams_retired);
}

test "D12: peer RESET_STREAM credits unread receive bytes and emits MAX_DATA" {
    var params_buf: [128]u8 = undefined;
    const server_params = try (transport_parameters.TransportParameters{
        .initial_max_data = 4,
        .initial_max_stream_data_bidi_local = 1_000,
        .initial_max_stream_data_bidi_remote = 1_000,
        .initial_max_stream_data_uni = 1_000,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 8,
    }).encode(&params_buf);
    var pair = try makePair(std.testing.allocator, server_params);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);

    const stream_id = try pair.client.openStream(.bidi);
    try pair.client.writeStream(stream_id, "data", false);
    const now = pair.client.now + 1;
    pair.client.next_send_at = 0;
    const data_tx = (try pair.client.pollTransmit(now)) orelse return error.TestUnexpectedResult;
    try pair.server.handleDatagram(now, data_tx.bytes);
    try std.testing.expectEqual(@as(usize, 4), pair.server.streamRecvBytes(stream_id).len);

    try pair.client.resetStream(stream_id, 77);
    pair.client.next_send_at = 0;
    const reset_tx = (try pair.client.pollTransmit(now + 1)) orelse return error.TestUnexpectedResult;
    try pair.server.handleDatagram(now + 1, reset_tx.bytes);
    try std.testing.expectEqual(@as(u64, 4), pair.server.abandonedRecvBytesForTest());

    pair.server.next_send_at = 0;
    const credit_tx = (try pair.server.pollTransmit(now + 2)) orelse return error.TestUnexpectedResult;
    var frames: [32]frame.Frame = undefined;
    const n = try decodeDataFrames(pair.server, credit_tx.bytes, &frames);
    try std.testing.expectEqual(@as(u64, 8), findMaxData(frames[0..n]).?);
}

test "G10: ACK_FREQUENCY re-sends on RTT change with incrementing sequence and RTT-tracked request" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);
    const c = pair.client;
    c.mtu_probe_queue_len = 0;
    c.probe_mtu = null;
    c.probe_pn = null;

    // noq next_outgoing_sequence_number starts at VarInt(0)
    // (ack_frequency.rs:30): the establishment frame took seq 0.
    try std.testing.expectEqual(@as(u64, 1), c.ack_frequency_seq);

    // A request base above the RTT clamp makes the candidate RTT-derived
    // (candidate_max_ack_delay, ack_frequency.rs:40-53: min(base,
    // max(rtt, 25 ms))).
    c.local_params.max_ack_delay = 100; // ms → 100_000 µs base
    c.rtt.smoothed = 40_000_000; // 40 ms → candidate 40_000 µs
    c.next_send_at = 0;
    const tx1 = (try c.pollTransmit(c.now + 1)) orelse return error.TestUnexpectedResult;
    var frames: [32]frame.Frame = undefined;
    const n1 = try decodeDataFrames(c, tx1.bytes, &frames);
    const af1 = findAckFrequency(frames[0..n1]) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 1), af1.sequence_number);
    try std.testing.expectEqual(@as(u64, 40_000), af1.request_max_ack_delay);

    // RTT moves enough (|90k−40k|·5 > 40k, MAX_RTT_ERROR 0.2,
    // ack_frequency.rs:91-94,154) → re-send with the next sequence number.
    c.rtt.smoothed = 90_000_000;
    c.next_send_at = 0;
    const tx2 = (try c.pollTransmit(c.now + 2)) orelse return error.TestUnexpectedResult;
    const n2 = try decodeDataFrames(c, tx2.bytes, &frames);
    const af2 = findAckFrequency(frames[0..n2]) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 2), af2.sequence_number);
    try std.testing.expectEqual(@as(u64, 90_000), af2.request_max_ack_delay);

    // No further divergence → no third frame.
    c.next_send_at = 0;
    if (try c.pollTransmit(c.now + 3)) |tx3| {
        const n3 = try decodeDataFrames(c, tx3.bytes, &frames);
        try std.testing.expect(findAckFrequency(frames[0..n3]) == null);
    }
}

test "G10: an acknowledged ACK_FREQUENCY commits its requested value (noq on_acked)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);
    const c = pair.client;
    c.mtu_probe_queue_len = 0;
    c.probe_mtu = null;
    c.probe_pn = null;
    c.local_params.max_ack_delay = 100;
    c.rtt.smoothed = 40_000_000;
    c.next_send_at = 0;
    const tx1 = (try c.pollTransmit(c.now + 1)) orelse return error.TestUnexpectedResult;
    var frames: [32]frame.Frame = undefined;
    const n1 = try decodeDataFrames(c, tx1.bytes, &frames);
    _ = findAckFrequency(frames[0..n1]) orelse return error.TestUnexpectedResult;
    const sent_pn = c.ack_freq_in_flight_pn orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 40_000), c.ack_freq_in_flight_value_us);

    // The peer ACKs the carrying packet → the requested value is now the one
    // in force (ack_frequency.rs:107-116) and the in-flight marker clears.
    c.onAck(.data, .{ .largest_acked = sent_pn, .ack_delay = 0, .first_range = 0 });
    try std.testing.expect(c.ack_freq_in_flight_pn == null);
    try std.testing.expectEqual(@as(u64, 40_000), c.ack_freq_peer_max_delay_us);

    // A stale ACK that does not cover the packet commits nothing.
    c.rtt.smoothed = 90_000_000;
    c.next_send_at = 0;
    _ = (try c.pollTransmit(c.now + 2)) orelse return error.TestUnexpectedResult;
    const pn2 = c.ack_freq_in_flight_pn orelse return error.TestUnexpectedResult;
    c.onAck(.data, .{ .largest_acked = pn2 - 1, .ack_delay = 0, .first_range = 0 });
    try std.testing.expect(c.ack_freq_in_flight_pn != null);
}

// ── G13: IMMEDIATE_ACK emission (noq pending_immediate_ack) ─────────────────

test "G13: data-space tail-loss probe carries IMMEDIATE_ACK (noq queue_tail_loss_probe)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);
    const c = pair.client;
    c.mtu_probe_queue_len = 0;
    c.probe_mtu = null;
    c.probe_pn = null;

    // One outstanding data packet, deliberately never delivered → PTO fires →
    // the probe retransmission must ask for an un-delayed ACK
    // (queue_tail_loss_probe, spaces.rs:97-107 + mod.rs:1539-1546).
    const sid = try c.openStream(.bidi);
    try c.writeStream(sid, "tlp", false);
    c.next_send_at = 0;
    _ = (try c.pollTransmit(c.now + 1)) orelse return error.TestUnexpectedResult;
    const expiry = c.ptoDeadline() orelse return error.TestUnexpectedResult;
    c.handleTimeout(expiry);
    try std.testing.expect(c.stats_pto_events > 0);
    try std.testing.expect(c.pending_immediate_ack);

    c.next_send_at = 0;
    const probe = (try c.pollTransmit(expiry + 1)) orelse return error.TestUnexpectedResult;
    var frames: [32]frame.Frame = undefined;
    const n = try decodeDataFrames(c, probe.bytes, &frames);
    var found = false;
    for (frames[0..n]) |f| {
        if (f == .immediate_ack) found = true;
    }
    try std.testing.expect(found);
    try std.testing.expect(!c.pending_immediate_ack); // consumed by the probe
}

test "G13: MTU probe packet carries IMMEDIATE_ACK (noq poll_transmit_mtu_probe)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);
    const c = pair.client;
    c.mtu = 1200;
    c.mtu_probe_queue_len = 0;
    c.probe_mtu = 1280;
    c.probe_pn = null;

    c.next_send_at = 0;
    // Other control frames (a deferred ACK, an ACK_FREQUENCY re-send) may be
    // emitted first — the dedicated probe only builds when nothing else
    // queued (the n == 0 path). Poll until the padded probe shows up.
    var probe: ?Transmit = null;
    var polls: usize = 0;
    while (polls < 8 and probe == null) : (polls += 1) {
        c.next_send_at = 0;
        if (try c.pollTransmit(c.now + 1 + @as(i64, @intCast(polls)))) |tx| {
            if (tx.bytes.len == 1280) probe = tx;
        }
    }
    const probe_tx = probe orelse return error.TestUnexpectedResult;
    var frames: [32]frame.Frame = undefined;
    const n = try decodeDataFrames(c, probe_tx.bytes, &frames);
    var found_ping = false;
    var found_immediate = false;
    for (frames[0..n]) |f| {
        if (f == .ping) found_ping = true;
        if (f == .immediate_ack) found_immediate = true;
    }
    // noq writes Ping then ImmediateAck (mod.rs:1818-1827).
    try std.testing.expect(found_ping);
    try std.testing.expect(found_immediate);
}

// ── Group G: timers / loss / congestion (G14, G15, G16, G18, G19) ───────────

test "G14: connection PTO deadline uses noq's capped backoff (MAX_PTO_INTERVAL)" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const c = pair.client;
    c.rtt = loss.RttEstimator.init(50_000_000); // ptoBase = 150ms
    c.handshake_confirmed = true;
    // Seed one outstanding data-space ack-eliciting packet sent at t=0.
    try c.sent.append(std.testing.allocator, .{
        .path_generation = 0,
        .time_sent = 0,
        .size = 100,
        .ack_eliciting = true,
        .packet_number = 0,
        .space = .data,
    });
    c.pto_count = 10;
    const mad = c.peerMaxAckDelayNs();
    const deadline = c.ptoDeadline().?;
    // Uncapped would be (pto_base + mad) · 2^10 ≈ 300s; noq caps each probe
    // step's increment at max_interval (2s here — idle 30s > 25s), so the
    // deadline stays in the tens of seconds and matches ptoDelay exactly.
    try std.testing.expect(deadline < (c.rtt.ptoBase() + mad) * 1024);
    try std.testing.expectEqual(loss.ptoDelay(c.rtt, 10, mad, c.ptoMaxIntervalNs()), deadline);
    // Successive expiries are never more than max_interval apart.
    c.pto_count = 11;
    try std.testing.expect(c.ptoDeadline().? - deadline <= c.ptoMaxIntervalNs());
}

test "G14: a conventional PTO retransmits the TWO oldest outstanding packets" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);
    const c = pair.client;
    c.mtu_probe_queue_len = 0;
    c.probe_mtu = null;
    c.probe_pn = null;

    // Two outstanding data packets, both deliberately dropped.
    const sid = try c.openStream(.bidi);
    try c.writeStream(sid, "probe-one", false);
    c.next_send_at = 0;
    _ = (try c.pollTransmit(c.now + 1_000_000)) orelse return error.TestUnexpectedResult;
    try c.writeStream(sid, "-probe-two", false);
    c.next_send_at = 0;
    _ = (try c.pollTransmit(c.now + 2_000_000)) orelse return error.TestUnexpectedResult;

    const outstanding_before = c.sent.items.len;
    try std.testing.expect(outstanding_before >= 2);
    const pto_events_before = c.stats_pto_events;
    const expiry = c.ptoDeadline() orelse return error.TestUnexpectedResult;
    c.handleTimeout(expiry);
    // noq on_loss_detection_timeout queues TWO probes for a conventional PTO
    // (mod.rs:3235-3242): both oldest packets' frames were re-queued.
    try std.testing.expectEqual(pto_events_before + 2, c.stats_pto_events);
    try std.testing.expectEqual(outstanding_before - 2, c.sent.items.len);
}

test "G14: data-space PTO is not armed before the handshake is confirmed" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    const c = pair.client; // fresh client: handshake not confirmed
    // Seed an outstanding data-space ack-eliciting packet.
    try c.sent.append(std.testing.allocator, .{
        .path_generation = 0,
        .time_sent = 0,
        .size = 100,
        .ack_eliciting = true,
        .packet_number = 0,
        .space = .data,
    });
    // RFC 9002 §6.2.1-7 (noq mod.rs:3592-3597): the Application Data space
    // MUST NOT arm a PTO until the handshake is confirmed. Nothing else is in
    // flight and no anti-deadlock probe has a base → no PTO at all.
    try std.testing.expect(c.ptoDeadline() == null);
    c.handshake_confirmed = true;
    try std.testing.expect(c.ptoDeadline() != null);
}

test "G14: established server confirms handshake and arms data-space PTO" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);

    const server = pair.server;
    const data_si = @intFromEnum(spaces.SpaceId.data);
    try std.testing.expect(server.state == .established);
    try std.testing.expect(server.write_keys[data_si] != null);
    try std.testing.expect(server.read_keys[data_si] != null);

    server.mtu_probe_queue_len = 0;
    server.probe_mtu = null;
    server.probe_pn = null;
    const sid = try server.openStream(.bidi);
    try server.writeStream(sid, "server-pto", false);
    server.next_send_at = 0;

    const sent_before = server.sent.items.len;
    _ = (try server.pollTransmit(server.now + 1_000_000)) orelse return error.TestUnexpectedResult;
    var stream_data_in_flight = false;
    for (server.sent.items[sent_before..]) |sp| {
        if (sp.space != .data) continue;
        var i: usize = 0;
        while (i < sp.content_len) : (i += 1) {
            if (sp.content[i] == .stream) stream_data_in_flight = true;
        }
    }
    try std.testing.expect(stream_data_in_flight);

    const pto_events_before = server.stats_pto_events;
    const expiry = server.ptoDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expect(server.handshake_confirmed);
    server.handleTimeout(expiry);
    try std.testing.expect(server.stats_pto_events > pto_events_before);
    try std.testing.expect(server.pending_immediate_ack);
}

test "G15: a late ACK of declared-lost packets restores the congestion window" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);
    const c = pair.client;
    const s = pair.server;
    c.mtu = min_mtu;
    c.mtu_search = null;
    c.mtu_probe_queue_len = 0;
    c.probe_mtu = null;
    c.probe_pn = null;
    s.mtu_probe_queue_len = 0;
    s.probe_mtu = null;
    s.probe_pn = null;
    const cc = c.cc orelse return error.TestUnexpectedResult;
    cc.onMtuUpdate(min_mtu);

    // Five consecutive data packets; all but the last are WITHHELD (delayed,
    // not dropped).
    const sid = try c.openStream(.bidi);
    var payload: [6800]u8 = undefined;
    @memset(&payload, 0x42);
    try c.writeStream(sid, &payload, false);
    var stash: [5][max_datagram]u8 = undefined;
    var stash_len: [5]usize = .{ 0, 0, 0, 0, 0 };
    var n: usize = 0;
    var t: Instant = c.now + 1_000_000;
    while (n < 5) : (n += 1) {
        c.next_send_at = 0;
        const tx = (try c.pollTransmit(t)) orelse break;
        @memcpy(stash[n][0..tx.bytes.len], tx.bytes);
        stash_len[n] = tx.bytes.len;
        t += 1_000_000;
    }
    try std.testing.expectEqual(@as(usize, 5), n);

    const w_pre = cc.window();
    // Deliver ONLY the 5th datagram: the server ACKs it immediately (it is
    // out-of-order), the client declares the oldest outstanding packets lost
    // (packet threshold 3) and the congestion window shrinks.
    const t5 = t + 1_000_000;
    try s.handleDatagram(t5, stash[4][0..stash_len[4]]);
    var polls: usize = 0;
    while (polls < 4) : (polls += 1) {
        s.next_send_at = 0;
        const ack_tx = (try s.pollTransmit(t5 + @as(i64, @intCast(polls)))) orelse break;
        try c.handleDatagram(t5 + @as(i64, @intCast(polls)), ack_tx.bytes);
        if (c.lost_packets[@intFromEnum(spaces.SpaceId.data)].items.len > 0) break;
    }
    try std.testing.expect(c.lost_packets[@intFromEnum(spaces.SpaceId.data)].items.len > 0);
    const w_reduced = cc.window();
    try std.testing.expect(w_reduced < w_pre); // the congestion event fired

    // The withheld datagrams finally arrive: every declared-lost packet is
    // ACKed → the lost set empties → the congestion event was spurious
    // (noq detect_spurious_loss → on_spurious_congestion_event).
    const t6 = t5 + 2_000_000;
    for (0..4) |i| try s.handleDatagram(t6, stash[i][0..stash_len[i]]);
    polls = 0;
    while (polls < 4) : (polls += 1) {
        s.next_send_at = 0;
        const ack_tx = (try s.pollTransmit(t6 + @as(i64, @intCast(polls)))) orelse break;
        try c.handleDatagram(t6 + @as(i64, @intCast(polls)), ack_tx.bytes);
    }
    try std.testing.expectEqual(@as(u64, 1), c.stats_spurious_congestion_events);
    // Cubic restored its pre-congestion state: the window is back at (or,
    // with slow-start growth on the exonerating ACKs, above) the pre-loss
    // value — not the reduced one.
    try std.testing.expect(cc.window() >= w_pre);
}

test "G16: a loss burst spanning the persistent-congestion window collapses cwnd to the minimum" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);
    const c = pair.client;
    const cc = c.cc orelse return error.TestUnexpectedResult;
    c.mtu = min_mtu;
    c.mtu_search = null;
    c.mtu_probe_queue_len = 0;
    c.probe_mtu = null;
    c.probe_pn = null;
    cc.onMtuUpdate(min_mtu);

    // Pin a known estimator: ptoBase = 300ms; congestion period =
    // 3 · (ptoBase + max_ack_delay) ≈ 975ms.
    c.rtt = loss.RttEstimator.init(100_000_000);
    c.first_pn_after_rtt_sample = .{ .space = .data, .pn = 0 };
    // Synthetic PNs must not collide with the A17 optimistic-ACK skip.
    c.spaces_state.get(.data).pn_filter = null;

    // Five outstanding data packets 400ms apart, all old enough for the time
    // threshold. The ACK covers pn 5 — deliberately NOT in the sent set, so
    // no RTT sample lands and the pinned estimator stays intact; the five
    // seeded packets form an UNBROKEN lost span of 1.2s > the period.
    const now: Instant = c.now + 10_000_000_000;
    c.now = now;
    var total_size: u64 = 0;
    var pn: u64 = 0;
    while (pn < 5) : (pn += 1) {
        const time_sent = now - @as(i64, @intCast(5 - pn)) * 400_000_000;
        try c.sent.append(std.testing.allocator, .{
            .path_generation = 0,
            .time_sent = time_sent,
            .size = 1200,
            .ack_eliciting = true,
            .packet_number = pn,
            .space = .data,
        });
        total_size += 1200;
    }
    c.bytes_in_flight = total_size;
    c.spaces_state.get(.data).next_pn = 6;

    try std.testing.expect(cc.window() > 2 * c.mtu);
    c.onAck(.data, .{ .largest_acked = 5, .ack_delay = 0, .first_range = 0 });
    // Persistent congestion (noq cubic.rs:226-238): the window collapses to
    // the minimum (2 · MTU), not the ordinary β-reduction.
    try std.testing.expectEqual(@as(u64, 2 * c.mtu), cc.window());
}

test "G18: keep-alive interval emits a PING after idle silence" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);
    const c = pair.client;

    c.setKeepAliveIntervalNs(60_000_000); // 60ms
    c.resetKeepAlive(); // as the last authenticated packet's receive path did
    const deadline = c.keep_alive_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(c.now + 60_000_000, deadline);
    // The deadline is surfaced to the pump.
    const poll_timeout = c.pollTimeout() orelse return error.TestUnexpectedResult;
    try std.testing.expect(poll_timeout <= deadline);

    // Silence past the interval → a data-space PING is queued and emitted.
    c.handleTimeout(deadline);
    try std.testing.expect(c.pending_ping[@intFromEnum(spaces.SpaceId.data)]);
    c.next_send_at = 0;
    const tx = (try c.pollTransmit(deadline + 1)) orelse return error.TestUnexpectedResult;
    var frames: [32]frame.Frame = undefined;
    const nf = try decodeDataFrames(c, tx.bytes, &frames);
    var found_ping = false;
    for (frames[0..nf]) |f| {
        if (f == .ping) found_ping = true;
    }
    try std.testing.expect(found_ping);

    // Disabled (null) keep-alive never arms (noq Option<Duration> = None).
    const c2 = pair.server;
    try std.testing.expect(c2.keep_alive_deadline == null);
    const t2 = c2.now + 600_000_000_000;
    c2.handleTimeout(t2);
    try std.testing.expect(!c2.pending_ping[@intFromEnum(spaces.SpaceId.data)]);
}

test "G19: close and key-discard deadlines track the live RTT-derived PTO" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    try flushDeferredAcks(&pair);
    const c = pair.client;

    // Pin a known estimator: 100ms RTT → ptoBase = 300ms (≠ the old fixed 1s).
    c.rtt = loss.RttEstimator.init(100_000_000);
    c.refreshTimerPtoBase();
    try std.testing.expect(c.write_keys[@intFromEnum(spaces.SpaceId.data)] != null);
    const mad = c.peerMaxAckDelayNs();
    const now: Instant = 1_000_000_000;

    // Handshake-key discard: 3 × pto_base WITHOUT max_ack_delay (noq
    // set_key_discard_timer on the Handshake space, mod.rs:3733-3743).
    c.timers.armHandshakeKeyDiscard(now);
    try std.testing.expectEqual(now + 3 * c.rtt.ptoBase(), c.timers.handshake_key_discard_deadline.?);
    // Previous-key discard + close: 3 × (pto_base + data max_ack_delay)
    // (noq mod.rs:3175-3194 + set_close_timer, mod.rs:6598-6606).
    c.timers.armPreviousKeyDiscard(now);
    try std.testing.expectEqual(now + 3 * (c.rtt.ptoBase() + mad), c.timers.previous_key_discard_deadline.?);
    c.closeWith(now, .{ .error_code = 0, .reason = "g19", .is_app = true });
    try std.testing.expectEqual(now + 3 * (c.rtt.ptoBase() + mad), c.timers.close_deadline.?);
    // …and NOT the old fixed 3s.
    try std.testing.expect(c.timers.close_deadline.? != now + 3_000_000_000);
}

test "handshake-key discard timer waits out an unsent client flight" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try pair.client.startClient();
    const hs = @intFromEnum(spaces.SpaceId.handshake);
    var now: Instant = 0;
    var pkt_idx: usize = 0;
    var rounds: usize = 0;
    // Drive until the client has queued (but not yet transmitted) its Finished:
    // pumpOnce feeds the server flight to the client after the client's own
    // transmit pass, so the flight always waits one pump for its keys.
    while (rounds < 32) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
        if (pair.client.crypto_out[hs].items.len > pair.client.crypto_sent[hs]) break;
    }
    try std.testing.expect(pair.client.crypto_out[hs].items.len > pair.client.crypto_sent[hs]);
    try std.testing.expect(pair.client.write_keys[hs] != null);
    const deadline = pair.client.timers.handshake_key_discard_deadline orelse return error.UnexpectedState;
    // A fire with the flight still unsent must not strand the handshake:
    // the keys survive and the timer re-arms (noq only discards client
    // Handshake keys on HANDSHAKE_DONE, mod.rs:5262).
    pair.client.handleTimeout(deadline);
    try std.testing.expect(pair.client.write_keys[hs] != null);
    try std.testing.expect(pair.client.read_keys[hs] != null);
    const rearmed = pair.client.timers.handshake_key_discard_deadline orelse return error.UnexpectedState;
    try std.testing.expect(rearmed > deadline);
    // The flight then flushes under the surviving keys and the handshake
    // completes; confirmation discards the keys (frame path).
    while (rounds < 64 and !pair.client.handshake_confirmed) : (rounds += 1) {
        now += 1_000_000;
        try pumpOnce(&pair, now, &pkt_idx, null);
    }
    try std.testing.expect(pair.client.handshake_confirmed);
    try std.testing.expect(pair.client.write_keys[hs] == null);
}
