//! Sans-io QUIC connection driver (N3b-3).
//!
//! Greenfield idiomatic Zig — not a line-for-line port of noq's 7797-L `mod.rs`.
//! Scope for N3b-3: complete a 1-RTT handshake over loopback (CRYPTO + ACK +
//! HandshakeDone + one STREAM), carrying `path_generation` on every SentPacket
//! (#7) and establishing the timer-table shape (#9) for N3b-4.
//!
//! Full loss/ACK bookkeeping / CC land in N3b-4.
//!
//! N1 reorientation (module-reorientation / reorient-noq): stream half-state,
//! path/CID/NAT types, and timers+events live in sibling modules
//! (`stream_state.zig`, `path_cid.zig`, `timers_events.zig`). This file is the
//! orchestrator + public re-export surface. `tx_build` stays here (integration
//! point — not a peer module).

const std = @import("std");
const crypto = @import("crypto.zig");
const crypto_zigtls = if (crypto.zigtls_enabled) @import("crypto_zigtls.zig") else struct {};
const endpoint = @import("endpoint.zig");
const frame = @import("frame.zig");
const initial_keys = @import("initial_keys.zig");
const key = @import("../key.zig");
const tls_name = @import("../connection/tls_name.zig");
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

const stream_state = @import("stream_state.zig");
const path_cid = @import("path_cid.zig");
const timers_events = @import("timers_events.zig");
/// Socket-ABI types only (the ECN codepoint enum). The driver stays sans-io:
/// it never calls into the socket layer, it just names the codepoint it wants.
const udp_cmsg = @import("../transport/udp_cmsg.zig");

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

/// Destination is implied by the pair harness for N3b-3 (single path).
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
};

/// Load-bearing sent-packet record (#7 path_generation carried now for N3b-4 CC-gate).
pub const SentPacket = struct {
    path_generation: u64,
    time_sent: Instant,
    size: u16,
    ack_eliciting: bool,
    packet_number: u64,
    space: spaces.SpaceId,
    loss_reported: bool = false,
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
pub const max_datagram: usize = 1400;
/// RFC 9000 §14.1: every client Initial datagram is at least 1200 bytes.
const min_client_initial_datagram_size: usize = 1200;
// QUIC transport error codes (RFC 9000 §20.1).
pub const err_no_error: u64 = 0x00;
pub const err_flow_control: u64 = 0x03;
pub const err_stream_limit: u64 = 0x04;
pub const err_stream_state: u64 = 0x05;
pub const err_final_size: u64 = 0x06;
pub const err_frame_encoding: u64 = 0x07;
pub const err_protocol_violation: u64 = 0x0a;
pub const err_key_update: u64 = 0x0e;
/// Default flow-control windows we advertise (receive side).
pub const default_initial_max_data: u64 = 1 << 20;
pub const default_initial_max_stream_data: u64 = 256 * 1024;
pub const default_initial_max_streams: u64 = 16;
pub const default_max_idle_timeout_ms: u64 = 30_000;
/// Initial plaintext we pack into one 1-RTT data packet's frame region.
///
/// This keeps the first post-handshake data packets below the base 1200-byte
/// QUIC datagram size. Once MTU probing raises `self.mtu`, the packet builder
/// can use the confirmed path headroom.
const base_data_payload_budget: usize = 1100;
const data_payload_headroom: usize = 96;

const TlsSession = union(enum) {
    picotls: if (crypto.picotls_enabled) *crypto.PicotlsSession else void,
    zigtls: if (crypto.zigtls_enabled) *crypto_zigtls.ZigtlsSession else void,

    fn destroy(self: *TlsSession) void {
        switch (self.*) {
            .picotls => |tls| {
                if (comptime crypto.picotls_enabled) {
                    tls.destroy();
                } else {}
            },
            .zigtls => |tls| {
                if (comptime crypto.zigtls_enabled) {
                    tls.destroy();
                } else {}
            },
        }
    }

    fn start(self: *TlsSession, allocator: std.mem.Allocator) Error!crypto.HandshakeOutput {
        return switch (self.*) {
            .picotls => |tls| picotls: {
                if (comptime crypto.picotls_enabled) {
                    break :picotls tls.start(allocator);
                } else {
                    break :picotls error.PicotlsError;
                }
            },
            .zigtls => |tls| zigtls: {
                if (comptime crypto.zigtls_enabled) {
                    break :zigtls tls.start(allocator) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.PicotlsError,
                    };
                } else {
                    break :zigtls error.ZigtlsDisabled;
                }
            },
        };
    }

    fn handleMessage(self: *TlsSession, allocator: std.mem.Allocator, epoch: crypto.Epoch, input: []const u8) Error!crypto.HandshakeOutput {
        return switch (self.*) {
            .picotls => |tls| picotls: {
                if (comptime crypto.picotls_enabled) {
                    break :picotls tls.handleMessage(allocator, epoch, input);
                } else {
                    break :picotls error.PicotlsError;
                }
            },
            .zigtls => |tls| zigtls: {
                if (comptime crypto.zigtls_enabled) {
                    break :zigtls tls.handleMessage(allocator, epoch, input) catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.PicotlsError,
                    };
                } else {
                    break :zigtls error.ZigtlsDisabled;
                }
            },
        };
    }

    fn isComplete(self: *const TlsSession) bool {
        return switch (self.*) {
            .picotls => |tls| picotls: {
                if (comptime crypto.picotls_enabled) {
                    break :picotls tls.isComplete();
                } else {
                    break :picotls false;
                }
            },
            .zigtls => |tls| zigtls: {
                if (comptime crypto.zigtls_enabled) {
                    break :zigtls tls.isComplete();
                } else {
                    break :zigtls false;
                }
            },
        };
    }

    fn trafficSecret(self: *const TlsSession, direction: crypto.Direction, epoch: crypto.Epoch) !crypto.TrafficSecret {
        return switch (self.*) {
            .picotls => |tls| picotls: {
                if (comptime crypto.picotls_enabled) {
                    break :picotls tls.trafficSecret(direction, epoch);
                } else {
                    break :picotls error.PicotlsError;
                }
            },
            .zigtls => |tls| zigtls: {
                if (comptime crypto.zigtls_enabled) {
                    break :zigtls tls.trafficSecret(direction, epoch);
                } else {
                    break :zigtls error.ZigtlsDisabled;
                }
            },
        };
    }

    fn peerTransportParams(self: *const TlsSession) ?[]const u8 {
        return switch (self.*) {
            .picotls => |tls| picotls: {
                if (comptime crypto.picotls_enabled) {
                    break :picotls tls.peerTransportParams();
                } else {
                    break :picotls null;
                }
            },
            .zigtls => |tls| zigtls: {
                if (comptime crypto.zigtls_enabled) {
                    break :zigtls tls.peerTransportParams();
                } else {
                    break :zigtls null;
                }
            },
        };
    }

    pub fn peerPublicKey(self: *TlsSession) !key.PublicKey {
        return switch (self.*) {
            .picotls => |tls| picotls: {
                if (comptime crypto.picotls_enabled) {
                    break :picotls tls.peerPublicKey();
                } else {
                    break :picotls error.PicotlsError;
                }
            },
            .zigtls => |tls| zigtls: {
                if (comptime crypto.zigtls_enabled) {
                    break :zigtls tls.peerPublicKey();
                } else {
                    break :zigtls error.ZigtlsDisabled;
                }
            },
        };
    }

    pub fn negotiatedProtocol(self: *TlsSession) ?[]const u8 {
        return switch (self.*) {
            .picotls => |tls| picotls: {
                if (comptime crypto.picotls_enabled) {
                    break :picotls tls.negotiatedProtocol();
                } else {
                    break :picotls null;
                }
            },
            .zigtls => |tls| zigtls: {
                if (comptime crypto.zigtls_enabled) {
                    break :zigtls tls.negotiatedProtocol();
                } else {
                    break :zigtls null;
                }
            },
        };
    }

    fn popZigtlsNewSessionTicket(self: *TlsSession) if (crypto.zigtls_enabled) ?crypto_zigtls.session.NewSessionTicketInfo else ?void {
        return switch (self.*) {
            .picotls => null,
            .zigtls => |tls| zigtls: {
                if (comptime crypto.zigtls_enabled) {
                    break :zigtls tls.popNewSessionTicket();
                } else {
                    break :zigtls null;
                }
            },
        };
    }

    fn wasZigtlsResumed(self: *const TlsSession) bool {
        return switch (self.*) {
            .picotls => false,
            .zigtls => |tls| zigtls: {
                if (comptime crypto.zigtls_enabled) {
                    break :zigtls tls.wasResumed();
                } else {
                    break :zigtls false;
                }
            },
        };
    }
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    role: crypto.Role,
    state: State = .handshake,
    tls: TlsSession,

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

    // Outbound CRYPTO per epoch (initial / handshake / app). Kept in full (not
    // cleared after send) so lost CRYPTO can be re-sent by offset (real retransmit).
    crypto_out: [3]std.ArrayList(u8) = .{ .empty, .empty, .empty },
    crypto_sent: [3]u64 = .{ 0, 0, 0 }, // high-water offset already put on the wire
    crypto_rtx: [3]std.Deque(Chunk) = .{ .empty, .empty, .empty }, // lost crypto chunks
    crypto_in_offset: [3]u64 = .{ 0, 0, 0 },

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
    data_blocked_at: u64 = 0,
    local_params: transport_parameters.TransportParameters = .{},
    peer_params: transport_parameters.TransportParameters = .{},
    peer_params_applied: bool = false,
    idle_timeout_ns: ?i64 = null,
    idle_deadline: ?Instant = null,

    // Close.
    close_frame: ?frame.ConnectionClose = null,
    close_sent: bool = false,

    // Path validation (5e, RFC 9000 §8.2). `challenge_pending` = tokens queued to
    // send once; `challenge_await` = sent, awaiting a matching PATH_RESPONSE;
    // `response_tx` = responses we owe for received PATH_CHALLENGEs; `validated` =
    // tokens confirmed (challenge echoed back verbatim). A path is validated ONLY
    // by a matching response — never by merely receiving a datagram (anti-spoofing
    // / anti-amplification).
    challenge_pending: [max_path_tokens][8]u8 = undefined,
    challenge_pending_len: usize = 0,
    challenge_await: [max_path_tokens][8]u8 = undefined,
    challenge_await_len: usize = 0,
    response_tx: [max_path_tokens][8]u8 = undefined,
    response_tx_len: usize = 0,
    validated: [max_path_tokens][8]u8 = undefined,
    validated_len: usize = 0,
    path_validated_any: bool = false,
    bytes_received: u64 = 0,
    bytes_sent_unvalidated: u64 = 0,

    stateless_reset_token: [packet.stateless_reset_token_len]u8 = .{0} ** packet.stateless_reset_token_len,
    peer_stateless_reset_token: ?[packet.stateless_reset_token_len]u8 = null,
    /// Test-only: when true, `matchesPeerStatelessReset` always returns false
    /// (mutation-RED disable-point for real-peer H3).
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
    pending_new_token: [32]u8 = undefined,
    pending_new_token_len: usize = 0,
    retry_secret_key: [32]u8 = undefined,

    datagram_out: std.Deque([]u8) = .empty,
    datagram_in: std.Deque([]u8) = .empty,

    peer_ack_eliciting_threshold: ?u64 = null,
    peer_ack_max_ack_delay: ?u64 = null,
    ack_frequency_pending: bool = false,
    ack_frequency_seq: u64 = 1,
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
    cc: ?congestion.Controller = null,
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

    handshake_done_sent: bool = false,
    handshake_done_received: bool = false,
    handshake_confirmed: bool = false,

    events: std.Deque(Event) = .empty,
    tx_scratch: [max_datagram]u8 = undefined,

    now: Instant = 0,
    /// CSPRNG for security tokens (reset / NEW_TOKEN / CIDs). ChaCha8 seeded
    /// from caller-supplied entropy — never a non-crypto PRNG (audit-v4 H4).
    rng: std.Random.DefaultCsprng,

    pub fn create(
        allocator: std.mem.Allocator,
        config: crypto.Config,
        local_cid: packet.ConnectionId,
        remote_cid: packet.ConnectionId,
        initial_dcid: packet.ConnectionId,
        /// 32-byte secret seed for the connection CSPRNG (production: fill via
        /// `std.Io.random`; tests may use a deterministic pattern).
        seed: [std.Random.DefaultCsprng.secret_seed_length]u8,
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
        // Never advertise a QUIC datagram size larger than this driver's fixed
        // receive/decrypt scratch space. Real peers otherwise legitimately send
        // packets we cannot open after the handshake.
        local_params.max_udp_payload_size = @min(local_params.max_udp_payload_size, max_datagram);
        // RFC 9000 §18.2: `stateless_reset_token` is a server-only transport
        // parameter. A client MUST NOT send it — quinn rejects with
        // TRANSPORT_PARAMETER_ERROR("illegal value") (the interop-noq regression).
        // We still keep a local reset token for NEW_CONNECTION_ID / inbound-reset
        // detection; only the handshake TP advertisement is role-gated.
        local_params.stateless_reset_token = if (config.role == .server) reset_token else null;
        // A server must authenticate the client's original destination CID in
        // its transport parameters (RFC 9000 section 18.2). Real QUIC clients
        // reject the handshake when this is absent even if in-memory peers do not.
        local_params.original_destination_connection_id = if (config.role == .server) initial_dcid else null;
        cfg.transport_params = local_params.encode(&params_scratch) catch null;
        if (cfg.alpn == null) cfg.alpn = "iroh-interop-test";

        var tls: TlsSession = switch (cfg.backend) {
            .picotls => if (comptime crypto.picotls_enabled)
                .{ .picotls = try crypto.PicotlsSession.create(allocator, cfg) }
            else
                return error.PicotlsError,
            .zigtls => if (comptime crypto.zigtls_enabled)
                .{ .zigtls = try crypto_zigtls.ZigtlsSession.create(allocator, cfg) }
            else
                return error.ZigtlsDisabled,
        };
        errdefer tls.destroy();
        const cc = try congestion.create(allocator, .cubic, 0, @intCast(max_datagram));
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
            .cc = cc,
            .idle_timeout_ns = idleTimeoutNs(local_params.max_idle_timeout),
            .rng = rng,
            .stateless_reset_token = reset_token,
        };
        self.rng.fill(&self.retry_secret_key);
        self.local_cids[0] = .{
            .sequence = 0,
            .cid = local_cid,
            .reset_token = self.stateless_reset_token,
        };
        self.local_cid_len = 1;
        self.ack_frequency_pending = true;
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
        for (&self.streams) |*s| {
            if (s.used) {
                s.send.deinit(self.allocator);
                s.recv.deinit(self.allocator);
            }
        }
        self.sent.deinit(self.allocator);
        self.events.deinit(self.allocator);
        var datagram_out_it = self.datagram_out.iterator();
        while (datagram_out_it.next()) |d| self.allocator.free(d);
        self.datagram_out.deinit(self.allocator);
        var datagram_in_it = self.datagram_in.iterator();
        while (datagram_in_it.next()) |d| self.allocator.free(d);
        self.datagram_in.deinit(self.allocator);
        if (self.initial_token.len != 0) self.allocator.free(self.initial_token);
        if (self.stored_new_token.len != 0) self.allocator.free(self.stored_new_token);
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

    /// Client kicks off ClientHello into Initial CRYPTO.
    pub fn startClient(self: *Connection) !void {
        if (self.role != .client) return error.UnexpectedState;
        var out = try self.tls.start(self.allocator);
        defer out.deinit();
        try self.queueTlsOutput(out);
    }

    pub fn pollTimeout(self: *const Connection) ?Instant {
        var next: ?Instant = null;
        if (self.idle_deadline) |d| next = minOpt(next, d);
        if (self.timers.close_deadline) |d| next = minOpt(next, d);
        if (self.timers.handshake_key_discard_deadline) |d| next = minOpt(next, d);
        if (self.timers.previous_key_discard_deadline) |d| next = minOpt(next, d);
        if (self.ptoDeadline()) |d| next = minOpt(next, d);
        // RFC 9000 §13.2.1: a deferred ACK still has a deadline, and the pump
        // must wake for it or the peer's RTT sampling stalls.
        if (self.ackDeadline()) |d| next = minOpt(next, d);
        if (self.next_send_at > self.now and self.hasPacedOutbound()) {
            next = minOpt(next, self.next_send_at);
        }
        return next;
    }

    /// PTO deadline (RFC 9002 §6.2.1): last ack-eliciting send + backoff, if any
    /// ack-eliciting packet is still outstanding. Application-data outstanding
    /// includes the peer's max_ack_delay term.
    fn ptoDeadline(self: *const Connection) ?Instant {
        var last: ?Instant = null;
        var data_outstanding = false;
        for (self.sent.items) |sp| {
            if (!sp.ack_eliciting) continue;
            last = if (last) |l| @max(l, sp.time_sent) else sp.time_sent;
            if (sp.space == .data) data_outstanding = true;
        }
        const t = last orelse return null;
        const mad: i64 = if (data_outstanding) self.peerMaxAckDelayNs() else 0;
        return t + loss.ptoDelay(self.rtt, self.pto_count, mad);
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

    pub fn popZigtlsNewSessionTicket(self: *Connection) if (crypto.zigtls_enabled) ?crypto_zigtls.session.NewSessionTicketInfo else ?void {
        return self.tls.popZigtlsNewSessionTicket();
    }

    pub fn wasZigtlsResumed(self: *const Connection) bool {
        return self.tls.wasZigtlsResumed();
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
                const initial = @intFromEnum(spaces.SpaceId.initial);
                const handshake = @intFromEnum(spaces.SpaceId.handshake);
                zeroPacketKeySlot(&self.write_keys[initial]);
                zeroPacketKeySlot(&self.read_keys[initial]);
                zeroPacketKeySlot(&self.write_keys[handshake]);
                zeroPacketKeySlot(&self.read_keys[handshake]);
                self.timers.handshake_key_discard_deadline = null;
            }
        }
        if (self.timers.previous_key_discard_deadline) |d| {
            if (now >= d) {
                zeroPacketKeySlot(&self.crypto_1rtt.prev);
                self.timers.previous_key_discard_deadline = null;
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
        // Find the oldest outstanding ack-eliciting packet and retransmit its frames.
        var oldest: ?usize = null;
        var oldest_time: Instant = std.math.maxInt(Instant);
        for (self.sent.items, 0..) |sp, i| {
            if (sp.ack_eliciting and sp.time_sent < oldest_time) {
                oldest_time = sp.time_sent;
                oldest = i;
            }
        }
        if (oldest) |i| {
            const sp = self.sent.items[i];
            const requeued_all = self.requeueContent(sp);
            self.stats_pto_events += 1;
            if (requeued_all) {
                self.notePacketLeftFlight(sp);
                _ = self.sent.orderedRemove(i);
                self.reclaimResetStreams();
            }
            self.pto_count +|= 1;
        }
    }

    /// The ALPN the TLS handshake selected for this connection. Backs the
    /// wire-neutral `transport.Connection.alpn()` seam the multi-ALPN Router
    /// dispatches on (`src/protocol.zig`).
    pub fn negotiatedProtocol(self: *Connection) ?[]const u8 {
        return self.tls.negotiatedProtocol();
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
        self.timers.armClose(now);
        self.events.pushBack(self.allocator, .{ .connection_lost = .{ .is_local = true, .reason = cc.reason } }) catch {};
    }

    /// Drive one outbound datagram (if anything to send). Returns slice into `tx_scratch`.
    pub fn pollTransmit(self: *Connection, now: Instant) Error!?Transmit {
        self.now = now;
        self.handleTimeout(now);
        if (self.state == .drained) return null;

        // Prefer spaces in order Initial → Handshake → Data (noq populate order).
        if (try self.buildSpacePacket(.initial)) |t| return t;
        if (try self.buildSpacePacket(.handshake)) |t| return t;
        // Data space runs once 1-RTT keys exist: established (streams/control) or
        // while emitting a pending CONNECTION_CLOSE after a local close.
        if (self.state == .established or self.handshake_confirmed or self.close_frame != null) {
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
            if (try self.buildSpacePacket(.data)) |t| return t;
        }
        return null;
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
        const fallback = @max(mtu * 2, @min(effective_window / 4, mtu * 10));
        capacity = @max(capacity, fallback);
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

    pub fn sendDatagram(self: *Connection, bytes: []const u8) Error!void {
        const max = self.peer_params.max_datagram_frame_size orelse self.local_params.max_datagram_frame_size orelse 1200;
        if (bytes.len > max) return error.DatagramTooLarge;
        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        try self.datagram_out.pushBack(self.allocator, copy);
    }

    pub fn recvDatagram(self: *Connection) ?[]u8 {
        return self.datagram_in.popFront();
    }

    pub fn queueNewConnectionId(self: *Connection) Error!void {
        if (self.pending_new_cid) return;
        if (self.local_cid_len >= max_local_cid_slots) return;
        var cid_bytes: [packet.max_cid_size]u8 = undefined;
        self.rng.fill(&cid_bytes);
        const cid_len: u8 = 8;
        self.pending_new_cid_len = cid_len;
        @memcpy(self.pending_new_cid_buf[0..cid_len], cid_bytes[0..cid_len]);
        self.rng.fill(&self.pending_new_cid_reset);
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

    pub fn consumeRetry(self: *Connection, datagram: []const u8) Error!void {
        if (self.role != .client) return error.UnexpectedState;
        const retry = try packet.parseRetry(datagram);
        if (retry.version != 1) return error.UnsupportedVersion;
        const prefix = try self.allocator.dupe(u8, datagram[0 .. datagram.len - 16]);
        defer self.allocator.free(prefix);
        const expected_tag = try initial_keys.retryIntegrityTag(self.allocator, self.initial_dcid.slice(), prefix);
        if (!std.mem.eql(u8, &expected_tag, &retry.integrity_tag)) return error.AuthenticationFailed;
        if (self.initial_token.len != 0) self.allocator.free(self.initial_token);
        self.initial_token = try self.allocator.dupe(u8, retry.token);
        // Retry Source CID carries the client's original DCID; adopt server path token.
        self.remote_cid = retry.src_cid;
        const secrets = initial_keys.deriveInitialSecrets(self.initial_dcid.slice());
        const client_k = packet_crypto.keysFromTrafficSecret(&secrets.client);
        const server_k = packet_crypto.keysFromTrafficSecret(&secrets.server);
        self.write_keys[@intFromEnum(spaces.SpaceId.initial)] = client_k;
        self.read_keys[@intFromEnum(spaces.SpaceId.initial)] = server_k;
    }

    pub fn storedNewToken(self: *const Connection) ?[]const u8 {
        if (self.stored_new_token.len == 0) return null;
        return self.stored_new_token;
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
    fn validatePeerEcn(self: *Connection, space: spaces.SpaceId, a: frame.Ack, newly_acked_marked: u64) void {
        if (self.ecn_state == .disabled) return;
        // Only the data space carries our ECT(0) marking.
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
    /// real-peer H1 to assert ACK-delay scaling does not inflate RTT.
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
        // If we are closing, re-arm one CONNECTION_CLOSE in response to this
        // incoming packet (RFC 9000 §10.2); does not resurrect a drained conn.
        if (self.close_frame != null and self.state == .closed) self.close_sent = false;
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
                if (self.peer_params_applied and n >= self.peer_params.initial_max_streams_bidi) return error.StreamLimit;
                self.next_bidi += 1;
                break :blk n * 4 + role_bit;
            },
            .uni => blk: {
                const n = self.next_uni;
                if (self.peer_params_applied and n >= self.peer_params.initial_max_streams_uni) return error.StreamLimit;
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
        if (e.recv.stop_code == null) e.recv.stop_code = code;
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

    /// Retained send storage, excluding already-reclaimed absolute prefixes.
    pub fn streamSendBufferedLen(self: *Connection, id: u64) usize {
        const e = self.findStream(id) orelse return 0;
        return e.send.buf.items.len;
    }

    // ── Path validation API (5e, RFC 9000 §8.2) ─────────────────────────────

    /// Queue a PATH_CHALLENGE carrying `token`; a matching PATH_RESPONSE marks
    /// the path validated. The caller supplies a random, unguessable token.
    pub fn challengePath(self: *Connection, token: [8]u8) void {
        if (self.challenge_pending_len >= max_path_tokens) return;
        self.challenge_pending[self.challenge_pending_len] = token;
        self.challenge_pending_len += 1;
    }

    /// Queue an n0 NAT-traversal address frame for transmission (magicsock).
    pub fn advertiseAddress(self: *Connection, a: NatAddress) void {
        if (self.nat_out_len >= max_path_tokens) return;
        self.nat_out[self.nat_out_len] = a;
        self.nat_out_len += 1;
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
                self.challenge_await_len -= 1;
                self.markPathValidated();
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
        if (!self.peer_params_applied) return 0;
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

    fn armIdle(self: *Connection, now: Instant) void {
        const timeout = self.idle_timeout_ns orelse return;
        self.idle_deadline = now +| timeout;
    }

    fn applyPeerParams(self: *Connection) void {
        if (self.peer_params_applied) return;
        const tp = self.tls.peerTransportParams() orelse return;
        self.peer_params = transport_parameters.decode(tp) catch return;
        self.peer_params_applied = true;
        self.send_max_data = self.peer_params.initial_max_data;
        self.idle_timeout_ns = effectiveIdleTimeoutNs(self.local_params.max_idle_timeout, self.peer_params.max_idle_timeout);
        if (self.peer_params.stateless_reset_token) |token| {
            self.peer_stateless_reset_token = token;
        }
        self.armIdle(self.now);
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
        // Application (1-RTT)
        if (self.write_keys[@intFromEnum(spaces.SpaceId.data)] == null) {
            if (self.tls.trafficSecret(.write, .application)) |sec| {
                self.write_keys[@intFromEnum(spaces.SpaceId.data)] = packet_crypto.keysFromTrafficSecret(sec.slice());
                @memcpy(self.app_write_secret[0..sec.len], sec.slice());
                self.app_write_secret_len = sec.len;
            } else |_| {}
        }
        if (self.read_keys[@intFromEnum(spaces.SpaceId.data)] == null) {
            if (self.tls.trafficSecret(.read, .application)) |sec| {
                self.read_keys[@intFromEnum(spaces.SpaceId.data)] = packet_crypto.keysFromTrafficSecret(sec.slice());
                @memcpy(self.app_read_secret[0..sec.len], sec.slice());
                self.app_read_secret_len = sec.len;
            } else |_| {}
        }

        if (self.tls.isComplete() and self.state == .handshake) {
            // Move to established once we have 1-RTT keys and TLS complete.
            if (self.write_keys[@intFromEnum(spaces.SpaceId.data)] != null) {
                self.state = .established;
                self.next_send_at = self.now;
                self.markPathValidated();
                self.applyPeerParams();
                self.scheduleMtuProbes();
                if (self.role == .server) self.new_token_pending = true;
                try self.events.pushBack(self.allocator, .connected);
                self.timers.armHandshakeKeyDiscard(self.now);
            }
        }
        if (self.read_keys[@intFromEnum(spaces.SpaceId.data)]) |keys| {
            self.crypto_1rtt.current = keys;
        }
    }

    fn buildSpacePacket(self: *Connection, space: spaces.SpaceId) Error!?Transmit {
        if (space == .data) self.maybeStartMtuProbe();
        const keys = self.write_keys[@intFromEnum(space)] orelse return null;
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
        var datagram_wire: ?[]const u8 = null;
        var stream_payload_bytes: usize = 0;
        var paced_payload_bytes: usize = 0;
        const pace_content_blocked = space == .data and self.pace_content_blocked;
        if (space == .data and !pace_content_blocked and self.hasPacedOutbound()) {
            const pacing_budget: usize = @intCast(@min(self.pacing_tokens, @as(u64, @intCast(budget))));
            budget = @min(budget, pacing_budget);
        }
        var reset_commits = [_]bool{false} ** max_streams;

        // ACK (multi-range, RFC 9000 §19.3) from the per-space receive tracker.
        if (self.needs_ack[si]) {
            if (self.pending_acks[si].toAckFrame(0)) |ack_base| {
                var ack = ack_base;
                const ecn_nonempty = self.ecn_counts.ect0 != 0 or self.ecn_counts.ect1 != 0 or self.ecn_counts.ce != 0;
                if (ecn_nonempty) ack.ecn = self.ecn_counts;
                frames[n] = .{ .ack = ack };
                n += 1;
                self.needs_ack[si] = false;
                // The obligation is discharged; a later deferred ACK re-arms.
                self.ack_deadline[si] = null;
            }
        }

        // CONNECTION_CLOSE (data space): send once, then only re-send in response
        // to an incoming packet while closing (RFC 9000 §10.2). This keeps the
        // pump's drain loop terminating rather than emitting close forever.
        if (space == .data and self.close_frame != null and !self.close_sent) {
            frames[n] = .{ .connection_close = self.close_frame.? };
            n += 1;
            ack_eliciting = true;
            const pn = self.spaces_state.get(space).getTxNumber();
            const tx = try self.finishPacket(space, keys, frames[0..n], &content, cn, ack_eliciting, pn, 0, 0);
            self.close_sent = true;
            return tx;
        }

        // CRYPTO: retransmit lost chunks first, then fresh unsent bytes.
        if (!pace_content_blocked) {
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

        if (space == .data and self.state == .established) {
            // NEW_CONNECTION_ID when queued.
            if (self.pending_new_cid and n < frames.len) {
                frames[n] = .{ .new_connection_id = .{
                    .sequence = self.pending_new_cid_seq,
                    .retire_prior_to = self.pending_new_cid_retire,
                    .connection_id = self.pending_new_cid_buf[0..self.pending_new_cid_len],
                    .reset_token = self.pending_new_cid_reset,
                } };
                n += 1;
                ack_eliciting = true;
            }

            // NEW_TOKEN once after handshake (address validation).
            if (self.new_token_pending and n < frames.len) {
                self.rng.fill(&self.pending_new_token);
                self.pending_new_token_len = self.pending_new_token.len;
                frames[n] = .{ .new_token = .{ .token = self.pending_new_token[0..self.pending_new_token_len] } };
                n += 1;
                ack_eliciting = true;
                self.new_token_pending = false;
            }

            // ACK_FREQUENCY once after handshake (RFC 9368).
            // `request_max_ack_delay` is MICROSECONDS; the transport-parameter
            // `max_ack_delay` is MILLISECONDS. Quinn rejects values below its
            // timer granularity (~1 ms) with PROTOCOL_VIOLATION ("less than
            // min_ack_delay") — the post-TP interop-noq failure mode.
            if (self.ack_frequency_pending and n < frames.len) {
                const max_ack_delay_us = std.math.mul(u64, self.local_params.max_ack_delay, 1000) catch std.math.maxInt(u64);
                frames[n] = .{ .ack_frequency = .{
                    .sequence_number = self.ack_frequency_seq,
                    .ack_eliciting_threshold = 2,
                    .request_max_ack_delay = max_ack_delay_us,
                    .reordering_threshold = 1,
                } };
                n += 1;
                ack_eliciting = true;
                self.ack_frequency_pending = false;
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
            while (self.response_tx_len > 0 and n < frames.len) {
                frames[n] = .{ .path_response = self.response_tx[0] };
                n += 1;
                ack_eliciting = true;
                std.mem.copyForwards([8]u8, self.response_tx[0 .. self.response_tx_len - 1], self.response_tx[1..self.response_tx_len]);
                self.response_tx_len -= 1;
            }
            // n0 NAT-traversal address advertisements (magicsock).
            while (self.nat_out_len > 0 and n < frames.len) {
                const a = self.nat_out[0];
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

            while (self.challenge_pending_len > 0 and n < frames.len) {
                const token = self.challenge_pending[0];
                frames[n] = .{ .path_challenge = token };
                n += 1;
                ack_eliciting = true;
                std.mem.copyForwards([8]u8, self.challenge_pending[0 .. self.challenge_pending_len - 1], self.challenge_pending[1..self.challenge_pending_len]);
                self.challenge_pending_len -= 1;
                if (self.challenge_await_len < max_path_tokens) {
                    self.challenge_await[self.challenge_await_len] = token;
                    self.challenge_await_len += 1;
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
                    const flow_window = self.streamSendWindow(e);
                    if (flow_window == 0) {
                        // Flow-control blocked → signal once per window.
                        if (e.send.blocked_at != e.send.max_data) {
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
                    ack_eliciting = true;
                    const pn = self.spaces_state.get(space).getTxNumber();
                    return self.finishPacket(space, keys, frames[0..n], &content, cn, ack_eliciting, pn, target, 0) catch |err| switch (err) {
                        error.AntiAmplificationLimit, error.NoSpaceLeft => {
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

        const pn = self.spaces_state.get(space).getTxNumber();
        var min_size: usize = 0;
        if (space == .data and ack_eliciting and stream_payload_bytes > 0) {
            if (self.probe_mtu) |target| {
                if (target > max_datagram) {
                    self.probe_mtu = null;
                } else if (stream_payload_bytes * 2 >= target and self.congestionSendWindow() >= target) {
                    min_size = @intCast(target);
                }
            }
        }
        const tx = self.finishPacket(space, keys, frames[0..n], &content, cn, ack_eliciting, pn, min_size, paced_payload_bytes) catch |err| switch (err) {
            error.AntiAmplificationLimit => return null,
            else => |e| return e,
        };
        for (reset_commits, 0..) |commit, stream_i| {
            if (commit) self.streams[stream_i].send.reset_sent = true;
        }
        if (datagram_wire) |owned| {
            _ = self.datagram_out.popFront();
            self.allocator.free(owned);
        }
        return tx;
    }

    fn finishPacket(
        self: *Connection,
        space: spaces.SpaceId,
        keys: packet_crypto.PacketKeys,
        frames: []const frame.Frame,
        content: *const [max_content]FrameRef,
        cn: usize,
        ack_eliciting: bool,
        pn: u64,
        min_datagram_size: usize,
        paced_payload_bytes: usize,
    ) Error!Transmit {
        const key_phase = if (space == .data) self.write_key_phase else false;
        const built = switch (space) {
            .initial => try packet_builder.buildLongHeader(&self.tx_scratch, .initial, 1, self.remote_cid, self.local_cid, "", pn, frames, keys, if (self.role == .client) min_client_initial_datagram_size else 0),
            .handshake => try packet_builder.buildLongHeader(&self.tx_scratch, .handshake, 1, self.remote_cid, self.local_cid, "", pn, frames, keys, 0),
            .data => try packet_builder.buildOneRtt(&self.tx_scratch, self.remote_cid, pn, key_phase, frames, keys, min_datagram_size),
        };
        if (self.role == .server and !self.isPathValidated()) {
            const limit = self.bytes_received * 3;
            if (self.bytes_sent_unvalidated + built.bytes.len > limit) return error.AntiAmplificationLimit;
            self.bytes_sent_unvalidated += built.bytes.len;
        }
        if (self.probe_mtu != null and min_datagram_size > 0) self.probe_pn = pn;
        // ECN is marked on 1-RTT data only: Initial/Handshake predate the
        // validation feedback loop, and a bleached handshake is not recoverable.
        const ecn: ?udp_cmsg.EcnCodepoint = if (space == .data) self.outgoingEcn() else null;
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
            .packet_number = pn,
            .space = space,
            .content_len = @intCast(cn),
            .ecn_marked = ecn != null,
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
        self.armIdle(self.now);
        return .{ .bytes = built.bytes, .ecn = ecn };
    }

    fn trackSent(self: *Connection, sp: SentPacket) void {
        std.debug.assert(self.sent.items.len < max_tracked_sent_packets);
        self.sent.appendAssumeCapacity(sp);
        if (self.sent.items.len > self.stats_peak_sent) self.stats_peak_sent = self.sent.items.len;
        if (sp.ack_eliciting) {
            self.bytes_in_flight +|= sp.size;
            if (self.cc) |cc| {
                cc.onPacketSent(self.now, sp.size, sp.packet_number);
                cc.onSent(self.now, sp.size, sp.packet_number);
            }
        }
    }

    fn notePacketLeftFlight(self: *Connection, sp: SentPacket) void {
        if (!sp.ack_eliciting) return;
        self.bytes_in_flight -|= sp.size;
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

    fn onPacketAcked(self: *Connection, sp: SentPacket) void {
        // A delivery of this size proves the path still carries it, which
        // exonerates suspicious loss bursts of smaller packets. This runs for
        // every acked packet, not just ack-eliciting ones, because delivery is
        // delivery as far as the path MTU is concerned.
        if (sp.space == .data) self.mtu_black_hole.onAcked(sp.size);
        if (!sp.ack_eliciting) return;
        self.notePacketLeftFlight(sp);
        if (self.cc) |cc| {
            cc.onAck(self.now, sp.time_sent, sp.size, sp.packet_number, false, self.rtt.sample());
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
        if (self.cc) |cc| {
            cc.onPacketLost(sp.size, sp.packet_number, self.now);
            cc.onCongestionEvent(self.now, sp.time_sent, false, false, sp.size, sp.packet_number);
        }
    }

    fn handleLongPacket(self: *Connection, data: []const u8) Error!usize {
        if (data.len < 7) return 0;
        const first = data[0];
        const long_kind = (first & 0x30) >> 4;
        const space: spaces.SpaceId = switch (long_kind) {
            0 => .initial,
            2 => .handshake,
            else => return 0,
        };
        const keys = self.read_keys[@intFromEnum(space)] orelse return 0;

        // Parse unprotected-header skeleton to find length / pn_offset.
        var cursor: coding.Cursor = .{ .bytes = data };
        _ = try cursor.readU8(); // first
        const version = try cursor.readU32();
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
        if (packet_end > data.len) return error.DecryptFailed;

        var pkt_buf: [max_datagram]u8 = undefined;
        if (packet_end > pkt_buf.len) return error.NoSpaceLeft;
        @memcpy(pkt_buf[0..packet_end], data[0..packet_end]);

        // Decrypt header to learn PN length, then payload.
        try packet_crypto.decryptHeaderWithKeys(pkt_buf[0..packet_end], pn_offset, keys);
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
            return err;
        };

        const payload = pkt_buf[header_len .. packet_end - packet_crypto.tag_len];
        try self.processPayload(space, full_pn, payload);
        // A client's Initial is addressed to its chosen temporary DCID. Once an
        // authenticated server Initial arrives, every later client packet must
        // instead target the server-selected SCID (RFC 9000 §7.2). The old
        // in-memory pair harness patched this externally; real peers do not.
        if (self.role == .client and space == .initial) self.remote_cid = source_cid;
        return packet_end;
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
            if (saved_largest == null or full_pn > saved_largest.?) {
                space.largest_received = full_pn;
            }
            try self.commitReadKeyUpdate(phase);
            const payload = trial[header_len .. data.len - packet_crypto.tag_len];
            try self.processPayload(.data, full_pn, payload);
            return;
        }
        space.largest_received = saved_largest;

        // Fallback when crypto_1rtt slots are empty (early 1-RTT): use read_keys.
        if (self.crypto_1rtt.current == null) {
            const keys = self.read_keys[@intFromEnum(spaces.SpaceId.data)] orelse return error.MissingKeys;
            var pkt_buf: [max_datagram]u8 = undefined;
            @memcpy(pkt_buf[0..data.len], data);
            try packet_crypto.decryptHeaderWithKeys(pkt_buf[0..data.len], pn_offset, keys);
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
                return err;
            };
            const payload = pkt_buf[header_len .. data.len - packet_crypto.tag_len];
            try self.processPayload(.data, full_pn, payload);
            return;
        }
        return last_err;
    }

    fn processPayload(self: *Connection, space: spaces.SpaceId, pn: u64, payload: []const u8) Error!void {
        const si = @intFromEnum(space);
        if (!self.dedup[si].checkAndInsert(pn)) return;
        self.pending_acks[si].onRecv(pn);

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
            switch (decoded_frame) {
                .ping => ack_eliciting = true,
                .immediate_ack => {
                    ack_eliciting = true;
                    force_ack = true;
                },
                .handshake_done => {
                    ack_eliciting = true;
                    self.handshake_done_received = true;
                    self.handshake_confirmed = true;
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
                            self.state = .{ .draining = .{ .is_local = false, .reason = "peer-close" } };
                            self.timers.armClose(self.now);
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
                    try self.events.pushBack(self.allocator, .{ .nat_address = .{ .kind = .observed, .seq = a.seq, .ip = a.ip, .port = a.port } });
                },
                .add_ipv4_address => |a| {
                    ack_eliciting = true;
                    try self.events.pushBack(self.allocator, .{ .nat_address = .{ .kind = .add, .seq = a.seq, .ip = a.ip, .port = a.port } });
                },
                .reach_out_at_ipv4 => |a| {
                    ack_eliciting = true;
                    try self.events.pushBack(self.allocator, .{ .nat_address = .{ .kind = .reach_out, .seq = a.seq, .ip = a.ip, .port = a.port } });
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
                    self.retireRemoteConnectionId(r.sequence);
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
                },
                .datagram => |d| {
                    ack_eliciting = true;
                    const copy = try self.allocator.dupe(u8, d.data);
                    try self.datagram_in.pushBack(self.allocator, copy);
                },
            }
        }
        if (ack_eliciting) {
            if (force_ack or space != .data or self.peer_ack_eliciting_threshold == null or self.peer_ack_eliciting_threshold.? <= 1) {
                self.needs_ack[si] = true;
            } else {
                self.peer_ack_eliciting_pending += 1;
                if (self.peer_ack_eliciting_pending >= self.peer_ack_eliciting_threshold.?) {
                    self.needs_ack[si] = true;
                    self.peer_ack_eliciting_pending = 0;
                } else {
                    // Below the threshold: the ACK is deferred, but RFC 9000
                    // §13.2.1 caps that deferral at `max_ack_delay`. Arm the
                    // timer (leaving an already-armed, earlier deadline alone —
                    // the obligation dates from the FIRST unacked packet).
                    self.armAckTimer(si);
                }
            }
            if (self.needs_ack[si]) self.ack_deadline[si] = null;
        }
    }

    /// Arm the delayed-ACK deadline for `si` if it is not already armed.
    fn armAckTimer(self: *Connection, si: usize) void {
        if (self.ack_deadline[si] != null) return;
        self.ack_deadline[si] = self.now + self.localMaxAckDelayNs();
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
    fn handleAckTimeout(self: *Connection, now: Instant) void {
        for (&self.ack_deadline, 0..) |*deadline, si| {
            const d = deadline.* orelse continue;
            if (now < d) continue;
            deadline.* = null;
            self.needs_ack[si] = true;
            self.peer_ack_eliciting_pending = 0;
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
    }

    fn retireRemoteConnectionId(self: *Connection, sequence: u64) void {
        for (&self.remote_cids, 0..) |*slot, i| {
            if (i < self.remote_cid_len and slot.sequence == sequence) slot.retired = true;
        }
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
        // Remove newly-acked packets (no retransmit) + sample RTT from the largest.
        var largest_time: ?Instant = null;
        var largest_acked_seen: ?u64 = null;
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
                if (sp.ecn_marked) newly_acked_marked += 1;
                self.onPacketAcked(sp);
                continue;
            }
            self.noteOutstandingStreamMin(sp, &reclaim_safe);
            if (write != read) self.sent.items[write] = sp;
            write += 1;
        }
        self.sent.shrinkRetainingCapacity(write);
        if (largest_time) |t| {
            const sample = self.now - t;
            // RFC 9002 §5: scale wire ack_delay by 2^ack_delay_exponent and cap
            // by max_ack_delay before feeding the RTT estimator (H1).
            if (sample > 0) self.rtt.update(self.scaledAckDelayNs(space, a.ack_delay), sample);
            self.pto_count = 0; // ack received → reset PTO backoff (RFC 9002 §6.2.1)
        }
        if (self.probe_pn) |probe| {
            if (ackContains(a, probe)) self.onMtuProbeAcked();
        }
        // RFC 9000 §13.4.2.1: validate the peer's ECN echo before letting it
        // drive congestion control, so a bleaching or lying path cannot shrink
        // our window. Runs before `onEndAcks` so the CC sees the full round.
        self.validatePeerEcn(space, a, newly_acked_marked);
        if (self.cc) |cc| cc.onEndAcks(self.now, self.bytes_in_flight, false, largest_acked_seen);
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

    fn detectAndRequeueLosses(self: *Connection, space: spaces.SpaceId) void {
        const largest = (self.spaces_state.getConst(space).largest_acked) orelse return;
        var out: [max_loss_batch]loss.LossEvent = undefined;
        const nlost = loss.detectLostPackets(self.sent.items, self.now, largest, space, self.rtt, &out);
        if (nlost == 0) return;
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

    fn ingestCrypto(self: *Connection, space: spaces.SpaceId, c: frame.Crypto) Error!void {
        // Require in-order CRYPTO for the N3b-3 lossless gate (N3b-4 adds reordering).
        const expected = self.crypto_in_offset[@intFromEnum(space)];
        if (c.offset != expected) {
            // Ignore future out-of-order for now (retransmit will fill gaps in N3b-4).
            if (c.offset > expected) return;
            // Retransmit of already-consumed data: skip
            if (c.offset + c.data.len <= expected) return;
            // Partial overlap: take the suffix
            const skip = expected - c.offset;
            const data = c.data[skip..];
            try self.feedTls(space, data);
            self.crypto_in_offset[@intFromEnum(space)] = expected + data.len;
            return;
        }
        try self.feedTls(space, c.data);
        self.crypto_in_offset[@intFromEnum(space)] = expected + c.data.len;
    }

    fn feedTls(self: *Connection, space: spaces.SpaceId, data: []const u8) Error!void {
        const epoch: crypto.Epoch = switch (space) {
            .initial => .initial,
            .handshake => .handshake,
            .data => .application,
        };
        var out = try self.tls.handleMessage(self.allocator, epoch, data);
        defer out.deinit();
        try self.queueTlsOutput(out);
        try self.events.pushBack(self.allocator, .handshake_data);
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
    }, client_cid, initial_dcid, initial_dcid, testCsprngSeed(0xC0FFEE));
    errdefer client.destroy();

    const server = try Connection.create(allocator, .{
        .backend = backend,
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = client_key.public(),
        .require_client_authentication = true,
        .transport_params = server_params,
    }, server_cid, client_cid, initial_dcid, testCsprngSeed(0xBADC0DE));
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

    for (0..40) |value| {
        try pair.client.sendDatagram(&.{@intCast(value)});
    }
    for (0..20) |expected| {
        const payload = pair.client.datagram_out.popFront() orelse return error.UnexpectedState;
        const value = payload[0];
        std.testing.allocator.free(payload);
        try std.testing.expectEqual(@as(u8, @intCast(expected)), value);
    }
    for (40..60) |value| {
        try pair.client.sendDatagram(&.{@intCast(value)});
    }
    for (20..60) |expected| {
        const payload = pair.client.datagram_out.popFront() orelse return error.UnexpectedState;
        const value = payload[0];
        std.testing.allocator.free(payload);
        try std.testing.expectEqual(@as(u8, @intCast(expected)), value);
    }
    try std.testing.expectEqual(@as(usize, 0), pair.client.datagram_out.len);
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
    try pair.client.processPayload(.data, 9001, buf[0..index]);
    const a = pair.client.recvDatagram() orelse return error.UnexpectedState;
    defer std.testing.allocator.free(a);
    const b = pair.client.recvDatagram() orelse return error.UnexpectedState;
    defer std.testing.allocator.free(b);
    try std.testing.expectEqualSlices(u8, "aa", a);
    try std.testing.expectEqualSlices(u8, "bb", b);
    // No third datagram (padding / leftover not absorbed).
    try std.testing.expect(pair.client.recvDatagram() == null);
}

test "processPayload malformed frame maps to FrameEncodeFailed and protocolClose" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try std.testing.expectError(error.FrameEncodeFailed, pair.client.processPayload(.data, 9002, &.{0xff}));
    const close_frame = pair.client.close_frame orelse return error.UnexpectedState;
    try std.testing.expectEqual(err_frame_encoding, close_frame.error_code);
}

test "length-bearing DATAGRAM does not absorb following padding as data" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    // 0x31 len=1 payload=0xaa then padding zeros — padding must not join the datagram.
    const wire = [_]u8{ 0x31, 0x01, 0xaa, 0x00, 0x00, 0x00 };
    try pair.client.processPayload(.data, 9003, &wire);
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
    try pair.client.processPayload(.data, 999, enc);
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

test "committed NEW_CONNECTION_ID enters local CID inventory" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const before = pair.server.local_cid_len;
    try pair.server.queueNewConnectionId();

    pair.server.next_send_at = 0;
    _ = (try pair.server.pollTransmit(pair.server.now + 1)) orelse return error.UnexpectedState;

    try std.testing.expectEqual(before + 1, pair.server.local_cid_len);
    const published = pair.server.localConnectionId(before) orelse return error.UnexpectedState;
    try std.testing.expectEqual(@as(u8, 8), published.len);
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

test "peer-initiated key update advances write keys before response" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.client.mtu_probe_queue_len = 0;
    pair.client.probe_mtu = null;
    pair.client.probe_pn = null;
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

test "N-3 ACK_FREQUENCY threshold delays ACK until third eliciting packet" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    pair.server.peer_ack_eliciting_threshold = 3;
    pair.server.peer_ack_eliciting_pending = 0;
    var buf: [64]u8 = undefined;
    const ping: frame.Frame = .ping;
    const enc = try ping.encode(&buf);
    try pair.server.processPayload(.data, 100, enc);
    try std.testing.expect(!pair.server.needs_ack[@intFromEnum(spaces.SpaceId.data)]);
    try pair.server.processPayload(.data, 101, enc);
    try std.testing.expect(!pair.server.needs_ack[@intFromEnum(spaces.SpaceId.data)]);
    try pair.server.processPayload(.data, 102, enc);
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

test "ECN: Initial and Handshake packets are never marked" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    // Marking before the validation feedback loop exists would be unrecoverable
    // if the path bleached the handshake.
    try pair.client.startClient();
    const initial = (try pair.client.pollTransmit(1_000_000)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(initial.ecn == null);
    try std.testing.expectEqual(@as(u64, 0), pair.client.ecnSentForTest().ect0);
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

    // One ack-eliciting packet, below the threshold: the ACK is deferred, but
    // the timer must be armed or the peer waits forever.
    var buf: [8]u8 = undefined;
    const ping_frame: frame.Frame = .ping;
    const ping = try ping_frame.encode(&buf);
    try s.processPayload(.data, 5000, ping);
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
    s.peer_ack_eliciting_threshold = 2;
    s.peer_ack_eliciting_pending = 0;
    s.needs_ack[si] = false;
    s.ack_deadline[si] = null;
    s.stats_delayed_ack_timeouts = 0;

    var buf: [8]u8 = undefined;
    const ping_frame: frame.Frame = .ping;
    const ping = try ping_frame.encode(&buf);
    try s.processPayload(.data, 6000, ping);
    try std.testing.expect(s.ackDeadlineForTest(.data) != null);

    try s.processPayload(.data, 6001, ping);
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

    var buf: [8]u8 = undefined;
    const ping_frame: frame.Frame = .ping;
    const ping = try ping_frame.encode(&buf);
    try s.processPayload(.data, 7000, ping);
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
    try pair.client.processPayload(.data, 500, enc);
    try std.testing.expectEqualStrings("resume-addr-token", pair.client.storedNewToken().?);
}

test "N-3 mtu probe ack raises mtu" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    try establishPair(&pair);
    const start_mtu = pair.client.mtu;
    pair.client.mtu_probe_queue_len = 0;
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
    // H3: detection uses the PEER's token (server's advertised reset token for the
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
    try std.testing.expect(client.state == .closed);
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
        try pair.client.processPayload(.data, 1000 + i, enc);
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
    try pair.client.processPayload(.data, 2001, try f1.encode(&buf));
    const f2: frame.Frame = .{ .new_connection_id = .{
        .sequence = 2,
        .retire_prior_to = 0,
        .connection_id = &cid_b,
        .reset_token = .{0x22} ** 16,
    } };
    try pair.client.processPayload(.data, 2002, try f2.encode(&buf));
    const f3: frame.Frame = .{ .new_connection_id = .{
        .sequence = 3,
        .retire_prior_to = 2,
        .connection_id = &cid_c,
        .reset_token = .{0x33} ** 16,
    } };
    try pair.client.processPayload(.data, 2003, try f3.encode(&buf));
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
    // Must use the PEER token (H3); our own token is never the detection key.
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
    try pair.client.processPayload(.data, 3001, try f.encode(&buf));
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

// ── audit-v4 noq+discovery hardening mutation-RED unit tests ────────────────

test "audit-v4 H1: ack_delay is scaled by 2^ack_delay_exponent and capped" {
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

test "audit-v4 H2: data-space PTO includes peer max_ack_delay" {
    var pair = try makePair(std.testing.allocator, null);
    defer pair.deinit();
    pair.client.peer_params.max_ack_delay = 25; // ms
    pair.client.peer_params_applied = true;
    pair.client.rtt = loss.RttEstimator.init(100_000_000); // 100 ms
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
    const without_mad = loss.ptoDelay(pair.client.rtt, 0, 0);
    const with_mad = loss.ptoDelay(pair.client.rtt, 0, pair.client.peerMaxAckDelayNs());
    try std.testing.expect(with_mad > without_mad);
    try std.testing.expectEqual(with_mad, deadline);
}

test "audit-v4 H3: own-token reset is ignored; peer-token RFC-shape drains" {
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

test "audit-v4 H4: connection CSPRNG is DefaultCsprng not Pcg" {
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

test "audit-v4 M1: long-header non-v1 is skipped without erroring the connection" {
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

test "audit-v4 M3: shortHeaderPnOffset matches rotated local CID length" {
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

test "audit-v4 M7: ACK of never-sent PN is PROTOCOL_VIOLATION" {
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
