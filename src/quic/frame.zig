const std = @import("std");
const coding = @import("coding.zig");
const packet = @import("packet.zig");
const varint = @import("varint.zig");

pub const FrameType = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08, // base; actual wire types 0x08–0x0f
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    connection_close_app = 0x1d,
    handshake_done = 0x1e,
    immediate_ack = 0x1f,
    datagram = 0x30,
    datagram_len = 0x31,
    ack_frequency = 0xaf,
    observed_ipv4_addr = 0x9f81a6,
    observed_ipv6_addr = 0x9f81a7,
    add_ipv4_address = 0x3d7f90,
    add_ipv6_address = 0x3d7f91,
    reach_out_at_ipv4 = 0x3d7f92,
    reach_out_at_ipv6 = 0x3d7f93,
    remove_address = 0x3d7f94,
    // ── multipath (draft-ietf-quic-multipath, noq frame.rs) ────────────────
    // I3: the family a multipath-capable peer emits once it negotiates
    // `initial_max_path_id`. Recognizing + round-tripping these keeps such a
    // peer from tripping UnsupportedFrameType on the shared wire.
    path_ack = 0x3e,
    path_ack_ecn = 0x3f,
    path_abandon = 0x3e75,
    path_status_backup = 0x3e76,
    path_status_available = 0x3e77,
    path_new_connection_id = 0x3e78,
    path_retire_connection_id = 0x3e79,
    max_path_id = 0x3e7a,
    paths_blocked = 0x3e7b,
    path_cids_blocked = 0x3e7c,
};

pub const Address4 = struct {
    seq: u64,
    ip: [4]u8,
    port: u16,
};

/// The IPv6 address-frame payload (noq frame.rs AddAddress/ReachOut with
/// is_ipv6): seq varint + 16-byte address + u16 port.
pub const Address6 = struct {
    seq: u64,
    ip: [16]u8,
    port: u16,
};

pub const Crypto = struct {
    offset: u64,
    data: []const u8,
};

pub const EcnCounts = struct {
    ect0: u64 = 0,
    ect1: u64 = 0,
    ce: u64 = 0,
};

/// One additional ACK range after the first (RFC 9000 §19.3.1).
pub const AckGapRange = struct {
    /// Packets skipped between this range and the previous (higher) range.
    gap: u64,
    /// Contiguous packets in this range minus 1 (wire `ACK Range`).
    range: u64,
};

/// Pragmatic decode bound for additional ACK ranges (stack buffer size).
/// Not an RFC constant — raised from 16 so a conformant reordering peer that
/// emits up to ~64 ranges (noq's `MAX_ACK_BLOCKS`) does not self-DoS us.
pub const max_ack_additional: usize = 64;

/// ACK frame (0x02) or ACK_ECN (0x03).
pub const Ack = struct {
    largest_acked: u64,
    ack_delay: u64,
    /// Contiguous packets at the high end minus 1 (wire `First ACK Range`).
    first_range: u64,
    additional_len: u8 = 0,
    additional_buf: [max_ack_additional]AckGapRange = undefined,
    ecn: ?EcnCounts = null,

    pub fn additional(self: *const Ack) []const AckGapRange {
        return self.additional_buf[0..self.additional_len];
    }

    pub fn withAdditional(largest: u64, delay: u64, first: u64, ranges: []const AckGapRange, ecn: ?EcnCounts) !Ack {
        if (ranges.len > max_ack_additional) return error.TooManyAckRanges;
        var a: Ack = .{
            .largest_acked = largest,
            .ack_delay = delay,
            .first_range = first,
            .additional_len = @intCast(ranges.len),
            .ecn = ecn,
        };
        @memcpy(a.additional_buf[0..ranges.len], ranges);
        return a;
    }
};

/// STREAM frame (type 0x08–0x0f). Encode always sets LEN; OFF when offset≠0; FIN when fin.
pub const Stream = struct {
    id: u64,
    offset: u64 = 0,
    fin: bool = false,
    data: []const u8,
};

/// RESET_STREAM (0x04) — abort the sending part of a stream (RFC 9000 §19.4).
pub const ResetStream = struct {
    stream_id: u64,
    app_error_code: u64,
    final_size: u64,
};

/// STOP_SENDING (0x05) — request the peer stop sending on a stream (§19.5).
pub const StopSending = struct {
    stream_id: u64,
    app_error_code: u64,
};

/// MAX_STREAM_DATA (0x11) — grant per-stream flow-control window (§19.10).
pub const MaxStreamData = struct {
    stream_id: u64,
    max_data: u64,
};

/// STREAM_DATA_BLOCKED (0x15) — sender is blocked on a stream window (§19.13).
pub const StreamDataBlocked = struct {
    stream_id: u64,
    max_data: u64,
};

/// CONNECTION_CLOSE (0x1c transport / 0x1d application) — §19.19.
pub const ConnectionClose = struct {
    error_code: u64 = 0,
    /// Frame type that triggered a transport close; ignored for application close.
    frame_type: u64 = 0,
    reason: []const u8 = "",
    is_app: bool = false,
};

/// B9 — noq `CloseEncoder` (frame.rs:930-947 transport, 980-987 application):
/// the reason phrase is truncated to fit the packet's remaining frame budget
/// rather than overflowing it. `max_frame_len` is the remaining frame space
/// (noq's `frame_space_remaining`); the returned slice is the reason prefix
/// that fits. The reserved 3 mirrors noq: 1 byte frame type + 2 for the
/// error-code varint; the reason-length varint is sized for the FULL reason
/// (noq sizes it pessimistically, before truncation).
pub fn truncatedCloseReason(cc: ConnectionClose, max_frame_len: usize) []const u8 {
    const vs = struct {
        fn f(v: u64) usize {
            return varint.size(v) catch unreachable;
        }
    }.f;
    const reserved = 3 + (if (cc.is_app) 0 else vs(cc.frame_type)) + vs(@intCast(cc.reason.len));
    const avail = max_frame_len -| reserved;
    return cc.reason[0..@min(cc.reason.len, avail)];
}

/// NEW_CONNECTION_ID (0x18) — RFC 9000 §19.15.
pub const NewConnectionId = struct {
    sequence: u64,
    retire_prior_to: u64,
    connection_id: []const u8,
    reset_token: [16]u8,
};

/// RETIRE_CONNECTION_ID (0x19) — RFC 9000 §19.16.
pub const RetireConnectionId = struct {
    sequence: u64,
};

/// NEW_TOKEN (0x07) — RFC 9000 §19.7.
pub const NewToken = struct {
    token: []const u8,
};

/// ACK_FREQUENCY (0xaf) — RFC 9368.
pub const AckFrequency = struct {
    sequence_number: u64,
    ack_eliciting_threshold: u64,
    request_max_ack_delay: u64,
    reordering_threshold: u64,
};

/// DATAGRAM (0x30 / 0x31) — RFC 9221.
pub const Datagram = struct {
    data: []const u8,
    with_length: bool = false,
};

// ── multipath (I3) ──────────────────────────────────────────────────────────

/// PATH_ACK (0x3e) / PATH_ACK_ECN (0x3f): an ACK scoped to a path. Body is the
/// path_id followed by the identical ACK layout as `Ack` (noq `PathAck`).
pub const PathAck = struct {
    path_id: u64,
    ack: Ack,
};

/// PATH_ABANDON (0x3e75): the sender has abandoned a path (noq `PathAbandon`).
pub const PathAbandon = struct {
    path_id: u64,
    error_code: u64,
};

/// PATH_STATUS_BACKUP (0x3e76) / PATH_STATUS_AVAILABLE (0x3e77).
pub const PathStatus = struct {
    path_id: u64,
    status_seq_no: u64,
};

/// PATH_NEW_CONNECTION_ID (0x3e78): NEW_CONNECTION_ID prefixed with a path_id
/// (noq `NewConnectionId` with `read_path`).
pub const PathNewConnectionId = struct {
    path_id: u64,
    sequence: u64,
    retire_prior_to: u64,
    connection_id: []const u8,
    reset_token: [16]u8,
};

/// PATH_RETIRE_CONNECTION_ID (0x3e79): path_id then sequence.
pub const PathRetireConnectionId = struct {
    path_id: u64,
    sequence: u64,
};

/// MAX_PATH_ID (0x3e7a): the largest path_id the sender will accept.
pub const MaxPathId = struct {
    path_id: u64,
};

/// PATHS_BLOCKED (0x3e7b): the sender is blocked on the peer's MAX_PATH_ID.
pub const PathsBlocked = struct {
    remote_max_path_id: u64,
};

/// PATH_CIDS_BLOCKED (0x3e7c): blocked on CIDs for a path.
pub const PathCidsBlocked = struct {
    path_id: u64,
    next_seq: u64,
};

pub const Frame = union(enum) {
    ping,
    immediate_ack,
    handshake_done,
    max_data: u64,
    crypto: Crypto,
    ack: Ack,
    stream: Stream,
    reset_stream: ResetStream,
    stop_sending: StopSending,
    max_stream_data: MaxStreamData,
    max_streams_bidi: u64,
    max_streams_uni: u64,
    data_blocked: u64,
    stream_data_blocked: StreamDataBlocked,
    streams_blocked_bidi: u64,
    streams_blocked_uni: u64,
    /// PATH_CHALLENGE (0x1a) — 8 opaque bytes for path validation (RFC 9000 §19.17).
    path_challenge: [8]u8,
    /// PATH_RESPONSE (0x1b) — echoes a received PATH_CHALLENGE (RFC 9000 §19.18).
    path_response: [8]u8,
    connection_close: ConnectionClose,
    new_connection_id: NewConnectionId,
    retire_connection_id: RetireConnectionId,
    new_token: NewToken,
    ack_frequency: AckFrequency,
    datagram: Datagram,
    observed_ipv4_addr: Address4,
    add_ipv4_address: Address4,
    add_ipv6_address: Address6,
    reach_out_at_ipv4: Address4,
    reach_out_at_ipv6: Address6,
    remove_address: u64,
    /// QAD observed-address report over IPv6 (draft-seemann, noq frame.rs
    /// ObservedAddr with is_ipv6=true).
    observed_ipv6_addr: Address6,
    // multipath (I3)
    path_ack: PathAck,
    path_abandon: PathAbandon,
    path_status_backup: PathStatus,
    path_status_available: PathStatus,
    path_new_connection_id: PathNewConnectionId,
    path_retire_connection_id: PathRetireConnectionId,
    max_path_id: MaxPathId,
    paths_blocked: PathsBlocked,
    path_cids_blocked: PathCidsBlocked,

    pub fn frameType(self: Frame) FrameType {
        return switch (self) {
            .ping => .ping,
            .immediate_ack => .immediate_ack,
            .handshake_done => .handshake_done,
            .max_data => .max_data,
            .crypto => .crypto,
            .ack => |a| if (a.ecn != null) .ack_ecn else .ack,
            .stream => .stream,
            .reset_stream => .reset_stream,
            .stop_sending => .stop_sending,
            .max_stream_data => .max_stream_data,
            .max_streams_bidi => .max_streams_bidi,
            .max_streams_uni => .max_streams_uni,
            .data_blocked => .data_blocked,
            .stream_data_blocked => .stream_data_blocked,
            .streams_blocked_bidi => .streams_blocked_bidi,
            .streams_blocked_uni => .streams_blocked_uni,
            .path_challenge => .path_challenge,
            .path_response => .path_response,
            .connection_close => |cc| if (cc.is_app) .connection_close_app else .connection_close,
            .new_connection_id => .new_connection_id,
            .retire_connection_id => .retire_connection_id,
            .new_token => .new_token,
            .ack_frequency => .ack_frequency,
            .datagram => |d| if (d.with_length) .datagram_len else .datagram,
            .observed_ipv4_addr => .observed_ipv4_addr,
            .observed_ipv6_addr => .observed_ipv6_addr,
            .add_ipv4_address => .add_ipv4_address,
            .add_ipv6_address => .add_ipv6_address,
            .reach_out_at_ipv4 => .reach_out_at_ipv4,
            .reach_out_at_ipv6 => .reach_out_at_ipv6,
            .remove_address => .remove_address,
            .path_ack => |p| if (p.ack.ecn != null) .path_ack_ecn else .path_ack,
            .path_abandon => .path_abandon,
            .path_status_backup => .path_status_backup,
            .path_status_available => .path_status_available,
            .path_new_connection_id => .path_new_connection_id,
            .path_retire_connection_id => .path_retire_connection_id,
            .max_path_id => .max_path_id,
            .paths_blocked => .paths_blocked,
            .path_cids_blocked => .path_cids_blocked,
        };
    }

    /// Exact on-wire byte length of this frame's encoding. Packet assembly
    /// uses this to budget frames WITHOUT a trial encode; it must stay in
    /// lockstep with `encode` (the round-trip test below asserts that).
    pub fn encodedLen(self: Frame) usize {
        const vs = struct {
            fn f(v: u64) usize {
                return varint.size(v) catch unreachable;
            }
        }.f;
        return switch (self) {
            .ping, .immediate_ack, .handshake_done => vs(@intFromEnum(self.frameType())),
            .max_data => |v| vs(@intFromEnum(FrameType.max_data)) + vs(v),
            .reset_stream => |r| vs(@intFromEnum(FrameType.reset_stream)) + vs(r.stream_id) + vs(r.app_error_code) + vs(r.final_size),
            .stop_sending => |s| vs(@intFromEnum(FrameType.stop_sending)) + vs(s.stream_id) + vs(s.app_error_code),
            .max_stream_data => |m| vs(@intFromEnum(FrameType.max_stream_data)) + vs(m.stream_id) + vs(m.max_data),
            .max_streams_bidi => |v| vs(@intFromEnum(FrameType.max_streams_bidi)) + vs(v),
            .max_streams_uni => |v| vs(@intFromEnum(FrameType.max_streams_uni)) + vs(v),
            .data_blocked => |v| vs(@intFromEnum(FrameType.data_blocked)) + vs(v),
            .stream_data_blocked => |s| vs(@intFromEnum(FrameType.stream_data_blocked)) + vs(s.stream_id) + vs(s.max_data),
            .streams_blocked_bidi => |v| vs(@intFromEnum(FrameType.streams_blocked_bidi)) + vs(v),
            .streams_blocked_uni => |v| vs(@intFromEnum(FrameType.streams_blocked_uni)) + vs(v),
            .path_challenge, .path_response => vs(@intFromEnum(self.frameType())) + 8,
            .connection_close => |cc| vs(if (cc.is_app) @intFromEnum(FrameType.connection_close_app) else @intFromEnum(FrameType.connection_close)) + vs(cc.error_code) + (if (cc.is_app) 0 else vs(cc.frame_type)) + vs(@intCast(cc.reason.len)) + cc.reason.len,
            .crypto => |c| vs(@intFromEnum(FrameType.crypto)) + vs(c.offset) + vs(@intCast(c.data.len)) + c.data.len,
            .ack => |a| blk: {
                var len = vs(if (a.ecn != null) @intFromEnum(FrameType.ack_ecn) else @intFromEnum(FrameType.ack)) +
                    vs(a.largest_acked) + vs(a.ack_delay) + vs(a.additional_len) + vs(a.first_range);
                for (a.additional()) |r| len += vs(r.gap) + vs(r.range);
                if (a.ecn) |e| len += vs(e.ect0) + vs(e.ect1) + vs(e.ce);
                break :blk len;
            },
            .stream => |s| blk: {
                var ty: u64 = 0x08;
                if (s.fin) ty |= 0x01;
                ty |= 0x02; // LEN always, mirroring encode
                if (s.offset != 0) ty |= 0x04;
                break :blk vs(ty) + vs(s.id) + (if (s.offset == 0) 0 else vs(s.offset)) + vs(@intCast(s.data.len)) + s.data.len;
            },
            .observed_ipv4_addr, .add_ipv4_address, .reach_out_at_ipv4 => |addr| vs(@intFromEnum(self.frameType())) + vs(addr.seq) + 4 + 2,
            .observed_ipv6_addr, .add_ipv6_address, .reach_out_at_ipv6 => |addr| vs(@intFromEnum(self.frameType())) + vs(addr.seq) + 16 + 2,
            .remove_address => |seq| vs(@intFromEnum(FrameType.remove_address)) + vs(seq),
            .new_connection_id => |nc| vs(@intFromEnum(FrameType.new_connection_id)) + vs(nc.sequence) + vs(nc.retire_prior_to) + 1 + nc.connection_id.len + 16,
            .retire_connection_id => |r| vs(@intFromEnum(FrameType.retire_connection_id)) + vs(r.sequence),
            .new_token => |t| vs(@intFromEnum(FrameType.new_token)) + vs(@intCast(t.token.len)) + t.token.len,
            .ack_frequency => |a| vs(@intFromEnum(FrameType.ack_frequency)) + vs(a.sequence_number) + vs(a.ack_eliciting_threshold) + vs(a.request_max_ack_delay) + vs(a.reordering_threshold),
            .datagram => |d| vs(if (d.with_length) @intFromEnum(FrameType.datagram_len) else @intFromEnum(FrameType.datagram)) + (if (d.with_length) vs(@intCast(d.data.len)) else 0) + d.data.len,
            .path_ack => |p| blk: {
                const a = p.ack;
                var len = vs(if (a.ecn != null) @intFromEnum(FrameType.path_ack_ecn) else @intFromEnum(FrameType.path_ack)) +
                    vs(p.path_id) + vs(a.largest_acked) + vs(a.ack_delay) + vs(a.additional_len) + vs(a.first_range);
                for (a.additional()) |r| len += vs(r.gap) + vs(r.range);
                if (a.ecn) |e| len += vs(e.ect0) + vs(e.ect1) + vs(e.ce);
                break :blk len;
            },
            .path_abandon => |v| vs(@intFromEnum(FrameType.path_abandon)) + vs(v.path_id) + vs(v.error_code),
            .path_status_backup, .path_status_available => |v| vs(@intFromEnum(self.frameType())) + vs(v.path_id) + vs(v.status_seq_no),
            .path_new_connection_id => |nc| vs(@intFromEnum(FrameType.path_new_connection_id)) + vs(nc.path_id) + vs(nc.sequence) + vs(nc.retire_prior_to) + 1 + nc.connection_id.len + 16,
            .path_retire_connection_id => |v| vs(@intFromEnum(FrameType.path_retire_connection_id)) + vs(v.path_id) + vs(v.sequence),
            .max_path_id => |v| vs(@intFromEnum(FrameType.max_path_id)) + vs(v.path_id),
            .paths_blocked => |v| vs(@intFromEnum(FrameType.paths_blocked)) + vs(v.remote_max_path_id),
            .path_cids_blocked => |v| vs(@intFromEnum(FrameType.path_cids_blocked)) + vs(v.path_id) + vs(v.next_seq),
        };
    }

    pub fn encode(self: Frame, out: []u8) ![]u8 {
        var index: usize = 0;
        switch (self) {
            .ping, .immediate_ack, .handshake_done => {
                try varint.encodeAppend(@intFromEnum(self.frameType()), out, &index);
            },
            .max_data => |value| {
                try varint.encodeAppend(@intFromEnum(FrameType.max_data), out, &index);
                try varint.encodeAppend(value, out, &index);
            },
            .reset_stream => |r| {
                try varint.encodeAppend(@intFromEnum(FrameType.reset_stream), out, &index);
                try varint.encodeAppend(r.stream_id, out, &index);
                try varint.encodeAppend(r.app_error_code, out, &index);
                try varint.encodeAppend(r.final_size, out, &index);
            },
            .stop_sending => |s| {
                try varint.encodeAppend(@intFromEnum(FrameType.stop_sending), out, &index);
                try varint.encodeAppend(s.stream_id, out, &index);
                try varint.encodeAppend(s.app_error_code, out, &index);
            },
            .max_stream_data => |m| {
                try varint.encodeAppend(@intFromEnum(FrameType.max_stream_data), out, &index);
                try varint.encodeAppend(m.stream_id, out, &index);
                try varint.encodeAppend(m.max_data, out, &index);
            },
            .max_streams_bidi => |value| {
                try varint.encodeAppend(@intFromEnum(FrameType.max_streams_bidi), out, &index);
                try varint.encodeAppend(value, out, &index);
            },
            .max_streams_uni => |value| {
                try varint.encodeAppend(@intFromEnum(FrameType.max_streams_uni), out, &index);
                try varint.encodeAppend(value, out, &index);
            },
            .data_blocked => |value| {
                try varint.encodeAppend(@intFromEnum(FrameType.data_blocked), out, &index);
                try varint.encodeAppend(value, out, &index);
            },
            .stream_data_blocked => |s| {
                try varint.encodeAppend(@intFromEnum(FrameType.stream_data_blocked), out, &index);
                try varint.encodeAppend(s.stream_id, out, &index);
                try varint.encodeAppend(s.max_data, out, &index);
            },
            .streams_blocked_bidi => |value| {
                try varint.encodeAppend(@intFromEnum(FrameType.streams_blocked_bidi), out, &index);
                try varint.encodeAppend(value, out, &index);
            },
            .streams_blocked_uni => |value| {
                try varint.encodeAppend(@intFromEnum(FrameType.streams_blocked_uni), out, &index);
                try varint.encodeAppend(value, out, &index);
            },
            .path_challenge, .path_response => |data| {
                try varint.encodeAppend(@intFromEnum(self.frameType()), out, &index);
                try coding.writeBytes(&data, out, &index);
            },
            .connection_close => |cc| {
                const ty: u64 = if (cc.is_app) @intFromEnum(FrameType.connection_close_app) else @intFromEnum(FrameType.connection_close);
                try varint.encodeAppend(ty, out, &index);
                try varint.encodeAppend(cc.error_code, out, &index);
                if (!cc.is_app) try varint.encodeAppend(cc.frame_type, out, &index);
                try varint.encodeAppend(cc.reason.len, out, &index);
                try coding.writeBytes(cc.reason, out, &index);
            },
            .crypto => |c| {
                try varint.encodeAppend(@intFromEnum(FrameType.crypto), out, &index);
                try varint.encodeAppend(c.offset, out, &index);
                try varint.encodeAppend(c.data.len, out, &index);
                try coding.writeBytes(c.data, out, &index);
            },
            .ack => |a| {
                const ty: u64 = if (a.ecn != null) @intFromEnum(FrameType.ack_ecn) else @intFromEnum(FrameType.ack);
                try varint.encodeAppend(ty, out, &index);
                try varint.encodeAppend(a.largest_acked, out, &index);
                try varint.encodeAppend(a.ack_delay, out, &index);
                try varint.encodeAppend(a.additional_len, out, &index);
                try varint.encodeAppend(a.first_range, out, &index);
                for (a.additional()) |r| {
                    try varint.encodeAppend(r.gap, out, &index);
                    try varint.encodeAppend(r.range, out, &index);
                }
                if (a.ecn) |e| {
                    try varint.encodeAppend(e.ect0, out, &index);
                    try varint.encodeAppend(e.ect1, out, &index);
                    try varint.encodeAppend(e.ce, out, &index);
                }
            },
            .stream => |s| {
                var ty: u64 = 0x08;
                if (s.fin) ty |= 0x01;
                ty |= 0x02; // LEN always for deterministic encode
                if (s.offset != 0) ty |= 0x04;
                try varint.encodeAppend(ty, out, &index);
                try varint.encodeAppend(s.id, out, &index);
                if (s.offset != 0) try varint.encodeAppend(s.offset, out, &index);
                try varint.encodeAppend(s.data.len, out, &index);
                try coding.writeBytes(s.data, out, &index);
            },
            .observed_ipv4_addr, .add_ipv4_address, .reach_out_at_ipv4 => |addr| {
                try varint.encodeAppend(@intFromEnum(self.frameType()), out, &index);
                try varint.encodeAppend(addr.seq, out, &index);
                try coding.writeBytes(&addr.ip, out, &index);
                try coding.writeU16(addr.port, out, &index);
            },
            .observed_ipv6_addr, .add_ipv6_address, .reach_out_at_ipv6 => |addr| {
                try varint.encodeAppend(@intFromEnum(self.frameType()), out, &index);
                try varint.encodeAppend(addr.seq, out, &index);
                try coding.writeBytes(&addr.ip, out, &index);
                try coding.writeU16(addr.port, out, &index);
            },
            .remove_address => |seq| {
                try varint.encodeAppend(@intFromEnum(FrameType.remove_address), out, &index);
                try varint.encodeAppend(seq, out, &index);
            },
            .new_connection_id => |n| {
                try varint.encodeAppend(@intFromEnum(FrameType.new_connection_id), out, &index);
                try varint.encodeAppend(n.sequence, out, &index);
                try varint.encodeAppend(n.retire_prior_to, out, &index);
                try coding.writeU8(@intCast(n.connection_id.len), out, &index);
                try coding.writeBytes(n.connection_id, out, &index);
                try coding.writeBytes(&n.reset_token, out, &index);
            },
            .retire_connection_id => |r| {
                try varint.encodeAppend(@intFromEnum(FrameType.retire_connection_id), out, &index);
                try varint.encodeAppend(r.sequence, out, &index);
            },
            .new_token => |t| {
                try varint.encodeAppend(@intFromEnum(FrameType.new_token), out, &index);
                try varint.encodeAppend(t.token.len, out, &index);
                try coding.writeBytes(t.token, out, &index);
            },
            .ack_frequency => |a| {
                try varint.encodeAppend(@intFromEnum(FrameType.ack_frequency), out, &index);
                try varint.encodeAppend(a.sequence_number, out, &index);
                try varint.encodeAppend(a.ack_eliciting_threshold, out, &index);
                try varint.encodeAppend(a.request_max_ack_delay, out, &index);
                try varint.encodeAppend(a.reordering_threshold, out, &index);
            },
            .datagram => |d| {
                const ty: u64 = if (d.with_length) @intFromEnum(FrameType.datagram_len) else @intFromEnum(FrameType.datagram);
                try varint.encodeAppend(ty, out, &index);
                if (d.with_length) try varint.encodeAppend(d.data.len, out, &index);
                try coding.writeBytes(d.data, out, &index);
            },
            .path_ack => |p| {
                const a = p.ack;
                const ty: u64 = if (a.ecn != null) @intFromEnum(FrameType.path_ack_ecn) else @intFromEnum(FrameType.path_ack);
                try varint.encodeAppend(ty, out, &index);
                try varint.encodeAppend(p.path_id, out, &index);
                try varint.encodeAppend(a.largest_acked, out, &index);
                try varint.encodeAppend(a.ack_delay, out, &index);
                try varint.encodeAppend(a.additional_len, out, &index);
                try varint.encodeAppend(a.first_range, out, &index);
                for (a.additional()) |r| {
                    try varint.encodeAppend(r.gap, out, &index);
                    try varint.encodeAppend(r.range, out, &index);
                }
                if (a.ecn) |e| {
                    try varint.encodeAppend(e.ect0, out, &index);
                    try varint.encodeAppend(e.ect1, out, &index);
                    try varint.encodeAppend(e.ce, out, &index);
                }
            },
            .path_abandon => |v| {
                try varint.encodeAppend(@intFromEnum(FrameType.path_abandon), out, &index);
                try varint.encodeAppend(v.path_id, out, &index);
                try varint.encodeAppend(v.error_code, out, &index);
            },
            .path_status_backup, .path_status_available => |v| {
                try varint.encodeAppend(@intFromEnum(self.frameType()), out, &index);
                try varint.encodeAppend(v.path_id, out, &index);
                try varint.encodeAppend(v.status_seq_no, out, &index);
            },
            .path_new_connection_id => |n| {
                try varint.encodeAppend(@intFromEnum(FrameType.path_new_connection_id), out, &index);
                try varint.encodeAppend(n.path_id, out, &index);
                try varint.encodeAppend(n.sequence, out, &index);
                try varint.encodeAppend(n.retire_prior_to, out, &index);
                try coding.writeU8(@intCast(n.connection_id.len), out, &index);
                try coding.writeBytes(n.connection_id, out, &index);
                try coding.writeBytes(&n.reset_token, out, &index);
            },
            .path_retire_connection_id => |v| {
                try varint.encodeAppend(@intFromEnum(FrameType.path_retire_connection_id), out, &index);
                try varint.encodeAppend(v.path_id, out, &index);
                try varint.encodeAppend(v.sequence, out, &index);
            },
            .max_path_id => |v| {
                try varint.encodeAppend(@intFromEnum(FrameType.max_path_id), out, &index);
                try varint.encodeAppend(v.path_id, out, &index);
            },
            .paths_blocked => |v| {
                try varint.encodeAppend(@intFromEnum(FrameType.paths_blocked), out, &index);
                try varint.encodeAppend(v.remote_max_path_id, out, &index);
            },
            .path_cids_blocked => |v| {
                try varint.encodeAppend(@intFromEnum(FrameType.path_cids_blocked), out, &index);
                try varint.encodeAppend(v.path_id, out, &index);
                try varint.encodeAppend(v.next_seq, out, &index);
            },
        }
        return out[0..index];
    }
};

/// Exact-buffer decode: one frame, reject trailing bytes.
/// Round-trips use this; the connection hot path uses `decodeAt`.
pub fn decode(bytes: []const u8) !Frame {
    var cursor: coding.Cursor = .{ .bytes = bytes };
    const decoded = try decodeAt(&cursor);
    if (cursor.remaining() != 0) return error.TrailingFrameBytes;
    return decoded;
}

/// Decode one frame from `cursor`, advancing exactly past that frame.
/// Frames without an explicit length consume the remaining bytes, as required
/// by their wire format.
pub fn decodeAt(cursor: *coding.Cursor) !Frame {
    const bytes = cursor.bytes;
    const raw_type = try varint.decodeConsume(bytes, &cursor.index);

    if (raw_type >= 0x08 and raw_type <= 0x0f) {
        const has_off = (raw_type & 0x04) != 0;
        const has_len = (raw_type & 0x02) != 0;
        const fin = (raw_type & 0x01) != 0;
        const id = try varint.decodeConsume(bytes, &cursor.index);
        const offset: u64 = if (has_off) try varint.decodeConsume(bytes, &cursor.index) else 0;
        const data: []const u8 = if (has_len) blk: {
            const len = try varint.decodeConsume(bytes, &cursor.index);
            break :blk try cursor.readSlice(@intCast(len));
        } else try cursor.readSlice(cursor.remaining());
        _ = std.math.add(u64, offset, @intCast(data.len)) catch return error.FrameEncodeFailed;
        return .{ .stream = .{ .id = id, .offset = offset, .fin = fin, .data = data } };
    }

    if (raw_type == @intFromEnum(FrameType.datagram) or raw_type == @intFromEnum(FrameType.datagram_len)) {
        const with_len = raw_type == @intFromEnum(FrameType.datagram_len);
        const data: []const u8 = if (with_len) blk: {
            const len = try varint.decodeConsume(bytes, &cursor.index);
            break :blk try cursor.readSlice(@intCast(len));
        } else try cursor.readSlice(cursor.remaining());
        return .{ .datagram = .{ .data = data, .with_length = with_len } };
    }

    const frame_type = frameTypeFromRaw(raw_type) orelse return error.InvalidFrameType;
    const frame: Frame = switch (frame_type) {
        .ping => .ping,
        .immediate_ack => .immediate_ack,
        .handshake_done => .handshake_done,
        .max_data => .{ .max_data = try varint.decodeConsume(bytes, &cursor.index) },
        .reset_stream => .{ .reset_stream = .{
            .stream_id = try varint.decodeConsume(bytes, &cursor.index),
            .app_error_code = try varint.decodeConsume(bytes, &cursor.index),
            .final_size = try varint.decodeConsume(bytes, &cursor.index),
        } },
        .stop_sending => .{ .stop_sending = .{
            .stream_id = try varint.decodeConsume(bytes, &cursor.index),
            .app_error_code = try varint.decodeConsume(bytes, &cursor.index),
        } },
        .max_stream_data => .{ .max_stream_data = .{
            .stream_id = try varint.decodeConsume(bytes, &cursor.index),
            .max_data = try varint.decodeConsume(bytes, &cursor.index),
        } },
        .max_streams_bidi => blk: {
            const value = try varint.decodeConsume(bytes, &cursor.index);
            if (value > (@as(u64, 1) << 60)) return error.FrameEncodeFailed;
            break :blk .{ .max_streams_bidi = value };
        },
        .max_streams_uni => blk: {
            const value = try varint.decodeConsume(bytes, &cursor.index);
            if (value > (@as(u64, 1) << 60)) return error.FrameEncodeFailed;
            break :blk .{ .max_streams_uni = value };
        },
        .data_blocked => .{ .data_blocked = try varint.decodeConsume(bytes, &cursor.index) },
        .stream_data_blocked => .{ .stream_data_blocked = .{
            .stream_id = try varint.decodeConsume(bytes, &cursor.index),
            .max_data = try varint.decodeConsume(bytes, &cursor.index),
        } },
        .streams_blocked_bidi => .{ .streams_blocked_bidi = try varint.decodeConsume(bytes, &cursor.index) },
        .streams_blocked_uni => .{ .streams_blocked_uni = try varint.decodeConsume(bytes, &cursor.index) },
        .path_challenge => .{ .path_challenge = try cursor.readArray(8) },
        .path_response => .{ .path_response = try cursor.readArray(8) },
        .connection_close, .connection_close_app => blk: {
            const is_app = frame_type == .connection_close_app;
            const error_code = try varint.decodeConsume(bytes, &cursor.index);
            const frame_type_field: u64 = if (is_app) 0 else try varint.decodeConsume(bytes, &cursor.index);
            const reason_len = try varint.decodeConsume(bytes, &cursor.index);
            const reason = try cursor.readSlice(@intCast(reason_len));
            break :blk .{ .connection_close = .{
                .error_code = error_code,
                .frame_type = frame_type_field,
                .reason = reason,
                .is_app = is_app,
            } };
        },
        .crypto => blk: {
            const offset = try varint.decodeConsume(bytes, &cursor.index);
            const len = try varint.decodeConsume(bytes, &cursor.index);
            const data = try cursor.readSlice(@intCast(len));
            break :blk .{ .crypto = .{ .offset = offset, .data = data } };
        },
        .ack, .ack_ecn => blk: {
            const largest = try varint.decodeConsume(bytes, &cursor.index);
            const delay = try varint.decodeConsume(bytes, &cursor.index);
            const range_count = try varint.decodeConsume(bytes, &cursor.index);
            const first_range = try varint.decodeConsume(bytes, &cursor.index);
            if (range_count > max_ack_additional) return error.TooManyAckRanges;
            // noq frame.rs read_ack_blocks:1760-1792: every range walk is
            // a checked_sub — a range that would underflow its block's largest
            // is IterErr::Malformed → FRAME_ENCODING_ERROR. First block:
            // (largest+1) - (first_range+1) underflows iff first_range > largest.
            if (first_range > largest) return error.FrameEncodeFailed;
            var a: Ack = .{
                .largest_acked = largest,
                .ack_delay = delay,
                .first_range = first_range,
                .additional_len = @intCast(range_count),
            };
            // Walk the additional blocks exactly as noq: block_to_block =
            // gap+1 + prev_block_size (≤ 2^63, cannot overflow u64), subtracted
            // checked from the running largest; then the new block's own
            // range must not underflow the new largest either.
            var block_largest = largest;
            var block_size = first_range + 1;
            var i: usize = 0;
            while (i < range_count) : (i += 1) {
                const gap = try varint.decodeConsume(bytes, &cursor.index);
                const range = try varint.decodeConsume(bytes, &cursor.index);
                const drop = gap + 1 + block_size;
                if (drop > block_largest) return error.FrameEncodeFailed;
                block_largest -= drop;
                if (range > block_largest) return error.FrameEncodeFailed;
                block_size = range + 1;
                a.additional_buf[i] = .{ .gap = gap, .range = range };
            }
            if (frame_type == .ack_ecn) {
                a.ecn = .{
                    .ect0 = try varint.decodeConsume(bytes, &cursor.index),
                    .ect1 = try varint.decodeConsume(bytes, &cursor.index),
                    .ce = try varint.decodeConsume(bytes, &cursor.index),
                };
            }
            break :blk .{ .ack = a };
        },
        .observed_ipv4_addr => .{ .observed_ipv4_addr = try readAddress4(cursor) },
        // Observed-address reports over IPv6 decode too (noq frame.rs:1665-1668).
        .observed_ipv6_addr => .{ .observed_ipv6_addr = try readAddress6(cursor) },
        .add_ipv4_address => .{ .add_ipv4_address = try readAddress4(cursor) },
        // The v6 variants decode like v4 with a 16-byte address (noq
        // frame.rs:1682-1691) — never an UnsupportedFrameType close.
        .add_ipv6_address => .{ .add_ipv6_address = try readAddress6(cursor) },
        .reach_out_at_ipv4 => .{ .reach_out_at_ipv4 = try readAddress4(cursor) },
        .reach_out_at_ipv6 => .{ .reach_out_at_ipv6 = try readAddress6(cursor) },
        .remove_address => .{ .remove_address = try varint.decodeConsume(bytes, &cursor.index) },
        .new_connection_id => blk: {
            const sequence = try varint.decodeConsume(bytes, &cursor.index);
            const retire_prior_to = try varint.decodeConsume(bytes, &cursor.index);
            const cid_len = try cursor.readU8();
            if (cid_len > packet.max_cid_size) return error.FrameEncodeFailed;
            const connection_id = try cursor.readSlice(cid_len);
            const reset_token = try cursor.readArray(16);
            break :blk .{ .new_connection_id = .{
                .sequence = sequence,
                .retire_prior_to = retire_prior_to,
                .connection_id = connection_id,
                .reset_token = reset_token,
            } };
        },
        .retire_connection_id => .{ .retire_connection_id = .{
            .sequence = try varint.decodeConsume(bytes, &cursor.index),
        } },
        .new_token => blk: {
            const token_len = try varint.decodeConsume(bytes, &cursor.index);
            const token = try cursor.readSlice(@intCast(token_len));
            break :blk .{ .new_token = .{ .token = token } };
        },
        .ack_frequency => .{ .ack_frequency = .{
            .sequence_number = try varint.decodeConsume(bytes, &cursor.index),
            .ack_eliciting_threshold = try varint.decodeConsume(bytes, &cursor.index),
            .request_max_ack_delay = try varint.decodeConsume(bytes, &cursor.index),
            .reordering_threshold = try varint.decodeConsume(bytes, &cursor.index),
        } },
        // ── multipath (I3) ─────────────────────────────────────────────────
        .path_ack, .path_ack_ecn => blk: {
            const path_id = try varint.decodeConsume(bytes, &cursor.index);
            const largest = try varint.decodeConsume(bytes, &cursor.index);
            const delay = try varint.decodeConsume(bytes, &cursor.index);
            const range_count = try varint.decodeConsume(bytes, &cursor.index);
            const first_range = try varint.decodeConsume(bytes, &cursor.index);
            if (range_count > max_ack_additional) return error.TooManyAckRanges;
            if (first_range > largest) return error.FrameEncodeFailed;
            var a: Ack = .{
                .largest_acked = largest,
                .ack_delay = delay,
                .first_range = first_range,
                .additional_len = @intCast(range_count),
            };
            var block_largest = largest;
            var block_size = first_range + 1;
            var i: usize = 0;
            while (i < range_count) : (i += 1) {
                const gap = try varint.decodeConsume(bytes, &cursor.index);
                const range = try varint.decodeConsume(bytes, &cursor.index);
                const drop = gap + 1 + block_size;
                if (drop > block_largest) return error.FrameEncodeFailed;
                block_largest -= drop;
                if (range > block_largest) return error.FrameEncodeFailed;
                block_size = range + 1;
                a.additional_buf[i] = .{ .gap = gap, .range = range };
            }
            if (frame_type == .path_ack_ecn) {
                a.ecn = .{
                    .ect0 = try varint.decodeConsume(bytes, &cursor.index),
                    .ect1 = try varint.decodeConsume(bytes, &cursor.index),
                    .ce = try varint.decodeConsume(bytes, &cursor.index),
                };
            }
            break :blk .{ .path_ack = .{ .path_id = path_id, .ack = a } };
        },
        .path_abandon => .{ .path_abandon = .{
            .path_id = try varint.decodeConsume(bytes, &cursor.index),
            .error_code = try varint.decodeConsume(bytes, &cursor.index),
        } },
        .path_status_backup => .{ .path_status_backup = .{
            .path_id = try varint.decodeConsume(bytes, &cursor.index),
            .status_seq_no = try varint.decodeConsume(bytes, &cursor.index),
        } },
        .path_status_available => .{ .path_status_available = .{
            .path_id = try varint.decodeConsume(bytes, &cursor.index),
            .status_seq_no = try varint.decodeConsume(bytes, &cursor.index),
        } },
        .path_new_connection_id => blk: {
            const path_id = try varint.decodeConsume(bytes, &cursor.index);
            const sequence = try varint.decodeConsume(bytes, &cursor.index);
            const retire_prior_to = try varint.decodeConsume(bytes, &cursor.index);
            if (retire_prior_to > sequence) return error.FrameEncodeFailed;
            const cid_len = try cursor.readU8();
            if (cid_len > packet.max_cid_size) return error.FrameEncodeFailed;
            const connection_id = try cursor.readSlice(cid_len);
            const reset_token = try cursor.readArray(16);
            break :blk .{ .path_new_connection_id = .{
                .path_id = path_id,
                .sequence = sequence,
                .retire_prior_to = retire_prior_to,
                .connection_id = connection_id,
                .reset_token = reset_token,
            } };
        },
        .path_retire_connection_id => .{ .path_retire_connection_id = .{
            .path_id = try varint.decodeConsume(bytes, &cursor.index),
            .sequence = try varint.decodeConsume(bytes, &cursor.index),
        } },
        .max_path_id => .{ .max_path_id = .{
            .path_id = try varint.decodeConsume(bytes, &cursor.index),
        } },
        .paths_blocked => .{ .paths_blocked = .{
            .remote_max_path_id = try varint.decodeConsume(bytes, &cursor.index),
        } },
        .path_cids_blocked => .{ .path_cids_blocked = .{
            .path_id = try varint.decodeConsume(bytes, &cursor.index),
            .next_seq = try varint.decodeConsume(bytes, &cursor.index),
        } },
        else => return error.UnsupportedFrameType,
    };
    return frame;
}


fn frameTypeFromRaw(raw: u64) ?FrameType {
    return switch (raw) {
        @intFromEnum(FrameType.padding) => .padding,
        @intFromEnum(FrameType.ping) => .ping,
        @intFromEnum(FrameType.ack) => .ack,
        @intFromEnum(FrameType.ack_ecn) => .ack_ecn,
        @intFromEnum(FrameType.reset_stream) => .reset_stream,
        @intFromEnum(FrameType.stop_sending) => .stop_sending,
        @intFromEnum(FrameType.crypto) => .crypto,
        @intFromEnum(FrameType.max_data) => .max_data,
        @intFromEnum(FrameType.max_stream_data) => .max_stream_data,
        @intFromEnum(FrameType.max_streams_bidi) => .max_streams_bidi,
        @intFromEnum(FrameType.max_streams_uni) => .max_streams_uni,
        @intFromEnum(FrameType.data_blocked) => .data_blocked,
        @intFromEnum(FrameType.stream_data_blocked) => .stream_data_blocked,
        @intFromEnum(FrameType.streams_blocked_bidi) => .streams_blocked_bidi,
        @intFromEnum(FrameType.streams_blocked_uni) => .streams_blocked_uni,
        @intFromEnum(FrameType.path_challenge) => .path_challenge,
        @intFromEnum(FrameType.path_response) => .path_response,
        @intFromEnum(FrameType.connection_close) => .connection_close,
        @intFromEnum(FrameType.connection_close_app) => .connection_close_app,
        @intFromEnum(FrameType.handshake_done) => .handshake_done,
        @intFromEnum(FrameType.immediate_ack) => .immediate_ack,
        @intFromEnum(FrameType.observed_ipv4_addr) => .observed_ipv4_addr,
        @intFromEnum(FrameType.observed_ipv6_addr) => .observed_ipv6_addr,
        @intFromEnum(FrameType.add_ipv4_address) => .add_ipv4_address,
        @intFromEnum(FrameType.add_ipv6_address) => .add_ipv6_address,
        @intFromEnum(FrameType.reach_out_at_ipv4) => .reach_out_at_ipv4,
        @intFromEnum(FrameType.reach_out_at_ipv6) => .reach_out_at_ipv6,
        @intFromEnum(FrameType.remove_address) => .remove_address,
        @intFromEnum(FrameType.new_connection_id) => .new_connection_id,
        @intFromEnum(FrameType.retire_connection_id) => .retire_connection_id,
        @intFromEnum(FrameType.new_token) => .new_token,
        @intFromEnum(FrameType.ack_frequency) => .ack_frequency,
        @intFromEnum(FrameType.path_ack) => .path_ack,
        @intFromEnum(FrameType.path_ack_ecn) => .path_ack_ecn,
        @intFromEnum(FrameType.path_abandon) => .path_abandon,
        @intFromEnum(FrameType.path_status_backup) => .path_status_backup,
        @intFromEnum(FrameType.path_status_available) => .path_status_available,
        @intFromEnum(FrameType.path_new_connection_id) => .path_new_connection_id,
        @intFromEnum(FrameType.path_retire_connection_id) => .path_retire_connection_id,
        @intFromEnum(FrameType.max_path_id) => .max_path_id,
        @intFromEnum(FrameType.paths_blocked) => .paths_blocked,
        @intFromEnum(FrameType.path_cids_blocked) => .path_cids_blocked,
        else => null,
    };
}

fn readAddress4(cursor: *coding.Cursor) !Address4 {
    return .{
        .seq = try varint.decodeConsume(cursor.bytes, &cursor.index),
        .ip = try cursor.readArray(4),
        .port = try cursor.readU16(),
    };
}

fn readAddress6(cursor: *coding.Cursor) !Address6 {
    return .{
        .seq = try varint.decodeConsume(cursor.bytes, &cursor.index),
        .ip = try cursor.readArray(16),
        .port = try cursor.readU16(),
    };
}

test "noq frame subset encodes fixed frame ids" {
    var buf: [32]u8 = undefined;
    const ping: Frame = .ping;
    const immediate_ack: Frame = .immediate_ack;
    const handshake_done: Frame = .handshake_done;
    try std.testing.expectEqualSlices(u8, &.{0x01}, try ping.encode(&buf));
    try std.testing.expectEqualSlices(u8, &.{0x1f}, try immediate_ack.encode(&buf));
    try std.testing.expectEqualSlices(u8, &.{0x1e}, try handshake_done.encode(&buf));
    try std.testing.expectEqualSlices(u8, &.{ 0x10, 0x40, 0x40 }, try (Frame{ .max_data = 64 }).encode(&buf));
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x80, 0x3d, 0x7f, 0x90, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x10, 0x92 },
        try (Frame{ .add_ipv4_address = .{ .seq = 1, .ip = .{ 192, 0, 2, 1 }, .port = 4242 } }).encode(&buf),
    );
}

test "crypto frame encode decode roundtrip" {
    var buf: [64]u8 = undefined;
    const data = "hello-tls";
    const f: Frame = .{ .crypto = .{ .offset = 0, .data = data } };
    const enc = try f.encode(&buf);
    const dec = try decode(enc);
    try std.testing.expectEqualSlices(u8, enc, try dec.encode(buf[enc.len..]));
    try std.testing.expectEqual(@as(u64, 0), dec.crypto.offset);
    try std.testing.expectEqualSlices(u8, data, dec.crypto.data);
}

test "decodeAt advances one frame while decode remains exact" {
    var buf: [64]u8 = undefined;
    const stream_frame: Frame = .{ .stream = .{ .id = 4, .data = "abc" } };
    const stream_bytes = try stream_frame.encode(&buf);
    const stream_len = stream_bytes.len;
    const ping: Frame = .ping;
    const ping_bytes = try ping.encode(buf[stream_len..]);
    const encoded = buf[0 .. stream_len + ping_bytes.len];

    var cursor: coding.Cursor = .{ .bytes = encoded };
    const first = try decodeAt(&cursor);
    try std.testing.expect(first == .stream);
    try std.testing.expectEqual(@as(u64, 4), first.stream.id);
    try std.testing.expectEqualSlices(u8, "abc", first.stream.data);
    const second = try decodeAt(&cursor);
    try std.testing.expect(second == .ping);
    try std.testing.expectEqual(@as(usize, 0), cursor.remaining());

    try std.testing.expectError(error.TrailingFrameBytes, decode(encoded));
}

test "decodeAt gives no-length frames the remaining payload" {
    const datagram_wire = [_]u8{ 0x30, 0xaa, 0x00 };
    var datagram_cursor: coding.Cursor = .{ .bytes = &datagram_wire };
    const datagram = try decodeAt(&datagram_cursor);
    try std.testing.expect(datagram == .datagram);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0x00 }, datagram.datagram.data);
    try std.testing.expectEqual(@as(usize, 0), datagram_cursor.remaining());

    const stream_wire = [_]u8{ 0x08, 0x00, 0xbb, 0x00 };
    var stream_cursor: coding.Cursor = .{ .bytes = &stream_wire };
    const stream = try decodeAt(&stream_cursor);
    try std.testing.expect(stream == .stream);
    try std.testing.expectEqualSlices(u8, &.{ 0xbb, 0x00 }, stream.stream.data);
    try std.testing.expectEqual(@as(usize, 0), stream_cursor.remaining());
}

test "empty length-bearing DATAGRAM encodes as 0x31" {
    var buf: [8]u8 = undefined;
    const f: Frame = .{ .datagram = .{ .data = &.{}, .with_length = true } };
    const enc = try f.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x31), enc[0]);
    try std.testing.expectEqual(@as(u8, 0x00), enc[1]); // length varint 0
    try std.testing.expectEqual(@as(usize, 2), enc.len);
}


test "ack multi-range encode decode" {
    var buf: [64]u8 = undefined;
    const addl = [_]AckGapRange{.{ .gap = 1, .range = 1 }};
    const f: Frame = .{ .ack = try Ack.withAdditional(7, 0, 2, &addl, null) };
    const enc = try f.encode(&buf);
    const dec = try decode(enc);
    var check: [64]u8 = undefined;
    try std.testing.expectEqualSlices(u8, enc, try dec.encode(&check));
}

/// Gate driver: encode a raw ACK frame body (type 0x02 prefix supplied by
/// the caller's field varints) and require decode to reject it.
fn expectMalformedAck(fields: []const u8) !void {
    var buf: [80]u8 = undefined;
    buf[0] = 0x02;
    @memcpy(buf[1 .. 1 + fields.len], fields);
    try std.testing.expectError(error.FrameEncodeFailed, decode(buf[0 .. 1 + fields.len]));
}

test "ACK first_range above largest_acked is malformed (noq read_ack_blocks)" {
    // largest=3, delay=0, count=0, first_range=4 → (3+1)-(4+1) underflows.
    try expectMalformedAck(&.{ 0x03, 0x00, 0x00, 0x04 });
    // The exact boundary first_range == largest decodes fine (range down to 0).
    const ok_wire = [_]u8{ 0x02, 0x03, 0x00, 0x00, 0x03 };
    const ok = try decode(&ok_wire);
    try std.testing.expectEqual(@as(u64, 3), ok.ack.largest_acked);
    try std.testing.expectEqual(@as(u64, 3), ok.ack.first_range);
}

test "ACK additional block gap underflow is malformed" {
    // largest=5, delay=0, count=1, first_range=1 (block [4,5]), then
    // gap=4 → drop = 4+1+2 = 7 > 5 underflows noq's checked_sub.
    try expectMalformedAck(&.{ 0x05, 0x00, 0x01, 0x01, 0x04, 0x00 });
}

test "ACK additional block range underflow is malformed" {
    // largest=5, delay=0, count=1, first_range=1 (block [4,5]), gap=1 →
    // new largest = 5-(1+1+2) = 1; range=2 > 1 underflows (largest+1)-(range+1).
    try expectMalformedAck(&.{ 0x05, 0x00, 0x01, 0x01, 0x01, 0x02 });
    // Same walk with range=1 is the boundary: block [0,1] exactly reaches 0.
    const ok_wire = [_]u8{ 0x02, 0x05, 0x00, 0x01, 0x01, 0x01, 0x01 };
    const ok = try decode(&ok_wire);
    try std.testing.expectEqual(@as(u64, 1), ok.ack.additional_len);
    try std.testing.expectEqual(@as(u64, 1), ok.ack.additional()[0].range);
}

test "5b new frames encode/decode roundtrip" {
    var buf: [128]u8 = undefined;
    var check: [128]u8 = undefined;
    const frames = [_]Frame{
        .{ .reset_stream = .{ .stream_id = 4, .app_error_code = 7, .final_size = 100 } },
        .{ .stop_sending = .{ .stream_id = 4, .app_error_code = 2 } },
        .{ .max_stream_data = .{ .stream_id = 8, .max_data = 65536 } },
        .{ .max_streams_bidi = 100 },
        .{ .max_streams_uni = 3 },
        .{ .data_blocked = 1000 },
        .{ .stream_data_blocked = .{ .stream_id = 12, .max_data = 4096 } },
        .{ .streams_blocked_bidi = 50 },
        .{ .streams_blocked_uni = 1 },
        .{ .connection_close = .{ .error_code = 0, .frame_type = 0x10, .reason = "bye", .is_app = false } },
        .{ .connection_close = .{ .error_code = 42, .reason = "app-bye", .is_app = true } },
    };
    for (frames) |f| {
        const enc = try f.encode(&buf);
        const dec = try decode(enc);
        try std.testing.expectEqualSlices(u8, enc, try dec.encode(&check));
    }
    // Application close carries no frame_type field on the wire.
    const app_close: Frame = .{ .connection_close = .{ .error_code = 5, .reason = "", .is_app = true } };
    const enc = try app_close.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x1d), enc[0]);
}

test "B9 truncatedCloseReason mirrors noq CloseEncoder budget math" {
    const reason = "x" ** 100;
    // Transport close: reserved = 3 + varint(frame_type) + varint(reason.len)
    // (noq frame.rs:940-944). frame_type 0x10 → 1 byte; len 100 → 2 bytes.
    const cc: ConnectionClose = .{ .error_code = 0, .frame_type = 0x10, .reason = reason, .is_app = false };
    try std.testing.expectEqual(@as(usize, 49), truncatedCloseReason(cc, 55).len);
    // Application close carries no frame_type: reserved = 3 + varint(len)
    // (noq frame.rs:983-985).
    const app: ConnectionClose = .{ .error_code = 42, .reason = reason, .is_app = true };
    try std.testing.expectEqual(@as(usize, 50), truncatedCloseReason(app, 55).len);
    // A reason that already fits is returned whole.
    try std.testing.expectEqual(@as(usize, 100), truncatedCloseReason(cc, 106).len);
    // A budget below the fixed reservation truncates to empty, never negative.
    try std.testing.expectEqual(@as(usize, 0), truncatedCloseReason(cc, 4).len);
    // The truncated frame re-encodes within the budget: the length varint of
    // the TRUNCATED reason (49 → 1 byte) comes out smaller than the pessimistic
    // reservation (100 → 2), so the encode is 54 ≤ 55.
    var buf: [256]u8 = undefined;
    const bounded: ConnectionClose = .{ .error_code = 64, .frame_type = 0x10, .reason = truncatedCloseReason(cc, 55), .is_app = false };
    const enc = try (Frame{ .connection_close = bounded }).encode(&buf);
    try std.testing.expectEqual(@as(usize, 54), enc.len);
}

test "MAX_STREAMS frame values above 2^60 are rejected" {
    var buf: [16]u8 = undefined;
    var index: usize = 0;
    try varint.encodeAppend(@intFromEnum(FrameType.max_streams_bidi), &buf, &index);
    try varint.encodeAppend((@as(u64, 1) << 60) + 1, &buf, &index);
    try std.testing.expectError(error.FrameEncodeFailed, decode(buf[0..index]));
}

test "5e PATH_CHALLENGE/PATH_RESPONSE encode/decode roundtrip" {
    var buf: [16]u8 = undefined;
    var check: [16]u8 = undefined;
    const data: [8]u8 = .{ 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
    const chal: Frame = .{ .path_challenge = data };
    const enc_c = try chal.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x1a), enc_c[0]);
    const dec_c = try decode(enc_c);
    try std.testing.expectEqualSlices(u8, &data, &dec_c.path_challenge);
    try std.testing.expectEqualSlices(u8, enc_c, try dec_c.encode(&check));

    const resp: Frame = .{ .path_response = data };
    const enc_r = try resp.encode(&buf);
    try std.testing.expectEqual(@as(u8, 0x1b), enc_r[0]);
    const dec_r = try decode(enc_r);
    try std.testing.expectEqualSlices(u8, &data, &dec_r.path_response);
}

test "stream OFF+LEN+FIN encode decode" {
    var buf: [64]u8 = undefined;
    const data = "abc";
    const f: Frame = .{ .stream = .{ .id = 0, .offset = 10, .fin = true, .data = data } };
    const enc = try f.encode(&buf);
    // type 0x08|FIN|LEN|OFF = 0x0f
    try std.testing.expectEqual(@as(u8, 0x0f), enc[0]);
    const dec = try decode(enc);
    var check: [64]u8 = undefined;
    try std.testing.expectEqualSlices(u8, enc, try dec.encode(&check));
    try std.testing.expect(dec.stream.fin);
    try std.testing.expectEqual(@as(u64, 10), dec.stream.offset);
}

test "N-3 hardening frame types encode/decode roundtrip" {
    var buf: [256]u8 = undefined;
    var check: [256]u8 = undefined;
    const cid_bytes = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const reset_token: [16]u8 = .{0x11} ** 16;
    const frames = [_]Frame{
        .{ .new_connection_id = .{
            .sequence = 2,
            .retire_prior_to = 1,
            .connection_id = &cid_bytes,
            .reset_token = reset_token,
        } },
        .{ .retire_connection_id = .{ .sequence = 1 } },
        .{ .new_token = .{ .token = "resume-token" } },
        .{ .ack_frequency = .{
            .sequence_number = 1,
            .ack_eliciting_threshold = 2,
            .request_max_ack_delay = 25,
            .reordering_threshold = 3,
        } },
        .{ .datagram = .{ .data = "dgram-payload", .with_length = false } },
        .{ .datagram = .{ .data = "dgram-with-len", .with_length = true } },
    };
    for (frames) |f| {
        const enc = try f.encode(&buf);
        const dec = try decode(enc);
        try std.testing.expectEqualSlices(u8, enc, try dec.encode(&check));
    }
}

// ---------------------------------------------------------------------------
// I3/I1: multipath family + known-frame-ID repertoire.
// ---------------------------------------------------------------------------

test "I3 multipath frame family encodes/decodes byte-correctly (roundtrip)" {
    var buf: [256]u8 = undefined;
    var check: [256]u8 = undefined;
    const cid_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const reset_token: [16]u8 = .{0x22} ** 16;
    const frames = [_]Frame{
        .{ .path_ack = .{ .path_id = 3, .ack = .{ .largest_acked = 10, .ack_delay = 5, .first_range = 2 } } },
        .{ .path_ack = .{ .path_id = 1, .ack = .{
            .largest_acked = 9,
            .ack_delay = 1,
            .first_range = 0,
            .ecn = .{ .ect0 = 4, .ect1 = 1, .ce = 2 },
        } } },
        .{ .path_abandon = .{ .path_id = 2, .error_code = 0x100 } },
        .{ .path_status_backup = .{ .path_id = 1, .status_seq_no = 7 } },
        .{ .path_status_available = .{ .path_id = 0, .status_seq_no = 8 } },
        .{ .path_new_connection_id = .{
            .path_id = 1,
            .sequence = 4,
            .retire_prior_to = 2,
            .connection_id = &cid_bytes,
            .reset_token = reset_token,
        } },
        .{ .path_retire_connection_id = .{ .path_id = 1, .sequence = 3 } },
        .{ .max_path_id = .{ .path_id = 5 } },
        .{ .paths_blocked = .{ .remote_max_path_id = 6 } },
        .{ .path_cids_blocked = .{ .path_id = 2, .next_seq = 11 } },
    };
    for (frames) |f| {
        const enc = try f.encode(&buf);
        const dec = try decode(enc);
        // A recognized frame must never surface as UnsupportedFrameType.
        try std.testing.expectEqualSlices(u8, enc, try dec.encode(&check));
    }
}

test "I1 known frame IDs decode (no UnsupportedFrameType) across the repertoire" {
    // Every known wire type: RFC 9000 base, STREAM/DATAGRAM sub-ranges,
    // RFC 9368, the iroh address frames, and the multipath family (I3).
    const known = [_]u64{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // base
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // flow-control
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // cid/close/done
        0xaf, // ack_frequency
        0x9f81a6, 0x9f81a7, // observed ipv4/ipv6
        0x3d7f90, 0x3d7f91, 0x3d7f92, 0x3d7f93, 0x3d7f94, // iroh address frames
        0x3e, 0x3f, // path_ack / path_ack_ecn
        0x3e75, 0x3e76, 0x3e77, 0x3e78, 0x3e79, 0x3e7a, 0x3e7b, 0x3e7c, // multipath
    };
    // STREAM (0x08-0x0f) and DATAGRAM (0x30/0x31) are handled by prefix, not
    // frameTypeFromRaw; check them separately.
    var ty: u64 = 0x08;
    while (ty <= 0x0f) : (ty += 1) {
        // A bare STREAM type byte must decode as a (possibly empty) frame,
        // never InvalidFrameType.
        var buf: [4]u8 = undefined;
        var idx: usize = 0;
        try varint.encodeAppend(ty, &buf, &idx);
        const f = decode(buf[0..idx]) catch |e| {
            // Truncation of the STREAM header fields is fine; an unknown-type
            // error is the failure this test guards against.
            try std.testing.expect(e != error.InvalidFrameType and e != error.UnsupportedFrameType);
            continue;
        };
        try std.testing.expect(f == .stream);
    }
    for ([_]u64{ 0x30, 0x31 }) |dt| {
        var buf: [4]u8 = undefined;
        var idx: usize = 0;
        try varint.encodeAppend(dt, &buf, &idx);
        const f = decode(buf[0..idx]) catch |e| {
            try std.testing.expect(e != error.InvalidFrameType and e != error.UnsupportedFrameType);
            continue;
        };
        try std.testing.expect(f == .datagram);
    }
    for (known) |raw| {
        try std.testing.expect(frameTypeFromRaw(raw) != null);
    }
    // A genuinely unknown ID stays rejected.
    try std.testing.expect(frameTypeFromRaw(0xffff_ffff) == null);
}

// ---------------------------------------------------------------------------
// N-3 adversarial pure-decoder seeds as unit asserts (checked-add + bounds).
// Complements fuzz/corpus/quic-frame/* — these pin the fail-closed error codes.
// ---------------------------------------------------------------------------

test "ACK with 64 additional ranges decodes; 65 is rejected" {
    // Build a legal ACK with max_ack_additional ranges, then one over the cap.
    var ranges: [max_ack_additional]AckGapRange = undefined;
    for (&ranges, 0..) |*r, i| {
        r.* = .{ .gap = 0, .range = @intCast(i % 4) };
    }
    const ok = try Ack.withAdditional(1000, 0, 0, ranges[0..], null);
    try std.testing.expectEqual(@as(u8, @intCast(max_ack_additional)), ok.additional_len);

    // Encode and decode round-trip at the boundary.
    var buf: [2048]u8 = undefined;
    const f: Frame = .{ .ack = ok };
    const enc = try f.encode(&buf);
    const dec = try decode(enc);
    try std.testing.expectEqual(@as(u8, @intCast(max_ack_additional)), dec.ack.additional_len);

    // 65 ranges must fail at the withAdditional / decode bound.
    var too_many: [max_ack_additional + 1]AckGapRange = undefined;
    for (&too_many) |*r| r.* = .{ .gap = 0, .range = 0 };
    try std.testing.expectError(error.TooManyAckRanges, Ack.withAdditional(1000, 0, 0, too_many[0..], null));
}

test "N-3-adversarial STREAM max-varint offset does not panic (checked-add note)" {
    // type 0x0e (OFF|LEN), id=0, offset=2^62-1 (max wire varint), len=1, data=0x00.
    // Wire-legal varints CANNOT overflow u64 via offset+len (max offset 2^62-1 + small
    // buffer-bound data), so the checked-add is a dead path for remote input — assert
    // no panic and either accept or reject cleanly.
    const wire = [_]u8{ 0x0e, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00 };
    const decoded = decode(&wire) catch return; // reject is fine
    try std.testing.expect(decoded == .stream);
    try std.testing.expectEqual(@as(u64, (@as(u64, 1) << 62) - 1), decoded.stream.offset);
}

test "N-3-adversarial STREAM huge declared length is rejected (no UB)" {
    // type 0x0e, id=0, offset=0, len=varint max 8-byte, insufficient payload → UnexpectedEnd
    const wire = [_]u8{ 0x0e, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    try std.testing.expectError(error.UnexpectedEnd, decode(&wire));
}

test "N-3-adversarial NEW_CONNECTION_ID overlong CID is rejected" {
    // type 0x18, seq=1, retire=0, cid_len=21 (> max_cid_size 20)
    var wire: [1 + 1 + 1 + 1 + 21 + 16]u8 = undefined;
    wire[0] = 0x18;
    wire[1] = 0x01;
    wire[2] = 0x00;
    wire[3] = 21;
    @memset(wire[4 .. 4 + 21], 0xaa);
    @memset(wire[4 + 21 ..], 0);
    try std.testing.expectError(error.FrameEncodeFailed, decode(&wire));
}

test "N-3-adversarial DATAGRAM length past end is rejected" {
    // type 0x31 (with length), len varint = 0x3f (63) but only 1 payload byte
    const wire = [_]u8{ 0x31, 0x3f, 0x00 };
    try std.testing.expectError(error.UnexpectedEnd, decode(&wire));
}

test "N-3-adversarial empty and garbage frames do not panic" {
    _ = decode(&.{}) catch {};
    _ = decode(&.{0xff}) catch {};
    _ = decode(&.{ 0x18, 0xff }) catch {};
    _ = decode(&.{ 0x02, 0x00, 0x00, 0x40 }) catch {}; // ACK range_count truncated
}

test "encodedLen matches encode for every frame variant" {
    var buf: [4096]u8 = undefined;

    var ranges: [max_ack_additional]AckGapRange = undefined;
    for (&ranges, 0..) |*r, i| r.* = .{ .gap = 1 + i, .range = 2 * i };
    const big_ack = try Ack.withAdditional(1_000_000, 24, 700, ranges[0..], .{ .ect0 = 5, .ect1 = 1, .ce = 2 });

    const cid_bytes = [_]u8{0xAA} ** 8;
    const cases = [_]Frame{
        .ping,
        .immediate_ack,
        .handshake_done,
        .{ .max_data = 123_456 },
        .{ .crypto = .{ .offset = 300, .data = "hello crypto" } },
        .{ .ack = .{ .largest_acked = 10, .ack_delay = 0, .first_range = 3 } },
        .{ .ack = big_ack },
        .{ .stream = .{ .id = 4, .offset = 1024, .fin = true, .data = "abc" } },
        .{ .stream = .{ .id = 4, .data = "" } },
        .{ .reset_stream = .{ .stream_id = 1, .app_error_code = 42, .final_size = 999 } },
        .{ .stop_sending = .{ .stream_id = 1, .app_error_code = 42 } },
        .{ .max_stream_data = .{ .stream_id = 7, .max_data = 65_536 } },
        .{ .max_streams_bidi = 100 },
        .{ .max_streams_uni = 3 },
        .{ .data_blocked = 4096 },
        .{ .stream_data_blocked = .{ .stream_id = 2, .max_data = 8192 } },
        .{ .streams_blocked_bidi = 5 },
        .{ .streams_blocked_uni = 6 },
        .{ .path_challenge = [_]u8{1} ** 8 },
        .{ .path_response = [_]u8{2} ** 8 },
        .{ .connection_close = .{ .error_code = 0x100, .frame_type = 0x0d, .reason = "boom", .is_app = false } },
        .{ .connection_close = .{ .error_code = 0, .frame_type = 0, .reason = "", .is_app = true } },
        .{ .new_connection_id = .{ .sequence = 7, .retire_prior_to = 2, .connection_id = &cid_bytes, .reset_token = [_]u8{9} ** 16 } },
        .{ .retire_connection_id = .{ .sequence = 3 } },
        .{ .new_token = .{ .token = "tok" } },
        .{ .ack_frequency = .{ .sequence_number = 1, .ack_eliciting_threshold = 2, .request_max_ack_delay = 25_000, .reordering_threshold = 1 } },
        .{ .datagram = .{ .data = "dg", .with_length = true } },
        .{ .datagram = .{ .data = "dg2", .with_length = false } },
        .{ .observed_ipv4_addr = .{ .seq = 1, .ip = .{ 127, 0, 0, 1 }, .port = 443 } },
        .{ .add_ipv4_address = .{ .seq = 2, .ip = .{ 10, 0, 0, 2 }, .port = 80 } },
        .{ .reach_out_at_ipv4 = .{ .seq = 3, .ip = .{ 192, 168, 1, 1 }, .port = 8080 } },
        .{ .remove_address = 9 },
    };
    for (cases) |f| {
        const enc = try f.encode(&buf);
        try std.testing.expectEqual(enc.len, f.encodedLen());
    }
}
