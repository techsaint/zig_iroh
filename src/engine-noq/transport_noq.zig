//! Greenfield noq QUIC engine wired behind the frozen `transport.zig` vtable.
//!
//! This is the noq-engine peer of the picoquic backend in
//! `transport/endpoint.zig`. It drives the sans-io noq driver
//! (`quic/connection.zig`) over a real UDP `net.Socket` pump, demuxing inbound
//! datagrams through the CID router (`quic/endpoint.zig`), and follows the same
//! mutex-free actor shape.
//!
//! Scope: the vtable impl + UDP pump + router integration +
//! client-connect AND server-accept + persistent-endpoint reclaim. The stream
//! layer, flow control, close/reset frames, and real retransmit already live in
//! the driver (5a+5b); 5c is pure vtable/pump/router glue on top of that API.
//!
//! The `noq-picotls` / `noq-zigtls` products select this backend through the
//! engine-select factory; `picoquic-picotls` never compiles it in.

const std = @import("std");
const tr = @import("transport");
const product_flags = @import("shared").product_flags;
const key = @import("shared").key;
const tls_name = @import("shared").tls_name;
const crypto = @import("crypto.zig");
const congestion = @import("congestion.zig");
const packet = @import("packet.zig");
const quic_conn = @import("connection.zig");
const quic_token = @import("token.zig");
const initial_keys = @import("initial_keys.zig");
const quic_frame = @import("frame.zig");
const quic_initial_keys = @import("initial_keys.zig");
const quic_packet_crypto = @import("packet_crypto.zig");
const transport_parameters = @import("transport_parameters.zig");
const router_mod = @import("endpoint.zig");
const magicsock = @import("shared").magicsock;
const ms_frames = @import("shared").magicsock.frames;
const path_observability = @import("shared").path_observability;
const uni_poll = @import("shared").transport_contract;
const udp_cmsg = @import("shared").udp_cmsg;
const relay_fallback = @import("shared").transport_relay_fallback;
const zigtls = if (crypto.zigtls_enabled) @import("zigtls") else struct {};

const net = std.Io.net;

/// Engine tag — distinguishing field so a transport-level gate can prove it is
/// actually exercising noq (harness-fake resistance), not picoquic.
pub const Engine = enum { picoquic, noq };

/// The relay-datagram seam is shared with the picoquic engine — one type, one
/// vtable, one set of adapters (`transport/relay_fallback.zig`). The noq pump
/// routes here when magicsock selects a `.relay` path, feeding received relay
/// datagrams back via `handleDatagram`. These aliases keep the historical noq
/// spelling at call sites.
pub const RelayDatagram = relay_fallback.Datagram;
pub const RelayClient = relay_fallback.Client;

const max_conns = 16;
const max_stream_impls = 64;
const max_peer_streams = 32;
/// Maximum UDP payload the endpoint advertises/accepts for one datagram
/// (RFC 9000 §14 ceiling on the wire). Matches noq's `max_udp_payload_size`
/// default of 65527 (`noq-proto/src/transport_parameters.rs:42`).
const max_udp_payload: usize = 65527;

const handshake_timeout_ns: i64 = 10 * std.time.ns_per_s;
const default_stream_timeout_ns: i64 = 60 * std.time.ns_per_s;
const drive_quiesce_deadline_ns: i64 = 5 * std.time.ns_per_s;
const send_writer_buffer_len: usize = 16 * 1024;
const send_buffer_high_water: usize = 2 * 1024 * 1024;
const send_buffer_low_water: usize = 1 * 1024 * 1024;
const recv_reader_buffer_len: usize = 32 * 1024;
const local_cid_len: usize = 8;
/// L6: receive batching depth. noq uses `BATCH_SIZE = 32` on Linux
/// (`noq-udp/src/unix.rs:826`); the per-message buffer is the L17
/// `max_datagram` ceiling, so the receive batch is kept smaller and
/// the `recvmmsg` drain loop iterates to cover a full window.
const socket_batch_size: usize = 8;

/// L17: per-message receive buffer for the GRO-off batched path. Sized to the
/// single-datagram ceiling so a legal packet is never MSG_TRUNC-truncated (the
/// old 2048 ceiling truncated real ones). GRO coalescing uses a dedicated
/// single large buffer instead (see `gro_recv_capacity`).
const max_datagram = max_udp_payload;

/// L7/L17: capacity of the single GRO receive buffer — the largest GRO list
/// the kernel may produce (`max_udp_payload * UDP_GRO_CNT_MAX`, quinn#1354).
/// One message slot at this width receives the whole coalesced list, which the
/// pump then splits by the `UDP_GRO` stride cmsg.
const gro_recv_capacity = max_udp_payload * 64;

/// Capacity of the GRO-off batched receive buffer: `socket_batch_size` equal
/// per-message slots of `max_datagram`.
const batched_recv_capacity = socket_batch_size * max_datagram;

/// Receive-storage sizing for an endpoint's GRO mode: the full GRO buffer when
/// the kernel accepted `UDP_GRO` (`gro_segments > 1`), otherwise the smaller
/// batched layout. The buffer is heap-allocated ONCE per batch owner at this
/// size and reused across every receive — never allocated per packet, never
/// stack-resident (audit findings lane-02-h1 / lane-07-m2).
fn recvCapacity(gro_segments: usize) usize {
    return if (gro_segments > 1) gro_recv_capacity else batched_recv_capacity;
}
const zigtls_ticket_key_rotation_seconds: i64 = 6 * std.time.s_per_hour;
const zigtls_ticket_key_validity_seconds: i64 = 2 * zigtls_ticket_key_rotation_seconds;

const drain_timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromNanoseconds(0), .clock = .awake } };

/// Consecutive background-pump round failures before the loop parks itself:
/// a dead socket must not hot-spin. Mirrors the picoquic backend's broken
/// posture (`endpoint.zig#notePumpError`). Caller inline pumping is
/// unaffected and keeps surfacing failures through its own paths.
const background_pump_broken_threshold: u32 = 100;

const IncomingBatch = struct {
    messages: [socket_batch_size]net.IncomingMessage = undefined,
    /// Heap-backed receive storage, owned by whoever created the batch: the
    /// parent endpoint owns the pump's buffer (allocated in `initOptions`),
    /// test/oracle callers own theirs via `create`/`destroy`. Sized by
    /// `recvCapacity(gro_segments)` for the owning endpoint's GRO mode. The
    /// GRO-off batched path splits it into `socket_batch_size` equal
    /// per-message buffers of `max_datagram` each; the GRO-on path uses the
    /// whole buffer as ONE message's storage so a full coalesced list fits
    /// (`gro_recv_capacity`), then splits by stride. The active layout is
    /// chosen by the endpoint's `gro` flag, not a runtime tag, and the two
    /// never mix within one receive. The buffer lives behind this slice — NOT
    /// inline in the value — so a batch can never place the ~4 MiB GRO window
    /// on a stack frame (audit findings lane-02-h1 / lane-07-m2).
    data: []u8 = &.{},
    /// Per-message ancillary-data buffers. `receiveManyTimeout` requires every
    /// message's `control` slice to be initialized by the caller; without these
    /// the kernel has nowhere to put the ECN cmsg and CE marks are invisible.
    control: [socket_batch_size][udp_cmsg.recv_control_space]u8 = undefined,

    /// Initialize every message's `control` pointer (required by
    /// `receiveManyTimeout`). The message slice + data layout is selected by
    /// `receiveArgs(gro)`.
    fn init(self: *IncomingBatch) void {
        for (&self.messages, &self.control) |*message, *control| {
            message.* = net.IncomingMessage.init;
            message.control = control;
        }
    }

    /// The message slice + data buffer to hand `receiveManyTimeout`.
    fn receiveArgs(self: *IncomingBatch, gro: bool) struct { []net.IncomingMessage, []u8 } {
        if (gro) {
            std.debug.assert(self.data.len >= gro_recv_capacity);
            return .{ self.messages[0..1], self.data[0..gro_recv_capacity] };
        }
        std.debug.assert(self.data.len >= batched_recv_capacity);
        return .{ self.messages[0..], self.data[0..batched_recv_capacity] };
    }

    /// Heap-allocate a batch plus its receive storage, sized for the owning
    /// endpoint's GRO mode (`endpoint.gro_segments`). One allocation for the
    /// batch's whole lifetime; the receive path never allocates per packet.
    pub fn create(allocator: std.mem.Allocator, gro_segments: usize) error{OutOfMemory}!*IncomingBatch {
        const self = try allocator.create(IncomingBatch);
        errdefer allocator.destroy(self);
        self.* = .{ .data = try allocator.alloc(u8, recvCapacity(gro_segments)) };
        return self;
    }

    pub fn destroy(self: *IncomingBatch, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        allocator.destroy(self);
    }
};

/// Public scratch for `receiveRawForTest`, so the behavioral oracle can drive
/// raw socket receives without depending on the pump's internal batch type.
pub const RawReceiveScratch = IncomingBatch;

/// Stack-budget invariant for `IncomingBatch`: the ~4 MiB GRO receive window
/// must live behind `data` (heap-backed), never inline in the value. Before
/// the heap move (audit findings lane-02-h1-incomingbatch-stack-size,
/// lane-07-m2-incomingbatch-stack-size) a stack frame holding a batch — a
/// pump local, an oracle scenario, a gate helper — was a ~4 MiB frame, risking
/// overflow under nested call depth. Pin the value size so a future inline
/// regression cannot pass silently (companion to `OutgoingBatch`'s budget).
fn incomingBatchStackBudgetOk(size: usize) bool {
    return size <= incoming_batch_stack_budget;
}

const incoming_batch_stack_budget: usize = 4 * 1024;

comptime {
    std.debug.assert(incomingBatchStackBudgetOk(@sizeOf(IncomingBatch)));
}

test "IncomingBatch stack budget rejects the historical ~4 MiB inline geometry" {
    try std.testing.expect(incomingBatchStackBudgetOk(@sizeOf(IncomingBatch)));
    try std.testing.expect(!incomingBatchStackBudgetOk(gro_recv_capacity));
}

/// Maximum datagrams the kernel will split from one `UDP_SEGMENT` send.
/// Linux's own limit is 64 (`UDP_MAX_SEGMENTS`); staying at it keeps a batch
/// within one skb chain.
const max_gso_segments: usize = 64;

/// Coalesces consecutive outbound datagrams destined for one peer into a single
/// GSO `sendmsg`.
///
/// The driver is sans-io and hands us one datagram per `pollTransmit`, writing
/// each into its own scratch buffer — so batching has to happen here, in the
/// only layer that owns the socket. The kernel's rule is that every segment but
/// the last must be exactly `segment_size`, which gives the flush conditions
/// below: a differing size, a differing peer, a differing ECN codepoint, or a
/// full batch.
///
/// **Pacing is preserved.** This coalesces datagrams the driver has ALREADY
/// decided to send (each one debited the pacing budget inside `finishPacket`),
/// so a batch can never exceed what the pacer allowed. An earlier GSO attempt
/// was reverted for loopback burst loss precisely because it bypassed the
/// pacer; batching after the pacing decision is what makes this safe.
/// Staging width per batch segment. The batch coalesces datagrams the driver
/// emitted at the path's packet size (bounded by the path MTU), so 2048 covers
/// every wire-sized segment; a single oversize datagram up to `max_udp_payload`
/// still fits the buffer whole (65527 <= 64 * 2048). Do NOT size this by
/// `max_udp_payload`: the batch is a per-call stack local, and the 64x65527
/// (4 MiB) geometry zero-initialized megabytes per `pumpOutgoing` call — the
/// 2026-07-31 noq throughput regression.
const gso_batch_segment_width: usize = 2048;

const OutgoingBatch = struct {
    bytes: [max_gso_segments * gso_batch_segment_width]u8 = undefined,
    len: usize = 0,
    /// Size of every segment currently staged (the last may be shorter, and
    /// once a short one lands the batch must flush).
    segment_size: u16 = 0,
    count: usize = 0,
    dest: ?net.IpAddress = null,
    ecn: ?udp_cmsg.EcnCodepoint = null,
    /// A short final segment closes the batch — nothing may follow it.
    sealed: bool = false,

    fn isEmpty(self: *const OutgoingBatch) bool {
        return self.count == 0;
    }

    /// Can `datagram` join the staged batch without violating the kernel's
    /// equal-segment rule?
    fn accepts(self: *const OutgoingBatch, dest: net.IpAddress, ecn: ?udp_cmsg.EcnCodepoint, size: usize) bool {
        if (self.count == 0) return true;
        if (self.sealed) return false;
        if (self.count >= max_gso_segments) return false;
        if (self.len + size > self.bytes.len) return false;
        if (!ipEql(self.dest.?, dest)) return false;
        if (!ecnEql(self.ecn, ecn)) return false;
        // Only the FINAL segment may be shorter than the rest.
        return size <= self.segment_size;
    }

    fn push(self: *OutgoingBatch, dest: net.IpAddress, ecn: ?udp_cmsg.EcnCodepoint, datagram: []const u8) void {
        if (self.count == 0) {
            self.dest = dest;
            self.ecn = ecn;
            self.segment_size = @intCast(datagram.len);
        } else if (datagram.len < self.segment_size) {
            self.sealed = true;
        }
        @memcpy(self.bytes[self.len..][0..datagram.len], datagram);
        self.len += datagram.len;
        self.count += 1;
    }

    fn reset(self: *OutgoingBatch) void {
        self.len = 0;
        self.count = 0;
        self.segment_size = 0;
        self.dest = null;
        self.ecn = null;
        self.sealed = false;
    }
};

/// Safety invariant for `OutgoingBatch`: `accepts` returns true
/// unconditionally for the FIRST datagram (`count == 0`) and `push` memcpy's
/// it into `bytes`, so a `max_udp_payload` past the staging capacity would
/// make that unconditional copy overflow the (stack-resident) buffer in
/// ReleaseFast. Keep the largest legal datagram within the batch geometry.
fn outgoingBatchCapacityOk(max_payload: usize, segments: usize, segment_width: usize) bool {
    return max_payload <= segments * segment_width;
}

comptime {
    std.debug.assert(outgoingBatchCapacityOk(max_udp_payload, max_gso_segments, gso_batch_segment_width));
}

test "OutgoingBatch capacity guard rejects an over-capacity configuration" {
    try std.testing.expect(outgoingBatchCapacityOk(max_udp_payload, max_gso_segments, gso_batch_segment_width));
    try std.testing.expect(!outgoingBatchCapacityOk(max_gso_segments * gso_batch_segment_width + 1, max_gso_segments, gso_batch_segment_width));
}

/// Stack-budget invariant for `OutgoingBatch`: the batch is a per-call stack
/// local in `pumpOutgoing`, so its staging buffer must stay small. Sizing the
/// buffer by the receive ceiling (the pre-2026-07-31 geometry `[max_gso_segments *
/// max_datagram]`) grew it silently from 128 KiB to ~4 MiB when `max_datagram`
/// bumped 2048 -> 65527 — audit finding `lane-07-m3-outgoingbatch-stack-size`
/// and the same-day pumpOutgoing throughput regression. The staging width is
/// now decoupled (`gso_batch_segment_width`); pin the frame size so a future
/// ceiling bump cannot silently grow the stack frame again.
fn outgoingBatchStackBudgetOk(size: usize) bool {
    return size <= outgoing_batch_stack_budget;
}

const outgoing_batch_stack_budget: usize = 192 * 1024;

comptime {
    std.debug.assert(outgoingBatchStackBudgetOk(@sizeOf(OutgoingBatch)));
}

test "OutgoingBatch stack budget rejects the regressed 4 MiB geometry" {
    try std.testing.expect(outgoingBatchStackBudgetOk(@sizeOf(OutgoingBatch)));
    try std.testing.expect(!outgoingBatchStackBudgetOk(max_gso_segments * max_datagram));
}

fn ecnEql(a: ?udp_cmsg.EcnCodepoint, b: ?udp_cmsg.EcnCodepoint) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return a.? == b.?;
}

fn ticketKeyNotAfter(now_unix: i64) i64 {
    return std.math.add(i64, now_unix, zigtls_ticket_key_validity_seconds) catch std.math.maxInt(i64);
}

fn ticketKeyRotationDue(rotated_at_unix: i64, now_unix: i64) bool {
    return now_unix > rotated_at_unix and now_unix - rotated_at_unix >= zigtls_ticket_key_rotation_seconds;
}

test "zigtls production ticket keys rotate periodically and have finite validity" {
    const started: i64 = 1_700_000_000;
    try std.testing.expect(!ticketKeyRotationDue(started, started + zigtls_ticket_key_rotation_seconds - 1));
    try std.testing.expect(ticketKeyRotationDue(started, started + zigtls_ticket_key_rotation_seconds));
    try std.testing.expect(ticketKeyNotAfter(started) > started);
    try std.testing.expect(ticketKeyNotAfter(started) < std.math.maxInt(i64));
}

fn toSockAddr(a: net.IpAddress) router_mod.SocketAddress {
    return switch (a) {
        .ip4 => |v| router_mod.SocketAddress.ipv4(v.bytes, v.port),
        .ip6 => |v| router_mod.SocketAddress.ipv6(v.bytes, v.port),
    };
}

fn ipEql(a: net.IpAddress, b: net.IpAddress) bool {
    return toSockAddr(a).eql(toSockAddr(b));
}

/// Translate a driver-surfaced n0 NAT frame into the magicsock frame type.
fn natToMagic(a: quic_conn.NatAddress) ms_frames.Frame {
    if (a.ip6) |ip6| {
        return switch (a.kind) {
            .add => .{ .ipv6_address = .{ .frame_type = .add_ipv6_address, .seq = a.seq, .ip = ip6, .port = a.port } },
            .reach_out => .{ .ipv6_address = .{ .frame_type = .reach_out_at_ipv6, .seq = a.seq, .ip = ip6, .port = a.port } },
            .observed => .{ .ipv6_address = .{ .frame_type = .observed_ipv6_addr, .seq = a.seq, .ip = ip6, .port = a.port } },
            .remove => .{ .remove_address = .{ .seq = a.seq } },
        };
    }
    return switch (a.kind) {
        .observed => .{ .ipv4_address = .{ .frame_type = .observed_ipv4_addr, .seq = a.seq, .ip = a.ip, .port = a.port } },
        .add => .{ .ipv4_address = .{ .frame_type = .add_ipv4_address, .seq = a.seq, .ip = a.ip, .port = a.port } },
        .reach_out => .{ .ipv4_address = .{ .frame_type = .reach_out_at_ipv4, .seq = a.seq, .ip = a.ip, .port = a.port } },
        .remove => .{ .remove_address = .{ .seq = a.seq } },
    };
}

/// A peer-initiated stream awaiting `acceptBi` / `acceptUni`.
const PeerStream = struct {
    id: u64,
    handed_off: bool = false,
};

/// A PATH_CHALLENGE token we sent, mapped to the magicsock candidate address it
/// is validating (5e): on the matching PATH_RESPONSE we mark that path succeeded.
const ProbeToken = struct {
    token: [8]u8,
    addr: net.IpAddress,
};

/// The `Transmit.dest_hint` value meaning "send to the migration
/// candidate, not the current path".
const migration_dest_hint: u64 = 1;

const ConnEntry = struct {
    used: bool = false,
    driver: *quic_conn.Connection = undefined,
    handle: router_mod.ConnectionHandle = undefined,
    /// Destination address for this conn's outbound datagrams (the driver's
    /// `Transmit` carries no address — the entry owns it, per design §2.2).
    remote: net.IpAddress = undefined,
    role: crypto.Role = .client,
    /// Number of driver-local CIDs already installed in `Endpoint.router`.
    /// The initial CID is registered when the connection entry is minted.
    registered_local_cids: usize = 1,
    connected: bool = false,
    lost: bool = false,
    /// QAD: the observed-address report was already queued for this conn.
    qad_observed_sent: bool = false,
    /// F13 QAD client: the last OBSERVED_ADDRESS report drained from this
    /// connection, taken (one-shot) by `Endpoint.qadClientTakeObserved`.
    /// Server-role entries never populate this (servers SEND the report).
    qad_observed: ?quic_conn.NatAddress = null,
    /// A TLS CertificateVerify failure on an inbound handshake. This is kept
    /// distinct from ordinary packet decode drops so Gate B can prove the
    /// server rejected the spoof before exposing a Connection.
    rejected: bool = false,
    handed_off: bool = false,
    peer_streams: [max_peer_streams]PeerStream = undefined,
    peer_stream_count: usize = 0,
    reset_ids: [max_peer_streams]u64 = undefined,
    reset_count: usize = 0,
    // 5e magicsock / path validation.
    remote_node: key.NodeId = undefined,
    remote_node_set: bool = false,
    magic: magicsock.State = undefined,
    magic_init: bool = false,
    probes: [max_peer_streams]ProbeToken = undefined,
    probe_count: usize = 0,
    /// When true, outbound datagrams route through the relay client, not the
    /// socket (magicsock selected a `.relay` path).
    relay_selected: bool = false,

    /// Passive-migration candidate under path validation (noq
    /// peer_may_migrate): the peer's packet arrived from this new address;
    /// the conn switches to it when our challenge validates there.
    migration_pending: bool = false,
    migration_candidate: net.IpAddress = undefined,
    migration_token: [8]u8 = undefined,
    /// The next NAT probe retry deadline (noq NatTraversalProbeRetry).
    next_nat_retry_ns: ?i64 = null,

    fn notePeerStream(self: *ConnEntry, id: u64) void {
        for (self.peer_streams[0..self.peer_stream_count]) |ps| {
            if (ps.id == id) return;
        }
        if (self.peer_stream_count >= max_peer_streams) return;
        self.peer_streams[self.peer_stream_count] = .{ .id = id };
        self.peer_stream_count += 1;
    }

    fn noteReset(self: *ConnEntry, id: u64) void {
        if (self.reset_count >= max_peer_streams) return;
        self.reset_ids[self.reset_count] = id;
        self.reset_count += 1;
    }

    fn popReset(self: *ConnEntry) ?u64 {
        if (self.reset_count == 0) return null;
        const id = self.reset_ids[0];
        if (self.reset_count > 1) {
            std.mem.copyForwards(u64, self.reset_ids[0 .. self.reset_count - 1], self.reset_ids[1..self.reset_count]);
        }
        self.reset_count -= 1;
        return id;
    }

    fn hasReset(self: *const ConnEntry, id: u64) bool {
        for (self.reset_ids[0..self.reset_count]) |r| {
            if (r == id) return true;
        }
        return false;
    }
};

const CachedZigtlsTicket = if (crypto.zigtls_enabled) struct {
    peer: key.NodeId,
    info: crypto.Types.NewSessionTicketInfo,

    fn deinit(self: *CachedZigtlsTicket, allocator: std.mem.Allocator) void {
        self.info.deinit(allocator);
        self.* = undefined;
    }
} else struct {};

/// B7 drain-window entry (noq ConnectionDriver, noq/src/connection.rs:245-293
/// — the driver future stays alive through the 3×PTO drain period so
/// stragglers are "handled gracefully"). A closed conn's slot is freed
/// immediately (persistent-endpoint discipline: liveConnectionCount drops,
/// the slot is reusable) but the driver + router registration move HERE so
/// an authenticated straggler still routes to the connection and re-draws
/// its CONNECTION_CLOSE (noq mod.rs:4439-4471) instead of falling off the
/// CID router to a stateless reset or silence. The entry is torn down when
/// the driver reaches drained (close_deadline = 3×max_pto, timers_events.zig).
const DrainEntry = struct {
    used: bool = false,
    driver: *quic_conn.Connection = undefined,
    handle: router_mod.ConnectionHandle = undefined,
    remote: net.IpAddress = undefined,
    remote_node: key.NodeId = undefined,
    remote_node_set: bool = false,
    relay_selected: bool = false,
};

/// RFC 9000 §2.1: a stream is peer-initiated when its initiator bit differs from
/// our role. Client-initiated ids have bit 0 == 0; server-initiated have bit 0 == 1.
fn isPeerInitiated(role: crypto.Role, id: u64) bool {
    const initiator_is_client = (id & 0x01) == 0;
    return switch (role) {
        .client => !initiator_is_client,
        .server => initiator_is_client,
    };
}

fn isBidi(id: u64) bool {
    return (id & 0x02) == 0;
}

pub const IncomingFilterOutcome = enum {
    accept,
    retry,
    reject,
    ignore,
};

pub const IncomingInfo = struct {
    remote: net.IpAddress,
    remote_addr_validated: bool,
    first_datagram: []const u8,
};

pub const IncomingFilter = struct {
    context: *anyopaque,
    callback: *const fn (context: *anyopaque, info: *const IncomingInfo) IncomingFilterOutcome,
};

pub const Endpoint = struct {
    /// Distinguishing field: proves a transport-level gate routed to noq.
    pub const engine: Engine = .noq;

    allocator: std.mem.Allocator,
    io_inst: std.Io,
    /// Serializes the sans-io driver/router/pump state when a public Router
    /// handler and the accept loop touch the same noQ endpoint from different
    /// OS threads. The driver is intentionally mutex-free; this endpoint seam is
    /// the thread boundary. The background pump task (`pump_task`) shares this
    /// mutex with the caller paths — every driver/router touch stays under it.
    pump_mu: std.Io.Mutex = .init,
    /// iroh-actor-style background pump state (opt-in, Options.background_pump):
    /// the spawned task + its stop flag. `deinit` stops + joins the task before
    /// any teardown, so it can never race socket/driver/router destruction.
    pump_task: ?std.Io.Future(void) = null,
    pump_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    secret: key.SecretKey,
    node_id: key.NodeId,
    alpn: [:0]const u8,
    /// Owned server ALPN list for new inbound handshakes (setAlpns).
    server_alpns: std.ArrayListUnmanaged([]u8) = .empty,
    socket: net.Socket,
    local_address: net.IpAddress,
    router: router_mod.Endpoint,
    /// When set, this endpoint accepts inbound connections, pinning the RPK
    /// verifier to this expected peer. Learned-peer accept is separately opt-in.
    expected_peer: ?key.NodeId,
    accept_unknown_peer: bool,
    certificate_public_key_override: ?key.NodeId,
    certificate_der_override: ?[]const u8,
    /// TLS backend for Connection.create (default picotls; opt-in zigtls).
    tls_backend: crypto.Backend,
    /// J2: congestion controller selection for new NOQ connections.
    congestion_kind: congestion.Kind,
    /// QAD server identity (draft-seemann-quic-address-discovery). When set,
    /// inbound connections are served X.509 (never RPK), client auth is off,
    /// the observed-address TP role `.send_only` is advertised with zero
    /// streams, and each connected peer's observed address is queued once.
    /// Requires tls_backend == .zigtls (the picotls glue is RPK-only).
    qad_identity: ?crypto.X509ServerIdentity = null,
    certificate_request_signature_algorithms: ?[]const u16,
    zigtls_ticket_key_manager: if (crypto.zigtls_enabled) crypto.Types.TicketKeyManager else void =
        if (crypto.zigtls_enabled) crypto.Types.TicketKeyManager.init() else {},
    zigtls_ticket_key_rotated_at_unix: i64 = 0,
    zigtls_cached_ticket: if (crypto.zigtls_enabled) ?CachedZigtlsTicket else void =
        if (crypto.zigtls_enabled) null else {},
    /// 0-RTT early data (zigtls backend only): server-side acceptance behind
    /// the replay strike register + 0-RTT-capable session tickets; client-side
    /// offer whenever a cached ticket permits. OFF by default — real-iroh
    /// peers (quinn) do not negotiate RPK 0-RTT today, so the default keeps
    /// the interop wire surface untouched until a deployment opts in.
    zero_rtt_enabled: bool = false,
    /// Long-lived 0-RTT replay strike register (RFC 9001 §9.2; the engine
    /// fail-closes an enabled early-data config that lacks one). Endpoint-
    /// scoped so the single-use-ticket policy survives across connections.
    /// Allocated in initOptions (no comptime default exists for the backing
    /// bit array).
    zigtls_replay_filter: if (crypto.zigtls_enabled) crypto.Types.ReplayFilter else void,
    conns: [max_conns]ConnEntry = [_]ConnEntry{.{}} ** max_conns,
    /// B7: closed conns held through their drain window (3×PTO); see DrainEntry.
    drains: [max_conns]DrainEntry = [_]DrainEntry{.{}} ** max_conns,
    sends: [max_stream_impls]SendImpl = undefined,
    recvs: [max_stream_impls]RecvImpl = undefined,
    /// Relay datagram client (engine-agnostic vtable). When a conn's magicsock
    /// selects a `.relay` path, its datagrams route here instead of the socket.
    relay: ?RelayClient = null,

    /// RFC 9000 §8.1 address-validation state (E5/E7/E9): the server-wide
    /// sealed-token key + the NEW_TOKEN anti-replay log + the client-side
    /// one-time-use token cache (E8).
    token_key: quic_token.TokenKey,
    token_log: quic_token.TokenLog,
    /// Require address validation via Retry for inbound connections (iroh
    /// default OFF; the capability is opt-in, matching noq's ServerConfig).
    retry_required: bool,
    incoming_filter: ?IncomingFilter = null,
    /// Lifetime of NEW_TOKEN tokens we issue/accept (noq default 2 weeks).
    new_token_lifetime_secs: u64,
    /// Client NEW_TOKEN cache: server name → token bytes (owned, one-time use).
    token_cache: std.StringHashMap([]u8),
    /// E3: the endpoint's stateless-reset HMAC key (noq EndpointConfig
    /// `reset_key`) + the min-reset-interval clock (noq `min_reset_interval`
    /// 20 ms). Connection reset tokens derive from this key so resets the
    /// endpoint sends are recognizable to peers.
    reset_key: [32]u8,
    last_stateless_reset_ns: i64 = 0,
    stats_stateless_reset_sent: u64 = 0,

    /// E11: first flights dropped because the conn table was saturated
    /// (noq `max_incoming`).
    stats_incoming_saturation_drops: u64 = 0,

    /// E5 evidence counters (oracle-visible, never reason strings).
    stats_retry_issued: u64 = 0,
    stats_retry_validated: u64 = 0,
    stats_new_token_validated: u64 = 0,

    /// Kernel reported the inbound TOS/TCLASS option was accepted, so ECN
    /// codepoints will arrive as ancillary data on receive.
    ecn_receive_enabled: bool = false,
    /// The IP layer is allowed to fragment (`unix.rs:110-127`). False on Linux,
    /// where we set `IP_MTU_DISCOVER=PROBE` (+ `IPV6_MTU_DISCOVER`) so PMTUD sees
    /// loss/`EMSGSIZE` instead of hidden fragments; true when the kernel refused.
    may_fragment: bool = true,
    /// Receive coalescing depth (`UDP_GRO`). 1 = no coalescing; 64 when the
    /// kernel accepted `UDP_GRO` (`UDP_GRO_CNT_MAX`). Sizes the recv ceiling.
    gro_segments: usize = 1,
    /// Destination-address cmsg armed (`IP_PKTINFO`/`IPV6_PKTINFO`).
    pktinfo_receive_enabled: bool = false,
    /// Kernel receive timestamps armed (`SO_TIMESTAMPNS`).
    timestamp_receive_enabled: bool = false,
    /// Kernel accepted a `UDP_SEGMENT` probe, so GSO sends are worth attempting.
    /// Cleared permanently on the first `GsoRejected`, mirroring Rust's
    /// `max_gso_segments = 1` fallback (`noq-udp/src/unix.rs:431-445`).
    gso_enabled: bool = false,

    // ── Structured send/receive evidence (the oracle keys on these) ──────────
    // Counters, not reason strings: a stubbed oracle row cannot move a counter
    // that only the production socket path increments.

    /// `sendmsg` calls that carried a `UDP_SEGMENT` cmsg AND covered >1 segment.
    stats_gso_segmented_sends: u64 = 0,
    /// Datagrams actually emitted by those segmented sends.
    stats_gso_segments_sent: u64 = 0,
    /// Times the kernel rejected a GSO send (EIO/EINVAL) and we fell back to
    /// per-datagram sends.
    stats_gso_rejected: u64 = 0,
    /// Datagrams sent with an ECN codepoint on the IP header.
    stats_ecn_sent: u64 = 0,
    /// Sends swallowed as expected MTU-probe loss (`EMSGSIZE`, L9).
    stats_send_msgsize: u64 = 0,
    /// Sends swallowed as transient delivery failures (L10).
    stats_send_transient: u64 = 0,
    /// Sends that pinned a source address via pktinfo (L12).
    stats_src_ip_sent: u64 = 0,
    /// Sends to a v4-mapped destination on a v6 socket (L14).
    stats_v4_mapped_sent: u64 = 0,
    /// Received datagrams that were GRO-coalesced (len > stride) (L7).
    stats_gro_coalesced_recv: u64 = 0,
    /// L11: a prior `sendmsg` returned EINVAL for the `IP_TOS` cmsg (old
    /// kernel). Once latched, ECN sends omit the cmsg (`unix.rs:447-458`).
    sendmsg_einval: bool = false,
    /// Sends retried without the ECN cmsg after an EINVAL (L11).
    stats_send_einval_retry: u64 = 0,
    /// Receive scratch for the pump. Its receive buffer (up to ~4 MiB with
    /// GRO) is heap-backed storage owned by this endpoint — allocated once in
    /// `initOptions`, freed in `deinit` — so the pump's stack stays small
    /// (lane-02-h1 / lane-07-m2).
    recv_scratch: RawReceiveScratch = .{},
    /// Datagrams received carrying a CE codepoint in a real IP header.
    stats_ecn_recv_marked: u64 = 0,
    /// Datagrams received carrying any ECT codepoint.
    stats_ecn_recv_ect: u64 = 0,

    /// Test-only: when set, outbound datagrams matching the predicate are dropped
    /// after the driver has tracked them as sent (LOSSY large-transfer gate).
    test_drop: ?*const fn (pkt_idx: usize) bool = null,
    /// Test-only: mutate a stack copy of outbound datagram bytes after the driver
    /// has tracked the original packet as sent, immediately before socket/relay
    /// publication (0-RTT authentication-failure negative gate).
    test_mutate: ?*const fn (pkt_idx: usize, bytes: []u8) void = null,
    test_tx_count: usize = 0,
    /// Per-endpoint stream I/O deadline (sendFinish / recvReadInto).
    stream_timeout_ns: i64 = default_stream_timeout_ns,

    pub const Options = struct {
        bind_address: net.IpAddress = .{ .ip4 = .loopback(0) },
        expected_peer: ?key.NodeId = null,
        accept_unknown_peer: bool = false,
        certificate_public_key_override: ?key.NodeId = null,
        /// zigtls-only adversarial certificate bytes; default null keeps the
        /// local RPK/SPKI generated from `secret` or `certificate_public_key`.
        certificate_der_override: ?[]const u8 = null,
        /// Opt-in pure-Zig TLS; default stays picotls (experimental posture).
        tls_backend: crypto.Backend = .picotls,
        /// J2: congestion controller selection. Cubic remains the default.
        congestion_kind: congestion.Kind = .cubic,
        /// QAD server identity (draft-seemann address discovery). zigtls only.
        qad_identity: ?crypto.X509ServerIdentity = null,
        /// zigtls-only server CertificateRequest offer policy; null uses the TLS default.
        certificate_request_signature_algorithms: ?[]const u16 = null,
        /// E5: require Retry-based address validation for inbound connections
        /// (iroh deployment default OFF, matching noq's ServerConfig default).
        retry: bool = false,
        /// E7/E9: lifetime of NEW_TOKEN tokens (noq default 2 weeks).
        new_token_lifetime_secs: u64 = 2 * 7 * 24 * 60 * 60,
        /// L7: arm `UDP_GRO` receive coalescing. Default on, matching the
        /// production path; tests that must observe per-segment receive
        /// boundaries (e.g. per-segment ECN marks) opt out.
        gro_receive: bool = true,
        /// 0-RTT early data (zigtls backend only). OFF by default: server
        /// acceptance is replay-filter-guarded and fail-closed, client offers
        /// ride cached 0-RTT-capable tickets.
        zero_rtt: bool = false,
        /// iroh-actor-style BACKGROUND PUMP: spawn one task per endpoint that
        /// continuously drives send/receive/timers independent of caller
        /// stream operations (the noq behavioral counterpart of the picoquic
        /// backend's spawned single-owner event loop, `endpoint.zig#run`, and
        /// of iroh's tokio-driven quinn endpoint driver). OFF by default: the
        /// deterministic gate/oracle surface drives the pump inline and pins
        /// transmit ordering; the product facade (`src/shared/endpoint.zig`) opts in.
        background_pump: bool = false,
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, secret: key.SecretKey, alpn: [:0]const u8) !*Endpoint {
        return initOptions(allocator, io, secret, alpn, .{});
    }

    pub fn initOptions(allocator: std.mem.Allocator, io: std.Io, secret: key.SecretKey, alpn: [:0]const u8, options: Options) !*Endpoint {
        if (!crypto.zigtls_enabled and options.tls_backend == .zigtls) {
            return error.ZigtlsDisabled;
        }
        if (options.qad_identity != null and options.tls_backend != .zigtls) {
            // The picotls glue is RPK-only; QAD serves rustls/webpki clients
            // and therefore needs the pure-Zig TLS backend's X.509 path.
            return error.QadRequiresZigtls;
        }

        const self = try allocator.create(Endpoint);
        errdefer allocator.destroy(self);

        var bind_addr = options.bind_address;
        const socket = try bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
        errdefer socket.close(io);

        var zigtls_ticket_key_manager = if (crypto.zigtls_enabled) crypto.Types.TicketKeyManager.init() else {};
        const zigtls_ticket_key_rotated_at_unix = std.Io.Clock.real.now(io).toSeconds();
        if (crypto.zigtls_enabled) {
            var ticket_material: [32]u8 = undefined;
            io.random(&ticket_material);
            var ticket_key_id_bytes: [4]u8 = undefined;
            io.random(&ticket_key_id_bytes);
            try zigtls_ticket_key_manager.rotate(.{
                .key_id = std.mem.readInt(u32, &ticket_key_id_bytes, .big),
                .material = ticket_material,
                .not_before_unix = zigtls_ticket_key_rotated_at_unix,
                .not_after_unix = ticketKeyNotAfter(zigtls_ticket_key_rotated_at_unix),
            });
        }

        // 0-RTT replay strike register (RFC 9001 §9.2). Allocated even when
        // `zero_rtt` is off: the cost is one 8 KiB bit array and it keeps a
        // later opt-in fail-closed-correct without an init path change.
        const zigtls_replay_filter = if (crypto.zigtls_enabled)
            try crypto.Types.ReplayFilter.init(allocator, 65536)
        else {};

        // CID-router hash key from the CSPRNG (dual-SipHash context, §"CID-hash").
        var hash_key: [16]u8 = undefined;
        io.random(&hash_key);

        // E5/E7: the sealed-token master key (64 random bytes → HKDF, per the
        // noq RetryTokenKey construction).
        var token_master: [64]u8 = undefined;
        io.random(&token_master);
        // E3: the stateless-reset HMAC key (noq EndpointConfig::new).
        var reset_key: [32]u8 = undefined;
        io.random(&reset_key);

        self.* = .{
            .allocator = allocator,
            .io_inst = io,
            .secret = secret,
            .node_id = secret.public(),
            .alpn = alpn,
            .socket = socket,
            .local_address = socket.address,
            .router = try router_mod.Endpoint.init(allocator, .{
                .peer_hash_key = hash_key,
                .local_cid_len = local_cid_len,
            }),
            .token_key = quic_token.TokenKey.initFromMaster(token_master),
            .token_log = quic_token.TokenLog.init(allocator),
            .reset_key = reset_key,
            .retry_required = options.retry,
            .new_token_lifetime_secs = options.new_token_lifetime_secs,
            .token_cache = std.StringHashMap([]u8).init(allocator),
            .expected_peer = options.expected_peer,
            .accept_unknown_peer = options.accept_unknown_peer,
            .certificate_public_key_override = options.certificate_public_key_override,
            .certificate_der_override = options.certificate_der_override,
            .tls_backend = options.tls_backend,
            .congestion_kind = options.congestion_kind,
            .qad_identity = options.qad_identity,
            .certificate_request_signature_algorithms = options.certificate_request_signature_algorithms,
            .zigtls_ticket_key_manager = if (crypto.zigtls_enabled) zigtls_ticket_key_manager else {},
            .zigtls_ticket_key_rotated_at_unix = zigtls_ticket_key_rotated_at_unix,
            .zigtls_cached_ticket = if (crypto.zigtls_enabled) null else {},
            .zero_rtt_enabled = options.zero_rtt,
            .zigtls_replay_filter = zigtls_replay_filter,
            // Both are best-effort kernel capabilities. A kernel that refuses
            // either leaves the endpoint fully functional, just without the
            // corresponding optimisation — never a hard init failure.
            .ecn_receive_enabled = udp_cmsg.enableEcnReceive(socket.handle, bind_addr == .ip4),
            .gso_enabled = udp_cmsg.gsoSupported(socket.handle),
            // L8: forbid IP fragmentation so PMTUD sees EMSGSIZE/loss. If the
            // kernel refused the option the socket `may_fragment` and the MTUD
            // upper bound must tolerate that (Rust `may_fragment`).
            .may_fragment = !udp_cmsg.disableFragmentation(socket.handle, bind_addr == .ip4),
            // L7: receive coalescing. `enableGro` returns the depth to size the
            // receive ceiling against (64 on success, 1 when unsupported).
            .gro_segments = if (options.gro_receive) udp_cmsg.enableGro(socket.handle) else 1,
            // L13: destination-address metadata on receive.
            .pktinfo_receive_enabled = udp_cmsg.enablePktinfoReceive(socket.handle, bind_addr == .ip4),
            // L15: kernel receive timestamps.
            .timestamp_receive_enabled = udp_cmsg.enableTimestampReceive(socket.handle),
        };
        for (&self.sends) |*s| s.* = .{};
        for (&self.recvs) |*r| r.* = .{};
        // Parent-own the pump's receive buffer on the heap, sized by the GRO
        // mode just probed above. Never stack-resident, never per-packet
        // (lane-02-h1 / lane-07-m2).
        self.recv_scratch.data = try allocator.alloc(u8, recvCapacity(self.gro_segments));
        errdefer allocator.free(self.recv_scratch.data);
        errdefer {
            std.crypto.secureZero(u8, &self.reset_key);
            std.crypto.secureZero(u8, &self.token_key.prk);
            self.secret.zeroize();
        }
        // Seed the server-advertised ALPN set from the constructor ALPN so an
        // endpoint that never calls setAlpns still advertises something. This is
        // the first fallible step after the CID router is live, so it owns the
        // router's cleanup (the outer errdefers only cover the socket + self).
        errdefer self.router.deinit();
        try self.setAlpns(&.{alpn});
        // The background pump observes endpoint state from here on; spawn it
        // LAST, after every fallible init step, so it can never see a
        // partially-initialized endpoint (the same discipline as the picoquic
        // actor spawn, `endpoint.zig#initOptions`).
        if (options.background_pump) {
            self.pump_task = io.async(backgroundPumpLoop, .{self});
        }
        return self;
    }

    /// Read-only: which TLS backend this endpoint feeds Connection.create.
    /// Gates assert `.zigtls` so a "zigtls smoke" cannot silently run on picotls.
    pub fn tlsBackend(self: *const Endpoint) crypto.Backend {
        return self.tls_backend;
    }

    /// True only when 0-RTT is opted in AND the pure-Zig backend is live.
    /// picotls disables early data by construction (omit_end_of_early_data),
    /// so a picotls endpoint can never open the replay surface.
    fn zeroRttOnZigtls(self: *const Endpoint) bool {
        return crypto.zigtls_enabled and self.tls_backend == .zigtls and self.zero_rtt_enabled;
    }

    /// Final owner teardown: callers must have stopped accept/pump/handler tasks
    /// and dropped connection wrappers before this destroys the endpoint storage.
    /// `pump_mu` cannot make use-after-deinit safe, so teardown is a documented
    /// single-owner non-concurrency boundary rather than a locked runtime path.
    pub fn deinit(self: *Endpoint) void {
        // Stop + join the background pump FIRST: it touches driver/router/
        // socket state under pump_mu, so no teardown below may race it. The
        // stop flag ends the loop at its next round boundary (a round holds
        // the lock for at most one bounded receive wait), so the join is
        // short-bounded and cannot deadlock a teardown.
        if (self.pump_task) |*future| {
            self.pump_stop.store(true, .release);
            future.await(self.io_inst);
            self.pump_task = null;
        }
        if (crypto.zigtls_enabled) {
            if (self.zigtls_cached_ticket) |*cached| cached.deinit(self.allocator);
            self.zigtls_cached_ticket = null;
            var filter = &self.zigtls_replay_filter;
            filter.deinit();
        }
        for (&self.conns) |*e| {
            if (e.used) {
                if (e.magic_init) e.magic.deinit();
                e.driver.destroy();
            }
        }
        for (&self.drains) |*d| {
            if (d.used) d.driver.destroy();
        }
        self.router.deinit();
        self.socket.close(self.io_inst);
        for (self.server_alpns.items) |owned| self.allocator.free(owned);
        self.server_alpns.deinit(self.allocator);
        var cache_it = self.token_cache.iterator();
        while (cache_it.next()) |kv| {
            self.allocator.free(@constCast(kv.key_ptr.*));
            self.allocator.free(kv.value_ptr.*);
        }
        self.token_cache.deinit();
        self.token_log.deinit();
        self.allocator.free(self.recv_scratch.data);
        std.crypto.secureZero(u8, &self.reset_key);
        std.crypto.secureZero(u8, &self.token_key.prk);
        self.secret.zeroize();
        self.allocator.destroy(self);
    }

    pub fn transport(self: *Endpoint) tr.Transport {
        return .{ .impl = self };
    }

    pub fn pubConnect(self: *Endpoint, peer: tr.NodeAddr) tr.Error!tr.Connection {
        return endpointConnect(self, peer);
    }
    pub fn pubAccept(self: *Endpoint) tr.Error!tr.Connection {
        return endpointAccept(self);
    }
    pub fn pubLocalNodeId(self: *Endpoint) tr.NodeId {
        return self.node_id;
    }
    pub fn pubIo(self: *Endpoint) std.Io {
        return self.io_inst;
    }

    pub fn localAddress(self: *Endpoint) net.IpAddress {
        return self.local_address;
    }

    /// Monotonic clock (nanoseconds) fed to the driver as `Instant`.
    fn clockNow(self: *const Endpoint) i64 {
        return @intCast(std.Io.Clock.now(.awake, self.io_inst).nanoseconds);
    }

    fn lockPump(self: *Endpoint) void {
        self.pump_mu.lockUncancelable(self.io_inst);
    }

    fn unlockPump(self: *Endpoint) void {
        self.pump_mu.unlock(self.io_inst);
    }

    /// Driver/router/reclaim helpers below are protected at the public/runtime
    /// boundary: acquire `pump_mu` once before mutating driver state, routing
    /// datagrams, reclaiming entries, or moving entries into/out of drains.
    /// The inner helper layer deliberately does not lock; `std.Io.Mutex` is
    /// non-recursive, so locking both an outer path and its helpers would deadlock.
    /// True iff at least one connection is currently live (reclaim gate helper).
    fn liveConnectionCountLocked(self: *const Endpoint) usize {
        var n: usize = 0;
        for (self.conns) |e| {
            if (e.used) n += 1;
        }
        return n;
    }

    pub fn liveConnectionCount(self: *const Endpoint) usize {
        const mutable_self: *Endpoint = @constCast(self);
        mutable_self.lockPump();
        defer mutable_self.unlockPump();
        return mutable_self.liveConnectionCountLocked();
    }

    /// Test hook: pump one round + drain events (the pump the vtable normally
    /// runs internally during a blocking op). Used to observe a peer close after
    /// the local side has finished all its blocking vtable calls.
    pub fn pumpForTest(self: *Endpoint) tr.Error!void {
        self.lockPump();
        defer self.unlockPump();
        const outgoing = try self.pumpOutgoing();
        _ = try self.pumpIncomingAfter(outgoing);
        for (&self.conns) |*e| {
            if (e.used) self.drainEvents(e);
        }
    }

    pub const SetAlpnsError = error{
        InvalidAlpn,
        OutOfMemory,
        EndpointClosed,
    };

    /// Replace server-advertised ALPNs (new inbound handshakes) AND the
    /// primary ALPN offered on new outbound dials — matching upstream
    /// Endpoint::set_alpns, which re-arms both roles. Dial precedence mirrors
    /// the accept side: server_alpns[0] when set, else the init-time alpn.
    ///
    /// Backs the multi-ALPN `Router` in `src/shared/protocol.zig`: the Router registers
    /// every handler's ALPN here before its accept loop starts, then dispatches
    /// each accepted connection on `Connection.alpn()`.
    pub fn setAlpns(self: *Endpoint, alpns: []const []const u8) SetAlpnsError!void {
        self.lockPump();
        defer self.unlockPump();
        if (alpns.len == 0) return error.InvalidAlpn;
        for (alpns) |a| {
            if (a.len == 0 or a.len > 64) return error.InvalidAlpn;
        }
        var next: std.ArrayListUnmanaged([]u8) = .empty;
        errdefer {
            for (next.items) |owned| self.allocator.free(owned);
            next.deinit(self.allocator);
        }
        try next.ensureTotalCapacity(self.allocator, alpns.len);
        for (alpns) |a| {
            next.appendAssumeCapacity(try self.allocator.dupe(u8, a));
        }
        for (self.server_alpns.items) |owned| self.allocator.free(owned);
        self.server_alpns.clearRetainingCapacity();
        self.server_alpns.deinit(self.allocator);
        self.server_alpns = next;
    }

    /// Nonblocking accept probe for protocol layers with their own cooperative
    /// pump. This drives one bounded I/O round and hands off at most one ready
    /// server connection; it does not park a blocking accept waiter.
    pub fn tryAcceptReady(self: *Endpoint) tr.Error!?tr.Connection {
        self.lockPump();
        defer self.unlockPump();
        try self.pollOnceLocked();
        for (&self.conns) |*e| {
            if (e.used and e.role == .server and e.connected and !e.handed_off) {
                e.handed_off = true;
                _ = try self.pumpOutgoing();
                const remote_node = e.driver.tls.peerPublicKey() catch return error.ConnectionLost;
                e.remote_node = remote_node;
                e.remote_node_set = true;
                const impl = self.allocator.create(ConnectionImpl) catch return error.OutOfMemory;
                impl.* = .{ .endpoint = self, .entry = e, .remote = remote_node };
                impl.snapshotAlpn(e);
                return wrapConn(impl);
            }
            // Only reclaim never-handed-off lost slots here. Handed-off conns
            // are owned by ConnectionImpl.close → reclaim; reclaiming both
            // double-frees magicsock (GPF under noq-zigtls accept stress).
            if (e.used and e.role == .server and e.lost and !e.handed_off) {
                self.reclaimLost(e);
            }
        }
        return null;
    }

    /// Test hook: install an outbound drop filter (LOSSY gate). Predicate sees a
    /// 1-based packet index; returning true drops the datagram on the wire while
    /// leaving the driver's sent-record intact so loss recovery must fire.
    pub fn setTestDropFilter(self: *Endpoint, filter: ?*const fn (usize) bool) void {
        self.lockPump();
        defer self.unlockPump();
        self.test_drop = filter;
        self.test_tx_count = 0;
    }

    /// Test hook: mutate a stack copy of outbound datagram bytes after sent-record
    /// tracking and before publication. Production leaves this null.
    pub fn setTestMutate(self: *Endpoint, mutator: ?*const fn (usize, []u8) void) void {
        self.lockPump();
        defer self.unlockPump();
        self.test_mutate = mutator;
        self.test_tx_count = 0;
    }

    pub fn setTestStreamTimeout(self: *Endpoint, timeout_ns: i64) void {
        self.lockPump();
        defer self.unlockPump();
        self.stream_timeout_ns = timeout_ns;
    }

    pub fn setIncomingFilter(self: *Endpoint, filter: ?IncomingFilter) void {
        self.lockPump();
        defer self.unlockPump();
        self.incoming_filter = filter;
    }

    /// Test hook: first live connection's driver (client or server by role).
    /// This is the one raw-driver escape hatch: callers must be single-threaded
    /// and must not race it with pump/handler operations because the pointer
    /// necessarily outlives any mutex guard. Prefer the locked value accessors.
    pub fn testDriver(self: *Endpoint, role: crypto.Role) ?*quic_conn.Connection {
        for (&self.conns) |*e| {
            if (e.used and e.role == role) return e.driver;
        }
        return null;
    }

    /// Test hook: smoothed RTT of the first live connection of `role` (real-peer RTT test).
    pub fn smoothedRttNsForTest(self: *Endpoint, role: crypto.Role) ?i64 {
        self.lockPump();
        defer self.unlockPump();
        const drv = self.testDriver(role) orelse return null;
        return drv.smoothedRttNsForTest();
    }

    /// Test hook: server-role conn reached `connected` — a READ-ONLY probe
    /// under pump_mu that never drives the pump. Lets a gate prove the
    /// BACKGROUND pump alone carried a handshake (no accept/pump call on this
    /// endpoint) without racing the loop the way the raw `testDriver` hatch
    /// would.
    pub fn serverConnectedForTest(self: *Endpoint) bool {
        self.lockPump();
        defer self.unlockPump();
        for (self.conns) |e| {
            if (e.used and e.role == .server and e.connected) return true;
        }
        return false;
    }

    /// Test hook: the first live conn of `role` has its FIN on `stream_id`
    /// fully acknowledged — read-only under pump_mu (background-pump-safe
    /// progress probe; the raw `testDriver` hatch would race the loop).
    pub fn streamSendCompleteForTest(self: *Endpoint, role: crypto.Role, stream_id: u64) ?bool {
        self.lockPump();
        defer self.unlockPump();
        const drv = self.testDriver(role) orelse return null;
        return drv.streamSendComplete(stream_id);
    }

    /// Test hook: clear peer reset tokens on the first live conn of `role` (stateless-reset mutation-RED).
    pub fn clearPeerStatelessResetTokensForTest(self: *Endpoint, role: crypto.Role) void {
        self.lockPump();
        defer self.unlockPump();
        if (self.testDriver(role)) |drv| drv.clearPeerStatelessResetTokensForTest();
    }

    /// Test hook: hard-disable peer reset matching (stateless-reset mutation-RED disable-point).
    pub fn setDisablePeerStatelessResetForTest(self: *Endpoint, role: crypto.Role, disable: bool) void {
        self.lockPump();
        defer self.unlockPump();
        if (self.testDriver(role)) |drv| drv.setDisablePeerStatelessResetForTest(disable);
    }

    /// Test hook: first live conn of `role` is draining on a peer stateless reset.
    pub fn isDrainingStatelessResetForTest(self: *Endpoint, role: crypto.Role) bool {
        self.lockPump();
        defer self.unlockPump();
        const drv = self.testDriver(role) orelse return false;
        return drv.isDrainingStatelessResetForTest();
    }

    /// Test hook: feed a raw datagram into the first live conn of `role` (raw datagram injection).
    /// Decrypt/malformed errors are swallowed (same as the production pump) so a
    /// crafted reset that does not match still exercises the detection path.
    pub fn injectDatagramForTest(self: *Endpoint, role: crypto.Role, datagram: []const u8) tr.Error!void {
        self.lockPump();
        defer self.unlockPump();
        const drv = self.testDriver(role) orelse return error.ConnectionLost;
        const now = self.clockNow();
        drv.handleDatagram(now, datagram) catch {};
        for (&self.conns) |*e| {
            if (e.used and e.role == role) self.drainEvents(e);
        }
    }

    fn canOfferZeroRttLocked(self: *Endpoint, peer: key.NodeId) bool {
        if (!crypto.zigtls_enabled) return false;
        if (!self.zeroRttOnZigtls()) return false;
        const cached = self.zigtls_cached_ticket orelse return false;
        if (!cached.peer.eql(peer)) return false;
        const ticket = cached.info.asResumptionTicket() orelse return false;
        return ticket.quic_0rtt_allowed;
    }

    pub fn canOfferZeroRtt(self: *Endpoint, peer: key.NodeId) bool {
        self.lockPump();
        defer self.unlockPump();
        return self.canOfferZeroRttLocked(peer);
    }

    pub fn hasZigtlsResumptionTicketForTest(self: *Endpoint, peer: key.NodeId) bool {
        self.lockPump();
        defer self.unlockPump();
        if (!crypto.zigtls_enabled or self.tls_backend != .zigtls) return false;
        const cached = self.zigtls_cached_ticket orelse return false;
        return cached.peer.eql(peer) and cached.info.asResumptionTicket() != null;
    }

    /// Test hook: aggregate hardening stats from the first live conn of `role`.
    pub const HardeningStats = struct {
        cc_limited: u64,
        loss_events: u64,
        retransmits: u64,
        peak_sent: u64,
        bytes_in_flight: u64,
    };

    pub fn testHardeningStats(self: *Endpoint, role: crypto.Role) ?HardeningStats {
        self.lockPump();
        defer self.unlockPump();
        const drv = self.testDriver(role) orelse return null;
        return .{
            .cc_limited = drv.stats_cc_limited,
            .loss_events = drv.stats_loss_events,
            .retransmits = drv.stats_retransmits,
            .peak_sent = drv.stats_peak_sent,
            .bytes_in_flight = drv.bytes_in_flight,
        };
    }

    /// Test hook: stream receive buffer occupancy (NEVER-DRAIN memory bound).
    pub fn testStreamRecvBuffered(self: *Endpoint, role: crypto.Role, stream_id: u64) ?usize {
        self.lockPump();
        defer self.unlockPump();
        const drv = self.testDriver(role) orelse return null;
        return drv.streamRecvBufferedLen(stream_id);
    }

    /// Test hook: has any server connection observed a peer CONNECTION_CLOSE?
    pub fn serverObservedClose(self: *const Endpoint) bool {
        const mutable_self: *Endpoint = @constCast(self);
        mutable_self.lockPump();
        defer mutable_self.unlockPump();
        for (mutable_self.conns) |e| {
            if (e.used and e.role == .server and e.lost) return true;
        }
        return false;
    }

    /// Gate B: server's local CID must be freshly chosen, not the client's
    /// original DCID retained as a local identity.
    pub fn serverUsesFreshLocalCid(self: *const Endpoint) bool {
        const mutable_self: *Endpoint = @constCast(self);
        mutable_self.lockPump();
        defer mutable_self.unlockPump();
        for (mutable_self.conns) |e| {
            if (e.used and e.role == .server) {
                return !std.mem.eql(u8, e.driver.local_cid.slice(), e.driver.initial_dcid.slice());
            }
        }
        return false;
    }

    /// Gate B: only a post-CertificateVerify key is observable on the server.
    pub fn serverHasVerifiedPeer(self: *const Endpoint) bool {
        const mutable_self: *Endpoint = @constCast(self);
        mutable_self.lockPump();
        defer mutable_self.unlockPump();
        for (mutable_self.conns) |e| {
            if (e.used and e.role == .server) {
                _ = e.driver.tls.peerPublicKey() catch continue;
                return true;
            }
        }
        return false;
    }

    /// Gate B negative-test hook: a server-side TLS failure was observed before
    /// any Connection could be accepted.
    pub fn serverHandshakeRejected(self: *const Endpoint) bool {
        const mutable_self: *Endpoint = @constCast(self);
        mutable_self.lockPump();
        defer mutable_self.unlockPump();
        for (mutable_self.conns) |e| {
            if (e.used and e.role == .server and e.rejected) return true;
        }
        return false;
    }

    fn firstLive(self: *Endpoint) ?*ConnEntry {
        for (&self.conns) |*e| {
            if (e.used) return e;
        }
        return null;
    }

    // ── 5e magicsock / path-validation / relay test hooks ────────────────────

    /// Advertise a direct-path candidate to the peer (n0 reach_out frame).
    pub fn advertiseReachOut(self: *Endpoint, seq: u64, ip: [4]u8, port: u16) void {
        self.lockPump();
        defer self.unlockPump();
        const e = self.firstLive() orelse return;
        e.driver.advertiseAddress(.{ .kind = .reach_out, .seq = seq, .ip = ip, .port = port });
    }

    /// How many remote candidates magicsock has learned on the live conn.
    pub fn magicCandidateCount(self: *Endpoint) usize {
        self.lockPump();
        defer self.unlockPump();
        const e = self.firstLive() orelse return 0;
        if (!e.magic_init) return 0;
        return e.magic.remote_candidates.items.len;
    }

    /// The magicsock-selected path address, or null if none is validated yet.
    /// Unvalidated (idle/active) candidates are NEVER selected.
    pub fn magicSelectedAddr(self: *Endpoint) ?net.IpAddress {
        self.lockPump();
        defer self.unlockPump();
        const e = self.firstLive() orelse return null;
        if (!e.magic_init) return null;
        const cand = e.magic.selectedPath() orelse return null;
        return cand.address;
    }

    /// Probe every idle candidate with a REAL PATH_CHALLENGE (random token). The
    /// candidate is only marked succeeded when the peer echoes the token back
    /// (handled in `drainEvents` on `.path_validated`).
    pub fn probeCandidates(self: *Endpoint) void {
        self.lockPump();
        defer self.unlockPump();
        const e = self.firstLive() orelse return;
        if (!e.magic_init) return;
        for (e.magic.remote_candidates.items) |cand| {
            if (cand.state != .idle) continue;
            var token: [8]u8 = undefined;
            self.io_inst.random(&token);
            e.driver.challengePath(token);
            if (e.probe_count < max_peer_streams) {
                e.probes[e.probe_count] = .{ .token = token, .addr = cand.address };
                e.probe_count += 1;
            }
            e.magic.markPathProbed(cand.address);
        }
    }

    /// Force a relay path: add + select a relay candidate and route this conn's
    /// outbound datagrams through the relay client (5e relay fallback).
    pub fn selectRelay(self: *Endpoint, seq: u64) void {
        self.lockPump();
        defer self.unlockPump();
        const e = self.firstLive() orelse return;
        if (!e.magic_init) return;
        e.magic.addRelayCandidate(seq) catch return;
        e.magic.selectRelayFallback();
        if (e.magic.selectedPath()) |cand| {
            e.relay_selected = cand.kind == .relay;
        }
    }

    pub fn setRelay(self: *Endpoint, relay: RelayClient) void {
        self.lockPump();
        defer self.unlockPump();
        self.relay = relay;
    }

    fn freeEntry(self: *Endpoint) ?*ConnEntry {
        for (&self.conns) |*e| {
            if (!e.used) return e;
        }
        return null;
    }

    fn entryForHandle(self: *Endpoint, handle: router_mod.ConnectionHandle) ?*ConnEntry {
        for (&self.conns) |*e| {
            if (e.used and e.handle.eql(handle)) return e;
        }
        return null;
    }

    fn entryByRemote(self: *Endpoint, remote: net.IpAddress) ?*ConnEntry {
        for (&self.conns) |*e| {
            if (e.used and ipEql(e.remote, remote)) return e;
        }
        return null;
    }

    fn routerLocal(self: *const Endpoint) router_mod.SocketAddress {
        return toSockAddr(self.local_address);
    }

    // ── socket send with ancillary data (ECN / GSO) ──────────────────────────

    /// Send one `Transmit` on the real socket, honoring its ECN codepoint and
    /// GSO segment size.
    ///
    /// GSO is *advisory*: `UDP_SEGMENT` is refused by some kernels, some
    /// interfaces, and any path where the resulting segments exceed the route
    /// MTU, all of which surface as `EIO`/`EINVAL`. Rust handles this by
    /// permanently dropping to `max_gso_segments = 1`
    /// (`noq-udp/src/unix.rs:431-445`); we do the same and then re-send the
    /// payload one datagram at a time, so a rejected batch is never lost — it
    /// is only sent less efficiently.
    /// True for an IPv4 destination OR an IPv4-mapped IPv6 destination
    /// (`unix.rs:607-609`). Such a destination is stamped with `IP_TOS`, not
    /// `IPV6_TCLASS` — the two live at different cmsg levels and a v4-mapped
    /// send rejected the v6 option on some kernels.
    fn isIp4Mapped(dest: *const net.IpAddress) bool {
        return switch (dest.*) {
            .ip4 => true,
            .ip6 => |a| ipv4FromMapped(a.bytes) != null,
        };
    }

    /// Extract the v4 octets from an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
    fn ipv4FromMapped(bytes: [16]u8) ?[4]u8 {
        if (bytes[0] != 0 or bytes[1] != 0 or bytes[2] != 0 or bytes[3] != 0 or
            bytes[4] != 0 or bytes[5] != 0 or bytes[6] != 0 or bytes[7] != 0 or
            bytes[8] != 0 or bytes[9] != 0) return null;
        if (bytes[10] != 0xff or bytes[11] != 0xff) return null;
        return bytes[12..16].*;
    }

    fn socketSend(self: *Endpoint, dest: *const net.IpAddress, tx: quic_conn.Transmit) tr.Error!void {
        const segment_size = tx.segment_size;
        const use_gso = self.gso_enabled and segment_size != null and
            segment_size.? > 0 and tx.bytes.len > segment_size.?;
        const is_ip4 = isIp4Mapped(dest);
        if (dest.* == .ip6 and ipv4FromMapped(dest.ip6.bytes) != null) self.stats_v4_mapped_sent += 1;

        var control_buf: [udp_cmsg.send_control_space]u8 = undefined;
        var enc = udp_cmsg.Encoder.init(&control_buf);
        // L11: once a kernel has rejected IP_TOS with EINVAL, omit the ECN cmsg
        // for the endpoint's lifetime (`sendmsg_einval`, `unix.rs:447-458`).
        const send_ecn = tx.ecn != null and !self.sendmsg_einval;
        if (send_ecn) {
            enc.pushEcn(is_ip4, tx.ecn.?) catch return error.ConnectionLost;
        }
        if (tx.src_ip) |src| {
            enc.pushSrcIp(src) catch return error.ConnectionLost;
        }
        if (use_gso) enc.pushSegmentSize(segment_size.?) catch return error.ConnectionLost;

        const control = enc.finish();
        if (control.len == 0) {
            self.socket.send(self.io_inst, dest, tx.bytes) catch |err| switch (err) {
                else => return error.ConnectionLost,
            };
            return;
        }

        udp_cmsg.rawSendmsg(self.socket.handle, dest, tx.bytes, control, use_gso) catch |err| switch (err) {
            // The batch was refused. Disable GSO for the endpoint's lifetime and
            // deliver the payload per-datagram so no bytes are dropped.
            error.GsoRejected => {
                self.gso_enabled = false;
                self.stats_gso_rejected += 1;
                return self.sendPerDatagram(dest, tx, segment_size.?, is_ip4);
            },
            // L11: the ECN cmsg was rejected with EINVAL (old kernel). Latch
            // `sendmsg_einval`, re-encode WITHOUT the ECN cmsg, and retry once
            // — the datagram goes out on the retry, never lost.
            error.Inval => {
                if (send_ecn) {
                    self.sendmsg_einval = true;
                    self.stats_send_einval_retry += 1;
                    return self.socketSend(dest, tx);
                }
                self.stats_send_transient += 1;
                return;
            },
            // L9: an MTU probe that exceeded the path MTU is expected loss —
            // swallow it and keep the connection alive (`unix.rs:212`).
            error.MsgSize => {
                self.stats_send_msgsize += 1;
                return;
            },
            // L10: a transient delivery failure is covered by retransmission.
            error.Transient => {
                self.stats_send_transient += 1;
                return;
            },
            error.SendFailed => return error.ConnectionLost,
        };

        if (send_ecn) self.stats_ecn_sent += 1;
        if (tx.src_ip != null) self.stats_src_ip_sent += 1;
        if (use_gso) {
            self.stats_gso_segmented_sends += 1;
            const segments = (tx.bytes.len + segment_size.? - 1) / segment_size.?;
            self.stats_gso_segments_sent += segments;
        }
    }

    /// GSO fallback: split a segmented payload and send each datagram alone,
    /// preserving the ECN codepoint and source address on every one.
    fn sendPerDatagram(
        self: *Endpoint,
        dest: *const net.IpAddress,
        tx: quic_conn.Transmit,
        segment_size: u16,
        is_ip4: bool,
    ) tr.Error!void {
        var offset: usize = 0;
        const send_ecn = tx.ecn != null and !self.sendmsg_einval;
        while (offset < tx.bytes.len) {
            const end = @min(offset + segment_size, tx.bytes.len);
            const chunk = tx.bytes[offset..end];
            if (send_ecn or tx.src_ip != null) {
                var control_buf: [udp_cmsg.send_control_space]u8 = undefined;
                var enc = udp_cmsg.Encoder.init(&control_buf);
                if (send_ecn) {
                    enc.pushEcn(is_ip4, tx.ecn.?) catch return error.ConnectionLost;
                }
                if (tx.src_ip) |src| {
                    enc.pushSrcIp(src) catch return error.ConnectionLost;
                }
                udp_cmsg.sendWithControl(self.socket.handle, dest, chunk, enc.finish(), false) catch |err| switch (err) {
                    error.MsgSize => self.stats_send_msgsize += 1,
                    error.Transient => self.stats_send_transient += 1,
                    else => return error.ConnectionLost,
                };
                if (send_ecn) self.stats_ecn_sent += 1;
                if (tx.src_ip != null) self.stats_src_ip_sent += 1;
            } else {
                self.socket.send(self.io_inst, dest, chunk) catch return error.ConnectionLost;
            }
            offset = end;
        }
    }

    /// Feed a received datagram's ECN codepoint (read off the REAL IP header)
    /// into the owning driver. No-op when the kernel reported no codepoint.
    fn ingestEcn(self: *Endpoint, entry: *ConnEntry, control: []const u8) void {
        if (!self.ecn_receive_enabled) return;
        const codepoint = udp_cmsg.decodeEcn(control) orelse return;
        switch (codepoint) {
            .ce => self.stats_ecn_recv_marked += 1,
            .ect0, .ect1 => self.stats_ecn_recv_ect += 1,
        }
        entry.driver.ingestReceivedEcn(codepoint);
    }

    // ── evidence accessors (structured, for the behavioral oracle) ───────────

    /// Segmented (multi-datagram) GSO `sendmsg` calls this endpoint completed.
    pub fn gsoSegmentedSendsForTest(self: *const Endpoint) u64 {
        return self.stats_gso_segmented_sends;
    }

    /// Datagrams emitted by segmented GSO sends.
    pub fn gsoSegmentsSentForTest(self: *const Endpoint) u64 {
        return self.stats_gso_segments_sent;
    }

    /// Times the kernel rejected a GSO send and we fell back per-datagram.
    pub fn gsoRejectedForTest(self: *const Endpoint) u64 {
        return self.stats_gso_rejected;
    }

    /// Whether this kernel accepted the `UDP_SEGMENT` capability probe.
    pub fn gsoEnabledForTest(self: *const Endpoint) bool {
        return self.gso_enabled;
    }

    /// Whether the kernel accepted `IP_RECVTOS`/`IPV6_RECVTCLASS`.
    pub fn ecnReceiveEnabledForTest(self: *const Endpoint) bool {
        return self.ecn_receive_enabled;
    }

    /// L7: receive coalescing depth (1 = off, 64 = UDP_GRO armed).
    pub fn groSegmentsForTest(self: *const Endpoint) usize {
        return self.gro_segments;
    }

    /// L7: datagrams that arrived GRO-coalesced (len > stride).
    pub fn groCoalescedRecvForTest(self: *const Endpoint) u64 {
        return self.stats_gro_coalesced_recv;
    }

    /// L8: whether the IP layer may fragment (false once PMTUDISC_PROBE took).
    pub fn mayFragmentForTest(self: *const Endpoint) bool {
        return self.may_fragment;
    }

    /// L13: whether pktinfo (destination-address) receive metadata is armed.
    pub fn pktinfoReceiveEnabledForTest(self: *const Endpoint) bool {
        return self.pktinfo_receive_enabled;
    }

    /// L15: whether kernel receive timestamps are armed.
    pub fn timestampReceiveEnabledForTest(self: *const Endpoint) bool {
        return self.timestamp_receive_enabled;
    }

    /// L9: sends swallowed as expected MTU-probe loss (EMSGSIZE).
    pub fn sendMsgsizeForTest(self: *const Endpoint) u64 {
        return self.stats_send_msgsize;
    }

    /// L10: sends swallowed as transient delivery failures.
    pub fn sendTransientForTest(self: *const Endpoint) u64 {
        return self.stats_send_transient;
    }

    /// L12: sends that pinned a source address via pktinfo.
    pub fn srcIpSentForTest(self: *const Endpoint) u64 {
        return self.stats_src_ip_sent;
    }

    /// L14: sends to a v4-mapped destination on a v6 socket.
    pub fn v4MappedSentForTest(self: *const Endpoint) u64 {
        return self.stats_v4_mapped_sent;
    }

    /// L11: sends retried without the ECN cmsg after an EINVAL.
    pub fn sendEinvalRetryForTest(self: *const Endpoint) u64 {
        return self.stats_send_einval_retry;
    }

    /// L11: whether the old-kernel IP_TOS EINVAL latch is set.
    pub fn sendmsgEinvalForTest(self: *const Endpoint) bool {
        return self.sendmsg_einval;
    }

    /// Datagrams sent with an ECN codepoint stamped on the IP header.
    pub fn ecnSentForTest(self: *const Endpoint) u64 {
        return self.stats_ecn_sent;
    }

    /// Datagrams received with a CE codepoint in a REAL IP header.
    pub fn ecnRecvMarkedForTest(self: *const Endpoint) u64 {
        return self.stats_ecn_recv_marked;
    }

    /// Datagrams received with any ECT codepoint in a real IP header.
    pub fn ecnRecvEctForTest(self: *const Endpoint) u64 {
        return self.stats_ecn_recv_ect;
    }

    /// Establish a client connection COOPERATIVELY: mint the connection and
    /// start the handshake, but do NOT block driving it to completion.
    ///
    /// `Transport.connect` blocks until connected, which deadlocks a
    /// single-threaded caller that owns both endpoints (the server never gets
    /// pumped). The oracle's real-socket legs need both endpoints in one
    /// thread, so they start here and then alternate `pumpForTest` calls.
    /// Everything after minting is the ordinary production path.
    pub fn connectCooperativeForTest(self: *Endpoint, peer: key.NodeId, ip: net.IpAddress) tr.Error!void {
        self.lockPump();
        defer self.unlockPump();
        var cid_bytes: [local_cid_len]u8 = undefined;
        self.io_inst.random(&cid_bytes);
        const scid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
        self.io_inst.random(&cid_bytes);
        const initial_dcid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
        var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        self.io_inst.random(&seed_bytes);
        const sni = tls_name.serverName(peer);

        // E8: present a cached NEW_TOKEN in the first Initial (one-time use —
        // the take already removed it from the cache, per noq TokenStore).
        const stored_token = self.takeStoredToken(&sni);
        defer if (stored_token.len != 0) self.allocator.free(@constCast(stored_token));

        const drv = quic_conn.Connection.create(self.allocator, .{
            .backend = self.tls_backend,
            .role = .client,
            .secret_key = self.secret,
            .peer_public_key = peer,
            .certificate_public_key = self.certificate_public_key_override,
            .certificate_der_override = self.certificate_der_override,
            .alpn = if (self.server_alpns.items.len > 0) self.server_alpns.items[0] else self.alpn,
            .server_name = &sni,
            .zigtls_resumption_ticket = if (crypto.zigtls_enabled) self.cachedZigtlsResumptionTicket(peer) else null,
            .zigtls_enable_early_data = self.zeroRttOnZigtls(),
            .zigtls_replay_filter = if (crypto.zigtls_enabled) &self.zigtls_replay_filter else null,
        }, scid, initial_dcid, initial_dcid, seed_bytes, .{
            .initial_token = stored_token,
            .reset_key = &self.reset_key,
            .congestion_kind = self.congestion_kind,
        }) catch return error.ConnectionLost;
        // G18: iroh keeps every connection alive at its heartbeat interval
        // (endpoint/quic.rs:156 keep_alive_interval(HEARTBEAT_INTERVAL)).
        drv.setKeepAliveIntervalNs(quic_conn.default_keep_alive_interval_ns);

        const handle = self.router.addConnection(.{
            .init_cid = scid,
            .side = .client,
            .local_cids = &.{scid},
            .initial_cids = &.{scid},
        }) catch {
            drv.destroy();
            return error.ConnectionLost;
        };

        const entry = self.freeEntry() orelse {
            self.router.removeConnection(handle) catch {};
            drv.destroy();
            return error.OutOfMemory;
        };
        entry.* = .{
            .used = true,
            .driver = drv,
            .handle = handle,
            .remote = ip,
            .role = .client,
            .remote_node = peer,
            .remote_node_set = true,
        };
        entry.magic = magicsock.State.init(self.allocator);
        entry.magic_init = true;

        drv.startClient() catch {
            self.reclaim(entry);
            return error.ConnectionLost;
        };
    }

    /// 0-RTT client connect (the noq `Connecting::into_0rtt` analogue): mint a
    /// client connection with a cached 0-RTT-capable resumption ticket and return
    /// it the moment the 0-RTT OFFER is live (early write keys installed) —
    /// BEFORE the handshake completes — so the caller can open streams and write
    /// real early bytes. Returns null before allocation when no offer is possible
    /// (no cached 0-RTT-capable ticket / wrong backend / early data disabled).
    pub fn connectZeroRtt(self: *Endpoint, peer: key.NodeId, ip: net.IpAddress) tr.Error!?tr.Connection {
        return self.connectZeroRttForTest(peer, ip);
    }

    /// Compatibility alias for `connectZeroRtt` (kept for existing tests).
    pub fn connectZeroRttForTest(self: *Endpoint, peer: key.NodeId, ip: net.IpAddress) tr.Error!?tr.Connection {
        self.lockPump();
        defer self.unlockPump();
        if (!self.canOfferZeroRttLocked(peer)) return null;

        var cid_bytes: [local_cid_len]u8 = undefined;
        self.io_inst.random(&cid_bytes);
        const scid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
        self.io_inst.random(&cid_bytes);
        const initial_dcid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
        var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        self.io_inst.random(&seed_bytes);
        const sni = tls_name.serverName(peer);

        const stored_token = self.takeStoredToken(&sni);
        defer if (stored_token.len != 0) self.allocator.free(@constCast(stored_token));

        const drv = quic_conn.Connection.create(self.allocator, .{
            .backend = self.tls_backend,
            .role = .client,
            .secret_key = self.secret,
            .peer_public_key = peer,
            .certificate_public_key = self.certificate_public_key_override,
            .certificate_der_override = self.certificate_der_override,
            .alpn = if (self.server_alpns.items.len > 0) self.server_alpns.items[0] else self.alpn,
            .server_name = &sni,
            .zigtls_resumption_ticket = if (crypto.zigtls_enabled) self.cachedZigtlsResumptionTicket(peer) else null,
            .zigtls_enable_early_data = self.zeroRttOnZigtls(),
            .zigtls_replay_filter = if (crypto.zigtls_enabled) &self.zigtls_replay_filter else null,
        }, scid, initial_dcid, initial_dcid, seed_bytes, .{
            .initial_token = stored_token,
            .reset_key = &self.reset_key,
            .congestion_kind = self.congestion_kind,
        }) catch return error.ConnectionLost;
        drv.setKeepAliveIntervalNs(quic_conn.default_keep_alive_interval_ns);

        const handle = self.router.addConnection(.{
            .init_cid = scid,
            .side = .client,
            .local_cids = &.{scid},
            .initial_cids = &.{scid},
        }) catch {
            drv.destroy();
            return error.ConnectionLost;
        };

        const entry = self.freeEntry() orelse {
            self.router.removeConnection(handle) catch {};
            drv.destroy();
            return error.OutOfMemory;
        };
        entry.* = .{
            .used = true,
            .driver = drv,
            .handle = handle,
            .remote = ip,
            .role = .client,
            .remote_node = peer,
            .remote_node_set = true,
        };
        entry.magic = magicsock.State.init(self.allocator);
        entry.magic_init = true;

        drv.startClient() catch {
            self.reclaim(entry);
            return error.ConnectionLost;
        };
        // A resumption that offers 0-RTT installs the early write keys while
        // the ClientHello is built — no round trip needed. If the lower layer
        // unexpectedly declines the offer after allocation, reclaim the entry
        // before surfacing null so the caller's fallback cannot leak or double-
        // own this connection slot.
        if (!drv.zeroRttSendActive()) {
            self.reclaim(entry);
            return null;
        }
        const impl = self.allocator.create(ConnectionImpl) catch {
            self.reclaim(entry);
            return error.OutOfMemory;
        };
        impl.* = .{ .endpoint = self, .entry = entry, .remote = peer };
        return wrapConn(impl);
    }

    /// Deep-copy the cached zigtls resumption ticket for `peer` into
    /// caller-owned memory, so a test can pin ONE ticket identity and present
    /// it to multiple connections (the anti-replay negative) without the
    /// client's re-caching swapping it out mid-test. Caller frees the slices.
    pub fn dupCachedResumptionTicketForTest(self: *Endpoint, alloc: std.mem.Allocator, peer: key.NodeId) !?crypto.ZigtlsResumptionTicket {
        self.lockPump();
        defer self.unlockPump();
        if (!crypto.zigtls_enabled) return null;
        if (self.tls_backend != .zigtls) return null;
        const cached = self.zigtls_cached_ticket orelse return null;
        if (!cached.peer.eql(peer)) return null;
        const src = cached.info.asResumptionTicket() orelse return null;
        var out: crypto.ZigtlsResumptionTicket = src;
        out.ticket_nonce = try alloc.dupe(u8, src.ticket_nonce);
        errdefer alloc.free(out.ticket_nonce);
        out.ticket = try alloc.dupe(u8, src.ticket);
        errdefer alloc.free(out.ticket);
        out.server_name = if (src.server_name) |s| try alloc.dupe(u8, s) else null;
        errdefer if (out.server_name) |s| alloc.free(s);
        out.alpn_protocol = if (src.alpn_protocol) |a| try alloc.dupe(u8, a) else null;
        errdefer if (out.alpn_protocol) |a| alloc.free(a);
        out.quic_transport_parameters = if (src.quic_transport_parameters) |t| try alloc.dupe(u8, t) else null;
        return out;
    }

    /// Free a ticket produced by dupCachedResumptionTicketForTest.
    pub fn freeDupResumptionTicket(alloc: std.mem.Allocator, ticket: crypto.ZigtlsResumptionTicket) void {
        alloc.free(ticket.ticket_nonce);
        alloc.free(ticket.ticket);
        if (ticket.server_name) |s| alloc.free(s);
        if (ticket.alpn_protocol) |a| alloc.free(a);
        if (ticket.quic_transport_parameters) |t| alloc.free(t);
    }

    /// 0-RTT client connect with an EXPLICIT resumption ticket (like
    /// connectZeroRttForTest, but not reading the endpoint cache). Lets a test
    /// present the SAME ticket identity to two connections for the anti-replay
    /// negative.
    pub fn connectZeroRttWithTicketForTest(self: *Endpoint, peer: key.NodeId, ip: net.IpAddress, ticket: crypto.ZigtlsResumptionTicket) tr.Error!?tr.Connection {
        self.lockPump();
        defer self.unlockPump();
        if (!self.zeroRttOnZigtls() or !ticket.quic_0rtt_allowed) return null;

        var cid_bytes: [local_cid_len]u8 = undefined;
        self.io_inst.random(&cid_bytes);
        const scid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
        self.io_inst.random(&cid_bytes);
        const initial_dcid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
        var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        self.io_inst.random(&seed_bytes);
        const sni = tls_name.serverName(peer);

        const stored_token = self.takeStoredToken(&sni);
        defer if (stored_token.len != 0) self.allocator.free(@constCast(stored_token));

        const drv = quic_conn.Connection.create(self.allocator, .{
            .backend = self.tls_backend,
            .role = .client,
            .secret_key = self.secret,
            .peer_public_key = peer,
            .certificate_public_key = self.certificate_public_key_override,
            .certificate_der_override = self.certificate_der_override,
            .alpn = if (self.server_alpns.items.len > 0) self.server_alpns.items[0] else self.alpn,
            .server_name = &sni,
            .zigtls_resumption_ticket = ticket,
            .zigtls_enable_early_data = self.zeroRttOnZigtls(),
            .zigtls_replay_filter = if (crypto.zigtls_enabled) &self.zigtls_replay_filter else null,
        }, scid, initial_dcid, initial_dcid, seed_bytes, .{
            .initial_token = stored_token,
            .reset_key = &self.reset_key,
            .congestion_kind = self.congestion_kind,
        }) catch return error.ConnectionLost;
        drv.setKeepAliveIntervalNs(quic_conn.default_keep_alive_interval_ns);

        const handle = self.router.addConnection(.{
            .init_cid = scid,
            .side = .client,
            .local_cids = &.{scid},
            .initial_cids = &.{scid},
        }) catch {
            drv.destroy();
            return error.ConnectionLost;
        };

        const entry = self.freeEntry() orelse {
            self.router.removeConnection(handle) catch {};
            drv.destroy();
            return error.OutOfMemory;
        };
        entry.* = .{
            .used = true,
            .driver = drv,
            .handle = handle,
            .remote = ip,
            .role = .client,
            .remote_node = peer,
            .remote_node_set = true,
        };
        entry.magic = magicsock.State.init(self.allocator);
        entry.magic_init = true;

        drv.startClient() catch {
            self.reclaim(entry);
            return error.ConnectionLost;
        };
        if (!drv.zeroRttSendActive()) {
            self.reclaim(entry);
            return null;
        }
        const impl = self.allocator.create(ConnectionImpl) catch {
            self.reclaim(entry);
            return error.OutOfMemory;
        };
        impl.* = .{ .endpoint = self, .entry = entry, .remote = peer };
        return wrapConn(impl);
    }

    /// 0-RTT early accept (the noq `Connecting::into_0rtt` accept side): hand
    /// off a server connection the moment the driver ACCEPTS 0-RTT (early read
    /// keys installed at ClientHello time), before the handshake completes, so
    /// the handler can read early bytes. Mirrors tryAcceptReady otherwise.
    pub fn tryAcceptReadyZeroRtt(self: *Endpoint) tr.Error!?tr.Connection {
        self.lockPump();
        defer self.unlockPump();
        try self.pollOnceLocked();
        for (&self.conns) |*e| {
            if (e.used and e.role == .server and e.driver.zeroRttAcceptedServer() and !e.handed_off) {
                e.handed_off = true;
                _ = try self.pumpOutgoing();
                const remote_node = e.driver.tls.peerPublicKey() catch return error.ConnectionLost;
                e.remote_node = remote_node;
                e.remote_node_set = true;
                const impl = self.allocator.create(ConnectionImpl) catch return error.OutOfMemory;
                impl.* = .{ .endpoint = self, .entry = e, .remote = remote_node };
                impl.snapshotAlpn(e);
                return wrapConn(impl);
            }
            if (e.used and e.role == .server and e.lost and !e.handed_off) {
                self.reclaimLost(e);
            }
        }
        return null;
    }

    /// Compatibility alias for `tryAcceptReadyZeroRtt` (kept for existing tests).
    pub fn tryAcceptReadyZeroRttForTest(self: *Endpoint) tr.Error!?tr.Connection {
        return self.tryAcceptReadyZeroRtt();
    }

    /// Drive a handed-off connection until the full handshake completes (or is
    /// lost). Used by `Accepting.complete` when a handler opts out of early
    /// 0-RTT use and wants the established connection.
    pub fn waitEstablished(conn: tr.Connection) tr.Error!void {
        const impl: *ConnectionImpl = if (comptime product_flags.is_mono_noq) conn.impl else @ptrCast(@alignCast(conn.context));
        var polls: usize = 0;
        while (polls < 30_000) : (polls += 1) {
            {
                impl.endpoint.lockPump();
                defer impl.endpoint.unlockPump();

                if (!impl.entry.used or impl.entry.lost) return error.ConnectionLost;
                if (impl.entry.connected) {
                    impl.snapshotAlpn(impl.entry);
                    return;
                }
                try impl.endpoint.pollOnceLocked();
                if (!impl.entry.used or impl.entry.lost) return error.ConnectionLost;
                if (impl.entry.connected) {
                    impl.snapshotAlpn(impl.entry);
                    return;
                }
            }
            impl.endpoint.io_inst.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
        }
        return error.ConnectionLost;
    }

    pub fn connectionIsEarlyZeroRtt(conn: tr.Connection) bool {
        const impl: *ConnectionImpl = if (comptime product_flags.is_mono_noq) conn.impl else @ptrCast(@alignCast(conn.context));
        impl.endpoint.lockPump();
        defer impl.endpoint.unlockPump();
        if (!impl.entry.used or impl.entry.lost) return false;
        return impl.entry.driver.zeroRttAcceptedServer() and !impl.entry.connected;
    }

    /// Test hook: make the first live conn of `role` stamp `codepoint` on its
    /// outgoing 1-RTT data instead of ECT(0). Loopback has no router to apply
    /// CE, so this is how a CE mark is put on the wire; it still traverses a
    /// real IP header and is still decoded from a real cmsg by the receiver.
    pub fn setEcnOverrideForTest(self: *Endpoint, role: crypto.Role, codepoint: ?udp_cmsg.EcnCodepoint) void {
        self.lockPump();
        defer self.unlockPump();
        if (self.testDriver(role)) |drv| drv.setEcnOverrideForTest(codepoint);
    }

    /// Send a raw payload on this endpoint's socket with an explicit ECN
    /// codepoint and optional GSO segment size. This exercises the SAME
    /// `socketSend` production path the pump uses; the oracle's real-socket legs
    /// use it to prove kernel behaviour without needing a full QUIC exchange.
    pub fn sendRawForTest(
        self: *Endpoint,
        dest: net.IpAddress,
        bytes: []u8,
        ecn: ?udp_cmsg.EcnCodepoint,
        segment_size: ?u16,
    ) tr.Error!void {
        var addr = dest;
        return self.socketSend(&addr, .{ .bytes = bytes, .ecn = ecn, .segment_size = segment_size });
    }

    /// L12: drive the production send path with a pinned source address
    /// (`IP_PKTINFO`/`IPV6_PKTINFO`).
    pub fn sendRawSrcIpForTest(
        self: *Endpoint,
        dest: net.IpAddress,
        src_ip: net.IpAddress,
        bytes: []u8,
    ) tr.Error!void {
        var addr = dest;
        return self.socketSend(&addr, .{ .bytes = bytes, .src_ip = src_ip });
    }

    /// Receive datagrams directly off this endpoint's socket, reporting the ECN
    /// codepoint the kernel decoded from each real IP header. Returns the number
    /// of datagrams received; `error.Timeout` if none arrived in time.
    pub fn receiveRawForTest(
        self: *Endpoint,
        payloads: [][]const u8,
        codepoints: []?udp_cmsg.EcnCodepoint,
        timeout_ns: i64,
        /// Caller-owned scratch: the returned `payloads` point INTO it, so it
        /// must outlive the caller's use of them.
        scratch: *RawReceiveScratch,
    ) !usize {
        std.debug.assert(payloads.len == codepoints.len);
        scratch.init();
        const timeout: std.Io.Timeout = .{
            .duration = .{ .raw = .fromNanoseconds(timeout_ns), .clock = .awake },
        };
        const gro = self.gro_segments > 1;
        const msgs, const data = scratch.receiveArgs(gro);
        const maybe_err, const count = self.socket.receiveManyTimeout(
            self.io_inst,
            msgs,
            data,
            .{},
            timeout,
        );
        if (maybe_err) |err| return err;
        var n: usize = 0;
        for (scratch.messages[0..count]) |msg| {
            if (n >= payloads.len) break;
            // L7: decode the GRO stride. A real coalesced datagram (len >
            // stride) is split into its segments here so callers observe
            // per-segment lengths and the stride is exercised on a real socket.
            const meta = udp_cmsg.decodeRecvMeta(msg.control);
            if (meta.stride) |s| {
                if (s > 0 and s < msg.data.len) self.stats_gro_coalesced_recv += 1;
            }
            const stride = if (meta.stride) |s| (if (s == 0) msg.data.len else s) else msg.data.len;
            var off: usize = 0;
            while (off < msg.data.len and n < payloads.len) : (off += stride) {
                payloads[n] = msg.data[off..@min(off + stride, msg.data.len)];
                codepoints[n] = udp_cmsg.decodeEcn(msg.control);
                if (codepoints[n]) |cp| switch (cp) {
                    .ce => self.stats_ecn_recv_marked += 1,
                    .ect0, .ect1 => self.stats_ecn_recv_ect += 1,
                };
                n += 1;
            }
        }
        return n;
    }

    /// L13/L15/L7: receive raw datagrams and report the full receive metadata
    /// (dst_ip, kernel timestamp, GRO stride) decoded off each real control
    /// buffer. One result per received message (NOT split by stride — metadata
    /// is per-message, and the L7 gate wants the coalesced length + stride).
    pub fn receiveRawMetaForTest(
        self: *Endpoint,
        payloads: [][]const u8,
        metas: []udp_cmsg.RecvMeta,
        timeout_ns: i64,
        scratch: *RawReceiveScratch,
    ) !usize {
        std.debug.assert(payloads.len == metas.len);
        scratch.init();
        const timeout: std.Io.Timeout = .{
            .duration = .{ .raw = .fromNanoseconds(timeout_ns), .clock = .awake },
        };
        const gro = self.gro_segments > 1;
        const msgs, const data = scratch.receiveArgs(gro);
        const maybe_err, const count = self.socket.receiveManyTimeout(
            self.io_inst,
            msgs,
            data,
            .{},
            timeout,
        );
        if (maybe_err) |err| return err;
        const n = @min(count, payloads.len);
        for (msgs[0..n], 0..) |msg, i| {
            payloads[i] = msg.data;
            metas[i] = udp_cmsg.decodeRecvMeta(msg.control);
        }
        return n;
    }

    pub const RawReceiveOneResult = struct {
        len: usize,
        flags: net.IncomingMessage.Flags,
    };

    pub fn receiveOneRawForTest(
        self: *Endpoint,
        buffer: []u8,
        control: []u8,
        timeout_ns: i64,
    ) !RawReceiveOneResult {
        var messages = [_]net.IncomingMessage{.init};
        messages[0].control = control;
        const timeout: std.Io.Timeout = .{
            .duration = .{ .raw = .fromNanoseconds(timeout_ns), .clock = .awake },
        };
        const maybe_err, const count = self.socket.receiveManyTimeout(
            self.io_inst,
            &messages,
            buffer,
            .{},
            timeout,
        );
        if (maybe_err) |err| return err;
        if (count != 1) return error.TestUnexpectedResult;
        return .{ .len = messages[0].data.len, .flags = messages[0].flags };
    }

    /// L17: receive ONE datagram into a caller-sized buffer and report the
    /// delivered length alongside the kernel's MSG_TRUNC flag. The
    /// production per-message ceiling is `max_datagram`, so a legal datagram
    /// never truncates there; this hook makes the truncation path itself
    /// exercisable — an oversized datagram into an undersized buffer MUST
    /// surface MSG_TRUNC rather than silently truncate.
    pub fn receiveTruncForTest(
        self: *Endpoint,
        buf: []u8,
        timeout_ns: i64,
    ) !struct { len: usize, trunc: bool } {
        var msg: net.IncomingMessage = .init;
        msg.control = &.{};
        const timeout: std.Io.Timeout = .{
            .duration = .{ .raw = .fromNanoseconds(timeout_ns), .clock = .awake },
        };
        const maybe_err, const count = self.socket.receiveManyTimeout(
            self.io_inst,
            (&msg)[0..1],
            buf,
            .{},
            timeout,
        );
        if (maybe_err) |err| return err;
        if (count == 0) return error.Timeout;
        return .{ .len = msg.data.len, .trunc = msg.flags.trunc };
    }

    // ── the UDP pump (design §2.2) ───────────────────────────────────────────

    /// Drive the NAT probe retry scheduler for this conn (noq
    /// NatTraversalProbeRetry): queued probes emit with per-candidate
    /// destination hints; on the retry deadline the next backoff round queues.
    fn driveNatRetries(self: *Endpoint, e: *ConnEntry, now: i64) void {
        if (!e.magic_init) return;
        while (e.magic.nextQueuedProbe()) |cand| {
            if (e.probe_count >= max_peer_streams) break;
            var token: [8]u8 = undefined;
            self.io_inst.random(&token);
            e.driver.challengePathTo(token, 2 + @as(u64, @intCast(e.probe_count)));
            e.probes[e.probe_count] = .{ .token = token, .addr = cand.address };
            e.probe_count += 1;
            e.magic.noteProbeSent(cand.address);
        }
        if (e.magic.retryDelay()) |delay_us| {
            if (e.next_nat_retry_ns == null) {
                e.next_nat_retry_ns = now + @as(i64, @intCast(delay_us)) * std.time.ns_per_us;
            } else if (now >= e.next_nat_retry_ns.?) {
                e.magic.queueRetries();
                // Retire the previous round's probe tokens so the fixed table
                // can't saturate across retries (cumulative-cap regression).
                e.probe_count = 0;
                e.next_nat_retry_ns = null;
            }
        } else {
            e.next_nat_retry_ns = null;
        }
    }

    fn pumpOutgoing(self: *Endpoint) tr.Error!bool {
        var sent = false;
        // `.{}` compiles to a memset of the whole staging buffer on every
        // call; `undefined` + `reset()` initializes only the bookkeeping.
        var batch: OutgoingBatch = undefined;
        batch.reset();
        const now = self.clockNow();
        for (&self.conns) |*e| {
            if (!e.used) continue;
            self.driveNatRetries(e, now);
            self.drainEvents(e);
            while (e.driver.pollTransmit(now) catch return error.ConnectionLost) |tx| {
                // `pollTransmit` commits a queued NEW_CONNECTION_ID to the
                // driver's local inventory. Register it before the datagram is
                // published so a peer can rotate immediately without racing
                // the router update.
                while (e.driver.localConnectionId(e.registered_local_cids)) |cid| {
                    self.router.registerLocalCid(e.handle, cid) catch return error.ConnectionLost;
                    e.registered_local_cids += 1;
                }
                self.test_tx_count += 1;
                const drop = if (self.test_drop) |f| f(self.test_tx_count) else false;
                if (!drop) {
                    var tx_out = tx;
                    var mutated_storage: [max_datagram]u8 = undefined;
                    if (self.test_mutate) |mutate| {
                        if (tx.bytes.len <= mutated_storage.len and tx.segment_size == null) {
                            @memcpy(mutated_storage[0..tx.bytes.len], tx.bytes);
                            mutate(self.test_tx_count, mutated_storage[0..tx.bytes.len]);
                            tx_out.bytes = mutated_storage[0..tx.bytes.len];
                        }
                    }
                    // A hinted probe goes to its mapped address (the
                    // migration candidate or the probe's candidate address);
                    // everything else rides the current path.
                    const hint = tx_out.dest_hint orelse 0;
                    const tx_dest = if (hint == migration_dest_hint and e.migration_pending)
                        e.migration_candidate
                    else if (hint >= 2 and hint - 2 < e.probe_count)
                        e.probes[hint - 2].addr
                    else
                        e.remote;
                    if (e.relay_selected and self.relay != null and e.remote_node_set) {
                        // magicsock selected a relay path → route via the relay
                        // client. Flush first so relay and socket datagrams
                        // cannot be reordered relative to each other.
                        try self.flushBatch(&batch);
                        self.relay.?.send(e.remote_node, tx_out.bytes) catch return error.ConnectionLost;
                    } else if (self.gso_enabled and tx_out.segment_size == null) {
                        // Coalesce into the pending GSO batch when possible;
                        // otherwise flush what is staged and start fresh.
                        if (!batch.accepts(tx_dest, tx_out.ecn, tx_out.bytes.len)) {
                            try self.flushBatch(&batch);
                        }
                        batch.push(tx_dest, tx_out.ecn, tx_out.bytes);
                    } else {
                        try self.flushBatch(&batch);
                        try self.socketSend(&tx_dest, tx_out);
                    }
                }
                sent = true;
            }
        }
        // B7: drive drain-window entries the same way (close re-draws after
        // stragglers), and tear down any whose 3×PTO window has elapsed.
        for (&self.drains) |*d| {
            if (!d.used) continue;
            while (d.driver.pollTransmit(now) catch return error.ConnectionLost) |tx| {
                self.test_tx_count += 1;
                const drop = if (self.test_drop) |f| f(self.test_tx_count) else false;
                if (!drop) {
                    var tx_out = tx;
                    var mutated_storage: [max_datagram]u8 = undefined;
                    if (self.test_mutate) |mutate| {
                        if (tx.bytes.len <= mutated_storage.len and tx.segment_size == null) {
                            @memcpy(mutated_storage[0..tx.bytes.len], tx.bytes);
                            mutate(self.test_tx_count, mutated_storage[0..tx.bytes.len]);
                            tx_out.bytes = mutated_storage[0..tx.bytes.len];
                        }
                    }
                    if (d.relay_selected and self.relay != null and d.remote_node_set) {
                        try self.flushBatch(&batch);
                        self.relay.?.send(d.remote_node, tx_out.bytes) catch return error.ConnectionLost;
                    } else if (self.gso_enabled and tx_out.segment_size == null) {
                        if (!batch.accepts(d.remote, tx_out.ecn, tx_out.bytes.len)) {
                            try self.flushBatch(&batch);
                        }
                        batch.push(d.remote, tx_out.ecn, tx_out.bytes);
                    } else {
                        try self.flushBatch(&batch);
                        try self.socketSend(&d.remote, tx_out);
                    }
                }
                sent = true;
            }
            if (d.used and d.driver.isDrained()) self.reclaimDrain(d);
        }
        try self.flushBatch(&batch);
        return sent;
    }

    /// Emit a staged batch. A single datagram goes out as a plain send (no
    /// `UDP_SEGMENT` cmsg — one segment is not a batch); two or more go out as
    /// one GSO `sendmsg`.
    fn flushBatch(self: *Endpoint, batch: *OutgoingBatch) tr.Error!void {
        if (batch.isEmpty()) return;
        defer batch.reset();
        const dest = batch.dest.?;
        const tx: quic_conn.Transmit = .{
            .bytes = batch.bytes[0..batch.len],
            .ecn = batch.ecn,
            .segment_size = if (batch.count > 1) batch.segment_size else null,
        };
        var addr = dest;
        try self.socketSend(&addr, tx);
    }

    /// Drain relay-delivered datagrams and feed them into the owning driver
    /// (the S4 relay-fallback ingress; mirrors `pumpRelayIncoming` on picoquic).
    ///
    /// First-flight Initials over relay MUST mint a server connection (NodeId-only
    /// accept). The prior implementation only delivered to already-known peers,
    /// which silently dropped the client's Initial and made EndpointId-only
    /// connect through a home relay time out forever.
    fn pumpRelayIncoming(self: *Endpoint) tr.Error!bool {
        const relay = self.relay orelse return false;
        var progressed = false;
        while (true) {
            var buf: [max_datagram]u8 = undefined;
            const dg = (relay.recv(&buf) catch return error.ConnectionLost) orelse break;

            var entry: ?*ConnEntry = null;
            for (&self.conns) |*e| {
                if (e.used and e.remote_node_set and e.remote_node.eql(dg.src)) {
                    entry = e;
                    break;
                }
            }

            if (entry == null and dg.data.len > 0) {
                // Synthetic path address shared by all relay-only peers (same
                // as legacy quic.Endpoint). Concurrent multi-client demux is
                // by NodeId once bound; first-flight mint uses this address.
                const from = magicsock.relayAddress();
                const four: router_mod.FourTuple = .{
                    .local = self.routerLocal(),
                    .remote = toSockAddr(from),
                };
                if (try self.route(four, dg.data, from)) |e| {
                    // DERP envelope carries the peer NodeId before TLS finishes.
                    e.remote_node = dg.src;
                    e.remote_node_set = true;
                    if (e.magic_init) {
                        e.magic.addRelayCandidate(0) catch {};
                        e.magic.selectRelayFallback();
                        e.relay_selected = true;
                    }
                    entry = e;
                }
            }

            if (entry) |e| {
                e.driver.handleDatagram(self.clockNow(), dg.data) catch |err| switch (err) {
                    error.PicotlsError => {
                        e.rejected = true;
                        e.lost = true;
                        // Same reject-cycle close flush as the direct-path
                        // branch in ingestDatagram: a relayed peer must also
                        // observe the CRYPTO_ERROR close, not silence.
                        _ = try self.pumpOutgoing();
                    },
                    else => {},
                };
                self.drainEvents(e);
            }
            progressed = true;
        }
        return progressed;
    }

    fn receiveTimeout(self: *Endpoint, progressed: bool) std.Io.Timeout {
        if (progressed) return drain_timeout;
        const now = self.clockNow();
        var wait_ns: i64 = std.time.ns_per_ms;
        for (&self.conns) |*entry| {
            if (!entry.used) continue;
            if (entry.driver.pollTimeout()) |deadline| {
                if (deadline <= now) return drain_timeout;
                wait_ns = @min(wait_ns, deadline - now);
            }
            // The NAT retry deadline participates in the pump wait.
            if (entry.next_nat_retry_ns) |deadline| {
                if (deadline <= now) return drain_timeout;
                wait_ns = @min(wait_ns, deadline - now);
            }
        }
        // B7: wake for a drain entry's close_deadline so its reclaim is not
        // starved when nothing else drives the pump.
        for (&self.drains) |*d| {
            if (!d.used) continue;
            if (d.driver.pollTimeout()) |deadline| {
                if (deadline <= now) return drain_timeout;
                wait_ns = @min(wait_ns, deadline - now);
            }
        }
        return .{ .duration = .{ .raw = .fromNanoseconds(wait_ns), .clock = .awake } };
    }

    fn pumpIncomingAfter(self: *Endpoint, prior_progress: bool) tr.Error!bool {
        var progressed = prior_progress;
        if (try self.pumpRelayIncoming()) progressed = true;
        // The GRO receive buffer is up to ~4 MiB; it is the heap-backed
        // `recv_scratch.data` owned by this endpoint, never the pump's stack.
        const batch = &self.recv_scratch;
        const gro = self.gro_segments > 1;
        while (true) {
            batch.init();
            const timeout = self.receiveTimeout(progressed);
            const msgs, const data = batch.receiveArgs(gro);
            const maybe_err, const count = self.socket.receiveManyTimeout(
                self.io_inst,
                msgs,
                data,
                .{},
                timeout,
            );
            if (maybe_err) |err| switch (err) {
                error.Timeout => break,
                else => return error.ConnectionLost,
            };
            if (count == 0) break;
            for (batch.messages[0..count]) |msg| {
                // L13/L15/L7: decode the receive metadata (dst_ip, timestamp,
                // GRO stride) off the real control buffer once, then split a
                // GRO-coalesced datagram into its segments so each one is fed
                // to the engine as a standalone QUIC datagram. A non-GRO
                // datagram has stride >= its length and yields exactly one
                // segment — the whole thing.
                const meta = udp_cmsg.decodeRecvMeta(msg.control);
                const stride = if (meta.stride) |s| (if (s == 0) msg.data.len else s) else msg.data.len;
                var seg_offset: usize = 0;
                while (seg_offset < msg.data.len) : (seg_offset += stride) {
                    const datagram = msg.data[seg_offset..@min(seg_offset + stride, msg.data.len)];
                    try self.ingestDatagram(msg.from, datagram, msg.control, meta);
                }
            }
            progressed = true;
        }
        return progressed;
    }

    /// Route one standalone QUIC datagram to its connection and feed it to the
    /// driver. GRO splitting is done by the caller; `datagram` is one segment.
    /// `meta` carries the receive metadata decoded from the message's control
    /// buffer (dst_ip L13, timestamp L15, stride L7).
    fn ingestDatagram(
        self: *Endpoint,
        from: net.IpAddress,
        datagram: []const u8,
        control: []const u8,
        meta: udp_cmsg.RecvMeta,
    ) tr.Error!void {
        _ = meta; // dst_ip/timestamp feed path addressing + RTT once plumbed.
        const four: router_mod.FourTuple = .{ .local = self.routerLocal(), .remote = toSockAddr(from) };
        if (try self.route(four, datagram, from)) |entry| {
            // Read the ECN codepoint off the REAL IP header before the
            // datagram is decrypted: a CE mark is path feedback and
            // stands whether or not the payload turns out to be valid
            // for this connection.
            self.ingestEcn(entry, control);
            const authed_before = entry.driver.total_authed_packets;
            entry.driver.handleDatagram(self.clockNow(), datagram) catch |err| switch (err) {
                // A TLS authentication failure is not a malformed-packet
                // drop: fail closed and ensure `accept` can never hand out
                // the unauthenticated server-side connection.
                error.PicotlsError => {
                    entry.rejected = true;
                    entry.lost = true;
                    // The driver queued its CRYPTO_ERROR close (B8). Flush it
                    // NOW, in the same pump cycle as the reject: the B8
                    // reclaim-time flush only runs under an accept/tryAccept
                    // caller, so a pump-only endpoint would otherwise leave
                    // silence on the wire and the peer hangs to its own
                    // timeout (issue #31 F2 no-common-schemes negative).
                    _ = try self.pumpOutgoing();
                },
                // A malformed / undecryptable datagram must not kill the pump
                // (fail-closed on attacker-controlled decode). Drop it.
                else => {},
            };
            // Migration may only follow an AUTHENTICATED packet — a
            // skipped version-unknown or undecryptable datagram is not
            // proof of keys (noq total_authed_packets semantics).
            self.maybeNoteMigration(entry, from, entry.driver.total_authed_packets > authed_before);
            self.drainEvents(entry);
        } else {
            // RFC 9000 §10.3: a stateless reset is intentionally unroutable by
            // DCID (random short-header shape). When demux finds no owner,
            // still scan live connections for a matching peer reset token.
            // Without this, real-peer resets never reach matchesPeerStatelessReset
            // (the unit test fed handleDatagram directly and hid the gap).
            try self.scanUnroutableForStatelessReset(datagram);
        }
    }

    /// Check every live connection for a peer stateless-reset token match on an
    /// unroutable datagram (RFC 9000 §10.3 demux-independent detection).
    fn scanUnroutableForStatelessReset(self: *Endpoint, dgram: []const u8) tr.Error!void {
        if (dgram.len < packet.stateless_reset_min_len) return;
        const now = self.clockNow();
        for (&self.conns) |*e| {
            if (!e.used) continue;
            if (!e.driver.matchesPeerStatelessReset(dgram)) continue;
            e.driver.notePeerStatelessReset(now) catch {};
            self.drainEvents(e);
        }
    }

    /// Test hook: drive the production migration path for the first live conn
    /// of `role` as if an authenticated packet arrived from `candidate`.
    pub fn triggerMigrationForTest(self: *Endpoint, role: crypto.Role, candidate: net.IpAddress) bool {
        self.lockPump();
        defer self.unlockPump();
        for (&self.conns) |*e| {
            if (e.used and e.role == role and !e.lost) {
                self.maybeNoteMigration(e, candidate, true);
                return e.migration_pending;
            }
        }
        return false;
    }

    /// Test hook: the conn of `role` switched its path to `addr`.
    pub fn isMigratedToForTest(self: *Endpoint, role: crypto.Role, addr: net.IpAddress) bool {
        self.lockPump();
        defer self.unlockPump();
        for (&self.conns) |*e| {
            if (e.used and e.role == role and !e.lost) {
                return !e.migration_pending and ipEql(e.remote, addr);
            }
        }
        return false;
    }

    /// Test hook: a migration probe is outstanding for the conn of `role`.
    pub fn migrationProbePendingForTest(self: *Endpoint, role: crypto.Role) bool {
        self.lockPump();
        defer self.unlockPump();
        for (&self.conns) |*e| {
            if (e.used and e.role == role and !e.lost) return e.migration_pending;
        }
        return false;
    }

    /// Passive migration handling for an authenticated inbound packet
    /// whose source differs from the conn's current path. Once connected, the
    /// candidate is probed (PATH_CHALLENGE) and only a verbatim echo switches
    /// the path (RFC 9000 §9 anti-spoofing). Mid-handshake, a CLIENT re-points
    /// its reply path when the SERVER's address changes after an authenticated
    /// packet — that is noq's `server_handshake_migration` (client-side only,
    /// connection/mod.rs:4298-4315; iroh sets it true — the relay-race case).
    /// A server never switches mid-handshake: noq drops off-path packets until
    /// authentication completes (mod.rs:2316-2347).
    fn maybeNoteMigration(self: *Endpoint, entry: *ConnEntry, from: net.IpAddress, authenticated: bool) void {
        if (!authenticated) return; // unproven traffic never moves a path
        if (ipEql(from, entry.remote)) return;
        if (entry.connected) {
            // A dead probe (gave up after max attempts) frees the slot — the
            // next address change probes anew (noq recovers after validation
            // failure; a dead probe must not wedge the conn).
            if (entry.migration_pending and
                entry.driver.timers.path_challenge_deadline == null and
                entry.driver.challenge_await_len == 0)
            {
                entry.migration_pending = false;
            }
            if (entry.migration_pending) return;
            self.io_inst.random(&entry.migration_token);
            entry.driver.challengePathTo(entry.migration_token, migration_dest_hint);
            entry.migration_candidate = from;
            entry.migration_pending = true;
        } else if (entry.role == .client and !entry.driver.handshake_confirmed) {
            // The relay won the race — answer at the new address (client
            // side, post-authentication, pre-confirmation; noq validates NOT).
            entry.remote = from;
        }
    }

    /// Public cooperative pump entry. Internal callers that already hold
    /// `pump_mu` use `pollOnceLocked` to avoid re-locking the non-recursive mutex.
    pub fn pollOnce(self: *Endpoint) tr.Error!void {
        self.lockPump();
        defer self.unlockPump();
        try self.pollOnceLocked();
    }

    fn pollOnceLocked(self: *Endpoint) tr.Error!void {
        const outgoing = try self.pumpOutgoing();
        _ = try self.pumpIncomingAfter(outgoing);
    }

    /// iroh-actor-style BACKGROUND PUMP body: one continuously-running task
    /// per opted-in endpoint that drives transmits (data/ACK/timers/retrans-
    /// mits/NAT retries/drain-window close re-draws) and ingress (relay +
    /// socket) INDEPENDENT of caller stream operations — the noq behavioral
    /// counterpart of the picoquic backend's spawned event loop
    /// (`endpoint.zig#run`) and of iroh's tokio-driven quinn endpoint driver.
    /// Caller-path inline pumping remains (blocking ops still drive their own
    /// progress); this loop is additionally what keeps ACKs/keep-alives/timers
    /// firing and ingress draining while ALL callers are idle, and shares the
    /// pump work under concurrency instead of serializing it on one caller.
    ///
    /// Each iteration takes `pump_mu` for ONE bounded round — send, relay
    /// ingress, socket ingress with the `receiveTimeout` wait (≤1 ms when
    /// idle, zero when there is progress) — then releases it, so caller paths
    /// and the loop share the pump under exactly the existing invariants.
    /// Sustained pump failures park the loop (no hot-spin on a dead socket);
    /// `deinit` sets `pump_stop` and joins.
    fn backgroundPumpLoop(self: *Endpoint) void {
        var failures: u32 = 0;
        while (!self.pump_stop.load(.acquire)) {
            const ok = blk: {
                self.lockPump();
                defer self.unlockPump();
                const outgoing = self.pumpOutgoing() catch break :blk false;
                _ = self.pumpIncomingAfter(outgoing) catch break :blk false;
                break :blk true;
            };
            if (ok) {
                failures = 0;
                continue;
            }
            failures += 1;
            if (failures >= background_pump_broken_threshold) {
                while (!self.pump_stop.load(.acquire)) {
                    std.Io.sleep(self.io_inst, .fromMilliseconds(10), .awake) catch {};
                }
                return;
            }
        }
    }

    /// Demux one inbound datagram to its connection entry, minting a server
    /// connection on a first-flight Initial to an unknown DCID (accept path).
    fn route(self: *Endpoint, four: router_mod.FourTuple, dgram: []const u8, from: net.IpAddress) tr.Error!?*ConnEntry {
        if (dgram.len == 0) return null;
        // 1. CID demux via the router (Initial by DCID, short-header by local-CID
        //    prefix or four-tuple). Malformed → treated as unroutable.
        if (self.router.routeDatagram(four, dgram) catch null) |r| {
            if (self.entryForHandle(r.target.handle)) |e| return e;
            // B7: the target is a closed conn held in its drain window — feed
            // the straggler so the driver re-arms its close (noq
            // mod.rs:4439-4471), then let the caller treat the datagram as
            // delivered (no live entry to return).
            if (self.drainForHandle(r.target.handle)) |d| {
                d.driver.handleDatagram(self.clockNow(), dgram) catch {};
                return null;
            }
        }
        // 2. First-flight Initial to an unknown DCID → server accept minting.
        const is_long = (dgram[0] & packet.long_header_form) != 0;
        const is_initial = is_long and ((dgram[0] & 0x30) >> 4) == 0;
        if (is_initial and (self.expected_peer != null or self.accept_unknown_peer) and self.entryByRemote(from) == null) {
            // A12: reject undersized Initials before token handling can send a
            // Retry. The router repeats the owning check below, but this guard
            // prevents a response to a spoofed short first flight.
            if (dgram.len < 1200) return null;
            // A12: the ≥1200 first-flight check also lives at the owning layer
            // (router.handleFirstPacket → error.InitialDatagramTooShort → the
            // catch below silently drops, matching noq endpoint.rs:452-455).
            // E5/E9: validate any token the client presented BEFORE minting
            // (noq IncomingToken::from_header). A Retry token binds the full
            // address and expires fast; a NEW_TOKEN token binds the IP,
            // expires slowly, and is single-use. Undecodable/foreign tokens
            // fall through as if absent (RFC 9000 §8.1.3).
            var validation: FirstFlightValidation = .{};
            if (packet.decodeProtectedHeader(dgram, true) catch null) |ph| {
                if (ph.initial.token.len != 0) {
                    const remote = toTokenAddress(from);
                    const now_secs: u64 = @intCast(std.Io.Clock.real.now(self.io_inst).toSeconds());
                    if (quic_token.validateRetry(&self.token_key, ph.initial.token, remote, now_secs, retry_token_lifetime_secs)) |info| {
                        validation.retry_info = info;
                    } else if (quic_token.validateNewToken(&self.token_key, ph.initial.token, remote.ip, now_secs, self.new_token_lifetime_secs, &self.token_log)) {
                        validation.new_token_valid = true;
                    }
                }
                // E5: Retry required and the flight is unvalidated → issue a
                // Retry instead of minting; the client returns with a token.
                if (self.retry_required and validation.retry_info == null and !validation.new_token_valid) {
                    self.issueRetryTo(from, ph.initial.dst_cid, ph.initial.src_cid);
                    return null;
                }
                if (self.incoming_filter) |filter| {
                    const info = IncomingInfo{
                        .remote = from,
                        .remote_addr_validated = validation.retry_info != null or validation.new_token_valid,
                        .first_datagram = dgram,
                    };
                    switch (filter.callback(filter.context, &info)) {
                        .accept => {},
                        .retry => {
                            if (!info.remote_addr_validated) {
                                self.issueRetryTo(from, ph.initial.dst_cid, ph.initial.src_cid);
                                return null;
                            }
                        },
                        .reject => {
                            if (self.router.buildInitialCloseDatagram(dgram, router_mod.transport_error_connection_refused) catch null) |close| {
                                defer self.allocator.free(close);
                                var dest = from;
                                self.socket.send(self.io_inst, &dest, close) catch {};
                            }
                            return null;
                        },
                        .ignore => {
                            return null;
                        },
                    }
                }
            }
            const first = self.router.handleFirstPacket(four, dgram) catch return null;
            switch (first) {
                .routed => |rr| return self.entryForHandle(rr.target.handle),
                .new_connection => |h| return try self.mintServerConn(h, dgram, from, validation),
                .version_negotiation => |vn| {
                    self.socket.send(self.io_inst, &from, vn) catch {};
                    self.allocator.free(vn);
                    return null;
                },
                .initial_close => |close| {
                    // A12/A13: endpoint-level refusal of a first flight (e.g.
                    // DCID < 8 → PROTOCOL_VIOLATION) — send the Initial-space
                    // CONNECTION_CLOSE instead of letting the peer retransmit
                    // to timeout (noq endpoint.rs:480-489).
                    self.socket.send(self.io_inst, &from, close) catch {};
                    self.allocator.free(close);
                    return null;
                },
            }
        }
        // 3. Four-tuple fallback: the router cannot parse a Handshake-space long
        //    header (returns NonInitialUnsupported), so mid-handshake packets and
        //    the client's single conn resolve by peer address. FLAGGED deviation.
        if (is_long and !is_initial) return self.entryByRemote(from);
        // E3: unroutable — answer with a stateless reset when the datagram has
        // a parseable DCID (noq Endpoint::stateless_reset).
        self.maybeStatelessReset(from, dgram);
        return null;
    }

    /// noq Endpoint::stateless_reset (endpoint.rs:273-334): rate-limited
    /// endpoint-wide (`min_reset_interval` 20 ms), padded to just below the
    /// inciting size (anti-amplification + reset-loop prevention), token =
    /// HMAC(reset_key, dcid) truncated to 16 bytes.
    fn maybeStatelessReset(self: *Endpoint, from: net.IpAddress, dgram: []const u8) void {
        const min_reset_interval_ns: i64 = 20 * std.time.ns_per_ms;
        const now = self.clockNow();
        if (self.last_stateless_reset_ns + min_reset_interval_ns > now) return;

        // Nothing parseable → nothing to reset (noq resets only packets whose
        // DCID failed routing).
        var dcid: ?packet.ConnectionId = null;
        if ((dgram[0] & packet.long_header_form) != 0) {
            if (packet.decodeProtectedLongHeader(dgram, true) catch null) |hdr| dcid = hdr.dst_cid;
        } else if (dgram.len >= 1 + local_cid_len) {
            dcid = packet.ConnectionId.init(dgram[1 .. 1 + local_cid_len]) catch null;
        }
        const target = dcid orelse return;
        // The CID must be genuinely UNKNOWN to the whole endpoint (noq's
        // connection-index miss, endpoint.rs:267): a retransmitted first
        // flight or a live conn's short header is unroutable at THIS demux
        // but must never draw a reset.
        if (self.router.dcidKnown(dgram)) return;

        // The reset MUST be smaller than the inciting datagram (RFC 9000 §10.3).
        const min_padding_len: usize = 5;
        const ideal_min_padding_len: usize = min_padding_len + packet.max_cid_size;
        if (dgram.len <= packet.stateless_reset_token_len + min_padding_len) return;
        const max_padding_len = dgram.len - packet.stateless_reset_token_len - 1;
        const padding_len = if (max_padding_len <= ideal_min_padding_len) max_padding_len else blk: {
            var span: [8]u8 = undefined;
            self.io_inst.random(&span);
            break :blk ideal_min_padding_len + std.mem.readInt(u64, &span, .little) % (max_padding_len - ideal_min_padding_len);
        };

        var buf: [max_datagram]u8 = undefined;
        self.io_inst.random(buf[0..padding_len]);
        // Randomized "short header" shape with the fixed bit set (RFC 9000
        // §10.3: indistinguishable from a real short-header packet).
        buf[0] = 0b0100_0000 | (buf[0] >> 2);
        const token = quic_token.resetToken(&self.reset_key, target);
        @memcpy(buf[padding_len..][0..packet.stateless_reset_token_len], &token);
        const pkt = buf[0 .. padding_len + packet.stateless_reset_token_len];
        var dest = from;
        self.socket.send(self.io_inst, &dest, pkt) catch return;
        self.last_stateless_reset_ns = now;
        self.stats_stateless_reset_sent += 1;
    }

    /// Token-validation outcome for a first-flight Initial (E5/E9).
    const FirstFlightValidation = struct {
        /// A validated Retry token: mint with the token's ODCID (TP) and the
        /// current flight's DCID (keys + retry_scid TP), path validated.
        retry_info: ?quic_token.RetryInfo = null,
        /// A validated NEW_TOKEN token: mint normally, path validated (E9's
        /// early anti-amplification lift).
        new_token_valid: bool = false,
    };

    /// noq default `retry_token_lifetime` (ServerConfig).
    const retry_token_lifetime_secs: u64 = 15;

    /// E5: issue a Retry to an unvalidated first flight (noq Endpoint::retry):
    /// fresh SCID, sealed address-bound token, integrity tag over the client's
    /// original DCID. The endpoint stays stateless — no connection is minted.
    fn issueRetryTo(self: *Endpoint, from: net.IpAddress, client_dcid: packet.ConnectionId, client_scid: packet.ConnectionId) void {
        const now_secs: u64 = @intCast(std.Io.Clock.real.now(self.io_inst).toSeconds());
        var retry_scid_bytes: [local_cid_len]u8 = undefined;
        self.io_inst.random(&retry_scid_bytes);
        const retry_scid = packet.ConnectionId.init(&retry_scid_bytes) catch return;
        var nonce_bytes: [16]u8 = undefined;
        self.io_inst.random(&nonce_bytes);
        var token_buf: [quic_token.max_token_len + quic_token.nonce_len]u8 = undefined;
        const sealed = quic_token.encode(&self.token_key, .{ .retry = .{
            .address = toTokenAddress(from),
            .orig_dst_cid = client_dcid,
            .issued_secs = now_secs,
        } }, std.mem.readInt(u128, &nonce_bytes, .little), &token_buf);
        const pseudo = packet.buildRetry(self.allocator, 1, client_scid, retry_scid, sealed, .{0} ** 16) catch return;
        defer self.allocator.free(pseudo);
        const tag = initial_keys.retryIntegrityTag(self.allocator, client_dcid.slice(), pseudo[0 .. pseudo.len - 16]) catch return;
        const retry_pkt = packet.buildRetry(self.allocator, 1, client_scid, retry_scid, sealed, tag) catch return;
        defer self.allocator.free(retry_pkt);
        var dest = from;
        self.socket.send(self.io_inst, &dest, retry_pkt) catch return;
        self.stats_retry_issued += 1;
    }

    fn toTokenAddress(from: net.IpAddress) quic_token.Address {
        return switch (from) {
            .ip4 => |a| .{ .ip = .{ .v4 = a.bytes }, .port = a.port },
            .ip6 => |a| .{ .ip = .{ .v6 = a.bytes }, .port = a.port },
        };
    }

    fn mintServerConn(self: *Endpoint, handle: router_mod.ConnectionHandle, dgram: []const u8, from: net.IpAddress, validation: FirstFlightValidation) tr.Error!?*ConnEntry {
        try self.ensureZigtlsTicketKeyFresh();
        const ph = packet.decodeProtectedHeader(dgram, true) catch {
            self.router.removeConnection(handle) catch {};
            return null;
        };
        errdefer self.router.removeConnection(handle) catch {};
        const dst_cid = ph.initial.dst_cid; // client's original DCID (X)
        const src_cid = ph.initial.src_cid; // client's SCID (C)
        // E11: `max_incoming` saturation — beyond the conn-table cap a new
        // first flight is DROPPED (noq drops the Incoming), never a pump error.
        const entry = self.freeEntry() orelse {
            // A13 (noq endpoint.rs accept():585-599): connection slots
            // exhausted at accept time → Initial-space CONNECTION_CLOSE with
            // CONNECTION_REFUSED, not a silent drop into retransmit-timeout.
            // The refusal is complete once the close is sent — the endpoint
            // itself is healthy, so this is a null (no entry), not an error.
            // Roll back the router mint explicitly: errdefer only fires on
            // error returns, not on this graceful-refusal null.
            self.stats_incoming_saturation_drops += 1;
            self.router.removeConnection(handle) catch {};
            if (self.router.buildInitialCloseDatagram(dgram, router_mod.transport_error_connection_refused) catch null) |close| {
                defer self.allocator.free(close);
                self.socket.send(self.io_inst, &from, close) catch {};
            }
            return null;
        };
        var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        self.io_inst.random(&seed_bytes);
        var local_cid_bytes: [local_cid_len]u8 = undefined;
        self.io_inst.random(&local_cid_bytes);
        const local_cid = packet.ConnectionId.init(&local_cid_bytes) catch {
            return error.ConnectionLost;
        };
        const qad = self.qad_identity != null;
        var qad_tp_scratch: [256]u8 = undefined;
        // QAD (upstream iroh-relay quic.rs): zero streams, observed-address
        // role send_only. Every other knob stays at this driver's defaults.
        const qad_tp: ?[]const u8 = if (qad) blk: {
            const params = transport_parameters.TransportParameters{
                .max_idle_timeout = 30_000, // matches connection.zig's default
                .initial_max_streams_bidi = 0,
                .initial_max_streams_uni = 0,
                .initial_source_connection_id = local_cid,
                .observed_addr_role = .send_only,
            };
            break :blk params.encode(&qad_tp_scratch) catch null;
        } else null;
        const drv = quic_conn.Connection.create(self.allocator, .{
            .backend = self.tls_backend,
            .role = .server,
            .secret_key = self.secret,
            .peer_public_key = if (qad) null else self.expected_peer,
            .certificate_der_override = self.certificate_der_override,
            .require_client_authentication = !qad,
            .alpn = if (self.server_alpns.items.len > 0) self.server_alpns.items[0] else self.alpn,
            .server_alpns = if (self.server_alpns.items.len > 0) self.server_alpns.items else null,
            .x509_server = self.qad_identity,
            .transport_params = qad_tp,
            .zigtls_ticket_key_manager = if (!qad and crypto.zigtls_enabled and self.tls_backend == .zigtls) &self.zigtls_ticket_key_manager else null,
            .zigtls_auto_issue_new_session_ticket = !qad and crypto.zigtls_enabled and self.tls_backend == .zigtls,
            // Server 0-RTT: acceptance is fail-closed on the replay filter
            // (the engine refuses an enabled config without one) and the
            // strike register makes each ticket single-use for early data.
            // QAD stays out of scope — it serves anonymous rustls clients.
            .zigtls_enable_early_data = !qad and self.zeroRttOnZigtls(),
            .zigtls_replay_filter = if (crypto.zigtls_enabled) &self.zigtls_replay_filter else null,
            .certificate_request_signature_algorithms = self.certificate_request_signature_algorithms,
        }, local_cid, src_cid, dst_cid, seed_bytes, .{
            // E5/F6: a validated Retry binds the token's ODCID and the Retry
            // SCID (this flight's DCID) into the transport parameters.
            .orig_dst_cid = if (validation.retry_info) |info| info.orig_dst_cid else null,
            .retry_src_cid = if (validation.retry_info != null) dst_cid else null,
            .reset_key = &self.reset_key,
            .congestion_kind = self.congestion_kind,
        }) catch {
            return error.ConnectionLost;
        };
        errdefer drv.destroy();
        // E5/E9: a validated token lifts the anti-amplification cap before the
        // handshake (noq IncomingToken::validated).
        if (validation.retry_info != null or validation.new_token_valid) {
            drv.markTokenValidated();
            if (validation.retry_info != null) {
                self.stats_retry_validated += 1;
            } else {
                self.stats_new_token_validated += 1;
            }
        }
        // E7: issue a sealed NEW_TOKEN for post-handshake emission, bound to
        // the peer's IP + issuance time (noq on_path_validated).
        {
            const now_secs: u64 = @intCast(std.Io.Clock.real.now(self.io_inst).toSeconds());
            var nonce_bytes: [16]u8 = undefined;
            self.io_inst.random(&nonce_bytes);
            var token_buf: [quic_token.max_token_len + quic_token.nonce_len]u8 = undefined;
            const sealed = quic_token.encode(&self.token_key, .{ .validation = .{
                .ip = toTokenAddress(from).ip,
                .issued_secs = now_secs,
            } }, std.mem.readInt(u128, &nonce_bytes, .little), &token_buf);
            drv.setNewTokenOverride(sealed) catch {};
        }
        // G18: iroh heartbeat keep-alive (endpoint/quic.rs:156).
        drv.setKeepAliveIntervalNs(quic_conn.default_keep_alive_interval_ns);
        self.router.registerLocalCid(handle, local_cid) catch return error.ConnectionLost;
        entry.* = .{
            .used = true,
            .driver = drv,
            .handle = handle,
            .remote = from,
            .role = .server,
            .remote_node = self.expected_peer orelse self.node_id,
            .remote_node_set = self.expected_peer != null,
        };
        entry.magic = magicsock.State.init(self.allocator);
        entry.magic_init = true;
        return entry;
    }

    fn ensureZigtlsTicketKeyFresh(self: *Endpoint) tr.Error!void {
        if (!crypto.zigtls_enabled or self.tls_backend != .zigtls) return;
        const now_unix = std.Io.Clock.real.now(self.io_inst).toSeconds();
        if (!ticketKeyRotationDue(self.zigtls_ticket_key_rotated_at_unix, now_unix)) return;

        var material: [32]u8 = undefined;
        self.io_inst.random(&material);
        var key_id_bytes: [4]u8 = undefined;
        self.io_inst.random(&key_id_bytes);
        self.zigtls_ticket_key_manager.rotate(.{
            .key_id = std.mem.readInt(u32, &key_id_bytes, .big),
            .material = material,
            .not_before_unix = now_unix,
            .not_after_unix = ticketKeyNotAfter(now_unix),
        }) catch return error.ConnectionLost;
        self.zigtls_ticket_key_rotated_at_unix = now_unix;
    }

    /// Queue the draft-seemann OBSERVED_ADDRESS report for a freshly
    /// connected QAD peer. Gated on the peer's negotiated role: a peer that
    /// did not ask for reports MUST NOT receive the frame (noq connection-
    /// errors on an unnegotiated OBSERVED_ADDRESS — connection/mod.rs).
    fn qadPushObserved(self: *Endpoint, entry: *ConnEntry) void {
        if (!entry.driver.peer_params_applied) return;
        const peer_role = entry.driver.peer_params.observed_addr_role orelse return;
        if (peer_role == .send_only) return; // a pure reporter wants no report
        switch (entry.remote) {
            .ip4 => |a| {
                entry.driver.advertiseAddress(.{ .kind = .observed, .seq = 0, .ip = a.bytes, .port = a.port });
                _ = self.pumpOutgoing() catch {};
            },
            .ip6 => {
                // RECORDED LIMITATION (QAD emit): no IPv6 report — NatAddress
                // is v4-only (shared with the n0 magicsock frame queue).
            },
        }
    }

    /// QAD service step (the relay binary's QAD thread): drive one bounded
    /// I/O round and reclaim closed server connections. QAD handshakes are
    /// never handed off through accept — the service only needs the observed-
    /// address push (drainEvents) and teardown.
    pub fn qadServiceStep(self: *Endpoint) tr.Error!usize {
        self.lockPump();
        defer self.unlockPump();
        try self.pollOnceLocked();
        for (&self.conns) |*e| {
            // Same ownership rule as tryAcceptReady: handed-off slots close via
            // ConnectionImpl; reclaim only orphaned (never-accepted) lost servers.
            if (e.used and e.role == .server and e.lost and !e.handed_off) self.reclaimLost(e);
        }
        return self.liveConnectionCountLocked();
    }

    // --- F13 QAD client -----------------------------------------------------
    //
    // A QAD probe has no peer node id (draft-seemann address discovery is
    // anonymous — see `crypto.Config.x509_trust_store`) and negotiates
    // `observed_addr_role = .receive_only` instead of the normal peer-to-peer
    // TP. It otherwise rides this same endpoint's UDP pump/router/timer
    // machinery — `qad.Client` (src/engine-noq/qad.zig) is the operator-facing
    // wrapper.

    /// Optional X.509 peer-validation overrides for `qadConnect` (cert-
    /// validation matrix + OCSP policy). Defaults preserve the production
    /// QAD client: trust-store + hostname, OCSP off, no mutation bypasses.
    pub const QadConnectOpts = struct {
        enforce_ocsp: bool = false,
        allow_soft_fail_ocsp: bool = false,
        stapled_ocsp: ?crypto.ZigtlsOcspResponseView = null,
        bypass_chain_verify: bool = false,
        bypass_hostname_verify: bool = false,
        bypass_trust_anchor: bool = false,
        bypass_ocsp_check: bool = false,
    };

    /// Dial `addr` presenting this endpoint's ALPN (the caller creates the
    /// endpoint with `alpn = qad.alpn` and `tls_backend = .zigtls`), checking
    /// the peer's X.509 identity against `trust_store` + `server_name`
    /// (`server_name` is both the ClientHello SNI and the expected cert
    /// hostname — upstream QAD ignores SNI server-side, but a real webpki
    /// client always sends one, so we do too). `trust_store` must outlive
    /// the connection.
    pub fn qadConnect(
        self: *Endpoint,
        addr: net.IpAddress,
        server_name: []const u8,
        trust_store: *const crypto.ZigtlsTrustStore,
    ) tr.Error!void {
        return self.qadConnectOpts(addr, server_name, trust_store, .{});
    }

    pub fn qadConnectOpts(
        self: *Endpoint,
        addr: net.IpAddress,
        server_name: []const u8,
        trust_store: *const crypto.ZigtlsTrustStore,
        opts: QadConnectOpts,
    ) tr.Error!void {
        self.lockPump();
        defer self.unlockPump();
        if (!crypto.zigtls_enabled or self.tls_backend != .zigtls) return error.ConnectionLost;
        var cid_bytes: [local_cid_len]u8 = undefined;
        self.io_inst.random(&cid_bytes);
        const scid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
        self.io_inst.random(&cid_bytes);
        const initial_dcid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
        var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        self.io_inst.random(&seed_bytes);

        const drv = quic_conn.Connection.create(self.allocator, .{
            .backend = .zigtls,
            .role = .client,
            .secret_key = self.secret,
            .peer_public_key = null,
            .alpn = self.alpn,
            .server_name = server_name,
            .x509_trust_store = trust_store,
            .x509_enforce_ocsp = opts.enforce_ocsp,
            .x509_allow_soft_fail_ocsp = opts.allow_soft_fail_ocsp,
            .x509_stapled_ocsp = opts.stapled_ocsp,
            .x509_bypass_chain_verify = opts.bypass_chain_verify,
            .x509_bypass_hostname_verify = opts.bypass_hostname_verify,
            .x509_bypass_trust_anchor = opts.bypass_trust_anchor,
            .x509_bypass_ocsp_check = opts.bypass_ocsp_check,
        }, scid, initial_dcid, initial_dcid, seed_bytes, .{
            .reset_key = &self.reset_key,
            .congestion_kind = self.congestion_kind,
            .observed_addr_role = .receive_only,
        }) catch return error.ConnectionLost;
        errdefer drv.destroy();

        const handle = self.router.addConnection(.{
            .init_cid = scid,
            .side = .client,
            .local_cids = &.{scid},
            .initial_cids = &.{scid},
        }) catch return error.ConnectionLost;

        const entry = self.freeEntry() orelse {
            self.router.removeConnection(handle) catch {};
            return error.OutOfMemory;
        };
        entry.* = .{
            .used = true,
            .driver = drv,
            .handle = handle,
            .remote = addr,
            .role = .client,
        };

        drv.startClient() catch {
            self.reclaim(entry);
            return error.ConnectionLost;
        };
    }

    /// Drive one I/O round and return the QAD connection's OBSERVED_ADDRESS
    /// report, taking it (one-shot — a second call returns null for the same
    /// report). `error.ConnectionLost` if the (single) client connection this
    /// endpoint holds has failed or been closed by the peer.
    pub fn qadClientTakeObserved(self: *Endpoint) tr.Error!?quic_conn.NatAddress {
        self.lockPump();
        defer self.unlockPump();
        try self.pollOnceLocked();
        for (&self.conns) |*e| {
            if (!e.used or e.role != .client) continue;
            if (e.qad_observed) |v| {
                e.qad_observed = null;
                return v;
            }
            if (e.lost) {
                return error.ConnectionLost;
            }
        }
        return null;
    }

    /// Close every live QAD client connection with the upstream close
    /// contract (iroh-relay `quic.rs` `QUIC_ADDR_DISC_CLOSE_CODE`/`_REASON`:
    /// app code 1, reason "finished"), flush, and reclaim.
    pub fn qadClientClose(self: *Endpoint) void {
        self.lockPump();
        defer self.unlockPump();
        for (&self.conns) |*entry| {
            if (entry.used and entry.role == .client and !entry.lost) {
                entry.driver.closeWith(self.clockNow(), .{ .error_code = 1, .reason = "finished", .is_app = true });
            }
        }
        self.driveQuiescent() catch {};
        for (&self.conns) |*entry| {
            if (!entry.used or entry.role != .client) continue;
            if (entry.lost or entry.driver.isDrained() or !self.moveToDrain(entry)) {
                self.reclaim(entry);
            }
        }
    }

    /// Drain driver events into the entry's flags (connected / lost / peer-stream
    /// opened / reset). Stream bytes are read directly from the driver.
    fn drainEvents(self: *Endpoint, entry: *ConnEntry) void {
        while (entry.driver.poll()) |ev| {
            switch (ev) {
                .connected => {
                    entry.connected = true;
                    self.cacheZigtlsTicket(entry);
                    if (self.qad_identity != null and entry.role == .server and !entry.qad_observed_sent) {
                        entry.qad_observed_sent = true;
                        self.qadPushObserved(entry);
                    }
                },
                .connection_lost => entry.lost = true,
                .stream_opened => |s| {
                    if (isPeerInitiated(entry.role, s.id)) entry.notePeerStream(s.id);
                },
                .stream_reset => |s| entry.noteReset(s.id),
                .nat_address => |a| {
                    // Feed the n0 NAT-traversal frame into magicsock (5e).
                    if (entry.magic_init) entry.magic.handleFrame(natToMagic(a)) catch {};
                    // F13 QAD client: stash the OBSERVED_ADDRESS report for
                    // `Endpoint.qadClientTakeObserved` (a QAD probe connection
                    // is client-role and has no magicsock traversal to feed).
                    if (entry.role == .client and a.kind == .observed) entry.qad_observed = a;
                },
                .path_validated => |token| {
                    // A path was REALLY validated (our random challenge echoed).
                    // Mark ONLY the mapped candidate succeeded — an unvalidated
                    // path is never marked, so `selectedPath` cannot pick it.
                    if (entry.magic_init) {
                        for (entry.probes[0..entry.probe_count]) |p| {
                            if (std.mem.eql(u8, &p.token, &token)) {
                                entry.magic.markPathSucceeded(p.addr, 1000);
                            }
                        }
                    }
                    // A validated migration probe switches the path.
                    if (entry.migration_pending and std.mem.eql(u8, &entry.migration_token, &token)) {
                        entry.remote = entry.migration_candidate;
                        entry.migration_pending = false;
                    }
                },
                else => {},
            }
        }
        self.cacheZigtlsTicket(entry);
        self.cacheNewToken(entry);
    }

    /// E8: a NEW_TOKEN the driver stored goes into the client token cache
    /// keyed by the peer's server name (noq TokenStore::insert).
    fn cacheNewToken(self: *Endpoint, entry: *ConnEntry) void {
        if (entry.role != .client or !entry.remote_node_set) return;
        const token_bytes = entry.driver.storedNewToken() orelse return;
        const sni = tls_name.serverName(entry.remote_node);
        const key_copy = self.allocator.dupe(u8, &sni) catch return;
        const val_copy = self.allocator.dupe(u8, token_bytes) catch {
            self.allocator.free(key_copy);
            return;
        };
        const gop = self.token_cache.getOrPut(key_copy) catch {
            self.allocator.free(key_copy);
            self.allocator.free(val_copy);
            return;
        };
        if (gop.found_existing) {
            self.allocator.free(key_copy);
            self.allocator.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = val_copy;
    }

    /// E8: take a cached NEW_TOKEN for `server_name` (one-time use — the take
    /// removes it, per noq TokenStore::take). The caller owns the bytes.
    fn takeStoredToken(self: *Endpoint, server_name: []const u8) []const u8 {
        const kv = self.token_cache.fetchRemove(server_name) orelse return "";
        self.allocator.free(@constCast(kv.key));
        return kv.value;
    }

    fn cachedZigtlsResumptionTicket(self: *Endpoint, peer: key.NodeId) ?crypto.ZigtlsResumptionTicket {
        if (!crypto.zigtls_enabled) return null;
        if (self.tls_backend != .zigtls) return null;
        const cached = self.zigtls_cached_ticket orelse return null;
        if (!cached.peer.eql(peer)) return null;
        return cached.info.asResumptionTicket();
    }

    fn cacheZigtlsTicket(self: *Endpoint, entry: *ConnEntry) void {
        if (!crypto.zigtls_enabled) return;
        if (self.tls_backend != .zigtls or entry.role != .client or !entry.remote_node_set) return;
        while (entry.driver.popZigtlsNewSessionTicket()) |ticket| {
            if (ticket.asResumptionTicket() == null) {
                var discard = ticket;
                discard.deinit(self.allocator);
                continue;
            }
            if (self.zigtls_cached_ticket) |*cached| cached.deinit(self.allocator);
            self.zigtls_cached_ticket = .{
                .peer = entry.remote_node,
                .info = ticket,
            };
        }
    }

    fn reclaim(self: *Endpoint, entry: *ConnEntry) void {
        // Idempotent: accept-loop and ConnectionImpl.pubClose can race on a lost server slot.
        // Claim the entry first so a concurrent reclaim is a no-op.
        if (!entry.used) return;
        entry.used = false;
        // Free stream impls bound to this conn.
        for (&self.sends) |*s| {
            if (s.used and s.entry == entry) {
                s.* = .{};
            }
        }
        for (&self.recvs) |*r| {
            if (r.used and r.entry == entry) r.* = .{};
        }
        self.router.removeConnection(entry.handle) catch {};
        if (entry.magic_init) {
            entry.magic.deinit();
            entry.magic_init = false;
        }
        entry.driver.destroy();
        entry.* = .{};
    }

    /// Reclaim a lost conn's slot, but flush any close the driver still owes
    /// the peer FIRST (B8): a handshake TLS failure queues a CRYPTO_ERROR
    /// CONNECTION_CLOSE, and reclaiming in the same pump iteration the
    /// failure landed in would drop it. (The reject branches flush that close
    /// eagerly in the reject pump cycle itself — issue #31 F2; this flush
    /// covers anything re-armed afterwards by stragglers.)
    fn reclaimLost(self: *Endpoint, entry: *ConnEntry) void {
        if (entry.used and entry.lost) {
            _ = self.pumpOutgoing() catch {};
        }
        self.reclaim(entry);
    }

    /// B7: move a closed conn's driver + router registration into a drain
    /// slot and free the conn slot WITHOUT tearing the driver down. Returns
    /// false when no drain slot is free (caller falls back to plain reclaim).
    fn moveToDrain(self: *Endpoint, entry: *ConnEntry) bool {
        for (&self.drains) |*d| {
            if (d.used) continue;
            d.* = .{
                .used = true,
                .driver = entry.driver,
                .handle = entry.handle,
                .remote = entry.remote,
                .remote_node = entry.remote_node,
                .remote_node_set = entry.remote_node_set,
                .relay_selected = entry.relay_selected,
            };
            // Free the slot but keep the driver and router registration alive:
            // same teardown as reclaim() minus router removal + driver destroy.
            entry.used = false;
            for (&self.sends) |*s| {
                if (s.used and s.entry == entry) s.* = .{};
            }
            for (&self.recvs) |*r| {
                if (r.used and r.entry == entry) r.* = .{};
            }
            if (entry.magic_init) {
                entry.magic.deinit();
                entry.magic_init = false;
            }
            entry.* = .{};
            return true;
        }
        return false;
    }

    fn drainForHandle(self: *Endpoint, handle: router_mod.ConnectionHandle) ?*DrainEntry {
        for (&self.drains) |*d| {
            if (d.used and d.handle.eql(handle)) return d;
        }
        return null;
    }

    /// Tear down a drained entry: the window elapsed, the CID registration
    /// and the driver go away together.
    fn reclaimDrain(self: *Endpoint, d: *DrainEntry) void {
        if (!d.used) return;
        self.router.removeConnection(d.handle) catch {};
        d.driver.destroy();
        d.* = .{};
    }

    /// Test hook: conns currently held in their drain window (B7).
    pub fn drainCountForTest(self: *const Endpoint) usize {
        const mutable_self: *Endpoint = @constCast(self);
        mutable_self.lockPump();
        defer mutable_self.unlockPump();
        var n: usize = 0;
        for (mutable_self.drains) |d| {
            if (d.used) n += 1;
        }
        return n;
    }

    /// Close every live connection at the driver level (Endpoint-close
    /// composition): queue CONNECTION_CLOSE on each live driver, flush once,
    /// then move each to its drain window (or reclaim when full/already
    /// drained) so stragglers re-draw the close instead of hitting a dead
    /// router entry. Lost conns go straight through reclaim (their owed close
    /// was already queued by the loss path; the flush above carries it).
    /// Connection wrappers stay valid across this: `connectionIsClosed` goes
    /// true and a later `ConnectionImpl.pubClose` only frees the wrapper (see its
    /// `!entry.used` guard).
    pub fn closeAllConnections(self: *Endpoint) void {
        self.lockPump();
        defer self.unlockPump();
        for (&self.conns) |*entry| {
            if (!entry.used or entry.lost) continue;
            entry.driver.close(self.clockNow());
        }
        self.driveQuiescent() catch {};
        for (&self.conns) |*entry| {
            if (!entry.used) continue;
            if (entry.lost or entry.driver.isDrained() or !self.moveToDrain(entry)) {
                self.reclaim(entry);
            }
        }
    }

    fn driveToConnected(self: *Endpoint, entry: *ConnEntry) tr.Error!void {
        const deadline = self.clockNow() + handshake_timeout_ns;
        while (self.clockNow() < deadline) {
            const outgoing = try self.pumpOutgoing();
            _ = try self.pumpIncomingAfter(outgoing);
            self.drainEvents(entry);
            if (entry.connected) return;
            if (entry.lost) return error.ConnectionLost;
        }
        return error.Timeout;
    }

    fn driveQuiescent(self: *Endpoint) tr.Error!void {
        const deadline = self.clockNow() + drive_quiesce_deadline_ns;
        while (self.clockNow() < deadline) {
            const s = try self.pumpOutgoing();
            const r = try self.pumpIncomingAfter(s);
            if (!s and !r) return;
        }
    }

    fn driveUntilStreamFin(self: *Endpoint, entry: *ConnEntry, id: u64) tr.Error!void {
        const deadline = self.clockNow() + self.stream_timeout_ns;
        while (self.clockNow() < deadline) {
            const outgoing = try self.pumpOutgoing();
            _ = try self.pumpIncomingAfter(outgoing);
            if (entry.hasReset(id)) return error.StreamReset;
            if (entry.driver.streamRecvFin(id)) return;
            if (entry.lost) return error.ConnectionLost;
        }
        return error.Timeout;
    }

    fn driveUntilPeerStream(self: *Endpoint, entry: *ConnEntry, want_bidi: bool) tr.Error!u64 {
        const deadline = self.clockNow() + self.stream_timeout_ns;
        while (self.clockNow() < deadline) {
            const outgoing = try self.pumpOutgoing();
            _ = try self.pumpIncomingAfter(outgoing);
            for (entry.peer_streams[0..entry.peer_stream_count]) |*ps| {
                if (ps.handed_off) continue;
                if (isBidi(ps.id) != want_bidi) continue;
                ps.handed_off = true;
                return ps.id;
            }
            if (entry.lost) return error.ConnectionLost;
        }
        return error.Timeout;
    }

    fn sendFor(self: *Endpoint, entry: *ConnEntry, id: u64) tr.Error!*SendImpl {
        for (&self.sends) |*s| {
            if (!s.used) {
                s.* = .{
                    .used = true,
                    .endpoint = self,
                    .entry = entry,
                    .stream_id = id,
                    .writer_storage = .{ .vtable = &noq_send_writer_vtable, .buffer = s.writer_buffer[0..] },
                };
                return s;
            }
        }
        return error.OutOfMemory;
    }

    fn recvFor(self: *Endpoint, entry: *ConnEntry, id: u64) tr.Error!*RecvImpl {
        for (&self.recvs) |*r| {
            if (!r.used) {
                r.* = .{ .used = true, .endpoint = self, .entry = entry, .stream_id = id };
                return r;
            }
        }
        return error.OutOfMemory;
    }
};

// ── Connection vtable ────────────────────────────────────────────────────────

pub const ConnectionImpl = struct {
    endpoint: *Endpoint,
    entry: *ConnEntry,
    remote: key.NodeId,
    alpn_storage: [64]u8 = undefined,
    alpn_len: usize = 0,
    next_stream_scan: usize = 0,

    fn snapshotAlpn(self: *ConnectionImpl, entry: *ConnEntry) void {
        self.alpn_len = 0;
        const negotiated = entry.driver.negotiatedProtocol() orelse return;
        if (negotiated.len == 0 or negotiated.len > self.alpn_storage.len) return;
        @memcpy(self.alpn_storage[0..negotiated.len], negotiated);
        self.alpn_len = negotiated.len;
    }

    pub fn pubOpenBi(self: *ConnectionImpl) tr.Error!tr.BiStream {
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        const id = self.entry.driver.openStream(.bidi) catch return error.ConnectionLost;
        const send = try self.endpoint.sendFor(self.entry, id);
        const recv = try self.endpoint.recvFor(self.entry, id);
        return .{ .send = .{ .impl = send }, .recv = .{ .impl = recv } };
    }
    pub fn pubAcceptBi(self: *ConnectionImpl) tr.Error!tr.BiStream {
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        const id = try self.endpoint.driveUntilPeerStream(self.entry, true);
        const send = try self.endpoint.sendFor(self.entry, id);
        const recv = try self.endpoint.recvFor(self.entry, id);
        return .{ .send = .{ .impl = send }, .recv = .{ .impl = recv } };
    }
    pub fn pubOpenUni(self: *ConnectionImpl) tr.Error!tr.SendStream {
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        const id = self.entry.driver.openStream(.uni) catch return error.ConnectionLost;
        const send = try self.endpoint.sendFor(self.entry, id);
        return .{ .impl = send };
    }
    pub fn pubAcceptUni(self: *ConnectionImpl) tr.Error!tr.RecvStream {
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        const id = try self.endpoint.driveUntilPeerStream(self.entry, false);
        const recv = try self.endpoint.recvFor(self.entry, id);
        return .{ .impl = recv };
    }
    pub fn pubRemoteNodeId(self: *ConnectionImpl) tr.NodeId {
        return self.remote;
    }
    pub fn pubAlpn(self: *ConnectionImpl) ?[]const u8 {
        if (self.alpn_len == 0) return null;
        return self.alpn_storage[0..self.alpn_len];
    }
    pub fn pubRemoteAddress(self: *ConnectionImpl) ?net.IpAddress {
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        if (!self.entry.used) return null;
        return self.entry.remote;
    }
    pub fn pubClose(self: *ConnectionImpl) void {
        const endpoint = self.endpoint;
        endpoint.lockPump();
        defer endpoint.unlockPump();
        const entry = self.entry;
        if (!entry.used) {
            endpoint.allocator.destroy(self);
            return;
        }
        entry.driver.close(endpoint.clockNow());
        endpoint.driveQuiescent() catch {};
        if (entry.driver.isDrained() or !endpoint.moveToDrain(entry)) {
            endpoint.reclaim(entry);
        }
        endpoint.allocator.destroy(self);
    }
    pub fn pubIo(self: *ConnectionImpl) std.Io {
        return self.endpoint.io_inst;
    }
    pub fn pubStats(self: *ConnectionImpl) tr.ConnectionStats {
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        if (!self.entry.used or self.entry.lost) return .{};
        const drv = self.entry.driver;
        return .{
            .smoothed_rtt_ns = drv.smoothedRttNsForTest(),
            .latest_rtt_ns = drv.latestRttNsForTest(),
            .path_mtu = drv.pathMtuForTest(),
            .congestion_window = drv.congestionWindowForTest(),
            .bytes_in_flight = drv.bytesInFlightForTest(),
            .congestion_controller = transportCongestionKind(drv.congestionKindForTest()),
            .app_limited_acks = drv.appLimitedAcksForTest(),
            .spurious_congestion_events = drv.spuriousCongestionEventsForTest(),
            .abandoned_recv_bytes = drv.abandonedRecvBytesForTest(),
        };
    }
};

pub fn connectionIsClosed(conn: tr.Connection) bool {
    const impl: *ConnectionImpl = conn.impl;
    impl.endpoint.lockPump();
    defer impl.endpoint.unlockPump();
    return !impl.entry.used or impl.entry.lost;
}

/// Queue FIN on a send stream without waiting for ACK (coop provide).
pub fn sendQueueFinish(send: tr.SendStream) tr.Error!void {
    const impl: *SendImpl = if (comptime product_flags.is_mono_noq) send.impl else @ptrCast(@alignCast(send.context));
    return impl.queueFinish();
}

/// One pump round; true when the queued FIN has been fully acknowledged.
pub fn sendPollFinishComplete(send: tr.SendStream) tr.Error!bool {
    const impl: *SendImpl = if (comptime product_flags.is_mono_noq) send.impl else @ptrCast(@alignCast(send.context));
    return impl.pollFinishComplete();
}

/// One pump round + hand off at most one ready peer bi-stream. Non-blocking
/// counterpart to `pubAcceptBi` for cooperative multi-connection adapters.
/// Locks `pump_mu` for the full pump + handoff — same boundary as `pubAcceptBi`.
pub fn connectionTryAcceptBi(conn: tr.Connection) tr.Error!?tr.BiStream {
    const impl: *ConnectionImpl = if (comptime product_flags.is_mono_noq) conn.impl else @ptrCast(@alignCast(conn.context));
    impl.endpoint.lockPump();
    defer impl.endpoint.unlockPump();
    if (!impl.entry.used or impl.entry.lost) return error.NotConnected;
    const outgoing = try impl.endpoint.pumpOutgoing();
    _ = try impl.endpoint.pumpIncomingAfter(outgoing);
    impl.endpoint.drainEvents(impl.entry);
    for (impl.entry.peer_streams[0..impl.entry.peer_stream_count]) |*ps| {
        if (ps.handed_off) continue;
        if (!isBidi(ps.id)) continue;
        ps.handed_off = true;
        const send = try impl.endpoint.sendFor(impl.entry, ps.id);
        const recv = try impl.endpoint.recvFor(impl.entry, ps.id);
        return .{ .send = .{ .impl = send }, .recv = .{ .impl = recv } };
    }
    return null;
}

pub fn connectionNextInboundUniEvent(conn: tr.Connection, buffer: []u8) tr.Error!?uni_poll.InboundUniEvent {
    if (buffer.len == 0) return null;
    const impl: *ConnectionImpl = conn.impl;
    impl.endpoint.lockPump();
    defer impl.endpoint.unlockPump();
    if (!impl.entry.used or impl.entry.lost) return error.NotConnected;

    const outgoing = try impl.endpoint.pumpOutgoing();
    _ = try impl.endpoint.pumpIncomingAfter(outgoing);
    impl.endpoint.drainEvents(impl.entry);

    if (impl.entry.popReset()) |stream_id| {
        return .{ .reset = stream_id };
    }

    const streams = impl.entry.peer_streams[0..impl.entry.peer_stream_count];
    if (streams.len == 0) return null;
    for (0..streams.len) |offset| {
        const index = (impl.next_stream_scan + offset) % streams.len;
        const ps = &impl.entry.peer_streams[index];
        if (ps.handed_off or isBidi(ps.id)) continue;

        impl.next_stream_scan = (index + 1) % streams.len;
        const available = impl.entry.driver.streamRecvBufferedLen(ps.id);
        if (available > 0) {
            const n = impl.entry.driver.readStreamInto(ps.id, buffer[0..@min(buffer.len, available)]);
            const fin = impl.entry.driver.streamRecvFin(ps.id) and impl.entry.driver.streamRecvBufferedLen(ps.id) == 0;
            if (fin) ps.handed_off = true;
            return .{ .chunk = .{
                .stream_id = ps.id,
                .bytes = buffer[0..n],
                .fin = fin,
            } };
        }
        if (impl.entry.driver.streamRecvFin(ps.id)) {
            ps.handed_off = true;
            return .{ .chunk = .{
                .stream_id = ps.id,
                .bytes = buffer[0..0],
                .fin = true,
            } };
        }
    }
    return null;
}

pub const DatagramError = tr.Error || error{
    DatagramTooLarge,
    DatagramUnsupported,
};

pub fn connectionSendDatagram(conn: tr.Connection, bytes: []const u8) DatagramError!void {
    const impl: *ConnectionImpl = conn.impl;
    impl.endpoint.lockPump();
    defer impl.endpoint.unlockPump();
    if (!impl.entry.used or impl.entry.lost) return error.NotConnected;
    impl.entry.driver.sendDatagram(bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.DatagramTooLarge => return error.DatagramTooLarge,
        error.DatagramUnavailable => return error.DatagramUnsupported,
        error.AlreadyClosed => return error.NotConnected,
        else => return error.ConnectionLost,
    };
    try impl.endpoint.pollOnceLocked();
}

pub fn connectionReadDatagram(conn: tr.Connection, buffer: []u8, timeout_ns: i64) DatagramError!?[]u8 {
    const impl: *ConnectionImpl = conn.impl;
    impl.endpoint.lockPump();
    defer impl.endpoint.unlockPump();
    const wait_ns = @max(timeout_ns, 0);
    const deadline = impl.endpoint.clockNow() + wait_ns;
    while (true) {
        if (!impl.entry.used or impl.entry.lost) return error.NotConnected;
        if (impl.entry.driver.recvDatagram()) |owned| {
            defer impl.endpoint.allocator.free(owned);
            if (owned.len > buffer.len) return error.DatagramTooLarge;
            @memcpy(buffer[0..owned.len], owned);
            return buffer[0..owned.len];
        }
        if (wait_ns == 0 or impl.endpoint.clockNow() >= deadline) return null;
        try impl.endpoint.pollOnceLocked();
    }
}

pub fn connectionMaxDatagramSize(conn: tr.Connection) ?usize {
    const impl: *ConnectionImpl = conn.impl;
    impl.endpoint.lockPump();
    defer impl.endpoint.unlockPump();
    if (!impl.entry.used or impl.entry.lost) return null;
    return impl.entry.driver.maxDatagramSize();
}

pub fn connectionSelectedPath(conn: tr.Connection) ?path_observability.SelectedPath {
    const impl: *ConnectionImpl = conn.impl;
    impl.endpoint.lockPump();
    defer impl.endpoint.unlockPump();
    if (!impl.entry.used or impl.entry.lost) return null;
    if (!impl.entry.magic_init) return null;
    const cand = impl.entry.magic.selectedPath() orelse return null;
    return path_observability.SelectedPath.fromMagicsockCandidate(cand);
}

fn wrapConn(impl: *ConnectionImpl) tr.Connection {
    return .{ .impl = impl };
}

fn endpointConnect(ctx: *anyopaque, peer: tr.NodeAddr) tr.Error!tr.Connection {
    const self: *Endpoint = @ptrCast(@alignCast(ctx));
    self.lockPump();
    defer self.unlockPump();
    const first_ip = peer.firstIpAddr();
    const relay_available = self.relay != null and peer.firstRelayUrl() != null;
    if (first_ip == null and !relay_available) return error.NotConnected;
    const ip = first_ip orelse magicsock.relayAddress();
    const relay_only = first_ip == null;

    var cid_bytes: [local_cid_len]u8 = undefined;
    self.io_inst.random(&cid_bytes);
    const scid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
    self.io_inst.random(&cid_bytes);
    const initial_dcid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
    var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
    self.io_inst.random(&seed_bytes);
    const sni = tls_name.serverName(peer.id);

    // E8: present a cached NEW_TOKEN in the first Initial (one-time use).
    const stored_token = self.takeStoredToken(&sni);
    defer if (stored_token.len != 0) self.allocator.free(@constCast(stored_token));

    const drv = quic_conn.Connection.create(self.allocator, .{
        .backend = self.tls_backend,
        .role = .client,
        .secret_key = self.secret,
        .peer_public_key = peer.id,
        .certificate_public_key = self.certificate_public_key_override,
        .certificate_der_override = self.certificate_der_override,
        .alpn = if (self.server_alpns.items.len > 0) self.server_alpns.items[0] else self.alpn,
        .server_name = &sni,
        .zigtls_resumption_ticket = if (crypto.zigtls_enabled) self.cachedZigtlsResumptionTicket(peer.id) else null,
        .zigtls_enable_early_data = self.zeroRttOnZigtls(),
        .zigtls_replay_filter = if (crypto.zigtls_enabled) &self.zigtls_replay_filter else null,
    }, scid, initial_dcid, initial_dcid, seed_bytes, .{
        .initial_token = stored_token,
        .reset_key = &self.reset_key,
        .congestion_kind = self.congestion_kind,
    }) catch return error.ConnectionLost;
    // G18: iroh heartbeat keep-alive (endpoint/quic.rs:156).
    drv.setKeepAliveIntervalNs(quic_conn.default_keep_alive_interval_ns);

    const handle = self.router.addConnection(.{
        .init_cid = scid,
        .side = .client,
        .local_cids = &.{scid},
        .initial_cids = &.{scid},
    }) catch {
        drv.destroy();
        return error.ConnectionLost;
    };

    const entry = self.freeEntry() orelse {
        self.router.removeConnection(handle) catch {};
        drv.destroy();
        return error.OutOfMemory;
    };
    entry.* = .{
        .used = true,
        .driver = drv,
        .handle = handle,
        .remote = ip,
        .role = .client,
        .remote_node = peer.id,
        .remote_node_set = true,
    };
    entry.magic = magicsock.State.init(self.allocator);
    entry.magic_init = true;
    entry.remote_node = peer.id;
    if (relay_available) {
        entry.magic.addRelayCandidate(0) catch {
            self.reclaim(entry);
            return error.ConnectionLost;
        };
        if (relay_only) {
            entry.magic.selectRelayFallback();
            entry.relay_selected = true;
        }
    }

    drv.startClient() catch {
        self.reclaim(entry);
        return error.ConnectionLost;
    };
    self.driveToConnected(entry) catch |err| {
        // B8: a client-side handshake failure owes the server its CRYPTO_ERROR
        // close too — flush before reclaiming, same as the accept loop.
        self.reclaimLost(entry);
        return err;
    };
    // The client reaches `connected` once it has 1-RTT keys, but the SERVER only
    // completes after it receives the client's final Handshake flight (Finished +
    // ACKs). Flush that flight now so a caller that blocks (e.g. awaiting accept)
    // does not deadlock the server's completion. (On a lossy path the stream
    // phase's pumping would also carry it; on loopback this flush suffices.)
    self.driveQuiescent() catch {};
    // A peer can reject the handshake (notably ALPN mismatch on noq-zigtls) in
    // the close flight immediately after the client reaches local 1-RTT. Surface
    // an observed close as a failed dial so public ConnectOptions.alpn_fallback
    // can try the next candidate instead of returning a connection that dies on
    // first use. Do not require client-side negotiatedProtocol() metadata here:
    // zigtls may not store an explicit selected ALPN on otherwise-valid client
    // handshakes, and the server-side preflight owns rejecting disallowed ALPNs
    // before it emits a misleading handshake flight.
    if (entry.lost) {
        self.reclaimLost(entry);
        return error.ConnectionLost;
    }
    self.cacheZigtlsTicket(entry);

    const remote_node = drv.tls.peerPublicKey() catch peer.id;
    const impl = self.allocator.create(ConnectionImpl) catch {
        self.reclaim(entry);
        return error.OutOfMemory;
    };
    impl.* = .{ .endpoint = self, .entry = entry, .remote = remote_node };
    impl.snapshotAlpn(entry);
    return wrapConn(impl);
}

fn endpointAccept(ctx: *anyopaque) tr.Error!tr.Connection {
    const self: *Endpoint = @ptrCast(@alignCast(ctx));
    self.lockPump();
    defer self.unlockPump();
    const deadline = self.clockNow() + handshake_timeout_ns;
    while (self.clockNow() < deadline) {
        const outgoing = try self.pumpOutgoing();
        _ = try self.pumpIncomingAfter(outgoing);
        for (&self.conns) |*e| {
            if (e.used and e.role == .server and e.connected and !e.handed_off) {
                e.handed_off = true;
                _ = try self.pumpOutgoing();
                const remote_node = e.driver.tls.peerPublicKey() catch return error.ConnectionLost;
                e.remote_node = remote_node;
                e.remote_node_set = true;
                const impl = self.allocator.create(ConnectionImpl) catch return error.OutOfMemory;
                impl.* = .{ .endpoint = self, .entry = e, .remote = remote_node };
                impl.snapshotAlpn(e);
                return wrapConn(impl);
            }
            if (e.used and e.role == .server and e.lost and !e.handed_off) {
                self.reclaimLost(e);
            }
        }
    }
    return error.Timeout;
}

fn transportCongestionKind(kind: congestion.Kind) tr.CongestionController {
    return switch (kind) {
        .new_reno => .new_reno,
        .cubic => .cubic,
        .bbr3 => .bbr3,
    };
}

// ── SendStream / RecvStream adapters (std.Io byte pipes over the driver) ──────

pub const SendFailure = enum { connection_lost, stream_reset, timeout };

pub const SendImpl = struct {
    used: bool = false,
    endpoint: *Endpoint = undefined,
    entry: *ConnEntry = undefined,
    stream_id: u64 = 0,
    writer_storage: std.Io.Writer = undefined,
    writer_buffer: [send_writer_buffer_len]u8 = undefined,
    write_failure: ?SendFailure = null,

    pub fn pubWriter(self: *SendImpl) *std.Io.Writer {
        return &self.writer_storage;
    }
    pub fn pubFlush(self: *SendImpl) tr.Error!void {
        // Flush first: writer drain → `queueSendBytes` self-locks `pump_mu`.
        // Holding the lock across flush would double-lock the non-recursive mutex.
        self.writer_storage.flush() catch return switch (self.write_failure orelse .connection_lost) {
            .connection_lost => error.ConnectionLost,
            .stream_reset => error.StreamReset,
            .timeout => error.Timeout,
        };
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        const outgoing = try self.endpoint.pumpOutgoing();
        _ = try self.endpoint.pumpIncomingAfter(outgoing);
    }
    pub fn pubFinish(self: *SendImpl) tr.Error!void {
        // Flush outside the lock (self-locks via `queueSendBytes`). Then
        // queue FIN under `pump_mu` once. Completion polls each take the lock
        // separately so we never double-lock the non-recursive mutex and never
        // starve other same-endpoint pump callers for the whole deadline.
        try self.queueFinish();
        const deadline = self.endpoint.clockNow() + self.endpoint.stream_timeout_ns;
        while (self.endpoint.clockNow() < deadline) {
            if (try self.pollFinishComplete()) return;
        }
        return error.Timeout;
    }

    /// Queue the stream FIN and pump once. Cooperative adapters poll
    /// `pollFinishComplete` instead of blocking in `pubFinish`.
    ///
    /// Locks `pump_mu` for the FIN + pump. Flush of buffered writer bytes is
    /// deliberately OUTSIDE the lock: `queueSendBytes` already self-locks, and
    /// `std.Io.Mutex` is non-recursive.
    pub fn queueFinish(self: *SendImpl) tr.Error!void {
        self.writer_storage.flush() catch return switch (self.write_failure orelse .connection_lost) {
            .connection_lost => error.ConnectionLost,
            .stream_reset => error.StreamReset,
            .timeout => error.Timeout,
        };
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        try self.queueFinishLocked();
    }

    /// Assumes writer is already flushed and `pump_mu` is held by the caller.
    fn queueFinishLocked(self: *SendImpl) tr.Error!void {
        self.entry.driver.writeStream(self.stream_id, &.{}, true) catch return error.ConnectionLost;
        const outgoing = try self.endpoint.pumpOutgoing();
        _ = try self.endpoint.pumpIncomingAfter(outgoing);
    }

    pub fn pollFinishComplete(self: *SendImpl) tr.Error!bool {
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        return self.pollFinishCompleteLocked();
    }

    /// Assumes `pump_mu` is held by the caller.
    fn pollFinishCompleteLocked(self: *SendImpl) tr.Error!bool {
        const outgoing = try self.endpoint.pumpOutgoing();
        _ = try self.endpoint.pumpIncomingAfter(outgoing);
        if (self.entry.driver.streamSendReset(self.stream_id)) return error.StreamReset;
        if (self.entry.lost) return error.ConnectionLost;
        if (self.entry.driver.streamSendComplete(self.stream_id)) {
            self.entry.driver.releaseStreamSendBuffer(self.stream_id);
            return true;
        }
        return false;
    }
    pub fn pubReset(self: *SendImpl) void {
        self.pubResetWithCode(0);
    }
    /// RESET_STREAM with application error code (peer-visible on the wire).
    pub fn pubResetWithCode(self: *SendImpl, code: u64) void {
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        if (!self.used) return;
        // First-writer-wins in the driver (reset_code set only when null).
        self.entry.driver.resetStream(self.stream_id, code) catch {};
        self.endpoint.driveQuiescent() catch {};
    }
    pub fn pubPendingFailure(self: *SendImpl) ?tr.Error {
        const failure = self.write_failure orelse return null;
        return switch (failure) {
            .connection_lost => error.ConnectionLost,
            .stream_reset => error.StreamReset,
            .timeout => error.Timeout,
        };
    }
    pub fn pubResetCode(self: *SendImpl) ?u64 {
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        if (!self.used) return null;
        return self.entry.driver.streamSendResetCode(self.stream_id);
    }
};

pub const RecvImpl = struct {
    used: bool = false,
    endpoint: *Endpoint = undefined,
    entry: *ConnEntry = undefined,
    stream_id: u64 = 0,
    reader_storage: std.Io.Reader = undefined,
    reader_buffer: [recv_reader_buffer_len]u8 = undefined,
    reader_ready: bool = false,
    finished: bool = false,

    pub fn pubReader(self: *RecvImpl) *std.Io.Reader {
        if (!self.reader_ready) {
            self.reader_storage = .{
                .vtable = &noq_reader_vtable,
                .buffer = self.reader_buffer[0..],
                .seek = 0,
                .end = 0,
            };
            self.reader_ready = true;
        }
        return &self.reader_storage;
    }
    pub fn pubStop(self: *RecvImpl) tr.Error!void {
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        if (!self.used) return error.NotConnected;
        self.entry.driver.stopStream(self.stream_id, 0) catch return error.ConnectionLost;
        const outgoing = try self.endpoint.pumpOutgoing();
        _ = try self.endpoint.pumpIncomingAfter(outgoing);
        self.finished = true;
    }
    pub fn pubResetCode(self: *RecvImpl) ?u64 {
        self.endpoint.lockPump();
        defer self.endpoint.unlockPump();
        if (!self.used) return null;
        return self.entry.driver.streamRecvResetCode(self.stream_id);
    }
};

fn queueSendBytes(send: *SendImpl, bytes: []const u8) std.Io.Writer.Error!void {
    send.endpoint.lockPump();
    defer send.endpoint.unlockPump();
    var offset: usize = 0;
    // Without this pump, a producer can enqueue an entire multi-hundred-MiB
    // stream before `finish`, so ACK-driven driver reclamation never has a
    // chance to bound peak storage.
    const deadline = send.endpoint.clockNow() + send.endpoint.stream_timeout_ns;
    while (offset < bytes.len) {
        var retained = send.entry.driver.streamSendBufferedLen(send.stream_id);
        while (retained >= send_buffer_high_water) {
            const outgoing = send.endpoint.pumpOutgoing() catch {
                send.write_failure = .connection_lost;
                return error.WriteFailed;
            };
            _ = send.endpoint.pumpIncomingAfter(outgoing) catch {
                send.write_failure = .connection_lost;
                return error.WriteFailed;
            };
            // Send-direction abort only — a peer RESET_STREAM on recv (common
            // after we STOP_SENDING an unused reverse half) must not fail writes.
            if (send.entry.driver.streamSendReset(send.stream_id)) {
                send.write_failure = .stream_reset;
                return error.WriteFailed;
            }
            if (send.entry.lost) {
                send.write_failure = .connection_lost;
                return error.WriteFailed;
            }
            if (send.endpoint.clockNow() >= deadline) {
                send.write_failure = .timeout;
                return error.WriteFailed;
            }
            retained = send.entry.driver.streamSendBufferedLen(send.stream_id);
            if (retained <= send_buffer_low_water) break;
        }
        const room = send_buffer_high_water - retained;
        const take = @min(room, bytes.len - offset);
        send.entry.driver.writeStream(send.stream_id, bytes[offset .. offset + take], false) catch {
            send.write_failure = .connection_lost;
            return error.WriteFailed;
        };
        offset += take;
    }
}

fn sendWriterDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    const send: *SendImpl = @alignCast(@fieldParentPtr("writer_storage", w));
    if (w.end > 0) {
        try queueSendBytes(send, w.buffer[0..w.end]);
        w.end = 0;
    }

    var consumed: usize = 0;
    for (data[0 .. data.len - 1]) |bytes| {
        try queueSendBytes(send, bytes);
        consumed += bytes.len;
    }
    const pattern = data[data.len - 1];
    var repeat: usize = 0;
    while (repeat < splat) : (repeat += 1) {
        try queueSendBytes(send, pattern);
        consumed += pattern.len;
    }
    return consumed;
}

fn sendWriterRebase(w: *std.Io.Writer, preserve: usize, minimum_len: usize) std.Io.Writer.Error!void {
    // `defaultRebase` asserts when a caller requests more contiguous writable
    // capacity than a fixed buffer can provide. Preserve standard Writer error
    // semantics for that case instead of turning a valid API request into a
    // process panic; ordinary Reader.stream paths request only a small slice.
    if (minimum_len > w.buffer.len -| preserve) return error.WriteFailed;
    return std.Io.Writer.defaultRebase(w, preserve, minimum_len);
}

const noq_send_writer_vtable: std.Io.Writer.VTable = .{
    .drain = sendWriterDrain,
    .rebase = sendWriterRebase,
};

fn recvReadInto(recv: *RecvImpl, dest: []u8) std.Io.Reader.Error!usize {
    if (dest.len == 0) return 0;
    recv.endpoint.lockPump();
    defer recv.endpoint.unlockPump();
    if (recv.finished) return error.EndOfStream;
    const deadline = recv.endpoint.clockNow() + recv.endpoint.stream_timeout_ns;
    while (recv.endpoint.clockNow() < deadline) {
        if (recv.entry.hasReset(recv.stream_id)) return error.ReadFailed;
        if (recv.entry.lost) return error.ReadFailed;

        const n = recv.entry.driver.readStreamInto(recv.stream_id, dest);
        if (n > 0) return n;
        if (recv.entry.driver.streamRecvFin(recv.stream_id) and recv.entry.driver.streamRecvBufferedLen(recv.stream_id) == 0) {
            recv.finished = true;
            return error.EndOfStream;
        }

        const outgoing = recv.endpoint.pumpOutgoing() catch return error.ReadFailed;
        _ = recv.endpoint.pumpIncomingAfter(outgoing) catch return error.ReadFailed;
    }
    return error.ReadFailed;
}

fn recvReaderStream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    const recv: *RecvImpl = @alignCast(@fieldParentPtr("reader_storage", r));
    const data = limit.slice(try w.writableSliceGreedy(1));
    const n = recvReadInto(recv, data) catch |err| switch (err) {
        error.ReadFailed => return error.ReadFailed,
        error.EndOfStream => return error.EndOfStream,
    };
    w.advance(n);
    return n;
}

const noq_reader_vtable: std.Io.Reader.VTable = .{
    .stream = recvReaderStream,
};

const EndpointPair = struct {
    client_conn: tr.Connection,
    server_conn: tr.Connection,
};

fn acceptEndpoint(server: *Endpoint) tr.Error!tr.Connection {
    return server.transport().accept();
}

fn establishEndpoints(client: *Endpoint, server: *Endpoint, server_pub: key.NodeId) !EndpointPair {
    const io = std.testing.io;
    var accept_future = io.async(acceptEndpoint, .{server});
    const client_conn = client.transport().connect(.{
        .id = server_pub,
        .addrs = &.{.{ .ip = server.localAddress() }},
    }) catch |err| {
        _ = accept_future.await(io) catch {};
        return err;
    };
    const server_conn = try accept_future.await(io);
    return .{ .client_conn = client_conn, .server_conn = server_conn };
}

// ── iroh-actor-style background pump: behavior gates ────────────────────────
// These prove the BEHAVIOR the inline-only pump cannot provide: an endpoint
// whose callers are ALL idle still sends/receives/times (ACKs land, FINs are
// acked, handshakes complete server-side without an accept call), and the
// pump work is shared under concurrency. Each opts in via
// `Options.background_pump`; the deterministic default stays inline-only.

fn backgroundPumpTlsBackend() crypto.Backend {
    return if (crypto.picotls_enabled) .picotls else .zigtls;
}

test "background pump: server handshake completes with no accept-side call" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-bg-pump-accept";

    const client_key = key.SecretKey.fromBytes([_]u8{0xB1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xB2} ** 32);

    // Server runs ONLY its background pump (no accept/pump call until the
    // probe below has already observed `connected`); the client stays
    // inline-only, so the discriminated side is exactly the server's
    // background driver.
    const server = try Endpoint.initOptions(allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
        .tls_backend = backgroundPumpTlsBackend(),
        .background_pump = true,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, alpn, .{
        .tls_backend = backgroundPumpTlsBackend(),
    });
    defer client.deinit();

    const client_conn = try client.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server.localAddress() }},
    });
    defer client_conn.close();

    // Read-only probe (never drives the pump): the server side reached
    // `connected` purely on its background pump.
    var polls: usize = 0;
    while (polls < 2000 and !server.serverConnectedForTest()) : (polls += 1) {
        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch {};
    }
    try std.testing.expect(server.serverConnectedForTest());

    // Hand-off then works even though no caller ever drove the handshake.
    const server_conn = (try server.tryAcceptReady()) orelse return error.TestUnexpectedResult;
    defer server_conn.close();
    try std.testing.expect(server_conn.remoteNodeId().eql(client_key.public()));
}

const background_pump_stream_bytes: usize = 256 * 1024;

fn backgroundPumpPatternByte(offset: usize, seed: u8) u8 {
    const x: u8 = @truncate(offset *% 31);
    return x +% seed;
}

/// Pattern seed derived from a NodeId so BOTH sides compute the same value
/// for the same conn no matter which accept worker receives which conn (the
/// endpoint accept order is first-connected-first-served, not dial order).
fn backgroundPumpSeed(node: key.NodeId) u8 {
    return node.toBytes()[0];
}

/// Per-stream seed offset keyed by the wire stream id, NOT by open/accept
/// order: the two client-opened bidi streams are ids 0 and 4, and under a
/// concurrent writer EITHER stream's first bytes can reach the server first,
/// so accept order is not a valid pairing discriminator (stream id is).
fn backgroundPumpStreamOffset(stream_id: u64) u8 {
    return if (stream_id == 0) 0 else 1;
}

fn backgroundPumpSendPattern(send: *SendImpl, seed: u8) tr.Error!void {
    var scratch: [16 * 1024]u8 = undefined;
    var offset: usize = 0;
    const writer = send.pubWriter();
    while (offset < background_pump_stream_bytes) {
        const n = @min(scratch.len, background_pump_stream_bytes - offset);
        for (scratch[0..n], 0..) |*b, i| {
            b.* = backgroundPumpPatternByte(offset + i, seed);
        }
        writer.writeAll(scratch[0..n]) catch return error.ConnectionLost;
        offset += n;
    }
    try send.pubFinish();
}

fn backgroundPumpRecvPattern(recv: *RecvImpl, seed: u8) !void {
    var scratch: [16 * 1024]u8 = undefined;
    var offset: usize = 0;
    const reader = recv.pubReader();
    while (offset < background_pump_stream_bytes) {
        const n = reader.readSliceShort(scratch[0..@min(scratch.len, background_pump_stream_bytes - offset)]) catch
            return error.TestUnexpectedResult;
        if (n == 0) return error.TestUnexpectedResult;
        for (scratch[0..n], 0..) |b, i| {
            if (b != backgroundPumpPatternByte(offset + i, seed)) return error.TestUnexpectedResult;
        }
        offset += n;
    }
    const eof = reader.readSliceShort(scratch[0..1]) catch return error.TestUnexpectedResult;
    if (eof != 0) return error.TestUnexpectedResult;
}

fn backgroundPumpClientConn(conn: tr.Connection, own_node: key.NodeId) tr.Error!void {
    const io = std.testing.io;
    const base = backgroundPumpSeed(own_node);
    const s1 = try conn.openBi();
    var w1 = io.async(backgroundPumpSendPattern, .{ s1.send.impl, base +% backgroundPumpStreamOffset(s1.send.impl.stream_id) });
    const s2 = try conn.openBi();
    const r2 = backgroundPumpSendPattern(s2.send.impl, base +% backgroundPumpStreamOffset(s2.send.impl.stream_id));
    // ALWAYS join the spawned writer before returning — a conn must not close
    // while a stream task still references its Send/Recv impls.
    const w1_res = w1.await(io);
    try w1_res;
    try r2;
}

fn backgroundPumpServerConn(conn: tr.Connection) tr.Error!void {
    const io = std.testing.io;
    const base = backgroundPumpSeed(conn.remoteNodeId());
    const s1 = try conn.acceptBi();
    var r1 = io.async(backgroundPumpRecvPattern, .{ s1.recv.impl, base +% backgroundPumpStreamOffset(s1.recv.impl.stream_id) });
    const s2 = try conn.acceptBi();
    const r2 = backgroundPumpRecvPattern(s2.recv.impl, base +% backgroundPumpStreamOffset(s2.recv.impl.stream_id));
    // ALWAYS join the spawned reader before returning (same lifecycle rule).
    r1.await(io) catch return error.ConnectionLost;
    r2 catch return error.ConnectionLost;
}

fn backgroundPumpServerWorker(server: *Endpoint) tr.Error!tr.Connection {
    const conn = try server.transport().accept();
    backgroundPumpServerConn(conn) catch |err| {
        conn.close();
        return err;
    };
    return conn;
}

test "background pump: concurrent conns/streams transfer byte-equal under the shared pump" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-bg-pump-concurrency";

    const client_a_key = key.SecretKey.fromBytes([_]u8{0xB3} ** 32);
    const client_b_key = key.SecretKey.fromBytes([_]u8{0xB4} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xB8} ** 32);

    // Concurrency-parity cell: TWO client endpoints dial one server; every
    // endpoint runs a background pump. Two streams per conn transfer
    // concurrently (all writer/reader workers in flight at once), and the
    // server's ONE background pump is shared by both conns under pump_mu —
    // the load shape inline-only pumping cannot honestly serve. (Two conns
    // need two client endpoints: noq routes by four-tuple, so one socket
    // owns at most one conn per peer.)
    const server = try Endpoint.initOptions(allocator, io, server_key, alpn, .{
        .accept_unknown_peer = true,
        .tls_backend = backgroundPumpTlsBackend(),
        .background_pump = true,
    });
    defer server.deinit();
    const client_a = try Endpoint.initOptions(allocator, io, client_a_key, alpn, .{
        .tls_backend = backgroundPumpTlsBackend(),
        .background_pump = true,
    });
    defer client_a.deinit();
    const client_b = try Endpoint.initOptions(allocator, io, client_b_key, alpn, .{
        .tls_backend = backgroundPumpTlsBackend(),
        .background_pump = true,
    });
    defer client_b.deinit();

    var server_w1 = io.async(backgroundPumpServerWorker, .{server});
    var server_w2 = io.async(backgroundPumpServerWorker, .{server});

    const conn_a = try client_a.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server.localAddress() }},
    });
    const conn_b = try client_b.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server.localAddress() }},
    });

    var c_a = io.async(backgroundPumpClientConn, .{ conn_a, client_a_key.public() });
    var c_b = io.async(backgroundPumpClientConn, .{ conn_b, client_b_key.public() });

    const r_a = c_a.await(io);
    const r_b = c_b.await(io);
    const sc1 = server_w1.await(io);
    const sc2 = server_w2.await(io);
    try r_a;
    try r_b;
    const server_conn1 = try sc1;
    const server_conn2 = try sc2;

    conn_a.close();
    conn_b.close();
    server_conn1.close();
    server_conn2.close();

    var wait: usize = 0;
    while (wait < 2000 and (client_a.liveConnectionCount() > 0 or client_b.liveConnectionCount() > 0 or server.liveConnectionCount() > 0)) : (wait += 1) {
        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch {};
    }
    try std.testing.expectEqual(@as(usize, 0), client_a.liveConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), client_b.liveConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), server.liveConnectionCount());
}

test "background pump: FIN is acked while both endpoints' callers stay idle" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const client_key = key.SecretKey.fromBytes([_]u8{0xB5} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xB6} ** 32);

    // TREATMENT: background pumps ON. queueFinish pumps the FIN flight out
    // once; after that NO caller touches either endpoint. Reaching
    // streamSendComplete requires the server pump to receive+ACK and the
    // client pump to ingest the ACK — both from the background loops alone.
    const server = try Endpoint.initOptions(allocator, io, server_key, "iroh-noq-bg-pump-ack", .{
        .expected_peer = client_key.public(),
        .tls_backend = backgroundPumpTlsBackend(),
        .background_pump = true,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, "iroh-noq-bg-pump-ack", .{
        .tls_backend = backgroundPumpTlsBackend(),
        .background_pump = true,
    });
    defer client.deinit();

    const pair = try establishEndpoints(client, server, server_key.public());
    defer pair.server_conn.close();
    defer pair.client_conn.close();

    const payload = "background-pump-ingress-independence";
    const stream = try pair.client_conn.openBi();
    const stream_id = stream.send.impl.stream_id;
    try stream.send.writer().writeAll(payload);
    try stream.send.impl.queueFinish();

    // Discriminator = SERVER-SIDE INGRESS. `streamSendComplete` flips once the
    // FIN is merely SENT, so it would pass with no pump at all. Buffered
    // receive bytes on the server require a real receive+decrypt — i.e. the
    // server's pump actually ran while NO caller touched the server. The
    // client endpoint is likewise idle after queueFinish, so nothing drives
    // either side except the two background loops.
    var arrived: usize = 0;
    for (0..1000) |_| {
        arrived = server.testStreamRecvBuffered(.server, stream_id) orelse 0;
        if (arrived >= payload.len) break;
        std.Io.sleep(io, .fromMilliseconds(5), .awake) catch {};
    }
    try std.testing.expect(arrived >= payload.len);
}

test "background pump: control — server never ingests bytes when no pump runs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const client_key = key.SecretKey.fromBytes([_]u8{0xB5} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xB6} ** 32);

    // CONTROL (isolated from the treatment test): pumps OFF everywhere. After
    // queueFinish's single inline pump there is no driver anywhere, so the
    // server MUST show zero buffered ingress for the whole window — the
    // discriminator in the treatment test is the pump task, not the wait.
    const server_ctl = try Endpoint.initOptions(allocator, io, server_key, "iroh-noq-bg-pump-ack-ctl", .{
        .expected_peer = client_key.public(),
        .tls_backend = backgroundPumpTlsBackend(),
    });
    defer server_ctl.deinit();
    const client_ctl = try Endpoint.initOptions(allocator, io, client_key, "iroh-noq-bg-pump-ack-ctl", .{
        .tls_backend = backgroundPumpTlsBackend(),
    });
    defer client_ctl.deinit();

    const ctl = try establishEndpoints(client_ctl, server_ctl, server_key.public());
    defer ctl.server_conn.close();
    defer ctl.client_conn.close();

    const ctl_stream = try ctl.client_conn.openBi();
    const ctl_stream_id = ctl_stream.send.impl.stream_id;
    try ctl_stream.send.writer().writeAll("control-no-pump");
    try ctl_stream.send.impl.queueFinish();

    std.Io.sleep(io, .fromMilliseconds(300), .awake) catch {};
    const arrived = server_ctl.testStreamRecvBuffered(.server, ctl_stream_id) orelse 0;
    try std.testing.expectEqual(@as(usize, 0), arrived);
}

test "background pump: deinit joins an idle background pump cleanly" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0xB7} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "iroh-noq-bg-pump-deinit", .{
        .tls_backend = backgroundPumpTlsBackend(),
        .background_pump = true,
    });
    // A hang here (test timeout) is the failure signal: deinit must set the
    // stop flag and join the loop at its next bounded round boundary.
    endpoint.deinit();
}

fn waitForCachedProtectedZigtlsTicket(client: *Endpoint, server: *Endpoint, peer: key.NodeId) !void {
    const io = std.testing.io;
    const started_ns = std.Io.Clock.now(.awake, io).nanoseconds;
    const limit_ns: i64 = handshake_timeout_ns;
    while (true) {
        try server.pumpForTest();
        try client.pumpForTest();
        if (client.zigtls_cached_ticket) |*cached| {
            if (cached.peer.eql(peer)) {
                const resumption_ticket = cached.info.asResumptionTicket() orelse return error.TestUnexpectedResult;
                const ticket_keys = zigtls.tls13.ticket_keys;
                try std.testing.expect(resumption_ticket.ticket.len >= ticket_keys.protected_ticket_overhead);
                try std.testing.expectEqual(ticket_keys.protected_ticket_version, resumption_ticket.ticket[0]);
                var opened = try server.zigtls_ticket_key_manager.unprotect(
                    std.testing.allocator,
                    std.Io.Clock.real.now(io).toSeconds(),
                    resumption_ticket.ticket,
                    "zigtls tls13 resumption ticket v1",
                );
                defer opened.deinit(std.testing.allocator);
                try std.testing.expect(opened.plaintext.len > 0);
                return;
            }
        }
        const now_ns = std.Io.Clock.now(.awake, io).nanoseconds;
        if (now_ns - started_ns >= limit_ns) return error.Timeout;
        io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
}

test "Zig-noq <-> Zig-noq zigtls real-socket endpoint caches protected NST and resumes same-peer session" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-zigtls-resumption";

    const client_key = key.SecretKey.fromBytes([_]u8{0xD1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xD2} ** 32);

    const server = try Endpoint.initOptions(allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
        .tls_backend = .zigtls,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, alpn, .{
        .tls_backend = .zigtls,
    });
    defer client.deinit();

    try std.testing.expectEqual(Engine.noq, Endpoint.engine);
    try std.testing.expectEqual(crypto.Backend.zigtls, client.tlsBackend());
    try std.testing.expectEqual(crypto.Backend.zigtls, server.tlsBackend());

    const first = try establishEndpoints(client, server, server_key.public());
    try std.testing.expect(first.client_conn.remoteNodeId().eql(server_key.public()));
    try std.testing.expect(first.server_conn.remoteNodeId().eql(client_key.public()));
    try std.testing.expect(!client.testDriver(.client).?.wasZigtlsResumed());
    try std.testing.expect(!server.testDriver(.server).?.wasZigtlsResumed());

    try waitForCachedProtectedZigtlsTicket(client, server, server_key.public());

    first.client_conn.close();
    var observed_close = false;
    var close_polls: usize = 0;
    while (close_polls < 500 and !observed_close) : (close_polls += 1) {
        try server.pumpForTest();
        observed_close = server.serverObservedClose();
    }
    try std.testing.expect(observed_close);
    first.server_conn.close();
    try std.testing.expectEqual(@as(usize, 0), client.liveConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), server.liveConnectionCount());

    const second = try establishEndpoints(client, server, server_key.public());
    defer second.client_conn.close();
    defer second.server_conn.close();
    try std.testing.expect(second.client_conn.remoteNodeId().eql(server_key.public()));
    try std.testing.expect(second.server_conn.remoteNodeId().eql(client_key.public()));

    const second_client_driver = client.testDriver(.client) orelse return error.TestUnexpectedResult;
    const second_server_driver = server.testDriver(.server) orelse return error.TestUnexpectedResult;
    try std.testing.expect(second_client_driver.wasZigtlsResumed());
    try std.testing.expect(second_server_driver.wasZigtlsResumed());
}

test "zigtls 0-RTT: resumption still resumes and the client offers early data" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-zigtls-0rtt-resume";

    const client_key = key.SecretKey.fromBytes([_]u8{0xE3} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xE4} ** 32);

    const server = try Endpoint.initOptions(allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
        .tls_backend = .zigtls,
        .zero_rtt = true,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, alpn, .{
        .tls_backend = .zigtls,
        .zero_rtt = true,
    });
    defer client.deinit();

    const first = try establishEndpoints(client, server, server_key.public());
    try waitForCachedProtectedZigtlsTicket(client, server, server_key.public());
    first.client_conn.close();
    var close_polls: usize = 0;
    while (close_polls < 500 and !server.serverObservedClose()) : (close_polls += 1) {
        try server.pumpForTest();
    }
    first.server_conn.close();
    try std.testing.expectEqual(@as(usize, 0), client.liveConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), server.liveConnectionCount());

    // conn 2 with the cached ticket: resumption MUST still negotiate and the
    // client MUST offer 0-RTT (early write keys live before completion).
    const zero_conn = (try client.connectZeroRttForTest(server_key.public(), server.localAddress())) orelse
        return error.TestUnexpectedResult;
    defer zero_conn.close();
    const c2 = client.testDriver(.client) orelse return error.TestUnexpectedResult;
    // The offer (early write keys) is live immediately after the ClientHello.
    try std.testing.expect(c2.zero_rtt_offered);
    try std.testing.expect(c2.zeroRttSendActive());
    // Drive the server side until the resumption is confirmed.
    var polls: usize = 0;
    while (polls < 2000 and !c2.wasZigtlsResumed()) : (polls += 1) {
        try client.pumpForTest();
        try server.pumpForTest();
    }
    try std.testing.expect(c2.wasZigtlsResumed());
    const s2 = server.testDriver(.server) orelse return error.TestUnexpectedResult;
    try std.testing.expect(s2.wasZigtlsResumed());
}

test "zigtls 0-RTT: live early bytes delivered pre-1-RTT and replayed flight refused" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-zigtls-0rtt-live";

    const client_key = key.SecretKey.fromBytes([_]u8{0xE5} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xE6} ** 32);

    const server = try Endpoint.initOptions(allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
        .tls_backend = .zigtls,
        .zero_rtt = true,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, alpn, .{
        .tls_backend = .zigtls,
        .zero_rtt = true,
    });
    defer client.deinit();

    // conn 1: cache a 0-RTT ticket.
    const first = try establishEndpoints(client, server, server_key.public());
    try waitForCachedProtectedZigtlsTicket(client, server, server_key.public());
    first.client_conn.close();
    var close_polls: usize = 0;
    while (close_polls < 500 and !server.serverObservedClose()) : (close_polls += 1) {
        try server.pumpForTest();
    }
    first.server_conn.close();
    try std.testing.expectEqual(@as(usize, 0), client.liveConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), server.liveConnectionCount());

    // Pin conn 1's ticket identity so BOTH the accept leg (conn 2) and the
    // anti-replay leg (conn 3) present the SAME ticket.
    const pinned = (try client.dupCachedResumptionTicketForTest(allocator, server_key.public())) orelse
        return error.TestUnexpectedResult;
    defer Endpoint.freeDupResumptionTicket(allocator, pinned);

    // conn 2: offer + send early bytes, server accepts pre-1-RTT.
    const zero_conn = (try client.connectZeroRttWithTicketForTest(server_key.public(), server.localAddress(), pinned)) orelse
        return error.TestUnexpectedResult;
    // Closed explicitly in the teardown below (before the replay leg) so the
    // slot reclaims — no scoped defer (it would double-close).
    const c2 = client.testDriver(.client) orelse return error.TestUnexpectedResult;
    try std.testing.expect(c2.zeroRttSendActive());

    const payload = "live-0rtt-early-bytes";
    const stream = try c2.openStream(.bidi);
    try c2.writeStream(stream, payload, true);

    // Drive until the server ACCEPTS the 0-RTT flight and has the early bytes,
    // then keep driving until BOTH sides finish the handshake (client learns
    // the accept verdict from EncryptedExtensions and completes).
    const early_payload_len: u64 = payload.len;
    var polls: usize = 0;
    var server_accepted = false;
    while (polls < 6000) : (polls += 1) {
        try client.pumpForTest();
        try server.pumpForTest();
        const sd = server.testDriver(.server) orelse break;
        if (!server_accepted and sd.zeroRttAcceptedServer() and sd.zeroRttStats().payload_bytes_received >= early_payload_len) {
            server_accepted = true;
        }
        if (server_accepted and sd.state == .established and c2.state == .established) break;
    }
    const c2_stats = c2.zeroRttStats();
    const sd = server.testDriver(.server) orelse return error.TestUnexpectedResult;
    const s2_stats = sd.zeroRttStats();
    try std.testing.expect(c2_stats.packets_sent > 0); // client sent 0-RTT packets
    try std.testing.expect(server_accepted); // server accepted before 1-RTT
    try std.testing.expect(s2_stats.packets_accepted > 0);
    var got: [64]u8 = undefined;
    const n = sd.readStreamInto(stream, &got);
    try std.testing.expectEqual(payload.len, n);
    try std.testing.expectEqualSlices(u8, payload, got[0..n]);
    try std.testing.expect(c2.wasZigtlsResumed());
    try std.testing.expect(sd.wasZigtlsResumed());
    try std.testing.expect(c2.zeroRttAcceptedClient()); // client saw the EE accept

    // Take ownership of conn 2's server entry (early accept) and close BOTH
    // ends so the slot reclaims before the replay leg mints conn 3 — otherwise
    // testDriver returns conn 2's stale server entry.
    if (try server.tryAcceptReadyZeroRttForTest()) |sc2| sc2.close();
    zero_conn.close();
    var tp: usize = 0;
    while (tp < 4000 and (client.liveConnectionCount() > 0 or server.liveConnectionCount() > 0)) : (tp += 1) {
        try client.pumpForTest();
        try server.pumpForTest();
    }

    // Replay the SAME conn-1 ticket (already struck by conn 2's acceptance).
    const replay_conn = (try client.connectZeroRttWithTicketForTest(server_key.public(), server.localAddress(), pinned)) orelse
        return error.TestUnexpectedResult;
    defer replay_conn.close();
    const rc = client.testDriver(.client) orelse return error.TestUnexpectedResult;
    try std.testing.expect(rc.zero_rtt_offered); // client does offer again
    const rstream = try rc.openStream(.bidi);
    try rc.writeStream(rstream, "replayed-flight", true);

    var rp: usize = 0;
    var replay_accepted = false;
    while (rp < 6000) : (rp += 1) {
        try client.pumpForTest();
        try server.pumpForTest();
        const rsd = server.testDriver(.server) orelse break;
        if (rsd.zeroRttAcceptedServer() and rsd.zeroRttStats().payload_bytes_received > 0) {
            replay_accepted = true;
            break;
        }
        if (rsd.state == .established) break;
    }
    try std.testing.expect(!replay_accepted); // anti-replay: second use refused
}

var test_mutated_zero_rtt_packets: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

fn mutateFirstZeroRttDatagramForTest(_: usize, bytes: []u8) void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const header = packet.decodeProtectedLongHeader(bytes[offset..], true) catch return;
        if (header.long_type == .zero_rtt) {
            if (header.packet_end > 0 and offset + header.packet_end <= bytes.len) {
                bytes[offset + header.packet_end - 1] ^= 0x01;
                _ = test_mutated_zero_rtt_packets.fetchAdd(1, .acq_rel);
            }
            return;
        }
        if (header.packet_end == 0 or offset + header.packet_end > bytes.len) return;
        offset += header.packet_end;
    }
}

test "zigtls 0-RTT: mutated early-data packet is rejected fail-closed" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-zigtls-0rtt-mutated";

    const client_key = key.SecretKey.fromBytes([_]u8{0xE7} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xE8} ** 32);

    const server = try Endpoint.initOptions(allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
        .tls_backend = .zigtls,
        .zero_rtt = true,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, alpn, .{
        .tls_backend = .zigtls,
        .zero_rtt = true,
    });
    defer client.deinit();

    // conn 1: cache a 0-RTT-capable protected ticket.
    const first = try establishEndpoints(client, server, server_key.public());
    try waitForCachedProtectedZigtlsTicket(client, server, server_key.public());
    first.client_conn.close();
    var close_polls: usize = 0;
    while (close_polls < 500 and !server.serverObservedClose()) : (close_polls += 1) {
        try server.pumpForTest();
    }
    first.server_conn.close();
    try std.testing.expectEqual(@as(usize, 0), client.liveConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), server.liveConnectionCount());

    test_mutated_zero_rtt_packets.store(0, .release);
    client.setTestMutate(mutateFirstZeroRttDatagramForTest);
    defer client.setTestMutate(null);

    const zero_conn = (try client.connectZeroRttForTest(server_key.public(), server.localAddress())) orelse
        return error.TestUnexpectedResult;
    defer zero_conn.close();
    const c2 = client.testDriver(.client) orelse return error.TestUnexpectedResult;
    try std.testing.expect(c2.zeroRttSendActive());

    const stream = try c2.openStream(.bidi);
    try c2.writeStream(stream, "mutated-early-data", true);

    var polls: usize = 0;
    var early_delivered = false;
    while (polls < 6000) : (polls += 1) {
        try client.pumpForTest();
        try server.pumpForTest();
        if (server.testDriver(.server)) |sd| {
            if (sd.zeroRttAcceptedServer() and sd.zeroRttStats().payload_bytes_received > 0) {
                early_delivered = true;
                break;
            }
            if (sd.state == .established and c2.state == .established) break;
        }
        if (server.serverHandshakeRejected()) break;
    }
    try std.testing.expect(test_mutated_zero_rtt_packets.load(.acquire) > 0);
    try std.testing.expect(!early_delivered);
}

test "E11: first-flight saturation beyond the conn-table cap drops silently, pump stays live" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0x93} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "e11-saturation-test", .{ .accept_unknown_peer = true });
    defer endpoint.deinit();

    // Drive the PRODUCTION route() mint path with valid first-flight Initials
    // from distinct remotes. The table holds max_conns; everything beyond is
    // the noq `max_incoming` saturation case — dropped, never a pump error.
    var minted: usize = 0;
    var i: u16 = 0;
    while (i < max_conns + 4) : (i += 1) {
        const remote = try net.IpAddress.parse("127.0.0.1", 49200 + i);
        const four: router_mod.FourTuple = .{ .local = toSockAddr(endpoint.localAddress()), .remote = toSockAddr(remote) };
        var dst_bytes: [local_cid_len]u8 = undefined;
        std.mem.writeInt(u64, &dst_bytes, 0xD100 + @as(u64, i), .big);
        const dst_cid = try packet.ConnectionId.init(&dst_bytes);
        const src_bytes = [_]u8{0xc1} ** local_cid_len;
        const src_cid = try packet.ConnectionId.init(&src_bytes);
        var initial: [1200]u8 = .{0} ** 1200;
        _ = try (packet.InitialHeader{
            .version = 1,
            .dst_cid = dst_cid,
            .src_cid = src_cid,
            .packet_number = .{ .value = 0, .len = 1 },
        }).encode(&initial);
        if ((try endpoint.route(four, &initial, remote)) != null) minted += 1;
    }
    try std.testing.expectEqual(@as(usize, max_conns), minted);
    try std.testing.expectEqual(@as(u64, 4), endpoint.stats_incoming_saturation_drops);
    // The pump stays live after saturation (no OutOfMemory cascade).
    try endpoint.pollOnce();
    try std.testing.expectEqual(@as(u64, 4), endpoint.stats_incoming_saturation_drops);
}

test "mid-handshake — a CLIENT re-points on the server's address change; a server NEVER switches (noq parity)" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0x94} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "h10-relay-race-test", .{ .accept_unknown_peer = true });
    defer endpoint.deinit();

    const remote_a = try net.IpAddress.parse("127.0.0.1", 49300);
    const remote_b = try net.IpAddress.parse("127.0.0.1", 49301);
    const four_a: router_mod.FourTuple = .{ .local = toSockAddr(endpoint.localAddress()), .remote = toSockAddr(remote_a) };
    const dst_bytes = [_]u8{0xd2} ** local_cid_len;
    const src_bytes = [_]u8{0xc2} ** local_cid_len;
    const dst_cid = try packet.ConnectionId.init(&dst_bytes);
    const src_cid = try packet.ConnectionId.init(&src_bytes);
    var initial: [1200]u8 = .{0} ** 1200;
    _ = try (packet.InitialHeader{
        .version = 1,
        .dst_cid = dst_cid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
    }).encode(&initial);

    // A minted SERVER conn mid-handshake: an off-path packet moves NOTHING
    // (noq drops mid-handshake off-path packets, mod.rs:2316-2347).
    const server_entry = (try endpoint.route(four_a, &initial, remote_a)) orelse return error.UnexpectedState;
    try std.testing.expect(!server_entry.connected);
    endpoint.maybeNoteMigration(server_entry, remote_b, true);
    try std.testing.expect(ipEql(server_entry.remote, remote_a));
    try std.testing.expect(!server_entry.migration_pending);

    // A CLIENT conn mid-handshake: an authenticated packet from the server's
    // new address re-points the reply path (the relay-race case iroh sets true).
    const client_entry = endpoint.freeEntry() orelse return error.UnexpectedState;
    client_entry.* = .{ .used = true, .remote = remote_a, .role = .client, .connected = false, .driver = server_entry.driver };
    defer {
        client_entry.driver = undefined;
        client_entry.used = false;
    }
    endpoint.maybeNoteMigration(client_entry, remote_b, true);
    try std.testing.expect(ipEql(client_entry.remote, remote_b));
    try std.testing.expect(!client_entry.migration_pending);

    // ...but NOT on an unauthenticated one (version≠1 garbage is not proof).
    client_entry.remote = remote_a;
    endpoint.maybeNoteMigration(client_entry, remote_b, false);
    try std.testing.expect(ipEql(client_entry.remote, remote_a));

    // After confirmation the client-side branch closes too — the validated
    // path takes over (the two branches never cross).
    client_entry.driver.handshake_confirmed = true;
    client_entry.connected = true;
    const remote_c = try net.IpAddress.parse("127.0.0.1", 49302);
    endpoint.maybeNoteMigration(client_entry, remote_c, true);
    try std.testing.expect(client_entry.migration_pending);
    try std.testing.expect(ipEql(client_entry.remote, remote_a));
}

test "H8: the PRODUCTION pump drives the NAT probe retry ladder (queueRetries/retryDelay live)" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0x96} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "h8-nat-retry-pump", .{ .accept_unknown_peer = true });
    defer endpoint.deinit();

    // Mint a REAL server conn (live driver) through the production route() path.
    const remote = try net.IpAddress.parse("127.0.0.1", 49310);
    const four: router_mod.FourTuple = .{ .local = toSockAddr(endpoint.localAddress()), .remote = toSockAddr(remote) };
    const dst_bytes = [_]u8{0xd3} ** local_cid_len;
    const src_bytes = [_]u8{0xc3} ** local_cid_len;
    const dst_cid = try packet.ConnectionId.init(&dst_bytes);
    const src_cid = try packet.ConnectionId.init(&src_bytes);
    var initial: [1200]u8 = .{0} ** 1200;
    _ = try (packet.InitialHeader{
        .version = 1,
        .dst_cid = dst_cid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
    }).encode(&initial);
    const entry = (try endpoint.route(four, &initial, remote)) orelse return error.UnexpectedState;
    try std.testing.expect(entry.magic_init);

    // Server-side production trigger: the peer's REACH_OUT n0 frame activates
    // the candidate and queues a probe (the .nat_address -> handleFrame path).
    // This test never calls probeCandidates, so any recorded probe token can
    // only have come from the queued-probe path driveNatRetries drains.
    const cand = try net.IpAddress.parse("127.0.0.1", 49311);
    try entry.magic.handleFrame(.{ .ipv4_address = .{
        .frame_type = .reach_out_at_ipv4,
        .seq = 1,
        .ip = cand.ip4.bytes,
        .port = cand.ip4.port,
    } });

    // Pump 1: the PRODUCTION pump emits the queued probe against the
    // candidate's address and arms the backoff deadline from retryDelay.
    _ = try endpoint.pumpOutgoing();
    try std.testing.expectEqual(@as(usize, 1), entry.probe_count);
    try std.testing.expect(ipEql(entry.probes[0].addr, cand));
    const armed = entry.next_nat_retry_ns orelse return error.UnexpectedState;
    try std.testing.expect(armed > 0);
    // The armed deadline participates in the pump's receive wait: a past
    // deadline forces an immediate wake (no starvation behind the 1 ms poll).
    entry.next_nat_retry_ns = 0;
    switch (endpoint.receiveTimeout(false)) {
        .duration => |d| try std.testing.expectEqual(@as(i96, 0), d.raw.nanoseconds),
        else => return error.UnexpectedState,
    }

    // The full backoff ladder: each deadline expiry makes the pump
    // queueRetries (retiring the round's probe tokens), and the NEXT pump
    // cycle re-emits the re-queued probe — 1 initial + 8 retries = 9 probes.
    var round: u8 = 1;
    while (round <= magicsock.MAX_NAT_PROBE_ATTEMPTS - 1) : (round += 1) {
        entry.next_nat_retry_ns = 0; // deadline reached
        _ = try endpoint.pumpOutgoing(); // queueRetries fires here
        try std.testing.expectEqual(@as(u8, round), entry.magic.attempt);
        try std.testing.expectEqual(@as(usize, 0), entry.probe_count);
        _ = try endpoint.pumpOutgoing(); // the re-queued probe emits here
        try std.testing.expectEqual(@as(usize, 1), entry.probe_count);
        try std.testing.expect(ipEql(entry.probes[0].addr, cand));
    }
    // The 9th probe exhausted the attempts: the candidate is failed, the
    // ladder stops (retryDelay null), and the deadline cleared — no retry storm.
    try std.testing.expect(entry.next_nat_retry_ns == null);
    try std.testing.expect(entry.magic.retryDelay() == null);
    try std.testing.expectEqual(magicsock.ProbeState.failed, entry.magic.remote_candidates.items[0].state);
}

test "F9 unknown short CID does not use known-remote fallback" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0x91} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "f9-router-test", .{});
    defer endpoint.deinit();

    const remote = try net.IpAddress.parse("127.0.0.1", 49191);
    const four: router_mod.FourTuple = .{
        .local = toSockAddr(endpoint.localAddress()),
        .remote = toSockAddr(remote),
    };
    endpoint.conns[0] = .{ .used = true, .remote = remote };
    defer endpoint.conns[0].used = false;
    try std.testing.expect(endpoint.entryByRemote(remote) != null);

    var datagram: [1 + local_cid_len + 1]u8 = undefined;
    datagram[0] = packet.fixed_bit;
    @memset(datagram[1 .. 1 + local_cid_len], 0xa5);
    datagram[datagram.len - 1] = 0;
    try std.testing.expect((try endpoint.route(four, &datagram, remote)) == null);
}

test "F9 minted server registers fresh local CID before publication" {
    // Exercises the picotls-default endpoint mint path; skip when picotls is
    // compiled out (noq-zigtls).
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0x92} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "f9-server-mint-test", .{ .accept_unknown_peer = true });
    defer endpoint.deinit();

    const remote = try net.IpAddress.parse("127.0.0.1", 49192);
    const four: router_mod.FourTuple = .{
        .local = toSockAddr(endpoint.localAddress()),
        .remote = toSockAddr(remote),
    };
    const dst_bytes = [_]u8{0xd1} ** local_cid_len;
    const src_bytes = [_]u8{0xc1} ** local_cid_len;
    const dst_cid = try packet.ConnectionId.init(&dst_bytes);
    const src_cid = try packet.ConnectionId.init(&src_bytes);
    var initial: [1200]u8 = .{0} ** 1200;
    _ = try (packet.InitialHeader{
        .version = 1,
        .dst_cid = dst_cid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
    }).encode(&initial);

    const first = try endpoint.router.handleFirstPacket(four, &initial);
    const handle = switch (first) {
        .new_connection => |h| h,
        .routed => return error.UnexpectedRoute,
        .version_negotiation => |vn| {
            allocator.free(vn);
            return error.UnexpectedVersionNegotiation;
        },
        .initial_close => |close| {
            allocator.free(close);
            return error.UnexpectedInitialClose;
        },
    };
    const entry = (try endpoint.mintServerConn(handle, &initial, remote, .{})) orelse return error.UnexpectedState;
    const fresh_cid = entry.driver.local_cid;
    try std.testing.expectEqual(@as(u8, local_cid_len), fresh_cid.len);

    var short: [1 + local_cid_len + 1]u8 = undefined;
    short[0] = packet.fixed_bit;
    @memcpy(short[1 .. 1 + local_cid_len], fresh_cid.slice());
    short[short.len - 1] = 0;
    const routed = (try endpoint.route(four, &short, remote)) orelse return error.UnexpectedRoute;
    try std.testing.expect(routed == entry);
}

test "production pump registers dynamic local CID before publication" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0x93} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "dynamic-cid-router-test", .{});
    defer endpoint.deinit();

    const remote = try net.IpAddress.parse("127.0.0.1", 49193);
    const local_bytes = [_]u8{0x71} ** local_cid_len;
    const remote_bytes = [_]u8{0x72} ** local_cid_len;
    const local_cid = try packet.ConnectionId.init(&local_bytes);
    const remote_cid = try packet.ConnectionId.init(&remote_bytes);
    var test_seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = .{0} ** std.Random.DefaultCsprng.secret_seed_length;
    test_seed[0] = 0x93;
    const driver = try quic_conn.Connection.create(allocator, .{
        .role = .client,
        .secret_key = secret,
        .peer_public_key = secret.public(),
        .alpn = "dynamic-cid-router-test",
    }, local_cid, remote_cid, remote_cid, test_seed, .{});
    errdefer driver.destroy();

    const handle = try endpoint.router.addConnection(.{
        .init_cid = local_cid,
        .side = .client,
        .local_cids = &.{local_cid},
        .initial_cids = &.{local_cid},
    });
    errdefer endpoint.router.removeConnection(handle) catch {};
    endpoint.conns[0] = .{
        .used = true,
        .driver = driver,
        .handle = handle,
        .remote = remote,
        .role = .client,
    };

    const data_index = @intFromEnum(@import("spaces.zig").SpaceId.data);
    const packet_keys = @import("packet_crypto.zig").PacketKeys.init(.{0x41} ** 16, .{0x42} ** 12, .{0x43} ** 16);
    driver.state = .established;
    driver.handshake_confirmed = true;
    driver.write_keys[data_index] = packet_keys;
    driver.ack_frequency_pending = false;
    try driver.queueNewConnectionId();

    // Keep this an in-process production-pump test: the packet is constructed
    // and registered, then deliberately dropped before socket publication.
    const always_drop = struct {
        fn drop(_: usize) bool {
            return true;
        }
    }.drop;
    endpoint.setTestDropFilter(always_drop);
    try std.testing.expect(try endpoint.pumpOutgoing());
    try std.testing.expectEqual(@as(usize, 2), endpoint.conns[0].registered_local_cids);

    const dynamic_cid = driver.localConnectionId(1) orelse return error.UnexpectedState;
    var short: [1 + local_cid_len + 1]u8 = undefined;
    short[0] = packet.fixed_bit;
    @memcpy(short[1 .. 1 + local_cid_len], dynamic_cid.slice());
    short[short.len - 1] = 0;
    const four: router_mod.FourTuple = .{
        .local = toSockAddr(endpoint.localAddress()),
        .remote = toSockAddr(remote),
    };
    const routed = (try endpoint.route(four, &short, remote)) orelse return error.UnexpectedRoute;
    try std.testing.expect(routed == &endpoint.conns[0]);
}

// ── real-socket ECN / GSO kernel legs ───────────────────────────────────────
//
// These are NOT harness simulations. They open two production `Endpoint`s on
// loopback and assert on what the KERNEL did with the datagrams. That is the
// only way to prove the cmsg ABI: an in-process pair harness never touches an
// IP header, so it can neither confirm nor refute that our cmsg is well formed.

/// Whichever TLS backend this product actually compiles in. The socket legs
/// are about IP headers and syscalls, not TLS, so they must run on every noq
/// product rather than pinning picotls (absent from `noq-zigtls`).
const test_tls_backend: crypto.Backend = if (crypto.picotls_enabled) .picotls else .zigtls;

/// Two production endpoints bound to loopback, for the socket-level legs.
const RawSocketPair = struct {
    sender: *Endpoint,
    receiver: *Endpoint,

    fn init(allocator: std.mem.Allocator, io: std.Io) !RawSocketPair {
        return initGro(allocator, io, false);
    }

    /// `receiver_gro` arms `UDP_GRO` on the receiver (the production default).
    /// Tests asserting per-segment receive boundaries pass `false` so the
    /// kernel does not coalesce the segments into one GRO list.
    fn initGro(allocator: std.mem.Allocator, io: std.Io, receiver_gro: bool) !RawSocketPair {
        const sender = try Endpoint.initOptions(allocator, io, key.SecretKey.fromBytes([_]u8{0xE1} ** 32), "noq-ecn-probe", .{
            .tls_backend = test_tls_backend,
        });
        errdefer sender.deinit();
        const receiver = try Endpoint.initOptions(allocator, io, key.SecretKey.fromBytes([_]u8{0xE2} ** 32), "noq-ecn-probe", .{
            .tls_backend = test_tls_backend,
            .gro_receive = receiver_gro,
        });
        return .{ .sender = sender, .receiver = receiver };
    }

    fn deinit(self: RawSocketPair) void {
        self.sender.deinit();
        self.receiver.deinit();
    }
};

test "K5: NOQ connection stats surface is public and vtable-backed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const server_key = key.SecretKey.fromBytes([_]u8{0xC3} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xC4} ** 32);
    const server = try Endpoint.initOptions(allocator, io, server_key, "noq-k5-stats", .{
        .expected_peer = client_key.public(),
        .tls_backend = test_tls_backend,
        .congestion_kind = .new_reno,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, "noq-k5-stats", .{
        .tls_backend = test_tls_backend,
        .congestion_kind = .new_reno,
    });
    defer client.deinit();

    const established = try establishEndpoints(client, server, server_key.public());
    defer established.client_conn.close();
    defer established.server_conn.close();

    const stats = established.client_conn.stats();
    try std.testing.expectEqual(tr.CongestionController.new_reno, stats.congestion_controller);
    try std.testing.expect(stats.path_mtu != null and stats.path_mtu.? >= quic_conn.min_mtu);
    try std.testing.expect(stats.congestion_window != null and stats.congestion_window.? > 0);
    try std.testing.expect(stats.smoothed_rtt_ns != null and stats.smoothed_rtt_ns.? > 0);
}

test "D19: NOQ stream reset and stop codes surface through public vtables" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const server_key = key.SecretKey.fromBytes([_]u8{0xC5} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xC6} ** 32);
    const server = try Endpoint.initOptions(allocator, io, server_key, "noq-d19-codes", .{
        .expected_peer = client_key.public(),
        .tls_backend = test_tls_backend,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, "noq-d19-codes", .{
        .tls_backend = test_tls_backend,
    });
    defer client.deinit();

    const established = try establishEndpoints(client, server, server_key.public());
    defer established.client_conn.close();
    defer established.server_conn.close();

    const client_bi = try established.client_conn.openBi();
    try client_bi.send.writer().writeAll("reset-code-probe");
    try client_bi.send.flush();
    const server_bi = try established.server_conn.acceptBi();

    const client_send_impl: *SendImpl = client_bi.send.impl;
    try client_send_impl.entry.driver.resetStream(client_send_impl.stream_id, 123);
    try client.pumpForTest();
    try server.pumpForTest();
    try std.testing.expectEqual(@as(?u64, 123), server_bi.recv.resetCode());

    const client_bi2 = try established.client_conn.openBi();
    try client_bi2.send.writer().writeAll("stop-code-probe");
    try client_bi2.send.flush();
    const server_bi2 = try established.server_conn.acceptBi();

    const server_recv_impl: *RecvImpl = server_bi2.recv.impl;
    try server_recv_impl.entry.driver.stopStream(server_recv_impl.stream_id, 321);
    try server.pumpForTest();
    try client.pumpForTest();
    try std.testing.expectEqual(@as(?u64, 321), client_bi2.send.resetCode());
}

test "NOQ RecvStream reader delivers pre-FIN bytes via takeByte" {
    // Regression: custom readVec ignored empty dests from Reader.fill, so
    // ObserveItem.decodeFrame hung with streamRecvBufferedLen>0 until timeout.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const server_key = key.SecretKey.fromBytes([_]u8{0x51} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0x52} ** 32);
    const server = try Endpoint.initOptions(allocator, io, server_key, "noq-prefin-reader", .{
        .expected_peer = client_key.public(),
        .tls_backend = test_tls_backend,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, "noq-prefin-reader", .{
        .tls_backend = test_tls_backend,
    });
    defer client.deinit();

    const established = try establishEndpoints(client, server, server_key.public());
    defer established.client_conn.close();
    defer established.server_conn.close();

    const client_bi = try established.client_conn.openBi();
    try client_bi.send.writer().writeAll("observe-req");
    try client_bi.send.finish();

    const server_bi = try established.server_conn.acceptBi();
    const item = [_]u8{ 0x05, 0x81, 0x80, 0x04, 0x01, 0x00 };
    try server_bi.send.writer().writeAll(&item);
    try server_bi.send.flush();
    try server.pumpForTest();
    try client.pumpForTest();

    const got0 = try client_bi.recv.reader().takeByte();
    try std.testing.expectEqual(@as(u8, 0x05), got0);
    var rest: [5]u8 = undefined;
    const n = try client_bi.recv.reader().readSliceShort(&rest);
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqualSlices(u8, item[1..], &rest);
}

test "real-socket ECN: the kernel carries our codepoint on a loopback IP header" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const pair = try RawSocketPair.init(allocator, std.testing.io);
    defer pair.deinit();

    // If the kernel refused IP_RECVTOS there is nothing to observe. Report that
    // honestly rather than passing on a vacuous assertion.
    if (!pair.receiver.ecnReceiveEnabledForTest()) return error.SkipZigTest;

    const batch = try RawReceiveScratch.create(allocator, pair.receiver.gro_segments);
    defer batch.destroy(allocator);
    for ([_]udp_cmsg.EcnCodepoint{ .ect0, .ce, .ect1 }) |expected| {
        var payload = [_]u8{ 'e', 'c', 'n', @intFromEnum(expected) };
        try pair.sender.sendRawForTest(pair.receiver.localAddress(), &payload, expected, null);

        var payloads: [1][]const u8 = undefined;
        var codepoints: [1]?udp_cmsg.EcnCodepoint = undefined;
        const n = try pair.receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, batch);
        try std.testing.expectEqual(@as(usize, 1), n);
        try std.testing.expectEqualSlices(u8, &payload, payloads[0]);
        // THE assertion: the codepoint survived a real IP header round trip.
        // With the old 1-byte cmsg payload this is where the kernel's EINVAL
        // (v6) or a wrong TOS byte would surface.
        try std.testing.expectEqual(expected, codepoints[0].?);
    }

    try std.testing.expectEqual(@as(u64, 3), pair.sender.ecnSentForTest());
    try std.testing.expectEqual(@as(u64, 1), pair.receiver.ecnRecvMarkedForTest());
    try std.testing.expectEqual(@as(u64, 2), pair.receiver.ecnRecvEctForTest());
}

test "real-socket ECN: an unmarked datagram reports no codepoint (mutation-RED control)" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const pair = try RawSocketPair.init(allocator, std.testing.io);
    defer pair.deinit();
    if (!pair.receiver.ecnReceiveEnabledForTest()) return error.SkipZigTest;

    // Without this control the ECN leg could "pass" on a decoder that returns a
    // codepoint unconditionally.
    var payload = [_]u8{ 'n', 'o', 'e', 'c', 'n' };
    try pair.sender.sendRawForTest(pair.receiver.localAddress(), &payload, null, null);

    const batch = try RawReceiveScratch.create(allocator, pair.receiver.gro_segments);
    defer batch.destroy(allocator);
    var payloads: [1][]const u8 = undefined;
    var codepoints: [1]?udp_cmsg.EcnCodepoint = undefined;
    const n = try pair.receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, batch);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expect(codepoints[0] == null);
    try std.testing.expectEqual(@as(u64, 0), pair.receiver.ecnRecvMarkedForTest());
    try std.testing.expectEqual(@as(u64, 0), pair.sender.ecnSentForTest());
}

test "real-socket GSO: one UDP_SEGMENT sendmsg becomes multiple kernel datagrams" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const pair = try RawSocketPair.init(allocator, std.testing.io);
    defer pair.deinit();
    if (!pair.sender.gsoEnabledForTest()) return error.SkipZigTest;

    const segment_size: u16 = 300;
    const segments: usize = 4;
    var payload: [segment_size * segments]u8 = undefined;
    // Stamp each segment so a coalesced or mis-split delivery is detectable.
    for (0..segments) |i| @memset(payload[i * segment_size ..][0..segment_size], @intCast('A' + i));

    try pair.sender.sendRawForTest(pair.receiver.localAddress(), &payload, null, segment_size);

    // A rejecting kernel must have fallen back, not lost bytes — either way the
    // receiver sees `segments` datagrams.
    if (pair.sender.gsoRejectedForTest() == 0) {
        try std.testing.expectEqual(@as(u64, 1), pair.sender.gsoSegmentedSendsForTest());
        try std.testing.expectEqual(@as(u64, segments), pair.sender.gsoSegmentsSentForTest());
    }

    const batch = try RawReceiveScratch.create(allocator, pair.receiver.gro_segments);
    defer batch.destroy(allocator);
    var received: usize = 0;
    while (received < segments) {
        var payloads: [socket_batch_size][]const u8 = undefined;
        var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
        const n = try pair.receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, batch);
        if (n == 0) break;
        for (payloads[0..n]) |got| {
            // Each datagram must be exactly one segment, with uniform content.
            try std.testing.expectEqual(@as(usize, segment_size), got.len);
            const expect_byte: u8 = @intCast('A' + received);
            for (got) |b| try std.testing.expectEqual(expect_byte, b);
            received += 1;
        }
    }
    try std.testing.expectEqual(segments, received);
}

test "real-socket GRO: a coalesced receive is split back into segments by stride" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    // Receiver has GRO armed (the production default); sender uses GSO so the
    // kernel has a same-flow run to coalesce.
    const pair = try RawSocketPair.initGro(allocator, std.testing.io, true);
    defer pair.deinit();
    if (!pair.sender.gsoEnabledForTest()) return error.SkipZigTest;
    if (pair.receiver.gro_segments <= 1) return error.SkipZigTest; // kernel refused UDP_GRO

    const segment_size: u16 = 200;
    const segments: usize = 4;
    var payload: [segment_size * segments]u8 = undefined;
    for (0..segments) |i| @memset(payload[i * segment_size ..][0..segment_size], @intCast('a' + i));
    try pair.sender.sendRawForTest(pair.receiver.localAddress(), &payload, null, segment_size);

    // Whatever the kernel does (coalesce or not), the receiver must observe
    // exactly `segments` standalone datagrams of `segment_size` each, in order.
    const batch = try RawReceiveScratch.create(allocator, pair.receiver.gro_segments);
    defer batch.destroy(allocator);
    var received: usize = 0;
    while (received < segments) {
        var payloads: [socket_batch_size][]const u8 = undefined;
        var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
        const n = try pair.receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, batch);
        if (n == 0) break;
        for (payloads[0..n]) |got| {
            try std.testing.expectEqual(@as(usize, segment_size), got.len);
            const expect_byte: u8 = @intCast('a' + received);
            for (got) |b| try std.testing.expectEqual(expect_byte, b);
            received += 1;
        }
    }
    try std.testing.expectEqual(segments, received);
}

test "real-socket GSO: ECN and UDP_SEGMENT cmsgs coexist in one control buffer" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const pair = try RawSocketPair.init(allocator, std.testing.io);
    defer pair.deinit();
    if (!pair.sender.gsoEnabledForTest() or !pair.receiver.ecnReceiveEnabledForTest()) return error.SkipZigTest;

    // Two cmsgs in one buffer is where a wrong CMSG_SPACE/alignment shows up:
    // the second header lands misaligned and the kernel rejects or misreads it.
    const segment_size: u16 = 200;
    var payload: [segment_size * 2]u8 = undefined;
    @memset(payload[0..segment_size], 'X');
    @memset(payload[segment_size..], 'Y');
    try pair.sender.sendRawForTest(pair.receiver.localAddress(), &payload, .ce, segment_size);

    const batch = try RawReceiveScratch.create(allocator, pair.receiver.gro_segments);
    defer batch.destroy(allocator);
    var seen: usize = 0;
    var marked: usize = 0;
    while (seen < 2) {
        var payloads: [socket_batch_size][]const u8 = undefined;
        var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
        const n = try pair.receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, batch);
        if (n == 0) break;
        for (payloads[0..n], codepoints[0..n]) |got, cp| {
            try std.testing.expectEqual(@as(usize, segment_size), got.len);
            if (cp == udp_cmsg.EcnCodepoint.ce) marked += 1;
            seen += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), seen);
    // Every segment of a GSO batch inherits the batch's ECN codepoint.
    try std.testing.expectEqual(@as(usize, 2), marked);
}

test "real-socket ECN: a CE mark reaches the driver's ingest counter, not noteEcn" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const server_key = key.SecretKey.fromBytes([_]u8{0xE3} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xE4} ** 32);
    const server = try Endpoint.initOptions(allocator, io, server_key, "noq-ecn-ingest", .{
        .expected_peer = client_key.public(),
        .tls_backend = test_tls_backend,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, "noq-ecn-ingest", .{
        .tls_backend = test_tls_backend,
    });
    defer client.deinit();
    if (!server.ecnReceiveEnabledForTest()) return error.SkipZigTest;

    const established = try establishEndpoints(client, server, server_key.public());
    defer established.client_conn.close();
    defer established.server_conn.close();

    const server_driver = server.testDriver(.server) orelse return error.TestUnexpectedResult;
    const before = server_driver.ecnRecvMarkedForTest();
    // `noteEcn` (the SIMULATED path) is untouched throughout; the counters we
    // assert on are moved only by `ingestReceivedEcn`, which only the real cmsg
    // decode calls. That split is what makes this leg un-fakeable.
    const counts_before = server_driver.ecnCountsForTest();

    // Loopback never applies CE, so mark it at the sender. Everything after
    // that is production: real IP header, real cmsg, real pump, real ingest.
    client.setEcnOverrideForTest(.client, .ce);

    // Drive genuine 1-RTT stream traffic — these are routable QUIC packets, so
    // they reach `route()` and therefore `ingestEcn`. The sans-io driver is
    // used directly (rather than the blocking stream API) so the single-threaded
    // pump below stays in control.
    const client_driver = client.testDriver(.client) orelse return error.TestUnexpectedResult;
    const sid = try client_driver.openStream(.bidi);
    try client_driver.writeStream(sid, "ecn-ingest-probe", true);

    var polls: usize = 0;
    while (polls < 400 and server_driver.ecnRecvMarkedForTest() == before) : (polls += 1) {
        try client.pumpForTest();
        try server.pumpForTest();
    }

    try std.testing.expect(server_driver.ecnRecvMarkedForTest() > before);
    // The endpoint-level counter must agree: both are incremented only on the
    // real cmsg path.
    try std.testing.expect(server.ecnRecvMarkedForTest() > 0);
    // And the ACK_ECN counters the server will echo to the peer must have moved
    // with them — this is what closes the loop back to congestion control.
    try std.testing.expect(server_driver.ecnCountsForTest().ce > counts_before.ce);
}

test "real-socket ECN: production endpoints mark ECT(0) on 1-RTT data" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const server_key = key.SecretKey.fromBytes([_]u8{0xE5} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xE6} ** 32);
    const server = try Endpoint.initOptions(allocator, io, server_key, "noq-ecn-mark", .{
        .expected_peer = client_key.public(),
        .tls_backend = test_tls_backend,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, "noq-ecn-mark", .{
        .tls_backend = test_tls_backend,
    });
    defer client.deinit();

    const established = try establishEndpoints(client, server, server_key.public());
    defer established.client_conn.close();
    defer established.server_conn.close();

    const client_driver = client.testDriver(.client) orelse return error.TestUnexpectedResult;
    // ECT(0) is stamped on 1-RTT data only; a completed handshake guarantees
    // some has gone out.
    try std.testing.expect(client_driver.ecnSentForTest().ect0 > 0);
    try std.testing.expect(client.ecnSentForTest() > 0);
    try std.testing.expect(client_driver.ecnStateForTest() != .disabled);
}

test "OutgoingBatch enforces the kernel's equal-segment rule" {
    const a = net.IpAddress{ .ip4 = .loopback(1111) };
    const b = net.IpAddress{ .ip4 = .loopback(2222) };
    var batch: OutgoingBatch = .{};

    const full = [_]u8{0xAA} ** 300;
    const short = [_]u8{0xBB} ** 100;

    try std.testing.expect(batch.accepts(a, null, full.len));
    batch.push(a, null, &full);
    // Same peer, same size, same codepoint: coalesces.
    try std.testing.expect(batch.accepts(a, null, full.len));
    batch.push(a, null, &full);
    try std.testing.expectEqual(@as(usize, 2), batch.count);
    try std.testing.expectEqual(@as(u16, 300), batch.segment_size);

    // A different peer must flush.
    try std.testing.expect(!batch.accepts(b, null, full.len));
    // A different ECN codepoint must flush (the cmsg applies to the whole batch).
    try std.testing.expect(!batch.accepts(a, .ce, full.len));
    // A LARGER datagram cannot join — only the final segment may differ, and
    // only by being shorter.
    try std.testing.expect(!batch.accepts(a, null, full.len + 1));

    // A short datagram may join as the final segment, and seals the batch.
    try std.testing.expect(batch.accepts(a, null, short.len));
    batch.push(a, null, &short);
    try std.testing.expect(batch.sealed);
    try std.testing.expect(!batch.accepts(a, null, short.len));

    batch.reset();
    try std.testing.expect(batch.isEmpty());
    try std.testing.expect(!batch.sealed);
}

test "OutgoingBatch stops at the kernel's segment limit and its buffer" {
    const a = net.IpAddress{ .ip4 = .loopback(1111) };
    var batch: OutgoingBatch = .{};
    const seg = [_]u8{0xCC} ** 16;
    for (0..max_gso_segments) |_| {
        try std.testing.expect(batch.accepts(a, null, seg.len));
        batch.push(a, null, &seg);
    }
    try std.testing.expectEqual(max_gso_segments, batch.count);
    try std.testing.expect(!batch.accepts(a, null, seg.len));
}

test "real-socket GSO: the PRODUCTION pump emits a segmented send under stream load" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const server_key = key.SecretKey.fromBytes([_]u8{0xE7} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xE8} ** 32);
    const server = try Endpoint.initOptions(allocator, io, server_key, "noq-gso-pump", .{
        .expected_peer = client_key.public(),
        .tls_backend = test_tls_backend,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, "noq-gso-pump", .{
        .tls_backend = test_tls_backend,
    });
    defer client.deinit();
    if (!client.gsoEnabledForTest()) return error.SkipZigTest;

    const established = try establishEndpoints(client, server, server_key.public());
    defer established.client_conn.close();
    defer established.server_conn.close();

    // Enough data that the driver produces several equally-sized 1-RTT
    // datagrams in one `pumpOutgoing` sweep — the condition the batcher needs.
    const client_driver = client.testDriver(.client) orelse return error.TestUnexpectedResult;
    const sid = try client_driver.openStream(.bidi);
    const payload = [_]u8{0x5A} ** (256 * 1024);
    try client_driver.writeStream(sid, &payload, true);

    const server_driver = server.testDriver(.server) orelse return error.TestUnexpectedResult;
    var polls: usize = 0;
    while (polls < 4000) : (polls += 1) {
        try client.pumpForTest();
        try server.pumpForTest();
        // Keep pumping past the first segmented send so the delivery assertion
        // below has data to check.
        if (client.gsoSegmentedSendsForTest() > 0 and server_driver.streamRecvBytes(sid).len > 0) break;
    }

    // STRUCTURED evidence: a counter only the real `sendmsg`-with-UDP_SEGMENT
    // path increments. A stubbed pass cannot move it.
    try std.testing.expect(client.gsoSegmentedSendsForTest() > 0);
    // Each segmented send covered more than one datagram, by construction.
    try std.testing.expect(client.gsoSegmentsSentForTest() > client.gsoSegmentedSendsForTest());
    // And the bytes actually arrived — a batch the kernel silently dropped
    // would leave the server's stream empty.
    try std.testing.expect(server_driver.streamRecvBytes(sid).len > 0);
}

test "A12/A13: first-flight with DCID under 8 gets Initial PROTOCOL_VIOLATION close on the wire" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0x94} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "a13-initial-close-test", .{ .accept_unknown_peer = true });
    defer endpoint.deinit();

    // Raw probe socket standing in for the rejected client: route() sends the
    // Initial close synchronously, so the datagram is queued before we recv.
    const probe_bind = try net.IpAddress.parse("127.0.0.1", 0);
    const probe = try probe_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer probe.close(io);
    const from = probe.address;

    const four: router_mod.FourTuple = .{
        .local = toSockAddr(endpoint.localAddress()),
        .remote = toSockAddr(from),
    };
    const short_dcid = try packet.ConnectionId.init(&.{ 0x50, 0x51, 0x52, 0x53 });
    const src_cid = try packet.ConnectionId.init(&.{ 0x60, 0x61, 0x62, 0x63 });
    var initial: [1200]u8 = .{0} ** 1200;
    _ = try (packet.InitialHeader{
        .version = 1,
        .dst_cid = short_dcid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
    }).encode(&initial);

    // Demux mints nothing and returns null (no ConnEntry), but must have sent
    // the Initial-space CONNECTION_CLOSE to the probe address.
    try std.testing.expect((try endpoint.route(four, &initial, from)) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint.liveConnectionCount());

    var recv_buf: [1500]u8 = undefined;
    const msg = probe.receiveTimeout(io, &recv_buf, .{ .duration = .{
        .raw = .fromMilliseconds(1000),
        .clock = .awake,
    } }) catch return error.ExpectedInitialClose;
    const close = msg.data;

    // Cleartext skeleton: v1 Initial addressed back to the client's SCID.
    const skeleton = try packet.decodeProtectedLongHeader(close, true);
    try std.testing.expectEqual(packet.LongType.initial, skeleton.long_type);
    try std.testing.expectEqual(@as(u32, 1), skeleton.version);
    try std.testing.expectEqualSlices(u8, src_cid.slice(), skeleton.dst_cid.slice());

    // Decrypt with the Initial keys any real client derives from its DCID and
    // read the CONNECTION_CLOSE frame (PROTOCOL_VIOLATION, noq endpoint.rs:725).
    const keys = quic_initial_keys.serverKeys(short_dcid.slice());
    var wire: [1500]u8 = undefined;
    @memcpy(wire[0..close.len], close);
    const bytes = wire[0..close.len];
    try quic_packet_crypto.decryptHeaderWithKeys(bytes, skeleton.pn_offset, keys);
    const pn_len: usize = @as(usize, bytes[0] & 0x03) + 1;
    const header_len = skeleton.pn_offset + pn_len;
    var pn: u64 = 0;
    for (bytes[skeleton.pn_offset..header_len]) |b| pn = (pn << 8) | b;
    try quic_packet_crypto.decryptPayload(bytes, header_len, pn, keys);
    const payload = bytes[header_len .. skeleton.packet_end - quic_packet_crypto.tag_len];
    const decoded = try quic_frame.decode(payload);
    switch (decoded) {
        .connection_close => |cc| {
            try std.testing.expectEqual(router_mod.transport_error_protocol_violation, cc.error_code);
            try std.testing.expect(!cc.is_app);
        },
        else => return error.UnexpectedFrame,
    }
}

test "A13: slot-exhausted server refuses first-flight with Initial CONNECTION_REFUSED on the wire" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0x95} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "a13-refuse-test", .{ .accept_unknown_peer = true });
    defer endpoint.deinit();

    // Occupy every connection slot (same trick as the F9 router test); reset
    // before deinit so no fake entry is torn down.
    const placeholder = try net.IpAddress.parse("127.0.0.2", 1);
    for (&endpoint.conns) |*e| e.* = .{ .used = true, .remote = placeholder };
    defer for (&endpoint.conns) |*e| {
        e.used = false;
    };

    const probe_bind = try net.IpAddress.parse("127.0.0.1", 0);
    const probe = try probe_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer probe.close(io);
    const from = probe.address;

    const four: router_mod.FourTuple = .{
        .local = toSockAddr(endpoint.localAddress()),
        .remote = toSockAddr(from),
    };
    const dcid = try packet.ConnectionId.init(&.{ 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77 });
    const src_cid = try packet.ConnectionId.init(&.{ 0x60, 0x61, 0x62, 0x63 });
    var initial: [1200]u8 = .{0} ** 1200;
    _ = try (packet.InitialHeader{
        .version = 1,
        .dst_cid = dcid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
    }).encode(&initial);

    // noq accept():585-599 — exhausted at accept → CONNECTION_REFUSED close,
    // not a silent drop into retransmit-timeout.
    try std.testing.expect((try endpoint.route(four, &initial, from)) == null);
    // The router mint from handleFirstPacket must have been rolled back:
    // no live slots, no initial-CID route, no buffered incoming bytes.
    try std.testing.expectEqual(@as(usize, 0), endpoint.router.connection_ids_initial.count());
    try std.testing.expectEqual(@as(usize, 0), endpoint.router.incoming_total_bytes);
    for (endpoint.router.connections.items) |slot| try std.testing.expect(!slot.live);

    var recv_buf: [1500]u8 = undefined;
    const msg = probe.receiveTimeout(io, &recv_buf, .{ .duration = .{
        .raw = .fromMilliseconds(1000),
        .clock = .awake,
    } }) catch return error.ExpectedInitialClose;
    const close = msg.data;

    const skeleton = try packet.decodeProtectedLongHeader(close, true);
    try std.testing.expectEqual(packet.LongType.initial, skeleton.long_type);
    try std.testing.expectEqualSlices(u8, src_cid.slice(), skeleton.dst_cid.slice());

    const keys = quic_initial_keys.serverKeys(dcid.slice());
    var wire: [1500]u8 = undefined;
    @memcpy(wire[0..close.len], close);
    const bytes = wire[0..close.len];
    try quic_packet_crypto.decryptHeaderWithKeys(bytes, skeleton.pn_offset, keys);
    const pn_len: usize = @as(usize, bytes[0] & 0x03) + 1;
    const header_len = skeleton.pn_offset + pn_len;
    var pn: u64 = 0;
    for (bytes[skeleton.pn_offset..header_len]) |b| pn = (pn << 8) | b;
    try quic_packet_crypto.decryptPayload(bytes, header_len, pn, keys);
    const payload = bytes[header_len .. skeleton.packet_end - quic_packet_crypto.tag_len];
    const decoded = try quic_frame.decode(payload);
    switch (decoded) {
        .connection_close => |cc| {
            try std.testing.expectEqual(router_mod.transport_error_connection_refused, cc.error_code);
            try std.testing.expect(!cc.is_app);
        },
        else => return error.UnexpectedFrame,
    }
}

// ── IncomingFilter: pre-handshake admission (upstream protocol.rs:459-475) ──

fn filterReject(_: *anyopaque, _: *const IncomingInfo) IncomingFilterOutcome {
    return .reject;
}
fn filterIgnore(_: *anyopaque, _: *const IncomingInfo) IncomingFilterOutcome {
    return .ignore;
}
fn filterRetry(_: *anyopaque, info: *const IncomingInfo) IncomingFilterOutcome {
    if (info.remote_addr_validated) return .accept;
    return .retry;
}
fn filterAccept(_: *anyopaque, _: *const IncomingInfo) IncomingFilterOutcome {
    return .accept;
}

fn buildFilterInitial() ![1200]u8 {
    const dcid = try packet.ConnectionId.init(&.{ 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7 });
    const src_cid = try packet.ConnectionId.init(&.{ 0xB0, 0xB1, 0xB2, 0xB3 });
    var initial: [1200]u8 = .{0} ** 1200;
    _ = try (packet.InitialHeader{
        .version = 1,
        .dst_cid = dcid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
    }).encode(&initial);
    return initial;
}

test "IncomingFilter reject sends Initial CONNECTION_REFUSED before handshake" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0xA1} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "filter-reject", .{ .accept_unknown_peer = true });
    defer endpoint.deinit();
    const probe_bind = try net.IpAddress.parse("127.0.0.1", 0);
    const probe = try probe_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer probe.close(io);
    const from = probe.address;
    const four: router_mod.FourTuple = .{ .local = toSockAddr(endpoint.localAddress()), .remote = toSockAddr(from) };
    var initial = try buildFilterInitial();

    var ctx: u8 = 0;
    endpoint.setIncomingFilter(.{ .context = &ctx, .callback = filterReject });
    try std.testing.expect((try endpoint.route(four, &initial, from)) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint.router.connection_ids_initial.count());

    var recv_buf: [1500]u8 = undefined;
    const msg = probe.receiveTimeout(io, &recv_buf, .{ .duration = .{ .raw = .fromMilliseconds(1000), .clock = .awake } }) catch return error.ExpectedRejectClose;
    const skeleton = try packet.decodeProtectedLongHeader(msg.data, true);
    try std.testing.expectEqual(packet.LongType.initial, skeleton.long_type);
    const dcid = try packet.ConnectionId.init(&.{ 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7 });
    const keys = quic_initial_keys.serverKeys(dcid.slice());
    var wire: [1500]u8 = undefined;
    @memcpy(wire[0..msg.data.len], msg.data);
    const bytes = wire[0..msg.data.len];
    try quic_packet_crypto.decryptHeaderWithKeys(bytes, skeleton.pn_offset, keys);
    const pn_len: usize = @as(usize, bytes[0] & 0x03) + 1;
    const header_len = skeleton.pn_offset + pn_len;
    var pn: u64 = 0;
    for (bytes[skeleton.pn_offset..header_len]) |b| pn = (pn << 8) | b;
    try quic_packet_crypto.decryptPayload(bytes, header_len, pn, keys);
    const payload = bytes[header_len .. skeleton.packet_end - quic_packet_crypto.tag_len];
    const decoded = try quic_frame.decode(payload);
    switch (decoded) {
        .connection_close => |cc| {
            try std.testing.expectEqual(router_mod.transport_error_connection_refused, cc.error_code);
            try std.testing.expect(!cc.is_app);
        },
        else => return error.UnexpectedFrame,
    }
}

test "IncomingFilter ignore drops first flight silently" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0xA2} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "filter-ignore", .{ .accept_unknown_peer = true });
    defer endpoint.deinit();
    const probe_bind = try net.IpAddress.parse("127.0.0.1", 0);
    const probe = try probe_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer probe.close(io);
    const from = probe.address;
    const four: router_mod.FourTuple = .{ .local = toSockAddr(endpoint.localAddress()), .remote = toSockAddr(from) };
    var initial = try buildFilterInitial();

    var ctx: u8 = 0;
    endpoint.setIncomingFilter(.{ .context = &ctx, .callback = filterIgnore });
    try std.testing.expect((try endpoint.route(four, &initial, from)) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint.router.connection_ids_initial.count());

    var recv_buf: [1500]u8 = undefined;
    const got = probe.receiveTimeout(io, &recv_buf, .{ .duration = .{ .raw = .fromMilliseconds(200), .clock = .awake } }) catch null;
    try std.testing.expect(got == null);
}

test "IncomingFilter retry issues Retry for unvalidated" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0xA3} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "filter-retry", .{ .accept_unknown_peer = true });
    defer endpoint.deinit();
    const probe_bind = try net.IpAddress.parse("127.0.0.1", 0);
    const probe = try probe_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer probe.close(io);
    const from = probe.address;
    const four: router_mod.FourTuple = .{ .local = toSockAddr(endpoint.localAddress()), .remote = toSockAddr(from) };
    var initial = try buildFilterInitial();

    var ctx: u8 = 0;
    endpoint.setIncomingFilter(.{ .context = &ctx, .callback = filterRetry });
    try std.testing.expect((try endpoint.route(four, &initial, from)) == null);
    try std.testing.expect(endpoint.stats_retry_issued >= 1);

    var recv_buf: [1500]u8 = undefined;
    const msg = probe.receiveTimeout(io, &recv_buf, .{ .duration = .{ .raw = .fromMilliseconds(1000), .clock = .awake } }) catch return error.ExpectedRetry;
    const retry = try packet.parseRetry(msg.data);
    try std.testing.expectEqual(@as(u32, 1), retry.version);
    try std.testing.expect(retry.token.len > 0);
}

test "IncomingFilter accept allows normal connection minting" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = key.SecretKey.fromBytes([_]u8{0xA4} ** 32);
    const endpoint = try Endpoint.initOptions(allocator, io, secret, "filter-accept", .{ .accept_unknown_peer = true });
    defer endpoint.deinit();
    const probe_bind = try net.IpAddress.parse("127.0.0.1", 0);
    const probe = try probe_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer probe.close(io);
    const from = probe.address;
    const four: router_mod.FourTuple = .{ .local = toSockAddr(endpoint.localAddress()), .remote = toSockAddr(from) };
    var initial = try buildFilterInitial();

    var ctx: u8 = 0;
    endpoint.setIncomingFilter(.{ .context = &ctx, .callback = filterAccept });
    const entry = try endpoint.route(four, &initial, from);
    try std.testing.expect(entry != null);
    try std.testing.expect(entry.?.used);
    try std.testing.expect(entry.?.role == .server);
}

// ── B8: TLS alert → CRYPTO_ERROR on the wire (noq crypto/rustls.rs:98-108) ──

fn b8SpoofConnect(client: *Endpoint, server_addr: net.IpAddress, server_pub: key.NodeId) tr.Error!tr.Connection {
    return client.transport().connect(.{
        .id = server_pub,
        .addrs = &.{.{ .ip = server_addr }},
    });
}

test "B8: forged-cert handshake failure closes with CRYPTO_ERROR, flushed before reclaim" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-b8-crypto-error";

    const signing_key = key.SecretKey.fromBytes([_]u8{0xB1} ** 32);
    const spoofed_key = key.SecretKey.fromBytes([_]u8{0xB2} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xB3} ** 32);

    // Phase 1 (manual pumps; the rejected driver stays observable): the
    // forged CertificateVerify must close the server conn with CRYPTO_ERROR
    // (0x0100 + alert) — and the close must actually leave on the wire.
    const server = try Endpoint.initOptions(allocator, io, server_key, alpn, .{ .accept_unknown_peer = true });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, signing_key, alpn, .{
        .certificate_public_key_override = spoofed_key.public(),
    });
    defer client.deinit();

    var rejected = false;
    var connect_future = io.async(b8SpoofConnect, .{ client, server.localAddress(), server_key.public() });
    defer _ = connect_future.cancel(io) catch {};
    for (0..2000) |_| {
        try server.pumpForTest();
        if (server.serverHandshakeRejected()) {
            rejected = true;
            break;
        }
        io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
    // The Gate B reject flag still sets (B8 must not weaken it).
    try std.testing.expect(rejected);
    // Flush the queued close, then read it back off the live driver.
    try server.pumpForTest();
    const drv = server.testDriver(.server) orelse return error.TestUnexpectedResult;
    try std.testing.expect(drv.state == .closed);
    const cc = drv.close_frame orelse return error.TestUnexpectedResult;
    try std.testing.expect(!cc.is_app);
    try std.testing.expect(cc.error_code >= 0x100 and cc.error_code <= 0x1ff);
    // close_sent: the highest keyed space carried the close (B2 machinery),
    // i.e. the CRYPTO_ERROR close was EMITTED, not just queued.
    try std.testing.expect(drv.close_sent);
    // The spoofed client's own TLS is sound from its side, so its connect may
    // complete or fail depending on whether the close lands first (Gate B
    // tolerates both); either way the handle must not leak.
    if (connect_future.await(io)) |c| c.close() else |_| {}

    // Phase 2 (reclaiming accept probe): with the reject-cycle flush the close
    // is already on the wire before any reclaim; the reclaiming accept path
    // must still tear the slot down cleanly and the peer must have observed
    // the close.
    const server2 = try Endpoint.initOptions(allocator, io, server_key, alpn, .{ .accept_unknown_peer = true });
    defer server2.deinit();
    const client2 = try Endpoint.initOptions(allocator, io, signing_key, alpn, .{
        .certificate_public_key_override = spoofed_key.public(),
    });
    defer client2.deinit();

    var connect2_future = io.async(b8SpoofConnect, .{ client2, server2.localAddress(), server_key.public() });
    defer _ = connect2_future.cancel(io) catch {};
    var saw_conn = false;
    for (0..2000) |_| {
        _ = server2.tryAcceptReady() catch null;
        if (server2.liveConnectionCount() > 0) {
            saw_conn = true;
        } else if (saw_conn) break;
        io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
    try std.testing.expect(saw_conn);
    try std.testing.expectEqual(@as(usize, 0), server2.liveConnectionCount());
    // The reclaim-time flush is no longer the first emission point: the reject
    // pump cycle itself now flushes the close (issue #31 F2). What phase 2 must
    // pin is the peer-visible property: the client observes the CRYPTO_ERROR
    // close — its dial fails off it, or its driver shows the peer close.
    if (connect2_future.await(io)) |c| {
        defer c.close();
        var saw_peer_close = false;
        for (0..2000) |_| {
            client2.pumpForTest() catch {};
            const cdrv = client2.testDriver(.client) orelse break;
            if (cdrv.state == .draining or cdrv.state == .closed) {
                saw_peer_close = true;
                break;
            }
            io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
        }
        try std.testing.expect(saw_peer_close);
    } else |err| {
        try std.testing.expect(err == error.ConnectionLost);
    }
}

test "F2: zigtls handshake reject flushes the CRYPTO_ERROR close in the reject pump cycle" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-f2-reject-flush";

    const signing_key = key.SecretKey.fromBytes([_]u8{0xF2} ** 32);
    const spoofed_key = key.SecretKey.fromBytes([_]u8{0xF3} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xF4} ** 32);

    // Issue #31 F2 shape: a pump-only server endpoint (no accept caller)
    // rejects the handshake. The reject pump cycle itself must already have
    // carried the CRYPTO_ERROR close onto the wire — pre-fix the close sat
    // queued until a later pump or an accept-loop reclaim, and a real peer
    // saw silence until its own timeout.
    const server = try Endpoint.initOptions(allocator, io, server_key, alpn, .{
        .accept_unknown_peer = true,
        .tls_backend = .zigtls,
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, signing_key, alpn, .{
        .certificate_public_key_override = spoofed_key.public(),
        .tls_backend = .zigtls,
    });
    defer client.deinit();

    var connect_future = io.async(b8SpoofConnect, .{ client, server.localAddress(), server_key.public() });
    defer _ = connect_future.cancel(io) catch {};
    var rejected = false;
    for (0..2000) |_| {
        try server.pumpForTest();
        if (server.serverHandshakeRejected()) {
            rejected = true;
            break;
        }
        io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
    try std.testing.expect(rejected);
    const drv = server.testDriver(.server) orelse return error.TestUnexpectedResult;
    try std.testing.expect(drv.state == .closed);
    const cc = drv.close_frame orelse return error.TestUnexpectedResult;
    try std.testing.expect(!cc.is_app);
    try std.testing.expect(cc.error_code >= 0x100 and cc.error_code <= 0x1ff);
    // The discriminating assertion: NO further server pump. Whatever close the
    // reject queued must already be on the wire, so the client observes it.
    // Pre-fix the close sat queued until a later server pump/accept-loop
    // reclaim, and the client below stayed established through every poll.
    if (connect_future.await(io)) |c| {
        defer c.close();
        var saw_peer_close = false;
        for (0..2000) |_| {
            client.pumpForTest() catch {};
            const cdrv = client.testDriver(.client) orelse break;
            if (cdrv.state == .draining or cdrv.state == .closed) {
                saw_peer_close = true;
                break;
            }
            io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
        }
        try std.testing.expect(saw_peer_close);
    } else |err| {
        // The dial itself surfaced the observed close as a failed connect.
        try std.testing.expect(err == error.ConnectionLost);
    }
}

// ── B7: drain window after close (noq/src/connection.rs:245-293) ────────────

fn b7DropAll(_: usize) bool {
    return true;
}

test "B7: closed conn holds a drain window — straggler re-draws close, reclaim at 3*PTO" {
    if (!crypto.picotls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-noq-b7-drain";

    const client_key = key.SecretKey.fromBytes([_]u8{0xC7} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xC8} ** 32);

    const server = try Endpoint.initOptions(allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
    });
    defer server.deinit();
    const client = try Endpoint.initOptions(allocator, io, client_key, alpn, .{});
    defer client.deinit();

    const conns = try establishEndpoints(client, server, server_key.public());
    defer conns.client_conn.close();

    // Shrink the drain window for the test: 3×PTO with PTO = 100 ms → 300 ms.
    server.testDriver(.server).?.timers.max_pto_ns = 100 * std.time.ns_per_ms;

    // Close with the server's first close datagram DROPPED, so the client
    // stays established and can source a straggler.
    server.setTestDropFilter(&b7DropAll);
    conns.server_conn.close();
    server.setTestDropFilter(null);

    // The slot frees immediately (persistent-endpoint discipline — the 5c
    // reclaim assertion still holds), but the driver + router registration
    // live on in a drain slot.
    try std.testing.expectEqual(@as(usize, 0), server.liveConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), server.drainCountForTest());

    // Straggler: the still-established client sends stream data. It must
    // route to the drain entry and re-draw the CONNECTION_CLOSE — not fall
    // off the CID router to a stateless reset, not meet silence.
    const client_driver = client.testDriver(.client).?;
    const sid = try client_driver.openStream(.bidi);
    try client_driver.writeStream(sid, "straggler", false);
    try client.pumpForTest(); // straggler onto the wire
    try server.pumpForTest(); // routes to the drain entry, re-arms the close
    try server.pumpForTest(); // the drain pump emits the re-drawn close
    try client.pumpForTest(); // client receives the re-drawn close

    // The client observed a CONNECTION_CLOSE (peer-close drain), NOT a
    // stateless reset and NOT silence (it was established before this).
    try std.testing.expect(client_driver.state == .draining);
    try std.testing.expect(!client.isDrainingStatelessResetForTest(.client));

    // Reclaim only after the window: past 3×PTO the pump tears the drain
    // entry down (router registration + driver).
    io.sleep(std.Io.Duration.fromMilliseconds(400), .awake) catch {};
    try server.pumpForTest();
    try std.testing.expectEqual(@as(usize, 0), server.drainCountForTest());
}

// ── L-row lower-transport gates ─────────────────────────────────────────────

fn newTestEndpoint(allocator: std.mem.Allocator, io: std.Io, byte: u8) !*Endpoint {
    return Endpoint.initOptions(allocator, io, key.SecretKey.fromBytes([_]u8{byte} ** 32), "noq-l-gate", .{
        .tls_backend = test_tls_backend,
    });
}

test "L8: IPv4 socket suppresses fragmentation (IP_MTU_DISCOVER=PROBE)" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const ep = try newTestEndpoint(std.testing.allocator, std.testing.io, 0xA1);
    defer ep.deinit();
    // The DF-suppression option took on this kernel or the endpoint honestly
    // reports may_fragment; the mutation (dropping the setsockopt) flips it.
    try std.testing.expect(!ep.mayFragmentForTest());
}

test "L8: DF option is actually armed on the live socket (getsockopt)" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const linux = std.os.linux;
    const ep = try newTestEndpoint(std.testing.allocator, std.testing.io, 0xA2);
    defer ep.deinit();
    var value: c_int = 0;
    var len: linux.socklen_t = @sizeOf(c_int);
    const rc = linux.getsockopt(ep.socket.handle, linux.IPPROTO.IP, linux.IP.MTU_DISCOVER, std.mem.asBytes(&value), &len);
    try std.testing.expect(linux.errno(rc) == .SUCCESS);
    try std.testing.expectEqual(@as(c_int, linux.IP.PMTUDISC_PROBE), value);
}

test "L16: send/recv buffer sizes set and read back (kernel-rounded)" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const ep = try newTestEndpoint(std.testing.allocator, std.testing.io, 0xA3);
    defer ep.deinit();
    const h = ep.socket.handle;
    // The kernel doubles the request for bookkeeping and caps it at
    // {r,w}mem_max. Exercise set → get and check the read-back is consistent
    // with the doubling/cap rule rather than asserting an exact value.
    const send_before = try udp_cmsg.sendBufferSize(h);
    const recv_before = try udp_cmsg.recvBufferSize(h);
    const want: c_int = 256 * 1024;
    try udp_cmsg.setSendBufferSize(h, want);
    try udp_cmsg.setRecvBufferSize(h, want);
    const send_after = try udp_cmsg.sendBufferSize(h);
    const recv_after = try udp_cmsg.recvBufferSize(h);
    // Read-back is positive and at least the requested size (the kernel's
    // doubling makes it >= 2*want unless capped); the set took effect iff the
    // value changed toward the request.
    try std.testing.expect(send_after > 0 and recv_after > 0);
    try std.testing.expect(send_after >= want or send_after != send_before);
    try std.testing.expect(recv_after >= want or recv_after != recv_before);
    // A second read is stable (the API round-trips).
    try std.testing.expectEqual(send_after, try udp_cmsg.sendBufferSize(h));
    try std.testing.expectEqual(recv_after, try udp_cmsg.recvBufferSize(h));
}

test "L13: destination IP is reported on a real loopback receive" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const sender = try newTestEndpoint(allocator, io, 0xB1);
    defer sender.deinit();
    const receiver = try newTestEndpoint(allocator, io, 0xB2);
    defer receiver.deinit();
    // HARD PRECONDITION: pktinfo receive must be ARMED on this socket. A
    // host that cannot arm it fails here — an unexercised gate is not
    // evidence, and a skip would let the row read green unproven.
    try std.testing.expect(receiver.pktinfoReceiveEnabledForTest());

    var payload = [_]u8{0x5A} ** 64;
    try sender.sendRawForTest(receiver.localAddress(), &payload, null, null);

    const batch = try RawReceiveScratch.create(allocator, receiver.gro_segments);
    defer batch.destroy(allocator);
    var payloads: [socket_batch_size][]const u8 = undefined;
    var metas: [socket_batch_size]udp_cmsg.RecvMeta = undefined;
    const n = try receiver.receiveRawMetaForTest(&payloads, &metas, 2 * std.time.ns_per_s, batch);
    try std.testing.expect(n >= 1);
    const dst = metas[0].dst_ip orelse return error.TestUnexpectedResult;
    // Loopback receive: the destination must be 127.0.0.1 (the receiver's addr).
    try std.testing.expect(dst == .ip4);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &dst.ip4.bytes);
}

test "L15: a real received datagram carries a kernel timestamp" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const sender = try newTestEndpoint(allocator, io, 0xC1);
    defer sender.deinit();
    const receiver = try newTestEndpoint(allocator, io, 0xC2);
    defer receiver.deinit();
    // HARD PRECONDITION: kernel receive timestamps must be ARMED on this
    // socket. A host that cannot arm them fails here — an unexercised gate
    // is not evidence, and a skip would let the row read green unproven.
    try std.testing.expect(receiver.timestampReceiveEnabledForTest());

    var payload = [_]u8{0x6B} ** 64;
    const before = std.Io.Clock.real.now(io).toNanoseconds();
    try sender.sendRawForTest(receiver.localAddress(), &payload, null, null);

    const batch = try RawReceiveScratch.create(allocator, receiver.gro_segments);
    defer batch.destroy(allocator);
    var payloads: [socket_batch_size][]const u8 = undefined;
    var metas: [socket_batch_size]udp_cmsg.RecvMeta = undefined;
    const n = try receiver.receiveRawMetaForTest(&payloads, &metas, 2 * std.time.ns_per_s, batch);
    try std.testing.expect(n >= 1);
    const ts = metas[0].timestamp_ns orelse return error.TestUnexpectedResult;
    const after = std.Io.Clock.real.now(io).toNanoseconds();
    // The kernel stamp must sit between the send and the read.
    try std.testing.expect(ts > 0);
    try std.testing.expect(ts >= @as(u64, @intCast(@max(before, 0))));
    try std.testing.expect(ts <= @as(u64, @intCast(@max(after, 0))) + std.time.ns_per_s);
}

test "L6: the batched receive pump drains every datagram of a burst" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    // GRO OFF so the batched (non-coalesced) path is what drains the burst.
    const pair = try RawSocketPair.initGro(allocator, io, false);
    defer pair.deinit();

    // A burst larger than one batch, so the drain loop must iterate.
    const burst: usize = socket_batch_size * 3;
    var sent: usize = 0;
    for (0..burst) |i| {
        var d: [48]u8 = @splat(@intCast(i & 0xff));
        try pair.sender.sendRawForTest(pair.receiver.localAddress(), &d, null, null);
        sent += 1;
    }

    const batch = try RawReceiveScratch.create(allocator, pair.receiver.gro_segments);
    defer batch.destroy(allocator);
    var received: usize = 0;
    var idle: usize = 0;
    while (received < sent and idle < 6) {
        var payloads: [socket_batch_size][]const u8 = undefined;
        var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
        const n = try pair.receiver.receiveRawForTest(&payloads, &codepoints, std.time.ns_per_s, batch);
        if (n == 0) {
            idle += 1;
        } else {
            received += n;
        }
    }
    // Every datagram of the burst arrived across the batched receive loop —
    // the batching/fallback behavior, proven on a real socket.
    try std.testing.expectEqual(sent, received);
    // The batching depth is pinned to the reference's BATCH_SIZE=32
    // (`noq-udp/src/unix.rs:826`); a batch is that many datagrams drained per
    // receive pass, iterated to cover the window.
    try std.testing.expect(socket_batch_size <= 32);
}

test "L7: UDP_GRO armed reports depth 64 and decodes a coalesced stride" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const pair = try RawSocketPair.initGro(allocator, io, true);
    defer pair.deinit();
    // HARD PRECONDITIONS: GSO send + GRO receive must be ARMED on this host.
    // A host that cannot arm them fails here — an unexercised gate is not
    // evidence, and a skip would let the row read green unproven.
    try std.testing.expect(pair.sender.gsoEnabledForTest());
    try std.testing.expect(pair.receiver.groSegmentsForTest() > 1);

    const segment_size: u16 = 300;
    const segments: usize = 3;
    var payload: [segment_size * segments]u8 = undefined;
    for (0..segments) |i| @memset(payload[i * segment_size ..][0..segment_size], @intCast('a' + i));
    try pair.sender.sendRawForTest(pair.receiver.localAddress(), &payload, null, segment_size);

    // GRO is armed, so a coalesced receive MUST be observed: the stride
    // split yields exactly the GSO segments, in order, and the coalesced
    // counter advances. Failure to observe is a hard failure, not a skip.
    const batch = try RawReceiveScratch.create(allocator, pair.receiver.gro_segments);
    defer batch.destroy(allocator);
    var payloads: [socket_batch_size][]const u8 = undefined;
    var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
    var received: usize = 0;
    var tries: usize = 0;
    while (tries < 4 and received < segments) : (tries += 1) {
        const n = try pair.receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, batch);
        received = @max(received, n);
    }
    try std.testing.expectEqual(segments, received);
    for (payloads[0..segments], 0..) |seg, i| {
        // Exactly the GSO segment size — a wrong stride would split the
        // coalesced list into different lengths.
        try std.testing.expectEqual(@as(usize, segment_size), seg.len);
        try std.testing.expectEqual(@as(u8, @intCast('a' + i)), seg[0]);
    }
    // THE assertion the old gate lacked: the kernel actually coalesced the
    // segments into one GRO list (count >= 1 on a u64 that CAN be zero),
    // replacing the tautological `>= 0`.
    try std.testing.expect(pair.receiver.groCoalescedRecvForTest() >= 1);
}

test "L12: a pinned source address leaves via IP_PKTINFO and the send succeeds" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    // Bind the sender to the loopback wildcard so src_ip has meaning.
    const sender = try Endpoint.initOptions(allocator, io, key.SecretKey.fromBytes([_]u8{0xD1} ** 32), "noq-l-gate", .{
        .tls_backend = test_tls_backend,
        .bind_address = .{ .ip4 = .unspecified(0) },
    });
    defer sender.deinit();
    const receiver = try newTestEndpoint(allocator, io, 0xD2);
    defer receiver.deinit();

    var payload = [_]u8{0x7C} ** 64;
    const src: net.IpAddress = .{ .ip4 = .loopback(0) };
    try sender.sendRawSrcIpForTest(receiver.localAddress(), src, &payload);
    try std.testing.expect(sender.srcIpSentForTest() >= 1);

    // The datagram arrives from the pinned source, not the wildcard.
    const batch = try RawReceiveScratch.create(allocator, receiver.gro_segments);
    defer batch.destroy(allocator);
    var payloads: [socket_batch_size][]const u8 = undefined;
    var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
    const n = try receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, batch);
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(usize, 64), payloads[0].len);
}

test "L14: v4-mapped destination is stamped with IP_TOS, not IPV6_TCLASS (encoder)" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const linux = std.os.linux;
    // A v4-mapped v6 destination must select the v4 cmsg.
    const mapped: net.IpAddress = .{ .ip6 = .{
        .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 },
        .port = 0,
    } };
    try std.testing.expect(Endpoint.isIp4Mapped(&mapped));
    var buf: [udp_cmsg.send_control_space]u8 = undefined;
    var enc = udp_cmsg.Encoder.init(&buf);
    try enc.pushEcn(Endpoint.isIp4Mapped(&mapped), .ect0);
    var it = udp_cmsg.Iterator.init(enc.finish());
    const cmsg = it.next() orelse return error.TestUnexpectedResult;
    // The cmsg is at the IPv4 level (IP_TOS), proving v4-mapped uses IP_TOS.
    try std.testing.expectEqual(@as(i32, linux.IPPROTO.IP), cmsg.level);
    try std.testing.expectEqual(@as(i32, linux.IP.TOS), cmsg.cmsg_type);
    // A pure v6 destination does NOT select v4.
    const v6: net.IpAddress = .{ .ip6 = .loopback(0) };
    try std.testing.expect(!Endpoint.isIp4Mapped(&v6));
}

test "L17: the receive ceiling holds a large datagram and MSG_TRUNC is observable" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const sender = try newTestEndpoint(allocator, io, 0xE1);
    defer sender.deinit();
    // GRO OFF so the receive exercises the batched per-message ceiling
    // (`max_datagram`) — the buffer the row's ceiling contract sizes.
    const receiver = try Endpoint.initOptions(allocator, io, key.SecretKey.fromBytes([_]u8{0xE2} ** 32), "noq-l-gate", .{
        .tls_backend = test_tls_backend,
        .gro_receive = false,
    });
    defer receiver.deinit();

    // A datagram ABOVE the old 2048 ceiling must arrive full-length: the
    // per-message buffer is max_udp_payload, so a legal datagram is never
    // truncated by the receive ceiling. (The old gate sent 1452 — BELOW the
    // ceiling it claimed to exceed — and proved nothing.)
    const big_len: usize = 4096; // above the old 2048 ceiling, below max_udp_payload
    var big: [big_len]u8 = undefined;
    @memset(&big, 0x33);
    try sender.sendRawForTest(receiver.localAddress(), &big, null, null);

    const batch = try RawReceiveScratch.create(allocator, receiver.gro_segments);
    defer batch.destroy(allocator);
    var payloads: [socket_batch_size][]const u8 = undefined;
    var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
    const n = try receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, batch);
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(big_len, payloads[0].len);
    try std.testing.expect(max_datagram >= max_udp_payload);
    try std.testing.expect(gro_recv_capacity == max_udp_payload * 64);

    // MSG_TRUNC observability: an oversized datagram into an undersized
    // buffer surfaces the kernel's truncation flag through the receive
    // stack — never a silent short read.
    var oversized: [big_len]u8 = undefined;
    @memset(&oversized, 0x44);
    try sender.sendRawForTest(receiver.localAddress(), &oversized, null, null);
    var undersized: [2048]u8 = undefined;
    const trunc_recv = try receiver.receiveTruncForTest(&undersized, 2 * std.time.ns_per_s);
    try std.testing.expectEqual(undersized.len, trunc_recv.len);
    try std.testing.expect(trunc_recv.trunc);
}

test "L9: EMSGSIZE is swallowed as loss and the endpoint keeps sending" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const sender = try newTestEndpoint(allocator, io, 0xF1);
    defer sender.deinit();
    const receiver = try newTestEndpoint(allocator, io, 0xF2);
    defer receiver.deinit();

    // Inject EMSGSIZE for one send (the MTU-probe outcome), then confirm the
    // send path swallows it (no ConnectionLost) and later traffic still flows.
    udp_cmsg.test_inject_errno = .MSGSIZE;
    var probe: [64]u8 = @splat(0x11);
    try sender.sendRawForTest(receiver.localAddress(), &probe, .ect0, null);
    try std.testing.expect(sender.sendMsgsizeForTest() >= 1);

    // A subsequent normal send still succeeds and arrives (the pump is alive).
    var normal: [64]u8 = @splat(0x22);
    try sender.sendRawForTest(receiver.localAddress(), &normal, .ect0, null);
    const batch = try RawReceiveScratch.create(allocator, receiver.gro_segments);
    defer batch.destroy(allocator);
    var payloads: [socket_batch_size][]const u8 = undefined;
    var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
    const n = try receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, batch);
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(usize, 64), payloads[0].len);
}

test "L10: a transient send failure is swallowed and later traffic succeeds" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const sender = try newTestEndpoint(allocator, io, 0xA4);
    defer sender.deinit();
    const receiver = try newTestEndpoint(allocator, io, 0xA5);
    defer receiver.deinit();

    // Inject EPERM (a representative transient non-WouldBlock failure) and
    // prove the send is swallowed as loss rather than ConnectionLost.
    udp_cmsg.test_inject_errno = .PERM;
    var dgram: [64]u8 = @splat(0x33);
    try sender.sendRawForTest(receiver.localAddress(), &dgram, .ect0, null);
    try std.testing.expect(sender.sendTransientForTest() >= 1);

    // The connection/send path remains usable afterward.
    var after: [64]u8 = @splat(0x44);
    try sender.sendRawForTest(receiver.localAddress(), &after, .ect0, null);
    const batch = try RawReceiveScratch.create(allocator, receiver.gro_segments);
    defer batch.destroy(allocator);
    var payloads: [socket_batch_size][]const u8 = undefined;
    var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
    const n = try receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, batch);
    try std.testing.expect(n >= 1);
}

test "L11: IP_TOS EINVAL retries without the cmsg and the send succeeds" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const sender = try newTestEndpoint(allocator, io, 0xA6);
    defer sender.deinit();
    const receiver = try newTestEndpoint(allocator, io, 0xA7);
    defer receiver.deinit();
    try std.testing.expect(!sender.sendmsgEinvalForTest());

    // Inject EINVAL for the cmsg-carrying send only (one-shot). The endpoint
    // must latch sendmsg_einval, re-encode WITHOUT IP_TOS, and deliver on retry.
    udp_cmsg.test_inject_errno = .INVAL;
    var dgram: [64]u8 = @splat(0x55);
    try sender.sendRawForTest(receiver.localAddress(), &dgram, .ect0, null);
    try std.testing.expect(sender.sendmsgEinvalForTest());
    try std.testing.expect(sender.sendEinvalRetryForTest() >= 1);

    // The retry delivered the datagram even though the first send was rejected.
    const batch = try RawReceiveScratch.create(allocator, receiver.gro_segments);
    defer batch.destroy(allocator);
    var payloads: [socket_batch_size][]const u8 = undefined;
    var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
    const n = try receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, batch);
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(usize, 64), payloads[0].len);

    // Once latched, subsequent ECN sends omit the cmsg (no retry counter bump).
    var after: [64]u8 = @splat(0x66);
    const retries_before = sender.sendEinvalRetryForTest();
    try sender.sendRawForTest(receiver.localAddress(), &after, .ect0, null);
    try std.testing.expectEqual(retries_before, sender.sendEinvalRetryForTest());
}

test "noq Endpoint deinit zeroizes secret + token/reset keys without touching caller copy" {
    // Backing covers the endpoint struct PLUS its heap-owned receive buffer
    // (worst case the full GRO window, allocated in `initOptions`) plus slack
    // for router/token/ALPN internals.
    const backing = try std.heap.page_allocator.alloc(u8, @sizeOf(Endpoint) + gro_recv_capacity + (1 << 20));
    defer std.heap.page_allocator.free(backing);
    var fba = std.heap.FixedBufferAllocator.init(backing);
    const allocator = fba.allocator();

    const seed = [_]u8{0x42} ** 32;
    const caller_secret = key.SecretKey.fromBytes(seed);
    const endpoint = try Endpoint.init(allocator, std.testing.io, caller_secret, "iroh-noq-zeroize-deinit");
    try std.testing.expectEqual(seed, endpoint.secret.toBytes());
    endpoint.deinit();

    try std.testing.expectEqual([_]u8{0} ** 32, endpoint.secret.toBytes());
    try std.testing.expectEqual([_]u8{0} ** 32, endpoint.reset_key);
    try std.testing.expectEqual([_]u8{0} ** 32, endpoint.token_key.prk);
    try std.testing.expectEqual(seed, caller_secret.toBytes());
}

test "noq Endpoint init-failure zeroizes secret + token/reset keys without touching caller copy" {
    // Backing covers the endpoint struct PLUS its heap-owned receive buffer
    // (worst case the full GRO window, allocated in `initOptions`) plus slack
    // for router/token/ALPN internals.
    const backing = try std.heap.page_allocator.alloc(u8, @sizeOf(Endpoint) + gro_recv_capacity + (1 << 20));
    defer std.heap.page_allocator.free(backing);
    var fba = std.heap.FixedBufferAllocator.init(backing);
    const allocator = fba.allocator();

    const seed = [_]u8{0x5a} ** 32;
    const caller_secret = key.SecretKey.fromBytes(seed);
    const oversized_alpn: [:0]const u8 = "x" ** 65;
    const result = Endpoint.initOptions(allocator, std.testing.io, caller_secret, oversized_alpn, .{});
    try std.testing.expectError(error.InvalidAlpn, result);

    const endpoint: *Endpoint = @ptrCast(@alignCast(backing.ptr));
    try std.testing.expectEqual([_]u8{0} ** 32, endpoint.secret.toBytes());
    try std.testing.expectEqual([_]u8{0} ** 32, endpoint.reset_key);
    try std.testing.expectEqual([_]u8{0} ** 32, endpoint.token_key.prk);
    try std.testing.expectEqual(seed, caller_secret.toBytes());
}

test {
    _ = @import("transport").factory;
}
