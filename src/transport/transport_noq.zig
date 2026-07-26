//! Greenfield noq QUIC engine wired behind the frozen `transport.zig` vtable.
//!
//! This is the THIRD transport backend (alongside the two picoquic ones in
//! `transport/quic.zig` and `transport/endpoint.zig`). It drives the sans-io noq
//! driver (`quic/connection.zig`) over a real UDP `net.Socket` pump, demuxing
//! inbound datagrams through the CID router (`quic/endpoint.zig`). Modeled on the
//! mutex-free `transport/endpoint.zig` (the port's forward direction), NOT the
//! mutex-based `transport/quic.zig`.
//!
//! Scope: N3b-5 slice 5c — the vtable impl + UDP pump + router integration +
//! client-connect AND server-accept + persistent-endpoint reclaim. The stream
//! layer, flow control, close/reset frames, and real retransmit already live in
//! the driver (5a+5b); 5c is pure vtable/pump/router glue on top of that API.
//!
//! The all-in-one default still selects picoquic for compatibility; mono noq
//! products select this backend through the engine-select factory.

const std = @import("std");
const tr = @import("../transport.zig");
const key = @import("../key.zig");
const tls_name = @import("../connection/tls_name.zig");
const crypto = @import("../quic/crypto.zig");
const packet = @import("../quic/packet.zig");
const quic_conn = @import("../quic/connection.zig");
const router_mod = @import("../quic/endpoint.zig");
const magicsock = @import("../magicsock/mod.zig");
const ms_frames = @import("../magicsock/frames.zig");
const uni_poll = @import("uni_poll.zig");
const udp_cmsg = @import("udp_cmsg.zig");
const zigtls = if (crypto.zigtls_enabled) @import("zigtls") else struct {};

const net = std.Io.net;

/// Engine tag — distinguishing field so a transport-level gate can prove it is
/// actually exercising noq (harness-fake resistance), not picoquic.
pub const Engine = enum { picoquic, noq };

/// A relay-delivered datagram (source node + payload). Mirrors the shape of the
/// picoquic backend's engine-agnostic `RelayDatagramClient` (transport/quic.zig)
/// so the same relay transport can front either engine.
pub const RelayDatagram = struct {
    src: key.NodeId,
    data: []u8,
};

/// Engine-agnostic relay datagram client: `send` to a node, `recv` the next
/// datagram addressed to us. The noq pump routes here when magicsock selects a
/// `.relay` path, feeding received relay datagrams back via `handleDatagram`.
pub const RelayClient = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (*anyopaque, key.NodeId, []const u8) tr.Error!void,
        recv: *const fn (*anyopaque, []u8) tr.Error!?RelayDatagram,
    };

    pub fn send(self: RelayClient, dst: key.NodeId, data: []const u8) tr.Error!void {
        return self.vtable.send(self.context, dst, data);
    }
    pub fn recv(self: RelayClient, buffer: []u8) tr.Error!?RelayDatagram {
        return self.vtable.recv(self.context, buffer);
    }
};

const max_conns = 16;
const max_stream_impls = 64;
const max_peer_streams = 32;
const max_datagram = 2048;
const handshake_timeout_ns: i64 = 10 * std.time.ns_per_s;
const default_stream_timeout_ns: i64 = 60 * std.time.ns_per_s;
const drive_quiesce_deadline_ns: i64 = 5 * std.time.ns_per_s;
const send_writer_buffer_len: usize = 16 * 1024;
const send_buffer_high_water: usize = 2 * 1024 * 1024;
const send_buffer_low_water: usize = 1 * 1024 * 1024;
const recv_reader_buffer_len: usize = 32 * 1024;
const local_cid_len: usize = 8;
const socket_batch_size: usize = 8;
const zigtls_ticket_key_rotation_seconds: i64 = 6 * std.time.s_per_hour;
const zigtls_ticket_key_validity_seconds: i64 = 2 * zigtls_ticket_key_rotation_seconds;

const drain_timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromNanoseconds(0), .clock = .awake } };

const IncomingBatch = struct {
    messages: [socket_batch_size]net.IncomingMessage = undefined,
    data: [socket_batch_size * max_datagram]u8 = undefined,
    /// Per-message ancillary-data buffers. `receiveManyTimeout` requires every
    /// message's `control` slice to be initialized by the caller; without these
    /// the kernel has nowhere to put the ECN cmsg and CE marks are invisible.
    control: [socket_batch_size][udp_cmsg.recv_control_space]u8 = undefined,

    fn init(self: *IncomingBatch) void {
        for (&self.messages, &self.control) |*message, *control| {
            message.* = net.IncomingMessage.init;
            message.control = control;
        }
    }
};

/// Public scratch for `receiveRawForTest`, so the behavioral oracle can drive
/// raw socket receives without depending on the pump's internal batch type.
pub const RawReceiveScratch = IncomingBatch;

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
const OutgoingBatch = struct {
    bytes: [max_gso_segments * max_datagram]u8 = undefined,
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
    info: zigtls.tls13.session.NewSessionTicketInfo,

    fn deinit(self: *CachedZigtlsTicket, allocator: std.mem.Allocator) void {
        self.info.deinit(allocator);
        self.* = undefined;
    }
} else struct {};

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

pub const Endpoint = struct {
    /// Distinguishing field: proves a transport-level gate routed to noq.
    pub const engine: Engine = .noq;

    allocator: std.mem.Allocator,
    io_inst: std.Io,
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
    certificate_request_signature_algorithms: ?[]const u16,
    zigtls_ticket_key_manager: if (crypto.zigtls_enabled) zigtls.tls13.ticket_keys.Manager else void =
        if (crypto.zigtls_enabled) zigtls.tls13.ticket_keys.Manager.init() else {},
    zigtls_ticket_key_rotated_at_unix: i64 = 0,
    zigtls_cached_ticket: if (crypto.zigtls_enabled) ?CachedZigtlsTicket else void =
        if (crypto.zigtls_enabled) null else {},
    conns: [max_conns]ConnEntry = [_]ConnEntry{.{}} ** max_conns,
    sends: [max_stream_impls]SendImpl = undefined,
    recvs: [max_stream_impls]RecvImpl = undefined,
    /// Relay datagram client (engine-agnostic vtable). When a conn's magicsock
    /// selects a `.relay` path, its datagrams route here instead of the socket.
    relay: ?RelayClient = null,

    /// Kernel reported the inbound TOS/TCLASS option was accepted, so ECN
    /// codepoints will arrive as ancillary data on receive.
    ecn_receive_enabled: bool = false,
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
    /// Datagrams received carrying a CE codepoint in a real IP header.
    stats_ecn_recv_marked: u64 = 0,
    /// Datagrams received carrying any ECT codepoint.
    stats_ecn_recv_ect: u64 = 0,

    /// Test-only: when set, outbound datagrams matching the predicate are dropped
    /// after the driver has tracked them as sent (LOSSY large-transfer gate).
    test_drop: ?*const fn (pkt_idx: usize) bool = null,
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
        /// zigtls-only server CertificateRequest offer policy; null uses the TLS default.
        certificate_request_signature_algorithms: ?[]const u16 = null,
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, secret: key.SecretKey, alpn: [:0]const u8) !*Endpoint {
        return initOptions(allocator, io, secret, alpn, .{});
    }

    pub fn initOptions(allocator: std.mem.Allocator, io: std.Io, secret: key.SecretKey, alpn: [:0]const u8, options: Options) !*Endpoint {
        if (!crypto.zigtls_enabled and options.tls_backend == .zigtls) {
            return error.ZigtlsDisabled;
        }

        const self = try allocator.create(Endpoint);
        errdefer allocator.destroy(self);

        var bind_addr = options.bind_address;
        const socket = try bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
        errdefer socket.close(io);

        var zigtls_ticket_key_manager = if (crypto.zigtls_enabled) zigtls.tls13.ticket_keys.Manager.init() else {};
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

        // CID-router hash key from the CSPRNG (dual-SipHash context, §"CID-hash").
        var hash_key: [16]u8 = undefined;
        io.random(&hash_key);

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
            .expected_peer = options.expected_peer,
            .accept_unknown_peer = options.accept_unknown_peer,
            .certificate_public_key_override = options.certificate_public_key_override,
            .certificate_der_override = options.certificate_der_override,
            .tls_backend = options.tls_backend,
            .certificate_request_signature_algorithms = options.certificate_request_signature_algorithms,
            .zigtls_ticket_key_manager = if (crypto.zigtls_enabled) zigtls_ticket_key_manager else {},
            .zigtls_ticket_key_rotated_at_unix = zigtls_ticket_key_rotated_at_unix,
            .zigtls_cached_ticket = if (crypto.zigtls_enabled) null else {},
            // Both are best-effort kernel capabilities. A kernel that refuses
            // either leaves the endpoint fully functional, just without the
            // corresponding optimisation — never a hard init failure.
            .ecn_receive_enabled = udp_cmsg.enableEcnReceive(socket.handle, bind_addr == .ip4),
            .gso_enabled = udp_cmsg.gsoSupported(socket.handle),
        };
        for (&self.sends) |*s| s.* = .{};
        for (&self.recvs) |*r| r.* = .{};
        // Seed the server-advertised ALPN set from the constructor ALPN so an
        // endpoint that never calls setAlpns still advertises something. This is
        // the first fallible step after the CID router is live, so it owns the
        // router's cleanup (the outer errdefers only cover the socket + self).
        errdefer self.router.deinit();
        try self.setAlpns(&.{alpn});
        return self;
    }

    /// Read-only: which TLS backend this endpoint feeds Connection.create.
    /// Gates assert `.zigtls` so a "zigtls smoke" cannot silently run on picotls.
    pub fn tlsBackend(self: *const Endpoint) crypto.Backend {
        return self.tls_backend;
    }

    pub fn deinit(self: *Endpoint) void {
        if (crypto.zigtls_enabled) {
            if (self.zigtls_cached_ticket) |*cached| cached.deinit(self.allocator);
            self.zigtls_cached_ticket = null;
        }
        for (&self.conns) |*e| {
            if (e.used) {
                if (e.magic_init) e.magic.deinit();
                e.driver.destroy();
            }
        }
        self.router.deinit();
        self.socket.close(self.io_inst);
        for (self.server_alpns.items) |owned| self.allocator.free(owned);
        self.server_alpns.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn transport(self: *Endpoint) tr.Transport {
        return .{ .context = self, .vtable = &endpoint_vtable };
    }

    pub fn localAddress(self: *Endpoint) net.IpAddress {
        return self.local_address;
    }

    /// Monotonic clock (nanoseconds) fed to the driver as `Instant`.
    fn clockNow(self: *const Endpoint) i64 {
        return @intCast(std.Io.Clock.now(.awake, self.io_inst).nanoseconds);
    }

    /// True iff at least one connection is currently live (reclaim gate helper).
    pub fn liveConnectionCount(self: *const Endpoint) usize {
        var n: usize = 0;
        for (self.conns) |e| {
            if (e.used) n += 1;
        }
        return n;
    }

    /// Test hook: pump one round + drain events (the pump the vtable normally
    /// runs internally during a blocking op). Used to observe a peer close after
    /// the local side has finished all its blocking vtable calls.
    pub fn pumpForTest(self: *Endpoint) tr.Error!void {
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

    /// Replace server-advertised ALPNs (new inbound handshakes only).
    ///
    /// Backs the multi-ALPN `Router` in `src/protocol.zig`: the Router registers
    /// every handler's ALPN here before its accept loop starts, then dispatches
    /// each accepted connection on `Connection.alpn()`.
    pub fn setAlpns(self: *Endpoint, alpns: []const []const u8) SetAlpnsError!void {
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
        try self.pollOnce();
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
                return .{ .context = impl, .vtable = &connection_vtable };
            }
            if (e.used and e.role == .server and e.lost) {
                self.reclaim(e);
            }
        }
        return null;
    }

    /// Test hook: install an outbound drop filter (LOSSY gate). Predicate sees a
    /// 1-based packet index; returning true drops the datagram on the wire while
    /// leaving the driver's sent-record intact so loss recovery must fire.
    pub fn setTestDropFilter(self: *Endpoint, filter: ?*const fn (usize) bool) void {
        self.test_drop = filter;
        self.test_tx_count = 0;
    }

    pub fn setTestStreamTimeout(self: *Endpoint, timeout_ns: i64) void {
        self.stream_timeout_ns = timeout_ns;
    }

    /// Test hook: first live connection's driver (client or server by role).
    pub fn testDriver(self: *Endpoint, role: crypto.Role) ?*quic_conn.Connection {
        for (&self.conns) |*e| {
            if (e.used and e.role == role) return e.driver;
        }
        return null;
    }

    /// Test hook: smoothed RTT of the first live connection of `role` (H1 real-peer).
    pub fn smoothedRttNsForTest(self: *Endpoint, role: crypto.Role) ?i64 {
        const drv = self.testDriver(role) orelse return null;
        return drv.smoothedRttNsForTest();
    }

    /// Test hook: clear peer reset tokens on the first live conn of `role` (H3 mutation-RED).
    pub fn clearPeerStatelessResetTokensForTest(self: *Endpoint, role: crypto.Role) void {
        if (self.testDriver(role)) |drv| drv.clearPeerStatelessResetTokensForTest();
    }

    /// Test hook: hard-disable peer reset matching (H3 mutation-RED disable-point).
    pub fn setDisablePeerStatelessResetForTest(self: *Endpoint, role: crypto.Role, disable: bool) void {
        if (self.testDriver(role)) |drv| drv.setDisablePeerStatelessResetForTest(disable);
    }

    /// Test hook: first live conn of `role` is draining on a peer stateless reset.
    pub fn isDrainingStatelessResetForTest(self: *Endpoint, role: crypto.Role) bool {
        const drv = self.testDriver(role) orelse return false;
        return drv.isDrainingStatelessResetForTest();
    }

    /// Test hook: feed a raw datagram into the first live conn of `role` (M1/H3 inject).
    /// Decrypt/malformed errors are swallowed (same as the production pump) so a
    /// crafted reset that does not match still exercises the detection path.
    pub fn injectDatagramForTest(self: *Endpoint, role: crypto.Role, datagram: []const u8) tr.Error!void {
        const drv = self.testDriver(role) orelse return error.ConnectionLost;
        const now = self.clockNow();
        drv.handleDatagram(now, datagram) catch {};
        for (&self.conns) |*e| {
            if (e.used and e.role == role) self.drainEvents(e);
        }
    }

    pub fn hasZigtlsResumptionTicketForTest(self: *Endpoint, peer: key.NodeId) bool {
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
        const drv = self.testDriver(role) orelse return null;
        return drv.streamRecvBufferedLen(stream_id);
    }

    /// Test hook: has any server connection observed a peer CONNECTION_CLOSE?
    pub fn serverObservedClose(self: *const Endpoint) bool {
        for (self.conns) |e| {
            if (e.used and e.role == .server and e.lost) return true;
        }
        return false;
    }

    /// Gate B: server's local CID must be freshly chosen, not the client's
    /// original DCID retained as a local identity.
    pub fn serverUsesFreshLocalCid(self: *const Endpoint) bool {
        for (self.conns) |e| {
            if (e.used and e.role == .server) {
                return !std.mem.eql(u8, e.driver.local_cid.slice(), e.driver.initial_dcid.slice());
            }
        }
        return false;
    }

    /// Gate B: only a post-CertificateVerify key is observable on the server.
    pub fn serverHasVerifiedPeer(self: *const Endpoint) bool {
        for (self.conns) |e| {
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
        for (self.conns) |e| {
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
        const e = self.firstLive() orelse return;
        e.driver.advertiseAddress(.{ .kind = .reach_out, .seq = seq, .ip = ip, .port = port });
    }

    /// How many remote candidates magicsock has learned on the live conn.
    pub fn magicCandidateCount(self: *Endpoint) usize {
        const e = self.firstLive() orelse return 0;
        if (!e.magic_init) return 0;
        return e.magic.remote_candidates.items.len;
    }

    /// The magicsock-selected path address, or null if none is validated yet.
    /// Unvalidated (idle/active) candidates are NEVER selected.
    pub fn magicSelectedAddr(self: *Endpoint) ?net.IpAddress {
        const e = self.firstLive() orelse return null;
        if (!e.magic_init) return null;
        const cand = e.magic.selectedPath() orelse return null;
        return cand.address;
    }

    /// Probe every idle candidate with a REAL PATH_CHALLENGE (random token). The
    /// candidate is only marked succeeded when the peer echoes the token back
    /// (handled in `drainEvents` on `.path_validated`).
    pub fn probeCandidates(self: *Endpoint) void {
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
        const e = self.firstLive() orelse return;
        if (!e.magic_init) return;
        e.magic.addRelayCandidate(seq) catch return;
        e.magic.selectRelayFallback();
        if (e.magic.selectedPath()) |cand| {
            e.relay_selected = cand.kind == .relay;
        }
    }

    pub fn setRelay(self: *Endpoint, relay: RelayClient) void {
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
    fn socketSend(self: *Endpoint, dest: *const net.IpAddress, tx: quic_conn.Transmit) tr.Error!void {
        const segment_size = tx.segment_size;
        const use_gso = self.gso_enabled and segment_size != null and
            segment_size.? > 0 and tx.bytes.len > segment_size.?;

        var control_buf: [udp_cmsg.send_control_space]u8 = undefined;
        var enc = udp_cmsg.Encoder.init(&control_buf);
        if (tx.ecn) |codepoint| {
            enc.pushEcn(dest.* == .ip4, codepoint) catch return error.ConnectionLost;
        }
        if (use_gso) enc.pushSegmentSize(segment_size.?) catch return error.ConnectionLost;

        const control = enc.finish();
        if (control.len == 0) {
            self.socket.send(self.io_inst, dest, tx.bytes) catch return error.ConnectionLost;
            return;
        }

        udp_cmsg.sendWithControl(self.socket.handle, dest, tx.bytes, control, use_gso) catch |err| switch (err) {
            // The batch was refused. Disable GSO for the endpoint's lifetime and
            // deliver the payload per-datagram so no bytes are dropped.
            error.GsoRejected => {
                self.gso_enabled = false;
                self.stats_gso_rejected += 1;
                return self.sendPerDatagram(dest, tx, segment_size.?);
            },
            error.SendFailed => return error.ConnectionLost,
        };

        if (tx.ecn != null) self.stats_ecn_sent += 1;
        if (use_gso) {
            self.stats_gso_segmented_sends += 1;
            const segments = (tx.bytes.len + segment_size.? - 1) / segment_size.?;
            self.stats_gso_segments_sent += segments;
        }
    }

    /// GSO fallback: split a segmented payload and send each datagram alone,
    /// preserving the ECN codepoint on every one.
    fn sendPerDatagram(
        self: *Endpoint,
        dest: *const net.IpAddress,
        tx: quic_conn.Transmit,
        segment_size: u16,
    ) tr.Error!void {
        var offset: usize = 0;
        while (offset < tx.bytes.len) {
            const end = @min(offset + segment_size, tx.bytes.len);
            const chunk = tx.bytes[offset..end];
            if (tx.ecn) |codepoint| {
                var control_buf: [udp_cmsg.send_control_space]u8 = undefined;
                var enc = udp_cmsg.Encoder.init(&control_buf);
                enc.pushEcn(dest.* == .ip4, codepoint) catch return error.ConnectionLost;
                udp_cmsg.sendWithControl(self.socket.handle, dest, chunk, enc.finish(), false) catch
                    return error.ConnectionLost;
                self.stats_ecn_sent += 1;
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
        var cid_bytes: [local_cid_len]u8 = undefined;
        self.io_inst.random(&cid_bytes);
        const scid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
        self.io_inst.random(&cid_bytes);
        const initial_dcid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
        var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        self.io_inst.random(&seed_bytes);
        const sni = tls_name.serverName(peer);

        const drv = quic_conn.Connection.create(self.allocator, .{
            .backend = self.tls_backend,
            .role = .client,
            .secret_key = self.secret,
            .peer_public_key = peer,
            .certificate_public_key = self.certificate_public_key_override,
            .certificate_der_override = self.certificate_der_override,
            .alpn = self.alpn,
            .server_name = &sni,
            .zigtls_resumption_ticket = if (crypto.zigtls_enabled) self.cachedZigtlsResumptionTicket(peer) else null,
        }, scid, initial_dcid, initial_dcid, seed_bytes) catch return error.ConnectionLost;

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

    /// Test hook: make the first live conn of `role` stamp `codepoint` on its
    /// outgoing 1-RTT data instead of ECT(0). Loopback has no router to apply
    /// CE, so this is how a CE mark is put on the wire; it still traverses a
    /// real IP header and is still decoded from a real cmsg by the receiver.
    pub fn setEcnOverrideForTest(self: *Endpoint, role: crypto.Role, codepoint: ?udp_cmsg.EcnCodepoint) void {
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
        const maybe_err, const count = self.socket.receiveManyTimeout(
            self.io_inst,
            &scratch.messages,
            &scratch.data,
            .{},
            timeout,
        );
        if (maybe_err) |err| return err;
        const n = @min(count, payloads.len);
        for (scratch.messages[0..n], 0..) |msg, i| {
            payloads[i] = msg.data;
            codepoints[i] = udp_cmsg.decodeEcn(msg.control);
            if (codepoints[i]) |cp| switch (cp) {
                .ce => self.stats_ecn_recv_marked += 1,
                .ect0, .ect1 => self.stats_ecn_recv_ect += 1,
            };
        }
        return n;
    }

    // ── the UDP pump (design §2.2) ───────────────────────────────────────────

    fn pumpOutgoing(self: *Endpoint) tr.Error!bool {
        var sent = false;
        var batch: OutgoingBatch = .{};
        const now = self.clockNow();
        for (&self.conns) |*e| {
            if (!e.used) continue;
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
                    if (e.relay_selected and self.relay != null and e.remote_node_set) {
                        // magicsock selected a relay path → route via the relay
                        // client. Flush first so relay and socket datagrams
                        // cannot be reordered relative to each other.
                        try self.flushBatch(&batch);
                        self.relay.?.send(e.remote_node, tx.bytes) catch return error.ConnectionLost;
                    } else if (self.gso_enabled and tx.segment_size == null) {
                        // Coalesce into the pending GSO batch when possible;
                        // otherwise flush what is staged and start fresh.
                        if (!batch.accepts(e.remote, tx.ecn, tx.bytes.len)) {
                            try self.flushBatch(&batch);
                        }
                        batch.push(e.remote, tx.ecn, tx.bytes);
                    } else {
                        try self.flushBatch(&batch);
                        try self.socketSend(&e.remote, tx);
                    }
                }
                sent = true;
            }
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
    fn pumpRelayIncoming(self: *Endpoint) tr.Error!bool {
        const relay = self.relay orelse return false;
        var progressed = false;
        while (true) {
            var buf: [max_datagram]u8 = undefined;
            const dg = (relay.recv(&buf) catch return error.ConnectionLost) orelse break;
            for (&self.conns) |*e| {
                if (e.used and e.remote_node_set and e.remote_node.eql(dg.src)) {
                    e.driver.handleDatagram(self.clockNow(), dg.data) catch {};
                    self.drainEvents(e);
                    break;
                }
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
        }
        return .{ .duration = .{ .raw = .fromNanoseconds(wait_ns), .clock = .awake } };
    }

    fn pumpIncomingAfter(self: *Endpoint, prior_progress: bool) tr.Error!bool {
        var progressed = prior_progress;
        if (try self.pumpRelayIncoming()) progressed = true;
        var batch: RawReceiveScratch = undefined;
        while (true) {
            batch.init();
            const timeout = self.receiveTimeout(progressed);
            const maybe_err, const count = self.socket.receiveManyTimeout(
                self.io_inst,
                &batch.messages,
                &batch.data,
                .{},
                timeout,
            );
            if (maybe_err) |err| switch (err) {
                error.Timeout => break,
                else => return error.ConnectionLost,
            };
            if (count == 0) break;
            for (batch.messages[0..count]) |msg| {
                const four: router_mod.FourTuple = .{ .local = self.routerLocal(), .remote = toSockAddr(msg.from) };
                if (try self.route(four, msg.data, msg.from)) |entry| {
                    // Read the ECN codepoint off the REAL IP header before the
                    // datagram is decrypted: a CE mark is path feedback and
                    // stands whether or not the payload turns out to be valid
                    // for this connection.
                    self.ingestEcn(entry, msg.control);
                    entry.driver.handleDatagram(self.clockNow(), msg.data) catch |err| switch (err) {
                        // A TLS authentication failure is not a malformed-packet
                        // drop: fail closed and ensure `accept` can never hand out
                        // the unauthenticated server-side connection.
                        error.PicotlsError => {
                            entry.rejected = true;
                            entry.lost = true;
                        },
                        // A malformed / undecryptable datagram must not kill the pump
                        // (fail-closed on attacker-controlled decode). Drop it.
                        else => {},
                    };
                    self.drainEvents(entry);
                } else {
                    // RFC 9000 §10.3: a stateless reset is intentionally unroutable by
                    // DCID (random short-header shape). When demux finds no owner,
                    // still scan live connections for a matching peer reset token.
                    // Without this, real-peer resets never reach matchesPeerStatelessReset
                    // (the unit test fed handleDatagram directly and hid the gap).
                    try self.scanUnroutableForStatelessReset(msg.data);
                }
            }
            progressed = true;
        }
        return progressed;
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

    pub fn pollOnce(self: *Endpoint) tr.Error!void {
        const outgoing = try self.pumpOutgoing();
        _ = try self.pumpIncomingAfter(outgoing);
    }

    /// Demux one inbound datagram to its connection entry, minting a server
    /// connection on a first-flight Initial to an unknown DCID (accept path).
    fn route(self: *Endpoint, four: router_mod.FourTuple, dgram: []const u8, from: net.IpAddress) tr.Error!?*ConnEntry {
        if (dgram.len == 0) return null;
        // 1. CID demux via the router (Initial by DCID, short-header by local-CID
        //    prefix or four-tuple). Malformed → treated as unroutable.
        if (self.router.routeDatagram(four, dgram) catch null) |r| {
            if (self.entryForHandle(r.target.handle)) |e| return e;
        }
        // 2. First-flight Initial to an unknown DCID → server accept minting.
        const is_long = (dgram[0] & packet.long_header_form) != 0;
        const is_initial = is_long and ((dgram[0] & 0x30) >> 4) == 0;
        if (is_initial and (self.expected_peer != null or self.accept_unknown_peer) and self.entryByRemote(from) == null) {
            if (dgram.len < 1200) return null;
            const first = self.router.handleFirstPacket(four, dgram) catch return null;
            switch (first) {
                .routed => |rr| return self.entryForHandle(rr.target.handle),
                .new_connection => |h| return try self.mintServerConn(h, dgram, from),
                .version_negotiation => |vn| {
                    self.socket.send(self.io_inst, &from, vn) catch {};
                    self.allocator.free(vn);
                    return null;
                },
            }
        }
        // 3. Four-tuple fallback: the router cannot parse a Handshake-space long
        //    header (returns NonInitialUnsupported), so mid-handshake packets and
        //    the client's single conn resolve by peer address. FLAGGED deviation.
        if (is_long and !is_initial) return self.entryByRemote(from);
        return null;
    }

    fn mintServerConn(self: *Endpoint, handle: router_mod.ConnectionHandle, dgram: []const u8, from: net.IpAddress) tr.Error!?*ConnEntry {
        try self.ensureZigtlsTicketKeyFresh();
        const ph = packet.decodeProtectedHeader(dgram) catch {
            self.router.removeConnection(handle) catch {};
            return null;
        };
        errdefer self.router.removeConnection(handle) catch {};
        const dst_cid = ph.initial.dst_cid; // client's original DCID (X)
        const src_cid = ph.initial.src_cid; // client's SCID (C)
        const entry = self.freeEntry() orelse {
            return error.OutOfMemory;
        };
        var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        self.io_inst.random(&seed_bytes);
        var local_cid_bytes: [local_cid_len]u8 = undefined;
        self.io_inst.random(&local_cid_bytes);
        const local_cid = packet.ConnectionId.init(&local_cid_bytes) catch {
            return error.ConnectionLost;
        };
        const drv = quic_conn.Connection.create(self.allocator, .{
            .backend = self.tls_backend,
            .role = .server,
            .secret_key = self.secret,
            .peer_public_key = self.expected_peer,
            .certificate_der_override = self.certificate_der_override,
            .require_client_authentication = true,
            .alpn = if (self.server_alpns.items.len > 0) self.server_alpns.items[0] else self.alpn,
            .server_alpns = if (self.server_alpns.items.len > 0) self.server_alpns.items else null,
            .zigtls_ticket_key_manager = if (crypto.zigtls_enabled and self.tls_backend == .zigtls) &self.zigtls_ticket_key_manager else null,
            .zigtls_auto_issue_new_session_ticket = crypto.zigtls_enabled and self.tls_backend == .zigtls,
            .certificate_request_signature_algorithms = self.certificate_request_signature_algorithms,
        }, local_cid, src_cid, dst_cid, seed_bytes) catch {
            return error.ConnectionLost;
        };
        errdefer drv.destroy();
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

    /// Drain driver events into the entry's flags (connected / lost / peer-stream
    /// opened / reset). Stream bytes are read directly from the driver.
    fn drainEvents(self: *Endpoint, entry: *ConnEntry) void {
        while (entry.driver.poll()) |ev| {
            switch (ev) {
                .connected => {
                    entry.connected = true;
                    self.cacheZigtlsTicket(entry);
                },
                .connection_lost => entry.lost = true,
                .stream_opened => |s| {
                    if (isPeerInitiated(entry.role, s.id)) entry.notePeerStream(s.id);
                },
                .stream_reset => |s| entry.noteReset(s.id),
                .nat_address => |a| {
                    // Feed the n0 NAT-traversal frame into magicsock (5e).
                    if (entry.magic_init) entry.magic.handleFrame(natToMagic(a)) catch {};
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
                },
                else => {},
            }
        }
        self.cacheZigtlsTicket(entry);
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
        if (entry.magic_init) entry.magic.deinit();
        entry.driver.destroy();
        entry.* = .{};
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

const ConnectionImpl = struct {
    endpoint: *Endpoint,
    entry: *ConnEntry,
    remote: key.NodeId,
    /// ALPN snapshot taken at hand-off. Copied by value because the TLS session
    /// it came from is owned by the driver and may be torn down before the
    /// caller stops asking; the Router dispatches on this.
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
};

pub fn connectionIsClosed(conn: tr.Connection) bool {
    const impl: *ConnectionImpl = @ptrCast(@alignCast(conn.context));
    return !impl.entry.used or impl.entry.lost;
}

pub fn connectionNextInboundUniEvent(conn: tr.Connection, buffer: []u8) tr.Error!?uni_poll.InboundUniEvent {
    if (buffer.len == 0) return null;
    const impl: *ConnectionImpl = @ptrCast(@alignCast(conn.context));
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

fn endpointConnect(ctx: *anyopaque, peer: tr.NodeAddr) tr.Error!tr.Connection {
    const self: *Endpoint = @ptrCast(@alignCast(ctx));
    const ip = peer.firstIpAddr() orelse return error.NotConnected;

    var cid_bytes: [local_cid_len]u8 = undefined;
    self.io_inst.random(&cid_bytes);
    const scid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
    self.io_inst.random(&cid_bytes);
    const initial_dcid = packet.ConnectionId.init(&cid_bytes) catch return error.ConnectionLost;
    var seed_bytes: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
    self.io_inst.random(&seed_bytes);
    const sni = tls_name.serverName(peer.id);

    const drv = quic_conn.Connection.create(self.allocator, .{
        .backend = self.tls_backend,
        .role = .client,
        .secret_key = self.secret,
        .peer_public_key = peer.id,
        .certificate_public_key = self.certificate_public_key_override,
        .certificate_der_override = self.certificate_der_override,
        .alpn = self.alpn,
        .server_name = &sni,
        .zigtls_resumption_ticket = if (crypto.zigtls_enabled) self.cachedZigtlsResumptionTicket(peer.id) else null,
    }, scid, initial_dcid, initial_dcid, seed_bytes) catch return error.ConnectionLost;

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

    drv.startClient() catch {
        self.reclaim(entry);
        return error.ConnectionLost;
    };
    self.driveToConnected(entry) catch |err| {
        self.reclaim(entry);
        return err;
    };
    // The client reaches `connected` once it has 1-RTT keys, but the SERVER only
    // completes after it receives the client's final Handshake flight (Finished +
    // ACKs). Flush that flight now so a caller that blocks (e.g. awaiting accept)
    // does not deadlock the server's completion. (On a lossy path the stream
    // phase's pumping would also carry it; on loopback this flush suffices.)
    self.driveQuiescent() catch {};
    self.cacheZigtlsTicket(entry);

    const remote_node = drv.tls.peerPublicKey() catch peer.id;
    const impl = self.allocator.create(ConnectionImpl) catch {
        self.reclaim(entry);
        return error.OutOfMemory;
    };
    impl.* = .{ .endpoint = self, .entry = entry, .remote = remote_node };
    impl.snapshotAlpn(entry);
    return .{ .context = impl, .vtable = &connection_vtable };
}

fn endpointAccept(ctx: *anyopaque) tr.Error!tr.Connection {
    const self: *Endpoint = @ptrCast(@alignCast(ctx));
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
                return .{ .context = impl, .vtable = &connection_vtable };
            }
            if (e.used and e.role == .server and e.lost) {
                self.reclaim(e);
            }
        }
    }
    return error.Timeout;
}

fn endpointLocalNodeId(ctx: *anyopaque) tr.NodeId {
    const self: *Endpoint = @ptrCast(@alignCast(ctx));
    return self.node_id;
}

fn endpointIo(ctx: *anyopaque) std.Io {
    const self: *Endpoint = @ptrCast(@alignCast(ctx));
    return self.io_inst;
}

const endpoint_vtable: tr.Transport.VTable = .{
    .connect = endpointConnect,
    .accept = endpointAccept,
    .localNodeId = endpointLocalNodeId,
    .io = endpointIo,
};

fn connOpenBi(ctx: *anyopaque) tr.Error!tr.BiStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    const id = conn.entry.driver.openStream(.bidi) catch return error.ConnectionLost;
    const send = try conn.endpoint.sendFor(conn.entry, id);
    const recv = try conn.endpoint.recvFor(conn.entry, id);
    return .{ .send = .{ .context = send, .vtable = &send_vtable }, .recv = .{ .context = recv, .vtable = &recv_vtable } };
}

fn connAcceptBi(ctx: *anyopaque) tr.Error!tr.BiStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    const id = try conn.endpoint.driveUntilPeerStream(conn.entry, true);
    const send = try conn.endpoint.sendFor(conn.entry, id);
    const recv = try conn.endpoint.recvFor(conn.entry, id);
    return .{ .send = .{ .context = send, .vtable = &send_vtable }, .recv = .{ .context = recv, .vtable = &recv_vtable } };
}

fn connOpenUni(ctx: *anyopaque) tr.Error!tr.SendStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    const id = conn.entry.driver.openStream(.uni) catch return error.ConnectionLost;
    const send = try conn.endpoint.sendFor(conn.entry, id);
    return .{ .context = send, .vtable = &send_vtable };
}

fn connAcceptUni(ctx: *anyopaque) tr.Error!tr.RecvStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    const id = try conn.endpoint.driveUntilPeerStream(conn.entry, false);
    const recv = try conn.endpoint.recvFor(conn.entry, id);
    return .{ .context = recv, .vtable = &recv_vtable };
}

fn connRemoteNodeId(ctx: *anyopaque) tr.NodeId {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    return conn.remote;
}

fn connClose(ctx: *anyopaque) void {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    const endpoint = conn.endpoint;
    const entry = conn.entry;
    entry.driver.close(endpoint.clockNow());
    // Flush the CONNECTION_CLOSE so the peer observes it (enters draining) rather
    // than idle-timing-out, then reclaim the slot (persistent-endpoint discipline).
    endpoint.driveQuiescent() catch {};
    endpoint.reclaim(entry);
    endpoint.allocator.destroy(conn);
}

fn connIo(ctx: *anyopaque) std.Io {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    return conn.endpoint.io_inst;
}

fn connAlpn(ctx: *anyopaque) ?[]const u8 {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    if (conn.alpn_len == 0) return null;
    return conn.alpn_storage[0..conn.alpn_len];
}

const connection_vtable: tr.Connection.VTable = .{
    .openBi = connOpenBi,
    .acceptBi = connAcceptBi,
    .openUni = connOpenUni,
    .acceptUni = connAcceptUni,
    .remoteNodeId = connRemoteNodeId,
    .alpn = connAlpn,
    .close = connClose,
    .io = connIo,
};

// ── SendStream / RecvStream adapters (std.Io byte pipes over the driver) ──────

const SendFailure = enum { connection_lost, stream_reset, timeout };

const SendImpl = struct {
    used: bool = false,
    endpoint: *Endpoint = undefined,
    entry: *ConnEntry = undefined,
    stream_id: u64 = 0,
    writer_storage: std.Io.Writer = undefined,
    writer_buffer: [send_writer_buffer_len]u8 = undefined,
    write_failure: ?SendFailure = null,
};

const RecvImpl = struct {
    used: bool = false,
    endpoint: *Endpoint = undefined,
    entry: *ConnEntry = undefined,
    stream_id: u64 = 0,
    reader_storage: std.Io.Reader = undefined,
    reader_buffer: [recv_reader_buffer_len]u8 = undefined,
    reader_ready: bool = false,
    finished: bool = false,
};

fn sendWriter(ctx: *anyopaque) *std.Io.Writer {
    const send: *SendImpl = @ptrCast(@alignCast(ctx));
    return &send.writer_storage;
}

fn queueSendBytes(send: *SendImpl, bytes: []const u8) std.Io.Writer.Error!void {
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
            if (send.entry.hasReset(send.stream_id)) {
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

fn sendFinish(ctx: *anyopaque) tr.Error!void {
    const send: *SendImpl = @ptrCast(@alignCast(ctx));
    send.writer_storage.flush() catch return switch (send.write_failure orelse .connection_lost) {
        .connection_lost => error.ConnectionLost,
        .stream_reset => error.StreamReset,
        .timeout => error.Timeout,
    };
    send.entry.driver.writeStream(send.stream_id, &.{}, true) catch return error.ConnectionLost;
    const deadline = send.endpoint.clockNow() + send.endpoint.stream_timeout_ns;
    while (send.endpoint.clockNow() < deadline) {
        const outgoing = try send.endpoint.pumpOutgoing();
        _ = try send.endpoint.pumpIncomingAfter(outgoing);
        if (send.entry.hasReset(send.stream_id)) return error.StreamReset;
        if (send.entry.lost) return error.ConnectionLost;
        if (send.entry.driver.streamSendComplete(send.stream_id)) {
            send.entry.driver.releaseStreamSendBuffer(send.stream_id);
            return;
        }
    }
    return error.Timeout;
}

fn sendFlush(ctx: *anyopaque) tr.Error!void {
    const send: *SendImpl = @ptrCast(@alignCast(ctx));
    send.writer_storage.flush() catch return switch (send.write_failure orelse .connection_lost) {
        .connection_lost => error.ConnectionLost,
        .stream_reset => error.StreamReset,
        .timeout => error.Timeout,
    };
    const outgoing = try send.endpoint.pumpOutgoing();
    _ = try send.endpoint.pumpIncomingAfter(outgoing);
}

fn sendReset(ctx: *anyopaque) void {
    const send: *SendImpl = @ptrCast(@alignCast(ctx));
    if (!send.used) return;
    send.entry.driver.resetStream(send.stream_id, 0) catch {};
    send.endpoint.driveQuiescent() catch {};
}

const send_vtable: tr.SendStream.VTable = .{ .writer = sendWriter, .flush = sendFlush, .finish = sendFinish, .reset = sendReset };

fn recvReader(ctx: *anyopaque) *std.Io.Reader {
    const recv: *RecvImpl = @ptrCast(@alignCast(ctx));
    if (!recv.reader_ready) {
        recv.reader_storage = .{
            .vtable = &noq_reader_vtable,
            .buffer = recv.reader_buffer[0..],
            .seek = 0,
            .end = 0,
        };
        recv.reader_ready = true;
    }
    return &recv.reader_storage;
}

fn recvStop(ctx: *anyopaque) tr.Error!void {
    const recv: *RecvImpl = @ptrCast(@alignCast(ctx));
    if (!recv.used) return error.NotConnected;
    recv.entry.driver.stopStream(recv.stream_id, 0) catch return error.ConnectionLost;
    const outgoing = try recv.endpoint.pumpOutgoing();
    _ = try recv.endpoint.pumpIncomingAfter(outgoing);
    recv.finished = true;
}

fn recvReadInto(recv: *RecvImpl, dests: [][]u8) std.Io.Reader.Error!usize {
    if (recv.finished) return error.EndOfStream;
    const deadline = recv.endpoint.clockNow() + recv.endpoint.stream_timeout_ns;
    while (recv.endpoint.clockNow() < deadline) {
        if (recv.entry.hasReset(recv.stream_id)) return error.ReadFailed;
        if (recv.entry.lost) return error.ReadFailed;

        var total: usize = 0;
        for (dests) |dest| {
            if (dest.len == 0) continue;
            const n = recv.entry.driver.readStreamInto(recv.stream_id, dest);
            total += n;
            if (n < dest.len) break;
        }
        if (total > 0) return total;
        if (recv.entry.driver.streamRecvFin(recv.stream_id) and recv.entry.driver.streamRecvBufferedLen(recv.stream_id) == 0) {
            recv.finished = true;
            return error.EndOfStream;
        }

        const outgoing = recv.endpoint.pumpOutgoing() catch return error.ReadFailed;
        _ = recv.endpoint.pumpIncomingAfter(outgoing) catch return error.ReadFailed;
    }
    return error.ReadFailed;
}

fn recvReaderReadVec(r: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
    const recv: *RecvImpl = @alignCast(@fieldParentPtr("reader_storage", r));
    return recvReadInto(recv, data);
}

fn recvReaderStream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    const recv: *RecvImpl = @alignCast(@fieldParentPtr("reader_storage", r));
    const data = limit.slice(try w.writableSliceGreedy(1));
    var vec: [1][]u8 = .{data};
    const n = recvReadInto(recv, &vec) catch |err| switch (err) {
        error.ReadFailed => return error.ReadFailed,
        error.EndOfStream => return error.EndOfStream,
    };
    w.advance(n);
    return n;
}

const noq_reader_vtable: std.Io.Reader.VTable = .{
    .stream = recvReaderStream,
    .readVec = recvReaderReadVec,
};

const recv_vtable: tr.RecvStream.VTable = .{ .reader = recvReader, .stop = recvStop };

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
    };
    const entry = (try endpoint.mintServerConn(handle, &initial, remote)) orelse return error.UnexpectedState;
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
    }, local_cid, remote_cid, remote_cid, test_seed);
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

    const data_index = @intFromEnum(@import("../quic/spaces.zig").SpaceId.data);
    const packet_keys = @import("../quic/packet_crypto.zig").PacketKeys.init(.{0x41} ** 16, .{0x42} ** 12, .{0x43} ** 16);
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
        const sender = try Endpoint.initOptions(allocator, io, key.SecretKey.fromBytes([_]u8{0xE1} ** 32), "noq-ecn-probe", .{
            .tls_backend = test_tls_backend,
        });
        errdefer sender.deinit();
        const receiver = try Endpoint.initOptions(allocator, io, key.SecretKey.fromBytes([_]u8{0xE2} ** 32), "noq-ecn-probe", .{
            .tls_backend = test_tls_backend,
        });
        return .{ .sender = sender, .receiver = receiver };
    }

    fn deinit(self: RawSocketPair) void {
        self.sender.deinit();
        self.receiver.deinit();
    }
};

test "real-socket ECN: the kernel carries our codepoint on a loopback IP header" {
    if (!udp_cmsg.is_supported) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const pair = try RawSocketPair.init(allocator, std.testing.io);
    defer pair.deinit();

    // If the kernel refused IP_RECVTOS there is nothing to observe. Report that
    // honestly rather than passing on a vacuous assertion.
    if (!pair.receiver.ecnReceiveEnabledForTest()) return error.SkipZigTest;

    var batch: RawReceiveScratch = undefined;
    for ([_]udp_cmsg.EcnCodepoint{ .ect0, .ce, .ect1 }) |expected| {
        var payload = [_]u8{ 'e', 'c', 'n', @intFromEnum(expected) };
        try pair.sender.sendRawForTest(pair.receiver.localAddress(), &payload, expected, null);

        var payloads: [1][]const u8 = undefined;
        var codepoints: [1]?udp_cmsg.EcnCodepoint = undefined;
        const n = try pair.receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, &batch);
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

    var batch: RawReceiveScratch = undefined;
    var payloads: [1][]const u8 = undefined;
    var codepoints: [1]?udp_cmsg.EcnCodepoint = undefined;
    const n = try pair.receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, &batch);
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

    var batch: RawReceiveScratch = undefined;
    var received: usize = 0;
    while (received < segments) {
        var payloads: [socket_batch_size][]const u8 = undefined;
        var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
        const n = try pair.receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, &batch);
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

    var batch: RawReceiveScratch = undefined;
    var seen: usize = 0;
    var marked: usize = 0;
    while (seen < 2) {
        var payloads: [socket_batch_size][]const u8 = undefined;
        var codepoints: [socket_batch_size]?udp_cmsg.EcnCodepoint = undefined;
        const n = try pair.receiver.receiveRawForTest(&payloads, &codepoints, 2 * std.time.ns_per_s, &batch);
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

test {
    _ = @import("factory.zig");
}
