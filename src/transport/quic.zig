//! Real QUIC-backed `Transport` implementation for the S2 direct-loopback gate.
//!
//! # Ownership precondition
//!
//! Each `Endpoint` admits **one exclusive driver at a time**. Concurrent
//! overlapping calls into Endpoint methods, Transport/Connection/stream vtable
//! ops, or the gossip chunk helpers (`connectionNextInboundUni*`,
//! `connectionConsumeInboundUniChunk`) on the same Endpoint — without external
//! serialization — are undefined behavior.
//!
//! Under `runtime_safety` (Debug **and** ReleaseSafe — this repo's safety gates
//! build ReleaseSafe, never ReleaseFast), the guard panics on concurrent entry.
//! Sequential handoff is allowed (e.g. `io.async(accept)` on a pool thread,
//! then further use on the awaiting thread after `await`): ownership is claimed
//! for the duration of each top-level call, not pinned to the creating thread.
//!
//! This is the non-throwaway stopgap for the legacy `mu`-only-covers-pump race:
//! documenting + enforcing single-owner matches the greenfield model (and
//! transfers to `endpoint.zig` until the greenfield endpoint enforces it structurally). It is **not**
//! a coarse take-mu-everywhere rework (throwaway at G5). See the transport
//! ownership synthesis for the background rationale.

const std = @import("std");
const builtin = @import("builtin");
const tr = @import("../transport.zig");
const key = @import("../key.zig");
const c = @import("../connection/c.zig").c;
const context = @import("../connection/context.zig");
const tls_name = @import("../connection/tls_name.zig");
const magicsock_frames = @import("../magicsock/frames.zig");
const magicsock = @import("../magicsock/mod.zig");
const relay_client = @import("../relay/client.zig");
const relay_proto = @import("../relay/proto.zig");
const relay_server = @import("../relay/server.zig");

const net = std.Io.net;

const legacy_fixed_stream_limit = 16;
const legacy_fixed_server_connection_limit = 16;
const default_max_stream_states = 1024;
const default_max_connection_impls = 4096;
const max_custom_frames = 16;
const max_custom_frame_len = 64;
const handshake_timeout_us: u64 = 15 * std.time.us_per_s;
const stream_open_timeout_us: u64 = 15 * std.time.us_per_s;
const stream_finish_timeout_us: u64 = 30 * std.time.us_per_s;
const stream_receive_credit_target: u64 = 128 * 1024 * 1024;
const udp_receive_max_wait_us: i64 = std.time.us_per_ms;
const udp_receive_drain_timeout: std.Io.Timeout = .{ .duration = .{
    .raw = .fromNanoseconds(0),
    .clock = .awake,
} };
const udp_receive_batch_size = 32;
const udp_receive_datagram_size = 2048;

const ReceivedUdpDatagram = struct {
    from: net.IpAddress,
    data: []u8,
};

const UdpReceiveBatch = struct {
    packets: [udp_receive_batch_size][udp_receive_datagram_size]u8 = undefined,
    items: [udp_receive_batch_size]ReceivedUdpDatagram = undefined,
    linux: LinuxStorage = .{},

    const LinuxStorage = switch (builtin.os.tag) {
        .linux => struct {
            messages: [udp_receive_batch_size]std.os.linux.mmsghdr = undefined,
            iovecs: [udp_receive_batch_size]std.posix.iovec = undefined,
            addrs: [udp_receive_batch_size]c.struct_sockaddr_storage = undefined,
        },
        else => struct {},
    };
};

const StreamState = struct {
    cnx: ?*c.picoquic_cnx_t = null,
    id: u64 = 0,
    used: bool = false,
    pico_released: bool = false,
    fin: bool = false,
    reset: bool = false,
    handed_off: bool = false,
    flow_credit_opened: bool = false,
    expected_read_capacity: usize = 0,
    read_offset: usize = 0,
    recv: std.Io.Writer.Allocating = undefined,
};

fn resetStream(stream: *StreamState) void {
    if (stream.used) stream.recv.deinit();
    stream.* = .{};
}

const CustomFrame = struct {
    len: usize = 0,
    bytes: [max_custom_frame_len]u8 = undefined,
};

const RelayDatagram = struct {
    src: key.NodeId,
    data: []u8,
};

pub const RelayDatagramClient = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (*anyopaque, key.NodeId, []const u8) tr.Error!void,
        recv: *const fn (*anyopaque, []u8) tr.Error!?RelayDatagram,
    };

    pub fn send(self: RelayDatagramClient, dst: key.NodeId, data: []const u8) tr.Error!void {
        return self.vtable.send(self.context, dst, data);
    }

    pub fn recv(self: RelayDatagramClient, buffer: []u8) tr.Error!?RelayDatagram {
        return self.vtable.recv(self.context, buffer);
    }
};

pub const DerpRelayDatagramClient = struct {
    client: *relay_client.Client,

    pub fn datagrams(self: *DerpRelayDatagramClient) RelayDatagramClient {
        return .{ .context = self, .vtable = &derp_relay_vtable };
    }
};

pub const Endpoint = struct {
    allocator: std.mem.Allocator,
    io_inst: std.Io,
    secret: key.SecretKey,
    node_id: key.NodeId,
    alpn: [:0]const u8,
    local_address: net.IpAddress,
    quic: *c.picoquic_quic_t,
    socket: net.Socket,
    streams: std.ArrayListUnmanaged(*StreamState) = .empty,
    sends: std.ArrayListUnmanaged(*SendImpl) = .empty,
    recvs: std.ArrayListUnmanaged(*RecvImpl) = .empty,
    connection_impls: std.ArrayListUnmanaged(*ConnectionImpl) = .empty,
    max_connection_impls: usize,
    max_connections: u32,
    max_stream_states: usize,
    max_inbound_stream_buffer: usize,
    accepted_server_cnx: std.AutoHashMapUnmanaged(*c.picoquic_cnx_t, void) = .empty,
    custom_frames: [max_custom_frames]CustomFrame = undefined,
    custom_frame_count: usize = 0,
    closed_connections: std.AutoHashMapUnmanaged(*c.picoquic_cnx_t, void) = .empty,
    /// Cnxs whose teardown became engine-owned when the close callback fired
    /// (remote close / application close / stateless reset). picoquic
    /// auto-deletes SERVER cnxs inside a later send pass (vendored
    /// sender.c:3806-3815); resolveDeadCnxs deletes the rest (client cnxs —
    /// the engine never auto-deletes those) at safe points.
    dead_cnxs_pending: std.ArrayList(*c.picoquic_cnx_t) = .empty,
    /// Per-connection magicsock/relay path state. Keyed by picoquic
    /// cnx so one dial cannot overwrite another's path/peer selection.
    path_by_cnx: std.AutoHashMapUnmanaged(*c.picoquic_cnx_t, *ConnPathState) = .empty,
    relay_datagrams: ?RelayDatagramClient = null,
    relay_send_count: usize = 0,
    relay_recv_count: usize = 0,
    handshake_timeout_us: u64 = handshake_timeout_us,
    deinitializing: bool = false,
    deleting_cnx: ?*c.picoquic_cnx_t = null,
    mu: std.atomic.Mutex = .unlocked,
    /// Exclusive-owner guard (runtime_safety only). 0 = free; else `Thread.Id`
    /// of the current exclusive driver. Nested same-thread re-entry uses
    /// `owner_depth`. Concurrent claim by another thread panics.
    active_owner: std.atomic.Value(std.Thread.Id) = .init(0),
    /// Nesting depth for `active_owner` (touched only by the exclusive owner).
    owner_depth: u32 = 0,

    pub const Options = struct {
        bind_address: net.IpAddress = .{ .ip4 = .loopback(0) },
        public_address: ?net.IpAddress = null,
        handshake_timeout_us: u64 = handshake_timeout_us,
        max_connections: u32 = 128,
        max_connection_impls: usize = default_max_connection_impls,
        max_stream_states: usize = default_max_stream_states,
        max_inbound_stream_buffer: usize = stream_receive_credit_target,
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, secret: key.SecretKey, alpn: [:0]const u8) !*Endpoint {
        return initOptions(allocator, io, secret, alpn, .{});
    }

    pub fn initOptions(allocator: std.mem.Allocator, io: std.Io, secret: key.SecretKey, alpn: [:0]const u8, options: Options) !*Endpoint {
        const self = try allocator.create(Endpoint);
        errdefer allocator.destroy(self);

        var reset_seed: [c.PICOQUIC_RESET_SECRET_SIZE]u8 = undefined;
        io.random(&reset_seed);
        const quic = c.picoquic_create(
            options.max_connections,
            null,
            null,
            null,
            alpn.ptr,
            callback,
            self,
            null,
            null,
            &reset_seed,
            c.picoquic_current_time(),
            null,
            null,
            null,
            0,
        ) orelse return error.OutOfMemory;
        errdefer c.picoquic_free(quic);
        std.crypto.secureZero(u8, &reset_seed);

        try context.applyTransportParams(quic, context.default_transport_params);
        c.picoquic_enable_path_callbacks_default(quic, 1);
        var local_seed = secret.toBytes();
        defer std.crypto.secureZero(u8, &local_seed);
        const local_public = secret.public().toBytes();
        if (c.iroh_picoquic_configure_raw_public_key(quic, &local_seed, &local_public, null, 1) != 0) {
            return error.ConnectionLost;
        }

        var bind_addr: net.IpAddress = options.bind_address;
        const socket = try bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
        errdefer socket.close(io);
        // Bulk-transfer headroom: the kernel default UDP receive buffer
        // (net.core.rmem_default = 208 KiB) overflows under bursty senders
        // faster than the caller-paced pump drains it — observed 2026-07-21
        // under netsim: fetcher rxq p99 >400 KiB with accumulating drops, the
        // sender's congestion control collapsing, FIN missing the 30 s read
        // deadline. 8 MiB stays under the stock 16 MiB net.core.rmem_max clamp.
        try std.posix.setsockopt(socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, &std.mem.toBytes(@as(c_int, 8 * 1024 * 1024)));
        const local_address = normalizePublicAddress(options.public_address orelse socket.address, socket.address.getPort());
        self.* = .{
            .allocator = allocator,
            .io_inst = io,
            .secret = secret,
            .node_id = secret.public(),
            .alpn = alpn,
            .local_address = local_address,
            .quic = quic,
            .socket = socket,
            .handshake_timeout_us = options.handshake_timeout_us,
            .max_connections = options.max_connections,
            .max_stream_states = options.max_stream_states,
            .max_connection_impls = options.max_connection_impls,
            .max_inbound_stream_buffer = options.max_inbound_stream_buffer,
        };
        errdefer self.secret.deinit();
        try self.closed_connections.ensureTotalCapacity(allocator, options.max_connections);
        for (&self.custom_frames) |*frame| frame.* = .{};
        return self;
    }

    pub fn deinit(self: *Endpoint) void {
        // Claim exclusive ownership for teardown; object is destroyed, so no leave.
        self.enterExclusive();
        self.deinitializing = true;
        for (self.streams.items) |stream| {
            self.resetStreamSlot(stream);
            self.allocator.destroy(stream);
        }
        self.streams.deinit(self.allocator);
        for (self.sends.items) |send| {
            if (send.used) send.buffer.deinit();
            self.allocator.destroy(send);
        }
        self.sends.deinit(self.allocator);
        for (self.recvs.items) |recv| self.allocator.destroy(recv);
        self.recvs.deinit(self.allocator);
        for (self.connection_impls.items) |impl| self.allocator.destroy(impl);
        self.connection_impls.deinit(self.allocator);
        self.accepted_server_cnx.deinit(self.allocator);
        self.closed_connections.deinit(self.allocator);
        self.dead_cnxs_pending.deinit(self.allocator);
        var path_it = self.path_by_cnx.iterator();
        while (path_it.next()) |e| {
            const path = e.value_ptr.*;
            path.magicsock_state.deinit();
            path.allocator.destroy(path);
        }
        self.path_by_cnx.deinit(self.allocator);
        self.socket.close(self.io_inst);
        c.iroh_picoquic_clear_raw_public_key(self.quic);
        c.picoquic_free(self.quic);
        self.secret.deinit();
        self.allocator.destroy(self);
    }

    pub fn transport(self: *Endpoint) tr.Transport {
        return .{ .context = self, .vtable = &endpoint_vtable };
    }

    pub fn localAddress(self: *Endpoint) net.IpAddress {
        return self.local_address;
    }

    pub fn boundAddress(self: *Endpoint) net.IpAddress {
        return self.socket.address;
    }

    /// One cooperative QUIC I/O round for single-threaded callers.
    ///
    /// Requires exclusive Endpoint ownership for the call (see module docs).
    pub fn pollOnce(self: *Endpoint) tr.Error!void {
        self.enterExclusive();
        defer self.leaveExclusive();
        self.lockPump();
        defer self.mu.unlock();
        _ = try self.pumpOutgoingLocked();
        _ = try self.pumpIncomingLocked();
        self.sweepClosedUnownedConnections();
    }

    /// Accept a connection that reached ready state, if any.
    ///
    /// Requires exclusive Endpoint ownership for the call (see module docs).
    pub fn tryAcceptReady(self: *Endpoint) tr.Error!?tr.Connection {
        self.enterExclusive();
        defer self.leaveExclusive();
        // Nested re-entry: pollOnce also enter/leaves.
        try self.pollOnce();
        if (self.firstReadyServerCnx()) |cnx| {
            _ = try self.pumpOutgoing();
            return try self.connectionForCnx(cnx, true);
        }
        return null;
    }

    pub fn setRelayDatagrams(self: *Endpoint, relay: RelayDatagramClient) void {
        self.relay_datagrams = relay;
    }

    /// Claim exclusive driver ownership for a top-level Endpoint/vtable call.
    ///
    /// Active under `runtime_safety` (Debug + ReleaseSafe). Sequential handoff
    /// between calls is fine; concurrent overlapping claims panic.
    pub fn enterExclusive(self: *Endpoint) void {
        if (!std.debug.runtime_safety) return;
        const me = std.Thread.getCurrentId();
        while (true) {
            const cur = self.active_owner.load(.acquire);
            if (cur == me) {
                self.owner_depth += 1;
                return;
            }
            if (cur == 0) {
                if (self.active_owner.cmpxchgWeak(0, me, .acquire, .monotonic)) |_| continue;
                self.owner_depth = 1;
                return;
            }
            std.debug.panic(
                "quic.Endpoint ownership precondition violated: concurrent access (thread {d} entered while owned by {d}). One exclusive owner at a time; serialize externally or use one driver thread. See module docs / transport-relay-concurrency ownership note.",
                .{ me, cur },
            );
        }
    }

    /// Release one nesting level of exclusive ownership acquired by `enterExclusive`.
    pub fn leaveExclusive(self: *Endpoint) void {
        if (!std.debug.runtime_safety) return;
        const me = std.Thread.getCurrentId();
        const cur = self.active_owner.load(.monotonic);
        if (cur != me) {
            std.debug.panic(
                "quic.Endpoint leaveExclusive by non-owner thread {d} (owner {d})",
                .{ me, cur },
            );
        }
        std.debug.assert(self.owner_depth > 0);
        self.owner_depth -= 1;
        if (self.owner_depth == 0) {
            self.active_owner.store(0, .release);
        }
    }

    fn findStreamState(self: *Endpoint, cnx: *c.picoquic_cnx_t, stream_id: u64) ?*StreamState {
        for (self.streams.items) |stream| {
            if (stream.used and stream.cnx == cnx and stream.id == stream_id) return stream;
        }
        return null;
    }

    fn linkStreamCtx(self: *Endpoint, stream: *StreamState) tr.Error!void {
        _ = self;
        if (!stream.used or stream.pico_released) return;
        const cnx = stream.cnx orelse return;
        if (c.picoquic_set_app_stream_ctx(cnx, stream.id, stream) != 0) return error.ConnectionLost;
    }

    fn unlinkStreamCtxIfLive(self: *Endpoint, stream: *StreamState) void {
        if (!stream.used or stream.pico_released) return;
        const cnx = stream.cnx orelse return;
        if (self.cnxEngineState(cnx) != null) {
            c.picoquic_unlink_app_stream_ctx(cnx, stream.id);
        }
        stream.pico_released = true;
    }

    fn resetStreamSlot(self: *Endpoint, stream: *StreamState) void {
        self.unlinkStreamCtxIfLive(stream);
        resetStream(stream);
    }

    fn streamFor(self: *Endpoint, cnx: *c.picoquic_cnx_t, stream_id: u64) tr.Error!*StreamState {
        if (self.findStreamState(cnx, stream_id)) |stream| {
            try self.linkStreamCtx(stream);
            return stream;
        }
        for (self.streams.items) |stream| {
            if (!stream.used) {
                stream.* = .{ .cnx = cnx, .id = stream_id, .used = true, .recv = .init(self.allocator) };
                try self.linkStreamCtx(stream);
                return stream;
            }
        }
        if (self.streams.items.len >= self.max_stream_states) return error.OutOfMemory;
        try self.streams.ensureUnusedCapacity(self.allocator, 1);
        const stream = try self.allocator.create(StreamState);
        errdefer self.allocator.destroy(stream);
        stream.* = .{ .cnx = cnx, .id = stream_id, .used = true, .recv = .init(self.allocator) };
        self.streams.appendAssumeCapacity(stream);
        try self.linkStreamCtx(stream);
        return stream;
    }

    fn sendFor(self: *Endpoint, cnx: *c.picoquic_cnx_t, stream_id: u64) tr.Error!*SendImpl {
        for (self.sends.items) |send| {
            if (send.used and send.cnx == cnx and send.stream_id == stream_id) return error.ConnectionLost;
        }
        for (self.sends.items) |send| {
            if (!send.used) {
                send.* = .{ .used = true, .endpoint = self, .cnx = cnx, .stream_id = stream_id, .buffer = .init(self.allocator) };
                return send;
            }
        }
        if (self.sends.items.len >= self.max_stream_states) return error.OutOfMemory;
        const send = self.allocator.create(SendImpl) catch return error.OutOfMemory;
        errdefer self.allocator.destroy(send);
        send.* = .{ .used = true, .endpoint = self, .cnx = cnx, .stream_id = stream_id, .buffer = .init(self.allocator) };
        self.sends.append(self.allocator, send) catch return error.OutOfMemory;
        return send;
    }

    fn recvFor(self: *Endpoint, cnx: *c.picoquic_cnx_t, stream_id: u64) tr.Error!*RecvImpl {
        for (self.recvs.items) |recv| {
            if (recv.used and recv.cnx == cnx and recv.stream_id == stream_id) return error.ConnectionLost;
        }
        for (self.recvs.items) |recv| {
            if (!recv.used) {
                recv.* = .{ .used = true, .endpoint = self, .cnx = cnx, .stream_id = stream_id };
                return recv;
            }
        }
        if (self.recvs.items.len >= self.max_stream_states) return error.OutOfMemory;
        const recv = self.allocator.create(RecvImpl) catch return error.OutOfMemory;
        errdefer self.allocator.destroy(recv);
        recv.* = .{ .used = true, .endpoint = self, .cnx = cnx, .stream_id = stream_id };
        self.recvs.append(self.allocator, recv) catch return error.OutOfMemory;
        return recv;
    }

    fn firstReadyServerCnx(self: *Endpoint) ?*c.picoquic_cnx_t {
        var maybe_cnx: ?*c.picoquic_cnx_t = c.picoquic_get_first_cnx(self.quic);
        while (maybe_cnx) |cnx| : (maybe_cnx = c.picoquic_get_next_cnx(cnx)) {
            if (c.picoquic_get_cnx_state(cnx) == c.picoquic_state_ready and
                c.picoquic_is_client(cnx) == 0 and
                !self.serverCnxHandedOff(cnx))
            {
                return cnx;
            }
        }
        return null;
    }

    fn serverCnxHandedOff(self: *const Endpoint, cnx: *c.picoquic_cnx_t) bool {
        return self.accepted_server_cnx.contains(cnx);
    }

    fn markServerCnxHandedOff(self: *Endpoint, cnx: *c.picoquic_cnx_t) tr.Error!void {
        try self.accepted_server_cnx.put(self.allocator, cnx, {});
    }

    fn unmarkServerCnxHandedOff(self: *Endpoint, cnx: *c.picoquic_cnx_t) void {
        _ = self.accepted_server_cnx.remove(cnx);
    }

    /// Release the reusable stream/send/recv state owned by a connection that is
    /// being torn down, so a persistent endpoint does not exhaust them across
    /// many sequential connections. Only the port-owned buffers are freed; the
    /// picoquic cnx itself is freed by the caller via picoquic_delete_cnx.
    fn reclaimConnection(self: *Endpoint, cnx: *c.picoquic_cnx_t) void {
        for (self.streams.items) |stream| {
            if (stream.used and stream.cnx == cnx) self.resetStreamSlot(stream);
        }
        for (self.sends.items) |send| {
            if (send.used and send.cnx == cnx) {
                send.buffer.deinit();
                send.* = .{};
            }
        }
        for (self.recvs.items) |recv| {
            if (recv.used and recv.cnx == cnx) recv.* = .{};
        }
        self.freePathState(cnx);
    }

    fn hasConnectionImpl(self: *const Endpoint, cnx: *c.picoquic_cnx_t) bool {
        for (self.connection_impls.items) |impl| {
            if (!impl.deleted.load(.acquire) and impl.cnx == cnx) return true;
        }
        return false;
    }

    fn deleteCnx(self: *Endpoint, cnx: *c.picoquic_cnx_t) void {
        _ = self.closed_connections.remove(cnx);
        self.unmarkServerCnxHandedOff(cnx);
        self.reclaimConnection(cnx);
        self.deleting_cnx = cnx;
        defer self.deleting_cnx = null;
        c.iroh_picoquic_forget_cnx_peer(cnx);
        c.picoquic_delete_cnx(cnx);
    }

    /// Engine-truth liveness: picoquic's own cnx list is the single source of
    /// truth (recycle-proof — a freed cnx is ABSENT; a recycled address holds
    /// a present, live cnx). Returns null when the engine no longer lists the
    /// cnx (picoquic auto-deletes SERVER cnxs inside a later send pass —
    /// vendored sender.c:3806-3815), else the cnx state.
    fn cnxEngineState(self: *Endpoint, cnx: *c.picoquic_cnx_t) ?c_uint {
        var maybe_cnx: ?*c.picoquic_cnx_t = c.picoquic_get_first_cnx(self.quic);
        while (maybe_cnx) |current| : (maybe_cnx = c.picoquic_get_next_cnx(current)) {
            if (current == cnx) return c.picoquic_get_cnx_state(current);
        }
        return null;
    }

    /// Delete engine-dead cnxs deterministically, at safe points where no
    /// caller is mid-operation on them (connectionForCnx entry, i.e. the next
    /// connection's accept/connect). Mirrors the greenfield backend's
    /// resolveDeadCnxs (endpoint.zig): delete only if still present AND
    /// disconnected — picoquic may already have auto-deleted a server cnx
    /// (absent); keep a still-draining cnx pending for the next sweep. The
    /// engine never auto-deletes CLIENT cnxs, so this sweep is what reclaims
    /// remote-closed clients engine-side. Zig-side stream state is NOT
    /// reclaimed here — a remote-closed connection may still hold readable
    /// buffered data (read-after-close); that teardown runs at connClose (or
    /// deinit).
    fn resolveDeadCnxs(self: *Endpoint) void {
        var kept: usize = 0;
        for (self.dead_cnxs_pending.items) |cnx| {
            const state = self.cnxEngineState(cnx);
            if (state == null) {
                // Engine no longer lists this cnx (already freed) — drop it. Retaining a
                // freed pointer leaks unboundedly and risks recycle-aliasing: the address
                // may be reused for a live cnx that a later sweep would then mis-delete.
                continue;
            }
            if (state.? == c.picoquic_state_disconnected) {
                self.unmarkServerCnxHandedOff(cnx);
                self.deleting_cnx = cnx;
                c.iroh_picoquic_forget_cnx_peer(cnx);
                c.picoquic_delete_cnx(cnx);
                self.deleting_cnx = null;
            } else {
                self.dead_cnxs_pending.items[kept] = cnx;
                kept += 1;
            }
        }
        self.dead_cnxs_pending.shrinkRetainingCapacity(kept);
    }

    fn beginClientCnx(self: *Endpoint, peer: key.NodeId, initial_addr: net.IpAddress, relay_available: bool, relay_only: bool) tr.Error!*c.picoquic_cnx_t {
        var peer_addr = sockaddrFromIp4(initial_addr) catch return error.NotConnected;
        const zero_cid: c.picoquic_connection_id_t = .{ .id = [_]u8{0} ** 20, .id_len = 0 };
        const sni = tls_name.serverName(peer);
        var sni_z: [tls_name.encoded_name_len + 1]u8 = undefined;
        @memcpy(sni_z[0..tls_name.encoded_name_len], &sni);
        sni_z[tls_name.encoded_name_len] = 0;
        const expected_public = peer.toBytes();

        // picoquic enforces max_connections for inbound creation, but its public
        // client create path does not. Serialize the check with creation so the
        // no-fail close callback can safely use its max_connections reservation.
        self.lockPump();
        defer self.mu.unlock();
        if (c.picoquic_current_number_connections(self.quic) >= self.max_connections) return error.OutOfMemory;

        const cnx = c.picoquic_create_cnx(self.quic, zero_cid, zero_cid, @ptrCast(&peer_addr), c.picoquic_current_time(), c.PICOQUIC_V1_VERSION, sni_z[0..tls_name.encoded_name_len :0].ptr, self.alpn.ptr, 1) orelse return error.ConnectionLost;
        errdefer self.deleteCnx(cnx);
        const path = try self.ensurePathState(cnx);
        path.peer = peer;
        path.relay_peer = peer;
        if (relay_available) {
            try path.magicsock_state.addRelayCandidate(0);
            if (relay_only) path.magicsock_state.selectRelayFallback();
        }
        if (c.iroh_picoquic_set_cnx_expected_peer(cnx, &expected_public) != 0) return error.ConnectionLost;
        c.picoquic_enable_path_callbacks(cnx, 1);
        self.enableKeepAlive(cnx);
        if (c.picoquic_start_client_cnx(cnx) != 0) return error.ConnectionLost;
        return cnx;
    }

    fn sweepClosedUnownedConnections(self: *Endpoint) void {
        while (true) {
            var victim: ?*c.picoquic_cnx_t = null;
            var it = self.closed_connections.keyIterator();
            while (it.next()) |cnx| {
                if (!self.hasConnectionImpl(cnx.*)) {
                    victim = cnx.*;
                    break;
                }
            }
            const cnx = victim orelse return;
            self.deleteCnx(cnx);
        }
    }

    fn ensurePathState(self: *Endpoint, cnx: *c.picoquic_cnx_t) tr.Error!*ConnPathState {
        const gop = self.path_by_cnx.getOrPut(self.allocator, cnx) catch return error.OutOfMemory;
        if (!gop.found_existing) {
            const ps = self.allocator.create(ConnPathState) catch return error.OutOfMemory;
            ps.* = .{
                .allocator = self.allocator,
                .magicsock_state = magicsock.State.init(self.allocator),
            };
            gop.value_ptr.* = ps;
        }
        return gop.value_ptr.*;
    }

    fn freePathState(self: *Endpoint, cnx: *c.picoquic_cnx_t) void {
        if (self.path_by_cnx.fetchRemove(cnx)) |kv| {
            const path = kv.value;
            path.magicsock_state.deinit();
            // Free with the create-time allocator (Endpoint.allocator may be swapped in tests).
            path.allocator.destroy(path);
        }
    }

    /// Test/diagnostic access to per-cnx path state.
    pub fn pathStateFor(self: *Endpoint, cnx: *c.picoquic_cnx_t) ?*ConnPathState {
        return self.path_by_cnx.get(cnx);
    }

    fn connectionForCnx(self: *Endpoint, cnx: *c.picoquic_cnx_t, server_handoff: bool) tr.Error!tr.Connection {
        // The creation point of the NEXT connection is the safe point to sweep
        // engine-dead cnxs (no caller is mid-operation on them here).
        self.resolveDeadCnxs();
        errdefer if (server_handoff) {
            self.deleteCnx(cnx);
        };
        if (server_handoff) try self.markServerCnxHandedOff(cnx);

        var remote_bytes: [32]u8 = undefined;
        if (c.iroh_picoquic_last_verified_peer_public_key(cnx, &remote_bytes) != 0) return error.ConnectionLost;
        const remote = key.PublicKey.fromBytes(remote_bytes) catch return error.ConnectionLost;
        self.enableKeepAlive(cnx);
        const path = try self.ensurePathState(cnx);
        path.peer = remote;
        if (self.connection_impls.items.len >= self.max_connection_impls) return error.OutOfMemory;
        const impl = self.allocator.create(ConnectionImpl) catch return error.OutOfMemory;
        errdefer self.allocator.destroy(impl);
        impl.* = .{
            .endpoint = self,
            .cnx = cnx,
            .remote = remote,
            .server_handoff = server_handoff,
        };
        impl.snapshotAlpn(cnx);
        self.connection_impls.append(self.allocator, impl) catch return error.OutOfMemory;
        return .{ .context = impl, .vtable = &connection_vtable };
    }

    fn enableKeepAlive(_: *Endpoint, cnx: *c.picoquic_cnx_t) void {
        const interval = context.default_transport_params.keep_alive_interval_us;
        if (interval != 0) c.picoquic_enable_keep_alive(cnx, interval);
    }

    pub fn takeCustomFrame(self: *Endpoint) ?CustomFrame {
        if (self.custom_frame_count == 0) return null;
        const frame = self.custom_frames[0];
        var i: usize = 1;
        while (i < self.custom_frame_count) : (i += 1) {
            self.custom_frames[i - 1] = self.custom_frames[i];
        }
        self.custom_frame_count -= 1;
        return frame;
    }

    fn pushCustomFrame(self: *Endpoint, cnx: *c.picoquic_cnx_t, bytes: []const u8) !void {
        if (self.custom_frame_count >= self.custom_frames.len) return error.OutOfMemory;
        if (bytes.len > max_custom_frame_len) return error.OutOfMemory;
        var frame: CustomFrame = .{ .len = bytes.len };
        @memcpy(frame.bytes[0..bytes.len], bytes);
        self.custom_frames[self.custom_frame_count] = frame;
        self.custom_frame_count += 1;
        const path = try self.ensurePathState(cnx);
        try path.magicsock_state.handleFrame(try magicsock_frames.decode(bytes));
        try self.probeMagicsockCandidates(cnx, path);
    }

    fn probeMagicsockCandidates(self: *Endpoint, cnx: *c.picoquic_cnx_t, path: *ConnPathState) tr.Error!void {
        while (path.magicsock_state.nextProbeCandidate()) |candidate| {
            var peer_addr = sockaddrFromIp4(candidate.address) catch return error.ConnectionLost;
            var local_addr = sockaddrFromIp4(self.pathLocalAddress(candidate.address)) catch return error.ConnectionLost;
            const rc = c.picoquic_probe_new_path(cnx, @ptrCast(&peer_addr), @ptrCast(&local_addr), c.picoquic_current_time());
            if (rc != 0) return error.ConnectionLost;
            path.magicsock_state.markPathProbed(candidate.address);
        }
    }

    fn handlePathAvailable(self: *Endpoint, cnx: *c.picoquic_cnx_t, unique_path_id: u64) tr.Error!void {
        const peer_addr = (try self.pathAddress(cnx, unique_path_id, 2)) orelse return error.ConnectionLost;
        const path = try self.ensurePathState(cnx);
        var quality: c.picoquic_path_quality_t = undefined;
        if (c.picoquic_get_path_quality(cnx, unique_path_id, &quality) != 0) {
            path.magicsock_state.markPathSucceeded(peer_addr, 0);
        } else {
            path.magicsock_state.markPathSucceeded(peer_addr, quality.rtt);
        }
        try self.recordPathObservedAddress(cnx, unique_path_id, path);
    }

    fn recordPathObservedAddress(self: *Endpoint, cnx: *c.picoquic_cnx_t, unique_path_id: u64, path: *ConnPathState) tr.Error!void {
        if (try self.pathAddress(cnx, unique_path_id, 3)) |observed| {
            path.magicsock_state.recordObserved(observed) catch return error.OutOfMemory;
        }
    }

    fn pathAddress(_: *Endpoint, cnx: *c.picoquic_cnx_t, unique_path_id: u64, selector: c_int) tr.Error!?net.IpAddress {
        var storage: c.struct_sockaddr_storage = undefined;
        if (c.picoquic_get_path_addr(cnx, unique_path_id, selector, &storage) != 0) return error.ConnectionLost;
        return optionalIp4FromSockaddr(storage) catch return error.ConnectionLost;
    }

    fn pumpOutgoing(self: *Endpoint) tr.Error!bool {
        self.lockPump();
        defer self.mu.unlock();
        return self.pumpOutgoingLocked();
    }

    fn pumpOutgoingLocked(self: *Endpoint) tr.Error!bool {
        var sent = false;
        while (true) {
            var buffer: [c.PICOQUIC_MAX_PACKET_SIZE]u8 = undefined;
            var send_len: usize = 0;
            var to: c.struct_sockaddr_storage = undefined;
            var from: c.struct_sockaddr_storage = undefined;
            var if_index: c_int = 0;
            var log_cid: c.picoquic_connection_id_t = undefined;
            var last_cnx: ?*c.picoquic_cnx_t = null;
            if (c.picoquic_prepare_next_packet(self.quic, c.picoquic_current_time(), &buffer, buffer.len, &send_len, &to, &from, &if_index, &log_cid, &last_cnx) != 0) {
                return error.ConnectionLost;
            }
            if (send_len == 0) return sent;
            if (last_cnx) |cnx| {
                if (self.path_by_cnx.get(cnx)) |path| {
                    if (path.magicsock_state.selectedPath()) |selected| {
                        if (selected.kind == .relay) {
                            const relay = self.relay_datagrams orelse return error.NotConnected;
                            const peer = path.relay_peer orelse return error.NotConnected;
                            try relay.send(peer, buffer[0..send_len]);
                            self.relay_send_count += 1;
                            sent = true;
                            continue;
                        }
                    }
                }
            }
            var dest = ip4FromSockaddr(to) catch return error.ConnectionLost;
            self.socket.send(self.io_inst, &dest, buffer[0..send_len]) catch return error.ConnectionLost;
            sent = true;
        }
    }

    fn pumpIncoming(self: *Endpoint) tr.Error!bool {
        self.lockPump();
        defer self.mu.unlock();
        return self.pumpIncomingLocked();
    }

    fn pumpIncomingLocked(self: *Endpoint) tr.Error!bool {
        var progressed = false;
        var batch: UdpReceiveBatch = .{};
        while (true) {
            const count = if (progressed)
                try self.drainUdpBatch(&batch)
            else
                try self.receiveUdpFirst(&batch);
            if (count == 0) break;
            try self.processUdpBatch(batch.items[0..count]);
            progressed = true;
        }
        return (try self.pumpRelayIncomingLocked()) or progressed;
    }

    fn receiveUdpFirst(self: *Endpoint, batch: *UdpReceiveBatch) tr.Error!usize {
        const msg = self.socket.receiveTimeout(self.io_inst, &batch.packets[0], self.receiveUdpWaitTimeout()) catch |err| switch (err) {
            error.Timeout => return 0,
            else => return error.ConnectionLost,
        };
        if (msg.flags.trunc or msg.flags.ctrunc) return error.ConnectionLost;
        batch.items[0] = .{ .from = msg.from, .data = msg.data };
        return 1;
    }

    fn receiveUdpWaitTimeout(self: *Endpoint) std.Io.Timeout {
        return receiveUdpWaitTimeoutFromWakeDelay(c.picoquic_get_next_wake_delay(
            self.quic,
            c.picoquic_current_time(),
            udp_receive_max_wait_us,
        ));
    }

    fn drainUdpBatch(self: *Endpoint, batch: *UdpReceiveBatch) tr.Error!usize {
        return switch (builtin.os.tag) {
            .linux => self.drainUdpBatchLinux(batch),
            else => self.drainUdpBatchPortable(batch),
        };
    }

    fn drainUdpBatchPortable(self: *Endpoint, batch: *UdpReceiveBatch) tr.Error!usize {
        var count: usize = 0;
        while (count < udp_receive_batch_size) : (count += 1) {
            const msg = self.socket.receiveTimeout(self.io_inst, &batch.packets[count], udp_receive_drain_timeout) catch |err| switch (err) {
                error.Timeout => return count,
                else => return error.ConnectionLost,
            };
            if (msg.flags.trunc or msg.flags.ctrunc) return error.ConnectionLost;
            batch.items[count] = .{ .from = msg.from, .data = msg.data };
        }
        return count;
    }

    fn drainUdpBatchLinux(self: *Endpoint, batch: *UdpReceiveBatch) tr.Error!usize {
        while (true) {
            for (0..udp_receive_batch_size) |i| {
                batch.linux.iovecs[i] = .{ .base = batch.packets[i][0..].ptr, .len = batch.packets[i].len };
                batch.linux.messages[i] = .{
                    .hdr = .{
                        .name = @ptrCast(&batch.linux.addrs[i]),
                        .namelen = @intCast(@sizeOf(c.struct_sockaddr_storage)),
                        .iov = batch.linux.iovecs[i..][0..1].ptr,
                        .iovlen = 1,
                        .control = null,
                        .controllen = 0,
                        .flags = 0,
                    },
                    .len = 0,
                };
            }

            const rc = std.os.linux.recvmmsg(
                self.socket.handle,
                batch.linux.messages[0..].ptr,
                @intCast(udp_receive_batch_size),
                std.os.linux.MSG.DONTWAIT,
                null,
            );
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => {
                    const count: usize = @intCast(rc);
                    for (0..count) |i| {
                        const msg = batch.linux.messages[i];
                        if (msg.hdr.namelen < @sizeOf(c.struct_sockaddr_in)) return error.ConnectionLost;
                        if ((msg.hdr.flags & (std.os.linux.MSG.TRUNC | std.os.linux.MSG.CTRUNC)) != 0) return error.ConnectionLost;
                        if (msg.len > batch.packets[i].len) return error.ConnectionLost;
                        const data_len: usize = @intCast(msg.len);
                        batch.items[i] = .{
                            .from = ip4FromSockaddr(batch.linux.addrs[i]) catch return error.ConnectionLost,
                            .data = batch.packets[i][0..data_len],
                        };
                    }
                    return count;
                },
                .INTR => continue,
                .AGAIN => return 0,
                else => return error.ConnectionLost,
            }
        }
    }

    fn processUdpBatch(self: *Endpoint, packets: []const ReceivedUdpDatagram) tr.Error!void {
        for (packets) |packet| {
            var from = sockaddrFromIp4(packet.from) catch return error.ConnectionLost;
            var to = sockaddrFromIp4(self.pathLocalAddress(packet.from)) catch return error.ConnectionLost;
            if (c.picoquic_incoming_packet(self.quic, packet.data.ptr, packet.data.len, @ptrCast(&from), @ptrCast(&to), 0, 0, c.picoquic_current_time()) != 0) {
                return error.ConnectionLost;
            }
        }
    }

    fn pumpRelayIncomingLocked(self: *Endpoint) tr.Error!bool {
        const relay = self.relay_datagrams orelse return false;
        var buffer: [2048]u8 = undefined;
        var progressed = false;
        while (true) {
            const msg = (try relay.recv(&buffer)) orelse return progressed;
            self.relay_recv_count += 1;

            var from = sockaddrFromIp4(magicsock.relayAddress()) catch return error.ConnectionLost;
            var to = sockaddrFromIp4(self.pathLocalAddress(magicsock.relayAddress())) catch return error.ConnectionLost;
            if (c.picoquic_incoming_packet(self.quic, msg.data.ptr, msg.data.len, @ptrCast(&from), @ptrCast(&to), 0, 0, c.picoquic_current_time()) != 0) {
                return error.ConnectionLost;
            }
            // After the packet creates/feeds a cnx, bind relay path state to the
            // matching peer — or, if none matched yet, exactly one unbound
            // mid-handshake cnx. Never a shared endpoint-global slot.
            var matched = false;
            var maybe_cnx: ?*c.picoquic_cnx_t = c.picoquic_get_first_cnx(self.quic);
            while (maybe_cnx) |cnx| : (maybe_cnx = c.picoquic_get_next_cnx(cnx)) {
                const path = try self.ensurePathState(cnx);
                if (path.peer) |p| {
                    if (!p.eql(msg.src)) continue;
                    path.relay_peer = msg.src;
                    try path.magicsock_state.addRelayCandidate(0);
                    path.magicsock_state.selectRelayFallback();
                    matched = true;
                }
            }
            if (!matched) {
                maybe_cnx = c.picoquic_get_first_cnx(self.quic);
                while (maybe_cnx) |cnx| : (maybe_cnx = c.picoquic_get_next_cnx(cnx)) {
                    const path = try self.ensurePathState(cnx);
                    if (path.peer != null) continue;
                    path.peer = msg.src;
                    path.relay_peer = msg.src;
                    try path.magicsock_state.addRelayCandidate(0);
                    path.magicsock_state.selectRelayFallback();
                    break;
                }
            }
            _ = try self.pumpOutgoingLocked();
            progressed = true;
        }
    }

    fn driveUntilReady(self: *Endpoint, cnx: *c.picoquic_cnx_t) tr.Error!void {
        const deadline = c.picoquic_current_time() + self.handshake_timeout_us;
        while (c.picoquic_current_time() < deadline) {
            _ = try self.pumpOutgoing();
            _ = try self.pumpIncoming();
            if (c.picoquic_get_cnx_state(cnx) == c.picoquic_state_ready) return;
        }
        return error.Timeout;
    }

    fn driveUntilStreamFin(self: *Endpoint, cnx: *c.picoquic_cnx_t, stream_id: u64) tr.Error!*StreamState {
        const deadline = c.picoquic_current_time() + 30 * std.time.us_per_s;
        while (c.picoquic_current_time() < deadline) {
            _ = try self.pumpOutgoing();
            _ = try self.pumpIncoming();
            const stream = self.streamFor(cnx, stream_id) catch return error.OutOfMemory;
            if (stream.reset) return error.StreamReset;
            if (stream.fin) return stream;
        }
        return error.Timeout;
    }

    fn pathLocalAddress(self: *Endpoint, peer: net.IpAddress) net.IpAddress {
        _ = peer;
        return self.local_address;
    }

    fn lockPump(self: *Endpoint) void {
        // Bounded backoff (same shape as relay ClientConn.send) — avoid hot-spin
        // while another pump holder is active.
        var spins: usize = 0;
        while (!self.mu.tryLock()) {
            spins += 1;
            if (spins & 0x3ff == 0) {
                self.io_inst.sleep(std.Io.Duration.fromMilliseconds(1), .real) catch {};
            } else {
                std.Thread.yield() catch {};
            }
        }
    }
};

pub const ConnPathState = struct {
    /// Allocator that created this slot — free with THIS, not Endpoint.allocator
    /// (tests swap the latter to failing_allocator mid-handoff).
    allocator: std.mem.Allocator,
    magicsock_state: magicsock.State,
    relay_peer: ?key.NodeId = null,
    peer: ?key.NodeId = null,
};

const ConnectionImpl = struct {
    endpoint: *Endpoint,
    cnx: *c.picoquic_cnx_t,
    remote: key.NodeId,
    server_handoff: bool = false,
    /// Snapshot of TLS-negotiated ALPN (borrowed by Connection.alpn()).
    alpn_storage: [64]u8 = undefined,
    alpn_len: usize = 0,
    /// Idempotent close: copied Connection handles must not double-delete the cnx.
    closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    remote_closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// The stable handle tombstone remains allocated, but no longer owns `cnx`.
    deleted: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    next_stream_scan: usize = 0,

    fn snapshotAlpn(self: *ConnectionImpl, cnx: *c.picoquic_cnx_t) void {
        self.alpn_len = 0;
        const negotiated = c.picoquic_tls_get_negotiated_alpn(cnx);
        if (negotiated == null) return;
        const slice = std.mem.span(negotiated);
        if (slice.len == 0 or slice.len > self.alpn_storage.len) return;
        @memcpy(self.alpn_storage[0..slice.len], slice);
        self.alpn_len = slice.len;
    }
};

const SendImpl = struct {
    used: bool = false,
    endpoint: *Endpoint = undefined,
    cnx: *c.picoquic_cnx_t = undefined,
    stream_id: u64 = 0,
    buffer: std.Io.Writer.Allocating = undefined,
    dead_writer: std.Io.Writer = std.Io.Writer.fixed(&.{}),
};

const RecvImpl = struct {
    used: bool = false,
    endpoint: *Endpoint = undefined,
    cnx: *c.picoquic_cnx_t = undefined,
    stream_id: u64 = 0,
    reader_storage: std.Io.Reader = undefined,
    ready: bool = false,
    expected_read_capacity: usize = 0,
    dead_reader: std.Io.Reader = std.Io.Reader.fixed(&.{}),
};

fn ensureConnectionLive(conn: *const ConnectionImpl) tr.Error!void {
    if (conn.closed.load(.acquire) or conn.remote_closed.load(.acquire) or conn.deleted.load(.acquire)) return error.NotConnected;
}

fn receiveUdpWaitTimeoutFromWakeDelay(wake_delay_us: i64) std.Io.Timeout {
    if (wake_delay_us <= 0) return udp_receive_drain_timeout;
    const capped_us = @min(wake_delay_us, udp_receive_max_wait_us);
    const wait_ns: u64 = @intCast(capped_us * std.time.ns_per_us);
    return .{ .duration = .{ .raw = .fromNanoseconds(wait_ns), .clock = .awake } };
}

fn streamFromCallback(endpoint: *Endpoint, cnx: *c.picoquic_cnx_t, stream_id: u64, stream_ctx: ?*anyopaque) tr.Error!*StreamState {
    if (stream_ctx) |ctx| {
        const stream: *StreamState = @ptrCast(@alignCast(ctx));
        if (stream.used and stream.cnx == cnx and stream.id == stream_id) return stream;
    }
    return endpoint.streamFor(cnx, stream_id);
}

fn callback(cnx: ?*c.picoquic_cnx_t, stream_id: u64, bytes: [*c]u8, length: usize, event: c.picoquic_call_back_event_t, callback_ctx: ?*anyopaque, stream_ctx: ?*anyopaque) callconv(.c) c_int {
    const endpoint: *Endpoint = @ptrCast(@alignCast(callback_ctx.?));
    if (endpoint.deinitializing) return 0;
    if (endpoint.deleting_cnx == cnx) return 0;
    if (event == c.picoquic_callback_stream_data or event == c.picoquic_callback_stream_fin) {
        const stream = streamFromCallback(endpoint, cnx.?, stream_id, stream_ctx) catch return -1;
        if (!stream.flow_credit_opened) {
            if (c.picoquic_open_flow_control(cnx.?, stream_id, stream_receive_credit_target) != 0) return -1;
            stream.flow_credit_opened = true;
        }
        const expected_capacity = stream.expected_read_capacity;
        if (expected_capacity > stream.recv.writer.buffer.len) {
            stream.recv.ensureTotalCapacity(expected_capacity) catch return -1;
        }
        const unread_len = stream.recv.written().len - stream.read_offset;
        if (length > endpoint.max_inbound_stream_buffer -| unread_len) return -1;
        if (length > 0) stream.recv.writer.writeAll(bytes[0..length]) catch return -1;
        if (event == c.picoquic_callback_stream_fin) stream.fin = true;
    } else if (event == c.picoquic_callback_stream_reset) {
        const stream = streamFromCallback(endpoint, cnx.?, stream_id, stream_ctx) catch return -1;
        stream.reset = true;
    } else if (event == c.picoquic_callback_stream_released) {
        if (stream_ctx) |ctx| {
            const stream: *StreamState = @ptrCast(@alignCast(ctx));
            if (stream.used and stream.cnx == cnx.? and stream.id == stream_id) {
                // Zig still owns terminal FIN/reset state until accept/read consumes it.
                stream.pico_released = true;
            }
        }
    } else if (event == c.picoquic_callback_stop_sending) {
        // RFC 9000 S3.5: acknowledge the peer's receive-side abort by
        // resetting our sending half with the same application error class.
        if (c.picoquic_reset_stream(cnx.?, stream_id, 0) != 0) return -1;
    } else if (event == c.picoquic_callback_close or
        event == c.picoquic_callback_application_close or
        event == c.picoquic_callback_stateless_reset)
    {
        c.iroh_picoquic_forget_cnx_peer(cnx.?);
        endpoint.closed_connections.putAssumeCapacity(cnx.?, {});
        // The teardown is now engine-owned: picoquic auto-deletes a SERVER cnx
        // inside a later send pass; queue for resolveDeadCnxs so a CLIENT cnx
        // (never auto-deleted) is reclaimed at a safe point.
        endpoint.dead_cnxs_pending.append(endpoint.allocator, cnx.?) catch {};
        for (endpoint.connection_impls.items) |impl| {
            if (!impl.deleted.load(.acquire) and impl.cnx == cnx.?) {
                impl.remote_closed.store(true, .release);
                break;
            }
        }
    } else if (event == c.picoquic_callback_iroh_custom_frame) {
        endpoint.pushCustomFrame(cnx.?, bytes[0..length]) catch return -1;
    } else if (event == c.picoquic_callback_path_available) {
        endpoint.handlePathAvailable(cnx.?, stream_id) catch return -1;
    } else if (event == c.picoquic_callback_path_address_observed) {
        const path = endpoint.ensurePathState(cnx.?) catch return -1;
        endpoint.recordPathObservedAddress(cnx.?, stream_id, path) catch return -1;
    }
    return 0;
}

fn derpRelaySend(ctx: *anyopaque, dst: key.NodeId, data: []const u8) tr.Error!void {
    const adapter: *DerpRelayDatagramClient = @ptrCast(@alignCast(ctx));
    adapter.client.send(.{ .datagram = .{
        .dst = dst,
        .datagrams = .{ .ecn = .not_ect, .segment_size = null, .contents = data },
    } }) catch return error.ConnectionLost;
}

fn derpRelayRecv(ctx: *anyopaque, buffer: []u8) tr.Error!?RelayDatagram {
    const adapter: *DerpRelayDatagramClient = @ptrCast(@alignCast(ctx));
    const msg = adapter.client.recv() catch return error.ConnectionLost;
    switch (msg) {
        .datagram => |d| {
            if (d.datagrams.contents.len > buffer.len) return error.ConnectionLost;
            @memcpy(buffer[0..d.datagrams.contents.len], d.datagrams.contents);
            return .{ .src = d.src, .data = buffer[0..d.datagrams.contents.len] };
        },
        .datagram_batch => |d| {
            // Batch frames carry GSO-style concatenated segments; surface the first
            // segment only here (sync adapter has no pending queue). Prefer QueuedRelayClient.
            const contents = d.datagrams.contents;
            const seg_len: usize = if (d.datagrams.segment_size) |s| @as(usize, s) else contents.len;
            const take = @min(seg_len, contents.len);
            if (take > buffer.len) return error.ConnectionLost;
            @memcpy(buffer[0..take], contents[0..take]);
            return .{ .src = d.src, .data = buffer[0..take] };
        },
        .endpoint_gone => return error.ConnectionLost,
        else => return null,
    }
}

const derp_relay_vtable: RelayDatagramClient.VTable = .{ .send = derpRelaySend, .recv = derpRelayRecv };

fn endpointConnect(ctx: *anyopaque, peer: tr.NodeAddr) tr.Error!tr.Connection {
    const endpoint: *Endpoint = @ptrCast(@alignCast(ctx));
    endpoint.enterExclusive();
    defer endpoint.leaveExclusive();
    const first_ip = peer.firstIpAddr();
    const relay_available = endpoint.relay_datagrams != null and peer.firstRelayUrl() != null;
    if (first_ip == null and !relay_available) return error.NotConnected;
    // Do NOT reconfigure endpoint-global RPK here: that raced concurrent dials.
    // Local keys were set at Endpoint.init; bind expected peer to THIS cnx only.

    const initial_addr = first_ip orelse magicsock.relayAddress();
    const cnx = try endpoint.beginClientCnx(peer.id, initial_addr, relay_available, first_ip == null);
    errdefer endpoint.deleteCnx(cnx);
    try endpoint.driveUntilReady(cnx);
    return try endpoint.connectionForCnx(cnx, false);
}

fn endpointAccept(ctx: *anyopaque) tr.Error!tr.Connection {
    const endpoint: *Endpoint = @ptrCast(@alignCast(ctx));
    endpoint.enterExclusive();
    defer endpoint.leaveExclusive();
    const deadline = c.picoquic_current_time() + endpoint.handshake_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        _ = try endpoint.pumpOutgoing();
        _ = try endpoint.pumpIncoming();
        if (endpoint.firstReadyServerCnx()) |cnx| {
            while (try endpoint.pumpOutgoing()) {}
            return endpoint.connectionForCnx(cnx, true);
        }
    }
    return error.Timeout;
}

fn endpointLocal(ctx: *anyopaque) tr.NodeId {
    const endpoint: *Endpoint = @ptrCast(@alignCast(ctx));
    return endpoint.node_id;
}

fn endpointIo(ctx: *anyopaque) std.Io {
    const endpoint: *Endpoint = @ptrCast(@alignCast(ctx));
    return endpoint.io_inst;
}

const endpoint_vtable: tr.Transport.VTable = .{ .connect = endpointConnect, .accept = endpointAccept, .localNodeId = endpointLocal, .io = endpointIo };

fn reserveLocalStreamId(conn: *ConnectionImpl, is_unidir: bool) tr.Error!u64 {
    try ensureConnectionLive(conn);
    const stream_id = c.picoquic_get_next_local_stream_id(conn.cnx, if (is_unidir) 1 else 0);
    _ = try conn.endpoint.streamFor(conn.cnx, stream_id);
    return stream_id;
}

fn connOpenBi(ctx: *anyopaque) tr.Error!tr.BiStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    conn.endpoint.enterExclusive();
    defer conn.endpoint.leaveExclusive();
    const stream_id = try reserveLocalStreamId(conn, false);
    const send = try conn.endpoint.sendFor(conn.cnx, stream_id);
    errdefer sendReset(send);
    const recv = try conn.endpoint.recvFor(conn.cnx, stream_id);
    return .{ .send = .{ .context = send, .vtable = &send_vtable }, .recv = .{ .context = recv, .vtable = &recv_vtable } };
}

fn connAcceptBi(ctx: *anyopaque) tr.Error!tr.BiStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    conn.endpoint.enterExclusive();
    defer conn.endpoint.leaveExclusive();
    try ensureConnectionLive(conn);
    const deadline = c.picoquic_current_time() + stream_open_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        _ = try conn.endpoint.pumpOutgoing();
        _ = try conn.endpoint.pumpIncoming();
        for (conn.endpoint.streams.items) |stream| {
            if (stream.used and stream.cnx == conn.cnx and !stream.handed_off and stream.id & 0x2 == 0) {
                if (stream.reset) {
                    conn.endpoint.resetStreamSlot(stream);
                    return error.StreamReset;
                }
                if (stream.read_offset >= stream.recv.written().len and !stream.fin) continue;
                const send = try conn.endpoint.sendFor(conn.cnx, stream.id);
                errdefer sendReset(send);
                const recv = try conn.endpoint.recvFor(conn.cnx, stream.id);
                stream.handed_off = true;
                return .{ .send = .{ .context = send, .vtable = &send_vtable }, .recv = .{ .context = recv, .vtable = &recv_vtable } };
            }
        }
    }
    return error.Timeout;
}

fn connOpenUni(ctx: *anyopaque) tr.Error!tr.SendStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    conn.endpoint.enterExclusive();
    defer conn.endpoint.leaveExclusive();
    const stream_id = try reserveLocalStreamId(conn, true);
    const send = try conn.endpoint.sendFor(conn.cnx, stream_id);
    return .{ .context = send, .vtable = &send_vtable };
}

fn connAcceptUni(ctx: *anyopaque) tr.Error!tr.RecvStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    conn.endpoint.enterExclusive();
    defer conn.endpoint.leaveExclusive();
    try ensureConnectionLive(conn);
    const deadline = c.picoquic_current_time() + stream_open_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        _ = try conn.endpoint.pumpOutgoing();
        _ = try conn.endpoint.pumpIncoming();
        for (conn.endpoint.streams.items) |stream| {
            if (stream.used and stream.cnx == conn.cnx and !stream.handed_off and stream.id & 0x2 != 0) {
                if (stream.reset) {
                    conn.endpoint.resetStreamSlot(stream);
                    return error.StreamReset;
                }
                if (!stream.fin) continue;
                const recv = try conn.endpoint.recvFor(conn.cnx, stream.id);
                stream.handed_off = true;
                return .{ .context = recv, .vtable = &recv_vtable };
            }
        }
    }
    return error.Timeout;
}

fn connRemote(ctx: *anyopaque) tr.NodeId {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    return conn.remote;
}

fn connRemoteAddress(ctx: *anyopaque) ?net.IpAddress {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    var sa: [*c]c.struct_sockaddr = null;
    c.picoquic_get_peer_addr(conn.cnx, &sa);
    // Legacy transport is IPv4-only (same restriction as ip4FromSockaddr).
    if (sa == null or sa.*.sa_family != c.AF_INET) return null;
    var storage = std.mem.zeroes(c.struct_sockaddr_storage);
    @memcpy(@as([*]u8, @ptrCast(&storage))[0..@sizeOf(c.struct_sockaddr_in)], @as([*]const u8, @ptrCast(sa))[0..@sizeOf(c.struct_sockaddr_in)]);
    return ip4FromSockaddr(storage) catch null;
}

fn connClose(ctx: *anyopaque) void {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    // Copied Connection values share this impl; only the first close tears down.
    if (conn.closed.swap(true, .acq_rel)) return;
    const endpoint = conn.endpoint;
    endpoint.enterExclusive();
    defer endpoint.leaveExclusive();
    const cnx = conn.cnx;
    if (conn.server_handoff) endpoint.unmarkServerCnxHandedOff(cnx);
    // Engine-truth teardown (recycle-proof): if picoquic no longer lists the
    // cnx it auto-deleted a remote-closed SERVER cnx inside a later send pass
    // (vendored sender.c:3806-3815) — picoquic_close + picoquic_delete_cnx on
    // it here would touch freed memory (observed 2026-07-21 as a GPF in
    // picoquic_delete_cnx from this exact path: netsim provider, fetcher
    // timed out + closed first). Zig-side reclaim only; the engine side is
    // already gone (client cnxs are never auto-deleted — resolveDeadCnxs
    // reclaims those before this can happen).
    const engine_state = endpoint.cnxEngineState(cnx);
    if (engine_state == null) {
        // The engine already auto-deleted this cnx (server drain), so we must NOT
        // call picoquic_delete_cnx again — but the close callback may already have
        // inserted it into the FIXED-CAPACITY closed_connections map (and the
        // handed-off set). Drop those bookkeeping entries here too, mirroring
        // deleteCnx minus the engine delete; otherwise a long-lived endpoint
        // (bench/cross_host runAnchor, the transfer_node provider) leaks one slot
        // per peer-close-first server cnx until putAssumeCapacity overruns
        // max_connections. dead_cnxs_pending (client cnxs) is reclaimed by
        // resolveDeadCnxs, which now drops absent entries.
        _ = endpoint.closed_connections.remove(cnx);
        endpoint.unmarkServerCnxHandedOff(cnx);
        endpoint.reclaimConnection(cnx);
        conn.deleted.store(true, .release);
        return;
    }
    // Tear down the picoquic connection so a persistent endpoint (one Endpoint
    // reused across many sequential accept()/connect() calls, as real nodes and
    // bench/cross_host.zig runAnchor do) does not keep stale, dead connections
    // in the quic context's list. Without this, firstReadyServerCnx() re-hands
    // off a dead connection and the next trial stalls on a fixed handshake/idle
    // timer; the per-connection structs also leak. iroh's noq Endpoint removes a
    // connection from its set on close (Drained -> try_remove + index.remove,
    // noq-proto/src/endpoint.rs); picoquic's analog is picoquic_delete_cnx,
    // which unlinks the cnx from quic->cnx_list (picoquic_remove_cnx_from_list)
    // and frees its per-connection state. picoquic_close first queues a
    // CONNECTION_CLOSE so the peer tears down promptly, mirroring noq's drain
    // (skipped when the peer already drove the disconnect).
    if (engine_state.? != c.picoquic_state_disconnected and c.picoquic_close(cnx, 0) == 0) {
        while (endpoint.pumpOutgoing() catch false) {}
    }
    endpoint.deleteCnx(cnx);
    conn.deleted.store(true, .release);
}

fn connIo(ctx: *anyopaque) std.Io {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    return conn.endpoint.io_inst;
}

pub fn connectionIsClosed(conn: tr.Connection) bool {
    const impl: *ConnectionImpl = @ptrCast(@alignCast(conn.context));
    return impl.closed.load(.acquire) or impl.remote_closed.load(.acquire) or impl.endpoint.closed_connections.contains(impl.cnx);
}

/// Poll for a finished inbound uni-stream without blocking.
///
/// Requires exclusive Endpoint ownership for the call (see module docs).
pub fn connectionTryAcceptUni(conn: tr.Connection) tr.Error!?tr.RecvStream {
    const impl: *ConnectionImpl = @ptrCast(@alignCast(conn.context));
    impl.endpoint.enterExclusive();
    defer impl.endpoint.leaveExclusive();
    try ensureConnectionLive(impl);
    try impl.endpoint.pollOnce();
    for (impl.endpoint.streams.items) |stream| {
        if (stream.used and stream.cnx == impl.cnx and !stream.handed_off and stream.id & 0x2 != 0) {
            if (stream.reset) {
                impl.endpoint.resetStreamSlot(stream);
                return error.StreamReset;
            }
            if (!stream.fin) continue;
            const recv = try impl.endpoint.recvFor(impl.cnx, stream.id);
            stream.handed_off = true;
            return .{ .context = recv, .vtable = &recv_vtable };
        }
    }
    return null;
}

pub const InboundUniChunk = struct {
    stream_id: u64,
    bytes: []const u8,
    fin: bool,
};

pub const InboundUniEvent = union(enum) {
    chunk: InboundUniChunk,
    reset: u64,
};

/// Poll for unread bytes on an inbound uni-stream without requiring FIN.
///
/// iroh-gossip keeps per-topic uni-streams open and writes multiple framed
/// messages to them, so callers that understand their own framing need access
/// before the generic FIN-based `acceptUni` reader is ready.
///
/// # Ownership / #19
/// Mutates stream receive state (`read_offset`, slot reclaim) without taking the
/// pump mutex — safe only under the Endpoint exclusive-owner precondition (same
/// as other Connection ops). Concurrent chunk poll/consume with another driver
/// on the same Endpoint is UB and panics under runtime_safety.
pub fn connectionNextInboundUniEvent(conn: tr.Connection) tr.Error!?InboundUniEvent {
    const impl: *ConnectionImpl = @ptrCast(@alignCast(conn.context));
    impl.endpoint.enterExclusive();
    defer impl.endpoint.leaveExclusive();
    try ensureConnectionLive(impl);
    try impl.endpoint.pollOnce();
    const streams = impl.endpoint.streams.items;
    if (streams.len == 0) return null;
    for (0..streams.len) |offset| {
        const index = (impl.next_stream_scan + offset) % streams.len;
        const stream = streams[index];
        if (stream.used and stream.cnx == impl.cnx and !stream.handed_off and (stream.id & 0x2) != 0) {
            if (stream.reset) {
                const stream_id = stream.id;
                impl.endpoint.resetStreamSlot(stream);
                impl.next_stream_scan = (index + 1) % streams.len;
                return .{ .reset = stream_id };
            }
            const written = stream.recv.written();
            if (stream.read_offset < written.len or stream.fin) {
                impl.next_stream_scan = (index + 1) % streams.len;
                return .{ .chunk = .{
                    .stream_id = stream.id,
                    .bytes = written[stream.read_offset..],
                    .fin = stream.fin,
                } };
            }
        }
    }
    return null;
}

pub fn connectionNextInboundUniChunk(conn: tr.Connection) tr.Error!?InboundUniChunk {
    const event = (try connectionNextInboundUniEvent(conn)) orelse return null;
    return switch (event) {
        .chunk => |chunk| chunk,
        .reset => error.StreamReset,
    };
}

/// Advance the chunk consumer past `len` bytes on `stream_id` (gossip framing).
///
/// # Ownership / #19
/// Mutates stream receive state without the pump mutex — requires exclusive
/// Endpoint ownership (see module docs). Not safe concurrent with any other
/// Endpoint/vtable op on the same Endpoint.
pub fn connectionConsumeInboundUniChunk(conn: tr.Connection, stream_id: u64, len: usize) tr.Error!void {
    const impl: *ConnectionImpl = @ptrCast(@alignCast(conn.context));
    impl.endpoint.enterExclusive();
    defer impl.endpoint.leaveExclusive();
    try ensureConnectionLive(impl);
    for (impl.endpoint.streams.items) |stream| {
        if (stream.used and stream.cnx == impl.cnx and stream.id == stream_id) {
            const written = stream.recv.written();
            if (len > written.len - stream.read_offset) return error.ConnectionLost;
            stream.read_offset += len;
            if (stream.fin and stream.read_offset >= written.len) {
                impl.endpoint.resetStreamSlot(stream);
            } else if (stream.read_offset == written.len) {
                stream.recv.writer.end = 0;
                stream.read_offset = 0;
            } else if (stream.read_offset >= 64 * 1024) {
                const unread = written[stream.read_offset..];
                @memmove(stream.recv.writer.buffer[0..unread.len], unread);
                stream.recv.writer.end = unread.len;
                stream.read_offset = 0;
            }
            return;
        }
    }
    return error.NotConnected;
}

test "F2: inbound uni chunk consumer reclaims slots beyond fixed table size" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{15} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{16} ** 32);
    const alpn: [:0]const u8 = "iroh-f2-17-uni-soak";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    const client_t = client_ep.transport();
    const server_t = server_ep.transport();
    var accept_future = std.testing.io.async(acceptConn, .{server_t});

    const client_conn = try client_t.connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    var payload_buf: [32]u8 = undefined;
    for (0..(legacy_fixed_stream_limit + 1)) |i| {
        const payload = try std.fmt.bufPrint(&payload_buf, "uni-{d}", .{i});
        const uni = try client_conn.openUni();
        try uni.writer().writeAll(payload);
        try uni.finish();

        const deadline = c.picoquic_current_time() + stream_finish_timeout_us;
        var got = false;
        while (c.picoquic_current_time() < deadline) {
            if (try connectionNextInboundUniChunk(server_conn)) |chunk| {
                if (chunk.bytes.len > 0) {
                    try std.testing.expectEqualStrings(payload, chunk.bytes);
                    try connectionConsumeInboundUniChunk(server_conn, chunk.stream_id, chunk.bytes.len);
                    got = true;
                    break;
                }
                if (chunk.fin) try connectionConsumeInboundUniChunk(server_conn, chunk.stream_id, 0);
            } else {
                _ = try client_ep.pollOnce();
                _ = try server_ep.pollOnce();
            }
        }
        try std.testing.expect(got);
    }
}

test "gossip transport supports more than sixteen simultaneous live uni streams" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x71} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x72} ** 32);
    const alpn: [:0]const u8 = "iroh-gossip-17-live-uni";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    const live_count = legacy_fixed_stream_limit + 1;
    var sends: [live_count]tr.SendStream = undefined;
    for (&sends, 0..) |*send, i| {
        send.* = try client_conn.openUni();
        try send.writer().writeByte(@intCast(i));
        try send.flush();
    }

    var seen = [_]bool{false} ** live_count;
    var seen_count: usize = 0;
    const deadline = c.picoquic_current_time() + stream_finish_timeout_us;
    while (seen_count < live_count and c.picoquic_current_time() < deadline) {
        if (try connectionNextInboundUniEvent(server_conn)) |event| switch (event) {
            .reset => return error.StreamReset,
            .chunk => |chunk| {
                if (chunk.bytes.len == 0) continue;
                const index = chunk.bytes[0];
                try std.testing.expect(index < live_count);
                if (!seen[index]) {
                    seen[index] = true;
                    seen_count += 1;
                }
                try connectionConsumeInboundUniChunk(server_conn, chunk.stream_id, chunk.bytes.len);
            },
        };
    }
    try std.testing.expectEqual(live_count, seen_count);

    for (&sends) |*send| try send.finish();
}

test "copied connection handles close idempotently without use after free" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x73} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x74} ** 32);
    const alpn: [:0]const u8 = "iroh-connection-copy-close";
    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();
    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    const alias = conn;
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    conn.close();
    alias.close();
    try std.testing.expect(connectionIsClosed(alias));
    try std.testing.expectError(error.NotConnected, alias.openUni());
    try std.testing.expectError(error.NotConnected, connectionNextInboundUniEvent(alias));
}

test "F2: endpoint accept skips handed-off server connections for later peers" {
    const allocator = std.testing.allocator;
    const a_key = key.SecretKey.fromBytes([_]u8{17} ** 32);
    const b_key = key.SecretKey.fromBytes([_]u8{18} ** 32);
    const c_key = key.SecretKey.fromBytes([_]u8{19} ** 32);
    const alpn: [:0]const u8 = "iroh-f2-three-peer-accept";

    const a_ep = try Endpoint.init(allocator, std.testing.io, a_key, alpn);
    defer a_ep.deinit();
    const b_ep = try Endpoint.init(allocator, std.testing.io, b_key, alpn);
    defer b_ep.deinit();
    const c_ep = try Endpoint.init(allocator, std.testing.io, c_key, alpn);
    defer c_ep.deinit();

    const b_t = b_ep.transport();
    var accept_a = std.testing.io.async(acceptConn, .{b_t});
    const a_conn = try a_ep.transport().connect(.{ .id = b_key.public(), .addrs = &.{.{ .ip = b_ep.localAddress() }} });
    defer a_conn.close();
    const b_from_a = try accept_a.await(std.testing.io);
    defer b_from_a.close();
    try std.testing.expect(b_from_a.remoteNodeId().eql(a_key.public()));

    var accept_c = std.testing.io.async(acceptConn, .{b_t});
    const c_conn = try c_ep.transport().connect(.{ .id = b_key.public(), .addrs = &.{.{ .ip = b_ep.localAddress() }} });
    defer c_conn.close();
    const b_from_c = try accept_c.await(std.testing.io);
    defer b_from_c.close();
    try std.testing.expect(b_from_c.remoteNodeId().eql(c_key.public()));
}

test "XH: persistent endpoint accepts each fresh connection after closing the previous one" {
    // Regression for the cross-host multi-trial degradation. A persistent anchor
    // endpoint (one Endpoint reused across many sequential accept() trials, as in
    // bench/cross_host.zig runAnchor) must tear down each closed picoquic
    // connection so accept() drives and returns the NEXT fresh connection instead
    // of short-circuiting on a stale, dead connection left in the quic context's
    // list. Pre-fix, accept() re-hands-off the stale cycle-0 cnx and stops
    // pumping the server side, so the next trial's handshake stalls until
    // handshake_timeout_us (error.Timeout) -- the same fixed-timer stall seen
    // cross-host.
    //
    // The cycle count exceeds the fixed stream/send/recv/server-cnx tables
    // (legacy_fixed_stream_limit + legacy_fixed_server_connection_limit), so a per-connection slot leak
    // surfaces here as OutOfMemory as well.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const server_key = key.SecretKey.fromBytes([_]u8{70} ** 32);
    const alpn: [:0]const u8 = "iroh-xh-persistent-accept";

    const server_ep = try Endpoint.init(allocator, io, server_key, alpn);
    defer server_ep.deinit();
    const server_t = server_ep.transport();

    const cycles = legacy_fixed_stream_limit + legacy_fixed_server_connection_limit + 4;
    // One persistent client endpoint per cycle, all kept alive until the end so
    // the test IO never reuses a port mid-run; only the SERVER endpoint is
    // reused across connections (the pattern runAnchor exercises).
    var client_eps: [legacy_fixed_stream_limit + legacy_fixed_server_connection_limit + 4]*Endpoint = undefined;

    var cycle: usize = 0;
    while (cycle < cycles) : (cycle += 1) {
        const client_key = key.SecretKey.fromBytes([_]u8{@intCast(80 + cycle)} ** 32);
        client_eps[cycle] = try Endpoint.init(allocator, io, client_key, alpn);

        var accept_future = io.async(acceptConn, .{server_t});
        const client_conn = try client_eps[cycle].transport().connect(.{
            .id = server_key.public(),
            .addrs = &.{.{ .ip = server_ep.localAddress() }},
        });
        const server_conn = try accept_future.await(io);

        try std.testing.expect(server_conn.remoteNodeId().eql(client_key.public()));

        // Close BOTH sides before the next cycle -- the trigger for the stall in
        // the cross-host harness, where the anchor closes one trial's connection
        // before accepting the next.
        client_conn.close();
        server_conn.close();
    }

    for (client_eps) |ep| ep.deinit();
}

test "auto-delete: server close after peer close does not double-free the cnx" {
    // Regression for the picoquic server-auto-delete trap (vendored
    // sender.c:3806-3815): a remote-closed SERVER cnx is deleted by picoquic
    // itself inside a later send pass, so connClose must not picoquic_close +
    // picoquic_delete_cnx it again — observed as a GPF in the netsim transfer
    // provider 2026-07-21 (fetcher timed out + closed first). In a plain
    // build the endpoint's continued health (a fresh connection succeeds) is
    // the signal; under test-safe-c (ASan) the UAF is deterministic.
    //
    // NOTE: the legacy endpoint is exclusive-caller (sequential ops only) —
    // the server is driven via short accept() calls, never a concurrent
    // background accept overlapping a connection op.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const client_key = key.SecretKey.fromBytes([_]u8{0xE1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xE2} ** 32);
    const alpn: [:0]const u8 = "iroh-legacy-peer-close-first";

    const client_ep = try Endpoint.init(allocator, io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.initOptions(allocator, io, server_key, alpn, .{
        .handshake_timeout_us = 500 * std.time.us_per_ms,
    });
    defer server_ep.deinit();

    var accept_future = io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try connectToServer(client_ep, server_key.public(), server_ep);
    defer client_conn.close();
    const server_conn = try accept_future.await(io);
    defer server_conn.close();

    // Peer (client) closes FIRST; short accept() calls keep the server
    // endpoint pumping (sequentially) so the close callback lands.
    client_conn.close();
    const deadline = c.picoquic_current_time() + 5 * std.time.us_per_s;
    var closed_seen = false;
    while (c.picoquic_current_time() < deadline and !closed_seen) {
        _ = server_ep.transport().accept() catch {};
        closed_seen = connectionIsClosed(server_conn);
    }
    if (!closed_seen) return error.TestExpectedRemoteClosed;

    // A few more pump rounds: the engine's send pass auto-deletes the
    // disconnected server cnx. Closing the server handle afterwards must NOT
    // touch the engine (the double-free trap).
    var rounds: usize = 0;
    while (rounds < 3) : (rounds += 1) {
        _ = server_ep.transport().accept() catch {};
    }
    server_conn.close();

    // The engine is still sane: a fresh connection succeeds (and the
    // resolveDeadCnxs sweep at the creation point reclaims the engine side).
    var accept2 = io.async(acceptConn, .{server_ep.transport()});
    const client2 = try connectToServer(client_ep, server_key.public(), server_ep);
    defer client2.close();
    const server2 = try accept2.await(io);
    defer server2.close();
    try std.testing.expect(server2.remoteNodeId().eql(client_key.public()));
}

test "CNX lifecycle: persistent client connect timeouts reclaim cnx" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const client_key = key.SecretKey.fromBytes([_]u8{90} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{91} ** 32);
    const alpn: [:0]const u8 = "iroh-cnx-timeout-reclaim";

    const client_ep = try Endpoint.initOptions(allocator, io, client_key, alpn, .{
        .handshake_timeout_us = 10 * std.time.us_per_ms,
    });
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, io, server_key, alpn);
    defer server_ep.deinit();

    const cycles = legacy_fixed_stream_limit + legacy_fixed_server_connection_limit + 4;
    var cycle: usize = 0;
    while (cycle < cycles) : (cycle += 1) {
        try std.testing.expectError(error.Timeout, client_ep.transport().connect(.{
            .id = server_key.public(),
            .addrs = &.{.{ .ip = server_ep.localAddress() }},
        }));
        try std.testing.expectEqual(@as(usize, 0), endpointCnxCount(client_ep));
    }
}

test "CNX lifecycle: client creation honors the endpoint connection cap" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x94} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x95} ** 32);
    const alpn: [:0]const u8 = "iroh-cnx-client-cap";

    const client_ep = try Endpoint.initOptions(allocator, std.testing.io, client_key, alpn, .{ .max_connections = 1 });
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    const first = try beginClientConnect(client_ep, server_key.public(), server_ep);
    try std.testing.expectEqual(@as(usize, 1), endpointCnxCount(client_ep));
    try std.testing.expectEqual(@as(usize, 1), c.iroh_picoquic_cnx_peer_count(client_ep.quic));
    try std.testing.expectError(error.OutOfMemory, beginClientConnect(client_ep, server_key.public(), server_ep));
    try std.testing.expectEqual(@as(usize, 1), endpointCnxCount(client_ep));

    client_ep.deleteCnx(first);
    try std.testing.expectEqual(@as(usize, 0), endpointCnxCount(client_ep));
    try std.testing.expectEqual(@as(usize, 0), c.iroh_picoquic_cnx_peer_count(client_ep.quic));

    const replacement = try beginClientConnect(client_ep, server_key.public(), server_ep);
    client_ep.deleteCnx(replacement);
}

test "RPK verifier state is evicted with each closed connection" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x96} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x97} ** 32);
    const alpn: [:0]const u8 = "iroh-rpk-cnx-eviction";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    const server_conn = try accept_future.await(std.testing.io);
    try std.testing.expectEqual(@as(usize, 1), c.iroh_picoquic_cnx_peer_count(client_ep.quic));
    try std.testing.expectEqual(@as(usize, 1), c.iroh_picoquic_cnx_peer_count(server_ep.quic));

    client_conn.close();
    try server_ep.pollOnce();
    try std.testing.expectEqual(@as(usize, 0), c.iroh_picoquic_cnx_peer_count(client_ep.quic));
    try std.testing.expectEqual(@as(usize, 0), c.iroh_picoquic_cnx_peer_count(server_ep.quic));

    server_conn.close();
    try std.testing.expectEqual(@as(usize, 0), c.iroh_picoquic_cnx_peer_count(client_ep.quic));
    try std.testing.expectEqual(@as(usize, 0), c.iroh_picoquic_cnx_peer_count(server_ep.quic));
}

// Crypto-seam: production-path client pin oracle.
// Mutation-RED: disable set_cnx_expected_peer + SNI pin in rpk.c verify → these
// go green wrongly (accept-any). Happy path (S2 / eviction above) must stay green.
// Server accept-any TOFU is intentionally NOT failed-closed (iroh verify_client_cert).

test "RPK-auth: production dial rejects cross-identity server RPK (client pin)" {
    // Client dials address of server X but pins expected identity Y (wrong NodeId).
    // Production path: beginClientCnx → set_cnx_expected_peer + SNI(Y).
    // Server presents X → BAD_CERTIFICATE → handshake never ready → Timeout.
    // Server TOFU may still complete its side (iroh verify_client_cert) — that is
    // intentional; only the client pin is the reject under test.
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xa1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xa2} ** 32);
    const wrong_key = key.SecretKey.fromBytes([_]u8{0xa3} ** 32);
    const alpn: [:0]const u8 = "iroh-rpk-cross-identity";

    const client_ep = try Endpoint.initOptions(allocator, std.testing.io, client_key, alpn, .{
        .handshake_timeout_us = 500 * std.time.us_per_ms,
    });
    defer client_ep.deinit();
    const server_ep = try Endpoint.initOptions(allocator, std.testing.io, server_key, alpn, .{
        .handshake_timeout_us = 500 * std.time.us_per_ms,
    });
    defer server_ep.deinit();

    // Pump server so TLS can complete far enough to present its RPK and be rejected.
    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    defer {
        _ = accept_future.cancel(std.testing.io) catch {};
    }

    const result = client_ep.transport().connect(.{
        .id = wrong_key.public(), // pin Y
        .addrs = &.{.{ .ip = server_ep.localAddress() }}, // address of X
    });
    try std.testing.expectError(error.Timeout, result);
}

test "RPK-auth: production dial accepts matching identity (positive control)" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xa4} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xa5} ** 32);
    const alpn: [:0]const u8 = "iroh-rpk-match-identity";

    const client_ep = try Endpoint.initOptions(allocator, std.testing.io, client_key, alpn, .{
        .handshake_timeout_us = 5 * std.time.us_per_s,
    });
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server_ep.localAddress() }},
    });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    try std.testing.expect(client_conn.remoteNodeId().eql(server_key.public()));
    try std.testing.expect(server_conn.remoteNodeId().eql(client_key.public()));
}

test "RPK-auth: imperative pin alone rejects when SNI matches but set_cnx expects other" {
    // Proves set_cnx_expected_peer is load-bearing even when SNI is honest:
    // dial with correct SNI/peer id via beginClientCnx, then overwrite the
    // per-cnx expected key to a different identity before the handshake finishes.
    // Mutation-RED: remove the has_expected memcmp in rpk.c → handshake succeeds
    // (SNI still matches the real server, so SNI-only defense would green this).
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xa6} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xa7} ** 32);
    const wrong_key = key.SecretKey.fromBytes([_]u8{0xa8} ** 32);
    const alpn: [:0]const u8 = "iroh-rpk-imperative-pin";

    const client_ep = try Endpoint.initOptions(allocator, std.testing.io, client_key, alpn, .{
        .handshake_timeout_us = 500 * std.time.us_per_ms,
    });
    defer client_ep.deinit();
    const server_ep = try Endpoint.initOptions(allocator, std.testing.io, server_key, alpn, .{
        .handshake_timeout_us = 500 * std.time.us_per_ms,
    });
    defer server_ep.deinit();

    // Honest SNI (server_key) but force wrong expected pin after create.
    // beginClientCnx already started the client; overwriting expected before
    // the server Certificate is verified is what the pin table supports.
    const cnx = try beginClientConnect(client_ep, server_key.public(), server_ep);
    const wrong_public = wrong_key.public().toBytes();
    try std.testing.expectEqual(@as(c_int, 0), c.iroh_picoquic_set_cnx_expected_peer(cnx, &wrong_public));

    // Drive until timeout — must not become ready. Do not deleteCnx after a
    // failed handshake: picoquic may already have reclaimed the cnx; Endpoint
    // deinit owns residual cleanup.
    var saw_ready = false;
    const deadline = c.picoquic_current_time() + client_ep.handshake_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        try client_ep.pollOnce();
        try server_ep.pollOnce();
        // Only observe state while the cnx is still listed on the client quic.
        var still_listed = false;
        var maybe: ?*c.picoquic_cnx_t = c.picoquic_get_first_cnx(client_ep.quic);
        while (maybe) |listed| : (maybe = c.picoquic_get_next_cnx(listed)) {
            if (listed == cnx) still_listed = true;
        }
        if (still_listed and c.picoquic_get_cnx_state(cnx) == c.picoquic_state_ready) {
            saw_ready = true;
            break;
        }
    }
    try std.testing.expect(!saw_ready);
}

test "D1: concurrent inbound handshakes resolve distinct peer identities" {
    const allocator = std.testing.allocator;
    const a_key = key.SecretKey.fromBytes([_]u8{41} ** 32);
    const b_key = key.SecretKey.fromBytes([_]u8{42} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{43} ** 32);
    const alpn: [:0]const u8 = "iroh-d1-concurrent-rpk";

    const a_ep = try Endpoint.init(allocator, std.testing.io, a_key, alpn);
    defer a_ep.deinit();
    const b_ep = try Endpoint.init(allocator, std.testing.io, b_key, alpn);
    defer b_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    const cnx_a = try beginClientConnect(a_ep, server_key.public(), server_ep);
    const cnx_b = try beginClientConnect(b_ep, server_key.public(), server_ep);

    var server_cnxs: [2]?*c.picoquic_cnx_t = .{ null, null };
    var server_count: usize = 0;
    const deadline = c.picoquic_current_time() + handshake_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        try a_ep.pollOnce();
        try b_ep.pollOnce();
        try server_ep.pollOnce();

        var maybe_server_cnx: ?*c.picoquic_cnx_t = c.picoquic_get_first_cnx(server_ep.quic);
        while (maybe_server_cnx) |cnx| : (maybe_server_cnx = c.picoquic_get_next_cnx(cnx)) {
            if (c.picoquic_get_cnx_state(cnx) != c.picoquic_state_ready or c.picoquic_is_client(cnx) != 0) continue;
            var already_collected = false;
            for (server_cnxs[0..server_count]) |existing| {
                if (existing == cnx) already_collected = true;
            }
            if (!already_collected and server_count < server_cnxs.len) {
                server_cnxs[server_count] = cnx;
                server_count += 1;
            }
        }

        if (c.picoquic_get_cnx_state(cnx_a) == c.picoquic_state_ready and
            c.picoquic_get_cnx_state(cnx_b) == c.picoquic_state_ready and
            server_count == server_cnxs.len)
        {
            break;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), server_count);
    try std.testing.expect(c.picoquic_get_cnx_state(cnx_a) == c.picoquic_state_ready);
    try std.testing.expect(c.picoquic_get_cnx_state(cnx_b) == c.picoquic_state_ready);

    const a_conn = try a_ep.connectionForCnx(cnx_a, false);
    defer a_conn.close();
    const b_conn = try b_ep.connectionForCnx(cnx_b, false);
    defer b_conn.close();
    const server_from_first = try server_ep.connectionForCnx(server_cnxs[0].?, true);
    defer server_from_first.close();
    const server_from_second = try server_ep.connectionForCnx(server_cnxs[1].?, true);
    defer server_from_second.close();

    const remote_first = server_from_first.remoteNodeId();
    const remote_second = server_from_second.remoteNodeId();
    try std.testing.expect(!remote_first.eql(remote_second));
    try std.testing.expect(
        (remote_first.eql(a_key.public()) and remote_second.eql(b_key.public())) or
            (remote_first.eql(b_key.public()) and remote_second.eql(a_key.public())),
    );
    try std.testing.expect(a_conn.remoteNodeId().eql(server_key.public()));
    try std.testing.expect(b_conn.remoteNodeId().eql(server_key.public()));
}

test "CNX lifecycle: failed server handoff reclaims and deletes cnx" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{92} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{93} ** 32);
    const alpn: [:0]const u8 = "iroh-cnx-server-handoff-fail";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    const client_cnx = try beginClientConnect(client_ep, server_key.public(), server_ep);
    defer client_ep.deleteCnx(client_cnx);

    var server_cnx: ?*c.picoquic_cnx_t = null;
    const deadline = c.picoquic_current_time() + handshake_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        try client_ep.pollOnce();
        try server_ep.pollOnce();
        if (server_ep.firstReadyServerCnx()) |cnx| {
            server_cnx = cnx;
            break;
        }
    }
    const cnx = server_cnx orelse return error.Timeout;

    const original_allocator = server_ep.allocator;
    server_ep.allocator = std.testing.failing_allocator;
    const handoff_result = server_ep.connectionForCnx(cnx, true);
    server_ep.allocator = original_allocator;
    try std.testing.expectError(error.OutOfMemory, handoff_result);

    try std.testing.expectEqual(@as(usize, 0), endpointCnxCount(server_ep));
    try std.testing.expect(server_ep.firstReadyServerCnx() == null);
}

test "T3: inbound uni streams with colliding IDs stay connection-scoped" {
    const allocator = std.testing.allocator;
    const a_key = key.SecretKey.fromBytes([_]u8{31} ** 32);
    const b_key = key.SecretKey.fromBytes([_]u8{32} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{33} ** 32);
    const alpn: [:0]const u8 = "iroh-t3-stream-scope";

    const a_ep = try Endpoint.init(allocator, std.testing.io, a_key, alpn);
    defer a_ep.deinit();
    const b_ep = try Endpoint.init(allocator, std.testing.io, b_key, alpn);
    defer b_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    const server_t = server_ep.transport();
    var accept_a = std.testing.io.async(acceptConn, .{server_t});
    const a_conn = try a_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer a_conn.close();
    const server_from_a = try accept_a.await(std.testing.io);
    defer server_from_a.close();

    var accept_b = std.testing.io.async(acceptConn, .{server_t});
    const b_conn = try b_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer b_conn.close();
    const server_from_b = try accept_b.await(std.testing.io);
    defer server_from_b.close();

    const a_uni = try a_conn.openUni();
    try a_uni.writer().writeAll("from-a");
    try a_uni.finish();
    const recv_a = try drivePairUntilAcceptUni(a_ep, server_ep, server_from_a);
    var a_buf: [16]u8 = undefined;
    const a_n = try recv_a.reader().readSliceShort(&a_buf);
    try std.testing.expectEqualStrings("from-a", a_buf[0..a_n]);

    const b_uni = try b_conn.openUni();
    try b_uni.writer().writeAll("from-b");
    try b_uni.finish();
    const recv_b = try drivePairUntilAcceptUni(b_ep, server_ep, server_from_b);
    var b_buf: [16]u8 = undefined;
    const b_n = try recv_b.reader().readSliceShort(&b_buf);
    try std.testing.expectEqualStrings("from-b", b_buf[0..b_n]);
}

test "T4: local stream opens reserve distinct picoquic stream IDs before finish" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{34} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{35} ** 32);
    const alpn: [:0]const u8 = "iroh-t4-open-reserve";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    const server_t = server_ep.transport();
    var accept_future = std.testing.io.async(acceptConn, .{server_t});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    const bi_one = try client_conn.openBi();
    const bi_two = try client_conn.openBi();
    const bi_one_send: *SendImpl = @ptrCast(@alignCast(bi_one.send.context));
    const bi_two_send: *SendImpl = @ptrCast(@alignCast(bi_two.send.context));
    try std.testing.expect(bi_one_send.stream_id != bi_two_send.stream_id);
    try bi_one.send.writer().writeAll("bi-one");
    try bi_two.send.writer().writeAll("bi-two");
    try bi_one.send.finish();
    try bi_two.send.finish();

    const server_bi_one = try drivePairUntilAcceptBi(client_ep, server_ep, server_conn);
    var bi_one_buf: [16]u8 = undefined;
    const bi_one_n = try server_bi_one.recv.reader().readSliceShort(&bi_one_buf);
    try std.testing.expectEqualStrings("bi-one", bi_one_buf[0..bi_one_n]);

    const server_bi_two = try drivePairUntilAcceptBi(client_ep, server_ep, server_conn);
    var bi_two_buf: [16]u8 = undefined;
    const bi_two_n = try server_bi_two.recv.reader().readSliceShort(&bi_two_buf);
    try std.testing.expectEqualStrings("bi-two", bi_two_buf[0..bi_two_n]);

    const uni_one = try client_conn.openUni();
    const uni_two = try client_conn.openUni();
    const uni_one_send: *SendImpl = @ptrCast(@alignCast(uni_one.context));
    const uni_two_send: *SendImpl = @ptrCast(@alignCast(uni_two.context));
    try std.testing.expect(uni_one_send.stream_id != uni_two_send.stream_id);
    try uni_one.writer().writeAll("uni-one");
    try uni_two.writer().writeAll("uni-two");
    try uni_one.finish();
    try uni_two.finish();

    const server_uni_one = try drivePairUntilAcceptUni(client_ep, server_ep, server_conn);
    var uni_one_buf: [16]u8 = undefined;
    const uni_one_n = try server_uni_one.reader().readSliceShort(&uni_one_buf);
    try std.testing.expectEqualStrings("uni-one", uni_one_buf[0..uni_one_n]);

    const server_uni_two = try drivePairUntilAcceptUni(client_ep, server_ep, server_conn);
    var uni_two_buf: [16]u8 = undefined;
    const uni_two_n = try server_uni_two.reader().readSliceShort(&uni_two_buf);
    try std.testing.expectEqualStrings("uni-two", uni_two_buf[0..uni_two_n]);
}

test "T4: SendStream reset queues transport reset and later opens advance" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{36} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{37} ** 32);
    const alpn: [:0]const u8 = "iroh-t4-reset-visible";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    const server_t = server_ep.transport();
    var accept_future = std.testing.io.async(acceptConn, .{server_t});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    const reset_uni = try client_conn.openUni();
    const reset_send: *SendImpl = @ptrCast(@alignCast(reset_uni.context));
    const reset_stream_id = reset_send.stream_id;
    try reset_uni.writer().writeAll("discarded");
    reset_uni.reset();
    try std.testing.expect(!reset_send.used);
    try drivePairUntilStreamReset(client_ep, server_ep, server_conn, reset_stream_id);

    const next_uni = try client_conn.openUni();
    const next_send: *SendImpl = @ptrCast(@alignCast(next_uni.context));
    try std.testing.expect(next_send.stream_id != reset_stream_id);
    try next_uni.writer().writeAll("after-reset");
    try next_uni.finish();

    const recv_next = try drivePairUntilAcceptUni(client_ep, server_ep, server_conn);
    var buf: [16]u8 = undefined;
    const n = try recv_next.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("after-reset", buf[0..n]);
}

test "recvReader survives peer stream reset without process abort" {
    // Real-path regression: peer RESETS after handoff; reader() must not panic.
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xC1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xC2} ** 32);
    const alpn: [:0]const u8 = "iroh-vc1-recvreader-reset";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    const bi = try client_conn.openBi();
    const send: *SendImpl = @ptrCast(@alignCast(bi.send.context));
    // Deliver data WITHOUT FIN so accept can hand off, then RESET before reader().
    try std.testing.expectEqual(@as(c_int, 0), c.picoquic_add_to_stream(send.cnx, send.stream_id, "x".ptr, 1, 0));
    const server_bi = try drivePairUntilAcceptBi(client_ep, server_ep, server_conn);
    const server_recv: *RecvImpl = @ptrCast(@alignCast(server_bi.recv.context));
    const target_stream_id = server_recv.stream_id;

    bi.send.reset();

    const deadline = c.picoquic_current_time() + stream_open_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        try client_ep.pollOnce();
        try server_ep.pollOnce();
        for (server_ep.streams.items) |stream| {
            if (stream.used and stream.cnx == server_recv.cnx and stream.id == target_stream_id and stream.reset) {
                const reader = server_bi.recv.reader();
                var scratch: [8]u8 = undefined;
                // empty fixed reader after graceful failure → 0 bytes, not a process abort
                const n = try reader.readSliceShort(&scratch);
                try std.testing.expectEqual(@as(usize, 0), n);
                return;
            }
        }
    }
    return error.Timeout;
}

test "RecvStream.stop emits STOP_SENDING and the peer answers with RESET_STREAM" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xD1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xD2} ** 32);
    const alpn: [:0]const u8 = "iroh-stream-stop";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    const client_bi = try client_conn.openBi();
    try client_bi.send.writer().writeAll("discard-me");
    try client_bi.send.flush();
    const server_bi = try drivePairUntilAcceptBi(client_ep, server_ep, server_conn);
    const server_recv: *RecvImpl = @ptrCast(@alignCast(server_bi.recv.context));
    try server_bi.recv.stop();

    const deadline = c.picoquic_current_time() + stream_open_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        try client_ep.pollOnce();
        try server_ep.pollOnce();
        for (server_ep.streams.items) |stream| {
            if (stream.used and stream.cnx == server_recv.cnx and stream.id == server_recv.stream_id and stream.reset) return;
        }
    }
    return error.Timeout;
}

test "two dials keep isolated magicsock path state" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x11} ** 32);
    const server_a_key = key.SecretKey.fromBytes([_]u8{0xA1} ** 32);
    const server_b_key = key.SecretKey.fromBytes([_]u8{0xB1} ** 32);
    const alpn: [:0]const u8 = "iroh-vc3-path-isolation";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_a = try Endpoint.init(allocator, std.testing.io, server_a_key, alpn);
    defer server_a.deinit();
    const server_b = try Endpoint.init(allocator, std.testing.io, server_b_key, alpn);
    defer server_b.deinit();

    var accept_a = std.testing.io.async(acceptConn, .{server_a.transport()});
    const conn_a = try client_ep.transport().connect(.{ .id = server_a_key.public(), .addrs = &.{.{ .ip = server_a.localAddress() }} });
    defer conn_a.close();
    const server_conn_a = try accept_a.await(std.testing.io);
    defer server_conn_a.close();

    var accept_b = std.testing.io.async(acceptConn, .{server_b.transport()});
    const conn_b = try client_ep.transport().connect(.{ .id = server_b_key.public(), .addrs = &.{.{ .ip = server_b.localAddress() }} });
    defer conn_b.close();
    const server_conn_b = try accept_b.await(std.testing.io);
    defer server_conn_b.close();

    const impl_a: *ConnectionImpl = @ptrCast(@alignCast(conn_a.context));
    const impl_b: *ConnectionImpl = @ptrCast(@alignCast(conn_b.context));
    const path_a = client_ep.pathStateFor(impl_a.cnx) orelse return error.PathStateMissing;
    const path_b = client_ep.pathStateFor(impl_b.cnx) orelse return error.PathStateMissing;
    try std.testing.expect(path_a != path_b);

    const addr_a: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 1111 } };
    const addr_b: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 2 }, .port = 2222 } };
    try path_a.magicsock_state.handleFrame(.{ .ipv4_address = .{
        .frame_type = .add_ipv4_address,
        .seq = 1,
        .ip = addr_a.ip4.bytes,
        .port = addr_a.ip4.port,
    } });
    try path_b.magicsock_state.handleFrame(.{ .ipv4_address = .{
        .frame_type = .add_ipv4_address,
        .seq = 1,
        .ip = addr_b.ip4.bytes,
        .port = addr_b.ip4.port,
    } });
    path_a.magicsock_state.markPathSucceeded(addr_a, 10);
    path_b.magicsock_state.markPathSucceeded(addr_b, 10);

    try std.testing.expectEqual(addr_a, path_a.magicsock_state.selectedPath().?.address);
    try std.testing.expectEqual(addr_b, path_b.magicsock_state.selectedPath().?.address);
    try std.testing.expect(!std.meta.eql(path_a.magicsock_state.selectedPath().?.address, path_b.magicsock_state.selectedPath().?.address));
}

test "lockPump acquires under contention with bounded backoff" {
    const allocator = std.testing.allocator;
    const secret = key.SecretKey.fromBytes([_]u8{0x22} ** 32);
    const ep = try Endpoint.init(allocator, std.testing.io, secret, "iroh-vc3-lockpump");
    defer ep.deinit();

    var hold = std.atomic.Value(bool).init(true);
    const holder = try std.Thread.spawn(.{}, struct {
        fn run(endpoint: *Endpoint, flag: *std.atomic.Value(bool)) void {
            // lockPump is internal pump serialization, not the exclusive-owner
            // guard — multi-thread contention here remains intentional.
            endpoint.lockPump();
            while (flag.load(.acquire)) {
                std.Thread.yield() catch {};
            }
            endpoint.mu.unlock();
        }
    }.run, .{ ep, &hold });

    std.Thread.yield() catch {};
    std.testing.io.sleep(std.Io.Duration.fromMilliseconds(5), .real) catch {};

    const waiter = try std.Thread.spawn(.{}, struct {
        fn run(endpoint: *Endpoint) void {
            endpoint.lockPump();
            endpoint.mu.unlock();
        }
    }.run, .{ep});

    std.testing.io.sleep(std.Io.Duration.fromMilliseconds(20), .real) catch {};
    hold.store(false, .release);
    holder.join();
    waiter.join();
}

test "ownership: sequential pollOnce and nested enter are green" {
    if (!std.debug.runtime_safety) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const secret = key.SecretKey.fromBytes([_]u8{0xA0} ** 32);
    const ep = try Endpoint.init(allocator, std.testing.io, secret, "iroh-ownership-sequential");
    defer ep.deinit();

    // Sequential top-level calls: free between calls, always GREEN.
    try ep.pollOnce();
    try ep.pollOnce();

    // Nested same-thread re-entry: outer claim + pollOnce's own enter/leave.
    ep.enterExclusive();
    defer ep.leaveExclusive();
    try ep.pollOnce();
    try std.testing.expectEqual(@as(u32, 1), ep.owner_depth);
}

// Concurrent violation is proven by `zig build quic-ownership-probe`
// (bench/quic_ownership_probe.zig): child panics under ReleaseSafe; build step
// expects SIGABRT. In-process expect-a-panic is impossible (process abort).

test "F4: initOptions preserves loopback default and supplies concrete public local address" {
    const allocator = std.testing.allocator;
    const secret = key.SecretKey.fromBytes([_]u8{20} ** 32);

    const loopback_ep = try Endpoint.init(allocator, std.testing.io, secret, "iroh-f4-loopback-default");
    defer loopback_ep.deinit();
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &loopback_ep.localAddress().ip4.bytes);
    try std.testing.expect(loopback_ep.localAddress().getPort() != 0);

    const wildcard_bind: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
    const public_addr: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    const public_ep = try Endpoint.initOptions(allocator, std.testing.io, secret, "iroh-f4-public-bind", .{
        .bind_address = wildcard_bind,
        .public_address = public_addr,
    });
    defer public_ep.deinit();

    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &public_ep.boundAddress().ip4.bytes);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &public_ep.localAddress().ip4.bytes);
    try std.testing.expectEqual(public_ep.boundAddress().getPort(), public_ep.localAddress().getPort());
    try std.testing.expectEqual(public_ep.localAddress(), public_ep.pathLocalAddress(.{ .ip4 = .loopback(9999) }));
}

fn connAlpn(ctx: *anyopaque) ?[]const u8 {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    if (conn.alpn_len == 0) return null;
    return conn.alpn_storage[0..conn.alpn_len];
}

const connection_vtable: tr.Connection.VTable = .{ .openBi = connOpenBi, .acceptBi = connAcceptBi, .openUni = connOpenUni, .acceptUni = connAcceptUni, .remoteNodeId = connRemote, .alpn = connAlpn, .remoteAddress = connRemoteAddress, .close = connClose, .io = connIo };

test "Endpoint deinit zeroizes stored secret without touching caller copy" {
    var backing: [@sizeOf(Endpoint) + 1024]u8 align(@alignOf(Endpoint)) = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const allocator = fba.allocator();
    const seed = [_]u8{0x42} ** 32;
    const caller_secret = key.SecretKey.fromBytes(seed);

    const endpoint = try Endpoint.initOptions(allocator, std.testing.io, caller_secret, "iroh-h8r-endpoint-zeroize", .{ .max_connections = 1 });
    try std.testing.expectEqual(seed, endpoint.secret.toBytes());
    endpoint.deinit();

    try std.testing.expectEqual([_]u8{0} ** 32, endpoint.secret.toBytes());
    try std.testing.expectEqual(seed, caller_secret.toBytes());
}

fn sendWriter(ctx: *anyopaque) *std.Io.Writer {
    const send: *SendImpl = @ptrCast(@alignCast(ctx));
    if (!send.used) return &send.dead_writer;
    return &send.buffer.writer;
}

fn sendFlush(ctx: *anyopaque) tr.Error!void {
    const send: *SendImpl = @ptrCast(@alignCast(ctx));
    return sendStreamFlush(.{ .context = send, .vtable = &send_vtable });
}

/// Submit buffered bytes on an open send stream without sending FIN.
///
/// Gossip uses this to retain Rust's one-long-lived-uni-stream-per-topic
/// ordering while still making each framed message visible immediately.
///
/// Requires exclusive Endpoint ownership for the call (see module docs).
pub fn sendStreamFlush(stream: tr.SendStream) tr.Error!void {
    const send: *SendImpl = @ptrCast(@alignCast(stream.context));
    if (!send.used) return error.NotConnected;
    const data = send.buffer.written();
    if (data.len == 0) return;

    send.endpoint.enterExclusive();
    defer send.endpoint.leaveExclusive();
    const stream_state = try send.endpoint.streamFor(send.cnx, send.stream_id);

    // #10: hold the pump lock only for the picoquic submit, not across the
    // blocking socket quiesce loop (drop/re-acquire between pump rounds).
    send.endpoint.lockPump();
    if (c.picoquic_add_to_stream_with_ctx(send.cnx, send.stream_id, data.ptr, data.len, 0, stream_state) != 0) {
        send.endpoint.mu.unlock();
        return error.ConnectionLost;
    }
    send.buffer.clearRetainingCapacity();
    send.endpoint.mu.unlock();
    while (true) {
        // A peer close can make picoquic auto-delete a server cnx mid-loop
        // (sender.c:3806-3815); stop before touching freed engine state.
        const engine_state = send.endpoint.cnxEngineState(send.cnx);
        if (engine_state == null or engine_state.? == c.picoquic_state_disconnected) return error.ConnectionLost;
        const sent = try send.endpoint.pumpOutgoing();
        const received = try send.endpoint.pumpIncoming();
        if (!sent and !received) return;
    }
}

fn sendFinish(ctx: *anyopaque) tr.Error!void {
    const send: *SendImpl = @ptrCast(@alignCast(ctx));
    // Copied SendStream handles share this slot; second finish is a no-op.
    if (!send.used) return;
    defer {
        send.buffer.deinit();
        send.* = .{};
    }
    const data = send.buffer.written();
    send.endpoint.enterExclusive();
    defer send.endpoint.leaveExclusive();
    const stream_state = try send.endpoint.streamFor(send.cnx, send.stream_id);

    // #10: same lock-scope fix as sendStreamFlush — do not hold mu across
    // the blocking quiesce loop.
    send.endpoint.lockPump();
    if (c.picoquic_add_to_stream_with_ctx(send.cnx, send.stream_id, data.ptr, data.len, 1, stream_state) != 0) {
        send.endpoint.mu.unlock();
        return error.ConnectionLost;
    }
    send.endpoint.mu.unlock();
    // Drive the connection until every queued byte (data + FIN) has been transmitted,
    // NOT just until the first idle pump round. picoquic paces a large send across many
    // round-trips: once the congestion window is full it has nothing to send while it
    // waits for ACKs, so a `!sent and !received` exit abandoned the remainder of a
    // multi-window stream — the peer then starved on the missing bytes (observed
    // 2026-07-18: a 65 KB Push delivered <1 window, stalling the provider 30 s).
    // Continuing to pump lets inbound ACKs reopen the window so the rest goes out.
    // The condition is FIN-transmitted, not acknowledged (see
    // iroh_picoquic_stream_send_flushed): this keeps the pre-existing return-after-flush
    // contract — small sends and request/response streams (Get) return as soon as their
    // bytes are on the wire, without blocking on the peer's ACK or response half — while
    // fixing only the large-send truncation. Bounded by the same deadline as
    // driveUntilStreamFin on the receive side.
    const deadline = c.picoquic_current_time() + stream_finish_timeout_us;
    while (true) {
        // A peer close can make picoquic auto-delete a server cnx mid-loop
        // (sender.c:3806-3815); stop before touching freed engine state.
        const engine_state = send.endpoint.cnxEngineState(send.cnx);
        if (engine_state == null or engine_state.? == c.picoquic_state_disconnected) return error.ConnectionLost;
        _ = try send.endpoint.pumpOutgoing();
        send.endpoint.lockPump();
        const flushed = c.iroh_picoquic_stream_send_flushed(send.cnx, send.stream_id) != 0;
        send.endpoint.mu.unlock();
        if (flushed) return;
        if (c.picoquic_current_time() >= deadline) return error.Timeout;
        _ = try send.endpoint.pumpIncoming();
    }
}

/// Wait until every byte queued on an OPEN send stream has been packetized
/// (picoquic's per-stream FIFO drained into packets) — wire pacing for
/// streaming senders.
///
/// `sendStreamFlush` returns as soon as picoquic has ACCEPTED the bytes into
/// its internal queue, so a send loop paced only by flush runs at memory speed
/// and the wire lags arbitrarily far behind (observed: a 5 s transfer-example
/// provide enqueued 717 MB and took 18 s on the wire). This waits on
/// `iroh_picoquic_stream_send_drained` (send_queue empty) — NOT the
/// fin_sent-based `send_flushed` used by sendFinish, which never fires on an
/// open stream. Same deadline as sendFinish — `error.Timeout` means the queue
/// did not drain in time.
///
/// Requires exclusive Endpoint ownership for the call (see module docs).
pub fn sendStreamWaitDrained(stream: tr.SendStream) tr.Error!void {
    const send: *SendImpl = @ptrCast(@alignCast(stream.context));
    if (!send.used) return error.NotConnected;
    send.endpoint.enterExclusive();
    defer send.endpoint.leaveExclusive();
    const deadline = c.picoquic_current_time() + stream_finish_timeout_us;
    while (true) {
        // A peer close can make picoquic auto-delete a server cnx mid-loop
        // (sender.c:3806-3815); stop before touching freed engine state.
        const engine_state = send.endpoint.cnxEngineState(send.cnx);
        if (engine_state == null or engine_state.? == c.picoquic_state_disconnected) return error.ConnectionLost;
        _ = try send.endpoint.pumpOutgoing();
        send.endpoint.lockPump();
        const drained = c.iroh_picoquic_stream_send_drained(send.cnx, send.stream_id) != 0;
        send.endpoint.mu.unlock();
        if (drained) return;
        if (c.picoquic_current_time() >= deadline) return error.Timeout;
        _ = try send.endpoint.pumpIncoming();
    }
}

/// Wait until an OPEN send stream's queue holds AT MOST `low_water` bytes —
/// the low-water variant of `sendStreamWaitDrained` for pipelined pacing.
///
/// Waiting for a FULL drain starves the packet builder between chunks: the
/// queue empties, the wire idles while the sender turns around and enqueues
/// the next chunk (measured under netsim 2026-07-21: explicit per-1 MiB drain
/// = 176.7 Mbps vs unpaced native = 301.5 Mbps over the same 256 MiB zig↔zig
/// transfer — a ~41% bubble). Waiting for `queued <= low_water` instead keeps
/// the builder fed continuously while still bounding the queue (caller caps
/// enqueue at a high-water mark), i.e. native-pacing throughput with bounded
/// memory. Same deadline as sendStreamWaitDrained.
///
/// Requires exclusive Endpoint ownership for the call (see module docs).
pub fn sendStreamWaitQueuedBelow(stream: tr.SendStream, low_water: usize) tr.Error!void {
    const send: *SendImpl = @ptrCast(@alignCast(stream.context));
    if (!send.used) return error.NotConnected;
    send.endpoint.enterExclusive();
    defer send.endpoint.leaveExclusive();
    const deadline = c.picoquic_current_time() + stream_finish_timeout_us;
    while (true) {
        // A peer close can make picoquic auto-delete a server cnx mid-loop
        // (sender.c:3806-3815); stop before touching freed engine state.
        const engine_state = send.endpoint.cnxEngineState(send.cnx);
        if (engine_state == null or engine_state.? == c.picoquic_state_disconnected) return error.ConnectionLost;
        _ = try send.endpoint.pumpOutgoing();
        send.endpoint.lockPump();
        const queued = c.iroh_picoquic_stream_send_queued(send.cnx, send.stream_id);
        send.endpoint.mu.unlock();
        if (queued <= low_water) return;
        if (c.picoquic_current_time() >= deadline) return error.Timeout;
        _ = try send.endpoint.pumpIncoming();
    }
}

fn sendReset(ctx: *anyopaque) void {
    const send: *SendImpl = @ptrCast(@alignCast(ctx));
    if (send.used) {
        // Cache endpoint before `send.* = .{}` — leaveExclusive runs after clear.
        const endpoint = send.endpoint;
        endpoint.enterExclusive();
        defer endpoint.leaveExclusive();
        if (c.picoquic_reset_stream(send.cnx, send.stream_id, 0) == 0) {
            while (endpoint.pumpOutgoing() catch false) {}
        }
        send.buffer.deinit();
        send.* = .{};
    }
}

const send_vtable: tr.SendStream.VTable = .{ .writer = sendWriter, .flush = sendFlush, .finish = sendFinish, .reset = sendReset };

fn recvReader(ctx: *anyopaque) *std.Io.Reader {
    const recv: *RecvImpl = @ptrCast(@alignCast(ctx));
    if (!recv.used) return &recv.dead_reader;
    if (!recv.ready) {
        recv.endpoint.enterExclusive();
        defer recv.endpoint.leaveExclusive();
        // RecvStream.VTable.reader cannot return an error — on remote receive
        // failure, mark the connection failed and return an empty reader so the
        // process does not abort. Callers see EndOfStream.
        const stream = recv.endpoint.driveUntilStreamFin(recv.cnx, recv.stream_id) catch |err| {
            if (err != error.StreamReset) {
                // StreamReset is stream-local; other failures mean the cnx is dead.
                _ = c.picoquic_close(recv.cnx, 0);
            }
            recv.reader_storage = std.Io.Reader.fixed(&[_]u8{});
            recv.ready = true;
            return &recv.reader_storage;
        };
        recv.reader_storage = std.Io.Reader.fixed(stream.recv.written());
        recv.ready = true;
    }
    return &recv.reader_storage;
}

fn recvStop(ctx: *anyopaque) tr.Error!void {
    const recv: *RecvImpl = @ptrCast(@alignCast(ctx));
    if (!recv.used) return error.NotConnected;
    recv.endpoint.enterExclusive();
    defer recv.endpoint.leaveExclusive();
    recv.endpoint.lockPump();
    defer recv.endpoint.mu.unlock();
    if (c.picoquic_stop_sending(recv.cnx, recv.stream_id, 0) != 0) return error.ConnectionLost;
    recv.reader_storage = std.Io.Reader.fixed(&.{});
    recv.ready = true;
    while (try recv.endpoint.pumpOutgoingLocked()) {}
}

const recv_vtable: tr.RecvStream.VTable = .{ .reader = recvReader, .stop = recvStop };

/// Concrete QUIC helper for bench/test call paths that need structured receive
/// errors and can borrow from the concrete stream buffer. The returned slice is
/// valid until the stream/connection is reclaimed or the endpoint is deinit'd.
pub fn recvStreamReadBorrowed(recv_stream: tr.RecvStream, max_bytes: usize) tr.Error![]const u8 {
    const recv: *RecvImpl = @ptrCast(@alignCast(recv_stream.context));
    if (!recv.used) return error.NotConnected;
    recv.endpoint.enterExclusive();
    defer recv.endpoint.leaveExclusive();
    setRecvExpectedCapacity(recv, max_bytes);
    defer setRecvExpectedCapacity(recv, 0);

    const stream = try recv.endpoint.driveUntilStreamFin(recv.cnx, recv.stream_id);
    const data = stream.recv.written();
    if (data.len > max_bytes) return error.ConnectionLost;
    recv.reader_storage = std.Io.Reader.fixed(data);
    recv.ready = true;
    return data;
}

/// Compatibility wrapper for older bench/test call paths that need ownership.
/// New hot-path benchmark code should prefer `recvStreamReadBorrowed`.
pub fn recvStreamReadAlloc(recv_stream: tr.RecvStream, allocator: std.mem.Allocator, max_bytes: usize) tr.Error![]u8 {
    const data = try recvStreamReadBorrowed(recv_stream, max_bytes);
    const out = allocator.alloc(u8, data.len) catch return error.OutOfMemory;
    @memcpy(out, data);
    return out;
}

/// Incremental read on a handed-off recv stream WITHOUT requiring FIN.
///
/// The vtable `RecvStream.reader()` is FIN-driven (`driveUntilStreamFin` buffers
/// the whole stream before any byte is readable) — right for request/response,
/// wrong for streaming protocols where the peer holds its send side open (e.g.
/// the iroh transfer-example contract, whose fetcher finishes its send stream
/// only AFTER the full download, so a provider reading the request via the
/// FIN-driven reader would deadlock).
///
/// Polls until >=1 byte is available (or FIN/reset), copies out up to `buf.len`,
/// and advances the read offset with the same compaction discipline as
/// `connectionConsumeInboundUniChunk` — so unread bytes stay bounded and the
/// `max_inbound_stream_buffer` cap is not hit by long streams. Returns 0 at
/// clean FIN (all bytes consumed). Bounded by the stream-finish deadline;
/// `error.Timeout` means no byte arrived in that window, not EOF.
///
/// Requires exclusive Endpoint ownership for the call (see module docs).
pub fn recvStreamReadSome(recv_stream: tr.RecvStream, buf: []u8) tr.Error!usize {
    const recv: *RecvImpl = @ptrCast(@alignCast(recv_stream.context));
    if (!recv.used) return error.NotConnected;
    recv.endpoint.enterExclusive();
    defer recv.endpoint.leaveExclusive();
    const deadline = c.picoquic_current_time() + stream_finish_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        _ = try recv.endpoint.pumpOutgoing();
        _ = try recv.endpoint.pumpIncoming();
        const stream = recv.endpoint.streamFor(recv.cnx, recv.stream_id) catch return error.OutOfMemory;
        if (stream.reset) {
            recv.endpoint.resetStreamSlot(stream);
            return error.StreamReset;
        }
        const written = stream.recv.written();
        const available = written.len - stream.read_offset;
        if (available > 0) {
            const n = @min(available, buf.len);
            @memcpy(buf[0..n], written[stream.read_offset..][0..n]);
            stream.read_offset += n;
            if (stream.read_offset == written.len) {
                // Fully consumed (FIN or not): rewind instead of growing.
                stream.recv.writer.end = 0;
                stream.read_offset = 0;
            } else if (stream.read_offset >= 64 * 1024) {
                const unread = written[stream.read_offset..];
                @memmove(stream.recv.writer.buffer[0..unread.len], unread);
                stream.recv.writer.end = unread.len;
                stream.read_offset = 0;
            }
            return n;
        }
        if (stream.fin) return 0;
    }
    return error.Timeout;
}

fn setRecvExpectedCapacity(recv: *RecvImpl, capacity: usize) void {
    recv.endpoint.lockPump();
    defer recv.endpoint.mu.unlock();
    recv.expected_read_capacity = capacity;
    if (recv.endpoint.findStreamState(recv.cnx, recv.stream_id)) |stream| {
        stream.expected_read_capacity = capacity;
    }
}

/// Poll for a finished inbound bi-stream without blocking.
///
/// Requires exclusive Endpoint ownership for the call (see module docs).
pub fn connectionTryAcceptBi(conn: tr.Connection) tr.Error!?tr.BiStream {
    const impl: *ConnectionImpl = @ptrCast(@alignCast(conn.context));
    impl.endpoint.enterExclusive();
    defer impl.endpoint.leaveExclusive();
    try ensureConnectionLive(impl);
    try impl.endpoint.pollOnce();
    for (impl.endpoint.streams.items) |stream| {
        if (stream.used and stream.cnx == impl.cnx and !stream.handed_off and stream.id & 0x2 == 0) {
            if (stream.reset) {
                impl.endpoint.resetStreamSlot(stream);
                return error.StreamReset;
            }
            if (stream.read_offset >= stream.recv.written().len and !stream.fin) continue;
            const send = try impl.endpoint.sendFor(impl.cnx, stream.id);
            errdefer sendReset(send);
            const recv = try impl.endpoint.recvFor(impl.cnx, stream.id);
            stream.handed_off = true;
            return .{ .send = .{ .context = send, .vtable = &send_vtable }, .recv = .{ .context = recv, .vtable = &recv_vtable } };
        }
    }
    return null;
}

fn sockaddrFromIp4(address: net.IpAddress) !c.struct_sockaddr_in {
    const ip4 = switch (address) {
        .ip4 => |ip4| ip4,
        .ip6 => return error.Ipv6NotSupported,
    };
    return .{
        .sin_family = c.AF_INET,
        .sin_port = std.mem.nativeToBig(u16, ip4.port),
        .sin_addr = .{ .s_addr = std.mem.nativeToBig(u32, std.mem.readInt(u32, &ip4.bytes, .big)) },
        .sin_zero = [_]u8{0} ** 8,
    };
}

fn normalizePublicAddress(address: net.IpAddress, bound_port: u16) net.IpAddress {
    return switch (address) {
        .ip4 => |ip4| .{ .ip4 = .{
            .bytes = ip4.bytes,
            .port = if (ip4.port == 0) bound_port else ip4.port,
        } },
        .ip6 => |ip6| .{ .ip6 = .{
            .bytes = ip6.bytes,
            .flow = ip6.flow,
            .interface = ip6.interface,
            .port = if (ip6.port == 0) bound_port else ip6.port,
        } },
    };
}

test "L1b: UDP receive helper drains queued datagrams in order" {
    const allocator = std.testing.allocator;
    const secret = key.SecretKey.fromBytes([_]u8{64} ** 32);
    const endpoint = try Endpoint.init(allocator, std.testing.io, secret, "iroh-l1b-recvmmsg-helper");
    defer endpoint.deinit();

    var sender_bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sender = try sender_bind.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(std.testing.io);

    var dest = endpoint.boundAddress();
    try sender.send(std.testing.io, &dest, "one");

    var batch: UdpReceiveBatch = .{};
    try std.testing.expectEqual(@as(usize, 1), try endpoint.receiveUdpFirst(&batch));
    try std.testing.expectEqual(sender.address, batch.items[0].from);
    try std.testing.expectEqualStrings("one", batch.items[0].data);

    try sender.send(std.testing.io, &dest, "two");
    try sender.send(std.testing.io, &dest, "three");

    const expected = [_][]const u8{ "two", "three" };
    var drained_total: usize = 0;
    while (drained_total < expected.len) {
        const drained = try endpoint.drainUdpBatch(&batch);
        if (drained == 0) break;
        for (batch.items[0..drained], 0..) |item, i| {
            try std.testing.expectEqual(sender.address, item.from);
            try std.testing.expectEqualStrings(expected[drained_total + i], item.data);
        }
        drained_total += drained;
    }
    try std.testing.expectEqual(expected.len, drained_total);
}

test "PC2: receive wait timeout follows picoquic wake delay" {
    try std.testing.expectEqual(std.Io.Duration.fromNanoseconds(0), receiveUdpWaitTimeoutFromWakeDelay(0).duration.raw);
    try std.testing.expectEqual(std.Io.Duration.fromNanoseconds(0), receiveUdpWaitTimeoutFromWakeDelay(-1).duration.raw);
    try std.testing.expectEqual(std.Io.Duration.fromNanoseconds(std.time.ns_per_us), receiveUdpWaitTimeoutFromWakeDelay(1).duration.raw);
    try std.testing.expectEqual(std.Io.Duration.fromMilliseconds(1), receiveUdpWaitTimeoutFromWakeDelay(10 * std.time.us_per_ms).duration.raw);
}

fn ip4FromSockaddr(storage: c.struct_sockaddr_storage) !net.IpAddress {
    const sin: *const c.struct_sockaddr_in = @ptrCast(@alignCast(&storage));
    if (sin.sin_family != c.AF_INET) return error.Ipv6NotSupported;
    const addr_be = std.mem.bigToNative(u32, sin.sin_addr.s_addr);
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, addr_be, .big);
    return .{ .ip4 = .{ .bytes = bytes, .port = std.mem.bigToNative(u16, sin.sin_port) } };
}

fn optionalIp4FromSockaddr(storage: c.struct_sockaddr_storage) !?net.IpAddress {
    const family: c.sa_family_t = storage.ss_family;
    if (family == c.AF_UNSPEC) return null;
    if (family != c.AF_INET) return error.Ipv6NotSupported;
    return try ip4FromSockaddr(storage);
}

fn acceptConn(t: tr.Transport) tr.Error!tr.Connection {
    return t.accept();
}

fn endpointCnxCount(endpoint: *Endpoint) usize {
    var count: usize = 0;
    var maybe_cnx: ?*c.picoquic_cnx_t = c.picoquic_get_first_cnx(endpoint.quic);
    while (maybe_cnx) |cnx| : (maybe_cnx = c.picoquic_get_next_cnx(cnx)) {
        count += 1;
    }
    return count;
}

fn connectToServer(client_ep: *Endpoint, server_id: key.NodeId, server_ep: *Endpoint) tr.Error!tr.Connection {
    const cnx = try beginClientConnect(client_ep, server_id, server_ep);
    try client_ep.driveUntilReady(cnx);
    return client_ep.connectionForCnx(cnx, false);
}

fn beginClientConnect(endpoint: *Endpoint, server_id: key.NodeId, server_ep: *Endpoint) tr.Error!*c.picoquic_cnx_t {
    return endpoint.beginClientCnx(server_id, server_ep.localAddress(), false, false);
}

fn drivePairUntilAcceptBi(sender: *Endpoint, receiver: *Endpoint, conn: tr.Connection) tr.Error!tr.BiStream {
    const deadline = c.picoquic_current_time() + stream_open_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        try sender.pollOnce();
        try receiver.pollOnce();
        if (try connectionTryAcceptBi(conn)) |stream| return stream;
    }
    return error.Timeout;
}

fn drivePairUntilAcceptUni(sender: *Endpoint, receiver: *Endpoint, conn: tr.Connection) tr.Error!tr.RecvStream {
    const deadline = c.picoquic_current_time() + stream_open_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        try sender.pollOnce();
        try receiver.pollOnce();
        if (try connectionTryAcceptUni(conn)) |stream| return stream;
    }
    return error.Timeout;
}

fn connectionConsumeStreamReset(conn: tr.Connection, stream_id: u64) tr.Error!bool {
    const impl: *ConnectionImpl = @ptrCast(@alignCast(conn.context));
    try ensureConnectionLive(impl);
    try impl.endpoint.pollOnce();
    for (impl.endpoint.streams.items) |stream| {
        if (stream.used and stream.cnx == impl.cnx and stream.id == stream_id and stream.reset) {
            impl.endpoint.resetStreamSlot(stream);
            return true;
        }
    }
    return false;
}

fn drivePairUntilStreamReset(sender: *Endpoint, receiver: *Endpoint, conn: tr.Connection, stream_id: u64) tr.Error!void {
    const deadline = c.picoquic_current_time() + stream_open_timeout_us;
    while (c.picoquic_current_time() < deadline) {
        try sender.pollOnce();
        try receiver.pollOnce();
        if (try connectionConsumeStreamReset(conn, stream_id)) return;
    }
    return error.Timeout;
}

/// Bounded relay receive adapter with owned queue entries.
///
/// The value may be returned and moved before `startReceiver`, but from that call
/// until `stopReceiver` returns it must remain at one stable address: both the
/// receiver thread and `datagrams()` vtable retain its pointer. All users of a
/// previously returned `RelayDatagramClient` must be quiesced before
/// `stopReceiver`; that call joins the receiver and releases the queue storage.
/// The client and allocator must also remain valid through `stopReceiver`.
pub const QueuedRelayClient = struct {
    // Match iroh's relay receive channel depth. Queue entries are heap-backed so
    // this does not put a 1 MiB+ fixed array in every adapter value.
    const max_queue = 512;
    const max_datagram = 2048;

    const Queued = struct {
        src: key.NodeId,
        segment_size: ?u16,
        offset: usize = 0,
        bytes: []u8,
    };

    client: *relay_client.Client,
    allocator: std.mem.Allocator,
    mu: std.atomic.Mutex = .unlocked,
    queue: ?[]Queued = null,
    head: usize = 0,
    len: usize = 0,
    thread: ?std.Thread = null,
    receiver_ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    sent_via_client: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    received_via_client: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    /// Historical compatibility aggregate: logical datagrams rejected for any
    /// reason, not only queue-capacity overflow. Consult the reason counters below
    /// to distinguish capacity, validation, and allocation failures. A dropped
    /// batch contributes its number of logical datagrams to every applicable count.
    dropped_by_overflow: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    dropped_by_queue_full: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    dropped_by_oversize_or_invalid: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    dropped_by_allocation_failure: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    queue_high_water_depth: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    pub fn init(client: *relay_client.Client) QueuedRelayClient {
        return initWithAllocator(std.heap.page_allocator, client);
    }

    pub fn initWithAllocator(allocator: std.mem.Allocator, client: *relay_client.Client) QueuedRelayClient {
        return .{ .client = client, .allocator = allocator };
    }

    fn initForTest(allocator: std.mem.Allocator) !QueuedRelayClient {
        var self: QueuedRelayClient = .{ .client = undefined, .allocator = allocator };
        try self.allocateQueue();
        return self;
    }

    fn allocateQueue(self: *QueuedRelayClient) !void {
        std.debug.assert(self.queue == null);
        self.queue = try self.allocator.alloc(Queued, max_queue);
    }

    fn deinitQueue(self: *QueuedRelayClient) void {
        std.debug.assert(self.thread == null);
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();

        const queue = self.queue orelse return;
        for (0..self.len) |i| {
            const index = (self.head + i) % queue.len;
            self.allocator.free(queue[index].bytes);
        }
        self.allocator.free(queue);
        self.queue = null;
        self.head = 0;
        self.len = 0;
    }

    pub fn datagrams(self: *QueuedRelayClient) RelayDatagramClient {
        return .{ .context = self, .vtable = &queued_relay_vtable };
    }

    /// Starts the sole queue producer and pins this value at its current address.
    pub fn startReceiver(self: *QueuedRelayClient) !void {
        std.debug.assert(self.thread == null);
        try self.allocateQueue();
        errdefer self.deinitQueue();
        self.receiver_ready.store(false, .release);
        const thread = try std.Thread.spawn(.{}, receiverThread, .{self});
        self.thread = thread;
        while (!self.receiver_ready.load(.acquire)) std.Thread.yield() catch {};
    }

    /// Stops and joins the producer, then releases all pending queue entries.
    /// Callers must first quiesce every consumer of the `datagrams()` handle.
    pub fn stopReceiver(self: *QueuedRelayClient) void {
        self.client.stream.shutdown(self.client.io, .both) catch {};
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        self.deinitQueue();
    }

    fn receiverThread(self: *QueuedRelayClient) void {
        self.receiver_ready.store(true, .release);
        while (true) {
            const msg = self.client.recv() catch return;
            switch (msg) {
                .datagram => |d| self.enqueue(d.src, d.datagrams.contents),
                .datagram_batch => |d| self.enqueueBatch(d.src, d.datagrams),
                .endpoint_gone => return,
                else => {},
            }
        }
    }

    fn send(self: *QueuedRelayClient, dst: key.NodeId, data: []const u8) tr.Error!void {
        self.client.send(.{ .datagram = .{
            .dst = dst,
            .datagrams = .{ .ecn = .not_ect, .segment_size = null, .contents = data },
        } }) catch return error.ConnectionLost;
        _ = self.sent_via_client.fetchAdd(1, .monotonic);
    }

    fn recv(self: *QueuedRelayClient, buffer: []u8) tr.Error!?RelayDatagram {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        if (self.len == 0) return null;
        const queue = self.queue orelse return error.ConnectionLost;
        const item = &queue[self.head];
        const remaining = item.bytes[item.offset..];
        const take = if (item.segment_size) |segment_size|
            @min(@as(usize, segment_size), remaining.len)
        else
            remaining.len;
        if (take > buffer.len) return error.ConnectionLost;

        const src = item.src;
        @memcpy(buffer[0..take], remaining[0..take]);
        item.offset += take;
        if (item.offset == item.bytes.len) {
            self.allocator.free(item.bytes);
            self.head = (self.head + 1) % queue.len;
            self.len -= 1;
        }
        return .{ .src = src, .data = buffer[0..take] };
    }

    fn enqueue(self: *QueuedRelayClient, src: key.NodeId, data: []const u8) void {
        self.enqueueDatagrams(src, null, data);
    }

    fn enqueueDatagrams(self: *QueuedRelayClient, src: key.NodeId, segment_size: ?u16, data: []const u8) void {
        const datagram_count = datagramCount(data.len, segment_size);
        if (segment_size) |segment| {
            if (segment == 0 or data.len == 0 or segment > max_datagram) {
                self.recordDrop(datagram_count, .oversize_or_invalid);
                return;
            }
        } else if (data.len > max_datagram) {
            self.recordDrop(datagram_count, .oversize_or_invalid);
            return;
        }

        // The relay client receive buffer is borrowed until its next recv, so an
        // accepted item must be copied. Check capacity first: a full bounded queue
        // drops the newest whole entry without allocating, matching Rust's
        // `try_send` behavior and keeping the reason counter deterministic under
        // allocator pressure.
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        const queue_before_alloc = self.queue orelse {
            self.mu.unlock();
            self.recordDrop(datagram_count, .allocation_failure);
            return;
        };
        if (self.len >= queue_before_alloc.len) {
            self.mu.unlock();
            self.recordDrop(datagram_count, .queue_full);
            return;
        }
        self.mu.unlock();

        const owned = self.allocator.dupe(u8, data) catch {
            self.recordDrop(datagram_count, .allocation_failure);
            return;
        };

        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        const queue = self.queue orelse {
            self.allocator.free(owned);
            self.recordDrop(datagram_count, .allocation_failure);
            return;
        };
        if (self.len >= queue.len) {
            self.allocator.free(owned);
            self.recordDrop(datagram_count, .queue_full);
            return;
        }

        const index = (self.head + self.len) % queue.len;
        queue[index] = .{
            .src = src,
            .segment_size = segment_size,
            .bytes = owned,
        };
        self.len += 1;
        _ = self.received_via_client.fetchAdd(datagram_count, .monotonic);
        if (self.len > self.queue_high_water_depth.load(.monotonic)) {
            self.queue_high_water_depth.store(self.len, .monotonic);
        }
    }

    /// Queue a whole batch as one logical item, splitting only as `recv` drains it.
    fn enqueueBatch(self: *QueuedRelayClient, src: key.NodeId, d: relay_proto.Datagrams) void {
        const seg = d.segment_size orelse {
            self.enqueue(src, d.contents);
            return;
        };
        self.enqueueDatagrams(src, seg, d.contents);
    }

    const DropReason = enum {
        queue_full,
        oversize_or_invalid,
        allocation_failure,
    };

    fn recordDrop(self: *QueuedRelayClient, count: usize, reason: DropReason) void {
        _ = self.dropped_by_overflow.fetchAdd(count, .monotonic);
        switch (reason) {
            .queue_full => _ = self.dropped_by_queue_full.fetchAdd(count, .monotonic),
            .oversize_or_invalid => _ = self.dropped_by_oversize_or_invalid.fetchAdd(count, .monotonic),
            .allocation_failure => _ = self.dropped_by_allocation_failure.fetchAdd(count, .monotonic),
        }
    }

    fn datagramCount(data_len: usize, segment_size: ?u16) usize {
        const segment = segment_size orelse return 1;
        if (segment == 0 or data_len == 0) return 1;
        return (data_len - 1) / @as(usize, segment) + 1;
    }
};

fn queuedRelaySend(ctx: *anyopaque, dst: key.NodeId, data: []const u8) tr.Error!void {
    const queued: *QueuedRelayClient = @ptrCast(@alignCast(ctx));
    return queued.send(dst, data);
}

fn queuedRelayRecv(ctx: *anyopaque, buffer: []u8) tr.Error!?RelayDatagram {
    const queued: *QueuedRelayClient = @ptrCast(@alignCast(ctx));
    return queued.recv(buffer);
}

const queued_relay_vtable: RelayDatagramClient.VTable = .{ .send = queuedRelaySend, .recv = queuedRelayRecv };

test "F1: queued relay overflow drops newest before allocation and preserves backlog" {
    const src = key.SecretKey.fromBytes([_]u8{21} ** 32).public();
    var failing_state = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var queue = try QueuedRelayClient.initForTest(failing_state.allocator());
    defer queue.deinitQueue();
    const payload = "relay-datagram";

    for (0..QueuedRelayClient.max_queue) |_| {
        queue.enqueue(src, payload);
    }
    failing_state.fail_index = failing_state.alloc_index;
    queue.enqueueBatch(src, .{
        .ecn = .not_ect,
        .segment_size = 4,
        .contents = "dropped-newest",
    });

    try std.testing.expectEqual(@as(usize, QueuedRelayClient.max_queue), queue.len);
    try std.testing.expectEqual(@as(usize, QueuedRelayClient.max_queue), queue.received_via_client.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 4), queue.dropped_by_overflow.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 4), queue.dropped_by_queue_full.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), queue.dropped_by_oversize_or_invalid.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), queue.dropped_by_allocation_failure.load(.monotonic));
    try std.testing.expectEqual(@as(usize, QueuedRelayClient.max_queue), queue.queue_high_water_depth.load(.monotonic));
    try std.testing.expect(!failing_state.has_induced_failure);

    var recv_buf: [QueuedRelayClient.max_datagram]u8 = undefined;
    var drained: usize = 0;
    while (try queue.recv(&recv_buf)) |msg| {
        try std.testing.expect(msg.src.eql(src));
        try std.testing.expectEqualStrings(payload, msg.data);
        drained += 1;
    }
    try std.testing.expectEqual(@as(usize, QueuedRelayClient.max_queue), drained);
    try std.testing.expectEqual(@as(usize, 0), queue.len);

    failing_state.fail_index = std.math.maxInt(usize);
    queue.enqueue(src, "still-usable");
    const after_overflow = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("still-usable", after_overflow.data);
    try std.testing.expectEqual(@as(usize, 0), queue.len);

    queue.deinitQueue();
    try std.testing.expectEqual(failing_state.allocated_bytes, failing_state.freed_bytes);
}

test "F1: queued relay batch occupies one slot and drains segments in order" {
    const src = key.SecretKey.fromBytes([_]u8{22} ** 32).public();
    var queue = try QueuedRelayClient.initForTest(std.testing.allocator);
    defer queue.deinitQueue();

    queue.enqueueBatch(src, .{
        .ecn = .not_ect,
        .segment_size = 4,
        .contents = "aaaabbbbcc",
    });
    queue.enqueue(src, "after-batch");
    try std.testing.expectEqual(@as(usize, 2), queue.len);
    try std.testing.expectEqual(@as(usize, 4), queue.received_via_client.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 2), queue.queue_high_water_depth.load(.monotonic));

    var recv_buf: [QueuedRelayClient.max_datagram]u8 = undefined;
    const first = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("aaaa", first.data);
    try std.testing.expectEqual(@as(usize, 2), queue.len);
    const second = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("bbbb", second.data);
    try std.testing.expectEqual(@as(usize, 2), queue.len);
    const third = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("cc", third.data);
    try std.testing.expectEqual(@as(usize, 1), queue.len);
    const after_batch = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("after-batch", after_batch.data);
    try std.testing.expectEqual(@as(usize, 0), queue.len);
    try std.testing.expect((try queue.recv(&recv_buf)) == null);
}

test "F1: queued relay reports capacity and invalid drops separately" {
    const src = key.SecretKey.fromBytes([_]u8{23} ** 32).public();
    var queue = try QueuedRelayClient.initForTest(std.testing.allocator);
    defer queue.deinitQueue();

    var oversize: [QueuedRelayClient.max_datagram + 1]u8 = undefined;
    @memset(&oversize, 0x5a);
    queue.enqueue(src, &oversize);
    queue.enqueueBatch(src, .{
        .ecn = .not_ect,
        .segment_size = 0,
        .contents = "invalid-batch",
    });

    try std.testing.expectEqual(@as(usize, 2), queue.dropped_by_overflow.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), queue.dropped_by_queue_full.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 2), queue.dropped_by_oversize_or_invalid.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), queue.dropped_by_allocation_failure.load(.monotonic));

    // Leave owned items queued for deinitQueue so the testing allocator proves cleanup.
    queue.enqueue(src, "cleanup-single");
    queue.enqueueBatch(src, .{
        .ecn = .not_ect,
        .segment_size = 4,
        .contents = "cleanup-batch",
    });
    try std.testing.expectEqual(@as(usize, 2), queue.len);
}

test "F1: queued relay allocation failure drops transactionally and remains usable" {
    const src = key.SecretKey.fromBytes([_]u8{24} ** 32).public();
    var failing_state = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    const failing_allocator = failing_state.allocator();
    var queue = try QueuedRelayClient.initForTest(failing_allocator);
    defer queue.deinitQueue();

    queue.enqueue(src, "allocation-fails");
    try std.testing.expectEqual(@as(usize, 0), queue.len);
    try std.testing.expectEqual(@as(usize, 1), queue.dropped_by_overflow.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 1), queue.dropped_by_allocation_failure.load(.monotonic));

    failing_state.fail_index = std.math.maxInt(usize);
    queue.enqueue(src, "usable-after-oom");
    var recv_buf: [QueuedRelayClient.max_datagram]u8 = undefined;
    const received = (try queue.recv(&recv_buf)).?;
    try std.testing.expectEqualStrings("usable-after-oom", received.data);
    try std.testing.expectEqual(@as(usize, 0), queue.len);

    queue.deinitQueue();
    try std.testing.expectEqual(failing_state.allocated_bytes, failing_state.freed_bytes);
}

test "S2: Transport connect/accept and bi stream use real picoquic over UDP" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{3} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{4} ** 32);
    const alpn: [:0]const u8 = "iroh-s2-test";
    var s2_phase: []const u8 = "endpoint-init";
    errdefer std.debug.print("FAIL: S2 phase {s}\n", .{s2_phase});

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    const client_t = client_ep.transport();
    const server_t = server_ep.transport();
    s2_phase = "handshake";
    var accept_future = std.testing.io.async(acceptConn, .{server_t});

    const client_conn = try client_t.connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    try std.testing.expect(client_conn.remoteNodeId().eql(server_key.public()));
    try std.testing.expect(server_conn.remoteNodeId().eql(client_key.public()));

    const client_impl: *ConnectionImpl = @ptrCast(@alignCast(client_conn.context));
    const server_impl: *ConnectionImpl = @ptrCast(@alignCast(server_conn.context));
    var frame_buf: [32]u8 = undefined;
    s2_phase = "custom-frame-add-address";
    const nat_frame = try (magicsock_frames.Ipv4AddressFrame{
        .frame_type = .add_ipv4_address,
        .seq = 1,
        .ip = .{ 127, 0, 0, 1 },
        .port = 12345,
    }).encode(&frame_buf);
    try std.testing.expectEqual(@as(c_int, 0), c.picoquic_queue_misc_frame(client_impl.cnx, nat_frame.ptr, nat_frame.len, 0, c.picoquic_packet_context_application));
    _ = try client_ep.pumpOutgoing();
    _ = try server_ep.pumpIncoming();
    try std.testing.expect(c.picoquic_get_cnx_state(server_impl.cnx) == c.picoquic_state_ready);
    const delivered = server_ep.takeCustomFrame() orelse return error.CustomFrameNotDelivered;
    try std.testing.expectEqualSlices(u8, nat_frame, delivered.bytes[0..delivered.len]);
    const server_path = server_ep.pathStateFor(server_impl.cnx) orelse return error.PathStateMissing;
    try std.testing.expectEqual(@as(usize, 1), server_path.magicsock_state.remote_candidates.items.len);
    const candidate = server_path.magicsock_state.remote_candidates.items[0];
    try std.testing.expectEqual(@as(u64, 1), candidate.seq);
    try std.testing.expectEqual(magicsock.PathKind.direct_ipv4, candidate.kind);
    try std.testing.expectEqual(net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 12345 } }, candidate.address);

    s2_phase = "qad-observed-address";
    const observed_frame = try (magicsock_frames.Ipv4AddressFrame{
        .frame_type = .observed_ipv4_addr,
        .seq = 2,
        .ip = .{ 203, 0, 113, 77 },
        .port = 42424,
    }).encode(&frame_buf);
    try std.testing.expectEqual(@as(c_int, 0), c.picoquic_queue_misc_frame(client_impl.cnx, observed_frame.ptr, observed_frame.len, 0, c.picoquic_packet_context_application));
    _ = try client_ep.pumpOutgoing();
    _ = try server_ep.pumpIncoming();
    const expected_observed: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 77 }, .port = 42424 } };
    var found_observed = false;
    for (server_path.magicsock_state.observed_addresses.items) |observed| {
        if (std.meta.eql(observed, expected_observed)) found_observed = true;
    }
    try std.testing.expect(found_observed);

    const client_stream = try client_conn.openBi();
    try client_stream.send.writer().writeAll("ping");
    s2_phase = "bi-client-finish";
    try client_stream.send.finish();

    s2_phase = "bi-accept";
    const server_stream = try drivePairUntilAcceptBi(client_ep, server_ep, server_conn);
    s2_phase = "bi-server-read";
    var buf: [16]u8 = undefined;
    const n = try server_stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("ping", buf[0..n]);

    s2_phase = "bi-client-read";
    try server_stream.send.writer().writeAll("pong");
    try server_stream.send.finish();
    var reply: [16]u8 = undefined;
    const m = try client_stream.recv.reader().readSliceShort(&reply);
    try std.testing.expectEqualStrings("pong", reply[0..m]);

    const uni = try client_conn.openUni();
    try uni.writer().writeAll("uni!");
    s2_phase = "uni-after-bi-client-finish";
    try uni.finish();
    s2_phase = "uni-after-bi-accept";
    const recv_uni = try drivePairUntilAcceptUni(client_ep, server_ep, server_conn);
    s2_phase = "uni-after-bi-read";
    var uni_buf: [8]u8 = undefined;
    const uni_n = try recv_uni.reader().readSliceShort(&uni_buf);
    try std.testing.expectEqualStrings("uni!", uni_buf[0..uni_n]);
    s2_phase = "complete";
}

test "PC5: queued byte helper reports remaining bytes after partial packetization" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x25} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x26} ** 32);
    const alpn: [:0]const u8 = "iroh-pc5-queued-remaining";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    const client_impl: *ConnectionImpl = @ptrCast(@alignCast(client_conn.context));
    const stream_id = c.picoquic_get_next_local_stream_id(client_impl.cnx, 1);
    const payload = try allocator.alloc(u8, 256 * 1024);
    defer allocator.free(payload);
    @memset(payload, 0xa5);

    try std.testing.expectEqual(@as(c_int, 0), c.picoquic_add_to_stream(client_impl.cnx, stream_id, payload.ptr, payload.len, 0));
    const queued_before = c.iroh_picoquic_stream_send_queued(client_impl.cnx, stream_id);
    try std.testing.expectEqual(payload.len, queued_before);

    try std.testing.expect(try client_ep.pumpOutgoing());
    const queued_after = c.iroh_picoquic_stream_send_queued(client_impl.cnx, stream_id);
    try std.testing.expect(queued_after < queued_before);
}

test "S3.5: direct magicsock selection preserves picoquic UDP destination" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{7} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{8} ** 32);
    const alpn: [:0]const u8 = "iroh-s3-5-routing-test";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var alt_bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const server_alt_socket = try alt_bind.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer server_alt_socket.close(std.testing.io);

    const client_t = client_ep.transport();
    const server_t = server_ep.transport();
    var accept_future = std.testing.io.async(acceptConn, .{server_t});

    const client_conn = try client_t.connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();
    const client_impl: *ConnectionImpl = @ptrCast(@alignCast(client_conn.context));

    const primary = server_ep.localAddress();
    const alternate = server_alt_socket.address;
    const client_path = client_ep.pathStateFor(client_impl.cnx) orelse return error.PathStateMissing;
    try client_path.magicsock_state.handleFrame(.{ .ipv4_address = .{
        .frame_type = .add_ipv4_address,
        .seq = 1,
        .ip = primary.ip4.bytes,
        .port = primary.ip4.port,
    } });
    try client_path.magicsock_state.handleFrame(.{ .ipv4_address = .{
        .frame_type = .add_ipv4_address,
        .seq = 2,
        .ip = alternate.ip4.bytes,
        .port = alternate.ip4.port,
    } });
    try std.testing.expectEqual(@as(usize, 2), client_path.magicsock_state.remote_candidates.items.len);

    client_path.magicsock_state.markPathSucceeded(primary, 50 * std.time.us_per_ms);
    try std.testing.expectEqual(primary, client_path.magicsock_state.selectedPath().?.address);
    const stream_primary = c.picoquic_get_next_local_stream_id(client_impl.cnx, 1);
    try std.testing.expectEqual(@as(c_int, 0), c.picoquic_add_to_stream(client_impl.cnx, stream_primary, "primary".ptr, "primary".len, 1));
    try std.testing.expect(try client_ep.pumpOutgoing());
    try std.testing.expect(try server_ep.pumpIncoming());

    client_path.magicsock_state.markPathSucceeded(alternate, 1 * std.time.us_per_ms);
    try std.testing.expectEqual(alternate, client_path.magicsock_state.selectedPath().?.address);
    const stream_alternate = c.picoquic_get_next_local_stream_id(client_impl.cnx, 1);
    try std.testing.expectEqual(@as(c_int, 0), c.picoquic_add_to_stream(client_impl.cnx, stream_alternate, "alternate".ptr, "alternate".len, 1));
    try std.testing.expect(try client_ep.pumpOutgoing());
    try std.testing.expect(try server_ep.pumpIncoming());

    var alt_buf: [2048]u8 = undefined;
    _ = server_alt_socket.receiveTimeout(std.testing.io, &alt_buf, .{ .duration = .{
        .raw = .fromMilliseconds(25),
        .clock = .awake,
    } }) catch |err| switch (err) {
        error.Timeout => return,
        else => return error.ConnectionLost,
    };
    return error.DirectPathOverrodePicoquicDestination;
}

test "S4: relay fallback transfers a bi stream when direct paths are unavailable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var done = std.atomic.Value(bool).init(false);
    var phase = std.atomic.Value(u8).init(0);
    const watchdog = try std.Thread.spawn(.{}, struct {
        fn run(done_flag: *std.atomic.Value(bool), phase_flag: *std.atomic.Value(u8)) void {
            var wd = std.Io.Threaded.init(std.heap.page_allocator, .{});
            defer wd.deinit();
            for (0..200) |_| {
                wd.io().sleep(std.Io.Duration.fromMilliseconds(100), .real) catch {};
                if (done_flag.load(.acquire)) return;
            }
            std.debug.print("FAIL: S4 relay fallback watchdog exceeded at phase {d}\n", .{phase_flag.load(.acquire)});
            std.process.exit(1);
        }
    }.run, .{ &done, &phase });
    defer {
        done.store(true, .release);
        watchdog.join();
    }
    const client_key = key.SecretKey.fromBytes([_]u8{9} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{10} ** 32);
    const alpn: [:0]const u8 = "iroh-s4-relay-test";

    var server = try relay_server.Server.init(std.heap.page_allocator, io, .{ .bind_host = "127.0.0.1", .bind_port = 0 });
    var accept_thread: ?std.Thread = null;
    defer {
        server.deinit();
        if (accept_thread) |thread| thread.join();
    }
    accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *relay_server.Server) void {
            while (srv.running.load(.acquire)) {
                srv.acceptAndSpawn() catch {};
            }
        }
    }.run, .{&server});
    io.sleep(std.Io.Duration.fromMilliseconds(50), .real) catch {};

    var relay_url_buf: [64]u8 = undefined;
    const relay_url = try std.fmt.bufPrint(&relay_url_buf, "ws://127.0.0.1:{d}/relay", .{server.localAddress().getPort()});

    phase.store(1, .release);
    var client_relay_client: relay_client.Client = undefined;
    try client_relay_client.connectInPlace(io, .{ .url = tr.RelayUrl.borrowed(relay_url), .secret_key = client_key });
    defer client_relay_client.close();
    phase.store(2, .release);
    var server_relay_client: relay_client.Client = undefined;
    try server_relay_client.connectInPlace(io, .{ .url = tr.RelayUrl.borrowed(relay_url), .secret_key = server_key });
    defer server_relay_client.close();
    phase.store(3, .release);

    var client_relay = QueuedRelayClient.initWithAllocator(allocator, &client_relay_client);
    var server_relay = QueuedRelayClient.initWithAllocator(allocator, &server_relay_client);
    try client_relay.startReceiver();
    errdefer client_relay.stopReceiver();
    try server_relay.startReceiver();
    errdefer server_relay.stopReceiver();

    const client_ep = try Endpoint.init(allocator, io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, io, server_key, alpn);
    defer server_ep.deinit();
    client_ep.setRelayDatagrams(client_relay.datagrams());
    server_ep.setRelayDatagrams(server_relay.datagrams());

    const client_t = client_ep.transport();
    const server_t = server_ep.transport();
    var accept_future = io.async(acceptConn, .{server_t});

    phase.store(4, .release);
    const client_conn = try client_t.connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .relay = tr.RelayUrl.borrowed(relay_url) }},
    });
    defer client_conn.close();
    phase.store(5, .release);
    const server_conn = try accept_future.await(io);
    defer server_conn.close();
    phase.store(6, .release);

    const client_impl_s4: *ConnectionImpl = @ptrCast(@alignCast(client_conn.context));
    const server_impl_s4: *ConnectionImpl = @ptrCast(@alignCast(server_conn.context));
    const client_path_s4 = client_ep.pathStateFor(client_impl_s4.cnx) orelse return error.PathStateMissing;
    const server_path_s4 = server_ep.pathStateFor(server_impl_s4.cnx) orelse return error.PathStateMissing;
    try std.testing.expectEqual(magicsock.PathKind.relay, client_path_s4.magicsock_state.selectedPath().?.kind);
    try std.testing.expectEqual(magicsock.PathKind.relay, server_path_s4.magicsock_state.selectedPath().?.kind);

    var accept_stream_future = io.async(struct {
        fn run(conn: tr.Connection) tr.Error!tr.BiStream {
            return conn.acceptBi();
        }
    }.run, .{server_conn});

    const client_stream = try client_conn.openBi();
    try client_stream.send.writer().writeAll("relay-ping");
    phase.store(7, .release);
    try client_stream.send.finish();

    const server_stream = try accept_stream_future.await(io);
    var buf: [32]u8 = undefined;
    const n = try server_stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("relay-ping", buf[0..n]);

    try server_stream.send.writer().writeAll("relay-pong");
    phase.store(8, .release);
    try server_stream.send.finish();
    var reply: [32]u8 = undefined;
    const m = try client_stream.recv.reader().readSliceShort(&reply);
    try std.testing.expectEqualStrings("relay-pong", reply[0..m]);

    try std.testing.expect(client_ep.relay_send_count > 0);
    try std.testing.expect(client_ep.relay_recv_count > 0);
    try std.testing.expect(server_ep.relay_send_count > 0);
    try std.testing.expect(server_ep.relay_recv_count > 0);
    try std.testing.expect(client_relay.sent_via_client.load(.monotonic) > 0);
    try std.testing.expect(client_relay.received_via_client.load(.monotonic) > 0);
    try std.testing.expect(server_relay.sent_via_client.load(.monotonic) > 0);
    try std.testing.expect(server_relay.received_via_client.load(.monotonic) > 0);
    client_relay.stopReceiver();
    server_relay.stopReceiver();
}
