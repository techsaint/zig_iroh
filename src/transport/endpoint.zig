//! Greenfield single-owner picoquic transport endpoint (actor model).
//!
//! ONE task owns the picoquic context, the UDP socket, and every stream /
//! connection table: the endpoint's event loop (`run`, spawned at init). All
//! vtable operations — connect/accept/open/accept-stream/flush/finish/reset/
//! stop/close — are COMMANDS submitted to the loop's inbox; the caller blocks
//! on a per-call completion (`std.Io.Event`). Only the loop ever calls
//! picoquic or mutates endpoint state, so there is no concurrent access and no
//! hot-path lock: exclusivity is by SCHEDULING, not by caller convention (the
//! G0/G1 `pollOnce`/`driveUntilReady` model this replaces). The picoquic
//! callback fires synchronously inside the loop's `picoquic_incoming_packet`
//! call — the same exclusive owner.
//!
//! The single cross-task structure is the command inbox: an intrusive
//! singly-linked queue (each caller stacks its own node) guarded by one
//! `std.Io.Mutex` — a genuine cross-task hand-off, per the design
//! (design.md §2.2). Submit never allocates and never blocks on capacity, so
//! the loop cannot be deadlocked through the inbox.
//!
//! Requirements and contracts:
//! - The captured `std.Io` must run the spawned loop task CONCURRENTLY with
//!   callers (any `Io.Threaded`-family implementation; `std.testing.io` in
//!   tests). This is the same assumption iroh makes of its tokio runtime.
//! - Callers may drive one endpoint from many threads — commands serialize
//!   through the inbox. Individual stream/connection HANDLES are not
//!   thread-safe (one driver per handle), matching the legacy backend.
//! - Command payload slices (e.g. `NodeAddr.addrs`) borrow caller state until
//!   the command's completion fires.
//! - The recv reader is incremental: each fill copies the next chunk of
//!   endpoint-owned stream bytes into the caller's own destination, so reads
//!   never alias loop-owned memory. Data is invalidated only by closing the
//!   owning connection or deinit'ing the endpoint.
//! - Do not call vtable ops after `deinit` starts; JOIN all in-flight handle
//!   users (readers/writers/commands) before deinit — deinit does not wait
//!   for them. Do not block inside the picoquic callback (it runs on the loop).
//!
//! Engine: picoquic for wire behavior (unchanged); this file owns the Zig-side
//! pump, tables, concurrency model, and DERP relay fallback datagram routing.

const std = @import("std");
const tr = @import("../transport.zig");
const key = @import("../key.zig");
const c = @import("../connection/c.zig").c;
const context = @import("../connection/context.zig");
const tls_name = @import("../connection/tls_name.zig");
const stream_mod = @import("stream.zig");
const pump = @import("pump.zig");
const relay_fallback = @import("relay_fallback.zig");
const uni_poll = @import("uni_poll.zig");
const magicsock = @import("../magicsock/mod.zig");
const path_observability = @import("../path_observability.zig");

const net = std.Io.net;

const handshake_timeout_default_us: u64 = 15 * std.time.us_per_s;
const stream_open_timeout_us: u64 = 15 * std.time.us_per_s;
const stream_fin_timeout_default_us: u64 = 30 * std.time.us_per_s;
/// Per-stream receive window: the sliding flow-control credit. The initial
/// transport credit is this size (connection/context.zig); the endpoint opens
/// `consumed_total + window` as the reader consumes (backpressure).
/// MAX_STREAM_DATA is monotonic, so the window must be >= the initial credit.
const stream_receive_window: u64 = 16 * 1024 * 1024;
/// Consecutive pump failures before the endpoint is declared broken: the loop
/// stops driving I/O, all waiters fail with ConnectionLost, and future
/// network commands fail fast (instead of a silent busy-spin on a dead socket).
const pump_error_broken_threshold = 100;
/// Bounded receive batches per pumpIncoming call: a sustained datagram inflow
/// must not starve the inbox and the waiter checks — the run loop round-robins.
const max_receive_batches_per_call = 16;

/// A one-shot request/response cell: the caller stacks one of these, the loop
/// writes the result and sets the event. `Event.set` is release / `wait` is
/// acquire, so the result is visible after the wait returns.
pub fn Completion(comptime T: type) type {
    return struct {
        event: std.Io.Event = .unset,
        result: T = undefined,

        const Self = @This();

        pub fn complete(self: *Self, io: std.Io, value: T) void {
            self.result = value;
            self.event.set(io);
        }

        pub fn awaitResult(self: *Self, io: std.Io) T {
            self.event.waitUncancelable(io);
            return self.result;
        }
    };
}

const ConnectResult = tr.Error!tr.Connection;
const AcceptResult = tr.Error!tr.Connection;
const OpenBiResult = tr.Error!tr.BiStream;
const AcceptBiResult = tr.Error!tr.BiStream;
const OpenUniResult = tr.Error!tr.SendStream;
const AcceptUniResult = tr.Error!tr.RecvStream;
const PollAcceptResult = tr.Error!?tr.Connection;
const PollInboundUniResult = tr.Error!?uni_poll.InboundUniEvent;
const SelectedPathResult = ?path_observability.SelectedPath;
pub const VoidResult = tr.Error!void;
/// The loop's answer to a recv-read fill: `data` bytes staged into the recv
/// handle's own buffer (already consumed from the stream queue), or end of
/// stream (fin + drained), or degraded (reset/closed/timed-out — reads EOF).
pub const RecvFill = union(enum) { data: usize, eof, degraded };

pub const SetAlpnsError = error{
    InvalidAlpn,
    OutOfMemory,
    EndpointClosed,
};
pub const SetAlpnsResult = SetAlpnsError!void;

pub const Command = union(enum) {
    connect: struct { peer: tr.NodeAddr, completion: *Completion(ConnectResult) },
    accept: struct { completion: *Completion(AcceptResult) },
    open_bi: struct { conn_id: u64, completion: *Completion(OpenBiResult) },
    accept_bi: struct { conn_id: u64, completion: *Completion(AcceptBiResult) },
    open_uni: struct { conn_id: u64, completion: *Completion(OpenUniResult) },
    accept_uni: struct { conn_id: u64, completion: *Completion(AcceptUniResult) },
    poll_accept: struct { completion: *Completion(PollAcceptResult) },
    poll_inbound_uni: struct { conn_id: u64, buffer: []u8, completion: *Completion(PollInboundUniResult) },
    selected_path: struct { conn_id: u64, completion: *Completion(SelectedPathResult) },
    connection_closed: struct { conn_id: u64, completion: *Completion(bool) },
    set_relay: struct { relay: relay_fallback.Client, completion: *Completion(VoidResult) },
    send_bytes: struct { send: *SendImpl, data: []const u8, completion: *Completion(VoidResult) },
    send_fin: struct { send: *SendImpl, completion: *Completion(VoidResult) },
    send_reset: struct { send: *SendImpl, completion: *Completion(void) },
    recv_stop: struct { recv: *RecvImpl, completion: *Completion(VoidResult) },
    recv_read: struct { recv: *RecvImpl, dest: []u8, completion: *Completion(RecvFill) },
    close_conn: struct { conn_id: u64, completion: *Completion(void) },
    close_all_conns: struct { completion: *Completion(void) },
    set_alpns: struct { alpns: []const []const u8, completion: *Completion(SetAlpnsResult) },
    shutdown: struct { completion: *Completion(void) },

    /// Caller-stacked queue node: submission links this node without
    /// allocating, so the inbox is infallible.
    pub const Node = struct {
        command: Command,
        next: ?*Node = null,
    };
};

/// The single cross-task structure in the design. Producers (any caller
/// thread) link their stacked node under the mutex; the loop unlinks the
/// whole list once per iteration.
const Inbox = struct {
    mutex: std.Io.Mutex = .init,
    head: ?*Command.Node = null,
    tail: ?*Command.Node = null,

    fn submit(self: *Inbox, io: std.Io, node: *Command.Node) void {
        node.next = null;
        self.mutex.lockUncancelable(io);
        if (self.tail) |tail| {
            tail.next = node;
        } else {
            self.head = node;
        }
        self.tail = node;
        self.mutex.unlock(io);
    }

    fn takeAll(self: *Inbox, io: std.Io) ?*Command.Node {
        self.mutex.lockUncancelable(io);
        const head = self.head;
        self.head = null;
        self.tail = null;
        self.mutex.unlock(io);
        return head;
    }
};

/// A parked request whose completion depends on future network state.
/// Checked by the loop after every pump round.
const Waiter = union(enum) {
    /// cnx_dead: the engine killed the cnx (resolveDeadCnxs deleted it); the
    /// waiter becomes a pure timer (Timeout at the deadline, no cnx access).
    connect: struct { cnx: *c.picoquic_cnx_t, deadline_us: u64, cnx_dead: bool = false, completion: *Completion(ConnectResult) },
    accept: struct { deadline_us: u64, completion: *Completion(AcceptResult) },
    accept_bi: struct { cnx: *c.picoquic_cnx_t, deadline_us: u64, completion: *Completion(AcceptBiResult) },
    accept_uni: struct { cnx: *c.picoquic_cnx_t, deadline_us: u64, completion: *Completion(AcceptUniResult) },
    recv_read: struct { recv: *RecvImpl, dest: []u8, deadline_us: u64, completion: *Completion(RecvFill) },
};

const RelayPeer = struct {
    cnx: *c.picoquic_cnx_t,
    peer: key.NodeId,
};

pub const Endpoint = struct {
    allocator: std.mem.Allocator,
    io_inst: std.Io,
    secret: key.SecretKey,
    node_id: key.NodeId,
    /// Client-connect default ALPN (constructor borrow; dial still uses this).
    alpn: [:0]const u8,
    /// Owned server-advertised ALPN set (setAlpns / Router.spawn). Select callback reads this.
    server_alpns: std.ArrayListUnmanaged([]u8) = .empty,
    local_address: net.IpAddress,
    quic: *c.picoquic_quic_t,
    socket: net.Socket,
    relay: ?relay_fallback.Client = null,
    handshake_timeout_us: u64 = handshake_timeout_default_us,
    stream_fin_timeout_us: u64 = stream_fin_timeout_default_us,

    // --- loop-owned state below (touched only by the event loop task) ---
    inbox: Inbox = .{},
    waiters: std.ArrayListUnmanaged(Waiter) = .empty,
    streams: std.ArrayListUnmanaged(*stream_mod.StreamState) = .empty,
    sends: std.ArrayListUnmanaged(*SendImpl) = .empty,
    recvs: std.ArrayListUnmanaged(*RecvImpl) = .empty,
    connections: std.ArrayListUnmanaged(*ConnectionImpl) = .empty,
    relay_peers: std.ArrayListUnmanaged(RelayPeer) = .empty,
    next_conn_id: u64 = 1,
    accepted_server_cnx: std.AutoHashMapUnmanaged(*c.picoquic_cnx_t, void) = .empty,
    dead_cnxs_pending: std.ArrayListUnmanaged(*c.picoquic_cnx_t) = .empty,
    stopping: bool = false,
    broken: bool = false,
    consecutive_pump_errors: u32 = 0,
    deleting_cnx: ?*c.picoquic_cnx_t = null,
    pending_close: ?*ConnectionImpl = null,
    loop_future: ?std.Io.Future(void) = null,

    pub const Options = struct {
        bind_address: net.IpAddress = .{ .ip4 = .loopback(0) },
        public_address: ?net.IpAddress = null,
        handshake_timeout_us: u64 = handshake_timeout_default_us,
        /// Receive-stall deadline for a single read (recv waiter). The
        /// 30s default matches the legacy FIN-gated read deadline.
        stream_fin_timeout_us: u64 = stream_fin_timeout_default_us,
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, secret: key.SecretKey, alpn: [:0]const u8) !*Endpoint {
        return initOptions(allocator, io, secret, alpn, .{});
    }

    pub fn initOptions(allocator: std.mem.Allocator, io: std.Io, secret: key.SecretKey, alpn: [:0]const u8, options: Options) !*Endpoint {
        const self = try allocator.create(Endpoint);
        errdefer allocator.destroy(self);

        var reset_seed: [c.PICOQUIC_RESET_SECRET_SIZE]u8 = undefined;
        io.random(&reset_seed);
        // Connection cap: legacy parity (128). The G0/G1 scaffold's cap of 8
        // wedged a persistent endpoint after a handful of closing-but-undrained
        // cnxs: rapid connect/close cycles accumulate cnxs in the
        // 3*RTO drain window, and new inbound initials get dropped (Timeout).
        const quic = c.picoquic_create(
            128,
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

        var bind_addr = options.bind_address;
        const socket = try bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
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
            .stream_fin_timeout_us = options.stream_fin_timeout_us,
        };
        errdefer freeServerAlpns(self);
        try replaceServerAlpns(self, &.{alpn});
        c.picoquic_set_alpn_select_fn_v2(quic, alpnSelectFn);
        // Pre-reserve the deferred dead-cnx list so the callback's append can
        // never fail mid-sweep (a lost deferred delete would zombie a client
        // cnx and stall its waiters to their deadlines).
        try self.dead_cnxs_pending.ensureTotalCapacity(self.allocator, 16);
        // The event loop owns all mutable state from here on; spawn it last so
        // it never observes a partially-initialized endpoint.
        self.loop_future = io.async(run, .{self});
        return self;
    }

    pub fn deinit(self: *Endpoint) void {
        // Stop the loop first: no picoquic/socket/state access may race teardown.
        if (self.loop_future) |*future| {
            var completion: Completion(void) = .{};
            var node: Command.Node = .{ .command = .{ .shutdown = .{ .completion = &completion } } };
            self.inbox.submit(self.io_inst, &node);
            completion.awaitResult(self.io_inst);
            future.await(self.io_inst);
            self.loop_future = null;
        }
        for (self.streams.items) |stream| {
            stream_mod.reset(stream, self.allocator);
            self.allocator.destroy(stream);
        }
        self.streams.deinit(self.allocator);
        for (self.sends.items) |send| self.allocator.destroy(send);
        self.sends.deinit(self.allocator);
        for (self.recvs.items) |recv| self.allocator.destroy(recv);
        self.recvs.deinit(self.allocator);
        for (self.connections.items) |conn| self.allocator.destroy(conn);
        self.connections.deinit(self.allocator);
        self.relay_peers.deinit(self.allocator);
        self.waiters.deinit(self.allocator);
        self.dead_cnxs_pending.deinit(self.allocator);
        self.accepted_server_cnx.deinit(self.allocator);
        self.socket.close(self.io_inst);
        c.iroh_picoquic_clear_raw_public_key(self.quic);
        c.picoquic_free(self.quic);
        freeServerAlpns(self);
        self.server_alpns.deinit(self.allocator);
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

    /// Factory cooperative-poll parity (`AnyEndpoint.pollOnce`).
    ///
    /// The greenfield endpoint's spawned actor loop already owns
    /// `pumpOutgoing`/`pumpIncoming`; callers must not drive those pumps.
    /// Protocol tests that loop on `pollOnce` (e.g. blobs-quic-interop after
    /// serve) still need a safe entry that yields the calling task so the
    /// actor can run — this is that yield, not a second pump.
    pub fn pollOnce(self: *Endpoint) tr.Error!void {
        // Brief awake sleep: avoid busy-spinning cooperative wait loops while
        // the actor loop continues pumping on its own task.
        std.Io.sleep(self.io_inst, .fromMilliseconds(1), .awake) catch {};
    }

    // =========================================================================
    // The event loop (the single owner of all mutable state)
    // =========================================================================

    fn run(self: *Endpoint) void {
        while (!self.stopping) {
            self.drainInbox();
            if (self.broken) {
                // Dead transport: keep processing commands (they fail fast or
                // clean up), but do not spin on a dead socket.
                std.Io.sleep(self.io_inst, .fromMilliseconds(10), .awake) catch {};
            } else {
                var failed = false;
                const relayed = self.pumpRelayIncoming() catch blk: {
                    failed = true;
                    break :blk false;
                };
                const sent = self.pumpOutgoing() catch blk: {
                    failed = true;
                    break :blk false;
                };
                _ = self.pumpIncoming(!sent and !relayed) catch blk: {
                    failed = true;
                    break :blk false;
                };
                if (failed) {
                    self.notePumpError();
                } else {
                    self.consecutive_pump_errors = 0;
                }
            }
            self.checkWaiters();
        }
        // Final drain so no submitted command is left uncompleted on shutdown;
        // anything the drain parked is failed out as well.
        self.drainInbox();
        self.failAllWaiters(error.ConnectionLost);
    }

    /// Pump failure bookkeeping: flips the endpoint broken after a sustained
    /// failure streak, failing all parked waiters instead of spinning silently
    /// on a dead socket.
    fn notePumpError(self: *Endpoint) void {
        self.consecutive_pump_errors += 1;
        if (self.consecutive_pump_errors >= pump_error_broken_threshold) {
            self.broken = true;
            self.failAllWaiters(error.ConnectionLost);
        }
    }

    /// Complete every parked waiter with a terminal failure (used on shutdown
    /// and when the endpoint goes broken).
    fn failAllWaiters(self: *Endpoint, err: tr.Error) void {
        for (self.waiters.items) |*waiter| {
            switch (waiter.*) {
                .connect => |*w| w.completion.complete(self.io_inst, err),
                .accept => |*w| w.completion.complete(self.io_inst, err),
                .accept_bi => |*w| w.completion.complete(self.io_inst, err),
                .accept_uni => |*w| w.completion.complete(self.io_inst, err),
                .recv_read => |*w| w.completion.complete(self.io_inst, .degraded),
            }
        }
        self.waiters.clearRetainingCapacity();
    }

    fn drainInbox(self: *Endpoint) void {
        var node = self.inbox.takeAll(self.io_inst);
        while (node) |current| {
            node = current.next;
            self.handleCommand(current.command);
        }
    }

    fn handleCommand(self: *Endpoint, command: Command) void {
        switch (command) {
            .connect => |cmd| self.doConnect(cmd.peer, cmd.completion),
            .accept => |cmd| self.waiters.append(self.allocator, .{ .accept = .{
                .deadline_us = c.picoquic_current_time() + self.handshake_timeout_us,
                .completion = cmd.completion,
            } }) catch cmd.completion.complete(self.io_inst, error.OutOfMemory),
            .open_bi => |cmd| self.doOpenBi(cmd.conn_id, cmd.completion),
            .accept_bi => |cmd| self.doParkStreamAccept(cmd.conn_id, false, cmd.completion),
            .open_uni => |cmd| self.doOpenUni(cmd.conn_id, cmd.completion),
            .accept_uni => |cmd| self.doParkStreamAccept(cmd.conn_id, true, cmd.completion),
            .poll_accept => |cmd| self.doPollAccept(cmd.completion),
            .poll_inbound_uni => |cmd| self.doPollInboundUni(cmd.conn_id, cmd.buffer, cmd.completion),
            .selected_path => |cmd| self.doSelectedPath(cmd.conn_id, cmd.completion),
            .connection_closed => |cmd| cmd.completion.complete(self.io_inst, self.connectionClosed(cmd.conn_id)),
            .set_relay => |cmd| {
                if (self.broken) {
                    cmd.completion.complete(self.io_inst, error.ConnectionLost);
                } else {
                    self.relay = cmd.relay;
                    cmd.completion.complete(self.io_inst, {});
                }
            },
            .send_bytes => |cmd| self.doSendBytes(cmd.send, cmd.data, cmd.completion),
            .send_fin => |cmd| self.doSendFin(cmd.send, cmd.completion),
            .send_reset => |cmd| {
                self.doSendReset(cmd.send);
                cmd.completion.complete(self.io_inst, {});
            },
            .recv_stop => |cmd| self.doRecvStop(cmd.recv, cmd.completion),
            .recv_read => |cmd| self.waiters.append(self.allocator, .{ .recv_read = .{
                .recv = cmd.recv,
                .dest = cmd.dest,
                .deadline_us = c.picoquic_current_time() + self.stream_fin_timeout_us,
                .completion = cmd.completion,
            } }) catch cmd.completion.complete(self.io_inst, .degraded),
            .close_conn => |cmd| {
                self.doCloseConn(cmd.conn_id);
                cmd.completion.complete(self.io_inst, {});
            },
            .close_all_conns => |cmd| {
                // closeConnImpl is idempotent and never mutates the
                // `connections` list itself (reclaimConnection only marks
                // stream/send/recv slots), so a straight pass is safe.
                for (self.connections.items) |conn| self.closeConnImpl(conn);
                cmd.completion.complete(self.io_inst, {});
            },
            .set_alpns => |cmd| {
                if (self.stopping) {
                    cmd.completion.complete(self.io_inst, error.EndpointClosed);
                } else {
                    cmd.completion.complete(self.io_inst, replaceServerAlpns(self, cmd.alpns));
                }
            },
            .shutdown => |cmd| {
                self.stopping = true;
                self.failAllWaiters(error.ConnectionLost);
                cmd.completion.complete(self.io_inst, {});
            },
        }
    }

    fn checkWaiters(self: *Endpoint) void {
        // Resolve engine deaths first (never from inside an arm).
        self.resolveDeadCnxs();
        const now = c.picoquic_current_time();
        var i: usize = 0;
        while (i < self.waiters.items.len) {
            if (self.checkWaiter(&self.waiters.items[i], now)) {
                _ = self.waiters.swapRemove(i);
            } else {
                i += 1;
            }
        }
        // Arms can trigger more deaths (delete-time callback): resolve again.
        self.resolveDeadCnxs();
        // Deferred connection close requested by a timeout arm (safe here —
        // the waiter iteration is done; closeConnImpl sweeps this cnx's
        // remaining waiters).
        if (self.pending_close) |conn| {
            self.pending_close = null;
            self.closeConnImpl(conn);
        }
    }

    /// Returns true when the waiter completed (and may be dropped).
    fn checkWaiter(self: *Endpoint, waiter: *Waiter, now_us: u64) bool {
        if (self.broken) {
            switch (waiter.*) {
                .connect => |*w| w.completion.complete(self.io_inst, error.ConnectionLost),
                .accept => |*w| w.completion.complete(self.io_inst, error.ConnectionLost),
                .accept_bi => |*w| w.completion.complete(self.io_inst, error.ConnectionLost),
                .accept_uni => |*w| w.completion.complete(self.io_inst, error.ConnectionLost),
                .recv_read => |*w| {
                    w.completion.complete(self.io_inst, .degraded);
                },
            }
            return true;
        }
        switch (waiter.*) {
            .connect => |*w| {
                if (!w.cnx_dead and c.picoquic_get_cnx_state(w.cnx) == c.picoquic_state_ready) {
                    w.completion.complete(self.io_inst, self.handOffConnection(w.cnx, false));
                    return true;
                }
                if (now_us >= w.deadline_us) {
                    // Live cnx: we own the delete (client cnxs are never
                    // auto-deleted). Dead cnx: resolveDeadCnxs already
                    // deleted it — this waiter is a pure timer now.
                    if (!w.cnx_dead) {
                        self.reclaimConnection(w.cnx);
                        self.guardedDeleteCnx(w.cnx);
                    }
                    w.completion.complete(self.io_inst, error.Timeout);
                    return true;
                }
                return false;
            },
            .accept => |*w| {
                if (self.firstReadyServerCnx()) |cnx| {
                    w.completion.complete(self.io_inst, self.handOffConnection(cnx, true));
                    return true;
                }
                if (now_us >= w.deadline_us) {
                    w.completion.complete(self.io_inst, error.Timeout);
                    return true;
                }
                return false;
            },
            .accept_bi => |*w| {
                if (self.findStreamHandoff(w.cnx, false)) |handoff| {
                    switch (handoff) {
                        .reset => w.completion.complete(self.io_inst, error.StreamReset),
                        .stream => |stream| w.completion.complete(self.io_inst, self.makeBiStream(w.cnx, stream.id, stream)),
                    }
                    return true;
                }
                if (now_us >= w.deadline_us) {
                    w.completion.complete(self.io_inst, error.Timeout);
                    return true;
                }
                return false;
            },
            .accept_uni => |*w| {
                if (self.findStreamHandoff(w.cnx, true)) |handoff| {
                    switch (handoff) {
                        .reset => w.completion.complete(self.io_inst, error.StreamReset),
                        .stream => |stream| w.completion.complete(self.io_inst, self.makeUniRecv(w.cnx, stream)),
                    }
                    return true;
                }
                if (now_us >= w.deadline_us) {
                    w.completion.complete(self.io_inst, error.Timeout);
                    return true;
                }
                return false;
            },
            .recv_read => |*w| {
                if (!w.recv.used.load(.monotonic)) {
                    // Reclaimed under the reader (connection closed): EOF now,
                    // not after the deadline.
                    w.completion.complete(self.io_inst, .degraded);
                    return true;
                }
                if (self.findStream(w.recv.cnx, w.recv.stream_id)) |stream| {
                    if (stream.reset) {
                        w.completion.complete(self.io_inst, .degraded);
                        return true;
                    }
                    if (stream.recvq.buffered > 0) {
                        // Incremental fill: copy into the caller's destination.
                        const n = stream.recvq.takeInto(self.allocator, w.dest);
                        if (stream.recvq.buffered < stream_receive_window / 2 and !stream.fin) {
                            // Slide the flow-control window as the reader
                            // drains: the frame
                            // grants engine_consumed + window — a monotonic
                            // 16 MiB sliding window; the connection MAX_DATA
                            // it also emits stays below the transport-param
                            // credit, so the peer ignores it (monotonic).
                            // Best-effort: a closing/discarded stream rejects
                            // the update and needs no more credit.
                            _ = c.picoquic_open_flow_control(w.recv.cnx, w.recv.stream_id, stream_receive_window);
                        }
                        w.completion.complete(self.io_inst, .{ .data = n });
                        return true;
                    }
                    if (stream.fin) {
                        w.completion.complete(self.io_inst, .eof);
                        return true;
                    }
                }
                if (now_us >= w.deadline_us) {
                    // Stream stalled out. Legacy parity: a receive-side stall
                    // is a connection-level failure — the reader degrades to
                    // EOF and the connection is closed. The close is DEFERRED
                    // to the end of checkWaiters (closeConnImpl sweeps this
                    // cnx's waiters; running it inside the arm would re-enter
                    // the waiter list mid-iteration).
                    if (self.pending_close == null) {
                        self.pending_close = self.connectionForCnxPtr(w.recv.cnx);
                    }
                    w.completion.complete(self.io_inst, .degraded);
                    return true;
                }
                return false;
            },
        }
    }

    // =========================================================================
    // Command bodies (loop-only)
    // =========================================================================

    fn doConnect(self: *Endpoint, peer: tr.NodeAddr, completion: *Completion(ConnectResult)) void {
        if (self.broken) {
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        }
        const first_ip = self.firstCompatibleIpAddr(peer);
        const relay_available = self.relay != null and peer.firstRelayUrl() != null;
        const initial_addr = first_ip orelse if (relay_available) magicsock.relayAddress() else {
            completion.complete(self.io_inst, error.NotConnected);
            return;
        };
        const expected_public = peer.id.toBytes();

        var peer_addr = sockaddrFromIp(initial_addr);
        const zero_cid: c.picoquic_connection_id_t = .{ .id = [_]u8{0} ** 20, .id_len = 0 };
        const sni = tls_name.serverName(peer.id);
        var sni_z: [tls_name.encoded_name_len + 1]u8 = undefined;
        @memcpy(sni_z[0..tls_name.encoded_name_len], &sni);
        sni_z[tls_name.encoded_name_len] = 0;
        const cnx = c.picoquic_create_cnx(self.quic, zero_cid, zero_cid, @ptrCast(&peer_addr), c.picoquic_current_time(), c.PICOQUIC_V1_VERSION, sni_z[0..tls_name.encoded_name_len :0].ptr, self.alpn.ptr, 1) orelse {
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        };
        if (relay_available) {
            self.rememberRelayPeer(cnx, peer.id) catch {
                self.guardedDeleteCnx(cnx);
                completion.complete(self.io_inst, error.OutOfMemory);
                return;
            };
        }
        if (c.iroh_picoquic_set_cnx_expected_peer(cnx, &expected_public) != 0) {
            self.guardedDeleteCnx(cnx);
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        }
        c.picoquic_enable_path_callbacks(cnx, 1);
        self.enableKeepAlive(cnx);
        if (c.picoquic_start_client_cnx(cnx) != 0) {
            self.guardedDeleteCnx(cnx);
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        }
        self.waiters.append(self.allocator, .{ .connect = .{
            .cnx = cnx,
            .deadline_us = c.picoquic_current_time() + self.handshake_timeout_us,
            .completion = completion,
        } }) catch {
            self.guardedDeleteCnx(cnx);
            completion.complete(self.io_inst, error.OutOfMemory);
        };
    }

    fn doSelectedPath(self: *Endpoint, conn_id: u64, completion: *Completion(SelectedPathResult)) void {
        const conn = self.liveConnection(conn_id) orelse {
            completion.complete(self.io_inst, null);
            return;
        };
        if (self.relayPeerFor(conn.cnx) != null) {
            completion.complete(self.io_inst, .{ .kind = .relay, .address = null });
            return;
        }
        completion.complete(self.io_inst, null);
    }

    fn doOpenBi(self: *Endpoint, conn_id: u64, completion: *Completion(OpenBiResult)) void {
        const conn = self.liveConnection(conn_id) orelse {
            completion.complete(self.io_inst, error.NotConnected);
            return;
        };
        const stream_id = self.reserveLocalStreamId(conn, false) orelse {
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        };
        completion.complete(self.io_inst, self.makeBiStream(conn.cnx, stream_id, null));
    }

    fn doOpenUni(self: *Endpoint, conn_id: u64, completion: *Completion(OpenUniResult)) void {
        const conn = self.liveConnection(conn_id) orelse {
            completion.complete(self.io_inst, error.NotConnected);
            return;
        };
        const stream_id = self.reserveLocalStreamId(conn, true) orelse {
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        };
        const send = self.makeSendImpl(conn.cnx, stream_id) orelse {
            completion.complete(self.io_inst, error.OutOfMemory);
            return;
        };
        completion.complete(self.io_inst, .{ .context = send, .vtable = &send_vtable });
    }

    fn doPollAccept(self: *Endpoint, completion: *Completion(PollAcceptResult)) void {
        if (self.broken) {
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        }
        if (self.firstReadyServerCnx()) |cnx| {
            const conn = self.handOffConnection(cnx, true) catch |err| {
                completion.complete(self.io_inst, err);
                return;
            };
            completion.complete(self.io_inst, @as(?tr.Connection, conn));
            return;
        }
        completion.complete(self.io_inst, null);
    }

    fn connectionClosed(self: *Endpoint, conn_id: u64) bool {
        const conn = self.findConnection(conn_id) orelse return true;
        return conn.closed or conn.remote_closed;
    }

    fn doPollInboundUni(
        self: *Endpoint,
        conn_id: u64,
        buffer: []u8,
        completion: *Completion(PollInboundUniResult),
    ) void {
        if (buffer.len == 0) {
            completion.complete(self.io_inst, null);
            return;
        }
        const conn = self.liveConnection(conn_id) orelse {
            completion.complete(self.io_inst, error.NotConnected);
            return;
        };
        const streams = self.streams.items;
        if (streams.len == 0) {
            completion.complete(self.io_inst, null);
            return;
        }

        const peer_initiated_bit: u64 = if (c.picoquic_is_client(conn.cnx) != 0) 1 else 0;
        for (0..streams.len) |offset| {
            const index = (conn.next_stream_scan + offset) % streams.len;
            const stream = streams[index];
            if (!stream.used or stream.cnx != conn.cnx or stream.handed_off) continue;
            if (stream.id & 0x1 != peer_initiated_bit) continue;
            if (stream.id & 0x2 == 0) continue;

            conn.next_stream_scan = (index + 1) % streams.len;
            if (stream.reset) {
                const stream_id = stream.id;
                stream_mod.reset(stream, self.allocator);
                completion.complete(self.io_inst, .{ .reset = stream_id });
                return;
            }
            if (stream.recvq.buffered > 0) {
                const stream_id = stream.id;
                const n = stream.recvq.takeSomeInto(self.allocator, buffer);
                if (stream.recvq.buffered < stream_receive_window / 2 and !stream.fin) {
                    _ = c.picoquic_open_flow_control(conn.cnx, stream_id, stream_receive_window);
                }
                const fin = stream.fin and stream.recvq.buffered == 0;
                if (fin) stream_mod.reset(stream, self.allocator);
                completion.complete(self.io_inst, .{ .chunk = .{
                    .stream_id = stream_id,
                    .bytes = buffer[0..n],
                    .fin = fin,
                } });
                return;
            }
            if (stream.fin) {
                const stream_id = stream.id;
                stream_mod.reset(stream, self.allocator);
                completion.complete(self.io_inst, .{ .chunk = .{
                    .stream_id = stream_id,
                    .bytes = buffer[0..0],
                    .fin = true,
                } });
                return;
            }
        }
        completion.complete(self.io_inst, null);
    }

    fn doParkStreamAccept(self: *Endpoint, conn_id: u64, comptime uni: bool, completion: anytype) void {
        const conn = self.liveConnection(conn_id) orelse {
            completion.complete(self.io_inst, error.NotConnected);
            return;
        };
        const deadline_us = c.picoquic_current_time() + stream_open_timeout_us;
        if (uni) {
            self.waiters.append(self.allocator, .{ .accept_uni = .{
                .cnx = conn.cnx,
                .deadline_us = deadline_us,
                .completion = completion,
            } }) catch completion.complete(self.io_inst, error.OutOfMemory);
        } else {
            self.waiters.append(self.allocator, .{ .accept_bi = .{
                .cnx = conn.cnx,
                .deadline_us = deadline_us,
                .completion = completion,
            } }) catch completion.complete(self.io_inst, error.OutOfMemory);
        }
    }

    fn doSendBytes(self: *Endpoint, send: *SendImpl, data: []const u8, completion: *Completion(VoidResult)) void {
        if (!send.used.load(.monotonic)) {
            completion.complete(self.io_inst, error.NotConnected);
            return;
        }
        if (self.broken) {
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        }
        // The slice is caller-borrowed (the caller is blocked on this
        // command's completion): read it here and nowhere else.
        if (c.picoquic_add_to_stream(send.cnx, send.stream_id, data.ptr, data.len, 0) != 0) {
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        }
        _ = self.pumpOutgoing() catch {};
        completion.complete(self.io_inst, {});
    }

    fn doSendFin(self: *Endpoint, send: *SendImpl, completion: *Completion(VoidResult)) void {
        if (!send.used.load(.monotonic)) {
            // finish on a finished stream is a no-op (legacy parity).
            completion.complete(self.io_inst, {});
            return;
        }
        defer send.used.store(false, .monotonic);
        if (self.broken) {
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        }
        if (c.picoquic_add_to_stream(send.cnx, send.stream_id, "", 0, 1) != 0) {
            // A failed finish still tombstones the send half (legacy parity):
            // later writes hit the dead writer.
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        }
        _ = self.pumpOutgoing() catch {};
        completion.complete(self.io_inst, {});
    }

    fn doSendReset(self: *Endpoint, send: *SendImpl) void {
        if (!send.used.load(.monotonic)) return;
        if (c.picoquic_reset_stream(send.cnx, send.stream_id, 0) == 0) {
            _ = self.pumpOutgoing() catch {};
        }
        send.used.store(false, .monotonic);
    }

    fn doRecvStop(self: *Endpoint, recv: *RecvImpl, completion: *Completion(VoidResult)) void {
        if (!recv.used.load(.monotonic)) {
            completion.complete(self.io_inst, error.NotConnected);
            return;
        }
        if (self.broken) {
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        }
        if (c.picoquic_stop_sending(recv.cnx, recv.stream_id, 0) != 0) {
            completion.complete(self.io_inst, error.ConnectionLost);
            return;
        }
        recv.stopped.store(true, .monotonic);
        _ = self.pumpOutgoing() catch {};
        completion.complete(self.io_inst, {});
    }

    fn doCloseConn(self: *Endpoint, conn_id: u64) void {
        const conn = self.findConnection(conn_id) orelse return;
        self.closeConnImpl(conn);
    }

    /// Local close of a connection. Idempotent (copied handles share the impl).
    ///
    /// Deletion ownership is asymmetric (verified against vendored picoquic
    /// sender.c:3806-3815): when a cnx disconnects, picoquic auto-deletes
    /// SERVER cnxs inside a later prepare pass but keeps CLIENT cnxs for the
    /// application. A remote-closed cnx is therefore left for
    /// `resolveDeadCnxs` — which deletes it only while it is still present AND
    /// disconnected, beating the engine's auto-delete without ever
    /// double-freeing. A live cnx gets the full close + delete here (the
    /// delete-time callback re-enters noteCnxDead, suppressed by
    /// `deleting_cnx`).
    fn closeConnImpl(self: *Endpoint, conn: *ConnectionImpl) void {
        if (conn.closed) return;
        conn.closed = true;
        const cnx = conn.cnx;
        self.reclaimConnection(cnx);
        // Always drop the accept-tracking entry here: the guarded delete
        // suppresses noteCnxDead (which removes it on the engine-death path),
        // and a stale entry makes firstReadyServerCnx skip a later cnx at the
        // recycled address (the N=200 accept-Timeout flake).
        _ = self.accepted_server_cnx.remove(cnx);
        if (conn.remote_closed) {
            // Engine owns the teardown; resolveDeadCnxs deletes it (or
            // picoquic already auto-deleted). Fail its waiters now.
            self.sweepCnxWaiters(cnx);
            return;
        }
        // Live cnx: queue CONNECTION_CLOSE (the loop's pumps deliver it), then
        // delete — matching the legacy backend's teardown order.
        if (c.picoquic_close(cnx, 0) == 0) {
            _ = self.pumpOutgoing() catch {};
        }
        self.guardedDeleteCnx(cnx);
        self.sweepCnxWaiters(cnx);
    }

    /// picoquic_delete_cnx with the delete-time close callback suppressed (the
    /// callback would otherwise re-queue the cnx for deletion).
    fn guardedDeleteCnx(self: *Endpoint, cnx: *c.picoquic_cnx_t) void {
        self.forgetRelayPeer(cnx);
        self.deleting_cnx = cnx;
        c.picoquic_delete_cnx(cnx);
        self.deleting_cnx = null;
    }

    /// Delete engine-dead cnxs deterministically, at the earliest safe point
    /// after the death callback (never inside it). For each dead cnx: fail its
    /// waiters, then delete ONLY if it is still present AND in disconnected
    /// state — picoquic may have auto-deleted it already (absent), and a
    /// recycled address belongs to a live cnx (not disconnected). This makes
    /// the double-free structurally impossible (the audit's remote-closed
    /// server case) while keeping the dead-cnx linger to ~1 loop iteration.
    fn resolveDeadCnxs(self: *Endpoint) void {
        for (self.dead_cnxs_pending.items) |cnx| {
            self.sweepCnxWaiters(cnx);
            // Connect waiters outlive their cnx as pure timers (a failed
            // handshake must still surface as Timeout, not ConnectionLost).
            for (self.waiters.items) |*waiter| {
                switch (waiter.*) {
                    .connect => |*w| {
                        if (w.cnx == cnx) w.cnx_dead = true;
                    },
                    else => {},
                }
            }
            if (self.cnxIsDisconnectedAndPresent(cnx)) {
                self.guardedDeleteCnx(cnx);
            }
        }
        self.dead_cnxs_pending.clearRetainingCapacity();
    }

    fn cnxIsDisconnectedAndPresent(self: *Endpoint, cnx: *c.picoquic_cnx_t) bool {
        var maybe_cnx: ?*c.picoquic_cnx_t = c.picoquic_get_first_cnx(self.quic);
        while (maybe_cnx) |current| : (maybe_cnx = c.picoquic_get_next_cnx(current)) {
            if (current == cnx) {
                return c.picoquic_get_cnx_state(current) == c.picoquic_state_disconnected;
            }
        }
        return false;
    }

    /// Uniform cleanup when a cnx dies (remote close / application close /
    /// stateless reset, or the synchronous delete-time callback from our own
    /// picoquic_delete_cnx). Idempotent. After this, no Zig state may be used
    /// to touch the cnx again except through resolveDeadCnxs.
    fn noteCnxDead(self: *Endpoint, cnx: *c.picoquic_cnx_t) void {
        if (self.deleting_cnx == cnx) return; // our own guarded delete
        c.iroh_picoquic_forget_cnx_peer(cnx);
        self.forgetRelayPeer(cnx);
        self.reclaimConnection(cnx);
        _ = self.accepted_server_cnx.remove(cnx);
        for (self.connections.items) |conn| {
            if (!conn.closed and conn.cnx == cnx) {
                conn.remote_closed = true;
                break;
            }
        }
        self.dead_cnxs_pending.append(self.allocator, cnx) catch {};
    }

    /// Fail waiters parked on a dead cnx (fast ConnectionLost instead of a
    /// 15s stall; iroh semantics: connection death fails its streams).
    /// Connect/endpoint-accept waiters are intentionally NOT swept — a failed
    /// handshake must surface as Timeout (characterization pin).
    fn sweepCnxWaiters(self: *Endpoint, cnx: *c.picoquic_cnx_t) void {
        var i: usize = 0;
        while (i < self.waiters.items.len) {
            const waiter = &self.waiters.items[i];
            const on_cnx = switch (waiter.*) {
                .accept_bi => |*w| w.cnx == cnx,
                .accept_uni => |*w| w.cnx == cnx,
                .recv_read => |*w| w.recv.cnx == cnx,
                else => false,
            };
            if (!on_cnx) {
                i += 1;
                continue;
            }
            switch (waiter.*) {
                .accept_bi => |*w| w.completion.complete(self.io_inst, error.ConnectionLost),
                .accept_uni => |*w| w.completion.complete(self.io_inst, error.ConnectionLost),
                .recv_read => |*w| {
                    w.completion.complete(self.io_inst, .degraded);
                },
                else => unreachable,
            }
            _ = self.waiters.swapRemove(i);
        }
    }

    // =========================================================================
    // Registry helpers (loop-only)
    // =========================================================================

    fn findConnection(self: *Endpoint, conn_id: u64) ?*ConnectionImpl {
        for (self.connections.items) |conn| {
            if (conn.id == conn_id) return conn;
        }
        return null;
    }

    fn connectionForCnxPtr(self: *Endpoint, cnx: *c.picoquic_cnx_t) ?*ConnectionImpl {
        for (self.connections.items) |conn| {
            if (conn.cnx == cnx) return conn;
        }
        return null;
    }

    fn liveConnection(self: *Endpoint, conn_id: u64) ?*ConnectionImpl {
        const conn = self.findConnection(conn_id) orelse return null;
        if (conn.closed or conn.remote_closed) return null;
        return conn;
    }

    fn reserveLocalStreamId(self: *Endpoint, conn: *ConnectionImpl, is_unidir: bool) ?u64 {
        _ = self;
        const stream_id = c.picoquic_get_next_local_stream_id(conn.cnx, if (is_unidir) 1 else 0);
        if (c.picoquic_set_app_stream_ctx(conn.cnx, stream_id, null) != 0) return null;
        return stream_id;
    }

    fn makeSendImpl(self: *Endpoint, cnx: *c.picoquic_cnx_t, stream_id: u64) ?*SendImpl {
        const send = self.allocator.create(SendImpl) catch return null;
        send.* = .{
            .endpoint = self,
            .cnx = cnx,
            .stream_id = stream_id,
            .writer_storage = .{
                .vtable = &stream_mod.send_writer_vtable,
                .buffer = send.writer_buffer[0..],
                .end = 0,
            },
        };
        self.sends.append(self.allocator, send) catch {
            self.allocator.destroy(send);
            return null;
        };
        return send;
    }

    fn makeRecvImpl(self: *Endpoint, cnx: *c.picoquic_cnx_t, stream_id: u64) ?*RecvImpl {
        const recv = self.allocator.create(RecvImpl) catch return null;
        recv.* = .{
            .endpoint = self,
            .cnx = cnx,
            .stream_id = stream_id,
        };
        self.recvs.append(self.allocator, recv) catch {
            self.allocator.destroy(recv);
            return null;
        };
        return recv;
    }

    const Handoff = union(enum) {
        reset,
        stream: *stream_mod.StreamState,
    };

    fn makeBiStream(self: *Endpoint, cnx: *c.picoquic_cnx_t, stream_id: u64, handoff: ?*stream_mod.StreamState) OpenBiResult {
        const send = self.makeSendImpl(cnx, stream_id) orelse return error.OutOfMemory;
        const recv = self.makeRecvImpl(cnx, stream_id) orelse {
            send.used.store(false, .monotonic);
            return error.OutOfMemory;
        };
        // Only mark handed-off once both handles exist (an OOM mid-handoff
        // must not strand the stream with no live handles).
        if (handoff) |stream| stream.handed_off = true;
        return .{ .send = .{ .context = send, .vtable = &send_vtable }, .recv = .{ .context = recv, .vtable = &recv_vtable } };
    }

    fn makeUniRecv(self: *Endpoint, cnx: *c.picoquic_cnx_t, stream: *stream_mod.StreamState) AcceptUniResult {
        const recv = self.makeRecvImpl(cnx, stream.id) orelse return error.OutOfMemory;
        stream.handed_off = true;
        return .{ .context = recv, .vtable = &recv_vtable };
    }

    fn findStream(self: *Endpoint, cnx: *c.picoquic_cnx_t, stream_id: u64) ?*stream_mod.StreamState {
        for (self.streams.items) |stream| {
            if (stream.used and stream.cnx == cnx and stream.id == stream_id) return stream;
        }
        return null;
    }

    fn streamFor(self: *Endpoint, cnx: *c.picoquic_cnx_t, stream_id: u64) ?*stream_mod.StreamState {
        if (self.findStream(cnx, stream_id)) |stream| return stream;
        const stream = self.allocator.create(stream_mod.StreamState) catch return null;
        stream.* = .{ .cnx = cnx, .id = stream_id, .used = true };
        self.streams.append(self.allocator, stream) catch {
            self.allocator.destroy(stream);
            return null;
        };
        return stream;
    }

    fn findStreamHandoff(self: *Endpoint, cnx: *c.picoquic_cnx_t, uni: bool) ?Handoff {
        // Only PEER-initiated streams may be accepted (quinn/iroh accept_bi
        // semantics): a locally-opened bi stream with response data must not
        // be handed to acceptBi as a second handle pair on the same stream.
        const peer_initiated_bit: u64 = if (c.picoquic_is_client(cnx) != 0) 1 else 0;
        for (self.streams.items) |stream| {
            if (!stream.used or stream.cnx != cnx or stream.handed_off) continue;
            if (stream.id & 0x1 != peer_initiated_bit) continue;
            const is_uni = stream.id & 0x2 != 0;
            if (is_uni != uni) continue;
            if (stream.reset) {
                stream.handed_off = true;
                return .reset;
            }
            // Both bi and uni accept hand off on first data or FIN (incremental
            // — the reader starts consuming immediately; the legacy's
            // uni-FIN-gating is dropped, journaled as GOOD drift, required so
            // a >window uni stream can't deadlock the sliding credit).
            if (stream.recvq.buffered == 0 and !stream.fin) continue;
            return .{ .stream = stream };
        }
        return null;
    }

    fn firstReadyServerCnx(self: *Endpoint) ?*c.picoquic_cnx_t {
        var maybe_cnx: ?*c.picoquic_cnx_t = c.picoquic_get_first_cnx(self.quic);
        while (maybe_cnx) |cnx| : (maybe_cnx = c.picoquic_get_next_cnx(cnx)) {
            if (c.picoquic_get_cnx_state(cnx) == c.picoquic_state_ready and
                c.picoquic_is_client(cnx) == 0 and
                !self.accepted_server_cnx.contains(cnx))
            {
                return cnx;
            }
        }
        return null;
    }

    fn handOffConnection(self: *Endpoint, cnx: *c.picoquic_cnx_t, server_handoff: bool) ConnectResult {
        if (server_handoff) {
            self.accepted_server_cnx.put(self.allocator, cnx, {}) catch return error.OutOfMemory;
        }
        // On any handoff failure the cnx must not leak (client cnx included —
        // picoquic never auto-deletes client cnxs).
        errdefer {
            if (server_handoff) _ = self.accepted_server_cnx.remove(cnx);
            self.reclaimConnection(cnx);
            self.guardedDeleteCnx(cnx);
        }

        var remote_bytes: [32]u8 = undefined;
        if (c.iroh_picoquic_last_verified_peer_public_key(cnx, &remote_bytes) != 0) return error.ConnectionLost;
        const remote = key.PublicKey.fromBytes(remote_bytes) catch return error.ConnectionLost;
        self.enableKeepAlive(cnx);
        const conn = self.allocator.create(ConnectionImpl) catch return error.OutOfMemory;
        conn.* = .{
            .endpoint = self,
            .id = self.next_conn_id,
            .cnx = cnx,
            .remote = remote,
        };
        conn.snapshotAlpn(cnx);
        self.next_conn_id += 1;
        self.connections.append(self.allocator, conn) catch {
            self.allocator.destroy(conn);
            return error.OutOfMemory;
        };
        return .{ .context = conn, .vtable = &connection_vtable };
    }

    fn enableKeepAlive(_: *Endpoint, cnx: *c.picoquic_cnx_t) void {
        const interval = context.default_transport_params.keep_alive_interval_us;
        if (interval != 0) c.picoquic_enable_keep_alive(cnx, interval);
    }

    fn reclaimConnection(self: *Endpoint, cnx: *c.picoquic_cnx_t) void {
        for (self.streams.items) |stream| {
            // Mark-only (never free here): a caller may hold a writer/reader
            // on this connection while another task closes it. All buffers
            // (recv queue chunks, inline reader/writer buffers) are released
            // only at Endpoint.deinit — the frozen vtable gives streams no
            // close op, so there is no safe earlier point (see the
            // F7 retention note).
            if (stream.used and stream.cnx == cnx) stream.used = false;
        }
        for (self.sends.items) |send| {
            if (send.used.load(.monotonic) and send.cnx == cnx) send.used.store(false, .monotonic);
        }
        for (self.recvs.items) |recv| {
            if (recv.used.load(.monotonic) and recv.cnx == cnx) recv.used.store(false, .monotonic);
        }
    }

    // =========================================================================
    // Pump (loop-only; picoquic is driven from here and nowhere else)
    // =========================================================================

    fn pumpOutgoing(self: *Endpoint) tr.Error!bool {
        var sent = false;
        while (true) {
            var batch: pump.OutgoingBatch = .{};
            while (!batch.isFull()) {
                var send_len: usize = 0;
                var to: c.struct_sockaddr_storage = undefined;
                var from: c.struct_sockaddr_storage = undefined;
                var if_index: c_int = 0;
                var log_cid: c.picoquic_connection_id_t = undefined;
                var last_cnx: ?*c.picoquic_cnx_t = null;
                var packet: [c.PICOQUIC_MAX_PACKET_SIZE]u8 = undefined;
                if (c.picoquic_prepare_next_packet(self.quic, c.picoquic_current_time(), &packet, packet.len, &send_len, &to, &from, &if_index, &log_cid, &last_cnx) != 0) {
                    return error.ConnectionLost;
                }
                if (send_len == 0) break;
                const dest = ipFromSockaddr(to) catch return error.ConnectionLost;
                if (sameIpAddress(dest, magicsock.relayAddress())) {
                    if (batch.count > 0) {
                        try self.sendUdpBatch(batch.slice());
                        sent = true;
                        batch = .{};
                    }
                    try self.sendRelayPacket(last_cnx, packet[0..send_len]);
                    sent = true;
                    continue;
                }
                if (!sameAddressFamily(self.socket.address, dest)) {
                    // One invalid peer path must not poison the endpoint pump.
                    if (batch.count == 0) return sent;
                    break;
                }
                batch.append(dest, packet[0..send_len]);
            }
            if (batch.count == 0) return sent;
            try self.sendUdpBatch(batch.slice());
            sent = true;
        }
    }

    fn sendUdpBatch(self: *Endpoint, batch: []net.OutgoingMessage) tr.Error!void {
        self.socket.sendMany(self.io_inst, batch, .{}) catch |err| switch (err) {
            error.AddressFamilyUnsupported => return,
            else => return error.ConnectionLost,
        };
    }

    fn sendRelayPacket(self: *Endpoint, cnx: ?*c.picoquic_cnx_t, data: []const u8) tr.Error!void {
        const relay = self.relay orelse return error.NotConnected;
        const peer = if (cnx) |cptr| self.relayPeerFor(cptr) orelse return error.NotConnected else return error.NotConnected;
        try relay.send(peer, data);
    }

    fn pumpRelayIncoming(self: *Endpoint) tr.Error!bool {
        const relay = self.relay orelse return false;
        var buffer: [2048]u8 = undefined;
        var progressed = false;
        while (true) {
            const msg = (try relay.recv(&buffer)) orelse return progressed;
            var from = sockaddrFromIp(magicsock.relayAddress());
            var to = sockaddrFromIp(self.pathLocalAddress(magicsock.relayAddress()));
            if (c.picoquic_incoming_packet(self.quic, msg.data.ptr, msg.data.len, @ptrCast(&from), @ptrCast(&to), 0, 0, c.picoquic_current_time()) != 0) {
                return error.ConnectionLost;
            }
            try self.bindRelayIncoming(msg.src);
            _ = try self.pumpOutgoing();
            progressed = true;
        }
    }

    fn pumpIncoming(self: *Endpoint, wait: bool) tr.Error!bool {
        var progressed = false;
        var batch: pump.IncomingBatch = undefined;
        // Bounded batches per call: a sustained inflow must not starve the
        // inbox and the waiter checks (the run loop round-robins back here).
        for (0..max_receive_batches_per_call) |_| {
            batch.init();
            const timeout = if (progressed or !wait) pump.drain_timeout else pump.wait_timeout;
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
            for (batch.messages[0..count]) |message| {
                // A datagram that cannot be converted is skipped, not fatal:
                // the loop has no caller to propagate to, and dropping one
                // datagram must not kill the endpoint.
                var from = sockaddrFromIp(message.from);
                var to = sockaddrFromIp(self.pathLocalAddress(message.from));
                if (c.picoquic_incoming_packet(self.quic, message.data.ptr, message.data.len, @ptrCast(&from), @ptrCast(&to), 0, 0, c.picoquic_current_time()) != 0) {
                    return error.ConnectionLost;
                }
                progressed = true;
            }
        }
        return progressed;
    }

    fn pathLocalAddress(self: *Endpoint, peer: net.IpAddress) net.IpAddress {
        _ = peer;
        return self.local_address;
    }

    fn firstCompatibleIpAddr(self: *Endpoint, peer: tr.NodeAddr) ?net.IpAddress {
        var it = peer.ipAddrs();
        while (it.next()) |ip| {
            if (sameAddressFamily(self.socket.address, ip)) return ip;
        }
        return null;
    }

    fn rememberRelayPeer(self: *Endpoint, cnx: *c.picoquic_cnx_t, peer: key.NodeId) tr.Error!void {
        for (self.relay_peers.items) |*entry| {
            if (entry.cnx == cnx) {
                entry.peer = peer;
                return;
            }
        }
        self.relay_peers.append(self.allocator, .{ .cnx = cnx, .peer = peer }) catch return error.OutOfMemory;
    }

    fn forgetRelayPeer(self: *Endpoint, cnx: *c.picoquic_cnx_t) void {
        var i: usize = 0;
        while (i < self.relay_peers.items.len) {
            if (self.relay_peers.items[i].cnx == cnx) {
                _ = self.relay_peers.swapRemove(i);
                return;
            }
            i += 1;
        }
    }

    fn relayPeerFor(self: *Endpoint, cnx: *c.picoquic_cnx_t) ?key.NodeId {
        for (self.relay_peers.items) |entry| {
            if (entry.cnx == cnx) return entry.peer;
        }
        return null;
    }

    fn bindRelayIncoming(self: *Endpoint, src: key.NodeId) tr.Error!void {
        var matched = false;
        var maybe_cnx: ?*c.picoquic_cnx_t = c.picoquic_get_first_cnx(self.quic);
        while (maybe_cnx) |cnx| : (maybe_cnx = c.picoquic_get_next_cnx(cnx)) {
            if (self.relayPeerFor(cnx)) |peer| {
                if (peer.eql(src)) matched = true;
            }
        }
        if (matched) return;

        maybe_cnx = c.picoquic_get_first_cnx(self.quic);
        while (maybe_cnx) |cnx| : (maybe_cnx = c.picoquic_get_next_cnx(cnx)) {
            if (c.picoquic_is_client(cnx) != 0) continue;
            if (self.relayPeerFor(cnx) != null) continue;
            try self.rememberRelayPeer(cnx, src);
            return;
        }
    }
};

const ConnectionImpl = struct {
    endpoint: *Endpoint,
    id: u64,
    cnx: *c.picoquic_cnx_t,
    remote: key.NodeId,
    alpn_storage: [64]u8 = undefined,
    alpn_len: usize = 0,
    closed: bool = false,
    remote_closed: bool = false,
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

const SendImpl = stream_mod.SendImpl;
const RecvImpl = stream_mod.RecvImpl;

/// Runs on the event loop (synchronous inside picoquic_incoming_packet): the
/// callback mutates loop-owned tables directly and never blocks.
fn callback(cnx: ?*c.picoquic_cnx_t, stream_id: u64, bytes: [*c]u8, length: usize, event: c.picoquic_call_back_event_t, callback_ctx: ?*anyopaque, stream_ctx: ?*anyopaque) callconv(.c) c_int {
    _ = stream_ctx;
    const endpoint: *Endpoint = @ptrCast(@alignCast(callback_ctx.?));
    if (endpoint.stopping) return 0;
    if (event == c.picoquic_callback_stream_data or event == c.picoquic_callback_stream_fin) {
        const stream = endpoint.streamFor(cnx.?, stream_id) orelse return -1;
        if (length > 0) stream.recvq.append(endpoint.allocator, bytes[0..length]) catch return -1;
        if (event == c.picoquic_callback_stream_fin) stream.fin = true;
    } else if (event == c.picoquic_callback_stream_reset) {
        const stream = endpoint.streamFor(cnx.?, stream_id) orelse return -1;
        stream.reset = true;
    } else if (event == c.picoquic_callback_stop_sending) {
        // RFC 9000 S3.5: acknowledge the peer's receive-side abort by
        // resetting our sending half (legacy parity).
        if (c.picoquic_reset_stream(cnx.?, stream_id, 0) != 0) return -1;
    } else if (event == c.picoquic_callback_close or
        event == c.picoquic_callback_application_close or
        event == c.picoquic_callback_stateless_reset)
    {
        // The cnx is dying (remote close, or the synchronous delete-time
        // callback from our own picoquic_delete_cnx): sweep all Zig state
        // tied to it. Idempotent. picoquic owns deletion for server cnxs.
        endpoint.noteCnxDead(cnx.?);
    }
    return 0;
}

// =============================================================================
// Vtable adapters — thin command submitters. None of these touch picoquic.
// =============================================================================

pub fn submit(endpoint: *Endpoint, command: Command, node: *Command.Node) void {
    node.command = command;
    endpoint.inbox.submit(endpoint.io_inst, node);
}

/// Close every live connection (Endpoint-close composition). Runs inside the
/// loop; the caller blocks until each connection has been through
/// closeConnImpl (CONNECTION_CLOSE queued + flushed) — so on return the
/// peer-observable teardown has already been emitted, matching the per-conn
/// close order. Connection handles stay valid: they read as closed and a
/// later per-conn close is a no-op.
pub fn closeAllConnections(endpoint: *Endpoint) void {
    var completion: Completion(void) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(endpoint, .{ .close_all_conns = .{ .completion = &completion } }, &node);
    completion.awaitResult(endpoint.io_inst);
}

fn alpnSelectFn(quic: ?*c.picoquic_quic_t, list: ?[*]c.picoquic_iovec_t, count: usize) callconv(.c) usize {
    if (quic == null or list == null or count == 0) return count;
    const ctx = c.picoquic_get_default_callback_context(quic);
    if (ctx == null) return count;
    const endpoint: *Endpoint = @ptrCast(@alignCast(ctx));
    // Prefer endpoint preference order (server_alpns), matching first client offer that is registered.
    for (endpoint.server_alpns.items) |owned| {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const offered = list.?[i];
            if (offered.base == null or offered.len == 0) continue;
            const bytes = offered.base[0..offered.len];
            if (std.mem.eql(u8, bytes, owned)) return i;
        }
    }
    return count; // no match → reject (picoquic treats count as "none")
}

fn freeServerAlpns(self: *Endpoint) void {
    for (self.server_alpns.items) |owned| self.allocator.free(owned);
    self.server_alpns.clearRetainingCapacity();
}

fn replaceServerAlpns(self: *Endpoint, alpns: []const []const u8) SetAlpnsError!void {
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
        const copy = try self.allocator.dupe(u8, a);
        next.appendAssumeCapacity(copy);
    }
    freeServerAlpns(self);
    self.server_alpns.deinit(self.allocator);
    self.server_alpns = next;
}

/// Replace the server-advertised ALPN set (affects NEW inbound handshakes only).
pub fn setAlpns(self: *Endpoint, alpns: []const []const u8) SetAlpnsError!void {
    if (self.loop_future == null) return error.EndpointClosed;
    var completion: Completion(SetAlpnsResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    // Copy slice headers onto the stack command; bytes must remain valid until completion.
    submit(self, .{ .set_alpns = .{ .alpns = alpns, .completion = &completion } }, &node);
    return completion.awaitResult(self.io_inst);
}

pub fn setRelay(self: *Endpoint, relay: relay_fallback.Client) tr.Error!void {
    var completion: Completion(VoidResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(self, .{ .set_relay = .{ .relay = relay, .completion = &completion } }, &node);
    return completion.awaitResult(self.io_inst);
}

pub fn tryAcceptReady(endpoint: *Endpoint) tr.Error!?tr.Connection {
    var completion: Completion(PollAcceptResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(endpoint, .{ .poll_accept = .{ .completion = &completion } }, &node);
    return completion.awaitResult(endpoint.io_inst);
}

pub fn connectionIsClosed(conn: tr.Connection) bool {
    const impl: *ConnectionImpl = @ptrCast(@alignCast(conn.context));
    var completion: Completion(bool) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(impl.endpoint, .{ .connection_closed = .{ .conn_id = impl.id, .completion = &completion } }, &node);
    return completion.awaitResult(impl.endpoint.io_inst);
}

pub fn connectionSelectedPath(conn: tr.Connection) ?path_observability.SelectedPath {
    const impl: *ConnectionImpl = @ptrCast(@alignCast(conn.context));
    var completion: Completion(SelectedPathResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(impl.endpoint, .{ .selected_path = .{ .conn_id = impl.id, .completion = &completion } }, &node);
    return completion.awaitResult(impl.endpoint.io_inst);
}

pub fn connectionNextInboundUniEvent(conn: tr.Connection, buffer: []u8) tr.Error!?uni_poll.InboundUniEvent {
    const impl: *ConnectionImpl = @ptrCast(@alignCast(conn.context));
    var completion: Completion(PollInboundUniResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(impl.endpoint, .{ .poll_inbound_uni = .{ .conn_id = impl.id, .buffer = buffer, .completion = &completion } }, &node);
    return completion.awaitResult(impl.endpoint.io_inst);
}

fn endpointConnect(ctx: *anyopaque, peer: tr.NodeAddr) tr.Error!tr.Connection {
    const endpoint: *Endpoint = @ptrCast(@alignCast(ctx));
    var completion: Completion(ConnectResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(endpoint, .{ .connect = .{ .peer = peer, .completion = &completion } }, &node);
    return completion.awaitResult(endpoint.io_inst);
}

fn endpointAccept(ctx: *anyopaque) tr.Error!tr.Connection {
    const endpoint: *Endpoint = @ptrCast(@alignCast(ctx));
    var completion: Completion(AcceptResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(endpoint, .{ .accept = .{ .completion = &completion } }, &node);
    return completion.awaitResult(endpoint.io_inst);
}

fn endpointLocal(ctx: *anyopaque) tr.NodeId {
    const endpoint: *Endpoint = @ptrCast(@alignCast(ctx));
    return endpoint.node_id;
}

fn endpointIo(ctx: *anyopaque) std.Io {
    const endpoint: *Endpoint = @ptrCast(@alignCast(ctx));
    return endpoint.io_inst;
}

const endpoint_vtable: tr.Transport.VTable = .{
    .connect = endpointConnect,
    .accept = endpointAccept,
    .localNodeId = endpointLocal,
    .io = endpointIo,
};

fn connOpenBi(ctx: *anyopaque) tr.Error!tr.BiStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    var completion: Completion(OpenBiResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(conn.endpoint, .{ .open_bi = .{ .conn_id = conn.id, .completion = &completion } }, &node);
    return completion.awaitResult(conn.endpoint.io_inst);
}

fn connAcceptBi(ctx: *anyopaque) tr.Error!tr.BiStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    var completion: Completion(AcceptBiResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(conn.endpoint, .{ .accept_bi = .{ .conn_id = conn.id, .completion = &completion } }, &node);
    return completion.awaitResult(conn.endpoint.io_inst);
}

fn connOpenUni(ctx: *anyopaque) tr.Error!tr.SendStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    var completion: Completion(OpenUniResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(conn.endpoint, .{ .open_uni = .{ .conn_id = conn.id, .completion = &completion } }, &node);
    return completion.awaitResult(conn.endpoint.io_inst);
}

fn connAcceptUni(ctx: *anyopaque) tr.Error!tr.RecvStream {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    var completion: Completion(AcceptUniResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(conn.endpoint, .{ .accept_uni = .{ .conn_id = conn.id, .completion = &completion } }, &node);
    return completion.awaitResult(conn.endpoint.io_inst);
}

fn connRemote(ctx: *anyopaque) tr.NodeId {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    return conn.remote;
}

fn connClose(ctx: *anyopaque) void {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    var completion: Completion(void) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(conn.endpoint, .{ .close_conn = .{ .conn_id = conn.id, .completion = &completion } }, &node);
    completion.awaitResult(conn.endpoint.io_inst);
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

fn connRemoteAddress(ctx: *anyopaque) ?net.IpAddress {
    const conn: *ConnectionImpl = @ptrCast(@alignCast(ctx));
    var sa: [*c]c.struct_sockaddr = null;
    c.picoquic_get_peer_addr(conn.cnx, &sa);
    if (sa == null) return null;
    return ipFromSockaddrPtr(sa) catch null;
}

const connection_vtable: tr.Connection.VTable = .{
    .openBi = connOpenBi,
    .acceptBi = connAcceptBi,
    .openUni = connOpenUni,
    .acceptUni = connAcceptUni,
    .remoteNodeId = connRemote,
    .alpn = connAlpn,
    .remoteAddress = connRemoteAddress,
    .close = connClose,
    .io = connIo,
};

const send_vtable = stream_mod.send_vtable;
const recv_vtable = stream_mod.recv_vtable;

fn sockaddrFromIp(address: net.IpAddress) c.struct_sockaddr_storage {
    var storage = std.mem.zeroes(c.struct_sockaddr_storage);
    switch (address) {
        .ip4 => |ip4| {
            const sin: *c.struct_sockaddr_in = @ptrCast(@alignCast(&storage));
            sin.* = .{
                .sin_family = c.AF_INET,
                .sin_port = std.mem.nativeToBig(u16, ip4.port),
                .sin_addr = .{ .s_addr = std.mem.nativeToBig(u32, std.mem.readInt(u32, &ip4.bytes, .big)) },
                .sin_zero = [_]u8{0} ** 8,
            };
        },
        .ip6 => |ip6| {
            const sin6: *c.struct_sockaddr_in6 = @ptrCast(@alignCast(&storage));
            sin6.* = std.mem.zeroes(c.struct_sockaddr_in6);
            sin6.sin6_family = c.AF_INET6;
            sin6.sin6_port = std.mem.nativeToBig(u16, ip6.port);
            sin6.sin6_flowinfo = ip6.flow;
            @memcpy(@as([*]u8, @ptrCast(&sin6.sin6_addr))[0..16], &ip6.bytes);
            sin6.sin6_scope_id = ip6.interface.index;
        },
    }
    return storage;
}

fn ipFromSockaddr(storage: c.struct_sockaddr_storage) !net.IpAddress {
    const sa: *const c.struct_sockaddr = @ptrCast(@alignCast(&storage));
    return ipFromSockaddrPtr(sa);
}

fn ipFromSockaddrPtr(sa: *const c.struct_sockaddr) !net.IpAddress {
    switch (sa.sa_family) {
        c.AF_INET => {
            const sin: *const c.struct_sockaddr_in = @ptrCast(@alignCast(sa));
            const addr_be = std.mem.bigToNative(u32, sin.sin_addr.s_addr);
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, addr_be, .big);
            return .{ .ip4 = .{ .bytes = bytes, .port = std.mem.bigToNative(u16, sin.sin_port) } };
        },
        c.AF_INET6 => {
            const sin6: *const c.struct_sockaddr_in6 = @ptrCast(@alignCast(sa));
            var bytes: [16]u8 = undefined;
            @memcpy(&bytes, @as([*]const u8, @ptrCast(&sin6.sin6_addr))[0..16]);
            return .{ .ip6 = .{
                .bytes = bytes,
                .port = std.mem.bigToNative(u16, sin6.sin6_port),
                .flow = sin6.sin6_flowinfo,
                .interface = .{ .index = sin6.sin6_scope_id },
            } };
        },
        else => return error.AddressFamilyUnsupported,
    }
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

fn sameAddressFamily(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => b == .ip4,
        .ip6 => b == .ip6,
    };
}

fn sameIpAddress(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| a4.port == b4.port and std.mem.eql(u8, &a4.bytes, &b4.bytes),
            .ip6 => false,
        },
        .ip6 => |a6| switch (b) {
            .ip4 => false,
            .ip6 => |b6| a6.port == b6.port and
                a6.flow == b6.flow and
                a6.interface.index == b6.interface.index and
                std.mem.eql(u8, &a6.bytes, &b6.bytes),
        },
    };
}

// =============================================================================
// Tests (actor style — no caller-side pumping; the loops drive everything)
// =============================================================================

fn acceptConn(t: tr.Transport) tr.Error!tr.Connection {
    return t.accept();
}

test "greenfield endpoint direct QUIC echo stability N=200" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{41} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{42} ** 32);
    const alpn: [:0]const u8 = "iroh-g2-greenfield";
    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    for (0..200) |i| {
        echoRound(client_ep, server_ep, server_key, i) catch |err| {
            std.debug.print("N=200 iteration {d} failed: {s}\n", .{ i, @errorName(err) });
            return err;
        };
    }
}

test "greenfield endpoint IPv6 loopback direct QUIC echo" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x61} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x62} ** 32);
    const alpn: [:0]const u8 = "iroh-g2-ipv6-loopback";
    const client_ep = Endpoint.initOptions(allocator, std.testing.io, client_key, alpn, .{
        .bind_address = .{ .ip6 = .loopback(0) },
    }) catch |err| switch (err) {
        error.AddressFamilyUnsupported,
        error.AddressUnavailable,
        error.ProtocolUnsupportedBySystem,
        error.ProtocolUnsupportedByAddressFamily,
        => return error.SkipZigTest,
        else => return err,
    };
    defer client_ep.deinit();
    const server_ep = Endpoint.initOptions(allocator, std.testing.io, server_key, alpn, .{
        .bind_address = .{ .ip6 = .loopback(0) },
    }) catch |err| switch (err) {
        error.AddressFamilyUnsupported,
        error.AddressUnavailable,
        error.ProtocolUnsupportedBySystem,
        error.ProtocolUnsupportedByAddressFamily,
        => return error.SkipZigTest,
        else => return err,
    };
    defer server_ep.deinit();

    try std.testing.expect(server_ep.localAddress() == .ip6);
    try echoRound(client_ep, server_ep, server_key, 0);
}

test "IPv4 endpoint uses compatible address after IPv6 candidate" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x63} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x64} ** 32);
    const alpn: [:0]const u8 = "iroh-g2-family-select";
    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    errdefer _ = accept_future.cancel(std.testing.io) catch {};
    const client_conn = try client_ep.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{
            .{ .ip = .{ .ip6 = .loopback(server_ep.localAddress().getPort()) } },
            .{ .ip = server_ep.localAddress() },
        },
    });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();
    try std.testing.expect(client_conn.remoteNodeId().eql(server_key.public()));
}

test "IPv4 endpoint rejects IPv6-only peer without breaking endpoint" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x65} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x66} ** 32);
    const alpn: [:0]const u8 = "iroh-g2-family-reject";
    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    try std.testing.expectError(error.NotConnected, client_ep.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = .{ .ip6 = .loopback(server_ep.localAddress().getPort()) } }},
    }));

    try echoRound(client_ep, server_ep, server_key, 1);
}

fn echoRound(client_ep: *Endpoint, server_ep: *Endpoint, server_key: key.SecretKey, i: usize) !void {
    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    errdefer _ = accept_future.cancel(std.testing.io) catch {};
    const client_conn = client_ep.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = server_ep.localAddress() }},
    }) catch |err| {
        std.debug.print("  stage=connect err={s}\n", .{@errorName(err)});
        return err;
    };
    errdefer client_conn.close();
    const server_conn = accept_future.await(std.testing.io) catch |err| {
        std.debug.print("  stage=accept err={s}\n", .{@errorName(err)});
        return err;
    };
    errdefer server_conn.close();

    try std.testing.expect(client_conn.remoteNodeId().eql(server_key.public()));
    try std.testing.expect(server_conn.remoteNodeId().eql(client_ep.node_id));

    const client_stream = client_conn.openBi() catch |err| {
        std.debug.print("  stage=openBi err={s}\n", .{@errorName(err)});
        return err;
    };
    var payload: [32]u8 = undefined;
    const text = try std.fmt.bufPrint(&payload, "ping-{d}", .{i});
    try client_stream.send.writer().writeAll(text);
    try client_stream.send.finish();

    const server_stream = server_conn.acceptBi() catch |err| {
        std.debug.print("  stage=acceptBi err={s}\n", .{@errorName(err)});
        return err;
    };
    var buf: [32]u8 = undefined;
    const n = try server_stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings(text, buf[0..n]);

    try server_stream.send.writer().writeAll("pong");
    try server_stream.send.finish();
    var reply: [8]u8 = undefined;
    const m = client_stream.recv.reader().readSliceShort(&reply) catch |err| {
        std.debug.print("  stage=readReply err={s}\n", .{@errorName(err)});
        return err;
    };
    try std.testing.expectEqualStrings("pong", reply[0..m]);

    client_conn.close();
    server_conn.close();
}

test "greenfield recvReader survives peer stream reset without process abort" {
    // Fault injection: the peer RESETS after handoff; reader()
    // must degrade to EndOfStream and the endpoint must stay up.
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xE1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xE2} ** 32);
    const alpn: [:0]const u8 = "iroh-g2-recv-reset";

    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    // Deliver data WITHOUT FIN so the accept hands off, then RESET.
    const client_stream = try client_conn.openBi();
    try client_stream.send.writer().writeAll("x");
    try client_stream.send.flush();
    const server_stream = try server_conn.acceptBi();
    client_stream.send.reset();

    const reader = server_stream.recv.reader();
    var scratch: [8]u8 = undefined;
    const n = try reader.readSliceShort(&scratch);
    try std.testing.expectEqual(@as(usize, 0), n);

    // The endpoint stays up: a fresh stream on the same pair still echoes.
    const second = try client_conn.openBi();
    try second.send.writer().writeAll("still-up");
    try second.send.finish();
    const server_second = try server_conn.acceptBi();
    var buf: [16]u8 = undefined;
    const k = try server_second.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("still-up", buf[0..k]);
}

test "server close after peer close does not double-free the cnx" {
    // Regression for the picoquic server-auto-delete trap (verified
    // sender.c:3806-3815): a remote-closed SERVER cnx is deleted by picoquic
    // itself; doCloseConn must not close/delete it again. Under the C
    // sanitizer build (test-safe-c) a double-free/UAF aborts; in a plain
    // build the endpoint's continued health is the signal.
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xD1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xD2} ** 32);
    const alpn: [:0]const u8 = "iroh-g2-peer-close-first";
    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    // Peer (client) closes FIRST.
    client_conn.close();

    // Wait until the server side has observed the death (remote_closed gates
    // new opens), i.e. the close callback + death sweep ran.
    const deadline = c.picoquic_current_time() + 5 * std.time.us_per_s;
    while (c.picoquic_current_time() < deadline) {
        if (server_conn.openBi()) |_| {
            return error.TestUnexpectedResult;
        } else |err| switch (err) {
            error.NotConnected => break,
            else => return err,
        }
        std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake) catch {};
    } else {
        return error.TestExpectedRemoteClosed;
    }

    // Let the auto-delete fire (the loop keeps pumping over the disconnected
    // server cnx), THEN close the server handle: the remote-closed-server
    // path must skip picoquic_close/delete_cnx entirely.
    std.Io.sleep(std.testing.io, .fromMilliseconds(100), .awake) catch {};
    server_conn.close();

    // The engine is still sane: a fresh connection succeeds.
    var accept2 = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client2 = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client2.close();
    const server2 = try accept2.await(std.testing.io);
    defer server2.close();
    try std.testing.expect(server2.remoteNodeId().eql(client_key.public()));
}

test "parked acceptBi is failed promptly when the peer closes" {
    // Death-sweep: a waiter parked on a cnx must complete with ConnectionLost
    // when the cnx dies, not stall to the 15s stream-open timeout.
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xD3} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xD4} ** 32);
    const alpn: [:0]const u8 = "iroh-g2-accept-sweep";
    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    const accept_bi = struct {
        fn run(conn: tr.Connection) tr.Error!tr.BiStream {
            return conn.acceptBi();
        }
    };
    var parked = std.testing.io.async(accept_bi.run, .{server_conn});
    client_conn.close();
    // Either the waiter was parked before the death (ConnectionLost from the
    // death sweep) or the death landed first (NotConnected from the liveness
    // gate) — both prove the waiter was failed promptly, not stalled 15s.
    const result = parked.await(std.testing.io);
    if (result) |_| {
        return error.TestUnexpectedResult;
    } else |err| switch (err) {
        error.ConnectionLost, error.NotConnected => {},
        else => return err,
    }
}

test "writes past the staging water-mark are wire-visible without flush" {
    // Deliberate semantic (journaled GOOD drift, M2 parity review #1): the
    // zero-copy send writer drains its staging buffer into the loop when it
    // fills (16 KiB), so a write larger than the water-mark reaches the peer
    // BEFORE any flush() — the water-mark shape + iroh's
    // send-as-you-go semantics. Legacy buffers until flush()/finish(); the
    // greenfield does not, and `flush()` remains the explicit "submit now" for
    // sub-water-mark writes. This pins the documented behavior so the
    // divergence is a decision, not an accident.
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xE5} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xE6} ** 32);
    const alpn: [:0]const u8 = "iroh-g2-watermark";
    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    const stream = try client_conn.openBi();
    // 32 KiB with NO flush() — spills the 16 KiB staging buffer twice.
    var payload: [32 * 1024]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i *% 2654435761 >> 13);
    try stream.send.writer().writeAll(&payload);

    // The server's acceptBi hands off on the first drained bytes (no flush,
    // no FIN), and the reader yields them.
    const server_stream = try server_conn.acceptBi();
    var buf: [1024]u8 = undefined;
    const n = try server_stream.recv.reader().readSliceShort(&buf);
    try std.testing.expect(n > 0);
    try std.testing.expectEqualSlices(u8, payload[0..n], buf[0..n]);
}

test "concurrent callers on one endpoint are serialized by the loop" {
    // Caveat (b) resolved: exclusivity is structural. Many tasks may submit
    // commands to one endpoint concurrently; nothing races (the old model
    // forbade this by caller convention only).
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xC1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xC2} ** 32);
    const alpn: [:0]const u8 = "iroh-g2-concurrent";
    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.init(allocator, std.testing.io, server_key, alpn);
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    // Two concurrent openBi + echo drivers on ONE connection from two tasks.
    const driver = struct {
        fn run(conn: tr.Connection, peer: tr.Connection, tag: []const u8) !u8 {
            const stream = try conn.openBi();
            try stream.send.writer().writeAll(tag);
            try stream.send.finish();
            const other = try peer.acceptBi();
            var buf: [16]u8 = undefined;
            const n = try other.recv.reader().readSliceShort(&buf);
            try std.testing.expectEqual(@as(usize, 1), n);
            return buf[0];
        }
    };
    var f1 = std.testing.io.async(driver.run, .{ client_conn, server_conn, "a" });
    var f2 = std.testing.io.async(driver.run, .{ client_conn, server_conn, "b" });
    const r1 = f1.await(std.testing.io);
    const r2 = f2.await(std.testing.io);
    const received = [_]u8{ try r1, try r2 };
    var count_a: usize = 0;
    var count_b: usize = 0;
    for (received) |tag| switch (tag) {
        'a' => count_a += 1,
        'b' => count_b += 1,
        else => return error.UnexpectedTag,
    };
    try std.testing.expectEqual(@as(usize, 1), count_a);
    try std.testing.expectEqual(@as(usize, 1), count_b);
}

test "receive-stall timeout degrades the reader and closes the conn (deferred)" {
    // The recv_read stall deadline fires: the reader degrades to EOF and the
    // connection is closed via the deferred pending_close path (a recv_read
    // timeout must not re-enter the waiter list mid-iteration — the close is
    // acted on after the waiter loop).
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xD5} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xD6} ** 32);
    const alpn: [:0]const u8 = "iroh-g2-recv-stall";
    const client_ep = try Endpoint.init(allocator, std.testing.io, client_key, alpn);
    defer client_ep.deinit();
    const server_ep = try Endpoint.initOptions(allocator, std.testing.io, server_key, alpn, .{
        .stream_fin_timeout_us = 200 * std.time.us_per_ms,
    });
    defer server_ep.deinit();

    var accept_future = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client_conn = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client_conn.close();
    const server_conn = try accept_future.await(std.testing.io);
    defer server_conn.close();

    // Deliver data WITHOUT FIN, then go silent past the stall deadline.
    const stream = try client_conn.openBi();
    try stream.send.writer().writeAll("partial");
    try stream.send.flush();
    const server_stream = try server_conn.acceptBi();

    var buf: [16]u8 = undefined;
    const n = try server_stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("partial", buf[0..n]);

    // The stream stalls (no more data, no FIN): the next read hits the stall
    // deadline and degrades to EOF instead of hanging.
    const m = try server_stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqual(@as(usize, 0), m);

    // The stall closed the connection (deferred pending_close): later opens
    // fail fast, and the waiter list is left consistent.
    try std.testing.expectError(error.NotConnected, server_conn.openBi());

    // The endpoint stays up: a fresh connection still echoes.
    var accept2 = std.testing.io.async(acceptConn, .{server_ep.transport()});
    const client2 = try client_ep.transport().connect(.{ .id = server_key.public(), .addrs = &.{.{ .ip = server_ep.localAddress() }} });
    defer client2.close();
    const server2 = try accept2.await(std.testing.io);
    defer server2.close();
    try std.testing.expect(server2.remoteNodeId().eql(client_key.public()));
}
