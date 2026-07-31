//! DERP relay server — accept connections, authenticate, route packets.
//!
//! Reference: `iroh/iroh-relay/src/server/`

const std = @import("std");
const builtin = @import("builtin");
const key = @import("../key.zig");
const proto = @import("proto.zig");
const handshake = @import("handshake.zig");
const access = @import("access.zig");
const ws = @import("ws.zig");
const tls_wrapper = @import("tls_wrapper.zig");
const relay_client = @import("client.zig");
const metrics_mod = @import("metrics.zig");

pub const AccessDecision = access.AccessDecision;
pub const AccessControl = access.AccessControl;
pub const ClientRequest = access.ClientRequest;
pub const ConnKey = access.ConnKey;
pub const TokenAccessControl = access.TokenAccessControl;
pub const Metrics = metrics_mod.Metrics;

pub const MAX_CLIENTS = 1024;
/// Cap tracked destination peers per connection to bound memory growth.
pub const MAX_SENT_TO: usize = 256;
pub const DEFAULT_OUTBOUND_QUEUE_DEPTH: usize = 512;
/// Bound on a bearer token carried by the upgrade request (header line is
/// already capped at 2048 bytes; a longer token is a protocol error).
pub const MAX_AUTH_TOKEN_BYTES: usize = 1024;

var test_fail_next_handler_spawn = std.atomic.Value(bool).init(false);
var test_fail_next_keepalive_spawn = std.atomic.Value(bool).init(false);
/// Test-only barrier parked AFTER ACL onConnect (index insert + confirm) and
/// BEFORE `Clients.register`. Forces a revoke into the under-close window
/// deterministically (no timing races).
var test_mid_handshake_barrier_armed = std.atomic.Value(bool).init(false);
var test_mid_handshake_barrier_reached = std.atomic.Value(bool).init(false);
var test_mid_handshake_barrier_release = std.atomic.Value(bool).init(false);

fn failNextHandlerSpawnForTest() void {
    std.debug.assert(builtin.is_test);
    test_fail_next_handler_spawn.store(true, .release);
}

fn failNextKeepaliveSpawnForTest() void {
    std.debug.assert(builtin.is_test);
    test_fail_next_keepalive_spawn.store(true, .release);
}

fn takeFailNextHandlerSpawnForTest() bool {
    if (!builtin.is_test) return false;
    return test_fail_next_handler_spawn.swap(false, .acq_rel);
}

fn takeFailNextKeepaliveSpawnForTest() bool {
    if (!builtin.is_test) return false;
    return test_fail_next_keepalive_spawn.swap(false, .acq_rel);
}

fn armMidHandshakeRevokeBarrierForTest() void {
    std.debug.assert(builtin.is_test);
    test_mid_handshake_barrier_reached.store(false, .release);
    test_mid_handshake_barrier_release.store(false, .release);
    test_mid_handshake_barrier_armed.store(true, .release);
}

fn waitMidHandshakeBarrierReachedForTest(io: std.Io, timeout_ns: u64) bool {
    std.debug.assert(builtin.is_test);
    // Same poll pattern as waitForAtomicBool / waitForConnectionCount.
    const poll_ns: u64 = 5 * std.time.ns_per_ms;
    var elapsed: u64 = 0;
    while (elapsed < timeout_ns) {
        if (test_mid_handshake_barrier_reached.load(.acquire)) return true;
        Server.sleepNs(io, poll_ns) catch return false;
        elapsed += poll_ns;
    }
    return test_mid_handshake_barrier_reached.load(.acquire);
}

fn releaseMidHandshakeBarrierForTest() void {
    std.debug.assert(builtin.is_test);
    test_mid_handshake_barrier_release.store(true, .release);
}

/// Parks the handler thread when the mid-handshake revoke barrier is armed.
/// One-shot: the arm bit is consumed so only the targeted connection parks.
fn parkMidHandshakeBarrierForTest() void {
    if (!builtin.is_test) return;
    if (!test_mid_handshake_barrier_armed.swap(false, .acq_rel)) return;
    test_mid_handshake_barrier_reached.store(true, .release);
    while (!test_mid_handshake_barrier_release.load(.acquire)) {
        std.Thread.yield() catch {};
    }
}

pub const ServerConfig = struct {
    bind_host: []const u8 = "127.0.0.1",
    bind_port: u16 = 8080,
    tls_cert_path: ?[]const u8 = null,
    tls_key_path: ?[]const u8 = null,
    preauth_timeout_ns: u64 = 5 * std.time.ns_per_s,
    keepalive_interval_ns: u64 = 15 * std.time.ns_per_s,
    keepalive_jitter_ns: u64 = 5 * std.time.ns_per_s,
    pong_timeout_ns: u64 = 5 * std.time.ns_per_s,
    outbound_queue_depth: usize = DEFAULT_OUTBOUND_QUEUE_DEPTH,
    write_timeout_ns: u64 = 2 * std.time.ns_per_s,
    /// Runtime authorization hook (reference: `RelayConfig::access`, defaulting
    /// to upstream `AllowAll`). Null admits every authenticated client; set it
    /// to enforce admit/deny at handshake + disconnect notification.
    access_control: ?*const AccessControl = null,
    /// Per-connection receive rate limit — a token bucket that THROTTLES reads
    /// (never drops/disconnects; reference: upstream `[limits.client.rx]`,
    /// `server/streams.rs` Bucket). Null = unlimited.
    rx_bytes_per_second: ?u32 = null,
    /// Burst capacity; defaults to rate/10 when unset (upstream default).
    rx_max_burst_bytes: ?u32 = null,
};

const QueueClass = enum {
    packet,
    control,
};

pub const EnqueueResult = enum {
    accepted,
    missing,
    full,
    closed,
    encode_failed,
    tracking_failed,
};

const OutboundFrame = struct {
    op: ws.OpCode,
    payload: []u8,
    close_after: bool = false,
};

const FrameRing = struct {
    items: []OutboundFrame,
    head: usize = 0,
    len: usize = 0,

    fn isFull(self: *const FrameRing) bool {
        return self.len == self.items.len;
    }

    fn push(self: *FrameRing, frame: OutboundFrame) void {
        std.debug.assert(!self.isFull());
        self.items[(self.head + self.len) % self.items.len] = frame;
        self.len += 1;
    }

    fn pop(self: *FrameRing) ?OutboundFrame {
        if (self.len == 0) return null;
        const frame = self.items[self.head];
        self.head = (self.head + 1) % self.items.len;
        self.len -= 1;
        return frame;
    }

    fn clear(self: *FrameRing, allocator: std.mem.Allocator) void {
        while (self.pop()) |frame| allocator.free(frame.payload);
        self.head = 0;
    }
};

const OutboundQueue = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mu: std.Io.Mutex = .init,
    ready: std.Io.Condition = .init,
    accepting: bool = true,
    aborting: bool = false,
    packets: FrameRing,
    controls: FrameRing,
    accepted: std.atomic.Value(usize) = .init(0),
    sent: std.atomic.Value(usize) = .init(0),
    dropped_full: std.atomic.Value(usize) = .init(0),
    dropped_closed: std.atomic.Value(usize) = .init(0),
    dropped_encode: std.atomic.Value(usize) = .init(0),
    high_water: std.atomic.Value(usize) = .init(0),

    fn init(allocator: std.mem.Allocator, io: std.Io, depth: usize) !OutboundQueue {
        std.debug.assert(depth > 0);
        const packets = try allocator.alloc(OutboundFrame, depth);
        errdefer allocator.free(packets);
        const controls = try allocator.alloc(OutboundFrame, depth);
        return .{
            .allocator = allocator,
            .io = io,
            .packets = .{ .items = packets },
            .controls = .{ .items = controls },
        };
    }

    fn deinit(self: *OutboundQueue) void {
        self.abort();
        self.allocator.free(self.packets.items);
        self.allocator.free(self.controls.items);
        self.packets.items = &.{};
        self.controls.items = &.{};
    }

    fn enqueueOwned(self: *OutboundQueue, class: QueueClass, frame: OutboundFrame) EnqueueResult {
        self.mu.lockUncancelable(self.io);
        if (!self.accepting or self.aborting) {
            self.mu.unlock(self.io);
            self.allocator.free(frame.payload);
            _ = self.dropped_closed.fetchAdd(1, .monotonic);
            return .closed;
        }

        const ring = switch (class) {
            .packet => &self.packets,
            .control => &self.controls,
        };
        if (ring.isFull()) {
            self.mu.unlock(self.io);
            self.allocator.free(frame.payload);
            _ = self.dropped_full.fetchAdd(1, .monotonic);
            return .full;
        }

        ring.push(frame);
        const depth = self.packets.len + self.controls.len;
        const previous_high_water = self.high_water.load(.monotonic);
        if (depth > previous_high_water) self.high_water.store(depth, .monotonic);
        self.mu.unlock(self.io);
        _ = self.accepted.fetchAdd(1, .monotonic);
        self.ready.signal(self.io);
        return .accepted;
    }

    fn enqueueTerminal(self: *OutboundQueue, frame: OutboundFrame) EnqueueResult {
        self.mu.lockUncancelable(self.io);
        if (!self.accepting or self.aborting) {
            self.mu.unlock(self.io);
            self.allocator.free(frame.payload);
            _ = self.dropped_closed.fetchAdd(1, .monotonic);
            return .closed;
        }

        self.accepting = false;
        self.packets.clear(self.allocator);
        self.controls.clear(self.allocator);
        var terminal = frame;
        terminal.close_after = true;
        self.controls.push(terminal);
        self.mu.unlock(self.io);
        _ = self.accepted.fetchAdd(1, .monotonic);
        self.ready.signal(self.io);
        return .accepted;
    }

    fn take(self: *OutboundQueue) ?OutboundFrame {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        while (!self.aborting and self.controls.len == 0 and self.packets.len == 0) {
            if (!self.accepting) return null;
            self.ready.waitUncancelable(self.io, &self.mu);
        }
        if (self.aborting) return null;
        // Rust's biased client actor drains already-accepted packet messages
        // before general control messages. Preserve that cross-queue ordering
        // so EndpointGone/duplicate status cannot overtake packet backlog.
        return self.packets.pop() orelse self.controls.pop();
    }

    fn tryTake(self: *OutboundQueue) ?OutboundFrame {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (self.aborting) return null;
        return self.packets.pop() orelse self.controls.pop();
    }

    fn abort(self: *OutboundQueue) void {
        self.mu.lockUncancelable(self.io);
        self.accepting = false;
        self.aborting = true;
        self.packets.clear(self.allocator);
        self.controls.clear(self.allocator);
        self.mu.unlock(self.io);
        self.ready.broadcast(self.io);
    }
};

fn encodeRelayFrame(allocator: std.mem.Allocator, msg: proto.RelayToClientMsg) !OutboundFrame {
    var encoded: std.Io.Writer.Allocating = .init(allocator);
    defer encoded.deinit();
    try proto.encodeRelayToClient(msg, &encoded.writer);
    return .{ .op = .binary, .payload = try encoded.toOwnedSlice() };
}

fn writeDeadlineExpired(deadline_ns: u64, now_ns: u64) bool {
    return deadline_ns != 0 and now_ns >= deadline_ns;
}

fn handlerTicketEligible(ticket: u64, completed: u64) bool {
    // Wrapping distance keeps the bounded ticket window correct across u64
    // rollover (assuming fewer than 2^63 outstanding reservations).
    return ticket -% completed < @as(u64, MAX_CLIENTS);
}

pub const ClientConn = struct {
    mu: std.atomic.Mutex,
    refcount: std.atomic.Value(u32),
    stream: std.Io.net.Stream,
    io: std.Io,
    version: proto.ProtocolVersion,
    /// Process-unique id assigned before the access decision (reference:
    /// upstream `ConnectionId`); lets revocation target one physical
    /// connection among several sharing an endpoint.
    conn_id: u64,
    write_buf: [proto.MAX_FRAME_SIZE + 256]u8,
    writer: std.Io.net.Stream.Writer,
    alive: std.atomic.Value(bool),
    keepalive_ping: ?[8]u8,
    tls_server: ?*tls_wrapper.TlsServer,
    shutdown_started: std.atomic.Value(bool),
    outbound: OutboundQueue,
    write_timeout_ns: u64,
    write_deadline_ns: std.atomic.Value(u64),
    write_timeouts: std.atomic.Value(usize),
    /// Receive-side token bucket (rate 0 = unlimited). Owned by the
    /// clientLoop thread — the only thread that reads inbound frames.
    rx_rate_bytes: u32,
    rx_burst_bytes: u32,
    rx_tokens: i64,
    rx_last_refill_ns: i64,
    rx_limited_once: bool,

    pub fn create(
        allocator: std.mem.Allocator,
        stream: std.Io.net.Stream,
        io: std.Io,
        version: proto.ProtocolVersion,
        queue_depth: usize,
        write_timeout_ns: u64,
    ) !*ClientConn {
        var outbound = try OutboundQueue.init(allocator, io, queue_depth);
        errdefer outbound.deinit();
        const conn = try allocator.create(ClientConn);
        conn.* = .{
            .mu = .unlocked,
            .refcount = std.atomic.Value(u32).init(1),
            .stream = stream,
            .io = io,
            .version = version,
            .conn_id = 0,
            .write_buf = undefined,
            .writer = stream.writer(io, &[_]u8{}),
            .alive = std.atomic.Value(bool).init(true),
            .keepalive_ping = null,
            .tls_server = null,
            .shutdown_started = .init(false),
            .outbound = outbound,
            .write_timeout_ns = write_timeout_ns,
            .write_deadline_ns = .init(0),
            .write_timeouts = .init(0),
            .rx_rate_bytes = 0,
            .rx_burst_bytes = 0,
            .rx_tokens = 0,
            .rx_last_refill_ns = 0,
            .rx_limited_once = false,
        };
        return conn;
    }

    pub fn retain(self: *ClientConn) void {
        _ = self.refcount.fetchAdd(1, .acq_rel);
    }

    pub fn release(self: *ClientConn, allocator: std.mem.Allocator) void {
        if (self.refcount.fetchSub(1, .acq_rel) == 1) {
            self.deinit();
            allocator.destroy(self);
        }
    }

    pub fn deinit(self: *ClientConn) void {
        self.shutdown();
        self.outbound.deinit();
        if (self.tls_server) |ts| {
            ts.deinit();
            self.tls_server = null;
        } else {
            self.stream.close(self.io);
        }
    }

    fn isAlive(self: *const ClientConn) bool {
        return self.alive.load(.acquire);
    }

    fn markDead(self: *ClientConn) void {
        self.alive.store(false, .release);
    }

    fn shutdown(self: *ClientConn) void {
        self.markDead();
        if (!self.shutdown_started.swap(true, .acq_rel)) {
            // Raw shutdown is deliberately lock-free: it must wake a writer blocked
            // inside either the raw or TLS-backed stream path.
            self.stream.shutdown(self.io, .both) catch {};
        }
        self.outbound.abort();
    }

    fn hasKeepalivePing(self: *ClientConn) bool {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        return self.keepalive_ping != null;
    }

    fn setKeepalivePing(self: *ClientConn, ping: [8]u8) void {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        self.keepalive_ping = ping;
    }

    fn clearKeepalivePing(self: *ClientConn, pong: [8]u8) void {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        if (self.keepalive_ping) |kp| {
            if (std.mem.eql(u8, &kp, &pong)) self.keepalive_ping = null;
        }
    }

    fn writeFrame(self: *ClientConn, frame: OutboundFrame) !void {
        if (!self.isAlive()) return error.ClientDisconnected;
        if (self.tls_server) |ts| {
            const tw = ts.writer();
            try ws.writeFrame(self.io, tw, frame.op, frame.payload, false);
            try tw.flush();
        } else {
            try ws.writeFrame(self.io, &self.writer.interface, frame.op, frame.payload, false);
            try self.writer.interface.flush();
        }
    }

    fn enqueueRelay(self: *ClientConn, msg: proto.RelayToClientMsg, class: QueueClass) EnqueueResult {
        const frame = encodeRelayFrame(self.outbound.allocator, msg) catch {
            _ = self.outbound.dropped_encode.fetchAdd(1, .monotonic);
            return .encode_failed;
        };
        return self.outbound.enqueueOwned(class, frame);
    }

    fn enqueueWsPong(self: *ClientConn, payload: []const u8) EnqueueResult {
        const owned = self.outbound.allocator.dupe(u8, payload) catch {
            _ = self.outbound.dropped_encode.fetchAdd(1, .monotonic);
            return .encode_failed;
        };
        return self.outbound.enqueueOwned(.control, .{ .op = .pong, .payload = owned });
    }

    fn enqueueClose(self: *ClientConn, payload: []const u8) EnqueueResult {
        const owned = self.outbound.allocator.dupe(u8, payload) catch {
            _ = self.outbound.dropped_encode.fetchAdd(1, .monotonic);
            return .encode_failed;
        };
        return self.outbound.enqueueTerminal(.{ .op = .close, .payload = owned });
    }

    fn enqueueStatus(self: *ClientConn, status: proto.Status) EnqueueResult {
        var unknown_buf: [64]u8 = undefined;
        const msg: proto.RelayToClientMsg = switch (self.version) {
            .v1 => .{ .health = switch (status) {
                .healthy => "The connection is healthy and has recovered from previous problems",
                .same_endpoint_id_connected => "Another endpoint connected with the same endpoint id. No more messages will be received.",
                _ => std.fmt.bufPrint(
                    &unknown_buf,
                    "Unsupported health message ({d})",
                    .{@intFromEnum(status)},
                ) catch return .encode_failed,
            } },
            .v2 => .{ .status = status },
        };
        return self.enqueueRelay(msg, .control);
    }

    fn startWriter(self: *ClientConn, allocator: std.mem.Allocator) !std.Thread {
        self.retain();
        errdefer self.release(allocator);
        return std.Thread.spawn(.{}, writerThread, .{ self, allocator });
    }

    fn writerThread(self: *ClientConn, allocator: std.mem.Allocator) void {
        defer self.release(allocator);
        while (self.outbound.take()) |frame| {
            defer self.outbound.allocator.free(frame.payload);
            self.armWriteDeadline();
            self.writeFrame(frame) catch {
                self.write_deadline_ns.store(0, .release);
                self.shutdown();
                return;
            };
            self.write_deadline_ns.store(0, .release);
            _ = self.outbound.sent.fetchAdd(1, .monotonic);
            if (frame.close_after) {
                self.shutdown();
                return;
            }
        }
    }

    fn armWriteDeadline(self: *ClientConn) void {
        const timestamp = std.Io.Clock.now(.awake, self.io).nanoseconds;
        const now: u64 = if (timestamp <= 0) 0 else @intCast(timestamp);
        const deadline = std.math.add(u64, now, self.write_timeout_ns) catch std.math.maxInt(u64);
        self.write_deadline_ns.store(deadline, .release);
    }

    fn checkWriteTimeout(self: *ClientConn) bool {
        const deadline = self.write_deadline_ns.load(.acquire);
        if (deadline == 0) return self.isAlive();
        const timestamp = std.Io.Clock.now(.awake, self.io).nanoseconds;
        const now: u64 = if (timestamp <= 0) 0 else @intCast(timestamp);
        if (!writeDeadlineExpired(deadline, now)) return self.isAlive();
        if (self.write_deadline_ns.cmpxchgStrong(deadline, 0, .acq_rel, .acquire) == null) {
            _ = self.write_timeouts.fetchAdd(1, .monotonic);
            self.shutdown();
            return false;
        }
        return self.isAlive();
    }
};

const ClientStateRemoval = union(enum) {
    not_found,
    inactive_removed,
    promoted: *ClientConn,
    final,
};

const ClientState = struct {
    active: *ClientConn,
    /// Older physical connections, in activation order. Promotion is LIFO.
    inactive: std.ArrayListUnmanaged(*ClientConn) = .empty,
    /// Endpoint-lifetime destinations, retained across active-socket replacement.
    sent_to: std.ArrayListUnmanaged(key.PublicKey) = .empty,

    fn deinit(self: *ClientState, allocator: std.mem.Allocator) void {
        self.inactive.deinit(allocator);
        self.sent_to.deinit(allocator);
    }

    fn replaceActive(
        self: *ClientState,
        allocator: std.mem.Allocator,
        conn: *ClientConn,
    ) !*ClientConn {
        const old = self.active;
        try self.inactive.append(allocator, old);
        self.active = conn;
        return old;
    }

    fn removeConnection(self: *ClientState, conn: *ClientConn) ClientStateRemoval {
        if (self.active == conn) {
            if (self.inactive.pop()) |promoted| {
                self.active = promoted;
                return .{ .promoted = promoted };
            }
            return .final;
        }
        for (self.inactive.items, 0..) |inactive, i| {
            if (inactive == conn) {
                _ = self.inactive.orderedRemove(i);
                return .inactive_removed;
            }
        }
        return .not_found;
    }
};

const UnregisterAction = union(enum) {
    none,
    inactive_removed,
    promoted,
    /// Owned by the caller, which notifies peers and then deinitializes it.
    final: std.ArrayListUnmanaged(key.PublicKey),
};

pub const Clients = struct {
    mu: std.atomic.Mutex,
    map: std.AutoHashMapUnmanaged(key.PublicKey, ClientState),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, _: std.Io) Clients {
        return .{
            .mu = .unlocked,
            .map = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Clients) void {
        var it = self.map.valueIterator();
        while (it.next()) |state| state.deinit(self.allocator);
        self.map.deinit(self.allocator);
    }

    pub fn count(self: *Clients) usize {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        return self.map.count();
    }

    pub fn closeAll(self: *Clients) void {
        var snapshot: [MAX_CLIENTS]*ClientConn = undefined;
        var snapshot_len: usize = 0;
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr;
            const physical = 1 + state.inactive.items.len;
            std.debug.assert(snapshot_len + physical <= snapshot.len);
            state.active.retain();
            snapshot[snapshot_len] = state.active;
            snapshot_len += 1;
            for (state.inactive.items) |conn| {
                conn.retain();
                snapshot[snapshot_len] = conn;
                snapshot_len += 1;
            }
        }
        self.mu.unlock();

        for (snapshot[0..snapshot_len]) |conn| {
            conn.shutdown();
            conn.release(self.allocator);
        }
    }

    pub fn register(
        self: *Clients,
        pk: key.PublicKey,
        conn: *ClientConn,
        running: *const std.atomic.Value(bool),
    ) !void {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        // Serialized with closeAll: once deinit publishes stopped, no client can
        // enter the registry after the shutdown snapshot.
        if (!running.load(.acquire)) return error.ServerStopped;
        const gop = try self.map.getOrPut(self.allocator, pk);
        if (gop.found_existing) {
            const old = try gop.value_ptr.replaceActive(self.allocator, conn);
            // Queue transition status while the endpoint entry is still
            // serialized. Packets accepted before demotion stay ahead of the
            // status; later routing sees only the new active connection.
            _ = old.enqueueStatus(.same_endpoint_id_connected);
            return;
        }
        gop.value_ptr.* = .{ .active = conn };
    }

    fn unregister(self: *Clients, pk: key.PublicKey, conn: *ClientConn) UnregisterAction {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        const state = self.map.getPtr(pk) orelse return .none;
        return switch (state.removeConnection(conn)) {
            .not_found => .none,
            .inactive_removed => .inactive_removed,
            .promoted => |promoted| blk: {
                // Queue Healthy under the same endpoint lock that performed
                // promotion. A later duplicate therefore queues Duplicate
                // after Healthy and cannot leave an inactive client stale-healthy.
                _ = promoted.enqueueStatus(.healthy);
                break :blk .promoted;
            },
            .final => blk: {
                var removed = self.map.fetchRemove(pk) orelse unreachable;
                std.debug.assert(removed.value.inactive.items.len == 0);
                removed.value.inactive.deinit(self.allocator);
                const sent_to = removed.value.sent_to;
                removed.value.sent_to = .empty;
                break :blk .{ .final = sent_to };
            },
        };
    }

    pub fn contains(self: *Clients, pk: key.PublicKey) bool {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        return self.map.contains(pk);
    }

    /// Disconnects the one connection registered for `pk` with `conn_id`
    /// (active or an inactive duplicate; connection ids are process-unique, so
    /// at most one matches). Reference: upstream
    /// `Clients::disconnect(endpoint_id, Some(connection_id))`. Returns false
    /// when nothing matched.
    ///
    /// Follows `closeAll`'s discipline: the match is found and `retain()`ed
    /// under the lock, `shutdown()` + `release()` happen after the unlock, and
    /// the map entry is NOT removed here — the connection's handler `defer
    /// clients.unregister(...)` owns removal, promotion, and `EndpointGone`.
    pub fn disconnect(self: *Clients, pk: key.PublicKey, conn_id: u64) bool {
        var target: ?*ClientConn = null;
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        if (self.map.getPtr(pk)) |state| {
            if (state.active.conn_id == conn_id) {
                target = state.active;
            } else {
                for (state.inactive.items) |conn| {
                    if (conn.conn_id == conn_id) {
                        target = conn;
                        break;
                    }
                }
            }
            if (target) |conn| conn.retain();
        }
        self.mu.unlock();

        const conn = target orelse return false;
        conn.shutdown();
        conn.release(self.allocator);
        return true;
    }

    fn sendTo(self: *Clients, pk: key.PublicKey, msg: proto.RelayToClientMsg, class: QueueClass) EnqueueResult {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        const conn = (self.map.getPtr(pk) orelse return .missing).active;
        // Encoding + bounded try-enqueue are nonblocking with respect to the
        // network. Keeping the endpoint lock closes the select/demote race and
        // matches Rust's entry-lock + try_send ordering.
        return conn.enqueueRelay(msg, class);
    }

    fn sendFromTo(
        self: *Clients,
        src: key.PublicKey,
        dst: key.PublicKey,
        msg: proto.RelayToClientMsg,
    ) EnqueueResult {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();

        const src_state = self.map.getPtr(src) orelse return .missing;
        var already_recorded = false;
        for (src_state.sent_to.items) |pk| {
            if (pk.eql(dst)) {
                already_recorded = true;
                break;
            }
        }

        const should_record = !already_recorded and src_state.sent_to.items.len < MAX_SENT_TO;
        if (should_record) {
            // Reserve tracking storage before delivery. A packet is therefore
            // never accepted and then followed by an OOM that disconnects the
            // source or silently loses its final EndpointGone obligation.
            src_state.sent_to.ensureUnusedCapacity(self.allocator, 1) catch
                return .tracking_failed;
        }

        const dst_conn = (self.map.getPtr(dst) orelse return .missing).active;
        const result = dst_conn.enqueueRelay(msg, .packet);
        if (result == .accepted and should_record) src_state.sent_to.appendAssumeCapacity(dst);
        return result;
    }
};

pub const Server = struct {
    listener: std.Io.net.Server,
    io: std.Io,
    clients: Clients,
    allocator: std.mem.Allocator,
    running: std.atomic.Value(bool),
    lifecycle_mu: std.atomic.Mutex,
    /// Detached accept handlers still in flight; deinit waits until zero.
    active_handlers: std.atomic.Value(u64),
    /// Fair admission tickets bound accepted/preauth/authenticated physical
    /// handlers without making a full server return/log-spin.
    next_handler_ticket: std.atomic.Value(u64),
    completed_handler_tickets: std.atomic.Value(u64),
    /// Process-unique connection ids (reference: upstream `ConnectionId::next`),
    /// assigned before the access decision so admit/disconnect indexing and
    /// token revocation can target individual physical connections.
    next_connection_id: std.atomic.Value(u64),
    config: ServerConfig,
    /// Operator counters (see metrics.zig; rendered at the `/metrics`
    /// endpoint). Plain atomics — the hot-path cost is one fetchAdd.
    metrics: Metrics,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, config: ServerConfig) !Server {
        if ((config.tls_cert_path == null) != (config.tls_key_path == null)) {
            return error.InvalidTlsConfig;
        }
        if (config.preauth_timeout_ns == 0) return error.InvalidPreauthTimeout;
        if (config.outbound_queue_depth == 0) return error.InvalidOutboundQueueDepth;
        if (config.write_timeout_ns == 0) return error.InvalidWriteTimeout;
        if (config.rx_bytes_per_second == null and config.rx_max_burst_bytes != null)
            return error.InvalidRateLimitConfig;
        if (config.rx_bytes_per_second) |rate| {
            if (rate == 0) return error.InvalidRateLimitConfig;
            if (config.rx_max_burst_bytes) |burst| {
                if (burst == 0) return error.InvalidRateLimitConfig;
            }
        }
        const addr = try std.Io.net.IpAddress.parse(config.bind_host, config.bind_port);
        const listener = try addr.listen(io, .{
            .reuse_address = true,
            .kernel_backlog = 64,
        });
        return .{
            .listener = listener,
            .io = io,
            .clients = Clients.init(allocator, io),
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(true),
            .lifecycle_mu = .unlocked,
            .active_handlers = std.atomic.Value(u64).init(0),
            .next_handler_ticket = .init(0),
            .completed_handler_tickets = .init(0),
            .next_connection_id = .init(1),
            .config = config,
            .metrics = .{},
        };
    }

    /// Stops accepting and disconnects every client, but does NOT release
    /// resources: safe to call from a signal-watcher thread while the accept
    /// loop is still running (idempotent). `deinit` calls this internally;
    /// call it early only to begin draining before the full teardown.
    pub fn initiateShutdown(self: *Server) void {
        while (!self.lifecycle_mu.tryLock()) std.Thread.yield() catch {};
        const was_running = self.running.load(.acquire);
        self.running.store(false, .release);
        self.lifecycle_mu.unlock();
        if (!was_running) return;
        // Closing a listening fd from another thread need not wake a blocking
        // accept. The std accept contract explicitly makes shutdown the
        // concurrent cancellation mechanism.
        const listener_stream: std.Io.net.Stream = .{ .socket = self.listener.socket };
        listener_stream.shutdown(self.io, .both) catch {};
        self.clients.closeAll();
    }

    pub fn deinit(self: *Server) void {
        self.initiateShutdown();
        // Join-equivalent: neither the listener nor registry can be destroyed
        // while a reserved acceptor/handler may still dereference this Server.
        while (self.active_handlers.load(.acquire) > 0) {
            self.io.sleep(std.Io.Duration.fromMilliseconds(1), .real) catch {};
        }
        self.listener.deinit(self.io);
        self.clients.deinit();
    }

    pub fn localAddress(self: *Server) std.Io.net.IpAddress {
        return self.listener.socket.address;
    }

    /// Disconnects the one registered connection with `(endpoint_id, conn_id)`
    /// (reference: upstream `Clients::disconnect(endpoint_id, Some(id))` — the
    /// eviction half of token revocation). Returns false when nothing matched;
    /// teardown and unregistration complete asynchronously in the connection's
    /// own handler.
    pub fn disconnectConnection(self: *Server, endpoint_id: key.PublicKey, conn_id: u64) bool {
        return self.clients.disconnect(endpoint_id, conn_id);
    }

    pub fn acceptOne(self: *Server) !void {
        // The reservation covers the blocking accept so deinit cannot return
        // while an acceptor still dereferences this Server.
        try self.reserveHandlerSlot();
        defer self.releaseHandlerSlot();
        const stream = try self.listener.accept(self.io);
        self.handleClient(stream) catch {};
    }

    pub fn acceptAndSpawn(self: *Server) !void {
        // On success the reservation transfers exactly once to the spawned handler.
        try self.reserveHandlerSlot();
        errdefer self.releaseHandlerSlot();
        const stream = try self.listener.accept(self.io);
        errdefer stream.close(self.io);
        if (takeFailNextHandlerSpawnForTest()) return error.TestInjectedSpawnFailure;
        const thread = std.Thread.spawn(.{}, handleClientThread, .{ self, stream }) catch |err| {
            std.debug.print("[server] handler thread spawn failed after accept: {}\n", .{err});
            return err;
        };
        thread.detach();
    }

    fn handleClientThread(self: *Server, stream: std.Io.net.Stream) void {
        defer self.releaseHandlerSlot();
        self.handleClient(stream) catch {};
    }

    fn reserveHandlerSlot(self: *Server) !void {
        // Linearize admission with deinit's stopped publication. Once deinit
        // owns this mutex, no uncounted acceptor can appear after its wait.
        while (!self.lifecycle_mu.tryLock()) std.Thread.yield() catch {};
        if (!self.running.load(.acquire)) {
            self.lifecycle_mu.unlock();
            return error.ServerStopped;
        }
        _ = self.active_handlers.fetchAdd(1, .acq_rel);
        const ticket = self.next_handler_ticket.fetchAdd(1, .acq_rel);
        self.lifecycle_mu.unlock();
        errdefer _ = self.active_handlers.fetchSub(1, .acq_rel);

        while (true) {
            if (!self.running.load(.acquire)) return error.ServerStopped;
            const completed = self.completed_handler_tickets.load(.acquire);
            if (handlerTicketEligible(ticket, completed)) return;
            self.io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch
                std.Thread.yield() catch {};
        }
    }

    fn releaseHandlerSlot(self: *Server) void {
        _ = self.completed_handler_tickets.fetchAdd(1, .acq_rel);
        _ = self.active_handlers.fetchSub(1, .acq_rel);
    }

    fn handleClient(self: *Server, stream: std.Io.net.Stream) !void {
        var mutable_stream = stream;

        var tls_srv: ?*tls_wrapper.TlsServer = null;
        var handler_owns_transport = true;
        defer {
            if (handler_owns_transport) {
                if (tls_srv) |ts| {
                    ts.deinit();
                } else {
                    mutable_stream.close(self.io);
                }
            }
        }

        // TLS owns its buffering. Raw pre-auth only needs enough for the bounded
        // HTTP headers and small challenge/auth frames, not two maximum relay frames.
        var read_buf: ?[]u8 = null;
        defer if (read_buf) |buf| self.allocator.free(buf);
        var write_buf: ?[]u8 = null;
        defer if (write_buf) |buf| self.allocator.free(buf);

        var preauth_done = std.atomic.Value(bool).init(false);
        var preauth_timeout_t: ?std.Thread = try std.Thread.spawn(.{}, preauthTimeoutThread, .{
            mutable_stream,
            self.io,
            self.config.preauth_timeout_ns,
            &preauth_done,
            &self.running,
        });
        defer {
            preauth_done.store(true, .release);
            if (preauth_timeout_t) |thread| thread.join();
        }

        var raw_reader: std.Io.net.Stream.Reader = undefined;
        var raw_writer: std.Io.net.Stream.Writer = undefined;

        var reader: *std.Io.Reader = undefined;
        var writer: *std.Io.Writer = undefined;

        if (self.config.tls_cert_path != null and self.config.tls_key_path != null) {
            tls_srv = tls_wrapper.TlsServer.accept(self.allocator, self.io, stream, self.config.tls_cert_path.?, self.config.tls_key_path.?) catch |err| {
                std.debug.print("[server] TLS handshake failed: {}\n", .{err});
                return;
            };
            reader = tls_srv.?.reader();
            writer = tls_srv.?.writer();
        } else {
            read_buf = try self.allocator.alloc(u8, 16 * 1024);
            write_buf = try self.allocator.alloc(u8, 4096);
            raw_reader = mutable_stream.reader(self.io, read_buf.?);
            raw_writer = mutable_stream.writer(self.io, write_buf.?);
            reader = &raw_reader.interface;
            writer = &raw_writer.interface;
        }

        const connection_id = self.next_connection_id.fetchAdd(1, .acq_rel);
        var token_buf: [MAX_AUTH_TOKEN_BYTES]u8 = undefined;
        const upgrade = try self.wsServerUpgrade(reader, writer, &token_buf);
        const version = upgrade.version;
        var ws_decoder: ws.Decoder = .{};
        const node_id = try self.challengeHandshake(reader, writer, &ws_decoder, connection_id, upgrade.auth_token, version);
        // Admitted: notify the policy exactly once when this connection ends,
        // on every exit path past this point (reference: upstream
        // `OnDisconnectGuard`). Installed before the register defer below, so
        // it fires AFTER unregister — matching upstream's actor-then-guard drop
        // order.
        var notify_disconnect = self.config.access_control != null;
        defer if (notify_disconnect) {
            notify_disconnect = false;
            self.config.access_control.?.onDisconnect(node_id, connection_id);
        };
        preauth_done.store(true, .release);
        if (preauth_timeout_t) |thread| {
            thread.join();
            preauth_timeout_t = null;
        }

        if (!self.running.load(.acquire)) return error.ServerStopped;
        const conn = try ClientConn.create(
            self.allocator,
            stream,
            self.io,
            version,
            self.config.outbound_queue_depth,
            self.config.write_timeout_ns,
        );
        conn.conn_id = connection_id;
        defer conn.release(self.allocator);

        // Receive rate limiter (token bucket, throttle-not-drop; upstream
        // `[limits.client.rx]`). Starts full so a well-behaved client never
        // notices it.
        if (self.config.rx_bytes_per_second) |rate| {
            conn.rx_rate_bytes = rate;
            conn.rx_burst_bytes = self.config.rx_max_burst_bytes orelse @max(rate / 10, 1);
            conn.rx_tokens = conn.rx_burst_bytes;
            const now_ts = std.Io.Clock.now(.awake, self.io).nanoseconds;
            conn.rx_last_refill_ns = if (now_ts <= 0) 0 else @intCast(now_ts);
        }

        if (tls_srv) |ts| {
            conn.tls_server = ts;
            tls_srv = null;
        } else {
            conn.writer = mutable_stream.writer(self.io, &conn.write_buf);
        }
        handler_owns_transport = false;

        // Deterministic test hook: park AFTER ACL admission (onConnect inside
        // challengeHandshake) and BEFORE Clients.register so a revoke can be
        // forced into the under-close window without relying on timing.
        parkMidHandshakeBarrierForTest();

        try self.clients.register(node_id, conn, &self.running);
        _ = self.metrics.accepts.fetchAdd(1, .monotonic);
        var registered = true;
        defer {
            conn.shutdown();
            if (registered) {
                registered = false;
                _ = self.metrics.disconnects.fetchAdd(1, .monotonic);
                switch (self.clients.unregister(node_id, conn)) {
                    .none, .inactive_removed => {},
                    .promoted => {},
                    .final => |owned_sent_to| {
                        var sent_to = owned_sent_to;
                        defer sent_to.deinit(self.allocator);
                        for (sent_to.items) |peer_pk| {
                            _ = self.clients.sendTo(peer_pk, .{ .endpoint_gone = node_id }, .control);
                        }
                    },
                }
            }
        }

        // ServerConfirmsAuth goes out only NOW — AFTER Clients.register, so a
        // client that observes the confirmation is always registered and
        // routable (relay_reverse_interop: a real Rust client sends datagrams
        // immediately after connect()) — and BEFORE the writer thread starts,
        // so this direct write is race-free.
        var confirm_buf: [8]u8 = undefined;
        var confirm_writer = std.Io.Writer.fixed(&confirm_buf);
        try handshake.encodeServerConfirmsAuth(.{}, &confirm_writer);
        try ws.writeFrame(self.io, writer, .binary, confirm_writer.buffered(), false);
        try writer.flush();

        // Post-register ACL revalidation (fail-closed). Closes the race where
        // revoke removes the ACL index entry and Clients.disconnect no-ops
        // because the connection was not registered yet — then register would
        // admit a connection under a now-revoked token with no index entry for
        // a later revoke to find.
        //
        // Happens-before under the two locks (ACL.mu + Clients.mu):
        //   handler order:  Clients.register  THEN  stillTracked (ACL)
        //   revoke  order:  ACL-index-remove  THEN  Clients.disconnect
        // For any interleaving either stillTracked sees the entry gone (we
        // tear down here) or register preceded disconnect (disconnect finds
        // the registered conn and shuts it down). No residual window.
        //
        // Ordering note (relay_reverse_interop): the confirmation above means
        // a mid-handshake revoke is observed by the client as
        // confirm-then-teardown, matching upstream's accept-then-insert order.
        if (self.config.access_control) |control| {
            if (!control.stillTracked(node_id, connection_id)) {
                return error.AccessRevokedDuringHandshake;
            }
        }

        const writer_t = try conn.startWriter(self.allocator);
        defer {
            conn.shutdown();
            writer_t.join();
        }

        if (takeFailNextKeepaliveSpawnForTest()) return error.TestInjectedSpawnFailure;
        const keepalive_t = std.Thread.spawn(.{}, keepaliveThread, .{
            conn,
            self.io,
            self.config.keepalive_interval_ns,
            self.config.keepalive_jitter_ns,
            self.config.pong_timeout_ns,
        }) catch |err| {
            std.debug.print("[server] keepalive thread spawn failed after register: {}\n", .{err});
            return err;
        };
        defer {
            conn.shutdown();
            keepalive_t.join();
        }

        const frame_buf = try self.allocator.alloc(u8, proto.MAX_FRAME_SIZE);
        defer self.allocator.free(frame_buf);

        self.clientLoop(conn, node_id, reader, frame_buf, &ws_decoder) catch {};
    }

    /// Result of the WebSocket upgrade: the negotiated protocol version plus
    /// the bearer token the client presented (reference: upstream
    /// `ClientRequest::auth_token` — first `Authorization: Bearer` header,
    /// else the `token` URL query parameter). `auth_token` slices the
    /// caller-owned `token_buf`; it is null when the client presented none.
    ///
    /// Divergence (documented): the query fallback is compared raw — upstream
    /// percent-decodes query pairs. Percent-encoded query tokens are not used
    /// by the iroh client (it sends the `Authorization` header), so this only
    /// matters for hand-rolled clients with exotic tokens.
    pub const WsUpgrade = struct {
        version: proto.ProtocolVersion,
        auth_token: ?[]const u8,
    };

    pub fn wsServerUpgrade(
        _: *Server,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        token_buf: []u8,
    ) !WsUpgrade {
        var ws_key_buf: [128]u8 = undefined;
        var ws_key_len: ?usize = null;
        var negotiated: ?proto.ProtocolVersion = null;
        var saw_valid_request = false;
        var saw_host = false;
        var saw_upgrade = false;
        var saw_connection_upgrade = false;
        var bearer_token: ?[]const u8 = null;
        var target_buf: [2048]u8 = undefined;
        var target_len: usize = 0;
        var saw_version_header = false;
        var saw_version_13 = false;
        var line_index: usize = 0;
        var total_header_bytes: usize = 0;

        while (true) {
            var hdr_line: [2048]u8 = undefined;
            var hdr_len: usize = 0;
            var terminated = false;
            while (hdr_len < hdr_line.len) {
                const b = reader.takeByte() catch return error.ProtocolError;
                hdr_line[hdr_len] = b;
                hdr_len += 1;
                if (hdr_len >= 2 and hdr_line[hdr_len - 2] == '\r' and hdr_line[hdr_len - 1] == '\n') {
                    terminated = true;
                    break;
                }
            }
            if (!terminated) return error.ProtocolError;
            total_header_bytes += hdr_len;
            if (total_header_bytes > 16 * 1024) return error.ProtocolError;
            if (hdr_len <= 2) break;
            const h = hdr_line[0 .. hdr_len - 2];
            if (line_index == 0) {
                saw_valid_request = validRelayUpgradeRequest(h);
                // Keep the request target: the `token` query parameter is the
                // auth-token fallback when no Bearer header arrives (headers
                // follow the request line, so the decision waits until the end).
                if (requestTarget(h)) |target| {
                    if (target.len > target_buf.len) return error.ProtocolError;
                    @memcpy(target_buf[0..target.len], target);
                    target_len = target.len;
                }
                line_index += 1;
                continue;
            }
            line_index += 1;
            if (httpHeaderValue(h, "host")) |value| {
                if (saw_host or value.len == 0) return error.ProtocolError;
                saw_host = true;
            } else if (httpHeaderValue(h, "upgrade")) |value| {
                saw_upgrade = saw_upgrade or httpValueContainsToken(value, "websocket");
            } else if (httpHeaderValue(h, "connection")) |value| {
                saw_connection_upgrade = saw_connection_upgrade or httpValueContainsToken(value, "upgrade");
            } else if (httpHeaderValue(h, "sec-websocket-version")) |value| {
                if (saw_version_header) return error.ProtocolError;
                saw_version_header = true;
                saw_version_13 = std.mem.eql(u8, value, "13");
            } else if (httpHeaderValue(h, "sec-websocket-key")) |value| {
                if (ws_key_len != null) return error.ProtocolError;
                if (value.len > ws_key_buf.len) return error.ProtocolError;
                @memcpy(ws_key_buf[0..value.len], value);
                ws_key_len = value.len;
            } else if (httpHeaderValue(h, "sec-websocket-protocol")) |value| {
                if (negotiateProtocol(value)) |candidate| {
                    if (negotiated == null or @intFromEnum(candidate) > @intFromEnum(negotiated.?)) {
                        negotiated = candidate;
                    }
                }
            } else if (httpHeaderValue(h, "authorization")) |value| {
                // First Bearer-scheme header wins; other schemes are skipped
                // (upstream `ClientRequest::auth_token`).
                if (bearer_token == null) {
                    if (bearerToken(value)) |token| {
                        if (token.len > token_buf.len) return error.ProtocolError;
                        @memcpy(token_buf[0..token.len], token);
                        bearer_token = token_buf[0..token.len];
                    }
                }
            }
        }

        const key_len = ws_key_len orelse return error.ProtocolError;
        const key_str = ws_key_buf[0..key_len];
        if (!saw_valid_request or !saw_host or !saw_upgrade or !saw_connection_upgrade or !saw_version_13) {
            return error.ProtocolError;
        }
        if (!validWebSocketKey(key_str)) return error.ProtocolError;
        const selected = negotiated orelse return error.ProtocolError;

        var accept_encoded: [28]u8 = undefined;
        const accept_val = ws.computeAccept(key_str, &accept_encoded);

        try writer.writeAll("HTTP/1.1 101 Switching Protocols\r\n");
        try writer.writeAll("Upgrade: websocket\r\n");
        try writer.writeAll("Connection: Upgrade\r\n");
        try writer.print("Sec-WebSocket-Accept: {s}\r\n", .{accept_val});
        try writer.print("Sec-WebSocket-Protocol: {s}\r\n", .{selected.toString()});
        try writer.writeAll("\r\n");
        try writer.flush();

        // No Bearer header: fall back to the `token` URL query parameter.
        if (bearer_token == null) {
            if (queryToken(target_buf[0..target_len])) |token| {
                if (token.len > token_buf.len) return error.ProtocolError;
                @memcpy(token_buf[0..token.len], token);
                bearer_token = token_buf[0..token.len];
            }
        }

        return .{ .version = selected, .auth_token = bearer_token };
    }

    /// Authenticates (challenge/response) and AUTHORIZES the client, but does
    /// NOT send `ServerConfirmsAuth`: the caller confirms only AFTER the
    /// connection is registered in `Clients` (see handleClient), so a client
    /// that observes the confirmation is always routable. A real Rust client
    /// sends datagrams immediately after `connect()` returns; confirming
    /// before registration opens a window where those datagrams hit a not-yet
    /// -registered destination and are silently dropped (caught by the
    /// relay_reverse_interop oracle row).
    pub fn challengeHandshake(
        self: *Server,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        decoder: *ws.Decoder,
        connection_id: u64,
        auth_token: ?[]const u8,
        version: proto.ProtocolVersion,
    ) !key.PublicKey {
        var challenge: [16]u8 = undefined;
        self.io.random(&challenge);

        var sc_buf: [32]u8 = undefined;
        var sc_writer = std.Io.Writer.fixed(&sc_buf);
        try handshake.encodeServerChallenge(.{ .challenge = challenge }, &sc_writer);
        try ws.writeFrame(self.io, writer, .binary, sc_writer.buffered(), false);
        try writer.flush();

        var frame_buf: [256]u8 = undefined;
        var auth_frame: ws.ReadFrameResult = undefined;
        while (true) {
            const candidate = decoder.readFrame(reader, &frame_buf, .server) catch return error.HandshakeFailed;
            switch (candidate.op) {
                .binary => {
                    auth_frame = candidate;
                    break;
                },
                .ping => {
                    ws.writeFrame(self.io, writer, .pong, candidate.payload, false) catch
                        return error.HandshakeFailed;
                    writer.flush() catch return error.HandshakeFailed;
                },
                .pong => {},
                .close => {
                    ws.writeFrame(self.io, writer, .close, candidate.payload, false) catch {};
                    writer.flush() catch {};
                    return error.HandshakeFailed;
                },
                else => return error.HandshakeFailed,
            }
        }

        const frame = handshake.decodeHandshakeFrame(auth_frame.payload) catch return error.HandshakeFailed;
        if (frame != .client_auth) return error.HandshakeFailed;

        handshake.verifyClientAuth(frame.client_auth, challenge) catch {
            var deny_buf: [64]u8 = undefined;
            var deny_writer = std.Io.Writer.fixed(&deny_buf);
            handshake.encodeServerDeniesAuth(.{ .reason = "signature invalid" }, &deny_writer) catch
                return error.HandshakeFailed;
            ws.writeFrame(self.io, writer, .binary, deny_writer.buffered(), false) catch
                return error.HandshakeFailed;
            writer.flush() catch return error.HandshakeFailed;
            return error.HandshakeFailed;
        };

        // Authenticated; now AUTHORIZE (reference: upstream
        // `authorize_with` after `serverside` verification). A denial reuses
        // the EXISTING server_denies_auth frame — "not authorized" by default
        // (bad signatures keep "signature invalid" above); no new frame.
        if (self.config.access_control) |control| {
            const decision = control.onConnect(.{
                .connection_id = connection_id,
                .endpoint_id = frame.client_auth.public_key,
                .version = version,
                .auth_token = auth_token,
            });
            switch (decision) {
                .allow => {},
                .deny => |reason_opt| {
                    const reason = reason_opt orelse "not authorized";
                    var deny_buf: [512]u8 = undefined;
                    var deny_writer = std.Io.Writer.fixed(&deny_buf);
                    handshake.encodeServerDeniesAuth(.{ .reason = reason }, &deny_writer) catch
                        return error.HandshakeFailed;
                    ws.writeFrame(self.io, writer, .binary, deny_writer.buffered(), false) catch
                        return error.HandshakeFailed;
                    writer.flush() catch return error.HandshakeFailed;
                    return error.HandshakeFailed;
                },
            }
        }

        return frame.client_auth.public_key;
    }

    fn keepaliveThread(
        conn: *ClientConn,
        io: std.Io,
        interval_ns: u64,
        jitter_ns: u64,
        pong_timeout_ns: u64,
    ) void {
        var seed_buf: [8]u8 = undefined;
        io.random(&seed_buf);
        const seed = std.mem.readInt(u64, &seed_buf, .little);
        var prng = std.Random.DefaultPrng.init(seed);
        var rng = prng.random();

        while (conn.isAlive()) {
            const half = jitter_ns / 2;
            const jitter = if (half > 0) half + rng.intRangeLessThan(u64, 0, half) else 0;
            if (!interruptibleSleep(conn, interval_ns + jitter)) return;

            if (!conn.hasKeepalivePing()) {
                var pd: [8]u8 = undefined;
                rng.bytes(&pd);
                conn.setKeepalivePing(pd);
                switch (conn.enqueueRelay(.{ .ping = pd }, .control)) {
                    .accepted => {},
                    .closed => return,
                    else => {
                        conn.shutdown();
                        return;
                    },
                }
            }

            if (!interruptibleSleep(conn, pong_timeout_ns)) return;

            if (conn.hasKeepalivePing()) {
                conn.shutdown();
                return;
            }
        }
    }

    fn interruptibleSleep(conn: *ClientConn, total_ns: u64) bool {
        const chunk_ns: u64 = 10 * std.time.ns_per_ms;
        var remaining = total_ns;
        while (remaining > 0) {
            if (!conn.checkWriteTimeout()) return false;
            const sleep_ns = if (remaining < chunk_ns) remaining else chunk_ns;
            sleepNs(conn.io, sleep_ns) catch return false;
            remaining -= sleep_ns;
        }
        return conn.checkWriteTimeout();
    }

    fn preauthTimeoutThread(
        stream: std.Io.net.Stream,
        io: std.Io,
        timeout_ns: u64,
        done: *std.atomic.Value(bool),
        running: *std.atomic.Value(bool),
    ) void {
        const chunk_ns: u64 = 10 * std.time.ns_per_ms;
        var remaining = timeout_ns;
        while (remaining > 0) {
            if (done.load(.acquire)) return;
            if (!running.load(.acquire)) {
                stream.shutdown(io, .both) catch {};
                return;
            }
            const sleep_ns = if (remaining < chunk_ns) remaining else chunk_ns;
            sleepNs(io, sleep_ns) catch return;
            remaining -= sleep_ns;
        }
        if (!done.load(.acquire)) {
            stream.shutdown(io, .both) catch {};
        }
    }

    fn sleepNs(io: std.Io, ns: u64) std.Io.Cancelable!void {
        return io.sleep(std.Io.Duration.fromNanoseconds(@intCast(ns)), .awake);
    }

    fn clientLoop(
        self: *Server,
        conn: *ClientConn,
        node_id: key.PublicKey,
        reader: *std.Io.Reader,
        frame_buf: []u8,
        decoder: *ws.Decoder,
    ) !void {
        while (conn.isAlive()) {
            const result = decoder.readFrame(reader, frame_buf, .server) catch {
                conn.shutdown();
                return;
            };

            if (result.op == .close) {
                if (conn.enqueueClose(result.payload) != .accepted) {
                    conn.shutdown();
                    return;
                }
                while (conn.isAlive()) sleepNs(conn.io, std.time.ns_per_ms) catch return;
                return;
            }
            if (result.op == .ping) {
                if (conn.enqueueWsPong(result.payload) != .accepted) {
                    conn.shutdown();
                    return;
                }
                continue;
            }
            if (result.op == .pong) continue;
            if (result.op != .binary) continue;

            // Per-connection receive rate limit: throttle (sleep), never drop
            // or disconnect (upstream `server/streams.rs` Bucket semantics).
            self.rxThrottle(conn, result.payload.len);

            const msg = proto.decodeClientToRelay(result.payload, conn.version) catch return;
            switch (msg) {
                .datagram => |d| {
                    _ = self.metrics.send_packets_recv.fetchAdd(1, .monotonic);
                    _ = self.metrics.bytes_recv.fetchAdd(d.datagrams.contents.len, .monotonic);
                    self.forwardDatagram(node_id, d.dst, .{
                        .datagram = .{
                            .src = node_id,
                            .datagrams = d.datagrams,
                        },
                    }, d.datagrams.contents.len);
                },
                .datagram_batch => |d| {
                    _ = self.metrics.send_packets_recv.fetchAdd(1, .monotonic);
                    _ = self.metrics.bytes_recv.fetchAdd(d.datagrams.contents.len, .monotonic);
                    self.forwardDatagram(node_id, d.dst, .{
                        .datagram_batch = .{
                            .src = node_id,
                            .datagrams = d.datagrams,
                        },
                    }, d.datagrams.contents.len);
                },
                .ping => |p| {
                    _ = self.metrics.got_ping.fetchAdd(1, .monotonic);
                    if (conn.enqueueRelay(.{ .pong = p }, .control) != .accepted) {
                        conn.shutdown();
                        return;
                    }
                    _ = self.metrics.sent_pong.fetchAdd(1, .monotonic);
                },
                .pong => |p| {
                    conn.clearKeepalivePing(p);
                },
            }
        }
    }

    /// Token-bucket throttle for the per-connection receive rate limit.
    /// Called only from clientLoop (the bucket's owning thread).
    fn rxThrottle(self: *Server, conn: *ClientConn, cost: u64) void {
        if (conn.rx_rate_bytes == 0) return;
        const now_ts = std.Io.Clock.now(.awake, self.io).nanoseconds;
        const now: i64 = if (now_ts <= 0) 0 else @intCast(now_ts);
        const elapsed: u64 = @intCast(@max(now - conn.rx_last_refill_ns, 0));
        const refill: u64 = @intCast(@divTrunc(@as(u128, elapsed) * conn.rx_rate_bytes, std.time.ns_per_s));
        conn.rx_tokens = @min(conn.rx_tokens + @as(i64, @intCast(refill)), @as(i64, conn.rx_burst_bytes));
        conn.rx_last_refill_ns = now;
        if (conn.rx_tokens >= 0 and @as(u64, @intCast(conn.rx_tokens)) >= cost) {
            conn.rx_tokens -= @intCast(cost);
            return;
        }
        const deficit: u64 = cost - @as(u64, @intCast(@max(conn.rx_tokens, 0)));
        conn.rx_tokens = 0;
        _ = self.metrics.bytes_rx_ratelimited_total.fetchAdd(cost, .monotonic);
        if (!conn.rx_limited_once) {
            conn.rx_limited_once = true;
            _ = self.metrics.conns_rx_ratelimited_total.fetchAdd(1, .monotonic);
        }
        const wait_ns: u64 = @intCast(@divTrunc(@as(u128, deficit) * std.time.ns_per_s, conn.rx_rate_bytes));
        self.io.sleep(std.Io.Duration.fromNanoseconds(wait_ns), .awake) catch {};
        const end_ts = std.Io.Clock.now(.awake, self.io).nanoseconds;
        conn.rx_last_refill_ns = if (end_ts <= 0) 0 else @intCast(end_ts);
    }

    fn forwardDatagram(
        self: *Server,
        src: key.PublicKey,
        dst: key.PublicKey,
        msg: proto.RelayToClientMsg,
        payload_len: usize,
    ) void {
        switch (self.clients.sendFromTo(src, dst, msg)) {
            .accepted => {
                _ = self.metrics.send_packets_sent.fetchAdd(1, .monotonic);
                _ = self.metrics.bytes_sent.fetchAdd(payload_len, .monotonic);
            },
            else => _ = self.metrics.send_packets_dropped.fetchAdd(1, .monotonic),
        }
    }
};

fn validRelayUpgradeRequest(line: []const u8) bool {
    var fields = std.mem.splitScalar(u8, line, ' ');
    const method = fields.next() orelse return false;
    const target = fields.next() orelse return false;
    const version = fields.next() orelse return false;
    if (fields.next() != null) return false;
    const valid_target = std.mem.eql(u8, target, "/relay") or
        std.mem.startsWith(u8, target, "/relay?");
    return std.mem.eql(u8, method, "GET") and valid_target and
        std.mem.eql(u8, version, "HTTP/1.1");
}

/// The request target (second field) of an HTTP request line, or null.
fn requestTarget(line: []const u8) ?[]const u8 {
    var fields = std.mem.splitScalar(u8, line, ' ');
    _ = fields.next() orelse return null;
    return fields.next();
}

/// The token of a `Bearer`-scheme Authorization header value (scheme matched
/// case-insensitively; reference: upstream `ClientRequest::auth_token`).
fn bearerToken(value: []const u8) ?[]const u8 {
    const space = std.mem.indexOfScalar(u8, value, ' ') orelse return null;
    if (!std.ascii.eqlIgnoreCase(value[0..space], "bearer")) return null;
    const token = std.mem.trim(u8, value[space + 1 ..], " \t");
    if (token.len == 0) return null;
    return token;
}

/// The raw value of the `token` query parameter in a request target
/// (`/relay?token=abc&x=y`), or null. Not percent-decoded (see WsUpgrade).
fn queryToken(target: []const u8) ?[]const u8 {
    const query = target[std.mem.indexOfScalar(u8, target, '?') orelse return null ..][1..];
    var pairs = std.mem.splitScalar(u8, query, '&');
    while (pairs.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], "token")) {
            const token = pair[eq + 1 ..];
            if (token.len == 0) return null;
            return token;
        }
    }
    return null;
}

fn httpHeaderValue(line: []const u8, name: []const u8) ?[]const u8 {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    if (!std.ascii.eqlIgnoreCase(line[0..colon], name)) return null;
    return std.mem.trim(u8, line[colon + 1 ..], " \t");
}

fn httpValueContainsToken(value: []const u8, token: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |candidate| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, candidate, " \t"), token)) return true;
    }
    return false;
}

fn negotiateProtocol(value: []const u8) ?proto.ProtocolVersion {
    var selected: ?proto.ProtocolVersion = null;
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |candidate| {
        const token = std.mem.trim(u8, candidate, " \t");
        const version = proto.ProtocolVersion.fromString(token) orelse continue;
        if (selected == null or @intFromEnum(version) > @intFromEnum(selected.?)) {
            selected = version;
        }
    }
    return selected;
}

fn validWebSocketKey(value: []const u8) bool {
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(value) catch return false;
    if (decoded_len != 16) return false;
    var decoded: [16]u8 = undefined;
    std.base64.standard.Decoder.decode(&decoded, value) catch return false;
    return true;
}

const testing = std.testing;

test "Server struct compiles" {
    _ = Server;
    _ = ServerConfig;
    _ = Clients;
    _ = ClientConn;
    _ = ws;
}

test "outbound queue is bounded drop-newest FIFO with owned cleanup" {
    var queue = try OutboundQueue.init(testing.allocator, testing.io, 2);
    defer queue.deinit();

    try testing.expectEqual(EnqueueResult.accepted, queue.enqueueOwned(.packet, .{
        .op = .binary,
        .payload = try testing.allocator.dupe(u8, "one"),
    }));
    try testing.expectEqual(EnqueueResult.accepted, queue.enqueueOwned(.packet, .{
        .op = .binary,
        .payload = try testing.allocator.dupe(u8, "two"),
    }));
    try testing.expectEqual(EnqueueResult.full, queue.enqueueOwned(.packet, .{
        .op = .binary,
        .payload = try testing.allocator.dupe(u8, "dropped"),
    }));

    try testing.expectEqual(@as(usize, 2), queue.accepted.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), queue.dropped_full.load(.monotonic));
    try testing.expectEqual(@as(usize, 2), queue.high_water.load(.monotonic));

    const first = queue.tryTake().?;
    defer testing.allocator.free(first.payload);
    const second = queue.tryTake().?;
    defer testing.allocator.free(second.payload);
    try testing.expectEqualStrings("one", first.payload);
    try testing.expectEqualStrings("two", second.payload);
    try testing.expect(queue.tryTake() == null);
}

test "outbound queue preserves packet-before-control actor ordering" {
    var queue = try OutboundQueue.init(testing.allocator, testing.io, 1);
    defer queue.deinit();

    try testing.expectEqual(EnqueueResult.accepted, queue.enqueueOwned(.control, .{
        .op = .binary,
        .payload = try testing.allocator.dupe(u8, "endpoint-gone"),
    }));
    try testing.expectEqual(EnqueueResult.accepted, queue.enqueueOwned(.packet, .{
        .op = .binary,
        .payload = try testing.allocator.dupe(u8, "accepted-packet"),
    }));

    const packet = queue.tryTake().?;
    defer testing.allocator.free(packet.payload);
    const control = queue.tryTake().?;
    defer testing.allocator.free(control.payload);
    try testing.expectEqualStrings("accepted-packet", packet.payload);
    try testing.expectEqualStrings("endpoint-gone", control.payload);
}

test "outbound relay frame owns bytes borrowed from the reader buffer" {
    var queue = try OutboundQueue.init(testing.allocator, testing.io, 1);
    defer queue.deinit();

    const src = key.SecretKey.fromBytes(.{0x61} ** 32).public();
    var borrowed = [_]u8{ 1, 2, 3, 4 };
    const frame = try encodeRelayFrame(testing.allocator, .{ .datagram = .{
        .src = src,
        .datagrams = .{ .ecn = .not_ect, .segment_size = null, .contents = &borrowed },
    } });
    try testing.expectEqual(EnqueueResult.accepted, queue.enqueueOwned(.packet, frame));
    @memset(&borrowed, 0xff);

    const owned = queue.tryTake().?;
    defer testing.allocator.free(owned.payload);
    const decoded = try proto.decodeRelayToClient(owned.payload, .v2);
    try testing.expect(decoded == .datagram);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, decoded.datagram.datagrams.contents);
}

test "outbound terminal frame drops backlog and closes future enqueue" {
    var queue = try OutboundQueue.init(testing.allocator, testing.io, 2);
    defer queue.deinit();

    try testing.expectEqual(EnqueueResult.accepted, queue.enqueueOwned(.packet, .{
        .op = .binary,
        .payload = try testing.allocator.dupe(u8, "backlog"),
    }));
    try testing.expectEqual(EnqueueResult.accepted, queue.enqueueTerminal(.{
        .op = .close,
        .payload = try testing.allocator.dupe(u8, "terminal"),
    }));

    const terminal = queue.tryTake().?;
    defer testing.allocator.free(terminal.payload);
    try testing.expect(terminal.close_after);
    try testing.expectEqualStrings("terminal", terminal.payload);
    try testing.expect(queue.tryTake() == null);
    try testing.expectEqual(EnqueueResult.closed, queue.enqueueOwned(.packet, .{
        .op = .binary,
        .payload = try testing.allocator.dupe(u8, "late"),
    }));
    try testing.expectEqual(@as(usize, 1), queue.dropped_closed.load(.monotonic));
}

test "write timeout deadline is disabled at zero and expires at its boundary" {
    try testing.expect(!writeDeadlineExpired(0, std.math.maxInt(u64)));
    try testing.expect(!writeDeadlineExpired(101, 100));
    try testing.expect(writeDeadlineExpired(101, 101));
    try testing.expect(writeDeadlineExpired(101, 102));
}

test "handler admission tickets are bounded and released fairly" {
    try testing.expect(handlerTicketEligible(MAX_CLIENTS - 1, 0));
    try testing.expect(!handlerTicketEligible(MAX_CLIENTS, 0));
    try testing.expect(handlerTicketEligible(MAX_CLIENTS, 1));
    try testing.expect(!handlerTicketEligible(MAX_CLIENTS + 1, 1));
    try testing.expect(handlerTicketEligible(std.math.maxInt(u64), std.math.maxInt(u64)));
    try testing.expect(handlerTicketEligible(0, std.math.maxInt(u64)));
    try testing.expect(!handlerTicketEligible(MAX_CLIENTS - 1, std.math.maxInt(u64)));
}

test "server rejects invalid bounded-resource configuration" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();
    try testing.expectError(error.InvalidTlsConfig, Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .tls_cert_path = "cert.pem",
    }));
    try testing.expectError(error.InvalidTlsConfig, Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .tls_key_path = "key.pem",
    }));
    try testing.expectError(error.InvalidPreauthTimeout, Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .preauth_timeout_ns = 0,
    }));
    try testing.expectError(error.InvalidOutboundQueueDepth, Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .outbound_queue_depth = 0,
    }));
    try testing.expectError(error.InvalidWriteTimeout, Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .write_timeout_ns = 0,
    }));
}

test "websocket server HTTP helpers require exact request, tokens, key, and protocol" {
    try testing.expect(validRelayUpgradeRequest("GET /relay HTTP/1.1"));
    try testing.expect(validRelayUpgradeRequest("GET /relay?token=abc HTTP/1.1"));
    try testing.expect(!validRelayUpgradeRequest("POST /relay HTTP/1.1"));
    try testing.expect(!validRelayUpgradeRequest("GET /other HTTP/1.1"));
    try testing.expect(httpValueContainsToken("keep-alive, Upgrade", "upgrade"));
    try testing.expect(!httpValueContainsToken("not-an-upgrade", "upgrade"));
    try testing.expectEqual(proto.ProtocolVersion.v2, negotiateProtocol("iroh-relay-v1, iroh-relay-v2").?);
    try testing.expect(negotiateProtocol("evil-iroh-relay-v2") == null);
    try testing.expect(validWebSocketKey("dGhlIHNhbXBsZSBub25jZQ=="));
    try testing.expect(!validWebSocketKey("not-base64"));
}

test "websocket upgrade merges list headers and rejects duplicate singletons or missing Host" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();
    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();

    const accepted =
        "GET /relay HTTP/1.1\r\n" ++
        "Host: example.test\r\n" ++
        "Upgrade: h2c\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: iroh-relay-v1\r\n" ++
        "Sec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n";
    var accepted_reader = std.Io.Reader.fixed(accepted);
    var accepted_output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer accepted_output.deinit();
    var accepted_token_buf: [MAX_AUTH_TOKEN_BYTES]u8 = undefined;
    const accepted_upgrade = try server.wsServerUpgrade(&accepted_reader, &accepted_output.writer, &accepted_token_buf);
    try testing.expectEqual(proto.ProtocolVersion.v2, accepted_upgrade.version);
    try testing.expect(accepted_upgrade.auth_token == null);

    const duplicate_key =
        "GET /relay HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n";
    var duplicate_key_reader = std.Io.Reader.fixed(duplicate_key);
    var rejected_output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer rejected_output.deinit();
    var rejected_token_buf: [MAX_AUTH_TOKEN_BYTES]u8 = undefined;
    try testing.expectError(error.ProtocolError, server.wsServerUpgrade(&duplicate_key_reader, &rejected_output.writer, &rejected_token_buf));

    const duplicate_version =
        "GET /relay HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n";
    var duplicate_version_reader = std.Io.Reader.fixed(duplicate_version);
    try testing.expectError(error.ProtocolError, server.wsServerUpgrade(&duplicate_version_reader, &rejected_output.writer, &rejected_token_buf));

    const missing_host =
        "GET /relay HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n";
    var missing_host_reader = std.Io.Reader.fixed(missing_host);
    try testing.expectError(error.ProtocolError, server.wsServerUpgrade(&missing_host_reader, &rejected_output.writer, &rejected_token_buf));
}

test "invalid relay signature receives denial before close" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();
    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();
    const port = server.localAddress().getPort();

    const handler = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            srv.acceptOne() catch {};
        }
    }.run, .{&server});
    defer handler.join();

    const fd = try connectTcp(port);
    defer _ = std.os.linux.close(fd);
    try doWsUpgradeRaw(fd);

    var frame_buf: [256]u8 = undefined;
    const challenge_frame = try readWsFrame(fd, &frame_buf);
    try testing.expectEqual(ws.OpCode.binary, challenge_frame.op);
    const challenge = try handshake.decodeHandshakeFrame(challenge_frame.payload);
    try testing.expect(challenge == .server_challenge);

    const sk = key.SecretKey.fromBytes(.{0x71} ** 32);
    const auth = handshake.clientAuthFor(sk, .{0x99} ** 16);
    var auth_buf: [128]u8 = undefined;
    var auth_writer = std.Io.Writer.fixed(&auth_buf);
    try handshake.encodeClientAuth(auth, &auth_writer);
    try writeWsFrame(fd, auth_writer.buffered(), true);

    const denial_frame = try readWsFrame(fd, &frame_buf);
    const denial = try handshake.decodeHandshakeFrame(denial_frame.payload);
    try testing.expect(denial == .server_denies_auth);
    try testing.expectEqualStrings("signature invalid", denial.server_denies_auth.reason);
}

test "server echoes a valid WebSocket close through the outbound writer" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();
    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();
    const port = server.localAddress().getPort();

    const handler = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            srv.acceptOne() catch {};
        }
    }.run, .{&server});
    defer handler.join();

    const fd = try connectTcp(port);
    defer _ = std.os.linux.close(fd);
    try doWsUpgradeRaw(fd);
    try doClientHandshakeRaw(fd, key.SecretKey.fromBytes(.{0x72} ** 32));

    const normal_close = [_]u8{ 0x03, 0xe8 };
    try writeWsFrameOp(fd, .close, &normal_close, true);
    var frame_buf: [16]u8 = undefined;
    const echoed = try readWsFrame(fd, &frame_buf);
    try testing.expectEqual(ws.OpCode.close, echoed.op);
    try testing.expectEqualSlices(u8, &normal_close, echoed.payload);
}

test "server preserves fragmented auth and relay messages across interleaved WebSocket ping" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();
    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .keepalive_interval_ns = 3600 * std.time.ns_per_s,
        .pong_timeout_ns = 3600 * std.time.ns_per_s,
    });
    defer server.deinit();
    const port = server.localAddress().getPort();

    const handler = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            srv.acceptOne() catch {};
        }
    }.run, .{&server});
    defer handler.join();

    const fd = try connectTcp(port);
    defer _ = std.os.linux.close(fd);
    try doWsUpgradeRaw(fd);

    var frame_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
    const challenge_frame = try readWsFrame(fd, &frame_buf);
    const challenge = try handshake.decodeHandshakeFrame(challenge_frame.payload);
    try testing.expect(challenge == .server_challenge);

    const sk = key.SecretKey.fromBytes(.{0x73} ** 32);
    const auth = handshake.clientAuthFor(sk, challenge.server_challenge.challenge);
    var auth_buf: [256]u8 = undefined;
    var auth_writer = std.Io.Writer.fixed(&auth_buf);
    try handshake.encodeClientAuth(auth, &auth_writer);
    const encoded_auth = auth_writer.buffered();
    const auth_split = encoded_auth.len / 2;
    try writeWsFragment(fd, false, .binary, encoded_auth[0..auth_split], true);
    try writeWsFrameOp(fd, .ping, "preauth-control", true);
    const preauth_pong = try readWsFrame(fd, &frame_buf);
    try testing.expectEqual(ws.OpCode.pong, preauth_pong.op);
    try testing.expectEqualStrings("preauth-control", preauth_pong.payload);
    try writeWsFragment(fd, true, .continuation, encoded_auth[auth_split..], true);

    const confirm_frame = try readWsFrame(fd, &frame_buf);
    const confirm = try handshake.decodeHandshakeFrame(confirm_frame.payload);
    try testing.expect(confirm == .server_confirms_auth);

    const relay_ping = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var ping_buf: [32]u8 = undefined;
    var ping_writer = std.Io.Writer.fixed(&ping_buf);
    try proto.encodeClientToRelay(.{ .ping = relay_ping }, &ping_writer);
    const encoded_ping = ping_writer.buffered();
    const ping_split = encoded_ping.len / 2;
    try writeWsFragment(fd, false, .binary, encoded_ping[0..ping_split], true);
    try writeWsFrameOp(fd, .ping, "active-control", true);
    const active_pong = try readWsFrame(fd, &frame_buf);
    try testing.expectEqual(ws.OpCode.pong, active_pong.op);
    try testing.expectEqualStrings("active-control", active_pong.payload);
    try writeWsFragment(fd, true, .continuation, encoded_ping[ping_split..], true);

    const relay_pong_frame = try readWsFrame(fd, &frame_buf);
    const relay_pong = try proto.decodeRelayToClient(relay_pong_frame.payload, .v2);
    try testing.expect(relay_pong == .pong);
    try testing.expectEqual(relay_ping, relay_pong.pong);

    const normal_close = [_]u8{ 0x03, 0xe8 };
    try writeWsFrameOp(fd, .close, &normal_close, true);
    const echoed = try readWsFrame(fd, &frame_buf);
    try testing.expectEqual(ws.OpCode.close, echoed.op);
}

test "client state duplicate removal is exact and active promotion is LIFO" {
    var physical: [3]ClientConn = undefined;
    const c1 = &physical[0];
    const c2 = &physical[1];
    const c3 = &physical[2];
    var state: ClientState = .{ .active = c1 };
    defer state.deinit(testing.allocator);

    const destination = key.SecretKey.fromBytes(.{0x74} ** 32).public();
    try state.sent_to.append(testing.allocator, destination);
    try testing.expectEqual(c1, try state.replaceActive(testing.allocator, c2));
    try testing.expectEqual(c2, try state.replaceActive(testing.allocator, c3));
    try testing.expectEqualSlices(*ClientConn, &.{ c1, c2 }, state.inactive.items);

    try testing.expect(state.removeConnection(c1) == .inactive_removed);
    try testing.expectEqualSlices(*ClientConn, &.{c2}, state.inactive.items);
    const promoted = state.removeConnection(c3);
    try testing.expect(promoted == .promoted);
    try testing.expectEqual(c2, promoted.promoted);
    try testing.expectEqual(c2, state.active);
    try testing.expectEqualSlices(key.PublicKey, &.{destination}, state.sent_to.items);
    try testing.expect(state.removeConnection(c2) == .final);
}

test "server deinit interrupts and joins long-lived preauth handler" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();
    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .preauth_timeout_ns = 60 * std.time.ns_per_s,
    });
    const port = server.localAddress().getPort();

    const handler = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            srv.acceptOne() catch {};
        }
    }.run, .{&server});

    const fd = try connectTcp(port);
    defer _ = std.os.linux.close(fd);
    try Server.sleepNs(io, 20 * std.time.ns_per_ms);
    server.deinit();
    handler.join();
    try testing.expect(waitForPeerClose(fd, 1000));
}

test "server deinit interrupts a blocked accept reservation" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();
    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
    });

    const acceptor = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    var joined = false;
    var deinited = false;
    defer {
        if (!deinited) server.deinit();
        if (!joined) acceptor.join();
    }

    for (0..100) |_| {
        if (server.active_handlers.load(.acquire) == 1) break;
        try Server.sleepNs(io, std.time.ns_per_ms);
    }
    try testing.expectEqual(@as(u64, 1), server.active_handlers.load(.acquire));
    server.deinit();
    deinited = true;
    acceptor.join();
    joined = true;
    try testing.expectEqual(@as(u64, 0), server.active_handlers.load(.acquire));
}

test "acceptAndSpawn closes accepted stream when handler thread spawn fails" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();

    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();
    const port = server.localAddress().getPort();

    failNextHandlerSpawnForTest();
    var saw_error = std.atomic.Value(bool).init(false);
    const handler = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server, saw: *std.atomic.Value(bool)) void {
            srv.acceptAndSpawn() catch {
                saw.store(true, .release);
                return;
            };
        }
    }.run, .{ &server, &saw_error });

    const fd = try connectTcp(port);
    defer _ = std.os.linux.close(fd);

    handler.join();
    try testing.expect(saw_error.load(.acquire));
    try testing.expect(waitForPeerClose(fd, 1000));
}

test "keepalive spawn failure unregisters registered client" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();

    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();
    const port = server.localAddress().getPort();

    const sk = key.SecretKey.fromBytes(.{33} ** 32);
    const pub_key = sk.public();

    failNextKeepaliveSpawnForTest();
    const handler = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            srv.acceptOne() catch {};
        }
    }.run, .{&server});

    var relay_url_buf: [64]u8 = undefined;
    const relay_url = try std.fmt.bufPrint(&relay_url_buf, "ws://127.0.0.1:{d}/relay", .{port});
    var client: relay_client.Client = undefined;
    try client.connectInPlace(io, .{ .url = relay_client.RelayUrl.borrowed(relay_url), .secret_key = sk });
    defer client.close();

    handler.join();
    try testing.expect(waitForClientState(io, &server.clients, pub_key, false, 500 * std.time.ns_per_ms));
    try testing.expect(!server.clients.contains(pub_key));
}

test "idle preauth connection is closed after timeout" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();

    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .preauth_timeout_ns = 50 * std.time.ns_per_ms,
    });
    defer server.deinit();
    const port = server.localAddress().getPort();

    const handler = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            srv.acceptOne() catch {};
        }
    }.run, .{&server});

    const fd = try connectTcp(port);
    defer _ = std.os.linux.close(fd);

    handler.join();
    try testing.expect(waitForPeerClose(fd, 1000));
}

test "keepalive: responding client stays alive, non-responding client is dropped" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();

    const ka_interval: u64 = 200 * std.time.ns_per_ms;
    const ka_jitter: u64 = 0;
    const ka_pong_timeout: u64 = 100 * std.time.ns_per_ms;

    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .keepalive_interval_ns = ka_interval,
        .keepalive_jitter_ns = ka_jitter,
        .pong_timeout_ns = ka_pong_timeout,
    });

    const port = server.localAddress().getPort();

    var watchdog_done = std.atomic.Value(bool).init(false);
    const watchdog = try std.Thread.spawn(.{}, struct {
        fn run(done: *std.atomic.Value(bool)) void {
            var wd_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
            for (0..300) |_| {
                wd_io.io().sleep(std.Io.Duration.fromMilliseconds(100), .real) catch {};
                if (done.load(.acquire)) {
                    return;
                }
            }
            std.debug.panic("keepalive test watchdog timeout (30s)", .{});
        }
    }.run, .{&watchdog_done});
    defer {
        watchdog_done.store(true, .release);
        watchdog.join();
    }

    const sk_good = key.SecretKey.fromBytes(.{11} ** 32);
    const pub_good = sk_good.public();
    const sk_bad = key.SecretKey.fromBytes(.{22} ** 32);
    const pub_bad = sk_bad.public();

    const good_handler = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            srv.acceptOne() catch {};
        }
    }.run, .{&server});

    const fd_good = try connectTcp(port);
    try doWsUpgradeRaw(fd_good);
    try doClientHandshakeRaw(fd_good, sk_good);

    var good_pong_sent = std.atomic.Value(bool).init(false);
    const good_reader = try std.Thread.spawn(.{}, struct {
        fn run(fd: i32, pong_sent: *std.atomic.Value(bool)) void {
            var frame_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
            while (true) {
                const result = readWsFrame(fd, &frame_buf) catch return;
                if (result.op == .close) return;
                if (result.op != .binary) continue;
                const msg = proto.decodeRelayToClient(result.payload, .v2) catch continue;
                if (msg == .ping) {
                    var pong_buf: [16]u8 = undefined;
                    var pw = std.Io.Writer.fixed(&pong_buf);
                    proto.encodeClientToRelay(.{ .pong = msg.ping }, &pw) catch return;
                    writeWsFrame(fd, pw.buffered(), true) catch return;
                    pong_sent.store(true, .release);
                    return;
                }
            }
        }
    }.run, .{ fd_good, &good_pong_sent });

    const bad_handler = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            srv.acceptOne() catch {};
        }
    }.run, .{&server});

    const fd_bad = try connectTcp(port);
    try doWsUpgradeRaw(fd_bad);
    try doClientHandshakeRaw(fd_bad, sk_bad);

    try testing.expect(waitForClientState(io, &server.clients, pub_good, true, 500 * std.time.ns_per_ms));
    try testing.expect(waitForClientState(io, &server.clients, pub_bad, true, 500 * std.time.ns_per_ms));
    try testing.expect(waitForAtomicBool(io, &good_pong_sent, true, 1000 * std.time.ns_per_ms));
    try testing.expect(waitForClientState(io, &server.clients, pub_bad, false, 1000 * std.time.ns_per_ms));
    try testing.expect(server.clients.contains(pub_good));

    _ = std.os.linux.close(fd_good);
    _ = std.os.linux.close(fd_bad);

    good_reader.join();
    good_handler.join();
    bad_handler.join();

    server.deinit();
}

test "F3 duplicate endpoint reconnect preserves new active connection and notifies old connection" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();

    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .keepalive_interval_ns = 3600 * std.time.ns_per_s,
        .pong_timeout_ns = 3600 * std.time.ns_per_s,
    });
    const port = server.localAddress().getPort();

    var watchdog_done = std.atomic.Value(bool).init(false);
    const watchdog = try std.Thread.spawn(.{}, struct {
        fn run(done: *std.atomic.Value(bool)) void {
            var wd_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
            for (0..150) |_| {
                wd_io.io().sleep(std.Io.Duration.fromMilliseconds(100), .real) catch {};
                if (done.load(.acquire)) return;
            }
            std.debug.panic("duplicate endpoint test watchdog timeout (15s)", .{});
        }
    }.run, .{&watchdog_done});
    defer {
        watchdog_done.store(true, .release);
        watchdog.join();
    }

    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            while (srv.running.load(.acquire)) {
                srv.acceptAndSpawn() catch {};
            }
        }
    }.run, .{&server});
    defer {
        server.deinit();
        accept_thread.join();
    }
    io.sleep(std.Io.Duration.fromMilliseconds(50), .real) catch {};

    const sk_a = key.SecretKey.fromBytes(.{33} ** 32);
    const pub_a = sk_a.public();
    const sk_b = key.SecretKey.fromBytes(.{44} ** 32);
    const pub_b = sk_b.public();
    const sk_v1 = key.SecretKey.fromBytes(.{55} ** 32);

    const fd_v1_old = try connectTcp(port);
    defer _ = std.os.linux.close(fd_v1_old);
    try doWsUpgradeRawProtocol(fd_v1_old, "iroh-relay-v1");
    try doClientHandshakeRaw(fd_v1_old, sk_v1);
    const fd_v1_new = try connectTcp(port);
    defer _ = std.os.linux.close(fd_v1_new);
    try doWsUpgradeRawProtocol(fd_v1_new, "iroh-relay-v1");
    try doClientHandshakeRaw(fd_v1_new, sk_v1);
    var v1_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
    const v1_frame = try readWsFrame(fd_v1_old, &v1_buf);
    try testing.expectEqual(ws.OpCode.binary, v1_frame.op);
    const v1_msg = try proto.decodeRelayToClient(v1_frame.payload, .v1);
    try testing.expect(v1_msg == .health);
    try testing.expectEqualStrings(
        "Another endpoint connected with the same endpoint id. No more messages will be received.",
        v1_msg.health,
    );
    const normal_close = [_]u8{ 0x03, 0xe8 };
    try writeWsFrameOp(fd_v1_new, .close, &normal_close, true);
    const v1_new_close = try readWsFrame(fd_v1_new, &v1_buf);
    try testing.expectEqual(ws.OpCode.close, v1_new_close.op);
    const v1_healthy_frame = try readWsFrame(fd_v1_old, &v1_buf);
    const v1_healthy = try proto.decodeRelayToClient(v1_healthy_frame.payload, .v1);
    try testing.expect(v1_healthy == .health);
    try testing.expectEqualStrings(
        "The connection is healthy and has recovered from previous problems",
        v1_healthy.health,
    );

    const fd_b = try connectTcp(port);
    defer _ = std.os.linux.close(fd_b);
    try doWsUpgradeRaw(fd_b);
    try doClientHandshakeRaw(fd_b, sk_b);

    var current_a = try connectTcp(port);
    try doWsUpgradeRaw(current_a);
    try doClientHandshakeRaw(current_a, sk_a);
    defer _ = std.os.linux.close(current_a);

    for (0..16) |cycle| {
        const old_a = current_a;
        current_a = try connectTcp(port);
        try doWsUpgradeRaw(current_a);
        try doClientHandshakeRaw(current_a, sk_a);

        var status_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
        const status_frame = try readWsFrame(old_a, &status_buf);
        try testing.expectEqual(ws.OpCode.binary, status_frame.op);
        const status_msg = try proto.decodeRelayToClient(status_frame.payload, .v2);
        try testing.expect(status_msg == .status);
        try testing.expectEqual(proto.Status.same_endpoint_id_connected, status_msg.status);
        _ = std.os.linux.close(old_a);

        var payload_buf: [32]u8 = undefined;
        const payload = try std.fmt.bufPrint(&payload_buf, "dupe-cycle-{d}", .{cycle});
        var frame_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
        var frame_writer = std.Io.Writer.fixed(&frame_buf);
        try proto.encodeClientToRelay(.{ .datagram = .{
            .dst = pub_b,
            .datagrams = .{ .ecn = .not_ect, .segment_size = null, .contents = payload },
        } }, &frame_writer);
        try writeWsFrame(current_a, frame_writer.buffered(), true);

        var recv_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
        const recv_frame = try readWsFrame(fd_b, &recv_buf);
        try testing.expectEqual(ws.OpCode.binary, recv_frame.op);
        const recv_msg = try proto.decodeRelayToClient(recv_frame.payload, .v2);
        try testing.expect(recv_msg == .datagram);
        try testing.expect(recv_msg.datagram.src.eql(pub_a));
        try testing.expectEqualStrings(payload, recv_msg.datagram.datagrams.contents);
    }
}

test "duplicate endpoint falls back old to new to old and only final removal reports gone" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();

    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .keepalive_interval_ns = 3600 * std.time.ns_per_s,
        .pong_timeout_ns = 3600 * std.time.ns_per_s,
    });
    const port = server.localAddress().getPort();
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        accept_thread.join();
    }

    const sk_a = key.SecretKey.fromBytes(.{0x75} ** 32);
    const pub_a = sk_a.public();
    const sk_b = key.SecretKey.fromBytes(.{0x76} ** 32);
    const pub_b = sk_b.public();

    const fd_b = try connectTcp(port);
    defer _ = std.os.linux.close(fd_b);
    try doWsUpgradeRaw(fd_b);
    try doClientHandshakeRaw(fd_b, sk_b);

    const fd_a_old = try connectTcp(port);
    defer _ = std.os.linux.close(fd_a_old);
    try doWsUpgradeRaw(fd_a_old);
    try doClientHandshakeRaw(fd_a_old, sk_a);

    try sendClientDatagram(fd_a_old, pub_b, "before-replacement");
    var recv_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
    var recv_frame = try readWsFrame(fd_b, &recv_buf);
    var recv_msg = try proto.decodeRelayToClient(recv_frame.payload, .v2);
    try testing.expect(recv_msg == .datagram);
    try testing.expect(recv_msg.datagram.src.eql(pub_a));
    try testing.expectEqualStrings("before-replacement", recv_msg.datagram.datagrams.contents);

    const fd_a_new = try connectTcp(port);
    defer _ = std.os.linux.close(fd_a_new);
    try doWsUpgradeRaw(fd_a_new);
    try doClientHandshakeRaw(fd_a_new, sk_a);

    var status_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
    const duplicate_frame = try readWsFrame(fd_a_old, &status_buf);
    const duplicate = try proto.decodeRelayToClient(duplicate_frame.payload, .v2);
    try testing.expect(duplicate == .status);
    try testing.expectEqual(proto.Status.same_endpoint_id_connected, duplicate.status);

    // The inactive physical connection keeps its read loop and may still send.
    try sendClientDatagram(fd_a_old, pub_b, "from-inactive-old");
    recv_frame = try readWsFrame(fd_b, &recv_buf);
    recv_msg = try proto.decodeRelayToClient(recv_frame.payload, .v2);
    try testing.expect(recv_msg == .datagram);
    try testing.expectEqualStrings("from-inactive-old", recv_msg.datagram.datagrams.contents);

    // Incoming routing selects only the newest active connection.
    try sendClientDatagram(fd_b, pub_a, "to-new-active");
    recv_frame = try readWsFrame(fd_a_new, &recv_buf);
    recv_msg = try proto.decodeRelayToClient(recv_frame.payload, .v2);
    try testing.expect(recv_msg == .datagram);
    try testing.expect(recv_msg.datagram.src.eql(pub_b));
    try testing.expectEqualStrings("to-new-active", recv_msg.datagram.datagrams.contents);

    const normal_close = [_]u8{ 0x03, 0xe8 };
    try writeWsFrameOp(fd_a_new, .close, &normal_close, true);
    const new_close = try readWsFrame(fd_a_new, &recv_buf);
    try testing.expectEqual(ws.OpCode.close, new_close.op);

    const healthy_frame = try readWsFrame(fd_a_old, &status_buf);
    const healthy = try proto.decodeRelayToClient(healthy_frame.payload, .v2);
    try testing.expect(healthy == .status);
    try testing.expectEqual(proto.Status.healthy, healthy.status);
    try testing.expect(!socketReadableWithin(fd_b, 50));

    try sendClientDatagram(fd_b, pub_a, "to-promoted-old");
    recv_frame = try readWsFrame(fd_a_old, &recv_buf);
    recv_msg = try proto.decodeRelayToClient(recv_frame.payload, .v2);
    try testing.expect(recv_msg == .datagram);
    try testing.expectEqualStrings("to-promoted-old", recv_msg.datagram.datagrams.contents);

    try writeWsFrameOp(fd_a_old, .close, &normal_close, true);
    const old_close = try readWsFrame(fd_a_old, &recv_buf);
    try testing.expectEqual(ws.OpCode.close, old_close.op);

    const gone_frame = try readWsFrame(fd_b, &recv_buf);
    const gone = try proto.decodeRelayToClient(gone_frame.payload, .v2);
    try testing.expect(gone == .endpoint_gone);
    try testing.expect(gone.endpoint_gone.eql(pub_a));
}

test "websocket upgrade captures bearer token with query fallback" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();
    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
    });
    defer server.deinit();

    const base =
        "Host: example.test\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: iroh-relay-v2\r\n";
    var token_buf: [MAX_AUTH_TOKEN_BYTES]u8 = undefined;

    // Bearer header is captured (scheme case-insensitive).
    const with_bearer = "GET /relay HTTP/1.1\r\n" ++ base ++ "Authorization: bearer tok-header\r\n\r\n";
    var bearer_reader = std.Io.Reader.fixed(with_bearer);
    var bearer_output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer bearer_output.deinit();
    const bearer_upgrade = try server.wsServerUpgrade(&bearer_reader, &bearer_output.writer, &token_buf);
    try testing.expectEqualStrings("tok-header", bearer_upgrade.auth_token.?);

    // No Authorization header: the token query parameter is the fallback.
    const with_query = "GET /relay?token=tok-query&x=1 HTTP/1.1\r\n" ++ base ++ "\r\n";
    var query_reader = std.Io.Reader.fixed(with_query);
    var query_output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer query_output.deinit();
    const query_upgrade = try server.wsServerUpgrade(&query_reader, &query_output.writer, &token_buf);
    try testing.expectEqualStrings("tok-query", query_upgrade.auth_token.?);

    // A Bearer header beats the query parameter; a non-Bearer scheme does not.
    const bearer_wins = "GET /relay?token=tok-query HTTP/1.1\r\n" ++ base ++ "Authorization: Bearer tok-header\r\n\r\n";
    var wins_reader = std.Io.Reader.fixed(bearer_wins);
    var wins_output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer wins_output.deinit();
    const wins_upgrade = try server.wsServerUpgrade(&wins_reader, &wins_output.writer, &token_buf);
    try testing.expectEqualStrings("tok-header", wins_upgrade.auth_token.?);

    const other_scheme = "GET /relay HTTP/1.1\r\n" ++ base ++ "Authorization: Basic dXNlcg==\r\n\r\n";
    var scheme_reader = std.Io.Reader.fixed(other_scheme);
    var scheme_output: std.Io.Writer.Allocating = .init(testing.allocator);
    defer scheme_output.deinit();
    const scheme_upgrade = try server.wsServerUpgrade(&scheme_reader, &scheme_output.writer, &token_buf);
    try testing.expect(scheme_upgrade.auth_token == null);
}

test "access control denies unknown token and admits allow-listed token at handshake" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();

    var acl = TokenAccessControl.init(testing.allocator);
    defer acl.deinit();
    try acl.add("token-a");

    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .keepalive_interval_ns = 3600 * std.time.ns_per_s,
        .pong_timeout_ns = 3600 * std.time.ns_per_s,
        .access_control = acl.accessControl(),
    });
    const port = server.localAddress().getPort();
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        accept_thread.join();
    }

    const sk = key.SecretKey.fromBytes(.{0x81} ** 32);

    // Unknown token and missing token are denied with "not authorized" (the
    // EXISTING deny frame; bad signatures keep "signature invalid").
    try expectAuthDenied(port, sk, "token-b", "not authorized");
    try expectAuthDenied(port, sk, null, "not authorized");

    // Runtime add admits the previously denied token (ping proves the
    // connection is fully registered, not just confirmed).
    try acl.add("token-b");
    const fd = try connectRawWithToken(port, sk, "token-b");
    defer _ = std.os.linux.close(fd);
    try doRelayPingRaw(fd, .{ 1, 2, 3, 4, 5, 6, 7, 8 });
}

test "access revocation is token-scoped across connections sharing an endpoint" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();

    var acl = TokenAccessControl.init(testing.allocator);
    defer acl.deinit();
    try acl.add("token-a");
    try acl.add("token-b");

    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .keepalive_interval_ns = 3600 * std.time.ns_per_s,
        .pong_timeout_ns = 3600 * std.time.ns_per_s,
        .access_control = acl.accessControl(),
    });
    const port = server.localAddress().getPort();
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        accept_thread.join();
    }

    var watchdog_done = std.atomic.Value(bool).init(false);
    const watchdog = try std.Thread.spawn(.{}, struct {
        fn run(done: *std.atomic.Value(bool)) void {
            var wd_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
            for (0..150) |_| {
                wd_io.io().sleep(std.Io.Duration.fromMilliseconds(100), .real) catch {};
                if (done.load(.acquire)) return;
            }
            std.debug.panic("revocation test watchdog timeout (15s)", .{});
        }
    }.run, .{&watchdog_done});
    defer {
        watchdog_done.store(true, .release);
        watchdog.join();
    }

    // runtime_auth.rs:226-247 — ONE SecretKey, two token-a connections and one
    // token-b connection. Revoking token-a must evict exactly the first two.
    const shared = key.SecretKey.fromBytes(.{0x82} ** 32);
    const fd1 = try connectRawWithToken(port, shared, "token-a");
    defer _ = std.os.linux.close(fd1);
    const fd2 = try connectRawWithToken(port, shared, "token-a");
    defer _ = std.os.linux.close(fd2);
    // Demotion status frames sit ahead of any pong on the older connections.
    try expectStatusFrame(fd1, .same_endpoint_id_connected);
    const fd3 = try connectRawWithToken(port, shared, "token-b");
    defer _ = std.os.linux.close(fd3);
    try expectStatusFrame(fd2, .same_endpoint_id_connected);

    // All three are live (pings double as a registration barrier).
    try doRelayPingRaw(fd1, .{ 1, 1, 1, 1, 1, 1, 1, 1 });
    try doRelayPingRaw(fd2, .{ 2, 2, 2, 2, 2, 2, 2, 2 });
    try doRelayPingRaw(fd3, .{ 3, 3, 3, 3, 3, 3, 3, 3 });
    try testing.expectEqual(@as(usize, 3), acl.connectionCount());

    // Revoke token-a: only its two connections are evicted.
    var removed: std.ArrayList(ConnKey) = .empty;
    defer removed.deinit(testing.allocator);
    try acl.revoke("token-a", &removed);
    try testing.expectEqual(@as(usize, 2), removed.items.len);
    for (removed.items) |ck| _ = server.disconnectConnection(ck.endpoint_id, ck.connection_id);

    try testing.expect(waitForPeerClose(fd1, 2000));
    try testing.expect(waitForPeerClose(fd2, 2000));

    // The token-b connection on the SAME public key survives and the index
    // settles to it alone.
    try doRelayPingRaw(fd3, .{ 4, 4, 4, 4, 4, 4, 4, 4 });
    try testing.expect(waitForConnectionCount(io, &acl, 1, 5 * std.time.ns_per_s));

    // The revoked token cannot reconnect.
    try expectAuthDenied(port, shared, "token-a", "not authorized");

    // An ordinary disconnect prunes the index back to zero.
    _ = std.os.linux.close(fd3);
    try testing.expect(waitForConnectionCount(io, &acl, 0, 5 * std.time.ns_per_s));
}

test "access revocation disconnects only the revoked token's connection" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();

    var acl = TokenAccessControl.init(testing.allocator);
    defer acl.deinit();
    try acl.add("token-a");
    try acl.add("token-b");

    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .keepalive_interval_ns = 3600 * std.time.ns_per_s,
        .pong_timeout_ns = 3600 * std.time.ns_per_s,
        .access_control = acl.accessControl(),
    });
    const port = server.localAddress().getPort();
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        accept_thread.join();
    }

    const fd_revoked = try connectRawWithToken(port, key.SecretKey.fromBytes(.{0x83} ** 32), "token-a");
    defer _ = std.os.linux.close(fd_revoked);
    const fd_kept = try connectRawWithToken(port, key.SecretKey.fromBytes(.{0x84} ** 32), "token-b");
    defer _ = std.os.linux.close(fd_kept);
    try doRelayPingRaw(fd_revoked, .{ 5, 5, 5, 5, 5, 5, 5, 5 });
    try doRelayPingRaw(fd_kept, .{ 6, 6, 6, 6, 6, 6, 6, 6 });

    var removed: std.ArrayList(ConnKey) = .empty;
    defer removed.deinit(testing.allocator);
    try acl.revoke("token-a", &removed);
    try testing.expectEqual(@as(usize, 1), removed.items.len);
    for (removed.items) |ck| _ = server.disconnectConnection(ck.endpoint_id, ck.connection_id);

    // The revoked connection is torn down; the other endpoint keeps working.
    try testing.expect(waitForPeerClose(fd_revoked, 2000));
    try doRelayPingRaw(fd_kept, .{ 7, 7, 7, 7, 7, 7, 7, 7 });
    try testing.expect(waitForConnectionCount(io, &acl, 1, 5 * std.time.ns_per_s));
}

// Revoke forced into the ACL-admission → Clients.register window via a
// deterministic test barrier (not timing). Without the post-register
// stillTracked recheck this connection SURVIVES (the original under-close
// race); with the recheck it is torn down fail-closed.
test "mid-handshake revoke tears down the connection fail-closed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    const io = threaded.io();

    var acl = TokenAccessControl.init(testing.allocator);
    defer acl.deinit();
    try acl.add("token-mid");

    var server = try Server.init(testing.allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .keepalive_interval_ns = 3600 * std.time.ns_per_s,
        .pong_timeout_ns = 3600 * std.time.ns_per_s,
        .access_control = acl.accessControl(),
    });
    const port = server.localAddress().getPort();
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        accept_thread.join();
    }

    var watchdog_done = std.atomic.Value(bool).init(false);
    const watchdog = try std.Thread.spawn(.{}, struct {
        fn run(done: *std.atomic.Value(bool)) void {
            var wd_io = std.Io.Threaded.init(std.heap.page_allocator, .{});
            for (0..150) |_| {
                wd_io.io().sleep(std.Io.Duration.fromMilliseconds(100), .real) catch {};
                if (done.load(.acquire)) return;
            }
            std.debug.panic("mid-handshake revoke test watchdog timeout (15s)", .{});
        }
    }.run, .{&watchdog_done});
    defer {
        watchdog_done.store(true, .release);
        watchdog.join();
    }

    armMidHandshakeRevokeBarrierForTest();

    const sk = key.SecretKey.fromBytes(.{0x85} ** 32);
    const ConnectResult = struct {
        fd: i32 = -1,
        err: ?anyerror = null,
    };
    var connect_result: ConnectResult = .{};
    const connect_thread = try std.Thread.spawn(.{}, struct {
        fn run(p: u16, secret: key.SecretKey, out: *ConnectResult) void {
            const fd = connectRawWithToken(p, secret, "token-mid") catch |e| {
                out.err = e;
                return;
            };
            out.fd = fd;
        }
    }.run, .{ port, sk, &connect_result });

    // Wait until the handler has admitted via ACL and parked before register.
    try testing.expect(waitMidHandshakeBarrierReachedForTest(io, 5 * std.time.ns_per_s));
    // At the barrier the connection is indexed but NOT yet in Clients — so
    // revoke removes the ACL entry and disconnect no-ops (the under-close
    // window). The post-register stillTracked recheck must catch this.
    try testing.expectEqual(@as(usize, 1), acl.connectionCount());
    var removed: std.ArrayList(ConnKey) = .empty;
    defer removed.deinit(testing.allocator);
    try acl.revoke("token-mid", &removed);
    try testing.expectEqual(@as(usize, 1), removed.items.len);
    for (removed.items) |ck| {
        // Expect false: connection is not registered yet.
        try testing.expect(!server.disconnectConnection(ck.endpoint_id, ck.connection_id));
    }
    try testing.expectEqual(@as(usize, 0), acl.connectionCount());

    releaseMidHandshakeBarrierForTest();
    connect_thread.join();

    // Confirm completed before the barrier, so the client fd is live even
    // though the server is about to (or has) tear down.
    if (connect_result.err) |e| return e;
    try testing.expect(connect_result.fd >= 0);
    defer _ = std.os.linux.close(connect_result.fd);

    // Fail-closed: the connection must NOT survive as a working relay peer.
    // Peer close is the primary signal; a surviving connection would answer a ping.
    try testing.expect(waitForPeerClose(connect_result.fd, 3000));
    try testing.expect(waitForConnectionCount(io, &acl, 0, 5 * std.time.ns_per_s));
    // Token stays revoked: a fresh connect is denied.
    try expectAuthDenied(port, sk, "token-mid", "not authorized");
}

fn waitForConnectionCount(io: std.Io, acl: *TokenAccessControl, want: usize, timeout_ns: u64) bool {
    const poll_ns: u64 = 5 * std.time.ns_per_ms;
    var elapsed: u64 = 0;
    while (elapsed < timeout_ns) {
        if (acl.connectionCount() == want) return true;
        Server.sleepNs(io, poll_ns) catch return false;
        elapsed += poll_ns;
    }
    return acl.connectionCount() == want;
}

fn doWsUpgradeRawAuth(fd: i32, token: ?[]const u8) !void {
    var key_bytes: [16]u8 = undefined;
    _ = std.os.linux.getrandom(&key_bytes, 16, 0);
    var ws_key_buf: [32]u8 = undefined;
    const ws_key = std.base64.standard.Encoder.encode(&ws_key_buf, &key_bytes);

    var req_buf: [1200]u8 = undefined;
    var req_writer = std.Io.Writer.fixed(&req_buf);
    try req_writer.print("GET /relay HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Protocol: iroh-relay-v2\r\nSec-WebSocket-Version: 13\r\n", .{ws_key});
    if (token) |tok| try req_writer.print("Authorization: Bearer {s}\r\n", .{tok});
    try req_writer.writeAll("\r\n");
    linuxWrite(fd, req_writer.buffered());

    var resp_buf: [1024]u8 = undefined;
    var total: usize = 0;
    while (true) {
        if (total >= resp_buf.len) return error.ResponseTooLarge;
        const n = linuxRead(fd, resp_buf[total .. total + 1]) catch return error.ConnectionClosed;
        if (n == 0) return error.ConnectionClosed;
        total += n;
        if (total >= 4 and std.mem.eql(u8, resp_buf[total - 4 .. total], "\r\n\r\n")) break;
    }
}

/// A full raw client connect (upgrade + signed challenge handshake) that
/// presents `token` as its bearer credential.
fn connectRawWithToken(port: u16, sk: key.SecretKey, token: ?[]const u8) !i32 {
    const fd = try connectTcp(port);
    errdefer _ = std.os.linux.close(fd);
    try doWsUpgradeRawAuth(fd, token);
    try doClientHandshakeRaw(fd, sk);
    return fd;
}

/// Connect expecting an authorization denial with `want_reason`.
fn expectAuthDenied(port: u16, sk: key.SecretKey, token: ?[]const u8, want_reason: []const u8) !void {
    const fd = try connectTcp(port);
    defer _ = std.os.linux.close(fd);
    try doWsUpgradeRawAuth(fd, token);

    var frame_buf: [256]u8 = undefined;
    const challenge_frame = try readWsFrame(fd, &frame_buf);
    const challenge = try handshake.decodeHandshakeFrame(challenge_frame.payload);
    try testing.expect(challenge == .server_challenge);

    const auth = handshake.clientAuthFor(sk, challenge.server_challenge.challenge);
    var auth_buf: [128]u8 = undefined;
    var auth_writer = std.Io.Writer.fixed(&auth_buf);
    try handshake.encodeClientAuth(auth, &auth_writer);
    try writeWsFrame(fd, auth_writer.buffered(), true);

    const denial_frame = try readWsFrame(fd, &frame_buf);
    const denial = try handshake.decodeHandshakeFrame(denial_frame.payload);
    try testing.expect(denial == .server_denies_auth);
    try testing.expectEqualStrings(want_reason, denial.server_denies_auth.reason);
}

/// Read the next binary frame and require a specific v2 status.
fn expectStatusFrame(fd: i32, want: proto.Status) !void {
    var frame_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
    const frame = try readWsFrame(fd, &frame_buf);
    try testing.expectEqual(ws.OpCode.binary, frame.op);
    const msg = try proto.decodeRelayToClient(frame.payload, .v2);
    try testing.expect(msg == .status);
    try testing.expectEqual(want, msg.status);
}

/// Relay-level ping/pong round trip over a raw fd (server keepalive pings are
/// answered; bounded by a readability poll so a dead connection fails instead
/// of hanging the test).
fn doRelayPingRaw(fd: i32, pd: [8]u8) !void {
    var ping_buf: [32]u8 = undefined;
    var ping_writer = std.Io.Writer.fixed(&ping_buf);
    try proto.encodeClientToRelay(.{ .ping = pd }, &ping_writer);
    try writeWsFrame(fd, ping_writer.buffered(), true);

    var frame_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
    while (true) {
        if (!socketReadableWithin(fd, 2000)) return error.PongTimeout;
        const frame = try readWsFrame(fd, &frame_buf);
        if (frame.op != .binary) continue;
        const msg = try proto.decodeRelayToClient(frame.payload, .v2);
        switch (msg) {
            .pong => |echo| {
                try testing.expectEqual(pd, echo);
                return;
            },
            .ping => |p| {
                var pong_buf: [16]u8 = undefined;
                var pong_writer = std.Io.Writer.fixed(&pong_buf);
                try proto.encodeClientToRelay(.{ .pong = p }, &pong_writer);
                try writeWsFrame(fd, pong_writer.buffered(), true);
            },
            else => {},
        }
    }
}

fn waitForClientState(io: std.Io, clients: *Clients, pk: key.PublicKey, want_present: bool, timeout_ns: u64) bool {
    const poll_ns: u64 = 5 * std.time.ns_per_ms;
    var elapsed: u64 = 0;
    while (elapsed < timeout_ns) {
        if (clients.contains(pk) == want_present) return true;
        Server.sleepNs(io, poll_ns) catch return false;
        elapsed += poll_ns;
    }
    return clients.contains(pk) == want_present;
}

fn waitForAtomicBool(io: std.Io, value: *std.atomic.Value(bool), want: bool, timeout_ns: u64) bool {
    const poll_ns: u64 = 5 * std.time.ns_per_ms;
    var elapsed: u64 = 0;
    while (elapsed < timeout_ns) {
        if (value.load(.acquire) == want) return true;
        Server.sleepNs(io, poll_ns) catch return false;
        elapsed += poll_ns;
    }
    return value.load(.acquire) == want;
}

fn waitForPeerClose(fd: i32, timeout_ms: i32) bool {
    var fds: [1]std.os.linux.pollfd = .{.{
        .fd = fd,
        .events = @intCast(std.os.linux.POLL.IN | std.os.linux.POLL.HUP | std.os.linux.POLL.ERR),
        .revents = 0,
    }};
    const rc = std.os.linux.poll(&fds, fds.len, timeout_ms);
    const poll_err = std.os.linux.errno(rc);
    if (poll_err != .SUCCESS or rc == 0) return false;

    var byte: [1]u8 = undefined;
    const read_rc = std.os.linux.read(fd, &byte, byte.len);
    const read_err = std.os.linux.errno(read_rc);
    if (read_err == .CONNRESET) return true;
    if (read_err != .SUCCESS) return false;
    return read_rc == 0;
}

fn socketReadableWithin(fd: i32, timeout_ms: i32) bool {
    var fds: [1]std.os.linux.pollfd = .{.{
        .fd = fd,
        .events = @intCast(std.os.linux.POLL.IN | std.os.linux.POLL.HUP | std.os.linux.POLL.ERR),
        .revents = 0,
    }};
    const rc = std.os.linux.poll(&fds, fds.len, timeout_ms);
    return std.os.linux.errno(rc) == .SUCCESS and rc > 0;
}

fn connectTcp(port: u16) !i32 {
    const rc = std.os.linux.socket(std.os.linux.AF.INET, std.os.linux.SOCK.STREAM, 0);
    const fd: i32 = @intCast(rc);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = std.os.linux.close(fd);
    var addr: std.os.linux.sockaddr.in = .{
        .family = std.os.linux.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = 0x0100007f,
    };
    const connect_rc = std.os.linux.connect(fd, @ptrCast(&addr), @sizeOf(std.os.linux.sockaddr.in));
    if (connect_rc != 0) return error.ConnectFailed;
    return fd;
}

fn doWsUpgradeRaw(fd: i32) !void {
    return doWsUpgradeRawProtocol(fd, "iroh-relay-v2");
}

fn doWsUpgradeRawProtocol(fd: i32, protocol: []const u8) !void {
    var key_bytes: [16]u8 = undefined;
    _ = std.os.linux.getrandom(&key_bytes, 16, 0);
    var ws_key_buf: [32]u8 = undefined;
    const ws_key = std.base64.standard.Encoder.encode(&ws_key_buf, &key_bytes);

    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "GET /relay HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Protocol: {s}\r\nSec-WebSocket-Version: 13\r\n\r\n", .{ ws_key, protocol });
    _ = linuxWrite(fd, req);

    var resp_buf: [1024]u8 = undefined;
    var total: usize = 0;
    while (true) {
        if (total >= resp_buf.len) return error.ResponseTooLarge;
        const n = linuxRead(fd, resp_buf[total .. total + 1]) catch return error.ConnectionClosed;
        if (n == 0) return error.ConnectionClosed;
        total += n;
        if (total >= 4 and std.mem.eql(u8, resp_buf[total - 4 .. total], "\r\n\r\n")) break;
    }
}

fn linuxRead(fd: i32, buf: []u8) !usize {
    while (true) {
        const rc = std.os.linux.read(fd, buf.ptr, buf.len);
        const err: std.posix.E = std.os.linux.errno(rc);
        if (err != .SUCCESS) {
            if (err == .INTR) continue;
            return error.ReadFailed;
        }
        return rc;
    }
}

fn linuxWrite(fd: i32, buf: []const u8) void {
    var written: usize = 0;
    while (written < buf.len) {
        const rc = std.os.linux.write(fd, buf.ptr + written, buf.len - written);
        const err: std.posix.E = std.os.linux.errno(rc);
        if (err != .SUCCESS) {
            if (err == .INTR) continue;
            return;
        }
        written += rc;
    }
}

fn doClientHandshakeRaw(fd: i32, sk: key.SecretKey) !void {
    var frame_buf: [256]u8 = undefined;
    const challenge_frame = readWsFrame(fd, &frame_buf) catch return error.HandshakeFailed;
    if (challenge_frame.op != .binary) return error.HandshakeFailed;

    const challenge = handshake.decodeHandshakeFrame(challenge_frame.payload) catch return error.HandshakeFailed;
    if (challenge != .server_challenge) return error.HandshakeFailed;

    const auth_msg = handshake.clientAuthFor(sk, challenge.server_challenge.challenge);
    var auth_buf: [256]u8 = undefined;
    var auth_writer = std.Io.Writer.fixed(&auth_buf);
    try handshake.encodeClientAuth(auth_msg, &auth_writer);
    try writeWsFrame(fd, auth_writer.buffered(), true);

    const confirm_frame = readWsFrame(fd, &frame_buf) catch return error.HandshakeFailed;
    if (confirm_frame.op != .binary) return error.HandshakeFailed;
    const confirm = handshake.decodeHandshakeFrame(confirm_frame.payload) catch return error.HandshakeFailed;
    if (confirm != .server_confirms_auth) return error.HandshakeFailed;
}

fn sendClientDatagram(fd: i32, dst: key.PublicKey, payload: []const u8) !void {
    var frame_buf: [proto.MAX_FRAME_SIZE]u8 = undefined;
    var frame_writer = std.Io.Writer.fixed(&frame_buf);
    try proto.encodeClientToRelay(.{ .datagram = .{
        .dst = dst,
        .datagrams = .{
            .ecn = .not_ect,
            .segment_size = null,
            .contents = payload,
        },
    } }, &frame_writer);
    try writeWsFrame(fd, frame_writer.buffered(), true);
}

fn readWsFrame(fd: i32, buf: []u8) !ws.ReadFrameResult {
    var hdr: [2]u8 = undefined;
    try readExact(fd, &hdr);
    const op: ws.OpCode = @enumFromInt(@as(u4, @intCast(hdr[0] & 0x0F)));
    var payload_len: usize = hdr[1] & 0x7F;
    if (payload_len == 126) {
        var len_buf: [2]u8 = undefined;
        try readExact(fd, &len_buf);
        payload_len = std.mem.readInt(u16, &len_buf, .big);
    } else if (payload_len == 127) {
        var len_buf: [8]u8 = undefined;
        try readExact(fd, &len_buf);
        payload_len = @intCast(std.mem.readInt(u64, &len_buf, .big));
    }
    if (payload_len > buf.len) return error.FrameTooLarge;
    if (payload_len > 0) try readExact(fd, buf[0..payload_len]);
    return .{ .op = op, .payload = buf[0..payload_len] };
}

fn writeWsFrame(fd: i32, payload: []const u8, mask: bool) !void {
    return writeWsFrameOp(fd, .binary, payload, mask);
}

fn writeWsFrameOp(fd: i32, op: ws.OpCode, payload: []const u8, mask: bool) !void {
    return writeWsFragment(fd, true, op, payload, mask);
}

fn writeWsFragment(fd: i32, fin: bool, op: ws.OpCode, payload: []const u8, mask: bool) !void {
    var hdr: [14]u8 = undefined;
    var hdr_len: usize = 2;
    hdr[0] = (if (fin) @as(u8, 0x80) else 0) | @as(u8, @intFromEnum(op));
    if (payload.len < 126) {
        hdr[1] = @intCast(payload.len);
    } else if (payload.len < 65536) {
        hdr[1] = 126;
        std.mem.writeInt(u16, hdr[2..4], @intCast(payload.len), .big);
        hdr_len = 4;
    } else {
        hdr[1] = 127;
        std.mem.writeInt(u64, hdr[2..10], payload.len, .big);
        hdr_len = 10;
    }
    if (mask) {
        hdr[1] |= 0x80;
        var mask_key: [4]u8 = undefined;
        _ = std.os.linux.getrandom(&mask_key, 4, 0);
        @memcpy(hdr[hdr_len..][0..4], &mask_key);
        hdr_len += 4;
        linuxWrite(fd, hdr[0..hdr_len]);
        var masked: [1024]u8 = undefined;
        for (payload, 0..) |b, i| {
            masked[i] = b ^ mask_key[i % 4];
        }
        linuxWrite(fd, masked[0..payload.len]);
    } else {
        linuxWrite(fd, hdr[0..hdr_len]);
        linuxWrite(fd, payload);
    }
}

fn readExact(fd: i32, buf: []u8) !void {
    var total: usize = 0;
    while (total < buf.len) {
        const n = linuxRead(fd, buf[total..]) catch return error.ConnectionClosed;
        if (n == 0) return error.ConnectionClosed;
        total += n;
    }
}
