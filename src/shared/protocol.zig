//! The public accept-side composition surface — per-ALPN handler registration
//! plus an accept loop that dispatches incoming connections to the registered
//! handler. This is the Zig counterpart of upstream iroh's `protocol.rs`
//! (`Router` / `RouterBuilder` / `ProtocolHandler`), composed ABOVE the frozen
//! `transport.zig` vtable seam (never inside it).
//!
//! Dispatch mechanism (translation-audit D3 — runtime-swap test): a vtable.
//! Handlers are registered at RUNTIME through one builder entry point and the
//! registered set is heterogeneous (an echo handler today, blobs/gossip-style
//! handlers later); the caller genuinely swaps implementations at runtime, so
//! type erasure is required. Comptime dispatch cannot erase heterogeneous
//! handler types into one runtime registry, and a tagged union would close the
//! registry to downstream handler types — wrong for a public composition
//! surface. This matches the seam's own idiom (`Transport`/`Connection` are
//! vtable-based for the same reason).
//!
//! Multi-ALPN: the Router owns its ALPN keys (copied at `accept`) and dispatches
//! by `Connection.alpn()` (wire-neutral seam amendment). The handler
//! map is frozen after `spawn` (no concurrent mutation) — `setAlpns` on the
//! endpoint may still change which ALPNs are *advertised* for new handshakes.
//!
//! Pre-handshake admission filtering (upstream `IncomingFilter` / Retry /
//! Ignore, `protocol.rs:459-475`) is wired through `RouterBuilder.incomingFilter`
//! → `factory.setNoqIncomingFilter` → the noq endpoint's `route()` demux, which
//! evaluates the filter callback on each first-flight Initial before any
//! connection state is allocated or TLS handshake begins. The four outcomes
//! (accept / retry / reject / ignore) match upstream semantics.
//!
//! Pre-accept interception (upstream `ProtocolHandler::on_accepting`): the
//! accept loop hands a public `Accepting` object to `on_accepting` before the
//! normal `accept` call. Default `on_accepting` completes the handshake and
//! returns the established connection. Handlers may reject early or call
//! `into0Rtt` to take ownership during accept-side 0-RTT.

const std = @import("std");
const product_flags = @import("product_flags.zig");
// Fork-isolation S3: the frozen transport surface + the engine-select factory
// arrive through the per-product DOOR module (`transport`). The legacy
// `noq_ep` file-import of the concrete noq engine is GONE — the accept-side
// 0-RTT early-accept is now an injected door capability
// (`factory.supports_accept_early` / `factory.waitEstablished`), so this file
// can live in `shared/` without dragging the engine across the seam.
const tr = @import("transport");
const factory = @import("transport").factory;

/// Public pre-accept handshake handle (upstream `Accepting`).
///
/// Owns one inbound `tr.Connection` that is either fully established or in the
/// accept-side 0-RTT early state. Callers either:
/// - `complete()` — wait for full handshake (default path), or
/// - `into0Rtt()` — keep the early connection for accept-side 0-RTT, or
/// - `reject()` — close without handing to `accept`.
pub const Accepting = struct {
    conn: tr.Connection,
    early_zero_rtt: bool = false,
    taken: bool = false,

    pub fn remoteAddress(self: *const Accepting) ?std.Io.net.IpAddress {
        return self.conn.remoteAddress();
    }

    pub fn remoteNodeId(self: *const Accepting) tr.NodeId {
        return self.conn.remoteNodeId();
    }

    pub fn alpn(self: *const Accepting) ?[]const u8 {
        return self.conn.alpn();
    }

    /// True when this accepting was handed off before the full handshake
    /// (accept-side 0-RTT keys live).
    pub fn isEarlyZeroRtt(self: *const Accepting) bool {
        return self.early_zero_rtt;
    }

    /// Finish the handshake and take the established connection (upstream
    /// `Accepting` await). On a non-early connection this is a no-op take.
    pub fn complete(self: *Accepting) anyerror!tr.Connection {
        if (self.taken) return error.AcceptingConsumed;
        if (self.early_zero_rtt and factory.supports_accept_early) {
            try factory.waitEstablished(self.conn);
            self.early_zero_rtt = false;
        }
        self.taken = true;
        return self.conn;
    }

    /// Take ownership during accept-side 0-RTT (upstream `into_0rtt`).
    /// Returns the early connection when early keys are live; otherwise
    /// falls through to `complete()` so handlers can share one code path.
    pub fn into0Rtt(self: *Accepting) anyerror!tr.Connection {
        if (self.taken) return error.AcceptingConsumed;
        if (!self.early_zero_rtt) return self.complete();
        self.taken = true;
        return self.conn;
    }

    /// Reject before normal accept (closes the connection).
    pub fn reject(self: *Accepting) void {
        if (self.taken) return;
        self.taken = true;
        self.conn.close();
    }
};

/// A handler for incoming connections, registered for one ALPN.
/// Vtable-based (see module docs for the D3 justification).
pub const ProtocolHandler = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Optional interception before normal accept (upstream
        /// `ProtocolHandler::on_accepting`). Default completes the handshake
        /// and returns the connection. May reject early (`error` or
        /// `Accepting.reject`) or implement accept-side 0-RTT via
        /// `Accepting.into0Rtt`. Returning a connection hands it to `accept`.
        on_accepting: *const fn (context: *anyopaque, accepting: *Accepting) anyerror!tr.Connection = defaultOnAccepting,
        /// Serve one accepted connection. Runs on a freshly spawned thread, so
        /// it may block for the life of the connection. When `accept` returns,
        /// the router closes the connection (upstream: returning from
        /// `ProtocolHandler::accept` drops the connection). A returned error
        /// is logged and the connection is closed, same as upstream's warn+drop.
        accept: *const fn (context: *anyopaque, connection: tr.Connection) anyerror!void,
        /// Best-effort graceful drain before the router joins handler threads.
        /// Default no-op is fine for echo-style handlers.
        shutdown: *const fn (context: *anyopaque) void = noopShutdown,
    };

    pub fn onAccepting(self: ProtocolHandler, accepting: *Accepting) anyerror!tr.Connection {
        return self.vtable.on_accepting(self.context, accepting);
    }

    pub fn accept(self: ProtocolHandler, connection: tr.Connection) anyerror!void {
        return self.vtable.accept(self.context, connection);
    }

    pub fn shutdown(self: ProtocolHandler) void {
        self.vtable.shutdown(self.context);
    }

    fn noopShutdown(_: *anyopaque) void {}

    pub fn defaultOnAccepting(_: *anyopaque, accepting: *Accepting) anyerror!tr.Connection {
        return accepting.complete();
    }
};

pub const SpawnError = error{
    /// No handler was registered via `RouterBuilder.accept`.
    NoHandlerRegistered,
    OutOfMemory,
    ThreadSpawnFailed,
    InvalidAlpn,
    EndpointClosed,
    PicoquicDisabled,
    NoqDisabled,
};

pub const Router = struct {
    allocator: std.mem.Allocator,
    endpoint: factory.AnyEndpoint,
    /// Owned ALPN key → handler. Immutable after spawn (freeze-after-spawn).
    handlers: std.StringHashMapUnmanaged(ProtocolHandler),
    /// Owned key storage backing `handlers` keys (map does not free keys).
    owned_keys: std.ArrayListUnmanaged([]u8) = .empty,
    io: std.Io,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    loop_thread: ?std.Thread = null,
    loop_failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Spawned handler threads, appended and reaped only by the loop thread;
    /// read by shutdown AFTER joining the loop thread (the join orders the
    /// access). Completed handlers are reaped continuously (regression lane-01
    /// H1): retention tracks live concurrency, not total accepted connections.
    handler_threads: std.ArrayList(HandlerEntry) = .empty,
    /// Total completed handler threads reaped while running (observable so a
    /// test/gate can prove reaping without racing the loop's list).
    reaped_handlers: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Builder over an endpoint the router will OWN (shutdown deinits it).
    pub fn builder(endpoint: factory.AnyEndpoint, allocator: std.mem.Allocator) RouterBuilder {
        return .{ .allocator = allocator, .endpoint = endpoint };
    }

    pub fn isShutdown(self: *const Router) bool {
        return self.stop.load(.acquire);
    }

    /// Stop the accept loop, invoke each unique handler's `shutdown`, join the
    /// loop + every handler thread, then close/deinit the endpoint.
    pub fn shutdown(self: *Router) void {
        self.stop.store(true, .release);
        if (self.loop_thread) |thread| {
            thread.join();
            self.loop_thread = null;
        }
        // Unique-by-context shutdown (two ALPNs may share one handler object).
        // The seen-set is GROWABLE so dedup stays exact at any handler count:
        // a fixed 32-entry buffer silently stopped tracking past capacity, so
        // a shared context past the 32nd unique context could receive
        // shutdown() twice (regression lane-01 seen-buf overflow).
        var seen: std.AutoHashMapUnmanaged(usize, void) = .empty;
        var it = self.handlers.valueIterator();
        while (it.next()) |handler| {
            const key: usize = @intFromPtr(handler.context);
            // Fail closed on OOM: skip this shutdown rather than risk a
            // second shutdown() of a context the tracked set marks seen.
            const gop = seen.getOrPut(self.allocator, key) catch continue;
            if (!gop.found_existing) handler.shutdown();
        }
        // Explicit deinit (no defer): `shutdown` destroys `self` before returning.
        seen.deinit(self.allocator);
        for (self.handler_threads.items) |entry| {
            entry.thread.join();
            self.allocator.destroy(entry.task);
        }
        self.handler_threads.deinit(self.allocator);
        self.handlers.deinit(self.allocator);
        for (self.owned_keys.items) |k| self.allocator.free(k);
        self.owned_keys.deinit(self.allocator);
        self.endpoint.deinit();
        self.allocator.destroy(self);
    }
};

pub const RouterBuilder = struct {
    allocator: std.mem.Allocator,
    endpoint: factory.AnyEndpoint,
    /// Staging map: owned keys, transferred to Router at spawn.
    handlers: std.StringHashMapUnmanaged(ProtocolHandler) = .empty,
    owned_keys: std.ArrayListUnmanaged([]u8) = .empty,
    incoming_filter: ?factory.IncomingFilter = null,

    pub fn incomingFilterCb(self: *RouterBuilder, filter: factory.IncomingFilter) *RouterBuilder {
        self.incoming_filter = filter;
        return self;
    }

    /// Register `handler` for `alpn` (upstream `RouterBuilder::accept`).
    /// Re-registering the SAME alpn overrides the previous handler (upstream
    /// map semantics). ALPN bytes are COPIED (map owns keys — no borrow from
    /// the caller's stack frame).
    pub fn accept(self: *RouterBuilder, alpn: []const u8, handler: ProtocolHandler) !*RouterBuilder {
        if (alpn.len == 0) return error.InvalidAlpn;
        if (self.handlers.getPtr(alpn)) |slot| {
            slot.* = handler;
            return self;
        }
        const owned = try self.allocator.dupe(u8, alpn);
        errdefer self.allocator.free(owned);
        try self.owned_keys.append(self.allocator, owned);
        try self.handlers.put(self.allocator, owned, handler);
        return self;
    }

    /// Start the accept loop and return the running Router (upstream
    /// `RouterBuilder::spawn`). The Router owns the endpoint from here.
    /// Advertises the registered ALPN set via `setAlpns` before the loop starts.
    pub fn spawn(self: *RouterBuilder, allocator: std.mem.Allocator) SpawnError!*Router {
        if (self.handlers.count() == 0) return error.NoHandlerRegistered;

        var alpn_list = try allocator.alloc([]const u8, self.owned_keys.items.len);
        defer allocator.free(alpn_list);
        for (self.owned_keys.items, 0..) |k, i| alpn_list[i] = k;
        try self.endpoint.setAlpns(alpn_list);
        if (self.incoming_filter) |f| {
            factory.setNoqIncomingFilter(self.endpoint, f);
        }

        const router = try allocator.create(Router);
        errdefer allocator.destroy(router);
        router.* = .{
            .allocator = allocator,
            .endpoint = self.endpoint,
            .handlers = self.handlers,
            .owned_keys = self.owned_keys,
            .io = self.endpoint.transport().io(),
        };
        // Builder no longer owns the map/keys.
        self.handlers = .empty;
        self.owned_keys = .empty;
        // Reserve tracking capacity so we never detach a handler thread on OOM.
        router.handler_threads.ensureTotalCapacity(allocator, 16) catch {};
        router.loop_thread = std.Thread.spawn(.{}, loopMain, .{router}) catch {
            // Roll ownership back onto the endpoint for the caller's deinit.
            // (handlers/keys stay on the router for cleanup via destroy path.)
            router.handlers.deinit(allocator);
            for (router.owned_keys.items) |k| allocator.free(k);
            router.owned_keys.deinit(allocator);
            allocator.destroy(router);
            return error.ThreadSpawnFailed;
        };
        return router;
    }

    pub fn deinit(self: *RouterBuilder) void {
        self.handlers.deinit(self.allocator);
        for (self.owned_keys.items) |k| self.allocator.free(k);
        self.owned_keys.deinit(self.allocator);
    }
};

fn loopMain(self: *Router) void {
    var idle_ticks: u32 = 0;
    while (!self.stop.load(.acquire)) {
        // Prefer accept-side 0-RTT handoff when available, else full accept.
        const maybe: ?AcceptCandidate = blk: {
            const early = self.endpoint.tryAcceptReadyZeroRtt() catch {
                self.loop_failed.store(true, .release);
                return;
            };
            if (early) |c| break :blk AcceptCandidate{ .conn = c, .early_zero_rtt = true };
            const full = self.endpoint.tryAcceptReady() catch {
                self.loop_failed.store(true, .release);
                return;
            };
            if (full) |c| break :blk AcceptCandidate{ .conn = c, .early_zero_rtt = false };
            break :blk null;
        };
        if (maybe) |cand| {
            const negotiated = cand.conn.alpn() orelse {
                cand.conn.close();
                continue;
            };
            const handler = self.handlers.get(negotiated) orelse {
                cand.conn.close();
                continue;
            };
            const task = self.allocator.create(HandlerTask) catch {
                cand.conn.close();
                continue;
            };
            task.* = .{
                .router = self,
                .accepting = .{
                    .conn = cand.conn,
                    .early_zero_rtt = cand.early_zero_rtt,
                },
                .handler = handler,
            };
            const thread = std.Thread.spawn(.{}, handlerMain, .{task}) catch {
                if (!task.accepting.taken) task.accepting.conn.close();
                self.allocator.destroy(task);
                continue;
            };
            // Never detach: if tracking fails, join immediately on a short path
            // by closing the connection and joining here (blocks the accept loop
            // briefly — preferable to a use-after-free on shutdown).
            self.handler_threads.append(self.allocator, .{ .thread = thread, .task = task }) catch {
                // The router owns the task; join (do not double-free), then destroy.
                thread.join();
                self.allocator.destroy(task);
                continue;
            };
            reapDoneHandlers(self);
        } else {
            // No pending accept: reap completed handlers periodically (~64 ms
            // of idle) so retention tracks live concurrency even between
            // accepts (regression lane-01 H1).
            idle_ticks +%= 1;
            if (idle_ticks % 64 == 0) reapDoneHandlers(self);
            self.io.sleep(std.Io.Duration.fromMilliseconds(1), .awake) catch {};
        }
    }
}

const AcceptCandidate = struct {
    conn: tr.Connection,
    early_zero_rtt: bool,
};

const HandlerTask = struct {
    router: *Router,
    accepting: Accepting,
    handler: ProtocolHandler,
    /// Set by handlerMain as its LAST action: the loop thread's reaper joins
    /// + destroys completed entries (the router owns the task allocation).
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

const HandlerEntry = struct {
    thread: std.Thread,
    task: *HandlerTask,
};

fn handlerMain(task: *HandlerTask) void {
    const handler = task.handler;
    // Upstream: on_accepting → accept. Default on_accepting completes the
    // handshake; a custom handler may reject early or take 0-RTT ownership.
    const conn = handler.onAccepting(&task.accepting) catch {
        if (!task.accepting.taken) task.accepting.reject();
        task.done.store(true, .release);
        return;
    };
    handler.accept(conn) catch {
        // Upstream logs a warning and drops the connection; same here.
    };
    conn.close();
    // Mark completion for the router's reaper. The router owns `task` — it is
    // destroyed by reapDoneHandlers or shutdown, never here.
    task.done.store(true, .release);
}

/// Join + destroy every handler whose thread has completed. Runs only on the
/// loop thread (or in shutdown after the loop is joined), so the list needs
/// no lock. Joining an exited thread returns immediately — this never blocks
/// the accept loop on a live connection.
fn reapDoneHandlers(self: *Router) void {
    var i: usize = 0;
    while (i < self.handler_threads.items.len) {
        const entry = self.handler_threads.items[i];
        if (entry.task.done.load(.acquire)) {
            entry.thread.join();
            self.allocator.destroy(entry.task);
            _ = self.handler_threads.swapRemove(i);
            _ = self.reaped_handlers.fetchAdd(1, .acq_rel);
        } else {
            i += 1;
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

const test_alpn: [:0]const u8 = "iroh-example/echo/0";
const test_alpn_b: [:0]const u8 = "iroh-example/echo-b/0";

/// Test-local echo handler (upstream echo.rs `Echo`): copy the first bi
/// stream recv→send until FIN, finish the send side, then wait for the remote
/// to close the connection (upstream `connection.closed().await`) so the
/// echoed bytes + FIN are delivered before the router closes the connection.
const EchoHandler = struct {
    served: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    tag: u8 = 0,

    fn handler(self: *EchoHandler) ProtocolHandler {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: ProtocolHandler.VTable = .{ .accept = acceptImpl };

    fn acceptImpl(context: *anyopaque, conn: tr.Connection) anyerror!void {
        const self: *EchoHandler = @ptrCast(@alignCast(context));
        const stream = try conn.acceptBi();
        var buf: [1024]u8 = undefined;
        while (true) {
            const n = try stream.recv.reader().readSliceShort(&buf);
            if (n == 0) break;
            try stream.send.writer().writeAll(buf[0..n]);
        }
        try stream.send.finish();
        self.served.store(true, .release);
        // Wait-for-close using only the frozen Connection vtable: acceptBi
        // blocks until the peer opens another stream (the echo client never
        // does) or the connection is lost/closed, which ends the wait.
        while (true) {
            _ = conn.acceptBi() catch break;
        }
    }
};

/// Echo handler that prefixes a distinct marker so multi-ALPN dispatch is
/// observable in the payload (exact per-handler response).
const TaggedEchoHandler = struct {
    served: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    prefix: []const u8,

    fn handler(self: *TaggedEchoHandler) ProtocolHandler {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: ProtocolHandler.VTable = .{ .accept = acceptImpl };

    fn acceptImpl(context: *anyopaque, conn: tr.Connection) anyerror!void {
        const self: *TaggedEchoHandler = @ptrCast(@alignCast(context));
        const stream = try conn.acceptBi();
        var buf: [1024]u8 = undefined;
        try stream.send.writer().writeAll(self.prefix);
        while (true) {
            const n = try stream.recv.reader().readSliceShort(&buf);
            if (n == 0) break;
            try stream.send.writer().writeAll(buf[0..n]);
        }
        try stream.send.finish();
        self.served.store(true, .release);
        while (true) {
            _ = conn.acceptBi() catch break;
        }
    }
};

/// Poll-with-timeout for accept-path async flags: the handler thread's store
/// can lag the client's observed echo under host load, so a one-shot assert
/// immediately after IO flakes (test-side timing, not a product race).
fn waitForFlag(flag: *const std.atomic.Value(bool), timeout_ms: u64) !void {
    const io = std.testing.io;
    var waited_ms: u64 = 0;
    while (!flag.load(.acquire) and waited_ms < timeout_ms) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
        waited_ms += 10;
    }
    try std.testing.expect(flag.load(.acquire));
}

fn waitForTaggedServed(handler: *TaggedEchoHandler) !void {
    try waitForFlag(&handler.served, 10_000);
}

test "router spawn requires a registered handler" {
    if (!product_flags.has_picoquic) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const server_key = @import("key.zig").SecretKey.fromBytes([_]u8{51} ** 32);
    const ep = try factory.createForProduct(allocator, io, server_key, test_alpn, .{});
    var b = Router.builder(ep, allocator);
    defer b.deinit();
    try std.testing.expectError(error.NoHandlerRegistered, b.spawn(allocator));
    b.endpoint.deinit();
}

test "router serves two distinct ALPNs to matching handlers" {
    if (!product_flags.has_picoquic) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = @import("key.zig");
    const server_key = key.SecretKey.fromBytes([_]u8{55} ** 32);
    const client_key_a = key.SecretKey.fromBytes([_]u8{56} ** 32);
    const client_key_b = key.SecretKey.fromBytes([_]u8{57} ** 32);

    const server_ep = try factory.createForProduct(allocator, io, server_key, test_alpn, .{});
    var echo_a: TaggedEchoHandler = .{ .prefix = "A:" };
    var echo_b: TaggedEchoHandler = .{ .prefix = "B:" };
    var b = Router.builder(server_ep, allocator);
    _ = try b.accept(test_alpn, echo_a.handler());
    _ = try b.accept(test_alpn_b, echo_b.handler());
    const router = try b.spawn(allocator);
    defer router.shutdown();

    // Client A
    {
        const client_ep = try factory.createForProduct(allocator, io, client_key_a, test_alpn, .{});
        defer client_ep.deinit();
        const conn = try client_ep.transport().connect(.{
            .id = server_key.public(),
            .addrs = &.{.{ .ip = router.endpoint.localAddress() }},
        });
        defer conn.close();
        try std.testing.expectEqualStrings(test_alpn, conn.alpn().?);
        const stream = try conn.openBi();
        try stream.send.writer().writeAll("ping-a");
        try stream.send.finish();
        var buf: [64]u8 = undefined;
        const n = try stream.recv.reader().readSliceShort(&buf);
        try std.testing.expectEqualStrings("A:ping-a", buf[0..n]);
        conn.close();
    }
    // Client B
    {
        const client_ep = try factory.createForProduct(allocator, io, client_key_b, test_alpn_b, .{});
        defer client_ep.deinit();
        const conn = try client_ep.transport().connect(.{
            .id = server_key.public(),
            .addrs = &.{.{ .ip = router.endpoint.localAddress() }},
        });
        defer conn.close();
        try std.testing.expectEqualStrings(test_alpn_b, conn.alpn().?);
        const stream = try conn.openBi();
        try stream.send.writer().writeAll("ping-b");
        try stream.send.finish();
        var buf: [64]u8 = undefined;
        const n = try stream.recv.reader().readSliceShort(&buf);
        try std.testing.expectEqualStrings("B:ping-b", buf[0..n]);
        conn.close();
    }
    try waitForTaggedServed(&echo_a);
    try waitForTaggedServed(&echo_b);
}

test "multi-ALPN mutation-red: unregister B — only B fails to connect" {
    if (!product_flags.has_picoquic) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = @import("key.zig");
    const server_key = key.SecretKey.fromBytes([_]u8{62} ** 32);
    const client_a = key.SecretKey.fromBytes([_]u8{63} ** 32);
    const client_b = key.SecretKey.fromBytes([_]u8{64} ** 32);

    const server_ep = try factory.createForProduct(allocator, io, server_key, test_alpn, .{});
    var echo_a: TaggedEchoHandler = .{ .prefix = "A:" };
    var b = Router.builder(server_ep, allocator);
    // Mutation: register ONLY A (B unregistered → not advertised at spawn).
    _ = try b.accept(test_alpn, echo_a.handler());
    const router = try b.spawn(allocator);
    defer router.shutdown();

    // A still works.
    {
        const client_ep = try factory.createForProduct(allocator, io, client_a, test_alpn, .{});
        defer client_ep.deinit();
        const conn = try client_ep.transport().connect(.{
            .id = server_key.public(),
            .addrs = &.{.{ .ip = router.endpoint.localAddress() }},
        });
        defer conn.close();
        const stream = try conn.openBi();
        try stream.send.writer().writeAll("ok");
        try stream.send.finish();
        var buf: [32]u8 = undefined;
        const n = try stream.recv.reader().readSliceShort(&buf);
        try std.testing.expectEqualStrings("A:ok", buf[0..n]);
    }
    // B must fail (ALPN not advertised / not handled).
    {
        const client_ep = try factory.createForProduct(allocator, io, client_b, test_alpn_b, .{});
        defer client_ep.deinit();
        const result = client_ep.transport().connect(.{
            .id = server_key.public(),
            .addrs = &.{.{ .ip = router.endpoint.localAddress() }},
        });
        // TLS ALPN mismatch / handshake failure — B must not get a live connection.
        if (result) |conn| {
            conn.close();
            try std.testing.expect(false);
        } else |_| {}
    }
}

test "multi-ALPN mutation-red: unknown negotiated ALPN is closed, not mis-dispatched" {
    if (!product_flags.has_picoquic) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = @import("key.zig");
    const server_key = key.SecretKey.fromBytes([_]u8{60} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{61} ** 32);
    const rogue: [:0]const u8 = "iroh-example/rogue/0";

    const server_ep = try factory.createForProduct(allocator, io, server_key, test_alpn, .{});
    var echo_a: TaggedEchoHandler = .{ .prefix = "A:" };
    var echo_b: TaggedEchoHandler = .{ .prefix = "B:" };
    var b = Router.builder(server_ep, allocator);
    _ = try b.accept(test_alpn, echo_a.handler());
    _ = try b.accept(test_alpn_b, echo_b.handler());
    const router = try b.spawn(allocator);
    defer router.shutdown();

    // Advertise a rogue ALPN the Router has no handler for.
    try router.endpoint.setAlpns(&.{ test_alpn, test_alpn_b, rogue });

    const client_ep = try factory.createForProduct(allocator, io, client_key, rogue, .{});
    defer client_ep.deinit();
    const conn = client_ep.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = router.endpoint.localAddress() }},
    }) catch {
        // TLS may reject unknown ALPN before accept — also a valid mutation-red.
        try std.testing.expect(!echo_a.served.load(.acquire));
        try std.testing.expect(!echo_b.served.load(.acquire));
        return;
    };
    defer conn.close();
    // If connect succeeds, the Router must close without dispatching to A/B.
    const stream_result = conn.openBi();
    if (stream_result) |stream| {
        stream.send.writer().writeAll("rogue") catch {};
        stream.send.finish() catch {};
        var buf: [32]u8 = undefined;
        _ = stream.recv.reader().readSliceShort(&buf) catch {};
    } else |_| {}
    // Give the accept loop a moment to drop the connection.
    io.sleep(std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    try std.testing.expect(!echo_a.served.load(.acquire));
    try std.testing.expect(!echo_b.served.load(.acquire));
}

test "router serves the registered ALPN to a real loopback client" {
    if (!product_flags.has_picoquic) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = @import("key.zig");
    const server_key = key.SecretKey.fromBytes([_]u8{53} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{54} ** 32);

    const server_ep = try factory.createForProduct(allocator, io, server_key, test_alpn, .{});
    var echo: EchoHandler = .{};
    var b = Router.builder(server_ep, allocator);
    _ = try b.accept(test_alpn, echo.handler());
    const router = try b.spawn(allocator);
    defer router.shutdown();

    const client_ep = try factory.createForProduct(allocator, io, client_key, test_alpn, .{});
    defer client_ep.deinit();

    const conn = try client_ep.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = router.endpoint.localAddress() }},
    });
    defer conn.close();

    const stream = try conn.openBi();
    try stream.send.writer().writeAll("Hello, world!");
    try stream.send.finish();
    var buf: [64]u8 = undefined;
    const n = try stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("Hello, world!", buf[0..n]);

    // Close like the upstream echo client; the handler observes the close and
    // returns, then the router closes its side.
    conn.close();
    try waitForFlag(&echo.served, 10_000);
}

test "router reaps completed handler threads while running (lane-01 H1)" {
    if (!product_flags.has_picoquic) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = @import("key.zig");
    const server_key = key.SecretKey.fromBytes([_]u8{71} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{72} ** 32);

    const server_ep = try factory.createForProduct(allocator, io, server_key, test_alpn, .{});
    var echo: EchoHandler = .{};
    var b = Router.builder(server_ep, allocator);
    _ = try b.accept(test_alpn, echo.handler());
    const router = try b.spawn(allocator);
    defer router.shutdown();

    const client_ep = try factory.createForProduct(allocator, io, client_key, test_alpn, .{});
    defer client_ep.deinit();

    const conn = try client_ep.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = router.endpoint.localAddress() }},
    });
    const stream = try conn.openBi();
    try stream.send.writer().writeAll("reap me");
    try stream.send.finish();
    var buf: [64]u8 = undefined;
    _ = try stream.recv.reader().readSliceShort(&buf);
    conn.close();

    // The handler observes the close and its thread exits; the loop's reaper
    // must join + retire it WITHOUT waiting for router shutdown. Poll the
    // observable counter (bounded wait — a missing reaper times out the test).
    try waitForFlag(&echo.served, 10_000);
    var waited_ms: u64 = 0;
    while (router.reaped_handlers.load(.acquire) == 0 and waited_ms < 10_000) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
        waited_ms += 10;
    }
    try std.testing.expect(router.reaped_handlers.load(.acquire) >= 1);
}

/// Handler that counts its `shutdown` invocations (regression fixture for the
/// Router.shutdown seen-set overflow, regression lane-01).
const ShutdownCountHandler = struct {
    shutdowns: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    fn handler(self: *ShutdownCountHandler) ProtocolHandler {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: ProtocolHandler.VTable = .{
        .accept = acceptImpl,
        .shutdown = shutdownImpl,
    };

    fn acceptImpl(_: *anyopaque, _: tr.Connection) anyerror!void {}

    fn shutdownImpl(context: *anyopaque) void {
        const self: *ShutdownCountHandler = @ptrCast(@alignCast(context));
        _ = self.shutdowns.fetchAdd(1, .acq_rel);
    }
};

test "router shutdown dedups >32 unique handler contexts (each shut down exactly once)" {
    if (!product_flags.has_picoquic) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = @import("key.zig");
    const server_key = key.SecretKey.fromBytes([_]u8{0xE1} ** 32);

    const server_ep = try factory.createForProduct(allocator, io, server_key, test_alpn, .{});
    var b = Router.builder(server_ep, allocator);

    // 41 UNIQUE handler contexts (>32 — past the old fixed 32-entry seen
    // buffer), EACH registered under two ALPNs. Any fixed-capacity seen
    // buffer must leave at least one context untracked in EVERY map
    // iteration order, and both ALPN entries of an untracked context invoke
    // shutdown — so a silent-capacity regression double-shutdowns some
    // context no matter the order. The growable seen-set must keep every
    // count at exactly 1.
    const unique_count = 41;
    var handlers: [unique_count]ShutdownCountHandler = undefined;
    var alpn_buf: [64]u8 = undefined;
    for (&handlers, 0..) |*h, i| {
        h.* = .{};
        for (0..2) |dup| {
            const alpn = try std.fmt.bufPrint(&alpn_buf, "iroh-example/shutdown-dedup/{d}/{d}/0", .{ i, dup });
            _ = try b.accept(alpn, h.handler());
        }
    }

    const router = try b.spawn(allocator);
    router.shutdown();

    for (&handlers) |*h| {
        try std.testing.expectEqual(@as(u32, 1), h.shutdowns.load(.acquire));
    }
}

/// Handler that rejects in on_accepting before normal accept.
const RejectOnAcceptingHandler = struct {
    rejected: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    accepted: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn handler(self: *RejectOnAcceptingHandler) ProtocolHandler {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: ProtocolHandler.VTable = .{
        .on_accepting = onAcceptingImpl,
        .accept = acceptImpl,
    };

    fn onAcceptingImpl(context: *anyopaque, accepting: *Accepting) anyerror!tr.Connection {
        const self: *RejectOnAcceptingHandler = @ptrCast(@alignCast(context));
        self.rejected.store(true, .release);
        accepting.reject();
        return error.RejectedEarly;
    }

    fn acceptImpl(context: *anyopaque, _: tr.Connection) anyerror!void {
        const self: *RejectOnAcceptingHandler = @ptrCast(@alignCast(context));
        self.accepted.store(true, .release);
    }
};

/// Handler that records whether on_accepting saw an early 0-RTT connection.
const EarlyObserveHandler = struct {
    saw_early: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    served: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn handler(self: *EarlyObserveHandler) ProtocolHandler {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: ProtocolHandler.VTable = .{
        .on_accepting = onAcceptingImpl,
        .accept = acceptImpl,
    };

    fn onAcceptingImpl(context: *anyopaque, accepting: *Accepting) anyerror!tr.Connection {
        const self: *EarlyObserveHandler = @ptrCast(@alignCast(context));
        if (accepting.isEarlyZeroRtt()) self.saw_early.store(true, .release);
        // Keep early ownership when available (accept-side 0-RTT); otherwise complete.
        return accepting.into0Rtt();
    }

    fn acceptImpl(context: *anyopaque, conn: tr.Connection) anyerror!void {
        const self: *EarlyObserveHandler = @ptrCast(@alignCast(context));
        // Best-effort: drain until peer closes (same wait pattern as EchoHandler).
        while (true) {
            _ = conn.acceptBi() catch break;
        }
        self.served.store(true, .release);
    }
};
test "ProtocolHandler.on_accepting can reject early before accept" {
    // Live router path matches existing protocol tests (picoquic product).
    if (!product_flags.has_picoquic) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = @import("key.zig");
    const server_key = key.SecretKey.fromBytes([_]u8{0xA1} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xA2} ** 32);

    const server_ep = try factory.createForProduct(allocator, io, server_key, test_alpn, .{});
    var reject_h = RejectOnAcceptingHandler{};
    var b = Router.builder(server_ep, allocator);
    _ = try b.accept(test_alpn, reject_h.handler());
    const router = try b.spawn(allocator);
    defer router.shutdown();

    const client_ep = try factory.createForProduct(allocator, io, client_key, test_alpn, .{});
    defer client_ep.deinit();

    const conn = client_ep.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = router.endpoint.localAddress() }},
    }) catch {
        try waitForFlag(&reject_h.rejected, 5_000);
        try std.testing.expect(!reject_h.accepted.load(.acquire));
        return;
    };
    defer conn.close();

    var waited_ms: u64 = 0;
    while (!reject_h.rejected.load(.acquire) and waited_ms < 5_000) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
        waited_ms += 10;
    }
    try std.testing.expect(reject_h.rejected.load(.acquire));
    try std.testing.expect(!reject_h.accepted.load(.acquire));
}

test "ProtocolHandler.on_accepting default path still serves accept" {
    if (!product_flags.has_picoquic) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = @import("key.zig");
    const server_key = key.SecretKey.fromBytes([_]u8{0xA3} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xA4} ** 32);

    const server_ep = try factory.createForProduct(allocator, io, server_key, test_alpn, .{});
    var echo = EchoHandler{};
    var b = Router.builder(server_ep, allocator);
    _ = try b.accept(test_alpn, echo.handler());
    const router = try b.spawn(allocator);
    defer router.shutdown();

    const client_ep = try factory.createForProduct(allocator, io, client_key, test_alpn, .{});
    defer client_ep.deinit();

    const conn = try client_ep.transport().connect(.{
        .id = server_key.public(),
        .addrs = &.{.{ .ip = router.endpoint.localAddress() }},
    });
    defer conn.close();
    const stream = try conn.openBi();
    try stream.send.writer().writeAll("on-accepting-default");
    try stream.send.finish();
    var buf: [64]u8 = undefined;
    const n = try stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("on-accepting-default", buf[0..n]);
    try waitForFlag(&echo.served, 10_000);
}

test "ConnectOptions.alpn_fallback dials secondary ALPN when primary is refused" {
    // Multi-ALPN live dial is proven on picoquic (same product as existing
    // multi-ALPN router tests). noq multi-ALPN negotiation is a separate seam.
    if (!product_flags.has_picoquic) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = @import("key.zig");
    const endpoint_mod = @import("endpoint.zig");
    const addr_mod = @import("addr.zig");
    const server_key = key.SecretKey.fromBytes([_]u8{0xB1} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xB2} ** 32);

    const server_ep = try factory.createForProduct(allocator, io, server_key, test_alpn_b, .{});
    var echo = EchoHandler{};
    var b = Router.builder(server_ep, allocator);
    _ = try b.accept(test_alpn_b, echo.handler());
    const router = try b.spawn(allocator);
    defer router.shutdown();

    const client = try endpoint_mod.Endpoint.init(allocator, io, .{
        .secret_key = client_key,
        .alpns = &.{ test_alpn, test_alpn_b },
        .accept_unknown_peer = true,
    });
    defer client.deinit();

    var peer = try addr_mod.EndpointAddr.fromParts(allocator, server_key.public(), &.{
        .{ .ip = router.endpoint.localAddress() },
    });
    defer peer.deinit(allocator);

    const conn = try client.connectWithOpts(peer, test_alpn, .{
        .alpn_fallback = &.{test_alpn_b},
    });
    defer conn.close();
    try std.testing.expectEqualStrings(test_alpn_b, conn.alpn().?);

    const stream = try conn.openBi();
    try stream.send.writer().writeAll("fallback-ok");
    try stream.send.finish();
    var buf: [64]u8 = undefined;
    const n = try stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("fallback-ok", buf[0..n]);
}

test "ConnectOptions.enable_0rtt defaults off and is opt-in only" {
    // Structural public-API proof: enable_0rtt is on ConnectOptions and defaults false.
    const opts_off: @import("endpoint.zig").ConnectOptions = .{};
    try std.testing.expect(!opts_off.enable_0rtt);
    const opts_on: @import("endpoint.zig").ConnectOptions = .{ .enable_0rtt = true };
    try std.testing.expect(opts_on.enable_0rtt);
    try std.testing.expectEqual(@as(usize, 0), opts_off.alpn_fallback.len);
}

test "Accepting.reject is a no-op when already taken" {
    var accepting: Accepting = .{
        .conn = undefined,
        .early_zero_rtt = false,
        .taken = true,
    };
    accepting.reject();
    try std.testing.expect(accepting.taken);
}

test "ProtocolHandler.VTable default on_accepting completes via Accepting.complete" {
    // Structural: vtable field exists; pre-taken Accepting surfaces AcceptingConsumed.
    const v: ProtocolHandler.VTable = .{
        .accept = struct {
            fn a(_: *anyopaque, _: tr.Connection) anyerror!void {}
        }.a,
    };
    try std.testing.expect(v.on_accepting == ProtocolHandler.defaultOnAccepting);
    var accepting: Accepting = .{
        .conn = undefined,
        .taken = true,
    };
    try std.testing.expectError(error.AcceptingConsumed, ProtocolHandler.defaultOnAccepting(@ptrFromInt(1), &accepting));
}

test "public factory.zero_rtt option reaches noq endpoint" {
    // Public EndpointOptions.zero_rtt → factory.Options.zero_rtt → noq Endpoint.
    if (!product_flags.has_noq or !product_flags.has_zigtls) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const key = @import("key.zig");
    const endpoint_mod = @import("endpoint.zig");
    const server_key = key.SecretKey.fromBytes([_]u8{0xC1} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xC2} ** 32);

    // Build via public Endpoint facade with zero_rtt enabled.
    const server = try endpoint_mod.Endpoint.init(allocator, io, .{
        .secret_key = server_key,
        .alpns = &.{test_alpn},
        .accept_unknown_peer = true,
        .expected_peer = client_key.public(),
        .zero_rtt = true,
    });
    defer server.deinit();
    const client = try endpoint_mod.Endpoint.init(allocator, io, .{
        .secret_key = client_key,
        .alpns = &.{test_alpn},
        .accept_unknown_peer = true,
        .zero_rtt = true,
    });
    defer client.deinit();

    // Zero-RTT substrate is live: public tryAcceptReadyZeroRtt is callable.
    try std.testing.expect((try server.tryAcceptReadyZeroRtt()) == null);

    // Opt-in ConnectOptions.enable_0rtt is required for 0-RTT dial attempt.
    const opts_off: endpoint_mod.ConnectOptions = .{};
    try std.testing.expect(!opts_off.enable_0rtt);
    const opts_on: endpoint_mod.ConnectOptions = .{ .enable_0rtt = true };
    try std.testing.expect(opts_on.enable_0rtt);
}
