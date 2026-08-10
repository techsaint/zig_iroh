//! Engine-touching FACADE tests (fork-isolation S3, migration P5 discipline).
//!
//! `endpoint.zig` / `protocol.zig` moved to `shared/` in S3; these tests could
//! not follow because they reach past the door into the concrete noq engine
//! (`quic/crypto.zig` backend introspection, `AnyEndpoint.noqPtr()` /
//! `pumpForTest()` / `liveConnectionCount()`). Tests that need a concrete
//! engine belong to the engine module — this file is their home under
//! `engine-noq/harness/`, collected by the NoQ engine root so the per-product
//! aggregate test count remains preserved.
//!
//! Test bodies are VERBATIM relocations from `src/{endpoint,protocol}.zig`
//! (only import routing changed). The private test helpers
//! (`TaggedEchoHandler`, `EarlyPayloadHandler`, the `waitFor*` polls,
//! `echoRoundTrip`) are verbatim copies of the same-named private helpers in
//! `shared/protocol.zig` — duplicated rather than made `pub` so the public
//! protocol surface does not grow test-only exports.

const std = @import("std");
const product_flags = @import("shared").product_flags;
const shared = @import("shared");
const key = shared.key;
const addr_mod = shared.addr;
const endpoint_mod = shared.endpoint;
const protocol = shared.protocol;
const tr = @import("transport");
const factory = @import("transport").factory;
const crypto = @import("../crypto.zig");

const Endpoint = endpoint_mod.Endpoint;
const Connection = endpoint_mod.Connection;
const EndpointAddr = addr_mod.EndpointAddr;
const ProtocolHandler = protocol.ProtocolHandler;
const Router = protocol.Router;
const Accepting = protocol.Accepting;

// ── Relocated from src/shared/endpoint.zig (S3) ────────────────────────────────────

test "public Endpoint 0-RTT opt-in first dial without ticket uses one normal connection" {
    if (!product_flags.has_noq or !product_flags.has_zigtls) return error.SkipZigTest;
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-public-0rtt-first-dial";
    const server_key = key.SecretKey.fromBytes([_]u8{0xD4} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xD5} ** 32);

    const server = try Endpoint.init(allocator, io, .{
        .secret_key = server_key,
        .alpns = &.{alpn},
        .expected_peer = client_key.public(),
        .accept_unknown_peer = true,
        .zero_rtt = true,
    });
    defer server.deinit();
    const client = try Endpoint.init(allocator, io, .{
        .secret_key = client_key,
        .alpns = &.{alpn},
        .accept_unknown_peer = true,
        .zero_rtt = true,
    });
    defer client.deinit();

    var peer = try EndpointAddr.fromParts(allocator, server_key.public(), &.{
        .{ .ip = server.localAddress() },
    });
    defer peer.deinit(allocator);

    try std.testing.expect(!client.inner.canOfferZeroRtt(server_key.public()));
    try std.testing.expectEqual(@as(usize, 0), client.inner.noqPtr().liveConnectionCount());

    var accept_future = io.async(struct {
        fn run(ep: *Endpoint) !Connection {
            return ep.accept();
        }
    }.run, .{server});
    const client_conn = client.connectWithOpts(peer, alpn, .{ .enable_0rtt = true }) catch |err| {
        _ = accept_future.await(io) catch {};
        return err;
    };
    const server_conn = try accept_future.await(io);

    // Old behavior left the speculative no-ticket 0-RTT entry live and then
    // performed a second normal dial. The guarded path has exactly one client
    // and one server connection.
    try std.testing.expectEqual(@as(usize, 1), client.inner.noqPtr().liveConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), server.inner.noqPtr().liveConnectionCount());
    try std.testing.expectEqual(@as(u64, 1), client.metrics().connect_successes);

    client_conn.close();
    server_conn.close();
}

// ── Relocated from src/shared/protocol.zig (S3) ────────────────────────────────────

test "public factory zero_rtt + tryAcceptReadyZeroRtt surface (noq-zigtls)" {
    // Public-caller path: factory.Options.zero_rtt, factory.tryAcceptReadyZeroRtt,
    // factory.connectZeroRtt — not *ForTest names. Live early-byte / anti-replay
    // evidence remains in transport_noq's 0-RTT substrate tests; this proves the
    // public names are reachable from protocol/endpoint callers.
    if (!product_flags.has_noq or !product_flags.has_zigtls) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    const alpn: [:0]const u8 = "iroh-public-0rtt/0";
    const server_key = key.SecretKey.fromBytes([_]u8{0xD1} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xD2} ** 32);

    const server = try factory.createForProduct(allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
        .accept_unknown_peer = true,
        .zero_rtt = true,
    });
    defer server.deinit();
    const client = try factory.createForProduct(allocator, io, client_key, alpn, .{
        .accept_unknown_peer = true,
        .zero_rtt = true,
    });
    defer client.deinit();

    // Public surfaces compile and are callable (null = no early state yet).
    try std.testing.expect((try server.tryAcceptReadyZeroRtt()) == null);
    try std.testing.expect((try client.connectZeroRtt(server_key.public(), server.localAddress())) == null);

    // Public Accepting default path rejects double-complete.
    var accepting: Accepting = .{ .conn = undefined, .taken = true };
    try std.testing.expectError(error.AcceptingConsumed, accepting.into0Rtt());
}

test "public ConnectOptions.enable_0rtt reaches Router handler with early bytes (noq-zigtls)" {
    if (!product_flags.has_noq or !product_flags.has_zigtls) return error.SkipZigTest;
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const alpn: [:0]const u8 = "iroh-public-0rtt-router-oracle";
    const first_payload = "ordinary-ticket-cache-dial";
    const early_payload = "public-router-early-bytes";
    const server_key = key.SecretKey.fromBytes([_]u8{0xD6} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xD7} ** 32);

    const server_ep = try factory.createForProduct(allocator, io, server_key, alpn, .{
        .expected_peer = client_key.public(),
        .accept_unknown_peer = true,
        .zero_rtt = true,
    });
    var handler: EarlyPayloadHandler = .{ .early_payload = early_payload };
    var builder = Router.builder(server_ep, allocator);
    _ = try builder.accept(alpn, handler.handler());
    const router = try builder.spawn(allocator);
    defer router.shutdown();

    const client = try endpoint_mod.Endpoint.init(allocator, io, .{
        .secret_key = client_key,
        .alpns = &.{alpn},
        .accept_unknown_peer = true,
        .zero_rtt = true,
    });
    defer client.deinit();

    var peer = try addr_mod.EndpointAddr.fromParts(allocator, server_key.public(), &.{
        .{ .ip = router.endpoint.localAddress() },
    });
    defer peer.deinit(allocator);

    try std.testing.expect(!client.inner.canOfferZeroRtt(server_key.public()));
    const first = try client.connectWithOpts(peer, alpn, .{});
    try echoRoundTrip(first, first_payload);
    first.close();
    try waitForRouterServed(&handler, 1);
    try waitForPublic0RttTicket(client, server_key.public());

    const early = try client.connectWithOpts(peer, alpn, .{ .enable_0rtt = true });
    try echoRoundTrip(early, early_payload);
    try waitForEarlyPayload(&handler, 2);
    early.close();
}

test "ConnectOptions.alpn_fallback works on noq-zigtls multi-ALPN Router" {
    if (!product_flags.has_noq or !product_flags.has_zigtls) return error.SkipZigTest;
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const primary: [:0]const u8 = "iroh-noq-zigtls-fallback-primary";
    const fallback: [:0]const u8 = "iroh-noq-zigtls-fallback-secondary";
    const server_key = key.SecretKey.fromBytes([_]u8{0xD8} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0xD9} ** 32);

    const server_ep = try factory.createForProduct(allocator, io, server_key, fallback, .{
        .expected_peer = client_key.public(),
        .accept_unknown_peer = true,
    });
    var echo: TaggedEchoHandler = .{ .prefix = "noq-fallback:" };
    var builder = Router.builder(server_ep, allocator);
    _ = try builder.accept(fallback, echo.handler());
    const router = try builder.spawn(allocator);
    defer router.shutdown();

    const client = try endpoint_mod.Endpoint.init(allocator, io, .{
        .secret_key = client_key,
        .alpns = &.{ primary, fallback },
        .accept_unknown_peer = true,
    });
    defer client.deinit();

    var peer = try addr_mod.EndpointAddr.fromParts(allocator, server_key.public(), &.{
        .{ .ip = router.endpoint.localAddress() },
    });
    defer peer.deinit(allocator);

    const conn = try client.connectWithOpts(peer, primary, .{ .alpn_fallback = &.{fallback} });
    defer conn.close();
    const stream = try conn.openBi();
    try stream.send.writer().writeAll("ok");
    try stream.send.finish();
    var buf: [64]u8 = undefined;
    const n = try stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings("noq-fallback:ok", buf[0..n]);
    try waitForTaggedServed(&echo);
}

// ── Test helpers (verbatim copies of shared/protocol.zig's private helpers) ──

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

/// Handler used by the public 0-RTT oracle: it takes accept-side early
/// ownership when available, echoes the first bi stream, and records that the
/// exact early payload arrived through the Router handler before 1-RTT accept.
const EarlyPayloadHandler = struct {
    early_payload: []const u8,
    saw_early: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    saw_early_payload: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    served_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn handler(self: *EarlyPayloadHandler) ProtocolHandler {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: ProtocolHandler.VTable = .{
        .on_accepting = onAcceptingImpl,
        .accept = acceptImpl,
    };

    fn onAcceptingImpl(context: *anyopaque, accepting: *Accepting) anyerror!tr.Connection {
        const self: *EarlyPayloadHandler = @ptrCast(@alignCast(context));
        if (accepting.isEarlyZeroRtt()) self.saw_early.store(true, .release);
        return accepting.into0Rtt();
    }

    fn acceptImpl(context: *anyopaque, conn: tr.Connection) anyerror!void {
        const self: *EarlyPayloadHandler = @ptrCast(@alignCast(context));
        const stream = try conn.acceptBi();
        var read_buf: [128]u8 = undefined;
        var captured: [128]u8 = undefined;
        var captured_len: usize = 0;
        while (true) {
            const n = try stream.recv.reader().readSliceShort(&read_buf);
            if (n == 0) break;
            if (captured_len + n <= captured.len) {
                @memcpy(captured[captured_len..][0..n], read_buf[0..n]);
                captured_len += n;
            }
            try stream.send.writer().writeAll(read_buf[0..n]);
        }
        if (std.mem.eql(u8, captured[0..captured_len], self.early_payload)) {
            self.saw_early_payload.store(true, .release);
        }
        _ = self.served_count.fetchAdd(1, .acq_rel);
        try stream.send.finish();
        while (true) {
            _ = conn.acceptBi() catch break;
        }
    }
};

fn echoRoundTrip(conn: anytype, payload: []const u8) !void {
    const stream = try conn.openBi();
    try stream.send.writer().writeAll(payload);
    try stream.send.finish();
    var buf: [128]u8 = undefined;
    var got_len: usize = 0;
    while (got_len < payload.len) {
        const n = try stream.recv.reader().readSliceShort(buf[got_len..]);
        if (n == 0) break;
        got_len += n;
    }
    try std.testing.expectEqualStrings(payload, buf[0..got_len]);
}

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

fn waitForPublic0RttTicket(client: *Endpoint, peer: key.NodeId) !void {
    const io = std.testing.io;
    var waited_ms: u64 = 0;
    while (!client.inner.canOfferZeroRtt(peer) and waited_ms < 10_000) {
        try client.inner.noqPtr().pumpForTest();
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
        waited_ms += 10;
    }
    try std.testing.expect(client.inner.canOfferZeroRtt(peer));
}

fn waitForEarlyPayload(handler: *EarlyPayloadHandler, min_served: u64) !void {
    const io = std.testing.io;
    var waited_ms: u64 = 0;
    while ((!handler.saw_early.load(.acquire) or !handler.saw_early_payload.load(.acquire) or
        handler.served_count.load(.acquire) < min_served) and waited_ms < 10_000)
    {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
        waited_ms += 10;
    }
    try std.testing.expect(handler.saw_early.load(.acquire));
    try std.testing.expect(handler.saw_early_payload.load(.acquire));
    try std.testing.expect(handler.served_count.load(.acquire) >= min_served);
}

fn waitForRouterServed(handler: *EarlyPayloadHandler, min_served: u64) !void {
    const io = std.testing.io;
    var waited_ms: u64 = 0;
    while (handler.served_count.load(.acquire) < min_served and waited_ms < 10_000) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
        waited_ms += 10;
    }
    try std.testing.expect(handler.served_count.load(.acquire) >= min_served);
}
