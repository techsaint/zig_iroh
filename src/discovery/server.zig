//! Self-hostable pkarr relay resolver over HTTP.

const std = @import("std");
const root = @import("../root.zig");
const discovery = @import("discovery.zig");

const net = std.Io.net;

pub const ServerOptions = struct {
    address: net.IpAddress = .{ .ip4 = .loopback(8080) },
    /// 0 disables the process-local accept-loop limiter.
    max_requests_per_second: usize = 256,
};

const RateLimiter = struct {
    max_requests: usize,
    window_start_us: ?i64 = null,
    used: usize = 0,

    fn init(max_requests: usize) RateLimiter {
        return .{ .max_requests = max_requests };
    }

    fn allow(self: *RateLimiter, io: std.Io) bool {
        return self.allowAt(std.Io.Clock.Timestamp.now(io, .awake).raw.toMicroseconds());
    }

    fn allowAt(self: *RateLimiter, now_us: i64) bool {
        if (self.max_requests == 0) return true;
        if (self.window_start_us == null or now_us - self.window_start_us.? >= std.time.us_per_s) {
            self.window_start_us = now_us;
            self.used = 0;
        }
        if (self.used >= self.max_requests) return false;
        self.used += 1;
        return true;
    }
};

pub fn serve(io: std.Io, allocator: std.mem.Allocator, options: ServerOptions) !void {
    var store = discovery.PacketStore.init(allocator);
    defer store.deinit();

    var listener = try options.address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var limiter = RateLimiter.init(options.max_requests_per_second);
    while (true) {
        var stream = listener.accept(io) catch continue;
        defer stream.close(io);
        handleAcceptedStream(io, allocator, &store, stream, &limiter);
    }
}

fn handleAcceptedStream(
    io: std.Io,
    allocator: std.mem.Allocator,
    store: *discovery.PacketStore,
    stream: net.Stream,
    limiter: *RateLimiter,
) void {
    if (!limiter.allow(io)) {
        respondRateLimited(io, stream) catch {};
        return;
    }
    handleStream(io, allocator, store, stream) catch return;
}

fn respondRateLimited(io: std.Io, stream: net.Stream) !void {
    var write_buf: [256]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeAll(
        "HTTP/1.1 429 Too Many Requests\r\n" ++
            "connection: close\r\n" ++
            "content-length: 20\r\n" ++
            "\r\n" ++
            "rate limit exceeded\n",
    );
    try writer.interface.flush();
}

pub fn handleStream(
    io: std.Io,
    allocator: std.mem.Allocator,
    store: *discovery.PacketStore,
    stream: net.Stream,
) !void {
    var read_buf: [8192]u8 = undefined;
    var write_buf: [4096]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var stream_writer = stream.writer(io, &write_buf);

    var http_server = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
    var request = try http_server.receiveHead();
    try handleRequest(allocator, store, &request);
    try stream_writer.interface.flush();
}

pub fn handleRequest(
    allocator: std.mem.Allocator,
    store: *discovery.PacketStore,
    request: *std.http.Server.Request,
) !void {
    const path = request.head.target;
    if (!std.mem.startsWith(u8, path, "/pkarr/")) {
        try request.respond("not found\n", .{ .status = .not_found, .keep_alive = false });
        return;
    }

    const z32 = path["/pkarr/".len..];
    const public_key = root.PublicKey.fromZ32(z32) catch {
        try request.respond("bad node id\n", .{ .status = .bad_request, .keep_alive = false });
        return;
    };

    switch (request.head.method) {
        .PUT => try handlePut(allocator, store, request, public_key),
        .GET => try handleGet(allocator, store, request, public_key),
        else => try request.respond("method not allowed\n", .{ .status = .method_not_allowed, .keep_alive = false }),
    }
}

fn handlePut(
    allocator: std.mem.Allocator,
    store: *discovery.PacketStore,
    request: *std.http.Server.Request,
    public_key: root.PublicKey,
) !void {
    _ = allocator;
    if (request.head.content_type) |content_type| {
        if (!std.ascii.eqlIgnoreCase(content_type, discovery.RELAY_CONTENT_TYPE)) {
            try request.respond("unsupported media type\n", .{ .status = .unsupported_media_type, .keep_alive = false });
            return;
        }
    }

    // Cap PUT body to the max signed-packet size (
    // unbounded Allocating stream was a memory DoS). Fixed writer rejects
    // oversize without heap growth proportional to attacker input.
    var body_storage: [discovery.MAX_SIGNED_PACKET_SIZE]u8 = undefined;
    var body: std.Io.Writer = .fixed(&body_storage);
    var read_buf: [1024]u8 = undefined;
    const body_reader = request.readerExpectNone(&read_buf);
    _ = body_reader.streamRemaining(&body) catch |err| switch (err) {
        error.ReadFailed => return request.respond("read failed\n", .{ .status = .bad_request, .keep_alive = false }),
        error.WriteFailed => return request.respond("payload too large\n", .{ .status = .payload_too_large, .keep_alive = false }),
    };
    const payload = body.buffered();

    store.putRelayPayload(public_key, payload) catch |err| switch (err) {
        error.OlderPacket => {
            try request.respond("", .{ .status = .no_content, .keep_alive = false });
            return;
        },
        else => {
            try request.respond("bad packet\n", .{ .status = .bad_request, .keep_alive = false });
            return;
        },
    };

    try request.respond("", .{ .status = .no_content, .keep_alive = false });
}

fn handleGet(
    allocator: std.mem.Allocator,
    store: *discovery.PacketStore,
    request: *std.http.Server.Request,
    public_key: root.PublicKey,
) !void {
    const payload = store.getRelayPayload(public_key) catch |err| switch (err) {
        error.MissingPacket => {
            try request.respond("not found\n", .{ .status = .not_found, .keep_alive = false });
            return;
        },
        else => return err,
    };
    defer allocator.free(payload);

    try request.respond(payload, .{
        .status = .ok,
        .keep_alive = false,
        .extra_headers = &.{
            .{ .name = "content-type", .value = discovery.RELAY_CONTENT_TYPE },
        },
    });
}

const TestServerContext = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    listener: *net.Server,
    store: *discovery.PacketStore,
    count: usize,
};

fn testServeN(ctx: *TestServerContext) !void {
    var limiter = RateLimiter.init(0);
    var i: usize = 0;
    while (i < ctx.count) : (i += 1) {
        var stream = try ctx.listener.accept(ctx.io);
        defer stream.close(ctx.io);
        handleAcceptedStream(ctx.io, ctx.allocator, ctx.store, stream, &limiter);
    }
}

test "pkarr relay rate limiter enforces per-window budget" {
    var limiter = RateLimiter.init(2);
    try std.testing.expect(limiter.allowAt(0));
    try std.testing.expect(limiter.allowAt(1));
    try std.testing.expect(!limiter.allowAt(2));
    try std.testing.expect(limiter.allowAt(std.time.us_per_s));
}

test "pkarr relay HTTP server round-trips through std.http.Client" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var store = discovery.PacketStore.init(allocator);
    defer store.deinit();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var ctx: TestServerContext = .{
        .io = io,
        .allocator = allocator,
        .listener = &listener,
        .store = &store,
        .count = 2,
    };
    const thread = try std.Thread.spawn(.{}, testServeN, .{&ctx});
    defer thread.join();

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    const secret = root.SecretKey.fromBytes(.{0x33} ** 32);
    const direct = try net.IpAddress.parse("127.0.0.1", 7777);
    var endpoint_relay = try root.RelayUrl.parse(allocator, "https://relay.example");
    defer endpoint_relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{ .{ .relay = endpoint_relay }, .{ .ip = direct } },
        null,
    );
    defer info.deinit(allocator);

    const relay_url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/pkarr", .{
        listener.socket.address.getPort(),
    });
    defer allocator.free(relay_url);

    try discovery.publishPkarrRelay(allocator, &client, relay_url, secret, info, discovery.DEFAULT_TTL, .{ .micros = 200 });
    const resolved = try discovery.resolvePkarrRelay(allocator, &client, relay_url, secret.public());
    defer resolved.deinit(allocator);
    try std.testing.expect(resolved.node_id.eql(secret.public()));
    try std.testing.expectEqualStrings("https://relay.example/", resolved.firstRelayUrl().?.asString());
    var resolved_ips = resolved.ipAddrs();
    try std.testing.expect(resolved_ips.next() == null);
}

test "pkarr relay HTTP server ignores stale PUT with no-content" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var store = discovery.PacketStore.init(allocator);
    defer store.deinit();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var ctx: TestServerContext = .{
        .io = io,
        .allocator = allocator,
        .listener = &listener,
        .store = &store,
        .count = 2,
    };
    const thread = try std.Thread.spawn(.{}, testServeN, .{&ctx});
    defer thread.join();

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    const secret = root.SecretKey.fromBytes(.{0x35} ** 32);
    const direct = try net.IpAddress.parse("127.0.0.1", 7778);
    const relay_url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/pkarr", .{
        listener.socket.address.getPort(),
    });
    defer allocator.free(relay_url);
    var endpoint_relay = try root.RelayUrl.parse(allocator, relay_url);
    defer endpoint_relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{ .{ .relay = endpoint_relay }, .{ .ip = direct } },
        null,
    );
    defer info.deinit(allocator);

    try discovery.publishPkarrRelay(allocator, &client, relay_url, secret, info, discovery.DEFAULT_TTL, .{ .micros = 300 });
    try discovery.publishPkarrRelay(allocator, &client, relay_url, secret, info, discovery.DEFAULT_TTL, .{ .micros = 200 });
}

test "pkarr relay HTTP server continues after malformed connection" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var store = discovery.PacketStore.init(allocator);
    defer store.deinit();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var ctx: TestServerContext = .{
        .io = io,
        .allocator = allocator,
        .listener = &listener,
        .store = &store,
        .count = 2,
    };
    const thread = try std.Thread.spawn(.{}, testServeN, .{&ctx});
    defer thread.join();

    var bad_stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    bad_stream.close(io);

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    const secret = root.SecretKey.fromBytes(.{0x36} ** 32);
    const direct = try net.IpAddress.parse("127.0.0.1", 7779);
    const relay_url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/pkarr", .{
        listener.socket.address.getPort(),
    });
    defer allocator.free(relay_url);
    var endpoint_relay = try root.RelayUrl.parse(allocator, relay_url);
    defer endpoint_relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{ .{ .relay = endpoint_relay }, .{ .ip = direct } },
        null,
    );
    defer info.deinit(allocator);

    try discovery.publishPkarrRelay(allocator, &client, relay_url, secret, info, discovery.DEFAULT_TTL, .{ .micros = 300 });
}

test "DiscoveryClient publishes and resolves through self-host relay" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var store = discovery.PacketStore.init(allocator);
    defer store.deinit();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var ctx: TestServerContext = .{
        .io = io,
        .allocator = allocator,
        .listener = &listener,
        .store = &store,
        .count = 2,
    };
    const thread = try std.Thread.spawn(.{}, testServeN, .{&ctx});
    defer thread.join();

    var http_client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http_client.deinit();

    const relay_url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/pkarr", .{
        listener.socket.address.getPort(),
    });
    defer allocator.free(relay_url);
    const client: discovery.DiscoveryClient = .{
        .allocator = allocator,
        .http_client = &http_client,
        .pkarr_relay_url = relay_url,
        .doh_url = null,
    };

    const secret = root.SecretKey.fromBytes(.{0x44} ** 32);
    const direct = try net.IpAddress.parse("127.0.0.1", 8888);
    var endpoint_relay = try root.RelayUrl.parse(allocator, relay_url);
    defer endpoint_relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{ .{ .relay = endpoint_relay }, .{ .ip = direct } },
        null,
    );
    defer info.deinit(allocator);

    try client.publish(secret, info, discovery.DEFAULT_TTL, .{ .micros = 300 });
    const resolved = try client.resolve(secret.public());
    defer resolved.deinit(allocator);
    try std.testing.expect(resolved.node_id.eql(secret.public()));
    try std.testing.expectEqualStrings(relay_url, resolved.firstRelayUrl().?.asString());
    var resolved_ips = resolved.ipAddrs();
    try std.testing.expect(resolved_ips.next() == null);
}
