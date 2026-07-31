//! Mainline (BEP-44) DHT fallback for the authoritative answer path.
//!
//! A zone-store miss with `mainline_enabled` enqueues the key on a background
//! resolver. The answer path stays a pure store read (returns NXDOMAIN on the
//! miss); once the resolver writes a verified packet into `ZoneStore`, the next
//! query is served from the store. Live DHT uses `discovery_dht.Client`; tests
//! inject a fixture lookup so the gate does not depend on public bootstrap
//! reachability.

const std = @import("std");
const root = @import("../root.zig");
const discovery = root.discovery;
const dht_client = @import("../discovery_dht/client.zig");
const store_mod = @import("store.zig");
const metrics_mod = @import("metrics.zig");

pub const Error = error{
    /// The mainline fallback was requested but no live DHT resolver is attached.
    MainlineClientUnavailable,
};

/// Optional injectable lookup for tests / fixtures. Returns an owned relay
/// payload (`signature || timestamp || dns-packet`) on success.
pub const InjectedLookup = *const fn (
    ctx: *anyopaque,
    allocator: std.mem.Allocator,
    public_key: root.PublicKey,
) Error![]u8;

pub const BackgroundResolver = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    store: *store_mod.ZoneStore,
    metrics: *metrics_mod.Metrics,
    running: std.atomic.Value(bool) = .init(true),
    mutex: std.Io.Mutex = .init,
    /// Pending public keys (raw 32-byte) awaiting a background resolve.
    pending: std.ArrayList([32]u8) = .empty,
    /// Dedup set so a burst of misses for one key only enqueues once.
    queued: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
    injected: ?struct { ctx: *anyopaque, func: InjectedLookup } = null,
    /// When true, attempt a live `discovery_dht.Client` get for each key.
    use_live_dht: bool = true,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        store: *store_mod.ZoneStore,
        metrics: *metrics_mod.Metrics,
    ) BackgroundResolver {
        return .{
            .allocator = allocator,
            .io = io,
            .store = store,
            .metrics = metrics,
        };
    }

    pub fn deinit(self: *BackgroundResolver) void {
        self.pending.deinit(self.allocator);
        self.queued.deinit(self.allocator);
    }

    pub fn setInjectedLookup(self: *BackgroundResolver, ctx: *anyopaque, func: InjectedLookup) void {
        self.injected = .{ .ctx = ctx, .func = func };
        self.use_live_dht = false;
    }

    pub fn initiateShutdown(self: *BackgroundResolver) void {
        self.running.store(false, .release);
    }

    /// Fast-path enqueue from the DNS answer path. Never blocks on DHT I/O.
    pub fn request(self: *BackgroundResolver, public_key: root.PublicKey) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const gop = self.queued.getOrPut(self.allocator, public_key.bytes) catch return;
        if (gop.found_existing) return;
        gop.value_ptr.* = {};
        self.pending.append(self.allocator, public_key.bytes) catch {
            _ = self.queued.remove(public_key.bytes);
            return;
        };
        _ = self.metrics.dns_mainline_enqueued.fetchAdd(1, .monotonic);
    }

    pub fn run(self: *BackgroundResolver) void {
        while (self.running.load(.acquire)) {
            const key_bytes = self.popOne() orelse {
                self.io.sleep(std.Io.Duration.fromMilliseconds(20), .awake) catch {};
                continue;
            };
            self.resolveOne(key_bytes) catch {
                _ = self.metrics.dns_mainline_unavailable.fetchAdd(1, .monotonic);
            };
        }
    }

    fn popOne(self: *BackgroundResolver) ?[32]u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.pending.items.len == 0) return null;
        const key_bytes = self.pending.orderedRemove(0);
        _ = self.queued.remove(key_bytes);
        return key_bytes;
    }

    fn resolveOne(self: *BackgroundResolver, key_bytes: [32]u8) !void {
        const public_key = root.PublicKey.fromBytes(key_bytes) catch return error.MainlineClientUnavailable;
        const payload = try self.lookupPayload(public_key);
        defer self.allocator.free(payload);

        // DHT trust boundary uses cofactored verify; HTTP pkarr PUT stays strict.
        var packet = try discovery.SignedPacket.fromRelayPayloadMode(
            self.allocator,
            public_key,
            payload,
            .cofactored,
        );
        defer packet.deinit(self.allocator);
        try self.store.putVerifiedRelayPayload(public_key, packet.relayPayload());
        _ = self.metrics.dns_mainline_resolved.fetchAdd(1, .monotonic);
    }

    fn lookupPayload(self: *BackgroundResolver, public_key: root.PublicKey) Error![]u8 {
        if (self.injected) |inj| {
            return inj.func(inj.ctx, self.allocator, public_key);
        }
        if (!self.use_live_dht) return error.MainlineClientUnavailable;
        return liveDhtLookup(self.allocator, self.io, public_key);
    }
};

/// Legacy sync seam — always unavailable. Prefer `BackgroundResolver.request`.
pub fn lookup(public_key: root.PublicKey) Error![]u8 {
    _ = public_key;
    return error.MainlineClientUnavailable;
}

fn liveDhtLookup(
    allocator: std.mem.Allocator,
    io: std.Io,
    public_key: root.PublicKey,
) Error![]u8 {
    var client = dht_client.Client.init(allocator, io) catch return error.MainlineClientUnavailable;
    defer client.deinit();
    client.resolveBootstrapNodes() catch return error.MainlineClientUnavailable;
    const result = client.get(public_key.bytes) catch return error.MainlineClientUnavailable;
    defer allocator.free(result.value);

    // BEP-44 → pkarr relay payload: signature || seq(be64 micros) || dns-packet.
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, result.seq, .big);
    const payload = allocator.alloc(u8, 64 + 8 + result.value.len) catch return error.MainlineClientUnavailable;
    @memcpy(payload[0..64], &result.signature);
    @memcpy(payload[64..72], &seq_be);
    @memcpy(payload[72..], result.value);
    return payload;
}

test "lookup reports the named dependency blocker" {
    const secret = root.SecretKey.fromBytes(.{0x7c} ** 32);
    try std.testing.expectError(error.MainlineClientUnavailable, lookup(secret.public()));
}

test "background resolver writes injected payload into ZoneStore" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-ml-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    var store = try store_mod.ZoneStore.init(allocator, io, rel);
    defer store.deinit();
    var metrics: metrics_mod.Metrics = .{};
    var resolver = BackgroundResolver.init(allocator, io, &store, &metrics);
    defer resolver.deinit();

    const secret = root.SecretKey.fromBytes(.{0x41} ** 32);
    const now = store_mod.ZoneStore.nowMicros(io);
    var endpoint_relay = try root.RelayUrl.parse(allocator, "https://relay.example");
    defer endpoint_relay.deinit(allocator);
    const direct = try std.Io.net.IpAddress.parse("127.0.0.1", 9042);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{ .{ .relay = endpoint_relay }, .{ .ip = direct } },
        null,
    );
    defer info.deinit(allocator);
    var packet = try discovery.SignedPacket.fromEndpointInfoAt(
        allocator,
        secret,
        info,
        discovery.DEFAULT_TTL,
        .{ .micros = now },
    );
    defer packet.deinit(allocator);
    const fixture_payload = try allocator.dupe(u8, packet.relayPayload());
    defer allocator.free(fixture_payload);

    const Ctx = struct {
        payload: []const u8,
        fn lookup(ctx: *anyopaque, alloc: std.mem.Allocator, key: root.PublicKey) Error![]u8 {
            _ = key;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return alloc.dupe(u8, self.payload) catch return error.MainlineClientUnavailable;
        }
    };
    var ctx: Ctx = .{ .payload = fixture_payload };
    // Injected path stores via cofactored verify — fixture is strict-signed so
    // cofactored also accepts (strict ⊂ cofactored acceptance for normal keys).
    resolver.setInjectedLookup(@ptrCast(&ctx), Ctx.lookup);

    // For the unit test, put via the injected path's verify then store helper
    // using strict-compatible bytes: use putRelayPayload after resolveOne's
    // cofactored verify. Normal Ed25519 signatures verify under both modes.
    resolver.request(secret.public());
    const thread = try std.Thread.spawn(.{}, BackgroundResolver.run, .{&resolver});
    defer {
        resolver.initiateShutdown();
        thread.join();
    }

    var waits: usize = 0;
    while (waits < 100) : (waits += 1) {
        if (metrics.dns_mainline_resolved.load(.monotonic) >= 1) break;
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    try std.testing.expect(metrics.dns_mainline_resolved.load(.monotonic) >= 1);
    const got = try store.getRelayPayload(secret.public());
    defer allocator.free(got);
    try std.testing.expectEqualSlices(u8, fixture_payload, got);
}
