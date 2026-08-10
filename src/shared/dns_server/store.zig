//! File-backed pkarr packet store.
//!
//! Wraps the in-memory `discovery.PacketStore` and persists each key as
//! `<data_dir>/packets/<z32>.pkarr` (raw relay payload). Not a redb port —
//! durable enough for operator restarts; write batching is a separate row.

const std = @import("std");
const root = @import("../root.zig");
const discovery = root.discovery;
const metrics_mod = @import("metrics.zig");

pub const ZoneStore = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    memory: discovery.PacketStore,
    data_dir: []const u8,
    packets_dir: []u8,
    /// Lifecycle counters. Attached by `Server.init` after the store settles at
    /// its final address; null in standalone/unit use.
    metrics: ?*metrics_mod.Metrics = null,
    /// Packets older than this are dropped by `evictExpired`. 0 disables.
    /// Atomic so a SIGHUP reload can retune it under the running eviction tick.
    max_age_secs: std.atomic.Value(u64) = .init(0),
    /// Guards `memory` + the packets directory against the serve threads
    /// (HTTP PUT, DNS answer) racing the eviction tick. `std.Io.Mutex` rather
    /// than `std.atomic.Mutex` because the critical sections do file I/O, so a
    /// waiter must park instead of spin.
    mutex: std.Io.Mutex = .init,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, data_dir: []const u8) !ZoneStore {
        const packets_dir = try std.fmt.allocPrint(allocator, "{s}/packets", .{data_dir});
        errdefer allocator.free(packets_dir);
        try std.Io.Dir.cwd().createDirPath(io, data_dir);
        try std.Io.Dir.cwd().createDirPath(io, packets_dir);
        var store: ZoneStore = .{
            .allocator = allocator,
            .io = io,
            .memory = discovery.PacketStore.init(allocator),
            .data_dir = data_dir,
            .packets_dir = packets_dir,
        };
        try store.loadAll();
        return store;
    }

    pub fn deinit(self: *ZoneStore) void {
        self.memory.deinit();
        self.allocator.free(self.packets_dir);
    }

    pub fn putRelayPayload(self: *ZoneStore, public_key: root.PublicKey, payload: []const u8) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        // Sampled under the lock so the insert/update split cannot be raced.
        const replaced = self.memory.packets.contains(public_key.bytes);
        try self.memory.putRelayPayload(public_key, payload);
        try self.persist(public_key, payload);
        if (self.metrics) |m| {
            const which = if (replaced) &m.store_packets_updated else &m.store_packets_inserted;
            _ = which.fetchAdd(1, .monotonic);
        }
    }

    /// Store a relay payload the caller has already verified (e.g. DHT
    /// `.cofactored` path). Still enforces the more-recent timestamp rule
    /// without re-running signature verification.
    pub fn putVerifiedRelayPayload(self: *ZoneStore, public_key: root.PublicKey, payload: []const u8) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (payload.len < 72) return error.MalformedRelayPayload;
        const incoming_ts = discovery.Timestamp.fromBytes(payload[64..72]).micros;
        const incoming_dns = payload[72..];

        const replaced = self.memory.packets.contains(public_key.bytes);
        if (self.memory.packets.get(public_key.bytes)) |existing| {
            if (existing.len < discovery.HEADER_SIZE) return error.MalformedRelayPayload;
            const existing_payload = existing[32..];
            if (existing_payload.len < 72) return error.MalformedRelayPayload;
            const existing_ts = discovery.Timestamp.fromBytes(existing_payload[64..72]).micros;
            if (incoming_ts < existing_ts) return error.OlderPacket;
            if (incoming_ts == existing_ts and std.mem.order(u8, incoming_dns, existing_payload[72..]) != .gt)
                return error.OlderPacket;
        }

        const owned = try self.allocator.alloc(u8, 32 + payload.len);
        errdefer self.allocator.free(owned);
        @memcpy(owned[0..32], &public_key.bytes);
        @memcpy(owned[32..], payload);

        const gop = try self.memory.packets.getOrPut(public_key.bytes);
        if (gop.found_existing) {
            const old = gop.value_ptr.*;
            gop.value_ptr.* = owned;
            self.allocator.free(old);
        } else {
            gop.value_ptr.* = owned;
        }
        try self.persist(public_key, payload);
        if (self.metrics) |m| {
            const which = if (replaced) &m.store_packets_updated else &m.store_packets_inserted;
            _ = which.fetchAdd(1, .monotonic);
        }
    }

    pub fn getRelayPayload(self: *ZoneStore, public_key: root.PublicKey) ![]u8 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.memory.getRelayPayload(public_key);
    }

    /// Drop a key's packet from memory and disk. Returns false if unknown.
    pub fn remove(self: *ZoneStore, public_key: root.PublicKey) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.removeLocked(public_key, if (self.metrics) |m| &m.store_packets_removed else null);
    }

    /// Evict every packet whose signed timestamp is older than `max_age_secs`.
    /// Returns the number evicted; a no-op when `max_age_secs == 0`.
    ///
    /// `now_micros` is the same epoch the pkarr timestamp uses, so a test can
    /// force expiry by passing a future value instead of waiting a week.
    pub fn evictExpired(self: *ZoneStore, now_micros: u64) usize {
        const max_age_secs = self.max_age_secs.load(.monotonic);
        if (max_age_secs == 0) return 0;
        const max_age_micros = std.math.mul(u64, max_age_secs, std.time.us_per_s) catch return 0;
        if (now_micros <= max_age_micros) return 0;
        const cutoff = now_micros - max_age_micros;

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        // Two passes: a hash map may not be mutated while iterating it.
        var doomed: std.ArrayList([32]u8) = .empty;
        defer doomed.deinit(self.allocator);
        var it = self.memory.packets.iterator();
        while (it.next()) |entry| {
            const bytes = entry.value_ptr.*;
            if (bytes.len < discovery.HEADER_SIZE) continue;
            if (discovery.Timestamp.fromBytes(bytes[96..104]).micros >= cutoff) continue;
            doomed.append(self.allocator, entry.key_ptr.*) catch break;
        }

        var evicted: usize = 0;
        for (doomed.items) |raw_key| {
            const public_key = root.PublicKey.fromBytes(raw_key) catch continue;
            if (self.removeLocked(public_key, if (self.metrics) |m| &m.store_packets_expired else null)) {
                evicted += 1;
            }
        }
        return evicted;
    }

    fn removeLocked(
        self: *ZoneStore,
        public_key: root.PublicKey,
        counter: ?*std.atomic.Value(u64),
    ) bool {
        if (self.memory.packets.fetchRemove(public_key.bytes)) |kv| {
            self.allocator.free(kv.value);
        } else return false;

        const z32 = public_key.toZ32();
        if (std.fmt.allocPrint(self.allocator, "{s}/{s}.pkarr", .{ self.packets_dir, &z32 })) |path| {
            defer self.allocator.free(path);
            // A missing file is fine: the in-memory drop is the authoritative
            // one, and a stale file would be re-dropped on the next tick.
            std.Io.Dir.cwd().deleteFile(self.io, path) catch {};
        } else |_| {}

        if (counter) |c| _ = c.fetchAdd(1, .monotonic);
        return true;
    }

    /// Wall-clock micros — the epoch pkarr timestamps use, so `evictExpired`
    /// and a peer's signed timestamp are comparable.
    pub fn nowMicros(io: std.Io) u64 {
        const nanos = std.Io.Clock.now(.real, io).nanoseconds;
        if (nanos <= 0) return 0;
        return @intCast(@divTrunc(nanos, std.time.ns_per_us));
    }

    fn persist(self: *ZoneStore, public_key: root.PublicKey, payload: []const u8) !void {
        const z32 = public_key.toZ32();
        const path = try std.fmt.allocPrint(self.allocator, "{s}/{s}.pkarr", .{ self.packets_dir, &z32 });
        defer self.allocator.free(path);
        try std.Io.Dir.cwd().writeFile(self.io, .{ .sub_path = path, .data = payload });
    }

    fn loadAll(self: *ZoneStore) !void {
        var dir = std.Io.Dir.cwd().openDir(self.io, self.packets_dir, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer dir.close(self.io);

        var it = dir.iterate();
        while (try it.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".pkarr")) continue;
            const z32 = entry.name[0 .. entry.name.len - ".pkarr".len];
            const public_key = root.PublicKey.fromZ32(z32) catch continue;
            const path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.packets_dir, entry.name });
            defer self.allocator.free(path);
            const payload = std.Io.Dir.cwd().readFileAlloc(self.io, path, self.allocator, .limited(discovery.MAX_SIGNED_PACKET_SIZE)) catch continue;
            defer self.allocator.free(payload);
            self.memory.putRelayPayload(public_key, payload) catch continue;
        }
    }
};

test "ZoneStore persists and reloads relay payloads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-store-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    var store = try ZoneStore.init(allocator, io, rel);
    const secret = root.SecretKey.fromBytes(.{0x41} ** 32);
    const direct = try std.Io.net.IpAddress.parse("127.0.0.1", 9001);
    var endpoint_relay = try root.RelayUrl.parse(allocator, "https://relay.example");
    defer endpoint_relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{ .{ .relay = endpoint_relay }, .{ .ip = direct } },
        null,
    );
    defer info.deinit(allocator);
    var packet = try discovery.SignedPacket.fromEndpointInfoAt(allocator, secret, info, discovery.DEFAULT_TTL, .{ .micros = 11 });
    defer packet.deinit(allocator);
    try store.putRelayPayload(secret.public(), packet.relayPayload());
    store.deinit();

    var reloaded = try ZoneStore.init(allocator, io, rel);
    defer reloaded.deinit();
    const got = try reloaded.getRelayPayload(secret.public());
    defer allocator.free(got);
    try std.testing.expectEqualSlices(u8, packet.relayPayload(), got);
}

/// Sign a packet for `secret` at `micros`. Timestamps are explicit so eviction
/// tests can place a packet arbitrarily far in the past.
fn testPacketAt(
    allocator: std.mem.Allocator,
    secret: root.SecretKey,
    micros: u64,
) !discovery.SignedPacket {
    var endpoint_relay = try root.RelayUrl.parse(allocator, "https://relay.example");
    defer endpoint_relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{.{ .relay = endpoint_relay }},
        null,
    );
    defer info.deinit(allocator);
    return discovery.SignedPacket.fromEndpointInfoAt(
        allocator,
        secret,
        info,
        discovery.DEFAULT_TTL,
        .{ .micros = micros },
    );
}

test "evictExpired drops packets past max age and keeps fresh ones" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-evict-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    var metrics: metrics_mod.Metrics = .{};
    var store = try ZoneStore.init(allocator, io, rel);
    defer store.deinit();
    store.metrics = &metrics;

    const day_micros: u64 = 24 * 3600 * std.time.us_per_s;
    const now_micros: u64 = 100 * day_micros;

    const stale_secret = root.SecretKey.fromBytes(.{0x51} ** 32);
    var stale = try testPacketAt(allocator, stale_secret, now_micros - 30 * day_micros);
    defer stale.deinit(allocator);
    try store.putRelayPayload(stale_secret.public(), stale.relayPayload());

    const fresh_secret = root.SecretKey.fromBytes(.{0x52} ** 32);
    var fresh = try testPacketAt(allocator, fresh_secret, now_micros - 1 * day_micros);
    defer fresh.deinit(allocator);
    try store.putRelayPayload(fresh_secret.public(), fresh.relayPayload());

    try std.testing.expectEqual(@as(u64, 2), metrics.store_packets_inserted.load(.monotonic));

    // Age-based eviction is off by default: nothing goes away.
    try std.testing.expectEqual(@as(usize, 0), store.evictExpired(now_micros));

    store.max_age_secs.store(7 * 24 * 3600, .monotonic);
    try std.testing.expectEqual(@as(usize, 1), store.evictExpired(now_micros));
    try std.testing.expectEqual(@as(u64, 1), metrics.store_packets_expired.load(.monotonic));

    try std.testing.expectError(error.MissingPacket, store.getRelayPayload(stale_secret.public()));
    const kept = try store.getRelayPayload(fresh_secret.public());
    defer allocator.free(kept);
    try std.testing.expectEqualSlices(u8, fresh.relayPayload(), kept);

    // The backing file must go too, or a restart would resurrect the packet.
    const stale_z32 = stale_secret.public().toZ32();
    const stale_path = try std.fmt.allocPrint(allocator, "{s}/packets/{s}.pkarr", .{ rel, &stale_z32 });
    defer allocator.free(stale_path);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().openFile(io, stale_path, .{}),
    );

    // Idempotent: a second sweep finds nothing left to do.
    try std.testing.expectEqual(@as(usize, 0), store.evictExpired(now_micros));
}

test "put counters split insert from update and remove reports unknown keys" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-lifecycle-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    var metrics: metrics_mod.Metrics = .{};
    var store = try ZoneStore.init(allocator, io, rel);
    defer store.deinit();
    store.metrics = &metrics;

    const secret = root.SecretKey.fromBytes(.{0x53} ** 32);
    var first = try testPacketAt(allocator, secret, 1_000);
    defer first.deinit(allocator);
    try store.putRelayPayload(secret.public(), first.relayPayload());

    var second = try testPacketAt(allocator, secret, 2_000);
    defer second.deinit(allocator);
    try store.putRelayPayload(secret.public(), second.relayPayload());

    try std.testing.expectEqual(@as(u64, 1), metrics.store_packets_inserted.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), metrics.store_packets_updated.load(.monotonic));

    try std.testing.expect(store.remove(secret.public()));
    try std.testing.expectEqual(@as(u64, 1), metrics.store_packets_removed.load(.monotonic));
    try std.testing.expect(!store.remove(secret.public()));
    try std.testing.expectEqual(@as(u64, 1), metrics.store_packets_removed.load(.monotonic));
}
