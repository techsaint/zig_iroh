//! Background republish lifecycle for discovery records.
//!
//! Periodic re-announce of the current EndpointInfo through an AddressLookup
//! (or pkarr publish function). `BackgroundRepublish` is the scheduler core
//! (tick/fake-clock testable). `BackgroundRepublishTask` owns a real
//! `std.Io.Group` loop so production start/stop does not require the caller
//! to manually drive ticks. Default interval mirrors iroh: 5 minutes.

const std = @import("std");
const root = @import("../root.zig");
const discovery = @import("discovery.zig");
const address_lookup = @import("address_lookup.zig");

pub const DEFAULT_REPUBLISH_INTERVAL_MS: u64 = 5 * 60 * 1000; // 5 minutes

pub const Error = error{
    NotRunning,
    AlreadyRunning,
    MissingEndpointInfo,
    PublishFailed,
    OutOfMemory,
};

pub const RepublishConfig = struct {
    interval_ms: u64 = DEFAULT_REPUBLISH_INTERVAL_MS,
    /// Publish immediately on start (in addition to interval ticks).
    publish_on_start: bool = true,
};

/// Tick-driven republish scheduler (unit-testable with a fake clock).
/// Prefer `BackgroundRepublishTask` for a real background lifecycle.
pub const BackgroundRepublish = struct {
    allocator: std.mem.Allocator,
    config: RepublishConfig,
    lookup: ?address_lookup.AddressLookup = null,
    /// Optional direct publish callback (pkarr store / relay) when no lookup.
    publish_fn: ?*const fn (context: *anyopaque, info: discovery.EndpointInfo) anyerror!void = null,
    publish_ctx: ?*anyopaque = null,

    current_info: ?discovery.EndpointInfo = null,
    running: bool = false,
    last_publish_ms: ?u64 = null,
    publish_count: usize = 0,
    last_error: ?anyerror = null,
    /// When true, tick never publishes (mutation control for gate).
    disabled: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: RepublishConfig) BackgroundRepublish {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *BackgroundRepublish) void {
        if (self.current_info) |*info| info.deinit(self.allocator);
        self.current_info = null;
        self.running = false;
    }

    pub fn setLookup(self: *BackgroundRepublish, lookup: address_lookup.AddressLookup) void {
        self.lookup = lookup;
    }

    pub fn setPublishFn(
        self: *BackgroundRepublish,
        context: *anyopaque,
        publishFn: *const fn (context: *anyopaque, info: discovery.EndpointInfo) anyerror!void,
    ) void {
        self.publish_ctx = context;
        self.publish_fn = publishFn;
    }

    /// Replace the EndpointInfo that will be republished.
    pub fn setEndpointInfo(self: *BackgroundRepublish, info: discovery.EndpointInfo) !void {
        if (self.current_info) |*old| old.deinit(self.allocator);
        self.current_info = try info.clone(self.allocator);
    }

    pub fn start(self: *BackgroundRepublish, now_ms: u64) !void {
        if (self.running) return error.AlreadyRunning;
        if (self.current_info == null) return error.MissingEndpointInfo;
        self.running = true;
        self.last_error = null;
        if (self.config.publish_on_start) {
            try self.publishOnce(now_ms);
        } else {
            self.last_publish_ms = now_ms;
        }
    }

    pub fn stop(self: *BackgroundRepublish) void {
        self.running = false;
    }

    pub fn isRunning(self: *const BackgroundRepublish) bool {
        return self.running;
    }

    /// Advance the scheduler. Publishes when interval has elapsed.
    pub fn tick(self: *BackgroundRepublish, now_ms: u64) !void {
        if (!self.running) return error.NotRunning;
        if (self.disabled) return; // mutation: scheduling present but publish suppressed
        const last = self.last_publish_ms orelse {
            try self.publishOnce(now_ms);
            return;
        };
        if (now_ms -% last >= self.config.interval_ms) {
            try self.publishOnce(now_ms);
        }
    }

    /// Force an immediate publish (e.g. on address change).
    pub fn publishNow(self: *BackgroundRepublish, now_ms: u64) !void {
        if (!self.running) return error.NotRunning;
        try self.publishOnce(now_ms);
    }

    fn publishOnce(self: *BackgroundRepublish, now_ms: u64) !void {
        if (self.disabled) return;
        const info = self.current_info orelse return error.MissingEndpointInfo;

        if (self.lookup) |lookup| {
            lookup.publish(info) catch |err| {
                self.last_error = err;
                return error.PublishFailed;
            };
        } else if (self.publish_fn) |pfn| {
            const ctx = self.publish_ctx orelse return error.PublishFailed;
            pfn(ctx, info) catch |err| {
                self.last_error = err;
                return error.PublishFailed;
            };
        } else {
            return error.PublishFailed;
        }

        self.last_publish_ms = now_ms;
        self.publish_count += 1;
        self.last_error = null;
    }
};

/// Real background lifecycle: start spawns an Io.Group loop that schedules
/// republish ticks; stop cancels the group. Callers do not manually tick.
pub const BackgroundRepublishTask = struct {
    io: std.Io,
    inner: BackgroundRepublish,
    group: std.Io.Group = .init,
    stop_requested: std.atomic.Value(bool) = .init(false),
    started: bool = false,
    /// Optional fake-clock injection for tests. Null → `std.Io.Clock` via `io`.
    now_ms_fn: ?*const fn () u64 = null,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, config: RepublishConfig) BackgroundRepublishTask {
        return .{
            .io = io,
            .inner = BackgroundRepublish.init(allocator, config),
        };
    }

    pub fn deinit(self: *BackgroundRepublishTask) void {
        self.stop();
        self.inner.deinit();
    }

    pub fn setLookup(self: *BackgroundRepublishTask, lookup: address_lookup.AddressLookup) void {
        self.inner.setLookup(lookup);
    }

    pub fn setPublishFn(
        self: *BackgroundRepublishTask,
        context: *anyopaque,
        publishFn: *const fn (context: *anyopaque, info: discovery.EndpointInfo) anyerror!void,
    ) void {
        self.inner.setPublishFn(context, publishFn);
    }

    pub fn setEndpointInfo(self: *BackgroundRepublishTask, info: discovery.EndpointInfo) !void {
        return self.inner.setEndpointInfo(info);
    }

    pub fn publishCount(self: *const BackgroundRepublishTask) usize {
        return self.inner.publish_count;
    }

    pub fn isRunning(self: *const BackgroundRepublishTask) bool {
        return self.started and self.inner.isRunning();
    }

    /// Start the scheduler and spawn the background loop. Does not require the
    /// caller to call `tick`.
    pub fn start(self: *BackgroundRepublishTask) !void {
        if (self.started) return error.AlreadyRunning;
        self.stop_requested.store(false, .release);
        try self.inner.start(self.currentNowMs());
        self.started = true;
        self.group.async(self.io, runLoop, .{self});
    }

    pub fn stop(self: *BackgroundRepublishTask) void {
        if (!self.started) return;
        self.stop_requested.store(true, .release);
        self.group.cancel(self.io);
        self.inner.stop();
        self.started = false;
    }

    fn currentNowMs(self: *const BackgroundRepublishTask) u64 {
        if (self.now_ms_fn) |f| return f();
        const ns = std.Io.Clock.Timestamp.now(self.io, .awake).raw.toNanoseconds();
        return @intCast(@divTrunc(ns, std.time.ns_per_ms));
    }

    fn runLoop(self: *BackgroundRepublishTask) void {
        const sleep_chunk_ms: u64 = @min(self.inner.config.interval_ms, 50);
        while (!self.stop_requested.load(.acquire)) {
            self.inner.tick(self.currentNowMs()) catch {};
            const timeout: std.Io.Timeout = .{ .duration = .{
                .raw = .fromMilliseconds(@intCast(sleep_chunk_ms)),
                .clock = .awake,
            } };
            timeout.sleep(self.io) catch {};
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const PublishCounter = struct {
    count: usize = 0,
    last_node: ?root.NodeId = null,

    fn publish(context: *anyopaque, info: discovery.EndpointInfo) anyerror!void {
        const self: *PublishCounter = @ptrCast(@alignCast(context));
        self.count += 1;
        self.last_node = info.node_id;
    }
};

test "BackgroundRepublish publishes on start and on interval ticks" {
    const allocator = std.testing.allocator;
    const secret = root.SecretKey.fromBytes(.{0xB1} ** 32);
    var relay = try root.RelayUrl.parse(allocator, "https://relay.example/");
    defer relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{.{ .relay = relay }},
        null,
    );
    defer info.deinit(allocator);

    var counter: PublishCounter = .{};
    var repub = BackgroundRepublish.init(allocator, .{
        .interval_ms = 1000,
        .publish_on_start = true,
    });
    defer repub.deinit();
    try repub.setEndpointInfo(info);
    repub.setPublishFn(&counter, PublishCounter.publish);

    try repub.start(0);
    try std.testing.expectEqual(@as(usize, 1), counter.count);
    try std.testing.expectEqual(@as(usize, 1), repub.publish_count);

    // Before interval: no additional publish.
    try repub.tick(500);
    try std.testing.expectEqual(@as(usize, 1), counter.count);

    // After interval: second publish.
    try repub.tick(1000);
    try std.testing.expectEqual(@as(usize, 2), counter.count);

    try repub.tick(2500);
    try std.testing.expectEqual(@as(usize, 3), counter.count);

    repub.stop();
    try std.testing.expectError(error.NotRunning, repub.tick(5000));
}

test "BackgroundRepublish mutation: disabled suppresses republish scheduling effect" {
    const allocator = std.testing.allocator;
    const secret = root.SecretKey.fromBytes(.{0xB2} ** 32);
    var relay = try root.RelayUrl.parse(allocator, "https://relay.example/");
    defer relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{.{ .relay = relay }},
        null,
    );
    defer info.deinit(allocator);

    var counter: PublishCounter = .{};
    var repub = BackgroundRepublish.init(allocator, .{
        .interval_ms = 100,
        .publish_on_start = true,
    });
    defer repub.deinit();
    try repub.setEndpointInfo(info);
    repub.setPublishFn(&counter, PublishCounter.publish);

    // Start with publish, then disable — further ticks must not publish.
    try repub.start(0);
    try std.testing.expectEqual(@as(usize, 1), counter.count);
    repub.disabled = true;
    try repub.tick(200);
    try repub.tick(500);
    try std.testing.expectEqual(@as(usize, 1), counter.count);
    // Mutation control statement: if `disabled` were ignored, count would be >1.
}

test "BackgroundRepublish via MemoryLookup AddressLookup" {
    const allocator = std.testing.allocator;
    const secret = root.SecretKey.fromBytes(.{0xB3} ** 32);
    var relay = try root.RelayUrl.parse(allocator, "https://relay.example/");
    defer relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{.{ .relay = relay }},
        null,
    );
    defer info.deinit(allocator);

    var mem = address_lookup.MemoryLookup.init(allocator);
    defer mem.deinit();

    var repub = BackgroundRepublish.init(allocator, .{
        .interval_ms = 50,
        .publish_on_start = true,
    });
    defer repub.deinit();
    try repub.setEndpointInfo(info);
    repub.setLookup(mem.asLookup());

    try repub.start(0);
    try std.testing.expectEqual(@as(usize, 1), mem.count());

    var resolved = try mem.asLookup().resolve(secret.public());
    defer resolved.deinit(allocator);
    try std.testing.expect(resolved.node_id.eql(secret.public()));
    try std.testing.expectEqualStrings("memory_lookup", resolved.provenance.?);

    // Republish after interval updates (still one entry, new publish count).
    try repub.tick(50);
    try std.testing.expectEqual(@as(usize, 2), repub.publish_count);
    try std.testing.expectEqual(@as(usize, 1), mem.count());
}

test "BackgroundRepublishTask background loop publishes without manual tick" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const secret = root.SecretKey.fromBytes(.{0xB5} ** 32);
    var relay = try root.RelayUrl.parse(allocator, "https://relay.example/");
    defer relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{.{ .relay = relay }},
        null,
    );
    defer info.deinit(allocator);

    var counter: PublishCounter = .{};
    // Fake clock advances on each now_ms call so the loop can fire intervals quickly.
    const Clock = struct {
        var t: u64 = 0;
        fn now() u64 {
            const cur = t;
            t +%= 60; // advance past a 50ms interval quickly
            return cur;
        }
    };
    Clock.t = 0;

    var task = BackgroundRepublishTask.init(allocator, io, .{
        .interval_ms = 50,
        .publish_on_start = true,
    });
    defer task.deinit();
    task.now_ms_fn = &Clock.now;
    try task.setEndpointInfo(info);
    task.setPublishFn(&counter, PublishCounter.publish);

    try task.start();
    try std.testing.expect(task.isRunning());
    // Allow the Io group loop to run a few iterations under testing.io.
    var spins: usize = 0;
    while (counter.count < 2 and spins < 200) : (spins += 1) {
        std.Thread.yield() catch {};
        // Drive progress for SingleThreaded / testing Io implementations.
        const nudge: std.Io.Timeout = .{ .duration = .{
            .raw = .fromMilliseconds(1),
            .clock = .awake,
        } };
        nudge.sleep(io) catch {};
    }
    try std.testing.expect(counter.count >= 2);
    try std.testing.expect(task.publishCount() >= 2);
    task.stop();
    try std.testing.expect(!task.isRunning());
    // Mutation control: if start did not schedule a loop (only publish_on_start),
    // count would stay at 1. Disabling scheduling must fail this gate.
}

test "BackgroundRepublish publishNow forces re-announce" {
    const allocator = std.testing.allocator;
    const secret = root.SecretKey.fromBytes(.{0xB4} ** 32);
    var relay = try root.RelayUrl.parse(allocator, "https://relay.example/");
    defer relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{.{ .relay = relay }},
        null,
    );
    defer info.deinit(allocator);

    var counter: PublishCounter = .{};
    var repub = BackgroundRepublish.init(allocator, .{
        .interval_ms = 10_000,
        .publish_on_start = false,
    });
    defer repub.deinit();
    try repub.setEndpointInfo(info);
    repub.setPublishFn(&counter, PublishCounter.publish);

    try repub.start(0);
    try std.testing.expectEqual(@as(usize, 0), counter.count); // publish_on_start=false
    try repub.publishNow(10);
    try std.testing.expectEqual(@as(usize, 1), counter.count);
}
