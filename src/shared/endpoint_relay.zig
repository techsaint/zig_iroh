//! Endpoint-owned home-relay lifecycle.
//!
//! Upstream's `Endpoint::online()` waits until the home relay client is
//! connected. This module owns that client for the public Zig `Endpoint`,
//! applies `ca_tls_config` at connect time (the first real effect of that
//! knob), and exposes relay datagram handles so transports can route
//! magicsock/relay-selected QUIC packets.
//!
//! `RelayMode` covers Disabled / Default / Staging / Custom. Default and
//! Staging resolve home URLs from `defaults.zig` (n0 hostnames).

const std = @import("std");
const addr = @import("addr.zig");
const key = @import("key.zig");
const product_flags = @import("product_flags.zig");
const limits = @import("limits.zig");
const relay_client = @import("root.zig").relay.client;
// Only `tr.Error` is used — the neutral contract carries it (same declaration
// the legacy `transport.zig` re-exports; type identity preserved).
const tr = @import("transport_contract.zig");
const relay_fallback = @import("transport/relay_fallback.zig");

pub const RelayMode = enum {
    /// No home relay; `online()` is a no-op success (direct-only endpoint).
    disabled,
    /// n0 production relay map (`defaults.prod`).
    default,
    /// n0 staging relay map (`defaults.staging`).
    staging,
    /// Connect the URL in `home_relay_url` (Custom map equivalent).
    custom,
};

/// Owned home-relay session: connected DERP client + bounded recv queue.
pub const HomeRelay = struct {
    const max_queue = 128;
    // Cap is NOT a local literal: HomeRelay must track the QUIC engine ceiling
    // (`limits.max_datagram`) so a raised PMTUD budget cannot silently drop
    // on the relay path. Use `limits.max_datagram` at every size site.

    const Queued = struct {
        src: key.NodeId,
        bytes: []u8,
    };

    allocator: std.mem.Allocator,
    io: std.Io,
    url_storage: []u8,
    client: relay_client.Client,
    mu: std.Io.Mutex = .init,
    queue: ?[]Queued = null,
    head: usize = 0,
    len: usize = 0,
    thread: ?std.Thread = null,
    receiver_ready: std.atomic.Value(bool) = .init(false),
    stopped: std.atomic.Value(bool) = .init(false),
    /// Observable backpressure signal (regression lane-03 H3): inbound relay
    /// datagrams dropped because the bounded recv ring was full. Before this
    /// counter the full-ring drop was silent and looked like opaque QUIC loss.
    dropped_queue_full: std.atomic.Value(u64) = .init(0),
    /// Inbound datagrams dropped because the copy allocation failed.
    dropped_alloc: std.atomic.Value(u64) = .init(0),

    /// Snapshot of the drop counters (relayed-datagram backpressure signal).
    pub const DropCounts = struct {
        queue_full: u64,
        alloc: u64,
    };

    pub fn dropCounts(self: *const HomeRelay) DropCounts {
        return .{
            .queue_full = self.dropped_queue_full.load(.acquire),
            .alloc = self.dropped_alloc.load(.acquire),
        };
    }

    pub fn url(self: *const HomeRelay) []const u8 {
        return self.url_storage;
    }

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        relay_url: []const u8,
        secret: key.SecretKey,
        insecure_skip_verify: bool,
        proxy_url: ?[]const u8,
        custom_dns_resolver: bool,
    ) !*HomeRelay {
        const self = try allocator.create(HomeRelay);
        errdefer allocator.destroy(self);
        const url_copy = try allocator.dupe(u8, relay_url);
        errdefer allocator.free(url_copy);

        self.* = .{
            .allocator = allocator,
            .io = io,
            .url_storage = url_copy,
            .client = undefined,
        };
        try self.client.connectInPlace(io, .{
            .url = addr.RelayUrl.borrowed(url_copy),
            .secret_key = secret,
            .insecure_skip_verify = insecure_skip_verify,
            .proxy_url = proxy_url,
            .custom_dns_resolver = custom_dns_resolver,
        });
        errdefer self.client.close();

        try self.startReceiver();
        return self;
    }

    pub fn deinit(self: *HomeRelay) void {
        self.stopReceiver();
        self.client.close();
        self.allocator.free(self.url_storage);
        self.allocator.destroy(self);
    }

    /// The relay-datagram handle both engines take (`relay_fallback.Client`).
    pub fn relayClient(self: *HomeRelay) relay_fallback.Client {
        return .{ .context = self, .vtable = &relay_vtable };
    }

    fn startReceiver(self: *HomeRelay) !void {
        std.debug.assert(self.thread == null);
        self.queue = try self.allocator.alloc(Queued, max_queue);
        errdefer {
            self.allocator.free(self.queue.?);
            self.queue = null;
        }
        self.stopped.store(false, .release);
        self.receiver_ready.store(false, .release);
        const thread = try std.Thread.spawn(.{}, receiverThread, .{self});
        self.thread = thread;
        while (!self.receiver_ready.load(.acquire)) std.Thread.yield() catch {};
    }

    fn stopReceiver(self: *HomeRelay) void {
        self.stopped.store(true, .release);
        self.client.stream.shutdown(self.client.io, .both) catch {};
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.queue) |queue| {
            for (0..self.len) |i| {
                const index = (self.head + i) % queue.len;
                self.allocator.free(queue[index].bytes);
            }
            self.allocator.free(queue);
            self.queue = null;
            self.head = 0;
            self.len = 0;
        }
    }

    fn receiverThread(self: *HomeRelay) void {
        self.receiver_ready.store(true, .release);
        while (!self.stopped.load(.acquire)) {
            const msg = self.client.recv() catch break;
            switch (msg) {
                .datagram => |d| self.enqueue(d.src, d.datagrams.contents),
                .datagram_batch => |d| {
                    const contents = d.datagrams.contents;
                    const seg: usize = if (d.datagrams.segment_size) |s| @as(usize, s) else contents.len;
                    var off: usize = 0;
                    while (off < contents.len) {
                        const take = @min(seg, contents.len - off);
                        self.enqueue(d.src, contents[off..][0..take]);
                        off += take;
                    }
                },
                .endpoint_gone => break,
                else => {},
            }
        }
    }

    fn enqueue(self: *HomeRelay, src: key.NodeId, data: []const u8) void {
        if (data.len == 0 or data.len > limits.max_datagram) return;
        const copy = self.allocator.dupe(u8, data) catch {
            _ = self.dropped_alloc.fetchAdd(1, .acq_rel);
            return;
        };
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        const queue = self.queue orelse {
            self.allocator.free(copy);
            return;
        };
        if (self.len >= queue.len) {
            self.allocator.free(copy);
            _ = self.dropped_queue_full.fetchAdd(1, .acq_rel);
            return;
        }
        const index = (self.head + self.len) % queue.len;
        queue[index] = .{ .src = src, .bytes = copy };
        self.len += 1;
    }

    fn send(self: *HomeRelay, dst: key.NodeId, data: []const u8) tr.Error!void {
        self.client.send(.{ .datagram = .{
            .dst = dst,
            .datagrams = .{ .ecn = .not_ect, .segment_size = null, .contents = data },
        } }) catch return error.ConnectionLost;
    }

    fn recv(self: *HomeRelay, buffer: []u8) tr.Error!?relay_fallback.Datagram {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (self.len == 0) return null;
        const queue = self.queue orelse return null;
        const item = queue[self.head];
        if (item.bytes.len > buffer.len) return error.ConnectionLost;
        @memcpy(buffer[0..item.bytes.len], item.bytes);
        const out: relay_fallback.Datagram = .{ .src = item.src, .data = buffer[0..item.bytes.len] };
        self.allocator.free(item.bytes);
        self.head = (self.head + 1) % queue.len;
        self.len -= 1;
        return out;
    }

    const relay_vtable: relay_fallback.Client.VTable = .{
        .send = relaySend,
        .recv = relayRecv,
    };

    fn relaySend(ctx: *anyopaque, dst: key.NodeId, data: []const u8) tr.Error!void {
        const self: *HomeRelay = @ptrCast(@alignCast(ctx));
        return self.send(dst, data);
    }

    fn relayRecv(ctx: *anyopaque, buffer: []u8) tr.Error!?relay_fallback.Datagram {
        const self: *HomeRelay = @ptrCast(@alignCast(ctx));
        return self.recv(buffer);
    }
};

test "HomeRelay queue-full drops are observable via drop counters" {
    // Regression lane-03 H3: before the counters, a full ring freed the datagram
    // and returned with no signal; persistent drops looked like opaque loss.
    const allocator = std.testing.allocator;
    const self = try allocator.create(HomeRelay);
    defer allocator.destroy(self);
    self.* = .{
        .allocator = allocator,
        .io = std.testing.io,
        .url_storage = try allocator.dupe(u8, "https://relay.invalid"),
        .client = undefined,
    };
    defer allocator.free(self.url_storage);
    self.queue = try allocator.alloc(HomeRelay.Queued, HomeRelay.max_queue);
    defer {
        // Drain any queued bytes, then release the ring itself.
        var buf: [limits.max_datagram]u8 = undefined;
        while ((self.recv(&buf) catch null) != null) {}
        allocator.free(self.queue.?);
    }

    const src = key.SecretKey.fromBytes([_]u8{7} ** 32).public();
    const total = HomeRelay.max_queue + 3;
    var i: usize = 0;
    while (i < total) : (i += 1) self.enqueue(src, "payload");

    // The ring holds exactly max_queue; the remaining three were dropped and
    // each drop is counted.
    try std.testing.expectEqual(@as(usize, HomeRelay.max_queue), self.len);
    const counts = self.dropCounts();
    try std.testing.expectEqual(@as(u64, 3), counts.queue_full);
    try std.testing.expectEqual(@as(u64, 0), counts.alloc);

    // Draining one slot makes room for exactly one more datagram.
    var buf: [limits.max_datagram]u8 = undefined;
    try std.testing.expect((try self.recv(&buf)) != null);
    self.enqueue(src, "payload");
    try std.testing.expectEqual(@as(u64, 3), self.dropCounts().queue_full);
}

test "HomeRelay delivers datagrams above the old 2048 relay cap" {
    // Regression guard for the two-constant drift: engine max_datagram was
    // raised to 8192 while HomeRelay silently dropped anything >2048 on the
    // inbound enqueue→recv path. Sizes must match limits.max_datagram.
    const allocator = std.testing.allocator;
    const self = try allocator.create(HomeRelay);
    defer allocator.destroy(self);
    self.* = .{
        .allocator = allocator,
        .io = std.testing.io,
        .url_storage = try allocator.dupe(u8, "https://relay.invalid"),
        .client = undefined,
    };
    defer allocator.free(self.url_storage);
    self.queue = try allocator.alloc(HomeRelay.Queued, HomeRelay.max_queue);
    defer {
        var drain: [limits.max_datagram]u8 = undefined;
        while ((self.recv(&drain) catch null) != null) {}
        allocator.free(self.queue.?);
    }

    const src = key.SecretKey.fromBytes([_]u8{9} ** 32).public();
    const sizes = [_]usize{ 2049, 4096, limits.max_datagram };
    for (sizes) |n| {
        const payload = try allocator.alloc(u8, n);
        defer allocator.free(payload);
        @memset(payload, @as(u8, @truncate(n)));
        self.enqueue(src, payload);
        try std.testing.expectEqual(@as(usize, 1), self.len);

        var buf: [limits.max_datagram]u8 = undefined;
        const got = (try self.recv(&buf)) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(src, got.src);
        try std.testing.expectEqual(n, got.data.len);
        try std.testing.expectEqualSlices(u8, payload, got.data);
        try std.testing.expectEqual(@as(usize, 0), self.len);
    }

    // Still drop above the single engine ceiling (not a second local literal).
    var oversize: [limits.max_datagram + 1]u8 = undefined;
    @memset(&oversize, 0xab);
    self.enqueue(src, &oversize);
    try std.testing.expectEqual(@as(usize, 0), self.len);
}
