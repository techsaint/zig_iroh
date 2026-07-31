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
const relay_client = @import("relay/client.zig");
const tr = @import("transport.zig");
const relay_fallback = @import("transport/relay_fallback.zig");
const noq_ep = if (product_flags.has_noq) @import("transport/transport_noq.zig") else struct {
    pub const RelayDatagram = struct { src: key.NodeId, data: []u8 };
    pub const RelayClient = struct {
        context: *anyopaque,
        vtable: *const VTable,
        pub const VTable = struct {
            send: *const fn (*anyopaque, key.NodeId, []const u8) tr.Error!void,
            recv: *const fn (*anyopaque, []u8) tr.Error!?RelayDatagram,
        };
    };
};

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
    const max_datagram = 2048;

    const Queued = struct {
        src: key.NodeId,
        bytes: []u8,
    };

    allocator: std.mem.Allocator,
    io: std.Io,
    url_storage: []u8,
    client: relay_client.Client,
    mu: std.atomic.Mutex = .unlocked,
    queue: ?[]Queued = null,
    head: usize = 0,
    len: usize = 0,
    thread: ?std.Thread = null,
    receiver_ready: std.atomic.Value(bool) = .init(false),
    stopped: std.atomic.Value(bool) = .init(false),

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

    pub fn noqClient(self: *HomeRelay) noq_ep.RelayClient {
        return .{ .context = self, .vtable = &noq_vtable };
    }

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
        if (data.len == 0 or data.len > max_datagram) return;
        const copy = self.allocator.dupe(u8, data) catch return;
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
        const queue = self.queue orelse {
            self.allocator.free(copy);
            return;
        };
        if (self.len >= queue.len) {
            self.allocator.free(copy);
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
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
        defer self.mu.unlock();
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

    const noq_vtable: noq_ep.RelayClient.VTable = .{
        .send = noqSend,
        .recv = noqRecv,
    };

    fn relaySend(ctx: *anyopaque, dst: key.NodeId, data: []const u8) tr.Error!void {
        const self: *HomeRelay = @ptrCast(@alignCast(ctx));
        return self.send(dst, data);
    }

    fn relayRecv(ctx: *anyopaque, buffer: []u8) tr.Error!?relay_fallback.Datagram {
        const self: *HomeRelay = @ptrCast(@alignCast(ctx));
        return self.recv(buffer);
    }

    fn noqSend(ctx: *anyopaque, dst: key.NodeId, data: []const u8) tr.Error!void {
        const self: *HomeRelay = @ptrCast(@alignCast(ctx));
        return self.send(dst, data);
    }

    fn noqRecv(ctx: *anyopaque, buffer: []u8) tr.Error!?noq_ep.RelayDatagram {
        const self: *HomeRelay = @ptrCast(@alignCast(ctx));
        const msg = (try self.recv(buffer)) orelse return null;
        return .{ .src = msg.src, .data = msg.data };
    }
};
