//! Process orchestration: HTTP + UDP/TCP DNS + optional metrics listeners.
//!
//! `Server` points at heap-owned `Shared` state; detached connection handlers
//! retain `Shared` so they cannot outlive stack `Server` storage.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("../root.zig");
const discovery = root.discovery;
const dns_wire = root.dns_wire;
const config_mod = @import("config.zig");
const dns_handler = @import("dns.zig");
const http_mod = @import("http.zig");
const mainline_mod = @import("mainline.zig");
const metrics_mod = @import("metrics.zig");
const store_mod = @import("store.zig");
const tls_mod = @import("tls.zig");
const tls_wrapper = @import("../relay/tls_wrapper.zig");

const net = std.Io.net;

const udp_idle_timeout: std.Io.Timeout = .{
    .duration = .{ .raw = .fromMilliseconds(100), .clock = .awake },
};

/// How often `run` sweeps the zone store for packets past `packet_max_age_secs`.
const evict_interval_ms: u64 = 1_000;
const handler_drain_poll_ms: u64 = 10;
const handler_drain_max_waits: usize = 500;

pub const Server = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    shared: *Shared,
    config: *config_mod.Config,
    /// Config generation the serve threads read. Points at `config` until a
    /// reload publishes a newer one.
    config_live: *dns_handler.ConfigSource,
    store: *store_mod.ZoneStore,
    metrics: *metrics_mod.Metrics,
    dns: *dns_handler.Handler,
    put_limiter: *http_mod.PutRateLimiter,
    running: std.atomic.Value(bool) = .init(true),
    data_dir_owned: []u8,
    /// In-flight TCP DNS + HTTP(+HTTPS) handler threads (bounded concurrency).
    active_handlers: *std.atomic.Value(u32),
    /// Optional PEM material for the live HTTPS listener (self_signed/manual).
    tls_cert_path: ?[]const u8 = null,
    tls_key_path: ?[]const u8 = null,
    /// Background mainline DHT resolver; null when mainline is disabled.
    mainline_resolver: ?*mainline_mod.BackgroundResolver = null,
    /// Filled after `run` binds (for tests / operator introspection).
    bound_http_port: std.atomic.Value(u16) = .init(0),
    bound_https_port: std.atomic.Value(u16) = .init(0),
    bound_dns_port: std.atomic.Value(u16) = .init(0),
    bound_metrics_port: std.atomic.Value(u16) = .init(0),
    /// Bumped by each completed reload so a test can wait for one to land.
    reload_generation: std.atomic.Value(u32) = .init(0),
    /// Config generations published by `reloadFromFile`, newest last.
    generations: *std.ArrayList(*Generation),

    /// One reloaded config plus the arena holding its strings. Kept alive after
    /// it is superseded because an in-flight request may still be reading it;
    /// released in `deinit`, once the serve threads have joined.
    pub const Generation = struct {
        arena: std.heap.ArenaAllocator,
        config: config_mod.Config,
    };

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        config: config_mod.Config,
        config_live: dns_handler.ConfigSource = undefined,
        store: store_mod.ZoneStore,
        metrics: metrics_mod.Metrics = .{},
        dns: dns_handler.Handler = undefined,
        put_limiter: http_mod.PutRateLimiter = .{},
        data_dir_owned: []u8,
        active_handlers: std.atomic.Value(u32) = .init(0),
        tls_cert_path: ?[]const u8 = null,
        tls_key_path: ?[]const u8 = null,
        mainline_resolver: ?*mainline_mod.BackgroundResolver = null,
        generations: std.ArrayList(*Generation) = .empty,
        refs: std.atomic.Value(u32) = .init(1),

        fn create(allocator: std.mem.Allocator, io: std.Io, config: config_mod.Config) !*Shared {
            const shared = try allocator.create(Shared);
            errdefer allocator.destroy(shared);

            const data_dir = try config_mod.resolveDataDir(allocator, &config);
            errdefer allocator.free(data_dir);

            var store = try store_mod.ZoneStore.init(allocator, io, data_dir);
            errdefer store.deinit();

            shared.* = .{
                .allocator = allocator,
                .io = io,
                .config = config,
                .store = store,
                .data_dir_owned = data_dir,
                .put_limiter = .{ .limit_per_window = .init(config.pkarr_put_rate_limit) },
            };
            shared.config_live = .init(&shared.config);
            shared.store.metrics = &shared.metrics;
            shared.store.max_age_secs = .init(config.packet_max_age_secs);
            shared.dns = .{
                .allocator = allocator,
                .config = &shared.config,
                .store = &shared.store,
                .metrics = &shared.metrics,
                .config_source = &shared.config_live,
                .mainline_resolver = null,
            };
            // Shared OWNS the resolver when mainline is enabled at init (a
            // SIGHUP reload only gates the answer path; existence stays an
            // init-time decision, as before). Freed in release, so a detached
            // handler retaining Shared also keeps the resolver alive.
            if (config.mainline_enabled) {
                const resolver = try allocator.create(mainline_mod.BackgroundResolver);
                resolver.* = mainline_mod.BackgroundResolver.init(allocator, io, &shared.store, &shared.metrics);
                shared.mainline_resolver = resolver;
                shared.dns.mainline_resolver = resolver;
            }
            return shared;
        }

        fn retain(self: *Shared) *Shared {
            _ = self.refs.fetchAdd(1, .acq_rel);
            return self;
        }

        fn release(self: *Shared) void {
            const prev = self.refs.fetchSub(1, .acq_rel);
            std.debug.assert(prev > 0);
            if (prev != 1) return;

            // Free the Shared-owned resolver before the store it borrows, and
            // only here: the last handler released, so no late `answer` can
            // still reach `request`.
            if (self.mainline_resolver) |resolver| {
                resolver.deinit();
                self.allocator.destroy(resolver);
            }
            self.store.deinit();
            // Safe here and only here: either run drained every handler, or late
            // detached handlers retained this Shared block and are now done.
            for (self.generations.items) |gen| {
                gen.arena.deinit();
                self.allocator.destroy(gen);
            }
            self.generations.deinit(self.allocator);
            self.allocator.free(self.data_dir_owned);
            self.allocator.destroy(self);
        }
    };

    /// Out-pointer init: pointers inside `dns` target heap-owned Shared storage
    /// so detached handlers cannot outlive stack `Server` storage.
    pub fn init(self: *Server, allocator: std.mem.Allocator, io: std.Io, config: config_mod.Config) !void {
        try config_mod.validate(&config);
        const shared = try Shared.create(allocator, io, config);
        self.* = .{
            .io = io,
            .allocator = allocator,
            .shared = shared,
            .config = &shared.config,
            .config_live = &shared.config_live,
            .store = &shared.store,
            .metrics = &shared.metrics,
            .dns = &shared.dns,
            .put_limiter = &shared.put_limiter,
            .data_dir_owned = shared.data_dir_owned,
            .active_handlers = &shared.active_handlers,
            .mainline_resolver = shared.mainline_resolver,
            .generations = &shared.generations,
        };
    }

    /// Attach PEM paths for the HTTPS accept loop (self_signed / manual).
    /// Paths must outlive `run` (typically under `cert_cache`).
    pub fn setTlsMaterial(self: *Server, cert_path: []const u8, key_path: []const u8) void {
        self.tls_cert_path = cert_path;
        self.tls_key_path = key_path;
        self.shared.tls_cert_path = cert_path;
        self.shared.tls_key_path = key_path;
    }

    /// Adopt the reloadable fields of `path` into a new config generation.
    ///
    /// Publishing is one atomic pointer store, so a concurrent request sees
    /// either the whole old generation or the whole new one — never a half-updated
    /// struct. The superseded generation is retired rather than freed for the same
    /// reason; `deinit` releases them all. Fails without changing anything if the
    /// file is unparseable or invalid.
    pub fn reloadFromFile(self: *Server, path: []const u8) !void {
        const gen = try self.allocator.create(Generation);
        errdefer self.allocator.destroy(gen);
        gen.* = .{ .arena = .init(self.allocator), .config = undefined };
        errdefer gen.arena.deinit();

        const fields = try config_mod.reloadableFromFile(gen.arena.allocator(), self.io, path);
        gen.config = self.config_live.load(.acquire).*;
        config_mod.applyReloadable(&gen.config, fields);

        try self.generations.append(self.allocator, gen);
        self.config_live.store(&gen.config, .release);

        // Both live outside the config struct, so retune them explicitly.
        self.put_limiter.limit_per_window.store(gen.config.pkarr_put_rate_limit, .monotonic);
        self.store.max_age_secs.store(gen.config.packet_max_age_secs, .monotonic);
        _ = self.reload_generation.fetchAdd(1, .release);
    }

    pub fn deinit(self: *Server) void {
        self.shared.release();
    }

    pub fn initiateShutdown(self: *Server) void {
        self.running.store(false, .release);
    }

    pub fn run(self: *Server) !void {
        const http_addr = try parseIp(self.config.http_addr orelse return error.NothingToServe);
        var http_listener = try http_addr.listen(self.io, .{ .reuse_address = true });
        defer http_listener.deinit(self.io);
        self.bound_http_port.store(http_listener.socket.address.getPort(), .release);

        var https_listener: ?net.Server = null;
        defer if (https_listener) |*l| l.deinit(self.io);
        if (self.tls_cert_path != null and self.tls_key_path != null) {
            if (self.config.https_addr) |https_s| {
                const https_addr = try parseIp(https_s);
                https_listener = try https_addr.listen(self.io, .{ .reuse_address = true });
                self.bound_https_port.store(https_listener.?.socket.address.getPort(), .release);
            }
        }

        var dns_bind = try parseIp(self.config.dns_addr);
        const dns_socket = try dns_bind.bind(self.io, .{ .mode = .dgram, .protocol = .udp });
        // Ephemeral UDP port (…:0) must be mirrored onto the TCP listener.
        dns_bind.setPort(dns_socket.address.getPort());
        self.bound_dns_port.store(dns_bind.getPort(), .release);

        // TCP DNS on the same host:port (RFC 1035 length-prefixed messages).
        var dns_tcp_listener = try dns_bind.listen(self.io, .{ .reuse_address = true });
        defer dns_tcp_listener.deinit(self.io);

        var metrics_listener: ?net.Server = null;
        defer if (metrics_listener) |*l| l.deinit(self.io);
        if (!self.config.metrics_disabled) {
            if (self.config.metrics_addr) |addr_s| {
                const maddr = try parseIp(addr_s);
                metrics_listener = try maddr.listen(self.io, .{ .reuse_address = true });
                self.bound_metrics_port.store(metrics_listener.?.socket.address.getPort(), .release);
            }
        }

        var mainline_thread: ?std.Thread = null;
        if (self.mainline_resolver) |resolver| {
            mainline_thread = try std.Thread.spawn(.{}, mainline_mod.BackgroundResolver.run, .{resolver});
        }
        defer if (mainline_thread) |t| {
            if (self.mainline_resolver) |resolver| resolver.initiateShutdown();
            t.join();
        };

        const http_thread = try std.Thread.spawn(.{}, httpAcceptLoop, .{ self, &http_listener });
        var https_thread: ?std.Thread = null;
        if (https_listener) |*hl| {
            https_thread = try std.Thread.spawn(.{}, httpsAcceptLoop, .{ self, hl });
        }
        const dns_udp_thread = try std.Thread.spawn(.{}, dnsUdpLoop, .{ self, dns_socket });
        const dns_tcp_thread = try std.Thread.spawn(.{}, dnsTcpAcceptLoop, .{ self, &dns_tcp_listener });
        var metrics_thread: ?std.Thread = null;
        if (metrics_listener) |*ml| {
            metrics_thread = try std.Thread.spawn(.{}, metricsAcceptLoop, .{ self, ml });
        }

        // Supervisor loop: also the eviction tick, so no extra thread is needed.
        var since_evict_ms: u64 = 0;
        while (self.running.load(.acquire)) {
            self.io.sleep(std.Io.Duration.fromMilliseconds(50), .awake) catch {};
            since_evict_ms += 50;
            if (since_evict_ms >= evict_interval_ms) {
                since_evict_ms = 0;
                _ = self.store.evictExpired(store_mod.ZoneStore.nowMicros(self.io));
            }
        }

        // Wake accept loops via shutdown. Do NOT close the UDP socket yet —
        // Debug Io treats concurrent close+receiveTimeout as BADF programmer-bug
        // panic. The UDP loop exits on the next receive timeout after `running`
        // clears; close the datagram socket only after that join.
        const hs: net.Stream = .{ .socket = http_listener.socket };
        hs.shutdown(self.io, .both) catch {};
        if (https_listener) |*hl| {
            const xs: net.Stream = .{ .socket = hl.socket };
            xs.shutdown(self.io, .both) catch {};
        }
        const ts: net.Stream = .{ .socket = dns_tcp_listener.socket };
        ts.shutdown(self.io, .both) catch {};
        if (metrics_listener) |*ml| {
            const ms: net.Stream = .{ .socket = ml.socket };
            ms.shutdown(self.io, .both) catch {};
        }

        http_thread.join();
        if (https_thread) |t| t.join();
        dns_tcp_thread.join();
        dns_udp_thread.join();
        dns_socket.close(self.io);
        if (metrics_thread) |t| t.join();

        // Detached handlers may still be draining; wait before tearing down
        // Server storage they read, but keep shutdown bounded.
        _ = drainActiveHandlersBounded(self.io, self.active_handlers, handler_drain_max_waits);
    }
};

fn drainActiveHandlersBounded(io: std.Io, active_handlers: *std.atomic.Value(u32), max_waits: usize) bool {
    var waits: usize = 0;
    while (active_handlers.load(.acquire) > 0 and waits < max_waits) : (waits += 1) {
        io.sleep(std.Io.Duration.fromMilliseconds(@intCast(handler_drain_poll_ms)), .awake) catch {};
    }
    return active_handlers.load(.acquire) == 0;
}

fn reserveHandlerSlot(self: *Server) bool {
    const max = self.config.max_concurrent_connections;
    while (self.running.load(.acquire)) {
        const cur = self.active_handlers.load(.acquire);
        if (cur >= max) return false;
        if (self.active_handlers.cmpxchgWeak(cur, cur + 1, .acq_rel, .acquire) == null) return true;
    }
    return false;
}

fn releaseHandlerSlot(shared: *Server.Shared) void {
    _ = shared.active_handlers.fetchSub(1, .acq_rel);
}

fn httpAcceptLoop(self: *Server, listener: *net.Server) void {
    while (self.running.load(.acquire)) {
        var stream = listener.accept(self.io) catch break;
        if (!reserveHandlerSlot(self)) {
            stream.close(self.io);
            continue;
        }
        const shared = self.shared.retain();
        const thread = std.Thread.spawn(.{}, httpConnThread, .{ shared, stream }) catch {
            shared.release();
            releaseHandlerSlot(self.shared);
            stream.close(self.io);
            continue;
        };
        thread.detach();
    }
}

fn httpConnThread(shared: *Server.Shared, stream: net.Stream) void {
    defer shared.release();
    defer releaseHandlerSlot(shared);
    defer stream.close(shared.io);
    handleHttpStream(shared, stream) catch {};
}

fn httpsAcceptLoop(self: *Server, listener: *net.Server) void {
    while (self.running.load(.acquire)) {
        var stream = listener.accept(self.io) catch break;
        if (!reserveHandlerSlot(self)) {
            stream.close(self.io);
            continue;
        }
        const shared = self.shared.retain();
        const thread = std.Thread.spawn(.{}, httpsConnThread, .{ shared, stream }) catch {
            shared.release();
            releaseHandlerSlot(self.shared);
            stream.close(self.io);
            continue;
        };
        thread.detach();
    }
}

fn httpsConnThread(shared: *Server.Shared, stream: net.Stream) void {
    defer shared.release();
    defer releaseHandlerSlot(shared);
    // TlsServer.close owns the TCP stream close.
    handleHttpsStream(shared, stream) catch {
        stream.close(shared.io);
    };
}

const ConnWatchdog = struct {
    stream: *net.Stream,
    io: std.Io,
    timeout_ms: u64,
    timed_out: *std.atomic.Value(bool),
    /// Set when the handler finishes so join does not wait out the full envelope.
    cancel: *std.atomic.Value(bool),
    fn run(wd: *@This()) void {
        // Slice the sleep so a finished handler can cancel without paying the
        // full deadline (otherwise every successful request stalls ~timeout_ms).
        var remaining = wd.timeout_ms;
        while (remaining > 0) {
            if (wd.cancel.load(.acquire)) return;
            const slice: u64 = @min(remaining, 20);
            wd.io.sleep(std.Io.Duration.fromMilliseconds(@intCast(slice)), .awake) catch {};
            remaining -= slice;
        }
        if (wd.cancel.load(.acquire)) return;
        wd.timed_out.store(true, .release);
        wd.stream.shutdown(wd.io, .both) catch {};
    }
};

fn armConnWatchdog(
    stream: *net.Stream,
    io: std.Io,
    timeout_ms: u64,
    timed_out: *std.atomic.Value(bool),
    cancel: *std.atomic.Value(bool),
    watchdog: *ConnWatchdog,
) ?std.Thread {
    if (timeout_ms == 0) return null;
    watchdog.* = .{
        .stream = stream,
        .io = io,
        .timeout_ms = timeout_ms,
        .timed_out = timed_out,
        .cancel = cancel,
    };
    return std.Thread.spawn(.{}, ConnWatchdog.run, .{watchdog}) catch null;
}

fn disarmConnWatchdog(cancel: *std.atomic.Value(bool), wd_thread: ?std.Thread) void {
    cancel.store(true, .release);
    if (wd_thread) |t| t.join();
}

fn handleHttpsStream(shared: *Server.Shared, stream: net.Stream) !void {
    const cert = shared.tls_cert_path orelse return error.SelfSignedListenerNotWired;
    const key = shared.tls_key_path orelse return error.SelfSignedListenerNotWired;

    var timed_out = std.atomic.Value(bool).init(false);
    var cancel = std.atomic.Value(bool).init(false);
    var watchdog_stream = stream;
    var watchdog: ConnWatchdog = undefined;
    const wd_thread = armConnWatchdog(
        &watchdog_stream,
        shared.io,
        shared.config.connection_read_timeout_ms,
        &timed_out,
        &cancel,
        &watchdog,
    );
    defer disarmConnWatchdog(&cancel, wd_thread);

    const tls_srv = tls_wrapper.TlsServer.accept(shared.allocator, shared.io, stream, cert, key) catch {
        if (timed_out.load(.acquire)) return error.ConnectionTimedOut;
        return error.TlsHandshakeFailed;
    };
    defer tls_srv.deinit();

    var http_server = std.http.Server.init(tls_srv.reader(), tls_srv.writer());
    var request = http_server.receiveHead() catch {
        if (timed_out.load(.acquire)) return error.ConnectionTimedOut;
        return error.HttpRequestFailed;
    };

    var ip_buf: [64]u8 = undefined;
    const client_ip = formatClientIp(stream.socket.address, &ip_buf);
    var app: http_mod.App = .{
        .allocator = shared.allocator,
        .io = shared.io,
        .store = &shared.store,
        .dns = &shared.dns,
        .metrics = &shared.metrics,
        .put_limiter = &shared.put_limiter,
        .client_ip = client_ip,
    };
    try http_mod.handleRequest(&app, &request);
    try tls_srv.writer().flush();
}

fn handleHttpStream(shared: *Server.Shared, stream: net.Stream) !void {
    var timed_out = std.atomic.Value(bool).init(false);
    var cancel = std.atomic.Value(bool).init(false);
    var watchdog_stream = stream;
    var watchdog: ConnWatchdog = undefined;
    const wd_thread = armConnWatchdog(
        &watchdog_stream,
        shared.io,
        shared.config.connection_read_timeout_ms,
        &timed_out,
        &cancel,
        &watchdog,
    );
    defer disarmConnWatchdog(&cancel, wd_thread);

    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var stream_reader = stream.reader(shared.io, &read_buf);
    var stream_writer = stream.writer(shared.io, &write_buf);
    var http_server = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
    var request = http_server.receiveHead() catch {
        if (timed_out.load(.acquire)) return error.ConnectionTimedOut;
        return error.HttpRequestFailed;
    };

    // `accept` fills the socket's address with the PEER's, which is the rate
    // limit key. Host only: a client's source port changes per connection, so
    // keying on it would hand every reconnect a fresh budget.
    var ip_buf: [64]u8 = undefined;
    const client_ip = formatClientIp(stream.socket.address, &ip_buf);

    var app: http_mod.App = .{
        .allocator = shared.allocator,
        .io = shared.io,
        .store = &shared.store,
        .dns = &shared.dns,
        .metrics = &shared.metrics,
        .put_limiter = &shared.put_limiter,
        .client_ip = client_ip,
    };
    try http_mod.handleRequest(&app, &request);
    try stream_writer.interface.flush();
}

/// Textual host part of `address`. `IpAddress.format` appends `:port` (and
/// brackets for v6), so trim that off to get a stable per-client key.
fn formatClientIp(address: net.IpAddress, buf: []u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.print("{f}", .{address}) catch return "";
    const text = w.buffered();
    if (text.len != 0 and text[0] == '[') {
        // "[2001:db8::1]:443" → "2001:db8::1"
        if (std.mem.lastIndexOfScalar(u8, text, ']')) |close| return text[1..close];
        return text;
    }
    if (std.mem.lastIndexOfScalar(u8, text, ':')) |colon| return text[0..colon];
    return text;
}

fn dnsUdpLoop(self: *Server, socket: net.Socket) void {
    var buf: [2048]u8 = undefined;
    while (self.running.load(.acquire)) {
        const recv = socket.receiveTimeout(self.io, &buf, udp_idle_timeout) catch |err| switch (err) {
            error.Timeout => continue,
            else => break,
        };
        _ = self.metrics.dns_requests_udp.fetchAdd(1, .monotonic);
        const resp = self.dns.answer(recv.data) catch {
            _ = self.metrics.dns_query_errors.fetchAdd(1, .monotonic);
            continue;
        };
        defer self.allocator.free(resp);
        var from = recv.from;
        socket.send(self.io, &from, resp) catch {};
    }
}

fn dnsTcpAcceptLoop(self: *Server, listener: *net.Server) void {
    while (self.running.load(.acquire)) {
        var stream = listener.accept(self.io) catch break;
        if (!reserveHandlerSlot(self)) {
            stream.close(self.io);
            continue;
        }
        const shared = self.shared.retain();
        const thread = std.Thread.spawn(.{}, dnsTcpConnThread, .{ shared, stream }) catch {
            shared.release();
            releaseHandlerSlot(self.shared);
            stream.close(self.io);
            continue;
        };
        thread.detach();
    }
}

fn dnsTcpConnThread(shared: *Server.Shared, stream: net.Stream) void {
    defer shared.release();
    defer releaseHandlerSlot(shared);
    defer stream.close(shared.io);
    handleDnsTcp(shared, stream) catch {
        _ = shared.metrics.dns_query_errors.fetchAdd(1, .monotonic);
    };
}

fn handleDnsTcp(shared: *Server.Shared, stream: net.Stream) !void {
    _ = shared.metrics.dns_requests_tcp.fetchAdd(1, .monotonic);

    var timed_out = std.atomic.Value(bool).init(false);
    var cancel = std.atomic.Value(bool).init(false);
    var watchdog_stream = stream;
    var watchdog: ConnWatchdog = undefined;
    const wd_thread = armConnWatchdog(
        &watchdog_stream,
        shared.io,
        shared.config.connection_read_timeout_ms,
        &timed_out,
        &cancel,
        &watchdog,
    );
    defer disarmConnWatchdog(&cancel, wd_thread);

    var len_buf: [2]u8 = undefined;
    var read_buf: [64]u8 = undefined;
    var reader = stream.reader(shared.io, &read_buf);
    reader.interface.readSliceAll(&len_buf) catch {
        if (timed_out.load(.acquire)) return error.ConnectionTimedOut;
        return error.DnsTcpReadFailed;
    };
    const msg_len = std.mem.readInt(u16, &len_buf, .big);
    if (msg_len == 0 or msg_len > 4096) return error.DnsTcpTooLarge;
    const query = try shared.allocator.alloc(u8, msg_len);
    defer shared.allocator.free(query);
    reader.interface.readSliceAll(query) catch {
        if (timed_out.load(.acquire)) return error.ConnectionTimedOut;
        return error.DnsTcpReadFailed;
    };

    const resp = try shared.dns.answer(query);
    defer shared.allocator.free(resp);
    if (resp.len > 65535) return error.DnsTcpTooLarge;

    var write_buf: [64]u8 = undefined;
    var writer = stream.writer(shared.io, &write_buf);
    var out_len: [2]u8 = undefined;
    std.mem.writeInt(u16, &out_len, @intCast(resp.len), .big);
    try writer.interface.writeAll(&out_len);
    try writer.interface.writeAll(resp);
    try writer.interface.flush();
}

fn metricsAcceptLoop(self: *Server, listener: *net.Server) void {
    while (self.running.load(.acquire)) {
        const stream = listener.accept(self.io) catch break;
        metrics_mod.serveOne(self.io, stream, self.metrics);
    }
}

fn parseIp(addr: []const u8) !net.IpAddress {
    const parts = try config_mod.splitBindAddr(addr);
    return net.IpAddress.parse(parts.host, parts.port);
}

test "Server.init out-pointer keeps handler pointers live" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-srv-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};
    const cfg: config_mod.Config = .{ .data_dir = rel, .metrics_disabled = true };
    var server: Server = undefined;
    try Server.init(&server, allocator, io, cfg);
    defer server.deinit();
    try std.testing.expect(server.running.load(.acquire));
    // Touch every self-pointer the UAF used to dangle.
    try std.testing.expectEqual(@as(usize, 1), server.dns.config.origins.len);
    try std.testing.expect(server.dns.store == server.store);
    try std.testing.expect(server.dns.metrics == server.metrics);
}

// Permanent UAF guard: construct via out-pointer, SERVE a real UDP + DoH query
// against the returned server, assert answers. Prefer ReleaseSafe
// (`zig build dns-server-serve-gate`).
test "Server serves UDP A and DoH against returned instance" {
    try serveUdpAndDohOnce(std.testing.allocator, std.testing.io);
}

pub fn serveUdpAndDohOnce(allocator: std.mem.Allocator, io: std.Io) !void {
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-live-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    // Ephemeral ports (0) — read back from Server.bound_* after start.
    const cfg: config_mod.Config = .{
        .data_dir = rel,
        .http_addr = "127.0.0.1:0",
        .dns_addr = "127.0.0.1:0",
        .metrics_disabled = true,
        .origins = &.{"irohdns.example."},
        .rr_a = "127.0.0.1",
        .rr_aaaa = "::1",
        .default_ttl = 60,
    };
    var server: Server = undefined;
    try Server.init(&server, allocator, io, cfg);
    defer server.deinit();

    const run_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *Server) void {
            s.run() catch {};
        }
    }.run, .{&server});
    defer {
        server.initiateShutdown();
        run_thread.join();
    }

    // Wait for binds.
    var waits: usize = 0;
    while ((server.bound_http_port.load(.acquire) == 0 or server.bound_dns_port.load(.acquire) == 0) and waits < 100) : (waits += 1) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    const http_port = server.bound_http_port.load(.acquire);
    const dns_port = server.bound_dns_port.load(.acquire);
    if (http_port == 0 or dns_port == 0) return error.BindTimeout;

    // --- UDP A query ---
    {
        const query = try buildRawQuery(allocator, "irohdns.example.", 1); // TYPE_A
        defer allocator.free(query);
        const dest = try net.IpAddress.parse("127.0.0.1", dns_port);
        const sock = try (net.IpAddress{ .ip4 = .loopback(0) }).bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer sock.close(io);
        try sock.send(io, &dest, query);
        var resp_buf: [512]u8 = undefined;
        const recv = try sock.receiveTimeout(io, &resp_buf, .{
            .duration = .{ .raw = .fromMilliseconds(2000), .clock = .awake },
        });
        try std.testing.expect(recv.data.len >= 12);
        const flags = std.mem.readInt(u16, recv.data[2..4], .big);
        try std.testing.expect((flags & 0x8000) != 0); // QR
        try std.testing.expectEqual(@as(u16, 0), flags & 0xf); // NOERROR
        try std.testing.expect(std.mem.readInt(u16, recv.data[6..8], .big) >= 1); // ancount
    }

    // --- TCP DNS (RFC 1035 length-prefixed) ---
    {
        const query = try buildRawQuery(allocator, "irohdns.example.", 1);
        defer allocator.free(query);
        const dest = try net.IpAddress.parse("127.0.0.1", dns_port);
        var stream = try dest.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var wbuf: [64]u8 = undefined;
        var writer = stream.writer(io, &wbuf);
        var len_be: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_be, @intCast(query.len), .big);
        try writer.interface.writeAll(&len_be);
        try writer.interface.writeAll(query);
        try writer.interface.flush();
        var rbuf: [64]u8 = undefined;
        var reader = stream.reader(io, &rbuf);
        var resp_len_be: [2]u8 = undefined;
        try reader.interface.readSliceAll(&resp_len_be);
        const resp_len = std.mem.readInt(u16, &resp_len_be, .big);
        const resp = try allocator.alloc(u8, resp_len);
        defer allocator.free(resp);
        try reader.interface.readSliceAll(resp);
        try std.testing.expect(resp.len >= 12);
        try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, resp[2..4], .big) & 0xf);
    }

    // --- DoH GET /dns-query ---
    {
        const query = try buildRawQuery(allocator, "irohdns.example.", 1);
        defer allocator.free(query);
        var b64_buf: [512]u8 = undefined;
        const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(query.len);
        _ = std.base64.url_safe_no_pad.Encoder.encode(b64_buf[0..enc_len], query);
        const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/dns-query?dns={s}", .{ http_port, b64_buf[0..enc_len] });
        defer allocator.free(url);

        var client: std.http.Client = .{ .allocator = allocator, .io = io };
        defer client.deinit();
        var body_buf: [512]u8 = undefined;
        var body_w: std.Io.Writer = .fixed(&body_buf);
        const result = try client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .response_writer = &body_w,
        });
        try std.testing.expectEqual(.ok, result.status);
        const body = body_w.buffered();
        try std.testing.expect(body.len >= 12);
        const flags = std.mem.readInt(u16, body[2..4], .big);
        try std.testing.expectEqual(@as(u16, 0), flags & 0xf);
    }

    // Safety mode note for emit: this test is also driven under ReleaseSafe via
    // `zig build dns-server-serve-gate`. Debug runs still exercise the serve path.
    _ = builtin.mode;
}

fn buildRawQuery(allocator: std.mem.Allocator, name: []const u8, typ: u16) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try writeU16(&out, allocator, 0x1234);
    try writeU16(&out, allocator, 0x0100);
    try writeU16(&out, allocator, 1);
    try writeU16(&out, allocator, 0);
    try writeU16(&out, allocator, 0);
    try writeU16(&out, allocator, 0);
    try dns_wire.appendName(&out, allocator, name);
    try writeU16(&out, allocator, typ);
    try writeU16(&out, allocator, dns_wire.CLASS_IN);
    return out.toOwnedSlice(allocator);
}

fn writeU16(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    try out.appendSlice(allocator, &buf);
}

// ---------------------------------------------------------------------------
// Hunter gate: the operator-visible surfaces, each driven over a real socket
// against a running `Server`.
//
// Everything below asserts a WIRE-OBSERVABLE outcome (status code, RCODE,
// answer count, response header), never an internal call. Several checks are
// mutation-red by construction — most importantly the tampered-PUT leg, which
// goes green only while `SignedPacket.fromRelayPayload` still verifies the
// signature.
// ---------------------------------------------------------------------------

test "Server refuses AXFR, serves published zones, and rejects forged packets" {
    try serveHunterGatesOnce(std.testing.allocator, std.testing.io);
}

pub fn serveHunterGatesOnce(allocator: std.mem.Allocator, io: std.Io) !void {
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-hunter-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    const origin = "irohdns.example.";
    const cfg: config_mod.Config = .{
        .data_dir = rel,
        .http_addr = "127.0.0.1:0",
        .dns_addr = "127.0.0.1:0",
        .metrics_disabled = true,
        .origins = &.{origin},
        .rr_a = "127.0.0.1",
        .default_ttl = 60,
    };
    var server: Server = undefined;
    try Server.init(&server, allocator, io, cfg);
    defer server.deinit();

    const run_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *Server) void {
            s.run() catch {};
        }
    }.run, .{&server});
    defer {
        server.initiateShutdown();
        run_thread.join();
    }

    var waits: usize = 0;
    while ((server.bound_http_port.load(.acquire) == 0 or server.bound_dns_port.load(.acquire) == 0) and waits < 200) : (waits += 1) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    const http_port = server.bound_http_port.load(.acquire);
    const dns_port = server.bound_dns_port.load(.acquire);
    if (http_port == 0 or dns_port == 0) return error.BindTimeout;

    // --- AXFR is REFUSED on both transports ---
    {
        const udp = try dnsOverUdp(allocator, io, dns_port, origin, dns_wire.TYPE_AXFR);
        defer allocator.free(udp);
        try std.testing.expectEqual(@as(u16, dns_wire.RCODE_REFUSED), rcodeOf(udp));

        const tcp = try dnsOverTcp(allocator, io, dns_port, origin, dns_wire.TYPE_AXFR);
        defer allocator.free(tcp);
        try std.testing.expectEqual(@as(u16, dns_wire.RCODE_REFUSED), rcodeOf(tcp));
    }

    // Wall-clock timestamps so the run loop's age-based eviction treats these
    // packets as fresh, exactly as it would a real peer's publish.
    const now_micros = store_mod.ZoneStore.nowMicros(io);

    // --- PUT a valid signed packet, then resolve it by both zone names ---
    const secret = root.SecretKey.fromBytes(.{0x31} ** 32);
    const z32 = secret.public().toZ32();
    {
        var packet = try signedEndpointPacket(allocator, secret, now_micros);
        defer packet.deinit(allocator);

        var put = try pkarrPut(allocator, io, http_port, &z32, packet.relayPayload());
        defer put.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 204), put.status);
        // CORS is on every response, not just the preflight.
        try std.testing.expect(put.header("access-control-allow-origin") != null);

        for ([_][]const u8{ "_iroh.", "" }) |prefix| {
            const qname = try std.fmt.allocPrint(allocator, "{s}{s}.{s}", .{ prefix, &z32, origin });
            defer allocator.free(qname);
            const resp = try dnsOverUdp(allocator, io, dns_port, qname, dns_wire.TYPE_TXT);
            defer allocator.free(resp);
            try std.testing.expectEqual(@as(u16, dns_wire.RCODE_NOERROR), rcodeOf(resp));
            if (ancountOf(resp) == 0) {
                std.debug.print("no answers for {s}\n", .{qname});
                return error.NoPkarrAnswers;
            }
            const values = try dns_wire.parseTxtAnswers(allocator, resp, qname);
            defer {
                for (values) |v| allocator.free(v);
                allocator.free(values);
            }
            try std.testing.expect(values.len >= 1);
        }
    }

    // --- A byte-flipped signature must be rejected, not stored ---
    {
        // Newer than the stored packet, so only the signature can reject it — a
        // stale-timestamp rejection would prove nothing about verification.
        var newer = try signedEndpointPacket(allocator, secret, now_micros + 1_000);
        defer newer.deinit(allocator);
        const forged = try allocator.dupe(u8, newer.relayPayload());
        defer allocator.free(forged);
        // Byte 0 of a relay payload is the first signature byte
        // (signature ++ timestamp ++ packet).
        forged[0] ^= 0x01;

        var put = try pkarrPut(allocator, io, http_port, &z32, forged);
        defer put.deinit(allocator);
        // MUTATION GUARD: drop the verify in `SignedPacket.fromRelayPayload` and
        // this becomes 204, failing here.
        try std.testing.expectEqual(@as(u16, 400), put.status);

        // The originally published packet must still be the one served — the
        // forged PUT must not have replaced it.
        var original = try signedEndpointPacket(allocator, secret, now_micros);
        defer original.deinit(allocator);
        var get = try pkarrGet(allocator, io, http_port, &z32);
        defer get.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), get.status);
        try std.testing.expectEqualSlices(u8, original.relayPayload(), get.body);
    }

    // --- A signed non-TXT zone record is served with the publisher's RDATA ---
    {
        const a_secret = root.SecretKey.fromBytes(.{0x32} ** 32);
        const a_z32 = a_secret.public().toZ32();
        const owner = try std.fmt.allocPrint(allocator, "_iroh.{s}", .{&a_z32});
        defer allocator.free(owner);
        const want_addr = [4]u8{ 203, 0, 113, 7 };
        const zone = try zoneRecordPacket(allocator, owner, dns_wire.TYPE_A, &want_addr);
        defer allocator.free(zone);
        var packet = try discovery.SignedPacket.fromEncodedDnsPacketAt(
            allocator,
            a_secret,
            zone,
            .{ .micros = now_micros },
        );
        defer packet.deinit(allocator);

        var put = try pkarrPut(allocator, io, http_port, &a_z32, packet.relayPayload());
        defer put.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 204), put.status);

        const qname = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ &a_z32, origin });
        defer allocator.free(qname);
        const resp = try dnsOverUdp(allocator, io, dns_port, qname, dns_wire.TYPE_A);
        defer allocator.free(resp);
        try std.testing.expectEqual(@as(u16, dns_wire.RCODE_NOERROR), rcodeOf(resp));
        try std.testing.expectEqual(@as(u16, 1), ancountOf(resp));
        const answers = try dns_handler.parseRawAnswers(allocator, resp);
        defer dns_handler.freeRawAnswers(allocator, answers);
        try std.testing.expectEqualSlices(u8, &want_addr, answers[0].rdata);

        // Same record through JSON DoH.
        const target = try std.fmt.allocPrint(allocator, "/dns-query?name={s}&type=A", .{qname});
        defer allocator.free(target);
        var json = try httpGet(allocator, io, http_port, target, "");
        defer json.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), json.status);
        try std.testing.expectEqualStrings("application/dns-json", json.header("content-type").?);
        try std.testing.expect(std.mem.indexOf(u8, json.body, "\"Status\":0") != null);
        try std.testing.expect(std.mem.indexOf(u8, json.body, "\"data\":\"203.0.113.7\"") != null);
    }

    // --- JSON DoH via the Accept header, for a TXT zone ---
    {
        const qname = try std.fmt.allocPrint(allocator, "_iroh.{s}.{s}", .{ &z32, origin });
        defer allocator.free(qname);
        const target = try std.fmt.allocPrint(allocator, "/dns-query?name={s}&type=TXT", .{qname});
        defer allocator.free(target);
        var json = try httpGet(allocator, io, http_port, target, "accept: application/dns-json\r\n");
        defer json.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), json.status);
        try std.testing.expect(std.mem.indexOf(u8, json.body, "\"Status\":0") != null);
        // A relay= TXT string proves the answer came out of the signed zone.
        try std.testing.expect(std.mem.indexOf(u8, json.body, "relay=") != null);
    }

    // --- Binary DoH still works and is cacheable ---
    {
        var doh = try dohBinary(allocator, io, http_port, origin, dns_wire.TYPE_A);
        defer doh.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), doh.status);
        try std.testing.expectEqualStrings("application/dns-message", doh.header("content-type").?);
        try std.testing.expectEqualStrings("s-maxage=60", doh.header("cache-control").?);
        try std.testing.expectEqual(@as(u16, dns_wire.RCODE_NOERROR), rcodeOf(doh.body));
    }

    // --- CORS preflight ---
    {
        const target = try std.fmt.allocPrint(allocator, "/pkarr/{s}", .{&z32});
        defer allocator.free(target);
        var pre = try httpRequest(allocator, io, http_port, "OPTIONS", target, "origin: https://example.com\r\n", "", null);
        defer pre.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 204), pre.status);
        try std.testing.expectEqualStrings("*", pre.header("access-control-allow-origin").?);
        try std.testing.expectEqualStrings("GET, POST, PUT, OPTIONS", pre.header("access-control-allow-methods").?);
    }

    // --- /healthz reports the build stamp the binary was compiled with ---
    {
        var health = try httpGet(allocator, io, http_port, "/healthz", "");
        defer health.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), health.status);
        const needle = try std.fmt.allocPrint(allocator, "\"git_hash\":\"{s}\"", .{http_mod.GIT_HASH});
        defer allocator.free(needle);
        if (std.mem.indexOf(u8, health.body, needle) == null) {
            std.debug.print("healthz body {s} lacks {s}\n", .{ health.body, needle });
            return error.MissingGitHash;
        }
    }

    // --- SIGHUP-style reload reaches the live serve path ---
    {
        const path = try std.fmt.allocPrint(allocator, "{s}/reload.toml", .{rel});
        defer allocator.free(path);
        try std.Io.Dir.cwd().writeFile(io, .{
            .sub_path = path,
            .data =
            \\pkarr_put_rate_limit = 1
            \\
            \\[dns]
            \\default_ttl = 123
            \\origins = ["irohdns.example."]
            \\rr_a = "127.0.0.1"
            \\
            ,
        });
        try server.reloadFromFile(path);

        // The new TTL is observable in the DoH cache directive.
        var doh = try dohBinary(allocator, io, http_port, origin, dns_wire.TYPE_A);
        defer doh.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), doh.status);
        try std.testing.expectEqualStrings("s-maxage=123", doh.header("cache-control").?);
    }

    // --- The reloaded per-IP PUT budget is enforced ---
    {
        var packet = try signedEndpointPacket(allocator, secret, now_micros);
        defer packet.deinit(allocator);
        // Budget is now 1 per second for this client IP; a burst must be clipped.
        var limited: usize = 0;
        for (0..4) |_| {
            var put = try pkarrPut(allocator, io, http_port, &z32, packet.relayPayload());
            defer put.deinit(allocator);
            if (put.status == 429) limited += 1;
        }
        if (limited == 0) return error.RateLimitNotEnforced;
    }

    _ = builtin.mode;
}

/// F1: a stalled TCP DNS client is dropped within the read deadline while a
/// concurrent well-behaved UDP query is still answered promptly.
pub fn serveSlowClientGateOnce(allocator: std.mem.Allocator, io: std.Io) !void {
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-slow-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    const cfg: config_mod.Config = .{
        .data_dir = rel,
        .http_addr = "127.0.0.1:0",
        .dns_addr = "127.0.0.1:0",
        .metrics_disabled = true,
        .origins = &.{"irohdns.example."},
        .rr_a = "127.0.0.1",
        .default_ttl = 60,
        .connection_read_timeout_ms = 200,
        .max_concurrent_connections = 16,
    };
    var server: Server = undefined;
    try Server.init(&server, allocator, io, cfg);
    defer server.deinit();

    const run_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *Server) void {
            s.run() catch {};
        }
    }.run, .{&server});
    defer {
        server.initiateShutdown();
        run_thread.join();
    }

    var waits: usize = 0;
    while ((server.bound_http_port.load(.acquire) == 0 or server.bound_dns_port.load(.acquire) == 0) and waits < 200) : (waits += 1) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    const dns_port = server.bound_dns_port.load(.acquire);
    if (dns_port == 0) return error.BindTimeout;

    const addr = try net.IpAddress.parse("127.0.0.1", dns_port);
    var stall = try addr.connect(io, .{ .mode = .stream });
    defer stall.close(io);

    // Concurrent well-behaved client must still be served promptly.
    const started = std.Io.Clock.Timestamp.now(io, .awake);
    const udp = try dnsOverUdp(allocator, io, dns_port, "irohdns.example.", dns_wire.TYPE_A);
    defer allocator.free(udp);
    try std.testing.expectEqual(@as(u16, dns_wire.RCODE_NOERROR), rcodeOf(udp));
    const well_behaved_ns = started.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toNanoseconds();
    if (well_behaved_ns > 500 * std.time.ns_per_ms) return error.WellBehavedClientStarved;

    // Stalled client (sent nothing) must be dropped within a small multiple of the deadline.
    var read_buf: [8]u8 = undefined;
    var reader = stall.reader(io, &read_buf);
    const stall_started = std.Io.Clock.Timestamp.now(io, .awake);
    const dropped = if (reader.interface.readSliceAll(read_buf[0..1])) |_| false else |_| true;
    const stall_ns = stall_started.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toNanoseconds();
    if (!dropped) return error.SlowClientNotDropped;
    // MUTATION GUARD: remove the connection watchdog → this hangs past ~1s.
    if (stall_ns > 1500 * std.time.ns_per_ms) return error.SlowClientDeadlineMissed;
    if (stall_ns < 50 * std.time.ns_per_ms) return error.SlowClientDroppedTooFast;
}

/// H3 sendback guard: a handler can remain active after the bounded drain
/// without keeping stack `Server` storage alive. The synthetic handler is stuck
/// outside socket read/write and has no watchdog, matching timeout=0 or watchdog
/// spawn failure/null paths.
pub fn serveDetachedHandlerLifetimeGateOnce(allocator: std.mem.Allocator, io: std.Io) !void {
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-lifetime-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    const cfg: config_mod.Config = .{
        .data_dir = rel,
        .http_addr = "127.0.0.1:0",
        .dns_addr = "127.0.0.1:0",
        .metrics_disabled = true,
        .connection_read_timeout_ms = 0,
    };
    var server: Server = undefined;
    try Server.init(&server, allocator, io, cfg);
    var server_released = false;
    errdefer if (!server_released) server.deinit();

    var dummy_stream: net.Stream = undefined;
    var timed_out = std.atomic.Value(bool).init(false);
    var cancel = std.atomic.Value(bool).init(false);
    var watchdog: ConnWatchdog = undefined;
    if (armConnWatchdog(&dummy_stream, io, 0, &timed_out, &cancel, &watchdog) != null)
        return error.TimeoutZeroArmedWatchdog;

    const shared = server.shared.retain();
    _ = shared.active_handlers.fetchAdd(1, .acq_rel);

    var release_stuck = std.atomic.Value(bool).init(false);
    var touched_after_deinit = std.atomic.Value(bool).init(false);
    const Ctx = struct {
        shared: *Server.Shared,
        io: std.Io,
        release_stuck: *std.atomic.Value(bool),
        touched_after_deinit: *std.atomic.Value(bool),

        fn run(ctx: *@This()) void {
            defer ctx.shared.release();
            defer releaseHandlerSlot(ctx.shared);
            while (!ctx.release_stuck.load(.acquire)) {
                ctx.io.sleep(std.Io.Duration.fromMilliseconds(5), .awake) catch {};
            }
            _ = ctx.shared.store.max_age_secs.load(.monotonic);
            if (ctx.shared.data_dir_owned.len != 0) {
                ctx.touched_after_deinit.store(true, .release);
            }
        }
    };
    var ctx: Ctx = .{
        .shared = shared,
        .io = io,
        .release_stuck = &release_stuck,
        .touched_after_deinit = &touched_after_deinit,
    };
    const thread = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});
    var joined = false;
    defer if (!joined) {
        release_stuck.store(true, .release);
        thread.join();
    };

    const started = std.Io.Clock.Timestamp.now(io, .awake);
    if (drainActiveHandlersBounded(io, server.active_handlers, 2)) return error.DetachedHandlerDrainedUnexpectedly;
    const drain_ns = started.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toNanoseconds();
    if (drain_ns > 250 * std.time.ns_per_ms) return error.DetachedHandlerDrainUnbounded;

    server.deinit();
    server_released = true;
    release_stuck.store(true, .release);
    thread.join();
    joined = true;

    if (!touched_after_deinit.load(.acquire)) return error.DetachedHandlerLifetimeNotProven;
}

/// Re-SENDBACK guard: with `mainline_enabled`, a stalled detached handler can
/// still reach the mainline resolver through the real answer path AFTER the
/// main thread's teardown. The resolver is Shared-owned, so it is freed only
/// when the last handler releases — never under a late `answer`. Same shape as
/// the H3 gate above: the synthetic handler is stuck outside socket read/write
/// and outlasts the bounded drain.
pub fn serveMainlineResolverLifetimeGateOnce(allocator: std.mem.Allocator, io: std.Io) !void {
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-ml-lifetime-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    const origin = "irohdns.example.";
    const cfg: config_mod.Config = .{
        .data_dir = rel,
        .http_addr = "127.0.0.1:0",
        .dns_addr = "127.0.0.1:0",
        .metrics_disabled = true,
        .origins = &.{origin},
        .connection_read_timeout_ms = 0,
        .mainline_enabled = true,
    };
    var server: Server = undefined;
    try Server.init(&server, allocator, io, cfg);
    var server_released = false;
    errdefer if (!server_released) server.deinit();

    // Shared owns the resolver when mainline is enabled at init.
    if (server.mainline_resolver == null) return error.MainlineResolverMissing;
    const enqueued_before = server.metrics.dns_mainline_enqueued.load(.monotonic);

    const shared = server.shared.retain();
    _ = shared.active_handlers.fetchAdd(1, .acq_rel);

    const secret = root.SecretKey.fromBytes(.{0x66} ** 32);
    const z32 = secret.public().toZ32();
    const qname = try std.fmt.allocPrint(allocator, "_iroh.{s}.{s}", .{ &z32, origin });
    defer allocator.free(qname);

    var release_stuck = std.atomic.Value(bool).init(false);
    var enqueued_after = std.atomic.Value(u64).init(0);
    const Ctx = struct {
        shared: *Server.Shared,
        allocator: std.mem.Allocator,
        io: std.Io,
        qname: []const u8,
        release_stuck: *std.atomic.Value(bool),
        enqueued_after: *std.atomic.Value(u64),

        fn run(ctx: *@This()) void {
            defer ctx.shared.release();
            defer releaseHandlerSlot(ctx.shared);
            while (!ctx.release_stuck.load(.acquire)) {
                ctx.io.sleep(std.Io.Duration.fromMilliseconds(5), .awake) catch {};
            }
            // The hazard path: a pkarr-miss `answer` enqueues on the mainline
            // resolver. It must still be served after main-thread teardown.
            const query = buildRawQuery(ctx.allocator, ctx.qname, dns_wire.TYPE_TXT) catch return;
            defer ctx.allocator.free(query);
            const resp = ctx.shared.dns.answer(query) catch return;
            defer ctx.allocator.free(resp);
            if (rcodeOf(resp) != dns_wire.RCODE_NXDOMAIN) return;
            ctx.enqueued_after.store(ctx.shared.metrics.dns_mainline_enqueued.load(.monotonic), .release);
        }
    };
    var ctx: Ctx = .{
        .shared = shared,
        .allocator = allocator,
        .io = io,
        .qname = qname,
        .release_stuck = &release_stuck,
        .enqueued_after = &enqueued_after,
    };
    const thread = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});
    var joined = false;
    defer if (!joined) {
        release_stuck.store(true, .release);
        thread.join();
    };

    // Force the bounded-drain miss, then the main thread's teardown ordering:
    // server.deinit() releases the main ref while the handler is still stuck.
    const started = std.Io.Clock.Timestamp.now(io, .awake);
    if (drainActiveHandlersBounded(io, server.active_handlers, 2)) return error.DetachedHandlerDrainedUnexpectedly;
    const drain_ns = started.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toNanoseconds();
    if (drain_ns > 250 * std.time.ns_per_ms) return error.DetachedHandlerDrainUnbounded;

    server.deinit();
    server_released = true;
    release_stuck.store(true, .release);
    thread.join();
    joined = true;

    // The late answer must have been served (NXDOMAIN miss) and must have
    // enqueued exactly once on a LIVE resolver — MUTATION GUARD: free the
    // resolver at server.deinit() and `request` runs on torn-down state.
    if (enqueued_after.load(.acquire) != enqueued_before + 1)
        return error.MainlineResolverLifetimeNotProven;
}

/// F2: Dockerfile EXPOSE ports match the shipped example config binds.
pub fn checkDockerPortCoherence(allocator: std.mem.Allocator, io: std.Io) !void {
    const dockerfile = try std.Io.Dir.cwd().readFileAlloc(io, "deploy/iroh-dns-server/Dockerfile", allocator, .limited(64 * 1024));
    defer allocator.free(dockerfile);
    const example = try std.Io.Dir.cwd().readFileAlloc(io, "dns_server.example.toml", allocator, .limited(64 * 1024));
    defer allocator.free(example);

    // Example binds: dns 5300, http 8080, metrics 9117.
    if (std.mem.indexOf(u8, example, "port = 5300") == null) return error.ExampleDnsPortMissing;
    if (std.mem.indexOf(u8, example, "port = 8080") == null) return error.ExampleHttpPortMissing;
    if (std.mem.indexOf(u8, example, "9117") == null) return error.ExampleMetricsPortMissing;

    // Dockerfile must expose the same container ports (not privileged 53 alone).
    // MUTATION GUARD: revert EXPOSE to 53/udp → this fails.
    if (std.mem.indexOf(u8, dockerfile, "EXPOSE 5300/udp 5300/tcp 8080 9117") == null)
        return error.DockerExposeIncoherent;
    if (std.mem.indexOf(u8, dockerfile, "EXPOSE 53/") != null)
        return error.DockerExposePrivilegedWithoutMap;
}

/// Live HTTPS DoH for self_signed mode (listener composition, not ACME policy).
pub fn serveHttpsSelfSignedGateOnce(allocator: std.mem.Allocator, io: std.Io) !void {
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-https-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};
    const cert_cache = try std.fmt.allocPrint(allocator, "{s}/certs", .{rel});
    defer allocator.free(cert_cache);

    const cfg: config_mod.Config = .{
        .data_dir = rel,
        .http_addr = "127.0.0.1:0",
        .https_addr = "127.0.0.1:0",
        .dns_addr = "127.0.0.1:0",
        .metrics_disabled = true,
        .origins = &.{"irohdns.example."},
        .rr_a = "127.0.0.1",
        .default_ttl = 60,
        .cert_mode = .self_signed,
        .cert_cache = cert_cache,
        .tls_domains = &.{"localhost"},
        .connection_read_timeout_ms = 5_000,
    };
    const plan = try tls_mod.planFromConfig(&cfg);
    var activated = try tls_mod.activate(allocator, io, plan);
    defer activated.deinit();

    var server: Server = undefined;
    try Server.init(&server, allocator, io, cfg);
    defer server.deinit();
    server.setTlsMaterial(activated.cert_path, activated.key_path);

    const run_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *Server) void {
            s.run() catch {};
        }
    }.run, .{&server});
    defer {
        server.initiateShutdown();
        run_thread.join();
    }

    var waits: usize = 0;
    while ((server.bound_https_port.load(.acquire) == 0 or server.bound_dns_port.load(.acquire) == 0) and waits < 200) : (waits += 1) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    const https_port = server.bound_https_port.load(.acquire);
    if (https_port == 0) return error.HttpsBindTimeout;

    // MUTATION GUARD: skip setTlsMaterial → bound_https_port stays 0 / SelfSignedListenerNotWired.
    const query = try buildRawQuery(allocator, "irohdns.example.", dns_wire.TYPE_A);
    defer allocator.free(query);

    const addr = try net.IpAddress.parse("127.0.0.1", https_port);
    const stream = try addr.connect(io, .{ .mode = .stream });
    const tls_client = try tls_wrapper.TlsClient.connect(allocator, io, stream, "localhost", true);
    defer tls_client.deinit();

    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "POST /dns-query HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/dns-message\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n", .{query.len});
    try tls_client.writer().writeAll(req);
    try tls_client.writer().writeAll(query);
    try tls_client.writer().flush();

    var resp_buf: [4096]u8 = undefined;
    const n = tls_client.reader().readSliceShort(resp_buf[0..]) catch 0;
    if (n == 0) return error.HttpsNoResponse;
    if (std.mem.indexOf(u8, resp_buf[0..n], "200") == null) return error.HttpsNotOk;
}

/// Mainline background resolver fills ZoneStore off the answer path.
pub fn serveMainlineBackgroundGateOnce(allocator: std.mem.Allocator, io: std.Io) !void {
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-mlgate-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    const origin = "irohdns.example.";
    const cfg: config_mod.Config = .{
        .data_dir = rel,
        .http_addr = "127.0.0.1:0",
        .dns_addr = "127.0.0.1:0",
        .metrics_disabled = true,
        .origins = &.{origin},
        .rr_a = "127.0.0.1",
        .default_ttl = 60,
        .mainline_enabled = true,
    };
    var server: Server = undefined;
    try Server.init(&server, allocator, io, cfg);
    defer server.deinit();

    const secret = root.SecretKey.fromBytes(.{0x55} ** 32);
    const now = store_mod.ZoneStore.nowMicros(io);
    var packet = try signedEndpointPacket(allocator, secret, now);
    defer packet.deinit(allocator);
    const fixture = try allocator.dupe(u8, packet.relayPayload());
    defer allocator.free(fixture);

    const Ctx = struct {
        payload: []const u8,
        fn lookup(ctx: *anyopaque, alloc: std.mem.Allocator, key: root.PublicKey) mainline_mod.Error![]u8 {
            _ = key;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return alloc.dupe(u8, self.payload) catch return error.MainlineClientUnavailable;
        }
    };
    var ctx: Ctx = .{ .payload = fixture };
    // Shared created the resolver at init (mainline_enabled); inject the
    // fixture before any query can reach it.
    const resolver = server.mainline_resolver orelse return error.MainlineResolverMissing;
    resolver.setInjectedLookup(@ptrCast(&ctx), Ctx.lookup);

    const run_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *Server) void {
            s.run() catch {};
        }
    }.run, .{&server});
    defer {
        server.initiateShutdown();
        run_thread.join();
    }

    var waits: usize = 0;
    while (server.bound_dns_port.load(.acquire) == 0 and waits < 200) : (waits += 1) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    const dns_port = server.bound_dns_port.load(.acquire);
    if (dns_port == 0) return error.BindTimeout;

    const z32 = secret.public().toZ32();
    const qname = try std.fmt.allocPrint(allocator, "_iroh.{s}.{s}", .{ &z32, origin });
    defer allocator.free(qname);

    // Miss → NXDOMAIN (fast path); enqueue happens in background.
    const miss = try dnsOverUdp(allocator, io, dns_port, qname, dns_wire.TYPE_TXT);
    defer allocator.free(miss);
    try std.testing.expectEqual(@as(u16, dns_wire.RCODE_NXDOMAIN), rcodeOf(miss));

    waits = 0;
    while (server.metrics.dns_mainline_resolved.load(.monotonic) == 0 and waits < 100) : (waits += 1) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    // MUTATION GUARD: force MainlineClientUnavailable in injected lookup → resolved stays 0.
    if (server.metrics.dns_mainline_resolved.load(.monotonic) == 0) return error.MainlineNotResolved;

    const hit = try dnsOverUdp(allocator, io, dns_port, qname, dns_wire.TYPE_TXT);
    defer allocator.free(hit);
    try std.testing.expectEqual(@as(u16, dns_wire.RCODE_NOERROR), rcodeOf(hit));
}

/// Drive the shipped `iroh-dns-pkarr` binary against a live server: publish a
/// signed packet, then resolve it back. Exercises the CLI as an operator does —
/// a separate process talking real HTTP — rather than re-testing the in-process
/// library it links. `cli_path` is the built executable.
pub fn serveCliRoundTripOnce(allocator: std.mem.Allocator, io: std.Io, cli_path: []const u8) !void {
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-cli-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    const cfg: config_mod.Config = .{
        .data_dir = rel,
        .http_addr = "127.0.0.1:0",
        .dns_addr = "127.0.0.1:0",
        .metrics_disabled = true,
        .origins = &.{"irohdns.example."},
        .rr_a = "127.0.0.1",
    };
    var server: Server = undefined;
    try Server.init(&server, allocator, io, cfg);
    defer server.deinit();

    const run_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *Server) void {
            s.run() catch {};
        }
    }.run, .{&server});
    defer {
        server.initiateShutdown();
        run_thread.join();
    }

    var waits: usize = 0;
    while (server.bound_http_port.load(.acquire) == 0 and waits < 200) : (waits += 1) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    const http_port = server.bound_http_port.load(.acquire);
    if (http_port == 0) return error.BindTimeout;

    const relay_base = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}", .{http_port});
    defer allocator.free(relay_base);
    const secret = root.SecretKey.fromBytes(.{0x5c} ** 32);
    const secret_hex = std.fmt.bytesToHex(secret.toBytes(), .lower);
    const z32 = secret.public().toZ32();

    const publish = try runCli(allocator, io, &.{
        cli_path,      "--publish",
        "--relay",     relay_base,
        "--secret",    &secret_hex,
        "--relay-url", "https://relay.example",
        "--addr",      "127.0.0.1:9042",
    });
    defer allocator.free(publish.output);
    if (publish.code != 0 or std.mem.indexOf(u8, publish.output, "-> 204") == null) {
        std.debug.print("iroh-dns-pkarr --publish exit={d} output:\n{s}\n", .{ publish.code, publish.output });
        return error.CliPublishFailed;
    }

    const resolve = try runCli(allocator, io, &.{
        cli_path, "--resolve", "--relay", relay_base, "--key", &z32,
    });
    defer allocator.free(resolve.output);
    // The CLI verifies the fetched packet's signature before printing records, so
    // any `relay=` line here is signed data that survived a real round-trip.
    if (resolve.code != 0 or std.mem.indexOf(u8, resolve.output, "relay=https://relay.example/") == null) {
        std.debug.print("iroh-dns-pkarr --resolve exit={d} output:\n{s}\n", .{ resolve.code, resolve.output });
        return error.CliResolveFailed;
    }
}

const CliRun = struct { code: u8, output: []u8 };

fn runCli(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) !CliRun {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    errdefer _ = child.wait(io) catch {};

    var buf: [4096]u8 = undefined;
    var reader = child.stdout.?.reader(io, &buf);
    const output = try reader.interface.allocRemaining(allocator, .limited(64 * 1024));
    errdefer allocator.free(output);

    const term = try child.wait(io);
    return .{
        .code = switch (term) {
            .exited => |code| code,
            else => 0xff,
        },
        .output = output,
    };
}

fn signedEndpointPacket(
    allocator: std.mem.Allocator,
    secret: root.SecretKey,
    micros: u64,
) !discovery.SignedPacket {
    var endpoint_relay = try root.RelayUrl.parse(allocator, "https://relay.example");
    defer endpoint_relay.deinit(allocator);
    const direct = try net.IpAddress.parse("127.0.0.1", 9042);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{ .{ .relay = endpoint_relay }, .{ .ip = direct } },
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

/// A one-record DNS reply, shaped like the packets `buildTxtReply` emits so it
/// can be signed into a pkarr zone.
fn zoneRecordPacket(
    allocator: std.mem.Allocator,
    owner: []const u8,
    typ: u16,
    rdata: []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &[_]u8{ 0, 0, 0x80, 0x00, 0, 0, 0, 1, 0, 0, 0, 0 });
    try dns_wire.appendName(&out, allocator, owner);
    try writeU16(&out, allocator, typ);
    try writeU16(&out, allocator, dns_wire.CLASS_IN);
    try writeU32(&out, allocator, discovery.DEFAULT_TTL);
    try writeU16(&out, allocator, @intCast(rdata.len));
    try out.appendSlice(allocator, rdata);
    return out.toOwnedSlice(allocator);
}

fn writeU32(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    try out.appendSlice(allocator, &buf);
}

fn rcodeOf(packet: []const u8) u16 {
    if (packet.len < 12) return 0xffff;
    return std.mem.readInt(u16, packet[2..4], .big) & 0xf;
}

fn ancountOf(packet: []const u8) u16 {
    if (packet.len < 12) return 0;
    return std.mem.readInt(u16, packet[6..8], .big);
}

fn dnsOverUdp(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    name: []const u8,
    typ: u16,
) ![]u8 {
    const query = try buildRawQuery(allocator, name, typ);
    defer allocator.free(query);
    const dest = try net.IpAddress.parse("127.0.0.1", port);
    const sock = try (net.IpAddress{ .ip4 = .loopback(0) }).bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer sock.close(io);
    try sock.send(io, &dest, query);
    var buf: [4096]u8 = undefined;
    const recv = try sock.receiveTimeout(io, &buf, .{
        .duration = .{ .raw = .fromMilliseconds(3000), .clock = .awake },
    });
    return allocator.dupe(u8, recv.data);
}

fn dnsOverTcp(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    name: []const u8,
    typ: u16,
) ![]u8 {
    const query = try buildRawQuery(allocator, name, typ);
    defer allocator.free(query);
    const dest = try net.IpAddress.parse("127.0.0.1", port);
    var stream = try dest.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [64]u8 = undefined;
    var writer = stream.writer(io, &wbuf);
    var len_be: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_be, @intCast(query.len), .big);
    try writer.interface.writeAll(&len_be);
    try writer.interface.writeAll(query);
    try writer.interface.flush();

    var rbuf: [64]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    var resp_len_be: [2]u8 = undefined;
    try reader.interface.readSliceAll(&resp_len_be);
    const resp = try allocator.alloc(u8, std.mem.readInt(u16, &resp_len_be, .big));
    errdefer allocator.free(resp);
    try reader.interface.readSliceAll(resp);
    return resp;
}

/// A parsed HTTP/1.1 response. Header names are compared case-insensitively.
const RawHttpResponse = struct {
    status: u16,
    /// Status line + header block, owned.
    head: []u8,
    /// Body slice into `head`'s backing buffer.
    body: []const u8,
    raw: []u8,

    fn deinit(self: *RawHttpResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.raw);
        self.* = undefined;
    }

    fn header(self: *const RawHttpResponse, name: []const u8) ?[]const u8 {
        var lines = std.mem.splitSequence(u8, self.head, "\r\n");
        _ = lines.next(); // status line
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " \t"), name)) continue;
            return std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
        return null;
    }
};

/// Speak HTTP/1.1 directly rather than through `std.http.Client`, because
/// `Client.fetch` surfaces only the status — these gates assert on response
/// headers (CORS, cache-control, content-type).
fn httpRequest(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    method: []const u8,
    target: []const u8,
    extra_headers: []const u8,
    body: []const u8,
    content_type: ?[]const u8,
) !RawHttpResponse {
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(allocator);
    try request.print(allocator, "{s} {s} HTTP/1.1\r\nhost: 127.0.0.1:{d}\r\nconnection: close\r\n", .{ method, target, port });
    if (content_type) |ct| try request.print(allocator, "content-type: {s}\r\n", .{ct});
    try request.print(allocator, "content-length: {d}\r\n", .{body.len});
    try request.appendSlice(allocator, extra_headers);
    try request.appendSlice(allocator, "\r\n");
    try request.appendSlice(allocator, body);

    const dest = try net.IpAddress.parse("127.0.0.1", port);
    var stream = try dest.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [1024]u8 = undefined;
    var writer = stream.writer(io, &wbuf);
    try writer.interface.writeAll(request.items);
    try writer.interface.flush();

    var rbuf: [1024]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    var response: std.Io.Writer.Allocating = .init(allocator);
    errdefer response.deinit();
    // `connection: close` means the server closes after responding, so
    // "stream until EOF" is the whole response.
    _ = reader.interface.streamRemaining(&response.writer) catch |err| switch (err) {
        error.ReadFailed => return error.HttpReadFailed,
        error.WriteFailed => return error.OutOfMemory,
    };

    const raw = try response.toOwnedSlice();
    errdefer allocator.free(raw);
    const split = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.MalformedHttpResponse;
    const head = raw[0..split];
    const rest = raw[split + 4 ..];
    // "HTTP/1.1 204 No Content"
    var status_parts = std.mem.splitScalar(u8, head, ' ');
    _ = status_parts.next() orelse return error.MalformedHttpResponse;
    const status_text = status_parts.next() orelse return error.MalformedHttpResponse;
    return .{
        .status = try std.fmt.parseInt(u16, status_text, 10),
        .head = head,
        .body = rest,
        .raw = raw,
    };
}

fn httpGet(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    target: []const u8,
    extra_headers: []const u8,
) !RawHttpResponse {
    return httpRequest(allocator, io, port, "GET", target, extra_headers, "", null);
}

fn pkarrPut(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    z32: []const u8,
    payload: []const u8,
) !RawHttpResponse {
    const target = try std.fmt.allocPrint(allocator, "/pkarr/{s}", .{z32});
    defer allocator.free(target);
    return httpRequest(allocator, io, port, "PUT", target, "", payload, discovery.RELAY_CONTENT_TYPE);
}

fn pkarrGet(allocator: std.mem.Allocator, io: std.Io, port: u16, z32: []const u8) !RawHttpResponse {
    const target = try std.fmt.allocPrint(allocator, "/pkarr/{s}", .{z32});
    defer allocator.free(target);
    return httpGet(allocator, io, port, target, "");
}

fn dohBinary(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    name: []const u8,
    typ: u16,
) !RawHttpResponse {
    const query = try buildRawQuery(allocator, name, typ);
    defer allocator.free(query);
    var b64: [1024]u8 = undefined;
    const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(query.len);
    if (enc_len > b64.len) return error.QueryTooLarge;
    _ = std.base64.url_safe_no_pad.Encoder.encode(b64[0..enc_len], query);
    const target = try std.fmt.allocPrint(allocator, "/dns-query?dns={s}", .{b64[0..enc_len]});
    defer allocator.free(target);
    return httpGet(allocator, io, port, target, "");
}
