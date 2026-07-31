//! Relay server binary — operator surface: CLI + TOML config + optional
//! metrics/health listener + signal-wired graceful shutdown.
//!
//! Usage:
//!   relay [--config PATH] [--dev] [--bind HOST:PORT] [--metrics HOST:PORT] [--help]
//!
//! Config sources, lowest to highest precedence: compiled-in defaults → TOML
//! file (`--config`) → environment (`IROH_RELAY_ACCESS_TOKEN`, replaces the
//! token list, upstream semantics) → CLI flags.
//!
//! Shutdown: SIGINT or SIGTERM starts a graceful stop (listener shutdown →
//! client teardown → clean exit 0). Upstream handles only SIGINT; SIGTERM is
//! the orchestrator/kube default and is handled here deliberately.

const std = @import("std");
const builtin = @import("builtin");
const zig_iroh = @import("zig_iroh");

const relay = zig_iroh.relay;
const Server = relay.server.Server;
const ServerConfig = relay.server.ServerConfig;
const TokenAccessControl = relay.server.TokenAccessControl;
const config_mod = relay.config;
const metrics_mod = relay.metrics;

const usage_text =
    \\Usage: relay [--config PATH] [--dev] [--bind HOST:PORT] [--metrics HOST:PORT] [--help]
    \\
    \\Options:
    \\  -c, --config PATH    TOML config file (see relay.example.toml)
    \\      --dev            dev mode: plain ws:// on 127.0.0.1:3340, TLS off
    \\      --bind ADDR      override the relay listener (host:port, [::]:port ok)
    \\      --metrics ADDR   serve /health + /metrics on this address (host:port)
    \\  -h, --help           print this text
    \\
    \\Environment:
    \\  IROH_RELAY_ACCESS_TOKEN   single access token; replaces the config list
    \\
;

/// Set by the signal handler (async-signal-safe: one atomic store); read by
/// the watcher thread. 0 = keep running, else the signal number.
var g_shutdown_signal: std.atomic.Value(u8) = .init(0);

fn onPosixSignal(sig: std.posix.SIG) callconv(.c) void {
    g_shutdown_signal.store(@intCast(@intFromEnum(sig)), .release);
}

fn installSignalHandlers() void {
    if (builtin.os.tag == .windows) return; // no posix signals; console ctrl is out of scope
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onPosixSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

/// Polls the signal flag and initiates a graceful stop. Sleeping in 20 ms
/// chunks keeps worst-case shutdown latency well under orchestrator grace
/// periods without burning CPU.
fn shutdownWatcher(server: *Server) void {
    while (g_shutdown_signal.load(.acquire) == 0) {
        server.io.sleep(std.Io.Duration.fromMilliseconds(20), .awake) catch {};
    }
    server.initiateShutdown();
}

/// Accept loop for the metrics/health listener; exits when the server's
/// shutdown closes the listener via the watcher below.
fn metricsAcceptLoop(
    io: std.Io,
    listener: *std.Io.net.Server,
    server: *Server,
) void {
    while (server.running.load(.acquire)) {
        const stream = listener.accept(io) catch return;
        metrics_mod.serveOne(io, stream, &server.metrics, @intCast(server.clients.count()));
    }
}

/// Watches the relay server and closes the metrics listener when it stops so
/// metricsAcceptLoop's blocking accept wakes up.
fn metricsShutdownWatcher(server: *Server, listener: *std.Io.net.Server, io: std.Io) void {
    while (server.running.load(.acquire)) {
        io.sleep(std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    }
    const s: std.Io.net.Stream = .{ .socket = listener.socket };
    s.shutdown(io, .both) catch {};
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const out = &stdout_writer.interface;
    defer out.flush() catch {};

    // --- CLI -----------------------------------------------------------------
    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    var config_path: ?[]const u8 = null;
    var dev_mode = false;
    var bind_override: ?[]const u8 = null;
    var metrics_override: ?[]const u8 = null;

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        const flagValue = struct {
            fn get(a: []const [:0]const u8, idx: *usize) ?[]const u8 {
                idx.* += 1;
                if (idx.* >= a.len) return null;
                return a[idx.*];
            }
        }.get;
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try out.writeAll(usage_text);
            return;
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            config_path = flagValue(argv, &i) orelse return fatal(out, "missing value for --config", null);
        } else if (std.mem.eql(u8, arg, "--dev")) {
            dev_mode = true;
        } else if (std.mem.eql(u8, arg, "--bind")) {
            bind_override = flagValue(argv, &i) orelse return fatal(out, "missing value for --bind", null);
        } else if (std.mem.eql(u8, arg, "--metrics")) {
            metrics_override = flagValue(argv, &i) orelse return fatal(out, "missing value for --metrics", null);
        } else {
            return fatal(out, "unknown argument", arg);
        }
    }

    // --- config: defaults -> file -> env -> CLI -------------------------------
    var config: config_mod.Config = .{};
    if (config_path) |path| {
        config_mod.parseFile(arena, io, path, &config) catch |err|
            return fatal(out, "cannot load config file", @errorName(err));
    }
    if (init.environ_map.get("IROH_RELAY_ACCESS_TOKEN")) |token| {
        if (token.len == 0) return fatal(out, "IROH_RELAY_ACCESS_TOKEN is empty", null);
        const tokens = try arena.alloc([]const u8, 1);
        tokens[0] = try arena.dupe(u8, token);
        config.access_tokens = tokens;
    }
    if (dev_mode) {
        config.bind_addr = "127.0.0.1:3340";
        config.tls_cert_path = null;
        config.tls_key_path = null;
    }
    if (bind_override) |addr| config.bind_addr = addr;
    if (metrics_override) |addr| config.metrics_addr = addr;
    config_mod.validate(&config) catch |err|
        return fatal(out, "invalid configuration", @errorName(err));

    const qad_mod = relay.qad;

    // --- QAD listener (optional) --------------------------------------------
    // Upstream shares the relay TLS config with QAD, so the identity comes
    // from the same PEM cert/key as the wss listener. Defer order matters:
    // the endpoint dies before the identity it borrows cert DERs from.
    var qad_identity: ?qad_mod.Identity = null;
    defer if (qad_identity) |*id| id.deinit();
    var qad_server: ?*qad_mod.Server = null;
    defer if (qad_server) |qs| qs.deinit(arena);
    var qad_thread: ?std.Thread = null;
    defer {
        // Idempotent stop BEFORE join so an early fatal cannot hang teardown.
        if (qad_server) |qs| qs.initiateShutdown();
        if (qad_thread) |t| t.join();
    }

    if (config.qad_addr) |qad_addr| {
        const qbind = config_mod.splitBindAddr(qad_addr) catch
            return fatal(out, "invalid qad bind_addr (want host:port)", qad_addr);
        const qaddr = std.Io.net.IpAddress.parse(qbind.host, qbind.port) catch
            return fatal(out, "invalid qad bind_addr (unparseable)", qad_addr);
        qad_identity = qad_mod.loadIdentityFromPem(arena, io, config.tls_cert_path.?, config.tls_key_path.?) catch |err|
            return fatal(out, "cannot load QAD TLS identity", @errorName(err));
        qad_server = qad_mod.Server.init(arena, io, qaddr, &qad_identity.?) catch |err|
            return fatal(out, "cannot start QAD listener", @errorName(err));
        try out.print("relay: qad listening on {s}:{d} (udp, ALPN /iroh-qad/0)\n", .{ qbind.host, qad_server.?.localAddress().getPort() });
        try out.flush();
        qad_thread = std.Thread.spawn(.{}, qadServiceEntry, .{ qad_server.?, io }) catch
            return fatal(out, "cannot start QAD service thread", null);
    }

    // --- QAD-only service mode (enable_relay = false) ------------------------
    if (!config.enable_relay) {
        if (config.metrics_addr != null)
            return fatal(out, "invalid configuration", "MetricsRequireRelay (QAD-only mode serves no /health)");
        installSignalHandlers();
        while (g_shutdown_signal.load(.acquire) == 0) {
            io.sleep(std.Io.Duration.fromMilliseconds(20), .awake) catch {};
        }
        const sig = g_shutdown_signal.load(.acquire);
        try out.print("relay: signal {d} received, shutting down\n", .{sig});
        if (qad_server) |qs| qs.initiateShutdown();
        try out.writeAll("relay: stopped\n");
        return;
    }

    const bind = config_mod.splitBindAddr(config.bind_addr) catch
        return fatal(out, "invalid bind_addr (want host:port)", config.bind_addr);

    // --- access control --------------------------------------------------------
    var acl: ?TokenAccessControl = null;
    var server_config: ServerConfig = .{
        .bind_host = bind.host,
        .bind_port = bind.port,
        .tls_cert_path = config.tls_cert_path,
        .tls_key_path = config.tls_key_path,
        .rx_bytes_per_second = config.limits.client_rx_bytes_per_second,
        .rx_max_burst_bytes = config.limits.client_rx_max_burst_bytes,
    };
    if (config.access_tokens.len > 0) {
        acl = TokenAccessControl.init(arena);
        for (config.access_tokens) |token| try acl.?.add(token);
        server_config.access_control = acl.?.accessControl();
    }

    // --- server ----------------------------------------------------------------
    installSignalHandlers();

    var server = Server.init(arena, io, server_config) catch |err|
        return fatal(out, "cannot start relay server", @errorName(err));

    const scheme: []const u8 = if (config.tls_cert_path != null) "wss" else "ws";
    try out.print("relay: listening on {s}://{s}:{d}\n", .{ scheme, bind.host, server.localAddress().getPort() });
    try out.flush();

    const watcher = try std.Thread.spawn(.{}, shutdownWatcher, .{&server});
    defer watcher.join();

    // Optional metrics/health listener.
    var metrics_listener: ?std.Io.net.Server = null;
    var metrics_threads: [2]?std.Thread = .{ null, null };
    if (config.metrics_addr) |addr| {
        const mbind = config_mod.splitBindAddr(addr) catch
            return fatal(out, "invalid metrics_addr (want host:port)", addr);
        const maddr = std.Io.net.IpAddress.parse(mbind.host, mbind.port) catch
            return fatal(out, "invalid metrics_addr (unparseable)", addr);
        metrics_listener = maddr.listen(io, .{ .reuse_address = true, .kernel_backlog = 16 }) catch |err|
            return fatal(out, "cannot bind metrics listener", @errorName(err));
        try out.print("relay: metrics on {s}:{d} (/health, /metrics)\n", .{ mbind.host, metrics_listener.?.socket.address.getPort() });
        try out.flush();
        metrics_threads[0] = try std.Thread.spawn(.{}, metricsAcceptLoop, .{ io, &metrics_listener.?, &server });
        metrics_threads[1] = try std.Thread.spawn(.{}, metricsShutdownWatcher, .{ &server, &metrics_listener.?, io });
    }
    defer {
        for (metrics_threads) |t| {
            if (t) |thread| thread.join();
        }
        if (metrics_listener) |*l| l.deinit(io);
    }

    // --- accept loop -----------------------------------------------------------
    while (server.running.load(.acquire)) {
        server.acceptAndSpawn() catch |err| {
            if (!server.running.load(.acquire)) break;
            std.debug.print("relay: accept error: {}\n", .{err});
        };
    }

    const sig = g_shutdown_signal.load(.acquire);
    if (sig != 0) try out.print("relay: signal {d} received, shutting down\n", .{sig});
    try out.flush();
    if (qad_server) |qs| qs.initiateShutdown();
    server.deinit();
    try out.writeAll("relay: stopped\n");
}

fn qadServiceEntry(qs: *relay.qad.Server, io: std.Io) void {
    qs.serviceLoop(io);
}

fn fatal(out: *std.Io.Writer, msg: []const u8, detail: ?[]const u8) error{Fatal} {
    out.print("relay: error: {s}{s}{s}\n", .{ msg, if (detail != null) ": " else "", detail orelse "" }) catch {};
    out.flush() catch {};
    return error.Fatal;
}
