//! `iroh-dns-server` binary — operator surface: CLI + TOML + graceful shutdown.
//!
//! Usage:
//!   iroh-dns-server [--config PATH] [--validate-config PATH] [--version] [--help]

const std = @import("std");
const builtin = @import("builtin");
const zig_iroh = @import("zig_iroh");

const dns_server = zig_iroh.dns_server;
const config_mod = dns_server.config;
const tls_mod = dns_server.tls;
const mainline_mod = dns_server.mainline;

const usage_text =
    \\Usage: iroh-dns-server [options]
    \\
    \\Options:
    \\  -c, --config PATH            TOML config file (see dns_server.example.toml)
    \\      --validate-config PATH   parse + validate TOML and exit (no serve)
    \\      --version                print version and exit
    \\  -h, --help                   print this text
    \\
    \\Signals:
    \\  SIGTERM/SIGINT               drain listeners and exit
    \\  SIGHUP                       re-read --config and adopt ttl / origins /
    \\                               static records / rate limit / packet max age
    \\
    \\Environment:
    \\  IROH_DNS_DATA_DIR            override the persistent data directory
    \\
;

var g_shutdown_signal: std.atomic.Value(u8) = .init(0);
/// Pending SIGHUP count. A counter, not a flag, so two reloads in quick
/// succession are not collapsed into one.
var g_reload_requests: std.atomic.Value(u32) = .init(0);

fn onPosixSignal(sig: std.posix.SIG) callconv(.c) void {
    g_shutdown_signal.store(@intCast(@intFromEnum(sig)), .release);
}

fn onPosixHup(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
    // Signal-handler safe: one atomic increment, no allocation or I/O. The
    // watcher thread does the actual file read.
    _ = g_reload_requests.fetchAdd(1, .release);
}

fn installSignalHandlers() void {
    if (builtin.os.tag == .windows) return;
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onPosixSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);

    const hup_act: std.posix.Sigaction = .{
        .handler = .{ .handler = onPosixHup },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.HUP, &hup_act, null);
}

const Watcher = struct {
    server: *dns_server.Server,
    /// `--config` path, or null when the server runs on defaults.
    config_path: ?[]const u8,
};

fn signalWatcher(watcher: Watcher) void {
    const server = watcher.server;
    var handled_reloads: u32 = 0;
    while (g_shutdown_signal.load(.acquire) == 0) {
        const requested = g_reload_requests.load(.acquire);
        if (requested != handled_reloads) {
            handled_reloads = requested;
            applyReload(watcher);
        }
        server.io.sleep(std.Io.Duration.fromMilliseconds(20), .awake) catch {};
    }
    server.initiateShutdown();
}

/// SIGHUP: re-read the config file and adopt its reloadable fields. A bad file
/// leaves the running config untouched — a reload must never take the server down.
fn applyReload(watcher: Watcher) void {
    const path = watcher.config_path orelse {
        std.log.info("SIGHUP ignored: no --config path to reload", .{});
        return;
    };
    watcher.server.reloadFromFile(path) catch |err| {
        std.log.warn("SIGHUP reload of {s} failed ({t}); keeping running config", .{ path, err });
        return;
    };
    const cfg = watcher.server.config_live.load(.acquire);
    std.log.info("SIGHUP reload of {s} applied: ttl={d} origins={d} put_rate_limit={d}", .{
        path,
        cfg.default_ttl,
        cfg.origins.len,
        cfg.pkarr_put_rate_limit,
    });
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const out = &stdout_writer.interface;
    defer out.flush() catch {};

    const argv = try init.minimal.args.toSlice(arena);
    var config_path: ?[]const u8 = null;
    var validate_only: ?[]const u8 = null;
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try out.writeAll(usage_text);
            return;
        } else if (std.mem.eql(u8, arg, "--version")) {
            try out.print("iroh-dns-server {s}\n", .{dns_server.http.VERSION});
            return;
        } else if (std.mem.eql(u8, arg, "--validate-config")) {
            i += 1;
            if (i >= argv.len) {
                try out.writeAll("error: --validate-config requires a path\n");
                std.process.exit(2);
            }
            validate_only = argv[i];
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            i += 1;
            if (i >= argv.len) {
                try out.writeAll("error: --config requires a path\n");
                std.process.exit(2);
            }
            config_path = argv[i];
        } else {
            try out.print("error: unknown argument {s}\n", .{arg});
            try out.writeAll(usage_text);
            std.process.exit(2);
        }
    }

    if (validate_only) |path| {
        var config: config_mod.Config = .{};
        try config_mod.parseFile(arena, io, path, &config);
        try config_mod.validate(&config);
        // Exercise TLS mode plumbing without needing a live CA.
        const plan = try tls_mod.planFromConfig(&config);
        try out.print("config ok cert_mode={s} origins={d}\n", .{ @tagName(plan.mode), config.origins.len });
        return;
    }

    var config: config_mod.Config = .{};
    if (config_path) |path| {
        try config_mod.parseFile(arena, io, path, &config);
    }
    try config_mod.validate(&config);

    var server: dns_server.Server = undefined;
    try dns_server.Server.init(&server, arena, io, config);
    defer server.deinit();

    var tls_activated: ?tls_mod.Activated = null;
    // Path strings are arena-owned; do not Activated.deinit (would double-free).
    if (config.cert_mode != .none) {
        const plan = try tls_mod.planFromConfig(&config);
        if (tls_mod.activate(arena, io, plan)) |act| {
            var owned = act;
            owned.owned_paths = false;
            tls_activated = owned;
            server.setTlsMaterial(owned.cert_path, owned.key_path);
        } else |err| switch (err) {
            error.RealAcmeCaUnavailable => try out.writeAll(
                "note: tls cert_mode=lets_encrypt planned; live ACME CA unavailable in this environment — serving HTTP only\n",
            ),
            error.ManualCertMaterialMissing,
            error.SelfSignedGenerationFailed,
            error.HttpsAddrRequired,
            error.CertCacheRequired,
            error.TlsDomainsRequired,
            => try out.print(
                "note: tls mode={s} not activated ({s}) — serving HTTP only\n",
                .{ @tagName(plan.mode), @errorName(err) },
            ),
            else => return err,
        }
    }

    var mainline_resolver: ?mainline_mod.BackgroundResolver = null;
    defer if (mainline_resolver) |*r| r.deinit();
    if (config.mainline_enabled) {
        mainline_resolver = mainline_mod.BackgroundResolver.init(arena, io, &server.store, &server.metrics);
        server.setMainlineResolver(&mainline_resolver.?);
    }

    installSignalHandlers();
    const watcher = try std.Thread.spawn(.{}, signalWatcher, .{Watcher{
        .server = &server,
        .config_path = config_path,
    }});
    defer watcher.join();

    try out.print("iroh-dns-server listening http={s} https={s} dns={s} metrics={s}\n", .{
        config.http_addr orelse "none",
        if (tls_activated != null) (config.https_addr orelse "none") else "none",
        config.dns_addr,
        if (config.metrics_disabled) "disabled" else (config.metrics_addr orelse "none"),
    });
    try out.flush();

    try server.run();
    try out.writeAll("shutdown\n");
}
