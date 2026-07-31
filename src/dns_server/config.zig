//! Operator configuration for the iroh-dns-server product.
//!
//! Small TOML subset (same dialect as `relay/config.zig`): `[section]` headers,
//! `key = value` with strings/ints/bools/string-arrays, `#` comments. Shape is
//! Zig-native (combined `host:port` bind strings) while covering the fields
//! operators need from `iroh/iroh-dns-server/src/config.rs`.

const std = @import("std");
const builtin = @import("builtin");

/// HTTPS certificate strategy (mode plumbing). Live ACME issuance is
/// environment-blocked without a real CA/Pebble; see `tls.zig`.
pub const CertMode = enum {
    none,
    manual,
    self_signed,
    lets_encrypt,

    pub fn parse(s: []const u8) ?CertMode {
        if (std.mem.eql(u8, s, "none") or std.mem.eql(u8, s, "disabled")) return .none;
        if (std.mem.eql(u8, s, "manual")) return .manual;
        if (std.mem.eql(u8, s, "self_signed") or std.mem.eql(u8, s, "self-signed")) return .self_signed;
        if (std.mem.eql(u8, s, "lets_encrypt") or std.mem.eql(u8, s, "letsencrypt") or std.mem.eql(u8, s, "acme"))
            return .lets_encrypt;
        return null;
    }
};

pub const Config = struct {
    http_addr: ?[]const u8 = "127.0.0.1:8080",
    https_addr: ?[]const u8 = null,
    metrics_addr: ?[]const u8 = "127.0.0.1:9117",
    metrics_disabled: bool = false,
    dns_addr: []const u8 = "127.0.0.1:5300",
    default_soa: []const u8 = "dns1.irohdns.example hostmaster.irohdns.example 0 10800 3600 604800 3600",
    default_ttl: u32 = 900,
    origins: []const []const u8 = &.{"irohdns.example."},
    rr_a: ?[]const u8 = null,
    rr_aaaa: ?[]const u8 = null,
    rr_ns: ?[]const u8 = null,
    data_dir: ?[]const u8 = null,
    /// PUT budget per client IP per window. 0 disables the limiter entirely.
    pkarr_put_rate_limit: u32 = 256,
    /// Signed packets older than this are evicted from the zone store.
    /// 0 disables age-based eviction (packets live until replaced).
    packet_max_age_secs: u64 = 7 * 24 * 3600,
    /// Enables the mainline (BEP-44) fallback seam on the authoritative answer
    /// path. Accepted by `validate`; a store miss then enqueues a background
    /// DHT resolve that writes into `ZoneStore` (see `mainline.zig`).
    mainline_enabled: bool = false,
    /// Per-connection read/write deadline for TCP DNS and HTTP/DoH accepts.
    /// A stalled client is dropped within this envelope so it cannot starve
    /// the accept loop. 0 disables the deadline (operator escape hatch only).
    connection_read_timeout_ms: u64 = 5_000,
    /// Cap on concurrent TCP DNS + HTTP handler threads. New accepts beyond
    /// this are closed immediately rather than queued unboundedly.
    max_concurrent_connections: u32 = 64,
    cert_mode: CertMode = .none,
    cert_cache: ?[]const u8 = null,
    letsencrypt_contact: ?[]const u8 = null,
    letsencrypt_prod: bool = false,
    tls_domains: []const []const u8 = &.{},
};

pub const Error = error{
    InvalidLine,
    InvalidSection,
    InvalidString,
    InvalidInteger,
    InvalidBool,
    InvalidArray,
    UnknownKey,
    DuplicateKey,
    NothingToServe,
    InvalidCertMode,
    LetsEncryptContactRequired,
    CertCacheRequired,
    TlsDomainsRequired,
} || std.mem.Allocator.Error;

pub fn validate(config: *const Config) Error!void {
    if (config.http_addr == null and config.https_addr == null) return error.NothingToServe;
    if (config.origins.len == 0) return error.NothingToServe;
    switch (config.cert_mode) {
        .none => {},
        .manual, .self_signed => {
            if (config.tls_domains.len == 0) return error.TlsDomainsRequired;
            if (config.cert_cache == null) return error.CertCacheRequired;
        },
        .lets_encrypt => {
            if (config.tls_domains.len == 0) return error.TlsDomainsRequired;
            if (config.letsencrypt_contact == null) return error.LetsEncryptContactRequired;
            if (config.cert_cache == null) return error.CertCacheRequired;
        },
    }
}

pub fn parseToml(allocator: std.mem.Allocator, text: []const u8, config: *Config) Error!void {
    var section: []const u8 = "";
    var seen: std.ArrayList(struct { section: []const u8, key: []const u8 }) = .empty;
    defer seen.deinit(allocator);

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const line = stripComment(raw_line);
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;

        if (trimmed[0] == '[') {
            if (trimmed.len < 3 or trimmed[trimmed.len - 1] != ']') return error.InvalidSection;
            section = std.mem.trim(u8, trimmed[1 .. trimmed.len - 1], " \t");
            if (section.len == 0) return error.InvalidSection;
            continue;
        }

        const eq = std.mem.indexOfScalar(u8, trimmed, '=') orelse return error.InvalidLine;
        const key = std.mem.trim(u8, trimmed[0..eq], " \t");
        const value = std.mem.trim(u8, trimmed[eq + 1 ..], " \t");
        if (key.len == 0 or value.len == 0) return error.InvalidLine;

        for (seen.items) |entry| {
            if (std.mem.eql(u8, entry.section, section) and std.mem.eql(u8, entry.key, key))
                return error.DuplicateKey;
        }
        try seen.append(allocator, .{ .section = section, .key = key });
        try setField(allocator, config, section, key, value);
    }
}

pub fn parseFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    config: *Config,
) !void {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.size > 1 << 20) return error.InvalidLine;
    const text = try allocator.alloc(u8, @intCast(stat.size));
    defer allocator.free(text);
    var buf: [4096]u8 = undefined;
    var file_reader = file.reader(io, &buf);
    try file_reader.interface.readSliceAll(text);
    try parseToml(allocator, text, config);
}

/// Resolve data dir: config → IROH_DNS_DATA_DIR → per-OS user data dir → ./iroh-dns-data.
///
/// The per-OS leg follows each platform's own convention rather than forcing the
/// XDG layout everywhere: macOS uses `~/Library/Application Support`, Windows
/// uses `%APPDATA%` (falling back to `%LOCALAPPDATA%`/`%USERPROFILE%`), and
/// everything else uses `$HOME/.local/share`.
pub fn resolveDataDir(allocator: std.mem.Allocator, config: *const Config) ![]u8 {
    if (config.data_dir) |d| return allocator.dupe(u8, d);
    if (getEnv("IROH_DNS_DATA_DIR")) |env| return allocator.dupe(u8, env);
    if (try platformDataDir(allocator)) |dir| return dir;
    return allocator.dupe(u8, "./iroh-dns-data");
}

/// The per-OS user data directory for `iroh-dns`, or null when the platform's
/// home/appdata variables are all unset (containers, empty environments).
pub fn platformDataDir(allocator: std.mem.Allocator) !?[]u8 {
    switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => {
            const home = getEnv("HOME") orelse return null;
            return try std.fmt.allocPrint(allocator, "{s}/Library/Application Support/iroh-dns", .{home});
        },
        .windows => {
            // %APPDATA% is the roaming per-user store; the other two are the
            // documented fallbacks when a service account has no roaming profile.
            const base = getEnv("APPDATA") orelse getEnv("LOCALAPPDATA") orelse getEnv("USERPROFILE") orelse return null;
            return try std.fmt.allocPrint(allocator, "{s}/iroh-dns", .{base});
        },
        else => {
            if (getEnv("XDG_DATA_HOME")) |xdg| {
                if (xdg.len != 0) return try std.fmt.allocPrint(allocator, "{s}/iroh-dns", .{xdg});
            }
            const home = getEnv("HOME") orelse return null;
            return try std.fmt.allocPrint(allocator, "{s}/.local/share/iroh-dns", .{home});
        },
    }
}

/// Zig 0.16 has no allocation-free `std.process.getEnvVarOwned` equivalent that
/// works without an `Io`; libc `getenv` is the same pattern portmapper/defaults use.
fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const raw = std.c.getenv(name) orelse return null;
    const value = std.mem.span(raw);
    if (value.len == 0) return null;
    return value;
}

/// Fields a running server may adopt from a re-read config file (SIGHUP).
///
/// Bind addresses, the data dir and TLS material are deliberately excluded: they
/// are captured by live listeners/handles, so changing them needs a restart.
pub const Reloadable = struct {
    default_ttl: u32,
    default_soa: []const u8,
    origins: []const []const u8,
    rr_a: ?[]const u8,
    rr_aaaa: ?[]const u8,
    rr_ns: ?[]const u8,
    pkarr_put_rate_limit: u32,
    packet_max_age_secs: u64,
    mainline_enabled: bool,

    pub fn from(config: *const Config) Reloadable {
        return .{
            .default_ttl = config.default_ttl,
            .default_soa = config.default_soa,
            .origins = config.origins,
            .rr_a = config.rr_a,
            .rr_aaaa = config.rr_aaaa,
            .rr_ns = config.rr_ns,
            .pkarr_put_rate_limit = config.pkarr_put_rate_limit,
            .packet_max_age_secs = config.packet_max_age_secs,
            .mainline_enabled = config.mainline_enabled,
        };
    }
};

/// Overwrite only the reloadable fields of `config`.
///
/// The caller owns the lifetime rule: `fields`' strings must outlive every
/// reader of `config`, and the previous generation's strings must NOT be freed
/// while requests are in flight. `Server.reloadFromFile` satisfies both by
/// allocating each generation from a long-lived allocator and retiring (not
/// freeing) the old one.
pub fn applyReloadable(config: *Config, fields: Reloadable) void {
    config.default_ttl = fields.default_ttl;
    config.default_soa = fields.default_soa;
    config.origins = fields.origins;
    config.rr_a = fields.rr_a;
    config.rr_aaaa = fields.rr_aaaa;
    config.rr_ns = fields.rr_ns;
    config.pkarr_put_rate_limit = fields.pkarr_put_rate_limit;
    config.packet_max_age_secs = fields.packet_max_age_secs;
    config.mainline_enabled = fields.mainline_enabled;
}

/// Parse `path` into a fresh `Config` and return just its reloadable fields.
/// Strings are allocated from `allocator` and outlive the returned value.
pub fn reloadableFromFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !Reloadable {
    var fresh: Config = .{};
    try parseFile(allocator, io, path, &fresh);
    try validate(&fresh);
    return .from(&fresh);
}

pub const BindAddr = struct { host: []const u8, port: u16 };

pub fn splitBindAddr(addr: []const u8) error{InvalidBindAddr}!BindAddr {
    if (addr.len == 0) return error.InvalidBindAddr;
    if (addr[0] == '[') {
        const close = std.mem.indexOfScalar(u8, addr, ']') orelse return error.InvalidBindAddr;
        if (close + 1 >= addr.len or addr[close + 1] != ':') return error.InvalidBindAddr;
        const port = std.fmt.parseInt(u16, addr[close + 2 ..], 10) catch return error.InvalidBindAddr;
        return .{ .host = addr[1..close], .port = port };
    }
    const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return error.InvalidBindAddr;
    if (colon == 0 or colon + 1 >= addr.len) return error.InvalidBindAddr;
    const port = std.fmt.parseInt(u16, addr[colon + 1 ..], 10) catch return error.InvalidBindAddr;
    return .{ .host = addr[0..colon], .port = port };
}

fn setField(
    allocator: std.mem.Allocator,
    config: *Config,
    section: []const u8,
    key: []const u8,
    value: []const u8,
) Error!void {
    if (section.len == 0) {
        if (std.mem.eql(u8, key, "data_dir")) {
            config.data_dir = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "pkarr_put_rate_limit")) {
            if (std.mem.eql(u8, value, "\"disabled\"") or std.mem.eql(u8, value, "'disabled'") or std.mem.eql(u8, value, "disabled")) {
                config.pkarr_put_rate_limit = 0;
            } else {
                config.pkarr_put_rate_limit = try parseNonNegInt(value);
            }
        } else if (std.mem.eql(u8, key, "packet_max_age_secs")) {
            if (std.mem.eql(u8, value, "\"disabled\"") or std.mem.eql(u8, value, "'disabled'") or std.mem.eql(u8, value, "disabled")) {
                config.packet_max_age_secs = 0;
            } else {
                config.packet_max_age_secs = try parseNonNegU64(value);
            }
        } else return error.UnknownKey;
    } else if (std.mem.eql(u8, section, "http")) {
        if (std.mem.eql(u8, key, "bind_addr") or std.mem.eql(u8, key, "addr")) {
            config.http_addr = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "port")) {
            const port = try parseNonNegInt(value);
            config.http_addr = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
        } else if (std.mem.eql(u8, key, "https_addr")) {
            config.https_addr = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "https_port")) {
            const port = try parseNonNegInt(value);
            config.https_addr = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
        } else return error.UnknownKey;
    } else if (std.mem.eql(u8, section, "tls")) {
        if (std.mem.eql(u8, key, "cert_mode") or std.mem.eql(u8, key, "mode")) {
            const s = try parseString(allocator, value);
            config.cert_mode = CertMode.parse(s) orelse return error.InvalidCertMode;
        } else if (std.mem.eql(u8, key, "cert_cache")) {
            config.cert_cache = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "domains")) {
            config.tls_domains = try parseStringArray(allocator, value);
        } else if (std.mem.eql(u8, key, "letsencrypt_contact") or std.mem.eql(u8, key, "contact")) {
            config.letsencrypt_contact = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "letsencrypt_prod") or std.mem.eql(u8, key, "prod")) {
            config.letsencrypt_prod = try parseBool(value);
        } else return error.UnknownKey;
    } else if (std.mem.eql(u8, section, "dns")) {
        if (std.mem.eql(u8, key, "bind_addr") or std.mem.eql(u8, key, "addr")) {
            const host = try parseString(allocator, value);
            const cur = splitBindAddr(config.dns_addr) catch BindAddr{ .host = "127.0.0.1", .port = 5300 };
            config.dns_addr = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, cur.port });
        } else if (std.mem.eql(u8, key, "port")) {
            const port = try parseNonNegInt(value);
            const cur = splitBindAddr(config.dns_addr) catch BindAddr{ .host = "127.0.0.1", .port = 5300 };
            config.dns_addr = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ cur.host, port });
        } else if (std.mem.eql(u8, key, "default_soa")) {
            config.default_soa = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "default_ttl")) {
            config.default_ttl = try parseNonNegInt(value);
        } else if (std.mem.eql(u8, key, "origins")) {
            config.origins = try parseStringArray(allocator, value);
        } else if (std.mem.eql(u8, key, "rr_a")) {
            config.rr_a = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "rr_aaaa")) {
            config.rr_aaaa = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "rr_ns")) {
            config.rr_ns = try parseString(allocator, value);
        } else return error.UnknownKey;
    } else if (std.mem.eql(u8, section, "metrics")) {
        if (std.mem.eql(u8, key, "disabled")) {
            config.metrics_disabled = try parseBool(value);
        } else if (std.mem.eql(u8, key, "bind_addr") or std.mem.eql(u8, key, "addr")) {
            config.metrics_addr = try parseString(allocator, value);
        } else return error.UnknownKey;
    } else if (std.mem.eql(u8, section, "mainline")) {
        if (std.mem.eql(u8, key, "enabled")) {
            config.mainline_enabled = try parseBool(value);
        } else return error.UnknownKey;
    } else return error.UnknownKey;
}

fn stripComment(line: []const u8) []const u8 {
    var in_basic = false;
    var in_literal = false;
    var escaped = false;
    for (line, 0..) |c, i| {
        if (escaped) {
            escaped = false;
            continue;
        }
        switch (c) {
            '\\' => if (in_basic) {
                escaped = true;
            },
            '"' => if (!in_literal) {
                in_basic = !in_basic;
            },
            '\'' => if (!in_basic) {
                in_literal = !in_literal;
            },
            '#' => if (!in_basic and !in_literal) {
                return line[0..i];
            },
            else => {},
        }
    }
    return line;
}

fn parseString(allocator: std.mem.Allocator, value: []const u8) Error![]const u8 {
    if (value.len >= 2 and value[0] == '\'' and value[value.len - 1] == '\'') {
        return allocator.dupe(u8, value[1 .. value.len - 1]);
    }
    if (value.len < 2 or value[0] != '"' or value[value.len - 1] != '"')
        return error.InvalidString;
    return allocator.dupe(u8, value[1 .. value.len - 1]);
}

fn parseBool(value: []const u8) Error!bool {
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return error.InvalidBool;
}

fn parseNonNegInt(value: []const u8) Error!u32 {
    return std.math.cast(u32, try parseNonNegU64(value)) orelse error.InvalidInteger;
}

fn parseNonNegU64(value: []const u8) Error!u64 {
    var buf: [24]u8 = undefined;
    if (value.len == 0 or value.len > buf.len) return error.InvalidInteger;
    var n: usize = 0;
    for (value) |c| {
        if (c == '_') continue;
        buf[n] = c;
        n += 1;
    }
    return std.fmt.parseInt(u64, buf[0..n], 10) catch return error.InvalidInteger;
}

fn parseStringArray(allocator: std.mem.Allocator, value: []const u8) Error![]const []const u8 {
    if (value.len < 2 or value[0] != '[' or value[value.len - 1] != ']')
        return error.InvalidArray;
    const body = std.mem.trim(u8, value[1 .. value.len - 1], " \t");
    if (body.len == 0) return &.{};
    var items: std.ArrayList([]const u8) = .empty;
    errdefer items.deinit(allocator);
    var parts = std.mem.splitScalar(u8, body, ',');
    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        if (trimmed.len == 0) return error.InvalidArray;
        try items.append(allocator, try parseString(allocator, trimmed));
    }
    return items.toOwnedSlice(allocator);
}

test "parseToml dns-server surface" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var config: Config = .{};
    try parseToml(allocator,
        \\pkarr_put_rate_limit = "disabled"
        \\data_dir = "/var/lib/iroh-dns"
        \\
        \\[http]
        \\port = 8080
        \\
        \\[dns]
        \\port = 5300
        \\bind_addr = "127.0.0.1"
        \\default_ttl = 900
        \\origins = ["irohdns.example.", "."]
        \\rr_a = "127.0.0.1"
        \\rr_ns = "ns1.irohdns.example."
        \\
        \\[metrics]
        \\disabled = false
        \\bind_addr = "127.0.0.1:9117"
        \\
        \\[mainline]
        \\enabled = false
        \\
    , &config);
    try validate(&config);
    try std.testing.expectEqual(@as(u32, 0), config.pkarr_put_rate_limit);
    try std.testing.expectEqualStrings("/var/lib/iroh-dns", config.data_dir.?);
    try std.testing.expectEqualStrings("127.0.0.1:8080", config.http_addr.?);
    try std.testing.expectEqualStrings("127.0.0.1:5300", config.dns_addr);
    try std.testing.expectEqual(@as(usize, 2), config.origins.len);
    try std.testing.expectEqualStrings("127.0.0.1", config.rr_a.?);
}

test "resolveDataDir prefers config then env" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var config: Config = .{ .data_dir = "/tmp/dns-data" };
    const dir = try resolveDataDir(allocator, &config);
    try std.testing.expectEqualStrings("/tmp/dns-data", dir);
}

test "platformDataDir follows the host OS convention" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const dir = (try platformDataDir(allocator)) orelse {
        // No HOME/APPDATA in this environment: resolveDataDir must still yield
        // the relative fallback rather than failing.
        var config: Config = .{};
        const fallback = try resolveDataDir(allocator, &config);
        try std.testing.expectEqualStrings("./iroh-dns-data", fallback);
        return;
    };

    switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => {
            try std.testing.expect(std.mem.endsWith(u8, dir, "/Library/Application Support/iroh-dns"));
        },
        .windows => {
            try std.testing.expect(std.mem.endsWith(u8, dir, "/iroh-dns"));
            try std.testing.expect(!std.mem.endsWith(u8, dir, "/.local/share/iroh-dns"));
        },
        else => {
            // XDG_DATA_HOME wins when set; otherwise the ~/.local/share default.
            try std.testing.expect(std.mem.endsWith(u8, dir, "/iroh-dns"));
            if (getEnv("XDG_DATA_HOME") == null) {
                try std.testing.expect(std.mem.endsWith(u8, dir, "/.local/share/iroh-dns"));
            }
        },
    }
}

test "mainline_enabled validates and packet_max_age_secs parses" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var config: Config = .{};
    try parseToml(allocator,
        \\packet_max_age_secs = 86_400
        \\
        \\[mainline]
        \\enabled = true
        \\
    , &config);
    // The mainline facade is a seam now, not a hard reject.
    try validate(&config);
    try std.testing.expect(config.mainline_enabled);
    try std.testing.expectEqual(@as(u64, 86_400), config.packet_max_age_secs);

    var disabled: Config = .{};
    try parseToml(allocator, "packet_max_age_secs = \"disabled\"\n", &disabled);
    try std.testing.expectEqual(@as(u64, 0), disabled.packet_max_age_secs);
    // Default is a week, so the eviction row is on unless explicitly disabled.
    try std.testing.expectEqual(@as(u64, 7 * 24 * 3600), (Config{}).packet_max_age_secs);
}

test "reloadable fields round-trip through a config file" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;

    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const dir_rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-reload-{d}", .{nonce});
    defer std.Io.Dir.cwd().deleteTree(io, dir_rel) catch {};
    try std.Io.Dir.cwd().createDirPath(io, dir_rel);
    const path = try std.fmt.allocPrint(allocator, "{s}/dns.toml", .{dir_rel});
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data =
        \\pkarr_put_rate_limit = 7
        \\packet_max_age_secs = 60
        \\
        \\[dns]
        \\default_ttl = 42
        \\origins = ["reloaded.example."]
        \\rr_a = "192.0.2.9"
        \\
        ,
    });

    var live: Config = .{ .http_addr = "127.0.0.1:1", .dns_addr = "127.0.0.1:2" };
    const before_http = live.http_addr.?;
    applyReloadable(&live, try reloadableFromFile(allocator, io, path));

    try std.testing.expectEqual(@as(u32, 42), live.default_ttl);
    try std.testing.expectEqual(@as(u32, 7), live.pkarr_put_rate_limit);
    try std.testing.expectEqual(@as(u64, 60), live.packet_max_age_secs);
    try std.testing.expectEqual(@as(usize, 1), live.origins.len);
    try std.testing.expectEqualStrings("reloaded.example.", live.origins[0]);
    try std.testing.expectEqualStrings("192.0.2.9", live.rr_a.?);
    // Bind addresses are captured by live listeners — reload must not move them.
    try std.testing.expectEqualStrings(before_http, live.http_addr.?);
    try std.testing.expectEqualStrings("127.0.0.1:2", live.dns_addr);
}
