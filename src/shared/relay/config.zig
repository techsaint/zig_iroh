//! Operator configuration for the relay server binary.
//!
//! A deliberately small TOML subset (the relay config has no wire contract —
//! it is pure product surface) parsed into a typed `Config`. Supported:
//! `[section]` headers (dotted ok), `key = value` with basic/literal strings,
//! integers, booleans, and string arrays; `#` comments outside quotes.
//! Unknown keys are hard errors so operator typos fail loudly at startup.
//!
//! Shape rationale (Zig-native, NOT a transliteration of iroh's `main.rs`
//! Config): one combined `host:port` string per listener (what a socket
//! actually wants) instead of iroh's split http/https/quic bind structs, and
//! flat top-level keys over deep table nesting.

const std = @import("std");

pub const Limits = struct {
    /// Per-connection receive token-bucket rate (reference: upstream
    /// `[limits.client.rx] bytes_per_second`). Null = unlimited.
    client_rx_bytes_per_second: ?u32 = null,
    /// Burst capacity; defaults to bytes_per_second/10 when unset (upstream
    /// behavior, `server/streams.rs`).
    client_rx_max_burst_bytes: ?u32 = null,
};

/// ACME (RFC 8555) certificate mode — the relay acquires and renews its own
/// TLS certificates via TLS-ALPN-01 instead of serving a static PEM pair
/// (upstream: `[tls] cert_mode = "LetsEncrypt"`). All fields required except
/// `contact`; `[acme]` in the file enables the mode.
pub const Acme = struct {
    /// ACME directory URL (Pebble in test, Let's Encrypt in production).
    directory_url: ?[]const u8 = null,
    /// PEM file with the CA that signs the ACME directory's own TLS
    /// certificate. Explicit trust anchor; verification is never skipped.
    ca_pem_path: ?[]const u8 = null,
    /// Persistent ES256 account key (created 0600 on first run).
    account_key_path: ?[]const u8 = null,
    /// Directory for `<hostname>.{crt,key}.pem` issued-cert storage.
    cert_dir: ?[]const u8 = null,
    /// Hostnames to provision + serve by SNI. At least one.
    hostnames: []const []const u8 = &.{},
    /// Optional contact address ("mailto:" is added by the ACME client).
    contact: ?[]const u8 = null,
};

pub const Config = struct {
    /// WebSocket relay listener (`host:port`, v6 bracketed ok).
    bind_addr: []const u8 = "127.0.0.1:8080",
    /// Both or neither; when set the listener serves wss:// (TLS 1.2/1.3 via
    /// the pure-Zig tls library).
    tls_cert_path: ?[]const u8 = null,
    tls_key_path: ?[]const u8 = null,
    /// Optional separate plain-HTTP listener for `/health` + `/metrics`.
    metrics_addr: ?[]const u8 = null,
    /// Shared-token access policy. Empty = allow all (upstream `everyone`).
    access_tokens: []const []const u8 = &.{},
    limits: Limits = .{},
    /// Optional `/iroh-qad/0` QUIC address-discovery listener (`host:port`).
    /// Requires TLS (upstream: QAD is TLS-only).
    qad_addr: ?[]const u8 = null,
    /// Serve the WebSocket relay data plane (upstream `enable_relay`, default
    /// true). `false` + `[qad]` = the QAD-only service mode.
    enable_relay: bool = true,
    /// ACME certificate mode. Mutually exclusive with the static PEM pair.
    acme: ?Acme = null,
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
    MissingValue,
    TlsConfigIncomplete,
    BurstWithoutRate,
    QadRequiresTls,
    NothingToServe,
    MixedTlsModes,
    AcmeConfigIncomplete,
    AcmeNoHostnames,
    AcmeDuplicateHostname,
} || std.mem.Allocator.Error;

/// Validates cross-field invariants (called by the binary after all sources
/// are merged, and by parseFile).
pub fn validate(config: *const Config) Error!void {
    if ((config.tls_cert_path == null) != (config.tls_key_path == null))
        return error.TlsConfigIncomplete;
    if (config.limits.client_rx_max_burst_bytes != null and
        config.limits.client_rx_bytes_per_second == null)
        return error.BurstWithoutRate;
    if (config.acme) |acme| {
        // Mixed modes are hard errors, never a precedence guess: static PEM
        // plus ACME would leave which cert a handshake serves ambiguous.
        if (config.tls_cert_path != null) return error.MixedTlsModes;
        // QAD borrows the static PEM identity; ACME mode has none yet.
        if (config.qad_addr != null) return error.QadRequiresTls;
        if (acme.directory_url == null or acme.ca_pem_path == null or
            acme.account_key_path == null or acme.cert_dir == null)
            return error.AcmeConfigIncomplete;
        if (acme.hostnames.len == 0) return error.AcmeNoHostnames;
        for (acme.hostnames, 0..) |h, i| {
            if (h.len == 0) return error.AcmeNoHostnames;
            for (acme.hostnames[i + 1 ..]) |other|
                if (std.mem.eql(u8, h, other)) return error.AcmeDuplicateHostname;
        }
    }
    if (config.qad_addr != null and config.tls_cert_path == null and config.acme == null)
        return error.QadRequiresTls;
    if (!config.enable_relay and config.qad_addr == null)
        return error.NothingToServe;
}

/// Parses TOML text into `config` (overwriting fields it sees; unset fields
/// keep their pre-call values so defaults → file → env → CLI layering works).
/// All strings are dupe'd from `allocator`.
pub fn parseToml(allocator: std.mem.Allocator, text: []const u8, config: *Config) Error!void {
    var section: []const u8 = "";
    // Duplicate-key detection by linear scan over (section, key) pairs —
    // slices into `text`, no allocation. Configs are small; O(n²) is fine.
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

/// Loads and parses a TOML file.
pub fn parseFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    config: *Config,
) !void {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.size > 1 << 20) return error.InvalidLine; // config files are small
    const text = try allocator.alloc(u8, @intCast(stat.size));
    defer allocator.free(text);
    var buf: [4096]u8 = undefined;
    var file_reader = file.reader(io, &buf);
    try file_reader.interface.readSliceAll(text);
    try parseToml(allocator, text, config);
}

fn setField(
    allocator: std.mem.Allocator,
    config: *Config,
    section: []const u8,
    key: []const u8,
    value: []const u8,
) Error!void {
    if (section.len == 0) {
        if (std.mem.eql(u8, key, "bind_addr")) {
            config.bind_addr = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "tls_cert_path")) {
            config.tls_cert_path = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "tls_key_path")) {
            config.tls_key_path = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "metrics_addr")) {
            config.metrics_addr = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "access_tokens")) {
            config.access_tokens = try parseStringArray(allocator, value);
        } else if (std.mem.eql(u8, key, "enable_relay")) {
            config.enable_relay = try parseBool(value);
        } else return error.UnknownKey;
    } else if (std.mem.eql(u8, section, "limits.client_rx")) {
        if (std.mem.eql(u8, key, "bytes_per_second")) {
            config.limits.client_rx_bytes_per_second = try parsePositiveInt(value);
        } else if (std.mem.eql(u8, key, "max_burst_bytes")) {
            config.limits.client_rx_max_burst_bytes = try parsePositiveInt(value);
        } else return error.UnknownKey;
    } else if (std.mem.eql(u8, section, "qad")) {
        if (std.mem.eql(u8, key, "bind_addr")) {
            config.qad_addr = try parseString(allocator, value);
        } else return error.UnknownKey;
    } else if (std.mem.eql(u8, section, "acme")) {
        if (config.acme == null) config.acme = .{};
        const acme = &config.acme.?;
        if (std.mem.eql(u8, key, "directory_url")) {
            acme.directory_url = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "ca_pem_path")) {
            acme.ca_pem_path = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "account_key_path")) {
            acme.account_key_path = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "cert_dir")) {
            acme.cert_dir = try parseString(allocator, value);
        } else if (std.mem.eql(u8, key, "hostnames")) {
            acme.hostnames = try parseStringArray(allocator, value);
        } else if (std.mem.eql(u8, key, "contact")) {
            acme.contact = try parseString(allocator, value);
        } else return error.UnknownKey;
    } else return error.UnknownKey;
}

/// Removes a trailing `#` comment, honoring quotes.
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
    const body = value[1 .. value.len - 1];
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        const c = body[i];
        if (c != '\\') {
            try out.append(allocator, c);
            continue;
        }
        i += 1;
        if (i >= body.len) return error.InvalidString;
        const unescaped: u8 = switch (body[i]) {
            '"' => '"',
            '\\' => '\\',
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '0' => 0,
            else => return error.InvalidString,
        };
        try out.append(allocator, unescaped);
    }
    return out.toOwnedSlice(allocator);
}

fn parseBool(value: []const u8) Error!bool {
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return error.InvalidBool;
}

fn parsePositiveInt(value: []const u8) Error!u32 {    var buf: [16]u8 = undefined;
    if (value.len == 0 or value.len > buf.len) return error.InvalidInteger;
    var n: usize = 0;
    for (value) |c| {
        if (c == '_') continue;
        buf[n] = c;
        n += 1;
    }
    const parsed = std.fmt.parseInt(u32, buf[0..n], 10) catch return error.InvalidInteger;
    if (parsed == 0) return error.InvalidInteger;
    return parsed;
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

/// Splits `host:port` (v6 `[::1]:8080` ok) for `ServerConfig`'s split fields.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseToml full surface" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var config: Config = .{};
    try parseToml(allocator,
        \\# relay config
        \\bind_addr = "0.0.0.0:443"
        \\tls_cert_path = "/etc/relay/cert.pem" # trailing comment
        \\tls_key_path = '/etc/relay/key.pem'
        \\metrics_addr = "127.0.0.1:9090"
        \\access_tokens = ["alpha", "beta gamma"]
        \\
        \\[limits.client_rx]
        \\bytes_per_second = 1_048_576
        \\max_burst_bytes = 131072
        \\
        \\[qad]
        \\bind_addr = "[::]:7842"
        \\
    , &config);
    try std.testing.expectEqualStrings("0.0.0.0:443", config.bind_addr);
    try std.testing.expectEqualStrings("/etc/relay/cert.pem", config.tls_cert_path.?);
    try std.testing.expectEqualStrings("/etc/relay/key.pem", config.tls_key_path.?);
    try std.testing.expectEqualStrings("127.0.0.1:9090", config.metrics_addr.?);
    try std.testing.expectEqual(@as(usize, 2), config.access_tokens.len);
    try std.testing.expectEqualStrings("beta gamma", config.access_tokens[1]);
    try std.testing.expectEqual(@as(?u32, 1048576), config.limits.client_rx_bytes_per_second);
    try std.testing.expectEqual(@as(?u32, 131072), config.limits.client_rx_max_burst_bytes);
    try std.testing.expectEqualStrings("[::]:7842", config.qad_addr.?);
    try validate(&config);
}

test "parseToml rejects unknown keys, duplicates, and bad values" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var config: Config = .{};
    try std.testing.expectError(error.UnknownKey, parseToml(allocator, "bind_adr = \"x\"", &config));
    try std.testing.expectError(error.UnknownKey, parseToml(allocator, "[relay]\nbind_addr = \"x\"", &config));
    try std.testing.expectError(error.DuplicateKey, parseToml(allocator, "bind_addr = \"a\"\nbind_addr = \"b\"", &config));
    try std.testing.expectError(error.InvalidString, parseToml(allocator, "bind_addr = 8080", &config));
    try std.testing.expectError(error.InvalidInteger, parseToml(allocator, "[limits.client_rx]\nbytes_per_second = 0", &config));
    try std.testing.expectError(error.InvalidLine, parseToml(allocator, "bind_addr", &config));
}

test "validate enforces cross-field invariants" {
    var config: Config = .{ .tls_cert_path = "c" };
    try std.testing.expectError(error.TlsConfigIncomplete, validate(&config));
    config = .{ .limits = .{ .client_rx_max_burst_bytes = 10 } };
    try std.testing.expectError(error.BurstWithoutRate, validate(&config));
    config = .{ .qad_addr = "127.0.0.1:7842" };
    try std.testing.expectError(error.QadRequiresTls, validate(&config));
    config = .{ .enable_relay = false };
    try std.testing.expectError(error.NothingToServe, validate(&config));
    config = .{ .enable_relay = false, .qad_addr = "127.0.0.1:7842", .tls_cert_path = "c", .tls_key_path = "k" };
    try validate(&config);
}

test "parseToml parses enable_relay bool and rejects junk" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var config: Config = .{};
    try parseToml(allocator, "enable_relay = false", &config);
    try std.testing.expect(!config.enable_relay);
    try std.testing.expectError(error.InvalidBool, parseToml(allocator, "enable_relay = \"false\"", &config));
}

test "parseToml parses the acme section and validate enforces acme invariants" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var config: Config = .{};
    try parseToml(allocator,
        \\bind_addr = "0.0.0.0:443"
        \\
        \\[acme]
        \\directory_url = "https://localhost:14000/dir"
        \\ca_pem_path = "/run/pebble.minica.pem"
        \\account_key_path = "/run/certs/account.key.pem"
        \\cert_dir = "/run/certs"
        \\hostnames = ["relay-a.localhost", "relay-b.localhost"]
        \\contact = "test@iroh.test"
        \\
    , &config);
    const acme = config.acme.?;
    try std.testing.expectEqualStrings("https://localhost:14000/dir", acme.directory_url.?);
    try std.testing.expectEqualStrings("/run/pebble.minica.pem", acme.ca_pem_path.?);
    try std.testing.expectEqual(@as(usize, 2), acme.hostnames.len);
    try std.testing.expectEqualStrings("test@iroh.test", acme.contact.?);
    try validate(&config);
}

test "validate hard-errors invalid acme mixed modes" {
    const base: Acme = .{
        .directory_url = "https://localhost:14000/dir",
        .ca_pem_path = "ca.pem",
        .account_key_path = "account.pem",
        .cert_dir = "certs",
        .hostnames = &.{"a.localhost"},
    };
    // Static PEM + ACME is a hard error, not a precedence.
    var config: Config = .{ .tls_cert_path = "c", .tls_key_path = "k", .acme = base };
    try std.testing.expectError(error.MixedTlsModes, validate(&config));
    // Missing required ACME fields.
    config = .{ .acme = .{ .directory_url = "https://x/dir" } };
    try std.testing.expectError(error.AcmeConfigIncomplete, validate(&config));
    // Zero hostnames.
    config = .{ .acme = .{ .directory_url = "u", .ca_pem_path = "c", .account_key_path = "a", .cert_dir = "d" } };
    try std.testing.expectError(error.AcmeNoHostnames, validate(&config));
    // Duplicate hostnames.
    config = .{ .acme = .{ .directory_url = "u", .ca_pem_path = "c", .account_key_path = "a", .cert_dir = "d", .hostnames = &.{ "h", "h" } } };
    try std.testing.expectError(error.AcmeDuplicateHostname, validate(&config));
    // QAD borrows the static PEM identity; ACME mode has none.
    config = .{ .acme = base, .qad_addr = "127.0.0.1:7842" };
    try std.testing.expectError(error.QadRequiresTls, validate(&config));
    // QAD without any TLS material at all still errors as before.
    config = .{ .qad_addr = "127.0.0.1:7842" };
    try std.testing.expectError(error.QadRequiresTls, validate(&config));
}

test "parseToml rejects unknown acme keys" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var config: Config = .{};
    try std.testing.expectError(error.UnknownKey, parseToml(allocator, "[acme]\ndirectory = \"x\"", &config));
}

test "splitBindAddr v4, v6, hostname" {
    const v4 = try splitBindAddr("127.0.0.1:8080");
    try std.testing.expectEqualStrings("127.0.0.1", v4.host);
    try std.testing.expectEqual(@as(u16, 8080), v4.port);
    const v6 = try splitBindAddr("[::1]:443");
    try std.testing.expectEqualStrings("::1", v6.host);
    try std.testing.expectEqual(@as(u16, 443), v6.port);
    const dns = try splitBindAddr("relay.example.com:9090");
    try std.testing.expectEqualStrings("relay.example.com", dns.host);
    try std.testing.expectError(error.InvalidBindAddr, splitBindAddr("noport"));
    try std.testing.expectError(error.InvalidBindAddr, splitBindAddr("host:notaport"));
}
