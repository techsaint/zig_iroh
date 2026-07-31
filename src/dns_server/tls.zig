//! HTTPS / ACME certificate mode plumbing for iroh-dns-server.
//!
//! Builds a `TlsPlan` from config and activates self_signed / manual modes by
//! materializing PEM paths the HTTPS accept loop can hand to `TlsServer`.
//! Live Let's Encrypt / Pebble issuance stays a named environment blocker —
//! this module does NOT change TLS/ACME security policy or cert validation.

const std = @import("std");
const config_mod = @import("config.zig");

pub const TlsPlan = struct {
    mode: config_mod.CertMode,
    domains: []const []const u8,
    cert_cache: ?[]const u8,
    letsencrypt_contact: ?[]const u8,
    letsencrypt_prod: bool,
    https_addr: ?[]const u8,
};

/// PEM paths ready for `TlsServer.accept`. Borrowed from `cert_cache` or
/// allocator-owned strings returned alongside the activation.
pub const Activated = struct {
    cert_path: []const u8,
    key_path: []const u8,
    /// When true, `deinit` frees the path strings (self_signed generated names).
    owned_paths: bool = false,
    allocator: ?std.mem.Allocator = null,

    pub fn deinit(self: *Activated) void {
        if (self.owned_paths) {
            if (self.allocator) |a| {
                a.free(self.cert_path);
                a.free(self.key_path);
            }
        }
        self.* = undefined;
    }
};

pub const ActivateError = error{
    /// Mode plumbing is ready; live ACME/Pebble CA is not available in this environment.
    RealAcmeCaUnavailable,
    /// Manual mode needs PEM material under cert_cache — not present.
    ManualCertMaterialMissing,
    /// Self-signed generation failed (openssl missing / write failed).
    SelfSignedGenerationFailed,
    HttpsAddrRequired,
    CertCacheRequired,
    TlsDomainsRequired,
} || std.mem.Allocator.Error;

/// Resolve the operator-facing TLS plan (validates mode-specific fields).
pub fn planFromConfig(config: *const config_mod.Config) config_mod.Error!TlsPlan {
    try config_mod.validate(config);
    return .{
        .mode = config.cert_mode,
        .domains = config.tls_domains,
        .cert_cache = config.cert_cache,
        .letsencrypt_contact = config.letsencrypt_contact,
        .letsencrypt_prod = config.letsencrypt_prod,
        .https_addr = config.https_addr,
    };
}

/// Activate HTTPS for the plan. Self-signed/manual return PEM paths; ACME
/// remains a named blocker. Listener composition is the caller's job.
pub fn activate(
    allocator: std.mem.Allocator,
    io: std.Io,
    plan: TlsPlan,
) ActivateError!Activated {
    if (plan.mode == .none) return error.HttpsAddrRequired;
    if (plan.https_addr == null) return error.HttpsAddrRequired;
    if (plan.domains.len == 0) return error.TlsDomainsRequired;
    switch (plan.mode) {
        .none => return error.HttpsAddrRequired,
        .lets_encrypt => return error.RealAcmeCaUnavailable,
        .manual => {
            const cache = plan.cert_cache orelse return error.CertCacheRequired;
            const cert_path = try std.fmt.allocPrint(allocator, "{s}/cert.pem", .{cache});
            errdefer allocator.free(cert_path);
            const key_path = try std.fmt.allocPrint(allocator, "{s}/key.pem", .{cache});
            errdefer allocator.free(key_path);
            if (!fileExists(io, cert_path) or !fileExists(io, key_path)) {
                allocator.free(cert_path);
                allocator.free(key_path);
                return error.ManualCertMaterialMissing;
            }
            return .{
                .cert_path = cert_path,
                .key_path = key_path,
                .owned_paths = true,
                .allocator = allocator,
            };
        },
        .self_signed => {
            const cache = plan.cert_cache orelse return error.CertCacheRequired;
            std.Io.Dir.cwd().createDirPath(io, cache) catch return error.SelfSignedGenerationFailed;
            const cert_path = try std.fmt.allocPrint(allocator, "{s}/cert.pem", .{cache});
            errdefer allocator.free(cert_path);
            const key_path = try std.fmt.allocPrint(allocator, "{s}/key.pem", .{cache});
            errdefer allocator.free(key_path);
            if (!fileExists(io, cert_path) or !fileExists(io, key_path)) {
                try generateSelfSignedPem(io, cert_path, key_path, plan.domains[0]);
            }
            return .{
                .cert_path = cert_path,
                .key_path = key_path,
                .owned_paths = true,
                .allocator = allocator,
            };
        },
    }
}

fn fileExists(io: std.Io, path: []const u8) bool {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    file.close(io);
    return true;
}

fn generateSelfSignedPem(
    io: std.Io,
    cert_path: []const u8,
    key_path: []const u8,
    cn: []const u8,
) ActivateError!void {
    // Compose around openssl for PEM material only — no TLS policy change.
    // The HTTPS listener still validates via ianic/tls CertKeyPair.fromFilePath.
    var subj_buf: [256]u8 = undefined;
    const subj = std.fmt.bufPrint(&subj_buf, "/CN={s}", .{cn}) catch return error.SelfSignedGenerationFailed;

    var child = std.process.spawn(io, .{
        .argv = &.{
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "365",
            "-nodes",
            "-subj",
            subj,
        },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return error.SelfSignedGenerationFailed;
    const term = child.wait(io) catch return error.SelfSignedGenerationFailed;
    switch (term) {
        .exited => |code| if (code != 0) return error.SelfSignedGenerationFailed,
        else => return error.SelfSignedGenerationFailed,
    }
}

test "tls plan accepts lets_encrypt config shape and names ACME blocker" {
    const cfg: config_mod.Config = .{
        .http_addr = "127.0.0.1:8080",
        .https_addr = "127.0.0.1:8443",
        .cert_mode = .lets_encrypt,
        .cert_cache = "/var/lib/iroh-dns/certs",
        .letsencrypt_contact = "ops@example.com",
        .tls_domains = &.{"dns.example.com"},
        .origins = &.{"irohdns.example."},
    };
    const plan = try planFromConfig(&cfg);
    try std.testing.expectEqual(config_mod.CertMode.lets_encrypt, plan.mode);
    const act = activate(std.testing.allocator, std.testing.io, plan);
    try std.testing.expectError(error.RealAcmeCaUnavailable, act);
}

test "tls plan rejects lets_encrypt without contact" {
    const cfg: config_mod.Config = .{
        .cert_mode = .lets_encrypt,
        .cert_cache = "/tmp/certs",
        .tls_domains = &.{"dns.example.com"},
        .origins = &.{"irohdns.example."},
    };
    try std.testing.expectError(error.LetsEncryptContactRequired, planFromConfig(&cfg));
}

test "tls activate self_signed materializes PEM under cert_cache" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const cache = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-tls-{d}", .{nonce});
    defer allocator.free(cache);
    defer std.Io.Dir.cwd().deleteTree(io, cache) catch {};

    const cfg: config_mod.Config = .{
        .http_addr = "127.0.0.1:8080",
        .https_addr = "127.0.0.1:0",
        .cert_mode = .self_signed,
        .cert_cache = cache,
        .tls_domains = &.{"localhost"},
        .origins = &.{"irohdns.example."},
    };
    const plan = try planFromConfig(&cfg);
    var activated = try activate(allocator, io, plan);
    defer activated.deinit();
    try std.testing.expect(fileExists(io, activated.cert_path));
    try std.testing.expect(fileExists(io, activated.key_path));
}
