//! ACME certificate manager for the relay: owns the per-hostname issued-cert
//! table and the live TLS-ALPN-01 challenge table, and answers the TLS
//! layer's `CertSelector` queries from them. This is the SNI-driven
//! certificate-selection policy:
//!
//!   - client offered `acme-tls/1`  → serve the ACTIVE challenge cert for the
//!     SNI hostname; no active challenge → refuse (fail closed);
//!   - otherwise                    → serve the issued cert for the SNI
//!     hostname; unknown/missing SNI → refuse (fail closed).
//!
//! Storage layout under `cert_dir`: `<hostname>.crt.pem` (issued chain as the
//! CA returned it) and `<hostname>.key.pem` (SEC1 P-256, 0600). The account
//! key lives at `account_key_path` in the same format. Cert pairs are
//! arena-allocated and never individually freed — renewal swaps the map
//! entry, in-flight handshakes keep their borrowed pair valid, and the whole
//! table dies with the manager (the leak is bounded: one pair per renewal).
//!
//! Renewal policy (explicit): a background thread re-runs
//! acquisition for any cert inside `renew_margin_secs` of expiry, every
//! `check_interval_ns`. On failure the LAST issued cert keeps serving and the
//! next cycle retries — never a wrong-hostname cert, never a fallback to a
//! synthesized one.

const std = @import("std");
const tls_wrapper = @import("../tls_wrapper.zig");
const acme_client = @import("client.zig");
const x509 = @import("x509.zig");

const tls = tls_wrapper.tls;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Error = error{
    CaLoadFailed,
    AccountKeyFailed,
    CertStorageFailed,
    AcquisitionFailed,
    OutOfMemory,
} || acme_client.Error;

pub const Config = struct {
    /// ACME directory URL (RFC 8555 §7.1.1).
    directory_url: []const u8,
    /// PEM file with the CA that signs the ACME DIRECTORY's TLS cert. This is
    /// the explicit trust anchor — the directory client never uses the system
    /// store and never skips verification.
    ca_pem_path: []const u8,
    /// Where the ES256 account key persists (created 0600 on first run).
    account_key_path: []const u8,
    /// Directory holding per-hostname issued certs + keys.
    cert_dir: []const u8,
    /// Hostnames to provision and serve; at least one (config validation).
    hostnames: []const []const u8,
    /// Optional ACME contact (a bare address; "mailto:" is added).
    contact: ?[]const u8 = null,
    /// Re-acquire when fewer than this many seconds remain. Default 30 days
    /// (Let's Encrypt 90-day certs → renewal at day 60).
    renew_margin_secs: i64 = 30 * 86400,
    /// Renewal-check cadence. Default 12h.
    check_interval_ns: u64 = 12 * 3600 * std.time.ns_per_s,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    root_ca: std.crypto.Certificate.Bundle,
    account_key: Ecdsa.KeyPair,
    /// Ephemeral key shared by all challenge certs (they are seconds-lived;
    /// per-challenge keys would buy nothing).
    challenge_key: Ecdsa.KeyPair,

    mu: std.Io.Mutex = .init,
    issued: std.StringHashMap(*tls.config.CertKeyPair),
    challenges: std.StringHashMap(*tls.config.CertKeyPair),

    running: std.atomic.Value(bool) = .init(true),
    renewal_thread: ?std.Thread = null,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, config: Config) Error!*Manager {
        const self = try allocator.create(Manager);
        errdefer allocator.destroy(self);

        var root_ca = std.crypto.Certificate.Bundle.empty;
        errdefer root_ca.deinit(allocator);
        root_ca.addCertsFromFilePathAbsolute(allocator, io, std.Io.Clock.real.now(io), config.ca_pem_path) catch
            return error.CaLoadFailed;
        if (root_ca.bytes.items.len == 0) return error.CaLoadFailed;

        self.* = .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .root_ca = root_ca,
            .account_key = try loadOrCreateAccountKey(allocator, io, config.account_key_path),
            .challenge_key = Ecdsa.KeyPair.generate(io),
            .issued = .init(allocator),
            .challenges = .init(allocator),
        };
        return self;
    }

    pub fn deinit(self: *Manager) void {
        self.running.store(false, .release);
        if (self.renewal_thread) |t| {
            t.join();
            self.renewal_thread = null;
        }
        self.root_ca.deinit(self.allocator);
        self.issued.deinit();
        self.challenges.deinit();
        self.allocator.destroy(self);
    }

    /// The TLS-layer entry point: hands the relay
    /// server a selector that resolves SNI+ALPN to the right cert per
    /// connection.
    pub fn certSelector(self: *Manager) tls_wrapper.CertSelector {
        return .{ .context = self, .select_fn = selectCert };
    }

    fn selectCert(context: *anyopaque, sni: ?[]const u8, client_alpns: []const []const u8) ?tls_wrapper.ServerHelloSelect {
        const self: *Manager = @ptrCast(@alignCast(context));
        const wants_acme = for (client_alpns) |p| {
            if (std.mem.eql(u8, p, tls_wrapper.acme_tls_alpn)) break true;
        } else false;

        const hostname = sni orelse return null; // fail closed: no SNI
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (wants_acme) {
            // Only an ACTIVE challenge for exactly this hostname is served.
            const pair = self.challenges.get(hostname) orelse return null;
            return .{ .pair = pair, .alpn_protocols = &.{tls_wrapper.acme_tls_alpn} };
        }
        const pair = self.issued.get(hostname) orelse return null; // fail closed: unknown SNI
        return .{ .pair = pair };
    }

    /// Startup provisioning: load any still-valid certs from `cert_dir`, then
    /// run a real ACME order for everything missing or inside the renewal
    /// margin. Fails the relay startup when a needed cert cannot be obtained.
    pub fn ensureCertificates(self: *Manager) Error!void {
        const now = std.Io.Clock.real.now(self.io).toSeconds();
        var missing: std.ArrayList([]const u8) = .empty;
        defer missing.deinit(self.allocator);

        for (self.config.hostnames) |hostname| {
            if (try self.loadStoredCert(hostname, now)) continue;
            try missing.append(self.allocator, hostname);
        }
        if (missing.items.len == 0) return;
        try self.acquire(missing.items);
    }

    /// Loads `<hostname>.crt.pem` + `.key.pem` when both exist, the leaf
    /// parses, and notAfter is beyond the renewal margin. Installs the pair
    /// into the issued table and returns true; any problem → false (caller
    /// re-acquires).
    fn loadStoredCert(self: *Manager, hostname: []const u8, now: i64) Error!bool {
        const cert_path = try self.certPath(hostname, ".crt.pem");
        defer self.allocator.free(cert_path);
        const key_path = try self.certPath(hostname, ".key.pem");
        defer self.allocator.free(key_path);

        const cert_pem = readFileAllocOpt(self.allocator, self.io, cert_path) orelse return false;
        const key_pem = readFileAllocOpt(self.allocator, self.io, key_path) orelse return false;

        const leaf_der = x509.firstCertDerFromPem(self.allocator, cert_pem) catch return false;
        const not_after = x509.notAfterFromCertDer(leaf_der) catch return false;
        if (not_after - now < self.config.renew_margin_secs) return false;

        const pair = self.allocator.create(tls.config.CertKeyPair) catch return error.OutOfMemory;
        pair.* = tls.config.CertKeyPair.fromSlice(self.allocator, self.io, cert_pem, key_pem) catch return false;
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        try self.issued.put(hostname, pair);
        return true;
    }

    /// One full ACME order for `hostnames`: account → order → per-authz
    /// TLS-ALPN-01 → finalize → download → persist + install. One retry with
    /// a backoff guards against transient order/nonce trouble.
    fn acquire(self: *Manager, hostnames: []const []const u8) Error!void {
        var attempt: usize = 0;
        while (true) {
            self.acquireOnce(hostnames) catch |err| {
                attempt += 1;
                if (attempt >= 3) {
                    std.debug.print("[acme] acquisition failed after {d} attempts: {}\n", .{ attempt, err });
                    return error.AcquisitionFailed;
                }
                std.debug.print("[acme] acquisition attempt {d} failed ({}), retrying\n", .{ attempt, err });
                self.io.sleep(std.Io.Duration.fromSeconds(@intCast(attempt)), .awake) catch {};
                continue;
            };
            return;
        }
    }

    fn acquireOnce(self: *Manager, hostnames: []const []const u8) Error!void {
        var client = acme_client.Client.init(self.allocator, self.io, &self.root_ca, self.config.directory_url, self.account_key);
        try client.discover();
        try client.ensureAccount(self.config.contact);

        var order = try client.newOrder(hostnames);
        defer client.freeOrder(&order);
        std.debug.print("[acme] order created for {d} hostname(s), {d} authorization(s)\n", .{ hostnames.len, order.authorizations.len });

        const sink = acme_client.ChallengeSink{
            .context = self,
            .install_fn = installChallenge,
            .remove_fn = removeChallenge,
        };
        for (order.authorizations) |authz_url| {
            try client.completeAuthorization(authz_url, sink, 500 * std.time.ns_per_ms, 30 * std.time.ns_per_s);
        }

        // One cert key covers the whole order (SAN cert).
        const cert_key = Ecdsa.KeyPair.generate(self.io);
        const csr = try x509.buildCsr(self.allocator, hostnames, cert_key);
        const cert_url = try client.finalizeOrder(&order, csr, 500 * std.time.ns_per_ms, 30 * std.time.ns_per_s);
        defer self.allocator.free(cert_url);
        const chain_pem = try client.downloadCertificate(cert_url);

        try self.persistAndInstall(hostnames, chain_pem, cert_key);
    }

    /// ChallengeSink callbacks — the live responder table.
    fn installChallenge(context: *anyopaque, hostname: []const u8, key_authorization: []const u8) anyerror!void {
        const self: *Manager = @ptrCast(@alignCast(context));
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(key_authorization, &digest, .{});

        const now = std.Io.Clock.real.now(self.io).toSeconds();
        const cert_der = try x509.buildChallengeCert(self.allocator, hostname, &digest, self.challenge_key, now);
        const cert_pem = try x509.pemEncode(self.allocator, "CERTIFICATE", cert_der);
        const key_pem = try x509.ecPrivateKeyPem(self.allocator, self.challenge_key);

        const pair = try self.allocator.create(tls.config.CertKeyPair);
        pair.* = try tls.config.CertKeyPair.fromSlice(self.allocator, self.io, cert_pem, key_pem);

        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        try self.challenges.put(try self.allocator.dupe(u8, hostname), pair);
    }

    fn removeChallenge(context: *anyopaque, hostname: []const u8) void {
        const self: *Manager = @ptrCast(@alignCast(context));
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        // The pair stays arena-alive: an in-flight VA handshake may still
        // hold it. Only the map entry goes away.
        _ = self.challenges.remove(hostname);
    }

    /// Writes `<hostname>.{crt,key}.pem` for every ordered hostname (the SAN
    /// cert covers all of them) and installs the pairs.
    fn persistAndInstall(self: *Manager, hostnames: []const []const u8, chain_pem: []const u8, cert_key: Ecdsa.KeyPair) Error!void {
        const cwd = std.Io.Dir.cwd();
        cwd.createDirPath(self.io, self.config.cert_dir) catch return error.CertStorageFailed;

        const key_pem = try x509.ecPrivateKeyPem(self.allocator, cert_key);
        for (hostnames) |hostname| {
            const cert_path = try self.certPath(hostname, ".crt.pem");
            defer self.allocator.free(cert_path);
            const key_path = try self.certPath(hostname, ".key.pem");
            defer self.allocator.free(key_path);
            cwd.writeFile(self.io, .{ .sub_path = cert_path, .data = chain_pem }) catch
                return error.CertStorageFailed;
            cwd.writeFile(self.io, .{
                .sub_path = key_path,
                .data = key_pem,
                .flags = .{ .permissions = std.Io.File.Permissions.fromMode(0o600) },
            }) catch return error.CertStorageFailed;

            const pair = self.allocator.create(tls.config.CertKeyPair) catch return error.OutOfMemory;
            pair.* = tls.config.CertKeyPair.fromSlice(self.allocator, self.io, chain_pem, key_pem) catch
                return error.CertStorageFailed;
            self.mu.lockUncancelable(self.io);
            try self.issued.put(hostname, pair);
            self.mu.unlock(self.io);
        }
    }

    /// Starts the background renewal thread (see the module doc for the
    /// policy). One thread per manager; call after `ensureCertificates`.
    pub fn startRenewal(self: *Manager) Error!void {
        if (self.renewal_thread != null) return;
        self.renewal_thread = std.Thread.spawn(.{}, renewalLoop, .{self}) catch return error.AcquisitionFailed;
    }

    fn renewalLoop(self: *Manager) void {
        while (self.running.load(.acquire)) {
            // Sleep in chunks so shutdown is noticed within ~100 ms.
            var slept: u64 = 0;
            while (slept < self.config.check_interval_ns and self.running.load(.acquire)) {
                const chunk = @min(100 * std.time.ns_per_ms, self.config.check_interval_ns - slept);
                self.io.sleep(std.Io.Duration.fromNanoseconds(@intCast(chunk)), .awake) catch {};
                slept += chunk;
            }
            if (!self.running.load(.acquire)) break;
            self.ensureCertificates() catch |err| {
                // Explicit policy: keep serving the last issued cert, log, and
                // retry at the next cycle. Never fall back to another
                // hostname's cert.
                std.debug.print("[acme] renewal cycle failed ({}), retrying next cycle\n", .{err});
            };
        }
    }

    fn certPath(self: *Manager, hostname: []const u8, suffix: []const u8) Error![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}{s}", .{ self.config.cert_dir, hostname, suffix });
    }
};

fn readFileAllocOpt(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ?[]u8 {
    const text = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 20)) catch return null;
    if (text.len == 0) return null;
    return text;
}

fn loadOrCreateAccountKey(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error!Ecdsa.KeyPair {
    if (readFileAllocOpt(allocator, io, path)) |pem| {
        const parsed = tls.config.PrivateKey.parsePem(pem) catch return error.AccountKeyFailed;
        if (parsed.signature_scheme != .ecdsa_secp256r1_sha256) return error.AccountKeyFailed;
        const raw = parsed.key.ecdsa;
        const secret_key = Ecdsa.SecretKey.fromBytes(raw[0..32].*) catch return error.AccountKeyFailed;
        return Ecdsa.KeyPair.fromSecretKey(secret_key) catch return error.AccountKeyFailed;
    }
    const key_pair = Ecdsa.KeyPair.generate(io);
    const pem = try x509.ecPrivateKeyPem(allocator, key_pair);
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir|
        cwd.createDirPath(io, dir) catch return error.AccountKeyFailed;
    cwd.writeFile(io, .{
        .sub_path = path,
        .data = pem,
        .flags = .{ .permissions = std.Io.File.Permissions.fromMode(0o600) },
    }) catch return error.AccountKeyFailed;
    return key_pair;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "selector fails closed without sni, serves issued and challenge certs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var manager: Manager = .{
        .allocator = a,
        .io = std.testing.io,
        .config = .{
            .directory_url = "https://localhost:14000/dir",
            .ca_pem_path = "unused",
            .account_key_path = "unused",
            .cert_dir = "unused",
            .hostnames = &.{},
        },
        .root_ca = .empty,
        .account_key = try Ecdsa.KeyPair.generateDeterministic(@splat(31)),
        .challenge_key = try Ecdsa.KeyPair.generateDeterministic(@splat(32)),
        .issued = .init(a),
        .challenges = .init(a),
    };

    // A pair whose contents we can distinguish by pointer identity; the
    // selector never dereferences it.
    var pair_a: tls.config.CertKeyPair = undefined;
    var pair_b: tls.config.CertKeyPair = undefined;
    try manager.issued.put("relay-a.localhost", &pair_a);
    try manager.challenges.put("relay-a.localhost", &pair_b);

    const selector = manager.certSelector();
    // No SNI → refuse.
    try std.testing.expect(selector.select(null, &.{}) == null);
    // Unknown hostname → refuse.
    try std.testing.expect(selector.select("relay-evil.localhost", &.{}) == null);
    // Plain relay client → issued cert, no ALPN.
    const prod = selector.select("relay-a.localhost", &.{}).?;
    try std.testing.expect(prod.pair == &pair_a);
    try std.testing.expectEqual(@as(usize, 0), prod.alpn_protocols.len);
    // ACME validation probe → challenge cert with acme-tls/1 offered.
    const probe = selector.select("relay-a.localhost", &.{"acme-tls/1"}).?;
    try std.testing.expect(probe.pair == &pair_b);
    try std.testing.expectEqualStrings("acme-tls/1", probe.alpn_protocols[0]);
    // acme-tls/1 requested for a hostname with no active challenge → refuse.
    try std.testing.expect(selector.select("relay-b.localhost", &.{"acme-tls/1"}) == null);

    // After the challenge is removed the probe is refused again.
    Manager.removeChallenge(&manager, "relay-a.localhost");
    try std.testing.expect(selector.select("relay-a.localhost", &.{"acme-tls/1"}) == null);
    // …and the production cert is unaffected.
    try std.testing.expect(selector.select("relay-a.localhost", &.{}).?.pair == &pair_a);
}

test "challenge install builds a servable pair keyed by hostname" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var manager: Manager = .{
        .allocator = a,
        .io = std.testing.io,
        .config = .{
            .directory_url = "https://localhost:14000/dir",
            .ca_pem_path = "unused",
            .account_key_path = "unused",
            .cert_dir = "unused",
            .hostnames = &.{},
        },
        .root_ca = .empty,
        .account_key = try Ecdsa.KeyPair.generateDeterministic(@splat(33)),
        .challenge_key = try Ecdsa.KeyPair.generateDeterministic(@splat(34)),
        .issued = .init(a),
        .challenges = .init(a),
    };

    try Manager.installChallenge(&manager, "relay-a.localhost", "token.thumbprint");
    const selector = manager.certSelector();
    const probe = selector.select("relay-a.localhost", &.{"acme-tls/1"}).?;
    // The pair was built from real PEM: the leaf DER is present in the bundle.
    try std.testing.expect(probe.pair.bundle.bytes.items.len > 100);
    try std.testing.expect(probe.pair.ecdsa_key_pair != null);
    // SNI is case-sensitive per RFC 6066; the unknown one is refused.
    try std.testing.expect(selector.select("Relay-A.localhost", &.{"acme-tls/1"}) == null);
}
