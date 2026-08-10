//! QAD — QUIC Address Discovery server (draft-seemann-quic-address-discovery,
//! ALPN `/iroh-qad/0`). Port of upstream `iroh/iroh-relay/src/quic.rs`.
//!
//! The whole protocol is: handshake (TLS 1.3 over QUIC, X.509 server cert —
//! stock rustls/webpki clients cannot negotiate RPK), the server advertises
//! the observed-address transport-parameter role `send_only` with zero
//! streams, then emits the peer's OBSERVED_ADDRESS report and waits for the
//! client to close (app code 1 "finished" upstream). No streams are used.
//!
//! This module owns the operator-facing pieces: PEM cert-chain / private-key
//! loading into a `crypto.X509ServerIdentity` (Ed25519 and ECDSA P-256 keys;
//! RSA is an honest startup error, never a silent fallback), and the service
//! wrapper around the noq endpoint. The engine work (TP codec, X.509 creds,
//! observed-address emission) lives in `src/quic/*` + `src/transport/
//! transport_noq.zig` — see those files' comments for the split.
//!
//! Recorded limitations:
//! - IPv6 paths get no report yet (the NAT-address queue is v4-only).
//! - The report is queued once per connection; upstream also re-emits on
//!   path migration/rebinding and retransmits on loss.

const std = @import("std");
const key = @import("shared").key;
const crypto = @import("crypto.zig");
const noq = @import("transport_noq.zig");

pub const alpn: [:0]const u8 = "/iroh-qad/0";

pub const Error = error{
    PemBlockMissing,
    DerMalformed,
    UnsupportedKeyType,
    KeyLengthMismatch,
} || std.mem.Allocator.Error;

/// Owned QAD TLS identity: DER cert chain + signing key extracted from PEM.
pub const Identity = struct {
    allocator: std.mem.Allocator,
    chain_der: []const []const u8,
    scheme: crypto.SignatureScheme,
    signing_key: crypto.SigningKey,

    pub fn asCrypto(self: *const Identity) crypto.X509ServerIdentity {
        return .{
            .chain_der = self.chain_der,
            .scheme = self.scheme,
            .key = self.signing_key,
        };
    }

    pub fn deinit(self: *Identity) void {
        switch (self.signing_key) {
            .ed25519 => |*sk| sk.zeroize(),
            .ecdsa_p256 => |*scalar| std.crypto.secureZero(u8, scalar),
        }
        for (self.chain_der) |der| self.allocator.free(der);
        self.allocator.free(self.chain_der);
        self.* = undefined;
    }
};

/// Loads the operator's PEM cert chain + private key (the same files the wss
/// listener uses — upstream shares one TLS config between HTTPS and QAD).
pub fn loadIdentityFromPem(
    allocator: std.mem.Allocator,
    io: std.Io,
    cert_path: []const u8,
    key_path: []const u8,
) !Identity {
    const cert_text = try readFileAlloc(allocator, io, cert_path);
    defer allocator.free(cert_text);
    const key_text = try readFileAlloc(allocator, io, key_path);
    defer {
        std.crypto.secureZero(u8, key_text);
        allocator.free(key_text);
    }

    var chain: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (chain.items) |der| allocator.free(der);
        chain.deinit(allocator);
    }
    var pem_rest: []const u8 = cert_text;
    while (pemBlock(&pem_rest, "CERTIFICATE") catch null) |der| {
        // `pemBlock` always allocates on `page_allocator` (every other call
        // site frees it right back there) — this is the one call site that
        // stores the DER past this function's return, in `Identity`, which
        // frees with the CALLER's `allocator` on `deinit`. Re-home it now so
        // that free matches its allocator (an arena's mismatched free is a
        // silent no-op — this only surfaced under `std.testing.allocator`'s
        // canary check).
        defer std.heap.page_allocator.free(der);
        const owned = try allocator.dupe(u8, der);
        errdefer allocator.free(owned);
        try chain.append(allocator, owned);
    }
    if (chain.items.len == 0) return error.PemBlockMissing;

    const signing = try parsePrivateKeyPem(key_text);
    return .{
        .allocator = allocator,
        .chain_der = try chain.toOwnedSlice(allocator),
        .scheme = signing.scheme,
        .signing_key = signing.key,
    };
}

/// The QAD service: one noq endpoint in QAD server mode plus a pump loop
/// meant to run on its own thread (the relay binary's thread model).
pub const Server = struct {
    endpoint: *noq.Endpoint,
    running: std.atomic.Value(bool) = .init(true),

    /// `bind` is the UDP address to listen on. The endpoint still carries an
    /// ephemeral RPK secret (the transport requires one); it never reaches
    /// the wire in QAD mode — the X.509 identity replaces it.
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind: std.Io.net.IpAddress,
        identity: *const Identity,
    ) !*Server {
        var secret_seed: [32]u8 = undefined;
        io.random(&secret_seed);
        const endpoint = try noq.Endpoint.initOptions(allocator, io, key.SecretKey.fromBytes(secret_seed), alpn, .{
            .bind_address = bind,
            .tls_backend = .zigtls,
            .qad_identity = identity.asCrypto(),
            // QAD has no peer identity to pin: any client may probe (the
            // protocol is unauthenticated by design — upstream iroh-relay
            // quic.rs). Client auth stays off (mintServerConn, QAD branch).
            .accept_unknown_peer = true,
        });
        const self = try allocator.create(Server);
        self.* = .{ .endpoint = endpoint };
        return self;
    }

    pub fn localAddress(self: *const Server) std.Io.net.IpAddress {
        return self.endpoint.localAddress();
    }

    pub fn initiateShutdown(self: *Server) void {
        self.running.store(false, .release);
    }

    /// Pump loop for the dedicated QAD thread: bounded I/O rounds with a
    /// short sleep, until initiateShutdown (then a final round flushes).
    /// Pump errors are operator-visible (upstream counts qad_incoming_error);
    /// a silently swallowed accept failure is undebuggable.
    pub fn serviceLoop(self: *Server, io: std.Io) void {
        while (self.running.load(.acquire)) {
            _ = self.endpoint.qadServiceStep() catch |err| {
                std.debug.print("relay: qad pump error: {s}\n", .{@errorName(err)});
            };
            io.sleep(std.Io.Duration.fromMilliseconds(5), .awake) catch {};
        }
        _ = self.endpoint.qadServiceStep() catch {};
    }

    pub fn deinit(self: *Server, allocator: std.mem.Allocator) void {
        self.endpoint.deinit();
        allocator.destroy(self);
    }
};

/// QAD probe client: dials a QAD server, negotiates address-discovery role
/// `receive_only`, and reports the OBSERVED_ADDRESS the server sends back.
///
/// QAD has no peer node id to pin (draft-seemann address discovery is
/// anonymous by design — see the real `iroh-relay` `qad_client.rs` example,
/// which dials with a "dangerous" skip-verify rustls config for exactly this
/// reason). This client does not take that shortcut: it validates the
/// server's X.509 identity against an explicit trust anchor (typically the
/// server's own self-signed cert, pinned out-of-band — the same trust model
/// as a first-use TOFU pin) plus a hostname check. The mandatory TLS 1.3
/// CertificateVerify signature check is never skippable either way.
pub const Client = struct {
    allocator: std.mem.Allocator,
    endpoint: *noq.Endpoint,
    trust_store: crypto.ZigtlsTrustStore,

    /// A decoded OBSERVED_ADDRESS report. Exactly one of `ip`/`ip6` is set
    /// (IPv6 QAD reports are a recorded limitation server-side — see
    /// `Server`'s doc comment — but the client-side decode stays general).
    pub const Observed = struct {
        ip: ?[4]u8 = null,
        ip6: ?[16]u8 = null,
        port: u16,
    };

    /// `trust_pem_path` is an absolute path to a PEM file whose certificate(s)
    /// are trusted as anchors for the QAD server's X.509 chain (pass the
    /// server's own cert file for a self-signed test/pinned deployment).
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind: std.Io.net.IpAddress,
        trust_pem_path: []const u8,
    ) !*Client {
        if (!crypto.zigtls_enabled) return error.ZigtlsDisabled;
        const self = try allocator.create(Client);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.trust_store = .initEmpty();
        errdefer self.trust_store.deinit(allocator);
        try self.trust_store.loadPemFileAbsolute(allocator, trust_pem_path);

        var secret_seed: [32]u8 = undefined;
        io.random(&secret_seed);
        self.endpoint = try noq.Endpoint.initOptions(allocator, io, key.SecretKey.fromBytes(secret_seed), alpn, .{
            .bind_address = bind,
            .tls_backend = .zigtls,
        });
        return self;
    }

    pub fn localAddress(self: *const Client) std.Io.net.IpAddress {
        return self.endpoint.localAddress();
    }

    pub fn deinit(self: *Client) void {
        self.endpoint.deinit();
        self.trust_store.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// Dials `server_addr` presenting `server_name` (SNI + the expected
    /// X.509 hostname), waits up to `timeout_ns` for the server's
    /// OBSERVED_ADDRESS report, and closes with the upstream QAD contract
    /// (app code 1, reason "finished") before returning — callers never
    /// need a separate close call, success or failure.
    pub fn probe(
        self: *Client,
        io: std.Io,
        server_addr: std.Io.net.IpAddress,
        server_name: []const u8,
        timeout_ns: i64,
    ) !Observed {
        return self.probeOpts(io, server_addr, server_name, timeout_ns, .{});
    }

    /// Like `probe`, with optional X.509 validation overrides (cert-validation
    /// matrix: OCSP policy + per-defense mutation bypasses).
    pub fn probeOpts(
        self: *Client,
        io: std.Io,
        server_addr: std.Io.net.IpAddress,
        server_name: []const u8,
        timeout_ns: i64,
        opts: noq.Endpoint.QadConnectOpts,
    ) !Observed {
        try self.endpoint.qadConnectOpts(server_addr, server_name, &self.trust_store, opts);
        errdefer self.endpoint.qadClientClose();

        const started_ns: i64 = @intCast(std.Io.Clock.now(.awake, io).nanoseconds);
        while (true) {
            if (try self.endpoint.qadClientTakeObserved()) |a| {
                self.endpoint.qadClientClose();
                return .{
                    .ip = if (a.ip6 == null) a.ip else null,
                    .ip6 = a.ip6,
                    .port = a.port,
                };
            }
            const now_ns: i64 = @intCast(std.Io.Clock.now(.awake, io).nanoseconds);
            if (now_ns - started_ns >= timeout_ns) return error.ObservedTimeout;
            io.sleep(std.Io.Duration.fromMilliseconds(5), .awake) catch {};
        }
    }
};

fn readFileAlloc(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.size > 1 << 20) return error.Unexpected;
    const text = try allocator.alloc(u8, @intCast(stat.size));
    errdefer allocator.free(text);
    var buf: [4096]u8 = undefined;
    var reader = file.reader(io, &buf);
    try reader.interface.readSliceAll(text);
    return text;
}

/// Extracts the next `-----BEGIN <label>-----` block from `*rest` (advanced
/// past it) and returns its base64-decoded DER (owned by the caller).
fn pemBlock(rest: *[]const u8, label: []const u8) Error!?[]u8 {
    var begin_buf: [64]u8 = undefined;
    const begin = std.fmt.bufPrint(&begin_buf, "-----BEGIN {s}-----", .{label}) catch unreachable;
    var end_buf: [64]u8 = undefined;
    const end = std.fmt.bufPrint(&end_buf, "-----END {s}-----", .{label}) catch unreachable;

    const text = rest.*;
    const start = std.mem.indexOf(u8, text, begin) orelse {
        rest.* = text[text.len..];
        return null;
    };
    const body_start = start + begin.len;
    const stop = std.mem.indexOfPos(u8, text, body_start, end) orelse return error.DerMalformed;
    rest.* = text[stop + end.len ..];

    var b64: std.ArrayList(u8) = .empty;
    defer b64.deinit(std.heap.page_allocator);
    for (text[body_start..stop]) |c| {
        if (!std.ascii.isWhitespace(c)) try b64.append(std.heap.page_allocator, c);
    }
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64.items) catch return error.DerMalformed;
    const der = try std.heap.page_allocator.alloc(u8, decoded_len);
    std.base64.standard.Decoder.decode(der, b64.items) catch {
        std.heap.page_allocator.free(der);
        return error.DerMalformed;
    };
    return der;
}

const ParsedKey = struct {
    scheme: crypto.SignatureScheme,
    key: crypto.SigningKey,
};

/// Parses a PEM private key: PKCS#8 ("PRIVATE KEY") or SEC1 ("EC PRIVATE
/// KEY"). Ed25519 and ECDSA P-256 only — RSA is an explicit error (QAD's
/// pure-Zig TLS signs with neither RSA-PSS nor RSA-PKCS1).
fn parsePrivateKeyPem(text: []const u8) Error!ParsedKey {
    var rest = text;
    if (try pemBlock(&rest, "PRIVATE KEY")) |der| {
        defer std.heap.page_allocator.free(der);
        return parsePkcs8(der);
    }
    rest = text;
    if (try pemBlock(&rest, "EC PRIVATE KEY")) |der| {
        defer std.heap.page_allocator.free(der);
        const scalar = try parseSec1EcPrivateKey(der);
        return .{ .scheme = .ecdsa_secp256r1_sha256, .key = .{ .ecdsa_p256 = scalar } };
    }
    rest = text;
    if (try pemBlock(&rest, "RSA PRIVATE KEY")) |_| return error.UnsupportedKeyType;
    return error.PemBlockMissing;
}

// --- minimal DER walking (fixed ASN.1 shapes only) -------------------------

const Tlv = struct {
    tag: u8,
    value: []const u8,
    rest: []const u8,
};

fn readTlv(bytes: []const u8) Error!Tlv {
    if (bytes.len < 2) return error.DerMalformed;
    const tag = bytes[0];
    var len: usize = bytes[1];
    var off: usize = 2;
    if (len & 0x80 != 0) {
        const n = len & 0x7f;
        if (n == 0 or n > @sizeOf(usize) or bytes.len < 2 + n) return error.DerMalformed;
        len = 0;
        for (bytes[2 .. 2 + n]) |b| len = (len << 8) | b;
        off += n;
    }
    if (bytes.len < off + len) return error.DerMalformed;
    return .{ .tag = tag, .value = bytes[off .. off + len], .rest = bytes[off + len ..] };
}

fn expectTlv(bytes: []const u8, tag: u8) Error!Tlv {
    const tlv = try readTlv(bytes);
    if (tlv.tag != tag) return error.DerMalformed;
    return tlv;
}

const oid_ed25519 = [_]u8{ 0x06, 0x03, 0x2B, 0x65, 0x70 };
const oid_ec_public_key = [_]u8{ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_p256 = [_]u8{ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const oid_rsa_encryption = [_]u8{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

fn parsePkcs8(der: []const u8) Error!ParsedKey {
    // PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey }
    const outer = try expectTlv(der, 0x30);
    var cursor = outer.value;
    _ = try expectTlv(cursor, 0x02); // version
    cursor = (try readTlv(cursor)).rest;
    const alg = try expectTlv(cursor, 0x30);
    cursor = alg.rest;
    const key_octets = try expectTlv(cursor, 0x04);

    const alg_oid = try readTlv(alg.value);
    if (std.mem.eql(u8, alg_oid.value, oid_ed25519[2..]) and alg_oid.tag == 0x06) {
        // Ed25519: privateKey wraps an OCTET STRING holding the 32-byte seed.
        const inner = try expectTlv(key_octets.value, 0x04);
        if (inner.value.len != 32) return error.KeyLengthMismatch;
        return .{
            .scheme = .ed25519,
            .key = .{ .ed25519 = key.SecretKey.fromBytes(inner.value[0..32].*) },
        };
    }
    if (std.mem.eql(u8, alg_oid.value, oid_ec_public_key[2..]) and alg_oid.tag == 0x06) {
        const params = try readTlv(alg_oid.rest);
        if (params.tag != 0x06 or !std.mem.eql(u8, params.value, oid_p256[2..])) return error.UnsupportedKeyType;
        const scalar = try parseSec1EcPrivateKey(key_octets.value);
        return .{ .scheme = .ecdsa_secp256r1_sha256, .key = .{ .ecdsa_p256 = scalar } };
    }
    if (alg_oid.tag == 0x06 and std.mem.eql(u8, alg_oid.value, oid_rsa_encryption[2..])) return error.UnsupportedKeyType;
    return error.UnsupportedKeyType;
}

fn parseSec1EcPrivateKey(der: []const u8) Error![32]u8 {
    // ECPrivateKey ::= SEQUENCE { version INTEGER(1), privateKey OCTET STRING, ... }
    const outer = try expectTlv(der, 0x30);
    var cursor = outer.value;
    _ = try expectTlv(cursor, 0x02); // version
    cursor = (try readTlv(cursor)).rest;
    const scalar_tlv = try expectTlv(cursor, 0x04);
    // A P-256 scalar is 32 bytes; tolerate a single leading zero pad byte.
    var scalar = scalar_tlv.value;
    if (scalar.len == 33 and scalar[0] == 0) scalar = scalar[1..];
    if (scalar.len != 32) return error.KeyLengthMismatch;
    return scalar[0..32].*;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const test_pkcs8_ed25519_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MC4CAQAwBQYDK2VwBCIEIKAC2FRb0SkzL0KPGAghDMg5htiRw3TXNxlxRznO9o1a
    \\-----END PRIVATE KEY-----
;

const test_pkcs8_p256_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYaHd2GqVv0i4KtBF
    \\zv/thOIxWB1lT+Xgg/gf0UWyXzGhRANCAAStr1NdTHtpbnsEfreVpF5NzNv4XvvM
    \\rsWtojLEital1j//SdELJx7Bey9y368sKffeD/LWP9iRP9nlOIqabFFp
    \\-----END PRIVATE KEY-----
;

test "parsePkcs8 extracts an Ed25519 seed" {
    const parsed = try parsePrivateKeyPem(test_pkcs8_ed25519_pem);
    try std.testing.expect(parsed.scheme == .ed25519);
    const seed: [32]u8 = parsed.key.ed25519.toBytes();
    // The seed is the trailing 32 bytes of the PKCS#8 DER.
    var rest: []const u8 = test_pkcs8_ed25519_pem;
    const der = (try pemBlock(&rest, "PRIVATE KEY")).?;
    defer std.heap.page_allocator.free(der);
    try std.testing.expectEqualSlices(u8, der[der.len - 32 ..], &seed);
}

test "parsePkcs8 extracts a P-256 scalar" {
    const parsed = try parsePrivateKeyPem(test_pkcs8_p256_pem);
    try std.testing.expect(parsed.scheme == .ecdsa_secp256r1_sha256);
    // openssl pkey -text `priv:` for the fixture above.
    const want = [_]u8{
        0x61, 0xa1, 0xdd, 0xd8, 0x6a, 0x95, 0xbf, 0x48,
        0xb8, 0x2a, 0xd0, 0x45, 0xce, 0xff, 0xed, 0x84,
        0xe2, 0x31, 0x58, 0x1d, 0x65, 0x4f, 0xe5, 0xe0,
        0x83, 0xf8, 0x1f, 0xd1, 0x45, 0xb2, 0x5f, 0x31,
    };
    try std.testing.expectEqualSlices(u8, &want, &parsed.key.ecdsa_p256);
}

test "readTlv short and long form lengths" {
    const short = try readTlv(&[_]u8{ 0x04, 0x03, 1, 2, 3, 0xff });
    try std.testing.expectEqual(@as(u8, 0x04), short.tag);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, short.value);
    try std.testing.expectEqualSlices(u8, &.{0xff}, short.rest);
    const long = try readTlv(&[_]u8{ 0x30, 0x81, 0x05, 1, 2, 3, 4, 5 });
    try std.testing.expectEqual(@as(usize, 5), long.value.len);
    try std.testing.expectError(error.DerMalformed, readTlv(&[_]u8{ 0x30, 0x05, 1 }));
}

test "pemBlock walks multiple blocks and misses cleanly" {
    const text =
        \\-----BEGIN CERTIFICATE-----
        \\AAEC
        \\-----END CERTIFICATE-----
        \\-----BEGIN CERTIFICATE-----
        \\AwQ=
        \\-----END CERTIFICATE-----
    ;
    var rest: []const u8 = text;
    const first = (try pemBlock(&rest, "CERTIFICATE")).?;
    defer std.heap.page_allocator.free(first);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2 }, first);
    const second = (try pemBlock(&rest, "CERTIFICATE")).?;
    defer std.heap.page_allocator.free(second);
    try std.testing.expectEqualSlices(u8, &.{3, 4}, second);
    try std.testing.expect(try pemBlock(&rest, "CERTIFICATE") == null);
}

test "parseSec1EcPrivateKey extracts a 32-byte scalar" {
    // SEQUENCE { INTEGER 1, OCTET STRING <32 x 0x11> }
    var der = [_]u8{ 0x30, 37, 0x02, 0x01, 0x01, 0x04, 0x20 } ++ [_]u8{0x11} ** 32;
    const scalar = try parseSec1EcPrivateKey(&der);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x11} ** 32), &scalar);
}

test "RSA keys are an explicit UnsupportedKeyType, never a fallback" {
    // PKCS#8 SEQUENCE { INTEGER 0, SEQUENCE { rsaEncryption OID }, OCTET STRING }
    const der = [_]u8{
        0x30, 0x16, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09,
    } ++ oid_rsa_encryption[2..] ++ [_]u8{ 0x04, 0x04, 1, 2, 3, 4 };
    try std.testing.expectError(error.UnsupportedKeyType, parsePkcs8(der));
}

// zigtls is off in the default `zig build test` graph (product-selection
// seam); this needs the real pure-Zig TLS/QUIC stack on both ends, so it
// SkipZigTest-gates like every other zigtls-only test in this codebase
// (transport_noq.zig, noq_gate.zig) rather than failing a build that never
// asked for it. Run it for real with `zig build test-qad-client`.
test "F13 QAD client observes its own address off a real Zig QAD server" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var identity = try loadIdentityFromPem(
        allocator,
        io,
        "relay-testdata/qad-test-cert.pem",
        "relay-testdata/qad-test-key.pem",
    );
    defer identity.deinit();

    const server = try Server.init(allocator, io, .{ .ip4 = .loopback(0) }, &identity);
    defer server.deinit(allocator);
    // Mirrors relay_main.zig's own qadServiceEntry: the service loop runs on
    // its own thread sharing this process's one `io` instance, exactly like
    // the production relay binary.
    const server_thread = try std.Thread.spawn(.{}, Server.serviceLoop, .{ server, io });
    defer {
        server.initiateShutdown();
        server_thread.join();
    }

    // The trust store needs an ABSOLUTE path (TrustStore.loadPemFileAbsolute
    // — a deliberate zigtls safety rail against relative-path ambiguity);
    // every other cert path in this codebase is relative-to-cwd, so resolve
    // it here rather than loosen that rail.
    const cert_abs = try std.Io.Dir.cwd().realPathFileAlloc(io, "relay-testdata/qad-test-cert.pem", allocator);
    defer allocator.free(cert_abs);

    const client = try Client.init(allocator, io, .{ .ip4 = .loopback(0) }, cert_abs);
    defer client.deinit();

    const observed = try client.probe(io, server.localAddress(), "localhost", 5 * std.time.ns_per_s);

    // Loopback, no NAT: the server's report must equal the client's own
    // bound address — the exact assertion upstream's quic_endpoint_basic
    // test makes (and what the real Rust qad_client.rs oracle row checks
    // against this same server, from the other direction).
    switch (client.localAddress()) {
        .ip4 => |a| {
            try std.testing.expect(observed.ip != null);
            try std.testing.expectEqualSlices(u8, &a.bytes, &observed.ip.?);
            try std.testing.expectEqual(a.port, observed.port);
        },
        .ip6 => return error.SkipZigTest,
    }
}

// Mutation-red control for relay-qad-client trust selection: probing a live
// QAD server with the WRONG trust anchor (a different self-signed PEM) must
// fail. A client that skips X.509 validation (Rust's "dangerous" config) or
// ignores the trust store would incorrectly succeed here.
//
// Zig intentionally does NOT offer an insecure-skip-verify QAD path — the
// connect-path knobs are: (1) explicit trust PEM vs (2) wrong/absent trust
// which fails closed; plus hard-coded `observed_addr_role = receive_only`
// inside `qadConnect` (see transport_noq.zig + connection.zig F13 tests).
test "F13 QAD client rejects untrusted server cert" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var identity = try loadIdentityFromPem(
        allocator,
        io,
        "relay-testdata/qad-test-cert.pem",
        "relay-testdata/qad-test-key.pem",
    );
    defer identity.deinit();

    const server = try Server.init(allocator, io, .{ .ip4 = .loopback(0) }, &identity);
    defer server.deinit(allocator);
    const server_thread = try std.Thread.spawn(.{}, Server.serviceLoop, .{ server, io });
    defer {
        server.initiateShutdown();
        server_thread.join();
    }

    // Different cert family than the QAD server identity — must not validate.
    const wrong_abs = try std.Io.Dir.cwd().realPathFileAlloc(io, "relay-testdata/test-cert.pem", allocator);
    defer allocator.free(wrong_abs);

    const client = try Client.init(allocator, io, .{ .ip4 = .loopback(0) }, wrong_abs);
    defer client.deinit();

    // Any success is a RED mutation failure (would mean validation was skipped).
    if (client.probe(io, server.localAddress(), "localhost", 3 * std.time.ns_per_s)) |_| {
        return error.TestUnexpectedResult;
    } else |_| {}
}

// ── Certificate-validation production matrix (real QUIC+zigtls peer) ─────────
//
// Positive/negative/mutation-red gates for chain, hostname/SAN, trust-anchor,
// and OCSP on the QAD X.509 path. Unit helpers in zigtls do not satisfy this
// floor; every cell here rides real sockets through validatePeerCertificatePolicy.

const matrix_timeout_ns: i64 = 5 * std.time.ns_per_s;

fn matrixAbs(allocator: std.mem.Allocator, io: std.Io, rel: []const u8) ![:0]u8 {
    // Preserve the sentinel: realPathFileAlloc returns [:0]u8 (dupeZ). Coercing
    // to []u8 makes DebugAllocator free len instead of len+1.
    return try std.Io.Dir.cwd().realPathFileAlloc(io, rel, allocator);
}

fn matrixProbe(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_cert_rel: []const u8,
    server_key_rel: []const u8,
    trust_rel: []const u8,
    server_name: []const u8,
    opts: noq.Endpoint.QadConnectOpts,
) !bool {
    var identity = try loadIdentityFromPem(allocator, io, server_cert_rel, server_key_rel);
    defer identity.deinit();

    const server = try Server.init(allocator, io, .{ .ip4 = .loopback(0) }, &identity);
    defer server.deinit(allocator);
    const server_thread = try std.Thread.spawn(.{}, Server.serviceLoop, .{ server, io });
    defer {
        server.initiateShutdown();
        server_thread.join();
    }

    const trust_abs = try matrixAbs(allocator, io, trust_rel);
    defer allocator.free(trust_abs);
    const client = try Client.init(allocator, io, .{ .ip4 = .loopback(0) }, trust_abs);
    defer client.deinit();

    if (client.probeOpts(io, server.localAddress(), server_name, matrix_timeout_ns, opts)) |_| {
        return true;
    } else |_| {
        return false;
    }
}

fn ocspNow() i64 {
    return std.Io.Clock.real.now(std.testing.io).toSeconds();
}

fn ocspGood() crypto.ZigtlsOcspResponseView {
    if (!crypto.zigtls_enabled) return .{};
    const now = ocspNow();
    return .{
        .status = .good,
        .produced_at = now - 100,
        .this_update = now - 100,
        .next_update = now + 3600,
    };
}

fn ocspRevoked() crypto.ZigtlsOcspResponseView {
    if (!crypto.zigtls_enabled) return .{};
    const now = ocspNow();
    return .{
        .status = .revoked,
        .produced_at = now,
        .this_update = now,
        .next_update = now + 3600,
    };
}

fn ocspStale() crypto.ZigtlsOcspResponseView {
    if (!crypto.zigtls_enabled) return .{};
    // Beyond max_clock_skew_sec (300) past next_update → StaleResponse.
    const now = ocspNow();
    return .{
        .status = .good,
        .produced_at = now - 10_000,
        .this_update = now - 10_000,
        .next_update = now - 5_000,
    };
}

test "cert-matrix: chain positive — CA-anchored leaf accepted" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{},
    );
    try std.testing.expect(ok);
}

test "cert-matrix: chain negative — mismatched issuer rejected" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-broken-sig.pem",
        "relay-testdata/x509-matrix/chain-broken-sig-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{},
    );
    try std.testing.expect(!ok);
}

test "cert-matrix: chain mutation-red — bypass lets mismatched issuer through" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-broken-sig.pem",
        "relay-testdata/x509-matrix/chain-broken-sig-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{ .bypass_chain_verify = true },
    );
    try std.testing.expect(ok);
}

test "cert-matrix: chain negative — expired leaf rejected" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-expired.pem",
        "relay-testdata/x509-matrix/chain-expired-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{},
    );
    try std.testing.expect(!ok);
}

test "cert-matrix: hostname positive — SAN localhost accepted" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{},
    );
    try std.testing.expect(ok);
}

test "cert-matrix: hostname negative — wrong SAN rejected" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-wrong-san.pem",
        "relay-testdata/x509-matrix/chain-wrong-san-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{},
    );
    try std.testing.expect(!ok);
}

test "cert-matrix: hostname mutation-red — bypass lets wrong SAN through" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-wrong-san.pem",
        "relay-testdata/x509-matrix/chain-wrong-san-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{ .bypass_hostname_verify = true },
    );
    try std.testing.expect(ok);
}

test "cert-matrix: trust-anchor positive — configured CA accepts chain" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{},
    );
    try std.testing.expect(ok);
}

test "cert-matrix: trust-anchor negative — other CA rejected" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/other-ca.pem",
        "localhost",
        .{},
    );
    try std.testing.expect(!ok);
}

test "cert-matrix: trust-anchor mutation-red — bypass lets untrusted CA through" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/other-ca.pem",
        "localhost",
        .{ .bypass_trust_anchor = true },
    );
    try std.testing.expect(ok);
}

test "cert-matrix: OCSP policy default-off — handshake succeeds without staple" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    // Product default: enforce_ocsp=false. Explicit gate so OCSP is not a
    // silent skip — the policy is named and proven.
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{ .enforce_ocsp = false },
    );
    try std.testing.expect(ok);
}

test "cert-matrix: OCSP positive — good staple accepted when enforced" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{
            .enforce_ocsp = true,
            .stapled_ocsp = ocspGood(),
        },
    );
    try std.testing.expect(ok);
}

test "cert-matrix: OCSP negative — revoked staple rejected when enforced" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{
            .enforce_ocsp = true,
            .stapled_ocsp = ocspRevoked(),
        },
    );
    try std.testing.expect(!ok);
}

test "cert-matrix: OCSP mutation-red — bypass lets revoked staple through" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const ok = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{
            .enforce_ocsp = true,
            .stapled_ocsp = ocspRevoked(),
            .bypass_ocsp_check = true,
        },
    );
    try std.testing.expect(ok);
}

test "cert-matrix: OCSP stale hard-fails; soft-fail policy accepts" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const hard = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{
            .enforce_ocsp = true,
            .allow_soft_fail_ocsp = false,
            .stapled_ocsp = ocspStale(),
        },
    );
    try std.testing.expect(!hard);
    const soft = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{
            .enforce_ocsp = true,
            .allow_soft_fail_ocsp = true,
            .stapled_ocsp = ocspStale(),
        },
    );
    try std.testing.expect(soft);
}

test "cert-matrix: OCSP missing hard-fails; soft-fail policy accepts" {
    if (!crypto.zigtls_enabled) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const hard = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{
            .enforce_ocsp = true,
            .allow_soft_fail_ocsp = false,
            .stapled_ocsp = null,
        },
    );
    try std.testing.expect(!hard);
    const soft = try matrixProbe(
        allocator,
        io,
        "relay-testdata/x509-matrix/chain-ok.pem",
        "relay-testdata/x509-matrix/chain-ok-key.pem",
        "relay-testdata/x509-matrix/ca.pem",
        "localhost",
        .{
            .enforce_ocsp = true,
            .allow_soft_fail_ocsp = true,
            .stapled_ocsp = null,
        },
    );
    try std.testing.expect(soft);
}
