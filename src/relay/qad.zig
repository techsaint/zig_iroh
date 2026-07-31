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
const key = @import("../key.zig");
const crypto = @import("../quic/crypto.zig");
const noq = @import("../transport/transport_noq.zig");

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
        try chain.append(allocator, der);
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
