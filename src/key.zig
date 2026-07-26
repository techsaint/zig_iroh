//! Cryptographic key handling — ported from iroh.
//!
//! Mirrors `original/iroh/iroh-base/src/key.rs` (n0-computer/iroh, Apache-2.0/MIT).
//! With wire interop required (plan Q-A = yes), these types must agree
//! byte-for-byte with iroh:
//!   - `NodeId` / `PublicKey` is a 32-byte Ed25519 public key.
//!   - `Display` / `toHex` is lowercase hex; `fmtShort` is the first 5 bytes hex.
//!   - `parse` mirrors iroh's `FromStr` (`decode_base32_hex`): 64-char
//!     lowercase hex, or 52-char STANDARD RFC 4648 base32 no-pad (iroh
//!     `BASE32_NOPAD`). It is NOT z-base-32 — that stays explicit via
//!     `toZ32`/`fromZ32` for pkarr discovery domain names, exactly as iroh
//!     separates `FromStr` from `to_z32`/`from_z32`.
//!   - `SecretKey` is a 32-byte seed; signing is plain Ed25519 (RFC 8032),
//!     identical to iroh's `ed25519_dalek` deterministic signatures. It offers
//!     an explicit `zeroize`/`deinit` secure-erase lifecycle (iroh derives
//!     `ZeroizeOnDrop`); long-lived owners call `deinit` on teardown, since
//!     Zig has no RAII drop.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

/// z-base-32 alphabet, as used by pkarr / iroh (`iroh-base` `Z_BASE_32`).
const Z_BASE_32 = "ybndrfg8ejkmcpqxot1uwisza345h769";

pub const KeyError = error{
    /// Bytes are not a canonical/valid Ed25519 public key.
    InvalidPublicKey,
    /// String is not valid for the expected encoding (hex, standard base32,
    /// or explicit z-base-32).
    InvalidEncoding,
    /// Signature verification failed.
    BadSignature,
};

/// An Ed25519 public key. This is iroh's `NodeId`.
pub const PublicKey = struct {
    bytes: [32]u8,

    /// Validate and wrap raw bytes (iroh `PublicKey::from_bytes`).
    pub fn fromBytes(bytes: [32]u8) KeyError!PublicKey {
        _ = Ed25519.PublicKey.fromBytes(bytes) catch return error.InvalidPublicKey;
        return .{ .bytes = bytes };
    }

    pub fn toBytes(self: PublicKey) [32]u8 {
        return self.bytes;
    }

    pub fn eql(self: PublicKey, other: PublicKey) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    /// Lowercase hex (64 chars), matching iroh's `Display`.
    pub fn toHex(self: PublicKey) [64]u8 {
        return std.fmt.bytesToHex(self.bytes, .lower);
    }

    /// First 5 bytes as lowercase hex (10 chars), matching iroh's `fmt_short`.
    pub fn fmtShort(self: PublicKey) [10]u8 {
        return std.fmt.bytesToHex(self.bytes[0..5].*, .lower);
    }

    /// z-base-32 encoding (52 chars), matching iroh's `to_z32`.
    pub fn toZ32(self: PublicKey) [52]u8 {
        var out: [52]u8 = undefined;
        const n = z32Encode(&self.bytes, &out);
        std.debug.assert(n == 52);
        return out;
    }

    /// Parse a z-base-32 key (iroh `from_z32`).
    pub fn fromZ32(s: []const u8) KeyError!PublicKey {
        var raw: [32]u8 = undefined;
        const n = z32Decode(s, &raw) catch return error.InvalidEncoding;
        if (n != 32) return error.InvalidEncoding;
        return fromBytes(raw);
    }

    /// Parse hex (64 chars) — iroh `Display` is hex, so this round-trips it.
    pub fn fromHex(s: []const u8) KeyError!PublicKey {
        if (s.len != 64) return error.InvalidEncoding;
        var raw: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&raw, s) catch return error.InvalidEncoding;
        return fromBytes(raw);
    }

    /// Parse hex or standard RFC 4648 base32 no-pad, mirroring iroh's
    /// `FromStr` (`decode_base32_hex`): 64 chars -> lowercase hex (iroh
    /// `HEXLOWER`); otherwise -> uppercase + standard base32 no-pad (iroh
    /// `BASE32_NOPAD`), which for a 32-byte key is exactly 52 chars. z-base-32
    /// is intentionally NOT accepted here — use `fromZ32` for discovery/pkarr.
    pub fn parse(s: []const u8) KeyError!PublicKey {
        return switch (s.len) {
            64 => fromHex(s),
            52 => fromBase32NoPad(s),
            else => error.InvalidEncoding,
        };
    }

    fn fromBase32NoPad(s: []const u8) KeyError!PublicKey {
        var raw: [32]u8 = undefined;
        const n = base32NoPadDecode(s, &raw) catch return error.InvalidEncoding;
        if (n != 32) return error.InvalidEncoding;
        return fromBytes(raw);
    }

    /// Verify a signature over `msg` (iroh's `PublicKey` uses strict verification).
    pub fn verify(self: PublicKey, msg: []const u8, sig: Signature) KeyError!void {
        const pk = Ed25519.PublicKey.fromBytes(self.bytes) catch return error.InvalidPublicKey;
        const s = Ed25519.Signature.fromBytes(sig.bytes);
        s.verifyStrict(msg, pk) catch return error.BadSignature;
    }

    /// Verify a signature with cofactored/lax Ed25519 verification.
    pub fn verifyCofactored(self: PublicKey, msg: []const u8, sig: Signature) KeyError!void {
        const pk = Ed25519.PublicKey.fromBytes(self.bytes) catch return error.InvalidPublicKey;
        const s = Ed25519.Signature.fromBytes(sig.bytes);
        s.verify(msg, pk) catch return error.BadSignature;
    }
};

/// iroh's `NodeId` is exactly its `PublicKey`.
pub const NodeId = PublicKey;

/// An Ed25519 secret key, stored as a 32-byte seed (iroh `SecretKey`).
pub const SecretKey = struct {
    seed: [32]u8,

    /// Generate a random secret key (iroh `SecretKey::generate`).
    /// Zig 0.16 has no `std.crypto.random` — use the process Io CSPRNG.
    pub fn generate(io: std.Io) SecretKey {
        var seed: [32]u8 = undefined;
        io.random(&seed);
        return .{ .seed = seed };
    }

    /// Wrap a 32-byte seed (iroh `SecretKey::from_bytes`).
    pub fn fromBytes(seed: [32]u8) SecretKey {
        return .{ .seed = seed };
    }

    pub fn fromHex(s: []const u8) KeyError!SecretKey {
        if (s.len != 64) return error.InvalidEncoding;
        var raw: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&raw, s) catch return error.InvalidEncoding;
        return fromBytes(raw);
    }

    /// Parse hex or standard RFC 4648 base32 no-pad, mirroring iroh's
    /// `SecretKey::FromStr` and the existing `PublicKey.parse` semantics.
    pub fn parse(s: []const u8) KeyError!SecretKey {
        return switch (s.len) {
            64 => fromHex(s),
            52 => fromBase32NoPad(s),
            else => error.InvalidEncoding,
        };
    }

    pub fn from_str(s: []const u8) KeyError!SecretKey {
        return parse(s);
    }

    fn fromBase32NoPad(s: []const u8) KeyError!SecretKey {
        var raw: [32]u8 = undefined;
        const n = base32NoPadDecode(s, &raw) catch return error.InvalidEncoding;
        if (n != 32) return error.InvalidEncoding;
        return fromBytes(raw);
    }

    /// The 32-byte seed (iroh `SecretKey::to_bytes`).
    pub fn toBytes(self: SecretKey) [32]u8 {
        return self.seed;
    }

    /// Securely overwrite the secret seed. iroh's `SecretKey` derives
    /// `zeroize::ZeroizeOnDrop`; Zig has no RAII drop, so long-lived owners
    /// call this (or `deinit`) on teardown instead of relying on a Drop impl.
    pub fn zeroize(self: *SecretKey) void {
        std.crypto.secureZero(u8, &self.seed);
    }

    /// Explicit teardown hook for long-lived `SecretKey` owners: zeroizes the
    /// seed. Call from the owner's `deinit`/drop path (e.g. relay client,
    /// transport, discovery teardown).
    pub fn deinit(self: *SecretKey) void {
        self.zeroize();
    }

    /// The corresponding public key / node id (iroh `SecretKey::public`).
    pub fn public(self: SecretKey) PublicKey {
        // Errors only for the ~2^-128 pathological seed; matches iroh's
        // infallible `public()`.
        const kp = Ed25519.KeyPair.generateDeterministic(self.seed) catch unreachable;
        return .{ .bytes = kp.public_key.toBytes() };
    }

    /// Sign a message — plain Ed25519 (RFC 8032), identical to iroh.
    pub fn sign(self: SecretKey, msg: []const u8) Signature {
        const kp = Ed25519.KeyPair.generateDeterministic(self.seed) catch unreachable;
        const s = kp.sign(msg, null) catch unreachable;
        return .{ .bytes = s.toBytes() };
    }
};

/// A 64-byte Ed25519 signature (iroh `Signature`).
pub const Signature = struct {
    bytes: [64]u8,

    pub fn fromBytes(bytes: [64]u8) Signature {
        return .{ .bytes = bytes };
    }

    pub fn toBytes(self: Signature) [64]u8 {
        return self.bytes;
    }

    pub fn toHex(self: Signature) [128]u8 {
        return std.fmt.bytesToHex(self.bytes, .lower);
    }
};

// --- standard RFC 4648 base32, no padding (iroh `BASE32_NOPAD`) ------------

/// Standard RFC 4648 base32 alphabet, no padding. This is what iroh's
/// `PublicKey`/`SecretKey` `FromStr` decodes (after `to_ascii_uppercase`) via
/// `data_encoding::BASE32_NOPAD` — distinct from the z-base-32 alphabet used
/// for discovery/pkarr domain names.
const BASE32_NOPAD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32Symbol(c: u8) ?u5 {
    // iroh uppercases the input before decoding (`s.to_ascii_uppercase()`), so
    // accept lowercase too.
    const upper = std.ascii.toUpper(c);
    for (BASE32_NOPAD, 0..) |s, i| {
        if (s == upper) return @intCast(i);
    }
    return null;
}

/// Decode standard RFC 4648 base32 without padding into `out`. Mirrors iroh's
/// `BASE32_NOPAD.decode_mut`: rejects `=` padding and symbols outside the
/// alphabet, and requires trailing bits to be zero (RFC 4648). Returns the
/// number of bytes written.
fn base32NoPadDecode(s: []const u8, out: []u8) !usize {
    var acc: u32 = 0;
    var nbits: u32 = 0;
    var oi: usize = 0;
    for (s) |c| {
        if (c == '=') return error.InvalidEncoding;
        const v = base32Symbol(c) orelse return error.InvalidEncoding;
        acc = (acc << 5) | v;
        nbits += 5;
        if (nbits >= 8) {
            nbits -= 8;
            if (oi >= out.len) return error.InvalidEncoding;
            out[oi] = @intCast((acc >> @as(u5, @intCast(nbits))) & 0xff);
            oi += 1;
        }
    }
    if (nbits > 0) {
        const mask = (@as(u32, 1) << @as(u5, @intCast(nbits))) - 1;
        if ((acc & mask) != 0) return error.InvalidEncoding;
    }
    return oi;
}

// --- z-base-32 (RFC 4648-style MSB-first bit packing, no padding) ----------

/// Encode `data` into `out` using the z-base-32 alphabet. Returns chars written.
/// `out` must be at least `(data.len * 8 + 4) / 5` bytes.
fn z32Encode(data: []const u8, out: []u8) usize {
    var acc: u32 = 0;
    var nbits: u32 = 0;
    var oi: usize = 0;
    for (data) |b| {
        acc = (acc << 8) | b;
        nbits += 8;
        while (nbits >= 5) {
            nbits -= 5;
            out[oi] = Z_BASE_32[(acc >> @as(u5, @intCast(nbits))) & 31];
            oi += 1;
        }
    }
    if (nbits > 0) {
        out[oi] = Z_BASE_32[(acc << @as(u5, @intCast(5 - nbits))) & 31];
        oi += 1;
    }
    return oi;
}

fn z32Symbol(c: u8) ?u5 {
    for (Z_BASE_32, 0..) |s, i| {
        if (s == c) return @intCast(i);
    }
    return null;
}

/// Decode z-base-32 `s` into `out`. Returns bytes written.
fn z32Decode(s: []const u8, out: []u8) !usize {
    var acc: u32 = 0;
    var nbits: u32 = 0;
    var oi: usize = 0;
    for (s) |c| {
        const v = z32Symbol(c) orelse return error.InvalidEncoding;
        acc = (acc << 5) | v;
        nbits += 5;
        if (nbits >= 8) {
            nbits -= 8;
            if (oi >= out.len) return error.InvalidEncoding;
            out[oi] = @intCast((acc >> @as(u5, @intCast(nbits))) & 0xff);
            oi += 1;
        }
    }
    return oi;
}

// --- tests -----------------------------------------------------------------
// Vectors are RFC 8032 ground truth (python-cryptography), which iroh's
// ed25519_dalek also implements. The z32 + iroh public-key vector come from
// `original/iroh/iroh-base/src/key.rs` (`ae58...502b6`).

const testing = std.testing;

fn hexToArr(comptime n: usize, s: *const [n * 2]u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "seed -> public key matches Ed25519 (RFC 8032) ground truth" {
    const sk = SecretKey.fromBytes(hexToArr(32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    const pk = sk.public();
    try testing.expectEqualStrings(
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
        &pk.toHex(),
    );
}

test "sign produces the iroh/RFC-8032 signature and verifies" {
    const sk = SecretKey.fromBytes(hexToArr(32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    const sig = sk.sign("iroh zig port");
    try testing.expectEqualStrings(
        "0ab61f64e471010532cd01f223a7256c0a88daa59ba3e5e2f4f0b464dcde678a" ++
            "4c7fd771e820db345d5096f1f72c41d888fde74ab84cc9ee7649724af7f76c08",
        &sig.toHex(),
    );
    try sk.public().verify("iroh zig port", sig);
}

test "verify rejects a tampered message" {
    const sk = SecretKey.fromBytes(hexToArr(32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    const sig = sk.sign("iroh zig port");
    try testing.expectError(error.BadSignature, sk.public().verify("iroh zig porT", sig));
}

test "verify is strict while verifyCofactored accepts cofactored-only signatures" {
    const msg = hexToArr(16, "65643235353139766563746f72732033"); // "ed25519vectors 3"
    const pk = try PublicKey.fromHex("86e72f5c2a7215151059aa151c0ee6f8e2155d301402f35d7498f078629a8f79");
    const sig = Signature.fromBytes(hexToArr(64, "fa9dde274f4820efb19a890f8ba2d8791710a4303ceef4aedf9dddc4e81a1f11701a598b9a02ae60505dd0c2938a1a0c2d6ffd4676cfb49125b19e9cb358da06"));

    try pk.verifyCofactored(&msg, sig);
    try testing.expectError(error.BadSignature, pk.verify(&msg, sig));
}

test "public key z-base-32 round-trips and matches the seed vector" {
    const pk = SecretKey.fromBytes(hexToArr(32, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")).public();
    try testing.expectEqualStrings("yqooxx9u3aemh8mo5wcqq16yufu6jitouq1o4za751dger1igghy", &pk.toZ32());
    const back = try PublicKey.fromZ32(&pk.toZ32());
    try testing.expect(back.eql(pk));
}

test "iroh public-key vector: parse accepts hex and standard base32 only" {
    // The hex + iroh public-key vector come from `iroh-base/src/key.rs`
    // (`ae58...502b6`). The 52-char base32 string is the RFC 4648 no-pad
    // encoding of those bytes — the same string iroh's `BASE32_NOPAD` accepts.
    const hex = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6";
    const base32 = "VZMP7CBTEQNMQLLP65QRARXNM62QOLIUFRMI2ADD5FBNTJ2VAK3A";
    const pk = try PublicKey.fromHex(hex);
    try testing.expectEqualStrings(hex, &pk.toHex());
    try testing.expectEqualStrings("i3cx9nburopcommx67otytzpc64oqmewftce4ydd7fbpuj4iyk5y", &pk.toZ32());
    try testing.expect((try PublicKey.parse(hex)).eql(pk));
    // 52-char STANDARD base32 (uppercase) parses, matching iroh FromStr.
    try testing.expect((try PublicKey.parse(base32)).eql(pk));
    // iroh uppercases before decoding, so lowercase standard base32 parses too.
    try testing.expect((try PublicKey.parse("vzmp7cbteqnmqllp65qrarxnm62qoliufrmi2add5fbntj2vak3a")).eql(pk));
    // z-base-32 is NOT standard base32: parse must reject it.
    try testing.expectError(error.InvalidEncoding, PublicKey.parse(&pk.toZ32()));
    // z-base-32 origins still resolve through the EXPLICIT fromZ32 path.
    try testing.expect((try PublicKey.fromZ32(&pk.toZ32())).eql(pk));
}

test "fmtShort is first 5 bytes of hex" {
    const pk = try PublicKey.fromHex("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6");
    try testing.expectEqualStrings("ae58ff8833", &pk.fmtShort());
}

test "fromBytes rejects a non-canonical public key" {
    // All-0xFF is not a canonical Ed25519 point encoding.
    try testing.expectError(error.InvalidPublicKey, PublicKey.fromBytes(.{0xff} ** 32));
}

test "SecretKey.generate fills from Io CSPRNG and is non-zero" {
    const sk = SecretKey.generate(std.testing.io);
    // Astronomically unlikely all-zero from a real CSPRNG; catches the old stub.
    try testing.expect(!std.mem.eql(u8, &sk.toBytes(), &[_]u8{0} ** 32));
    const sk2 = SecretKey.generate(std.testing.io);
    try testing.expect(!std.mem.eql(u8, &sk.toBytes(), &sk2.toBytes()));
}

test "secret key parse accepts hex and standard base32 preserving public key" {
    const seed_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const seed_base32 = "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ";
    const expected = SecretKey.fromBytes(hexToArr(32, seed_hex));

    const from_hex = try SecretKey.parse(seed_hex);
    try testing.expectEqual(expected.toBytes(), from_hex.toBytes());
    try testing.expect(from_hex.public().eql(expected.public()));

    const from_base32 = try SecretKey.from_str(seed_base32);
    try testing.expectEqual(expected.toBytes(), from_base32.toBytes());
    try testing.expect(from_base32.public().eql(expected.public()));
    try testing.expect((try SecretKey.parse("aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq")).public().eql(expected.public()));
    try testing.expectError(error.InvalidEncoding, SecretKey.parse("AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ="));
}
