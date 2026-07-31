//! DERP handshake frames — postcard-encoded auth protocol.
//!
//! Challenge path:
//!   1. Server → Client: ServerChallenge (tag 0) with 16 random bytes
//!   2. Client → Server: ClientAuth (tag 1) with pubkey + signature
//!   3. Server → Client: ServerConfirmsAuth (tag 2) or ServerDeniesAuth (tag 3)
//!
//! Reference: `iroh/iroh-relay/src/protos/handshake.rs`
//!
//! TLS-exporter client auth (RFC 5705, upstream's CLIENT_AUTH_HEADER fast
//! path on wss): **deliberately N/A** (decision recorded 2026-07-27,
//! relay completion work). Upstream treats exporter auth as an OPTIONAL
//! fast path — the challenge handshake above is the interoperable floor and
//! always works. The relay's wss TLS stack (ianic/tls.zig, tls_wrapper.zig)
//! exposes no keying-material exporter, and inventing one to close a bucket
//! was explicitly out of scope. Revisit only as a deliberate
//! feature with real exporter support in the TLS stack.

const std = @import("std");
const key = @import("../key.zig");
const proto = @import("proto.zig");

/// Blake3 derive_key context for challenge signing.
/// Reference: `handshake.rs:210-220`
const CHALLENGE_CONTEXT = "iroh-relay handshake v1 challenge signature";

// --- Frame types ------------------------------------------------------------

/// Server → Client: 16 random bytes challenge.
/// Wire: tag(0x00) + challenge[16] = 17 bytes
/// Reference: `handshake.rs:77`, `:203-206`
pub const ServerChallenge = struct {
    challenge: [16]u8,
};

/// Client → Server: public key + signature.
/// Wire: tag(0x01) + public_key[32] + varint(64) + signature[64] = 98 bytes
/// Reference: `handshake.rs:88-97`
pub const ClientAuth = struct {
    public_key: key.PublicKey,
    signature: key.Signature,
};

/// Server → Client: auth confirmed (0 payload bytes).
/// Wire: tag(0x02) = 1 byte
/// Reference: `handshake.rs:101`
pub const ServerConfirmsAuth = struct {};

/// Server → Client: auth denied with reason string.
/// Wire: tag(0x03) + varint(len(reason)) + reason UTF-8
/// Reference: `handshake.rs:105`
pub const ServerDeniesAuth = struct {
    reason: []const u8,
};

// --- Crypto helpers ---------------------------------------------------------

/// Compute the 32-byte message to sign from a challenge.
/// `blake3::derive_key("iroh-relay handshake v1 challenge signature", challenge)`
/// Reference: `handshake.rs:210-220`
pub fn messageToSign(challenge: [16]u8) [32]u8 {
    var out: [32]u8 = undefined;
    // iroh uses blake3::derive_key(context, challenge) → KDF mode.
    // Zig 0.16: Blake3.initKdf(context, .{}) then update(challenge) then final.
    var hasher = std.crypto.hash.Blake3.initKdf(CHALLENGE_CONTEXT, .{});
    hasher.update(&challenge);
    hasher.final(&out);
    return out;
}

/// Create a `ClientAuth` for a given secret key and challenge.
pub fn clientAuthFor(sk: key.SecretKey, challenge: [16]u8) ClientAuth {
    const msg = messageToSign(challenge);
    const sig = sk.sign(&msg);
    return .{
        .public_key = sk.public(),
        .signature = sig,
    };
}

/// Verify a `ClientAuth` against a challenge.
/// Reference: `handshake.rs:233-247`
pub fn verifyClientAuth(auth: ClientAuth, challenge: [16]u8) !void {
    const msg = messageToSign(challenge);
    try auth.public_key.verify(&msg, auth.signature);
}

// --- Encoding ---------------------------------------------------------------

/// Encode a ServerChallenge frame.
pub fn encodeServerChallenge(sc: ServerChallenge, writer: *std.Io.Writer) !void {
    try writer.writeByte(0x00);
    try writer.writeAll(&sc.challenge);
}

/// Encode a ClientAuth frame.
pub fn encodeClientAuth(ca: ClientAuth, writer: *std.Io.Writer) !void {
    try writer.writeByte(0x01);
    try writer.writeAll(&ca.public_key.bytes);
    // postcard encodes 64 as varint 0x40 (single byte), then 64 bytes of signature
    try writer.writeByte(0x40);
    try writer.writeAll(&ca.signature.bytes);
}

/// Encode a ServerConfirmsAuth frame.
pub fn encodeServerConfirmsAuth(_: ServerConfirmsAuth, writer: *std.Io.Writer) !void {
    try writer.writeByte(0x02);
}

/// Encode a ServerDeniesAuth frame.
pub fn encodeServerDeniesAuth(sda: ServerDeniesAuth, writer: *std.Io.Writer) !void {
    if (!std.unicode.utf8ValidateSlice(sda.reason)) return error.InvalidUtf8;
    try writer.writeByte(0x03);
    try writePostcardVarint(sda.reason.len, writer);
    try writer.writeAll(sda.reason);
}

// --- Decoding ---------------------------------------------------------------

pub const HandshakeFrame = union(enum) {
    server_challenge: ServerChallenge,
    client_auth: ClientAuth,
    server_confirms_auth: ServerConfirmsAuth,
    server_denies_auth: ServerDeniesAuth,
};

/// Decode a handshake frame from raw bytes (including the tag byte).
pub fn decodeHandshakeFrame(buf: []const u8) !HandshakeFrame {
    if (buf.len == 0) return error.EmptyFrame;
    return switch (buf[0]) {
        0x00 => {
            if (buf.len != 17) return error.InvalidFrameLength;
            var challenge: [16]u8 = undefined;
            @memcpy(&challenge, buf[1..17]);
            return .{ .server_challenge = .{ .challenge = challenge } };
        },
        0x01 => {
            // tag + 32 pubkey + 1 varint + 64 sig = 98 bytes
            if (buf.len != 98) return error.InvalidFrameLength;
            const pk = try key.PublicKey.fromBytes(buf[1..33].*);
            // Expect varint 0x40 = 64
            if (buf[33] != 0x40) return error.InvalidSignatureLength;
            var sig: [64]u8 = undefined;
            @memcpy(&sig, buf[34..98]);
            return .{ .client_auth = .{
                .public_key = pk,
                .signature = key.Signature.fromBytes(sig),
            } };
        },
        0x02 => {
            if (buf.len != 1) return error.InvalidFrameLength;
            return .{ .server_confirms_auth = .{} };
        },
        0x03 => {
            if (buf.len < 2) return error.FrameTooShort;
            const reason_len = try readPostcardVarint(buf[1..]);
            const varint_size = postcardVarintSize(buf[1..]);
            const start = 1 + varint_size;
            const end = std.math.add(usize, start, reason_len) catch return error.FrameTooLong;
            if (end != buf.len) return error.InvalidFrameLength;
            const reason = buf[start..end];
            if (!std.unicode.utf8ValidateSlice(reason)) return error.InvalidUtf8;
            return .{ .server_denies_auth = .{ .reason = reason } };
        },
        else => error.UnknownHandshakeFrame,
    };
}

// --- Postcard varint helpers ------------------------------------------------
// postcard uses LEB128 varint encoding.

fn writePostcardVarint(val: usize, writer: *std.Io.Writer) !void {
    var v = val;
    while (v >= 0x80) {
        try writer.writeByte(@intCast((v & 0x7F) | 0x80));
        v >>= 7;
    }
    try writer.writeByte(@intCast(v));
}

fn readPostcardVarint(buf: []const u8) !usize {
    var result: usize = 0;
    var shift: u6 = 0;
    for (buf) |b| {
        if (shift >= @as(u6, 63) and b > 1) return error.VarintOverflow;
        result |= @as(usize, b & 0x7F) << shift;
        if (b < 0x80) return result;
        shift += 7;
    }
    return error.VarintTruncated;
}

fn postcardVarintSize(buf: []const u8) usize {
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        if (buf[i] < 0x80) return i + 1;
    }
    return buf.len;
}

// --- Tests ------------------------------------------------------------------

const testing = std.testing;

test "ServerChallenge with [0xAB;16] encodes as 00 + 16 bytes" {
    const sc = ServerChallenge{ .challenge = .{0xAB} ** 16 };
    var buf: [32]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeServerChallenge(sc, &writer);
    const encoded = writer.buffered();
    try testing.expectEqual(@as(usize, 17), encoded.len);
    try testing.expectEqual(@as(u8, 0x00), encoded[0]);
    for (encoded[1..17]) |b| try testing.expectEqual(@as(u8, 0xAB), b);
}

test "ServerConfirmsAuth encodes as single byte 02" {
    var buf: [8]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeServerConfirmsAuth(.{}, &writer);
    const encoded = writer.buffered();
    try testing.expectEqual(@as(usize, 1), encoded.len);
    try testing.expectEqual(@as(u8, 0x02), encoded[0]);
}

test "ServerDeniesAuth encodes correctly" {
    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeServerDeniesAuth(.{ .reason = "nope" }, &writer);
    const encoded = writer.buffered();
    // tag(03) + varint(4) + "nope"
    try testing.expectEqual(@as(usize, 6), encoded.len);
    try testing.expectEqual(@as(u8, 0x03), encoded[0]);
    try testing.expectEqual(@as(u8, 0x04), encoded[1]); // LEB128 of 4
    try testing.expectEqualStrings("nope", encoded[2..]);
}

test "ClientAuth layout: 01 || pub(32) || 40 || sig(64)" {
    const sk = key.SecretKey.fromBytes(.{42} ** 32);
    const challenge: [16]u8 = .{0x11} ** 16;
    const ca = clientAuthFor(sk, challenge);

    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeClientAuth(ca, &writer);
    const encoded = writer.buffered();

    try testing.expectEqual(@as(usize, 98), encoded.len);
    try testing.expectEqual(@as(u8, 0x01), encoded[0]);
    try testing.expectEqualSlices(u8, &ca.public_key.bytes, encoded[1..33]);
    try testing.expectEqual(@as(u8, 0x40), encoded[33]);
    try testing.expectEqualSlices(u8, &ca.signature.bytes, encoded[34..98]);
}

test "challenge sign/verify round-trip" {
    const sk = key.SecretKey.fromBytes(.{42} ** 32);
    const challenge: [16]u8 = .{0x11} ** 16;
    const ca = clientAuthFor(sk, challenge);
    try verifyClientAuth(ca, challenge);
}

test "verify rejects wrong challenge" {
    const sk = key.SecretKey.fromBytes(.{42} ** 32);
    const challenge: [16]u8 = .{0x11} ** 16;
    const ca = clientAuthFor(sk, challenge);
    const wrong: [16]u8 = .{0x22} ** 16;
    try testing.expectError(error.BadSignature, verifyClientAuth(ca, wrong));
}

test "decode ServerChallenge round-trip" {
    const sc = ServerChallenge{ .challenge = .{0xCD} ** 16 };
    var buf: [32]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeServerChallenge(sc, &writer);
    const encoded = writer.buffered();

    const decoded = try decodeHandshakeFrame(encoded);
    try testing.expect(decoded == .server_challenge);
    try testing.expectEqualSlices(u8, &sc.challenge, &decoded.server_challenge.challenge);
}

test "decode ClientAuth round-trip" {
    const sk = key.SecretKey.fromBytes(.{42} ** 32);
    const challenge: [16]u8 = .{0x11} ** 16;
    const ca = clientAuthFor(sk, challenge);

    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeClientAuth(ca, &writer);
    const encoded = writer.buffered();

    const decoded = try decodeHandshakeFrame(encoded);
    try testing.expect(decoded == .client_auth);
    try testing.expect(decoded.client_auth.public_key.eql(ca.public_key));
}

test "decode ServerConfirmsAuth round-trip" {
    var buf: [8]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeServerConfirmsAuth(.{}, &writer);
    const encoded = writer.buffered();

    const decoded = try decodeHandshakeFrame(encoded);
    try testing.expect(decoded == .server_confirms_auth);
}

test "decode ServerDeniesAuth round-trip" {
    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeServerDeniesAuth(.{ .reason = "access denied" }, &writer);
    const encoded = writer.buffered();

    const decoded = try decodeHandshakeFrame(encoded);
    try testing.expect(decoded == .server_denies_auth);
    try testing.expectEqualStrings("access denied", decoded.server_denies_auth.reason);
}

test "decode ServerDeniesAuth with multi-byte LEB128 length" {
    var buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try encodeServerDeniesAuth(.{ .reason = "x" ** 200 }, &writer);
    const encoded = writer.buffered();

    const decoded = try decodeHandshakeFrame(encoded);
    try testing.expect(decoded == .server_denies_auth);
    try testing.expectEqual(@as(usize, 200), decoded.server_denies_auth.reason.len);
}

test "handshake decoder rejects trailing fixed fields and hostile denial lengths" {
    try testing.expectError(error.InvalidFrameLength, decodeHandshakeFrame(&([_]u8{0x00} ++ [_]u8{0} ** 17)));
    try testing.expectError(error.InvalidFrameLength, decodeHandshakeFrame(&[_]u8{ 0x02, 0x00 }));

    const max_usize_reason = [_]u8{0x03} ++ [_]u8{0xff} ** 9 ++ [_]u8{0x01};
    try testing.expectError(error.FrameTooLong, decodeHandshakeFrame(&max_usize_reason));

    const invalid_utf8 = [_]u8{ 0x03, 0x01, 0xff };
    try testing.expectError(error.InvalidUtf8, decodeHandshakeFrame(&invalid_utf8));
}

test "ServerDeniesAuth rejects invalid UTF-8 before writing" {
    var buf: [8]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try testing.expectError(error.InvalidUtf8, encodeServerDeniesAuth(.{ .reason = "\xff" }, &writer));
    try testing.expectEqual(@as(usize, 0), writer.buffered().len);
}

test "messageToSign is deterministic" {
    const challenge: [16]u8 = .{0x42} ** 16;
    const a = messageToSign(challenge);
    const b = messageToSign(challenge);
    try testing.expectEqualSlices(u8, &a, &b);
}

test "ServerDeniesAuth postcard length vectors cover LEB128 boundaries" {
    const cases = [_]struct {
        len: usize,
        varint: []const u8,
    }{
        .{ .len = 127, .varint = "\x7f" },
        .{ .len = 128, .varint = "\x80\x01" },
        .{ .len = 255, .varint = "\xff\x01" },
        .{ .len = 256, .varint = "\x80\x02" },
        .{ .len = 16_384, .varint = "\x80\x80\x01" },
    };

    for (cases) |case| {
        const reason = try testing.allocator.alloc(u8, case.len);
        defer testing.allocator.free(reason);
        @memset(reason, 'x');

        const encoded_buf = try testing.allocator.alloc(u8, 1 + case.varint.len + case.len);
        defer testing.allocator.free(encoded_buf);
        var writer = std.Io.Writer.fixed(encoded_buf);
        try encodeServerDeniesAuth(.{ .reason = reason }, &writer);
        const encoded = writer.buffered();

        try testing.expectEqual(@as(u8, 0x03), encoded[0]);
        try testing.expectEqualSlices(u8, case.varint, encoded[1 .. 1 + case.varint.len]);
        try testing.expectEqual(@as(usize, encoded_buf.len), encoded.len);

        const decoded = try decodeHandshakeFrame(encoded);
        try testing.expect(decoded == .server_denies_auth);
        try testing.expectEqual(@as(usize, case.len), decoded.server_denies_auth.reason.len);
        try testing.expectEqualSlices(u8, reason, decoded.server_denies_auth.reason);
    }
}
