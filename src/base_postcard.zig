//! iroh-base serde/postcard trait surface for the base types — the Zig
//! counterpart of the `Serialize`/`Deserialize` impls in
//! `iroh/iroh-base/src/{key,relay_url}.rs` under postcard
//! (non-human-readable) serialization.
//!
//! Byte-level parity is pinned by `src/iroh_base_fixtures.zig` (generated from
//! the pinned Rust reference by `tools/iroh_base_probe`):
//!   - `PublicKey`  -> 32 raw bytes (fixed array; postcard adds no length prefix)
//!   - `SecretKey`  -> varint(32) ++ seed (ed25519-dalek `SigningKey` serializes
//!     as a byte slice, which postcard length-prefixes)
//!   - `Signature`  -> 64 raw bytes (serde tuple of 64 u8; no length prefix)
//!   - `RelayUrl`   -> varint(len) ++ utf8 (serde string)
//!
//! Decode mirrors postcard::from_bytes: the input must be consumed EXACTLY —
//! trailing bytes are an error.

const std = @import("std");
const key = @import("key.zig");
const addr = @import("addr.zig");

pub const Error = error{
    EndOfStream,
    VarintOverflow,
    BufferTooSmall,
    InvalidLength,
    InvalidPublicKey,
    InvalidRelayUrl,
    OutOfMemory,
};

// --- PublicKey ---------------------------------------------------------------

/// postcard bytes of a `PublicKey`: the raw 32-byte encoding.
pub fn encodePublicKey(pk: key.PublicKey, out: []u8) Error![]u8 {
    if (out.len < key.PublicKey.LENGTH) return error.BufferTooSmall;
    const bytes = pk.toBytes();
    @memcpy(out[0..key.PublicKey.LENGTH], &bytes);
    return out[0..key.PublicKey.LENGTH];
}

/// postcard decode of a `PublicKey`: exactly 32 bytes, validated like
/// `PublicKey::from_bytes` (iroh rejects non-decompressing encodings here —
/// serde `Deserialize` maps that to a data error).
pub fn decodePublicKey(bytes: []const u8) Error!key.PublicKey {
    if (bytes.len != key.PublicKey.LENGTH) return error.InvalidLength;
    var raw: [32]u8 = undefined;
    @memcpy(&raw, bytes);
    return key.PublicKey.fromBytes(raw) catch return error.InvalidPublicKey;
}

// --- SecretKey ---------------------------------------------------------------

/// postcard bytes of a `SecretKey`: varint(32) ++ 32-byte seed.
pub fn encodeSecretKey(sk: key.SecretKey, out: []u8) Error![]u8 {
    var index: usize = 0;
    try writeVarint(out, &index, key.PublicKey.LENGTH);
    if (out.len < index + 32) return error.BufferTooSmall;
    const seed = sk.toBytes();
    @memcpy(out[index..][0..32], &seed);
    return out[0 .. index + 32];
}

/// postcard decode of a `SecretKey`: varint(32) ++ 32-byte seed, exact.
pub fn decodeSecretKey(bytes: []const u8) Error!key.SecretKey {
    var index: usize = 0;
    const len = try readVarint(bytes, &index);
    if (len != 32) return error.InvalidLength;
    if (bytes.len - index != 32) return error.InvalidLength;
    var seed: [32]u8 = undefined;
    @memcpy(&seed, bytes[index..][0..32]);
    return key.SecretKey.fromBytes(seed);
}

// --- Signature ---------------------------------------------------------------

/// postcard bytes of a `Signature`: the raw 64-byte encoding.
pub fn encodeSignature(sig: key.Signature, out: []u8) Error![]u8 {
    if (out.len < key.Signature.LENGTH) return error.BufferTooSmall;
    const bytes = sig.toBytes();
    @memcpy(out[0..key.Signature.LENGTH], &bytes);
    return out[0..key.Signature.LENGTH];
}

/// postcard decode of a `Signature`: exactly 64 bytes.
pub fn decodeSignature(bytes: []const u8) Error!key.Signature {
    return key.Signature.fromSlice(bytes) catch return error.InvalidLength;
}

// --- RelayUrl ----------------------------------------------------------------

/// postcard bytes of a `RelayUrl`: varint(len) ++ utf8 of the canonical string.
pub fn encodeRelayUrl(url: addr.RelayUrl, out: []u8) Error![]u8 {
    var index: usize = 0;
    const text = url.asString();
    try writeVarint(out, &index, text.len);
    if (out.len < index + text.len) return error.BufferTooSmall;
    @memcpy(out[index..][0..text.len], text);
    return out[0 .. index + text.len];
}

/// postcard decode of a `RelayUrl`: varint(len) ++ utf8, exact, parsed and
/// canonicalized like `RelayUrl::from_str`.
pub fn decodeRelayUrl(allocator: std.mem.Allocator, bytes: []const u8) Error!addr.RelayUrl {
    var index: usize = 0;
    const len = try readVarint(bytes, &index);
    if (bytes.len - index != len) return error.InvalidLength;
    return addr.RelayUrl.parse(allocator, bytes[index..][0..len]) catch return error.InvalidRelayUrl;
}

// --- varint helpers (postcard LEB128) ----------------------------------------

fn writeVarint(out: []u8, index: *usize, value: u64) Error!void {
    var v = value;
    while (true) {
        const byte: u8 = @truncate(v & 0x7f);
        v >>= 7;
        if (index.* >= out.len) return error.BufferTooSmall;
        if (v == 0) {
            out[index.*] = byte;
            index.* += 1;
            return;
        }
        out[index.*] = byte | 0x80;
        index.* += 1;
    }
}

fn readVarint(bytes: []const u8, index: *usize) Error!u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        if (index.* >= bytes.len) return error.EndOfStream;
        const byte = bytes[index.*];
        index.* += 1;
        result |= @as(u64, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) return result;
        if (shift >= 63) return error.VarintOverflow;
        shift += 7;
    }
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;
const fixtures = @import("iroh_base_fixtures.zig");

fn hexToArr(comptime n: usize, s: *const [n * 2]u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected_buf: [256]u8 = undefined;
    const expected = std.fmt.hexToBytes(&expected_buf, expected_hex) catch unreachable;
    try testing.expectEqualSlices(u8, expected, actual);
}

test "postcard PublicKey bytes match the reference fixture" {
    const pk = try key.PublicKey.fromHex(fixtures.postcard.public_hex);
    var buf: [64]u8 = undefined;
    const encoded = try encodePublicKey(pk, &buf);
    // Mutation-RED: any prefix/padding/reordering of the 32 raw bytes fails.
    try expectHex(fixtures.postcard.public_postcard_hex, encoded);

    const decoded = try decodePublicKey(encoded);
    try testing.expect(decoded.eql(pk));
    // Exact-length decode: trailing bytes rejected like postcard::from_bytes.
    try testing.expectError(error.InvalidLength, decodePublicKey(buf[0..33]));
    try testing.expectError(error.InvalidLength, decodePublicKey(buf[0..31]));
    // A non-decompressing encoding is a data error, mirroring iroh Deserialize.
    const no_root = hexToArr(32, "0200000000000000000000000000000000000000000000000000000000000000");
    try testing.expectError(error.InvalidPublicKey, decodePublicKey(&no_root));
}

test "postcard SecretKey bytes match the reference fixture (varint length prefix)" {
    const sk = key.SecretKey.fromBytes(hexToArr(32, fixtures.postcard.seed_hex[0..64]));
    var buf: [64]u8 = undefined;
    const encoded = try encodeSecretKey(sk, &buf);
    // Reference: 0x20 (varint 32) ++ seed — NOT the bare 32 bytes.
    try expectHex(fixtures.postcard.secret_postcard_hex, encoded);

    const decoded = try decodeSecretKey(encoded);
    try testing.expectEqual(sk.toBytes(), decoded.toBytes());
    try testing.expectError(error.InvalidLength, decodeSecretKey(buf[0..32]));
    try testing.expectError(error.InvalidLength, decodeSecretKey(buf[0..34]));
}

test "postcard Signature bytes match the reference fixture" {
    const sig = key.Signature.fromBytes(hexToArr(64, fixtures.postcard.signature_hex[0..128]));
    var buf: [128]u8 = undefined;
    const encoded = try encodeSignature(sig, &buf);
    try expectHex(fixtures.postcard.signature_postcard_hex, encoded);

    const decoded = try decodeSignature(encoded);
    try testing.expectEqual(sig.toBytes(), decoded.toBytes());
    try testing.expectError(error.InvalidLength, decodeSignature(buf[0..63]));
    try testing.expectError(error.InvalidLength, decodeSignature(buf[0..65]));
}

test "postcard RelayUrl bytes match the reference fixture" {
    const allocator = testing.allocator;
    var url = try addr.RelayUrl.parse(allocator, "https://relay.example.com.");
    defer url.deinit(allocator);
    var buf: [64]u8 = undefined;
    const encoded = try encodeRelayUrl(url, &buf);
    try expectHex(fixtures.postcard.relay_url_postcard_hex, encoded);

    var decoded = try decodeRelayUrl(allocator, encoded);
    defer decoded.deinit(allocator);
    try testing.expectEqualStrings(fixtures.postcard.relay_url, decoded.asString());
    try testing.expectError(error.InvalidLength, decodeRelayUrl(allocator, buf[0 .. encoded.len - 1]));
}
