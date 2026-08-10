//! JWS (RFC 7515) with ES256 for ACME (RFC 8555 §6.2) plus the RFC 7638 JWK
//! thumbprint the TLS-ALPN-01 key authorization is built from.
//!
//! Only what the ACME lane needs: flattened JSON serialization, detached
//! payload option ("POST-as-GET" signs the empty payload), no `b64=false`
//! extension — Pebble/Boulder want standard base64url bodies.

const std = @import("std");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const b64url_enc = std.base64.url_safe_no_pad.Encoder;
pub const b64url_dec = std.base64.url_safe_no_pad.Decoder;

pub const Error = error{InvalidEncoding} || std.mem.Allocator.Error;

pub fn b64urlEncode(allocator: std.mem.Allocator, data: []const u8) Error![]u8 {
    const out = try allocator.alloc(u8, b64url_enc.calcSize(data.len));
    _ = b64url_enc.encode(out, data);
    return out;
}

/// Canonical JWK JSON for an ES256 account key. Member order is
/// lexicographic ("crv", "kty", "x", "y") so this same string IS the RFC 7638
/// thumbprint input.
pub fn jwkJson(allocator: std.mem.Allocator, public_sec1: *const [65]u8) Error![]u8 {
    const x = try b64urlEncode(allocator, public_sec1[1..33]);
    defer allocator.free(x);
    const y = try b64urlEncode(allocator, public_sec1[33..65]);
    defer allocator.free(y);
    return std.fmt.allocPrint(allocator, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ x, y });
}

/// RFC 7638 thumbprint: base64url(SHA-256(canonical JWK JSON)).
pub fn jwkThumbprint(public_sec1: *const [65]u8, out: *[43]u8) void {
    var x_b64: [43]u8 = undefined;
    var y_b64: [43]u8 = undefined;
    _ = b64url_enc.encode(&x_b64, public_sec1[1..33]);
    _ = b64url_enc.encode(&y_b64, public_sec1[33..65]);
    var json_buf: [128]u8 = undefined;
    const json = std.fmt.bufPrint(&json_buf, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ x_b64, y_b64 }) catch unreachable;
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(json, &digest, .{});
    _ = b64url_enc.encode(out, &digest);
}

/// Signs `payload` per RFC 8555: flattened JWS JSON {"protected","payload",
/// "signature"}. `protected_json` is the already-rendered protected header
/// ({"alg":"ES256","nonce":..,"url":..,"jwk"|"kid":..}); an empty `payload`
/// produces the POST-as-GET form ("" payload member).
pub fn signFlattened(
    allocator: std.mem.Allocator,
    key_pair: Ecdsa.KeyPair,
    protected_json: []const u8,
    payload: []const u8,
) Error![]u8 {
    const protected_b64 = try b64urlEncode(allocator, protected_json);
    defer allocator.free(protected_b64);
    const payload_b64 = try b64urlEncode(allocator, payload);
    defer allocator.free(payload_b64);

    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ protected_b64, payload_b64 });
    defer allocator.free(signing_input);
    const sig = key_pair.sign(signing_input, null) catch return error.InvalidEncoding;
    const raw = sig.toBytes(); // JWS ES256 signature is raw r || s
    const sig_b64 = try b64urlEncode(allocator, &raw);
    defer allocator.free(sig_b64);

    return std.fmt.allocPrint(allocator,
        "{{\"protected\":\"{s}\",\"payload\":\"{s}\",\"signature\":\"{s}\"}}", .{ protected_b64, payload_b64, sig_b64 });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "jwk thumbprint is stable for a fixed key and lexicographic" {
    const seed: [Ecdsa.KeyPair.seed_length]u8 = @splat(3);
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(seed);
    const public = key_pair.public_key.toUncompressedSec1();

    var thumb: [43]u8 = undefined;
    jwkThumbprint(&public, &thumb);

    // Independently recompute: canonical JSON over the same x/y, hashed.
    var x_b64: [43]u8 = undefined;
    var y_b64: [43]u8 = undefined;
    _ = b64url_enc.encode(&x_b64, public[1..33]);
    _ = b64url_enc.encode(&y_b64, public[33..65]);
    var json_buf: [128]u8 = undefined;
    const json = try std.fmt.bufPrint(&json_buf, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ x_b64, y_b64 });
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(json, &digest, .{});
    var expected: [43]u8 = undefined;
    _ = b64url_enc.encode(&expected, &digest);
    try std.testing.expectEqualSlices(u8, &expected, &thumb);

    // A different key must thumbprint differently.
    const other = try Ecdsa.KeyPair.generateDeterministic(@splat(4));
    const other_public = other.public_key.toUncompressedSec1();
    var other_thumb: [43]u8 = undefined;
    jwkThumbprint(&other_public, &other_thumb);
    try std.testing.expect(!std.mem.eql(u8, &thumb, &other_thumb));
}

test "flattened jws signature verifies over protected.payload" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const key_pair = try Ecdsa.KeyPair.generateDeterministic(@splat(6));
    const jws = try signFlattened(a, key_pair, "{\"alg\":\"ES256\",\"nonce\":\"n\",\"url\":\"u\"}", "{\"termsOfServiceAgreed\":true}");

    // Pull the three members back out (the builder emits them in order).
    const parsed = try std.json.parseFromSlice(std.json.Value, a, jws, .{});
    const obj = parsed.value.object;
    const protected_b64 = obj.get("protected").?.string;
    const payload_b64 = obj.get("payload").?.string;
    const sig_b64 = obj.get("signature").?.string;

    var sig_raw: [Ecdsa.Signature.encoded_length]u8 = undefined;
    try b64url_dec.decode(&sig_raw, sig_b64);
    const signature = Ecdsa.Signature.fromBytes(sig_raw);

    const signing_input = try std.fmt.allocPrint(a, "{s}.{s}", .{ protected_b64, payload_b64 });
    try signature.verify(signing_input, key_pair.public_key);

    // POST-as-GET: empty payload member decodes to "".
    const pag = try signFlattened(a, key_pair, "{\"alg\":\"ES256\"}", "");
    const pag_parsed = try std.json.parseFromSlice(std.json.Value, a, pag, .{});
    try std.testing.expectEqualStrings("", pag_parsed.value.object.get("payload").?.string);
}
