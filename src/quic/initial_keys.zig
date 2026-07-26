//! QUIC Initial key derivation (RFC 9001 §5.2) — N3b-2.5 leaf.
//!
//! `initial_secret = HKDF-Extract(initial_salt_v1, DCID)`, then
//! HKDF-Expand-Label `"client in"` / `"server in"`, then
//! `packet_crypto.keysFromTrafficSecret` for AEAD/IV/HP.

const std = @import("std");
const packet_crypto = @import("packet_crypto.zig");

/// RFC 9001 §5.2 initial salt for QUICv1.
pub const initial_salt_v1: [20]u8 = .{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

pub const secret_len: usize = 32;

pub const InitialSecrets = struct {
    client: [secret_len]u8,
    server: [secret_len]u8,
};

/// Derive client/server initial secrets from the destination connection ID.
pub fn deriveInitialSecrets(dcid: []const u8) InitialSecrets {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const initial_secret = Hkdf.extract(&initial_salt_v1, dcid);
    return .{
        .client = std.crypto.tls.hkdfExpandLabel(Hkdf, initial_secret, "client in", "", secret_len),
        .server = std.crypto.tls.hkdfExpandLabel(Hkdf, initial_secret, "server in", "", secret_len),
    };
}

pub fn clientKeys(dcid: []const u8) packet_crypto.PacketKeys {
    return packet_crypto.keysFromTrafficSecret(&deriveInitialSecrets(dcid).client);
}

pub fn serverKeys(dcid: []const u8) packet_crypto.PacketKeys {
    return packet_crypto.keysFromTrafficSecret(&deriveInitialSecrets(dcid).server);
}

/// RFC 9001 §5.8 — retry integrity AEAD key/nonce are FIXED QUICv1 constants
/// (NOT derived from the Initial secret). Every Retry path here is v1-only
/// (`issueRetry` hard-codes version 1; `consumeRetry` rejects `version != 1`),
/// so no version guard is needed today.
pub const retry_key_v1: [16]u8 = .{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
pub const retry_nonce_v1: [12]u8 = .{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
    0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

/// RFC 9001 §5.8 / Appendix A.4 — integrity tag over the Retry pseudo-packet:
/// AAD = ODCID Length (u8) ‖ ODCID ‖ Retry packet without tag, plaintext
/// empty, AEAD_AES_128_GCM with the fixed v1 constants above.
pub fn retryIntegrityTag(allocator: std.mem.Allocator, original_dcid: []const u8, retry_bytes_without_tag: []const u8) ![16]u8 {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const pseudo = try allocator.alloc(u8, 1 + original_dcid.len + retry_bytes_without_tag.len);
    defer allocator.free(pseudo);
    pseudo[0] = @intCast(original_dcid.len);
    @memcpy(pseudo[1 .. 1 + original_dcid.len], original_dcid);
    @memcpy(pseudo[1 + original_dcid.len ..], retry_bytes_without_tag);
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    var cipher: [0]u8 = undefined;
    Aes128Gcm.encrypt(&cipher, &tag, &.{}, pseudo, retry_nonce_v1, retry_key_v1);
    return tag;
}

/// RFC 9001 Appendix A.1 sample DCID.
pub const rfc9001_app_a_dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

test "RFC 9001 Appendix A.1 Initial secrets and keys KAT" {
    const secrets = deriveInitialSecrets(&rfc9001_app_a_dcid);

    // RFC 9001 Appendix A.1 — client/server initial secrets
    try std.testing.expectEqualSlices(u8, &comptimeHex(32, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"), &secrets.client);
    try std.testing.expectEqualSlices(u8, &comptimeHex(32, "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"), &secrets.server);

    const ck = clientKeys(&rfc9001_app_a_dcid);
    try std.testing.expectEqualSlices(u8, &comptimeHex(16, "1f369613dd76d5467730efcbe3b1a22d"), &ck.aead_key);
    try std.testing.expectEqualSlices(u8, &comptimeHex(12, "fa044b2f42a3fd3b46fb255c"), &ck.iv);
    try std.testing.expectEqualSlices(u8, &comptimeHex(16, "9f50449e04a0e810283a1e9933adedd2"), &ck.hp_key);

    const sk = serverKeys(&rfc9001_app_a_dcid);
    try std.testing.expectEqualSlices(u8, &comptimeHex(16, "cf3a5331653c364c88f0f379b6067e37"), &sk.aead_key);
    try std.testing.expectEqualSlices(u8, &comptimeHex(12, "0ac1493ca1905853b0bba03e"), &sk.iv);
    try std.testing.expectEqualSlices(u8, &comptimeHex(16, "c206b8d9b9f0f37644430b490eeaa314"), &sk.hp_key);
}

fn comptimeHex(comptime n: usize, comptime hex: *const [n * 2:0]u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "RFC 9001 Appendix A.4 Retry integrity tag KAT" {
    // Worked example: server Retry answering the A.2 Initial (ODCID =
    // 8394c8f03e515708). Wire packet ff000000010008f067a5502a4262b5746f6b656e
    // (token "token") carries integrity tag 04a265ba2eff4d829058fb3f0f2496ba.
    // External oracle: fails if the key/nonce are re-derived from the Initial
    // secret (the audit-v4 C1 bug) or the ODCID pseudo-packet prefix is lost.
    const odcid = comptimeHex(8, "8394c8f03e515708");
    const retry_without_tag = comptimeHex(20, "ff000000010008f067a5502a4262b5746f6b656e");
    const tag = try retryIntegrityTag(std.testing.allocator, &odcid, &retry_without_tag);
    try std.testing.expectEqualSlices(u8, &comptimeHex(16, "04a265ba2eff4d829058fb3f0f2496ba"), &tag);
}
