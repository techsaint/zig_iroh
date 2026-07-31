//! Packet protection: AEAD payload + two-phase header protection.
//!
//! HP sample is taken at a FIXED offset `pn_offset + 4` (RFC 9001 §5.4 / noq
//! `PartialDecode::decrypt_header`). Key-phase selection: current / prev / next.
//!
//! Keys may come from a `TrafficSecret` (caller derives AEAD+HP) or from
//! explicit test/oracle material. Uses `std.crypto` AES-128-GCM + AES-ECB.

const std = @import("std");
const Aes128 = std.crypto.core.aes.Aes128;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const sample_size: usize = 16;
pub const tag_len: usize = Aes128Gcm.tag_length;
pub const aead_key_len: usize = Aes128Gcm.key_length;
pub const iv_len: usize = Aes128Gcm.nonce_length;
pub const hp_key_len: usize = 16;

/// A16 AEAD limits (RFC 9001 §6.6 / Appendix B.1) for AES-128-GCM, the only
/// AEAD this port negotiates. Values match rustls 0.23's ring provider
/// (`crypto/ring/tls13.rs`: QUIC confidentiality 1<<23, integrity 1<<52),
/// which noq 1.1.0 delegates `PacketKey::confidentiality_limit` /
/// `integrity_limit` to (noq-proto crypto/rustls.rs:663-669).
/// Maximum number of packets that may be sent using a single key.
pub const confidentiality_limit: u64 = 1 << 23;
/// Maximum number of incoming packets that may fail authentication before the
/// connection must be abandoned (noq closes AEAD_LIMIT_REACHED past this).
pub const integrity_limit: u64 = 1 << 52;
/// Perform key updates this many packets before the AEAD confidentiality
/// limit. Chosen arbitrarily by noq, intended to be large enough to prevent
/// spurious connection loss (noq connection/packet_crypto.rs:22).
pub const key_update_margin: u64 = 10_000;
pub const Aes128Enc = @TypeOf(Aes128.initEnc(.{0} ** hp_key_len));

pub const Error = error{
    PacketTooShort,
    MalformedHeaderProtection,
    AuthenticationFailed,
    MissingKeys,
    InvalidKeyPhase,
};

pub const PacketKeys = struct {
    aead_key: [aead_key_len]u8,
    iv: [iv_len]u8,
    hp_key: [hp_key_len]u8,
    hp_ctx: Aes128Enc,

    pub fn init(
        aead_key: [aead_key_len]u8,
        iv: [iv_len]u8,
        hp_key: [hp_key_len]u8,
    ) PacketKeys {
        return .{
            .aead_key = aead_key,
            .iv = iv,
            .hp_key = hp_key,
            .hp_ctx = Aes128.initEnc(hp_key),
        };
    }
};

/// Derive AEAD key / IV / HP key from a TLS 1.3 traffic secret using the QUIC
/// labels (`quic key`, `quic iv`, `quic hp`) — matches TLS-QUIC key schedule
/// shape used by rustls/picotls (`tls13 ` prefix via hkdfExpandLabel).
/// RFC 9001 §6.3 — derive the next 1-RTT traffic secret from the current one.
pub fn nextTrafficSecret(secret: []const u8) [aead_key_len * 2]u8 {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const out_len = Hkdf.prk_length;
    var prk: [Hkdf.prk_length]u8 = undefined;
    if (secret.len == Hkdf.prk_length) {
        @memcpy(prk[0..], secret[0..Hkdf.prk_length]);
    } else {
        prk = Hkdf.extract(&.{}, secret);
    }
    return std.crypto.tls.hkdfExpandLabel(Hkdf, prk, "quic ku", "", out_len);
}

pub fn keysFromTrafficSecret(secret: []const u8) PacketKeys {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    var prk: [Hkdf.prk_length]u8 = undefined;
    // Treat the traffic secret as already-extracted PRK material when len matches;
    // otherwise extract with empty salt (test/oracle secrets are often raw 32 bytes).
    if (secret.len == Hkdf.prk_length) {
        @memcpy(prk[0..], secret[0..Hkdf.prk_length]);
    } else {
        prk = Hkdf.extract(&.{}, secret);
    }
    const key = std.crypto.tls.hkdfExpandLabel(Hkdf, prk, "quic key", "", aead_key_len);
    const iv = std.crypto.tls.hkdfExpandLabel(Hkdf, prk, "quic iv", "", iv_len);
    const hp = std.crypto.tls.hkdfExpandLabel(Hkdf, prk, "quic hp", "", hp_key_len);
    return PacketKeys.init(key, iv, hp);
}

/// QUIC key updates rotate the packet AEAD key and IV while header protection
/// remains direction-specific and unchanged for the connection lifetime.
pub fn keysFromKeyUpdate(secret: []const u8, preserved_hp_key: [hp_key_len]u8) PacketKeys {
    var keys = keysFromTrafficSecret(secret);
    keys.hp_key = preserved_hp_key;
    keys.hp_ctx = Aes128.initEnc(preserved_hp_key);
    return keys;
}

pub fn nonceForPacket(iv: [iv_len]u8, packet_number: u64) [iv_len]u8 {
    var nonce = iv;
    // XOR the packet number into the last 8 bytes of the IV (RFC 9001).
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const shift: u6 = @intCast((7 - i) * 8);
        nonce[iv_len - 8 + i] ^= @truncate(packet_number >> shift);
    }
    return nonce;
}

/// AES-ECB header-protection mask from a 16-byte sample (AES-128).
pub fn headerProtectionMask(hp_key: [hp_key_len]u8, sample: *const [sample_size]u8) [sample_size]u8 {
    const ctx = Aes128.initEnc(hp_key);
    return headerProtectionMaskWithContext(&ctx, sample);
}

pub fn headerProtectionMaskWithContext(ctx: *const Aes128Enc, sample: *const [sample_size]u8) [sample_size]u8 {
    var mask: [sample_size]u8 = undefined;
    ctx.encrypt(&mask, sample);
    return mask;
}

fn xorHeaderProtection(packet: []u8, pn_offset: usize, ctx: *const Aes128Enc, decrypting: bool) Error!void {
    if (packet.len < pn_offset + 4 + sample_size) return error.PacketTooShort;

    var sample: [sample_size]u8 = undefined;
    @memcpy(sample[0..], packet[pn_offset + 4 ..][0..sample_size]);
    const mask = headerProtectionMaskWithContext(ctx, &sample);

    const long_header = (packet[0] & 0x80) != 0;
    const bits: u8 = if (long_header) 0x0f else 0x1f;

    // Match rustls: when decrypting, determine pn_len after unmasking first byte;
    // when encrypting, determine pn_len from plaintext first byte before mask.
    const first_plain: u8 = if (decrypting)
        packet[0] ^ (mask[0] & bits)
    else
        packet[0];
    const pn_len: usize = @as(usize, first_plain & 0x03) + 1;
    if (pn_offset + pn_len > packet.len) return error.MalformedHeaderProtection;

    packet[0] ^= mask[0] & bits;
    var i: usize = 0;
    while (i < pn_len) : (i += 1) {
        packet[pn_offset + i] ^= mask[1 + i];
    }
}

/// RFC 9000 §17.2/§17.3: reserved bits (long header mask 0x0c, short header
/// mask 0x18) must be zero once header protection is removed. Mirror of noq
/// `Packet::reserved_bits_valid` (packet.rs). The connection receive path
/// checks this only AFTER the packet authenticates — a keyless attacker's
/// garbage must keep failing AEAD silently, never protocol-close the conn.
pub fn reservedBitsValid(first_byte: u8) bool {
    const long_header = (first_byte & 0x80) != 0;
    const mask: u8 = if (long_header) 0x0c else 0x18;
    return first_byte & mask == 0;
}

pub fn encryptHeader(packet: []u8, pn_offset: usize, hp_key: [hp_key_len]u8) Error!void {
    const ctx = Aes128.initEnc(hp_key);
    try xorHeaderProtection(packet, pn_offset, &ctx, false);
}

pub fn decryptHeader(packet: []u8, pn_offset: usize, hp_key: [hp_key_len]u8) Error!void {
    const ctx = Aes128.initEnc(hp_key);
    try xorHeaderProtection(packet, pn_offset, &ctx, true);
}

pub fn encryptHeaderWithKeys(packet: []u8, pn_offset: usize, keys: PacketKeys) Error!void {
    try xorHeaderProtection(packet, pn_offset, &keys.hp_ctx, false);
}

pub fn decryptHeaderWithKeys(packet: []u8, pn_offset: usize, keys: PacketKeys) Error!void {
    try xorHeaderProtection(packet, pn_offset, &keys.hp_ctx, true);
}

pub fn encryptPayload(
    packet: []u8,
    header_len: usize,
    packet_number: u64,
    keys: PacketKeys,
) Error!void {
    if (packet.len < header_len + tag_len) return error.PacketTooShort;
    const payload_end = packet.len - tag_len;
    if (payload_end < header_len) return error.PacketTooShort;

    const header = packet[0..header_len];
    const plain = packet[header_len..payload_end];
    const nonce = nonceForPacket(keys.iv, packet_number);
    var tag: [tag_len]u8 = undefined;
    Aes128Gcm.encrypt(plain, &tag, plain, header, nonce, keys.aead_key);
    @memcpy(packet[payload_end..][0..tag_len], &tag);
}

pub fn decryptPayload(
    packet: []u8,
    header_len: usize,
    packet_number: u64,
    keys: PacketKeys,
) Error!void {
    if (packet.len < header_len + tag_len) return error.PacketTooShort;
    const payload_end = packet.len - tag_len;
    const header = packet[0..header_len];
    const cipher = packet[header_len..payload_end];
    var tag: [tag_len]u8 = undefined;
    @memcpy(&tag, packet[payload_end..][0..tag_len]);
    const nonce = nonceForPacket(keys.iv, packet_number);
    // std.crypto leaves the destination undefined on authentication failure.
    // Callers must pass a trial/packet-owned buffer, never borrowed wire memory.
    Aes128Gcm.decrypt(cipher, cipher, tag, header, nonce, keys.aead_key) catch {
        return error.AuthenticationFailed;
    };
}

pub const KeyPhase = enum { current, prev, next };

/// Minimal CryptoState for 1-RTT key-phase selection (current / prev / next).
pub const CryptoState = struct {
    current: ?PacketKeys = null,
    prev: ?PacketKeys = null,
    next: ?PacketKeys = null,
    /// Current authenticated receive key-phase bit for 1-RTT short headers.
    key_phase: bool = false,

    pub fn select(self: *const CryptoState, phase: KeyPhase) Error!PacketKeys {
        const slot = switch (phase) {
            .current => self.current,
            .prev => self.prev,
            .next => self.next,
        };
        return slot orelse error.MissingKeys;
    }

    /// Pick keys for an incoming packet's key-phase bit (Data space).
    pub fn selectForIncoming(self: *const CryptoState, packet_key_phase: bool) Error!struct { KeyPhase, PacketKeys } {
        if (packet_key_phase == self.key_phase) {
            return .{ .current, try self.select(.current) };
        }
        // Prefer next (peer updated), else prev (we updated, peer still on old).
        if (self.next) |keys| {
            return .{ .next, keys };
        }
        if (self.prev) |keys| {
            return .{ .prev, keys };
        }
        return error.InvalidKeyPhase;
    }

    pub fn protect(
        self: *const CryptoState,
        packet: []u8,
        header_len: usize,
        pn_offset: usize,
        packet_number: u64,
        phase: KeyPhase,
    ) Error!void {
        const keys = try self.select(phase);
        try encryptPayload(packet, header_len, packet_number, keys);
        try encryptHeaderWithKeys(packet, pn_offset, keys);
    }

    pub fn unprotect(
        self: *const CryptoState,
        packet: []u8,
        header_len_without_pn: usize,
        pn_offset: usize,
        packet_key_phase: bool,
    ) Error!struct { packet_number_truncated_len: u8, full_header_len: usize, keys: PacketKeys, phase: KeyPhase } {
        // First decrypt header with candidate keys. For short headers we need HP
        // before we know pn_len; try current then next/prev.
        const candidates = [_]KeyPhase{ .current, .next, .prev };
        var last_err: Error = error.MissingKeys;
        for (candidates) |phase| {
            const keys = self.select(phase) catch |err| {
                last_err = err;
                continue;
            };
            // Work on a copy for header trial only if phase bit mismatch path needs it —
            // simpler: decrypt header in place with keys matching the packet bit after.
            _ = packet_key_phase;
            var trial: [4096]u8 = undefined;
            if (packet.len > trial.len) return error.PacketTooShort;
            @memcpy(trial[0..packet.len], packet);
            decryptHeaderWithKeys(trial[0..packet.len], pn_offset, keys) catch |err| {
                last_err = err;
                continue;
            };
            const pn_len: u8 = @intCast((trial[0] & 0x03) + 1);
            const header_len = header_len_without_pn + pn_len;
            decryptPayload(trial[0..packet.len], header_len, 0, keys) catch {
                // PN not yet expanded — caller must reconstruct then decrypt payload.
                // Here we only prove HP works; return keys + pn_len.
                @memcpy(packet, trial[0..packet.len]);
                return .{
                    .packet_number_truncated_len = pn_len,
                    .full_header_len = header_len,
                    .keys = keys,
                    .phase = phase,
                };
            };
            @memcpy(packet, trial[0..packet.len]);
            return .{
                .packet_number_truncated_len = pn_len,
                .full_header_len = header_len,
                .keys = keys,
                .phase = phase,
            };
        }
        return last_err;
    }
};

test "header protection round-trips short header PN" {
    var pkt = [_]u8{
        0x40 | 0x01, // short, fixed bit, pn_len=2
        0x11, 0x22, 0x33, 0x44, // dcid 4
        0xab, 0xcd, // pn
    } ++ [_]u8{0x5a} ** 32; // sample + payload padding

    const keys = PacketKeys.init(.{0x01} ** 16, .{0x02} ** 12, .{0x03} ** 16);
    const pn_offset: usize = 1 + 4;
    const original = pkt;
    try encryptHeaderWithKeys(&pkt, pn_offset, keys);
    try std.testing.expect(!std.mem.eql(u8, pkt[0..6], original[0..6]));
    try decryptHeaderWithKeys(&pkt, pn_offset, keys);
    try std.testing.expectEqualSlices(u8, original[0..], pkt[0..]);
}

test "AEAD payload round-trips with PN nonce" {
    var buf: [64]u8 = undefined;
    const header = "hdr!!!!!"; // 8 bytes
    @memcpy(buf[0..8], header);
    const plain = "ping-body";
    @memcpy(buf[8 .. 8 + plain.len], plain);
    const total = 8 + plain.len + tag_len;
    // zero tag region
    @memset(buf[8 + plain.len .. total], 0);

    const keys = PacketKeys.init(.{0x10} ** 16, .{0x20} ** 12, .{0x30} ** 16);
    try encryptPayload(buf[0..total], 8, 7, keys);
    try std.testing.expect(!std.mem.eql(u8, buf[8 .. 8 + plain.len], plain));
    try decryptPayload(buf[0..total], 8, 7, keys);
    try std.testing.expectEqualSlices(u8, plain, buf[8 .. 8 + plain.len]);
}

test "AEAD auth failure mutates only caller-owned trial buffer" {
    var wire: [64]u8 = undefined;
    const header = "hdr!!!!!";
    @memcpy(wire[0..8], header);
    const plain = "ping-body";
    @memcpy(wire[8 .. 8 + plain.len], plain);
    const total = 8 + plain.len + tag_len;
    @memset(wire[8 + plain.len .. total], 0);

    const keys = PacketKeys.init(.{0x10} ** 16, .{0x20} ** 12, .{0x30} ** 16);
    const wrong = PacketKeys.init(.{0x11} ** 16, .{0x20} ** 12, .{0x30} ** 16);
    try encryptPayload(wire[0..total], 8, 7, keys);
    const saved_wire = wire;

    var trial = wire;
    try std.testing.expectError(error.AuthenticationFailed, decryptPayload(trial[0..total], 8, 7, wrong));
    try std.testing.expectEqualSlices(u8, saved_wire[0..total], wire[0..total]);
}

test "cached header protection context matches raw key mask" {
    const keys = PacketKeys.init(.{0x01} ** 16, .{0x02} ** 12, .{0x03} ** 16);
    const sample = [_]u8{0x55} ** sample_size;
    const raw = headerProtectionMask(keys.hp_key, &sample);
    const cached = headerProtectionMaskWithContext(&keys.hp_ctx, &sample);
    try std.testing.expectEqualSlices(u8, &raw, &cached);
}

test "key update rotates AEAD and IV while preserving header protection" {
    const current_secret = [_]u8{0x11} ** 32;
    const current = keysFromTrafficSecret(&current_secret);
    const next_secret = nextTrafficSecret(&current_secret);
    const raw_next = keysFromTrafficSecret(&next_secret);
    const updated = keysFromKeyUpdate(&next_secret, current.hp_key);

    try std.testing.expectEqualSlices(u8, &raw_next.aead_key, &updated.aead_key);
    try std.testing.expectEqualSlices(u8, &raw_next.iv, &updated.iv);
    try std.testing.expectEqualSlices(u8, &current.hp_key, &updated.hp_key);
    try std.testing.expect(!std.mem.eql(u8, &current.aead_key, &updated.aead_key));
    try std.testing.expect(!std.mem.eql(u8, &current.iv, &updated.iv));
    try std.testing.expect(!std.mem.eql(u8, &raw_next.hp_key, &updated.hp_key));
}

test "key-phase selection current/prev/next" {
    var state: CryptoState = .{
        .current = PacketKeys.init(.{1} ** 16, .{1} ** 12, .{1} ** 16),
        .prev = PacketKeys.init(.{2} ** 16, .{2} ** 12, .{2} ** 16),
        .next = PacketKeys.init(.{3} ** 16, .{3} ** 12, .{3} ** 16),
        .key_phase = false,
    };
    const cur = try state.select(.current);
    try std.testing.expectEqual(@as(u8, 1), cur.aead_key[0]);
    const pair = try state.selectForIncoming(true); // != key_phase → next
    try std.testing.expect(pair[0] == .next);
    try std.testing.expectEqual(@as(u8, 3), pair[1].aead_key[0]);
}

// ---------------------------------------------------------------------------
// N-3 adversarial (stateful): key-update fail-closed under malformed phase bits.
// These are NOT pure byte-decoder fuzz — they fixture a CryptoState and assert
// the guard returns InvalidKeyPhase (no UB / no default keys).
// ---------------------------------------------------------------------------

test "N-3-adversarial selectForIncoming fails closed when phase bit has no keys" {
    // Only current keys installed; peer key-phase flipped → no next/prev → reject.
    const state: CryptoState = .{
        .current = PacketKeys.init(.{1} ** 16, .{1} ** 12, .{1} ** 16),
        .prev = null,
        .next = null,
        .key_phase = false,
    };
    try std.testing.expectError(error.InvalidKeyPhase, state.selectForIncoming(true));
    // Matching phase still works.
    const ok = try state.selectForIncoming(false);
    try std.testing.expect(ok[0] == .current);
}

test "N-3-adversarial selectForIncoming fails closed with empty CryptoState" {
    const state: CryptoState = .{ .key_phase = false };
    try std.testing.expectError(error.MissingKeys, state.selectForIncoming(false));
    try std.testing.expectError(error.InvalidKeyPhase, state.selectForIncoming(true));
}

test "N-3-adversarial selectForIncoming prefers next then prev under phase flip" {
    const state: CryptoState = .{
        .current = PacketKeys.init(.{1} ** 16, .{1} ** 12, .{1} ** 16),
        .prev = PacketKeys.init(.{2} ** 16, .{2} ** 12, .{2} ** 16),
        .next = null,
        .key_phase = true, // we updated; peer still on old (false)
    };
    const pair = try state.selectForIncoming(false);
    try std.testing.expect(pair[0] == .prev);
    try std.testing.expectEqual(@as(u8, 2), pair[1].aead_key[0]);
}

test "N-3-adversarial selectForIncoming rejects after next consumed (no prev)" {
    // Simulate post-update window closed: only current, phase already flipped.
    const state: CryptoState = .{
        .current = PacketKeys.init(.{9} ** 16, .{9} ** 12, .{9} ** 16),
        .prev = null,
        .next = null,
        .key_phase = true,
    };
    // Replay old phase bit (false) with no prev keys → fail-closed.
    try std.testing.expectError(error.InvalidKeyPhase, state.selectForIncoming(false));
}
