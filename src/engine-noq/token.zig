//! RFC 9000 §8.1 address-validation tokens — the noq `token.rs` port (C21).
//!
//! The token BYTES are server-local (a free choice per RFC); what a peer can
//! observe are the semantics: a Retry token is bound to the client's address
//! and expires (`retry_token_lifetime`, noq default 15 s); a NEW_TOKEN token
//! is bound to the client's IP, expires, and is single-use (anti-replay log).
//!
//! Construction mirrors noq `crypto::ring_like::RetryTokenKey`: a 64-byte
//! random master extracted with HKDF-SHA256 (empty salt), a per-token
//! AES-256-GCM key expanded with info = the 16-byte little-endian token nonce,
//! sealed under the all-zero AEAD nonce with empty AAD. Wire layout:
//!   type(1) || payload || aead_tag(16) || nonce(16 LE)
//! Retry (0) payload:     ip(0+4 | 1+16) || port(u16 BE) || odcid(u8 len + bytes) || issued(u64 BE secs)
//! Validation (1) payload: ip(0+4 | 1+16) || issued(u64 BE secs)

const std = @import("std");
const packet = @import("packet.zig");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const nonce_len: usize = 16;
pub const tag_len: usize = Aes256Gcm.tag_length;
pub const key_len: usize = Aes256Gcm.key_length;
/// Upper bound for a token on the wire (v6 retry token: 1+17+2+1+20+8+16+16).
pub const max_token_len: usize = 81;

pub const zero_aead_nonce: [Aes256Gcm.nonce_length]u8 = [_]u8{0} ** Aes256Gcm.nonce_length;

pub const TokenKey = struct {
    prk: [32]u8,

    /// noq RetryTokenKey::new: HKDF-SHA256 extract, empty salt, 64 random bytes.
    pub fn init(rng: std.Random) TokenKey {
        var master: [64]u8 = undefined;
        rng.bytes(&master);
        defer std.crypto.secureZero(u8, &master);
        return .{ .prk = Hkdf.extract("", &master) };
    }

    /// Deterministic master for tests (same construction, caller-supplied IKM).
    pub fn initFromMaster(master: [64]u8) TokenKey {
        return .{ .prk = Hkdf.extract("", &master) };
    }

    fn deriveAead(self: *const TokenKey, token_nonce: u128) [key_len]u8 {
        var nonce_bytes: [nonce_len]u8 = undefined;
        std.mem.writeInt(u128, &nonce_bytes, token_nonce, .little);
        var out: [key_len]u8 = undefined;
        Hkdf.expand(&out, &nonce_bytes, self.prk);
        return out;
    }

    /// seal_in_place_append_tag: ciphertext || tag appended, empty AAD.
    pub fn seal(self: *const TokenKey, token_nonce: u128, plaintext: []const u8, out: []u8) []u8 {
        var aead = self.deriveAead(token_nonce);
        defer std.crypto.secureZero(u8, &aead);
        var tag: [tag_len]u8 = undefined;
        Aes256Gcm.encrypt(out[0..plaintext.len], &tag, plaintext, "", zero_aead_nonce, aead);
        @memcpy(out[plaintext.len..][0..tag_len], &tag);
        return out[0 .. plaintext.len + tag_len];
    }

    /// open_in_place: verifies the tag; returns the plaintext or null.
    pub fn open(self: *const TokenKey, token_nonce: u128, sealed: []const u8, out: []u8) ?[]u8 {
        if (sealed.len < tag_len) return null;
        var aead = self.deriveAead(token_nonce);
        defer std.crypto.secureZero(u8, &aead);
        var tag: [tag_len]u8 = undefined;
        @memcpy(&tag, sealed[sealed.len - tag_len ..]);
        Aes256Gcm.decrypt(out[0 .. sealed.len - tag_len], sealed[0 .. sealed.len - tag_len], tag, "", zero_aead_nonce, aead) catch return null;
        return out[0 .. sealed.len - tag_len];
    }
};

pub const Ip = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

    pub fn eql(a: Ip, b: Ip) bool {
        if (@as(std.meta.Tag(Ip), a) != @as(std.meta.Tag(Ip), b)) return false;
        return switch (a) {
            .v4 => |x| std.mem.eql(u8, &x, &b.v4),
            .v6 => |x| std.mem.eql(u8, &x, &b.v6),
        };
    }
};

pub const Address = struct {
    ip: Ip,
    port: u16,

    pub fn eql(a: Address, b: Address) bool {
        return a.ip.eql(b.ip) and a.port == b.port;
    }
};

pub const Token = union(enum) {
    /// Token carried in a Retry packet: binds the client's full address and
    /// the original DCID, expires after `retry_token_lifetime`.
    retry: struct { address: Address, orig_dst_cid: packet.ConnectionId, issued_secs: u64 },
    /// Token carried in a NEW_TOKEN frame: binds the client's IP only (the
    /// port may change between connections), expires after a longer lifetime.
    validation: struct { ip: Ip, issued_secs: u64 },
};

const type_retry: u8 = 0;
const type_validation: u8 = 1;

fn encodeIp(ip: Ip, buf: []u8, index: *usize) void {
    switch (ip) {
        .v4 => |octets| {
            buf[index.*] = 0;
            index.* += 1;
            @memcpy(buf[index.*..][0..4], &octets);
            index.* += 4;
        },
        .v6 => |octets| {
            buf[index.*] = 1;
            index.* += 1;
            @memcpy(buf[index.*..][0..16], &octets);
            index.* += 16;
        },
    }
}

fn decodeIp(bytes: []const u8, index: *usize) ?Ip {
    if (bytes.len <= index.*) return null;
    switch (bytes[index.*]) {
        0 => {
            index.* += 1;
            if (bytes.len < index.* + 4) return null;
            var octets: [4]u8 = undefined;
            @memcpy(&octets, bytes[index.*..][0..4]);
            index.* += 4;
            return Ip{ .v4 = octets };
        },
        1 => {
            index.* += 1;
            if (bytes.len < index.* + 16) return null;
            var octets: [16]u8 = undefined;
            @memcpy(&octets, bytes[index.*..][0..16]);
            index.* += 16;
            return Ip{ .v6 = octets };
        },
        else => return null,
    }
}

/// Encode + seal a token. `nonce` must be unique per token (the caller fills it
/// from the CSPRNG). Returns the token bytes (type || payload || tag || nonce).
pub fn encode(key: *const TokenKey, token: Token, nonce: u128, out: []u8) []u8 {
    var plaintext: [max_token_len]u8 = undefined;
    var index: usize = 0;
    switch (token) {
        .retry => |r| {
            plaintext[index] = type_retry;
            index += 1;
            encodeIp(r.address.ip, &plaintext, &index);
            std.mem.writeInt(u16, plaintext[index..][0..2], r.address.port, .big);
            index += 2;
            plaintext[index] = @intCast(r.orig_dst_cid.len);
            index += 1;
            @memcpy(plaintext[index..][0..r.orig_dst_cid.len], r.orig_dst_cid.slice());
            index += r.orig_dst_cid.len;
            std.mem.writeInt(u64, plaintext[index..][0..8], r.issued_secs, .big);
            index += 8;
        },
        .validation => |v| {
            plaintext[index] = type_validation;
            index += 1;
            encodeIp(v.ip, &plaintext, &index);
            std.mem.writeInt(u64, plaintext[index..][0..8], v.issued_secs, .big);
            index += 8;
        },
    }
    const sealed_len = index + tag_len;
    _ = key.seal(nonce, plaintext[0..index], out[0..sealed_len]);
    std.mem.writeInt(u128, out[sealed_len..][0..nonce_len], nonce, .little);
    return out[0 .. sealed_len + nonce_len];
}

/// Decrypt + decode a token. Any failure (bad tag, bad shape, trailing bytes)
/// yields null — the caller proceeds as if the client sent no token
/// (RFC 9000 §8.1.3: an invalid token MUST NOT close the connection).
pub fn decode(key: *const TokenKey, token_bytes: []const u8) ?Token {
    if (token_bytes.len < 1 + tag_len + nonce_len) return null;
    // An oversized token is garbage, not a crash: the plaintext scratch is
    // max_token_len bytes and a longer input would slice past it.
    if (token_bytes.len > max_token_len + nonce_len) return null;
    const sealed = token_bytes[0 .. token_bytes.len - nonce_len];
    const nonce = std.mem.readInt(u128, token_bytes[token_bytes.len - nonce_len ..][0..nonce_len], .little);
    var plaintext: [max_token_len]u8 = undefined;
    const data = key.open(nonce, sealed, &plaintext) orelse return null;
    var index: usize = 0;
    if (data.len == 0) return null;
    const ty = data[0];
    index += 1;
    switch (ty) {
        type_retry => {
            const ip = decodeIp(data, &index) orelse return null;
            if (data.len < index + 2) return null;
            const port = std.mem.readInt(u16, data[index..][0..2], .big);
            index += 2;
            if (data.len <= index) return null;
            const cid_len = data[index];
            index += 1;
            if (data.len < index + cid_len + 8) return null;
            const cid = packet.ConnectionId.init(data[index..][0..cid_len]) catch return null;
            index += cid_len;
            const issued_secs = std.mem.readInt(u64, data[index..][0..8], .big);
            index += 8;
            if (index != data.len) return null;
            return Token{ .retry = .{ .address = .{ .ip = ip, .port = port }, .orig_dst_cid = cid, .issued_secs = issued_secs } };
        },
        type_validation => {
            const ip = decodeIp(data, &index) orelse return null;
            if (data.len < index + 8) return null;
            const issued_secs = std.mem.readInt(u64, data[index..][0..8], .big);
            index += 8;
            if (index != data.len) return null;
            return Token{ .validation = .{ .ip = ip, .issued_secs = issued_secs } };
        },
        else => return null,
    }
}

/// A validated Retry token's contents, returned to the accept path.
pub const RetryInfo = struct {
    orig_dst_cid: packet.ConnectionId,
    issued_secs: u64,
};

/// Retry token validation (noq IncomingToken::from_header Retry arm): the
/// token must seal-open, bind the sender's exact address, and be unexpired.
/// A null here is SOFT at the endpoint (falls through to fresh-Retry/
/// unvalidated proceed, RFC 9000 §8.1.3); noq additionally HARD-refuses a
/// decoded-but-mismatched Retry token with an INVALID_TOKEN close
/// (InvalidRetryTokenError) — a parity gap.
pub fn validateRetry(
    key: *const TokenKey,
    token_bytes: []const u8,
    remote: Address,
    now_secs: u64,
    retry_token_lifetime_secs: u64,
) ?RetryInfo {
    const token = decode(key, token_bytes) orelse return null;
    switch (token) {
        .retry => |r| {
            if (!r.address.eql(remote)) return null;
            if (r.issued_secs + retry_token_lifetime_secs < now_secs) return null;
            return .{ .orig_dst_cid = r.orig_dst_cid, .issued_secs = r.issued_secs };
        },
        .validation => return null,
    }
}

/// NEW_TOKEN validation (noq IncomingToken::from_header Validation arm): binds
/// the sender's IP (port free), unexpired, single-use against `log`. All
/// failures are SOFT — the caller proceeds with an unvalidated address.
pub fn validateNewToken(
    key: *const TokenKey,
    token_bytes: []const u8,
    remote_ip: Ip,
    now_secs: u64,
    lifetime_secs: u64,
    log: *TokenLog,
) bool {
    const token = decode(key, token_bytes) orelse return false;
    switch (token) {
        .validation => |v| {
            if (!v.ip.eql(remote_ip)) return false;
            if (v.issued_secs + lifetime_secs < now_secs) return false;
            return log.checkAndInsert(trailingNonce(token_bytes), v.issued_secs, lifetime_secs, now_secs);
        },
        .retry => return false,
    }
}

/// The trailing 16-byte little-endian nonce of an encoded token.
fn trailingNonce(token_bytes: []const u8) u128 {
    return std.mem.readInt(u128, token_bytes[token_bytes.len - nonce_len ..][0..nonce_len], .little);
}

/// Stateless-reset token derivation (noq ResetToken::new — endpoint.rs:319):
/// HMAC-SHA256 under the endpoint's reset key over the connection ID,
/// truncated to the 16-byte wire token. The SAME derivation backs the
/// endpoint's own connection tokens (TP/NEW_CONNECTION_ID) and the resets it
/// sends for unknown CIDs — that shared key is what makes a sent reset
/// recognizable to the peer.
pub fn resetToken(hmac_key: []const u8, cid: packet.ConnectionId) [packet.stateless_reset_token_len]u8 {
    var signature: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&signature, cid.slice(), hmac_key);
    var out: [packet.stateless_reset_token_len]u8 = undefined;
    @memcpy(&out, signature[0..packet.stateless_reset_token_len]);
    return out;
}

/// Anti-replay log for NEW_TOKEN tokens (noq TokenLog). Exact-match nonce set
/// with expiry purge — strictly stronger than noq's probabilistic
/// BloomTokenLog (false positives are safe: the token is simply ignored).
pub const TokenLog = struct {
    pub const max_entries: usize = 65536;

    entries: std.AutoHashMap(u128, u64),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) TokenLog {
        return .{ .entries = std.AutoHashMap(u128, u64).init(allocator), .allocator = allocator };
    }

    pub fn deinit(self: *TokenLog) void {
        self.entries.deinit();
    }

    /// True when the nonce is fresh and was recorded; false on replay. A full
    /// log errs toward false-positive (safe: the token is ignored).
    pub fn checkAndInsert(self: *TokenLog, nonce: u128, issued_secs: u64, lifetime_secs: u64, now_secs: u64) bool {
        // Purge expired entries lazily on insert.
        var it = self.entries.iterator();
        var stale: [64]u128 = undefined;
        var stale_len: usize = 0;
        while (it.next()) |e| {
            if (e.value_ptr.* + lifetime_secs < now_secs) {
                if (stale_len < stale.len) {
                    stale[stale_len] = e.key_ptr.*;
                    stale_len += 1;
                } else break;
            }
        }
        for (stale[0..stale_len]) |k| _ = self.entries.remove(k);
        if (self.entries.contains(nonce)) return false;
        if (self.entries.count() >= max_entries) return false;
        self.entries.put(nonce, issued_secs) catch return false;
        return true;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const test_master = [_]u8{0xA7} ** 64;

fn testKey() TokenKey {
    return TokenKey.initFromMaster(test_master);
}

test "C21: retry token round trip (v4 + v6) with address/expiry binding" {
    const key = testKey();
    const odcid = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const remote_v4: Address = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 4433 };
    const remote_v6: Address = .{ .ip = .{ .v6 = ([_]u8{0} ** 15) ++ [_]u8{1} }, .port = 4434 };

    for ([_]Address{ remote_v4, remote_v6 }) |remote| {
        var buf: [max_token_len + nonce_len]u8 = undefined;
        const bytes = encode(&key, .{ .retry = .{ .address = remote, .orig_dst_cid = odcid, .issued_secs = 1000 } }, 0x11223344556677889900AABBCCDDEEFF, &buf);

        const info = validateRetry(&key, bytes, remote, 1000, 15) orelse return error.UnexpectedState;
        try std.testing.expectEqualSlices(u8, odcid.slice(), info.orig_dst_cid.slice());
        try std.testing.expectEqual(@as(u64, 1000), info.issued_secs);

        // Wrong address (ip or port) → reject.
        var other: Address = remote;
        other.port +%= 1;
        try std.testing.expect(validateRetry(&key, bytes, other, 1000, 15) == null);
        // Expired → reject (boundary: issued + 15 is still valid; +16 is not).
        try std.testing.expect(validateRetry(&key, bytes, remote, 1000 + 15, 15) != null);
        try std.testing.expect(validateRetry(&key, bytes, remote, 1000 + 16, 15) == null);
    }
}

test "C21: NEW_TOKEN validation binds IP not port, expires, and is single-use" {
    const key = testKey();
    const ip: Ip = .{ .v4 = .{ 192, 0, 2, 7 } };
    var buf: [max_token_len + nonce_len]u8 = undefined;
    const bytes = encode(&key, .{ .validation = .{ .ip = ip, .issued_secs = 2000 } }, 42, &buf);

    var log = TokenLog.init(std.testing.allocator);
    defer log.deinit();

    // Fresh: accepted (any port — the IP binds).
    try std.testing.expect(validateNewToken(&key, bytes, ip, 2000, 604800, &log));
    // Replay: rejected by the anti-replay log.
    try std.testing.expect(!validateNewToken(&key, bytes, ip, 2000, 604800, &log));
    // Wrong IP: rejected.
    try std.testing.expect(!validateNewToken(&key, bytes, .{ .v4 = .{ 192, 0, 2, 8 } }, 2000, 604800, &log));
    // Expired: rejected.
    try std.testing.expect(!validateNewToken(&key, bytes, ip, 2000 + 604800 + 1, 604800, &log));
    // A retry token is NOT a NEW_TOKEN token (type confusion must not validate).
    var rbuf: [max_token_len + nonce_len]u8 = undefined;
    const rbytes = encode(&key, .{ .retry = .{ .address = .{ .ip = ip, .port = 1 }, .orig_dst_cid = try packet.ConnectionId.init(&.{1}), .issued_secs = 2000 } }, 43, &rbuf);
    try std.testing.expect(!validateNewToken(&key, rbytes, ip, 2000, 604800, &log));
}

test "E3: reset token derivation matches the noq HMAC-SHA256 truncation (pinned vector)" {
    const cid = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    // Pinned from an independent HMAC-SHA256 computation (key 64x0xA7, the
    // test master) — a drift in the derivation is a wire break.
    const expected = [_]u8{ 0x5b, 0xe4, 0x4f, 0xd3, 0x8b, 0xbd, 0x38, 0x68, 0xde, 0xab, 0x3a, 0xaa, 0x9e, 0x0d, 0x74, 0xfb };
    try std.testing.expectEqualSlices(u8, &expected, &resetToken(&test_master, cid));
}

test "C21: tampered or foreign tokens never open (soft-decode discipline)" {
    const key = testKey();
    var buf: [max_token_len + nonce_len]u8 = undefined;
    const bytes = encode(&key, .{ .validation = .{ .ip = .{ .v4 = .{ 10, 0, 0, 1 } }, .issued_secs = 1 } }, 7, &buf);

    // Bit-flip anywhere → tag failure → null (never a decode into garbage).
    for (0..bytes.len) |i| {
        var tampered: [max_token_len + nonce_len]u8 = undefined;
        @memcpy(tampered[0..bytes.len], bytes);
        tampered[i] ^= 0x01;
        try std.testing.expect(decode(&key, tampered[0..bytes.len]) == null);
    }
    // A different key does not open the token.
    const other_key = TokenKey.initFromMaster([_]u8{0x5A} ** 64);
    try std.testing.expect(decode(&other_key, bytes) == null);
    // Truncations and empties decode to null.
    try std.testing.expect(decode(&key, bytes[0 .. bytes.len - 1]) == null);
    try std.testing.expect(decode(&key, "") == null);
    try std.testing.expect(decode(&key, &([_]u8{0} ** 16)) == null);
    // An oversized unauthenticated token is garbage, not a crash (the
    // one-packet accept-path finding from independent review).
    var huge: [1200]u8 = undefined;
    @memset(&huge, 0x42);
    try std.testing.expect(decode(&key, &huge) == null);
}
