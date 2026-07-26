//! The BLAKE3 hash used throughout iroh, ported to Zig.
//!
//! Mirrors `original/iroh-blobs/src/hash.rs` (n0-computer/iroh, Apache-2.0/MIT).
//! A blob's `Hash` is the 32-byte BLAKE3 root hash of its content. With wire
//! interop required (plan Q-A = yes), this type must agree byte-for-byte with
//! iroh's `Hash`: same bytes, same lowercase-hex display.

const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;

pub const HashError = error{
    InvalidEncoding,
};

pub const Hash = struct {
    bytes: [32]u8,

    /// Hash of the empty input (`b""`). Cross-checked against iroh's
    /// `Hash::EMPTY` constant — this is our fidelity anchor.
    pub const empty: Hash = .{ .bytes = .{
        175, 19,  73,  185, 245, 249, 161, 166, 160, 64,  77,
        234, 54,  220, 201, 73,  155, 203, 37,  201, 173, 193,
        18,  183, 204, 154, 147, 202, 228, 31,  50,  98,
    } };

    /// BLAKE3 hash of `data`. Equivalent to iroh's `Hash::new`.
    pub fn of(data: []const u8) Hash {
        var out: [32]u8 = undefined;
        Blake3.hash(data, &out, .{});
        return .{ .bytes = out };
    }

    pub fn fromBytes(bytes: [32]u8) Hash {
        return .{ .bytes = bytes };
    }

    pub fn fromHex(s: []const u8) HashError!Hash {
        if (s.len != 64) return error.InvalidEncoding;
        for (s) |c| {
            if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return error.InvalidEncoding;
        }
        var raw: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&raw, s) catch return error.InvalidEncoding;
        return fromBytes(raw);
    }

    /// Parse lowercase hex (64 chars) or standard RFC 4648 base32 no-pad,
    /// matching iroh's `Hash::from_str`. This intentionally does not accept
    /// z-base-32 DNS names.
    pub fn parse(s: []const u8) HashError!Hash {
        return switch (s.len) {
            64 => fromHex(s),
            52 => fromBase32NoPad(s),
            else => error.InvalidEncoding,
        };
    }

    pub fn from_str(s: []const u8) HashError!Hash {
        return parse(s);
    }

    fn fromBase32NoPad(s: []const u8) HashError!Hash {
        var raw: [32]u8 = undefined;
        const n = base32NoPadDecode(s, &raw) catch return error.InvalidEncoding;
        if (n != 32) return error.InvalidEncoding;
        return fromBytes(raw);
    }

    pub fn eql(self: Hash, other: Hash) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    /// Lowercase hex (64 chars), matching iroh's `Display` / `to_hex`.
    pub fn toHex(self: Hash) [64]u8 {
        return std.fmt.bytesToHex(self.bytes, .lower);
    }

    /// First 5 bytes as lowercase hex (10 chars), matching iroh's `fmt_short`.
    pub fn fmtShort(self: Hash) [10]u8 {
        return std.fmt.bytesToHex(self.bytes[0..5].*, .lower);
    }
};

const BASE32_NOPAD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32Symbol(c: u8) ?u5 {
    const upper = std.ascii.toUpper(c);
    for (BASE32_NOPAD, 0..) |s, i| {
        if (s == upper) return @intCast(i);
    }
    return null;
}

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

test "hash of empty input matches iroh Hash::EMPTY (byte-for-byte)" {
    const h = Hash.of("");
    try std.testing.expect(h.eql(Hash.empty));
    try std.testing.expectEqualStrings(
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        &h.toHex(),
    );
}

test "fmtShort is first 5 bytes of hex" {
    try std.testing.expectEqualStrings("af1349b9f5", &Hash.empty.fmtShort());
}

test "fromBytes / toHex round-trips" {
    const h = Hash.fromBytes(Hash.empty.bytes);
    try std.testing.expect(h.eql(Hash.empty));
}

test "parse accepts lowercase hex and standard base32 no-pad only" {
    const hex = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const base32 = "V4JUTOPV7GQ2NICAJXVDNXGJJGN4WJOJVXARFN6MTKJ4VZA7GJRA";
    const empty = try Hash.parse(hex);
    try std.testing.expect(empty.eql(Hash.empty));
    try std.testing.expect((try Hash.from_str(hex)).eql(Hash.empty));
    try std.testing.expect((try Hash.parse(base32)).eql(Hash.empty));
    try std.testing.expect((try Hash.parse("v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra")).eql(Hash.empty));
    try std.testing.expectError(error.InvalidEncoding, Hash.parse("AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262"));
    try std.testing.expectError(error.InvalidEncoding, Hash.parse("V4JUTOPV7GQ2NICAJXVDNXGJJGN4WJOJVXARFN6MTKJ4VZA7GJRA="));
}
