const std = @import("std");

pub const client_certificate_type_extension: u16 = 19;
pub const server_certificate_type_extension: u16 = 20;

pub const CertificateType = enum(u8) {
    x509 = 0,
    raw_public_key = 2,
};

pub const ed25519_spki_length = 44;
pub const ed25519_spki_prefix = [_]u8{
    0x30, 0x2a,
    0x30, 0x05,
    0x06, 0x03,
    0x2b, 0x65,
    0x70, 0x03,
    0x21, 0x00,
};

pub const Error = error{
    InvalidCertificateTypeList,
    InvalidCertificateTypeSelection,
    InvalidSubjectPublicKeyInfo,
    NoMutuallySupportedCertificateType,
};

pub fn encodeEd25519SubjectPublicKeyInfo(public_key: [32]u8) [ed25519_spki_length]u8 {
    var out: [ed25519_spki_length]u8 = undefined;
    @memcpy(out[0..ed25519_spki_prefix.len], &ed25519_spki_prefix);
    @memcpy(out[ed25519_spki_prefix.len..], &public_key);
    return out;
}

pub fn decodeEd25519SubjectPublicKeyInfo(der: []const u8) Error![32]u8 {
    if (der.len != ed25519_spki_length) return error.InvalidSubjectPublicKeyInfo;
    if (!std.mem.eql(u8, der[0..ed25519_spki_prefix.len], &ed25519_spki_prefix)) {
        return error.InvalidSubjectPublicKeyInfo;
    }
    return der[ed25519_spki_prefix.len..][0..32].*;
}

/// RFC 7250 ClientHello extension_data is a one-byte vector length followed by
/// the offered CertificateType values.
pub fn encodeOffer(types: []const CertificateType, out: []u8) Error![]const u8 {
    if (types.len == 0 or types.len > std.math.maxInt(u8) or out.len < 1 + types.len) {
        return error.InvalidCertificateTypeList;
    }
    out[0] = @intCast(types.len);
    for (types, 0..) |certificate_type, i| out[1 + i] = @intFromEnum(certificate_type);
    return out[0 .. 1 + types.len];
}

pub fn offerContains(extension_data: []const u8, wanted: CertificateType) Error!bool {
    if (extension_data.len < 2 or extension_data[0] == 0 or extension_data.len != 1 + extension_data[0]) {
        return error.InvalidCertificateTypeList;
    }
    for (extension_data[1..]) |raw| {
        if (raw == @intFromEnum(wanted)) return true;
    }
    return false;
}

/// ServerHello/EncryptedExtensions selection is exactly one CertificateType byte.
pub fn decodeSelection(extension_data: []const u8) Error!CertificateType {
    if (extension_data.len != 1) return error.InvalidCertificateTypeSelection;
    return std.enums.fromInt(CertificateType, extension_data[0]) orelse error.InvalidCertificateTypeSelection;
}

pub fn selectRawPublicKey(extension_data: []const u8) Error!CertificateType {
    if (!try offerContains(extension_data, .raw_public_key)) return error.NoMutuallySupportedCertificateType;
    return .raw_public_key;
}

test "Ed25519 SubjectPublicKeyInfo has canonical RFC 8410 encoding" {
    var public_key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&public_key, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const encoded = encodeEd25519SubjectPublicKeyInfo(public_key);
    var expected: [ed25519_spki_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    try std.testing.expectEqualSlices(u8, &expected, &encoded);
    try std.testing.expectEqualSlices(u8, &public_key, &(try decodeEd25519SubjectPublicKeyInfo(&encoded)));
}

test "RFC 7250 raw-public-key offer and selection use value 2" {
    var encoded: [3]u8 = undefined;
    const offer = try encodeOffer(&.{ .raw_public_key, .x509 }, &encoded);
    try std.testing.expectEqualSlices(u8, &.{ 2, 2, 0 }, offer);
    try std.testing.expectEqual(CertificateType.raw_public_key, try selectRawPublicKey(offer));
    try std.testing.expectEqual(CertificateType.raw_public_key, try decodeSelection(&.{2}));
    try std.testing.expectError(error.InvalidCertificateTypeSelection, decodeSelection(&.{ 2, 0 }));
}

test "Ed25519 SubjectPublicKeyInfo rejects noncanonical encodings" {
    var encoded = encodeEd25519SubjectPublicKeyInfo([_]u8{0x42} ** 32);
    encoded[1] = 0x2b;
    try std.testing.expectError(error.InvalidSubjectPublicKeyInfo, decodeEd25519SubjectPublicKeyInfo(&encoded));
}
