const std = @import("std");

const P256 = std.crypto.ecc.P256;

pub const secret_key_length = 32;
pub const public_key_length = 65;
pub const shared_secret_length = 32;

pub const Error = error{
    InvalidSecretKey,
    InvalidPublicKey,
};

pub const KeyPair = struct {
    secret_key: [secret_key_length]u8,
    public_key: [public_key_length]u8,

    pub fn generate(io: std.Io) KeyPair {
        const secret_key = P256.scalar.random(io, .big);
        return fromSecretKey(secret_key) catch unreachable;
    }

    pub fn fromSecretKey(secret_key: [secret_key_length]u8) Error!KeyPair {
        P256.scalar.rejectNonCanonical(secret_key, .big) catch return error.InvalidSecretKey;
        if (std.mem.allEqual(u8, &secret_key, 0)) return error.InvalidSecretKey;
        const point = P256.basePoint.mul(secret_key, .big) catch return error.InvalidSecretKey;
        return .{
            .secret_key = secret_key,
            .public_key = point.toUncompressedSec1(),
        };
    }

    pub fn sharedSecret(self: KeyPair, peer_public_key: []const u8) Error![shared_secret_length]u8 {
        const peer = P256.fromSec1(peer_public_key) catch return error.InvalidPublicKey;
        peer.rejectIdentity() catch return error.InvalidPublicKey;
        const shared_point = peer.mul(self.secret_key, .big) catch return error.InvalidPublicKey;
        return shared_point.affineCoordinates().x.toBytes(.big);
    }
};

test "RFC 5903 section 8.1 P-256 ECDH known-answer vector" {
    var initiator_secret: [32]u8 = undefined;
    var responder_secret: [32]u8 = undefined;
    var initiator_public: [65]u8 = undefined;
    var responder_public: [65]u8 = undefined;
    var expected_shared: [32]u8 = undefined;

    _ = try std.fmt.hexToBytes(&initiator_secret, "C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
    _ = try std.fmt.hexToBytes(&responder_secret, "C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53");
    initiator_public[0] = 0x04;
    responder_public[0] = 0x04;
    _ = try std.fmt.hexToBytes(initiator_public[1..], "DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C37725811805271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3");
    _ = try std.fmt.hexToBytes(responder_public[1..], "D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF6356FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB");
    _ = try std.fmt.hexToBytes(&expected_shared, "D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");

    const initiator = try KeyPair.fromSecretKey(initiator_secret);
    const responder = try KeyPair.fromSecretKey(responder_secret);
    try std.testing.expectEqualSlices(u8, &initiator_public, &initiator.public_key);
    try std.testing.expectEqualSlices(u8, &responder_public, &responder.public_key);
    try std.testing.expectEqualSlices(u8, &expected_shared, &(try initiator.sharedSecret(&responder.public_key)));
    try std.testing.expectEqualSlices(u8, &expected_shared, &(try responder.sharedSecret(&initiator.public_key)));
}

test "P-256 ECDH rejects zero scalar and invalid SEC1 point" {
    try std.testing.expectError(error.InvalidSecretKey, KeyPair.fromSecretKey([_]u8{0} ** 32));
    const kp = KeyPair.generate(std.testing.io);
    try std.testing.expectError(error.InvalidPublicKey, kp.sharedSecret(&([_]u8{0} ** 65)));
}
