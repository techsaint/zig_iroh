//! iroh TLS SNI name encoding shared by both QUIC engines.

const std = @import("std");
const key = @import("key.zig");

const BASE32_DNSSEC = "0123456789abcdefghijklmnopqrstuv";
const SUFFIX = ".iroh.invalid";

pub const encoded_name_len = 52 + SUFFIX.len;

pub fn serverName(node_id: key.NodeId) [encoded_name_len]u8 {
    var out: [encoded_name_len]u8 = undefined;
    const n = base32DnssecEncode(&node_id.bytes, out[0..52]);
    std.debug.assert(n == 52);
    @memcpy(out[52..], SUFFIX);
    return out;
}

fn base32DnssecEncode(data: []const u8, out: []u8) usize {
    var acc: u16 = 0;
    var nbits: u4 = 0;
    var oi: usize = 0;

    for (data) |b| {
        acc = (acc << 8) | b;
        nbits += 8;
        while (nbits >= 5) {
            nbits -= 5;
            out[oi] = BASE32_DNSSEC[(acc >> nbits) & 31];
            oi += 1;
        }
    }

    if (nbits > 0) {
        out[oi] = BASE32_DNSSEC[(acc << (5 - nbits)) & 31];
        oi += 1;
    }

    return oi;
}

test "SNI snapshot matches iroh tls/name.rs zero-key vector" {
    const zero_seed = [_]u8{0} ** 32;
    const node_id = key.SecretKey.fromBytes(zero_seed).public();
    try std.testing.expectEqualStrings(
        "7dl2ff6emqi2qol3l382krodedij45bn3nh479hqo14a32qpr8kg.iroh.invalid",
        &serverName(node_id),
    );
}
