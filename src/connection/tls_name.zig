//! iroh TLS SNI names.

const std = @import("std");
const product_flags = @import("../product_flags.zig");
const key = @import("../key.zig");
// `c.zig` is the picoquic cImport; the noq engine imports this file only for the
// pure-Zig `serverName` encoder, so the C decoder binding is picoquic-gated
// (component-repo restructure).
const c = if (product_flags.has_picoquic) @import("c.zig").c else struct {};

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

// Production encoder↔decoder pair: Zig `serverName` + C `iroh_decode_iroh_sni`
// (the load-bearing decoder in the client-pin verify path). Do NOT reintroduce a
// parallel Zig-only decoder — it would drift from the C path.
test "SNI encode/decode roundtrip via C iroh_decode_iroh_sni" {
    // The C decoder lives in `connection/rpk.c` (picoquic glue), so this
    // cross-check is picoquic-only; mono-noq products skip it.
    if (comptime product_flags.has_picoquic) {
        const node_id = key.SecretKey.fromBytes([_]u8{0xab} ** 32).public();
        const name = serverName(node_id);
        var sni_z: [encoded_name_len + 1]u8 = undefined;
        @memcpy(sni_z[0..encoded_name_len], &name);
        sni_z[encoded_name_len] = 0;

        var out: [32]u8 = undefined;
        try std.testing.expectEqual(@as(c_int, 0), c.iroh_decode_iroh_sni(&sni_z, &out));
        try std.testing.expectEqualSlices(u8, &node_id.toBytes(), &out);

        // Malformed SNI must fail closed (non-zero).
        try std.testing.expect(c.iroh_decode_iroh_sni("not-an-iroh-sni", &out) != 0);
    } else {
        return error.SkipZigTest;
    }
}
