//! Picoquic-specific SNI decoder verification tail.
//!
//! The pure SNI encoder lives in `shared/tls_name.zig`; this module keeps the
//! picoquic RPK C-decoder cross-check beside the `rpk.c` ownership boundary.

const std = @import("std");
const shared = @import("shared");
const c = @import("connection/c.zig").c;

pub const encoded_name_len = shared.tls_name.encoded_name_len;
pub const serverName = shared.tls_name.serverName;

test "SNI encode/decode roundtrip via C iroh_decode_iroh_sni" {
    const node_id = shared.key.SecretKey.fromBytes([_]u8{0xab} ** 32).public();
    const name = serverName(node_id);
    var sni_z: [encoded_name_len + 1]u8 = undefined;
    @memcpy(sni_z[0..encoded_name_len], &name);
    sni_z[encoded_name_len] = 0;

    var out: [32]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), c.iroh_decode_iroh_sni(&sni_z, &out));
    try std.testing.expectEqualSlices(u8, &node_id.toBytes(), &out);

    // Malformed SNI must fail closed (non-zero).
    try std.testing.expect(c.iroh_decode_iroh_sni("not-an-iroh-sni", &out) != 0);
}
