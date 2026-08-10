//! S6 composition test: was the test-only tls-picotls → engine-noq cycle
//! (`crypto_picotls.zig` N3b5-5a importing transport_parameters). Relocated here
//! so tls_backend → shared stays cycle-free; collected by the engine module.

const std = @import("std");
const key = @import("shared").key;
const product_flags = @import("shared").product_flags;
const crypto = @import("../crypto.zig");
const PicotlsSession = if (crypto.picotls_enabled) @import("tls_backend").PicotlsSession else struct {};
const EndpointHandshake = if (crypto.picotls_enabled) @import("tls_backend").EndpointHandshake else struct {};

test "N3b5-5a handshake carries ALPN, SNI, and QUIC transport parameters" {
    // Fork-isolation S4: the TP codec (`transport_parameters.zig`) moved to
    // the ENGINE module and a picoquic product no longer compiles the noq
    // engine, so this leg runs where that engine exists (noq-picotls) and is
    // an honest comptime SKIP on picoquic-picotls (the branch prunes — the
    // `engine` name is never resolved there). The picotls handshake itself
    // stays covered on picoquic by the surrounding N3b5 tests.
    if (comptime !product_flags.has_noq or !crypto.picotls_enabled) {
        return error.SkipZigTest;
    } else {
    const allocator = std.testing.allocator;
    const tp = @import("../transport_parameters.zig");
    const client_key = key.SecretKey.fromBytes(.{0x33} ** 32);
    const server_key = key.SecretKey.fromBytes(.{0x44} ** 32);

    var client_params_buf: [128]u8 = undefined;
    const client_params = try (tp.TransportParameters{
        .initial_max_data = 1_000_000,
        .initial_max_stream_data_bidi_local = 256_000,
        .initial_max_stream_data_bidi_remote = 256_000,
        .initial_max_stream_data_uni = 256_000,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 8,
    }).encode(&client_params_buf);

    var server_params_buf: [128]u8 = undefined;
    const server_params = try (tp.TransportParameters{
        .initial_max_data = 2_000_000,
        .initial_max_stream_data_bidi_local = 512_000,
        .initial_max_stream_data_bidi_remote = 512_000,
        .initial_max_stream_data_uni = 512_000,
        .initial_max_streams_bidi = 32,
        .initial_max_streams_uni = 8,
    }).encode(&server_params_buf);

    var client = try PicotlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = "iroh-interop-test",
        .server_name = "iroh-node",
        .transport_params = client_params,
    });
    defer client.destroy();

    var server = try PicotlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = client_key.public(),
        .require_client_authentication = true,
        .alpn = "iroh-interop-test",
        .transport_params = server_params,
    });
    defer server.destroy();

    try EndpointHandshake.complete(allocator, client, server);
    try std.testing.expect(client.isComplete());
    try std.testing.expect(server.isComplete());

    // ALPN negotiated on both ends (RFC 7301).
    try std.testing.expectEqualStrings("iroh-interop-test", client.negotiatedProtocol().?);
    try std.testing.expectEqualStrings("iroh-interop-test", server.negotiatedProtocol().?);

    // SNI observed by the server.
    try std.testing.expectEqualStrings("iroh-node", server.serverName().?);

    // Transport parameters exchanged: each side collected the peer's 0x39 bytes.
    try std.testing.expectEqualSlices(u8, server_params, client.peerTransportParams().?);
    try std.testing.expectEqualSlices(u8, client_params, server.peerTransportParams().?);

    // And they decode to the advertised NONZERO flow-control windows (F1).
    const peer_on_client = try tp.decode(client.peerTransportParams().?);
    try std.testing.expectEqual(@as(u64, 2_000_000), peer_on_client.initial_max_data);
    try std.testing.expectEqual(@as(u64, 512_000), peer_on_client.initial_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(u64, 32), peer_on_client.initial_max_streams_bidi);
    }
}