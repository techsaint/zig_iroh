//! S1 loopback handshake driver over real UDP sockets.

const std = @import("std");
const c = @import("c.zig").c;
const context = @import("context.zig");
const tls_name = @import("tls_name.zig");
const key = @import("../key.zig");

const net = std.Io.net;

const Endpoint = struct {
    quic: *c.picoquic_quic_t,
    socket: net.Socket,
    local: net.IpAddress,

    fn deinit(self: *Endpoint, io: std.Io) void {
        self.socket.close(io);
        c.picoquic_free(self.quic);
    }
};

fn callback(
    cnx: ?*c.picoquic_cnx_t,
    stream_id: u64,
    bytes: [*c]u8,
    length: usize,
    event: c.picoquic_call_back_event_t,
    callback_ctx: ?*anyopaque,
    stream_ctx: ?*anyopaque,
) callconv(.c) c_int {
    _ = cnx;
    _ = stream_id;
    _ = bytes;
    _ = length;
    _ = event;
    _ = callback_ctx;
    _ = stream_ctx;
    return 0;
}

fn makeEndpoint(io: std.Io, alpn: [*:0]const u8, local_key: key.SecretKey, expected_peer: ?key.NodeId, require_client_auth: bool) !Endpoint {
    var reset_seed = [_]u8{0} ** c.PICOQUIC_RESET_SECRET_SIZE;
    const now = c.picoquic_current_time();
    const quic = c.picoquic_create(
        8,
        null,
        null,
        null,
        alpn,
        callback,
        null,
        null,
        null,
        &reset_seed,
        now,
        null,
        null,
        null,
        0,
    ) orelse return error.PicoquicCreateFailed;
    errdefer c.picoquic_free(quic);

    try context.applyTransportParams(quic, context.default_transport_params);
    const local_seed = local_key.toBytes();
    const local_public = local_key.public().toBytes();
    const expected_public = if (expected_peer) |peer| peer.toBytes() else null;
    if (c.iroh_picoquic_configure_raw_public_key(
        quic,
        &local_seed,
        &local_public,
        if (expected_public) |*public| public else null,
        @intFromBool(require_client_auth),
    ) != 0) return error.RawPublicKeyConfigFailed;

    var bind_addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const socket = try bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    return .{ .quic = quic, .socket = socket, .local = socket.address };
}

fn sockaddrFromIp4(address: net.IpAddress) !c.struct_sockaddr_in {
    const ip4 = switch (address) {
        .ip4 => |ip4| ip4,
        .ip6 => return error.Ipv6NotSupportedInS1Loopback,
    };

    return .{
        .sin_family = c.AF_INET,
        .sin_port = std.mem.nativeToBig(u16, ip4.port),
        .sin_addr = .{ .s_addr = std.mem.nativeToBig(u32, std.mem.readInt(u32, &ip4.bytes, .big)) },
        .sin_zero = [_]u8{0} ** 8,
    };
}

fn ip4FromSockaddr(storage: c.struct_sockaddr_storage) !net.IpAddress {
    const sin: *const c.struct_sockaddr_in = @ptrCast(@alignCast(&storage));
    if (sin.sin_family != c.AF_INET) return error.Ipv6NotSupportedInS1Loopback;
    const addr_be = std.mem.bigToNative(u32, sin.sin_addr.s_addr);
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, addr_be, .big);
    return .{ .ip4 = .{
        .bytes = bytes,
        .port = std.mem.bigToNative(u16, sin.sin_port),
    } };
}

fn pumpOutgoing(io: std.Io, endpoint: *Endpoint) !bool {
    var sent = false;
    while (true) {
        var buffer: [c.PICOQUIC_MAX_PACKET_SIZE]u8 = undefined;
        var send_len: usize = 0;
        var to: c.struct_sockaddr_storage = undefined;
        var from: c.struct_sockaddr_storage = undefined;
        var if_index: c_int = 0;
        var log_cid: c.picoquic_connection_id_t = undefined;
        var last_cnx: ?*c.picoquic_cnx_t = null;

        if (c.picoquic_prepare_next_packet(
            endpoint.quic,
            c.picoquic_current_time(),
            &buffer,
            buffer.len,
            &send_len,
            &to,
            &from,
            &if_index,
            &log_cid,
            &last_cnx,
        ) != 0) return error.PicoquicPrepareFailed;

        if (send_len == 0) return sent;
        var dest = try ip4FromSockaddr(to);
        try endpoint.socket.send(io, &dest, buffer[0..send_len]);
        sent = true;
    }
}

fn pumpIncoming(io: std.Io, endpoint: *Endpoint) !bool {
    var buffer: [2048]u8 = undefined;
    const msg = endpoint.socket.receiveTimeout(io, &buffer, .{ .duration = .{
        .raw = .fromMilliseconds(1),
        .clock = .awake,
    } }) catch |err| switch (err) {
        error.Timeout => return false,
        else => return err,
    };

    var from = try sockaddrFromIp4(msg.from);
    var to = try sockaddrFromIp4(endpoint.local);
    if (c.picoquic_incoming_packet(
        endpoint.quic,
        msg.data.ptr,
        msg.data.len,
        @ptrCast(&from),
        @ptrCast(&to),
        0,
        0,
        c.picoquic_current_time(),
    ) != 0) return error.PicoquicIncomingFailed;
    return true;
}

pub fn runHandshake(io: std.Io) !void {
    const alpn = "iroh-loopback-test";
    const client_key = key.SecretKey.fromBytes([_]u8{1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{2} ** 32);

    var client = try makeEndpoint(io, alpn, client_key, server_key.public(), false);
    defer client.deinit(io);
    var server = try makeEndpoint(io, alpn, server_key, null, true);
    defer server.deinit(io);

    var server_addr = try sockaddrFromIp4(server.local);
    const zero_cid: c.picoquic_connection_id_t = .{ .id = [_]u8{0} ** 20, .id_len = 0 };
    const sni = tls_name.serverName(server_key.public());
    var sni_z: [tls_name.encoded_name_len + 1]u8 = undefined;
    @memcpy(sni_z[0..tls_name.encoded_name_len], &sni);
    sni_z[tls_name.encoded_name_len] = 0;

    const cnx = c.picoquic_create_cnx(
        client.quic,
        zero_cid,
        zero_cid,
        @ptrCast(&server_addr),
        c.picoquic_current_time(),
        c.PICOQUIC_V1_VERSION,
        sni_z[0..tls_name.encoded_name_len :0].ptr,
        alpn,
        1,
    ) orelse return error.PicoquicConnectionCreateFailed;
    // Production dial paths pin via set_cnx_expected_peer (endpoint.zig /
    // quic.zig beginClientCnx). configure_raw_public_key intentionally ignores
    // expected_peer (V3-B per-cnx isolation). Without this call the loopback
    // "real RPK handshake" test cannot catch a client-pin regression.
    const expected_server = server_key.public().toBytes();
    if (c.iroh_picoquic_set_cnx_expected_peer(cnx, &expected_server) != 0) {
        return error.RawPublicKeyConfigFailed;
    }
    if (c.picoquic_start_client_cnx(cnx) != 0) return error.PicoquicStartClientFailed;

    const deadline = c.picoquic_current_time() + 5 * std.time.us_per_s;
    while (c.picoquic_current_time() < deadline) {
        _ = try pumpOutgoing(io, &client);
        _ = try pumpOutgoing(io, &server);
        _ = try pumpIncoming(io, &server);
        _ = try pumpIncoming(io, &client);

        const server_ready = if (c.picoquic_get_first_cnx(server.quic)) |server_cnx|
            c.picoquic_get_cnx_state(server_cnx) == c.picoquic_state_ready
        else
            false;
        if (server_ready and c.picoquic_get_cnx_state(cnx) == c.picoquic_state_ready) return;
    }

    return error.HandshakeTimedOut;
}

test "picoquic client and server complete real RPK TLS handshake over loopback UDP" {
    try runHandshake(std.testing.io);
}
