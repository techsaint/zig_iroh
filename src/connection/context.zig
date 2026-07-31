//! picoquic context setup shared by client/server endpoints.

const std = @import("std");
const c = @import("c.zig").c;

pub const TransportParams = struct {
    keep_alive_interval_us: u64 = 5 * std.time.us_per_s,
    default_path_keep_alive_interval_us: u64 = 5 * std.time.us_per_s,
    default_path_max_idle_timeout_us: u64 = 15 * std.time.us_per_s,
    max_concurrent_multipath_paths: u64 = 8,
    max_remote_nat_traversal_addresses: u64 = 32,
    server_handshake_migration: bool = true,
    max_concurrent_bidi_streams: u64 = 100,
    max_concurrent_uni_streams: u64 = 100,
    max_idle_timeout_ms: u64 = 30_000,
    stream_receive_window: u64 = 16 * 1024 * 1024,
    send_window: u64 = 1024 * 1024 * 1024,
    initial_mtu: u64 = 1200,
    min_mtu: u64 = 1200,
    datagram_receive_buffer_size: u64 = 1_250_000,
    datagram_send_buffer_size: u64 = 1_048_576,
    grease_quic_bit: bool = false,
    multipath: bool = true,
    address_discovery_mode: c_int = 3,
};

pub const default_transport_params: TransportParams = .{};

pub fn applyTransportParams(quic: *c.picoquic_quic_t, params: TransportParams) !void {
    try setDefaultTp(quic, c.picoquic_tp_initial_max_streams_bidi, params.max_concurrent_bidi_streams);
    try setDefaultTp(quic, c.picoquic_tp_initial_max_streams_uni, params.max_concurrent_uni_streams);
    try setDefaultTp(quic, c.picoquic_tp_idle_timeout, params.max_idle_timeout_ms);
    try setDefaultTp(quic, c.picoquic_tp_initial_max_stream_data_bidi_local, params.stream_receive_window);
    try setDefaultTp(quic, c.picoquic_tp_initial_max_stream_data_bidi_remote, params.stream_receive_window);
    try setDefaultTp(quic, c.picoquic_tp_initial_max_data, params.send_window);
    try setDefaultTp(quic, c.picoquic_tp_max_packet_size, params.initial_mtu);
    try setDefaultTp(quic, c.picoquic_tp_max_datagram_frame_size, params.datagram_receive_buffer_size);
    try setDefaultTp(quic, c.picoquic_tp_grease_quic_bit, @intFromBool(params.grease_quic_bit));
    c.picoquic_set_default_multipath_option(quic, @intFromBool(params.multipath));
    c.picoquic_set_default_address_discovery_mode(quic, params.address_discovery_mode);
}

fn setDefaultTp(quic: *c.picoquic_quic_t, tp: u64, value: u64) !void {
    if (c.picoquic_set_default_tp_value(quic, tp, value) != 0) return error.PicoquicTransportParamFailed;
}

test "picoquic context creates and accepts iroh transport parameter defaults" {
    var reset_seed = [_]u8{0} ** c.PICOQUIC_RESET_SECRET_SIZE;
    const quic = c.picoquic_create(
        8,
        null,
        null,
        null,
        "iroh-test",
        null,
        null,
        null,
        null,
        &reset_seed,
        0,
        null,
        null,
        null,
        0,
    ) orelse return error.PicoquicCreateFailed;
    defer c.picoquic_free(quic);

    try applyTransportParams(quic, default_transport_params);
    const tp = c.picoquic_get_default_tp(quic);
    try std.testing.expect(tp.*.do_grease_quic_bit == 0);
    try std.testing.expect(tp.*.initial_max_path_id > 0);
    try std.testing.expect(tp.*.address_discovery_mode == 3);
}
