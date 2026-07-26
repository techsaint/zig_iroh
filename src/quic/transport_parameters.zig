const std = @import("std");
const coding = @import("coding.zig");
const packet = @import("packet.zig");
const varint = @import("varint.zig");

pub const stateless_reset_token_len: usize = 16;

pub const TransportParameterId = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    max_datagram_frame_size = 0x20,
    grease_quic_bit = 0x2ab2,
    n0_nat_traversal = 0x3d7f91120401,
};

pub const TransportParameters = struct {
    original_destination_connection_id: ?packet.ConnectionId = null,
    max_idle_timeout: u64 = 0,
    stateless_reset_token: ?[packet.stateless_reset_token_len]u8 = null,
    max_udp_payload_size: u64 = 65527,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u64 = 3,
    max_ack_delay: u64 = 25,
    active_connection_id_limit: u64 = 2,
    initial_source_connection_id: ?packet.ConnectionId = null,
    max_datagram_frame_size: ?u64 = null,
    grease_quic_bit: bool = false,
    max_remote_nat_traversal_addresses: ?u8 = null,

    pub fn encode(self: TransportParameters, out: []u8) ![]u8 {
        var index: usize = 0;
        if (self.original_destination_connection_id) |cid| {
            try varint.encodeAppend(@intFromEnum(TransportParameterId.original_destination_connection_id), out, &index);
            try varint.encodeAppend(cid.len, out, &index);
            try coding.writeBytes(cid.slice(), out, &index);
        }
        if (self.max_idle_timeout != 0) try writeVarParam(.max_idle_timeout, self.max_idle_timeout, out, &index);
        if (self.stateless_reset_token) |token| {
            try varint.encodeAppend(@intFromEnum(TransportParameterId.stateless_reset_token), out, &index);
            try varint.encodeAppend(packet.stateless_reset_token_len, out, &index);
            try coding.writeBytes(&token, out, &index);
        }
        if (self.max_udp_payload_size != 65527) try writeVarParam(.max_udp_payload_size, self.max_udp_payload_size, out, &index);
        if (self.initial_max_data != 0) try writeVarParam(.initial_max_data, self.initial_max_data, out, &index);
        if (self.initial_max_stream_data_bidi_local != 0) try writeVarParam(.initial_max_stream_data_bidi_local, self.initial_max_stream_data_bidi_local, out, &index);
        if (self.initial_max_stream_data_bidi_remote != 0) try writeVarParam(.initial_max_stream_data_bidi_remote, self.initial_max_stream_data_bidi_remote, out, &index);
        if (self.initial_max_stream_data_uni != 0) try writeVarParam(.initial_max_stream_data_uni, self.initial_max_stream_data_uni, out, &index);
        if (self.initial_max_streams_bidi != 0) try writeVarParam(.initial_max_streams_bidi, self.initial_max_streams_bidi, out, &index);
        if (self.initial_max_streams_uni != 0) try writeVarParam(.initial_max_streams_uni, self.initial_max_streams_uni, out, &index);
        if (self.ack_delay_exponent != 3) try writeVarParam(.ack_delay_exponent, self.ack_delay_exponent, out, &index);
        if (self.max_ack_delay != 25) try writeVarParam(.max_ack_delay, self.max_ack_delay, out, &index);
        if (self.active_connection_id_limit != 2) try writeVarParam(.active_connection_id_limit, self.active_connection_id_limit, out, &index);
        if (self.initial_source_connection_id) |cid| {
            try varint.encodeAppend(@intFromEnum(TransportParameterId.initial_source_connection_id), out, &index);
            try varint.encodeAppend(cid.len, out, &index);
            try coding.writeBytes(cid.slice(), out, &index);
        }
        if (self.max_datagram_frame_size) |value| try writeVarParam(.max_datagram_frame_size, value, out, &index);
        if (self.grease_quic_bit) {
            try varint.encodeAppend(@intFromEnum(TransportParameterId.grease_quic_bit), out, &index);
            try varint.encodeAppend(0, out, &index);
        }
        if (self.max_remote_nat_traversal_addresses) |value| {
            if (value == 0) return error.IllegalTransportParameter;
            try varint.encodeAppend(@intFromEnum(TransportParameterId.n0_nat_traversal), out, &index);
            try varint.encodeAppend(1, out, &index);
            try coding.writeU8(value, out, &index);
        }
        return out[0..index];
    }
};

pub fn decode(bytes: []const u8) !TransportParameters {
    var cursor: coding.Cursor = .{ .bytes = bytes };
    var params: TransportParameters = .{};
    var got_initial_max_data = false;
    var got_original_dst_cid = false;
    var got_initial_src_cid = false;
    var got_max_idle_timeout = false;
    var got_max_datagram = false;
    var got_nat = false;
    var got_stateless_reset = false;

    while (cursor.remaining() > 0) {
        const raw_id = try varint.decodeConsume(cursor.bytes, &cursor.index);
        const len = try varint.decodeConsume(cursor.bytes, &cursor.index);
        if (cursor.remaining() < len) return error.MalformedTransportParameter;
        const start = cursor.index;
        const id = transportParameterIdFromRaw(raw_id) orelse {
            try cursor.skip(@intCast(len));
            continue;
        };

        switch (id) {
            .original_destination_connection_id => {
                if (got_original_dst_cid or len > packet.max_cid_size) return error.MalformedTransportParameter;
                params.original_destination_connection_id = try packet.ConnectionId.init(try cursor.readSlice(@intCast(len)));
                got_original_dst_cid = true;
            },
            .initial_max_data => {
                if (got_initial_max_data) return error.DuplicateTransportParameter;
                params.initial_max_data = try readVarPayload(&cursor, len);
                got_initial_max_data = true;
            },
            .max_idle_timeout => {
                if (got_max_idle_timeout) return error.DuplicateTransportParameter;
                params.max_idle_timeout = try readVarPayload(&cursor, len);
                got_max_idle_timeout = true;
            },
            .stateless_reset_token => {
                if (got_stateless_reset or len != packet.stateless_reset_token_len) return error.MalformedTransportParameter;
                var token: [packet.stateless_reset_token_len]u8 = undefined;
                @memcpy(&token, try cursor.readSlice(@intCast(len)));
                params.stateless_reset_token = token;
                got_stateless_reset = true;
            },
            .initial_source_connection_id => {
                if (got_initial_src_cid or len > packet.max_cid_size) return error.MalformedTransportParameter;
                params.initial_source_connection_id = try packet.ConnectionId.init(try cursor.readSlice(@intCast(len)));
                got_initial_src_cid = true;
            },
            .max_datagram_frame_size => {
                if (got_max_datagram) return error.DuplicateTransportParameter;
                params.max_datagram_frame_size = try readVarPayload(&cursor, len);
                got_max_datagram = true;
            },
            .grease_quic_bit => {
                if (len != 0 or params.grease_quic_bit) return error.MalformedTransportParameter;
                params.grease_quic_bit = true;
            },
            .n0_nat_traversal => {
                if (got_nat or len != 1) return error.MalformedTransportParameter;
                const value = try cursor.readU8();
                if (value == 0) return error.IllegalTransportParameter;
                params.max_remote_nat_traversal_addresses = value;
                got_nat = true;
            },
            .max_udp_payload_size => params.max_udp_payload_size = try readVarPayload(&cursor, len),
            .initial_max_stream_data_bidi_local => params.initial_max_stream_data_bidi_local = try readVarPayload(&cursor, len),
            .initial_max_stream_data_bidi_remote => params.initial_max_stream_data_bidi_remote = try readVarPayload(&cursor, len),
            .initial_max_stream_data_uni => params.initial_max_stream_data_uni = try readVarPayload(&cursor, len),
            .initial_max_streams_bidi => params.initial_max_streams_bidi = try readVarPayload(&cursor, len),
            .initial_max_streams_uni => params.initial_max_streams_uni = try readVarPayload(&cursor, len),
            .ack_delay_exponent => params.ack_delay_exponent = try readVarPayload(&cursor, len),
            .max_ack_delay => params.max_ack_delay = try readVarPayload(&cursor, len),
            .active_connection_id_limit => params.active_connection_id_limit = try readVarPayload(&cursor, len),
        }

        if (cursor.index != start + len) return error.MalformedTransportParameter;
    }

    if (params.ack_delay_exponent > 20) return error.IllegalTransportParameter;
    if (params.max_ack_delay >= (@as(u64, 1) << 14)) return error.IllegalTransportParameter;
    if (params.active_connection_id_limit < 2) return error.IllegalTransportParameter;
    if (params.max_udp_payload_size < 1200) return error.IllegalTransportParameter;
    // RFC 9000 §18.2: a max_streams value MUST NOT exceed 2^60 (else FRAME_ENCODING_ERROR).
    const max_streams_limit: u64 = @as(u64, 1) << 60;
    if (params.initial_max_streams_bidi > max_streams_limit) return error.IllegalTransportParameter;
    if (params.initial_max_streams_uni > max_streams_limit) return error.IllegalTransportParameter;
    return params;
}

fn transportParameterIdFromRaw(raw: u64) ?TransportParameterId {
    return switch (raw) {
        @intFromEnum(TransportParameterId.original_destination_connection_id) => .original_destination_connection_id,
        @intFromEnum(TransportParameterId.max_idle_timeout) => .max_idle_timeout,
        @intFromEnum(TransportParameterId.stateless_reset_token) => .stateless_reset_token,
        @intFromEnum(TransportParameterId.max_udp_payload_size) => .max_udp_payload_size,
        @intFromEnum(TransportParameterId.initial_max_data) => .initial_max_data,
        @intFromEnum(TransportParameterId.initial_max_stream_data_bidi_local) => .initial_max_stream_data_bidi_local,
        @intFromEnum(TransportParameterId.initial_max_stream_data_bidi_remote) => .initial_max_stream_data_bidi_remote,
        @intFromEnum(TransportParameterId.initial_max_stream_data_uni) => .initial_max_stream_data_uni,
        @intFromEnum(TransportParameterId.initial_max_streams_bidi) => .initial_max_streams_bidi,
        @intFromEnum(TransportParameterId.initial_max_streams_uni) => .initial_max_streams_uni,
        @intFromEnum(TransportParameterId.ack_delay_exponent) => .ack_delay_exponent,
        @intFromEnum(TransportParameterId.max_ack_delay) => .max_ack_delay,
        @intFromEnum(TransportParameterId.active_connection_id_limit) => .active_connection_id_limit,
        @intFromEnum(TransportParameterId.initial_source_connection_id) => .initial_source_connection_id,
        @intFromEnum(TransportParameterId.max_datagram_frame_size) => .max_datagram_frame_size,
        @intFromEnum(TransportParameterId.grease_quic_bit) => .grease_quic_bit,
        @intFromEnum(TransportParameterId.n0_nat_traversal) => .n0_nat_traversal,
        else => null,
    };
}

fn writeVarParam(id: TransportParameterId, value: u64, out: []u8, index: *usize) !void {
    var tmp: [varint.max_size]u8 = undefined;
    const n = try varint.encode(value, &tmp);
    try varint.encodeAppend(@intFromEnum(id), out, index);
    try varint.encodeAppend(n, out, index);
    try coding.writeBytes(tmp[0..n], out, index);
}

fn readVarPayload(cursor: *coding.Cursor, len: u64) !u64 {
    if (len > varint.max_size) return error.MalformedTransportParameter;
    const before = cursor.index;
    const value = try varint.decodeConsume(cursor.bytes, &cursor.index);
    if (cursor.index != before + len) return error.MalformedTransportParameter;
    return value;
}

test "noq transport parameter stateless reset token roundtrip" {
    var token: [packet.stateless_reset_token_len]u8 = undefined;
    @memset(&token, 0xCD);
    var buf: [128]u8 = undefined;
    const encoded = try (TransportParameters{
        .initial_max_data = 1024,
        .stateless_reset_token = token,
    }).encode(&buf);
    const decoded = try decode(encoded);
    try std.testing.expect(decoded.stateless_reset_token != null);
    try std.testing.expectEqualSlices(u8, &token, &decoded.stateless_reset_token.?);
}

test "noq transport parameter subset round trips" {
    const cid = try packet.ConnectionId.init(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    var buf: [128]u8 = undefined;
    const encoded = try (TransportParameters{
        .original_destination_connection_id = cid,
        .max_idle_timeout = 30_000,
        .initial_max_data = 4096,
        .initial_max_stream_data_bidi_local = 2048,
        .initial_max_stream_data_bidi_remote = 2049,
        .initial_max_stream_data_uni = 2050,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 3,
        .initial_source_connection_id = cid,
        .max_datagram_frame_size = 1200,
        .grease_quic_bit = true,
        .max_remote_nat_traversal_addresses = 8,
    }).encode(&buf);
    const decoded = try decode(encoded);
    try std.testing.expect(decoded.original_destination_connection_id != null);
    try std.testing.expectEqualSlices(u8, cid.slice(), decoded.original_destination_connection_id.?.slice());
    try std.testing.expectEqual(@as(u64, 30_000), decoded.max_idle_timeout);
    try std.testing.expectEqual(@as(u64, 4096), decoded.initial_max_data);
    try std.testing.expectEqual(@as(u64, 2048), decoded.initial_max_stream_data_bidi_local);
    try std.testing.expectEqual(@as(u64, 2049), decoded.initial_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(u64, 2050), decoded.initial_max_stream_data_uni);
    try std.testing.expectEqual(@as(u64, 16), decoded.initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 3), decoded.initial_max_streams_uni);
    try std.testing.expect(decoded.initial_source_connection_id != null);
    try std.testing.expectEqualSlices(u8, cid.slice(), decoded.initial_source_connection_id.?.slice());
    try std.testing.expectEqual(@as(u64, 1200), decoded.max_datagram_frame_size.?);
    try std.testing.expect(decoded.grease_quic_bit);
    try std.testing.expectEqual(@as(u8, 8), decoded.max_remote_nat_traversal_addresses.?);
}
