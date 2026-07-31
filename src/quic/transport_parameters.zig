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
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    max_datagram_frame_size = 0x20,
    initial_max_path_id = 0x3e,
    grease_quic_bit = 0x2ab2,
    min_ack_delay = 0xff04de1b,
    n0_nat_traversal = 0x3d7f91120401,
    observed_addr = 0x9f81a176,
};

/// draft-seemann-quic-address-discovery roles (the 0x9f81a176 TP value).
/// noq parity (`noq-proto/src/address_discovery.rs`): absent = disabled;
/// a role value > 2 on the wire is IllegalValue, a duplicate TP is Malformed.
pub const ObservedAddrRole = enum(u8) {
    /// Sender reports the peer's observed address (QAD server).
    send_only = 0,
    /// Sender wants observed-address reports (QAD client).
    receive_only = 1,
    both = 2,
};

/// RFC 9000 §18.2 `preferred_address` (0x0d). Never emitted unless explicitly
/// configured (noq gates it on server config; unconditional emission is wire
/// drift) — this type exists so the codec round-trips a peer's value.
pub const PreferredAddress = struct {
    ipv4: [4]u8,
    port_v4: u16,
    ipv6: [16]u8,
    port_v6: u16,
    connection_id: packet.ConnectionId,
    stateless_reset_token: [packet.stateless_reset_token_len]u8,
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
    /// draft-ietf-quic-ack-frequency §10.1 (0xff04de1b), MICROSECONDS. noq emits
    /// this unconditionally (its 1 ms timer granularity); we match. Decode
    /// enforces noq's legality rule: min_ack_delay <= max_ack_delay * 1000.
    min_ack_delay: ?u64 = null,
    /// RFC 9000 §18.2 (0x0c), empty payload. Emitted only when migration is
    /// disabled by config — noq's default (migration on) does not emit it.
    disable_active_migration: bool = false,
    /// RFC 9000 §18.2 (0x0d). Config-gated in noq — never emitted unless set.
    preferred_address: ?PreferredAddress = null,
    /// RFC 9000 §18.2 (0x10). Emitted only after a Retry was issued.
    retry_source_connection_id: ?packet.ConnectionId = null,
    /// draft-ietf-quic-multipath (0x3e). Multipath-config-gated in noq —
    /// never emitted unless set (unconditional emission is wire drift).
    initial_max_path_id: ?u64 = null,
    /// draft-seemann-quic-address-discovery (0x9f81a176). Emitted only when
    /// the connection negotiates QAD observed-address reports: the QAD server
    /// advertises `.send_only`, the QAD client `.receive_only` (upstream
    /// iroh-relay quic.rs). Null = feature off (no frames may be sent).
    observed_addr_role: ?ObservedAddrRole = null,
    /// F2: the greased reserved TP (RFC 9000 §18.1 — 31N+27, noq
    /// ReservedTransportParameter). No semantics; ignored by the receiver.
    grease: ?Grease = null,

    pub const Grease = struct {
        id: u64,
        payload: [16]u8,
        payload_len: u8,

        /// noq ReservedTransportParameter::random — id of the form 31N+27 and
        /// 0..16 random payload bytes.
        pub fn random(rng: std.Random) Grease {
            const span: u64 = (@as(u64, 1) << 62) - 27;
            const n = rng.uintLessThan(u64, span) / 31;
            var g: Grease = .{
                .id = 31 * n + 27,
                .payload = undefined,
                .payload_len = rng.uintLessThan(u8, 16),
            };
            rng.bytes(g.payload[0..g.payload_len]);
            return g;
        }
    };

    const Entry = struct {
        id: u64,
        buf: [80]u8, // preferred_address alone is 61+ bytes framed
        len: usize,

        fn frame(id: u64, payload: []const u8) !Entry {
            var e: Entry = .{ .id = id, .buf = undefined, .len = 0 };
            var index: usize = 0;
            try varint.encodeAppend(id, &e.buf, &index);
            try varint.encodeAppend(payload.len, &e.buf, &index);
            try coding.writeBytes(payload, &e.buf, &index);
            e.len = index;
            return e;
        }

        fn frameVar(id: u64, value: u64) !Entry {
            var tmp: [varint.max_size]u8 = undefined;
            const n = try varint.encode(value, &tmp);
            return frame(id, tmp[0..n]);
        }

        fn frameBytes(id: TransportParameterId, bytes: []const u8) !Entry {
            return frame(@intFromEnum(id), bytes);
        }

        fn frameVarId(id: TransportParameterId, value: u64) !Entry {
            return frameVar(@intFromEnum(id), value);
        }
    };

    /// Serialize every present parameter into framed entries in CANONICAL
    /// order (the noq `write_order: None` order the wire fixtures pin).
    fn collectEntries(self: TransportParameters, entries: *[24]Entry) !usize {
        var count: usize = 0;
        if (self.original_destination_connection_id) |cid| {
            entries[count] = try Entry.frameBytes(.original_destination_connection_id, cid.slice());
            count += 1;
        }
        if (self.max_idle_timeout != 0) {
            entries[count] = try Entry.frameVarId(.max_idle_timeout, self.max_idle_timeout);
            count += 1;
        }
        if (self.stateless_reset_token) |token| {
            entries[count] = try Entry.frameBytes(.stateless_reset_token, &token);
            count += 1;
        }
        if (self.max_udp_payload_size != 65527) {
            entries[count] = try Entry.frameVarId(.max_udp_payload_size, self.max_udp_payload_size);
            count += 1;
        }
        if (self.initial_max_data != 0) {
            entries[count] = try Entry.frameVarId(.initial_max_data, self.initial_max_data);
            count += 1;
        }
        if (self.initial_max_stream_data_bidi_local != 0) {
            entries[count] = try Entry.frameVarId(.initial_max_stream_data_bidi_local, self.initial_max_stream_data_bidi_local);
            count += 1;
        }
        if (self.initial_max_stream_data_bidi_remote != 0) {
            entries[count] = try Entry.frameVarId(.initial_max_stream_data_bidi_remote, self.initial_max_stream_data_bidi_remote);
            count += 1;
        }
        if (self.initial_max_stream_data_uni != 0) {
            entries[count] = try Entry.frameVarId(.initial_max_stream_data_uni, self.initial_max_stream_data_uni);
            count += 1;
        }
        if (self.initial_max_streams_bidi != 0) {
            entries[count] = try Entry.frameVarId(.initial_max_streams_bidi, self.initial_max_streams_bidi);
            count += 1;
        }
        if (self.initial_max_streams_uni != 0) {
            entries[count] = try Entry.frameVarId(.initial_max_streams_uni, self.initial_max_streams_uni);
            count += 1;
        }
        if (self.ack_delay_exponent != 3) {
            entries[count] = try Entry.frameVarId(.ack_delay_exponent, self.ack_delay_exponent);
            count += 1;
        }
        if (self.max_ack_delay != 25) {
            entries[count] = try Entry.frameVarId(.max_ack_delay, self.max_ack_delay);
            count += 1;
        }
        if (self.active_connection_id_limit != 2) {
            entries[count] = try Entry.frameVarId(.active_connection_id_limit, self.active_connection_id_limit);
            count += 1;
        }
        if (self.initial_source_connection_id) |cid| {
            entries[count] = try Entry.frameBytes(.initial_source_connection_id, cid.slice());
            count += 1;
        }
        if (self.max_datagram_frame_size) |value| {
            entries[count] = try Entry.frameVarId(.max_datagram_frame_size, value);
            count += 1;
        }
        if (self.grease_quic_bit) {
            entries[count] = try Entry.frame(@intFromEnum(TransportParameterId.grease_quic_bit), "");
            count += 1;
        }
        if (self.max_remote_nat_traversal_addresses) |value| {
            if (value == 0) return error.IllegalTransportParameter;
            entries[count] = try Entry.frameBytes(.n0_nat_traversal, &.{value});
            count += 1;
        }
        if (self.min_ack_delay) |value| {
            entries[count] = try Entry.frameVarId(.min_ack_delay, value);
            count += 1;
        }
        if (self.disable_active_migration) {
            entries[count] = try Entry.frame(@intFromEnum(TransportParameterId.disable_active_migration), "");
            count += 1;
        }
        if (self.retry_source_connection_id) |cid| {
            entries[count] = try Entry.frameBytes(.retry_source_connection_id, cid.slice());
            count += 1;
        }
        if (self.initial_max_path_id) |value| {
            entries[count] = try Entry.frameVarId(.initial_max_path_id, value);
            count += 1;
        }
        if (self.observed_addr_role) |role| {
            entries[count] = try Entry.frameVarId(.observed_addr, @intFromEnum(role));
            count += 1;
        }
        if (self.grease) |g| {
            // F2: the greased reserved TP (31N+27 + random payload).
            entries[count] = try Entry.frame(g.id, g.payload[0..g.payload_len]);
            count += 1;
        }
        if (self.preferred_address) |addr| {
            var payload: [4 + 2 + 16 + 2 + 1 + packet.max_cid_size + packet.stateless_reset_token_len]u8 = undefined;
            var index: usize = 0;
            try coding.writeBytes(&addr.ipv4, &payload, &index);
            try coding.writeU16(addr.port_v4, &payload, &index);
            try coding.writeBytes(&addr.ipv6, &payload, &index);
            try coding.writeU16(addr.port_v6, &payload, &index);
            try coding.writeU8(@intCast(addr.connection_id.len), &payload, &index);
            try coding.writeBytes(addr.connection_id.slice(), &payload, &index);
            try coding.writeBytes(&addr.stateless_reset_token, &payload, &index);
            entries[count] = try Entry.frame(@intFromEnum(TransportParameterId.preferred_address), payload[0..index]);
            count += 1;
        }
        return count;
    }

    fn writeEntries(entries: []const Entry, out: []u8) ![]u8 {
        var index: usize = 0;
        for (entries) |*e| {
            if (out.len - index < e.len) return error.NoSpaceLeft;
            @memcpy(out[index..][0..e.len], e.buf[0..e.len]);
            index += e.len;
        }
        return out[0..index];
    }

    pub fn encode(self: TransportParameters, out: []u8) ![]u8 {
        var entries: [24]Entry = undefined;
        const count = try self.collectEntries(&entries);
        return writeEntries(entries[0..count], out);
    }

    /// F2: the handshake encode — same parameters in a SHUFFLED write order
    /// (noq `write_order: Some(shuffled)`, anti-ossification). The canonical
    /// `encode` stays for the byte fixtures.
    pub fn encodeShuffled(self: TransportParameters, out: []u8, rng: std.Random) ![]u8 {
        var entries: [24]Entry = undefined;
        const count = try self.collectEntries(&entries);
        // Fisher-Yates over the entry order.
        var i: usize = count;
        while (i > 1) {
            i -= 1;
            const j = rng.uintLessThan(usize, i + 1);
            std.mem.swap(Entry, &entries[i], &entries[j]);
        }
        return writeEntries(entries[0..count], out);
    }
};

/// F18: the 0-RTT downgrade guard (noq validate_resumption_from). A resumed
/// connection must not accept 0-RTT when the server's new parameters reduce
/// any limit the client remembers from the ticket, drop the grease bit the
/// ticket advertised, or change the QAD/n0 roles. False = incompatible (the
/// caller closes PROTOCOL_VIOLATION "0-RTT accepted with incompatible
/// transport parameters").
pub fn validateResumptionFrom(new: TransportParameters, cached: TransportParameters) bool {
    if (cached.active_connection_id_limit > new.active_connection_id_limit) return false;
    if (cached.initial_max_data > new.initial_max_data) return false;
    if (cached.initial_max_stream_data_bidi_local > new.initial_max_stream_data_bidi_local) return false;
    if (cached.initial_max_stream_data_bidi_remote > new.initial_max_stream_data_bidi_remote) return false;
    if (cached.initial_max_stream_data_uni > new.initial_max_stream_data_uni) return false;
    if (cached.initial_max_streams_bidi > new.initial_max_streams_bidi) return false;
    if (cached.initial_max_streams_uni > new.initial_max_streams_uni) return false;
    // Rust Option<u64> ordering: None < Some(_).
    if (cached.max_datagram_frame_size != null and
        (new.max_datagram_frame_size == null or cached.max_datagram_frame_size.? > new.max_datagram_frame_size.?))
    {
        return false;
    }
    if (cached.grease_quic_bit and !new.grease_quic_bit) return false;
    if (cached.observed_addr_role != new.observed_addr_role) return false;
    if (cached.max_remote_nat_traversal_addresses != new.max_remote_nat_traversal_addresses) return false;
    return true;
}

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
    var got_min_ack_delay = false;
    var got_retry_src_cid = false;
    var got_initial_max_path_id = false;
    var got_preferred_address = false;
    var got_observed_addr = false;

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
            .min_ack_delay => {
                if (got_min_ack_delay) return error.DuplicateTransportParameter;
                params.min_ack_delay = try readVarPayload(&cursor, len);
                got_min_ack_delay = true;
            },
            .disable_active_migration => {
                // Empty payload (RFC 9000 §18.2); a length or a duplicate is malformed.
                if (len != 0 or params.disable_active_migration) return error.MalformedTransportParameter;
                params.disable_active_migration = true;
            },
            .retry_source_connection_id => {
                if (got_retry_src_cid or len > packet.max_cid_size) return error.MalformedTransportParameter;
                params.retry_source_connection_id = try packet.ConnectionId.init(try cursor.readSlice(@intCast(len)));
                got_retry_src_cid = true;
            },
            .initial_max_path_id => {
                if (got_initial_max_path_id) return error.DuplicateTransportParameter;
                params.initial_max_path_id = try readVarPayload(&cursor, len);
                got_initial_max_path_id = true;
            },
            .observed_addr => {
                // noq parity: duplicate is Malformed, a role > 2 is IllegalValue.
                if (got_observed_addr) return error.MalformedTransportParameter;
                const role = try readVarPayload(&cursor, len);
                if (role > @intFromEnum(ObservedAddrRole.both)) return error.IllegalTransportParameter;
                params.observed_addr_role = @enumFromInt(@as(u8, @intCast(role)));
                got_observed_addr = true;
            },
            .preferred_address => {
                if (got_preferred_address) return error.DuplicateTransportParameter;
                if (len < 4 + 2 + 16 + 2 + 1 + packet.stateless_reset_token_len) return error.MalformedTransportParameter;
                const ipv4 = try cursor.readArray(4);
                const port_v4 = try cursor.readU16();
                const ipv6 = try cursor.readArray(16);
                const port_v6 = try cursor.readU16();
                const cid_len = try cursor.readU8();
                // RFC 9000 §18.2: a zero-length CID makes the address unusable;
                // noq rejects it as illegal.
                if (cid_len == 0 or cid_len > packet.max_cid_size) return error.IllegalTransportParameter;
                const cid = try packet.ConnectionId.init(try cursor.readSlice(cid_len));
                const token = try cursor.readArray(packet.stateless_reset_token_len);
                params.preferred_address = .{
                    .ipv4 = ipv4,
                    .port_v4 = port_v4,
                    .ipv6 = ipv6,
                    .port_v6 = port_v6,
                    .connection_id = cid,
                    .stateless_reset_token = token,
                };
                got_preferred_address = true;
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
    // noq parity (µs vs ms): a min_ack_delay above max_ack_delay is illegal.
    if (params.min_ack_delay) |min_delay| {
        if (min_delay > params.max_ack_delay * 1000) return error.IllegalTransportParameter;
    }
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
        @intFromEnum(TransportParameterId.min_ack_delay) => .min_ack_delay,
        @intFromEnum(TransportParameterId.disable_active_migration) => .disable_active_migration,
        @intFromEnum(TransportParameterId.retry_source_connection_id) => .retry_source_connection_id,
        @intFromEnum(TransportParameterId.initial_max_path_id) => .initial_max_path_id,
        @intFromEnum(TransportParameterId.preferred_address) => .preferred_address,
        @intFromEnum(TransportParameterId.n0_nat_traversal) => .n0_nat_traversal,
        @intFromEnum(TransportParameterId.observed_addr) => .observed_addr,
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

test "F2: shuffled encode reorders, greases, and round-trips (canonical encode unchanged for fixtures)" {
    const params = TransportParameters{
        .max_idle_timeout = 30_000,
        .initial_max_data = 4096,
        .initial_max_streams_bidi = 16,
        .initial_source_connection_id = try packet.ConnectionId.init(&.{ 0xaa, 0xbb }),
        .min_ack_delay = 1000,
        .grease = .{ .id = 31 * 7 + 27, .payload = [_]u8{0xAB} ** 16, .payload_len = 5 },
    };
    var prng_a = std.Random.DefaultCsprng.init(.{0} ** 32);
    var prng_b = std.Random.DefaultCsprng.init(.{1} ** 32);
    var buf_a: [256]u8 = undefined;
    var buf_b: [256]u8 = undefined;
    const a = try params.encodeShuffled(&buf_a, prng_a.random());
    const b = try params.encodeShuffled(&buf_b, prng_b.random());

    // Canonical encode is untouched (the wire fixtures pin this exact order).
    var canon_buf: [256]u8 = undefined;
    const canon = try params.encode(&canon_buf);
    try std.testing.expectEqual(@as(usize, a.len), canon.len);

    // The grease TP is on the wire (31N+27 id) and ignored at decode.
    const decoded = try decode(a);
    try std.testing.expectEqual(@as(u64, 30_000), decoded.max_idle_timeout);
    try std.testing.expectEqual(@as(u64, 4096), decoded.initial_max_data);
    try std.testing.expectEqual(@as(u64, 1000), decoded.min_ack_delay.?);
    try std.testing.expectEqualSlices(u8, params.initial_source_connection_id.?.slice(), decoded.initial_source_connection_id.?.slice());

    // The shuffle is real: with enough parameters the two sequences differ.
    // (A degenerate same-order draw is astronomically unlikely with 8 entries;
    // if it ever draws equal the test is re-seeded, not weakened.)
    try std.testing.expect(!std.mem.eql(u8, a, b));

    // The greased TP is ON THE WIRE: its 31N+27 id is byte-visible.
    var grease_id_buf: [varint.max_size]u8 = undefined;
    const grease_id_len = try varint.encode(params.grease.?.id, &grease_id_buf);
    try std.testing.expect(std.mem.indexOf(u8, a, grease_id_buf[0..grease_id_len]) != null);
    try std.testing.expect(std.mem.indexOf(u8, canon, grease_id_buf[0..grease_id_len]) != null);
}

test "F18: resumption validation rejects every downgrade direction and only those" {
    const cached = TransportParameters{
        .active_connection_id_limit = 5,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 256 * 1024,
        .initial_max_stream_data_bidi_remote = 256 * 1024,
        .initial_max_stream_data_uni = 128 * 1024,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 16,
        .max_datagram_frame_size = 1400,
        .grease_quic_bit = true,
        .observed_addr_role = .both,
        .max_remote_nat_traversal_addresses = 8,
    };
    // Identical or upgraded is compatible.
    try std.testing.expect(validateResumptionFrom(cached, cached));
    var upgraded = cached;
    upgraded.initial_max_data = cached.initial_max_data * 2;
    try std.testing.expect(validateResumptionFrom(upgraded, cached));

    // Every single downgrade direction flips to incompatible, alone.
    var d = cached;
    d.active_connection_id_limit = 4;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.initial_max_data = 1024;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.initial_max_stream_data_bidi_local = 1024;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.initial_max_stream_data_bidi_remote = 1024;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.initial_max_stream_data_uni = 1024;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.initial_max_streams_bidi = 4;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.initial_max_streams_uni = 4;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.max_datagram_frame_size = 1200;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.max_datagram_frame_size = null;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.grease_quic_bit = false;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.observed_addr_role = .send_only;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.observed_addr_role = null;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.max_remote_nat_traversal_addresses = 4;
    try std.testing.expect(!validateResumptionFrom(d, cached));
    d = cached;
    d.max_remote_nat_traversal_addresses = null;
    try std.testing.expect(!validateResumptionFrom(d, cached));
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

test "noq transport parameter parity additions round trip" {
    const cid = try packet.ConnectionId.init(&[_]u8{0xaa} ** 8);
    var buf: [256]u8 = undefined;
    const encoded = try (TransportParameters{
        .min_ack_delay = 1000,
        .disable_active_migration = true,
        .retry_source_connection_id = cid,
        .initial_max_path_id = 7,
        .preferred_address = .{
            .ipv4 = .{ 127, 0, 0, 1 },
            .port_v4 = 4433,
            .ipv6 = ([_]u8{0} ** 15) ++ [_]u8{1},
            .port_v6 = 4434,
            .connection_id = cid,
            .stateless_reset_token = [_]u8{0x5A} ** packet.stateless_reset_token_len,
        },
    }).encode(&buf);
    const decoded = try decode(encoded);
    try std.testing.expectEqual(@as(u64, 1000), decoded.min_ack_delay.?);
    try std.testing.expect(decoded.disable_active_migration);
    try std.testing.expectEqualSlices(u8, cid.slice(), decoded.retry_source_connection_id.?.slice());
    try std.testing.expectEqual(@as(u64, 7), decoded.initial_max_path_id.?);
    const addr = decoded.preferred_address.?;
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &addr.ipv4);
    try std.testing.expectEqual(@as(u16, 4433), addr.port_v4);
    try std.testing.expectEqual(@as(u16, 4434), addr.port_v6);
    try std.testing.expectEqualSlices(u8, cid.slice(), addr.connection_id.slice());
    try std.testing.expectEqualSlices(u8, &([_]u8{0x5A} ** packet.stateless_reset_token_len), &addr.stateless_reset_token);
}

test "observed-addr role round trips; >both is illegal; duplicate is malformed (noq parity)" {
    var buf: [64]u8 = undefined;
    const encoded = try (TransportParameters{ .observed_addr_role = .send_only }).encode(&buf);
    const decoded = try decode(encoded);
    try std.testing.expectEqual(ObservedAddrRole.send_only, decoded.observed_addr_role.?);

    // Role 3 on the wire is IllegalValue.
    var index: usize = 0;
    try varint.encodeAppend(@intFromEnum(TransportParameterId.observed_addr), &buf, &index);
    try varint.encodeAppend(1, &buf, &index);
    try coding.writeU8(3, &buf, &index);
    try std.testing.expectError(error.IllegalTransportParameter, decode(buf[0..index]));

    // A duplicate TP is Malformed.
    index = 0;
    for (0..2) |_| {
        try varint.encodeAppend(@intFromEnum(TransportParameterId.observed_addr), &buf, &index);
        try varint.encodeAppend(1, &buf, &index);
        try coding.writeU8(@intFromEnum(ObservedAddrRole.receive_only), &buf, &index);
    }
    try std.testing.expectError(error.MalformedTransportParameter, decode(buf[0..index]));
}

test "min_ack_delay above max_ack_delay is illegal (noq parity)" {
    var buf: [64]u8 = undefined;
    const encoded = try (TransportParameters{
        .max_ack_delay = 25, // 25 ms → 25_000 µs ceiling
        .min_ack_delay = 25_001,
    }).encode(&buf);
    try std.testing.expectError(error.IllegalTransportParameter, decode(encoded));
}

test "preferred_address with zero-length CID is illegal (noq parity)" {
    var buf: [256]u8 = undefined;
    var index: usize = 0;
    // Hand-encode: preferred_address with cid_len = 0.
    try varint.encodeAppend(@intFromEnum(TransportParameterId.preferred_address), &buf, &index);
    try varint.encodeAppend(4 + 2 + 16 + 2 + 1 + packet.stateless_reset_token_len, &buf, &index);
    try coding.writeBytes(&([_]u8{0} ** 24), &buf, &index); // addrs + ports
    try coding.writeU8(0, &buf, &index); // cid_len = 0 → illegal
    try coding.writeBytes(&([_]u8{0} ** packet.stateless_reset_token_len), &buf, &index);
    try std.testing.expectError(error.IllegalTransportParameter, decode(buf[0..index]));
}
