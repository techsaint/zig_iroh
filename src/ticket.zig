//! EndpointTicket + EndpointAddr postcard (ID1b).
//!
//! Wire formats match iroh-base (serde/postcard) and iroh-tickets 1.0:
//! - `EndpointAddr` postcard: id[32] + BTreeSet<TransportAddr>
//! - `TransportAddr`: enum Relay=0 / Ip=1 / Custom=2
//! - `EndpointTicket` bytes: enum Variant1=0 + same layout as EndpointAddr fields
//! - string form: lowercase `"endpoint"` + base32-nopad of ticket bytes

const std = @import("std");
const addr = @import("addr.zig");
const key = @import("key.zig");
const net = std.Io.net;

pub const Error = error{
    EndOfStream,
    VarintOverflow,
    InvalidEncoding,
    UnsupportedVariant,
    BufferTooSmall,
    OutOfMemory,
    InvalidPublicKey,
    InvalidRelayUrl,
    InvalidCustomAddr,
    InvalidIpAddress,
};

const BASE32_NOPAD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Postcard-encode an `EndpointAddr` (iroh-base layout).
pub fn encodeEndpointAddr(endpoint: addr.EndpointAddr, out: []u8) Error![]u8 {
    var index: usize = 0;
    try writeBytes(out, &index, endpoint.id.bytes[0..]);
    try writeVarint(out, &index, endpoint.addrs.len);
    for (endpoint.addrs) |ta| {
        try encodeTransportAddr(ta, out, &index);
    }
    return out[0..index];
}

pub fn decodeEndpointAddr(allocator: std.mem.Allocator, bytes: []const u8) Error!addr.EndpointAddr {
    var index: usize = 0;
    if (bytes.len < 32) return error.EndOfStream;
    var id_bytes: [32]u8 = undefined;
    @memcpy(&id_bytes, bytes[0..32]);
    index = 32;
    const id = key.PublicKey.fromBytes(id_bytes) catch return error.InvalidPublicKey;
    const count = try readVarint(bytes, &index);
    var list: std.ArrayList(addr.TransportAddr) = .empty;
    errdefer {
        for (list.items) |item| item.deinit(allocator);
        list.deinit(allocator);
    }
    var i: usize = 0;
    while (i < count) : (i += 1) {
        try list.append(allocator, try decodeTransportAddr(allocator, bytes, &index));
    }
    if (index != bytes.len) return error.InvalidEncoding;
    // fromParts clones + sorts/dedups; free our temporary list.
    const result = addr.EndpointAddr.fromParts(allocator, id, list.items) catch {
        for (list.items) |item| item.deinit(allocator);
        list.deinit(allocator);
        return error.OutOfMemory;
    };
    for (list.items) |item| item.deinit(allocator);
    list.deinit(allocator);
    return result;
}

fn encodeTransportAddr(ta: addr.TransportAddr, out: []u8, index: *usize) Error!void {
    switch (ta) {
        .relay => |relay| {
            try writeVarint(out, index, 0);
            const s = relay.asString();
            try writeVarint(out, index, s.len);
            try writeBytes(out, index, s);
        },
        .ip => |ip| {
            try writeVarint(out, index, 1);
            switch (ip) {
                .ip4 => |v4| {
                    try writeVarint(out, index, 0);
                    try writeBytes(out, index, &v4.bytes);
                    try writeVarint(out, index, v4.port);
                },
                .ip6 => |v6| {
                    try writeVarint(out, index, 1);
                    try writeBytes(out, index, &v6.bytes);
                    try writeVarint(out, index, v6.port);
                },
            }
        },
        .custom => |custom| {
            try writeVarint(out, index, 2);
            try writeVarint(out, index, custom.id);
            // CustomAddrBytes: Inline { size, data: [u8;30] } when len <= 30,
            // else Heap (length-prefixed) — matches iroh's enum serde.
            if (custom.data.len <= 30) {
                try writeVarint(out, index, 0); // Inline
                try writeU8(out, index, @intCast(custom.data.len));
                var pad: [30]u8 = .{0} ** 30;
                @memcpy(pad[0..custom.data.len], custom.data);
                try writeBytes(out, index, &pad);
            } else {
                try writeVarint(out, index, 1); // Heap
                try writeVarint(out, index, custom.data.len);
                try writeBytes(out, index, custom.data);
            }
        },
    }
}

fn decodeTransportAddr(allocator: std.mem.Allocator, bytes: []const u8, index: *usize) Error!addr.TransportAddr {
    const tag = try readVarint(bytes, index);
    return switch (tag) {
        0 => blk: {
            const len = try readVarint(bytes, index);
            const s = try readSlice(bytes, index, len);
            const relay = addr.RelayUrl.parse(allocator, s) catch return error.InvalidRelayUrl;
            break :blk .{ .relay = relay };
        },
        1 => blk: {
            const family = try readVarint(bytes, index);
            if (family == 0) {
                const ip_bytes = try readSlice(bytes, index, 4);
                // Wire varint port > 0xFFFF must reject, not trap (fuzz ticket-decode).
                const port = std.math.cast(u16, try readVarint(bytes, index)) orelse return error.InvalidIpAddress;
                var arr: [4]u8 = undefined;
                @memcpy(&arr, ip_bytes);
                break :blk .{ .ip = .{ .ip4 = .{ .bytes = arr, .port = port } } };
            } else if (family == 1) {
                const ip_bytes = try readSlice(bytes, index, 16);
                const port = std.math.cast(u16, try readVarint(bytes, index)) orelse return error.InvalidIpAddress;
                var arr: [16]u8 = undefined;
                @memcpy(&arr, ip_bytes);
                break :blk .{ .ip = .{ .ip6 = .{ .bytes = arr, .port = port } } };
            } else return error.InvalidIpAddress;
        },
        2 => blk: {
            const id = try readVarint(bytes, index);
            const variant = try readVarint(bytes, index);
            if (variant == 0) {
                const size = try readU8(bytes, index);
                // Inline pad is fixed 30B; size>30 is malformed (iroh never emits it —
                // Heap is used for longer). Bound before slice: reject, do not clamp.
                if (size > 30) return error.InvalidCustomAddr;
                const data = try readSlice(bytes, index, 30);
                const custom = addr.CustomAddr.fromParts(allocator, id, data[0..size]) catch return error.InvalidCustomAddr;
                break :blk .{ .custom = custom };
            } else if (variant == 1) {
                // Heap: length-prefixed bytes
                const len = try readVarint(bytes, index);
                const data = try readSlice(bytes, index, len);
                const custom = addr.CustomAddr.fromParts(allocator, id, data) catch return error.InvalidCustomAddr;
                break :blk .{ .custom = custom };
            } else return error.InvalidCustomAddr;
        },
        else => error.UnsupportedVariant,
    };
}

/// EndpointTicket wire bytes (iroh-tickets).
pub fn encodeTicketBytes(endpoint: addr.EndpointAddr, out: []u8) Error![]u8 {
    if (out.len < 1) return error.BufferTooSmall;
    out[0] = 0; // TicketWireFormat::Variant1
    const rest = try encodeEndpointAddr(endpoint, out[1..]);
    return out[0 .. 1 + rest.len];
}

pub fn decodeTicketBytes(allocator: std.mem.Allocator, bytes: []const u8) Error!addr.EndpointAddr {
    if (bytes.len < 1) return error.EndOfStream;
    if (bytes[0] != 0) return error.UnsupportedVariant;
    return decodeEndpointAddr(allocator, bytes[1..]);
}

/// Canonical string: `"endpoint"` + lowercase base32-nopad of ticket bytes.
pub fn encodeTicketString(allocator: std.mem.Allocator, endpoint: addr.EndpointAddr) Error![]u8 {
    var buf: [512]u8 = undefined;
    const ticket_bytes = try encodeTicketBytes(endpoint, &buf);
    var b32_buf: [1024]u8 = undefined;
    const b32_len = try base32NoPadEncode(ticket_bytes, &b32_buf);
    // lowercase
    for (b32_buf[0..b32_len]) |*c| c.* = std.ascii.toLower(c.*);
    return std.fmt.allocPrint(allocator, "endpoint{s}", .{b32_buf[0..b32_len]}) catch return error.OutOfMemory;
}

pub fn decodeTicketString(allocator: std.mem.Allocator, s: []const u8) Error!addr.EndpointAddr {
    const prefix = "endpoint";
    if (!std.mem.startsWith(u8, s, prefix)) return error.InvalidEncoding;
    const rest = s[prefix.len..];
    var upper_buf: [1024]u8 = undefined;
    if (rest.len > upper_buf.len) return error.BufferTooSmall;
    for (rest, 0..) |c, i| upper_buf[i] = std.ascii.toUpper(c);
    var raw: [512]u8 = undefined;
    const n = try base32NoPadDecode(upper_buf[0..rest.len], &raw);
    return decodeTicketBytes(allocator, raw[0..n]);
}

fn writeVarint(out: []u8, index: *usize, value: u64) Error!void {
    var v = value;
    while (true) {
        const byte: u8 = @truncate(v & 0x7f);
        v >>= 7;
        if (v == 0) {
            try writeU8(out, index, byte);
            return;
        }
        try writeU8(out, index, byte | 0x80);
    }
}

fn readVarint(bytes: []const u8, index: *usize) Error!u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        if (index.* >= bytes.len) return error.EndOfStream;
        const byte = bytes[index.*];
        index.* += 1;
        const low: u64 = byte & 0x7f;
        result |= low << shift;
        if (byte & 0x80 == 0) return result;
        // u6 tops out at 63: guard BEFORE `shift += 7` or the add itself traps
        // on a 10th continuation byte (fuzz ticket-decode).
        if (shift >= 63) return error.VarintOverflow;
        shift += 7;
    }
}

fn writeU8(out: []u8, index: *usize, value: u8) Error!void {
    if (index.* >= out.len) return error.BufferTooSmall;
    out[index.*] = value;
    index.* += 1;
}

fn writeBytes(out: []u8, index: *usize, bytes: []const u8) Error!void {
    if (index.* + bytes.len > out.len) return error.BufferTooSmall;
    @memcpy(out[index.*..][0..bytes.len], bytes);
    index.* += bytes.len;
}

fn readU8(bytes: []const u8, index: *usize) Error!u8 {
    if (index.* >= bytes.len) return error.EndOfStream;
    const b = bytes[index.*];
    index.* += 1;
    return b;
}

fn readSlice(bytes: []const u8, index: *usize, len: usize) Error![]const u8 {
    if (index.* + len > bytes.len) return error.EndOfStream;
    const s = bytes[index.* .. index.* + len];
    index.* += len;
    return s;
}

fn base32Symbol(c: u8) ?u5 {
    const upper = std.ascii.toUpper(c);
    for (BASE32_NOPAD, 0..) |s, i| {
        if (s == upper) return @intCast(i);
    }
    return null;
}

fn base32NoPadDecode(s: []const u8, out: []u8) Error!usize {
    var acc: u32 = 0;
    var nbits: u32 = 0;
    var oi: usize = 0;
    for (s) |c| {
        if (c == '=') return error.InvalidEncoding;
        const v = base32Symbol(c) orelse return error.InvalidEncoding;
        acc = (acc << 5) | v;
        nbits += 5;
        if (nbits >= 8) {
            nbits -= 8;
            if (oi >= out.len) return error.BufferTooSmall;
            out[oi] = @intCast((acc >> @as(u5, @intCast(nbits))) & 0xff);
            oi += 1;
        }
    }
    // iroh-tickets' data_encoding base32 rejects non-zero trailing bits.
    if (nbits > 0) {
        const mask = (@as(u32, 1) << @as(u5, @intCast(nbits))) - 1;
        if ((acc & mask) != 0) return error.InvalidEncoding;
    }
    return oi;
}

fn base32NoPadEncode(input: []const u8, out: []u8) Error!usize {
    var acc: u32 = 0;
    var nbits: u32 = 0;
    var oi: usize = 0;
    for (input) |byte| {
        acc = (acc << 8) | byte;
        nbits += 8;
        while (nbits >= 5) {
            nbits -= 5;
            if (oi >= out.len) return error.BufferTooSmall;
            out[oi] = BASE32_NOPAD[(acc >> @as(u5, @intCast(nbits))) & 0x1f];
            oi += 1;
        }
    }
    if (nbits > 0) {
        if (oi >= out.len) return error.BufferTooSmall;
        out[oi] = BASE32_NOPAD[(acc << @as(u5, @intCast(5 - nbits))) & 0x1f];
        oi += 1;
    }
    return oi;
}

test "endpoint postcard relay matches rust fixture shape" {
    const allocator = std.testing.allocator;
    const sk = key.SecretKey.fromBytes(.{0x11} ** 32);
    const id = sk.public();
    var relay = try addr.RelayUrl.parse(allocator, "https://relay.example.com.");
    defer relay.deinit(allocator);
    var endpoint = try addr.EndpointAddr.fromParts(allocator, id, &.{.{ .relay = relay }});
    defer endpoint.deinit(allocator);

    var buf: [256]u8 = undefined;
    const encoded = try encodeEndpointAddr(endpoint, &buf);
    // Rust fixture postcard_hex for endpoint/relay
    const expected_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701001b68747470733a2f2f72656c61792e6578616d706c652e636f6d2e2f";
    var expected: [128]u8 = undefined;
    const expected_slice = try std.fmt.hexToBytes(expected[0..], expected_hex);
    try std.testing.expectEqualSlices(u8, expected_slice, encoded);

    const ticket = try encodeTicketString(allocator, endpoint);
    defer allocator.free(ticket);
    try std.testing.expect(std.mem.startsWith(u8, ticket, "endpoint"));
    var round = try decodeTicketString(allocator, ticket);
    defer round.deinit(allocator);
    try std.testing.expect(round.id.eql(endpoint.id));
}

/// Inline CustomAddrBytes: after ticket Variant1 byte + EndpointAddr id[32] + count=1
/// + TransportAddr tag=Custom + custom id + Inline variant=0, the next byte is `size`.
const custom_inline_size_off_in_ticket = 1 + 32 + 1 + 1 + 1 + 1;

test "ticket custom Inline size>30 rejects gracefully (mutation-RED OOB)" {
    const allocator = std.testing.allocator;
    const sk = key.SecretKey.fromBytes(.{0x22} ** 32);
    const id = sk.public();
    var custom = try addr.CustomAddr.fromParts(allocator, 7, "hello");
    defer custom.deinit(allocator);
    var endpoint = try addr.EndpointAddr.fromParts(allocator, id, &.{.{ .custom = custom }});
    defer endpoint.deinit(allocator);

    var buf: [256]u8 = undefined;
    const encoded = try encodeTicketBytes(endpoint, &buf);
    try std.testing.expect(encoded.len > custom_inline_size_off_in_ticket);
    try std.testing.expectEqual(@as(u8, 5), encoded[custom_inline_size_off_in_ticket]);
    // Malformed: claim size past the fixed 30B Inline pad. Pre-fix: data[0..size] panics/UB.
    // Post-fix: graceful InvalidCustomAddr. Revert the size>30 bound → this test panics (mutation-RED).
    encoded[custom_inline_size_off_in_ticket] = 31;
    try std.testing.expectError(error.InvalidCustomAddr, decodeTicketBytes(allocator, encoded));

    encoded[custom_inline_size_off_in_ticket] = 255;
    try std.testing.expectError(error.InvalidCustomAddr, decodeTicketBytes(allocator, encoded));
}

test "ticket custom Inline valid size round-trips byte-identical (wire-preserving)" {
    const allocator = std.testing.allocator;
    const sk = key.SecretKey.fromBytes(.{0x33} ** 32);
    const id = sk.public();
    // size ∈ {0, 30} — both legal Inline; must stay byte-identical through decode→re-encode.
    const empty: []const u8 = "";
    const full_pad: [30]u8 = .{'x'} ** 30;
    const payloads = [_][]const u8{ empty, full_pad[0..] };
    for (payloads) |payload| {
        var custom = try addr.CustomAddr.fromParts(allocator, 9, payload);
        defer custom.deinit(allocator);
        var endpoint = try addr.EndpointAddr.fromParts(allocator, id, &.{.{ .custom = custom }});
        defer endpoint.deinit(allocator);

        var buf_a: [256]u8 = undefined;
        const first = try encodeTicketBytes(endpoint, &buf_a);
        var decoded = try decodeTicketBytes(allocator, first);
        defer decoded.deinit(allocator);
        try std.testing.expect(decoded.id.eql(endpoint.id));
        try std.testing.expectEqual(@as(usize, 1), decoded.addrs.len);
        const got = decoded.addrs[0].custom;
        try std.testing.expectEqual(custom.id, got.id);
        try std.testing.expectEqualSlices(u8, payload, got.data);

        var buf_b: [256]u8 = undefined;
        const second = try encodeTicketBytes(decoded, &buf_b);
        try std.testing.expectEqualSlices(u8, first, second);
    }
}

const fixtures = @import("iroh_base_fixtures.zig");

fn expectFixtureHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected_buf: [512]u8 = undefined;
    const expected = std.fmt.hexToBytes(&expected_buf, expected_hex) catch unreachable;
    try std.testing.expectEqualSlices(u8, expected, actual);
}

fn parseFixtureIpPort(s: []const u8) !net.IpAddress {
    if (std.mem.startsWith(u8, s, "[")) {
        const close = std.mem.indexOfScalar(u8, s, ']').?;
        const port = try std.fmt.parseUnsigned(u16, s[close + 2 ..], 10);
        return net.IpAddress.parse(s[1..close], port);
    }
    const colon = std.mem.lastIndexOfScalar(u8, s, ':').?;
    const port = try std.fmt.parseUnsigned(u16, s[colon + 1 ..], 10);
    return net.IpAddress.parse(s[0..colon], port);
}

test "CustomAddr postcard Inline/Heap encoding matches the reference (fixture-driven)" {
    // Bare-CustomAddr postcard bytes pinned by the probe: Inline (<=30B) and
    // Heap (>30B) variants, incl. the 30/31 boundary and a 100-byte payload.
    // Mutation-RED: reverting the Heap branch to the old `error.InvalidCustomAddr`
    // on >30B fails the 31/100-byte cases.
    const allocator = std.testing.allocator;
    for (fixtures.custom_addr) |case| {
        var data_buf: [256]u8 = undefined;
        const data = try std.fmt.hexToBytes(&data_buf, case.data_hex);
        var ca = try addr.CustomAddr.fromParts(allocator, case.id, data);
        defer ca.deinit(allocator);

        var buf: [512]u8 = undefined;
        var index: usize = 0;
        try encodeTransportAddr(.{ .custom = ca }, &buf, &index);
        const encoded = buf[0..index];
        // Fixture is the BARE CustomAddr postcard; strip the TransportAddr tag byte.
        try std.testing.expectEqual(@as(u8, 2), encoded[0]);
        try expectFixtureHex(case.postcard_hex, encoded[1..]);

        // Decode the reference bytes back: tag byte + fixture bytes.
        var wire: [520]u8 = undefined;
        wire[0] = 2;
        var expected_buf: [512]u8 = undefined;
        const expected = std.fmt.hexToBytes(&expected_buf, case.postcard_hex) catch unreachable;
        @memcpy(wire[1 .. 1 + expected.len], expected);
        var di: usize = 0;
        const decoded = try decodeTransportAddr(allocator, wire[0 .. 1 + expected.len], &di);
        defer decoded.deinit(allocator);
        try std.testing.expectEqual(case.id, decoded.custom.id);
        try std.testing.expectEqualSlices(u8, data, decoded.custom.data);

        // Decode -> re-encode is byte-identical (wire-preserving).
        var buf2: [512]u8 = undefined;
        var index2: usize = 0;
        try encodeTransportAddr(decoded, &buf2, &index2);
        try std.testing.expectEqualSlices(u8, wire[0 .. 1 + expected.len], buf2[0..index2]);
    }
}

test "EndpointAddr postcard and ticket wire forms match reference fixtures (fixture-driven)" {
    // Full composite fixtures from tools/addr_ticket_fixture_gen `generate`:
    // relay-only, ipv4, ipv6, custom, ordering/dedup invariance, ticket
    // string round-trip. Mutation-RED: field order, varint, enum tag, or
    // set-ordering drift flips the byte comparison.
    const allocator = std.testing.allocator;
    for (fixtures.endpoint_fixtures) |fx| {
        const id = try key.PublicKey.fromHex(fx.endpoint_id_hex);
        var list: std.ArrayList(addr.TransportAddr) = .empty;
        defer {
            for (list.items) |item| item.deinit(allocator);
            list.deinit(allocator);
        }
        for (fx.addrs) |a| {
            switch (a.kind) {
                .relay => try list.append(allocator, .{ .relay = try addr.RelayUrl.parse(allocator, a.value) }),
                .ip => try list.append(allocator, .{ .ip = try parseFixtureIpPort(a.value) }),
                .custom => {
                    var data_buf: [256]u8 = undefined;
                    const data = try std.fmt.hexToBytes(&data_buf, a.value);
                    try list.append(allocator, .{ .custom = try addr.CustomAddr.fromParts(allocator, a.id, data) });
                },
            }
        }
        var endpoint = try addr.EndpointAddr.fromParts(allocator, id, list.items);
        defer endpoint.deinit(allocator);

        var buf: [512]u8 = undefined;
        const encoded = try encodeEndpointAddr(endpoint, &buf);
        try expectFixtureHex(fx.postcard_hex, encoded);

        // Decode -> re-encode is byte-identical.
        var decoded = try decodeEndpointAddr(allocator, encoded);
        defer decoded.deinit(allocator);
        var buf2: [512]u8 = undefined;
        const re_encoded = try encodeEndpointAddr(decoded, &buf2);
        try std.testing.expectEqualSlices(u8, encoded, re_encoded);

        // Ticket wire envelope (Variant1 byte + EndpointAddr postcard).
        var ticket_buf: [520]u8 = undefined;
        const ticket_bytes = try encodeTicketBytes(endpoint, &ticket_buf);
        try expectFixtureHex(fx.ticket_bytes_hex, ticket_bytes);

        // Ticket string form ("endpoint" + lowercase base32-nopad).
        const ticket_string = try encodeTicketString(allocator, endpoint);
        defer allocator.free(ticket_string);
        try std.testing.expectEqualStrings(fx.ticket_string, ticket_string);
        var back = try decodeTicketString(allocator, ticket_string);
        defer back.deinit(allocator);
        try std.testing.expect(back.id.eql(endpoint.id));
        try std.testing.expectEqual(endpoint.addrs.len, back.addrs.len);
    }
}
