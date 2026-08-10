//! STUN (RFC 5389) binding probe for the net report: a minimal codec
//! (Binding Request encode / Binding Response XOR-MAPPED-ADDRESS decode,
//! with plain MAPPED-ADDRESS as a legacy fallback) plus a real-UDP-socket
//! probe that reports the server-reflexive address the STUN server observed.
//!
//! The codec functions are pure (no sockets, no allocation) so they are
//! unit-testable in isolation; `probeBinding` is the only socket-touching
//! entry point.

const std = @import("std");

const net = std.Io.net;

/// RFC 5389 §6 magic cookie.
pub const magic_cookie: u32 = 0x2112A442;
/// STUN header size: type + length + cookie + 96-bit transaction id.
pub const header_len = 20;
pub const txn_id_len = 12;

const msg_type_binding_request: u16 = 0x0001;
const msg_type_binding_response: u16 = 0x0101;
const attr_mapped_address: u16 = 0x0001;
const attr_xor_mapped_address: u16 = 0x0020;
const family_ip4: u8 = 0x01;
const family_ip6: u8 = 0x02;

pub const DecodeError = error{
    /// Fewer bytes than the header (or than the declared message length).
    Truncated,
    /// Message type is not Binding Response.
    NotBindingResponse,
    /// Magic cookie mismatch — not a RFC 5389 message.
    WrongCookie,
    /// Transaction id does not match the request we sent.
    TransactionMismatch,
    /// Attribute header/value lengths do not parse.
    MalformedAttribute,
    /// Well-formed response carrying no (XOR-)MAPPED-ADDRESS.
    MissingMappedAddress,
    /// (XOR-)MAPPED-ADDRESS with an address family other than IPv4/IPv6.
    UnsupportedAddressFamily,
};

/// Encode a 20-byte Binding Request header (no attributes) into `out`.
pub fn encodeBindingRequest(out: *[header_len]u8, txn_id: *const [txn_id_len]u8) void {
    std.mem.writeInt(u16, out[0..2], msg_type_binding_request, .big);
    std.mem.writeInt(u16, out[2..4], 0, .big);
    std.mem.writeInt(u32, out[4..8], magic_cookie, .big);
    out[8..20].* = txn_id.*;
}

/// Parse a Binding Response and return the server-reflexive address from its
/// XOR-MAPPED-ADDRESS attribute (preferred) or a plain MAPPED-ADDRESS
/// attribute (legacy fallback). `txn_id` must be the transaction id of the
/// request this answers; a mismatch rejects the message.
pub fn decodeBindingResponse(bytes: []const u8, txn_id: *const [txn_id_len]u8) DecodeError!net.IpAddress {
    if (bytes.len < header_len) return error.Truncated;
    if (std.mem.readInt(u16, bytes[0..2], .big) != msg_type_binding_response) return error.NotBindingResponse;
    const msg_len = std.mem.readInt(u16, bytes[2..4], .big);
    if (bytes.len < header_len + @as(usize, msg_len)) return error.Truncated;
    if (std.mem.readInt(u32, bytes[4..8], .big) != magic_cookie) return error.WrongCookie;
    if (!std.mem.eql(u8, bytes[8..20], txn_id)) return error.TransactionMismatch;

    var mapped: ?net.IpAddress = null;
    var attrs = bytes[header_len .. header_len + @as(usize, msg_len)];
    while (attrs.len >= 4) {
        const attr_type = std.mem.readInt(u16, attrs[0..2], .big);
        const attr_len = std.mem.readInt(u16, attrs[2..4], .big);
        if (attrs.len < 4 + @as(usize, attr_len)) return error.MalformedAttribute;
        const value = attrs[4 .. 4 + @as(usize, attr_len)];
        switch (attr_type) {
            // XOR-MAPPED-ADDRESS wins immediately (RFC 5389 §15.2: it is the
            // authoritative server-reflexive address when present).
            attr_xor_mapped_address => return parseMappedAddress(value, txn_id, true),
            attr_mapped_address => mapped = try parseMappedAddress(value, txn_id, false),
            else => {},
        }
        const padded = (@as(usize, attr_len) + 3) & ~@as(usize, 3);
        if (4 + padded > attrs.len) return error.MalformedAttribute;
        attrs = attrs[4 + padded ..];
    }
    return mapped orelse error.MissingMappedAddress;
}

fn parseMappedAddress(value: []const u8, txn_id: *const [txn_id_len]u8, xor: bool) DecodeError!net.IpAddress {
    if (value.len < 4) return error.MalformedAttribute;
    const family = value[1];
    const raw_port = std.mem.readInt(u16, value[2..4], .big);
    const cookie_hi: u16 = @truncate(magic_cookie >> 16);
    const port: u16 = if (xor) raw_port ^ cookie_hi else raw_port;
    switch (family) {
        family_ip4 => {
            if (value.len < 8) return error.MalformedAttribute;
            var ip_bytes: [4]u8 = value[4..8].*;
            if (xor) {
                var mask: [4]u8 = undefined;
                std.mem.writeInt(u32, &mask, magic_cookie, .big);
                for (&ip_bytes, mask) |*b, m| b.* ^= m;
            }
            return .{ .ip4 = .{ .bytes = ip_bytes, .port = port } };
        },
        family_ip6 => {
            if (value.len < 20) return error.MalformedAttribute;
            var ip_bytes: [16]u8 = value[4..20].*;
            if (xor) {
                var mask: [16]u8 = undefined;
                std.mem.writeInt(u32, mask[0..4], magic_cookie, .big);
                mask[4..16].* = txn_id.*;
                for (&ip_bytes, mask) |*b, m| b.* ^= m;
            }
            return .{ .ip6 = .{ .bytes = ip_bytes, .port = port } };
        },
        else => return error.UnsupportedAddressFamily,
    }
}

/// Encode a Binding Response carrying `mapped` as XOR-MAPPED-ADDRESS,
/// echoing `txn_id`. Test fixtures use this to stand up a local STUN server.
/// Returns the message length written into `out` (32 bytes IPv4, 44 IPv6).
pub fn encodeBindingResponse(out: []u8, txn_id: *const [txn_id_len]u8, mapped: net.IpAddress) usize {
    const cookie_hi: u16 = @truncate(magic_cookie >> 16);
    switch (mapped) {
        .ip4 => |ip4| {
            std.debug.assert(out.len >= 32);
            std.mem.writeInt(u16, out[0..2], msg_type_binding_response, .big);
            std.mem.writeInt(u16, out[2..4], 4 + 8, .big);
            std.mem.writeInt(u32, out[4..8], magic_cookie, .big);
            out[8..20].* = txn_id.*;
            std.mem.writeInt(u16, out[20..22], attr_xor_mapped_address, .big);
            std.mem.writeInt(u16, out[22..24], 8, .big);
            out[24] = 0;
            out[25] = family_ip4;
            std.mem.writeInt(u16, out[26..28], ip4.port ^ cookie_hi, .big);
            var mask: [4]u8 = undefined;
            std.mem.writeInt(u32, &mask, magic_cookie, .big);
            for (out[28..32], ip4.bytes, mask) |*o, b, m| o.* = b ^ m;
            return 32;
        },
        .ip6 => |ip6| {
            std.debug.assert(out.len >= 48);
            std.mem.writeInt(u16, out[0..2], msg_type_binding_response, .big);
            std.mem.writeInt(u16, out[2..4], 4 + 20, .big);
            std.mem.writeInt(u32, out[4..8], magic_cookie, .big);
            out[8..20].* = txn_id.*;
            std.mem.writeInt(u16, out[20..22], attr_xor_mapped_address, .big);
            std.mem.writeInt(u16, out[22..24], 20, .big);
            out[24] = 0;
            out[25] = family_ip6;
            std.mem.writeInt(u16, out[26..28], ip6.port ^ cookie_hi, .big);
            var mask: [16]u8 = undefined;
            std.mem.writeInt(u32, mask[0..4], magic_cookie, .big);
            mask[4..16].* = txn_id.*;
            for (out[28..44], ip6.bytes, mask) |*o, b, m| o.* = b ^ m;
            return 44;
        },
    }
}

pub const BindingResult = struct {
    /// Server-reflexive address the STUN server observed for this probe.
    srflx: net.IpAddress,
    /// Local address of the probe socket (ephemeral port resolved by bind).
    local: net.IpAddress,
};

/// One STUN Binding Request against `server` over a real UDP socket, with a
/// `receiveTimeout` wait for the response. Returns `error.Timeout` when no
/// response arrives within `timeout`.
///
/// The probe socket binds loopback when the server is a loopback address
/// (local-path probes observe the true local address) and unspecified
/// otherwise — see `net_report.classifyNat` for how that shapes the NAT
/// classification.
pub fn probeBinding(io: std.Io, server: net.IpAddress, timeout: std.Io.Timeout) !BindingResult {
    var bind_addr: net.IpAddress = switch (server) {
        .ip4 => |ip4| .{ .ip4 = if (ip4.bytes[0] == 127) net.Ip4Address.loopback(0) else net.Ip4Address.unspecified(0) },
        .ip6 => |ip6| .{ .ip6 = if (ip6.isLoopBack()) net.Ip6Address.loopback(0) else net.Ip6Address.unspecified(0) },
    };
    const socket = try bind_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    var txn_id: [txn_id_len]u8 = undefined;
    io.random(&txn_id);
    var request: [header_len]u8 = undefined;
    encodeBindingRequest(&request, &txn_id);
    try socket.send(io, &server, &request);

    var buf: [576]u8 = undefined;
    const msg = socket.receiveTimeout(io, &buf, timeout) catch |err| switch (err) {
        error.Timeout => return error.Timeout,
        else => return err,
    };
    if (!sameHost(msg.from, server)) return error.UnexpectedSource;
    return .{
        .srflx = try decodeBindingResponse(msg.data, &txn_id),
        .local = socket.address,
    };
}

fn sameHost(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| std.mem.eql(u8, &a4.bytes, &b4.bytes),
            .ip6 => false,
        },
        .ip6 => |a6| switch (b) {
            .ip4 => false,
            .ip6 => |b6| std.mem.eql(u8, &a6.bytes, &b6.bytes),
        },
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_txn: [txn_id_len]u8 = .{ 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB };

test "STUN binding request encode is a well-formed 20-byte header" {
    var request: [header_len]u8 = undefined;
    encodeBindingRequest(&request, &test_txn);
    try testing.expectEqual(msg_type_binding_request, std.mem.readInt(u16, request[0..2], .big));
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, request[2..4], .big));
    try testing.expectEqual(magic_cookie, std.mem.readInt(u32, request[4..8], .big));
    try testing.expectEqualSlices(u8, &test_txn, request[8..20]);
}

test "STUN XOR-MAPPED-ADDRESS decode round-trips an IPv4 address" {
    // Hand-built response for mapped 203.0.113.7:40000 (no shared code with
    // the decoder, so a codec bug cannot mask itself):
    //   xport = 40000 ^ 0x2112 = 0x9C40 ^ 0x2112 = 0xBD52
    //   xaddr = {203,0,113,7} ^ {0x21,0x12,0xA4,0x42} = {0xEA,0x12,0xD5,0x45}
    const response = [_]u8{
        0x01, 0x01, // Binding Response
        0x00, 0x0C, // message length 12 (one attribute)
        0x21, 0x12, 0xA4, 0x42, // magic cookie
    } ++ test_txn ++ [_]u8{
        0x00, 0x20, // XOR-MAPPED-ADDRESS
        0x00, 0x08, // attribute length 8
        0x00, 0x01, // zero, family IPv4
        0xBD, 0x52, // XOR port
        0xEA, 0x12, 0xD5, 0x45, // XOR address
    };
    const mapped = try decodeBindingResponse(&response, &test_txn);
    try testing.expectEqual(net.IpAddress{ .ip4 = .{ .bytes = .{ 203, 0, 113, 7 }, .port = 40000 } }, mapped);
}

test "STUN decode accepts plain MAPPED-ADDRESS as a fallback" {
    const response = [_]u8{
        0x01, 0x01, // Binding Response
        0x00, 0x0C, // message length 12
        0x21, 0x12, 0xA4, 0x42,
    } ++ test_txn ++ [_]u8{
        0x00, 0x01, // MAPPED-ADDRESS (legacy, no XOR)
        0x00, 0x08,
        0x00, 0x01,
        0x9C, 0x40, // port 40000, in the clear
        203,  0,   113, 7,
    };
    const mapped = try decodeBindingResponse(&response, &test_txn);
    try testing.expectEqual(net.IpAddress{ .ip4 = .{ .bytes = .{ 203, 0, 113, 7 }, .port = 40000 } }, mapped);
}

test "STUN decode rejects garbage, truncated, wrong-cookie, and foreign responses" {
    const valid = [_]u8{
        0x01, 0x01,
        0x00, 0x0C,
        0x21, 0x12, 0xA4, 0x42,
    } ++ test_txn ++ [_]u8{
        0x00, 0x20,
        0x00, 0x08,
        0x00, 0x01,
        0xBD, 0x52,
        0xEA, 0x12, 0xD5, 0x45,
    };

    // Truncated below the header, and truncated inside the attribute body.
    try testing.expectError(error.Truncated, decodeBindingResponse(valid[0..10], &test_txn));
    try testing.expectError(error.Truncated, decodeBindingResponse(valid[0..24], &test_txn));

    // Garbage: not a Binding Response type.
    var wrong_type = valid;
    wrong_type[1] = 0x11;
    try testing.expectError(error.NotBindingResponse, decodeBindingResponse(&wrong_type, &test_txn));

    // Wrong magic cookie.
    var wrong_cookie = valid;
    wrong_cookie[4] = 0x00;
    try testing.expectError(error.WrongCookie, decodeBindingResponse(&wrong_cookie, &test_txn));

    // Response to somebody else's transaction id.
    var other_txn = test_txn;
    other_txn[11] ^= 0xFF;
    try testing.expectError(error.TransactionMismatch, decodeBindingResponse(&valid, &other_txn));

    // Declared attribute length overruns the message body.
    var overrun = valid;
    overrun[23] = 0x10; // attribute length 16 > remaining 8
    try testing.expectError(error.MalformedAttribute, decodeBindingResponse(&overrun, &test_txn));

    // Well-formed response with no mapped-address attribute at all.
    const bare = [_]u8{
        0x01, 0x01,
        0x00, 0x00, // message length 0
        0x21, 0x12, 0xA4, 0x42,
    } ++ test_txn;
    try testing.expectError(error.MissingMappedAddress, decodeBindingResponse(&bare, &test_txn));
}

test "STUN decode rejects maximum message length truncation without panic" {
    const response = [_]u8{
        0x01, 0x01, // Binding Response
        0xFF, 0xFF, // message length 65535 > available body
        0x21, 0x12, 0xA4, 0x42,
    } ++ test_txn;
    try testing.expectError(error.Truncated, decodeBindingResponse(&response, &test_txn));
}

test "STUN decode rejects oversized attribute length without panic" {
    const response = [_]u8{
        0x01, 0x01, // Binding Response
        0x00, 0x04, // message length 4 (attribute header only)
        0x21, 0x12, 0xA4, 0x42,
    } ++ test_txn ++ [_]u8{
        0x77, 0x77, // unknown attribute type
        0xFF, 0xFC, // attribute length 65532 > remaining body
    };
    try testing.expectError(error.MalformedAttribute, decodeBindingResponse(&response, &test_txn));
}

test "STUN decode rejects attribute padding overrun without panic" {
    const response = [_]u8{
        0x01, 0x01, // Binding Response
        0x00, 0x05, // message length 5 (attribute header + 1 unpadded byte)
        0x21, 0x12, 0xA4, 0x42,
    } ++ test_txn ++ [_]u8{
        0x77, 0x77, // unknown attribute type
        0x00, 0x01, // attribute length 1, padded extent would be 4
        0x00,
    };
    try testing.expectError(error.MalformedAttribute, decodeBindingResponse(&response, &test_txn));
}

test "STUN binding probe over a real loopback UDP socket reports the server-reflexive address" {
    const allocator = testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Minimal STUN server: answer any well-formed Binding Request with a
    // XOR-MAPPED-ADDRESS echoing the request's transaction id and carrying
    // the sender's observed address.
    const Fixture = struct {
        io: std.Io,
        socket: net.Socket,
        stopped: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            defer self.socket.close(self.io);
            var buf: [576]u8 = undefined;
            while (!self.stopped.load(.acquire)) {
                const msg = self.socket.receiveTimeout(self.io, &buf, .{
                    .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake },
                }) catch continue;
                if (msg.data.len < header_len) continue;
                if (std.mem.readInt(u16, msg.data[0..2], .big) != msg_type_binding_request) continue;
                var resp: [64]u8 = undefined;
                const n = encodeBindingResponse(&resp, msg.data[8..20], msg.from);
                self.socket.send(self.io, &msg.from, resp[0..n]) catch {};
            }
        }
    };

    // Bound by the main thread before spawn, so the first request cannot
    // race the fixture's bind (same discipline as the portmapper tests).
    var fixture_bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const fixture_socket = try fixture_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var fixture: Fixture = .{ .io = io, .socket = fixture_socket };
    const thread = try std.Thread.spawn(.{}, Fixture.run, .{&fixture});
    defer {
        fixture.stopped.store(true, .release);
        thread.join();
    }

    const server: net.IpAddress = .{ .ip4 = .loopback(fixture_socket.address.getPort()) };
    const result = try probeBinding(io, server, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });

    // Loopback path: the server observes exactly the probe socket's local
    // address, and the bind resolved a real ephemeral port.
    try testing.expect(result.local.getPort() != 0);
    try testing.expect(result.srflx.eql(&result.local));
}
