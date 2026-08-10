//! BlobTicket content locator compatible with iroh-blobs' legacy ticket wire.

const std = @import("std");
const addr = @import("../addr.zig");
const endpoint_ticket = @import("../ticket.zig");
const key = @import("../key.zig");
const Hash = @import("../hash.zig").Hash;
const types = @import("types.zig");

pub const BlobFormat = types.BlobFormat;
pub const HashAndFormat = types.HashAndFormat;
pub const Error = endpoint_ticket.Error || addr.AddrError || error{InvalidBlobFormat};

/// Decode bounds for untrusted BlobTicket bytes / `blob…` strings (F27).
/// iroh-blobs documents no hard ticket max; these are explicit product caps.
pub const max_relay_url_len: usize = 8 * 1024; // 8 KiB
pub const max_ip_addrs: u64 = 32;
/// Minimum postcard wire size for one direct IP (family tag + IPv4 + 1-byte port).
const min_ip_wire_bytes: u64 = 6;

pub const BlobTicket = struct {
    endpoint: addr.EndpointAddr,
    hash: Hash,
    format: BlobFormat,

    pub fn init(
        allocator: std.mem.Allocator,
        endpoint: addr.EndpointAddr,
        hash: Hash,
        format: BlobFormat,
    ) Error!BlobTicket {
        return .{
            .endpoint = try endpoint.clone(allocator),
            .hash = hash,
            .format = format,
        };
    }

    pub fn deinit(self: *BlobTicket, allocator: std.mem.Allocator) void {
        self.endpoint.deinit(allocator);
        self.* = undefined;
    }

    pub fn recursive(self: BlobTicket) bool {
        return self.format == .hash_seq;
    }

    pub fn hashAndFormat(self: BlobTicket) HashAndFormat {
        return .{ .hash = self.hash, .format = self.format };
    }

    pub fn encodeBytes(self: BlobTicket, out: []u8) Error![]u8 {
        var index: usize = 0;
        try writeVarint(out, &index, 0); // TicketWireFormat::Variant0
        try writeBytes(out, &index, &self.endpoint.id.bytes);

        var first_relay: ?addr.RelayUrl = null;
        var ip_count: usize = 0;
        for (self.endpoint.addrs) |transport_addr| switch (transport_addr) {
            .relay => |relay| if (first_relay == null) {
                first_relay = relay;
            },
            .ip => ip_count += 1,
            .custom => {}, // Legacy BlobTicket cannot carry custom addresses.
        };

        if (first_relay) |relay| {
            try writeVarint(out, &index, 1); // Option::Some
            const value = relay.asString();
            try writeVarint(out, &index, value.len);
            try writeBytes(out, &index, value);
        } else {
            try writeVarint(out, &index, 0); // Option::None
        }

        try writeVarint(out, &index, ip_count);
        for (self.endpoint.addrs) |transport_addr| switch (transport_addr) {
            .ip => |ip| try encodeSocketAddr(ip, out, &index),
            else => {},
        };

        try writeVarint(out, &index, @intFromEnum(self.format));
        try writeBytes(out, &index, &self.hash.bytes);
        return out[0..index];
    }

    pub fn encodeString(self: BlobTicket, allocator: std.mem.Allocator) Error![]u8 {
        const raw = allocator.alloc(u8, encodedSizeBound(self.endpoint)) catch return error.OutOfMemory;
        defer allocator.free(raw);
        const bytes = try self.encodeBytes(raw);
        const encoded_len = (bytes.len * 8 + 4) / 5;
        const encoded = allocator.alloc(u8, encoded_len) catch return error.OutOfMemory;
        defer allocator.free(encoded);
        const actual_len = try endpoint_ticket.base32NoPadEncode(bytes, encoded);
        for (encoded[0..actual_len]) |*byte| byte.* = std.ascii.toLower(byte.*);
        return std.fmt.allocPrint(allocator, "blob{s}", .{encoded[0..actual_len]}) catch error.OutOfMemory;
    }

    pub fn decodeBytes(allocator: std.mem.Allocator, bytes: []const u8) Error!BlobTicket {
        var index: usize = 0;
        if (try readVarint(bytes, &index) != 0) return error.UnsupportedVariant;

        const id_slice = try readSlice(bytes, &index, 32);
        var id_bytes: [32]u8 = undefined;
        @memcpy(&id_bytes, id_slice);
        const id = key.PublicKey.fromBytes(id_bytes) catch return error.InvalidPublicKey;

        var addrs: std.ArrayList(addr.TransportAddr) = .empty;
        errdefer {
            for (addrs.items) |item| item.deinit(allocator);
            addrs.deinit(allocator);
        }

        switch (try readVarint(bytes, &index)) {
            0 => {},
            1 => {
                const relay_len = std.math.cast(usize, try readVarint(bytes, &index)) orelse
                    return error.InvalidRelayUrl;
                if (relay_len > max_relay_url_len) return error.InvalidRelayUrl;
                // Remaining-bytes check before parse/alloc that copies the URL.
                if (relay_len > bytes.len - index) return error.InvalidEncoding;
                const relay_text = try readSlice(bytes, &index, relay_len);
                const relay = addr.RelayUrl.parse(allocator, relay_text) catch return error.InvalidRelayUrl;
                try addrs.append(allocator, .{ .relay = relay });
            },
            else => return error.InvalidEncoding,
        }

        const ip_count = try readVarint(bytes, &index);
        if (ip_count > max_ip_addrs) return error.InvalidEncoding;
        // Remaining-bytes floor before the decode loop (min IPv4 wire size × count).
        if (ip_count > 0) {
            const need = std.math.mul(u64, ip_count, min_ip_wire_bytes) catch return error.InvalidEncoding;
            if (need > bytes.len - index) return error.InvalidEncoding;
        }
        var ip_index: u64 = 0;
        while (ip_index < ip_count) : (ip_index += 1) {
            try addrs.append(allocator, .{ .ip = try decodeSocketAddr(bytes, &index) });
        }

        const format: BlobFormat = switch (try readVarint(bytes, &index)) {
            0 => .raw,
            1 => .hash_seq,
            else => return error.InvalidBlobFormat,
        };
        const hash_slice = try readSlice(bytes, &index, 32);
        if (index != bytes.len) return error.InvalidEncoding;
        var hash_bytes: [32]u8 = undefined;
        @memcpy(&hash_bytes, hash_slice);

        const endpoint = try addr.EndpointAddr.fromParts(allocator, id, addrs.items);
        for (addrs.items) |item| item.deinit(allocator);
        addrs.deinit(allocator);
        return .{
            .endpoint = endpoint,
            .hash = .fromBytes(hash_bytes),
            .format = format,
        };
    }

    pub fn decodeString(allocator: std.mem.Allocator, text: []const u8) Error!BlobTicket {
        const prefix = "blob";
        if (!std.mem.startsWith(u8, text, prefix)) return error.InvalidEncoding;
        const encoded = text[prefix.len..];
        const upper = allocator.alloc(u8, encoded.len) catch return error.OutOfMemory;
        defer allocator.free(upper);
        for (encoded, 0..) |byte, i| upper[i] = std.ascii.toUpper(byte);
        const raw = allocator.alloc(u8, (encoded.len * 5 + 7) / 8) catch return error.OutOfMemory;
        defer allocator.free(raw);
        const raw_len = try endpoint_ticket.base32NoPadDecode(upper, raw);
        return decodeBytes(allocator, raw[0..raw_len]);
    }
};

fn encodedSizeBound(endpoint: addr.EndpointAddr) usize {
    var size: usize = 1 + 32 + 1 + 10 + 1 + 32;
    for (endpoint.addrs) |transport_addr| switch (transport_addr) {
        .relay => |relay| size += 10 + relay.asString().len,
        .ip => size += 1 + 16 + 5,
        .custom => {},
    };
    return size;
}

fn encodeSocketAddr(ip: std.Io.net.IpAddress, out: []u8, index: *usize) Error!void {
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
}

fn decodeSocketAddr(bytes: []const u8, index: *usize) Error!std.Io.net.IpAddress {
    return switch (try readVarint(bytes, index)) {
        0 => blk: {
            var ip_bytes: [4]u8 = undefined;
            @memcpy(&ip_bytes, try readSlice(bytes, index, 4));
            const port = std.math.cast(u16, try readVarint(bytes, index)) orelse return error.InvalidIpAddress;
            break :blk .{ .ip4 = .{ .bytes = ip_bytes, .port = port } };
        },
        1 => blk: {
            var ip_bytes: [16]u8 = undefined;
            @memcpy(&ip_bytes, try readSlice(bytes, index, 16));
            const port = std.math.cast(u16, try readVarint(bytes, index)) orelse return error.InvalidIpAddress;
            break :blk .{ .ip6 = .{ .bytes = ip_bytes, .port = port } };
        },
        else => error.InvalidIpAddress,
    };
}

fn writeVarint(out: []u8, index: *usize, value: u64) Error!void {
    var remaining = value;
    while (true) {
        const byte: u8 = @truncate(remaining & 0x7f);
        remaining >>= 7;
        try writeByte(out, index, if (remaining == 0) byte else byte | 0x80);
        if (remaining == 0) return;
    }
}

fn readVarint(bytes: []const u8, index: *usize) Error!u64 {
    var result: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        const byte = try readByte(bytes, index);
        result |= @as(u64, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) return result;
        if (shift >= 63) return error.VarintOverflow;
        shift += 7;
    }
}

fn writeByte(out: []u8, index: *usize, byte: u8) Error!void {
    if (index.* >= out.len) return error.BufferTooSmall;
    out[index.*] = byte;
    index.* += 1;
}

fn writeBytes(out: []u8, index: *usize, bytes: []const u8) Error!void {
    if (index.* + bytes.len > out.len) return error.BufferTooSmall;
    @memcpy(out[index.*..][0..bytes.len], bytes);
    index.* += bytes.len;
}

fn readByte(bytes: []const u8, index: *usize) Error!u8 {
    if (index.* >= bytes.len) return error.EndOfStream;
    const byte = bytes[index.*];
    index.* += 1;
    return byte;
}

fn readSlice(bytes: []const u8, index: *usize, len: usize) Error![]const u8 {
    const end = std.math.add(usize, index.*, len) catch return error.EndOfStream;
    if (end > bytes.len) return error.EndOfStream;
    const result = bytes[index.*..end];
    index.* = end;
    return result;
}

test "BlobTicket matches iroh-blobs no-address golden bytes" {
    const allocator = std.testing.allocator;
    const endpoint_id = try key.PublicKey.fromHex("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6");
    const hash = try Hash.fromHex("0b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072");
    const endpoint = addr.EndpointAddr.new(endpoint_id);
    var ticket = try BlobTicket.init(allocator, endpoint, hash, .raw);
    defer ticket.deinit(allocator);

    var bytes_buffer: [256]u8 = undefined;
    const actual = try ticket.encodeBytes(&bytes_buffer);
    const expected_hex = "00ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b60000000b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072";
    var expected_buffer: [128]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&expected_buffer, expected_hex);
    try std.testing.expectEqualSlices(u8, expected, actual);

    const text = try ticket.encodeString(allocator);
    defer allocator.free(text);
    try std.testing.expect(std.mem.startsWith(u8, text, "blob"));
    var decoded = try BlobTicket.decodeString(allocator, text);
    defer decoded.deinit(allocator);
    try std.testing.expect(decoded.endpoint.id.eql(endpoint_id));
    try std.testing.expect(decoded.hash.eql(hash));
    try std.testing.expectEqual(BlobFormat.raw, decoded.format);
}

test "BlobTicket round-trips relay IPv4 IPv6 and recursive format" {
    const allocator = std.testing.allocator;
    const endpoint_id = key.SecretKey.fromBytes(.{0x42} ** 32).public();
    var relay = try addr.RelayUrl.parse(allocator, "https://relay.example.com.");
    defer relay.deinit(allocator);
    const ipv4 = try std.Io.net.IpAddress.parse("192.0.2.1", 4242);
    const ipv6 = try std.Io.net.IpAddress.parse("2001:db8::1", 443);
    var endpoint = try addr.EndpointAddr.fromParts(allocator, endpoint_id, &.{
        .{ .relay = relay },
        .{ .ip = ipv4 },
        .{ .ip = ipv6 },
    });
    defer endpoint.deinit(allocator);
    var ticket = try BlobTicket.init(allocator, endpoint, Hash.of("collection"), .hash_seq);
    defer ticket.deinit(allocator);
    try std.testing.expect(ticket.recursive());

    var buffer: [512]u8 = undefined;
    const encoded = try ticket.encodeBytes(&buffer);
    var decoded = try BlobTicket.decodeBytes(allocator, encoded);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), decoded.endpoint.addrs.len);
    try std.testing.expect(decoded.hash.eql(ticket.hash));
    try std.testing.expectEqual(BlobFormat.hash_seq, decoded.format);

    // Legal encodeString → decodeString round-trip still holds under F27 caps.
    const text = try ticket.encodeString(allocator);
    defer allocator.free(text);
    var from_text = try BlobTicket.decodeString(allocator, text);
    defer from_text.deinit(allocator);
    try std.testing.expect(from_text.hash.eql(ticket.hash));
    try std.testing.expectEqual(BlobFormat.hash_seq, from_text.format);
}

fn testEndpointIdBytes() ![32]u8 {
    // Deterministic valid Ed25519 public key (same seed family as round-trip test).
    return key.SecretKey.fromBytes(.{0x42} ** 32).public().bytes;
}

test "BlobTicket decode rejects relay_len above max_relay_url_len" {
    const allocator = std.testing.allocator;
    var buf: [64]u8 = undefined;
    var index: usize = 0;
    try writeVarint(&buf, &index, 0); // Variant0
    try writeBytes(&buf, &index, &(try testEndpointIdBytes()));
    try writeVarint(&buf, &index, 1); // Option::Some relay
    try writeVarint(&buf, &index, max_relay_url_len + 1);
    // No URL body — cap must fire before remaining-bytes / parse alloc.
    try std.testing.expectError(error.InvalidRelayUrl, BlobTicket.decodeBytes(allocator, buf[0..index]));
}

test "BlobTicket decode rejects relay_len past remaining bytes" {
    const allocator = std.testing.allocator;
    var buf: [64]u8 = undefined;
    var index: usize = 0;
    try writeVarint(&buf, &index, 0);
    try writeBytes(&buf, &index, &(try testEndpointIdBytes()));
    try writeVarint(&buf, &index, 1);
    try writeVarint(&buf, &index, 16); // within cap, but body absent
    try std.testing.expectError(error.InvalidEncoding, BlobTicket.decodeBytes(allocator, buf[0..index]));
}

test "BlobTicket decode rejects ip_count above max_ip_addrs" {
    const allocator = std.testing.allocator;
    var buf: [64]u8 = undefined;
    var index: usize = 0;
    try writeVarint(&buf, &index, 0);
    try writeBytes(&buf, &index, &(try testEndpointIdBytes()));
    try writeVarint(&buf, &index, 0); // no relay
    try writeVarint(&buf, &index, max_ip_addrs + 1);
    try std.testing.expectError(error.InvalidEncoding, BlobTicket.decodeBytes(allocator, buf[0..index]));
}

test "BlobTicket decode rejects ip_count that exceeds remaining bytes" {
    const allocator = std.testing.allocator;
    var buf: [64]u8 = undefined;
    var index: usize = 0;
    try writeVarint(&buf, &index, 0);
    try writeBytes(&buf, &index, &(try testEndpointIdBytes()));
    try writeVarint(&buf, &index, 0); // no relay
    try writeVarint(&buf, &index, 2); // within cap, but need ≥12 body bytes
    // Only 5 trailing bytes — below 2 × min_ip_wire_bytes.
    try writeBytes(&buf, &index, &.{ 0, 1, 2, 3, 4 });
    try std.testing.expectError(error.InvalidEncoding, BlobTicket.decodeBytes(allocator, buf[0..index]));
}
