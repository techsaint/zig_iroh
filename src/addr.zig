//! Endpoint addressing — where to reach an iroh endpoint.
//!
//! Mirrors iroh's `EndpointAddr { id, addrs: BTreeSet<TransportAddr> }`
//! shape while using Zig-owned slices instead of a tree container. Builders
//! sort and deduplicate so stored addresses have deterministic BTreeSet-like
//! order. `NodeAddr` remains a temporary alias for callers that have not yet
//! renamed their transport-facing type.

const std = @import("std");
const key = @import("key.zig");

const net = std.Io.net;

pub const AddrError = error{
    InvalidRelayUrl,
    InvalidCustomAddr,
    CustomAddrTooShort,
    OutOfMemory,
};

pub const RelayUrl = struct {
    text: []const u8,
    owned: bool = false,

    pub fn parse(allocator: std.mem.Allocator, value: []const u8) AddrError!RelayUrl {
        validateRelayUrl(value) catch return error.InvalidRelayUrl;
        return .{ .text = try canonicalRelayUrl(allocator, value), .owned = true };
    }

    pub fn borrowed(value: []const u8) RelayUrl {
        return .{ .text = value, .owned = false };
    }

    pub fn clone(self: RelayUrl, allocator: std.mem.Allocator) AddrError!RelayUrl {
        return .{ .text = try allocator.dupe(u8, self.text), .owned = true };
    }

    pub fn deinit(self: RelayUrl, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.text);
    }

    pub fn eql(self: RelayUrl, other: RelayUrl) bool {
        return std.mem.eql(u8, self.text, other.text);
    }

    pub fn asString(self: RelayUrl) []const u8 {
        return self.text;
    }
};

fn validateRelayUrl(value: []const u8) AddrError!void {
    if (std.mem.indexOfAny(u8, value, " \t\r\n") != null) return error.InvalidRelayUrl;
    const scheme = std.mem.indexOf(u8, value, "://") orelse return error.InvalidRelayUrl;
    if (scheme == 0) return error.InvalidRelayUrl;
    const authority_start = scheme + 3;
    const rest = value[authority_start..];
    const authority_len = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    if (authority_len == 0) return error.InvalidRelayUrl;
}

fn canonicalRelayUrl(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const scheme = std.mem.indexOf(u8, value, "://") orelse return allocator.dupe(u8, value);
    const authority_start = scheme + 3;
    const rest = value[authority_start..];
    const path_start = std.mem.indexOfAny(u8, rest, "/?#") orelse
        return std.fmt.allocPrint(allocator, "{s}/", .{value});
    if (rest[path_start] == '/') return allocator.dupe(u8, value);
    const insert_at = authority_start + path_start;
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ value[0..insert_at], value[insert_at..] });
}

pub const CustomAddr = struct {
    id: u64,
    data: []const u8 = &.{},
    owned: bool = false,

    pub fn fromParts(allocator: std.mem.Allocator, id: u64, data: []const u8) AddrError!CustomAddr {
        return .{ .id = id, .data = try allocator.dupe(u8, data), .owned = true };
    }

    pub fn borrowed(id: u64, data: []const u8) CustomAddr {
        return .{ .id = id, .data = data, .owned = false };
    }

    pub fn parse(allocator: std.mem.Allocator, value: []const u8) AddrError!CustomAddr {
        const sep = std.mem.indexOfScalar(u8, value, '_') orelse return error.InvalidCustomAddr;
        const id_text = value[0..sep];
        const data_text = value[sep + 1 ..];
        const id = std.fmt.parseUnsigned(u64, id_text, 16) catch return error.InvalidCustomAddr;
        if (data_text.len % 2 != 0) return error.InvalidCustomAddr;
        for (data_text) |c| {
            if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return error.InvalidCustomAddr;
        }
        const data = try allocator.alloc(u8, data_text.len / 2);
        errdefer allocator.free(data);
        _ = std.fmt.hexToBytes(data, data_text) catch return error.InvalidCustomAddr;
        return .{ .id = id, .data = data, .owned = true };
    }

    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) AddrError!CustomAddr {
        if (bytes.len < 8) return error.CustomAddrTooShort;
        const id = std.mem.readInt(u64, bytes[0..8], .little);
        return fromParts(allocator, id, bytes[8..]);
    }

    pub fn toBytes(self: CustomAddr, allocator: std.mem.Allocator) AddrError![]u8 {
        const out = try allocator.alloc(u8, 8 + self.data.len);
        std.mem.writeInt(u64, out[0..8], self.id, .little);
        @memcpy(out[8..], self.data);
        return out;
    }

    pub fn toString(self: CustomAddr, allocator: std.mem.Allocator) AddrError![]u8 {
        return std.fmt.allocPrint(allocator, "{x}_{x}", .{ self.id, self.data });
    }

    pub fn clone(self: CustomAddr, allocator: std.mem.Allocator) AddrError!CustomAddr {
        return fromParts(allocator, self.id, self.data);
    }

    pub fn deinit(self: CustomAddr, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.data);
    }

    pub fn eql(self: CustomAddr, other: CustomAddr) bool {
        return self.id == other.id and std.mem.eql(u8, self.data, other.data);
    }
};

pub const TransportAddr = union(enum) {
    relay: RelayUrl,
    ip: net.IpAddress,
    custom: CustomAddr,

    pub fn relayUrl(value: RelayUrl) TransportAddr {
        return .{ .relay = value };
    }

    pub fn ipAddr(value: net.IpAddress) TransportAddr {
        return .{ .ip = value };
    }

    pub fn customAddr(value: CustomAddr) TransportAddr {
        return .{ .custom = value };
    }

    pub fn isRelay(self: TransportAddr) bool {
        return switch (self) {
            .relay => true,
            else => false,
        };
    }

    pub fn isIp(self: TransportAddr) bool {
        return switch (self) {
            .ip => true,
            else => false,
        };
    }

    pub fn isCustom(self: TransportAddr) bool {
        return switch (self) {
            .custom => true,
            else => false,
        };
    }

    pub fn clone(self: TransportAddr, allocator: std.mem.Allocator) AddrError!TransportAddr {
        return switch (self) {
            .relay => |relay| .{ .relay = try relay.clone(allocator) },
            .ip => |ip| .{ .ip = ip },
            .custom => |custom| .{ .custom = try custom.clone(allocator) },
        };
    }

    pub fn deinit(self: TransportAddr, allocator: std.mem.Allocator) void {
        switch (self) {
            .relay => |relay| relay.deinit(allocator),
            .ip => {},
            .custom => |custom| custom.deinit(allocator),
        }
    }

    pub fn eql(self: TransportAddr, other: TransportAddr) bool {
        return orderTransportAddr(self, other) == .eq;
    }

    pub fn toString(self: TransportAddr, allocator: std.mem.Allocator) AddrError![]u8 {
        return switch (self) {
            .relay => |relay| std.fmt.allocPrint(allocator, "relay:{s}", .{relay.asString()}),
            .ip => |ip| std.fmt.allocPrint(allocator, "ip:{f}", .{ip}),
            .custom => |custom| blk: {
                const custom_text = try custom.toString(allocator);
                defer allocator.free(custom_text);
                break :blk std.fmt.allocPrint(allocator, "custom:{s}", .{custom_text});
            },
        };
    }
};

pub const EndpointAddr = struct {
    id: key.NodeId,
    addrs: []const TransportAddr = &.{},
    owned: bool = false,

    pub fn new(id: key.NodeId) EndpointAddr {
        return .{ .id = id };
    }

    pub fn init(id: key.NodeId) EndpointAddr {
        return new(id);
    }

    pub fn fromParts(
        allocator: std.mem.Allocator,
        id: key.NodeId,
        addrs: []const TransportAddr,
    ) AddrError!EndpointAddr {
        var list: std.ArrayList(TransportAddr) = .empty;
        errdefer {
            for (list.items) |item| item.deinit(allocator);
            list.deinit(allocator);
        }
        for (addrs) |item| try list.append(allocator, try item.clone(allocator));
        const owned_addrs = try sortedDedupedOwnedSlice(allocator, &list);
        return .{ .id = id, .addrs = owned_addrs, .owned = true };
    }

    /// Consumes `self` and returns a new address set containing `relay_url`.
    pub fn withRelayUrl(
        self: EndpointAddr,
        allocator: std.mem.Allocator,
        relay_url: RelayUrl,
    ) AddrError!EndpointAddr {
        return self.withAddrs(allocator, &.{.{ .relay = relay_url }});
    }

    /// Consumes `self` and returns a new address set containing `addr`.
    pub fn withIpAddr(
        self: EndpointAddr,
        allocator: std.mem.Allocator,
        addr: net.IpAddress,
    ) AddrError!EndpointAddr {
        return self.withAddrs(allocator, &.{.{ .ip = addr }});
    }

    /// Consumes `self` and returns a new address set containing all `addrs`.
    pub fn withAddrs(
        self: EndpointAddr,
        allocator: std.mem.Allocator,
        addrs: []const TransportAddr,
    ) AddrError!EndpointAddr {
        var old = self;
        defer old.deinit(allocator);
        var list: std.ArrayList(TransportAddr) = .empty;
        errdefer {
            for (list.items) |item| item.deinit(allocator);
            list.deinit(allocator);
        }
        for (self.addrs) |item| try list.append(allocator, try item.clone(allocator));
        for (addrs) |item| try list.append(allocator, try item.clone(allocator));
        const owned_addrs = try sortedDedupedOwnedSlice(allocator, &list);
        return .{ .id = self.id, .addrs = owned_addrs, .owned = true };
    }

    pub fn clone(self: EndpointAddr, allocator: std.mem.Allocator) AddrError!EndpointAddr {
        return fromParts(allocator, self.id, self.addrs);
    }

    pub fn deinit(self: *EndpointAddr, allocator: std.mem.Allocator) void {
        if (!self.owned) return;
        for (self.addrs) |item| item.deinit(allocator);
        allocator.free(self.addrs);
        self.* = .{ .id = self.id };
    }

    pub fn isEmpty(self: EndpointAddr) bool {
        return self.addrs.len == 0;
    }

    pub fn firstIpAddr(self: EndpointAddr) ?net.IpAddress {
        var it = self.ipAddrs();
        return it.next();
    }

    pub fn firstRelayUrl(self: EndpointAddr) ?RelayUrl {
        var it = self.relayUrls();
        return it.next();
    }

    pub fn ipAddrs(self: EndpointAddr) IpAddrIterator {
        return .{ .addrs = self.addrs };
    }

    pub fn relayUrls(self: EndpointAddr) RelayUrlIterator {
        return .{ .addrs = self.addrs };
    }
};

pub const NodeAddr = EndpointAddr;

pub const IpAddrIterator = struct {
    addrs: []const TransportAddr,
    index: usize = 0,

    pub fn next(self: *IpAddrIterator) ?net.IpAddress {
        while (self.index < self.addrs.len) {
            const item = self.addrs[self.index];
            self.index += 1;
            switch (item) {
                .ip => |ip| return ip,
                else => {},
            }
        }
        return null;
    }
};

pub const RelayUrlIterator = struct {
    addrs: []const TransportAddr,
    index: usize = 0,

    pub fn next(self: *RelayUrlIterator) ?RelayUrl {
        while (self.index < self.addrs.len) {
            const item = self.addrs[self.index];
            self.index += 1;
            switch (item) {
                .relay => |relay| return relay,
                else => {},
            }
        }
        return null;
    }
};

fn sortedDedupedOwnedSlice(
    allocator: std.mem.Allocator,
    list: *std.ArrayList(TransportAddr),
) AddrError![]TransportAddr {
    std.sort.pdq(TransportAddr, list.items, {}, transportAddrLessThan);
    if (list.items.len == 0) return list.toOwnedSlice(allocator);
    var write: usize = 1;
    var read: usize = 1;
    while (read < list.items.len) : (read += 1) {
        if (list.items[write - 1].eql(list.items[read])) {
            list.items[read].deinit(allocator);
            continue;
        }
        if (write != read) list.items[write] = list.items[read];
        write += 1;
    }
    list.shrinkAndFree(allocator, write);
    return list.toOwnedSlice(allocator);
}

fn transportAddrLessThan(_: void, a: TransportAddr, b: TransportAddr) bool {
    return orderTransportAddr(a, b) == .lt;
}

fn orderTransportAddr(a: TransportAddr, b: TransportAddr) std.math.Order {
    const ar = transportAddrRank(a);
    const br = transportAddrRank(b);
    if (ar != br) return std.math.order(ar, br);
    return switch (a) {
        .relay => |ra| std.mem.order(u8, ra.asString(), b.relay.asString()),
        .ip => |ia| orderIpAddress(ia, b.ip),
        .custom => |ca| orderCustomAddr(ca, b.custom),
    };
}

fn transportAddrRank(addr: TransportAddr) u8 {
    return switch (addr) {
        .relay => 0,
        .ip => 1,
        .custom => 2,
    };
}

fn orderCustomAddr(a: CustomAddr, b: CustomAddr) std.math.Order {
    const id_order = std.math.order(a.id, b.id);
    if (id_order != .eq) return id_order;
    return std.mem.order(u8, a.data, b.data);
}

fn orderIpAddress(a: net.IpAddress, b: net.IpAddress) std.math.Order {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| orderIp4(a4, b4),
            .ip6 => .lt,
        },
        .ip6 => |a6| switch (b) {
            .ip4 => .gt,
            .ip6 => |b6| orderIp6(a6, b6),
        },
    };
}

fn orderIp4(a: net.Ip4Address, b: net.Ip4Address) std.math.Order {
    const bytes = std.mem.order(u8, &a.bytes, &b.bytes);
    if (bytes != .eq) return bytes;
    return std.math.order(a.port, b.port);
}

fn orderIp6(a: net.Ip6Address, b: net.Ip6Address) std.math.Order {
    const bytes = std.mem.order(u8, &a.bytes, &b.bytes);
    if (bytes != .eq) return bytes;
    const port = std.math.order(a.port, b.port);
    if (port != .eq) return port;
    const flow = std.math.order(a.flow, b.flow);
    if (flow != .eq) return flow;
    return std.math.order(a.interface.index, b.interface.index);
}

test "CustomAddr display parse and little-endian binary encoding" {
    const allocator = std.testing.allocator;
    var bt = try CustomAddr.fromParts(allocator, 1, &.{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 });
    defer bt.deinit(allocator);
    const text = try bt.toString(allocator);
    defer allocator.free(text);
    try std.testing.expectEqualStrings("1_a1b2c3d4e5f6", text);

    var parsed = try CustomAddr.parse(allocator, text);
    defer parsed.deinit(allocator);
    try std.testing.expect(parsed.eql(bt));

    const bytes = try bt.toBytes(allocator);
    defer allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{ 1, 0, 0, 0, 0, 0, 0, 0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 }, bytes);

    var from_bytes = try CustomAddr.fromBytes(allocator, bytes);
    defer from_bytes.deinit(allocator);
    try std.testing.expect(from_bytes.eql(bt));
    try std.testing.expectError(error.InvalidCustomAddr, CustomAddr.parse(allocator, "1_abc"));
    try std.testing.expectError(error.CustomAddrTooShort, CustomAddr.fromBytes(allocator, bytes[0..7]));
}

test "RelayUrl canonicalizes Rust url display cases" {
    const allocator = std.testing.allocator;
    var plain = try RelayUrl.parse(allocator, "https://example.com");
    defer plain.deinit(allocator);
    try std.testing.expectEqualStrings("https://example.com/", plain.asString());

    var dotted = try RelayUrl.parse(allocator, "https://example.com.");
    defer dotted.deinit(allocator);
    try std.testing.expectEqualStrings("https://example.com./", dotted.asString());

    var with_query = try RelayUrl.parse(allocator, "https://example.com?x=1");
    defer with_query.deinit(allocator);
    try std.testing.expectEqualStrings("https://example.com/?x=1", with_query.asString());
}

test "EndpointAddr builders sort deduplicate and preserve custom addresses" {
    const allocator = std.testing.allocator;
    const id = key.SecretKey.fromBytes(.{0x42} ** 32).public();
    var relay = try RelayUrl.parse(allocator, "https://example.com");
    defer relay.deinit(allocator);
    const custom_data = [_]u8{0xab} ** 32;
    var custom = try CustomAddr.fromParts(allocator, 42, &custom_data);
    defer custom.deinit(allocator);
    const ip = try net.IpAddress.parse("127.0.0.1", 1234);

    var addr = try EndpointAddr.fromParts(allocator, id, &.{
        .{ .custom = custom },
        .{ .ip = ip },
        .{ .relay = relay },
        .{ .ip = ip },
    });
    defer addr.deinit(allocator);
    try std.testing.expect(!addr.isEmpty());
    try std.testing.expectEqual(@as(usize, 3), addr.addrs.len);
    try std.testing.expect(addr.addrs[0].isRelay());
    try std.testing.expect(addr.addrs[1].isIp());
    try std.testing.expect(addr.addrs[2].isCustom());
    try std.testing.expectEqual(ip, addr.firstIpAddr().?);
    try std.testing.expectEqualStrings("https://example.com/", addr.firstRelayUrl().?.asString());
}

test "TransportAddr display prefixes" {
    const allocator = std.testing.allocator;
    var relay = try RelayUrl.parse(allocator, "https://example.com");
    defer relay.deinit(allocator);
    var custom = try CustomAddr.fromParts(allocator, 0x2a, &.{ 0xab, 0xcd });
    defer custom.deinit(allocator);
    const ip = try net.IpAddress.parse("127.0.0.1", 1234);

    const relay_text = try (TransportAddr{ .relay = relay }).toString(allocator);
    defer allocator.free(relay_text);
    try std.testing.expectEqualStrings("relay:https://example.com/", relay_text);

    const ip_text = try (TransportAddr{ .ip = ip }).toString(allocator);
    defer allocator.free(ip_text);
    try std.testing.expectEqualStrings("ip:127.0.0.1:1234", ip_text);

    const custom_text = try (TransportAddr{ .custom = custom }).toString(allocator);
    defer allocator.free(custom_text);
    try std.testing.expectEqualStrings("custom:2a_abcd", custom_text);
}
