//! Endpoint addressing — where to reach an iroh endpoint.
//!
//! Mirrors iroh's `EndpointAddr { id, addrs: BTreeSet<TransportAddr> }`
//! shape while using Zig-owned slices instead of a tree container. Builders
//! sort and deduplicate so stored addresses have deterministic BTreeSet-like
//! order. `NodeAddr` remains a temporary alias for callers that have not yet
//! renamed their transport-facing type.

const std = @import("std");
const key = @import("key.zig");
const fixtures = @import("iroh_base_fixtures.zig");

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

    /// Parse and canonicalize a relay URL, mirroring iroh's `RelayUrl::from_str`
    /// (the Rust `url` crate): scheme/host are lowercased, the default port for
    /// the scheme is elided, an empty path becomes "/", dot-segments in the path
    /// are resolved (RFC 3986 §5.2.4), and query/fragment/userinfo pass through.
    /// Rejects missing scheme, empty authority, and invalid ports — the full
    /// matrix is pinned by the `relay_url` fixtures in `shared/iroh_base_fixtures.zig`.
    pub fn parse(allocator: std.mem.Allocator, value: []const u8) AddrError!RelayUrl {
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

fn defaultPortForScheme(scheme: []const u8) ?u16 {
    if (std.mem.eql(u8, scheme, "http") or std.mem.eql(u8, scheme, "ws")) return 80;
    if (std.mem.eql(u8, scheme, "https") or std.mem.eql(u8, scheme, "wss")) return 443;
    if (std.mem.eql(u8, scheme, "ftp")) return 21;
    return null;
}

fn canonicalRelayUrl(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    if (value.len == 0) return error.InvalidRelayUrl;
    // The Rust url crate is more lenient here (it strips \t\r\n); iroh relay
    // URLs never carry them, so the port rejects instead of silently rewriting.
    if (std.mem.indexOfAny(u8, value, " \t\r\n") != null) return error.InvalidRelayUrl;

    const scheme_end = std.mem.indexOf(u8, value, "://") orelse return error.InvalidRelayUrl;
    const scheme_raw = value[0..scheme_end];
    if (scheme_raw.len == 0) return error.InvalidRelayUrl;
    if (!std.ascii.isAlphabetic(scheme_raw[0])) return error.InvalidRelayUrl;
    var scheme_buf: [16]u8 = undefined;
    if (scheme_raw.len > scheme_buf.len) return error.InvalidRelayUrl;
    for (scheme_raw, 0..) |c, i| {
        if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '-' and c != '.')
            return error.InvalidRelayUrl;
        scheme_buf[i] = std.ascii.toLower(c);
    }
    const scheme = scheme_buf[0..scheme_raw.len];

    const rest = value[scheme_end + 3 ..];
    const authority_len = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    const authority = rest[0..authority_len];
    if (authority.len == 0) return error.InvalidRelayUrl;
    const tail = rest[authority_len..];

    // userinfo: the LAST '@' delimits it (userinfo itself may not hold a raw '@').
    const hostport = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at|
        authority[at + 1 ..]
    else
        authority;
    const userinfo = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at|
        authority[0 .. at + 1]
    else
        "";

    var host: []const u8 = undefined;
    var port_text: ?[]const u8 = null;
    if (hostport.len > 0 and hostport[0] == '[') {
        // IP literal: keep the bracketed form (lowercased), optional :port after.
        const close = std.mem.indexOfScalar(u8, hostport, ']') orelse return error.InvalidRelayUrl;
        host = hostport[0 .. close + 1];
        if (close + 1 < hostport.len) {
            if (hostport[close + 1] != ':') return error.InvalidRelayUrl;
            port_text = hostport[close + 2 ..];
        }
    } else {
        const colons = std.mem.count(u8, hostport, ":");
        if (colons > 1) return error.InvalidRelayUrl; // bare IPv6 must be bracketed
        if (std.mem.indexOfScalar(u8, hostport, ':')) |colon| {
            host = hostport[0..colon];
            port_text = hostport[colon + 1 ..];
        } else {
            host = hostport;
        }
    }
    if (host.len == 0) return error.InvalidRelayUrl;

    var port: ?u16 = null;
    if (port_text) |text| {
        if (text.len > 0) {
            for (text) |c| {
                if (!std.ascii.isDigit(c)) return error.InvalidRelayUrl;
            }
            const parsed = std.fmt.parseUnsigned(u32, text, 10) catch return error.InvalidRelayUrl;
            if (parsed > 65535) return error.InvalidRelayUrl;
            const p: u16 = @intCast(parsed);
            // The url crate elides the scheme's default port.
            if (defaultPortForScheme(scheme)) |def| {
                if (p != def) port = p;
            } else {
                port = p;
            }
        }
    }

    // path / query / fragment split.
    const frag_start = std.mem.indexOfScalar(u8, tail, '#') orelse tail.len;
    const query_start = std.mem.indexOfScalar(u8, tail[0..frag_start], '?') orelse frag_start;
    const path_raw = tail[0..query_start];
    const suffix = tail[query_start..]; // "?query" and/or "#fragment", verbatim

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, scheme);
    try out.appendSlice(allocator, "://");
    try out.appendSlice(allocator, userinfo);
    if (host.len > 0 and host[0] == '[') {
        for (host) |c| try out.append(allocator, std.ascii.toLower(c));
    } else {
        for (host) |c| try out.append(allocator, std.ascii.toLower(c));
    }
    if (port) |p| {
        try out.append(allocator, ':');
        try out.print(allocator, "{d}", .{p});
    }
    if (path_raw.len == 0) {
        try out.append(allocator, '/');
    } else {
        const path = try removeDotSegments(allocator, path_raw);
        defer allocator.free(path);
        try out.appendSlice(allocator, path);
    }
    try out.appendSlice(allocator, suffix);
    return out.toOwnedSlice(allocator);
}

/// RFC 3986 §5.2.4 dot-segment removal, as the Rust url crate applies to paths.
fn removeDotSegments(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var input = path;
    while (input.len > 0) {
        if (std.mem.startsWith(u8, input, "../")) {
            input = input[3..];
        } else if (std.mem.startsWith(u8, input, "./")) {
            input = input[2..];
        } else if (std.mem.startsWith(u8, input, "/./")) {
            input = input[2..]; // replace "/." with "/"
        } else if (std.mem.eql(u8, input, "/.")) {
            input = "/";
        } else if (std.mem.startsWith(u8, input, "/../")) {
            input = input[3..]; // replace "/.." with "/"
            removeLastPathSegment(&out);
        } else if (std.mem.eql(u8, input, "/..")) {
            input = "/";
            removeLastPathSegment(&out);
        } else if (std.mem.eql(u8, input, ".") or std.mem.eql(u8, input, "..")) {
            input = "";
        } else {
            const end = if (input[0] == '/')
                std.mem.indexOfScalarPos(u8, input, 1, '/') orelse input.len
            else
                std.mem.indexOfScalar(u8, input, '/') orelse input.len;
            try out.appendSlice(allocator, input[0..end]);
            input = input[end..];
        }
    }
    return out.toOwnedSlice(allocator);
}

fn removeLastPathSegment(out: *std.ArrayList(u8)) void {
    if (std.mem.lastIndexOfScalar(u8, out.items, '/')) |last| {
        out.shrinkRetainingCapacity(last);
    } else {
        out.shrinkRetainingCapacity(0);
    }
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

test "RelayUrl normalization and rejection matrix matches the reference (fixture-driven)" {
    // Every case is pinned by the pinned-Rust probe (tools/iroh_base_probe):
    // scheme/host lowercasing, default-port elision, empty-path -> "/",
    // dot-segment resolution, userinfo/IP-literal passthrough, and rejection
    // of missing scheme/authority and bad ports. Mutation-RED: dropping any
    // of those canonicalization steps flips its cases red.
    const allocator = std.testing.allocator;
    for (fixtures.relay_url) |case| {
        const result = RelayUrl.parse(allocator, case.input);
        if (case.ok) {
            var url = try result;
            defer url.deinit(allocator);
            try std.testing.expectEqualStrings(case.canonical, url.asString());
            // Canonical form is a fixed point (iroh Display == reparse).
            var again = try RelayUrl.parse(allocator, url.asString());
            defer again.deinit(allocator);
            try std.testing.expectEqualStrings(case.canonical, again.asString());
        } else {
            try std.testing.expectError(error.InvalidRelayUrl, result);
        }
    }
}

test "CustomAddr display and binary forms match the reference (fixture-driven)" {
    // Display `<id>_<hex>`, binary to_vec (LE u64 ++ data), and parse
    // acceptance are pinned by the probe (covers the Rust unit vectors:
    // 1_a1b2c3d4e5f6, 2a_ab.., 0_, deadbeef_0102, plus 30/31-byte inline/heap
    // boundary and 100-byte data).
    const allocator = std.testing.allocator;
    for (fixtures.custom_addr) |case| {
        var data_buf: [256]u8 = undefined;
        const data = try std.fmt.hexToBytes(&data_buf, case.data_hex);
        var ca = try CustomAddr.fromParts(allocator, case.id, data);
        defer ca.deinit(allocator);

        const text = try ca.toString(allocator);
        defer allocator.free(text);
        try std.testing.expectEqualStrings(case.display, text);

        const bytes = try ca.toBytes(allocator);
        defer allocator.free(bytes);
        var expect_buf: [264]u8 = undefined;
        const expected = try std.fmt.hexToBytes(&expect_buf, case.to_vec_hex);
        try std.testing.expectEqualSlices(u8, expected, bytes);

        var parsed = try CustomAddr.parse(allocator, text);
        defer parsed.deinit(allocator);
        try std.testing.expect(parsed.eql(ca));

        var from_bytes = try CustomAddr.fromBytes(allocator, bytes);
        defer from_bytes.deinit(allocator);
        try std.testing.expect(from_bytes.eql(ca));
    }
}

test "CustomAddr string parse acceptance matches the reference (fixture-driven)" {
    const allocator = std.testing.allocator;
    for (fixtures.custom_addr_parse) |case| {
        const result = CustomAddr.parse(allocator, case.input);
        if (case.ok) {
            var ca = try result;
            defer ca.deinit(allocator);
        } else {
            try std.testing.expectError(error.InvalidCustomAddr, result);
        }
    }
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
