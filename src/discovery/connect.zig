//! Resolve-then-connect seam for EndpointId-only dial.
//!
//! Callers supply only a NodeId. This helper resolves reachability through a
//! concrete discovery type (`anytype` with `.resolve(NodeId)`), then dials the
//! frozen transport vtable with the resolved NodeAddr. There is no runtime
//! `*anyopaque` resolver vtable — product/test selection is comptime
//! monomorphization (see `discovery/product.zig`).

const std = @import("std");
const key = @import("../key.zig");
const addr = @import("../addr.zig");
const discovery = @import("discovery.zig");
const address_lookup = @import("address_lookup.zig");
const tr = @import("../transport.zig");

pub const ConnectByIdError = error{
    IntentNotEmpty,
    IntentHasIp,
    IntentHasRelay,
    ResolveReturnedEmpty,
    ResolveFailed,
    ResolvedDirectAddressDisabled,
    OutOfMemory,
} || tr.Error;

pub const ConnectByIdOptions = struct {
    /// When false, a resolver result containing an IP address is rejected before
    /// dialing. This keeps relay-only oracle rows from passing through a direct
    /// address while preserving the general EndpointId connect helper default.
    allow_resolved_direct_addresses: bool = true,
    /// Upstream magicsock path racing, serialized: when the resolved record
    /// carries BOTH direct and relay reachability and the direct dial fails,
    /// retry once via the relay-only subset. The original dial error is
    /// returned when no relay fallback exists.
    fallback_to_relay_on_failure: bool = false,
};

/// Relay-only subset of a resolved address set (the retry dial set for
/// relay fallback). Errors with `error.NoRelayAddr` when the set carries no
/// relay reachability; callers typically mask that with the original dial
/// error.
pub fn relayOnlySubset(allocator: std.mem.Allocator, src: addr.EndpointAddr) (addr.AddrError || error{NoRelayAddr})!addr.EndpointAddr {
    var items: std.ArrayList(addr.TransportAddr) = .empty;
    defer items.deinit(allocator);
    for (src.addrs) |ta| {
        if (ta.isRelay()) try items.append(allocator, ta);
    }
    if (items.items.len == 0) return error.NoRelayAddr;
    return addr.EndpointAddr.fromParts(allocator, src.id, items.items);
}

/// In-memory/static discovery provider for EndpointId-only connects. Owns its
/// endpoint-info entries and exposes a direct `.resolve` method (no vtable).
pub const StaticResolver = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMap([32]u8, discovery.EndpointInfo),

    pub fn init(allocator: std.mem.Allocator) StaticResolver {
        return .{
            .allocator = allocator,
            .entries = .init(allocator),
        };
    }

    pub fn deinit(self: *StaticResolver) void {
        var it = self.entries.valueIterator();
        while (it.next()) |info| info.deinit(self.allocator);
        self.entries.deinit();
    }

    pub fn resolve(self: *StaticResolver, node_id: key.NodeId) !discovery.EndpointInfo {
        const info = self.entries.get(node_id.bytes) orelse return error.StaticDiscoveryMiss;
        return info.clone(self.allocator);
    }

    pub fn setEndpointAddr(
        self: *StaticResolver,
        endpoint_addr: addr.EndpointAddr,
        user_data: ?[]const u8,
    ) !void {
        const owned = try discovery.EndpointInfo.fromNodeAddrWithMetadata(self.allocator, endpoint_addr, user_data, .{
            .provenance = "static",
            .last_updated = discovery.Timestamp.now(),
        });
        try self.putOwned(owned);
    }

    pub fn set_endpoint_addr(
        self: *StaticResolver,
        endpoint_addr: addr.EndpointAddr,
        user_data: ?[]const u8,
    ) !void {
        return self.setEndpointAddr(endpoint_addr, user_data);
    }

    pub fn setEndpointInfo(self: *StaticResolver, info: discovery.EndpointInfo) !void {
        const owned = try info.clone(self.allocator);
        try self.putOwned(owned);
    }

    pub fn set_endpoint_info(self: *StaticResolver, info: discovery.EndpointInfo) !void {
        return self.setEndpointInfo(info);
    }

    pub fn removeEndpointInfo(self: *StaticResolver, node_id: key.NodeId) bool {
        if (self.entries.fetchRemove(node_id.bytes)) |kv| {
            var info = kv.value;
            info.deinit(self.allocator);
            return true;
        }
        return false;
    }

    pub fn remove_endpoint_info(self: *StaticResolver, node_id: key.NodeId) bool {
        return self.removeEndpointInfo(node_id);
    }

    fn putOwned(self: *StaticResolver, owned: discovery.EndpointInfo) !void {
        var value = owned;
        errdefer value.deinit(self.allocator);
        const gop = try self.entries.getOrPut(value.node_id.bytes);
        if (gop.found_existing) gop.value_ptr.deinit(self.allocator);
        gop.value_ptr.* = value;
    }
};

/// Runtime registry of address-lookup (discovery) services with merge
/// semantics (upstream iroh `AddressLookupServices`): a lookup queries every
/// registered service and the result is the UNION of all returned addresses
/// (deduped), with user_data/provenance taken from the first provider that
/// carries them. An empty registry is an explicit error
/// (`error.NoAddressLookupService`), distinct from services-present-but-
/// answered-empty (surfaced as `error.ResolveReturnedEmpty` at the connect
/// layer). One failing service does not sink the lookup — the remaining
/// services still answer; the first error surfaces only when NO service
/// resolved at all.
///
/// Providers register as `address_lookup.AddressLookup` values (the live
/// provider seam from `discovery/address_lookup.zig`); there is no
/// connect-layer resolver vtable.
pub const AddressLookupServices = struct {
    allocator: std.mem.Allocator,
    providers: std.ArrayList(address_lookup.AddressLookup),

    pub fn init(allocator: std.mem.Allocator) AddressLookupServices {
        return .{ .allocator = allocator, .providers = .empty };
    }

    pub fn deinit(self: *AddressLookupServices) void {
        self.providers.deinit(self.allocator);
    }

    /// Register a service. The AddressLookup's context is borrowed — the
    /// provider must outlive this registry.
    pub fn add(self: *AddressLookupServices, service: address_lookup.AddressLookup) !void {
        try self.providers.append(self.allocator, service);
    }

    pub fn clear(self: *AddressLookupServices) void {
        self.providers.clearRetainingCapacity();
    }

    pub fn len(self: *const AddressLookupServices) usize {
        return self.providers.items.len;
    }

    pub fn isEmpty(self: *const AddressLookupServices) bool {
        return self.providers.items.len == 0;
    }

    /// Owner-bound merged resolve — stable while `self` lives. Preferred over
    /// `asLookup()` for the common "query the registry" path, and the shape
    /// `connectById*`'s `anytype` resolver seam monomorphizes against.
    pub fn resolve(self: *AddressLookupServices, node_id: key.NodeId) anyerror!discovery.EndpointInfo {
        if (self.providers.items.len == 0) return error.NoAddressLookupService;

        var merged_addrs: std.ArrayList(addr.TransportAddr) = .empty;
        defer {
            for (merged_addrs.items) |item| item.deinit(self.allocator);
            merged_addrs.deinit(self.allocator);
        }
        var owned_user_data: ?[]u8 = null;
        defer if (owned_user_data) |u| self.allocator.free(u);
        var owned_provenance: ?[]u8 = null;
        defer if (owned_provenance) |p| self.allocator.free(p);
        var successes: usize = 0;
        var first_error: ?anyerror = null;

        for (self.providers.items) |service| {
            var info = service.resolve(node_id) catch |err| {
                if (first_error == null) first_error = err;
                continue;
            };
            defer info.deinit(self.allocator);
            successes += 1;
            for (info.addrs) |item| {
                var dup = false;
                for (merged_addrs.items) |kept| {
                    if (kept.eql(item)) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) try merged_addrs.append(self.allocator, try item.clone(self.allocator));
            }
            if (owned_user_data == null and info.user_data != null) {
                owned_user_data = try self.allocator.dupe(u8, info.user_data.?);
            }
            if (owned_provenance == null and info.provenance != null) {
                owned_provenance = try self.allocator.dupe(u8, info.provenance.?);
            }
        }

        if (successes == 0) return first_error orelse error.ResolveFailed;
        return discovery.EndpointInfo.fromPartsWithMetadata(self.allocator, node_id, merged_addrs.items, owned_user_data, .{
            .provenance = owned_provenance,
            .last_updated = discovery.Timestamp.now(),
        });
    }

    /// Adapt to the provider seam, so a registry composes anywhere an
    /// `AddressLookup` is accepted (including inside another registry or a
    /// `CompositeLookup`). Keep the registry (not a copied AddressLookup)
    /// alive for the adapter's lifetime.
    pub fn asLookup(self: *AddressLookupServices) address_lookup.AddressLookup {
        return .{
            .context = self,
            .provenance = "services",
            .publishFn = publishAll,
            .resolveFn = resolveMerged,
        };
    }

    fn publishAll(context: *anyopaque, info: discovery.EndpointInfo) anyerror!void {
        const self: *AddressLookupServices = @ptrCast(@alignCast(context));
        if (self.providers.items.len == 0) return error.NoAddressLookupService;
        for (self.providers.items) |service| try service.publish(info);
    }

    fn resolveMerged(context: *anyopaque, node_id: key.NodeId) anyerror!discovery.EndpointInfo {
        const self: *AddressLookupServices = @ptrCast(@alignCast(context));
        return self.resolve(node_id);
    }
};

/// Assert EndpointId-only intent, resolve via a concrete `resolver` type that
/// exposes `.resolve(NodeId) !EndpointInfo`, then connect. On success,
/// `resolved_out` receives the owned EndpointAddr used for the dial when
/// non-null; caller must deinit it.
pub fn connectById(
    allocator: std.mem.Allocator,
    transport: tr.Transport,
    resolver: anytype,
    node_id: key.NodeId,
    resolved_out: ?*addr.EndpointAddr,
) ConnectByIdError!tr.Connection {
    return connectByIdWithOpts(allocator, transport, resolver, node_id, resolved_out, .{});
}

pub fn connectByIdWithOpts(
    allocator: std.mem.Allocator,
    transport: tr.Transport,
    resolver: anytype,
    node_id: key.NodeId,
    resolved_out: ?*addr.EndpointAddr,
    options: ConnectByIdOptions,
) ConnectByIdError!tr.Connection {
    const intent = addr.EndpointAddr.new(node_id);
    if (!intent.isEmpty()) return error.IntentNotEmpty;
    if (intent.addrs.len != 0) return error.IntentNotEmpty;
    if (intent.firstIpAddr() != null) return error.IntentHasIp;
    if (intent.firstRelayUrl() != null) return error.IntentHasRelay;

    var info = resolver.resolve(node_id) catch return error.ResolveFailed;
    defer info.deinit(allocator);
    if (info.addrs.len == 0) return error.ResolveReturnedEmpty;

    var resolved = info.toNodeAddr(allocator) catch return error.OutOfMemory;
    errdefer resolved.deinit(allocator);
    if (!options.allow_resolved_direct_addresses and resolved.firstIpAddr() != null) {
        return error.ResolvedDirectAddressDisabled;
    }

    const conn = transport.connect(resolved) catch |err| blk: {
        if (!options.fallback_to_relay_on_failure) return err;
        if (resolved.firstIpAddr() == null) return err; // already relay-only: the retry is the same dial
        var relay_only = relayOnlySubset(allocator, resolved) catch return err; // keep the original dial error
        defer relay_only.deinit(allocator);
        break :blk try transport.connect(relay_only);
    };
    if (resolved_out) |out| {
        out.* = resolved;
    } else {
        resolved.deinit(allocator);
    }
    return conn;
}

test "connectById empty-intent predicates" {
    const id = key.SecretKey.fromBytes(.{0x55} ** 32).public();
    const intent = addr.EndpointAddr.new(id);
    try std.testing.expect(intent.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), intent.addrs.len);
    try std.testing.expect(intent.firstIpAddr() == null);
    try std.testing.expect(intent.firstRelayUrl() == null);
}

test "connectById resolves before dialing and rejects empty discovery" {
    const allocator = std.testing.allocator;
    const node_id = key.SecretKey.fromBytes(.{0x61} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(4242) };

    var resolver_state = FakeResolver{
        .allocator = allocator,
        .resolved_node = node_id,
        .resolved_ip = direct,
    };
    var transport_state = FakeTransport{ .expected_remote = node_id };
    var resolved: addr.EndpointAddr = undefined;

    const conn = try connectById(
        allocator,
        transport_state.transport(),
        &resolver_state,
        node_id,
        &resolved,
    );
    defer conn.close();
    defer resolved.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    try std.testing.expectEqual(@as(usize, 1), transport_state.calls);
    try std.testing.expect(transport_state.saw_expected_remote);
    try std.testing.expect(!transport_state.saw_empty_addr);
    try std.testing.expect(transport_state.saw_direct_ip);
    try std.testing.expect(resolved.firstIpAddr() != null);

    var empty_resolver = FakeResolver{
        .allocator = allocator,
        .resolved_node = node_id,
        .resolved_ip = direct,
        .return_empty = true,
    };
    var unused_transport = FakeTransport{ .expected_remote = node_id };
    try std.testing.expectError(
        error.ResolveReturnedEmpty,
        connectById(allocator, unused_transport.transport(), &empty_resolver, node_id, null),
    );
    try std.testing.expectEqual(@as(usize, 1), empty_resolver.calls);
    try std.testing.expectEqual(@as(usize, 0), unused_transport.calls);
}

test "connectById can forbid resolved direct addresses before dialing" {
    const allocator = std.testing.allocator;
    const node_id = key.SecretKey.fromBytes(.{0x62} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(5151) };

    var resolver_state = FakeResolver{
        .allocator = allocator,
        .resolved_node = node_id,
        .resolved_ip = direct,
    };
    var transport_state = FakeTransport{ .expected_remote = node_id };

    try std.testing.expectError(
        error.ResolvedDirectAddressDisabled,
        connectByIdWithOpts(
            allocator,
            transport_state.transport(),
            &resolver_state,
            node_id,
            null,
            .{ .allow_resolved_direct_addresses = false },
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    try std.testing.expectEqual(@as(usize, 0), transport_state.calls);
}

test "StaticResolver owns endpoint info and exposes a direct resolve method" {
    const allocator = std.testing.allocator;
    const node_id = key.SecretKey.fromBytes(.{0x63} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(6161) };
    var endpoint_addr = try addr.EndpointAddr.fromParts(allocator, node_id, &.{.{ .ip = direct }});
    defer endpoint_addr.deinit(allocator);

    var static = StaticResolver.init(allocator);
    defer static.deinit();

    try static.setEndpointAddr(endpoint_addr, "ticket");

    var resolved = try static.resolve(node_id);
    defer resolved.deinit(allocator);
    try std.testing.expect(resolved.node_id.eql(node_id));
    try std.testing.expectEqualStrings("ticket", resolved.user_data.?);
    try std.testing.expectEqualStrings("static", resolved.provenance.?);
    try std.testing.expect(resolved.last_updated != null);
    var ips = resolved.ipAddrs();
    try std.testing.expect(ips.next() != null);

    const missing = key.SecretKey.fromBytes(.{0x64} ** 32).public();
    try std.testing.expectError(error.StaticDiscoveryMiss, static.resolve(missing));
    try std.testing.expect(static.removeEndpointInfo(node_id));
    try std.testing.expectError(error.StaticDiscoveryMiss, static.resolve(node_id));
}

const FakeResolver = struct {
    allocator: std.mem.Allocator,
    resolved_node: key.NodeId,
    resolved_ip: std.Io.net.IpAddress,
    resolved_relay: ?addr.RelayUrl = null,
    return_empty: bool = false,
    calls: usize = 0,

    fn resolve(self: *FakeResolver, node_id: key.NodeId) !discovery.EndpointInfo {
        self.calls += 1;
        if (!node_id.eql(self.resolved_node)) return error.WrongNode;
        if (self.return_empty) {
            return .{ .node_id = self.resolved_node };
        }
        var addrs: std.ArrayList(addr.TransportAddr) = .empty;
        defer addrs.deinit(self.allocator);
        try addrs.append(self.allocator, .{ .ip = self.resolved_ip });
        if (self.resolved_relay) |relay| try addrs.append(self.allocator, .{ .relay = relay });
        return discovery.EndpointInfo.fromParts(
            self.allocator,
            self.resolved_node,
            addrs.items,
            null,
        );
    }
};

const FakeTransport = struct {
    expected_remote: key.NodeId,
    fail_dials_with_ip: bool = false,
    calls: usize = 0,
    relay_only_dials: usize = 0,
    saw_expected_remote: bool = false,
    saw_empty_addr: bool = false,
    saw_direct_ip: bool = false,

    fn transport(self: *FakeTransport) tr.Transport {
        return .{ .context = self, .vtable = &fake_transport_vtable };
    }
};

fn fakeConnect(context: *anyopaque, peer: tr.NodeAddr) tr.Error!tr.Connection {
    const self: *FakeTransport = @ptrCast(@alignCast(context));
    self.calls += 1;
    self.saw_expected_remote = peer.id.eql(self.expected_remote);
    self.saw_empty_addr = peer.isEmpty();
    self.saw_direct_ip = peer.firstIpAddr() != null;
    if (self.saw_empty_addr) return error.NotConnected;
    if (peer.firstIpAddr() != null and self.fail_dials_with_ip) return error.Timeout;
    if (peer.firstIpAddr() == null and peer.firstRelayUrl() != null) self.relay_only_dials += 1;
    return .{ .context = self, .vtable = &fake_connection_vtable };
}

fn fakeAccept(context: *anyopaque) tr.Error!tr.Connection {
    _ = context;
    return error.NotConnected;
}

fn fakeLocalNodeId(context: *anyopaque) key.NodeId {
    const self: *FakeTransport = @ptrCast(@alignCast(context));
    return self.expected_remote;
}

fn fakeIo(context: *anyopaque) std.Io {
    _ = context;
    return std.testing.io;
}

const fake_transport_vtable: tr.Transport.VTable = .{
    .connect = fakeConnect,
    .accept = fakeAccept,
    .localNodeId = fakeLocalNodeId,
    .io = fakeIo,
};

fn fakeOpenBi(context: *anyopaque) tr.Error!tr.BiStream {
    _ = context;
    return error.NotConnected;
}

fn fakeAcceptBi(context: *anyopaque) tr.Error!tr.BiStream {
    _ = context;
    return error.NotConnected;
}

fn fakeOpenUni(context: *anyopaque) tr.Error!tr.SendStream {
    _ = context;
    return error.NotConnected;
}

fn fakeAcceptUni(context: *anyopaque) tr.Error!tr.RecvStream {
    _ = context;
    return error.NotConnected;
}

fn fakeRemoteNodeId(context: *anyopaque) key.NodeId {
    const self: *FakeTransport = @ptrCast(@alignCast(context));
    return self.expected_remote;
}

fn fakeAlpn(context: *anyopaque) ?[]const u8 {
    _ = context;
    return "fake";
}

fn fakeRemoteAddress(context: *anyopaque) ?std.Io.net.IpAddress {
    _ = context;
    return null; // FakeTransport has no socket path
}

fn fakeClose(context: *anyopaque) void {
    _ = context;
}

const fake_connection_vtable: tr.Connection.VTable = .{
    .openBi = fakeOpenBi,
    .acceptBi = fakeAcceptBi,
    .openUni = fakeOpenUni,
    .acceptUni = fakeAcceptUni,
    .remoteNodeId = fakeRemoteNodeId,
    .alpn = fakeAlpn,
    .remoteAddress = fakeRemoteAddress,
    .close = fakeClose,
    .io = fakeIo,
};

const FailProvider = struct {
    calls: usize = 0,
    fail_with: anyerror = error.Boom,

    fn asLookup(self: *FailProvider) address_lookup.AddressLookup {
        return .{
            .context = self,
            .provenance = "fail",
            .publishFn = publish,
            .resolveFn = resolve,
        };
    }

    fn publish(context: *anyopaque, info: discovery.EndpointInfo) anyerror!void {
        _ = context;
        _ = info;
    }

    fn resolve(context: *anyopaque, node_id: key.NodeId) anyerror!discovery.EndpointInfo {
        _ = node_id;
        const self: *FailProvider = @ptrCast(@alignCast(context));
        self.calls += 1;
        return self.fail_with;
    }
};

test "AddressLookupServices merges the union of provider addresses with dedup" {
    const allocator = std.testing.allocator;
    const node_id = key.SecretKey.fromBytes(.{0x70} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(7070) };
    const relay_url = try addr.RelayUrl.parse(allocator, "https://relay-a.example.com");
    defer relay_url.deinit(allocator);

    // Provider 1 carries the relay URL (+ user_data); provider 2 carries the
    // direct IP and the SAME relay URL, exercising cross-provider dedup.
    var relay_only = address_lookup.StaticLookup.init(allocator);
    defer relay_only.deinit();
    {
        var ea = try addr.EndpointAddr.fromParts(allocator, node_id, &.{.{ .relay = relay_url }});
        defer ea.deinit(allocator);
        try relay_only.setEndpointAddr(ea, "from-relay");
    }
    var direct_plus = address_lookup.StaticLookup.init(allocator);
    defer direct_plus.deinit();
    {
        var ea = try addr.EndpointAddr.fromParts(allocator, node_id, &.{ .{ .ip = direct }, .{ .relay = relay_url } });
        defer ea.deinit(allocator);
        try direct_plus.setEndpointAddr(ea, null);
    }

    var services = AddressLookupServices.init(allocator);
    defer services.deinit();
    try std.testing.expect(services.isEmpty());
    try services.add(relay_only.asLookup());
    try services.add(direct_plus.asLookup());
    try std.testing.expectEqual(@as(usize, 2), services.len());

    var merged = try services.resolve(node_id);
    defer merged.deinit(allocator);
    try std.testing.expect(merged.node_id.eql(node_id));
    var relay_count: usize = 0;
    var ip_count: usize = 0;
    for (merged.addrs) |ta| {
        if (ta.isRelay()) relay_count += 1;
        if (ta.isIp()) ip_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), relay_count);
    try std.testing.expectEqual(@as(usize, 1), ip_count);
    try std.testing.expectEqualStrings("from-relay", merged.user_data.?);

    services.clear();
    try std.testing.expect(services.isEmpty());
    try std.testing.expectError(error.NoAddressLookupService, services.resolve(node_id));
}

test "AddressLookupServices empty registry is an explicit error" {
    const allocator = std.testing.allocator;
    const node_id = key.SecretKey.fromBytes(.{0x71} ** 32).public();
    var services = AddressLookupServices.init(allocator);
    defer services.deinit();
    try std.testing.expectError(error.NoAddressLookupService, services.resolve(node_id));
}

test "AddressLookupServices survives one failing provider and surfaces first error when all fail" {
    const allocator = std.testing.allocator;
    const node_id = key.SecretKey.fromBytes(.{0x72} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(7272) };

    var failing = FailProvider{};
    var good = address_lookup.StaticLookup.init(allocator);
    defer good.deinit();
    {
        var ea = try addr.EndpointAddr.fromParts(allocator, node_id, &.{.{ .ip = direct }});
        defer ea.deinit(allocator);
        try good.setEndpointAddr(ea, null);
    }

    var services = AddressLookupServices.init(allocator);
    defer services.deinit();
    try services.add(failing.asLookup());
    try services.add(good.asLookup());

    var merged = try services.resolve(node_id);
    defer merged.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), failing.calls);
    try std.testing.expectEqual(@as(usize, 1), merged.addrs.len);

    var services_all_fail = AddressLookupServices.init(allocator);
    defer services_all_fail.deinit();
    var fail_a = FailProvider{ .fail_with = error.FirstBoom };
    var fail_b = FailProvider{ .fail_with = error.SecondBoom };
    try services_all_fail.add(fail_a.asLookup());
    try services_all_fail.add(fail_b.asLookup());
    try std.testing.expectError(error.FirstBoom, services_all_fail.resolve(node_id));
}

// Mutation-red control for the relay-fallback seam: with the option OFF the
// direct-dial error surfaces as-is (one dial); with it ON a failed direct
// dial is retried with the relay-only subset (second dial carries the relay
// URL and no IP). A fallback that never retries, or retries with the direct
// address still attached, fails these assertions.
test "connectById falls back to relay-only dialing only when enabled and a relay exists" {
    const allocator = std.testing.allocator;
    const node_id = key.SecretKey.fromBytes(.{0x73} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(7373) };
    const relay = addr.RelayUrl.borrowed("https://relay-fallback.example.com");

    var resolver_state = FakeResolver{
        .allocator = allocator,
        .resolved_node = node_id,
        .resolved_ip = direct,
        .resolved_relay = relay,
    };

    // Option OFF: the direct failure surfaces, exactly one dial attempted.
    var strict_transport = FakeTransport{ .expected_remote = node_id, .fail_dials_with_ip = true };
    try std.testing.expectError(
        error.Timeout,
        connectById(allocator, strict_transport.transport(), &resolver_state, node_id, null),
    );
    try std.testing.expectEqual(@as(usize, 1), strict_transport.calls);
    try std.testing.expectEqual(@as(usize, 0), strict_transport.relay_only_dials);

    // Option ON: direct fails, relay-only retry succeeds.
    var fallback_transport = FakeTransport{ .expected_remote = node_id, .fail_dials_with_ip = true };
    const conn = try connectByIdWithOpts(
        allocator,
        fallback_transport.transport(),
        &resolver_state,
        node_id,
        null,
        .{ .fallback_to_relay_on_failure = true },
    );
    defer conn.close();
    try std.testing.expectEqual(@as(usize, 2), fallback_transport.calls);
    try std.testing.expectEqual(@as(usize, 1), fallback_transport.relay_only_dials);

    // No relay in the record: the original error is kept, no pointless retry.
    var no_relay_resolver = FakeResolver{
        .allocator = allocator,
        .resolved_node = node_id,
        .resolved_ip = direct,
    };
    var no_relay_transport = FakeTransport{ .expected_remote = node_id, .fail_dials_with_ip = true };
    try std.testing.expectError(
        error.Timeout,
        connectByIdWithOpts(
            allocator,
            no_relay_transport.transport(),
            &no_relay_resolver,
            node_id,
            null,
            .{ .fallback_to_relay_on_failure = true },
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), no_relay_transport.calls);
}
