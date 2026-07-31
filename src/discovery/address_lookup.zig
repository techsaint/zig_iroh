//! Address-lookup framework — multi-provider discovery composition.
//!
//! Zig-shaped counterpart to iroh's `address_lookup` trait surface:
//! providers publish/resolve endpoint reachability, results carry
//! provenance, and a composite fan-out queries multiple providers.
//! Composition around the frozen pkarr codec only — no wire/crypto edits.

const std = @import("std");
const root = @import("../root.zig");
const discovery = @import("discovery.zig");
const connect = @import("connect.zig");

pub const Error = error{
    LookupMiss,
    LookupFailed,
    ProviderError,
    EmptyProviders,
    ProvenanceMismatch,
    OutOfMemory,
};

/// One resolved address set with provenance (which provider produced it).
pub const LookupItem = struct {
    info: discovery.EndpointInfo,
    provenance: []const u8,
    /// Optional provider-level error string when resolve partially failed.
    error_detail: ?[]const u8 = null,

    pub fn deinit(self: *LookupItem, allocator: std.mem.Allocator) void {
        self.info.deinit(allocator);
        if (self.error_detail) |d| allocator.free(d);
        self.* = undefined;
    }
};

/// Provider-level error with provenance for the error surface.
pub const LookupError = struct {
    provenance: []const u8,
    err: anyerror,
    detail: ?[]const u8 = null,

    pub fn deinit(self: *LookupError, allocator: std.mem.Allocator) void {
        if (self.detail) |d| allocator.free(d);
        self.* = undefined;
    }
};

/// Result of a multi-provider resolve: zero or more items + collected errors.
pub const ResolveBatch = struct {
    allocator: std.mem.Allocator,
    items: []LookupItem,
    errors: []LookupError,

    pub fn deinit(self: *ResolveBatch) void {
        for (self.items) |*item| item.deinit(self.allocator);
        self.allocator.free(self.items);
        for (self.errors) |*e| e.deinit(self.allocator);
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    /// Borrowed view of the first successful item, if any.
    /// Lifetime: valid until `deinit`. Does not transfer ownership of `EndpointInfo`.
    pub fn first(self: *const ResolveBatch) ?*const LookupItem {
        if (self.items.len == 0) return null;
        return &self.items[0];
    }

    /// Borrowed view of the item with matching provenance, if any.
    /// Lifetime: valid until `deinit`. Does not transfer ownership of `EndpointInfo`.
    pub fn byProvenance(self: *const ResolveBatch, provenance: []const u8) ?*const LookupItem {
        for (self.items) |*item| {
            if (std.mem.eql(u8, item.provenance, provenance)) return item;
        }
        return null;
    }

    /// Explicit owned clone of the first item (caller owns; batch retains its copy).
    pub fn cloneFirst(self: *const ResolveBatch, allocator: std.mem.Allocator) !?LookupItem {
        const item = self.first() orelse return null;
        return .{
            .info = try item.info.clone(allocator),
            .provenance = item.provenance,
            .error_detail = if (item.error_detail) |d| try allocator.dupe(u8, d) else null,
        };
    }
};

/// Vtable address-lookup provider (publish + resolve).
pub const AddressLookup = struct {
    context: *anyopaque,
    provenance: []const u8,
    publishFn: *const fn (context: *anyopaque, info: discovery.EndpointInfo) anyerror!void,
    resolveFn: *const fn (context: *anyopaque, node_id: root.NodeId) anyerror!discovery.EndpointInfo,

    pub fn publish(self: AddressLookup, info: discovery.EndpointInfo) anyerror!void {
        return self.publishFn(self.context, info);
    }

    pub fn resolve(self: AddressLookup, node_id: root.NodeId) anyerror!discovery.EndpointInfo {
        return self.resolveFn(self.context, node_id);
    }
};

/// Fan-out composite: publish to all; resolve from all; collect provenance + errors.
pub const CompositeLookup = struct {
    allocator: std.mem.Allocator,
    providers: []const AddressLookup,
    /// When true, first successful resolve short-circuits remaining providers.
    short_circuit: bool = false,

    pub fn init(allocator: std.mem.Allocator, providers: []const AddressLookup) CompositeLookup {
        return .{ .allocator = allocator, .providers = providers };
    }

    pub fn asLookup(self: *CompositeLookup) AddressLookup {
        return .{
            .context = self,
            .provenance = "composite",
            .publishFn = publishComposite,
            .resolveFn = resolveCompositeFirst,
        };
    }

    /// Publish to every provider; first hard failure aborts (after prior success is kept).
    pub fn publishAll(self: *CompositeLookup, info: discovery.EndpointInfo) !void {
        if (self.providers.len == 0) return error.EmptyProviders;
        for (self.providers) |p| {
            try p.publish(info);
        }
    }

    /// Resolve from every provider; collect successes and per-provider errors.
    pub fn resolveAll(self: *CompositeLookup, node_id: root.NodeId) !ResolveBatch {
        if (self.providers.len == 0) return error.EmptyProviders;

        var items: std.ArrayList(LookupItem) = .empty;
        errdefer {
            for (items.items) |*it| it.deinit(self.allocator);
            items.deinit(self.allocator);
        }
        var errors: std.ArrayList(LookupError) = .empty;
        errdefer {
            for (errors.items) |*e| e.deinit(self.allocator);
            errors.deinit(self.allocator);
        }

        for (self.providers) |p| {
            const resolved = p.resolve(node_id) catch |err| {
                try errors.append(self.allocator, .{
                    .provenance = p.provenance,
                    .err = err,
                    .detail = try std.fmt.allocPrint(self.allocator, "{s}", .{@errorName(err)}),
                });
                continue;
            };
            // Ensure provenance is set on the info when provider didn't stamp it.
            var info = resolved;
            if (info.provenance == null) {
                info.provenance = try self.allocator.dupe(u8, p.provenance);
            }
            try items.append(self.allocator, .{
                .info = info,
                .provenance = p.provenance,
            });
            if (self.short_circuit) break;
        }

        return .{
            .allocator = self.allocator,
            .items = try items.toOwnedSlice(self.allocator),
            .errors = try errors.toOwnedSlice(self.allocator),
        };
    }

    fn publishComposite(context: *anyopaque, info: discovery.EndpointInfo) anyerror!void {
        const self: *CompositeLookup = @ptrCast(@alignCast(context));
        return self.publishAll(info);
    }

    fn resolveCompositeFirst(context: *anyopaque, node_id: root.NodeId) anyerror!discovery.EndpointInfo {
        const self: *CompositeLookup = @ptrCast(@alignCast(context));
        var batch = try self.resolveAll(node_id);
        defer batch.deinit();
        if (batch.items.len == 0) {
            if (batch.errors.len > 0) return batch.errors[0].err;
            return error.LookupMiss;
        }
        // Clone first item's info for the caller (batch deinit frees the rest).
        return batch.items[0].info.clone(self.allocator);
    }
};

/// In-memory address lookup — out-of-band endpoint info (tickets, manual add).
/// Distinct provenance `"memory_lookup"` from StaticResolver's `"static"`.
pub const MemoryLookup = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMap([32]u8, discovery.EndpointInfo),
    provenance: []const u8 = "memory_lookup",
    /// When true, resolve returns error instead of miss (for error-surface tests).
    force_error: ?anyerror = null,

    pub fn init(allocator: std.mem.Allocator) MemoryLookup {
        return .{
            .allocator = allocator,
            .entries = .init(allocator),
        };
    }

    pub fn initWithProvenance(allocator: std.mem.Allocator, provenance: []const u8) MemoryLookup {
        return .{
            .allocator = allocator,
            .entries = .init(allocator),
            .provenance = provenance,
        };
    }

    pub fn deinit(self: *MemoryLookup) void {
        var it = self.entries.valueIterator();
        while (it.next()) |info| info.deinit(self.allocator);
        self.entries.deinit();
    }

    pub fn asLookup(self: *MemoryLookup) AddressLookup {
        return .{
            .context = self,
            .provenance = self.provenance,
            .publishFn = publishMemory,
            .resolveFn = resolveMemory,
        };
    }

    /// Direct resolve against this owner — stable while `self` lives.
    /// Prefer this (or `asLookup()` kept alive on a local) over any adapter chain
    /// that would capture a by-value temporary.
    pub fn resolve(self: *MemoryLookup, node_id: root.NodeId) !discovery.EndpointInfo {
        return resolveMemory(self, node_id);
    }

    pub fn addEndpointInfo(self: *MemoryLookup, info: discovery.EndpointInfo) !void {
        const owned = try info.clone(self.allocator);
        // Stamp provenance if missing.
        var value = owned;
        if (value.provenance == null) {
            value.provenance = try self.allocator.dupe(u8, self.provenance);
        }
        errdefer value.deinit(self.allocator);
        const gop = try self.entries.getOrPut(value.node_id.bytes);
        if (gop.found_existing) gop.value_ptr.deinit(self.allocator);
        gop.value_ptr.* = value;
    }

    pub fn addEndpointAddr(
        self: *MemoryLookup,
        endpoint_addr: root.EndpointAddr,
        user_data: ?[]const u8,
    ) !void {
        const owned = try discovery.EndpointInfo.fromNodeAddrWithMetadata(
            self.allocator,
            endpoint_addr,
            user_data,
            .{
                .provenance = self.provenance,
                .last_updated = discovery.Timestamp.now(),
            },
        );
        errdefer owned.deinit(self.allocator);
        const gop = try self.entries.getOrPut(owned.node_id.bytes);
        if (gop.found_existing) gop.value_ptr.deinit(self.allocator);
        gop.value_ptr.* = owned;
    }

    pub fn remove(self: *MemoryLookup, node_id: root.NodeId) bool {
        if (self.entries.fetchRemove(node_id.bytes)) |kv| {
            var info = kv.value;
            info.deinit(self.allocator);
            return true;
        }
        return false;
    }

    pub fn count(self: *const MemoryLookup) usize {
        return self.entries.count();
    }

    fn publishMemory(context: *anyopaque, info: discovery.EndpointInfo) anyerror!void {
        const self: *MemoryLookup = @ptrCast(@alignCast(context));
        return self.addEndpointInfo(info);
    }

    fn resolveMemory(context: *anyopaque, node_id: root.NodeId) anyerror!discovery.EndpointInfo {
        const self: *MemoryLookup = @ptrCast(@alignCast(context));
        if (self.force_error) |e| return e;
        const info = self.entries.get(node_id.bytes) orelse return error.LookupMiss;
        return info.clone(self.allocator);
    }
};

/// Static provider wrapper around `connect.StaticResolver` with AddressLookup seam.
pub const StaticLookup = struct {
    inner: connect.StaticResolver,
    provenance: []const u8 = "static",

    pub fn init(allocator: std.mem.Allocator) StaticLookup {
        return .{ .inner = connect.StaticResolver.init(allocator) };
    }

    pub fn deinit(self: *StaticLookup) void {
        self.inner.deinit();
    }

    pub fn asLookup(self: *StaticLookup) AddressLookup {
        return .{
            .context = self,
            .provenance = self.provenance,
            .publishFn = publishStatic,
            .resolveFn = resolveStatic,
        };
    }

    pub fn resolve(self: *StaticLookup, node_id: root.NodeId) !discovery.EndpointInfo {
        return self.inner.resolve(node_id);
    }

    pub fn setEndpointAddr(
        self: *StaticLookup,
        endpoint_addr: root.EndpointAddr,
        user_data: ?[]const u8,
    ) !void {
        return self.inner.setEndpointAddr(endpoint_addr, user_data);
    }

    pub fn setEndpointInfo(self: *StaticLookup, info: discovery.EndpointInfo) !void {
        return self.inner.setEndpointInfo(info);
    }

    fn publishStatic(context: *anyopaque, info: discovery.EndpointInfo) anyerror!void {
        const self: *StaticLookup = @ptrCast(@alignCast(context));
        return self.inner.setEndpointInfo(info);
    }

    fn resolveStatic(context: *anyopaque, node_id: root.NodeId) anyerror!discovery.EndpointInfo {
        const self: *StaticLookup = @ptrCast(@alignCast(context));
        return self.inner.resolve(node_id);
    }
};

/// Adapt a DiscoveryClient (pkarr/DoH) to AddressLookup. Publish uses client.publish;
/// resolve uses client.resolve. Caller owns the client lifetime.
pub const PkarrLookup = struct {
    client: *const discovery.DiscoveryClient,
    secret_key: ?root.SecretKey = null,
    ttl: u32 = discovery.DEFAULT_TTL,
    provenance: []const u8 = "pkarr",

    pub fn asLookup(self: *PkarrLookup) AddressLookup {
        return .{
            .context = self,
            .provenance = self.provenance,
            .publishFn = publishPkarr,
            .resolveFn = resolvePkarr,
        };
    }

    fn publishPkarr(context: *anyopaque, info: discovery.EndpointInfo) anyerror!void {
        const self: *PkarrLookup = @ptrCast(@alignCast(context));
        const sk = self.secret_key orelse return error.ProviderError;
        return self.client.publish(sk, info, self.ttl, discovery.Timestamp.now());
    }

    fn resolvePkarr(context: *anyopaque, node_id: root.NodeId) anyerror!discovery.EndpointInfo {
        const self: *PkarrLookup = @ptrCast(@alignCast(context));
        return self.client.resolve(node_id);
    }
};

// ---------------------------------------------------------------------------
// Tests — exercise framework, providers, provenance, composite fan-out.
// ---------------------------------------------------------------------------

test "MemoryLookup publish/resolve with provenance memory_lookup" {
    const allocator = std.testing.allocator;
    const node_id = root.SecretKey.fromBytes(.{0x71} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(7171) };
    var endpoint_addr = try root.EndpointAddr.fromParts(allocator, node_id, &.{.{ .ip = direct }});
    defer endpoint_addr.deinit(allocator);

    var mem = MemoryLookup.init(allocator);
    defer mem.deinit();
    try mem.addEndpointAddr(endpoint_addr, "ticket-data");

    var resolved = try mem.asLookup().resolve(node_id);
    defer resolved.deinit(allocator);
    try std.testing.expect(resolved.node_id.eql(node_id));
    try std.testing.expectEqualStrings("memory_lookup", resolved.provenance.?);
    try std.testing.expectEqualStrings("ticket-data", resolved.user_data.?);

    const missing = root.SecretKey.fromBytes(.{0x72} ** 32).public();
    try std.testing.expectError(error.LookupMiss, mem.asLookup().resolve(missing));
    try std.testing.expect(mem.remove(node_id));
    try std.testing.expectEqual(@as(usize, 0), mem.count());
}

test "StaticLookup AddressLookup seam and static provenance" {
    const allocator = std.testing.allocator;
    const node_id = root.SecretKey.fromBytes(.{0x73} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(7373) };
    var endpoint_addr = try root.EndpointAddr.fromParts(allocator, node_id, &.{.{ .ip = direct }});
    defer endpoint_addr.deinit(allocator);

    var static_lookup = StaticLookup.init(allocator);
    defer static_lookup.deinit();
    try static_lookup.setEndpointAddr(endpoint_addr, null);

    var resolved = try static_lookup.asLookup().resolve(node_id);
    defer resolved.deinit(allocator);
    try std.testing.expectEqualStrings("static", resolved.provenance.?);
}

test "CompositeLookup fan-out collects provenance and surfaces provider errors" {
    const allocator = std.testing.allocator;
    const node_id = root.SecretKey.fromBytes(.{0x74} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(7474) };
    var endpoint_addr = try root.EndpointAddr.fromParts(allocator, node_id, &.{.{ .ip = direct }});
    defer endpoint_addr.deinit(allocator);

    var mem = MemoryLookup.init(allocator);
    defer mem.deinit();
    try mem.addEndpointAddr(endpoint_addr, "from-memory");

    var empty_static = StaticLookup.init(allocator);
    defer empty_static.deinit();

    var failing = MemoryLookup.initWithProvenance(allocator, "failing-provider");
    defer failing.deinit();
    failing.force_error = error.ProviderError;

    const providers = [_]AddressLookup{
        failing.asLookup(),
        mem.asLookup(),
        empty_static.asLookup(),
    };
    var composite = CompositeLookup.init(allocator, &providers);

    // Publish to all that accept (failing also stores via addEndpointInfo path — force_error only on resolve).
    const publish_info = try discovery.EndpointInfo.fromNodeAddrWithMetadata(
        allocator,
        endpoint_addr,
        "published",
        .{ .provenance = "composite-publish" },
    );
    defer publish_info.deinit(allocator);
    try composite.publishAll(publish_info);

    var batch = try composite.resolveAll(node_id);
    defer batch.deinit();

    // failing-provider must appear in errors with provenance.
    try std.testing.expect(batch.errors.len >= 1);
    try std.testing.expectEqualStrings("failing-provider", batch.errors[0].provenance);
    try std.testing.expect(batch.errors[0].detail != null);

    // memory_lookup must produce a success with correct provenance.
    const mem_item = batch.byProvenance("memory_lookup");
    try std.testing.expect(mem_item != null);
    try std.testing.expectEqualStrings("memory_lookup", mem_item.?.provenance);

    // Borrowed accessors + batch deinit must not double-free (item is a view).
    const first_view = batch.first();
    try std.testing.expect(first_view != null);
    try std.testing.expect(first_view.?.info.node_id.eql(node_id));

    // Mutation control: if composite ignored provenance and returned a synthetic
    // empty success without consulting providers, items would be empty while
    // force_error was set — assert we got at least one real item.
    try std.testing.expect(batch.items.len >= 1);
}

test "CompositeLookup short-circuit returns first success via asLookup resolve" {
    const allocator = std.testing.allocator;
    const node_id = root.SecretKey.fromBytes(.{0x75} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(7575) };
    var endpoint_addr = try root.EndpointAddr.fromParts(allocator, node_id, &.{.{ .ip = direct }});
    defer endpoint_addr.deinit(allocator);

    var mem = MemoryLookup.init(allocator);
    defer mem.deinit();
    try mem.addEndpointAddr(endpoint_addr, null);

    var empty = StaticLookup.init(allocator);
    defer empty.deinit();

    const providers = [_]AddressLookup{ mem.asLookup(), empty.asLookup() };
    var composite = CompositeLookup.init(allocator, &providers);
    composite.short_circuit = true;

    var resolved = try composite.asLookup().resolve(node_id);
    defer resolved.deinit(allocator);
    try std.testing.expect(resolved.node_id.eql(node_id));
}

test "MemoryLookup.resolve stays valid for connectById anytype seam" {
    const allocator = std.testing.allocator;
    const node_id = root.SecretKey.fromBytes(.{0x76} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(7676) };
    var endpoint_addr = try root.EndpointAddr.fromParts(allocator, node_id, &.{.{ .ip = direct }});
    defer endpoint_addr.deinit(allocator);

    var mem = MemoryLookup.init(allocator);
    defer mem.deinit();
    try mem.addEndpointAddr(endpoint_addr, null);

    // Owner-bound resolve: context is `*MemoryLookup`, not a by-value temporary.
    var resolved = try mem.resolve(node_id);
    defer resolved.deinit(allocator);
    try std.testing.expect(resolved.node_id.eql(node_id));

    // Lifetime evidence: resolve after intermediate expression would have ended.
    const again = try mem.resolve(node_id);
    defer again.deinit(allocator);
    try std.testing.expect(again.node_id.eql(node_id));
}

test "ResolveBatch borrowed accessors do not hand out owned EndpointInfo" {
    const allocator = std.testing.allocator;
    const node_id = root.SecretKey.fromBytes(.{0x78} ** 32).public();
    const direct: std.Io.net.IpAddress = .{ .ip4 = .loopback(7878) };
    var endpoint_addr = try root.EndpointAddr.fromParts(allocator, node_id, &.{.{ .ip = direct }});
    defer endpoint_addr.deinit(allocator);

    var mem = MemoryLookup.init(allocator);
    defer mem.deinit();
    try mem.addEndpointAddr(endpoint_addr, "batch-own");

    const providers = [_]AddressLookup{mem.asLookup()};
    var composite = CompositeLookup.init(allocator, &providers);
    var batch = try composite.resolveAll(node_id);
    // Explicit clone is independently owned.
    var cloned = (try batch.cloneFirst(allocator)).?;
    defer cloned.deinit(allocator);
    try std.testing.expectEqualStrings("batch-own", cloned.info.user_data.?);
    // Batch deinit frees its own items; clone remains valid (separate ownership).
    batch.deinit();
    try std.testing.expect(cloned.info.node_id.eql(node_id));
}

test "provenance error surface: force_error is not swallowed as miss" {
    const allocator = std.testing.allocator;
    var mem = MemoryLookup.initWithProvenance(allocator, "err-provider");
    defer mem.deinit();
    mem.force_error = error.LookupFailed;

    const node_id = root.SecretKey.fromBytes(.{0x77} ** 32).public();
    try std.testing.expectError(error.LookupFailed, mem.asLookup().resolve(node_id));

    // Via composite: error must be recorded, not converted to empty success.
    const providers = [_]AddressLookup{mem.asLookup()};
    var composite = CompositeLookup.init(allocator, &providers);
    var batch = try composite.resolveAll(node_id);
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 0), batch.items.len);
    try std.testing.expectEqual(@as(usize, 1), batch.errors.len);
    try std.testing.expectEqualStrings("err-provider", batch.errors[0].provenance);
    try std.testing.expectEqual(error.LookupFailed, batch.errors[0].err);
}
