//! Relay runtime access control — the authorization seam + a token allow-list.
//!
//! The relay handshake proves *who you are* (signature over the challenge); this
//! module decides *whether you are allowed*. Reference:
//! `original/iroh/iroh-relay/src/server.rs` (`AccessControl`, `ClientRequest`,
//! `Access`, `AllowAll`) and `original/iroh/iroh-relay/tests/runtime_auth.rs`
//! (`TokenAccess`).
//!
//! Identity is TOKEN-scoped, not endpoint-scoped: several connections can share
//! one public key while authenticating with different bearer tokens, and revoking
//! a token must evict exactly the connections admitted under it
//! (`runtime_auth.rs` `revoked_token_disconnects_every_endpoint_connection`).
//! Connections are therefore indexed by `(endpoint_id, connection_id)`; the
//! connection id is process-unique and assigned by the server before the access
//! decision runs.

const std = @import("std");
const key = @import("../key.zig");
const proto = @import("proto.zig");

/// Decision returned by an access-control policy for one connecting client.
/// Reference: `server.rs` `enum Access`.
pub const AccessDecision = union(enum) {
    allow,
    /// Optional reason; null is sent to the client as "not authorized"
    /// (upstream `handshake.rs` `deny`: `reason.unwrap_or_else(|| "not authorized")`).
    /// A provided reason must be valid UTF-8 (the deny frame requires it).
    deny: ?[]const u8,
};

/// Details about one incoming relay client connection, proven by the handshake.
/// Reference: `server.rs` `ClientRequest`. `auth_token` borrows handler-owned
/// storage: it is valid only for the duration of `onConnect`.
pub const ClientRequest = struct {
    connection_id: u64,
    endpoint_id: key.PublicKey,
    version: proto.ProtocolVersion,
    auth_token: ?[]const u8,
};

/// Runtime-polymorphic access-control seam. Reference: `server.rs`
/// `AccessControl`/`DynAccessControl` (`on_connect` + `on_disconnect`).
///
/// A two-slot interface rather than a comptime policy or a lone function
/// pointer (translation-audit D3): the two callbacks share policy state, and
/// the seam exists so an operator can supply a policy the server does not know
/// at comptime — `relay_main` and the oracle harness plug different policies
/// into the same `Server` type.
pub const AccessControl = struct {
    context: *anyopaque,
    onConnectFn: *const fn (context: *anyopaque, request: ClientRequest) AccessDecision,
    onDisconnectFn: *const fn (context: *anyopaque, endpoint_id: key.PublicKey, connection_id: u64) void,
    /// Optional post-register revalidation of the ACL index entry for this
    /// connection. Policies that do not index connections leave this null;
    /// `stillTracked` then returns true (no race window of this class).
    ///
    /// Policies that index in `onConnect` (e.g. `TokenAccessControl`) MUST
    /// implement this so the server can fail-closed if a revoke removed the
    /// entry between ACL admission and `Clients.register`.
    stillTrackedFn: ?*const fn (context: *anyopaque, endpoint_id: key.PublicKey, connection_id: u64) bool = null,

    /// Called once per incoming connection after the signature check, before
    /// the connection is registered. Reference: `AccessControl::on_connect`.
    pub fn onConnect(self: *const AccessControl, request: ClientRequest) AccessDecision {
        return self.onConnectFn(self.context, request);
    }

    /// Called exactly once for every connection `onConnect` admitted, after the
    /// connection ends, identified by the same connection id. Reference:
    /// `AccessControl::on_disconnect`.
    pub fn onDisconnect(self: *const AccessControl, endpoint_id: key.PublicKey, connection_id: u64) void {
        self.onDisconnectFn(self.context, endpoint_id, connection_id);
    }

    /// True iff this policy still tracks `(endpoint_id, connection_id)` as an
    /// admitted connection. Checks the **index entry**, not "token currently
    /// allowed" — a revoke that removed the entry mid-handshake must make this
    /// false even if a later re-add of the same token bytes would re-allow.
    pub fn stillTracked(self: *const AccessControl, endpoint_id: key.PublicKey, connection_id: u64) bool {
        const f = self.stillTrackedFn orelse return true;
        return f(self.context, endpoint_id, connection_id);
    }
};

/// One tracked connection: the revocation unit. Reference: the
/// `(EndpointId, ConnectionId)` index key in `runtime_auth.rs` `AccessState`.
pub const ConnKey = struct {
    endpoint_id: key.PublicKey,
    connection_id: u64,
};

/// A runtime-mutable bearer-token allow-list. Reference: `runtime_auth.rs`
/// `TokenAccess` — admits a connection iff its auth token is currently allowed,
/// records the token id of every admitted connection so `revoke` maps back to
/// the connections to evict, and prunes the index on disconnect.
///
/// Thread-safe: the server's handler threads call the `AccessControl`
/// callbacks while an operator thread calls `add`/`revoke`.
pub const TokenAccessControl = struct {
    allocator: std.mem.Allocator,
    mu: std.atomic.Mutex = .unlocked,
    /// Allowed token -> token id. Owns the key bytes (duped on `add`).
    tokens: std.StringHashMapUnmanaged(u64) = .empty,
    /// Admitted connection -> the token id it was admitted under.
    connections: std.AutoHashMapUnmanaged(ConnKey, u64) = .empty,
    next_token_id: u64 = 0,
    control: AccessControl = undefined,

    pub fn init(allocator: std.mem.Allocator) TokenAccessControl {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *TokenAccessControl) void {
        var it = self.tokens.keyIterator();
        while (it.next()) |token| self.allocator.free(token.*);
        self.tokens.deinit(self.allocator);
        self.connections.deinit(self.allocator);
    }

    /// The `AccessControl` view to hand to `ServerConfig.access_control`.
    /// Fixes the self-reference: call this only once the struct is at its final
    /// address (it is self-referential, so it must not be moved afterwards).
    pub fn accessControl(self: *TokenAccessControl) *const AccessControl {
        self.control = .{
            .context = @ptrCast(self),
            .onConnectFn = onConnectThunk,
            .onDisconnectFn = onDisconnectThunk,
            .stillTrackedFn = stillTrackedThunk,
        };
        return &self.control;
    }

    /// Whether `(endpoint_id, connection_id)` is still in the admitted index.
    /// Used by the server's post-register recheck (closes the revoke-before-
    /// register under-close race).
    pub fn isTracked(self: *TokenAccessControl, endpoint_id: key.PublicKey, connection_id: u64) bool {
        self.lock();
        defer self.mu.unlock();
        return self.connections.contains(.{ .endpoint_id = endpoint_id, .connection_id = connection_id });
    }

    /// Adds `token` to the allow-list; new connections presenting it are
    /// admitted. Reference: `TokenAccess::allow`.
    pub fn add(self: *TokenAccessControl, token: []const u8) !void {
        self.lock();
        defer self.mu.unlock();
        const gop = try self.tokens.getOrPut(self.allocator, token);
        if (gop.found_existing) return;
        errdefer _ = self.tokens.remove(token);
        gop.key_ptr.* = try self.allocator.dupe(u8, token);
        gop.value_ptr.* = self.next_token_id;
        self.next_token_id += 1;
    }

    /// Removes `token` from the allow-list and appends the connections admitted
    /// under it to `removed` (reference: `TokenAccess::revoke` returning the
    /// `(EndpointId, ConnectionId)` pairs). The caller evicts each via
    /// `Server.disconnectConnection`; already-ended connections simply fail to
    /// match there. A token that is not allowed revokes nothing.
    pub fn revoke(self: *TokenAccessControl, token: []const u8, removed: *std.ArrayList(ConnKey)) !void {
        self.lock();
        defer self.mu.unlock();
        const kv = self.tokens.fetchRemove(token) orelse return;
        self.allocator.free(kv.key);
        const revoked_id = kv.value;
        // Copy out the matching keys first; removing during iteration is not allowed.
        const base = removed.items.len;
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == revoked_id) try removed.append(self.allocator, entry.key_ptr.*);
        }
        for (removed.items[base..]) |conn_key| _ = self.connections.remove(conn_key);
    }

    /// Number of admitted connections currently tracked (reference:
    /// `RestrictedServer::connection_count` in `runtime_auth.rs`).
    pub fn connectionCount(self: *TokenAccessControl) usize {
        self.lock();
        defer self.mu.unlock();
        return self.connections.count();
    }

    fn lock(self: *TokenAccessControl) void {
        while (!self.mu.tryLock()) std.Thread.yield() catch {};
    }

    fn onConnectThunk(context: *anyopaque, request: ClientRequest) AccessDecision {
        const self: *TokenAccessControl = @ptrCast(@alignCast(context));
        self.lock();
        defer self.mu.unlock();
        const token = request.auth_token orelse return .{ .deny = null };
        const token_id = self.tokens.get(token) orelse return .{ .deny = null };
        self.connections.put(self.allocator, .{
            .endpoint_id = request.endpoint_id,
            .connection_id = request.connection_id,
        }, token_id) catch {
            // Fail closed: an admission we cannot index could never be evicted.
            return .{ .deny = null };
        };
        return .allow;
    }

    fn onDisconnectThunk(context: *anyopaque, endpoint_id: key.PublicKey, connection_id: u64) void {
        const self: *TokenAccessControl = @ptrCast(@alignCast(context));
        self.lock();
        defer self.mu.unlock();
        _ = self.connections.remove(.{ .endpoint_id = endpoint_id, .connection_id = connection_id });
    }

    fn stillTrackedThunk(context: *anyopaque, endpoint_id: key.PublicKey, connection_id: u64) bool {
        const self: *TokenAccessControl = @ptrCast(@alignCast(context));
        return self.isTracked(endpoint_id, connection_id);
    }
};

const testing = std.testing;

fn testRequest(token: ?[]const u8, conn_id: u64) ClientRequest {
    return .{
        .connection_id = conn_id,
        .endpoint_id = key.SecretKey.fromBytes(.{0x31} ** 32).public(),
        .version = .v2,
        .auth_token = token,
    };
}

test "token allow-list: unknown and missing tokens are denied, allowed token admits" {
    var acl = TokenAccessControl.init(testing.allocator);
    defer acl.deinit();
    try acl.add("token-a");
    const control = acl.accessControl();

    try testing.expect(control.onConnect(testRequest("token-b", 1)) == .deny);
    try testing.expect(control.onConnect(testRequest(null, 2)) == .deny);
    try testing.expect(control.onConnect(testRequest("token-a", 3)) == .allow);
    try testing.expectEqual(@as(usize, 1), acl.connectionCount());
}

test "runtime add admits a previously denied token" {
    var acl = TokenAccessControl.init(testing.allocator);
    defer acl.deinit();
    const control = acl.accessControl();

    try testing.expect(control.onConnect(testRequest("late", 1)) == .deny);
    try acl.add("late");
    try testing.expect(control.onConnect(testRequest("late", 2)) == .allow);
}

test "revoke is token-scoped across connections sharing one endpoint" {
    var acl = TokenAccessControl.init(testing.allocator);
    defer acl.deinit();
    try acl.add("token-a");
    try acl.add("token-b");
    const control = acl.accessControl();
    const shared = key.SecretKey.fromBytes(.{0x32} ** 32).public();

    // Two connections under token-a and one under token-b on ONE public key.
    _ = control.onConnect(.{ .connection_id = 1, .endpoint_id = shared, .version = .v2, .auth_token = "token-a" });
    _ = control.onConnect(.{ .connection_id = 2, .endpoint_id = shared, .version = .v2, .auth_token = "token-a" });
    _ = control.onConnect(.{ .connection_id = 3, .endpoint_id = shared, .version = .v2, .auth_token = "token-b" });
    try testing.expectEqual(@as(usize, 3), acl.connectionCount());

    var removed: std.ArrayList(ConnKey) = .empty;
    defer removed.deinit(testing.allocator);
    try acl.revoke("token-a", &removed);

    // Exactly the two token-a connections are evicted; token-b survives.
    try testing.expectEqual(@as(usize, 2), removed.items.len);
    for (removed.items) |ck| {
        try testing.expect(ck.endpoint_id.eql(shared));
        try testing.expect(ck.connection_id == 1 or ck.connection_id == 2);
    }
    try testing.expectEqual(@as(usize, 1), acl.connectionCount());

    // The revoked token no longer admits; the surviving token still does.
    try testing.expect(control.onConnect(testRequest("token-a", 4)) == .deny);
    try testing.expect(control.onConnect(testRequest("token-b", 5)) == .allow);

    // Revoking an unknown token is a no-op.
    const before = removed.items.len;
    try acl.revoke("never-allowed", &removed);
    try testing.expectEqual(before, removed.items.len);
}

test "ordinary disconnect prunes the connection index" {
    var acl = TokenAccessControl.init(testing.allocator);
    defer acl.deinit();
    try acl.add("token-a");
    const control = acl.accessControl();
    const endpoint = key.SecretKey.fromBytes(.{0x33} ** 32).public();

    _ = control.onConnect(.{ .connection_id = 7, .endpoint_id = endpoint, .version = .v2, .auth_token = "token-a" });
    try testing.expectEqual(@as(usize, 1), acl.connectionCount());
    control.onDisconnect(endpoint, 7);
    try testing.expectEqual(@as(usize, 0), acl.connectionCount());

    // A disconnect that was already evicted by revoke prunes nothing further.
    _ = control.onConnect(.{ .connection_id = 8, .endpoint_id = endpoint, .version = .v2, .auth_token = "token-a" });
    var removed: std.ArrayList(ConnKey) = .empty;
    defer removed.deinit(testing.allocator);
    try acl.revoke("token-a", &removed);
    try testing.expectEqual(@as(usize, 1), removed.items.len);
    control.onDisconnect(endpoint, 8);
    try testing.expectEqual(@as(usize, 0), acl.connectionCount());
}

test "stillTracked reflects the index entry, not mere token allow-list membership" {
    var acl = TokenAccessControl.init(testing.allocator);
    defer acl.deinit();
    try acl.add("token-a");
    const control = acl.accessControl();
    const endpoint = key.SecretKey.fromBytes(.{0x34} ** 32).public();

    try testing.expect(!control.stillTracked(endpoint, 1));
    _ = control.onConnect(.{ .connection_id = 1, .endpoint_id = endpoint, .version = .v2, .auth_token = "token-a" });
    try testing.expect(control.stillTracked(endpoint, 1));

    var removed: std.ArrayList(ConnKey) = .empty;
    defer removed.deinit(testing.allocator);
    try acl.revoke("token-a", &removed);
    // Revoke removed the index entry even though the token bytes could be
    // re-allowed later — recheck must see the specific connection gone.
    try testing.expect(!control.stillTracked(endpoint, 1));
    try testing.expectEqual(@as(usize, 1), removed.items.len);
}
