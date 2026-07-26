const std = @import("std");
const packet = @import("packet.zig");

pub const ConnectionId = packet.ConnectionId;
pub const ResetToken = [16]u8;
pub const PathId = u32;
pub const zero_path: PathId = 0;

pub const SocketAddress = struct {
    bytes: [16]u8 = .{0} ** 16,
    len: u8 = 4,
    port: u16 = 0,

    pub fn ipv4(bytes: [4]u8, port: u16) SocketAddress {
        var self: SocketAddress = .{ .len = 4, .port = port };
        @memcpy(self.bytes[0..4], &bytes);
        return self;
    }

    pub fn ipv6(bytes: [16]u8, port: u16) SocketAddress {
        return .{ .bytes = bytes, .len = 16, .port = port };
    }

    pub fn eql(a: SocketAddress, b: SocketAddress) bool {
        return a.len == b.len and
            a.port == b.port and
            std.mem.eql(u8, a.bytes[0..a.len], b.bytes[0..b.len]);
    }
};

pub const FourTuple = struct {
    local: SocketAddress,
    remote: SocketAddress,

    pub fn eql(a: FourTuple, b: FourTuple) bool {
        return a.local.eql(b.local) and a.remote.eql(b.remote);
    }
};

pub const ConnectionHandle = struct {
    idx: u32,
    gen: u32,

    pub fn eql(a: ConnectionHandle, b: ConnectionHandle) bool {
        return a.idx == b.idx and a.gen == b.gen;
    }
};

pub const ConnHandlePath = struct {
    handle: ConnectionHandle,
    path_id: PathId = zero_path,
};

pub const Side = enum {
    client,
    server,
};

pub const RouteSource = enum {
    local_cid,
    initial_cid,
    empty_cid,
    stateless_reset,
};

pub const Route = struct {
    source: RouteSource,
    target: ConnHandlePath,
};

pub const FirstPacket = union(enum) {
    routed: Route,
    new_connection: ConnectionHandle,
    /// Owned VN datagram — caller must free with the endpoint GPA.
    version_negotiation: []u8,
};

pub const Options = struct {
    peer_hash_key: [16]u8,
    local_cid_len: u8,
    incoming_buffer_size: usize = 64 * 1024,
    incoming_buffer_size_total: usize = 256 * 1024,
};

pub const AddConnection = struct {
    init_cid: ConnectionId,
    side: Side = .server,
    local_cids: []const ConnectionId = &.{},
    initial_cids: []const ConnectionId = &.{},
    zero_cid_tuple: ?FourTuple = null,
    zero_cid_remote: ?SocketAddress = null,
    reset_remote: ?SocketAddress = null,
    reset_tokens: []const ResetToken = &.{},
};

pub const IncomingBuffer = struct {
    datagrams: std.ArrayList([]u8) = .empty,
    total_bytes: usize = 0,

    fn deinit(self: *IncomingBuffer, gpa: std.mem.Allocator) void {
        for (self.datagrams.items) |datagram| gpa.free(datagram);
        self.datagrams.deinit(gpa);
        self.* = undefined;
    }
};

pub const ConnectionMeta = struct {
    init_cid: ConnectionId = .{},
    side: Side = .server,
    incoming: IncomingBuffer = .{},
};

const ConnectionSlot = struct {
    gen: u32 = 0,
    live: bool = false,
    meta: ConnectionMeta = .{},
};

const SipHash = std.hash.SipHash64(2, 4);

const SipHashCidContext = struct {
    key: [16]u8,

    pub fn hash(self: @This(), cid: ConnectionId) u64 {
        return SipHash.toInt(cid.slice(), &self.key);
    }

    pub fn eql(_: @This(), a: ConnectionId, b: ConnectionId) bool {
        return cidEql(a, b);
    }
};

const SipHashAddressContext = struct {
    key: [16]u8,

    pub fn hash(self: @This(), addr: SocketAddress) u64 {
        var h = SipHash.init(&self.key);
        updateAddressHash(&h, addr);
        return h.finalInt();
    }

    pub fn eql(_: @This(), a: SocketAddress, b: SocketAddress) bool {
        return a.eql(b);
    }
};

const SipHashFourTupleContext = struct {
    key: [16]u8,

    pub fn hash(self: @This(), tuple: FourTuple) u64 {
        var h = SipHash.init(&self.key);
        updateAddressHash(&h, tuple.local);
        updateAddressHash(&h, tuple.remote);
        return h.finalInt();
    }

    pub fn eql(_: @This(), a: FourTuple, b: FourTuple) bool {
        return a.eql(b);
    }
};

const ResetKey = struct {
    remote: SocketAddress,
    token: ResetToken,
};

const SipHashResetContext = struct {
    key: [16]u8,

    pub fn hash(self: @This(), reset: ResetKey) u64 {
        var h = SipHash.init(&self.key);
        updateAddressHash(&h, reset.remote);
        h.update(&reset.token);
        return h.finalInt();
    }

    pub fn eql(_: @This(), a: ResetKey, b: ResetKey) bool {
        return a.remote.eql(b.remote) and std.mem.eql(u8, &a.token, &b.token);
    }
};

const InitialCidMap = std.HashMap(ConnectionId, ConnHandlePath, SipHashCidContext, 80);
const LocalCidMap = std.HashMap(ConnectionId, ConnHandlePath, SipHashCidContext, 80);
const IncomingRemoteMap = std.HashMap(FourTuple, ConnectionHandle, SipHashFourTupleContext, 80);
const OutgoingRemoteMap = std.HashMap(SocketAddress, ConnectionHandle, SipHashAddressContext, 80);
const ResetTokenMap = std.HashMap(ResetKey, ConnHandlePath, SipHashResetContext, 80);

pub const Endpoint = struct {
    gpa: std.mem.Allocator,
    incoming_buffer_size: usize,
    incoming_buffer_size_total: usize,
    incoming_total_bytes: usize = 0,
    connections: std.ArrayList(ConnectionSlot) = .empty,
    free_list: std.ArrayList(u32) = .empty,
    connection_ids_initial: InitialCidMap,
    connection_ids: LocalCidMap,
    /// Fixed short-header DCID length for this endpoint. QUIC short headers do
    /// not encode a length, so mixed local lengths cannot be disambiguated.
    local_cid_len: u8,
    incoming_connection_remotes: IncomingRemoteMap,
    outgoing_connection_remotes: OutgoingRemoteMap,
    connection_reset_tokens: ResetTokenMap,

    pub fn init(gpa: std.mem.Allocator, options: Options) !Endpoint {
        if (options.local_cid_len > packet.max_cid_size) return error.InvalidLocalCidLength;
        const cid_ctx: SipHashCidContext = .{ .key = options.peer_hash_key };
        const tuple_ctx: SipHashFourTupleContext = .{ .key = options.peer_hash_key };
        const addr_ctx: SipHashAddressContext = .{ .key = options.peer_hash_key };
        const reset_ctx: SipHashResetContext = .{ .key = options.peer_hash_key };
        return .{
            .gpa = gpa,
            .incoming_buffer_size = options.incoming_buffer_size,
            .incoming_buffer_size_total = options.incoming_buffer_size_total,
            .connection_ids_initial = InitialCidMap.initContext(gpa, cid_ctx),
            .connection_ids = LocalCidMap.initContext(gpa, cid_ctx),
            .local_cid_len = options.local_cid_len,
            .incoming_connection_remotes = IncomingRemoteMap.initContext(gpa, tuple_ctx),
            .outgoing_connection_remotes = OutgoingRemoteMap.initContext(gpa, addr_ctx),
            .connection_reset_tokens = ResetTokenMap.initContext(gpa, reset_ctx),
        };
    }

    pub fn deinit(self: *Endpoint) void {
        for (self.connections.items) |*slot| {
            if (slot.live) slot.meta.incoming.deinit(self.gpa);
        }
        self.connections.deinit(self.gpa);
        self.free_list.deinit(self.gpa);
        self.connection_ids_initial.deinit();
        self.connection_ids.deinit();
        self.incoming_connection_remotes.deinit();
        self.outgoing_connection_remotes.deinit();
        self.connection_reset_tokens.deinit();
        self.* = undefined;
    }

    pub fn addConnection(self: *Endpoint, args: AddConnection) !ConnectionHandle {
        const reset_remote = if (args.reset_tokens.len == 0)
            null
        else
            args.reset_remote orelse args.zero_cid_remote orelse if (args.zero_cid_tuple) |tuple| tuple.remote else return error.MissingResetTokenRemote;

        for (args.local_cids, 0..) |cid, cid_i| {
            if (cid.len != self.local_cid_len) return error.LocalCidLengthMismatch;
            if (cid.len != 0 and self.connection_ids.contains(cid)) return error.DuplicateLocalCid;
            for (args.local_cids[0..cid_i]) |prior| {
                if (cidEql(cid, prior)) return error.DuplicateLocalCid;
            }
        }
        for (args.initial_cids, 0..) |cid, cid_i| {
            if (cid.len != 0 and self.connection_ids_initial.contains(cid)) return error.DuplicateInitialCid;
            for (args.initial_cids[0..cid_i]) |prior| {
                if (cidEql(cid, prior)) return error.DuplicateInitialCid;
            }
        }
        if (self.local_cid_len == 0) {
            if (args.zero_cid_tuple) |tuple| {
                if (self.incoming_connection_remotes.contains(tuple)) return error.DuplicateZeroCidRoute;
            }
            if (args.zero_cid_remote) |remote| {
                if (self.outgoing_connection_remotes.contains(remote)) return error.DuplicateZeroCidRoute;
            }
        } else if (args.zero_cid_tuple != null or args.zero_cid_remote != null) {
            return error.ZeroCidRouteNotAllowed;
        }

        if (self.free_list.items.len == 0) {
            try self.connections.ensureUnusedCapacity(self.gpa, 1);
        }
        try self.connection_ids.ensureUnusedCapacity(@intCast(args.local_cids.len));
        try self.connection_ids_initial.ensureUnusedCapacity(@intCast(args.initial_cids.len));
        if (args.zero_cid_tuple != null) try self.incoming_connection_remotes.ensureUnusedCapacity(1);
        if (args.zero_cid_remote != null) try self.outgoing_connection_remotes.ensureUnusedCapacity(1);
        try self.connection_reset_tokens.ensureUnusedCapacity(@intCast(args.reset_tokens.len));

        errdefer comptime unreachable;

        const idx = if (self.free_list.pop()) |free_idx| free_idx else idx: {
            const next: u32 = @intCast(self.connections.items.len);
            self.connections.appendAssumeCapacity(.{});
            break :idx next;
        };
        const slot = &self.connections.items[@intCast(idx)];
        slot.live = true;
        slot.meta = .{ .init_cid = args.init_cid, .side = args.side };

        const handle: ConnectionHandle = .{ .idx = idx, .gen = slot.gen };
        const target: ConnHandlePath = .{ .handle = handle };
        for (args.local_cids) |cid| {
            if (cid.len == 0) continue;
            self.connection_ids.putAssumeCapacity(cid, target);
        }
        for (args.initial_cids) |cid| {
            if (cid.len == 0) continue;
            self.connection_ids_initial.putAssumeCapacity(cid, target);
        }
        if (args.zero_cid_tuple) |tuple| {
            self.incoming_connection_remotes.putAssumeCapacity(tuple, handle);
        }
        if (args.zero_cid_remote) |remote| {
            self.outgoing_connection_remotes.putAssumeCapacity(remote, handle);
        }
        for (args.reset_tokens) |token| {
            self.connection_reset_tokens.putAssumeCapacity(.{ .remote = reset_remote.?, .token = token }, target);
        }
        return handle;
    }

    pub fn removeConnection(self: *Endpoint, handle: ConnectionHandle) !void {
        const slot = try self.slotFor(handle);
        try self.free_list.ensureUnusedCapacity(self.gpa, 1);

        self.removeConnectionReferences(handle);
        self.incoming_total_bytes -= slot.meta.incoming.total_bytes;
        slot.meta.incoming.deinit(self.gpa);
        slot.live = false;
        slot.gen +%= 1;
        self.free_list.appendAssumeCapacity(handle.idx);
    }

    pub fn connection(self: *Endpoint, handle: ConnectionHandle) !*ConnectionMeta {
        return &(try self.slotFor(handle)).meta;
    }

    pub fn registerLocalCid(self: *Endpoint, handle: ConnectionHandle, cid: ConnectionId) !void {
        _ = try self.slotFor(handle);
        if (cid.len == 0 or cid.len != self.local_cid_len) return error.LocalCidLengthMismatch;
        if (self.connection_ids.contains(cid)) return error.DuplicateLocalCid;
        try self.connection_ids.put(cid, .{ .handle = handle });
    }

    pub fn registerResetToken(
        self: *Endpoint,
        handle: ConnectionHandle,
        remote: SocketAddress,
        token: ResetToken,
    ) !void {
        _ = try self.slotFor(handle);
        const target: ConnHandlePath = .{ .handle = handle };
        try self.connection_reset_tokens.put(.{ .remote = remote, .token = token }, target);
    }

    pub fn routeDatagram(self: *Endpoint, path: FourTuple, datagram: []const u8) !?Route {
        if (datagram.len == 0) return null;
        const first = datagram[0];
        if (first & packet.long_header_form != 0) {
            const protected = packet.decodeProtectedHeader(datagram) catch |err| switch (err) {
                error.NonInitialUnsupported => return null,
                else => return err,
            };
            return try self.routeInitial(protected.initial.dst_cid);
        }

        if (self.local_cid_len != 0) {
            if (self.matchLocalCid(datagram[1..])) |target| {
                return try self.routeTarget(.local_cid, target);
            }
        } else {
            if (try self.routeEmptyCid(path)) |route| return route;
        }
        return try self.routeStatelessReset(path.remote, datagram);
    }

    pub fn maybeVersionNegotiation(self: *Endpoint, path: FourTuple, datagram: []const u8) !?[]u8 {
        if (datagram.len == 0) return null;
        if ((datagram[0] & packet.long_header_form) == 0) return null;
        const protected = packet.decodeProtectedHeader(datagram) catch return null;
        if (protected.initial.version == 1) return null;
        _ = path;
        const supported = [_]u32{1};
        return try packet.buildVersionNegotiation(
            self.gpa,
            protected.initial.src_cid,
            protected.initial.dst_cid,
            &supported,
        );
    }

    pub fn handleFirstPacket(self: *Endpoint, path: FourTuple, datagram: []const u8) !FirstPacket {
        // Staged validation BEFORE allocation (v3 cross-apply): reject non-Initial /
        // bad-version first-contact datagrams without minting connection state.
        if (datagram.len == 0) return error.PacketTooShort;
        if ((datagram[0] & packet.long_header_form) == 0) return error.InvalidPacket;
        const protected = try packet.decodeProtectedHeader(datagram);
        if (protected.initial.version != 1) {
            if (try self.maybeVersionNegotiation(path, datagram)) |vn| {
                return .{ .version_negotiation = vn };
            }
            return error.UnsupportedVersion;
        }
        if (try self.routeInitial(protected.initial.dst_cid)) |route| {
            return .{ .routed = route };
        }

        const dst_cid = protected.initial.dst_cid;
        try checkIncomingLimit(0, datagram.len, self.incoming_buffer_size);
        try checkIncomingLimit(self.incoming_total_bytes, datagram.len, self.incoming_buffer_size_total);

        var incoming: IncomingBuffer = .{};
        errdefer incoming.deinit(self.gpa);
        try incoming.datagrams.ensureUnusedCapacity(self.gpa, 1);
        const copy = try self.gpa.dupe(u8, datagram);
        incoming.datagrams.appendAssumeCapacity(copy);
        incoming.total_bytes = datagram.len;

        const handle = try self.addConnection(.{
            .init_cid = dst_cid,
            .side = .server,
            .initial_cids = &.{dst_cid},
            .zero_cid_tuple = if (self.local_cid_len == 0) path else null,
        });
        const slot = self.slotFor(handle) catch unreachable;
        slot.meta.incoming = incoming;
        incoming = .{};
        self.incoming_total_bytes += datagram.len;
        return .{ .new_connection = handle };
    }

    pub fn bufferIncoming(self: *Endpoint, handle: ConnectionHandle, datagram: []const u8) !void {
        const slot = try self.slotFor(handle);
        try checkIncomingLimit(slot.meta.incoming.total_bytes, datagram.len, self.incoming_buffer_size);
        try checkIncomingLimit(self.incoming_total_bytes, datagram.len, self.incoming_buffer_size_total);

        const copy = try self.gpa.dupe(u8, datagram);
        errdefer self.gpa.free(copy);
        try slot.meta.incoming.datagrams.append(self.gpa, copy);
        slot.meta.incoming.total_bytes += datagram.len;
        self.incoming_total_bytes += datagram.len;
    }

    fn slotFor(self: *Endpoint, handle: ConnectionHandle) !*ConnectionSlot {
        if (handle.idx >= self.connections.items.len) return error.StaleConnectionHandle;
        const slot = &self.connections.items[@intCast(handle.idx)];
        if (!slot.live or slot.gen != handle.gen) return error.StaleConnectionHandle;
        return slot;
    }

    fn routeInitial(self: *Endpoint, dst_cid: ConnectionId) !?Route {
        const target = self.connection_ids_initial.get(dst_cid) orelse return null;
        return try self.routeTarget(.initial_cid, target);
    }

    fn routeEmptyCid(self: *Endpoint, path: FourTuple) !?Route {
        if (self.incoming_connection_remotes.get(path)) |handle| {
            return try self.routeTarget(.empty_cid, .{ .handle = handle });
        }
        if (self.outgoing_connection_remotes.get(path.remote)) |handle| {
            return try self.routeTarget(.empty_cid, .{ .handle = handle });
        }
        return null;
    }

    fn routeStatelessReset(self: *Endpoint, remote: SocketAddress, datagram: []const u8) !?Route {
        if (datagram.len < 16) return null;
        const token = datagram[datagram.len - 16 ..][0..16].*;
        const target = self.connection_reset_tokens.get(.{ .remote = remote, .token = token }) orelse return null;
        return try self.routeTarget(.stateless_reset, target);
    }

    fn routeTarget(self: *Endpoint, source: RouteSource, target: ConnHandlePath) !Route {
        _ = try self.slotFor(target.handle);
        return .{ .source = source, .target = target };
    }

    fn matchLocalCid(self: *Endpoint, bytes: []const u8) ?ConnHandlePath {
        const len: usize = self.local_cid_len;
        if (len == 0 or bytes.len < len) return null;
        const cid = ConnectionId.init(bytes[0..len]) catch unreachable;
        return self.connection_ids.get(cid);
    }

    fn removeConnectionReferences(self: *Endpoint, handle: ConnectionHandle) void {
        while (true) {
            var found: ?ConnectionId = null;
            var it = self.connection_ids.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.handle.eql(handle)) {
                    found = entry.key_ptr.*;
                    break;
                }
            }
            if (found) |key| {
                _ = self.connection_ids.remove(key);
            } else break;
        }
        while (true) {
            var found: ?ConnectionId = null;
            var it = self.connection_ids_initial.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.handle.eql(handle)) {
                    found = entry.key_ptr.*;
                    break;
                }
            }
            if (found) |key| {
                _ = self.connection_ids_initial.remove(key);
            } else break;
        }

        while (true) {
            var found: ?FourTuple = null;
            var it = self.incoming_connection_remotes.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.eql(handle)) {
                    found = entry.key_ptr.*;
                    break;
                }
            }
            if (found) |key| {
                _ = self.incoming_connection_remotes.remove(key);
            } else break;
        }

        while (true) {
            var found: ?SocketAddress = null;
            var it = self.outgoing_connection_remotes.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.eql(handle)) {
                    found = entry.key_ptr.*;
                    break;
                }
            }
            if (found) |key| {
                _ = self.outgoing_connection_remotes.remove(key);
            } else break;
        }

        while (true) {
            var found: ?ResetKey = null;
            var it = self.connection_reset_tokens.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.handle.eql(handle)) {
                    found = entry.key_ptr.*;
                    break;
                }
            }
            if (found) |key| {
                _ = self.connection_reset_tokens.remove(key);
            } else break;
        }
    }
};

fn cidEql(a: ConnectionId, b: ConnectionId) bool {
    return a.len == b.len and std.mem.eql(u8, a.slice(), b.slice());
}

fn checkIncomingLimit(current: usize, additional: usize, limit: usize) !void {
    if (current > limit or additional > limit - current) return error.IncomingBufferFull;
}

fn updateAddressHash(h: *SipHash, addr: SocketAddress) void {
    h.update(&.{addr.len});
    h.update(addr.bytes[0..addr.len]);
    h.update(std.mem.asBytes(&addr.port));
}

fn shortDatagram(cid: ConnectionId, out: []u8) ![]u8 {
    if (out.len < 1 + cid.len + 1) return error.NoSpaceLeft;
    out[0] = packet.fixed_bit;
    @memcpy(out[1..][0..cid.len], cid.slice());
    out[1 + cid.len] = 0xaa;
    return out[0 .. 1 + cid.len + 1];
}

fn testKey() [16]u8 {
    return .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
}

test "N3b-1 endpoint routes local, initial, and stateless reset" {
    var endpoint = try Endpoint.init(std.testing.allocator, .{ .peer_hash_key = testKey(), .local_cid_len = 4 });
    defer endpoint.deinit();

    const local_addr = SocketAddress.ipv4(.{ 127, 0, 0, 1 }, 4433);
    const remote_a = SocketAddress.ipv4(.{ 192, 0, 2, 1 }, 9000);
    const remote_b = SocketAddress.ipv4(.{ 192, 0, 2, 2 }, 9001);
    const path_a: FourTuple = .{ .local = local_addr, .remote = remote_a };
    const path_b: FourTuple = .{ .local = local_addr, .remote = remote_b };

    const local_cid = try ConnectionId.init(&.{ 0x10, 0x11, 0x12, 0x13 });
    const initial_cid = try ConnectionId.init(&.{ 0x20, 0x21, 0x22, 0x23 });
    const other_local_cid = try ConnectionId.init(&.{ 0x30, 0x31, 0x32, 0x33 });
    const reset_token: ResetToken = .{0x55} ** 16;

    const handle_a = try endpoint.addConnection(.{
        .init_cid = initial_cid,
        .local_cids = &.{local_cid},
        .initial_cids = &.{initial_cid},
    });
    const handle_b = try endpoint.addConnection(.{
        .init_cid = other_local_cid,
        .local_cids = &.{other_local_cid},
        .reset_remote = remote_b,
        .reset_tokens = &.{reset_token},
    });

    var short_buf: [32]u8 = undefined;
    const local_route = (try endpoint.routeDatagram(path_a, try shortDatagram(local_cid, &short_buf))).?;
    try std.testing.expectEqual(RouteSource.local_cid, local_route.source);
    try std.testing.expect(local_route.target.handle.eql(handle_a));

    var initial_buf: [64]u8 = undefined;
    const src_cid = try ConnectionId.init(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    const initial = try (packet.InitialHeader{
        .version = 1,
        .dst_cid = initial_cid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
    }).encode(&initial_buf);
    const initial_route = (try endpoint.routeDatagram(path_a, initial)).?;
    try std.testing.expectEqual(RouteSource.initial_cid, initial_route.source);
    try std.testing.expect(initial_route.target.handle.eql(handle_a));

    var reset_datagram: [24]u8 = .{0x42} ** 24;
    @memcpy(reset_datagram[reset_datagram.len - 16 ..], &reset_token);
    const reset_route = (try endpoint.routeDatagram(path_b, &reset_datagram)).?;
    try std.testing.expectEqual(RouteSource.stateless_reset, reset_route.source);
    try std.testing.expect(reset_route.target.handle.eql(handle_b));
}

test "N3b-1 endpoint keeps zero-length CIDs out of CID prefix maps" {
    var endpoint = try Endpoint.init(std.testing.allocator, .{ .peer_hash_key = testKey(), .local_cid_len = 0 });
    defer endpoint.deinit();

    const local_addr = SocketAddress.ipv4(.{ 127, 0, 0, 1 }, 4433);
    const remote_a = SocketAddress.ipv4(.{ 192, 0, 2, 9 }, 9010);
    const remote_b = SocketAddress.ipv4(.{ 192, 0, 2, 10 }, 9011);
    const path_a: FourTuple = .{ .local = local_addr, .remote = remote_a };
    const path_b: FourTuple = .{ .local = local_addr, .remote = remote_b };
    const empty_cid = try ConnectionId.init(&.{});

    const handle = try endpoint.addConnection(.{
        .init_cid = empty_cid,
        .local_cids = &.{empty_cid},
        .initial_cids = &.{empty_cid},
        .zero_cid_tuple = path_a,
    });
    try std.testing.expectEqual(@as(usize, 0), endpoint.connection_ids.count());
    try std.testing.expectEqual(@as(usize, 0), endpoint.connection_ids_initial.count());

    const empty_route = (try endpoint.routeDatagram(path_a, &.{ packet.fixed_bit, 0xaa, 0xbb })).?;
    try std.testing.expectEqual(RouteSource.empty_cid, empty_route.source);
    try std.testing.expect(empty_route.target.handle.eql(handle));
    try std.testing.expect((try endpoint.routeDatagram(path_b, &.{ packet.fixed_bit, 0xaa, 0xbb })) == null);
    try std.testing.expectError(error.DuplicateZeroCidRoute, endpoint.addConnection(.{
        .init_cid = empty_cid,
        .local_cids = &.{empty_cid},
        .zero_cid_tuple = path_a,
    }));
    try std.testing.expectEqual(@as(usize, 1), endpoint.connections.items.len);
}

test "N3b-1 endpoint rejects mixed and duplicate local CIDs atomically" {
    var endpoint = try Endpoint.init(std.testing.allocator, .{ .peer_hash_key = testKey(), .local_cid_len = 4 });
    defer endpoint.deinit();

    const short_cid = try ConnectionId.init(&.{ 0x10, 0x11 });
    const long_cid = try ConnectionId.init(&.{ 0x10, 0x11, 0x12, 0x13 });
    try std.testing.expectError(error.LocalCidLengthMismatch, endpoint.addConnection(.{ .init_cid = short_cid, .local_cids = &.{short_cid} }));
    try std.testing.expectEqual(@as(usize, 0), endpoint.connections.items.len);
    const handle = try endpoint.addConnection(.{ .init_cid = long_cid, .local_cids = &.{long_cid} });
    try std.testing.expectError(error.DuplicateLocalCid, endpoint.addConnection(.{ .init_cid = long_cid, .local_cids = &.{long_cid} }));
    try std.testing.expectError(error.DuplicateLocalCid, endpoint.addConnection(.{ .init_cid = long_cid, .local_cids = &.{ long_cid, long_cid } }));
    try std.testing.expectEqual(@as(usize, 1), endpoint.connections.items.len);
    try std.testing.expect((try endpoint.connection(handle)).init_cid.len == long_cid.len);
    try std.testing.expectError(error.InvalidLocalCidLength, Endpoint.init(std.testing.allocator, .{
        .peer_hash_key = testKey(),
        .local_cid_len = packet.max_cid_size + 1,
    }));
}

test "N3b-1 endpoint rejects stale generation handles and prunes removed routes" {
    var endpoint = try Endpoint.init(std.testing.allocator, .{ .peer_hash_key = testKey(), .local_cid_len = 4 });
    defer endpoint.deinit();

    const local_addr = SocketAddress.ipv4(.{ 127, 0, 0, 1 }, 4433);
    const remote = SocketAddress.ipv4(.{ 192, 0, 2, 3 }, 9002);
    const path: FourTuple = .{ .local = local_addr, .remote = remote };
    const old_cid = try ConnectionId.init(&.{ 0x40, 0x41, 0x42, 0x43 });
    const new_cid = try ConnectionId.init(&.{ 0x50, 0x51, 0x52, 0x53 });

    const old_handle = try endpoint.addConnection(.{
        .init_cid = old_cid,
        .local_cids = &.{old_cid},
    });
    try endpoint.removeConnection(old_handle);

    const new_handle = try endpoint.addConnection(.{
        .init_cid = new_cid,
        .local_cids = &.{new_cid},
    });
    try std.testing.expectEqual(old_handle.idx, new_handle.idx);
    try std.testing.expect(old_handle.gen != new_handle.gen);
    try std.testing.expectError(error.StaleConnectionHandle, endpoint.connection(old_handle));

    var datagram: [16]u8 = undefined;
    try std.testing.expect((try endpoint.routeDatagram(path, try shortDatagram(old_cid, &datagram))) == null);
    const reused_handle = try endpoint.addConnection(.{ .init_cid = old_cid, .local_cids = &.{old_cid} });
    const reused_route = (try endpoint.routeDatagram(path, try shortDatagram(old_cid, &datagram))).?;
    try std.testing.expect(reused_route.target.handle.eql(reused_handle));
    try std.testing.expect(!reused_route.target.handle.eql(old_handle));
}

test "N3b-1 removeConnection prunes all routing indexes for the handle" {
    var endpoint = try Endpoint.init(std.testing.allocator, .{ .peer_hash_key = testKey(), .local_cid_len = 4 });
    defer endpoint.deinit();

    const local_addr = SocketAddress.ipv4(.{ 127, 0, 0, 1 }, 4433);
    const remote = SocketAddress.ipv4(.{ 192, 0, 2, 4 }, 9004);
    const path: FourTuple = .{ .local = local_addr, .remote = remote };
    const local_cid = try ConnectionId.init(&.{ 0x60, 0x61, 0x62, 0x63 });
    const initial_cid = try ConnectionId.init(&.{ 0x70, 0x71, 0x72, 0x73 });
    const reset_token: ResetToken = .{0x88} ** 16;

    const handle = try endpoint.addConnection(.{
        .init_cid = initial_cid,
        .local_cids = &.{local_cid},
        .initial_cids = &.{initial_cid},
        .reset_remote = remote,
        .reset_tokens = &.{reset_token},
    });
    try endpoint.removeConnection(handle);

    var short_buf: [32]u8 = undefined;
    try std.testing.expect((try endpoint.routeDatagram(path, try shortDatagram(local_cid, &short_buf))) == null);

    var initial_buf: [64]u8 = undefined;
    const src_cid = try ConnectionId.init(&.{ 0xaa, 0xbb, 0xcc, 0xdd });
    const initial = try (packet.InitialHeader{
        .version = 1,
        .dst_cid = initial_cid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
    }).encode(&initial_buf);
    try std.testing.expect((try endpoint.routeDatagram(path, initial)) == null);

    try std.testing.expect((try endpoint.routeDatagram(path, &.{ packet.fixed_bit, 0xee, 0xee })) == null);

    var reset_datagram: [24]u8 = .{0x42} ** 24;
    @memcpy(reset_datagram[reset_datagram.len - 16 ..], &reset_token);
    try std.testing.expect((try endpoint.routeDatagram(path, &reset_datagram)) == null);
}

test "N3b-1 incoming buffer enforces per-buffer and global memory caps" {
    var endpoint = try Endpoint.init(std.testing.allocator, .{
        .peer_hash_key = testKey(),
        .local_cid_len = 4,
        .incoming_buffer_size = 8,
        .incoming_buffer_size_total = 12,
    });
    defer endpoint.deinit();

    const cid_a = try ConnectionId.init(&.{0xa0});
    const cid_b = try ConnectionId.init(&.{0xb0});
    const handle_a = try endpoint.addConnection(.{ .init_cid = cid_a });
    const handle_b = try endpoint.addConnection(.{ .init_cid = cid_b });

    try endpoint.bufferIncoming(handle_a, "12345678");
    try std.testing.expectError(error.IncomingBufferFull, endpoint.bufferIncoming(handle_a, "x"));
    try std.testing.expectError(error.IncomingBufferFull, endpoint.bufferIncoming(handle_b, "12345"));
}

test "N3b-1 handleFirstPacket mints a keyless incoming route by cleartext DCID" {
    var endpoint = try Endpoint.init(std.testing.allocator, .{ .peer_hash_key = testKey(), .local_cid_len = 4 });
    defer endpoint.deinit();

    const local_addr = SocketAddress.ipv4(.{ 127, 0, 0, 1 }, 4433);
    const remote = SocketAddress.ipv4(.{ 198, 51, 100, 1 }, 9003);
    const path: FourTuple = .{ .local = local_addr, .remote = remote };
    const dst_cid = try ConnectionId.init(&.{ 0xc0, 0xc1, 0xc2, 0xc3 });
    const src_cid = try ConnectionId.init(&.{ 0xd0, 0xd1, 0xd2, 0xd3 });

    var initial_buf: [64]u8 = undefined;
    const initial = try (packet.InitialHeader{
        .version = 1,
        .dst_cid = dst_cid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
    }).encode(&initial_buf);

    const first = try endpoint.handleFirstPacket(path, initial);
    const handle = switch (first) {
        .new_connection => |handle| handle,
        .routed => return error.UnexpectedRoute,
        .version_negotiation => |vn| {
            std.testing.allocator.free(vn);
            return error.UnexpectedVersionNegotiation;
        },
    };
    const meta = try endpoint.connection(handle);
    try std.testing.expectEqualSlices(u8, dst_cid.slice(), meta.init_cid.slice());
    try std.testing.expectEqual(initial.len, meta.incoming.total_bytes);

    const fresh_local_cid = try ConnectionId.init(&.{ 0x41, 0x42, 0x43, 0x44 });
    try endpoint.registerLocalCid(handle, fresh_local_cid);
    var short_buf: [16]u8 = undefined;
    const short_route = (try endpoint.routeDatagram(path, try shortDatagram(fresh_local_cid, &short_buf))).?;
    try std.testing.expectEqual(RouteSource.local_cid, short_route.source);
    try std.testing.expect(short_route.target.handle.eql(handle));

    const routed = try endpoint.handleFirstPacket(path, initial);
    const route = switch (routed) {
        .routed => |route| route,
        .new_connection => return error.UnexpectedNewConnection,
        .version_negotiation => |vn| {
            std.testing.allocator.free(vn);
            return error.UnexpectedVersionNegotiation;
        },
    };
    try std.testing.expectEqual(RouteSource.initial_cid, route.source);
    try std.testing.expect(route.target.handle.eql(handle));
}

test "N3b-1 handleFirstPacket is all-or-nothing when initial buffering exceeds caps" {
    var endpoint = try Endpoint.init(std.testing.allocator, .{
        .peer_hash_key = testKey(),
        .local_cid_len = 4,
        .incoming_buffer_size = 1,
        .incoming_buffer_size_total = 1,
    });
    defer endpoint.deinit();

    const local_addr = SocketAddress.ipv4(.{ 127, 0, 0, 1 }, 4433);
    const remote = SocketAddress.ipv4(.{ 198, 51, 100, 2 }, 9005);
    const path: FourTuple = .{ .local = local_addr, .remote = remote };
    const dst_cid = try ConnectionId.init(&.{ 0xe0, 0xe1, 0xe2, 0xe3 });
    const src_cid = try ConnectionId.init(&.{ 0xf0, 0xf1, 0xf2, 0xf3 });

    var initial_buf: [64]u8 = undefined;
    const initial = try (packet.InitialHeader{
        .version = 1,
        .dst_cid = dst_cid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
    }).encode(&initial_buf);

    try std.testing.expectError(error.IncomingBufferFull, endpoint.handleFirstPacket(path, initial));
    try std.testing.expectEqual(@as(usize, 0), endpoint.connections.items.len);
    try std.testing.expectEqual(@as(usize, 0), endpoint.connection_ids_initial.count());
    try std.testing.expectEqual(@as(usize, 0), endpoint.incoming_connection_remotes.count());
    try std.testing.expectEqual(@as(usize, 0), endpoint.incoming_total_bytes);
    try std.testing.expect((try endpoint.routeDatagram(path, initial)) == null);
}

test "N-3 endpoint registerResetToken routes stateless reset" {
    var endpoint = try Endpoint.init(std.testing.allocator, .{ .peer_hash_key = testKey(), .local_cid_len = 1 });
    defer endpoint.deinit();
    const remote = SocketAddress.ipv4(.{ 203, 0, 113, 1 }, 9443);
    const path: FourTuple = .{ .local = SocketAddress.ipv4(.{ 127, 0, 0, 1 }, 4433), .remote = remote };
    const cid = try ConnectionId.init(&.{0xab});
    const handle = try endpoint.addConnection(.{ .init_cid = cid, .local_cids = &.{cid} });
    const token: ResetToken = .{0x77} ** 16;
    try endpoint.registerResetToken(handle, remote, token);
    var reset_datagram: [24]u8 = .{0x42} ** 24;
    @memcpy(reset_datagram[reset_datagram.len - 16 ..], &token);
    const route = (try endpoint.routeDatagram(path, &reset_datagram)).?;
    try std.testing.expectEqual(RouteSource.stateless_reset, route.source);
    try std.testing.expect(route.target.handle.eql(handle));
}

test "N-2 staged validation rejects short-header and bad-version before alloc" {
    var endpoint = try Endpoint.init(std.testing.allocator, .{ .peer_hash_key = testKey(), .local_cid_len = 4 });
    defer endpoint.deinit();
    const local_addr = SocketAddress.ipv4(.{ 127, 0, 0, 1 }, 4433);
    const remote = SocketAddress.ipv4(.{ 198, 51, 100, 9 }, 9009);
    const path: FourTuple = .{ .local = local_addr, .remote = remote };

    try std.testing.expectError(error.InvalidPacket, endpoint.handleFirstPacket(path, &[_]u8{packet.fixed_bit}));
    try std.testing.expectEqual(@as(usize, 0), endpoint.connections.items.len);

    const dst_cid = try ConnectionId.init(&.{ 0x10, 0x11, 0x12, 0x13 });
    const src_cid = try ConnectionId.init(&.{ 0x20, 0x21, 0x22, 0x23 });
    var initial_buf: [64]u8 = undefined;
    const bad = try (packet.InitialHeader{
        .version = 0x0a0a0a0a,
        .dst_cid = dst_cid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
    }).encode(&initial_buf);
    const first = try endpoint.handleFirstPacket(path, bad);
    try std.testing.expect(first == .version_negotiation);
    const vn = first.version_negotiation;
    defer std.testing.allocator.free(vn);
    try std.testing.expectEqual(@as(usize, 0), endpoint.connections.items.len);
    const parsed = try packet.parseVersionNegotiation(vn);
    try std.testing.expectEqual(@as(u32, 1), parsed.supported_versions[0]);
}

test "N-3 VN auto-reply bad-version Initial yields parseable VN listing version 1" {
    var endpoint = try Endpoint.init(std.testing.allocator, .{ .peer_hash_key = testKey(), .local_cid_len = 4 });
    defer endpoint.deinit();
    const path: FourTuple = .{
        .local = SocketAddress.ipv4(.{ 127, 0, 0, 1 }, 4433),
        .remote = SocketAddress.ipv4(.{ 10, 0, 0, 1 }, 9000),
    };
    const dst_cid = try ConnectionId.init(&.{ 0xaa, 0xbb });
    const src_cid = try ConnectionId.init(&.{ 0xcc, 0xdd });
    var buf: [128]u8 = undefined;
    const initial = try (packet.InitialHeader{
        .version = 0xdeadbeef,
        .dst_cid = dst_cid,
        .src_cid = src_cid,
        .packet_number = .{ .value = 0, .len = 1 },
        .payload_len = 0,
    }).encode(&buf);
    const first = try endpoint.handleFirstPacket(path, initial);
    try std.testing.expect(first == .version_negotiation);
    defer std.testing.allocator.free(first.version_negotiation);
    const parsed = try packet.parseVersionNegotiation(first.version_negotiation);
    try std.testing.expectEqualSlices(u8, src_cid.slice(), parsed.dst_cid.slice());
    try std.testing.expectEqualSlices(u8, dst_cid.slice(), parsed.src_cid.slice());
    try std.testing.expect(parsed.supported_versions.len >= 1);
    try std.testing.expectEqual(@as(u32, 1), parsed.supported_versions[0]);
}
