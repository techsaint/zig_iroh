const std = @import("std");
const root = @import("../root.zig");
const discovery = @import("../discovery/discovery.zig");
const dht_client = @import("client.zig");
const krpc = @import("krpc.zig");
const bencode = @import("bencode.zig");

fn envEnabled(name: [:0]const u8) bool {
    const raw = std.c.getenv(name.ptr) orelse return false;
    const value = std.mem.span(raw);
    return std.mem.eql(u8, value, "1") or
        std.ascii.eqlIgnoreCase(value, "true") or
        std.ascii.eqlIgnoreCase(value, "yes");
}

pub const DhtDiscovery = struct {
    client: *dht_client.Client,

    pub fn publish(
        self: DhtDiscovery,
        secret_key: root.SecretKey,
        info: discovery.EndpointInfo,
        ttl: u32,
        timestamp: discovery.Timestamp,
    ) !void {
        var packet = try discovery.SignedPacket.fromEndpointInfoAt(
            self.client.allocator,
            secret_key,
            info,
            ttl,
            timestamp,
        );
        defer packet.deinit(self.client.allocator);

        try self.client.put(
            secret_key.public().bytes,
            timestamp.micros,
            packet.encodedPacket(),
            packet.signature.bytes,
        );
    }

    pub fn resolve(self: DhtDiscovery, node_id: root.NodeId) !discovery.EndpointInfo {
        const res = try self.client.get(node_id.bytes);
        defer self.client.allocator.free(res.value);

        var payload = try self.client.allocator.alloc(u8, 64 + 8 + res.value.len);
        defer self.client.allocator.free(payload);
        @memcpy(payload[0..64], &res.signature);
        std.mem.writeInt(u64, payload[64..72], res.seq, .big);
        @memcpy(payload[72..], res.value);

        // client.get already cofactor-verified the BEP-44 signature (ADR
        // 2026-06-27: lax ONLY at the DHT boundary). Re-verify with the same
        // cofactored mode — do NOT use the strict default, which would reject
        // malleable encodings mainline/iroh DHT accept. pkarr/relay keep strict
        // via SignedPacket.fromRelayPayload → fromBytesOwned(.strict).
        var packet = try discovery.SignedPacket.fromRelayPayloadMode(
            self.client.allocator,
            node_id,
            payload,
            .cofactored,
        );
        defer packet.deinit(self.client.allocator);

        return try discovery.EndpointInfo.fromSignedPacket(self.client.allocator, packet);
    }
};

const StoredItem = struct {
    v: []const u8,
    sig: [64]u8,
    seq: u64,
    k: [32]u8,
};

const MockDhtServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    socket: std.Io.net.Socket,
    store: std.AutoHashMap([20]u8, StoredItem),
    running: std.atomic.Value(bool),
    thread: ?std.Thread = null,

    fn start(self: *MockDhtServer) !void {
        self.running.store(true, .monotonic);
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn stop(self: *MockDhtServer) void {
        self.running.store(false, .monotonic);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        var it = self.store.valueIterator();
        while (it.next()) |val| {
            self.allocator.free(val.v);
        }
        self.store.deinit();
        self.socket.close(self.io);
    }

    fn putSigned(self: *MockDhtServer, target_pubkey: [32]u8, k: [32]u8, v: []const u8, sig: [64]u8, seq: u64) !void {
        var target: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(&target_pubkey, &target, .{});

        const v_copy = try self.allocator.dupe(u8, v);
        errdefer self.allocator.free(v_copy);
        const old = self.store.get(target);
        try self.store.put(target, .{
            .v = v_copy,
            .sig = sig,
            .seq = seq,
            .k = k,
        });
        if (old) |old_item| self.allocator.free(old_item.v);
    }

    fn run(self: *MockDhtServer) void {
        var buf: [1500]u8 = undefined;
        while (self.running.load(.monotonic)) {
            const timeout = std.Io.Timeout{
                .duration = .{
                    .raw = std.Io.Duration.fromMilliseconds(50),
                    .clock = .awake,
                },
            };
            const msg = self.socket.receiveTimeout(self.io, &buf, timeout) catch |err| {
                if (err == error.Timeout) continue;
                break;
            };

            const val = bencode.parse(msg.data, self.allocator) catch continue;
            defer val.deinit(self.allocator);

            const parsed = krpc.Message.parse(val) catch continue;

            if (parsed.msg_type == .query) {
                const q = parsed.body.query;
                if (std.mem.eql(u8, q.method, "find_node")) {
                    var nodes_buf: std.Io.Writer.Allocating = .init(self.allocator);
                    defer nodes_buf.deinit();
                    const self_node = krpc.NodeInfo{
                        .id = [_]u8{3} ** 20,
                        .address = self.socket.address,
                    };
                    self_node.encodeCompact(&nodes_buf.writer) catch continue;
                    const nodes = nodes_buf.toOwnedSlice() catch continue;
                    defer self.allocator.free(nodes);

                    var res_kvs: std.ArrayList(bencode.Value.KV) = .empty;
                    defer res_kvs.deinit(self.allocator);
                    res_kvs.append(self.allocator, .{ .key = "id", .value = .{ .string = &[_]u8{3} ** 20 } }) catch continue;
                    res_kvs.append(self.allocator, .{ .key = "nodes", .value = .{ .string = nodes } }) catch continue;

                    const resp = krpc.Message{
                        .transaction_id = parsed.transaction_id,
                        .msg_type = .response,
                        .body = .{ .response = .{ .dict = res_kvs.items } },
                    };

                    var write_buf: std.Io.Writer.Allocating = .init(self.allocator);
                    defer write_buf.deinit();
                    resp.encode(self.allocator, &write_buf.writer) catch continue;
                    const resp_payload = write_buf.toOwnedSlice() catch continue;
                    defer self.allocator.free(resp_payload);

                    _ = self.socket.send(self.io, &msg.from, resp_payload) catch {};
                } else if (std.mem.eql(u8, q.method, "get")) {
                    const target_bytes = q.args.getAsString("target") orelse continue;
                    if (target_bytes.len != 20) continue;
                    var target: [20]u8 = undefined;
                    @memcpy(&target, target_bytes);

                    var res_kvs: std.ArrayList(bencode.Value.KV) = .empty;
                    defer res_kvs.deinit(self.allocator);
                    res_kvs.append(self.allocator, .{ .key = "id", .value = .{ .string = &[_]u8{3} ** 20 } }) catch continue;
                    res_kvs.append(self.allocator, .{ .key = "token", .value = .{ .string = "mock_token" } }) catch continue;

                    if (self.store.get(target)) |item| {
                        res_kvs.append(self.allocator, .{ .key = "v", .value = .{ .string = item.v } }) catch continue;
                        res_kvs.append(self.allocator, .{ .key = "sig", .value = .{ .string = &item.sig } }) catch continue;
                        res_kvs.append(self.allocator, .{ .key = "seq", .value = .{ .integer = @intCast(item.seq) } }) catch continue;
                        res_kvs.append(self.allocator, .{ .key = "k", .value = .{ .string = &item.k } }) catch continue;
                    }

                    const resp = krpc.Message{
                        .transaction_id = parsed.transaction_id,
                        .msg_type = .response,
                        .body = .{ .response = .{ .dict = res_kvs.items } },
                    };

                    var write_buf: std.Io.Writer.Allocating = .init(self.allocator);
                    defer write_buf.deinit();
                    resp.encode(self.allocator, &write_buf.writer) catch continue;
                    const resp_payload = write_buf.toOwnedSlice() catch continue;
                    defer self.allocator.free(resp_payload);

                    _ = self.socket.send(self.io, &msg.from, resp_payload) catch {};
                } else if (std.mem.eql(u8, q.method, "put")) {
                    const k_bytes = q.args.getAsString("k") orelse continue;
                    if (k_bytes.len != 32) continue;
                    var k_arr: [32]u8 = undefined;
                    @memcpy(&k_arr, k_bytes);

                    var target: [20]u8 = undefined;
                    std.crypto.hash.Sha1.hash(&k_arr, &target, .{});

                    const v = q.args.getAsString("v") orelse continue;
                    const sig = q.args.getAsString("sig") orelse continue;
                    const seq = q.args.getAsInteger("seq") orelse continue;

                    if (sig.len != 64) continue;
                    var sig_arr: [64]u8 = undefined;
                    @memcpy(&sig_arr, sig);

                    const old = self.store.get(target);
                    self.store.put(target, .{
                        .v = self.allocator.dupe(u8, v) catch continue,
                        .sig = sig_arr,
                        .seq = @intCast(seq),
                        .k = k_arr,
                    }) catch continue;

                    if (old) |old_item| {
                        self.allocator.free(old_item.v);
                    }

                    var res_kvs: std.ArrayList(bencode.Value.KV) = .empty;
                    defer res_kvs.deinit(self.allocator);
                    res_kvs.append(self.allocator, .{ .key = "id", .value = .{ .string = &[_]u8{3} ** 20 } }) catch continue;

                    const resp = krpc.Message{
                        .transaction_id = parsed.transaction_id,
                        .msg_type = .response,
                        .body = .{ .response = .{ .dict = res_kvs.items } },
                    };

                    var write_buf: std.Io.Writer.Allocating = .init(self.allocator);
                    defer write_buf.deinit();
                    resp.encode(self.allocator, &write_buf.writer) catch continue;
                    const resp_payload = write_buf.toOwnedSlice() catch continue;
                    defer self.allocator.free(resp_payload);

                    _ = self.socket.send(self.io, &msg.from, resp_payload) catch {};
                }
            }
        }
    }
};

test "dht publish and resolve round-trip over loopback mock server" {
    const a = std.testing.allocator;
    const io = std.testing.io;

    // Spin up mock server on loopback port 0
    const local = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const socket = try local.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    var server = MockDhtServer{
        .allocator = a,
        .io = io,
        .socket = socket,
        .store = std.AutoHashMap([20]u8, StoredItem).init(a),
        .running = std.atomic.Value(bool).init(false),
    };
    try server.start();
    defer server.stop();

    // Get the address port of the mock server
    const server_addr = server.socket.address;

    // Initialize DHT client
    var client = try dht_client.Client.init(a, io);
    defer client.deinit();

    // Directly insert the mock server's address into bootstrap nodes to route to it
    try client.bootstrap_addresses.append(a, server_addr);

    const secret = root.SecretKey.fromBytes(.{0x55} ** 32);
    const direct_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 4455);
    var relay = try root.RelayUrl.parse(a, "https://dht.example/relay");
    defer relay.deinit(a);
    const info = try discovery.EndpointInfo.fromParts(
        a,
        secret.public(),
        &.{ .{ .relay = relay }, .{ .ip = direct_addr } },
        null,
    );
    defer info.deinit(a);

    const facade = DhtDiscovery{ .client = &client };

    // Publish
    try facade.publish(secret, info, discovery.DEFAULT_TTL, .{ .micros = 1000 });

    // Resolve
    const resolved = try facade.resolve(secret.public());
    defer resolved.deinit(a);

    try std.testing.expect(resolved.node_id.eql(secret.public()));
    try std.testing.expectEqualStrings("https://dht.example/relay", resolved.firstRelayUrl().?.asString());
    var resolved_ips = resolved.ipAddrs();
    try std.testing.expect(resolved_ips.next() == null);
}

test "dht resolve rejects record signed by different returned key" {
    const a = std.testing.allocator;
    const io = std.testing.io;

    const local = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const socket = try local.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    var server = MockDhtServer{
        .allocator = a,
        .io = io,
        .socket = socket,
        .store = std.AutoHashMap([20]u8, StoredItem).init(a),
        .running = std.atomic.Value(bool).init(false),
    };
    try server.start();
    defer server.stop();

    var client = try dht_client.Client.init(a, io);
    defer client.deinit();
    try client.bootstrap_addresses.append(a, server.socket.address);

    const victim = root.SecretKey.fromBytes(.{0x44} ** 32).public();
    const attacker_secret = root.SecretKey.fromBytes(.{0x22} ** 32);
    const attacker = attacker_secret.public();

    const direct_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 4457);
    var relay = try root.RelayUrl.parse(a, "https://attacker.example/relay");
    defer relay.deinit(a);
    const attacker_info = try discovery.EndpointInfo.fromParts(
        a,
        attacker,
        &.{ .{ .relay = relay }, .{ .ip = direct_addr } },
        null,
    );
    defer attacker_info.deinit(a);

    var packet = try discovery.SignedPacket.fromEndpointInfoAt(
        a,
        attacker_secret,
        attacker_info,
        discovery.DEFAULT_TTL,
        .{ .micros = 4242 },
    );
    defer packet.deinit(a);

    try server.putSigned(victim.bytes, attacker.bytes, packet.encodedPacket(), packet.signature.bytes, packet.timestamp.micros);

    const facade = DhtDiscovery{ .client = &client };
    try std.testing.expectError(error.ValueNotFound, facade.resolve(victim));
}

test "dht live mainline publish and resolve round-trip (env gated)" {
    if (!envEnabled("IROH_PORT_DHT_LIVE")) return error.SkipZigTest;

    const a = std.testing.allocator;
    const io = std.testing.io;

    var client = try dht_client.Client.init(a, io);
    defer client.deinit();
    try client.resolveBootstrapNodes();

    var secret_seed: [32]u8 = undefined;
    io.random(&secret_seed);
    const secret = root.SecretKey.fromBytes(secret_seed);
    const direct_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 4456);
    var relay = try root.RelayUrl.parse(a, "https://dht-live.example/relay");
    defer relay.deinit(a);
    const info = try discovery.EndpointInfo.fromParts(
        a,
        secret.public(),
        &.{ .{ .relay = relay }, .{ .ip = direct_addr } },
        null,
    );
    defer info.deinit(a);

    const facade = DhtDiscovery{ .client = &client };
    try facade.publish(secret, info, discovery.DEFAULT_TTL, .{ .micros = 1 });

    const resolved = try facade.resolve(secret.public());
    defer resolved.deinit(a);

    try std.testing.expect(resolved.node_id.eql(secret.public()));
    try std.testing.expectEqualStrings("https://dht-live.example/relay", resolved.firstRelayUrl().?.asString());
    var resolved_ips = resolved.ipAddrs();
    try std.testing.expect(resolved_ips.next() == null);
}
