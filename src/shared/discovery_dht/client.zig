const std = @import("std");
const root = @import("../root.zig");
const bencode = @import("bencode.zig");
const krpc = @import("krpc.zig");
const discovery = @import("../discovery/discovery.zig");

pub const BootstrapNode = struct {
    host: []const u8,
    port: u16,
};

pub const BOOTSTRAP_NODES = &[_]BootstrapNode{
    .{ .host = "router.bittorrent.com", .port = 6881 },
    .{ .host = "dht.transmissionbt.com", .port = 6881 },
    .{ .host = "dht.libtorrent.org", .port = 25401 },
    .{ .host = "relay.pkarr.org", .port = 6881 },
};

fn liveDebugEnabled() bool {
    const raw = std.c.getenv("IROH_PORT_DHT_LIVE") orelse return false;
    const value = std.mem.span(raw);
    return std.mem.eql(u8, value, "1") or
        std.ascii.eqlIgnoreCase(value, "true") or
        std.ascii.eqlIgnoreCase(value, "yes");
}

fn debugPrintHex(bytes: []const u8) void {
    const table = "0123456789abcdef";
    const n: usize = @min(bytes.len, 32);
    var out: [64]u8 = undefined;
    for (bytes[0..n], 0..) |byte, i| {
        out[i * 2] = table[@as(usize, byte >> 4)];
        out[i * 2 + 1] = table[@as(usize, byte & 0x0f)];
    }
    const out_len: usize = n * 2;
    std.debug.print("{s}", .{out[0..out_len]});
    if (bytes.len > n) std.debug.print("...", .{});
}

fn debugPrintAddress(address: std.Io.net.IpAddress) void {
    switch (address) {
        .ip4 => |ip4| {
            std.debug.print("{d}.{d}.{d}.{d}:{d}", .{
                ip4.bytes[0],
                ip4.bytes[1],
                ip4.bytes[2],
                ip4.bytes[3],
                ip4.port,
            });
        },
        .ip6 => |ip6| {
            const b = ip6.bytes;
            std.debug.print("[{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}]:{d}", .{
                std.mem.readInt(u16, b[0..2], .big),
                std.mem.readInt(u16, b[2..4], .big),
                std.mem.readInt(u16, b[4..6], .big),
                std.mem.readInt(u16, b[6..8], .big),
                std.mem.readInt(u16, b[8..10], .big),
                std.mem.readInt(u16, b[10..12], .big),
                std.mem.readInt(u16, b[12..14], .big),
                std.mem.readInt(u16, b[14..16], .big),
                ip6.port,
            });
        },
    }
}

fn debugPrintInboundPrefix(from: std.Io.net.IpAddress, data: []const u8) void {
    std.debug.print("dht-live inbound src=", .{});
    debugPrintAddress(from);
    std.debug.print(" len={d} first32=", .{data.len});
    debugPrintHex(data);
    std.debug.print(" parse=", .{});
}

fn debugPrintOutbound(address: std.Io.net.IpAddress, method: []const u8, tx_id: []const u8, len: usize) void {
    std.debug.print("dht-live outbound dst=", .{});
    debugPrintAddress(address);
    std.debug.print(" method={s} txid=", .{method});
    debugPrintHex(tx_id);
    std.debug.print(" len={d}\n", .{len});
}

fn addressFamily(address: std.Io.net.IpAddress) []const u8 {
    return switch (address) {
        .ip4 => "v4",
        .ip6 => "v6",
    };
}

fn responseSeq(seq: i64) ?u64 {
    if (seq < 0) return null;
    return @intCast(seq);
}

pub const GetResult = struct {
    value: []u8, // DNS packet payload
    signature: [64]u8, // 64-byte Ed25519 signature
    seq: u64, // timestamp in microseconds
    k: [32]u8, // public key
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    node_id: krpc.Id,
    socket: std.Io.net.Socket,
    io: std.Io,
    known_nodes: std.ArrayList(krpc.NodeInfo),
    bootstrap_addresses: std.ArrayList(std.Io.net.IpAddress),

    pub fn init(allocator: std.mem.Allocator, io: std.Io) !Client {
        // Generate random node ID
        var node_id: krpc.Id = undefined;
        io.random(&node_id);

        // Bind local UDP socket on ephemeral port
        const local = std.Io.net.IpAddress{ .ip4 = .unspecified(0) };
        const socket = try local.bind(io, .{
            .mode = .dgram,
            .protocol = .udp,
        });

        if (liveDebugEnabled()) {
            std.debug.print("dht-live socket local=", .{});
            debugPrintAddress(socket.address);
            std.debug.print(" family={s}\n", .{addressFamily(socket.address)});
        }

        var known_nodes: std.ArrayList(krpc.NodeInfo) = .empty;
        errdefer known_nodes.deinit(allocator);

        var bootstrap_addresses: std.ArrayList(std.Io.net.IpAddress) = .empty;
        errdefer bootstrap_addresses.deinit(allocator);
        return Client{
            .allocator = allocator,
            .node_id = node_id,
            .socket = socket,
            .io = io,
            .known_nodes = known_nodes,
            .bootstrap_addresses = bootstrap_addresses,
        };
    }

    pub fn deinit(self: *Client) void {
        self.socket.close(self.io);
        self.bootstrap_addresses.deinit(self.allocator);
        self.known_nodes.deinit(self.allocator);
    }

    pub fn resolveBootstrapNodes(self: *Client) !void {
        for (BOOTSTRAP_NODES) |bootstrap| {
            var results_buf: [16]std.Io.net.HostName.LookupResult = undefined;
            var results: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results_buf);
            const host_name = std.Io.net.HostName.init(bootstrap.host) catch |err| {
                std.debug.print("invalid hostname '{s}': {}\n", .{ bootstrap.host, err });
                continue;
            };
            std.Io.net.HostName.lookup(host_name, self.io, &results, .{ .port = bootstrap.port }) catch |err| {
                std.debug.print("failed to lookup '{s}': {}\n", .{ bootstrap.host, err });
                continue;
            };
            while (true) {
                var result: [1]std.Io.net.HostName.LookupResult = undefined;
                const n = results.getUncancelable(self.io, &result, 0) catch |err| switch (err) {
                    error.Closed => break,
                };
                if (n == 0) break;
                switch (result[0]) {
                    .address => |addr| {
                        if (liveDebugEnabled()) {
                            std.debug.print("dht-live bootstrap host={s} addr=", .{bootstrap.host});
                            debugPrintAddress(addr);
                            std.debug.print(" family={s}\n", .{addressFamily(addr)});
                        }
                        try self.bootstrap_addresses.append(self.allocator, addr);
                    },
                    .canonical_name => {},
                }
            }
        }
        if (self.bootstrap_addresses.items.len == 0) {
            return error.NoBootstrapNodesResolved;
        }
    }

    pub fn sendQuery(
        self: *Client,
        address: std.Io.net.IpAddress,
        method: []const u8,
        args: bencode.Value,
        timeout_duration: std.Io.Duration,
        retries: usize,
        recv_buf: []u8,
    ) !bencode.Value {
        var tx_id: [2]u8 = undefined;
        self.io.random(&tx_id);

        const msg = krpc.Message{
            .transaction_id = &tx_id,
            .msg_type = .query,
            .body = .{
                .query = .{
                    .method = method,
                    .args = args,
                },
            },
        };

        var buf: std.Io.Writer.Allocating = .init(self.allocator);
        defer buf.deinit();
        try msg.encode(self.allocator, &buf.writer);
        const payload = try buf.toOwnedSlice();
        defer self.allocator.free(payload);

        const debug_live = liveDebugEnabled();
        var attempt: usize = 0;
        while (attempt <= retries) : (attempt += 1) {
            if (debug_live) debugPrintOutbound(address, method, &tx_id, payload.len);
            self.socket.send(self.io, &address, payload) catch |err| {
                if (debug_live) {
                    std.debug.print("dht-live outbound-send-error dst=", .{});
                    debugPrintAddress(address);
                    std.debug.print(" method={s} txid=", .{method});
                    debugPrintHex(&tx_id);
                    std.debug.print(" error={}\n", .{err});
                } else {
                    std.debug.print("send failed: {}\n", .{err});
                }
                continue;
            };

            const timeout = (std.Io.Timeout{
                .duration = .{
                    .raw = timeout_duration,
                    .clock = .awake,
                },
            }).toDeadline(self.io);

            while (true) {
                const recv_msg = self.socket.receiveTimeout(self.io, recv_buf, timeout) catch |err| {
                    if (err == error.Timeout) {
                        break;
                    }
                    return err;
                };

                // Bind responses to the queried peer (txid alone is spoofable).
                if (!recv_msg.from.eql(&address)) {
                    if (debug_live) {
                        std.debug.print("dht-live ignore-from-mismatch expected=", .{});
                        debugPrintAddress(address);
                        std.debug.print(" got=", .{});
                        debugPrintAddress(recv_msg.from);
                        std.debug.print("\n", .{});
                    }
                    continue;
                }

                if (debug_live) debugPrintInboundPrefix(recv_msg.from, recv_msg.data);
                const parsed_val = bencode.parse(recv_msg.data, self.allocator) catch |err| {
                    if (debug_live) std.debug.print("bencode_error:{}\n", .{err});
                    continue;
                };
                errdefer parsed_val.deinit(self.allocator);

                const parsed_msg = krpc.Message.parse(parsed_val) catch |err| {
                    if (debug_live) std.debug.print("krpc_error:{}\n", .{err});
                    parsed_val.deinit(self.allocator);
                    continue;
                };

                const matched = std.mem.eql(u8, parsed_msg.transaction_id, &tx_id);
                if (debug_live) {
                    std.debug.print("ok msg_type={s} txid=", .{@tagName(parsed_msg.msg_type)});
                    debugPrintHex(parsed_msg.transaction_id);
                    std.debug.print(" expected=", .{});
                    debugPrintHex(&tx_id);
                    std.debug.print(" matched={}\n", .{matched});
                }

                if (matched) {
                    return parsed_val;
                } else {
                    parsed_val.deinit(self.allocator);
                }
            }
        }
        return error.QueryTimeout;
    }

    const Candidate = struct {
        info: krpc.NodeInfo,
        distance: krpc.Id,
        queried: bool = false,
        token: ?[]u8 = null,

        fn deinit(self: *Candidate, allocator: std.mem.Allocator) void {
            if (self.token) |t| allocator.free(t);
        }
    };

    fn zeroId(id: krpc.Id) bool {
        return std.mem.eql(u8, &id, &([_]u8{0} ** 20));
    }

    fn supportsCandidateAddress(address: std.Io.net.IpAddress) bool {
        return switch (address) {
            .ip4 => true,
            .ip6 => false,
        };
    }

    fn addCandidate(candidates: *std.ArrayList(Candidate), info: krpc.NodeInfo, target: krpc.Id, allocator: std.mem.Allocator) !void {
        if (!supportsCandidateAddress(info.address)) return;
        for (candidates.items) |c| {
            if (c.info.address.eql(&info.address)) return;
            if (!zeroId(info.id) and std.mem.eql(u8, &c.info.id, &info.id)) return;
        }
        try candidates.append(allocator, .{
            .info = info,
            .distance = krpc.xorDistance(target, info.id),
        });
    }

    fn rememberNode(self: *Client, info: krpc.NodeInfo) !void {
        if (!supportsCandidateAddress(info.address) or zeroId(info.id)) return;
        for (self.known_nodes.items) |node| {
            if (node.address.eql(&info.address)) return;
            if (std.mem.eql(u8, &node.id, &info.id)) return;
        }
        try self.known_nodes.append(self.allocator, info);
    }

    fn updateCandidateFromResponse(self: *Client, candidates: *std.ArrayList(Candidate), idx: usize, target: krpc.Id, r: bencode.Value) !void {
        if (r.getAsString("id")) |node_id_str| {
            if (node_id_str.len == 20) {
                @memcpy(&candidates.items[idx].info.id, node_id_str);
                candidates.items[idx].distance = krpc.xorDistance(target, candidates.items[idx].info.id);
            }
        }

        if (r.getAsString("nodes")) |nodes_bytes| {
            const new_nodes = krpc.parseCompactNodes(nodes_bytes, self.allocator) catch return;
            defer self.allocator.free(new_nodes);
            for (new_nodes) |node| {
                try addCandidate(candidates, node, target, self.allocator);
            }
        }
    }

    /// Consider one verified BEP-44 response for an ongoing lookup. `best` is
    /// updated iff `seq` is strictly greater than the current best's seq, so the
    /// resolve path returns the highest-seq value seen across all nodes instead
    /// of the first valid one. `v` is borrowed (duped on adopt); the displaced
    /// best's value is freed. A dupe failure never frees the current best.
    fn considerGetResult(
        allocator: std.mem.Allocator,
        best: *?GetResult,
        seq: u64,
        v: []const u8,
        signature: [64]u8,
        k: [32]u8,
    ) !void {
        if (best.*) |current| {
            if (seq <= current.seq) return; // stale or equal: keep current best
        }
        // Allocate the new value before freeing the old one so an allocation
        // failure can't leave `best` pointing at freed memory.
        const duped = try allocator.dupe(u8, v);
        if (best.*) |current| allocator.free(current.value);
        best.* = GetResult{
            .value = duped,
            .signature = signature,
            .seq = seq,
            .k = k,
        };
    }

    pub fn get(self: *Client, target_pubkey: [32]u8) !GetResult {
        // Target is SHA-1 of public key
        var target: krpc.Id = undefined;
        std.crypto.hash.Sha1.hash(&target_pubkey, &target, .{});

        var candidates: std.ArrayList(Candidate) = .empty;
        defer {
            for (candidates.items) |*c| c.deinit(self.allocator);
            candidates.deinit(self.allocator);
        }

        for (self.known_nodes.items) |node| {
            try addCandidate(&candidates, node, target, self.allocator);
        }

        // Add bootstrap nodes to start lookup
        for (self.bootstrap_addresses.items) |addr| {
            // Bootstrap nodes don't have a known ID initially, we can use zero or random
            const boot_info = krpc.NodeInfo{
                .id = [_]u8{0} ** 20,
                .address = addr,
            };
            try addCandidate(&candidates, boot_info, target, self.allocator);
        }

        const timeout_duration = std.Io.Duration.fromMilliseconds(500);
        const retries = 0;
        const max_queries = 24;
        var queries_sent: usize = 0;
        // BEP-44 resolve must compare seq across all responding nodes and keep the
        // greatest; a stale lower-seq replica must not shadow a fresher value.
        var best: ?GetResult = null;
        errdefer if (best) |result| self.allocator.free(result.value);

        while (queries_sent < max_queries) {
            // Sort candidates by distance to target
            const sortFn = struct {
                fn lessThan(_: void, lhs: Candidate, rhs: Candidate) bool {
                    return std.mem.lessThan(u8, &lhs.distance, &rhs.distance);
                }
            }.lessThan;
            std.mem.sort(Candidate, candidates.items, {}, sortFn);

            // Find the closest unqueried candidate
            var target_idx: ?usize = null;
            for (candidates.items, 0..) |c, idx| {
                if (!c.queried) {
                    target_idx = idx;
                    break;
                }
            }

            const idx = target_idx orelse break; // No more unqueried candidates
            candidates.items[idx].queried = true;
            queries_sent += 1;

            var args_kvs: std.ArrayList(bencode.Value.KV) = .empty;
            defer args_kvs.deinit(self.allocator);
            try args_kvs.append(self.allocator, .{ .key = "id", .value = .{ .string = &self.node_id } });
            try args_kvs.append(self.allocator, .{ .key = "target", .value = .{ .string = &target } });

            var recv_buf: [1500]u8 = undefined;
            const lookup_method: []const u8 = if (zeroId(candidates.items[idx].info.id)) "find_node" else "get";

            const response_val = self.sendQuery(
                candidates.items[idx].info.address,
                lookup_method,
                .{ .dict = args_kvs.items },
                timeout_duration,
                retries,
                &recv_buf,
            ) catch {
                continue;
            };
            defer response_val.deinit(self.allocator);

            const response = krpc.Message.parse(response_val) catch continue;

            if (response.msg_type == .response) {
                const r = response.body.response;
                try self.updateCandidateFromResponse(&candidates, idx, target, r);

                if (!std.mem.eql(u8, lookup_method, "get")) {
                    if (!zeroId(candidates.items[idx].info.id)) candidates.items[idx].queried = false;
                    continue;
                }

                // If token is present, capture it (dupe before free — OOM-safe).
                if (r.getAsString("token")) |tok| {
                    const owned = try self.allocator.dupe(u8, tok);
                    if (candidates.items[idx].token) |t| self.allocator.free(t);
                    candidates.items[idx].token = owned;
                }

                // If value is present, we found it!
                if (r.getAsString("v")) |v| {
                    const k = r.getAsString("k") orelse continue;
                    const sig = r.getAsString("sig") orelse continue;
                    const seq = r.getAsInteger("seq") orelse continue;
                    const seq_u64 = responseSeq(seq) orelse continue;

                    if (k.len != 32 or sig.len != 64) continue;
                    if (!std.mem.eql(u8, k, &target_pubkey)) continue;

                    var k_arr: [32]u8 = undefined;
                    @memcpy(&k_arr, k);
                    var sig_arr: [64]u8 = undefined;
                    @memcpy(&sig_arr, sig);

                    // Reconstruct SignedPacket and verify signature
                    const msg_signable = try discovery.signable(self.allocator, seq_u64, v);
                    defer self.allocator.free(msg_signable);

                    const pk = root.PublicKey.fromBytes(k_arr) catch continue;
                    const signature = root.Signature.fromBytes(sig_arr);
                    pk.verifyCofactored(msg_signable, signature) catch continue;

                    // BEP-44: adopt iff this response has a strictly greater seq
                    // than the best seen so far; stale replicas must not win.
                    try considerGetResult(self.allocator, &best, seq_u64, v, sig_arr, k_arr);
                }
            }
        }

        if (best) |result| return result;
        return error.ValueNotFound;
    }

    pub fn put(self: *Client, target_pubkey: [32]u8, seq: u64, v: []const u8, sig: [64]u8) !void {
        var target: krpc.Id = undefined;
        std.crypto.hash.Sha1.hash(&target_pubkey, &target, .{});

        var candidates: std.ArrayList(Candidate) = .empty;
        defer {
            for (candidates.items) |*c| c.deinit(self.allocator);
            candidates.deinit(self.allocator);
        }

        for (self.known_nodes.items) |node| {
            try addCandidate(&candidates, node, target, self.allocator);
        }

        for (self.bootstrap_addresses.items) |addr| {
            const boot_info = krpc.NodeInfo{
                .id = [_]u8{0} ** 20,
                .address = addr,
            };
            try addCandidate(&candidates, boot_info, target, self.allocator);
        }

        const timeout_duration = std.Io.Duration.fromMilliseconds(500);
        const retries = 0;
        const max_queries = 24;
        var queries_sent: usize = 0;
        var responses_seen: usize = 0;
        var tokens_collected: usize = 0;

        // Perform get query iteration to find closest nodes and collect tokens
        while (queries_sent < max_queries) {
            const sortFn = struct {
                fn lessThan(_: void, lhs: Candidate, rhs: Candidate) bool {
                    return std.mem.lessThan(u8, &lhs.distance, &rhs.distance);
                }
            }.lessThan;
            std.mem.sort(Candidate, candidates.items, {}, sortFn);

            var target_idx: ?usize = null;
            for (candidates.items, 0..) |c, idx| {
                if (!c.queried) {
                    target_idx = idx;
                    break;
                }
            }

            const idx = target_idx orelse break;
            candidates.items[idx].queried = true;
            queries_sent += 1;

            var args_kvs: std.ArrayList(bencode.Value.KV) = .empty;
            defer args_kvs.deinit(self.allocator);
            try args_kvs.append(self.allocator, .{ .key = "id", .value = .{ .string = &self.node_id } });
            try args_kvs.append(self.allocator, .{ .key = "target", .value = .{ .string = &target } });

            var recv_buf: [1500]u8 = undefined;
            const lookup_method: []const u8 = if (zeroId(candidates.items[idx].info.id)) "find_node" else "get";

            const response_val = self.sendQuery(
                candidates.items[idx].info.address,
                lookup_method,
                .{ .dict = args_kvs.items },
                timeout_duration,
                retries,
                &recv_buf,
            ) catch {
                continue;
            };
            defer response_val.deinit(self.allocator);

            const response = krpc.Message.parse(response_val) catch continue;

            if (response.msg_type == .response) {
                const r = response.body.response;
                try self.updateCandidateFromResponse(&candidates, idx, target, r);

                if (!std.mem.eql(u8, lookup_method, "get")) {
                    if (!zeroId(candidates.items[idx].info.id)) candidates.items[idx].queried = false;
                    continue;
                }
                responses_seen += 1;

                if (r.getAsString("token")) |tok| {
                    if (candidates.items[idx].token == null) tokens_collected += 1;
                    const owned = try self.allocator.dupe(u8, tok);
                    if (candidates.items[idx].token) |t| self.allocator.free(t);
                    candidates.items[idx].token = owned;
                    if (tokens_collected >= 8) break;
                }
            }
        }

        // Sort candidates again to find the absolute closest nodes we got tokens from
        const sortFn = struct {
            fn lessThan(_: void, lhs: Candidate, rhs: Candidate) bool {
                return std.mem.lessThan(u8, &lhs.distance, &rhs.distance);
            }
        }.lessThan;
        std.mem.sort(Candidate, candidates.items, {}, sortFn);

        var tokens_seen: usize = 0;
        var put_succeeded: usize = 0;
        for (candidates.items) |c| {
            const token = c.token orelse continue;
            tokens_seen += 1;

            var args_kvs: std.ArrayList(bencode.Value.KV) = .empty;
            defer args_kvs.deinit(self.allocator);
            try args_kvs.append(self.allocator, .{ .key = "id", .value = .{ .string = &self.node_id } });
            try args_kvs.append(self.allocator, .{ .key = "k", .value = .{ .string = &target_pubkey } });
            try args_kvs.append(self.allocator, .{ .key = "seq", .value = .{ .integer = @intCast(seq) } });
            try args_kvs.append(self.allocator, .{ .key = "sig", .value = .{ .string = &sig } });
            try args_kvs.append(self.allocator, .{ .key = "token", .value = .{ .string = token } });
            try args_kvs.append(self.allocator, .{ .key = "v", .value = .{ .string = v } });

            var recv_buf: [1500]u8 = undefined;
            const response_val = self.sendQuery(
                c.info.address,
                "put",
                .{ .dict = args_kvs.items },
                timeout_duration,
                retries,
                &recv_buf,
            ) catch {
                continue;
            };
            defer response_val.deinit(self.allocator);

            const response = krpc.Message.parse(response_val) catch continue;

            if (response.msg_type == .response) {
                put_succeeded += 1;
                try self.rememberNode(c.info);
                if (put_succeeded >= 8) break;
            }
        }

        if (responses_seen == 0) {
            return error.NoLookupResponses;
        }
        if (tokens_seen == 0) {
            return error.NoWriteTokens;
        }
        if (put_succeeded == 0) {
            return error.PutFailedAllNodes;
        }
    }
};

test "client bootstrap candidates keep distinct zero-id addresses" {
    const a = std.testing.allocator;
    var candidates: std.ArrayList(Client.Candidate) = .empty;
    defer candidates.deinit(a);

    const target = [_]u8{9} ** 20;
    try Client.addCandidate(&candidates, .{
        .id = [_]u8{0} ** 20,
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 6881),
    }, target, a);
    try Client.addCandidate(&candidates, .{
        .id = [_]u8{0} ** 20,
        .address = try std.Io.net.IpAddress.parse("127.0.0.2", 6881),
    }, target, a);
    try Client.addCandidate(&candidates, .{
        .id = [_]u8{0} ** 20,
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 6881),
    }, target, a);

    try std.testing.expectEqual(@as(usize, 2), candidates.items.len);
}

test "client initialization" {
    const a = std.testing.allocator;
    const io = std.testing.io;

    var client = try Client.init(a, io);
    defer client.deinit();

    // Check we generated a valid node ID
    try std.testing.expect(client.node_id.len == 20);
}

test "client get keeps the highest-seq response across nodes" {
    // BEP-44 resolve must return the greatest-seq valid response, not the first
    // one received. Feeds seqs out of order so a first-response impl would fail;
    // std.testing.allocator catches any leak/double-free in the replace path.
    const a = std.testing.allocator;

    var best: ?GetResult = null;
    defer if (best) |r| a.free(r.value);

    var sig: [64]u8 = undefined;
    var k: [32]u8 = undefined;
    @memset(&sig, 0xAA);
    @memset(&k, 0xBB);

    // Lowest seq arrives first, then a fresher value, then stale + equal replicas.
    try Client.considerGetResult(a, &best, 10, "low", sig, k);
    try Client.considerGetResult(a, &best, 99, "high", sig, k);
    try Client.considerGetResult(a, &best, 50, "mid", sig, k); // stale: must not win
    try Client.considerGetResult(a, &best, 99, "dup", sig, k); // equal: must not win

    const got = best orelse return error.TestExpectedResult;
    try std.testing.expectEqual(@as(u64, 99), got.seq);
    try std.testing.expectEqualStrings("high", got.value);
    try std.testing.expectEqual(@as(u8, 0xAA), got.signature[0]);
    try std.testing.expectEqual(@as(u8, 0xBB), got.k[0]);
}

test "client rejects negative response seq before unsigned cast" {
    try std.testing.expectEqual(@as(?u64, null), responseSeq(-1));
    try std.testing.expectEqual(@as(?u64, 0), responseSeq(0));
}
