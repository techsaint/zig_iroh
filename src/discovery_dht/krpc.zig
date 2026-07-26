const std = @import("std");
const root = @import("../root.zig");
const bencode = @import("bencode.zig");

pub const Id = [20]u8;

pub const NodeInfo = struct {
    id: Id,
    address: std.Io.net.IpAddress,

    pub fn encodeCompact(self: NodeInfo, writer: anytype) !void {
        try writer.writeAll(&self.id);
        switch (self.address) {
            .ip4 => |ip4| {
                try writer.writeAll(&ip4.bytes);
                var port_buf: [2]u8 = undefined;
                std.mem.writeInt(u16, &port_buf, ip4.port, .big);
                try writer.writeAll(&port_buf);
            },
            .ip6 => |ip6| {
                try writer.writeAll(&ip6.bytes);
                var port_buf: [2]u8 = undefined;
                std.mem.writeInt(u16, &port_buf, ip6.port, .big);
                try writer.writeAll(&port_buf);
            },
        }
    }

    pub fn decodeCompact(bytes: []const u8) !NodeInfo {
        if (bytes.len == 26) {
            var id: Id = undefined;
            @memcpy(&id, bytes[0..20]);
            var ip_bytes: [4]u8 = undefined;
            @memcpy(&ip_bytes, bytes[20..24]);
            const port = std.mem.readInt(u16, bytes[24..26], .big);
            return NodeInfo{
                .id = id,
                .address = .{
                    .ip4 = .{
                        .bytes = ip_bytes,
                        .port = port,
                    },
                },
            };
        } else if (bytes.len == 38) {
            var id: Id = undefined;
            @memcpy(&id, bytes[0..20]);
            var ip_bytes: [16]u8 = undefined;
            @memcpy(&ip_bytes, bytes[20..36]);
            const port = std.mem.readInt(u16, bytes[36..38], .big);
            return NodeInfo{
                .id = id,
                .address = .{
                    .ip6 = .{
                        .bytes = ip_bytes,
                        .port = port,
                        .flow = 0,
                        .interface = .none,
                    },
                },
            };
        } else {
            return error.InvalidCompactNodeInfoLength;
        }
    }
};

pub fn parseCompactNodes(bytes: []const u8, allocator: std.mem.Allocator) ![]NodeInfo {
    if (bytes.len % 26 != 0) return error.InvalidCompactNodesLength;
    const count = bytes.len / 26;
    const list = try allocator.alloc(NodeInfo, count);
    errdefer allocator.free(list);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        list[i] = try NodeInfo.decodeCompact(bytes[i * 26 .. (i + 1) * 26]);
    }
    return list;
}

pub fn parseCompactNodes6(bytes: []const u8, allocator: std.mem.Allocator) ![]NodeInfo {
    if (bytes.len % 38 != 0) return error.InvalidCompactNodes6Length;
    const count = bytes.len / 38;
    const list = try allocator.alloc(NodeInfo, count);
    errdefer allocator.free(list);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        list[i] = try NodeInfo.decodeCompact(bytes[i * 38 .. (i + 1) * 38]);
    }
    return list;
}

pub fn xorDistance(a: Id, b: Id) Id {
    var dist: Id = undefined;
    for (0..20) |i| {
        dist[i] = a[i] ^ b[i];
    }
    return dist;
}

pub fn compareDistance(target: Id, lhs: Id, rhs: Id) std.math.Order {
    const dist_lhs = xorDistance(target, lhs);
    const dist_rhs = xorDistance(target, rhs);
    return std.mem.order(u8, &dist_lhs, &dist_rhs);
}

pub const Message = struct {
    transaction_id: []const u8,
    msg_type: enum { query, response, error_msg },
    body: union(enum) {
        query: struct {
            method: []const u8,
            args: bencode.Value,
        },
        response: bencode.Value,
        error_msg: struct {
            code: i64,
            message: []const u8,
        },
    },

    pub fn deinit(self: Message, allocator: std.mem.Allocator) void {
        switch (self.body) {
            .query => |q| q.args.deinit(allocator),
            .response => |r| r.deinit(allocator),
            else => {},
        }
    }

    pub fn encode(self: Message, allocator: std.mem.Allocator, writer: anytype) !void {
        var kvs: std.ArrayList(bencode.Value.KV) = .empty;
        defer kvs.deinit(allocator);

        try kvs.append(allocator, .{ .key = "t", .value = .{ .string = self.transaction_id } });
        switch (self.msg_type) {
            .query => {
                try kvs.append(allocator, .{ .key = "y", .value = .{ .string = "q" } });
                try kvs.append(allocator, .{ .key = "q", .value = .{ .string = self.body.query.method } });
                try kvs.append(allocator, .{ .key = "a", .value = self.body.query.args });
            },
            .response => {
                try kvs.append(allocator, .{ .key = "y", .value = .{ .string = "r" } });
                try kvs.append(allocator, .{ .key = "r", .value = self.body.response });
            },
            .error_msg => {
                try kvs.append(allocator, .{ .key = "y", .value = .{ .string = "e" } });
                var err_list: std.ArrayList(bencode.Value) = .empty;
                defer err_list.deinit(allocator);
                try err_list.append(allocator, .{ .integer = self.body.error_msg.code });
                try err_list.append(allocator, .{ .string = self.body.error_msg.message });
                try kvs.append(allocator, .{ .key = "e", .value = .{ .list = try err_list.toOwnedSlice(allocator) } });
            },
        }

        const dict_val = bencode.Value{ .dict = kvs.items };
        try bencode.encode(dict_val, allocator, writer);
    }

    pub fn parse(val: bencode.Value) !Message {
        const t = val.getAsString("t") orelse return error.MissingTransactionId;
        const y = val.getAsString("y") orelse return error.MissingMessageType;

        if (std.mem.eql(u8, y, "q")) {
            const q = val.getAsString("q") orelse return error.MissingQueryMethod;
            const a = val.get("a") orelse return error.MissingQueryArgs;
            return Message{
                .transaction_id = t,
                .msg_type = .query,
                .body = .{
                    .query = .{
                        .method = q,
                        .args = a,
                    },
                },
            };
        } else if (std.mem.eql(u8, y, "r")) {
            const r = val.get("r") orelse return error.MissingResponseData;
            return Message{
                .transaction_id = t,
                .msg_type = .response,
                .body = .{ .response = r },
            };
        } else if (std.mem.eql(u8, y, "e")) {
            const e = val.getAsList("e") orelse return error.MissingErrorData;
            if (e.len < 2) return error.InvalidErrorFormat;
            const code = switch (e[0]) {
                .integer => |i| i,
                else => return error.InvalidErrorCode,
            };
            const message = switch (e[1]) {
                .string => |s| s,
                else => return error.InvalidErrorMessage,
            };
            return Message{
                .transaction_id = t,
                .msg_type = .error_msg,
                .body = .{
                    .error_msg = .{
                        .code = code,
                        .message = message,
                    },
                },
            };
        } else {
            return error.UnknownMessageType;
        }
    }
};

test "krpc: node info compact format" {
    const a = std.testing.allocator;
    const ip4 = try std.Io.net.IpAddress.parse("192.168.1.1", 6881);
    const id = [_]u8{1} ** 20;
    const info = NodeInfo{ .id = id, .address = ip4 };

    var buf: std.Io.Writer.Allocating = .init(a);
    defer buf.deinit();
    try info.encodeCompact(&buf.writer);

    const bytes = try buf.toOwnedSlice();
    defer a.free(bytes);

    try std.testing.expectEqual(bytes.len, 26);
    try std.testing.expectEqualStrings(bytes[0..20], &id);
    try std.testing.expectEqual(bytes[20], 192);
    try std.testing.expectEqual(bytes[21], 168);
    try std.testing.expectEqual(bytes[22], 1);
    try std.testing.expectEqual(bytes[23], 1);
    try std.testing.expectEqual(std.mem.readInt(u16, bytes[24..26], .big), 6881);

    const decoded = try NodeInfo.decodeCompact(bytes);
    try std.testing.expectEqualStrings(&decoded.id, &id);
    try std.testing.expect(decoded.address.eql(&ip4));
}

test "krpc: message encode/decode" {
    const a = std.testing.allocator;

    var args_kvs: std.ArrayList(bencode.Value.KV) = .empty;
    defer args_kvs.deinit(a);
    try args_kvs.append(a, .{ .key = "id", .value = .{ .string = "abcdefghij0123456789" } });

    var query_msg = Message{
        .transaction_id = "aa",
        .msg_type = .query,
        .body = .{
            .query = .{
                .method = "ping",
                .args = .{ .dict = args_kvs.items },
            },
        },
    };

    var buf: std.Io.Writer.Allocating = .init(a);
    defer buf.deinit();
    try query_msg.encode(a, &buf.writer);

    const bytes = try buf.toOwnedSlice();
    defer a.free(bytes);

    const parsed_val = try bencode.parse(bytes, a);
    defer parsed_val.deinit(a);

    const parsed_msg = try Message.parse(parsed_val);
    try std.testing.expectEqualStrings(parsed_msg.transaction_id, "aa");
    try std.testing.expectEqual(parsed_msg.msg_type, .query);
    try std.testing.expectEqualStrings(parsed_msg.body.query.method, "ping");
    try std.testing.expectEqualStrings(parsed_msg.body.query.args.getAsString("id").?, "abcdefghij0123456789");
}
