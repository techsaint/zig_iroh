const std = @import("std");

pub const MAX_PARSE_DEPTH: usize = 128;

pub const Value = union(enum) {
    integer: i64,
    string: []const u8,
    list: []const Value,
    dict: []const KV,

    pub const KV = struct {
        key: []const u8,
        value: Value,
    };

    pub fn deinit(self: Value, allocator: std.mem.Allocator) void {
        switch (self) {
            .list => |l| {
                for (l) |item| {
                    item.deinit(allocator);
                }
                allocator.free(l);
            },
            .dict => |d| {
                for (d) |kv| {
                    kv.value.deinit(allocator);
                }
                allocator.free(d);
            },
            else => {},
        }
    }

    pub fn clone(self: Value, allocator: std.mem.Allocator) anyerror!Value {
        switch (self) {
            .integer => |i| return Value{ .integer = i },
            .string => |s| return Value{ .string = try allocator.dupe(u8, s) },
            .list => |l| {
                const new_l = try allocator.alloc(Value, l.len);
                errdefer allocator.free(new_l);
                for (l, 0..) |item, i| {
                    new_l[i] = try item.clone(allocator);
                }
                return Value{ .list = new_l };
            },
            .dict => |d| {
                const new_d = try allocator.alloc(KV, d.len);
                errdefer allocator.free(new_d);
                for (d, 0..) |kv, i| {
                    new_d[i] = .{
                        .key = try allocator.dupe(u8, kv.key),
                        .value = try kv.value.clone(allocator),
                    };
                }
                return Value{ .dict = new_d };
            },
        }
    }

    pub fn get(self: Value, key: []const u8) ?Value {
        switch (self) {
            .dict => |d| {
                for (d) |kv| {
                    if (std.mem.eql(u8, kv.key, key)) return kv.value;
                }
            },
            else => {},
        }
        return null;
    }

    pub fn getAsString(self: Value, key: []const u8) ?[]const u8 {
        const val = self.get(key) orelse return null;
        return switch (val) {
            .string => |s| s,
            else => null,
        };
    }

    pub fn getAsInteger(self: Value, key: []const u8) ?i64 {
        const val = self.get(key) orelse return null;
        return switch (val) {
            .integer => |i| i,
            else => null,
        };
    }

    pub fn getAsList(self: Value, key: []const u8) ?[]const Value {
        const val = self.get(key) orelse return null;
        return switch (val) {
            .list => |l| l,
            else => null,
        };
    }

    pub fn getAsDict(self: Value, key: []const u8) ?[]const KV {
        const val = self.get(key) orelse return null;
        return switch (val) {
            .dict => |d| d,
            else => null,
        };
    }
};

pub const Parser = struct {
    input: []const u8,
    pos: usize,

    pub fn init(input: []const u8) Parser {
        return .{ .input = input, .pos = 0 };
    }

    fn peek(self: Parser) ?u8 {
        if (self.pos >= self.input.len) return null;
        return self.input[self.pos];
    }

    fn advance(self: *Parser) void {
        self.pos += 1;
    }

    pub fn parse(self: *Parser, allocator: std.mem.Allocator) !Value {
        return self.parseDepth(allocator, 0);
    }

    fn parseDepth(self: *Parser, allocator: std.mem.Allocator, depth: usize) !Value {
        if (depth > MAX_PARSE_DEPTH) return error.BencodeDepthExceeded;
        const next = self.peek() orelse return error.UnexpectedEof;
        switch (next) {
            'i' => {
                self.advance();
                const start = self.pos;
                while (self.peek()) |c| {
                    if (c == 'e') break;
                    self.advance();
                } else return error.UnexpectedEof;
                const end = self.pos;
                self.advance(); // consume 'e'
                const val = try std.fmt.parseInt(i64, self.input[start..end], 10);
                return Value{ .integer = val };
            },
            'l' => {
                self.advance();
                var list: std.ArrayList(Value) = .empty;
                errdefer {
                    for (list.items) |item| item.deinit(allocator);
                    list.deinit(allocator);
                }
                while (self.peek()) |c| {
                    if (c == 'e') break;
                    const item = try self.parseDepth(allocator, depth + 1);
                    list.append(allocator, item) catch |err| {
                        item.deinit(allocator);
                        return err;
                    };
                } else return error.UnexpectedEof;
                self.advance(); // consume 'e'
                return Value{ .list = try list.toOwnedSlice(allocator) };
            },
            'd' => {
                self.advance();
                var dict: std.ArrayList(Value.KV) = .empty;
                errdefer {
                    for (dict.items) |kv| kv.value.deinit(allocator);
                    dict.deinit(allocator);
                }
                while (self.peek()) |c| {
                    if (c == 'e') break;
                    const key_val = try self.parseDepth(allocator, depth + 1);
                    const key = switch (key_val) {
                        .string => |s| s,
                        else => {
                            key_val.deinit(allocator);
                            return error.InvalidDictKey;
                        },
                    };
                    const value = try self.parseDepth(allocator, depth + 1);
                    dict.append(allocator, .{ .key = key, .value = value }) catch |err| {
                        value.deinit(allocator);
                        return err;
                    };
                } else return error.UnexpectedEof;
                self.advance(); // consume 'e'

                const sortFn = struct {
                    fn lessThan(_: void, lhs: Value.KV, rhs: Value.KV) bool {
                        return std.mem.lessThan(u8, lhs.key, rhs.key);
                    }
                }.lessThan;
                std.mem.sort(Value.KV, dict.items, {}, sortFn);

                return Value{ .dict = try dict.toOwnedSlice(allocator) };
            },
            '0'...'9' => {
                const start = self.pos;
                while (self.peek()) |c| {
                    if (c == ':') break;
                    self.advance();
                } else return error.UnexpectedEof;
                const end = self.pos;
                self.advance(); // consume ':'
                const len = try std.fmt.parseInt(usize, self.input[start..end], 10);
                // Checked remaining length — `pos + len` can wrap on attacker-controlled len.
                if (len > self.input.len - self.pos) return error.UnexpectedEof;
                const str = self.input[self.pos .. self.pos + len];
                self.pos += len;
                return Value{ .string = str };
            },
            else => return error.InvalidCharacter,
        }
    }
};

pub fn parse(input: []const u8, allocator: std.mem.Allocator) !Value {
    var parser = Parser.init(input);
    const val = try parser.parse(allocator);
    if (parser.pos < input.len) {
        val.deinit(allocator);
        return error.ExtraData;
    }
    return val;
}

pub fn encode(value: Value, allocator: std.mem.Allocator, writer: anytype) !void {
    switch (value) {
        .integer => |val| {
            try writer.writeAll("i");
            try writer.print("{d}", .{val});
            try writer.writeAll("e");
        },
        .string => |str| {
            try writer.print("{d}:", .{str.len});
            try writer.writeAll(str);
        },
        .list => |list| {
            try writer.writeAll("l");
            for (list) |item| {
                try encode(item, allocator, writer);
            }
            try writer.writeAll("e");
        },
        .dict => |dict| {
            try writer.writeAll("d");
            const sorted = try allocator.alloc(Value.KV, dict.len);
            defer allocator.free(sorted);
            @memcpy(sorted, dict);
            const sortFn = struct {
                fn lessThan(_: void, lhs: Value.KV, rhs: Value.KV) bool {
                    return std.mem.lessThan(u8, lhs.key, rhs.key);
                }
            }.lessThan;
            std.mem.sort(Value.KV, sorted, {}, sortFn);

            for (sorted) |kv| {
                // key
                try writer.print("{d}:", .{kv.key.len});
                try writer.writeAll(kv.key);
                // value
                try encode(kv.value, allocator, writer);
            }
            try writer.writeAll("e");
        },
    }
}

pub fn encodeAlloc(value: Value, allocator: std.mem.Allocator) ![]u8 {
    var buf: std.Io.Writer.Allocating = .init(allocator);
    errdefer buf.deinit();
    try encode(value, allocator, &buf.writer);
    return buf.toOwnedSlice();
}

test "bencode: integer" {
    const io = std.testing.io;
    _ = io;
    const a = std.testing.allocator;

    const v1 = try parse("i42e", a);
    defer v1.deinit(a);
    try std.testing.expectEqual(v1.integer, 42);

    const v2 = try parse("i-100e", a);
    defer v2.deinit(a);
    try std.testing.expectEqual(v2.integer, -100);

    const enc1 = try encodeAlloc(v1, a);
    defer a.free(enc1);
    try std.testing.expectEqualStrings(enc1, "i42e");
}

test "bencode: string" {
    const a = std.testing.allocator;

    const v1 = try parse("4:spam", a);
    defer v1.deinit(a);
    try std.testing.expectEqualStrings(v1.string, "spam");

    const enc1 = try encodeAlloc(v1, a);
    defer a.free(enc1);
    try std.testing.expectEqualStrings(enc1, "4:spam");
}

test "bencode: list" {
    const a = std.testing.allocator;

    const v1 = try parse("l4:spami42ee", a);
    defer v1.deinit(a);
    try std.testing.expect(v1 == .list);
    try std.testing.expectEqual(v1.list.len, 2);
    try std.testing.expectEqualStrings(v1.list[0].string, "spam");
    try std.testing.expectEqual(v1.list[1].integer, 42);

    const enc1 = try encodeAlloc(v1, a);
    defer a.free(enc1);
    try std.testing.expectEqualStrings(enc1, "l4:spami42ee");
}

test "bencode: dict" {
    const a = std.testing.allocator;

    const v1 = try parse("d3:cow3:moo4:spam4:eggse", a);
    defer v1.deinit(a);
    try std.testing.expect(v1 == .dict);
    try std.testing.expectEqual(v1.dict.len, 2);
    try std.testing.expectEqualStrings(v1.getAsString("cow").?, "moo");
    try std.testing.expectEqualStrings(v1.getAsString("spam").?, "eggs");

    // Test unsorted dict encoding forces sorted output
    const raw_kvs = [_]Value.KV{
        .{ .key = "spam", .value = .{ .string = "eggs" } },
        .{ .key = "cow", .value = .{ .string = "moo" } },
    };
    const v2 = Value{ .dict = &raw_kvs };
    const enc2 = try encodeAlloc(v2, a);
    defer a.free(enc2);
    try std.testing.expectEqualStrings(enc2, "d3:cow3:moo4:spam4:eggse");
}

test "bencode: malformed non-string dict key is rejected without leaking" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidDictKey, parse("dli1ee1:ve", a));
}

test "bencode: string length that would wrap pos+len is rejected" {
    const a = std.testing.allocator;
    // Length parses as usize but exceeds remaining bytes (no pos+len wrap).
    try std.testing.expectError(error.UnexpectedEof, parse("1000:x", a));
    // Oversize digit string rejected by parseInt before the length check.
    try std.testing.expectError(error.Overflow, parse("99999999999999999999:x", a));
}

test "bencode: parser rejects excessive nesting depth" {
    const a = std.testing.allocator;
    var input: [((MAX_PARSE_DEPTH + 2) * 2)]u8 = undefined;
    var i: usize = 0;
    while (i < MAX_PARSE_DEPTH + 2) : (i += 1) input[i] = 'l';
    while (i < input.len) : (i += 1) input[i] = 'e';

    try std.testing.expectError(error.BencodeDepthExceeded, parse(&input, a));
}
