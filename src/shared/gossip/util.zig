//! Protocol utilities: IndexSet, TimeBoundCache, TimerMap.
const std = @import("std");

pub fn IndexSet(comptime T: type) type {
    return struct {
        map: std.AutoArrayHashMapUnmanaged(T, void),

        pub fn init() @This() {
            return .{ .map = .empty };
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.map.deinit(allocator);
        }

        pub fn len(self: *const @This()) usize {
            return self.map.count();
        }

        pub fn isEmpty(self: *const @This()) bool {
            return self.map.count() == 0;
        }

        pub fn contains(self: *const @This(), key: T) bool {
            return self.map.contains(key);
        }

        pub fn insert(self: *@This(), allocator: std.mem.Allocator, key: T) !bool {
            const gop = try self.map.getOrPut(allocator, key);
            if (gop.found_existing) return false;
            return true;
        }

        pub fn remove(self: *@This(), key: T) bool {
            return self.map.swapRemove(key);
        }

        pub fn removeIndex(self: *@This(), index: usize) ?T {
            if (index >= self.len()) return null;
            const key = self.keyAt(index);
            _ = self.map.swapRemoveAt(index);
            return key;
        }

        pub fn getIndexOf(self: *const @This(), key: T) ?usize {
            return self.map.getIndex(key);
        }

        pub fn keyAt(self: *const @This(), index: usize) T {
            return self.map.keys()[index];
        }

        pub fn keys(self: *const @This()) []const T {
            return self.map.keys();
        }

        pub fn pickRandomIndex(self: *const @This(), rng: *std.Random) ?usize {
            if (self.isEmpty()) return null;
            return rng.intRangeLessThan(usize, 0, self.len());
        }

        pub fn pickRandom(self: *const @This(), rng: *std.Random) ?T {
            const idx = self.pickRandomIndex(rng) orelse return null;
            return self.keyAt(idx);
        }

        fn keysEqual(a: T, b: T) bool {
            if (@typeInfo(T) == .int) return a == b;
            return a.eql(b);
        }

        pub fn pickRandomWithout(self: *const @This(), allocator: std.mem.Allocator, without: []const T, rng: *std.Random) ?T {
            _ = allocator;
            if (self.isEmpty()) return null;
            var selected: ?T = null;
            var eligible: usize = 0;
            for (self.keys()) |k| {
                var skip = false;
                for (without) |w| {
                    if (keysEqual(k, w)) {
                        skip = true;
                        break;
                    }
                }
                if (!skip) {
                    eligible += 1;
                    if (rng.intRangeLessThan(usize, 0, eligible) == 0) selected = k;
                }
            }
            return selected;
        }

        pub fn removeRandom(self: *@This(), rng: *std.Random) ?T {
            const idx = self.pickRandomIndex(rng) orelse return null;
            return self.removeIndex(idx);
        }

        pub fn shuffled(self: *const @This(), allocator: std.mem.Allocator, rng: *std.Random) ![]T {
            const items = try allocator.dupe(T, self.keys());
            rng.shuffle(T, items);
            return items;
        }

        pub fn shuffledAndCapped(self: *const @This(), allocator: std.mem.Allocator, rng: *std.Random, cap: usize) ![]T {
            const all = try self.shuffled(allocator, rng);
            defer allocator.free(all);
            const n = @min(all.len, cap);
            return try allocator.dupe(T, all[0..n]);
        }

        pub fn shuffledWithout(
            self: *const @This(),
            allocator: std.mem.Allocator,
            rng: *std.Random,
            without: []const T,
        ) ![]T {
            var tmp: std.ArrayList(T) = .empty;
            defer tmp.deinit(allocator);
            for (self.keys()) |k| {
                var skip = false;
                for (without) |w| {
                    if (keysEqual(k, w)) {
                        skip = true;
                        break;
                    }
                }
                if (!skip) tmp.append(allocator, k) catch return error.OutOfMemory;
            }
            const items = try allocator.dupe(T, tmp.items);
            rng.shuffle(T, items);
            return items;
        }

        pub fn shuffledWithoutAndCapped(
            self: *const @This(),
            allocator: std.mem.Allocator,
            rng: *std.Random,
            without: []const T,
            cap: usize,
        ) ![]T {
            const all = try self.shuffledWithout(allocator, rng, without);
            defer allocator.free(all);
            const n = @min(all.len, cap);
            return try allocator.dupe(T, all[0..n]);
        }

        pub const IterWithout = struct {
            set: *const IndexSet(T),
            skip: T,
            i: usize,

            pub fn next(self: *IterWithout) ?T {
                while (self.i < self.set.len()) {
                    const k = self.set.keyAt(self.i);
                    self.i += 1;
                    if (!peersEqlStatic(T, k, self.skip)) return k;
                }
                return null;
            }
        };

        fn peersEqlStatic(comptime Peer: type, a: Peer, b: Peer) bool {
            if (@typeInfo(Peer) == .int) return a == b;
            return a.eql(b);
        }

        pub fn iterWithout(self: *const @This(), skip: T) IterWithout {
            return .{ .set = self, .skip = skip, .i = 0 };
        }
    };
}

pub fn TimerMap(comptime T: type) type {
    const TimerEntry = struct {
        time: u64,
        seq: u64,
        item: T,

        fn lessThan(_: void, a: @This(), b: @This()) std.math.Order {
            if (a.time != b.time) return if (a.time < b.time) .lt else .gt;
            return if (a.seq < b.seq) .lt else if (a.seq > b.seq) .gt else .eq;
        }
    };

    return struct {
        heap: std.PriorityQueue(TimerEntry, void, TimerEntry.lessThan),
        seq: u64 = 0,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) @This() {
            return .{
                .heap = std.PriorityQueue(TimerEntry, void, TimerEntry.lessThan).initContext({}),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *@This()) void {
            self.heap.deinit(self.allocator);
        }

        pub fn insert(self: *@This(), time: u64, item: T) !void {
            const entry: TimerEntry = .{ .time = time, .seq = self.seq, .item = item };
            self.seq += 1;
            try self.heap.push(self.allocator, entry);
        }

        pub fn ensureUnusedCapacity(self: *@This(), additional_count: usize) !void {
            try self.heap.ensureUnusedCapacity(self.allocator, additional_count);
        }

        pub fn peekTime(self: *@This()) ?u64 {
            if (self.heap.len() == 0) return null;
            return self.heap.peek().?.time;
        }

        pub fn popBefore(self: *@This(), limit: u64) ?struct { time: u64, item: T } {
            if (self.heap.peek()) |e| {
                if (e.time <= limit) {
                    const popped = self.heap.pop() orelse return null;
                    return .{ .time = popped.time, .item = popped.item };
                }
            }
            return null;
        }

        pub fn drainUntil(self: *@This(), allocator: std.mem.Allocator, limit: u64, out: *std.ArrayList(struct { time: u64, item: T })) !void {
            while (self.popBefore(limit)) |entry| {
                try out.append(allocator, entry);
            }
        }
    };
}

pub fn TimeBoundCache(comptime K: type, comptime V: type) type {
    const value_has_deinit = comptime switch (@typeInfo(V)) {
        .void => false,
        else => @hasDecl(V, "deinit"),
    };
    return struct {
        map: std.AutoHashMapUnmanaged(K, struct { expires: u64, value: V }),
        expiry: TimerMap(K),

        pub fn init() @This() {
            return .{ .map = .empty, .expiry = undefined };
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.map.deinit(allocator);
            self.expiry.deinit();
        }

        pub fn initWithAllocator(allocator: std.mem.Allocator) @This() {
            return .{ .map = .empty, .expiry = TimerMap(K).init(allocator) };
        }

        pub fn len(self: *const @This()) usize {
            return self.map.count();
        }

        pub fn containsKey(self: *const @This(), key: K) bool {
            return self.map.contains(key);
        }

        pub fn get(self: *const @This(), key: K) ?*const V {
            const entry = self.map.getPtr(key) orelse return null;
            return &entry.value;
        }

        pub fn insert(self: *@This(), allocator: std.mem.Allocator, key: K, value: V, expires: u64) !void {
            // Reserve both indexes before taking ownership so an allocation
            // failure cannot leave an entry with no expiry record.
            try self.map.ensureUnusedCapacity(allocator, 1);
            try self.expiry.ensureUnusedCapacity(1);
            if (self.map.fetchPutAssumeCapacity(key, .{ .expires = expires, .value = value })) |old| {
                if (value_has_deinit) old.value.value.deinit(allocator);
            }
            self.expiry.insert(expires, key) catch unreachable;
        }

        pub fn expireUntil(self: *@This(), allocator: std.mem.Allocator, instant: u64) usize {
            var removed: usize = 0;
            while (self.expiry.popBefore(instant)) |entry| {
                const key = entry.item;
                if (self.map.get(key)) |stored| {
                    if (stored.expires == entry.time) {
                        if (value_has_deinit) {
                            stored.value.deinit(allocator);
                        }
                        _ = self.map.remove(key);
                        removed += 1;
                    }
                }
            }
            return removed;
        }

        pub fn deinitValues(self: *@This(), allocator: std.mem.Allocator) void {
            if (value_has_deinit) {
                var it = self.map.valueIterator();
                while (it.next()) |entry| {
                    entry.value.deinit(allocator);
                }
            }
            self.map.deinit(allocator);
            self.expiry.deinit();
        }
    };
}

test "TimeBoundCache replacement releases the previous owned value" {
    const Owned = struct {
        bytes: []u8,

        fn deinit(self: @This(), allocator: std.mem.Allocator) void {
            allocator.free(self.bytes);
        }
    };

    const alloc = std.testing.allocator;
    var cache = TimeBoundCache(u32, Owned).initWithAllocator(alloc);
    defer cache.deinitValues(alloc);

    try cache.insert(alloc, 1, .{ .bytes = try alloc.dupe(u8, "first") }, 10);
    try cache.insert(alloc, 1, .{ .bytes = try alloc.dupe(u8, "second") }, 20);
    try std.testing.expectEqualStrings("second", cache.get(1).?.bytes);
    try std.testing.expectEqual(@as(usize, 1), cache.len());
}
