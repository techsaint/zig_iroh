//! BLAKE3 primitives needed for bao-tree compatibility.
//!
//! Extracted from Zig 0.16 `std/crypto/blake3.zig` (private compression core).

const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;
const HashMod = @import("../hash.zig");

const mem = std.mem;

const chunk_length = 1024;

const iv: [8]u32 = .{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

const msg_schedule: [7][16]u8 = .{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 },
    .{ 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 },
    .{ 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6 },
    .{ 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4 },
    .{ 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7 },
    .{ 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13 },
};

const Flags = packed struct(u8) {
    chunk_start: bool = false,
    chunk_end: bool = false,
    parent: bool = false,
    root: bool = false,
    keyed_hash: bool = false,
    derive_key_context: bool = false,
    derive_key_material: bool = false,
    reserved: bool = false,

    fn toInt(self: Flags) u8 {
        return @bitCast(self);
    }

    fn with(self: Flags, other: Flags) Flags {
        return @bitCast(self.toInt() | other.toInt());
    }
};

inline fn rotr32(w: u32, c: u5) u32 {
    return std.math.rotr(u32, w, c);
}

inline fn load32(bytes: []const u8) u32 {
    return mem.readInt(u32, bytes[0..4], .little);
}

inline fn store32(bytes: []u8, w: u32) void {
    mem.writeInt(u32, bytes[0..4], w, .little);
}

fn storeCvWords(cv_words: [8]u32) [Blake3.digest_length]u8 {
    var bytes: [Blake3.digest_length]u8 = undefined;
    for (0..8) |i| store32(bytes[i * 4 ..][0..4], cv_words[i]);
    return bytes;
}

inline fn g(state: *[16]u32, a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) void {
    state[a] +%= state[b] +% x;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] +%= state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] +%= state[b] +% y;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] +%= state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

inline fn roundFn(state: *[16]u32, msg: *const [16]u32, round: usize) void {
    const schedule = &msg_schedule[round];
    g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
    g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
    g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
    g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);
    g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
    g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
    g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
    g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
}

fn compressPre(state: *[16]u32, cv: *const [8]u32, block: []const u8, block_len: u8, counter: u64, flags: Flags) void {
    var block_words: [16]u32 = undefined;
    for (0..16) |i| block_words[i] = load32(block[i * 4 ..][0..4]);
    for (0..8) |i| state[i] = cv[i];
    for (0..4) |i| state[i + 8] = iv[i];
    state[12] = @truncate(counter);
    state[13] = @truncate(counter >> 32);
    state[14] = @as(u32, block_len);
    state[15] = @as(u32, flags.toInt());
    for (0..7) |round| roundFn(state, &block_words, round);
}

fn compressInPlace(cv: *[8]u32, block: []const u8, block_len: u8, counter: u64, flags: Flags) void {
    var state: [16]u32 = undefined;
    compressPre(&state, cv, block, block_len, counter, flags);
    for (0..8) |i| cv[i] = state[i] ^ state[i + 8];
}

const ChunkState = struct {
    cv: [8]u32 align(16),
    chunk_counter: u64,
    buf: [Blake3.block_length]u8 align(16),
    buf_len: u8,
    blocks_compressed: u8,
    flags: Flags,

    fn init(key: [8]u32, flags: Flags) ChunkState {
        return .{
            .cv = key,
            .chunk_counter = 0,
            .buf = @splat(0),
            .buf_len = 0,
            .blocks_compressed = 0,
            .flags = flags,
        };
    }

    fn len(self: *const ChunkState) usize {
        return (Blake3.block_length * @as(usize, self.blocks_compressed)) + @as(usize, self.buf_len);
    }

    fn fillBuf(self: *ChunkState, input: []const u8) usize {
        const take = @min(Blake3.block_length - @as(usize, self.buf_len), input.len);
        @memcpy(self.buf[self.buf_len..][0..take], input[0..take]);
        self.buf_len += @intCast(take);
        return take;
    }

    fn maybeStartFlag(self: *const ChunkState) Flags {
        return if (self.blocks_compressed == 0) .{ .chunk_start = true } else .{};
    }

    fn update(self: *ChunkState, input: []const u8) void {
        var inp = input;
        while (inp.len > 0) {
            if (self.buf_len == Blake3.block_length) {
                compressInPlace(&self.cv, &self.buf, Blake3.block_length, self.chunk_counter, self.flags.with(self.maybeStartFlag()));
                self.blocks_compressed += 1;
                self.buf = @splat(0);
                self.buf_len = 0;
            }
            const take = self.fillBuf(inp);
            inp = inp[take..];
        }
    }

    fn reset(self: *ChunkState, key: [8]u32, chunk_counter: u64) void {
        self.cv = key;
        self.chunk_counter = chunk_counter;
        self.blocks_compressed = 0;
        self.buf = @splat(0);
        self.buf_len = 0;
    }

    fn output(self: *const ChunkState) Output {
        const block_flags = self.flags.with(self.maybeStartFlag()).with(.{ .chunk_end = true });
        return .{
            .input_cv = self.cv,
            .block = self.buf,
            .block_len = self.buf_len,
            .counter = self.chunk_counter,
            .flags = block_flags,
        };
    }
};

const Output = struct {
    input_cv: [8]u32 align(16),
    block: [Blake3.block_length]u8 align(16),
    block_len: u8,
    counter: u64,
    flags: Flags,

    fn chainingValue(self: *const Output) [8]u32 {
        var cv_words = self.input_cv;
        compressInPlace(&cv_words, &self.block, self.block_len, self.counter, self.flags);
        return cv_words;
    }
};

fn parentOutputFromCvs(left_cv: [8]u32, right_cv: [8]u32, key: [8]u32, flags: Flags) Output {
    var block: [Blake3.block_length]u8 align(16) = undefined;
    for (0..8) |i| {
        store32(block[i * 4 ..][0..4], left_cv[i]);
        store32(block[(i + 8) * 4 ..][0..4], right_cv[i]);
    }
    return .{
        .input_cv = key,
        .block = block,
        .block_len = Blake3.block_length,
        .counter = 0,
        .flags = flags.with(.{ .parent = true }),
    };
}

fn loadCvWords(bytes: [Blake3.digest_length]u8) [8]u32 {
    var cv_words: [8]u32 = undefined;
    for (0..8) |i| cv_words[i] = load32(bytes[i * 4 ..][0..4]);
    return cv_words;
}

fn highestOne(x: u64) u6 {
    if (x == 0) return 0;
    return @intCast(63 - @clz(x));
}

fn roundDownToPowerOf2(x: u64) u64 {
    return @as(u64, 1) << highestOne(x | 1);
}

fn leftSubtreeLen(input_len: usize) usize {
    const full_chunks = (input_len - 1) / chunk_length;
    return @intCast(roundDownToPowerOf2(full_chunks) * chunk_length);
}

fn compressChunksSequential(input: []const u8, key: [8]u32, chunk_counter: u64, flags: Flags, out: []u8) usize {
    var i: usize = 0;
    var counter = chunk_counter;
    var n: usize = 0;
    while (i + chunk_length <= input.len) {
        var cs = ChunkState.init(key, flags);
        cs.chunk_counter = counter;
        cs.update(input[i .. i + chunk_length]);
        const cv = storeCvWords(cs.output().chainingValue());
        @memcpy(out[n * 32 .. n * 32 + 32], &cv);
        n += 1;
        counter += 1;
        i += chunk_length;
    }
    if (i < input.len) {
        var cs = ChunkState.init(key, flags);
        cs.chunk_counter = counter;
        cs.update(input[i..]);
        const cv = storeCvWords(cs.output().chainingValue());
        @memcpy(out[n * 32 .. n * 32 + 32], &cv);
        n += 1;
    }
    return n;
}

fn compressParentsSequential(child_cvs: []const u8, num: usize, key: [8]u32, flags: Flags, out: []u8) usize {
    var n_parents: usize = 0;
    var i: usize = 0;
    while (i + 1 < num) {
        var left_bytes: [32]u8 = undefined;
        var right_bytes: [32]u8 = undefined;
        @memcpy(&left_bytes, child_cvs[i * 32 .. i * 32 + 32]);
        @memcpy(&right_bytes, child_cvs[(i + 1) * 32 .. (i + 1) * 32 + 32]);
        const left = loadCvWords(left_bytes);
        const right = loadCvWords(right_bytes);
        const output = parentOutputFromCvs(left, right, key, flags);
        const cv = storeCvWords(output.chainingValue());
        @memcpy(out[n_parents * 32 .. n_parents * 32 + 32], &cv);
        n_parents += 1;
        i += 2;
    }
    if (i < num) {
        @memcpy(out[n_parents * 32 .. n_parents * 32 + 32], child_cvs[i * 32 .. i * 32 + 32]);
        n_parents += 1;
    }
    return n_parents;
}

fn compressSubtreeWideSimple(input: []const u8, key: [8]u32, chunk_counter: u64, flags: Flags, out: []u8) usize {
    if (input.len <= 16 * chunk_length) {
        return compressChunksSequential(input, key, chunk_counter, flags, out);
    }
    const left_len = leftSubtreeLen(input.len);
    const right_counter = chunk_counter + left_len / chunk_length;
    var cv_array: [512]u8 = undefined;
    const left_n = compressSubtreeWideSimple(input[0..left_len], key, chunk_counter, flags, cv_array[0..]);
    const right_n = compressSubtreeWideSimple(input[left_len..], key, right_counter, flags, cv_array[left_n * 32 ..]);
    const total = left_n + right_n;
    return compressParentsSequential(cv_array[0 .. total * 32], total, key, flags, out);
}

fn compressSubtreeToParentNode(input: []const u8, key: [8]u32, chunk_counter: u64, flags: Flags, out: *[2 * Blake3.digest_length]u8) void {
    var cv_array: [512]u8 = undefined;
    var num = compressSubtreeWideSimple(input, key, chunk_counter, flags, &cv_array);
    var out_arr: [512]u8 = undefined;
    while (num > 2) {
        num = compressParentsSequential(cv_array[0 .. num * 32], num, key, flags, &out_arr);
        @memcpy(cv_array[0 .. num * 32], out_arr[0 .. num * 32]);
    }
    @memcpy(out, cv_array[0 .. 2 * Blake3.digest_length]);
}

const max_depth = 54;

const SubtreeHasher = struct {
    key: [8]u32,
    chunk: ChunkState,
    cv_stack_len: u8,
    cv_stack: [max_depth + 1][8]u32,

    fn init(start_chunk: u64) SubtreeHasher {
        var self: SubtreeHasher = .{
            .key = iv,
            .chunk = ChunkState.init(iv, .{}),
            .cv_stack_len = 0,
            .cv_stack = undefined,
        };
        self.chunk.chunk_counter = start_chunk;
        return self;
    }

    fn mergeCvStack(self: *SubtreeHasher, total_len: u64) void {
        const post_merge_stack_len: u8 = @intCast(@popCount(total_len));
        while (self.cv_stack_len > post_merge_stack_len) {
            const left_cv = self.cv_stack[self.cv_stack_len - 2];
            const right_cv = self.cv_stack[self.cv_stack_len - 1];
            const output = parentOutputFromCvs(left_cv, right_cv, self.key, .{});
            self.cv_stack[self.cv_stack_len - 2] = output.chainingValue();
            self.cv_stack_len -= 1;
        }
    }

    fn pushCv(self: *SubtreeHasher, new_cv: [8]u32, chunk_counter: u64) void {
        self.mergeCvStack(chunk_counter);
        self.cv_stack[self.cv_stack_len] = new_cv;
        self.cv_stack_len += 1;
    }

    fn update(self: *SubtreeHasher, input: []const u8) void {
        if (input.len == 0) return;
        var inp = input;
        if (self.chunk.len() > 0) {
            const take = @min(chunk_length - self.chunk.len(), inp.len);
            self.chunk.update(inp[0..take]);
            inp = inp[take..];
            if (inp.len > 0) {
                const chunk_cv = self.chunk.output().chainingValue();
                self.pushCv(chunk_cv, self.chunk.chunk_counter);
                self.chunk.reset(self.key, self.chunk.chunk_counter + 1);
            } else return;
        }
        while (inp.len > chunk_length) {
            var subtree_len = roundDownToPowerOf2(inp.len);
            const count_so_far = self.chunk.chunk_counter * chunk_length;
            while ((subtree_len - 1) & count_so_far != 0) {
                subtree_len /= 2;
            }
            const subtree_chunks = subtree_len / chunk_length;
            if (subtree_len <= chunk_length) {
                var chunk_state = ChunkState.init(self.key, .{});
                chunk_state.chunk_counter = self.chunk.chunk_counter;
                chunk_state.update(inp[0..subtree_len]);
                const cv = chunk_state.output().chainingValue();
                self.pushCv(cv, chunk_state.chunk_counter);
            } else {
                var cv_pair: [2 * Blake3.digest_length]u8 = undefined;
                compressSubtreeToParentNode(inp[0..subtree_len], self.key, self.chunk.chunk_counter, .{}, &cv_pair);
                const left_cv = loadCvWords(cv_pair[0..32].*);
                const right_cv = loadCvWords(cv_pair[32..64].*);
                self.pushCv(left_cv, self.chunk.chunk_counter);
                self.pushCv(right_cv, self.chunk.chunk_counter + (subtree_chunks / 2));
            }
            self.chunk.chunk_counter += subtree_chunks;
            inp = inp[subtree_len..];
        }
        if (inp.len > 0) {
            self.chunk.update(inp);
        }
    }

    fn finalizeNonRoot(self: *SubtreeHasher) [32]u8 {
        self.mergeCvStack(self.chunk.chunk_counter);
        if (self.cv_stack_len == 0) {
            return storeCvWords(self.chunk.output().chainingValue());
        }
        var output: Output = undefined;
        var cvs_remaining: usize = undefined;
        if (self.chunk.len() > 0) {
            cvs_remaining = self.cv_stack_len;
            output = self.chunk.output();
        } else if (self.cv_stack_len >= 2) {
            cvs_remaining = self.cv_stack_len - 2;
            const left_cv = self.cv_stack[cvs_remaining];
            const right_cv = self.cv_stack[cvs_remaining + 1];
            output = parentOutputFromCvs(left_cv, right_cv, self.key, .{});
        } else {
            return storeCvWords(self.cv_stack[self.cv_stack_len - 1]);
        }
        while (cvs_remaining > 0) {
            cvs_remaining -= 1;
            const left_cv = self.cv_stack[cvs_remaining];
            const right_cv = output.chainingValue();
            output = parentOutputFromCvs(left_cv, right_cv, self.key, .{});
        }
        return storeCvWords(output.chainingValue());
    }
};

/// Hash a subtree starting at `start_chunk` (chunk index, not byte offset).
/// `is_root` uses one-shot BLAKE3; otherwise chunk hash with input offset `start_chunk * 1024`.
pub fn hashSubtree(start_chunk: u64, data: []const u8, is_root: bool) [32]u8 {
    if (is_root) {
        std.debug.assert(start_chunk == 0);
        var out: [32]u8 = undefined;
        Blake3.hash(data, &out, .{});
        return out;
    }
    std.debug.assert(data.len > 0);
    var hasher = SubtreeHasher.init(start_chunk);
    hasher.update(data);
    return hasher.finalizeNonRoot();
}

/// Combine two child chaining values into a parent CV/hash.
pub fn parentCv(left: [32]u8, right: [32]u8, is_root: bool) [32]u8 {
    var left_cv: [8]u32 = undefined;
    var right_cv: [8]u32 = undefined;
    for (0..8) |i| {
        left_cv[i] = load32(left[i * 4 ..][0..4]);
        right_cv[i] = load32(right[i * 4 ..][0..4]);
    }
    var flags: Flags = .{};
    if (is_root) flags.root = true;
    const output = parentOutputFromCvs(left_cv, right_cv, iv, flags);
    return storeCvWords(output.chainingValue());
}

test "hash empty matches Hash.empty" {
    const h = hashSubtree(0, "", true);
    try std.testing.expectEqual(HashMod.Hash.empty.bytes, h);
}
