//! Golden test constants and hex helpers for blobs tests.

const std = @import("std");

pub fn hexToBytes(comptime hex_str: []const u8) [hex_str.len / 2]u8 {
    var out: [hex_str.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

pub fn hexToBytesAlloc(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    if (hex_str.len % 2 != 0) return error.InvalidHex;
    const out = try allocator.alloc(u8, hex_str.len / 2);
    errdefer allocator.free(out);
    _ = try std.fmt.hexToBytes(out, hex_str);
    return out;
}

/// Deterministic blob bytes: byte `i` is `i % 256`.
pub fn makeTestData(allocator: std.mem.Allocator, n: usize) ![]u8 {
    const data = try allocator.alloc(u8, n);
    for (0..n) |i| data[i] = @intCast(i % 256);
    return data;
}

pub const golden = struct {
    pub const hash_empty = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    pub const hash_1024 = "882179b8dbccd285cda241d968cfcccb3156c5edac2fa3761bb6eda7ff8cb172";
    pub const hash_16384 = "d49d367e4b0011a34510a28a1eb0caeb3e51e77ff2d30136849454640fefefc1";
    pub const hash_16385 = "2fa27eb0a80b89e74472646463ba0b7b1c619dfaafb3d3027d3e57defdbb3ce4";
    pub const outboard_16385 = "a4480fcd5c4f7dbd434489ad04b61343893d9e77ae72ed05e39025ead44ca1b979cdd2ba539c8be5c77e3afbb25f7e768e665c43195678796c9a5a2dac258435";
};
