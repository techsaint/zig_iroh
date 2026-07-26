pub const frames = @import("frames.zig");

const std = @import("std");
const net = std.Io.net;

pub const MAX_NAT_PROBE_ATTEMPTS: u8 = 9;
pub const ipv6_bias_us: u64 = 3 * std.time.us_per_ms;
pub const switch_hysteresis_us: u64 = 5 * std.time.us_per_ms;

pub const PathKind = enum { direct_ipv4, direct_ipv6, relay };
pub const ProbeState = enum { idle, active, succeeded, failed };

pub const Candidate = struct {
    seq: u64,
    address: net.IpAddress,
    state: ProbeState = .idle,
    attempts_remaining: u8 = 0,
    rtt_us: ?u64 = null,
    kind: PathKind,
};

pub fn relayAddress() net.IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } };
}

pub const State = struct {
    allocator: std.mem.Allocator,
    remote_candidates: std.ArrayList(Candidate) = .empty,
    observed_addresses: std.ArrayList(net.IpAddress) = .empty,
    round: u64 = 0,
    selected_index: ?usize = null,

    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *State) void {
        self.remote_candidates.deinit(self.allocator);
        self.observed_addresses.deinit(self.allocator);
    }

    pub fn handleFrame(self: *State, frame: frames.Frame) !void {
        switch (frame) {
            .ipv4_address => |f| switch (f.frame_type) {
                .add_ipv4_address => try self.upsertCandidate(f.seq, .{ .ip4 = .{ .bytes = f.ip, .port = f.port } }, .direct_ipv4),
                .reach_out_at_ipv4 => {
                    if (f.seq >= self.round) self.round = f.seq;
                    try self.upsertCandidate(f.seq, .{ .ip4 = .{ .bytes = f.ip, .port = f.port } }, .direct_ipv4);
                },
                .observed_ipv4_addr => try self.recordObserved(.{ .ip4 = .{ .bytes = f.ip, .port = f.port } }),
                else => {},
            },
            .ipv6_address => |f| switch (f.frame_type) {
                .add_ipv6_address => try self.upsertCandidate(f.seq, .{ .ip6 = .{ .bytes = f.ip, .port = f.port } }, .direct_ipv6),
                .reach_out_at_ipv6 => {
                    if (f.seq >= self.round) self.round = f.seq;
                    try self.upsertCandidate(f.seq, .{ .ip6 = .{ .bytes = f.ip, .port = f.port } }, .direct_ipv6);
                },
                .observed_ipv6_addr => try self.recordObserved(.{ .ip6 = .{ .bytes = f.ip, .port = f.port } }),
                else => {},
            },
            .remove_address => |f| self.removeCandidate(f.seq),
        }
    }

    pub fn initiateNatTraversalRound(self: *State) void {
        self.round += 1;
        for (self.remote_candidates.items) |*candidate| {
            candidate.state = .active;
            candidate.attempts_remaining = MAX_NAT_PROBE_ATTEMPTS - 1;
        }
    }

    pub fn markPathSucceeded(self: *State, address: net.IpAddress, rtt_us: u64) void {
        for (self.remote_candidates.items, 0..) |*candidate, i| {
            if (sameAddress(candidate.address, address)) {
                candidate.state = .succeeded;
                candidate.rtt_us = rtt_us;
                self.selected_index = selectPath(self.remote_candidates.items, self.selected_index);
                if (self.selected_index == null) self.selected_index = i;
                return;
            }
        }
    }

    pub fn addRelayCandidate(self: *State, seq: u64) !void {
        try self.upsertCandidate(seq, relayAddress(), .relay);
    }

    pub fn selectRelayFallback(self: *State) void {
        for (self.remote_candidates.items) |candidate| {
            if (candidate.kind != .relay and candidate.state == .succeeded) return;
        }
        for (self.remote_candidates.items, 0..) |*candidate, i| {
            if (candidate.kind == .relay) {
                candidate.state = .succeeded;
                candidate.rtt_us = std.math.maxInt(u32);
                self.selected_index = i;
                return;
            }
        }
    }

    pub fn markPathProbed(self: *State, address: net.IpAddress) void {
        for (self.remote_candidates.items) |*candidate| {
            if (sameAddress(candidate.address, address)) {
                if (candidate.state == .idle) {
                    candidate.state = .active;
                    candidate.attempts_remaining = MAX_NAT_PROBE_ATTEMPTS - 1;
                }
                return;
            }
        }
    }

    pub fn selectedPath(self: State) ?Candidate {
        const index = self.selected_index orelse return null;
        return self.remote_candidates.items[index];
    }

    pub fn nextProbeCandidate(self: State) ?Candidate {
        for (self.remote_candidates.items) |candidate| {
            if (candidate.state == .idle) return candidate;
        }
        return null;
    }

    fn upsertCandidate(self: *State, seq: u64, address: net.IpAddress, kind: PathKind) !void {
        for (self.remote_candidates.items) |*candidate| {
            if (sameAddress(candidate.address, address)) {
                candidate.seq = seq;
                candidate.kind = kind;
                return;
            }
        }
        try self.remote_candidates.append(self.allocator, .{ .seq = seq, .address = address, .kind = kind });
    }

    fn removeCandidate(self: *State, seq: u64) void {
        var i: usize = 0;
        while (i < self.remote_candidates.items.len) {
            if (self.remote_candidates.items[i].seq == seq) {
                const last = self.remote_candidates.items.len - 1;
                _ = self.remote_candidates.swapRemove(i);
                if (self.selected_index) |sel| {
                    if (sel == i) {
                        // Removed the selected candidate.
                        self.selected_index = null;
                    } else if (sel == last) {
                        // Last element (previously selected) moved into slot i.
                        self.selected_index = i;
                    }
                    // else: selected index unchanged (sel < i, or sel between i+1 and last-1).
                }
                // Do not increment i — re-check the swapped-in element.
            } else {
                i += 1;
            }
        }
        if (self.selected_index != null and self.selected_index.? >= self.remote_candidates.items.len) {
            self.selected_index = null;
        }
    }

    pub fn recordObserved(self: *State, address: net.IpAddress) !void {
        for (self.observed_addresses.items) |existing| {
            if (sameAddress(existing, address)) return;
        }
        try self.observed_addresses.append(self.allocator, address);
    }
};

pub fn selectPath(candidates: []const Candidate, current_index: ?usize) ?usize {
    var best_index: ?usize = null;
    var best_score: u64 = std.math.maxInt(u64);
    for (candidates, 0..) |candidate, i| {
        if (candidate.state != .succeeded) continue;
        var score = candidate.rtt_us orelse std.math.maxInt(u32);
        if (candidate.kind == .direct_ipv6) score = if (score > ipv6_bias_us) score - ipv6_bias_us else 0;
        if (candidate.kind == .relay) score += 1_000_000_000;
        if (current_index) |current| {
            if (i != current and candidates[current].state == .succeeded) {
                const current_rtt = candidates[current].rtt_us orelse std.math.maxInt(u32);
                if (score + switch_hysteresis_us >= current_rtt) continue;
            }
        }
        if (score < best_score) {
            best_score = score;
            best_index = i;
        }
    }
    return best_index;
}

fn sameAddress(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| std.mem.eql(u8, &a4.bytes, &b4.bytes) and a4.port == b4.port,
            else => false,
        },
        .ip6 => |a6| switch (b) {
            .ip6 => |b6| std.mem.eql(u8, &a6.bytes, &b6.bytes) and a6.port == b6.port,
            else => false,
        },
    };
}

test {
    _ = frames;
}

test "S3 magicsock state tracks reach-out, observed address, and path selection" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    try state.handleFrame(try frames.decode(&.{ 0x80, 0x3d, 0x7f, 0x92, 0x02, 0x7f, 0x00, 0x00, 0x01, 0x27, 0x0f }));
    try std.testing.expectEqual(@as(usize, 1), state.remote_candidates.items.len);
    state.initiateNatTraversalRound();
    try std.testing.expectEqual(ProbeState.active, state.remote_candidates.items[0].state);
    try std.testing.expectEqual(@as(u8, MAX_NAT_PROBE_ATTEMPTS - 1), state.remote_candidates.items[0].attempts_remaining);

    try state.handleFrame(try frames.decode(&.{ 0x80, 0x9f, 0x81, 0xa6, 0x05, 0xcb, 0x00, 0x71, 0x0a, 0x11, 0x5c }));
    try std.testing.expectEqual(@as(usize, 1), state.observed_addresses.items.len);

    state.markPathSucceeded(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9999 } }, 20 * std.time.us_per_ms);
    const selected = state.selectedPath().?;
    try std.testing.expectEqual(ProbeState.succeeded, selected.state);
}

test "S4 magicsock relay fallback is backup to validated direct paths" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    try state.addRelayCandidate(99);
    state.selectRelayFallback();
    try std.testing.expectEqual(PathKind.relay, state.selectedPath().?.kind);

    const direct: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 7777 } };
    try state.handleFrame(.{ .ipv4_address = .{
        .frame_type = .add_ipv4_address,
        .seq = 1,
        .ip = direct.ip4.bytes,
        .port = direct.ip4.port,
    } });
    state.markPathSucceeded(direct, 10 * std.time.us_per_ms);
    try std.testing.expectEqual(PathKind.direct_ipv4, state.selectedPath().?.kind);
}

test "F4: observed address recording deduplicates QAD authority" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const observed: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 9 }, .port = 54321 } };
    try state.recordObserved(observed);
    try state.recordObserved(observed);

    try std.testing.expectEqual(@as(usize, 1), state.observed_addresses.items.len);
    try std.testing.expectEqual(observed, state.observed_addresses.items[0]);
}
