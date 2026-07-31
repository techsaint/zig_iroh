pub const frames = @import("frames.zig");

const std = @import("std");
const net = std.Io.net;

pub const MAX_NAT_PROBE_ATTEMPTS: u8 = 9;
pub const ipv6_bias_us: u64 = 3 * std.time.us_per_ms;
pub const switch_hysteresis_us: u64 = 5 * std.time.us_per_ms;
/// H8: the NAT probe retry schedule (noq n0_nat_traversal.rs retry_delay):
/// base = initial_rtt/10 (33.3 ms at the 333 ms default), exponential to a 2 s
/// cap, ≤9 attempts per candidate.
pub const nat_probe_base_delay_us: u64 = 33300;
pub const nat_probe_max_delay_us: u64 = 2 * std.time.us_per_s;
const max_backoff_exponent: u8 = 8;

pub const PathKind = enum { direct_ipv4, direct_ipv6, relay };
pub const ProbeState = enum { idle, active, succeeded, failed };

pub const Candidate = struct {
    seq: u64,
    address: net.IpAddress,
    state: ProbeState = .idle,
    attempts_remaining: u8 = 0,
    rtt_us: ?u64 = null,
    kind: PathKind,
    /// H8: the probe is queued for immediate emission.
    probe_queued: bool = false,
};

pub fn relayAddress() net.IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } };
}

pub const State = struct {
    allocator: std.mem.Allocator,
    remote_candidates: std.ArrayList(Candidate) = .empty,
    observed_addresses: std.ArrayList(net.IpAddress) = .empty,
    round: u64 = 0,
    /// H8: the retry round's attempt counter (drives the backoff).
    attempt: u8 = 0,
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
                    try self.onReachOut(f.seq, .{ .ip4 = .{ .bytes = f.ip, .port = f.port } }, .direct_ipv4);
                },
                .observed_ipv4_addr => try self.recordObserved(.{ .ip4 = .{ .bytes = f.ip, .port = f.port } }),
                else => {},
            },
            .ipv6_address => |f| switch (f.frame_type) {
                .add_ipv6_address => try self.upsertCandidate(f.seq, .{ .ip6 = .{ .bytes = f.ip, .port = f.port } }, .direct_ipv6),
                .reach_out_at_ipv6 => {
                    try self.onReachOut(f.seq, .{ .ip6 = .{ .bytes = f.ip, .port = f.port } }, .direct_ipv6);
                },
                .observed_ipv6_addr => try self.recordObserved(.{ .ip6 = .{ .bytes = f.ip, .port = f.port } }),
                else => {},
            },
            .remove_address => |f| self.removeCandidate(f.seq),
        }
    }

    pub fn initiateNatTraversalRound(self: *State) void {
        self.round += 1;
        self.attempt = 0;
        for (self.remote_candidates.items) |*candidate| {
            candidate.state = .active;
            candidate.attempts_remaining = MAX_NAT_PROBE_ATTEMPTS - 1;
            candidate.probe_queued = true;
        }
    }

    /// H8: the retry-delay for the current attempt (noq retry_delay):
    /// base×2^attempt (attempt 0) else base×2^attempt − base×2^(attempt−1),
    /// capped at 2 s. Returns null when nothing is retryable.
    pub fn retryDelay(self: *const State) ?u64 {
        const retryable = for (self.remote_candidates.items) |c| {
            if (c.state == .active and c.attempts_remaining > 0) break true;
        } else false;
        if (!retryable) return null;
        const attempt = @min(self.attempt, max_backoff_exponent);
        const shift: u6 = @intCast(attempt);
        if (attempt == 0) return nat_probe_base_delay_us;
        const interval = (nat_probe_base_delay_us << shift) - (nat_probe_base_delay_us << @intCast(attempt - 1));
        return @min(interval, nat_probe_max_delay_us);
    }

    /// H8: re-queue probes that have not yet succeeded or exhausted attempts
    /// (noq queue_retries): each retryable candidate loses one attempt and is
    /// queued; a candidate with zero remaining is failed.
    pub fn queueRetries(self: *State) void {
        self.attempt +|= 1;
        for (self.remote_candidates.items) |*c| {
            if (c.state != .active) continue;
            if (c.attempts_remaining == 0) {
                c.state = .failed;
                c.probe_queued = false;
            } else {
                c.attempts_remaining -= 1;
                c.probe_queued = true;
            }
        }
    }

    /// H8: the next queued probe's candidate (emit, then `noteProbeSent`).
    pub fn nextQueuedProbe(self: *const State) ?Candidate {
        for (self.remote_candidates.items) |c| {
            if (c.state == .active and c.probe_queued) return c;
        }
        return null;
    }

    /// H8: the queued probe to `address` was sent (noq mark_probe_sent).
    /// Consuming the last attempt marks the candidate failed (≤9 probes).
    pub fn noteProbeSent(self: *State, address: net.IpAddress) void {
        for (self.remote_candidates.items) |*c| {
            if (sameAddress(c.address, address)) {
                c.probe_queued = false;
                if (c.state == .active and c.attempts_remaining == 0) c.state = .failed;
                return;
            }
        }
    }

    /// H8: server-side REACH_OUT-triggered probing (noq ServerState frame
    /// handling): the peer asked us to punch to this address — activate the
    /// candidate and queue a probe. `round` is the traversal round: a stale
    /// round is ignored, a NEW round resets the retry state (noq :796-810);
    /// within a round, an address re-announce dedups.
    pub fn onReachOut(self: *State, round: u64, address: net.IpAddress, kind: PathKind) !void {
        if (round < self.round) return; // stale round (noq ignores)
        const new_round = round > self.round;
        if (new_round) {
            // A new traversal round: retry attempts refresh (noq clears state).
            self.round = round;
            self.attempt = 0;
            for (self.remote_candidates.items) |*c| {
                if (c.state == .failed) c.state = .idle;
                c.attempts_remaining = MAX_NAT_PROBE_ATTEMPTS - 1;
            }
        }
        for (self.remote_candidates.items) |*c| {
            if (sameAddress(c.address, address)) {
                // Same-round retransmit: no re-queue. New round: re-probe.
                if (!new_round) return;
                if (c.state != .succeeded) {
                    c.state = .active;
                    c.probe_queued = true;
                }
                return;
            }
        }
        try self.upsertCandidate(round, address, kind);
        for (self.remote_candidates.items) |*c| {
            if (sameAddress(c.address, address)) {
                c.state = .active;
                c.attempts_remaining = MAX_NAT_PROBE_ATTEMPTS - 1;
                c.probe_queued = true;
                return;
            }
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

test "H8: NAT probe retry schedule — 33ms exponential to 2s cap, ≤9 attempts, REACH_OUT re-probes" {
    const allocator = std.testing.allocator;
    var state = State.init(allocator);
    defer state.deinit();

    const addr: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 7 }, .port = 4433 } };
    try state.handleFrame(.{ .ipv4_address = .{
        .frame_type = .add_ipv4_address,
        .seq = 1,
        .ip = addr.ip4.bytes,
        .port = addr.ip4.port,
    } });

    // A traversal round queues every candidate with 8 retries left.
    state.initiateNatTraversalRound();
    try std.testing.expectEqual(@as(u64, 1), state.round);
    const first = state.nextQueuedProbe() orelse return error.UnexpectedState;
    try std.testing.expectEqual(@as(u8, MAX_NAT_PROBE_ATTEMPTS - 1), first.attempts_remaining);
    state.noteProbeSent(addr);
    try std.testing.expect(state.nextQueuedProbe() == null);

    // The noq retry ladder (its own test's sequence): each queue_retries arm
    // reads 33.3, 66.6, 133.2, 266.4, 532.8, 1065.6 ms, then the 2 s cap.
    const expected = [_]u64{ 33300, 66600, 133200, 266400, 532800, 1065600, 2_000_000 };
    for (expected) |want_us| {
        state.queueRetries();
        const got = state.retryDelay() orelse return error.UnexpectedState;
        try std.testing.expectEqual(want_us, got);
        const probe = state.nextQueuedProbe() orelse return error.UnexpectedState;
        state.noteProbeSent(probe.address);
    }
    // The final retry round queues probe 9; sending it exhausts the attempts.
    state.queueRetries();
    const last = state.nextQueuedProbe() orelse return error.UnexpectedState;
    state.noteProbeSent(last.address);
    try std.testing.expect(state.retryDelay() == null);
    try std.testing.expectEqual(ProbeState.failed, state.remote_candidates.items[0].state);

    // Server-side REACH_OUT: the peer asking us to punch re-activates + queues
    // a probe (noq ServerState), and a same-address retransmit dedups.
    const addr2: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 9 }, .port = 4434 } };
    try state.onReachOut(2, addr2, .direct_ipv4);
    const probe2 = state.nextQueuedProbe() orelse return error.UnexpectedState;
    try std.testing.expect(sameAddress(probe2.address, addr2));
    try std.testing.expectEqual(@as(u8, MAX_NAT_PROBE_ATTEMPTS - 1), probe2.attempts_remaining);
    state.noteProbeSent(addr2);
    try std.testing.expect(state.nextQueuedProbe() == null);
    try state.onReachOut(2, addr2, .direct_ipv4); // retransmit: no re-queue
    try std.testing.expect(state.nextQueuedProbe() == null);
    // Round semantics: a stale round is ignored; a NEW round refreshes the
    // retry state and re-enables the address (noq :796-810).
    state.remote_candidates.items[1].attempts_remaining = 0;
    state.remote_candidates.items[1].state = .failed;
    try state.onReachOut(1, addr2, .direct_ipv4); // stale round
    try std.testing.expectEqual(ProbeState.failed, state.remote_candidates.items[1].state);
    try state.onReachOut(3, addr2, .direct_ipv4); // new round
    const probe3 = state.nextQueuedProbe() orelse return error.UnexpectedState;
    try std.testing.expectEqual(@as(u8, MAX_NAT_PROBE_ATTEMPTS - 1), probe3.attempts_remaining);
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
