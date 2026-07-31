//! Selected-path observability for patchbay / NAT / path-migration rows.
//!
//! Upstream's contract (`PathConnectionExt::wait_selected` in
//! `iroh/iroh/tests/patchbay/util.rs`) asserts WHICH path is selected
//! (relay vs IP family + remote address), not merely that a connection works.
//! A connectivity-only green is a false green for this family.
//!
//! This module is the Zig-side assertion surface. Live engine plumbing lives
//! above the frozen `transport.zig` vtable (factory + public Endpoint
//! Connection), matching the datagram pattern.

const std = @import("std");
const magicsock = @import("magicsock/mod.zig");

const net = std.Io.net;

pub const PathKind = enum {
    relay,
    direct_ipv4,
    direct_ipv6,

    pub fn fromMagicsock(kind: magicsock.PathKind) PathKind {
        return switch (kind) {
            .relay => .relay,
            .direct_ipv4 => .direct_ipv4,
            .direct_ipv6 => .direct_ipv6,
        };
    }

    pub fn isRelay(self: PathKind) bool {
        return self == .relay;
    }

    pub fn isIp(self: PathKind) bool {
        return self == .direct_ipv4 or self == .direct_ipv6;
    }

    pub fn asString(self: PathKind) []const u8 {
        return switch (self) {
            .relay => "relay",
            .direct_ipv4 => "direct_ipv4",
            .direct_ipv6 => "direct_ipv6",
        };
    }
};

/// Snapshot of the currently selected path. `address` is null for relay
/// (magicsock uses a sentinel; callers must not treat it as a peer IP).
pub const SelectedPath = struct {
    kind: PathKind,
    address: ?net.IpAddress = null,

    pub fn fromMagicsockCandidate(cand: magicsock.Candidate) SelectedPath {
        const kind = PathKind.fromMagicsock(cand.kind);
        return .{
            .kind = kind,
            .address = if (kind.isIp()) cand.address else null,
        };
    }

    pub fn isRelay(self: SelectedPath) bool {
        return self.kind.isRelay();
    }

    pub fn isIp(self: SelectedPath) bool {
        return self.kind.isIp();
    }

    pub fn isIpv4(self: SelectedPath) bool {
        return self.kind == .direct_ipv4;
    }

    pub fn isIpv6(self: SelectedPath) bool {
        return self.kind == .direct_ipv6;
    }
};

/// Predicate used by patchbay rows (upstream `wait_selected` filter).
pub const PathPredicate = *const fn (SelectedPath) bool;

pub fn predIsRelay(path: SelectedPath) bool {
    return path.isRelay();
}

pub fn predIsIp(path: SelectedPath) bool {
    return path.isIp();
}

pub fn predIsIpv4(path: SelectedPath) bool {
    return path.isIpv4();
}

pub fn predIsIpv6(path: SelectedPath) bool {
    return path.isIpv6();
}

/// Score a holepunch transition: must have started relayed, then selected an IP path.
/// Returns null on success; otherwise a stable reason string.
pub fn scoreHolepunchTransition(started_relayed: bool, selected: ?SelectedPath) ?[]const u8 {
    if (!started_relayed) return "connection did not start relayed";
    const path = selected orelse return "no selected path observed";
    if (!path.isIp()) return "selected path is not direct IP after holepunch";
    return null;
}

/// Score a path migration: selected remote address must change and remain direct.
/// A missing `previous_addr` is a REJECT — "we never observed a first path" must
/// not score as "migration proven" (false-green the patchbay family exists to prevent).
pub fn scorePathMigration(
    previous_addr: ?net.IpAddress,
    selected: ?SelectedPath,
) ?[]const u8 {
    const prev = previous_addr orelse return "no previous selected path to migrate from";
    const path = selected orelse return "no selected path observed after migration";
    if (!path.isIp()) return "selected path is not direct IP after migration";
    const addr = path.address orelse return "direct path missing remote address";
    if (sameAddress(prev, addr)) return "selected remote address did not change after migration";
    return null;
}

fn sameAddress(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| a4.port == b4.port and std.mem.eql(u8, &a4.bytes, &b4.bytes),
            else => false,
        },
        .ip6 => |a6| switch (b) {
            .ip6 => |b6| a6.port == b6.port and std.mem.eql(u8, &a6.bytes, &b6.bytes),
            else => false,
        },
    };
}

test "SelectedPath mirrors magicsock candidate kinds" {
    const relay = SelectedPath.fromMagicsockCandidate(.{
        .seq = 1,
        .address = magicsock.relayAddress(),
        .kind = .relay,
        .state = .succeeded,
    });
    try std.testing.expect(relay.isRelay());
    try std.testing.expect(!relay.isIp());
    try std.testing.expect(relay.address == null);

    const direct = SelectedPath.fromMagicsockCandidate(.{
        .seq = 2,
        .address = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 2 }, .port = 4433 } },
        .kind = .direct_ipv4,
        .state = .succeeded,
    });
    try std.testing.expect(direct.isIp());
    try std.testing.expect(direct.isIpv4());
    try std.testing.expect(direct.address != null);
}

test "scoreHolepunchTransition requires relay then direct" {
    try std.testing.expectEqualStrings(
        "connection did not start relayed",
        scoreHolepunchTransition(false, .{ .kind = .direct_ipv4 }).?,
    );
    try std.testing.expectEqualStrings(
        "no selected path observed",
        scoreHolepunchTransition(true, null).?,
    );
    try std.testing.expectEqualStrings(
        "selected path is not direct IP after holepunch",
        scoreHolepunchTransition(true, .{ .kind = .relay }).?,
    );
    try std.testing.expect(scoreHolepunchTransition(true, .{
        .kind = .direct_ipv4,
        .address = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 1 } },
    }) == null);
}

test "scorePathMigration rejects unchanged remote" {
    const addr = net.IpAddress{ .ip4 = .{ .bytes = .{ 10, 0, 0, 9 }, .port = 9 } };
    try std.testing.expectEqualStrings(
        "selected remote address did not change after migration",
        scorePathMigration(addr, .{ .kind = .direct_ipv4, .address = addr }).?,
    );
    const other = net.IpAddress{ .ip4 = .{ .bytes = .{ 10, 0, 0, 10 }, .port = 9 } };
    try std.testing.expect(scorePathMigration(addr, .{ .kind = .direct_ipv4, .address = other }) == null);
}

test "scorePathMigration rejects missing previous path" {
    const selected = SelectedPath{
        .kind = .direct_ipv4,
        .address = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 1 } },
    };
    try std.testing.expectEqualStrings(
        "no previous selected path to migrate from",
        scorePathMigration(null, selected).?,
    );
}

test "magicsock State selectedPath feeds holepunch scorer" {
    var state = magicsock.State.init(std.testing.allocator);
    defer state.deinit();
    try state.addRelayCandidate(1);
    state.selectRelayFallback();
    const started = SelectedPath.fromMagicsockCandidate(state.selectedPath().?);
    try std.testing.expect(started.isRelay());

    const peer = net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 168, 1, 10 }, .port = 41641 } };
    try state.handleFrame(.{ .ipv4_address = .{
        .frame_type = .add_ipv4_address,
        .seq = 2,
        .ip = peer.ip4.bytes,
        .port = peer.ip4.port,
    } });
    state.markPathSucceeded(peer, 1_000);
    const after = SelectedPath.fromMagicsockCandidate(state.selectedPath().?);
    try std.testing.expect(scoreHolepunchTransition(started.isRelay(), after) == null);
}
