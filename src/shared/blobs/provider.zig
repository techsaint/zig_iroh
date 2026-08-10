//! Provider host — the production entry point for serving blobs requests on
//! an accepted connection.
//!
//! The host holds a `Policy` so the security posture is chosen ONCE at
//! construction instead of re-passed on every serve call. The default is
//! `Policy.default`: reads allowed, push DENIED (push can write the local
//! store) — iroh's EventMask::DEFAULT posture. `Provider.allow_all` is the
//! explicit opt-in to the pre-policy open behavior, for interop harnesses
//! and intentional open servers.
//!
//! Wire framing is unchanged: each method forwards to the `*WithPolicy` leaf
//! in `get.zig` / `observe_push.zig` with the host's policy. The bare leaf
//! wrappers (`serveBlob` / `serveAll` / `serveMany` / `serveObserve` /
//! `receivePushBlob`) remain `allow_all` compatibility shims for existing
//! callers; production code should construct a `Provider` instead.

const std = @import("std");
const Hash = @import("../hash.zig").Hash;
const key = @import("../key.zig");
const mock = @import("../transport/mock.zig");
const fixtures = @import("fixtures.zig");
const get = @import("get.zig");
const observe_push = @import("observe_push.zig");
const protocol = @import("protocol.zig");
const provider_policy = @import("provider_policy.zig");

pub const Policy = provider_policy.Policy;
pub const PushedBlob = observe_push.PushedBlob;
pub const Error = observe_push.Error;

/// Blobs provider host. `policy` defaults to `Policy.default`, so
/// `Provider{}` (or `.policy` never touched) is the secure posture: get /
/// get_many / observe / connect allowed, push denied.
pub const Provider = struct {
    policy: Policy = .default,

    /// Explicit opt-in to the fully open posture (push allowed). NOT the
    /// default — interop and deliberate open servers only.
    pub const allow_all: Provider = .{ .policy = .allow_all };

    /// Serve one blob (Get) on the next accepted bi-stream.
    pub fn serveBlob(self: Provider, allocator: std.mem.Allocator, conn: anytype, hash: Hash, data: []const u8) Error!void {
        return get.serveBlobWithPolicy(allocator, conn, hash, data, self.policy);
    }

    /// Serve a hashseq root + each child blob (GetRequest::all).
    pub fn serveAll(self: Provider, allocator: std.mem.Allocator, conn: anytype, hash_seq_bytes: []const u8, child_data: []const []const u8) Error!void {
        return get.serveAllWithPolicy(allocator, conn, hash_seq_bytes, child_data, self.policy);
    }

    /// Serve each requested GetMany child in request order.
    pub fn serveMany(self: Provider, allocator: std.mem.Allocator, conn: anytype, child_data: []const []const u8) Error!void {
        return get.serveManyWithPolicy(allocator, conn, child_data, self.policy);
    }

    /// Serve a bounded sequence of Observe updates.
    pub fn serveObserve(self: Provider, allocator: std.mem.Allocator, conn: anytype, expected_hash: Hash, updates: []const protocol.ObserveItem) Error!void {
        return observe_push.serveObserveWithPolicy(allocator, conn, expected_hash, updates, self.policy);
    }

    /// Accept and verify one complete raw-blob Push. Under the default
    /// policy this refuses with `error.PermissionDenied` and a peer-visible
    /// ERR_PERMISSION reset; use `Provider.allow_all` to accept push.
    pub fn receivePushBlob(self: Provider, allocator: std.mem.Allocator, conn: anytype) Error!PushedBlob {
        return observe_push.receivePushBlobWithPolicy(allocator, conn, self.policy);
    }
};

fn testId(seed: u8) key.NodeId {
    return key.SecretKey.fromBytes(.{seed} ** 32).public();
}

test "provider host policy defaults to Policy.default (push deny)" {
    const host = Provider{};
    try std.testing.expect(host.policy.authorize(.get) == .allow);
    try std.testing.expect(host.policy.authorize(.get_many) == .allow);
    try std.testing.expect(host.policy.authorize(.observe) == .allow);
    switch (host.policy.authorize(.push)) {
        .deny => |r| try std.testing.expect(r == .permission),
        .allow => return error.TestUnexpectedResult,
    }
    // allow_all is a deliberate opt-in, never the default.
    try std.testing.expect(Provider.allow_all.policy.authorize(.push) == .allow);
}

test "provider host default denies push (peer-visible permission reset)" {
    const allocator = std.testing.allocator;
    const pair = mock.Pair.init(allocator, std.testing.io, testId(30), testId(31));
    defer pair.deinit(allocator);

    const data = try fixtures.makeTestData(allocator, 2048);
    defer allocator.free(data);
    const hash = Hash.of(data);

    const host = Provider{};
    try observe_push.pushBlob(allocator, pair.client(), hash, data);
    try std.testing.expectError(
        error.PermissionDenied,
        host.receivePushBlob(allocator, pair.server()),
    );
    const life = pair.lifecycle();
    try std.testing.expect(life.server_send_reset);
    try std.testing.expectEqual(@as(?u64, protocol.ERR_PERMISSION), life.server_send_reset_code);
    try std.testing.expect(life.server_recv_stopped);
}

test "provider host default serves get reads unchanged" {
    const allocator = std.testing.allocator;
    const pair = mock.Pair.init(allocator, std.testing.io, testId(32), testId(33));
    defer pair.deinit(allocator);

    const data = try fixtures.makeTestData(allocator, 16385);
    defer allocator.free(data);
    const hash = Hash.of(data);

    const bi = try pair.client().openBi();
    var req_buf: [128]u8 = undefined;
    var req_w: std.Io.Writer = .fixed(&req_buf);
    try protocol.GetRequest.blob(hash).encode(&req_w);
    try bi.send.writer().writeAll(req_buf[0..req_w.end]);
    try bi.send.finish();

    const host = Provider{};
    try host.serveBlob(allocator, pair.server(), hash, data);

    var size_buf: [8]u8 = undefined;
    const sn = try bi.recv.reader().readSliceShort(&size_buf);
    if (sn != 8) return error.EndOfStream;
    const size = std.mem.readInt(u64, &size_buf, .little);
    const got = try @import("bao.zig").decodeVerified(allocator, hash, size, bi.recv.reader());
    defer allocator.free(got);
    try std.testing.expectEqualSlices(u8, data, got);
}

test "provider host allow_all opt-in accepts push" {
    const allocator = std.testing.allocator;
    const pair = mock.Pair.init(allocator, std.testing.io, testId(34), testId(35));
    defer pair.deinit(allocator);

    const data = try fixtures.makeTestData(allocator, 1024);
    defer allocator.free(data);
    const hash = Hash.of(data);

    const host = Provider.allow_all;
    try observe_push.pushBlob(allocator, pair.client(), hash, data);
    const pushed = try host.receivePushBlob(allocator, pair.server());
    defer pushed.deinit(allocator);
    try std.testing.expect(pushed.hash.eql(hash));
    try std.testing.expectEqualSlices(u8, data, pushed.data);
}
