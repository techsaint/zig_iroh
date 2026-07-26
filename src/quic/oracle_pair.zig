//! Deterministic in-process connection-pair harness for the noq BEHAVIORAL oracle.
//!
//! Purpose-port of upstream `original/noq/noq-proto/src/tests/util.rs::Pair` fields
//! (mtu / congestion_experienced / latency / virtual clock) around the existing
//! private `TestPair` pattern in `connection.zig` (makePair / pumpOnce / establishPair).
//!
//! Convention call: GENERALIZE TestPair's purpose into a public module rather than
//! inventing a second loopback OR extracting the private test-only harness out of
//! connection.zig (that would churn every in-file unit test). Same Connection APIs,
//! plus a simulated LINK.
//!
//! D7: the pump supplies monotonic `now`; protocol code never reads the OS clock.

const std = @import("std");
const connection = @import("connection.zig");
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");
const key = @import("../key.zig");
const tls_name = @import("../connection/tls_name.zig");

const Connection = connection.Connection;
const Instant = connection.Instant;
const SecretKey = key.SecretKey;

pub const default_mtu: usize = 1452;
pub const max_delayed: usize = 64;

pub const LinkConfig = struct {
    /// Packets exceeding this size are dropped (upstream Pair.mtu).
    mtu: usize = default_mtu,
    /// When true, delivered packets are CE-marked via `Connection.noteEcn` (upstream
    /// Pair.congestion_experienced). Partial: counts only — no real IP TOS bits.
    congestion_experienced: bool = false,
    /// One-way latency in nanoseconds (upstream Pair.latency). 0 = deliver immediately.
    latency_ns: Instant = 0,
    /// When true, every outbound datagram is dropped (mutation / blackhole).
    drop_all: bool = false,
    /// Simulates an MTU BLACK HOLE: datagrams at or above this size vanish
    /// silently — no ICMP, no error, exactly like a real path that has quietly
    /// shrunk. This is distinct from `mtu` above, which models a link that
    /// drops oversized packets as part of ordinary PMTUD discovery. A black
    /// hole is what the detector exists to find, so the harness has to be able
    /// to produce one.
    black_hole_at: ?usize = null,
};

const Delayed = struct {
    deliver_at: Instant,
    to_server: bool,
    /// Owned copy of datagram bytes (pair-local scratch, freed on deliver/drop).
    bytes: []u8,
};

pub const Pair = struct {
    allocator: std.mem.Allocator,
    client: *Connection,
    server: *Connection,
    now: Instant = 0,
    link: LinkConfig,
    /// Datagrams dropped for exceeding link MTU (client→server + server→client).
    dropped_oversize: usize = 0,
    /// Datagrams dropped by drop_all / blackhole.
    dropped_forced: usize = 0,
    /// Datagrams swallowed by the simulated MTU black hole.
    dropped_black_hole: usize = 0,
    /// Datagrams delivered with CE mark (noteEcn called).
    ce_marked: usize = 0,
    /// Datagrams successfully delivered.
    delivered: usize = 0,
    delayed: [max_delayed]Delayed = undefined,
    delayed_len: usize = 0,
    pkt_idx: usize = 0,

    pub fn deinit(self: *Pair) void {
        var i: usize = 0;
        while (i < self.delayed_len) : (i += 1) {
            self.allocator.free(self.delayed[i].bytes);
        }
        self.delayed_len = 0;
        self.client.destroy();
        self.server.destroy();
    }

    /// Advance virtual time by `delta_ns` and release any delayed packets due.
    pub fn advance(self: *Pair, delta_ns: Instant) !void {
        self.now += delta_ns;
        try self.flushDue();
    }

    /// One pump round: handle timeouts, poll transmits, apply link, deliver.
    pub fn pumpOnce(self: *Pair) !void {
        self.client.handleTimeout(self.now);
        self.server.handleTimeout(self.now);

        while (try self.client.pollTransmit(self.now)) |tx| {
            try self.route(tx.bytes, true);
        }
        while (try self.server.pollTransmit(self.now)) |tx| {
            try self.route(tx.bytes, false);
        }
        try self.flushDue();
        self.client.drainEvents();
        self.server.drainEvents();
    }

    /// Drive until both sides established or `max_rounds` exhausted.
    pub fn establish(self: *Pair, max_rounds: usize) !void {
        try self.client.startClient();
        var rounds: usize = 0;
        while (rounds < max_rounds and
            !(self.client.state == .established and self.server.state == .established)) : (rounds += 1)
        {
            try self.advance(1_000_000);
            try self.pumpOnce();
        }
        if (self.client.state != .established or self.server.state != .established) {
            return error.HandshakeDidNotEstablish;
        }
    }

    /// Drive `rounds` more steps of 1ms virtual time each.
    pub fn drive(self: *Pair, rounds: usize) !void {
        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            try self.advance(1_000_000);
            try self.pumpOnce();
        }
    }

    fn route(self: *Pair, bytes: []const u8, client_to_server: bool) !void {
        self.pkt_idx += 1;
        if (self.link.drop_all) {
            self.dropped_forced += 1;
            return;
        }
        if (self.link.black_hole_at) |threshold| {
            if (bytes.len >= threshold) {
                self.dropped_black_hole += 1;
                return;
            }
        }
        if (bytes.len > self.link.mtu) {
            self.dropped_oversize += 1;
            return;
        }
        if (self.link.latency_ns <= 0) {
            try self.deliver(bytes, client_to_server);
            return;
        }
        if (self.delayed_len >= max_delayed) return error.DelayedQueueFull;
        const copy = try self.allocator.dupe(u8, bytes);
        self.delayed[self.delayed_len] = .{
            .deliver_at = self.now + self.link.latency_ns,
            .to_server = client_to_server,
            .bytes = copy,
        };
        self.delayed_len += 1;
    }

    fn flushDue(self: *Pair) !void {
        var i: usize = 0;
        while (i < self.delayed_len) {
            if (self.delayed[i].deliver_at <= self.now) {
                const d = self.delayed[i];
                // swap-remove
                self.delayed[i] = self.delayed[self.delayed_len - 1];
                self.delayed_len -= 1;
                defer self.allocator.free(d.bytes);
                try self.deliver(d.bytes, d.to_server);
            } else {
                i += 1;
            }
        }
    }

    fn deliver(self: *Pair, bytes: []const u8, client_to_server: bool) !void {
        if (self.link.congestion_experienced) {
            // Partial ECN path: mark one CE on the receiver (IP-bit ingestion not present).
            if (client_to_server) {
                self.server.noteEcn(0, 0, 1);
            } else {
                self.client.noteEcn(0, 0, 1);
            }
            self.ce_marked += 1;
        }
        if (client_to_server) {
            try self.server.handleDatagram(self.now, bytes);
        } else {
            try self.client.handleDatagram(self.now, bytes);
        }
        self.delivered += 1;
    }
};

fn testCsprngSeed(tag: u64) [std.Random.DefaultCsprng.secret_seed_length]u8 {
    var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = .{0} ** std.Random.DefaultCsprng.secret_seed_length;
    std.mem.writeInt(u64, seed[0..8], tag, .little);
    var i: usize = 8;
    while (i + 8 <= seed.len) : (i += 8) {
        std.mem.writeInt(u64, seed[i..][0..8], tag *% (@as(u64, @intCast(i)) +% 0x9e37_79b9_7f4a_7c15), .little);
    }
    return seed;
}

/// Build a client+server pair with the given link config.
pub fn makePair(allocator: std.mem.Allocator, link: LinkConfig) !Pair {
    const backend: crypto.Backend = if (crypto.picotls_enabled) .picotls else .zigtls;
    return makePairBackend(allocator, backend, link);
}

pub fn makePairBackend(allocator: std.mem.Allocator, backend: crypto.Backend, link: LinkConfig) !Pair {
    const client_key = SecretKey.fromBytes(.{0x11} ** 32);
    const server_key = SecretKey.fromBytes(.{0x22} ** 32);
    const client_cid = try packet.ConnectionId.init(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });
    const server_cid = try packet.ConnectionId.init(&.{ 0x51, 0x52, 0x53, 0x54 });
    const initial_dcid = try packet.ConnectionId.init(&.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    const server_name = tls_name.serverName(server_key.public());

    const client = try Connection.create(allocator, .{
        .backend = backend,
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .server_name = &server_name,
    }, client_cid, initial_dcid, initial_dcid, testCsprngSeed(0xC0FFEE));
    errdefer client.destroy();

    const server = try Connection.create(allocator, .{
        .backend = backend,
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = client_key.public(),
        .require_client_authentication = true,
    }, server_cid, client_cid, initial_dcid, testCsprngSeed(0xBADC0DE));
    errdefer server.destroy();

    return .{
        .allocator = allocator,
        .client = client,
        .server = server,
        .link = link,
    };
}

test "pair establish + stream echo" {
    var p = try makePair(std.testing.allocator, .{});
    defer p.deinit();
    try p.establish(32);
    const sid = try p.client.openStream(.bidi);
    try p.client.writeStream(sid, "oracle-ctrl", true);
    var got = false;
    var rounds: usize = 0;
    while (rounds < 32) : (rounds += 1) {
        try p.drive(1);
        if (p.server.streamRecvFin(sid)) {
            try std.testing.expectEqualStrings("oracle-ctrl", p.server.streamRecvBytes(sid));
            try p.server.writeStream(sid, p.server.streamRecvBytes(sid), true);
            got = true;
            break;
        }
    }
    try std.testing.expect(got);
    rounds = 0;
    while (rounds < 32 and !p.client.streamRecvFin(sid)) : (rounds += 1) {
        try p.drive(1);
    }
    try std.testing.expectEqualStrings("oracle-ctrl", p.client.streamRecvBytes(sid));
}

test "pair link mtu drops oversized" {
    var p = try makePair(std.testing.allocator, .{ .mtu = 200 });
    defer p.deinit();
    // Direct route of a fake oversized payload through the link.
    const big = [_]u8{0xab} ** 500;
    try p.route(&big, true);
    try std.testing.expectEqual(@as(usize, 1), p.dropped_oversize);
    try std.testing.expectEqual(@as(usize, 0), p.delivered);
}
