//! In-memory loopback `Transport` for testing leaves before the real
//! connection core (Tier-2) lands.
//!
//! Scope: a single connected pair sharing one bidirectional stream, modelled as
//! two one-shot directional byte buffers (write fully, then read). That is
//! enough to exercise request/response leaf logic (e.g. the blobs get protocol)
//! against the frozen `transport` contract. It is NOT concurrent and NOT a real
//! transport — that is the connection-core track's job.

const std = @import("std");
const transport = @import("../transport.zig");
const key = @import("../key.zig");

/// One direction of bytes: an allocating sink plus a lazily-created reader
/// over what was written (one-shot: write completes before reading).
const Channel = struct {
    sink: std.Io.Writer.Allocating,
    reader_storage: std.Io.Reader = undefined,
    reader_ready: bool = false,
    send_finished: bool = false,
    send_reset: bool = false,
    recv_stopped: bool = false,

    fn init(allocator: std.mem.Allocator) Channel {
        return .{ .sink = std.Io.Writer.Allocating.init(allocator) };
    }
    fn deinit(self: *Channel) void {
        self.sink.deinit();
    }
    fn reader(self: *Channel) *std.Io.Reader {
        if (!self.reader_ready) {
            self.reader_storage = std.Io.Reader.fixed(self.sink.written());
            self.reader_ready = true;
        }
        return &self.reader_storage;
    }
};

// --- SendStream impl (over a *Channel we write into) ---

fn sendWriter(ctx: *anyopaque) *std.Io.Writer {
    const ch: *Channel = @ptrCast(@alignCast(ctx));
    return &ch.sink.writer;
}
fn sendFinish(ctx: *anyopaque) transport.Error!void {
    const ch: *Channel = @ptrCast(@alignCast(ctx));
    ch.send_finished = true;
}
fn sendFlush(ctx: *anyopaque) transport.Error!void {
    _ = ctx;
}
fn sendReset(ctx: *anyopaque) void {
    const ch: *Channel = @ptrCast(@alignCast(ctx));
    ch.send_reset = true;
}
const send_vtable: transport.SendStream.VTable = .{
    .writer = sendWriter,
    .flush = sendFlush,
    .finish = sendFinish,
    .reset = sendReset,
};

// --- RecvStream impl (over a *Channel we read from) ---

fn recvReader(ctx: *anyopaque) *std.Io.Reader {
    const ch: *Channel = @ptrCast(@alignCast(ctx));
    return ch.reader();
}
fn recvStop(ctx: *anyopaque) transport.Error!void {
    const ch: *Channel = @ptrCast(@alignCast(ctx));
    ch.recv_stopped = true;
}
const recv_vtable: transport.RecvStream.VTable = .{ .reader = recvReader, .stop = recvStop };

// --- Connection impl ---

const ConnImpl = struct {
    send_ch: *Channel,
    recv_ch: *Channel,
    remote: key.NodeId,
    io_inst: std.Io,
};

fn connOpenBi(ctx: *anyopaque) transport.Error!transport.BiStream {
    const c: *ConnImpl = @ptrCast(@alignCast(ctx));
    return .{
        .send = .{ .context = c.send_ch, .vtable = &send_vtable },
        .recv = .{ .context = c.recv_ch, .vtable = &recv_vtable },
    };
}
fn connOpenUni(ctx: *anyopaque) transport.Error!transport.SendStream {
    const c: *ConnImpl = @ptrCast(@alignCast(ctx));
    return .{ .context = c.send_ch, .vtable = &send_vtable };
}
fn connAcceptUni(ctx: *anyopaque) transport.Error!transport.RecvStream {
    const c: *ConnImpl = @ptrCast(@alignCast(ctx));
    return .{ .context = c.recv_ch, .vtable = &recv_vtable };
}
fn connRemote(ctx: *anyopaque) key.NodeId {
    const c: *ConnImpl = @ptrCast(@alignCast(ctx));
    return c.remote;
}
fn connAlpn(ctx: *anyopaque) ?[]const u8 {
    _ = ctx;
    return null;
}
fn connRemoteAddress(ctx: *anyopaque) ?std.Io.net.IpAddress {
    _ = ctx;
    return null; // mock loopback has no socket address
}
fn connClose(ctx: *anyopaque) void {
    _ = ctx;
}
fn connIo(ctx: *anyopaque) std.Io {
    const c: *ConnImpl = @ptrCast(@alignCast(ctx));
    return c.io_inst;
}
const conn_vtable: transport.Connection.VTable = .{
    .openBi = connOpenBi,
    .acceptBi = connOpenBi, // mock: one shared bi stream
    .openUni = connOpenUni,
    .acceptUni = connAcceptUni,
    .remoteNodeId = connRemote,
    .alpn = connAlpn,
    .remoteAddress = connRemoteAddress,
    .close = connClose,
    .io = connIo,
};

/// A connected pair of endpoints sharing one bidirectional stream.
/// `client` writes on `a2b` and reads on `b2a`; `server` is mirrored.
pub const Pair = struct {
    a2b: Channel,
    b2a: Channel,
    client_conn: ConnImpl,
    server_conn: ConnImpl,
    client_id: key.NodeId,
    server_id: key.NodeId,

    pub const Lifecycle = struct {
        client_send_finished: bool,
        client_send_reset: bool,
        client_recv_stopped: bool,
        server_send_finished: bool,
        server_send_reset: bool,
        server_recv_stopped: bool,
    };

    pub fn init(allocator: std.mem.Allocator, io_inst: std.Io, client_id: key.NodeId, server_id: key.NodeId) *Pair {
        const self = allocator.create(Pair) catch @panic("OOM");
        self.* = .{
            .a2b = Channel.init(allocator),
            .b2a = Channel.init(allocator),
            .client_conn = undefined,
            .server_conn = undefined,
            .client_id = client_id,
            .server_id = server_id,
        };
        self.client_conn = .{ .send_ch = &self.a2b, .recv_ch = &self.b2a, .remote = server_id, .io_inst = io_inst };
        self.server_conn = .{ .send_ch = &self.b2a, .recv_ch = &self.a2b, .remote = client_id, .io_inst = io_inst };
        return self;
    }

    pub fn deinit(self: *Pair, allocator: std.mem.Allocator) void {
        self.a2b.deinit();
        self.b2a.deinit();
        allocator.destroy(self);
    }

    pub fn client(self: *Pair) transport.Connection {
        return .{ .context = &self.client_conn, .vtable = &conn_vtable };
    }
    pub fn server(self: *Pair) transport.Connection {
        return .{ .context = &self.server_conn, .vtable = &conn_vtable };
    }

    pub fn lifecycle(self: *const Pair) Lifecycle {
        return .{
            .client_send_finished = self.a2b.send_finished,
            .client_send_reset = self.a2b.send_reset,
            .client_recv_stopped = self.b2a.recv_stopped,
            .server_send_finished = self.b2a.send_finished,
            .server_send_reset = self.b2a.send_reset,
            .server_recv_stopped = self.a2b.recv_stopped,
        };
    }
};

// --- tests (C-3 invariants) ---

const testing = std.testing;

fn testId(seed_byte: u8) key.NodeId {
    return key.SecretKey.fromBytes(.{seed_byte} ** 32).public();
}

test "C3-i1/i2: bytes written on a SendStream read back on the paired RecvStream" {
    const alloc = testing.allocator;
    const client_id = testId(1);
    const server_id = testId(2);

    const pair = Pair.init(alloc, testing.io, client_id, server_id);
    defer pair.deinit(alloc);

    const client = pair.client();
    const server = pair.server();

    // remote ids are wired correctly (C3-i2: the two endpoints know each other)
    try testing.expect(client.remoteNodeId().eql(server_id));
    try testing.expect(server.remoteNodeId().eql(client_id));

    // client opens a stream and writes a request
    const c = try client.openBi();
    try c.send.writer().writeAll("ping");
    try c.send.finish();

    // server accepts the stream and reads the request verbatim (C3-i1)
    const s = try server.acceptBi();
    var buf: [16]u8 = undefined;
    const n = try s.recv.reader().readSliceShort(&buf);
    try testing.expectEqualStrings("ping", buf[0..n]);

    // server replies; client reads it back
    try s.send.writer().writeAll("pong");
    try s.send.finish();
    var buf2: [16]u8 = undefined;
    const m = try c.recv.reader().readSliceShort(&buf2);
    try testing.expectEqualStrings("pong", buf2[0..m]);
}

fn addOne(x: usize) usize {
    return x + 1;
}

test "Connection.io() exposes a usable std.Io (the tokio-runtime replacement)" {
    const alloc = testing.allocator;
    const pair = Pair.init(alloc, testing.io, testId(1), testId(2));
    defer pair.deinit(alloc);

    // A leaf can reach the runtime and launch concurrency through it.
    const io = pair.client().io();
    var fut = io.async(addOne, .{@as(usize, 41)});
    try testing.expectEqual(@as(usize, 42), fut.await(io));
}

test "unidirectional stream: client openUni -> server acceptUni" {
    const alloc = testing.allocator;
    const pair = Pair.init(alloc, testing.io, testId(3), testId(4));
    defer pair.deinit(alloc);

    const send = try pair.client().openUni();
    try send.writer().writeAll("uni!");
    try send.finish();

    const recv = try pair.server().acceptUni();
    var buf: [8]u8 = undefined;
    const n = try recv.reader().readSliceShort(&buf);
    try testing.expectEqualStrings("uni!", buf[0..n]);
}
