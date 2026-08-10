//! In-memory loopback test transport for leaf protocol logic.
//!
//! Scope: a single connected pair sharing one bidirectional stream, modelled as
//! two one-shot directional byte buffers (write fully, then read). That is
//! enough to exercise request/response leaf logic (e.g. the blobs get protocol)
//! against the `transport` contract. It is NOT concurrent and NOT a real
//! transport — that is the connection-core track's job.
//!
//! The types below are concrete, not type-erased: leaves take the connection
//! and stream handles as `anytype`, so the method surface (`openBi`,
//! `acceptBi`, `openUni`, `acceptUni`, `remoteNodeId`, `alpn`, `remoteAddress`,
//! `close`, `io`, plus `writer`/`reader`/`finish`/`reset`/`stop` on streams) is
//! the whole contract they see.

const std = @import("std");
const transport = @import("../transport_contract.zig");
const key = @import("../key.zig");

/// One direction of bytes: an allocating sink plus a lazily-created reader
/// over what was written (one-shot: write completes before reading).
const Channel = struct {
    sink: std.Io.Writer.Allocating,
    reader_storage: std.Io.Reader = undefined,
    reader_ready: bool = false,
    send_finished: bool = false,
    send_reset: bool = false,
    send_reset_code: ?u64 = null,
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

pub const SendStream = struct {
    channel: *Channel,

    pub fn writer(self: SendStream) *std.Io.Writer {
        return &self.channel.sink.writer;
    }
    pub fn pendingFailure(_: SendStream) ?transport.Error {
        return null;
    }
    pub fn resetCode(self: SendStream) ?u64 {
        return self.channel.send_reset_code;
    }
    pub fn flush(_: SendStream) transport.Error!void {}
    pub fn finish(self: SendStream) transport.Error!void {
        self.channel.send_finished = true;
    }
    pub fn reset(self: SendStream) void {
        self.channel.send_reset = true;
    }
    /// Policy/abort path: RESET with an application error code (peer-visible).
    pub fn resetWithCode(self: SendStream, code: u64) void {
        self.channel.send_reset = true;
        self.channel.send_reset_code = code;
    }
};

pub const RecvStream = struct {
    channel: *Channel,

    pub fn reader(self: RecvStream) *std.Io.Reader {
        return self.channel.reader();
    }
    pub fn stop(self: RecvStream) transport.Error!void {
        self.channel.recv_stopped = true;
    }
    pub fn resetCode(_: RecvStream) ?u64 {
        return null;
    }
};

pub const BiStream = struct {
    send: SendStream,
    recv: RecvStream,
};

const ConnState = struct {
    send_ch: *Channel,
    recv_ch: *Channel,
    remote: key.NodeId,
    io_inst: std.Io,
};

pub const Connection = struct {
    state: *ConnState,

    pub fn openBi(self: Connection) transport.Error!BiStream {
        return .{
            .send = .{ .channel = self.state.send_ch },
            .recv = .{ .channel = self.state.recv_ch },
        };
    }
    /// The mock has exactly one bidirectional stream, so accept returns the
    /// same pair of channels open would.
    pub fn acceptBi(self: Connection) transport.Error!BiStream {
        return self.openBi();
    }
    pub fn openUni(self: Connection) transport.Error!SendStream {
        return .{ .channel = self.state.send_ch };
    }
    pub fn acceptUni(self: Connection) transport.Error!RecvStream {
        return .{ .channel = self.state.recv_ch };
    }
    pub fn remoteNodeId(self: Connection) key.NodeId {
        return self.state.remote;
    }
    pub fn alpn(_: Connection) ?[]const u8 {
        return null;
    }
    pub fn remoteAddress(_: Connection) ?std.Io.net.IpAddress {
        return null; // mock loopback has no socket address
    }
    pub fn close(_: Connection) void {}
    pub fn io(self: Connection) std.Io {
        return self.state.io_inst;
    }
    pub fn stats(_: Connection) transport.ConnectionStats {
        return .{};
    }
};

/// A connected pair of endpoints sharing one bidirectional stream.
/// `client` writes on `a2b` and reads on `b2a`; `server` is mirrored.
pub const Pair = struct {
    a2b: Channel,
    b2a: Channel,
    client_conn: ConnState,
    server_conn: ConnState,
    client_id: key.NodeId,
    server_id: key.NodeId,

    pub const Lifecycle = struct {
        client_send_finished: bool,
        client_send_reset: bool,
        client_send_reset_code: ?u64,
        client_recv_stopped: bool,
        server_send_finished: bool,
        server_send_reset: bool,
        server_send_reset_code: ?u64,
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

    pub fn client(self: *Pair) Connection {
        return .{ .state = &self.client_conn };
    }
    pub fn server(self: *Pair) Connection {
        return .{ .state = &self.server_conn };
    }

    pub fn lifecycle(self: *const Pair) Lifecycle {
        return .{
            .client_send_finished = self.a2b.send_finished,
            .client_send_reset = self.a2b.send_reset,
            .client_send_reset_code = self.a2b.send_reset_code,
            .client_recv_stopped = self.b2a.recv_stopped,
            .server_send_finished = self.b2a.send_finished,
            .server_send_reset = self.b2a.send_reset,
            .server_send_reset_code = self.b2a.send_reset_code,
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
