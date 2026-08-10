//! Stream state types + Send/Recv handle impls for the greenfield single-owner
//! transport endpoint (design §2.2 layout). The endpoint's event loop owns
//! these structs; the vtable adapters here are thin command submitters onto
//! the loop's inbox (see endpoint.zig for the loop + Command/Completion).

const std = @import("std");
const tr = @import("transport");
const c = @import("../connection/c.zig").c;
const endpoint_mod = @import("endpoint.zig");

const Endpoint = endpoint_mod.Endpoint;
const Command = endpoint_mod.Command;
const Completion = endpoint_mod.Completion;
const submit = endpoint_mod.submit;
const VoidResult = endpoint_mod.VoidResult;
const RecvFill = endpoint_mod.RecvFill;

/// Per-stream receive queue: a deque of byte chunks (one engine->chunk copy
/// per callback event, then no further copies). The reader consumes from the
/// head; `takeInto` advances and frees whole chunks. Bounded in-flight bytes
/// are enforced by the sliding flow-control window (the endpoint opens credit
/// as the reader consumes), not by this queue.
pub const RecvQueue = struct {
    chunks: std.ArrayListUnmanaged([]u8) = .empty,
    /// Index of the first live chunk in `chunks` (popped prefix is dropped
    /// lazily, in bulk — pops are O(1) amortized, not O(n) memmoves).
    head_index: usize = 0,
    head_offset: usize = 0,
    buffered: usize = 0,
    consumed_total: u64 = 0,

    const compact_threshold = 64;

    pub fn append(self: *RecvQueue, allocator: std.mem.Allocator, bytes: []const u8) !void {
        if (bytes.len == 0) return;
        const copy = try allocator.dupe(u8, bytes);
        errdefer allocator.free(copy);
        try self.chunks.append(allocator, copy);
        self.buffered += bytes.len;
    }

    /// Copy and consume up to `dest.len` bytes, then compact dead queue heads.
    /// This is the same primitive as `takeInto`; the neutral poll adapter uses
    /// it directly so transport ownership and flow-control accounting stay here.
    pub fn takeSomeInto(self: *RecvQueue, allocator: std.mem.Allocator, dest: []u8) usize {
        return self.takeInto(allocator, dest);
    }

    /// Copy up to `dest.len` unconsumed bytes into `dest` and consume them.
    /// Returns the number of bytes copied.
    pub fn takeInto(self: *RecvQueue, allocator: std.mem.Allocator, dest: []u8) usize {
        var copied: usize = 0;
        while (copied < dest.len and self.head_index < self.chunks.items.len) {
            const chunk = self.chunks.items[self.head_index];
            const avail = chunk[self.head_offset..];
            const n = @min(avail.len, dest.len - copied);
            @memcpy(dest[copied..][0..n], avail[0..n]);
            copied += n;
            self.head_offset += n;
            self.buffered -= n;
            self.consumed_total += n;
            if (self.head_offset == chunk.len) {
                allocator.free(chunk);
                self.head_index += 1;
                self.head_offset = 0;
            }
        }
        if (self.head_index >= compact_threshold) self.compact(allocator);
        return copied;
    }

    fn compact(self: *RecvQueue, allocator: std.mem.Allocator) void {
        _ = allocator;
        const keep = self.chunks.items[self.head_index..];
        std.mem.copyForwards([]u8, self.chunks.items[0..keep.len], keep);
        self.chunks.items.len = keep.len;
        self.head_index = 0;
    }

    pub fn deinit(self: *RecvQueue, allocator: std.mem.Allocator) void {
        for (self.chunks.items[self.head_index..]) |chunk| allocator.free(chunk);
        self.chunks.deinit(allocator);
        self.* = .{};
    }
};

pub const StreamState = struct {
    cnx: ?*c.picoquic_cnx_t = null,
    id: u64 = 0,
    used: bool = false,
    fin: bool = false,
    reset: bool = false,
    send_stopped: bool = false,
    handed_off: bool = false,
    recvq: RecvQueue = .{},
};

/// Release the recv queue and clear the slot. Called only from
/// `Endpoint.deinit` (reclaim marks `used = false` without freeing — a reader
/// may still be borrowing from a RecvImpl staged buffer).
pub fn reset(slot: *StreamState, allocator: std.mem.Allocator) void {
    slot.recvq.deinit(allocator);
    slot.* = .{};
}

// =============================================================================
// Send handle
// =============================================================================

pub const SendImpl = struct {
    /// Tombstone: written by the loop (finish/reset/reclaim), read by caller
    /// threads in the vtable adapters. Atomic — the loop and callers are
    /// concurrent; monotonic suffices (the completion handshake orders the
    /// rest).
    used: std.atomic.Value(bool) = .init(true),
    endpoint: *Endpoint,
    cnx: *c.picoquic_cnx_t,
    stream_id: u64,
    /// The caller-facing byte sink: a small fixed staging buffer. `drain`
    /// hands staged + caller slices to the loop as send-bytes commands
    /// (borrowed slices — no intermediate re-buffering).
    writer_storage: std.Io.Writer = undefined,
    writer_buffer: [send_buffer_len]u8 = undefined,
    dead_writer: std.Io.Writer = std.Io.Writer.fixed(&.{}),

    pub fn pubWriter(self: *SendImpl) *std.Io.Writer {
        if (!self.used.load(.monotonic)) return &self.dead_writer;
        return &self.writer_storage;
    }
    pub fn pubFlush(self: *SendImpl) tr.Error!void {
        if (!self.used.load(.monotonic)) return error.NotConnected;
        self.writer_storage.flush() catch return error.ConnectionLost;
    }
    pub fn pubFinish(self: *SendImpl) tr.Error!void {
        if (!self.used.load(.monotonic)) return;
        const flush_err: ?tr.Error = blk: {
            self.writer_storage.flush() catch break :blk error.ConnectionLost;
            break :blk null;
        };
        var completion: Completion(VoidResult) = .{};
        var node: Command.Node = .{ .command = undefined };
        submit(self.endpoint, .{ .send_fin = .{ .send = self, .completion = &completion } }, &node);
        const fin_err = completion.awaitResult(self.endpoint.io_inst);
        if (fin_err) |_| {} else |err| return err;
        if (flush_err) |err| return err;
    }
    pub fn pubReset(self: *SendImpl) void {
        self.pubResetWithCode(0);
    }
    /// RESET_STREAM with application error code (peer-visible on the wire).
    pub fn pubResetWithCode(self: *SendImpl, code: u64) void {
        var completion: Completion(void) = .{};
        var node: Command.Node = .{ .command = undefined };
        submit(self.endpoint, .{ .send_reset = .{ .send = self, .code = code, .completion = &completion } }, &node);
        completion.awaitResult(self.endpoint.io_inst);
    }
    pub fn pubPendingFailure(_: *SendImpl) ?tr.Error {
        return null;
    }
    pub fn pubResetCode(_: *SendImpl) ?u64 {
        return null;
    }
};

pub const send_buffer_len = 16 * 1024;
/// Largest slice handed to the loop per send-bytes command (bounds the
/// caller-borrowed in-flight bytes and the loop's per-command work).
pub const send_command_chunk_max = 1024 * 1024;

/// The send sink's drain: hand staged + caller slices to the loop as
/// send-bytes commands (borrowed slices — the caller is blocked on each
/// command, so the loop reads them safely; no intermediate re-buffering).
fn sendWriterDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    const send: *SendImpl = @alignCast(@fieldParentPtr("writer_storage", w));
    if (!send.used.load(.monotonic)) return error.WriteFailed;
    if (w.end > 0) {
        try submitSendBytes(send, w.buffer[0..w.end]);
        w.end = 0;
    }
    var consumed: usize = 0;
    for (data[0 .. data.len - 1]) |bytes| {
        try submitSendBytesChunked(send, bytes);
        consumed += bytes.len;
    }
    const pattern = data[data.len - 1];
    var repeat: usize = 0;
    while (repeat < splat) : (repeat += 1) {
        try submitSendBytesChunked(send, pattern);
        consumed += pattern.len;
    }
    return consumed;
}

fn submitSendBytesChunked(send: *SendImpl, bytes: []const u8) std.Io.Writer.Error!void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const chunk = bytes[offset..@min(offset + send_command_chunk_max, bytes.len)];
        try submitSendBytes(send, chunk);
        offset += chunk.len;
    }
}

fn submitSendBytes(send: *SendImpl, data: []const u8) std.Io.Writer.Error!void {
    if (data.len == 0) return;
    var completion: Completion(VoidResult) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(send.endpoint, .{ .send_bytes = .{ .send = send, .data = data, .completion = &completion } }, &node);
    completion.awaitResult(send.endpoint.io_inst) catch return error.WriteFailed;
}

fn sendWriterRebase(w: *std.Io.Writer, preserve: usize, minimum_len: usize) std.Io.Writer.Error!void {
    // `defaultRebase` asserts when a caller requests more contiguous writable
    // capacity than a fixed buffer provides. Preserve standard Writer error
    // semantics instead (same escape hatch as the noq backend).
    if (minimum_len > w.buffer.len -| preserve) return error.WriteFailed;
    return std.Io.Writer.defaultRebase(w, preserve, minimum_len);
}

pub const send_writer_vtable: std.Io.Writer.VTable = .{
    .drain = sendWriterDrain,
    .rebase = sendWriterRebase,
};

// =============================================================================
// Recv handle
// =============================================================================

pub const RecvImpl = struct {
    /// Tombstone / stop flags: loop-written, caller-read (see SendImpl.used).
    used: std.atomic.Value(bool) = .init(true),
    stopped: std.atomic.Value(bool) = .init(false),
    endpoint: *Endpoint,
    cnx: *c.picoquic_cnx_t,
    stream_id: u64,
    reader_storage: std.Io.Reader = undefined,
    reader_buffer: [recv_buffer_len]u8 = undefined,
    ready: bool = false,
    dead_reader: std.Io.Reader = std.Io.Reader.fixed(&.{}),

    pub fn pubReader(self: *RecvImpl) *std.Io.Reader {
        if (!self.used.load(.monotonic) or self.stopped.load(.monotonic)) return &self.dead_reader;
        if (!self.ready) {
            self.reader_storage = .{
                .vtable = &recv_reader_vtable,
                .buffer = self.reader_buffer[0..],
                .seek = 0,
                .end = 0,
            };
            self.ready = true;
        }
        return &self.reader_storage;
    }
    pub fn pubStop(self: *RecvImpl) tr.Error!void {
        var completion: Completion(VoidResult) = .{};
        var node: Command.Node = .{ .command = undefined };
        submit(self.endpoint, .{ .recv_stop = .{ .recv = self, .completion = &completion } }, &node);
        return completion.awaitResult(self.endpoint.io_inst);
    }
    pub fn pubResetCode(_: *RecvImpl) ?u64 {
        return null;
    }
};

pub const recv_buffer_len = 16 * 1024;

/// The incremental reader's refill: wait on the loop to copy the next chunk
/// of stream data into the caller's own destination (or EOF / degraded).
/// Never blocks the loop; never FIN-gates — data flows as it arrives.
fn recvStreamFill(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    const recv: *RecvImpl = @alignCast(@fieldParentPtr("reader_storage", r));
    if (!recv.used.load(.monotonic) or recv.stopped.load(.monotonic)) return error.EndOfStream;
    // writableSliceGreedy flushes the destination to guarantee capacity —
    // without it a full writer would see 0 forever (std consumer loops
    // livelock). Same idiom as the noq backend.
    const dest = limit.slice(try w.writableSliceGreedy(1));
    var completion: Completion(RecvFill) = .{};
    var node: Command.Node = .{ .command = undefined };
    submit(recv.endpoint, .{ .recv_read = .{ .recv = recv, .dest = dest, .completion = &completion } }, &node);
    const fill = completion.awaitResult(recv.endpoint.io_inst);
    switch (fill) {
        .data => |n| {
            // The loop copied n bytes into dest (visible after the completion).
            w.advance(n);
            return n;
        },
        .eof, .degraded => return error.EndOfStream,
    }
}

const recv_reader_vtable: std.Io.Reader.VTable = .{
    .stream = recvStreamFill,
};
