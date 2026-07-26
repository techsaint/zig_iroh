//! The transport contract — the stable seam every leaf codes against.
//!
//! This is the seam the port owns (the analog of iroh's `Endpoint` API). Leaves
//! (blobs, gossip) consume `Connection` / `BiStream` and never reference a
//! concrete transport. The connection-core track (Tier-2) provides the real
//! implementation (ngtcp2 + magicsock); `transport/mock.zig` provides an
//! in-memory loopback for testing leaves before that lands.
//!
//! Interfaces are vtable-based (the std.Io.Reader/Writer pattern), so async
//! lives entirely on the implementation side — no function coloring crosses
//! this seam (per the Zig 0.16 `std.Io` model).
//!
//! Async runtime: iroh runs on tokio; the Zig port's equivalent is **`std.Io`**
//! (`Io.Threaded` for correctness, `Io.Evented`/io_uring for the perf upside —
//! plan Q-B). The convention here:
//!   - A concrete endpoint **captures a `std.Io` at construction** (the tokio
//!     handle equivalent) — construction is impl-specific, not in these vtables,
//!     so dial/accept/openBi take no `io` parameter.
//!   - Byte I/O flows through each stream's `std.Io.Reader`/`Writer`, which
//!     captured the `io` when created — leaves never thread `io` to read/write.
//!   - `Transport.io()` / `Connection.io()` expose that `std.Io` for leaves that
//!     need to launch their own concurrency (`io.async`, `Io.Group`, …).
//!
//! FROZEN at the Tier-0 freeze; re-frozen 2026-07-17 with
//! `SendStream.flush()` and `RecvStream.stop()`. Amended 2026-07-25
//! (port-00-core wire-neutral): `Connection.alpn()` surfaces the TLS-negotiated
//! ALPN already known internally — zero wire-byte change. Change only via
//! amendment to `plans/port-00-core/` with a migration note.

const std = @import("std");
const product_flags = @import("product_flags.zig");
const key = @import("key.zig");
const addr = @import("addr.zig");

pub const NodeId = key.NodeId;
pub const EndpointAddr = addr.EndpointAddr;
pub const NodeAddr = addr.NodeAddr;
pub const TransportAddr = addr.TransportAddr;
pub const RelayUrl = addr.RelayUrl;
pub const CustomAddr = addr.CustomAddr;

pub const Error = error{
    /// The connection is gone (peer closed, reset, or transport failure).
    ConnectionLost,
    /// The stream was reset by the peer.
    StreamReset,
    /// Operation timed out.
    Timeout,
    /// No connection / not connected.
    NotConnected,
    /// Allocation failed.
    OutOfMemory,
};

/// The writable half of a bidirectional stream.
pub const SendStream = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        writer: *const fn (*anyopaque) *std.Io.Writer,
        flush: *const fn (*anyopaque) Error!void,
        finish: *const fn (*anyopaque) Error!void,
        reset: *const fn (*anyopaque) void,
    };

    /// The byte sink. Callers use the standard `std.Io.Writer` API.
    pub fn writer(self: SendStream) *std.Io.Writer {
        return self.vtable.writer(self.context);
    }
    /// Flush buffered bytes without ending the stream.
    pub fn flush(self: SendStream) Error!void {
        return self.vtable.flush(self.context);
    }
    /// Signal clean end-of-stream (flush + FIN).
    pub fn finish(self: SendStream) Error!void {
        return self.vtable.finish(self.context);
    }
    /// Abort the stream.
    pub fn reset(self: SendStream) void {
        self.vtable.reset(self.context);
    }
};

/// The readable half of a bidirectional stream.
pub const RecvStream = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        reader: *const fn (*anyopaque) *std.Io.Reader,
        stop: *const fn (*anyopaque) Error!void,
    };

    /// The byte source. Callers use the standard `std.Io.Reader` API.
    pub fn reader(self: RecvStream) *std.Io.Reader {
        return self.vtable.reader(self.context);
    }
    /// Stop accepting data and request that the peer stop sending.
    pub fn stop(self: RecvStream) Error!void {
        return self.vtable.stop(self.context);
    }
};

pub const BiStream = struct {
    send: SendStream,
    recv: RecvStream,
};

/// An established connection to a single peer.
pub const Connection = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        openBi: *const fn (*anyopaque) Error!BiStream,
        acceptBi: *const fn (*anyopaque) Error!BiStream,
        openUni: *const fn (*anyopaque) Error!SendStream,
        acceptUni: *const fn (*anyopaque) Error!RecvStream,
        remoteNodeId: *const fn (*anyopaque) NodeId,
        /// TLS-negotiated ALPN bytes, or null if none was selected. Borrowed
        /// from the connection impl; valid until `close()` / endpoint deinit.
        alpn: *const fn (*anyopaque) ?[]const u8,
        close: *const fn (*anyopaque) void,
        io: *const fn (*anyopaque) std.Io,
    };

    /// Open a new bidirectional stream we initiate.
    pub fn openBi(self: Connection) Error!BiStream {
        return self.vtable.openBi(self.context);
    }
    /// Accept the next bidirectional stream the peer opened.
    pub fn acceptBi(self: Connection) Error!BiStream {
        return self.vtable.acceptBi(self.context);
    }
    /// Open a unidirectional stream we send on (iroh-gossip uses these).
    pub fn openUni(self: Connection) Error!SendStream {
        return self.vtable.openUni(self.context);
    }
    /// Accept the next unidirectional stream the peer opened (read side).
    pub fn acceptUni(self: Connection) Error!RecvStream {
        return self.vtable.acceptUni(self.context);
    }
    pub fn remoteNodeId(self: Connection) NodeId {
        return self.vtable.remoteNodeId(self.context);
    }
    /// The ALPN selected during the TLS handshake for this connection.
    /// Wire-neutral accessor (the bytes were already negotiated on the wire).
    pub fn alpn(self: Connection) ?[]const u8 {
        return self.vtable.alpn(self.context);
    }
    pub fn close(self: Connection) void {
        self.vtable.close(self.context);
    }
    /// The `std.Io` this connection's endpoint runs on (tokio-handle
    /// equivalent). For leaves that launch their own concurrency.
    pub fn io(self: Connection) std.Io {
        return self.vtable.io(self.context);
    }
};

/// An endpoint that can dial peers and accept incoming connections.
pub const Transport = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        connect: *const fn (*anyopaque, NodeAddr) Error!Connection,
        accept: *const fn (*anyopaque) Error!Connection,
        localNodeId: *const fn (*anyopaque) NodeId,
        io: *const fn (*anyopaque) std.Io,
    };

    /// Dial a peer.
    pub fn connect(self: Transport, peer: NodeAddr) Error!Connection {
        return self.vtable.connect(self.context, peer);
    }
    /// Accept the next incoming connection.
    pub fn accept(self: Transport) Error!Connection {
        return self.vtable.accept(self.context);
    }
    pub fn localNodeId(self: Transport) NodeId {
        return self.vtable.localNodeId(self.context);
    }
    /// The `std.Io` this endpoint runs on (tokio-handle equivalent).
    pub fn io(self: Transport) std.Io {
        return self.vtable.io(self.context);
    }
};

test {
    _ = @import("transport/mock.zig");
    if (product_flags.has_picoquic) _ = @import("transport/endpoint.zig");
    if (product_flags.has_noq) _ = @import("transport/transport_noq.zig");
    if (product_flags.has_noq) _ = @import("transport/udp_cmsg.zig");
    _ = @import("transport/factory.zig");
    if (product_flags.has_noq) _ = @import("transport/noq_gate.zig");
    if (comptime @import("quic/crypto.zig").zigtls_enabled) {
        _ = @import("transport/noq_zigtls_gate.zig");
    }
}
