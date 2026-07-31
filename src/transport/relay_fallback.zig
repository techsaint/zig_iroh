//! Relay fallback datagram adapter for the greenfield picoquic endpoint.
//!
//! The public Endpoint owns the DERP/WebSocket home relay. G2 only needs a
//! small, transport-neutral datagram handle: send QUIC packets to a peer NodeId
//! and poll already-received relay datagrams back into picoquic.

const key = @import("../key.zig");
const tr = @import("../transport.zig");

pub const Datagram = struct {
    src: key.NodeId,
    data: []u8,
};

pub const Client = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (*anyopaque, key.NodeId, []const u8) tr.Error!void,
        recv: *const fn (*anyopaque, []u8) tr.Error!?Datagram,
    };

    pub fn send(self: Client, dst: key.NodeId, data: []const u8) tr.Error!void {
        return self.vtable.send(self.context, dst, data);
    }

    pub fn recv(self: Client, buffer: []u8) tr.Error!?Datagram {
        return self.vtable.recv(self.context, buffer);
    }
};

pub const Disabled = struct {
    pub fn init() Disabled {
        return .{};
    }

    pub fn available(_: Disabled) bool {
        return false;
    }
};
