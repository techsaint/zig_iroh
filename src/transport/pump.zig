//! Batched UDP pump helpers for the greenfield transport endpoint.

const std = @import("std");
const c = @import("../connection/c.zig").c;

const net = std.Io.net;

pub const outgoing_batch_size = 8;
pub const incoming_batch_size = 8;
pub const incoming_datagram_size = 2048;

pub const wait_timeout: std.Io.Timeout = .{ .duration = .{
    .raw = .fromMilliseconds(1),
    .clock = .awake,
} };

pub const drain_timeout: std.Io.Timeout = .{ .duration = .{
    .raw = .fromNanoseconds(0),
    .clock = .awake,
} };

pub const OutgoingBatch = struct {
    packets: [outgoing_batch_size][c.PICOQUIC_MAX_PACKET_SIZE]u8 = undefined,
    destinations: [outgoing_batch_size]net.IpAddress = undefined,
    messages: [outgoing_batch_size]net.OutgoingMessage = undefined,
    count: usize = 0,

    pub fn isFull(self: *const OutgoingBatch) bool {
        return self.count == outgoing_batch_size;
    }

    pub fn append(self: *OutgoingBatch, destination: net.IpAddress, bytes: []const u8) void {
        std.debug.assert(self.count < outgoing_batch_size);
        std.debug.assert(bytes.len <= c.PICOQUIC_MAX_PACKET_SIZE);
        const index = self.count;
        self.destinations[index] = destination;
        @memcpy(self.packets[index][0..bytes.len], bytes);
        self.messages[index] = .{
            .address = &self.destinations[index],
            .data_ptr = self.packets[index][0..bytes.len].ptr,
            .data_len = bytes.len,
        };
        self.count += 1;
    }

    pub fn slice(self: *OutgoingBatch) []net.OutgoingMessage {
        return self.messages[0..self.count];
    }
};

pub const IncomingBatch = struct {
    messages: [incoming_batch_size]net.IncomingMessage = undefined,
    data: [incoming_batch_size * incoming_datagram_size]u8 = undefined,

    pub fn init(self: *IncomingBatch) void {
        for (&self.messages) |*message| message.* = net.IncomingMessage.init;
    }
};
