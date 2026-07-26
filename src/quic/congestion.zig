//! Congestion controller vtable + factories (N3b-4).
//!
//! Mirrors noq `congestion.rs` Controller seam. All three controllers
//! (NewReno, Cubic, BBR3) live behind one interface.

const std = @import("std");
const new_reno = @import("congestion/new_reno.zig");
const cubic = @import("congestion/cubic.zig");
const bbr3 = @import("congestion/bbr3.zig");

pub const base_datagram_size: u64 = 1200;
pub const Instant = i64; // ns

pub const RttSample = struct {
    latest_ns: i64,
    smoothed_ns: i64,
    min_ns: i64,
    var_ns: i64,

    pub fn get(self: RttSample) i64 {
        return self.smoothed_ns;
    }
    pub fn conservative(self: RttSample) i64 {
        return @max(self.smoothed_ns, self.latest_ns);
    }
};

/// Full Controller seam (noq congestion.rs) — a no-op that only exposes `window()`
/// must fail BBR3 conformance tests that exercise state transitions + pacing.
pub const Controller = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        on_sent: *const fn (ptr: *anyopaque, now: Instant, bytes: u64, largest_pn: u64) void,
        on_packet_sent: *const fn (ptr: *anyopaque, now: Instant, bytes: u16, pn: u64) void,
        on_ack: *const fn (ptr: *anyopaque, now: Instant, sent: Instant, bytes: u64, pn: u64, app_limited: bool, rtt: RttSample) void,
        on_end_acks: *const fn (ptr: *anyopaque, now: Instant, in_flight: u64, app_limited: bool, largest_acked: ?u64) void,
        on_congestion_event: *const fn (ptr: *anyopaque, now: Instant, sent: Instant, is_persistent: bool, is_ecn: bool, lost_bytes: u64, largest_lost_pn: u64) void,
        on_packet_lost: *const fn (ptr: *anyopaque, lost_bytes: u16, pn: u64, now: Instant) void,
        on_spurious_congestion_event: *const fn (ptr: *anyopaque) void,
        on_mtu_update: *const fn (ptr: *anyopaque, new_mtu: u16) void,
        window: *const fn (ptr: *anyopaque) u64,
        pacing_rate: *const fn (ptr: *anyopaque) ?u64,
        send_quantum: *const fn (ptr: *anyopaque) ?u64,
        destroy: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) void,
    };

    pub fn onSent(self: Controller, now: Instant, bytes: u64, largest_pn: u64) void {
        self.vtable.on_sent(self.ptr, now, bytes, largest_pn);
    }
    pub fn onPacketSent(self: Controller, now: Instant, bytes: u16, pn: u64) void {
        self.vtable.on_packet_sent(self.ptr, now, bytes, pn);
    }
    pub fn onAck(self: Controller, now: Instant, sent: Instant, bytes: u64, pn: u64, app_limited: bool, rtt: RttSample) void {
        self.vtable.on_ack(self.ptr, now, sent, bytes, pn, app_limited, rtt);
    }
    pub fn onEndAcks(self: Controller, now: Instant, in_flight: u64, app_limited: bool, largest_acked: ?u64) void {
        self.vtable.on_end_acks(self.ptr, now, in_flight, app_limited, largest_acked);
    }
    pub fn onCongestionEvent(self: Controller, now: Instant, sent: Instant, is_persistent: bool, is_ecn: bool, lost_bytes: u64, largest_lost_pn: u64) void {
        self.vtable.on_congestion_event(self.ptr, now, sent, is_persistent, is_ecn, lost_bytes, largest_lost_pn);
    }
    pub fn onPacketLost(self: Controller, lost_bytes: u16, pn: u64, now: Instant) void {
        self.vtable.on_packet_lost(self.ptr, lost_bytes, pn, now);
    }
    pub fn onSpuriousCongestionEvent(self: Controller) void {
        self.vtable.on_spurious_congestion_event(self.ptr);
    }
    pub fn onMtuUpdate(self: Controller, new_mtu: u16) void {
        self.vtable.on_mtu_update(self.ptr, new_mtu);
    }
    pub fn window(self: Controller) u64 {
        return self.vtable.window(self.ptr);
    }
    pub fn pacingRate(self: Controller) ?u64 {
        return self.vtable.pacing_rate(self.ptr);
    }
    pub fn sendQuantum(self: Controller) ?u64 {
        return self.vtable.send_quantum(self.ptr);
    }
    pub fn destroy(self: Controller, allocator: std.mem.Allocator) void {
        self.vtable.destroy(self.ptr, allocator);
    }
};

pub const Kind = enum { new_reno, cubic, bbr3 };

pub fn create(allocator: std.mem.Allocator, kind: Kind, now: Instant, mtu: u16) !Controller {
    return switch (kind) {
        .new_reno => try new_reno.create(allocator, now, mtu),
        .cubic => try cubic.create(allocator, now, mtu),
        .bbr3 => try bbr3.create(allocator, now, mtu),
    };
}

test {
    _ = new_reno;
    _ = cubic;
    _ = bbr3;
}
