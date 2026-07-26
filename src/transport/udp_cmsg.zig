//! Linux UDP ancillary-data (cmsg) plumbing for the noq socket path.
//!
//! Two capabilities live here, both of which are *socket ABI*, not protocol:
//!
//!   * **ECN** — stamping the RFC 3168 codepoint on an outgoing IP header
//!     (`IP_TOS` / `IPV6_TCLASS`) and reading the codepoint back off an
//!     inbound datagram (`IP_RECVTOS` / `IPV6_RECVTCLASS`). The protocol layer
//!     (`quic/connection.zig`) is sans-io and deals only in the two ECN bits;
//!     this module is the only place that knows how the kernel spells them.
//!   * **GSO** — the `UDP_SEGMENT` control message that lets one `sendmsg`
//!     hand the kernel a run of equally-sized datagrams.
//!
//! ## The payload-width rule (a real, kernel-enforced ABI constraint)
//!
//! `IP_TOS` and `IPV6_TCLASS` cmsg payloads are a **4-byte `c_int`**, NOT a
//! 1-byte `u8`. The reference implementation types this explicitly
//! (`original/noq/noq-udp/src/unix.rs:37-40`, `IpTosTy = libc::c_int` on every
//! platform except FreeBSD) and pushes a `c_int` for both option types
//! (`unix.rs:741,:745`). Empirically on Linux a 1-byte `IPV6_TCLASS` payload is
//! rejected with `EINVAL`; `IP_TOS` happens to be forgiving of both widths,
//! which makes a too-narrow payload a *latent* bug that only bites on v6.
//! `ecn_payload_size` below is the single place that width is decided, and
//! `@sizeOf(c_int)` is asserted at comptime so a hostile target cannot make it
//! silently narrow.
//!
//! `UDP_SEGMENT` is a separate ABI: its payload is a `u16` (the kernel reads
//! `*(__u16 *)CMSG_DATA(cmsg)`), matching `unix.rs:1063-1068`.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const is_supported = builtin.os.tag == .linux;

/// RFC 3168 ECN codepoints, as carried in the low two bits of the IPv4 TOS /
/// IPv6 traffic-class octet. Values are the wire bit patterns
/// (`original/noq/noq-udp/src/lib.rs:239-246`).
pub const EcnCodepoint = enum(u8) {
    ect1 = 0b01,
    ect0 = 0b10,
    ce = 0b11,

    /// Decode the two ECN bits of a TOS/TCLASS octet. `0b00` (Not-ECT) is
    /// `null` — it is the absence of a codepoint, not a codepoint.
    pub fn fromBits(x: u8) ?EcnCodepoint {
        return switch (x & 0b11) {
            0b01 => .ect1,
            0b10 => .ect0,
            0b11 => .ce,
            else => null,
        };
    }

    pub fn bits(self: EcnCodepoint) u8 {
        return @intFromEnum(self);
    }
};

// ── cmsg geometry (the CMSG_* macros, which are not exposed by std) ──────────

const Cmsghdr = if (is_supported) std.os.linux.cmsghdr else extern struct {
    len: usize,
    level: i32,
    type: i32,
};

const cmsg_align_to = @sizeOf(usize);

fn cmsgAlign(len: usize) usize {
    return (len + cmsg_align_to - 1) & ~@as(usize, cmsg_align_to - 1);
}

/// `CMSG_LEN(len)` — the value the kernel wants in `cmsghdr.len`: the header
/// (aligned) plus the *unpadded* payload.
fn cmsgLen(payload: usize) usize {
    return cmsgAlign(@sizeOf(Cmsghdr)) + payload;
}

/// `CMSG_SPACE(len)` — bytes this cmsg consumes in the control buffer,
/// including the trailing pad that aligns the next header.
fn cmsgSpace(payload: usize) usize {
    return cmsgAlign(@sizeOf(Cmsghdr)) + cmsgAlign(payload);
}

/// The one place the ECN cmsg payload width is decided. See the module doc.
pub const ecn_payload_size: usize = @sizeOf(c_int);

comptime {
    // A narrow `c_int` would silently reintroduce the EINVAL bug this module
    // exists to prevent. Fail the build instead.
    std.debug.assert(ecn_payload_size == 4);
}

/// Control-buffer size for a send carrying an ECN cmsg AND a GSO cmsg.
pub const send_control_space: usize = cmsgSpace(ecn_payload_size) + cmsgSpace(@sizeOf(u16));

/// Control-buffer size for a receive. Sized for the ECN cmsg plus generous
/// slack so an unexpected cmsg the kernel adds cannot set `MSG_CTRUNC` and
/// truncate the one we actually want.
pub const recv_control_space: usize = cmsgSpace(ecn_payload_size) * 4;

// ── encode ──────────────────────────────────────────────────────────────────

/// Appends control messages to a caller-owned buffer. `finish()` yields the
/// exact prefix to hand to `sendmsg` as `msg_control` / `msg_controllen`.
pub const Encoder = struct {
    buffer: []u8,
    len: usize = 0,

    pub fn init(buffer: []u8) Encoder {
        return .{ .buffer = buffer };
    }

    /// Push one cmsg whose payload is `T`. The header records the *unpadded*
    /// `CMSG_LEN`, while the cursor advances by the padded `CMSG_SPACE`, which
    /// is what keeps the next header 8-byte aligned.
    fn push(self: *Encoder, comptime T: type, level: i32, cmsg_type: i32, value: T) error{NoSpaceLeft}!void {
        const space = cmsgSpace(@sizeOf(T));
        if (self.len + space > self.buffer.len) return error.NoSpaceLeft;
        const slot = self.buffer[self.len..][0..space];
        // Zero first: the pad bytes are handed to the kernel, and stale stack
        // contents in ancillary data is an information leak.
        @memset(slot, 0);
        const hdr: *align(1) Cmsghdr = @ptrCast(slot.ptr);
        hdr.* = .{
            .len = @intCast(cmsgLen(@sizeOf(T))),
            .level = level,
            .type = cmsg_type,
        };
        const data = slot[cmsgAlign(@sizeOf(Cmsghdr))..][0..@sizeOf(T)];
        @memcpy(data, std.mem.asBytes(&value));
        self.len += space;
    }

    /// Stamp the ECN codepoint on the outgoing IP header. `is_ip4` selects
    /// `IP_TOS` vs `IPV6_TCLASS`; the payload is a 4-byte `c_int` either way
    /// (`unix.rs:741,:745`).
    pub fn pushEcn(self: *Encoder, is_ip4: bool, ecn: EcnCodepoint) error{NoSpaceLeft}!void {
        if (!is_supported) return;
        const linux = std.os.linux;
        const value: c_int = @intCast(ecn.bits());
        if (is_ip4) {
            try self.push(c_int, linux.IPPROTO.IP, linux.IP.TOS, value);
        } else {
            try self.push(c_int, linux.IPPROTO.IPV6, linux.IPV6.TCLASS, value);
        }
    }

    /// Ask the kernel to split this `sendmsg`'s payload into `segment_size`
    /// datagrams (`unix.rs:1063-1068`). Payload is a `u16`, not a `c_int`.
    pub fn pushSegmentSize(self: *Encoder, segment_size: u16) error{NoSpaceLeft}!void {
        if (!is_supported) return;
        const linux = std.os.linux;
        try self.push(u16, linux.IPPROTO.UDP, linux.UDP.SEGMENT, segment_size);
    }

    pub fn finish(self: *const Encoder) []const u8 {
        return self.buffer[0..self.len];
    }
};

// ── decode ──────────────────────────────────────────────────────────────────

/// Walk a received control buffer and return the ECN codepoint the kernel
/// reported, if any. Mirrors `ControlMetadata::decode`
/// (`original/noq/noq-udp/src/unix.rs:927-950`): `IP_TOS`, `IP_RECVTOS` and
/// `IPV6_TCLASS` all carry the TOS/TCLASS octet.
///
/// Width is read defensively: Linux delivers `IP_RECVTOS` as a single byte but
/// `IPV6_TCLASS` as a `c_int`, so the payload length decides how to read it
/// rather than a hardcoded assumption.
pub fn decodeEcn(control: []const u8) ?EcnCodepoint {
    if (!is_supported) return null;
    const linux = std.os.linux;
    var it = Iterator.init(control);
    while (it.next()) |cmsg| {
        const matches = switch (cmsg.level) {
            linux.IPPROTO.IP => cmsg.cmsg_type == linux.IP.TOS or cmsg.cmsg_type == linux.IP.RECVTOS,
            linux.IPPROTO.IPV6 => cmsg.cmsg_type == linux.IPV6.TCLASS,
            else => false,
        };
        if (!matches) continue;
        const bits = readTosOctet(cmsg.data) orelse continue;
        if (EcnCodepoint.fromBits(bits)) |cp| return cp;
    }
    return null;
}

/// The TOS/TCLASS value is the low byte of the payload on every little-endian
/// width the kernel uses (1 or 4 bytes), so read the first byte once the
/// length is known to be sane.
fn readTosOctet(data: []const u8) ?u8 {
    if (data.len == 0) return null;
    if (data.len >= @sizeOf(c_int)) {
        const v = std.mem.readInt(c_int, data[0..@sizeOf(c_int)], builtin.cpu.arch.endian());
        return @truncate(@as(u32, @bitCast(v)));
    }
    return data[0];
}

pub const Cmsg = struct {
    level: i32,
    cmsg_type: i32,
    data: []const u8,
};

/// Iterates the cmsgs in a control buffer (`CMSG_FIRSTHDR` / `CMSG_NXTHDR`).
pub const Iterator = struct {
    control: []const u8,
    offset: usize = 0,

    pub fn init(control: []const u8) Iterator {
        return .{ .control = control };
    }

    pub fn next(self: *Iterator) ?Cmsg {
        const hdr_space = cmsgAlign(@sizeOf(Cmsghdr));
        if (self.offset + hdr_space > self.control.len) return null;
        const hdr: *align(1) const Cmsghdr = @ptrCast(self.control.ptr + self.offset);
        const len: usize = @intCast(hdr.len);
        // A malformed/truncated buffer must terminate the walk, never wrap the
        // cursor or index past the end.
        if (len < hdr_space) return null;
        if (self.offset + len > self.control.len) return null;
        const data = self.control[self.offset + hdr_space ..][0 .. len - hdr_space];
        const advance = cmsgSpace(len - hdr_space);
        // Guard against a zero/backwards advance looping forever.
        if (advance == 0) return null;
        self.offset += advance;
        return .{ .level = hdr.level, .cmsg_type = hdr.type, .data = data };
    }
};

// ── socket options ──────────────────────────────────────────────────────────

/// Ask the kernel to deliver the inbound TOS/TCLASS octet as ancillary data.
/// Without this, `decodeEcn` sees an empty control buffer and CE marking is
/// invisible to the receiver. Best-effort: a kernel that refuses the option
/// leaves ECN receive off rather than failing endpoint construction
/// (`unix.rs:107-109` does the same).
pub fn enableEcnReceive(handle: posix.socket_t, is_ip4: bool) bool {
    if (!is_supported) return false;
    const linux = std.os.linux;
    const on: c_int = 1;
    const bytes = std.mem.asBytes(&on);
    if (is_ip4) {
        posix.setsockopt(handle, linux.IPPROTO.IP, linux.IP.RECVTOS, bytes) catch return false;
    } else {
        // A v6 socket may receive v4-mapped traffic, so arm both.
        posix.setsockopt(handle, linux.IPPROTO.IPV6, linux.IPV6.RECVTCLASS, bytes) catch return false;
        posix.setsockopt(handle, linux.IPPROTO.IP, linux.IP.RECVTOS, bytes) catch {};
    }
    return true;
}

// ── send ────────────────────────────────────────────────────────────────────

pub const SendError = error{
    /// The kernel refused the `UDP_SEGMENT` batch (EIO/EINVAL). Recoverable:
    /// the caller disables GSO and re-sends per datagram.
    GsoRejected,
    /// Any other send failure. The datagram did not go out.
    SendFailed,
};

/// `sendmsg` with ancillary data.
///
/// This deliberately bypasses `std.Io.net.Socket.sendMany`, which classifies
/// `EINVAL` as a programmer bug (`Threaded.errnoBug` → panic in debug builds).
/// For a GSO send `EINVAL`/`EIO` is not a bug: it is the documented way a
/// kernel, an interface, or a route MTU declines the batch, and the caller is
/// required to fall back rather than crash. So the errno is classified here.
pub fn sendWithControl(
    handle: posix.socket_t,
    dest: *const std.Io.net.IpAddress,
    payload: []const u8,
    control: []const u8,
    /// True when `control` carries a `UDP_SEGMENT` cmsg, so `EINVAL`/`EIO`
    /// should be reported as `GsoRejected` rather than a hard failure.
    has_gso: bool,
) SendError!void {
    if (!is_supported) return error.SendFailed;
    var storage: std.Io.Threaded.PosixAddress = undefined;
    const namelen = std.Io.Threaded.addressToPosix(dest, &storage);
    var iov: posix.iovec_const = .{ .base = payload.ptr, .len = payload.len };
    const msg: posix.msghdr_const = .{
        .name = &storage.any,
        .namelen = namelen,
        .iov = (&iov)[0..1],
        .iovlen = 1,
        // The kernel returns EINVAL on a bad pointer even when controllen is 0.
        .control = if (control.len == 0) null else control.ptr,
        .controllen = @intCast(control.len),
        .flags = 0,
    };
    while (true) {
        const rc = posix.system.sendmsg(handle, &msg, posix.MSG.NOSIGNAL);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            // The GSO batch was declined. Every other meaning of these errnos
            // on a bound UDP socket with a valid buffer is already excluded, so
            // attributing them to GSO is safe — and if we are wrong, the
            // fallback still delivers the bytes.
            .INVAL, .IO => return if (has_gso) error.GsoRejected else error.SendFailed,
            // Payload exceeds what the path will take in one datagram; for a
            // GSO batch that is also a "send it smaller" signal.
            .MSGSIZE => return if (has_gso) error.GsoRejected else error.SendFailed,
            else => return error.SendFailed,
        }
    }
}

/// Probe whether this kernel accepts `UDP_SEGMENT` at all. Rust does the same
/// setsockopt probe and falls back to `max_gso_segments = 1`
/// (`unix.rs:1046-1060`); we mirror that by reporting false and letting the
/// caller send per-datagram.
pub fn gsoSupported(handle: posix.socket_t) bool {
    if (!is_supported) return false;
    const linux = std.os.linux;
    const probe: c_int = 1500;
    posix.setsockopt(handle, linux.IPPROTO.UDP, linux.UDP.SEGMENT, std.mem.asBytes(&probe)) catch return false;
    // Leave the socket-wide option off; the per-send cmsg is what we use.
    const off: c_int = 0;
    posix.setsockopt(handle, linux.IPPROTO.UDP, linux.UDP.SEGMENT, std.mem.asBytes(&off)) catch {};
    return true;
}

// ── tests ───────────────────────────────────────────────────────────────────

test "ECN cmsg payload is a 4-byte c_int (the ABI bug this module fixes)" {
    // The bug was a 1-byte payload. Assert the width at the source of truth AND
    // in the bytes actually produced, so neither can drift alone.
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(c_int));
    try std.testing.expectEqual(@as(usize, 4), ecn_payload_size);

    if (!is_supported) return error.SkipZigTest;
    const linux = std.os.linux;

    var buf: [send_control_space]u8 = undefined;
    var enc = Encoder.init(&buf);
    try enc.pushEcn(true, .ect0);
    const control = enc.finish();

    var it = Iterator.init(control);
    const cmsg = it.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i32, linux.IPPROTO.IP), cmsg.level);
    try std.testing.expectEqual(@as(i32, linux.IP.TOS), cmsg.cmsg_type);
    try std.testing.expectEqual(@as(usize, 4), cmsg.data.len);
    try std.testing.expectEqual(@as(c_int, 0b10), std.mem.readInt(c_int, cmsg.data[0..4], builtin.cpu.arch.endian()));
    try std.testing.expect(it.next() == null);
}

test "IPV6_TCLASS also uses the 4-byte width (the v6 leg the kernel rejects at 1 byte)" {
    if (!is_supported) return error.SkipZigTest;
    const linux = std.os.linux;

    var buf: [send_control_space]u8 = undefined;
    var enc = Encoder.init(&buf);
    try enc.pushEcn(false, .ce);
    var it = Iterator.init(enc.finish());
    const cmsg = it.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i32, linux.IPPROTO.IPV6), cmsg.level);
    try std.testing.expectEqual(@as(i32, linux.IPV6.TCLASS), cmsg.cmsg_type);
    try std.testing.expectEqual(@as(usize, 4), cmsg.data.len);
}

test "cmsg header length is CMSG_LEN (unpadded) while the cursor advances CMSG_SPACE" {
    if (!is_supported) return error.SkipZigTest;
    var buf: [send_control_space]u8 = undefined;
    var enc = Encoder.init(&buf);
    try enc.pushEcn(true, .ect0);
    try enc.pushSegmentSize(1200);

    const control = enc.finish();
    try std.testing.expectEqual(cmsgSpace(4) + cmsgSpace(2), control.len);

    const hdr: *align(1) const Cmsghdr = @ptrCast(control.ptr);
    try std.testing.expectEqual(cmsgLen(4), @as(usize, @intCast(hdr.len)));

    // Second header must land on an 8-byte boundary.
    try std.testing.expectEqual(@as(usize, 0), cmsgSpace(4) % cmsg_align_to);
}

test "GSO segment size is a u16 payload, not a c_int" {
    if (!is_supported) return error.SkipZigTest;
    const linux = std.os.linux;
    var buf: [send_control_space]u8 = undefined;
    var enc = Encoder.init(&buf);
    try enc.pushSegmentSize(1350);
    var it = Iterator.init(enc.finish());
    const cmsg = it.next() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i32, linux.IPPROTO.UDP), cmsg.level);
    try std.testing.expectEqual(@as(i32, linux.UDP.SEGMENT), cmsg.cmsg_type);
    try std.testing.expectEqual(@as(usize, 2), cmsg.data.len);
    try std.testing.expectEqual(@as(u16, 1350), std.mem.readInt(u16, cmsg.data[0..2], builtin.cpu.arch.endian()));
}

test "decodeEcn round-trips every codepoint at both kernel widths" {
    if (!is_supported) return error.SkipZigTest;
    const linux = std.os.linux;
    for ([_]EcnCodepoint{ .ect0, .ect1, .ce }) |cp| {
        var buf: [send_control_space]u8 = undefined;
        var enc = Encoder.init(&buf);
        try enc.pushEcn(true, cp);
        try std.testing.expectEqual(cp, decodeEcn(enc.finish()).?);
    }

    // Linux delivers IP_RECVTOS as a single byte; the decoder must accept it.
    var narrow: [cmsgSpace(1)]u8 = undefined;
    @memset(&narrow, 0);
    const hdr: *align(1) Cmsghdr = @ptrCast(&narrow);
    hdr.* = .{ .len = @intCast(cmsgLen(1)), .level = linux.IPPROTO.IP, .type = linux.IP.RECVTOS };
    narrow[cmsgAlign(@sizeOf(Cmsghdr))] = 0b11;
    try std.testing.expectEqual(EcnCodepoint.ce, decodeEcn(&narrow).?);
}

test "decodeEcn ignores Not-ECT, foreign cmsgs, and truncated buffers" {
    if (!is_supported) return error.SkipZigTest;
    const linux = std.os.linux;

    // Not-ECT (0b00) is an absent codepoint, not a decode failure.
    var buf: [send_control_space]u8 = undefined;
    var enc = Encoder.init(&buf);
    try enc.push(c_int, linux.IPPROTO.IP, linux.IP.TOS, 0);
    try std.testing.expect(decodeEcn(enc.finish()) == null);

    // A cmsg we do not care about must be skipped, not misread.
    var buf2: [send_control_space]u8 = undefined;
    var enc2 = Encoder.init(&buf2);
    try enc2.pushSegmentSize(1200);
    try std.testing.expect(decodeEcn(enc2.finish()) == null);

    // An empty buffer and a header claiming more bytes than exist both stop.
    try std.testing.expect(decodeEcn(&.{}) == null);
    var bogus: [cmsgSpace(ecn_payload_size)]u8 = undefined;
    @memset(&bogus, 0);
    const hdr: *align(1) Cmsghdr = @ptrCast(&bogus);
    hdr.* = .{ .len = 4096, .level = linux.IPPROTO.IP, .type = linux.IP.TOS };
    try std.testing.expect(decodeEcn(&bogus) == null);
}

test "Encoder reports NoSpaceLeft rather than overrunning its buffer" {
    if (!is_supported) return error.SkipZigTest;
    var small: [cmsgSpace(ecn_payload_size)]u8 = undefined;
    var enc = Encoder.init(&small);
    try enc.pushEcn(true, .ect0);
    try std.testing.expectError(error.NoSpaceLeft, enc.pushSegmentSize(1200));
    try std.testing.expectEqual(small.len, enc.finish().len);
}

test "EcnCodepoint bit patterns match RFC 3168" {
    try std.testing.expectEqual(@as(u8, 0b10), EcnCodepoint.ect0.bits());
    try std.testing.expectEqual(@as(u8, 0b01), EcnCodepoint.ect1.bits());
    try std.testing.expectEqual(@as(u8, 0b11), EcnCodepoint.ce.bits());
    try std.testing.expect(EcnCodepoint.fromBits(0b00) == null);
    // High DSCP bits must not leak into the codepoint.
    try std.testing.expectEqual(EcnCodepoint.ce, EcnCodepoint.fromBits(0xFF).?);
}
