//! Minimal WebSocket framing for DERP relay (RFC 6455).
//!
//! Client frames MUST be masked; server frames are unmasked.
//! The relay only uses binary messages; WS ping/pong/close are transport-level.

const std = @import("std");

pub const OpCode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
    _,
};

pub const WsError = error{
    InvalidFrame,
    FrameTooLarge,
    UnsupportedOpCode,
    MaskingViolation,
};

/// RFC 6455 §5.1: client->server frames MUST be masked; server->client MUST NOT.
pub const Role = enum {
    server,
    client,
};

pub const upgrade_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the RFC 6455 `Sec-WebSocket-Accept` response for a client key.
pub fn computeAccept(client_key: []const u8, out: *[28]u8) []const u8 {
    var input_buf: [128]u8 = undefined;
    const input = std.fmt.bufPrint(&input_buf, "{s}{s}", .{ client_key, upgrade_guid }) catch unreachable;
    var digest: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(input, &digest, .{});
    return std.base64.standard.Encoder.encode(out, &digest);
}

pub fn writeFrame(
    io: std.Io,
    writer: *std.Io.Writer,
    op: OpCode,
    payload: []const u8,
    mask: bool,
) !void {
    switch (op) {
        .continuation, .text, .binary => {},
        .close, .ping, .pong => if (payload.len > 125) return error.InvalidFrame,
        else => return error.UnsupportedOpCode,
    }
    const first: u8 = 0x80 | @as(u8, @intFromEnum(op));
    try writer.writeByte(first);

    const mask_bit: u8 = if (mask) 0x80 else 0x00;
    if (payload.len < 126) {
        try writer.writeByte(mask_bit | @as(u8, @intCast(payload.len)));
    } else if (payload.len < 65536) {
        try writer.writeByte(mask_bit | 126);
        try writer.writeInt(u16, @intCast(payload.len), .big);
    } else {
        try writer.writeByte(mask_bit | 127);
        try writer.writeInt(u64, payload.len, .big);
    }

    if (mask) {
        var mask_key: [4]u8 = undefined;
        io.random(&mask_key);
        try writer.writeAll(&mask_key);
        for (payload, 0..) |b, i| {
            try writer.writeByte(b ^ mask_key[i % 4]);
        }
    } else {
        try writer.writeAll(payload);
    }
}

pub const FrameHeader = struct {
    fin: bool,
    op: OpCode,
    masked: bool,
    payload_len: usize,
};

pub fn readFrameHeader(reader: *std.Io.Reader) !FrameHeader {
    const first = reader.takeByte() catch |err| switch (err) {
        error.EndOfStream => return error.ConnectionClosed,
        else => return error.InvalidFrame,
    };
    if (first & 0x70 != 0) return error.InvalidFrame;
    const fin = (first & 0x80) != 0;
    const op: OpCode = @enumFromInt(@as(u4, @intCast(first & 0x0F)));
    switch (op) {
        .continuation, .text, .binary, .close, .ping, .pong => {},
        else => return error.UnsupportedOpCode,
    }

    const second = try reader.takeByte();
    const masked = (second & 0x80) != 0;
    const encoded_len = second & 0x7F;
    var payload_len: usize = encoded_len;

    if (encoded_len == 126) {
        payload_len = try reader.takeInt(u16, .big);
        if (payload_len < 126) return error.InvalidFrame;
    } else if (encoded_len == 127) {
        const len64 = try reader.takeInt(u64, .big);
        if (len64 & (@as(u64, 1) << 63) != 0) return error.InvalidFrame;
        if (len64 <= std.math.maxInt(u16)) return error.InvalidFrame;
        payload_len = std.math.cast(usize, len64) orelse return error.FrameTooLarge;
    }

    const is_control = op == .close or op == .ping or op == .pong;
    if (is_control and (!fin or payload_len > 125)) {
        return error.InvalidFrame;
    }

    return .{
        .fin = fin,
        .op = op,
        .masked = masked,
        .payload_len = payload_len,
    };
}

pub fn readMaskKey(reader: *std.Io.Reader, masked: bool) ![4]u8 {
    if (!masked) return .{0} ** 4;
    const bytes = try reader.take(4);
    return .{ bytes[0], bytes[1], bytes[2], bytes[3] };
}

pub fn unmaskPayload(payload: []u8, mask: [4]u8) void {
    for (payload, 0..) |*b, i| {
        b.* ^= mask[i % 4];
    }
}

fn validCloseCode(code: u16) bool {
    if (code >= 3000 and code <= 4999) return true;
    if (code < 1000 or code > 1014) return false;
    return switch (code) {
        1004, 1005, 1006 => false,
        else => true,
    };
}

fn validateClosePayload(payload: []const u8) !void {
    if (payload.len == 1) return error.InvalidFrame;
    if (payload.len == 0) return;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    if (!validCloseCode(code)) return error.InvalidFrame;
    if (!std.unicode.utf8ValidateSlice(payload[2..])) return error.InvalidFrame;
}

/// Read one complete WS frame: header + mask key (if masked) + unmasked payload.
/// Enforces RFC 6455 §5.1 masking rules by role:
///   - server: rejects unmasked client frames
///   - client: rejects masked server frames
/// Returns the op and a slice into `out_buf` containing the clean payload.
pub const ReadFrameResult = struct {
    op: OpCode,
    payload: []u8,
};

fn isControl(op: OpCode) bool {
    return op == .close or op == .ping or op == .pong;
}

/// Persistent RFC 6455 receive state.
///
/// A fragmented data message remains in `out_buf` while interleaved control
/// frames are returned from `control_payload`. Callers must therefore reuse the
/// same `out_buf` until the fragmented message completes. Returned control-frame
/// payloads remain valid only until the next call on this decoder.
pub const Decoder = struct {
    message_op: ?OpCode = null,
    message_len: usize = 0,
    control_payload: [125]u8 = undefined,

    pub fn readFrame(
        self: *Decoder,
        reader: *std.Io.Reader,
        out_buf: []u8,
        role: Role,
    ) !ReadFrameResult {
        while (true) {
            const hdr = try readFrameHeader(reader);

            // Enforce masking rules per RFC 6455 §5.1.
            switch (role) {
                .server => {
                    if (!hdr.masked) return error.MaskingViolation;
                },
                .client => {
                    if (hdr.masked) return error.MaskingViolation;
                },
            }

            if (isControl(hdr.op)) {
                const payload = self.control_payload[0..hdr.payload_len];
                const mask = try readMaskKey(reader, hdr.masked);
                try reader.readSliceAll(payload);
                if (hdr.masked) unmaskPayload(payload, mask);
                if (hdr.op == .close) try validateClosePayload(payload);
                return .{ .op = hdr.op, .payload = payload };
            }

            switch (hdr.op) {
                .continuation => if (self.message_op == null) return error.InvalidFrame,
                .binary, .text => {
                    if (self.message_op != null) return error.InvalidFrame;
                    self.message_op = hdr.op;
                    self.message_len = 0;
                },
                else => return error.UnsupportedOpCode,
            }

            if (self.message_len > out_buf.len or hdr.payload_len > out_buf.len - self.message_len) {
                return error.FrameTooLarge;
            }
            const payload = out_buf[self.message_len..][0..hdr.payload_len];
            const mask = try readMaskKey(reader, hdr.masked);
            try reader.readSliceAll(payload);
            if (hdr.masked) unmaskPayload(payload, mask);
            self.message_len += hdr.payload_len;

            if (!hdr.fin) continue;

            const op = self.message_op orelse return error.InvalidFrame;
            const message = out_buf[0..self.message_len];
            self.message_op = null;
            self.message_len = 0;
            if (op == .text and !std.unicode.utf8ValidateSlice(message)) {
                return error.InvalidFrame;
            }
            return .{ .op = op, .payload = message };
        }
    }
};

/// Stateless convenience reader. It preserves the historical single-call
/// behavior for complete messages and standalone control frames. Callers that
/// must resume a fragmented message after an interleaved control frame use a
/// persistent `Decoder` instead.
pub fn readFrame(
    reader: *std.Io.Reader,
    out_buf: []u8,
    role: Role,
) !ReadFrameResult {
    var decoder: Decoder = .{};
    const result = try decoder.readFrame(reader, out_buf, role);
    if (isControl(result.op)) {
        if (result.payload.len > out_buf.len) return error.FrameTooLarge;
        @memcpy(out_buf[0..result.payload.len], result.payload);
        return .{ .op = result.op, .payload = out_buf[0..result.payload.len] };
    }
    return result;
}

const testing = std.testing;

test "writeFrame binary unmasked round-trip" {
    const io = std.testing.io;
    var buf: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try writeFrame(io, &writer, .binary, "hello", false);
    const frame = writer.buffered();

    var reader = std.Io.Reader.fixed(frame);
    const hdr = try readFrameHeader(&reader);
    try testing.expect(hdr.fin);
    try testing.expectEqual(OpCode.binary, hdr.op);
    try testing.expect(!hdr.masked);
    try testing.expectEqual(@as(usize, 5), hdr.payload_len);
}

test "writeFrame binary masked round-trip" {
    const io = std.testing.io;
    var buf: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try writeFrame(io, &writer, .binary, "hello", true);
    const frame = writer.buffered();

    var reader = std.Io.Reader.fixed(frame);
    const hdr = try readFrameHeader(&reader);
    try testing.expect(hdr.fin);
    try testing.expectEqual(OpCode.binary, hdr.op);
    try testing.expect(hdr.masked);

    const mask = try readMaskKey(&reader, hdr.masked);
    const payload = try reader.take(5);
    var unmasked: [5]u8 = undefined;
    @memcpy(&unmasked, payload);
    unmaskPayload(&unmasked, mask);
    try testing.expectEqualStrings("hello", &unmasked);
}

test "ping/pong frame round-trip" {
    const io = std.testing.io;
    var buf: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try writeFrame(io, &writer, .ping, "data", false);
    const frame = writer.buffered();

    var reader = std.Io.Reader.fixed(frame);
    const hdr = try readFrameHeader(&reader);
    try testing.expectEqual(OpCode.ping, hdr.op);
    try testing.expectEqual(@as(usize, 4), hdr.payload_len);
}

test "readFrame masked binary — server reads clean payload" {
    const io = std.testing.io;
    var buf: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try writeFrame(io, &writer, .binary, "Hello from client!", true);
    const frame = writer.buffered();

    var reader = std.Io.Reader.fixed(frame);
    var out: [256]u8 = undefined;
    const result = try readFrame(&reader, &out, .server);
    try testing.expectEqual(OpCode.binary, result.op);
    try testing.expectEqualStrings("Hello from client!", result.payload);
}

test "F3: readFrame masked ping reads mask before payload" {
    const io = std.testing.io;
    var buf: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try writeFrame(io, &writer, .ping, "ping", true);
    const frame = writer.buffered();

    var reader = std.Io.Reader.fixed(frame);
    var out: [16]u8 = undefined;
    const result = try readFrame(&reader, &out, .server);
    try testing.expectEqual(OpCode.ping, result.op);
    try testing.expectEqualStrings("ping", result.payload);
}

test "readFrame unmasked binary — client reads clean payload" {
    const io = std.testing.io;
    var buf: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try writeFrame(io, &writer, .binary, "Hello from server!", false);
    const frame = writer.buffered();

    var reader = std.Io.Reader.fixed(frame);
    var out: [256]u8 = undefined;
    const result = try readFrame(&reader, &out, .client);
    try testing.expectEqual(OpCode.binary, result.op);
    try testing.expectEqualStrings("Hello from server!", result.payload);
}

test "readFrame server rejects unmasked client frame" {
    const io = std.testing.io;
    var buf: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try writeFrame(io, &writer, .binary, "unmasked", false);
    const frame = writer.buffered();

    var reader = std.Io.Reader.fixed(frame);
    var out: [256]u8 = undefined;
    const result = readFrame(&reader, &out, .server);
    try testing.expectError(error.MaskingViolation, result);
}

test "readFrame client rejects masked server frame" {
    const io = std.testing.io;
    var buf: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try writeFrame(io, &writer, .binary, "masked", true);
    const frame = writer.buffered();

    var reader = std.Io.Reader.fixed(frame);
    var out: [256]u8 = undefined;
    const result = readFrame(&reader, &out, .client);
    try testing.expectError(error.MaskingViolation, result);
}

test "readFrame reassembles fragmented binary payload" {
    const part1 = "Hello, ";
    const part2 = "world!";
    var frame: [64]u8 = undefined;
    var pos: usize = 0;

    // Binary fragment without FIN.
    frame[pos] = 0x02;
    frame[pos + 1] = 0x80 | @as(u8, @intCast(part1.len));
    const mask1: [4]u8 = .{ 1, 2, 3, 4 };
    @memcpy(frame[pos + 2 .. pos + 6], &mask1);
    for (part1, 0..) |b, i| frame[pos + 6 + i] = b ^ mask1[i % 4];
    pos += 6 + part1.len;

    // Continuation fragment with FIN.
    frame[pos] = 0x80; // FIN + continuation opcode 0
    frame[pos + 1] = 0x80 | @as(u8, @intCast(part2.len));
    const mask2: [4]u8 = .{ 5, 6, 7, 8 };
    @memcpy(frame[pos + 2 .. pos + 6], &mask2);
    for (part2, 0..) |b, i| frame[pos + 6 + i] = b ^ mask2[i % 4];
    pos += 6 + part2.len;

    var reader = std.Io.Reader.fixed(frame[0..pos]);
    var out: [64]u8 = undefined;
    const result = try readFrame(&reader, &out, .server);
    try testing.expectEqual(OpCode.binary, result.op);
    try testing.expectEqualStrings("Hello, world!", result.payload);
}

test "Decoder preserves fragmented binary across interleaved ping" {
    const encoded = [_]u8{
        0x02, 0x03, 'a', 'b', 'c', // binary, FIN=0
        0x89, 0x04, 'p', 'i', 'n', 'g', // ping, FIN=1
        0x80, 0x03, 'd', 'e', 'f', // continuation, FIN=1
    };
    var reader = std.Io.Reader.fixed(&encoded);
    var out: [16]u8 = undefined;
    var decoder: Decoder = .{};

    const ping = try decoder.readFrame(&reader, &out, .client);
    try testing.expectEqual(OpCode.ping, ping.op);
    try testing.expectEqualStrings("ping", ping.payload);

    const binary = try decoder.readFrame(&reader, &out, .client);
    try testing.expectEqual(OpCode.binary, binary.op);
    try testing.expectEqualStrings("abcdef", binary.payload);
}

test "Decoder reassembles text and rejects invalid continuation sequences" {
    const encoded_text = [_]u8{
        0x01, 0x03, 'h', 'e', 'l', // text, FIN=0
        0x80, 0x02, 'l', 'o', // continuation, FIN=1
    };
    var text_reader = std.Io.Reader.fixed(&encoded_text);
    var out: [16]u8 = undefined;
    var decoder: Decoder = .{};
    const text = try decoder.readFrame(&text_reader, &out, .client);
    try testing.expectEqual(OpCode.text, text.op);
    try testing.expectEqualStrings("hello", text.payload);

    var stray_continuation = std.Io.Reader.fixed(&[_]u8{ 0x80, 0x00 });
    var stray_decoder: Decoder = .{};
    try testing.expectError(error.InvalidFrame, stray_decoder.readFrame(&stray_continuation, &out, .client));

    const interrupted_text = [_]u8{
        0x01, 0x01, 'a', // text, FIN=0
        0x82, 0x01, 'b', // binary instead of continuation
    };
    var interrupted_reader = std.Io.Reader.fixed(&interrupted_text);
    var interrupted_decoder: Decoder = .{};
    try testing.expectError(error.InvalidFrame, interrupted_decoder.readFrame(&interrupted_reader, &out, .client));
}

test "computeAccept matches RFC 6455 example" {
    var out: [28]u8 = undefined;
    const accept = computeAccept("dGhlIHNhbXBsZSBub25jZQ==", &out);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
}

test "readFrame rejects reserved bits and invalid control framing" {
    var out: [256]u8 = undefined;

    var reserved = std.Io.Reader.fixed(&[_]u8{ 0xc2, 0x00 });
    try testing.expectError(error.InvalidFrame, readFrame(&reserved, &out, .client));

    var fragmented_ping = std.Io.Reader.fixed(&[_]u8{ 0x09, 0x00 });
    try testing.expectError(error.InvalidFrame, readFrame(&fragmented_ping, &out, .client));

    var oversized_ping = std.Io.Reader.fixed(&([_]u8{ 0x89, 0x7e, 0x00, 0x7e } ++ [_]u8{0} ** 126));
    try testing.expectError(error.InvalidFrame, readFrame(&oversized_ping, &out, .client));
}

test "readFrame consumes a masked close payload" {
    const io = std.testing.io;
    var frame_buf: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&frame_buf);
    try writeFrame(io, &writer, .close, &[_]u8{ 0x03, 0xe8 }, true);

    var reader = std.Io.Reader.fixed(writer.buffered());
    var out: [8]u8 = undefined;
    const result = try readFrame(&reader, &out, .server);
    try testing.expectEqual(OpCode.close, result.op);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0xe8 }, result.payload);
}

test "readFrame validates close status and UTF-8 reason" {
    var out: [16]u8 = undefined;

    var one_byte = std.Io.Reader.fixed(&[_]u8{ 0x88, 0x01, 0x03 });
    try testing.expectError(error.InvalidFrame, readFrame(&one_byte, &out, .client));

    var reserved = std.Io.Reader.fixed(&[_]u8{ 0x88, 0x02, 0x03, 0xed }); // 1005
    try testing.expectError(error.InvalidFrame, readFrame(&reserved, &out, .client));

    var invalid_reason = std.Io.Reader.fixed(&[_]u8{ 0x88, 0x03, 0x03, 0xe8, 0xff });
    try testing.expectError(error.InvalidFrame, readFrame(&invalid_reason, &out, .client));

    var application = std.Io.Reader.fixed(&[_]u8{ 0x88, 0x02, 0x0b, 0xb8 }); // 3000
    const result = try readFrame(&application, &out, .client);
    try testing.expectEqual(OpCode.close, result.op);
}

test "readFrame returns text so relay callers can skip it" {
    const io = std.testing.io;
    var frame_buf: [64]u8 = undefined;
    var writer = std.Io.Writer.fixed(&frame_buf);
    try writeFrame(io, &writer, .text, "ignored", false);

    var reader = std.Io.Reader.fixed(writer.buffered());
    var out: [16]u8 = undefined;
    const result = try readFrame(&reader, &out, .client);
    try testing.expectEqual(OpCode.text, result.op);
    try testing.expectEqualStrings("ignored", result.payload);
}

test "readFrame rejects invalid UTF-8 text" {
    var reader = std.Io.Reader.fixed(&[_]u8{ 0x81, 0x01, 0xff });
    var out: [8]u8 = undefined;
    try testing.expectError(error.InvalidFrame, readFrame(&reader, &out, .client));
}

test "writeFrame and readFrame reject invalid control lengths" {
    const io = std.testing.io;
    var payload: [126]u8 = .{0} ** 126;
    var encoded: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&encoded);
    try testing.expectError(error.InvalidFrame, writeFrame(io, &writer, .ping, &payload, false));

    const invalid_63_bit = [_]u8{ 0x82, 0x7f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    var reader = std.Io.Reader.fixed(&invalid_63_bit);
    var out: [8]u8 = undefined;
    try testing.expectError(error.InvalidFrame, readFrame(&reader, &out, .client));
}

test "readFrame streams a payload larger than the reader buffer" {
    const io = std.testing.io;
    var payload: [512]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @truncate(i);

    var encoded: [520]u8 = undefined;
    var writer = std.Io.Writer.fixed(&encoded);
    try writeFrame(io, &writer, .binary, &payload, false);

    var tiny_reader_buf: [17]u8 = undefined;
    var source: std.Io.Reader = .fixed(writer.buffered());
    var limited: std.Io.Reader.Limited = .init(
        &source,
        .limited(writer.buffered().len),
        &tiny_reader_buf,
    );
    var out: [512]u8 = undefined;
    const result = try readFrame(&limited.interface, &out, .client);
    try testing.expectEqualSlices(u8, &payload, result.payload);
}
