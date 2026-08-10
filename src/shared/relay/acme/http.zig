//! Minimal HTTP/1.1 client over `tls_wrapper.TlsClient`, sized for the ACME
//! lane: one TLS connection per request (`Connection: close` — ACME is a
//! handful of small requests at startup/renewal), explicit trust anchor,
//! Content-Length and chunked bodies, and the two headers ACME consumes
//! (Replay-Nonce, Location). No proxies, no redirects, no HTTP/2 — Pebble and
//! Boulder both serve RFC 8555 over plain HTTP/1.1.

const std = @import("std");
const tls_wrapper = @import("../tls_wrapper.zig");

pub const Error = error{
    ConnectionFailed,
    TlsHandshakeFailed,
    BadResponse,
    ResponseTooLarge,
    OutOfMemory,
    ReadFailed,
    WriteFailed,
};

pub const Method = enum { get, head, post };

pub const Response = struct {
    status: u16,
    /// Owned by the caller (free with allocator).
    body: []u8,
    /// Owned copy of the Replay-Nonce header, when present.
    replay_nonce: ?[]u8 = null,
    /// Owned copy of the Location header, when present.
    location: ?[]u8 = null,

    pub fn deinit(self: *Response, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        if (self.replay_nonce) |n| allocator.free(n);
        if (self.location) |l| allocator.free(l);
    }
};

const max_header_bytes = 32 * 1024;
const max_body_bytes = 8 * 1024 * 1024;

fn methodString(m: Method) []const u8 {
    return switch (m) {
        .get => "GET",
        .head => "HEAD",
        .post => "POST",
    };
}

/// Issues one HTTPS request to `host:port` verifying the server against
/// `root_ca` (never the system store, never skip-verify). SNI and hostname
/// verification use `host`.
pub fn request(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_ca: *const std.crypto.Certificate.Bundle,
    method: Method,
    host: []const u8,
    port: u16,
    path: []const u8,
    content_type: ?[]const u8,
    body: []const u8,
) Error!Response {
    const stream = try connectHost(io, host, port);
    var tls_client = tls_wrapper.TlsClient.connectWithTrust(allocator, io, stream, host, root_ca) catch |err| {
        stream.close(io);
        return switch (err) {
            error.TlsHandshakeFailed => error.TlsHandshakeFailed,
            else => error.ConnectionFailed,
        };
    };
    defer tls_client.deinit();

    const writer = tls_client.writer();
    // Host header carries the port when it is not the https default — Go's
    // net/http (Pebble) routes on it.
    if (port == 443) {
        writer.print("{s} {s} HTTP/1.1\r\nHost: {s}\r\n", .{ methodString(method), path, host }) catch
            return error.WriteFailed;
    } else {
        writer.print("{s} {s} HTTP/1.1\r\nHost: {s}:{d}\r\n", .{ methodString(method), path, host, port }) catch
            return error.WriteFailed;
    }
    writer.writeAll("User-Agent: zig-iroh-relay-acme\r\nConnection: close\r\n") catch return error.WriteFailed;
    if (method == .post) {
        writer.print("Content-Length: {d}\r\n", .{body.len}) catch return error.WriteFailed;
        if (content_type) |ct|
            writer.print("Content-Type: {s}\r\n", .{ct}) catch return error.WriteFailed;
    }
    writer.writeAll("\r\n") catch return error.WriteFailed;
    if (method == .post and body.len > 0)
        writer.writeAll(body) catch return error.WriteFailed;
    writer.flush() catch return error.WriteFailed;

    const reader = tls_client.reader();

    // Status line.
    var status_buf: [1024]u8 = undefined;
    const status_line = readHeaderLine(reader, &status_buf) catch return error.BadResponse;
    const status = parseStatusLine(status_line) orelse return error.BadResponse;

    // Headers.
    var response: Response = .{ .status = status, .body = &.{} };
    errdefer response.deinit(allocator);
    var content_length: ?usize = null;
    var chunked = false;
    var header_bytes: usize = status_line.len;
    var line_buf: [4096]u8 = undefined;
    while (true) {
        const line = readHeaderLine(reader, &line_buf) catch return error.BadResponse;
        header_bytes += line.len + 2;
        if (header_bytes > max_header_bytes) return error.ResponseTooLarge;
        if (line.len == 0) break; // end of header block
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadResponse;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.BadResponse;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (std.ascii.eqlIgnoreCase(value, "chunked")) chunked = true;
        } else if (std.ascii.eqlIgnoreCase(name, "replay-nonce")) {
            response.replay_nonce = try allocator.dupe(u8, value);
        } else if (std.ascii.eqlIgnoreCase(name, "location")) {
            response.location = try allocator.dupe(u8, value);
        }
    }

    // Body. HEAD never has one; 1xx/204/304 neither (ACME newNonce is 204).
    if (method == .head or (status >= 100 and status < 200) or status == 204 or status == 304) {
        response.body = try allocator.dupe(u8, "");
        return response;
    }
    if (content_length) |len| {
        if (len > max_body_bytes) return error.ResponseTooLarge;
        const out = try allocator.alloc(u8, len);
        reader.readSliceAll(out) catch return error.ReadFailed;
        response.body = out;
    } else if (chunked) {
        response.body = try readChunkedBody(allocator, reader, &line_buf);
    } else {
        // No framing: read until close_notify / EOF.
        response.body = reader.allocRemaining(allocator, .limited(max_body_bytes)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.ReadFailed,
        };
    }
    return response;
}

/// Reads one CRLF-terminated header line, returning the line without the
/// trailing CRLF. A bare "\r\n" (end of headers) returns "".
fn readHeaderLine(reader: *std.Io.Reader, buf: []u8) Error![]const u8 {
    const line = reader.takeDelimiterInclusive('\n') catch return error.BadResponse;
    if (line.len > buf.len) return error.ResponseTooLarge;
    var trimmed = line;
    if (trimmed.len > 0 and trimmed[trimmed.len - 1] == '\n') trimmed = trimmed[0 .. trimmed.len - 1];
    if (trimmed.len > 0 and trimmed[trimmed.len - 1] == '\r') trimmed = trimmed[0 .. trimmed.len - 1];
    @memcpy(buf[0..trimmed.len], trimmed);
    return buf[0..trimmed.len];
}

fn parseStatusLine(line: []const u8) ?u16 {
    // "HTTP/1.1 200 OK"
    if (!std.mem.startsWith(u8, line, "HTTP/1.1 ") and !std.mem.startsWith(u8, line, "HTTP/1.0 "))
        return null;
    if (line.len < 12) return null;
    return std.fmt.parseInt(u16, line[9..12], 10) catch null;
}

fn readChunkedBody(allocator: std.mem.Allocator, reader: *std.Io.Reader, line_buf: []u8) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    while (true) {
        const size_line = readHeaderLine(reader, line_buf) catch return error.BadResponse;
        const semi = std.mem.indexOfScalar(u8, size_line, ';') orelse size_line.len;
        const size = std.fmt.parseInt(usize, std.mem.trim(u8, size_line[0..semi], " \t"), 16) catch
            return error.BadResponse;
        if (size == 0) {
            // Trailer section: read until the terminating empty line.
            while (true) {
                const trailer = readHeaderLine(reader, line_buf) catch return error.BadResponse;
                if (trailer.len == 0) break;
            }
            break;
        }
        if (out.items.len + size > max_body_bytes) return error.ResponseTooLarge;
        const chunk = try out.addManyAsSlice(allocator, size);
        reader.readSliceAll(chunk) catch return error.ReadFailed;
        const crlf = reader.take(2) catch return error.BadResponse;
        if (!std.mem.eql(u8, crlf, "\r\n")) return error.BadResponse;
    }
    return out.toOwnedSlice(allocator);
}

/// TCP dial with hostname resolution — the same boundary discipline as
/// `relay/client.zig` (literal IP skips DNS entirely).
fn connectHost(io: std.Io, host: []const u8, port: u16) Error!std.Io.net.Stream {
    if (std.Io.net.IpAddress.parse(host, port)) |addr| {
        return addr.connect(io, .{ .mode = .stream }) catch return error.ConnectionFailed;
    } else |_| {}

    const host_name = std.Io.net.HostName.init(host) catch return error.ConnectionFailed;
    var results_buf: [16]std.Io.net.HostName.LookupResult = undefined;
    var results: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results_buf);
    std.Io.net.HostName.lookup(host_name, io, &results, .{ .port = port }) catch
        return error.ConnectionFailed;

    while (true) {
        var result: [1]std.Io.net.HostName.LookupResult = undefined;
        const n = results.getUncancelable(io, &result, 0) catch |err| switch (err) {
            error.Closed => break,
        };
        if (n == 0) break;
        switch (result[0]) {
            .address => |addr| {
                if (addr.connect(io, .{ .mode = .stream })) |stream| return stream else |_| {}
            },
            .canonical_name => {},
        }
    }
    return error.ConnectionFailed;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "status line parsing" {
    try std.testing.expectEqual(@as(?u16, 200), parseStatusLine("HTTP/1.1 200 OK"));
    try std.testing.expectEqual(@as(?u16, 400), parseStatusLine("HTTP/1.1 400 Bad Request"));
    try std.testing.expectEqual(@as(?u16, null), parseStatusLine("HTTP/2 200"));
    try std.testing.expectEqual(@as(?u16, null), parseStatusLine("garbage"));
}

test "chunked body decoding" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var r: std.Io.Reader = .fixed("4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\nX-T: v\r\n\r\n");
    var line_buf: [128]u8 = undefined;
    const body = try readChunkedBody(a, &r, &line_buf);
    try std.testing.expectEqualStrings("Wikipedia", body);
}

test "header line reader strips crlf and bounds long lines" {
    var r: std.Io.Reader = .fixed("Content-Length: 12\r\n\r\n");
    var buf: [64]u8 = undefined;
    const line = try readHeaderLine(&r, &buf);
    try std.testing.expectEqualStrings("Content-Length: 12", line);
    const empty = try readHeaderLine(&r, &buf);
    try std.testing.expectEqualStrings("", empty);
}
