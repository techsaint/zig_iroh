//! Relay server metrics + health HTTP endpoint.
//!
//! Counters are plain atomics on the server (no metrics framework — the relay
//! is a single binary; a registry would be speculative machinery). Names
//! follow upstream iroh-relay (`relayserver_*`, group `relay`) so dashboards
//! and alerts written for the Rust relay keep working; that naming IS an
//! operator-facing compat surface even though nothing on the wire forces it.
//!
//! The endpoint is a tiny plain-HTTP listener on a SEPARATE address (upstream:
//! `metrics_bind_addr`, default `[::]:9090`, served by iroh-metrics). Routes:
//! `GET /health` → `200 {"status":"ok"}` (upstream `/healthz` shape, plus the
//! `/ping`-style liveness ops probes actually use), `GET /metrics` →
//! OpenMetrics text. Anything else → 404 (deliberate deviation from upstream's
//! path-agnostic metrics handler: a typo'd probe path should fail loudly).

const std = @import("std");

pub const Metrics = struct {
    accepts: std.atomic.Value(u64) = .init(0),
    disconnects: std.atomic.Value(u64) = .init(0),
    bytes_sent: std.atomic.Value(u64) = .init(0),
    bytes_recv: std.atomic.Value(u64) = .init(0),
    send_packets_sent: std.atomic.Value(u64) = .init(0),
    send_packets_recv: std.atomic.Value(u64) = .init(0),
    send_packets_dropped: std.atomic.Value(u64) = .init(0),
    got_ping: std.atomic.Value(u64) = .init(0),
    sent_pong: std.atomic.Value(u64) = .init(0),
    bytes_rx_ratelimited_total: std.atomic.Value(u64) = .init(0),
    conns_rx_ratelimited_total: std.atomic.Value(u64) = .init(0),
};

fn counter(w: *std.Io.Writer, comptime name: []const u8, comptime help: []const u8, value: u64) !void {
    try w.print(
        "# HELP relayserver_" ++ name ++ " " ++ help ++ "\n" ++
            "# TYPE relayserver_" ++ name ++ " counter\n" ++
            "relayserver_" ++ name ++ " {d}\n",
        .{value},
    );
}

/// Renders the OpenMetrics text exposition for `/metrics`.
/// `active_clients` is the live registry size (a gauge, not a counter).
pub fn renderPrometheus(w: *std.Io.Writer, m: *const Metrics, active_clients: u64) !void {
    try counter(w, "accepts", "Number of client connections accepted.", m.accepts.load(.monotonic));
    try counter(w, "disconnects", "Number of client connections disconnected.", m.disconnects.load(.monotonic));
    try counter(w, "bytes_sent", "Relay payload bytes sent to clients.", m.bytes_sent.load(.monotonic));
    try counter(w, "bytes_recv", "Relay payload bytes received from clients.", m.bytes_recv.load(.monotonic));
    try counter(w, "send_packets_sent", "Datagrams forwarded to a recipient.", m.send_packets_sent.load(.monotonic));
    try counter(w, "send_packets_recv", "Datagrams received for forwarding.", m.send_packets_recv.load(.monotonic));
    try counter(w, "send_packets_dropped", "Datagrams dropped (unknown recipient or full queue).", m.send_packets_dropped.load(.monotonic));
    try counter(w, "got_ping", "Relay pings received from clients.", m.got_ping.load(.monotonic));
    try counter(w, "sent_pong", "Relay pongs sent to clients.", m.sent_pong.load(.monotonic));
    try counter(w, "bytes_rx_ratelimited_total", "Bytes delayed by the per-connection receive rate limit.", m.bytes_rx_ratelimited_total.load(.monotonic));
    try counter(w, "conns_rx_ratelimited_total", "Connections that hit the receive rate limit at least once.", m.conns_rx_ratelimited_total.load(.monotonic));
    try w.print(
        "# HELP relayserver_unique_client_keys Currently registered client endpoint ids.\n" ++
            "# TYPE relayserver_unique_client_keys gauge\n" ++
            "relayserver_unique_client_keys {d}\n",
        .{active_clients},
    );
}

pub const health_body = "{\"status\":\"ok\"}";

fn writeResponse(
    io: std.Io,
    writer: *std.Io.Writer,
    status: []const u8,
    content_type: []const u8,
    body: []const u8,
) !void {
    try writer.print(
        "HTTP/1.1 {s}\r\ncontent-type: {s}\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n",
        .{ status, content_type, body.len },
    );
    try writer.writeAll(body);
    try writer.flush();
    _ = io;
}

/// Serves one accepted connection: read the request line, route, respond,
/// close. Header bytes are bounded (4 KiB read buffer); only the request
/// line is parsed — there is nothing else this endpoint needs.
pub fn serveOne(
    io: std.Io,
    stream: std.Io.net.Stream,
    metrics: *const Metrics,
    active_clients: u64,
) void {
    defer stream.close(io);
    // One read buffer bounds the request line: anything longer trips
    // StreamTooLong and the connection is closed.
    var read_buf: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var write_buf: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    const r = &reader.interface;
    const w = &writer.interface;

    const raw_line = r.takeDelimiter('\n') catch return;
    const line = raw_line orelse return;
    const trimmed = std.mem.trimEnd(u8, line, "\r");
    var parts = std.mem.splitScalar(u8, trimmed, ' ');
    const method = parts.next() orelse return;
    const target = parts.next() orelse return;
    const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;

    if (!std.mem.eql(u8, method, "GET")) {
        writeResponse(io, w, "405 Method Not Allowed", "text/plain", "method not allowed\n") catch {};
        return;
    }
    if (std.mem.eql(u8, path, "/health") or std.mem.eql(u8, path, "/healthz")) {
        writeResponse(io, w, "200 OK", "application/json", health_body) catch {};
        return;
    }
    if (std.mem.eql(u8, path, "/metrics")) {
        var body: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
        defer body.deinit();
        renderPrometheus(&body.writer, metrics, active_clients) catch return;
        writeResponse(io, w, "200 OK", "text/plain; version=0.0.4", body.writer.buffered()) catch {};
        return;
    }
    writeResponse(io, w, "404 Not Found", "text/plain", "not found\n") catch {};
}

test "renderPrometheus emits iroh-compatible names" {
    var m: Metrics = .{};
    _ = m.accepts.fetchAdd(3, .monotonic);
    _ = m.bytes_recv.fetchAdd(42, .monotonic);
    var body: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer body.deinit();
    try renderPrometheus(&body.writer, &m, 2);
    const text = body.writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, text, "relayserver_accepts 3") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "relayserver_bytes_recv 42") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "relayserver_unique_client_keys 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "relayserver_bytes_rx_ratelimited_total 0") != null);
}
