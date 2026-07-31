//! DNS-server Prometheus metrics + separate metrics HTTP listener helpers.

const std = @import("std");

pub const Metrics = struct {
    dns_requests_udp: std.atomic.Value(u64) = .init(0),
    dns_requests_tcp: std.atomic.Value(u64) = .init(0),
    dns_lookups_success: std.atomic.Value(u64) = .init(0),
    dns_lookups_nxdomain: std.atomic.Value(u64) = .init(0),
    dns_lookups_refused: std.atomic.Value(u64) = .init(0),
    /// Queries the UDP/TCP serve loops could not answer at all (handler error),
    /// as distinct from an answered query carrying NXDOMAIN/REFUSED.
    dns_query_errors: std.atomic.Value(u64) = .init(0),
    /// Answer path reached the mainline seam and found no live DHT client.
    dns_mainline_unavailable: std.atomic.Value(u64) = .init(0),
    /// Zone-store misses enqueued for background mainline resolve.
    dns_mainline_enqueued: std.atomic.Value(u64) = .init(0),
    /// Background mainline resolves that wrote a packet into the zone store.
    dns_mainline_resolved: std.atomic.Value(u64) = .init(0),
    pkarr_puts: std.atomic.Value(u64) = .init(0),
    pkarr_gets: std.atomic.Value(u64) = .init(0),
    pkarr_puts_rate_limited: std.atomic.Value(u64) = .init(0),
    http_requests: std.atomic.Value(u64) = .init(0),
    /// Requests answered with a 1xx/2xx/3xx status.
    http_requests_success: std.atomic.Value(u64) = .init(0),
    /// Requests answered with a 4xx/5xx status, or that failed before responding.
    http_requests_error: std.atomic.Value(u64) = .init(0),
    /// Cumulative handler wall time. A counter (not a histogram) so a scraper
    /// derives mean latency from `rate(duration_ms) / rate(requests)`.
    http_requests_duration_ms: std.atomic.Value(u64) = .init(0),
    doh_requests: std.atomic.Value(u64) = .init(0),
    store_packets_inserted: std.atomic.Value(u64) = .init(0),
    store_packets_updated: std.atomic.Value(u64) = .init(0),
    store_packets_removed: std.atomic.Value(u64) = .init(0),
    store_packets_expired: std.atomic.Value(u64) = .init(0),
};

fn counter(w: *std.Io.Writer, comptime name: []const u8, comptime help: []const u8, value: u64) !void {
    try w.print(
        "# HELP irohdns_" ++ name ++ " " ++ help ++ "\n" ++
            "# TYPE irohdns_" ++ name ++ " counter\n" ++
            "irohdns_" ++ name ++ " {d}\n",
        .{value},
    );
}

pub fn renderPrometheus(w: *std.Io.Writer, m: *const Metrics) !void {
    try counter(w, "dns_requests_udp", "DNS queries received over UDP.", m.dns_requests_udp.load(.monotonic));
    try counter(w, "dns_requests_tcp", "DNS queries received over TCP.", m.dns_requests_tcp.load(.monotonic));
    try counter(w, "dns_lookups_success", "DNS lookups that returned answers.", m.dns_lookups_success.load(.monotonic));
    try counter(w, "dns_lookups_nxdomain", "DNS lookups that returned NXDOMAIN.", m.dns_lookups_nxdomain.load(.monotonic));
    try counter(w, "dns_lookups_refused", "DNS lookups that returned REFUSED.", m.dns_lookups_refused.load(.monotonic));
    try counter(w, "dns_query_errors", "DNS queries the serve loops failed to answer.", m.dns_query_errors.load(.monotonic));
    try counter(w, "dns_mainline_unavailable", "Answer-path mainline lookups with no live DHT client.", m.dns_mainline_unavailable.load(.monotonic));
    try counter(w, "dns_mainline_enqueued", "Zone-store misses enqueued for background mainline resolve.", m.dns_mainline_enqueued.load(.monotonic));
    try counter(w, "dns_mainline_resolved", "Background mainline resolves written into the zone store.", m.dns_mainline_resolved.load(.monotonic));
    try counter(w, "pkarr_puts", "Successful pkarr PUT requests.", m.pkarr_puts.load(.monotonic));
    try counter(w, "pkarr_gets", "Successful pkarr GET requests.", m.pkarr_gets.load(.monotonic));
    try counter(w, "pkarr_puts_rate_limited", "pkarr PUTs rejected by the per-IP rate limiter.", m.pkarr_puts_rate_limited.load(.monotonic));
    try counter(w, "http_requests", "HTTP requests handled by the dns-server app.", m.http_requests.load(.monotonic));
    try counter(w, "http_requests_success", "HTTP requests answered with a non-error status.", m.http_requests_success.load(.monotonic));
    try counter(w, "http_requests_error", "HTTP requests answered with a 4xx/5xx status or that failed.", m.http_requests_error.load(.monotonic));
    try counter(w, "http_requests_duration_ms", "Cumulative HTTP handler wall time in milliseconds.", m.http_requests_duration_ms.load(.monotonic));
    try counter(w, "doh_requests", "DoH /dns-query requests.", m.doh_requests.load(.monotonic));
    try counter(w, "store_packets_inserted", "Signed packets stored for a previously unknown key.", m.store_packets_inserted.load(.monotonic));
    try counter(w, "store_packets_updated", "Signed packets that replaced an existing key's packet.", m.store_packets_updated.load(.monotonic));
    try counter(w, "store_packets_removed", "Signed packets removed from the zone store.", m.store_packets_removed.load(.monotonic));
    try counter(w, "store_packets_expired", "Signed packets evicted for exceeding the max age.", m.store_packets_expired.load(.monotonic));
}

pub fn serveOne(io: std.Io, stream: std.Io.net.Stream, metrics: *const Metrics) void {
    defer stream.close(io);
    var read_buf: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var write_buf: [2048]u8 = undefined;
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
        writeResponse(w, "405 Method Not Allowed", "text/plain", "method not allowed\n") catch {};
        return;
    }
    if (std.mem.eql(u8, path, "/metrics")) {
        var body: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
        defer body.deinit();
        renderPrometheus(&body.writer, metrics) catch return;
        writeResponse(w, "200 OK", "text/plain; version=0.0.4", body.writer.buffered()) catch {};
        return;
    }
    writeResponse(w, "404 Not Found", "text/plain", "not found\n") catch {};
}

fn writeResponse(w: *std.Io.Writer, status: []const u8, content_type: []const u8, body: []const u8) !void {
    try w.print(
        "HTTP/1.1 {s}\r\ncontent-type: {s}\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n",
        .{ status, content_type, body.len },
    );
    try w.writeAll(body);
    try w.flush();
}

test "renderPrometheus emits irohdns_ counters" {
    var m: Metrics = .{};
    _ = m.dns_requests_udp.fetchAdd(2, .monotonic);
    var body: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer body.deinit();
    try renderPrometheus(&body.writer, &m);
    try std.testing.expect(std.mem.indexOf(u8, body.writer.buffered(), "irohdns_dns_requests_udp 2") != null);
}

test "renderPrometheus exposes HTTP outcome and store lifecycle series" {
    var m: Metrics = .{};
    _ = m.http_requests_success.fetchAdd(3, .monotonic);
    _ = m.http_requests_error.fetchAdd(1, .monotonic);
    _ = m.http_requests_duration_ms.fetchAdd(17, .monotonic);
    _ = m.dns_query_errors.fetchAdd(4, .monotonic);
    _ = m.store_packets_inserted.fetchAdd(5, .monotonic);
    _ = m.store_packets_updated.fetchAdd(6, .monotonic);
    _ = m.store_packets_removed.fetchAdd(7, .monotonic);
    _ = m.store_packets_expired.fetchAdd(8, .monotonic);

    var body: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer body.deinit();
    try renderPrometheus(&body.writer, &m);
    const out = body.writer.buffered();
    for ([_][]const u8{
        "irohdns_http_requests_success 3",
        "irohdns_http_requests_error 1",
        "irohdns_http_requests_duration_ms 17",
        "irohdns_dns_query_errors 4",
        "irohdns_store_packets_inserted 5",
        "irohdns_store_packets_updated 6",
        "irohdns_store_packets_removed 7",
        "irohdns_store_packets_expired 8",
    }) |needle| {
        if (std.mem.indexOf(u8, out, needle) == null) {
            std.debug.print("missing prometheus series: {s}\n", .{needle});
            return error.MissingSeries;
        }
    }
}
