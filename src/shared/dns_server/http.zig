//! HTTP app for iroh-dns-server: `/`, `/healthz`, `/healthcheck`, `/dns-query`, `/pkarr/{z32}`.

const std = @import("std");
const build_options = @import("build_options");
const root = @import("../root.zig");
const discovery = root.discovery;
const dns_wire = root.dns_wire;
const dns_handler = @import("dns.zig");
const metrics_mod = @import("metrics.zig");
const store_mod = @import("store.zig");

pub const VERSION = "0.1.0-zig";

/// Short commit the binary was built from, or "unknown" outside a git checkout.
pub const GIT_HASH = build_options.git_hash;

/// Longest textual IP a bucket key can hold: 45 for a v4-mapped IPv6 literal,
/// plus room for a scope suffix.
const max_ip_len = 64;

/// Per-client-IP PUT limiter (fixed window per IP).
///
/// A fixed table rather than a hash map: the keys come from unauthenticated
/// remote peers, so an allocating map would itself be the amplification vector.
/// `bucket_count` slots is ample for a pkarr relay's writer set, and the eviction
/// rule (reclaim the least-recently-seen slot) degrades to shared accounting
/// under flood instead of unbounded growth.
pub const PutRateLimiter = struct {
    /// Atomic so a SIGHUP reload can retune the budget while PUTs are in flight.
    limit_per_window: std.atomic.Value(u32) = .init(256),
    window_ns: i64 = 1_000_000_000, // 1s
    mutex: std.Io.Mutex = .init,
    buckets: [bucket_count]Bucket = @splat(.{}),

    pub const bucket_count = 64;

    const Bucket = struct {
        ip_buf: [max_ip_len]u8 = undefined,
        ip_len: u8 = 0,
        window_start_ns: i64 = 0,
        count: u32 = 0,
        last_seen_ns: i64 = 0,

        fn ip(self: *const Bucket) []const u8 {
            return self.ip_buf[0..self.ip_len];
        }
    };

    /// True when `ip` may perform another PUT in the current window.
    /// `limit_per_window == 0` disables limiting entirely.
    pub fn allow(self: *PutRateLimiter, io: std.Io, ip: []const u8) bool {
        const limit = self.limit_per_window.load(.monotonic);
        if (limit == 0) return true;
        const now_wide = std.Io.Clock.now(.awake, io).nanoseconds;
        const now: i64 = if (now_wide <= 0) 1 else @intCast(@min(now_wide, std.math.maxInt(i64)));
        const key = if (ip.len > max_ip_len) ip[0..max_ip_len] else ip;

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const bucket = self.bucketFor(key, now);
        // Refreshed on every hit, not just on claim: otherwise an active bucket
        // looks stale and a flood of new IPs could evict it, handing the evicted
        // client a fresh budget.
        bucket.last_seen_ns = now;
        if (bucket.window_start_ns == 0 or now - bucket.window_start_ns >= self.window_ns) {
            bucket.window_start_ns = now;
            bucket.count = 1;
            return true;
        }
        bucket.count = std.math.add(u32, bucket.count, 1) catch std.math.maxInt(u32);
        return bucket.count <= limit;
    }

    /// Find `key`'s bucket, claiming a free or stalest slot if it has none.
    /// Caller holds `mutex`.
    fn bucketFor(self: *PutRateLimiter, key: []const u8, now: i64) *Bucket {
        var free_slot: ?*Bucket = null;
        var stalest: *Bucket = &self.buckets[0];
        for (&self.buckets) |*bucket| {
            if (bucket.ip_len != 0 and std.mem.eql(u8, bucket.ip(), key)) return bucket;
            if (bucket.ip_len == 0) {
                if (free_slot == null) free_slot = bucket;
            } else if (bucket.last_seen_ns < stalest.last_seen_ns) {
                stalest = bucket;
            }
        }
        const claimed = free_slot orelse stalest;
        @memcpy(claimed.ip_buf[0..key.len], key);
        claimed.ip_len = @intCast(key.len);
        claimed.window_start_ns = 0;
        claimed.count = 0;
        claimed.last_seen_ns = now;
        return claimed;
    }
};

pub const App = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    store: *store_mod.ZoneStore,
    dns: *dns_handler.Handler,
    metrics: *metrics_mod.Metrics,
    put_limiter: ?*PutRateLimiter = null,
    /// Textual peer address of the connection being served, used as the rate
    /// limit key. Empty when unknown (in-process test harnesses).
    client_ip: []const u8 = "",
};

/// Sent on every response so a browser-side pkarr client can talk to the relay
/// directly (the Rust server wires the same permissive CORS layer).
const cors_headers = [_]std.http.Header{
    .{ .name = "access-control-allow-origin", .value = "*" },
    .{ .name = "access-control-allow-methods", .value = "GET, POST, PUT, OPTIONS" },
    .{ .name = "access-control-allow-headers", .value = "content-type" },
};

/// Respond with `body`, adding the CORS headers to `extra`.
fn respond(
    request: *std.http.Server.Request,
    status: std.http.Status,
    body: []const u8,
    extra: []const std.http.Header,
) !std.http.Status {
    var headers: [cors_headers.len + 4]std.http.Header = undefined;
    var n: usize = 0;
    for (cors_headers) |h| {
        headers[n] = h;
        n += 1;
    }
    for (extra) |h| {
        if (n == headers.len) return error.TooManyResponseHeaders;
        headers[n] = h;
        n += 1;
    }
    try request.respond(body, .{
        .status = status,
        .keep_alive = false,
        .extra_headers = headers[0..n],
    });
    return status;
}

pub fn handleRequest(app: *App, request: *std.http.Server.Request) !void {
    _ = app.metrics.http_requests.fetchAdd(1, .monotonic);
    const start_ns = std.Io.Clock.now(.awake, app.io).nanoseconds;

    const outcome = route(app, request);

    const elapsed_ns = std.Io.Clock.now(.awake, app.io).nanoseconds - start_ns;
    if (elapsed_ns > 0) {
        const elapsed_ms: u64 = @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));
        _ = app.metrics.http_requests_duration_ms.fetchAdd(elapsed_ms, .monotonic);
    }

    const status = outcome catch |err| {
        // Nothing was written (or the write itself failed): count it as an error
        // and let the caller drop the connection.
        _ = app.metrics.http_requests_error.fetchAdd(1, .monotonic);
        return err;
    };
    const counter = switch (status.class()) {
        .informational, .success, .redirect => &app.metrics.http_requests_success,
        .client_error, .server_error => &app.metrics.http_requests_error,
    };
    _ = counter.fetchAdd(1, .monotonic);
}

fn route(app: *App, request: *std.http.Server.Request) !std.http.Status {
    const path = request.head.target;
    const path_only = if (std.mem.indexOfScalar(u8, path, '?')) |q| path[0..q] else path;

    // CORS preflight: answer for every route rather than per-handler.
    if (request.head.method == .OPTIONS) {
        return respond(request, .no_content, "", &.{});
    }

    if (std.mem.eql(u8, path_only, "/")) {
        return respond(request, .ok, "Hi!\n", &.{});
    }
    if (std.mem.eql(u8, path_only, "/healthz")) {
        const body = try std.fmt.allocPrint(
            app.allocator,
            "{{\"status\":\"ok\",\"version\":\"{s}\",\"git_hash\":\"{s}\"}}",
            .{ VERSION, GIT_HASH },
        );
        defer app.allocator.free(body);
        return respond(request, .ok, body, &.{
            .{ .name = "content-type", .value = "application/json" },
        });
    }
    if (std.mem.eql(u8, path_only, "/healthcheck")) {
        return respond(request, .ok, "OK", &.{});
    }
    if (std.mem.eql(u8, path_only, "/dns-query")) {
        return handleDoh(app, request, path);
    }
    if (std.mem.startsWith(u8, path_only, "/pkarr/")) {
        return handlePkarr(app, request, path_only);
    }
    return respond(request, .not_found, "not found\n", &.{});
}

fn handleDoh(app: *App, request: *std.http.Server.Request, full_target: []const u8) !std.http.Status {
    _ = app.metrics.doh_requests.fetchAdd(1, .monotonic);
    const query_string: []const u8 = if (std.mem.indexOfScalar(u8, full_target, '?')) |q|
        full_target[q + 1 ..]
    else
        "";

    // RFC 8484 wire mode vs. the Google/Cloudflare JSON mode. JSON is selected by
    // `name=`/`type=` params or an `application/dns-json` Accept header; wire mode
    // stays the default so existing `?dns=<base64url>` clients are untouched.
    if (request.head.method == .GET) {
        const wants_json = findQueryParam(query_string, "name") != null or acceptsDnsJson(request);
        if (wants_json) return handleDohJson(app, request, query_string);
    }

    var query_buf: [2048]u8 = undefined;
    const query: []const u8 = switch (request.head.method) {
        .GET => blk: {
            const dns_param = findQueryParam(query_string, "dns") orelse {
                return respond(request, .bad_request, "missing dns param\n", &.{});
            };
            const n = base64UrlDecode(dns_param, &query_buf) catch {
                return respond(request, .bad_request, "bad dns param\n", &.{});
            };
            break :blk query_buf[0..n];
        },
        .POST => blk: {
            var body: std.Io.Writer = .fixed(&query_buf);
            var read_buf: [512]u8 = undefined;
            const body_reader = request.readerExpectNone(&read_buf);
            _ = body_reader.streamRemaining(&body) catch {
                return respond(request, .bad_request, "bad body\n", &.{});
            };
            break :blk body.buffered();
        },
        else => return respond(request, .method_not_allowed, "method not allowed\n", &.{}),
    };

    const resp = app.dns.answer(query) catch {
        return respond(request, .internal_server_error, "dns error\n", &.{});
    };
    defer app.allocator.free(resp);

    // RFC 8484 §5.1: a DoH answer is cacheable for the TTL of its records; this
    // zone's authoritative TTL is the operator's `default_ttl`.
    var cache_buf: [48]u8 = undefined;
    const cache_control = try std.fmt.bufPrint(&cache_buf, "s-maxage={d}", .{app.dns.liveConfig().default_ttl});
    return respond(request, .ok, resp, &.{
        .{ .name = "content-type", .value = "application/dns-message" },
        .{ .name = "cache-control", .value = cache_control },
    });
}

/// JSON DoH: `GET /dns-query?name=<name>&type=<A|TXT|16|…>`.
fn handleDohJson(
    app: *App,
    request: *std.http.Server.Request,
    query_string: []const u8,
) !std.http.Status {
    const name_param = findQueryParam(query_string, "name") orelse {
        return respond(request, .bad_request, "{\"Status\":2,\"Comment\":\"missing name\"}", &json_content_type);
    };
    var name_buf: [256]u8 = undefined;
    const name = percentDecode(name_param, &name_buf) catch {
        return respond(request, .bad_request, "{\"Status\":2,\"Comment\":\"bad name\"}", &json_content_type);
    };
    if (name.len == 0) {
        return respond(request, .bad_request, "{\"Status\":2,\"Comment\":\"missing name\"}", &json_content_type);
    }
    // Absent `type` means A, matching the JSON-DoH convention.
    const qtype = parseQueryType(findQueryParam(query_string, "type") orelse "A") orelse {
        return respond(request, .bad_request, "{\"Status\":2,\"Comment\":\"bad type\"}", &json_content_type);
    };

    const query = buildJsonModeQuery(app.allocator, name, qtype) catch {
        return respond(request, .bad_request, "{\"Status\":2,\"Comment\":\"bad name\"}", &json_content_type);
    };
    defer app.allocator.free(query);

    const resp = app.dns.answer(query) catch {
        return respond(request, .internal_server_error, "{\"Status\":2,\"Comment\":\"dns error\"}", &json_content_type);
    };
    defer app.allocator.free(resp);

    const body = try renderDnsJson(app.allocator, name, qtype, resp);
    defer app.allocator.free(body);

    var cache_buf: [48]u8 = undefined;
    const cache_control = try std.fmt.bufPrint(&cache_buf, "s-maxage={d}", .{app.dns.liveConfig().default_ttl});
    return respond(request, .ok, body, &.{
        json_content_type[0],
        .{ .name = "cache-control", .value = cache_control },
    });
}

const json_content_type = [_]std.http.Header{
    .{ .name = "content-type", .value = "application/dns-json" },
};

fn acceptsDnsJson(request: *std.http.Server.Request) bool {
    var it = request.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "accept")) continue;
        if (std.mem.indexOf(u8, header.value, "application/dns-json") != null) return true;
    }
    return false;
}

fn parseQueryType(raw: []const u8) ?u16 {
    if (raw.len == 0) return null;
    if (std.ascii.isDigit(raw[0])) return std.fmt.parseInt(u16, raw, 10) catch null;
    const names = [_]struct { name: []const u8, typ: u16 }{
        .{ .name = "A", .typ = dns_wire.TYPE_A },
        .{ .name = "NS", .typ = dns_wire.TYPE_NS },
        .{ .name = "SOA", .typ = dns_wire.TYPE_SOA },
        .{ .name = "TXT", .typ = dns_wire.TYPE_TXT },
        .{ .name = "AAAA", .typ = dns_wire.TYPE_AAAA },
    };
    for (names) |entry| {
        if (std.ascii.eqlIgnoreCase(raw, entry.name)) return entry.typ;
    }
    return null;
}

fn buildJsonModeQuery(allocator: std.mem.Allocator, name: []const u8, qtype: u16) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    // id 0 / RD set, same header shape as `dns_wire.buildTxtQuery`.
    try out.appendSlice(allocator, &[_]u8{ 0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 });
    try dns_wire.appendName(&out, allocator, name);
    var tail: [4]u8 = undefined;
    std.mem.writeInt(u16, tail[0..2], qtype, .big);
    std.mem.writeInt(u16, tail[2..4], dns_wire.CLASS_IN, .big);
    try out.appendSlice(allocator, &tail);
    return out.toOwnedSlice(allocator);
}

/// Render a wire answer as the JSON-DoH object. `data` follows presentation
/// format for A/AAAA and the quoted-string form for TXT; other types fall back
/// to lowercase hex of the raw RDATA.
fn renderDnsJson(
    allocator: std.mem.Allocator,
    name: []const u8,
    qtype: u16,
    wire: []const u8,
) ![]u8 {
    if (wire.len < 12) return error.PacketTooShort;
    const flags = std.mem.readInt(u16, wire[2..4], .big);
    const rcode: u4 = @truncate(flags);

    // A malformed answer section still yields a well-formed JSON envelope
    // carrying the RCODE, which is more useful to a client than a 500.
    const answers = dns_handler.parseRawAnswers(allocator, wire) catch
        try allocator.alloc(dns_handler.RawAnswer, 0);
    defer dns_handler.freeRawAnswers(allocator, answers);

    var body: std.Io.Writer.Allocating = .init(allocator);
    defer body.deinit();
    const w = &body.writer;
    try w.print("{{\"Status\":{d},\"TC\":{s},\"RD\":true,\"RA\":false,\"AD\":false,\"CD\":false,", .{
        rcode,
        if ((flags & 0x0200) != 0) "true" else "false",
    });
    try w.writeAll("\"Question\":[{\"name\":\"");
    try writeJsonEscaped(w, name);
    try w.print("\",\"type\":{d}}}],\"Answer\":[", .{qtype});
    for (answers, 0..) |a, i| {
        if (i != 0) try w.writeAll(",");
        try w.writeAll("{\"name\":\"");
        try writeJsonEscaped(w, a.name);
        try w.print("\",\"type\":{d},\"TTL\":{d},\"data\":\"", .{ a.typ, a.ttl });
        try writeRdataJson(w, a.typ, a.rdata);
        try w.writeAll("\"}");
    }
    try w.writeAll("]}");
    return allocator.dupe(u8, body.writer.buffered());
}

fn writeRdataJson(w: *std.Io.Writer, typ: u16, rdata: []const u8) !void {
    switch (typ) {
        dns_wire.TYPE_A => {
            if (rdata.len != 4) return writeHex(w, rdata);
            try w.print("{d}.{d}.{d}.{d}", .{ rdata[0], rdata[1], rdata[2], rdata[3] });
        },
        dns_wire.TYPE_AAAA => {
            if (rdata.len != 16) return writeHex(w, rdata);
            // `Ip6Address.format` would add the `[…]:port` wrapper; the
            // Unresolved form is the bare textual address DNS JSON wants.
            const addr: std.Io.net.Ip6Address.Unresolved = .{
                .bytes = rdata[0..16].*,
                .interface_name = null,
            };
            try w.print("{f}", .{addr});
        },
        dns_wire.TYPE_TXT => {
            // Character-strings are concatenated the way the JSON DoH APIs do.
            var off: usize = 0;
            while (off < rdata.len) {
                const len = rdata[off];
                off += 1;
                if (off + len > rdata.len) break;
                try writeJsonEscaped(w, rdata[off .. off + len]);
                off += len;
            }
        },
        else => try writeHex(w, rdata),
    }
}

fn writeHex(w: *std.Io.Writer, bytes: []const u8) !void {
    for (bytes) |b| try w.print("{x:0>2}", .{b});
}

fn writeJsonEscaped(w: *std.Io.Writer, s: []const u8) !void {
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0...8, 11, 12, 14...31 => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
}

fn percentDecode(src: []const u8, dest: []u8) ![]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        if (n == dest.len) return error.NoSpaceLeft;
        const c = src[i];
        if (c == '%') {
            if (i + 2 >= src.len) return error.InvalidPercentEncoding;
            dest[n] = try std.fmt.parseInt(u8, src[i + 1 .. i + 3], 16);
            i += 3;
        } else {
            dest[n] = if (c == '+') ' ' else c;
            i += 1;
        }
        n += 1;
    }
    return dest[0..n];
}

fn handlePkarr(app: *App, request: *std.http.Server.Request, path: []const u8) !std.http.Status {
    const z32 = path["/pkarr/".len..];
    const public_key = root.PublicKey.fromZ32(z32) catch {
        return respond(request, .bad_request, "bad node id\n", &.{});
    };

    switch (request.head.method) {
        .PUT => {
            if (app.put_limiter) |lim| {
                if (!lim.allow(app.io, app.client_ip)) {
                    _ = app.metrics.pkarr_puts_rate_limited.fetchAdd(1, .monotonic);
                    return respond(request, .too_many_requests, "rate limited\n", &.{});
                }
            }
            if (request.head.content_type) |content_type| {
                if (!std.ascii.eqlIgnoreCase(content_type, discovery.RELAY_CONTENT_TYPE)) {
                    return respond(request, .unsupported_media_type, "unsupported media type\n", &.{});
                }
            }
            var body_storage: [discovery.MAX_SIGNED_PACKET_SIZE]u8 = undefined;
            var body: std.Io.Writer = .fixed(&body_storage);
            var read_buf: [1024]u8 = undefined;
            const body_reader = request.readerExpectNone(&read_buf);
            _ = body_reader.streamRemaining(&body) catch |err| switch (err) {
                error.ReadFailed => return respond(request, .bad_request, "read failed\n", &.{}),
                error.WriteFailed => return respond(request, .payload_too_large, "payload too large\n", &.{}),
            };
            const payload = body.buffered();
            // `putRelayPayload` verifies the Ed25519 signature against the key in
            // the URL. A tampered packet lands in the `else` arm as a 400 — this
            // is the only thing standing between the store and forged zones.
            app.store.putRelayPayload(public_key, payload) catch |err| switch (err) {
                error.OlderPacket => return respond(request, .no_content, "", &.{}),
                else => return respond(request, .bad_request, "bad packet\n", &.{}),
            };
            _ = app.metrics.pkarr_puts.fetchAdd(1, .monotonic);
            return respond(request, .no_content, "", &.{});
        },
        .GET => {
            const payload = app.store.getRelayPayload(public_key) catch |err| switch (err) {
                error.MissingPacket => return respond(request, .not_found, "not found\n", &.{}),
                else => return err,
            };
            defer app.allocator.free(payload);
            _ = app.metrics.pkarr_gets.fetchAdd(1, .monotonic);
            return respond(request, .ok, payload, &.{
                .{ .name = "content-type", .value = discovery.RELAY_CONTENT_TYPE },
            });
        },
        else => return respond(request, .method_not_allowed, "method not allowed\n", &.{}),
    }
}

fn findQueryParam(qs: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, qs, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
    }
    return null;
}

fn base64UrlDecode(src: []const u8, dest: []u8) !usize {
    // std.base64.url_safe_no_pad decoder
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const max = try decoder.calcSizeForSlice(src);
    if (max > dest.len) return error.NoSpaceLeft;
    try decoder.decode(dest[0..max], src);
    return max;
}

test "PUT rate limit buckets are per client IP" {
    const io = std.testing.io;
    // A 1-hour window so nothing rolls over mid-test.
    var limiter: PutRateLimiter = .{ .limit_per_window = .init(2), .window_ns = 3_600 * std.time.ns_per_s };

    // First IP burns its whole budget.
    try std.testing.expect(limiter.allow(io, "192.0.2.1"));
    try std.testing.expect(limiter.allow(io, "192.0.2.1"));
    try std.testing.expect(!limiter.allow(io, "192.0.2.1"));

    // A different IP must not inherit that exhaustion — the bug a single global
    // counter has.
    try std.testing.expect(limiter.allow(io, "192.0.2.2"));
    try std.testing.expect(limiter.allow(io, "192.0.2.2"));
    try std.testing.expect(!limiter.allow(io, "192.0.2.2"));

    // A third, so the buckets are clearly independent and not just alternating.
    try std.testing.expect(limiter.allow(io, "2001:db8::1"));
    // The first IP is still blocked; its bucket was not reset by the others.
    try std.testing.expect(!limiter.allow(io, "192.0.2.1"));
}

test "PUT rate limit of zero disables limiting" {
    const io = std.testing.io;
    var limiter: PutRateLimiter = .{ .limit_per_window = .init(0) };
    for (0..PutRateLimiter.bucket_count * 4) |_| {
        try std.testing.expect(limiter.allow(io, "192.0.2.1"));
    }
}

test "PUT rate limit stays bounded when flooded with distinct IPs" {
    const io = std.testing.io;
    var limiter: PutRateLimiter = .{ .limit_per_window = .init(1), .window_ns = 3_600 * std.time.ns_per_s };
    var buf: [32]u8 = undefined;
    // More distinct sources than there are slots: the table must recycle rather
    // than grow, and every fresh source still gets its first PUT.
    for (0..PutRateLimiter.bucket_count * 3) |i| {
        const ip = try std.fmt.bufPrint(&buf, "198.51.100.{d}", .{i % 256});
        try std.testing.expect(limiter.allow(io, ip));
    }
}

const TestHttpCtx = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    listener: *std.Io.net.Server,
    app: *App,
};

fn testServeOne(ctx: *TestHttpCtx) !void {
    var stream = try ctx.listener.accept(ctx.io);
    defer stream.close(ctx.io);
    var read_buf: [4096]u8 = undefined;
    var write_buf: [4096]u8 = undefined;
    var stream_reader = stream.reader(ctx.io, &read_buf);
    var stream_writer = stream.writer(ctx.io, &write_buf);
    var http_server = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
    var request = try http_server.receiveHead();
    try handleRequest(ctx.app, &request);
    try stream_writer.interface.flush();
}

test "health and root routes over HTTP" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-http-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    var store = try store_mod.ZoneStore.init(allocator, io, rel);
    defer store.deinit();
    var metrics: metrics_mod.Metrics = .{};
    const cfg: @import("config.zig").Config = .{ .data_dir = rel };
    var dns: dns_handler.Handler = .{
        .allocator = allocator,
        .config = &cfg,
        .store = &store,
        .metrics = &metrics,
    };
    var app: App = .{
        .allocator = allocator,
        .io = io,
        .store = &store,
        .dns = &dns,
        .metrics = &metrics,
    };

    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var ctx: TestHttpCtx = .{
        .io = io,
        .allocator = allocator,
        .listener = &listener,
        .app = &app,
    };

    // /healthz
    {
        const thread = try std.Thread.spawn(.{}, testServeOne, .{&ctx});
        defer thread.join();
        var client: std.http.Client = .{ .allocator = allocator, .io = io };
        defer client.deinit();
        const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/healthz", .{listener.socket.address.getPort()});
        defer allocator.free(url);
        var body_buf: [256]u8 = undefined;
        var body_w: std.Io.Writer = .fixed(&body_buf);
        const result = try client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .response_writer = &body_w,
        });
        try std.testing.expectEqual(.ok, result.status);
        try std.testing.expect(std.mem.indexOf(u8, body_w.buffered(), "\"status\":\"ok\"") != null);
    }

    // /
    {
        const thread = try std.Thread.spawn(.{}, testServeOne, .{&ctx});
        defer thread.join();
        var client: std.http.Client = .{ .allocator = allocator, .io = io };
        defer client.deinit();
        const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/", .{listener.socket.address.getPort()});
        defer allocator.free(url);
        var body_buf: [64]u8 = undefined;
        var body_w: std.Io.Writer = .fixed(&body_buf);
        const result = try client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .response_writer = &body_w,
        });
        try std.testing.expectEqual(.ok, result.status);
        try std.testing.expectEqualStrings("Hi!\n", body_w.buffered());
    }
}
