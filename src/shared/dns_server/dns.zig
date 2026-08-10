//! Authoritative DNS query handling for pkarr zones + static origin records.
//!
//! UDP + TCP serving are wired by `server.zig` (TCP uses RFC 1035 length-prefix).

const std = @import("std");
const root = @import("../root.zig");
const discovery = root.discovery;
const dns_wire = root.dns_wire;
const config_mod = @import("config.zig");
const mainline = @import("mainline.zig");
const metrics_mod = @import("metrics.zig");
const store_mod = @import("store.zig");

/// Publishes a config generation to the serve threads.
///
/// SIGHUP reload swaps a whole immutable `Config` behind one atomic pointer
/// instead of editing the live struct in place: a field-by-field update would
/// race an in-flight `answer` and could tear a slice (new pointer, old length).
pub const ConfigSource = std.atomic.Value(*const config_mod.Config);

pub const Handler = struct {
    allocator: std.mem.Allocator,
    config: *const config_mod.Config,
    store: *store_mod.ZoneStore,
    metrics: *metrics_mod.Metrics,
    /// When set, the generation published here wins over `config`.
    config_source: ?*ConfigSource = null,
    /// Background mainline resolver; answer path only enqueues.
    mainline_resolver: ?*mainline.BackgroundResolver = null,

    /// The config generation to serve this request from. Read once per request so
    /// a reload cannot change the answer half-way through building it.
    pub fn liveConfig(self: *const Handler) *const config_mod.Config {
        if (self.config_source) |src| return src.load(.acquire);
        return self.config;
    }

    pub fn answer(self: *Handler, query: []const u8) ![]u8 {
        const cfg = self.liveConfig();
        const q = try dns_wire.parseQuestion(self.allocator, query);
        defer self.allocator.free(q.name);

        if (q.typ == dns_wire.TYPE_AXFR) {
            // Zone transfers are never served: the whole point of a pkarr zone is
            // that a key's records are fetched by name, not enumerated.
            _ = self.metrics.dns_lookups_refused.fetchAdd(1, .monotonic);
            return dns_wire.buildResponse(self.allocator, q.id, q.name, q.typ, dns_wire.RCODE_REFUSED, &.{}, cfg.default_ttl);
        }

        if (try self.answerStatic(cfg, q)) |resp| return resp;
        if (try self.answerPkarr(cfg, q)) |resp| {
            _ = self.metrics.dns_lookups_success.fetchAdd(1, .monotonic);
            return resp;
        }

        _ = self.metrics.dns_lookups_nxdomain.fetchAdd(1, .monotonic);
        return dns_wire.buildResponse(self.allocator, q.id, q.name, q.typ, dns_wire.RCODE_NXDOMAIN, &.{}, cfg.default_ttl);
    }

    fn answerStatic(self: *Handler, cfg: *const config_mod.Config, q: dns_wire.Question) !?[]u8 {
        const name = std.mem.trimEnd(u8, q.name, ".");
        for (cfg.origins) |origin_raw| {
            const origin = std.mem.trimEnd(u8, origin_raw, ".");
            if (origin.len == 0) continue;
            if (!std.ascii.eqlIgnoreCase(name, origin)) continue;

            if (q.typ == dns_wire.TYPE_SOA) {
                const soa = try parseSoa(cfg.default_soa);
                return @as(?[]u8, try dns_wire.buildSoaResponse(
                    self.allocator,
                    q.id,
                    q.name,
                    soa.mname,
                    soa.rname,
                    soa.serial,
                    cfg.default_ttl,
                ));
            }
            if (q.typ == dns_wire.TYPE_A) {
                if (cfg.rr_a) |a| {
                    return @as(?[]u8, try buildAResponse(self.allocator, q.id, q.name, a, cfg.default_ttl));
                }
            }
            if (q.typ == dns_wire.TYPE_AAAA) {
                if (cfg.rr_aaaa) |aaaa| {
                    return @as(?[]u8, try buildAaaaResponse(self.allocator, q.id, q.name, aaaa, cfg.default_ttl));
                }
            }
            if (q.typ == dns_wire.TYPE_NS) {
                if (cfg.rr_ns) |ns| {
                    return @as(?[]u8, try buildNsResponse(self.allocator, q.id, q.name, ns, cfg.default_ttl));
                }
            }
        }
        return null;
    }

    /// Serve any record type held in a pkarr zone, not just TXT.
    ///
    /// A published zone is an arbitrary DNS packet signed by the endpoint key, so
    /// an A/AAAA record is as legitimate as the iroh TXT set. Answers are
    /// selected by question type and re-owned under the queried name (the zone
    /// stores them under the internal `_iroh.<z32>` / `<z32>` owner).
    fn answerPkarr(self: *Handler, cfg: *const config_mod.Config, q: dns_wire.Question) !?[]u8 {
        const parsed = parsePkarrName(q.name, cfg.origins) orelse return null;
        const payload = self.store.getRelayPayload(parsed.public_key) catch |err| switch (err) {
            error.MissingPacket => return self.answerMainline(cfg, parsed.public_key),
            else => return err,
        };
        defer self.allocator.free(payload);

        // Prefer strict verify (pkarr PUT trust boundary). DHT-sourced packets
        // may only verify under `.cofactored` — compose the existing mode, do
        // not change TLS/pkarr policy.
        var packet = discovery.SignedPacket.fromRelayPayload(self.allocator, parsed.public_key, payload) catch |err| switch (err) {
            error.BadSignature => try discovery.SignedPacket.fromRelayPayloadMode(
                self.allocator,
                parsed.public_key,
                payload,
                .cofactored,
            ),
            else => return err,
        };
        defer packet.deinit(self.allocator);

        const answers = try parseRawAnswers(self.allocator, packet.encodedPacket());
        defer freeRawAnswers(self.allocator, answers);

        const z32 = parsed.public_key.toZ32();
        const internal_name = try std.fmt.allocPrint(self.allocator, "_iroh.{s}", .{&z32});
        defer self.allocator.free(internal_name);

        var matched: std.ArrayList(RawAnswer) = .empty;
        defer matched.deinit(self.allocator);
        for (answers) |a| {
            if (a.typ != q.typ or a.class != dns_wire.CLASS_IN) continue;
            // Only the zone's own records; a signed packet must not be able to
            // inject answers for a name it does not own.
            if (!ownerIsZone(a.name, internal_name, &z32)) continue;
            if (!rdataIsSelfContained(a.typ)) continue;
            try matched.append(self.allocator, .{
                .name = q.name,
                .typ = a.typ,
                .class = a.class,
                .ttl = cfg.default_ttl,
                .rdata = a.rdata,
            });
        }
        if (matched.items.len == 0) return null;

        return @as(?[]u8, try buildRawAnswersResponse(
            self.allocator,
            q.id,
            q.name,
            q.typ,
            matched.items,
        ));
    }

    /// Mainline (BEP-44) fallback for a zone-store miss. Enqueues a background
    /// resolve and returns null so the caller falls through to NXDOMAIN —
    /// the answer path stays fast; a later query hits the store once resolved.
    fn answerMainline(self: *Handler, cfg: *const config_mod.Config, public_key: root.PublicKey) !?[]u8 {
        if (!cfg.mainline_enabled) return null;
        if (self.mainline_resolver) |resolver| {
            resolver.request(public_key);
            return null;
        }
        _ = self.metrics.dns_mainline_unavailable.fetchAdd(1, .monotonic);
        return null;
    }
};

/// One answer record, with `rdata` borrowed from the packet it was parsed out of.
pub const RawAnswer = struct {
    name: []const u8,
    typ: u16,
    class: u16,
    ttl: u32,
    /// Points into the source packet — valid only while that packet lives.
    rdata: []const u8,
};

/// True when a type's RDATA is opaque bytes, so it can be copied between packets
/// without rewriting embedded compression pointers. Name-bearing types (NS,
/// CNAME, SOA, MX, SRV, …) are excluded: their RDATA may hold offsets that only
/// mean anything inside the original packet.
fn rdataIsSelfContained(typ: u16) bool {
    return switch (typ) {
        dns_wire.TYPE_A, dns_wire.TYPE_AAAA, dns_wire.TYPE_TXT => true,
        else => false,
    };
}

fn ownerIsZone(owner: []const u8, internal_name: []const u8, z32: []const u8) bool {
    return std.ascii.eqlIgnoreCase(owner, internal_name) or std.ascii.eqlIgnoreCase(owner, z32);
}

/// Parse every answer record in `packet`. Names are allocated; `rdata` borrows
/// from `packet`. Free with `freeRawAnswers`.
pub fn parseRawAnswers(allocator: std.mem.Allocator, packet: []const u8) ![]RawAnswer {
    if (packet.len < 12) return error.PacketTooShort;
    const qdcount = std.mem.readInt(u16, packet[4..6], .big);
    const ancount = std.mem.readInt(u16, packet[6..8], .big);

    var offset: usize = 12;
    var i: usize = 0;
    while (i < qdcount) : (i += 1) {
        var scratch: std.ArrayList(u8) = .empty;
        defer scratch.deinit(allocator);
        offset = try readName(allocator, packet, offset, &scratch);
        if (offset + 4 > packet.len) return error.PacketTooShort;
        offset += 4;
    }

    var out: std.ArrayList(RawAnswer) = .empty;
    errdefer {
        for (out.items) |a| allocator.free(a.name);
        out.deinit(allocator);
    }

    i = 0;
    while (i < ancount) : (i += 1) {
        var name: std.ArrayList(u8) = .empty;
        errdefer name.deinit(allocator);
        offset = try readName(allocator, packet, offset, &name);
        if (offset + 10 > packet.len) return error.PacketTooShort;
        const typ = std.mem.readInt(u16, packet[offset..][0..2], .big);
        const class = std.mem.readInt(u16, packet[offset + 2 ..][0..2], .big);
        const ttl = std.mem.readInt(u32, packet[offset + 4 ..][0..4], .big);
        const rdlen = std.mem.readInt(u16, packet[offset + 8 ..][0..2], .big);
        offset += 10;
        if (offset + rdlen > packet.len) return error.TruncatedRecord;
        const rdata = packet[offset .. offset + rdlen];
        offset += rdlen;
        try out.append(allocator, .{
            .name = try name.toOwnedSlice(allocator),
            .typ = typ,
            .class = class,
            .ttl = ttl,
            .rdata = rdata,
        });
    }
    return out.toOwnedSlice(allocator);
}

pub fn freeRawAnswers(allocator: std.mem.Allocator, answers: []RawAnswer) void {
    for (answers) |a| allocator.free(a.name);
    allocator.free(answers);
}

/// Build an authoritative NOERROR response carrying `answers` verbatim.
///
/// This is the dns-server's own builder, deliberately separate from
/// `dns_wire.buildResponse`: that one takes TXT *values* and re-encodes them
/// (the shape discovery's resolver expects), whereas a zone answer must ship the
/// signed packet's RDATA byte-for-byte, whatever its type.
pub fn buildRawAnswersResponse(
    allocator: std.mem.Allocator,
    query_id: u16,
    question_name: []const u8,
    question_type: u16,
    answers: []const RawAnswer,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try writeU16(&out, allocator, query_id);
    try writeU16(&out, allocator, 0x8400); // QR + AA, RCODE=NOERROR
    try writeU16(&out, allocator, 1);
    try writeU16(&out, allocator, @intCast(answers.len));
    try writeU16(&out, allocator, 0);
    try writeU16(&out, allocator, 0);

    const qname_offset = out.items.len;
    try dns_wire.appendName(&out, allocator, question_name);
    try writeU16(&out, allocator, question_type);
    try writeU16(&out, allocator, dns_wire.CLASS_IN);

    for (answers, 0..) |a, i| {
        // First owner spelled out, the rest point back at it (RFC 1035 §4.1.4).
        if (i == 0) {
            try dns_wire.appendName(&out, allocator, a.name);
        } else {
            if (qname_offset > 0x3fff) return error.BadPointer;
            try writeU16(&out, allocator, 0xc000 | @as(u16, @intCast(qname_offset)));
        }
        try writeU16(&out, allocator, a.typ);
        try writeU16(&out, allocator, a.class);
        try writeU32(&out, allocator, a.ttl);
        if (a.rdata.len > std.math.maxInt(u16)) return error.TruncatedRecord;
        try writeU16(&out, allocator, @intCast(a.rdata.len));
        try out.appendSlice(allocator, a.rdata);
    }
    return out.toOwnedSlice(allocator);
}

/// RFC 1035 name reader with compression-pointer support. Returns the offset
/// just past the name as it appeared at `start`.
fn readName(
    allocator: std.mem.Allocator,
    packet: []const u8,
    start: usize,
    out: *std.ArrayList(u8),
) !usize {
    var offset = start;
    var next = start;
    var jumped = false;
    var jumps: usize = 0;
    while (true) {
        if (offset >= packet.len) return error.PacketTooShort;
        const len = packet[offset];
        if ((len & 0xc0) == 0xc0) {
            if (offset + 1 >= packet.len) return error.PacketTooShort;
            const ptr = (@as(usize, len & 0x3f) << 8) | packet[offset + 1];
            if (ptr >= packet.len) return error.BadPointer;
            if (!jumped) next = offset + 2;
            jumped = true;
            jumps += 1;
            if (jumps > 16) return error.PointerLoop;
            offset = ptr;
            continue;
        }
        if ((len & 0xc0) != 0) return error.BadName;
        offset += 1;
        if (len == 0) {
            if (!jumped) next = offset;
            break;
        }
        if (len > 63 or offset + len > packet.len) return error.BadName;
        if (out.items.len != 0) try out.append(allocator, '.');
        try out.appendSlice(allocator, packet[offset .. offset + len]);
        offset += len;
    }
    return next;
}

const PkarrName = struct {
    public_key: root.PublicKey,
};

fn parsePkarrName(name_in: []const u8, origins: []const []const u8) ?PkarrName {
    const name = std.mem.trimEnd(u8, name_in, ".");
    for (origins) |origin_raw| {
        const origin = std.mem.trimEnd(u8, origin_raw, ".");
        if (origin.len == 0) {
            // Root origin "." — accept bare z32 or _iroh.z32
            if (parseZ32Label(name)) |pk| return .{ .public_key = pk };
            if (std.mem.startsWith(u8, name, "_iroh.")) {
                if (parseZ32Label(name["_iroh.".len..])) |pk| return .{ .public_key = pk };
            }
            continue;
        }
        if (name.len <= origin.len) continue;
        if (!std.mem.endsWith(u8, name, origin)) continue;
        if (name[name.len - origin.len - 1] != '.') continue;
        const prefix = name[0 .. name.len - origin.len - 1];
        // Forms: `<z32>.<origin>` or `_iroh.<z32>.<origin>`
        if (std.mem.startsWith(u8, prefix, "_iroh.")) {
            const rest = prefix["_iroh.".len..];
            const label = if (std.mem.indexOfScalar(u8, rest, '.')) |dot| rest[0..dot] else rest;
            if (parseZ32Label(label)) |pk| return .{ .public_key = pk };
        } else {
            // For `<z32>.<origin>` the z32 is the rightmost label above origin.
            const zlabel = blk: {
                if (std.mem.lastIndexOfScalar(u8, prefix, '.')) |dot| break :blk prefix[dot + 1 ..];
                break :blk prefix;
            };
            if (parseZ32Label(zlabel)) |pk| return .{ .public_key = pk };
        }
    }
    return null;
}

fn parseZ32Label(label: []const u8) ?root.PublicKey {
    return root.PublicKey.fromZ32(label) catch null;
}

const SoaParts = struct { mname: []const u8, rname: []const u8, serial: u32 };

fn parseSoa(soa: []const u8) !SoaParts {
    var it = std.mem.tokenizeAny(u8, soa, " \t");
    const mname = it.next() orelse return error.InvalidSoa;
    const rname = it.next() orelse return error.InvalidSoa;
    const serial_s = it.next() orelse "0";
    const serial = std.fmt.parseInt(u32, serial_s, 10) catch 0;
    return .{ .mname = mname, .rname = rname, .serial = serial };
}

fn buildAResponse(allocator: std.mem.Allocator, id: u16, name: []const u8, ipv4: []const u8, ttl: u32) ![]u8 {
    var addr: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, ipv4, '.');
    var i: usize = 0;
    while (parts.next()) |p| : (i += 1) {
        if (i >= 4) return error.InvalidIpv4;
        addr[i] = try std.fmt.parseInt(u8, p, 10);
    }
    if (i != 4) return error.InvalidIpv4;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try writeU16(&out, allocator, id);
    try writeU16(&out, allocator, 0x8400);
    try writeU16(&out, allocator, 1);
    try writeU16(&out, allocator, 1);
    try writeU16(&out, allocator, 0);
    try writeU16(&out, allocator, 0);
    try dns_wire.appendName(&out, allocator, name);
    try writeU16(&out, allocator, dns_wire.TYPE_A);
    try writeU16(&out, allocator, dns_wire.CLASS_IN);
    try dns_wire.appendName(&out, allocator, name);
    try writeU16(&out, allocator, dns_wire.TYPE_A);
    try writeU16(&out, allocator, dns_wire.CLASS_IN);
    try writeU32(&out, allocator, ttl);
    try writeU16(&out, allocator, 4);
    try out.appendSlice(allocator, &addr);
    return out.toOwnedSlice(allocator);
}

fn buildAaaaResponse(allocator: std.mem.Allocator, id: u16, name: []const u8, ipv6: []const u8, ttl: u32) ![]u8 {
    const parsed = std.Io.net.IpAddress.parseIp6(ipv6, 0) catch return error.InvalidIpv6;
    const addr = parsed.ip6.bytes;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try writeU16(&out, allocator, id);
    try writeU16(&out, allocator, 0x8400);
    try writeU16(&out, allocator, 1);
    try writeU16(&out, allocator, 1);
    try writeU16(&out, allocator, 0);
    try writeU16(&out, allocator, 0);
    try dns_wire.appendName(&out, allocator, name);
    try writeU16(&out, allocator, dns_wire.TYPE_AAAA);
    try writeU16(&out, allocator, dns_wire.CLASS_IN);
    try dns_wire.appendName(&out, allocator, name);
    try writeU16(&out, allocator, dns_wire.TYPE_AAAA);
    try writeU16(&out, allocator, dns_wire.CLASS_IN);
    try writeU32(&out, allocator, ttl);
    try writeU16(&out, allocator, 16);
    try out.appendSlice(allocator, &addr);
    return out.toOwnedSlice(allocator);
}

fn buildNsResponse(allocator: std.mem.Allocator, id: u16, name: []const u8, ns: []const u8, ttl: u32) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try writeU16(&out, allocator, id);
    try writeU16(&out, allocator, 0x8400);
    try writeU16(&out, allocator, 1);
    try writeU16(&out, allocator, 1);
    try writeU16(&out, allocator, 0);
    try writeU16(&out, allocator, 0);
    try dns_wire.appendName(&out, allocator, name);
    try writeU16(&out, allocator, dns_wire.TYPE_NS);
    try writeU16(&out, allocator, dns_wire.CLASS_IN);
    try dns_wire.appendName(&out, allocator, name);
    try writeU16(&out, allocator, dns_wire.TYPE_NS);
    try writeU16(&out, allocator, dns_wire.CLASS_IN);
    try writeU32(&out, allocator, ttl);
    const rdlen_at = out.items.len;
    try writeU16(&out, allocator, 0);
    const start = out.items.len;
    try dns_wire.appendName(&out, allocator, ns);
    const rdlen: u16 = @intCast(out.items.len - start);
    std.mem.writeInt(u16, out.items[rdlen_at..][0..2], rdlen, .big);
    return out.toOwnedSlice(allocator);
}

fn writeU16(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    try out.appendSlice(allocator, &buf);
}

fn writeU32(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    try out.appendSlice(allocator, &buf);
}

test "AAAA answers for origin apex" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-aaaa-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    var store = try store_mod.ZoneStore.init(allocator, io, rel);
    defer store.deinit();
    var metrics: metrics_mod.Metrics = .{};
    const cfg: config_mod.Config = .{
        .origins = &.{"irohdns.example."},
        .rr_aaaa = "::1",
    };
    var handler: Handler = .{
        .allocator = allocator,
        .config = &cfg,
        .store = &store,
        .metrics = &metrics,
    };
    const query = try buildRawQuery(allocator, "irohdns.example.", dns_wire.TYPE_AAAA);
    defer allocator.free(query);
    const resp = try handler.answer(query);
    defer allocator.free(resp);
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, resp[2..4], .big) & 0xf);
    try std.testing.expect(std.mem.readInt(u16, resp[6..8], .big) >= 1);
}

test "AXFR is refused" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-axfr-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    var store = try store_mod.ZoneStore.init(allocator, io, rel);
    defer store.deinit();
    var metrics: metrics_mod.Metrics = .{};
    const cfg: config_mod.Config = .{};
    var handler: Handler = .{
        .allocator = allocator,
        .config = &cfg,
        .store = &store,
        .metrics = &metrics,
    };

    const query = try buildRawQuery(allocator, "irohdns.example.", dns_wire.TYPE_AXFR);
    defer allocator.free(query);
    const resp = try handler.answer(query);
    defer allocator.free(resp);
    try std.testing.expectEqual(@as(u16, dns_wire.RCODE_REFUSED), std.mem.readInt(u16, resp[2..4], .big) & 0xf);
}

test "pkarr TXT answers for z32.origin" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-pkarr-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    var store = try store_mod.ZoneStore.init(allocator, io, rel);
    defer store.deinit();
    var metrics: metrics_mod.Metrics = .{};
    const cfg: config_mod.Config = .{
        .origins = &.{"irohdns.example."},
        .rr_a = "127.0.0.1",
    };
    var handler: Handler = .{
        .allocator = allocator,
        .config = &cfg,
        .store = &store,
        .metrics = &metrics,
    };

    const secret = root.SecretKey.fromBytes(.{0x42} ** 32);
    const direct = try std.Io.net.IpAddress.parse("127.0.0.1", 9002);
    var endpoint_relay = try root.RelayUrl.parse(allocator, "https://relay.example");
    defer endpoint_relay.deinit(allocator);
    const info = try discovery.EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{ .{ .relay = endpoint_relay }, .{ .ip = direct } },
        null,
    );
    defer info.deinit(allocator);
    var packet = try discovery.SignedPacket.fromEndpointInfoAt(allocator, secret, info, discovery.DEFAULT_TTL, .{ .micros = 22 });
    defer packet.deinit(allocator);
    try store.putRelayPayload(secret.public(), packet.relayPayload());

    const qname = try std.fmt.allocPrint(allocator, "_iroh.{s}.irohdns.example.", .{&secret.public().toZ32()});
    defer allocator.free(qname);
    const query = try buildRawQuery(allocator, qname, dns_wire.TYPE_TXT);
    defer allocator.free(query);
    const resp = try handler.answer(query);
    defer allocator.free(resp);
    const values = try dns_wire.parseTxtAnswers(allocator, resp, qname);
    defer {
        for (values) |v| allocator.free(v);
        allocator.free(values);
    }
    try std.testing.expect(values.len >= 1);
}

/// Encode a bare DNS reply holding one answer with opaque `rdata`, shaped like
/// the packets `buildTxtReply` produces (id 0, qdcount 0) so it can be signed
/// into a pkarr zone.
fn buildZoneRecordPacket(
    allocator: std.mem.Allocator,
    owner: []const u8,
    typ: u16,
    rdata: []const u8,
    ttl: u32,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try writeU16(&out, allocator, 0); // id
    try writeU16(&out, allocator, 0x8000); // response
    try writeU16(&out, allocator, 0); // qdcount
    try writeU16(&out, allocator, 1); // ancount
    try writeU16(&out, allocator, 0);
    try writeU16(&out, allocator, 0);
    try dns_wire.appendName(&out, allocator, owner);
    try writeU16(&out, allocator, typ);
    try writeU16(&out, allocator, dns_wire.CLASS_IN);
    try writeU32(&out, allocator, ttl);
    try writeU16(&out, allocator, @intCast(rdata.len));
    try out.appendSlice(allocator, rdata);
    return out.toOwnedSlice(allocator);
}

test "pkarr zone serves a signed A record, not just TXT" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-pkarr-a-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    var store = try store_mod.ZoneStore.init(allocator, io, rel);
    defer store.deinit();
    var metrics: metrics_mod.Metrics = .{};
    const cfg: config_mod.Config = .{
        .origins = &.{"irohdns.example."},
        .default_ttl = 300,
    };
    var handler: Handler = .{
        .allocator = allocator,
        .config = &cfg,
        .store = &store,
        .metrics = &metrics,
    };

    const secret = root.SecretKey.fromBytes(.{0x64} ** 32);
    const z32 = secret.public().toZ32();
    const owner = try std.fmt.allocPrint(allocator, "_iroh.{s}", .{&z32});
    defer allocator.free(owner);
    const want_addr = [4]u8{ 203, 0, 113, 7 };
    const zone_packet = try buildZoneRecordPacket(allocator, owner, dns_wire.TYPE_A, &want_addr, 300);
    defer allocator.free(zone_packet);

    var packet = try discovery.SignedPacket.fromEncodedDnsPacketAt(
        allocator,
        secret,
        zone_packet,
        .{ .micros = 77 },
    );
    defer packet.deinit(allocator);
    try store.putRelayPayload(secret.public(), packet.relayPayload());

    const qname = try std.fmt.allocPrint(allocator, "{s}.irohdns.example.", .{&z32});
    defer allocator.free(qname);

    // A: served out of the zone with the RDATA the publisher signed.
    {
        const query = try buildRawQuery(allocator, qname, dns_wire.TYPE_A);
        defer allocator.free(query);
        const resp = try handler.answer(query);
        defer allocator.free(resp);
        try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, resp[2..4], .big) & 0xf);
        try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, resp[6..8], .big));
        const answers = try parseRawAnswers(allocator, resp);
        defer freeRawAnswers(allocator, answers);
        try std.testing.expectEqual(@as(usize, 1), answers.len);
        try std.testing.expectEqual(dns_wire.TYPE_A, answers[0].typ);
        // Owner rewritten from the internal `_iroh.<z32>` to the queried name.
        try std.testing.expectEqualStrings(std.mem.trimEnd(u8, qname, "."), answers[0].name);
        try std.testing.expectEqualSlices(u8, &want_addr, answers[0].rdata);
    }

    // A type the zone does not hold still falls through to NXDOMAIN.
    {
        const query = try buildRawQuery(allocator, qname, dns_wire.TYPE_AAAA);
        defer allocator.free(query);
        const resp = try handler.answer(query);
        defer allocator.free(resp);
        try std.testing.expectEqual(
            @as(u16, dns_wire.RCODE_NXDOMAIN),
            std.mem.readInt(u16, resp[2..4], .big) & 0xf,
        );
    }
}

test "tampered zone packet is rejected before it can be served" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-pkarr-tamper-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    var store = try store_mod.ZoneStore.init(allocator, io, rel);
    defer store.deinit();

    const secret = root.SecretKey.fromBytes(.{0x65} ** 32);
    const z32 = secret.public().toZ32();
    const owner = try std.fmt.allocPrint(allocator, "_iroh.{s}", .{&z32});
    defer allocator.free(owner);
    const zone_packet = try buildZoneRecordPacket(allocator, owner, dns_wire.TYPE_A, &[4]u8{ 1, 2, 3, 4 }, 60);
    defer allocator.free(zone_packet);
    var packet = try discovery.SignedPacket.fromEncodedDnsPacketAt(allocator, secret, zone_packet, .{ .micros = 78 });
    defer packet.deinit(allocator);

    const tampered = try allocator.dupe(u8, packet.relayPayload());
    defer allocator.free(tampered);
    tampered[3] ^= 0x01; // flip a signature bit

    try std.testing.expectError(
        error.BadSignature,
        store.putRelayPayload(secret.public(), tampered),
    );
}

test "mainline seam records the blocker instead of answering" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var nonce: u32 = undefined;
    io.random(std.mem.asBytes(&nonce));
    const rel = try std.fmt.allocPrint(allocator, "zig-cache/tmp/dns-mainline-{d}", .{nonce});
    defer allocator.free(rel);
    defer std.Io.Dir.cwd().deleteTree(io, rel) catch {};

    var store = try store_mod.ZoneStore.init(allocator, io, rel);
    defer store.deinit();
    var metrics: metrics_mod.Metrics = .{};
    const cfg: config_mod.Config = .{
        .origins = &.{"irohdns.example."},
        .mainline_enabled = true,
    };
    var handler: Handler = .{
        .allocator = allocator,
        .config = &cfg,
        .store = &store,
        .metrics = &metrics,
    };

    const secret = root.SecretKey.fromBytes(.{0x66} ** 32);
    const z32 = secret.public().toZ32();
    const qname = try std.fmt.allocPrint(allocator, "{s}.irohdns.example.", .{&z32});
    defer allocator.free(qname);
    const query = try buildRawQuery(allocator, qname, dns_wire.TYPE_TXT);
    defer allocator.free(query);

    const resp = try handler.answer(query);
    defer allocator.free(resp);
    try std.testing.expectEqual(
        @as(u16, dns_wire.RCODE_NXDOMAIN),
        std.mem.readInt(u16, resp[2..4], .big) & 0xf,
    );
    try std.testing.expectEqual(@as(u64, 1), metrics.dns_mainline_unavailable.load(.monotonic));
}

fn buildRawQuery(allocator: std.mem.Allocator, name: []const u8, typ: u16) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try writeU16(&out, allocator, 0x1234);
    try writeU16(&out, allocator, 0x0100);
    try writeU16(&out, allocator, 1);
    try writeU16(&out, allocator, 0);
    try writeU16(&out, allocator, 0);
    try writeU16(&out, allocator, 0);
    try dns_wire.appendName(&out, allocator, name);
    try writeU16(&out, allocator, typ);
    try writeU16(&out, allocator, dns_wire.CLASS_IN);
    return out.toOwnedSlice(allocator);
}
