//! mDNS address-lookup provider, wire-compatible with iroh's
//! `iroh-mdns-address-lookup` crate (which is built on `swarm-discovery`).
//!
//! Wire scheme (the fidelity target, from the Rust lib.rs + sender.rs):
//!   - Multicast group 224.0.0.251:5353 (IPv4 only in this slice).
//!   - Service name `_irohv1._udp.local` (Options.service_name = "irohv1").
//!   - Instance name `<b32(NodeId)>._irohv1._udp.local` where b32 is
//!     RFC 4648 base32, lowercase, no padding (52 chars for a 32-byte id).
//!   - Queriers send a PTR question for the service name.
//!   - Responders answer with SRV (priority 0, weight 0, port = discovery
//!     port, target `<b32>-<port>.local`) + TXT (`relay=<url>` and/or
//!     `user-data=<text>`, only the strings that are present) in the answer
//!     section, and one A record per advertised IPv4 (name = SRV target) in
//!     the additional section. TTL is 0 on every record; there is NO PTR
//!     answer record (the querier learns the instance name from the SRV).
//!   - Resolved `EndpointInfo` carries provenance "mdns".
//!
//! Socket/thread model: one datagram socket (SO_REUSEADDR + SO_REUSEPORT,
//! bound to 0.0.0.0:5353, joined to the group on Options.multicast_interface)
//! owned by a single background reader thread — the ONLY recv on the socket —
//! which answers PTR queries when advertising and ingests responses into a
//! mutex-protected peers map. `resolve` polls that map and re-sends the PTR
//! query roughly once per second until the record appears or the timeout
//! hits.

const std = @import("std");
const key = @import("../key.zig");
const addr = @import("../addr.zig");
const discovery = @import("discovery.zig");
const address_lookup = @import("address_lookup.zig");
const dns_wire = @import("dns_wire.zig");

const posix = std.posix;
const net = std.Io.net;

pub const MDNS_PORT: u16 = 5353;
pub const MULTICAST_GROUP: [4]u8 = .{ 224, 0, 0, 251 };

pub const TYPE_PTR: u16 = 12;
pub const TYPE_SRV: u16 = 33;
const TYPE_A = dns_wire.TYPE_A;
const TYPE_TXT = dns_wire.TYPE_TXT;
const CLASS_IN = dns_wire.CLASS_IN;

const GROUP_U32: u32 = 0xE00000FB; // 224.0.0.251
const MAX_IPS = 8;
const RECV_TIMEOUT_US = 200_000;
const POLL_MS = 25;
const QUERY_INTERVAL_MS = 1000;
const MAX_QUESTIONS = 4;
const MAX_RECORDS = 64;
const READER_BUF = 2048;

pub const Error = error{
    MdnsResolveTimeout,
    SocketCreateFailed,
    SocketOptionFailed,
    SocketBindFailed,
    MulticastJoinFailed,
};

pub const Options = struct {
    advertise: bool = true,
    service_name: []const u8 = "irohv1",
    multicast_interface: [4]u8 = .{ 127, 0, 0, 1 },
    resolve_timeout_ms: u32 = 5000,
};

const ip_mreq = extern struct {
    imr_multiaddr: u32,
    imr_interface: u32,
};

/// A published or discovered record. `relay` / `user_data` are borrowed on
/// the encode path and owned (duped) once stored in the provider.
const Record = struct {
    port: u16 = 0,
    ips: [MAX_IPS][4]u8 = undefined,
    ip_count: usize = 0,
    relay: ?[]const u8 = null,
    user_data: ?[]const u8 = null,
};

fn freeRecordSlices(allocator: std.mem.Allocator, rec: *Record) void {
    if (rec.relay) |r| allocator.free(r);
    if (rec.user_data) |u| allocator.free(u);
    rec.relay = null;
    rec.user_data = null;
}

/// RFC 4648 base32 (lowercase, no padding). Writes into `out`, returns the
/// number of characters written. NOT the z-base-32 of `key.NodeId.toZ32` —
/// iroh's mDNS instance names use the RFC 4648 alphabet.
pub fn base32EncodeLower(data: []const u8, out: []u8) usize {
    const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    var acc: u32 = 0;
    var acc_bits: u5 = 0;
    var n: usize = 0;
    for (data) |b| {
        acc = (acc << 8) | b;
        acc_bits += 8;
        while (acc_bits >= 5) {
            acc_bits -= 5;
            out[n] = alphabet[(acc >> acc_bits) & 0x1f];
            n += 1;
        }
        // Keep only the unconsumed low bits so the accumulator cannot grow
        // without bound over long inputs (release-safe overflow).
        acc &= (@as(u32, 1) << acc_bits) - 1;
    }
    if (acc_bits > 0) {
        out[n] = alphabet[(acc << (5 - acc_bits)) & 0x1f];
        n += 1;
    }
    return n;
}

/// The 52-character RFC 4648 base32 form of a 32-byte NodeId.
pub fn base32NodeId(node_id: key.NodeId) [52]u8 {
    var out: [52]u8 = undefined;
    const n = base32EncodeLower(&node_id.bytes, &out);
    std.debug.assert(n == 52);
    return out;
}

pub const MdnsAddressLookup = struct {
    allocator: std.mem.Allocator,
    node_id: key.NodeId,
    options: Options,
    service_name: []u8, // "_<service_name>._udp.local", owned
    b32: [52]u8,
    fd: posix.fd_t,
    thread: ?std.Thread = null,
    stopped: std.atomic.Value(bool) = .init(false),
    mu: std.atomic.Mutex = .unlocked, // guards `published` and `peers`
    published: ?Record = null,
    peers: std.AutoHashMap([52]u8, Record),

    pub fn init(allocator: std.mem.Allocator, node_id: key.NodeId, options: Options) !*MdnsAddressLookup {
        const self = try allocator.create(MdnsAddressLookup);
        errdefer allocator.destroy(self);
        const service_name = try std.fmt.allocPrint(allocator, "_{s}._udp.local", .{options.service_name});
        errdefer allocator.free(service_name);
        const fd = try openSocket(options.multicast_interface);
        errdefer _ = posix.system.close(fd);
        self.* = .{
            .allocator = allocator,
            .node_id = node_id,
            .options = options,
            .service_name = service_name,
            .b32 = base32NodeId(node_id),
            .fd = fd,
            .peers = std.AutoHashMap([52]u8, Record).init(allocator),
        };
        self.thread = try std.Thread.spawn(.{}, readerMain, .{self});
        return self;
    }

    pub fn deinit(self: *MdnsAddressLookup) void {
        self.stopped.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        _ = posix.system.close(self.fd);
        if (self.published) |*p| freeRecordSlices(self.allocator, p);
        var it = self.peers.valueIterator();
        while (it.next()) |rec| freeRecordSlices(self.allocator, rec);
        self.peers.deinit();
        self.allocator.free(self.service_name);
        self.allocator.destroy(self);
    }

    /// Publish our reachability and, when advertising, send ONE unsolicited
    /// response announcement to the group. Replaces (and frees) any previous
    /// published record.
    pub fn publish(self: *MdnsAddressLookup, endpoint_addr: addr.EndpointAddr, user_data: ?[]const u8) !void {
        var rec = Record{};
        var ip_it = endpoint_addr.ipAddrs();
        while (ip_it.next()) |ip| {
            switch (ip) {
                .ip4 => |ip4| {
                    if (rec.ip_count == 0) rec.port = ip4.port;
                    if (rec.ip_count < MAX_IPS) {
                        rec.ips[rec.ip_count] = ip4.bytes;
                        rec.ip_count += 1;
                    }
                },
                .ip6 => {}, // IPv4-only slice
            }
        }
        if (endpoint_addr.firstRelayUrl()) |relay| rec.relay = relay.asString();
        rec.user_data = user_data;

        const owned_relay = if (rec.relay) |r| try self.allocator.dupe(u8, r) else null;
        errdefer if (owned_relay) |r| self.allocator.free(r);
        const owned_user_data = if (rec.user_data) |u| try self.allocator.dupe(u8, u) else null;
        errdefer if (owned_user_data) |u| self.allocator.free(u);
        rec.relay = owned_relay;
        rec.user_data = owned_user_data;

        lockMu(&self.mu);
        if (self.published) |*old| freeRecordSlices(self.allocator, old);
        self.published = rec;
        self.mu.unlock();

        if (self.options.advertise) {
            const packet = try buildResponsePacket(self.allocator, self.service_name, &self.b32, rec);
            defer self.allocator.free(packet);
            self.sendPacket(packet);
        }
    }

    /// Adapt to the address-lookup provider seam (`address_lookup.AddressLookup`).
    /// The adapter borrows `self` — the provider must outlive any registry it
    /// is registered into.
    pub fn asLookup(self: *MdnsAddressLookup) address_lookup.AddressLookup {
        return .{
            .context = self,
            .provenance = "mdns",
            .publishFn = publishSeam,
            .resolveFn = resolveSeam,
        };
    }

    fn publishSeam(context: *anyopaque, info: discovery.EndpointInfo) anyerror!void {
        const self: *MdnsAddressLookup = @ptrCast(@alignCast(context));
        var node_addr = try info.toNodeAddr(self.allocator);
        defer node_addr.deinit(self.allocator);
        return self.publish(node_addr, info.user_data);
    }

    fn resolveSeam(context: *anyopaque, node_id: key.NodeId) anyerror!discovery.EndpointInfo {
        const self: *MdnsAddressLookup = @ptrCast(@alignCast(context));
        return self.resolve(node_id);
    }

    /// Resolve via Options.resolve_timeout_ms.
    pub fn resolve(self: *MdnsAddressLookup, node_id: key.NodeId) !discovery.EndpointInfo {
        return self.resolveWithTimeout(node_id, self.options.resolve_timeout_ms);
    }

    /// Poll the peers map for `node_id`, re-sending the PTR query roughly
    /// every second, until the record appears or `timeout_ms` elapses
    /// (→ `error.MdnsResolveTimeout`).
    pub fn resolveWithTimeout(self: *MdnsAddressLookup, node_id: key.NodeId, timeout_ms: u32) !discovery.EndpointInfo {
        const target = base32NodeId(node_id);
        const query = try buildPtrQuery(self.allocator, self.service_name);
        defer self.allocator.free(query);

        const deadline = nowMillis() + timeout_ms;
        // Force the first query to go out immediately.
        var last_query_ms = nowMillis() - QUERY_INTERVAL_MS;
        while (true) {
            if (try self.snapshotPeer(&target)) |found| {
                var snapshot = found;
                defer freeRecordSlices(self.allocator, &snapshot);
                return try self.buildEndpointInfo(node_id, snapshot);
            }
            const now = nowMillis();
            if (now >= deadline) return error.MdnsResolveTimeout;
            if (now - last_query_ms >= QUERY_INTERVAL_MS) {
                self.sendPacket(query);
                last_query_ms = now;
            }
            sleepMillis(POLL_MS);
        }
    }

    fn snapshotPeer(self: *MdnsAddressLookup, id_b32: *const [52]u8) !?Record {
        lockMu(&self.mu);
        defer self.mu.unlock();
        const rec = self.peers.get(id_b32.*) orelse return null;
        var copy = rec;
        copy.relay = if (rec.relay) |r| try self.allocator.dupe(u8, r) else null;
        copy.user_data = if (rec.user_data) |u| try self.allocator.dupe(u8, u) else null;
        return copy;
    }

    fn snapshotPublished(self: *MdnsAddressLookup) !?Record {
        lockMu(&self.mu);
        defer self.mu.unlock();
        const rec = self.published orelse return null;
        var copy = rec;
        copy.relay = if (rec.relay) |r| try self.allocator.dupe(u8, r) else null;
        copy.user_data = if (rec.user_data) |u| try self.allocator.dupe(u8, u) else null;
        return copy;
    }

    fn buildEndpointInfo(self: *MdnsAddressLookup, node_id: key.NodeId, rec: Record) !discovery.EndpointInfo {
        var addrs: std.ArrayList(addr.TransportAddr) = .empty;
        defer {
            for (addrs.items) |item| item.deinit(self.allocator);
            addrs.deinit(self.allocator);
        }
        for (rec.ips[0..rec.ip_count]) |ip4| {
            try addrs.append(self.allocator, .{ .ip = .{ .ip4 = .{ .bytes = ip4, .port = rec.port } } });
        }
        if (rec.relay) |text| {
            if (addr.RelayUrl.parse(self.allocator, text)) |relay| {
                try addrs.append(self.allocator, .{ .relay = relay });
            } else |_| {} // a malformed stored relay must not fail the resolve
        }
        // fromPartsWithMetadata clones every address and dupes user_data.
        return discovery.EndpointInfo.fromPartsWithMetadata(
            self.allocator,
            node_id,
            addrs.items,
            rec.user_data,
            .{ .provenance = "mdns", .last_updated = discovery.Timestamp.now() },
        );
    }

    fn sendPacket(self: *MdnsAddressLookup, packet: []const u8) void {
        const dst = posix.sockaddr.in{
            .port = std.mem.nativeToBig(u16, MDNS_PORT),
            .addr = std.mem.nativeToBig(u32, GROUP_U32),
        };
        const rc = posix.system.sendto(
            self.fd,
            packet.ptr,
            packet.len,
            0,
            @ptrCast(&dst),
            @sizeOf(posix.sockaddr.in),
        );
        _ = posix.errno(rc); // best-effort: multicast sends are fire-and-forget
    }

    /// The single reader on the socket: answers PTR queries for our service
    /// (when advertising with a published record) and ingests responses.
    fn readerMain(self: *MdnsAddressLookup) void {
        var buf: [READER_BUF]u8 = undefined;
        while (!self.stopped.load(.acquire)) {
            const rc = posix.system.recvfrom(self.fd, &buf, buf.len, 0, null, null);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .INTR, .AGAIN => continue, // AGAIN = SO_RCVTIMEO expiry
                else => {
                    sleepMillis(POLL_MS); // avoid a hot loop on persistent errors
                    continue;
                },
            }
            const n: usize = @intCast(rc);
            self.handlePacket(buf[0..n]);
        }
    }

    fn handlePacket(self: *MdnsAddressLookup, packet: []const u8) void {
        if (packet.len < 12) return;
        if ((packet[2] & 0x80) != 0) {
            // A response: ingest any records for our service.
            lockMu(&self.mu);
            defer self.mu.unlock();
            ingestResponse(self.allocator, &self.peers, self.service_name, packet) catch {};
            return;
        }
        // A query: answer when it asks (PTR) for our service and we publish.
        if (!self.options.advertise) return;
        if (!hasServicePtrQuery(self.service_name, packet)) return;
        var snapshot = (self.snapshotPublished() catch return) orelse return;
        defer freeRecordSlices(self.allocator, &snapshot);
        const response = buildResponsePacket(self.allocator, self.service_name, &self.b32, snapshot) catch return;
        defer self.allocator.free(response);
        self.sendPacket(response);
    }
};

fn lockMu(mu: *std.atomic.Mutex) void {
    while (!mu.tryLock()) std.Thread.yield() catch {};
}

fn openSocket(iface: [4]u8) Error!posix.fd_t {
    const rc = posix.system.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP);
    if (posix.errno(rc) != .SUCCESS) return error.SocketCreateFailed;
    const fd: posix.fd_t = @intCast(rc);
    errdefer _ = posix.system.close(fd);

    const one = std.mem.toBytes(@as(c_int, 1));
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &one) catch return error.SocketOptionFailed;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, &one) catch return error.SocketOptionFailed;

    const bind_addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, MDNS_PORT),
        .addr = 0, // 0.0.0.0
    };
    if (posix.errno(posix.system.bind(fd, @ptrCast(&bind_addr), @sizeOf(posix.sockaddr.in))) != .SUCCESS)
        return error.SocketBindFailed;

    const mreq = ip_mreq{
        .imr_multiaddr = std.mem.nativeToBig(u32, GROUP_U32),
        .imr_interface = std.mem.nativeToBig(u32, packIp4(iface)),
    };
    posix.setsockopt(fd, posix.IPPROTO.IP, posix.IP.ADD_MEMBERSHIP, std.mem.asBytes(&mreq)) catch
        return error.MulticastJoinFailed;
    posix.setsockopt(fd, posix.IPPROTO.IP, posix.IP.MULTICAST_LOOP, &[_]u8{1}) catch return error.SocketOptionFailed;
    const if_be = std.mem.nativeToBig(u32, packIp4(iface));
    posix.setsockopt(fd, posix.IPPROTO.IP, posix.IP.MULTICAST_IF, std.mem.asBytes(&if_be)) catch
        return error.SocketOptionFailed;

    const tv = posix.timeval{ .sec = 0, .usec = RECV_TIMEOUT_US };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch return error.SocketOptionFailed;

    return fd;
}

fn packIp4(b: [4]u8) u32 {
    return (@as(u32, b[0]) << 24) | (@as(u32, b[1]) << 16) | (@as(u32, b[2]) << 8) | b[3];
}

fn nowMillis() i64 {
    var ts: posix.timespec = undefined;
    const rc = posix.system.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    if (posix.errno(rc) != .SUCCESS) return 0;
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), std.time.ns_per_ms);
}

fn sleepMillis(ms: u64) void {
    const ts: posix.timespec = .{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    _ = posix.system.nanosleep(&ts, null);
}

// ---------------------------------------------------------------------------
// DNS wire codec (mDNS flavor)
// ---------------------------------------------------------------------------

const NameRec = struct {
    name_buf: [256]u8 = undefined,
    name_len: usize = 0,
    typ: u16 = 0,
    rdata_off: usize = 0,
    rdata: []const u8 = &.{},

    fn name(self: *const NameRec) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

const Message = struct {
    is_response: bool = false,
    questions: [MAX_QUESTIONS]NameRec = undefined,
    n_questions: usize = 0,
    records: [MAX_RECORDS]NameRec = undefined,
    n_records: usize = 0,
};

/// Compression-aware RFC 1035 name reader (0xC0 pointers, hop cap 16).
/// Writes the dotted name into `out`, sets `out_len`, and returns the offset
/// just past the name in its ORIGINAL (possibly pointer-terminated) position.
fn readName(packet: []const u8, start: usize, out: []u8, out_len: *usize) !usize {
    var offset = start;
    var next = start;
    var jumped = false;
    var jumps: usize = 0;
    var len: usize = 0;
    while (true) {
        if (offset >= packet.len) return error.PacketTooShort;
        const l = packet[offset];
        if ((l & 0xc0) == 0xc0) {
            if (offset + 1 >= packet.len) return error.PacketTooShort;
            const ptr = (@as(usize, l & 0x3f) << 8) | packet[offset + 1];
            if (ptr >= packet.len) return error.BadPointer;
            if (!jumped) next = offset + 2;
            jumped = true;
            jumps += 1;
            if (jumps > 16) return error.PointerLoop;
            offset = ptr;
            continue;
        }
        if ((l & 0xc0) != 0) return error.BadName;
        offset += 1;
        if (l == 0) {
            if (!jumped) next = offset;
            break;
        }
        if (offset + l > packet.len) return error.BadName;
        if (len != 0) {
            if (len >= out.len) return error.NameTooLong;
            out[len] = '.';
            len += 1;
        }
        if (len + l > out.len) return error.NameTooLong;
        @memcpy(out[len..][0..l], packet[offset..][0..l]);
        len += l;
        offset += l;
    }
    out_len.* = len;
    return next;
}

fn readU16(packet: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, packet[offset..][0..2], .big);
}

fn appendU16(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    try out.appendSlice(allocator, &buf);
}

fn appendU32(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    try out.appendSlice(allocator, &buf);
}

/// Parses the header and question section; returns the offset of the first
/// record. Extra questions beyond MAX_QUESTIONS are walked but dropped.
fn parseHeaderQuestions(packet: []const u8, msg: *Message) !usize {
    if (packet.len < 12) return error.PacketTooShort;
    msg.is_response = (packet[2] & 0x80) != 0;
    const qdcount = readU16(packet, 4);
    var offset: usize = 12;
    var i: usize = 0;
    while (i < qdcount) : (i += 1) {
        var q: NameRec = .{};
        offset = try readName(packet, offset, &q.name_buf, &q.name_len);
        if (offset + 4 > packet.len) return error.PacketTooShort;
        q.typ = readU16(packet, offset);
        offset += 4; // skip qtype + qclass
        if (msg.n_questions < msg.questions.len) {
            msg.questions[msg.n_questions] = q;
            msg.n_questions += 1;
        }
    }
    return offset;
}

/// Walks the answer + authority + additional sections into msg.records.
/// Extra records beyond MAX_RECORDS are walked but dropped.
fn parseRecords(packet: []const u8, offset_in: usize, msg: *Message) !void {
    if (packet.len < 12) return error.PacketTooShort;
    const total = @as(usize, readU16(packet, 6)) + readU16(packet, 8) + readU16(packet, 10);
    var offset = offset_in;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var rr: NameRec = .{};
        offset = try readName(packet, offset, &rr.name_buf, &rr.name_len);
        if (offset + 10 > packet.len) return error.PacketTooShort;
        rr.typ = readU16(packet, offset);
        const rdlen = readU16(packet, offset + 8);
        offset += 10; // skip type + class + ttl + rdlength
        if (offset + rdlen > packet.len) return error.TruncatedRecord;
        rr.rdata_off = offset;
        rr.rdata = packet[offset..][0..rdlen];
        offset += rdlen;
        if (msg.n_records < msg.records.len) {
            msg.records[msg.n_records] = rr;
            msg.n_records += 1;
        }
    }
}

/// True when `packet` is a DNS query carrying a PTR question for `service_name`.
fn hasServicePtrQuery(service_name: []const u8, packet: []const u8) bool {
    if (packet.len < 12) return false;
    if ((packet[2] & 0x80) != 0) return false;
    var msg: Message = .{};
    _ = parseHeaderQuestions(packet, &msg) catch return false;
    for (msg.questions[0..msg.n_questions]) |*q| {
        if (q.typ == TYPE_PTR and std.ascii.eqlIgnoreCase(q.name(), service_name)) return true;
    }
    return false;
}

/// Extracts and validates the 52-char instance id from `<b32>.<service_name>`
/// (case-insensitive on the service suffix; id is lowercased into the key).
fn extractInstanceId(instance: []const u8, service_name: []const u8) ?[52]u8 {
    if (instance.len != 52 + 1 + service_name.len) return null;
    if (instance[52] != '.') return null;
    if (!std.ascii.eqlIgnoreCase(instance[53..], service_name)) return null;
    var id: [52]u8 = undefined;
    for (instance[0..52], 0..) |c, i| {
        const l = std.ascii.toLower(c);
        const ok = (l >= 'a' and l <= 'z') or (l >= '2' and l <= '7');
        if (!ok) return null;
        id[i] = l;
    }
    return id;
}

/// Ingests a DNS response: for every SRV record whose owner is an instance of
/// our service, correlate the same-instance TXT (`relay=` / `user-data=`) and
/// the A records named by the SRV target, then upsert into `peers`
/// (dupe-ing the text slices; a replaced record's slices are freed).
fn ingestResponse(
    allocator: std.mem.Allocator,
    peers: *std.AutoHashMap([52]u8, Record),
    service_name: []const u8,
    packet: []const u8,
) !void {
    var msg: Message = .{};
    const after_questions = try parseHeaderQuestions(packet, &msg);
    try parseRecords(packet, after_questions, &msg);

    for (msg.records[0..msg.n_records]) |*srv| {
        if (srv.typ != TYPE_SRV) continue;
        const id = extractInstanceId(srv.name(), service_name) orelse continue;
        if (srv.rdata.len < 6) continue;
        var rec = Record{ .port = std.mem.readInt(u16, srv.rdata[4..6], .big) };
        var target_buf: [256]u8 = undefined;
        var target_len: usize = 0;
        _ = readName(packet, srv.rdata_off + 6, &target_buf, &target_len) catch continue;
        const target = target_buf[0..target_len];

        for (msg.records[0..msg.n_records]) |*txt| {
            if (txt.typ != TYPE_TXT) continue;
            if (!std.ascii.eqlIgnoreCase(txt.name(), srv.name())) continue;
            parseTxtStrings(txt.rdata, &rec);
        }
        for (msg.records[0..msg.n_records]) |*a| {
            if (a.typ != TYPE_A) continue;
            if (a.rdata.len != 4) continue;
            if (!std.ascii.eqlIgnoreCase(a.name(), target)) continue;
            if (rec.ip_count >= MAX_IPS) break;
            rec.ips[rec.ip_count] = a.rdata[0..4].*;
            rec.ip_count += 1;
        }
        try upsertPeer(allocator, peers, id, rec);
    }
}

fn parseTxtStrings(rdata: []const u8, rec: *Record) void {
    var offset: usize = 0;
    while (offset < rdata.len) {
        const len = rdata[offset];
        offset += 1;
        if (offset + len > rdata.len) return;
        const s = rdata[offset .. offset + len];
        offset += len;
        if (std.mem.startsWith(u8, s, "relay=")) {
            if (rec.relay == null) rec.relay = s["relay=".len..];
        } else if (std.mem.startsWith(u8, s, "user-data=")) {
            if (rec.user_data == null) rec.user_data = s["user-data=".len..];
        }
    }
}

fn upsertPeer(allocator: std.mem.Allocator, peers: *std.AutoHashMap([52]u8, Record), id: [52]u8, rec: Record) !void {
    const owned_relay = if (rec.relay) |r| try allocator.dupe(u8, r) else null;
    errdefer if (owned_relay) |r| allocator.free(r);
    const owned_user_data = if (rec.user_data) |u| try allocator.dupe(u8, u) else null;
    errdefer if (owned_user_data) |u| allocator.free(u);
    const gop = try peers.getOrPut(id);
    if (gop.found_existing) freeRecordSlices(allocator, gop.value_ptr);
    var stored = rec;
    stored.relay = owned_relay;
    stored.user_data = owned_user_data;
    gop.value_ptr.* = stored;
}

/// PTR query for the service (id 0, QR=0, one question).
fn buildPtrQuery(allocator: std.mem.Allocator, service_name: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendU16(&out, allocator, 0); // id
    try appendU16(&out, allocator, 0x0000); // flags: query
    try appendU16(&out, allocator, 1); // qdcount
    try appendU16(&out, allocator, 0); // ancount
    try appendU16(&out, allocator, 0); // nscount
    try appendU16(&out, allocator, 0); // arcount
    try dns_wire.appendName(&out, allocator, service_name);
    try appendU16(&out, allocator, TYPE_PTR);
    try appendU16(&out, allocator, CLASS_IN);
    return out.toOwnedSlice(allocator);
}

/// The swarm-discovery response: answers SRV + TXT (TXT only when at least
/// one string is present), additionals one A per advertised IPv4. TTL 0 on
/// every record, NO PTR answer. Names are written uncompressed (receivers
/// parse that fine).
fn buildResponsePacket(
    allocator: std.mem.Allocator,
    service_name: []const u8,
    id_b32: *const [52]u8,
    rec: Record,
) ![]u8 {
    const instance = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ id_b32, service_name });
    defer allocator.free(instance);
    const target = try std.fmt.allocPrint(allocator, "{s}-{d}.local", .{ id_b32, rec.port });
    defer allocator.free(target);

    const has_txt = rec.relay != null or rec.user_data != null;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendU16(&out, allocator, 0); // id
    try appendU16(&out, allocator, 0x8400); // QR=1, AA=1
    try appendU16(&out, allocator, 0); // qdcount
    try appendU16(&out, allocator, if (has_txt) 2 else 1); // ancount
    try appendU16(&out, allocator, 0); // nscount
    try appendU16(&out, allocator, @intCast(rec.ip_count)); // arcount

    // SRV answer.
    try dns_wire.appendName(&out, allocator, instance);
    try appendU16(&out, allocator, TYPE_SRV);
    try appendU16(&out, allocator, CLASS_IN);
    try appendU32(&out, allocator, 0); // ttl
    const srv_rdlen_at = out.items.len;
    try appendU16(&out, allocator, 0); // rdlength, patched below
    const srv_rdata_start = out.items.len;
    try appendU16(&out, allocator, 0); // priority
    try appendU16(&out, allocator, 0); // weight
    try appendU16(&out, allocator, rec.port);
    try dns_wire.appendName(&out, allocator, target);
    std.mem.writeInt(u16, out.items[srv_rdlen_at..][0..2], @intCast(out.items.len - srv_rdata_start), .big);

    // TXT answer (only when there is at least one string).
    if (has_txt) {
        try dns_wire.appendName(&out, allocator, instance);
        try appendU16(&out, allocator, TYPE_TXT);
        try appendU16(&out, allocator, CLASS_IN);
        try appendU32(&out, allocator, 0); // ttl
        const txt_rdlen_at = out.items.len;
        try appendU16(&out, allocator, 0); // rdlength, patched below
        const txt_rdata_start = out.items.len;
        if (rec.relay) |relay| try appendTxtString(&out, allocator, "relay=", relay);
        if (rec.user_data) |user_data| try appendTxtString(&out, allocator, "user-data=", user_data);
        std.mem.writeInt(u16, out.items[txt_rdlen_at..][0..2], @intCast(out.items.len - txt_rdata_start), .big);
    }

    // A additionals, one per advertised IPv4, named by the SRV target.
    for (rec.ips[0..rec.ip_count]) |ip4| {
        try dns_wire.appendName(&out, allocator, target);
        try appendU16(&out, allocator, TYPE_A);
        try appendU16(&out, allocator, CLASS_IN);
        try appendU32(&out, allocator, 0); // ttl
        try appendU16(&out, allocator, 4); // rdlength
        try out.appendSlice(allocator, &ip4);
    }

    return out.toOwnedSlice(allocator);
}

fn appendTxtString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, prefix: []const u8, value: []const u8) !void {
    if (prefix.len + value.len > 255) return error.LabelTooLong;
    try out.append(allocator, @intCast(prefix.len + value.len));
    try out.appendSlice(allocator, prefix);
    try out.appendSlice(allocator, value);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const TEST_SERVICE = "_irohv1._udp.local";

fn freePeers(allocator: std.mem.Allocator, peers: *std.AutoHashMap([52]u8, Record)) void {
    var it = peers.valueIterator();
    while (it.next()) |rec| freeRecordSlices(allocator, rec);
    peers.deinit();
}

test "base32EncodeLower matches RFC 4648 vectors and sizes a NodeId to 52 chars" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), base32EncodeLower("", &buf));
    try std.testing.expectEqualStrings("my", buf[0..base32EncodeLower("f", &buf)]);
    try std.testing.expectEqualStrings("mzxq", buf[0..base32EncodeLower("fo", &buf)]);
    try std.testing.expectEqualStrings("mzxw6", buf[0..base32EncodeLower("foo", &buf)]);
    try std.testing.expectEqualStrings("mzxw6yq", buf[0..base32EncodeLower("foob", &buf)]);
    try std.testing.expectEqualStrings("mzxw6ytb", buf[0..base32EncodeLower("fooba", &buf)]);
    try std.testing.expectEqualStrings("mzxw6ytboi", buf[0..base32EncodeLower("foobar", &buf)]);

    const node_id = key.SecretKey.fromBytes(.{0x5a} ** 32).public();
    const b32 = base32NodeId(node_id);
    try std.testing.expectEqual(@as(usize, 52), base32EncodeLower(&node_id.bytes, &buf));
    try std.testing.expectEqualSlices(u8, &b32, buf[0..52]);
    for (b32) |c| try std.testing.expect((c >= 'a' and c <= 'z') or (c >= '2' and c <= '7'));
}

test "mdns response codec roundtrips SRV TXT and A records" {
    const allocator = std.testing.allocator;
    const node_id = key.SecretKey.fromBytes(.{0x6b} ** 32).public();
    const b32 = base32NodeId(node_id);

    var rec = Record{ .port = 33445, .relay = "https://relay.example.invalid/", .user_data = "codec-test" };
    rec.ips[0] = .{ 192, 168, 1, 20 };
    rec.ips[1] = .{ 10, 0, 0, 7 };
    rec.ip_count = 2;

    const packet = try buildResponsePacket(allocator, TEST_SERVICE, &b32, rec);
    defer allocator.free(packet);

    // A response must not be mistaken for a PTR query.
    try std.testing.expect(!hasServicePtrQuery(TEST_SERVICE, packet));

    var peers = std.AutoHashMap([52]u8, Record).init(allocator);
    defer freePeers(allocator, &peers);
    try ingestResponse(allocator, &peers, TEST_SERVICE, packet);

    const got = peers.get(b32) orelse return error.TestExpectedPeer;
    try std.testing.expectEqual(@as(u16, 33445), got.port);
    try std.testing.expectEqual(@as(usize, 2), got.ip_count);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 20 }, &got.ips[0]);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 7 }, &got.ips[1]);
    try std.testing.expectEqualStrings("https://relay.example.invalid/", got.relay.?);
    try std.testing.expectEqualStrings("codec-test", got.user_data.?);

    // Re-ingesting a shorter record replaces (and frees) the previous one.
    var updated = Record{ .port = 33446 };
    updated.ips[0] = .{ 192, 168, 1, 21 };
    updated.ip_count = 1;
    const packet2 = try buildResponsePacket(allocator, TEST_SERVICE, &b32, updated);
    defer allocator.free(packet2);
    try ingestResponse(allocator, &peers, TEST_SERVICE, packet2);
    const got2 = peers.get(b32) orelse return error.TestExpectedPeer;
    try std.testing.expectEqual(@as(u16, 33446), got2.port);
    try std.testing.expectEqual(@as(usize, 1), got2.ip_count);
    try std.testing.expect(got2.relay == null);
    try std.testing.expect(got2.user_data == null);

    // Records of a DIFFERENT service are ignored.
    const other = try buildResponsePacket(allocator, "_other._udp.local", &b32, rec);
    defer allocator.free(other);
    try ingestResponse(allocator, &peers, TEST_SERVICE, other);
    try std.testing.expectEqual(@as(u32, 1), peers.count());

    // PTR query builder <-> query detector roundtrip.
    const query = try buildPtrQuery(allocator, TEST_SERVICE);
    defer allocator.free(query);
    try std.testing.expect(hasServicePtrQuery(TEST_SERVICE, query));
    try std.testing.expect(!hasServicePtrQuery("_other._udp.local", query));
}

test "mdns providers resolve over real loopback multicast" {
    const allocator = std.testing.allocator;
    const node_a = key.SecretKey.fromBytes(.{0xa1} ** 32).public();
    const node_b = key.SecretKey.fromBytes(.{0xb2} ** 32).public();
    const node_never_published = key.SecretKey.fromBytes(.{0xc3} ** 32).public();

    const options = Options{
        .multicast_interface = .{ 127, 0, 0, 1 },
        .resolve_timeout_ms = 3000,
    };
    const a = try MdnsAddressLookup.init(allocator, node_a, options);
    defer a.deinit();

    // Publish BEFORE B exists: the one-shot announcement is lost, so B's
    // resolve must exercise the PTR query -> response path.
    const published_ip = net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 45777 } };
    var relay = try addr.RelayUrl.parse(allocator, "https://relay.example.invalid/");
    defer relay.deinit(allocator);
    var endpoint_addr = try addr.EndpointAddr.fromParts(allocator, node_a, &.{
        .{ .ip = published_ip },
        .{ .relay = relay },
    });
    defer endpoint_addr.deinit(allocator);
    try a.publish(endpoint_addr, "zig-mdns-e2e");

    const b = try MdnsAddressLookup.init(allocator, node_b, options);
    defer b.deinit();

    const resolved = try b.resolve(node_a);
    defer resolved.deinit(allocator);
    try std.testing.expect(resolved.node_id.eql(node_a));
    try std.testing.expectEqualStrings("mdns", resolved.provenance.?);
    try std.testing.expect(resolved.last_updated != null);
    try std.testing.expectEqualStrings("zig-mdns-e2e", resolved.user_data.?);
    try std.testing.expectEqualStrings("https://relay.example.invalid/", resolved.firstRelayUrl().?.asString());
    var ip_it = resolved.ipAddrs();
    const resolved_ip = ip_it.next() orelse return error.TestExpectedIp;
    try std.testing.expectEqual(published_ip, resolved_ip);
    try std.testing.expect(ip_it.next() == null);

    // Mutation control: a never-published node id must time out.
    try std.testing.expectError(
        error.MdnsResolveTimeout,
        b.resolveWithTimeout(node_never_published, 800),
    );
}
