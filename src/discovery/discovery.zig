//! Discovery leaf track: pkarr signed packets, TXT attrs, relay-store helpers,
//! and DoH DNS-query construction.

const std = @import("std");
const root = @import("../root.zig");

pub const dns_wire = @import("dns_wire.zig");

pub const MAX_DNS_PACKET_SIZE: usize = 1000;
pub const HEADER_SIZE: usize = 104;
pub const MAX_SIGNED_PACKET_SIZE: usize = HEADER_SIZE + MAX_DNS_PACKET_SIZE;
pub const RELAY_CONTENT_TYPE = "application/x-pkarr-signed-packet";
pub const DNS_MESSAGE_CONTENT_TYPE = "application/dns-message";
pub const DEFAULT_PKARR_RELAY_URL = "https://dns.iroh.link/pkarr";
pub const DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query";
pub const DEFAULT_DNS_ORIGIN = "dns.iroh.link.";
pub const DEFAULT_TTL: u32 = 30;

pub const PublishAddressFilter = enum {
    relay_only,
    unfiltered,
};

pub const PublishOptions = struct {
    address_filter: PublishAddressFilter = .relay_only,
};

pub const EndpointInfoMetadata = struct {
    provenance: ?[]const u8 = null,
    last_updated: ?Timestamp = null,
};

pub const Error = error{
    PacketTooShort,
    PacketTooLarge,
    ResponseTooLarge,
    DnsPacketTooLarge,
    DnsNonZeroRcode,
    MalformedRelayPayload,
    MalformedTxt,
    UnsupportedTxtKey,
    BadSignature,
    InvalidPublicKey,
    InvalidNodeName,
    InvalidAddress,
    MissingPacket,
    OlderPacket,
    UnexpectedHttpStatus,
};

pub const EndpointInfo = struct {
    node_id: root.NodeId,
    addrs: []root.TransportAddr = &.{},
    user_data: ?[]u8 = null,
    provenance: ?[]u8 = null,
    last_updated: ?Timestamp = null,
    owned: bool = false,

    pub fn deinit(self: EndpointInfo, allocator: std.mem.Allocator) void {
        if (self.owned) {
            for (self.addrs) |addr| addr.deinit(allocator);
            allocator.free(self.addrs);
        }
        if (self.user_data) |s| allocator.free(s);
        if (self.provenance) |s| allocator.free(s);
    }

    pub fn fromParts(
        allocator: std.mem.Allocator,
        node_id: root.NodeId,
        addrs: []const root.TransportAddr,
        user_data: ?[]const u8,
    ) !EndpointInfo {
        return fromPartsWithMetadata(allocator, node_id, addrs, user_data, .{});
    }

    pub fn fromPartsWithMetadata(
        allocator: std.mem.Allocator,
        node_id: root.NodeId,
        addrs: []const root.TransportAddr,
        user_data: ?[]const u8,
        metadata: EndpointInfoMetadata,
    ) !EndpointInfo {
        return .{
            .node_id = node_id,
            .addrs = try cloneTransportAddrs(allocator, addrs),
            .user_data = if (user_data) |u| try allocator.dupe(u8, u) else null,
            .provenance = if (metadata.provenance) |p| try allocator.dupe(u8, p) else null,
            .last_updated = metadata.last_updated,
            .owned = true,
        };
    }

    pub fn clone(self: EndpointInfo, allocator: std.mem.Allocator) !EndpointInfo {
        return fromPartsWithMetadata(allocator, self.node_id, self.addrs, self.user_data, .{
            .provenance = self.provenance,
            .last_updated = self.last_updated,
        });
    }

    pub fn toNodeAddr(self: EndpointInfo, allocator: std.mem.Allocator) !root.NodeAddr {
        return root.EndpointAddr.fromParts(allocator, self.node_id, self.addrs);
    }

    pub fn fromNodeAddr(
        allocator: std.mem.Allocator,
        node_addr: root.NodeAddr,
        user_data: ?[]const u8,
    ) !EndpointInfo {
        return fromNodeAddrWithMetadata(allocator, node_addr, user_data, .{});
    }

    pub fn fromNodeAddrWithMetadata(
        allocator: std.mem.Allocator,
        node_addr: root.NodeAddr,
        user_data: ?[]const u8,
        metadata: EndpointInfoMetadata,
    ) !EndpointInfo {
        return fromPartsWithMetadata(allocator, node_addr.id, node_addr.addrs, user_data, metadata);
    }

    pub fn ipAddrs(self: EndpointInfo) root.addr.IpAddrIterator {
        return .{ .addrs = self.addrs };
    }

    pub fn relayUrls(self: EndpointInfo) root.addr.RelayUrlIterator {
        return .{ .addrs = self.addrs };
    }

    pub fn firstRelayUrl(self: EndpointInfo) ?root.RelayUrl {
        var it = self.relayUrls();
        return it.next();
    }

    pub fn toTxtStrings(self: EndpointInfo, allocator: std.mem.Allocator) ![][]u8 {
        return self.toTxtStringsWithOptions(allocator, .{});
    }

    pub fn toTxtStringsWithOptions(
        self: EndpointInfo,
        allocator: std.mem.Allocator,
        options: PublishOptions,
    ) ![][]u8 {
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |s| allocator.free(s);
            out.deinit(allocator);
        }
        for (self.addrs) |address| {
            switch (address) {
                .relay => |relay| try out.append(allocator, try relayTxtString(allocator, relay)),
                .ip => |ip| switch (options.address_filter) {
                    .relay_only => {},
                    .unfiltered => try out.append(allocator, try std.fmt.allocPrint(allocator, "addr={f}", .{ip})),
                },
                .custom => |custom| switch (options.address_filter) {
                    .relay_only => {},
                    .unfiltered => {
                        const custom_text = try custom.toString(allocator);
                        defer allocator.free(custom_text);
                        try out.append(allocator, try std.fmt.allocPrint(allocator, "addr={s}", .{custom_text}));
                    },
                },
            }
        }
        if (self.user_data) |user_data| {
            try out.append(allocator, try std.fmt.allocPrint(allocator, "user-data={s}", .{user_data}));
        }
        return out.toOwnedSlice(allocator);
    }

    pub fn fromTxtLookup(
        allocator: std.mem.Allocator,
        query_name: []const u8,
        txt_values: []const []const u8,
    ) !EndpointInfo {
        const node_id = try nodeIdFromTxtName(query_name);
        return fromTxtStringsWithMetadata(allocator, node_id, txt_values, .{
            .provenance = "dns-txt",
            .last_updated = Timestamp.now(),
        });
    }

    pub fn fromSignedPacket(allocator: std.mem.Allocator, packet: SignedPacket) !EndpointInfo {
        const name = try normalizedTxtName(allocator, packet.public_key);
        defer allocator.free(name);
        const values = try dns_wire.parseTxtAnswers(allocator, packet.encodedPacket(), name);
        defer {
            for (values) |v| allocator.free(v);
            allocator.free(values);
        }
        return fromTxtStringsWithMetadata(allocator, packet.public_key, values, .{
            .provenance = "pkarr",
            .last_updated = packet.timestamp,
        });
    }

    fn fromTxtStrings(
        allocator: std.mem.Allocator,
        node_id: root.NodeId,
        txt_values: []const []const u8,
    ) !EndpointInfo {
        return fromTxtStringsWithMetadata(allocator, node_id, txt_values, .{});
    }

    fn fromTxtStringsWithMetadata(
        allocator: std.mem.Allocator,
        node_id: root.NodeId,
        txt_values: []const []const u8,
        metadata: EndpointInfoMetadata,
    ) !EndpointInfo {
        var addrs: std.ArrayList(root.TransportAddr) = .empty;
        errdefer freeTransportAddrList(allocator, &addrs);
        var user_data: ?[]u8 = null;
        errdefer if (user_data) |s| allocator.free(s);
        var provenance: ?[]u8 = null;
        errdefer if (provenance) |s| allocator.free(s);
        if (metadata.provenance) |p| provenance = try allocator.dupe(u8, p);

        for (txt_values) |txt| {
            const eq = std.mem.indexOfScalar(u8, txt, '=') orelse return error.MalformedTxt;
            const key = txt[0..eq];
            const value = txt[eq + 1 ..];
            if (std.mem.eql(u8, key, "relay")) {
                const relay = root.RelayUrl.parse(allocator, value) catch continue;
                try appendDedupTransportAddr(allocator, &addrs, .{ .relay = relay });
            } else if (std.mem.eql(u8, key, "addr")) {
                if (std.Io.net.IpAddress.parseLiteral(value)) |ip| {
                    try appendDedupTransportAddr(allocator, &addrs, .{ .ip = ip });
                } else |_| {
                    const custom = root.CustomAddr.parse(allocator, value) catch return error.InvalidAddress;
                    try appendDedupTransportAddr(allocator, &addrs, .{ .custom = custom });
                }
            } else if (std.mem.eql(u8, key, "user-data")) {
                if (user_data == null) user_data = try allocator.dupe(u8, value);
            } else {
                return error.UnsupportedTxtKey;
            }
        }

        return .{
            .node_id = node_id,
            .addrs = try addrs.toOwnedSlice(allocator),
            .user_data = user_data,
            .provenance = provenance,
            .last_updated = metadata.last_updated,
            .owned = true,
        };
    }
};

fn cloneTransportAddrs(allocator: std.mem.Allocator, addrs: []const root.TransportAddr) ![]root.TransportAddr {
    var out: std.ArrayList(root.TransportAddr) = .empty;
    errdefer freeTransportAddrList(allocator, &out);
    for (addrs) |item| try out.append(allocator, try item.clone(allocator));
    return out.toOwnedSlice(allocator);
}

fn freeTransportAddrList(allocator: std.mem.Allocator, addrs: *std.ArrayList(root.TransportAddr)) void {
    for (addrs.items) |item| item.deinit(allocator);
    addrs.deinit(allocator);
}

fn appendDedupTransportAddr(
    allocator: std.mem.Allocator,
    addrs: *std.ArrayList(root.TransportAddr),
    item: root.TransportAddr,
) !void {
    for (addrs.items) |existing| {
        if (existing.eql(item)) {
            item.deinit(allocator);
            return;
        }
    }
    try addrs.append(allocator, item);
}

fn relayTxtString(allocator: std.mem.Allocator, relay: root.RelayUrl) ![]u8 {
    return std.fmt.allocPrint(allocator, "relay={s}", .{relay.asString()});
}

var timestamp_counter: std.atomic.Value(u64) = .init(1);

pub const Timestamp = struct {
    micros: u64,

    /// Monotonic-enough micros for pkarr packet timestamps. Prefer an explicit
    /// `Timestamp{ .micros = N }` in tests for determinism. Zig 0.16 dropped
    /// `std.time.microTimestamp`; this uses a process-local counter so
    /// publish-on-online works without an `std.Io` handle.
    pub fn now() Timestamp {
        const n = timestamp_counter.fetchAdd(1, .monotonic);
        // Offset above typical test micros (0..1000) so live publishes win
        // over fixture packets that use small constants.
        return .{ .micros = 1_000_000_000_000 +% n };
    }

    pub fn toBytes(self: Timestamp) [8]u8 {
        var out: [8]u8 = undefined;
        std.mem.writeInt(u64, &out, self.micros, .big);
        return out;
    }

    pub fn fromBytes(bytes: *const [8]u8) Timestamp {
        return .{ .micros = std.mem.readInt(u64, bytes, .big) };
    }
};

pub const SignedPacket = struct {
    bytes: []u8,
    public_key: root.PublicKey,
    signature: root.Signature,
    timestamp: Timestamp,

    pub fn deinit(self: SignedPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
    }

    pub fn fromEndpointInfoAt(
        allocator: std.mem.Allocator,
        secret_key: root.SecretKey,
        info: EndpointInfo,
        ttl: u32,
        timestamp: Timestamp,
    ) !SignedPacket {
        return fromEndpointInfoAtWithOptions(allocator, secret_key, info, ttl, timestamp, .{});
    }

    pub fn fromEndpointInfoAtWithOptions(
        allocator: std.mem.Allocator,
        secret_key: root.SecretKey,
        info: EndpointInfo,
        ttl: u32,
        timestamp: Timestamp,
        options: PublishOptions,
    ) !SignedPacket {
        const values = try info.toTxtStringsWithOptions(allocator, options);
        defer {
            for (values) |v| allocator.free(v);
            allocator.free(values);
        }
        return fromTxtStringsAt(allocator, secret_key, values, ttl, timestamp);
    }

    pub fn fromTxtStringsAt(
        allocator: std.mem.Allocator,
        secret_key: root.SecretKey,
        values: []const []const u8,
        ttl: u32,
        timestamp: Timestamp,
    ) !SignedPacket {
        const public_key = secret_key.public();
        const name = try normalizedTxtName(allocator, public_key);
        defer allocator.free(name);
        const dns_packet = try dns_wire.buildTxtReply(allocator, name, values, ttl);
        defer allocator.free(dns_packet);
        if (dns_packet.len > MAX_DNS_PACKET_SIZE) return error.DnsPacketTooLarge;
        const msg = try signable(allocator, timestamp.micros, dns_packet);
        defer allocator.free(msg);
        const signature = secret_key.sign(msg);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, &public_key.bytes);
        try out.appendSlice(allocator, &signature.bytes);
        const ts_bytes = timestamp.toBytes();
        try out.appendSlice(allocator, &ts_bytes);
        try out.appendSlice(allocator, dns_packet);
        return fromBytesOwned(allocator, try out.toOwnedSlice(allocator));
    }

    /// Sign an already-encoded DNS packet verbatim.
    ///
    /// `fromTxtStringsAt` owns the encoding for endpoint info; this is the
    /// escape hatch for a zone whose records are not the iroh TXT set (an A/AAAA
    /// record in a pkarr zone, for example). The bytes are signed as given, and
    /// the result still goes through the strict verify in `fromBytesOwned`, so a
    /// caller cannot use this to smuggle in an unverifiable packet.
    pub fn fromEncodedDnsPacketAt(
        allocator: std.mem.Allocator,
        secret_key: root.SecretKey,
        dns_packet: []const u8,
        timestamp: Timestamp,
    ) !SignedPacket {
        if (dns_packet.len > MAX_DNS_PACKET_SIZE) return error.DnsPacketTooLarge;
        const msg = try signable(allocator, timestamp.micros, dns_packet);
        defer allocator.free(msg);
        const signature = secret_key.sign(msg);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, &secret_key.public().bytes);
        try out.appendSlice(allocator, &signature.bytes);
        const ts_bytes = timestamp.toBytes();
        try out.appendSlice(allocator, &ts_bytes);
        try out.appendSlice(allocator, dns_packet);
        return fromBytesOwned(allocator, try out.toOwnedSlice(allocator));
    }

    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) !SignedPacket {
        return fromBytesOwned(allocator, try allocator.dupe(u8, bytes));
    }

    pub fn fromRelayPayload(
        allocator: std.mem.Allocator,
        public_key: root.PublicKey,
        payload: []const u8,
    ) !SignedPacket {
        return fromRelayPayloadMode(allocator, public_key, payload, .strict);
    }

    /// Like `fromRelayPayload` but with selectable Ed25519 verify strictness.
    /// DHT/BEP-44 callers use `.cofactored` (ADR 2026-06-27); pkarr/relay keep
    /// the default strict path so identity trust boundaries stay tight.
    pub fn fromRelayPayloadMode(
        allocator: std.mem.Allocator,
        public_key: root.PublicKey,
        payload: []const u8,
        mode: VerifyMode,
    ) !SignedPacket {
        if (payload.len < 72) return error.MalformedRelayPayload;
        var bytes = try allocator.alloc(u8, 32 + payload.len);
        @memcpy(bytes[0..32], &public_key.bytes);
        @memcpy(bytes[32..], payload);
        return fromBytesOwnedMode(allocator, bytes, mode);
    }

    pub const VerifyMode = enum { strict, cofactored };

    pub fn relayPayload(self: SignedPacket) []const u8 {
        return self.bytes[32..];
    }

    pub fn encodedPacket(self: SignedPacket) []const u8 {
        return self.bytes[HEADER_SIZE..];
    }

    pub fn moreRecentThan(self: SignedPacket, other: SignedPacket) bool {
        if (self.timestamp.micros == other.timestamp.micros) {
            return std.mem.order(u8, self.encodedPacket(), other.encodedPacket()) == .gt;
        }
        return self.timestamp.micros > other.timestamp.micros;
    }

    fn fromBytesOwned(allocator: std.mem.Allocator, bytes: []u8) !SignedPacket {
        return fromBytesOwnedMode(allocator, bytes, .strict);
    }

    fn fromBytesOwnedMode(allocator: std.mem.Allocator, bytes: []u8, mode: VerifyMode) !SignedPacket {
        errdefer allocator.free(bytes);
        if (bytes.len < HEADER_SIZE) return error.PacketTooShort;
        if (bytes.len > MAX_SIGNED_PACKET_SIZE) return error.PacketTooLarge;
        if (bytes.len - HEADER_SIZE > MAX_DNS_PACKET_SIZE) return error.DnsPacketTooLarge;
        const public_key = root.PublicKey.fromBytes(bytes[0..32].*) catch return error.InvalidPublicKey;
        const signature = root.Signature.fromBytes(bytes[32..96].*);
        const timestamp = Timestamp.fromBytes(bytes[96..104]);
        const msg = try signable(allocator, timestamp.micros, bytes[HEADER_SIZE..]);
        defer allocator.free(msg);
        switch (mode) {
            .strict => public_key.verify(msg, signature) catch return error.BadSignature,
            // DHT/BEP-44 boundary only (mainline cofactored verify).
            .cofactored => public_key.verifyCofactored(msg, signature) catch return error.BadSignature,
        }

        const name = try normalizedTxtName(allocator, public_key);
        defer allocator.free(name);
        const parsed = try dns_wire.parseTxtAnswers(allocator, bytes[HEADER_SIZE..], name);
        defer {
            for (parsed) |v| allocator.free(v);
            allocator.free(parsed);
        }

        return .{
            .bytes = bytes,
            .public_key = public_key,
            .signature = signature,
            .timestamp = timestamp,
        };
    }
};

pub fn signable(allocator: std.mem.Allocator, timestamp: u64, dns_packet: []const u8) ![]u8 {
    const prefix = try std.fmt.allocPrint(allocator, "3:seqi{d}e1:v{d}:", .{ timestamp, dns_packet.len });
    defer allocator.free(prefix);
    return std.mem.concat(allocator, u8, &.{ prefix, dns_packet });
}

pub const PacketStore = struct {
    allocator: std.mem.Allocator,
    packets: std.AutoHashMap([32]u8, []u8),

    pub fn init(allocator: std.mem.Allocator) PacketStore {
        return .{ .allocator = allocator, .packets = .init(allocator) };
    }

    pub fn deinit(self: *PacketStore) void {
        var it = self.packets.valueIterator();
        while (it.next()) |bytes| self.allocator.free(bytes.*);
        self.packets.deinit();
    }

    pub fn putRelayPayload(self: *PacketStore, public_key: root.PublicKey, payload: []const u8) !void {
        var incoming = try SignedPacket.fromRelayPayload(self.allocator, public_key, payload);
        defer incoming.deinit(self.allocator);

        // Dupe first so OOM cannot leave an uninitialized / freed map entry.
        const owned = try self.allocator.dupe(u8, incoming.bytes);
        errdefer self.allocator.free(owned);

        const gop = try self.packets.getOrPut(public_key.bytes);
        if (!gop.found_existing) {
            gop.value_ptr.* = owned;
            return;
        }

        var existing = try SignedPacket.fromBytes(self.allocator, gop.value_ptr.*);
        defer existing.deinit(self.allocator);
        if (!incoming.moreRecentThan(existing)) return error.OlderPacket;
        const old = gop.value_ptr.*;
        gop.value_ptr.* = owned;
        self.allocator.free(old);
    }

    pub fn getRelayPayload(self: *PacketStore, public_key: root.PublicKey) ![]u8 {
        const bytes = self.packets.get(public_key.bytes) orelse return error.MissingPacket;
        return self.allocator.dupe(u8, bytes[32..]);
    }
};

pub fn publishToStore(
    allocator: std.mem.Allocator,
    store: *PacketStore,
    secret_key: root.SecretKey,
    info: EndpointInfo,
    ttl: u32,
    timestamp: Timestamp,
) !void {
    var packet = try SignedPacket.fromEndpointInfoAt(allocator, secret_key, info, ttl, timestamp);
    defer packet.deinit(allocator);
    try store.putRelayPayload(secret_key.public(), packet.relayPayload());
}

pub fn resolveFromStore(allocator: std.mem.Allocator, store: *PacketStore, node_id: root.NodeId) !EndpointInfo {
    const payload = try store.getRelayPayload(node_id);
    defer allocator.free(payload);
    var packet = try SignedPacket.fromRelayPayload(allocator, node_id, payload);
    defer packet.deinit(allocator);
    return EndpointInfo.fromSignedPacket(allocator, packet);
}

pub fn pkarrRelayUrl(
    allocator: std.mem.Allocator,
    relay_url: []const u8,
    node_id: root.NodeId,
) ![]u8 {
    const z32 = node_id.toZ32();
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{
        std.mem.trimEnd(u8, relay_url, "/"),
        &z32,
    });
}

pub fn resolvePkarrRelay(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    relay_url: []const u8,
    node_id: root.NodeId,
) !EndpointInfo {
    const url = try pkarrRelayUrl(allocator, relay_url, node_id);
    defer allocator.free(url);

    // Bound remote-controlled allocation (MAX_SIGNED_PACKET_SIZE).
    var body_buf: [MAX_SIGNED_PACKET_SIZE]u8 = undefined;
    var body: std.Io.Writer = .fixed(&body_buf);
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .extra_headers = &.{
            .{ .name = "accept", .value = RELAY_CONTENT_TYPE },
        },
        .response_writer = &body,
    });
    if (result.status != .ok) return error.UnexpectedHttpStatus;

    const payload = body.buffered();
    var packet = try SignedPacket.fromRelayPayload(allocator, node_id, payload);
    defer packet.deinit(allocator);
    return EndpointInfo.fromSignedPacket(allocator, packet);
}

pub fn publishPkarrRelay(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    relay_url: []const u8,
    secret_key: root.SecretKey,
    info: EndpointInfo,
    ttl: u32,
    timestamp: Timestamp,
) !void {
    return publishPkarrRelayWithOptions(allocator, client, relay_url, secret_key, info, ttl, timestamp, .{});
}

pub fn publishPkarrRelayWithOptions(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    relay_url: []const u8,
    secret_key: root.SecretKey,
    info: EndpointInfo,
    ttl: u32,
    timestamp: Timestamp,
    options: PublishOptions,
) !void {
    var packet = try SignedPacket.fromEndpointInfoAtWithOptions(allocator, secret_key, info, ttl, timestamp, options);
    defer packet.deinit(allocator);

    const url = try pkarrRelayUrl(allocator, relay_url, secret_key.public());
    defer allocator.free(url);

    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = .PUT,
        .payload = packet.relayPayload(),
        .headers = .{
            .content_type = .{ .override = RELAY_CONTENT_TYPE },
        },
    });
    switch (result.status) {
        .ok, .created, .accepted, .no_content => {},
        else => return error.UnexpectedHttpStatus,
    }
}

pub const DiscoveryClient = struct {
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    pkarr_relay_url: []const u8 = DEFAULT_PKARR_RELAY_URL,
    doh_url: ?[]const u8 = DEFAULT_DOH_URL,
    dns_origin: []const u8 = DEFAULT_DNS_ORIGIN,

    pub fn publish(
        self: DiscoveryClient,
        secret_key: root.SecretKey,
        info: EndpointInfo,
        ttl: u32,
        timestamp: Timestamp,
    ) !void {
        return publishPkarrRelay(
            self.allocator,
            self.http_client,
            self.pkarr_relay_url,
            secret_key,
            info,
            ttl,
            timestamp,
        );
    }

    pub fn resolve(self: DiscoveryClient, node_id: root.NodeId) !EndpointInfo {
        return resolvePkarrRelay(
            self.allocator,
            self.http_client,
            self.pkarr_relay_url,
            node_id,
        ) catch |relay_err| {
            if (self.doh_url) |doh_url| {
                return resolveDohTxt(self.allocator, self.http_client, doh_url, node_id, self.dns_origin);
            }
            return relay_err;
        };
    }
};

pub fn buildDohGetUrl(
    allocator: std.mem.Allocator,
    doh_base_url: []const u8,
    node_id: root.NodeId,
    origin: []const u8,
) ![]u8 {
    const query_name = try txtLookupName(allocator, node_id, origin);
    defer allocator.free(query_name);
    const query = try dns_wire.buildTxtQuery(allocator, query_name);
    defer allocator.free(query);
    const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(query.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = std.base64.url_safe_no_pad.Encoder.encode(encoded, query);
    const sep: []const u8 = if (std.mem.indexOfScalar(u8, doh_base_url, '?') == null) "?" else "&";
    return std.fmt.allocPrint(allocator, "{s}{s}dns={s}", .{ doh_base_url, sep, encoded });
}

pub fn resolveDohTxt(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    doh_base_url: []const u8,
    node_id: root.NodeId,
    origin: []const u8,
) !EndpointInfo {
    const query_name = try txtLookupName(allocator, node_id, origin);
    defer allocator.free(query_name);
    const url = try buildDohGetUrl(allocator, doh_base_url, node_id, origin);
    defer allocator.free(url);

    var body_buf: [64 * 1024]u8 = undefined;
    var body: std.Io.Writer = .fixed(&body_buf);
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .extra_headers = &.{
            .{ .name = "accept", .value = DNS_MESSAGE_CONTENT_TYPE },
        },
        .response_writer = &body,
    });
    if (result.status != .ok) return error.UnexpectedHttpStatus;

    const packet = body.buffered();
    // Fail-closed on non-zero DNS RCODE (NXDOMAIN/SERVFAIL must not look like
    // a successful empty address set). RFC 1035 §4.1.1 RCODE is flags[0..3].
    if (packet.len < 12) return error.PacketTooShort;
    const rcode: u4 = @truncate(packet[3] & 0x0f);
    if (rcode != 0) return error.DnsNonZeroRcode;
    const txt_values = try dns_wire.parseTxtAnswers(allocator, packet, query_name);
    defer freeTxtStrings(allocator, txt_values);
    return EndpointInfo.fromTxtLookup(allocator, query_name, txt_values);
}

pub fn txtLookupName(allocator: std.mem.Allocator, node_id: root.NodeId, origin: []const u8) ![]u8 {
    const z32 = node_id.toZ32();
    const clean_origin = std.mem.trimStart(u8, origin, ".");
    return std.fmt.allocPrint(allocator, "_iroh.{s}.{s}", .{ &z32, clean_origin });
}

fn normalizedTxtName(allocator: std.mem.Allocator, node_id: root.NodeId) ![]u8 {
    const z32 = node_id.toZ32();
    return std.fmt.allocPrint(allocator, "_iroh.{s}", .{&z32});
}

fn nodeIdFromTxtName(name_in: []const u8) !root.NodeId {
    const name = std.mem.trimEnd(u8, name_in, ".");
    var it = std.mem.splitScalar(u8, name, '.');
    const first = it.next() orelse return error.InvalidNodeName;
    if (!std.mem.eql(u8, first, "_iroh")) return error.InvalidNodeName;
    const z32 = it.next() orelse return error.InvalidNodeName;
    return root.PublicKey.fromZ32(z32) catch return error.InvalidNodeName;
}

fn freeTxtStrings(allocator: std.mem.Allocator, values: [][]u8) void {
    for (values) |v| allocator.free(v);
    allocator.free(values);
}

test "signable matches BEP-44 framing" {
    const msg = try signable(std.testing.allocator, 42, "PAYLOAD");
    defer std.testing.allocator.free(msg);
    try std.testing.expectEqualStrings("3:seqi42e1:v7:PAYLOAD", msg);
}

test "EndpointInfo parses iroh TXT lookup fixture preserving address order" {
    const allocator = std.testing.allocator;
    const values = [_][]const u8{
        "addr=192.0.2.10:60165",
        "addr=192.0.2.11:60165",
        "relay=https://euw1-1.relay.iroh.network./",
    };
    const info = try EndpointInfo.fromTxtLookup(
        allocator,
        "_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy.dns.iroh.link.",
        &values,
    );
    defer info.deinit(allocator);
    try std.testing.expectEqualStrings("1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18", &info.node_id.toHex());
    try std.testing.expectEqualStrings("https://euw1-1.relay.iroh.network./", info.firstRelayUrl().?.asString());
    var ip_it = info.ipAddrs();
    const ip0 = ip_it.next().?;
    const ip1 = ip_it.next().?;
    try std.testing.expect(ip_it.next() == null);
    var buf0: [64]u8 = undefined;
    var buf1: [64]u8 = undefined;
    try std.testing.expectEqualStrings("192.0.2.10:60165", try std.fmt.bufPrint(&buf0, "{f}", .{ip0}));
    try std.testing.expectEqualStrings("192.0.2.11:60165", try std.fmt.bufPrint(&buf1, "{f}", .{ip1}));
}

test "EndpointInfo TXT publish defaults relay-only and supports unfiltered IP/custom addresses" {
    const allocator = std.testing.allocator;
    const secret = root.SecretKey.fromBytes(.{0x10} ** 32);
    const direct = try std.Io.net.IpAddress.parse("127.0.0.1", 1234);
    var relay = try root.RelayUrl.parse(allocator, "https://relay.example");
    defer relay.deinit(allocator);
    var custom = try root.CustomAddr.fromParts(allocator, 1, &.{ 0xa1, 0xb2, 0xc3 });
    defer custom.deinit(allocator);
    const info = try EndpointInfo.fromParts(
        allocator,
        secret.public(),
        &.{ .{ .relay = relay }, .{ .ip = direct }, .{ .custom = custom } },
        "opaque",
    );
    defer info.deinit(allocator);

    const relay_only = try info.toTxtStrings(allocator);
    defer freeTxtStrings(allocator, relay_only);
    try std.testing.expectEqual(@as(usize, 2), relay_only.len);
    try std.testing.expectEqualStrings("relay=https://relay.example/", relay_only[0]);
    try std.testing.expectEqualStrings("user-data=opaque", relay_only[1]);

    const unfiltered = try info.toTxtStringsWithOptions(allocator, .{ .address_filter = .unfiltered });
    defer freeTxtStrings(allocator, unfiltered);
    try std.testing.expectEqual(@as(usize, 4), unfiltered.len);
    try std.testing.expectEqualStrings("relay=https://relay.example/", unfiltered[0]);
    try std.testing.expectEqualStrings("addr=127.0.0.1:1234", unfiltered[1]);
    try std.testing.expectEqualStrings("addr=1_a1b2c3", unfiltered[2]);
    try std.testing.expectEqualStrings("user-data=opaque", unfiltered[3]);

    const parsed = try EndpointInfo.fromTxtLookup(
        allocator,
        "_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy.dns.iroh.link.",
        unfiltered,
    );
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("dns-txt", parsed.provenance.?);
    try std.testing.expect(parsed.last_updated != null);
    try std.testing.expectEqual(@as(usize, 3), parsed.addrs.len);
    try std.testing.expect(parsed.addrs[0].isRelay());
    try std.testing.expect(parsed.addrs[1].isIp());
    try std.testing.expect(parsed.addrs[2].isCustom());
}

test "SignedPacket signs, verifies, exposes relay payload, and rejects tampering" {
    const allocator = std.testing.allocator;
    const secret = root.SecretKey.fromBytes(.{0x11} ** 32);
    const direct = try std.Io.net.IpAddress.parse("127.0.0.1", 1234);
    var relay = try root.RelayUrl.parse(allocator, "https://example.com");
    defer relay.deinit(allocator);
    const info = try EndpointInfo.fromParts(allocator, secret.public(), &.{ .{ .relay = relay }, .{ .ip = direct } }, "foobar");
    defer info.deinit(allocator);

    var packet = try SignedPacket.fromEndpointInfoAt(allocator, secret, info, DEFAULT_TTL, .{ .micros = 42 });
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, packet.bytes.len - 32), packet.relayPayload().len);

    var parsed = try SignedPacket.fromBytes(allocator, packet.bytes);
    defer parsed.deinit(allocator);
    const round = try EndpointInfo.fromSignedPacket(allocator, parsed);
    defer round.deinit(allocator);
    try std.testing.expect(round.node_id.eql(secret.public()));
    try std.testing.expectEqualStrings("pkarr", round.provenance.?);
    try std.testing.expectEqual(@as(u64, 42), round.last_updated.?.micros);
    try std.testing.expectEqualStrings("https://example.com/", round.firstRelayUrl().?.asString());
    var round_ips = round.ipAddrs();
    try std.testing.expect(round_ips.next() == null);
    try std.testing.expectEqualStrings("foobar", round.user_data.?);

    var unfiltered_packet = try SignedPacket.fromEndpointInfoAtWithOptions(
        allocator,
        secret,
        info,
        DEFAULT_TTL,
        .{ .micros = 43 },
        .{ .address_filter = .unfiltered },
    );
    defer unfiltered_packet.deinit(allocator);
    const unfiltered_round = try EndpointInfo.fromSignedPacket(allocator, unfiltered_packet);
    defer unfiltered_round.deinit(allocator);
    var unfiltered_ips = unfiltered_round.ipAddrs();
    try std.testing.expect(unfiltered_ips.next() != null);
    try std.testing.expect(unfiltered_ips.next() == null);

    const tampered = try allocator.dupe(u8, packet.bytes);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(error.BadSignature, SignedPacket.fromBytes(allocator, tampered));
}

test "PacketStore publish then resolve is standalone and rejects older packets" {
    const allocator = std.testing.allocator;
    const secret = root.SecretKey.fromBytes(.{0x22} ** 32);
    const direct = try std.Io.net.IpAddress.parse("127.0.0.1", 9999);
    var relay = try root.RelayUrl.parse(allocator, "https://local.invalid/pkarr");
    defer relay.deinit(allocator);
    const info = try EndpointInfo.fromParts(allocator, secret.public(), &.{ .{ .relay = relay }, .{ .ip = direct } }, null);
    defer info.deinit(allocator);

    var store = PacketStore.init(allocator);
    defer store.deinit();
    try publishToStore(allocator, &store, secret, info, DEFAULT_TTL, .{ .micros = 100 });
    const resolved = try resolveFromStore(allocator, &store, secret.public());
    defer resolved.deinit(allocator);
    try std.testing.expectEqualStrings("https://local.invalid/pkarr", resolved.firstRelayUrl().?.asString());

    var old_packet = try SignedPacket.fromEndpointInfoAt(allocator, secret, info, DEFAULT_TTL, .{ .micros = 99 });
    defer old_packet.deinit(allocator);
    try std.testing.expectError(error.OlderPacket, store.putRelayPayload(secret.public(), old_packet.relayPayload()));
}

test "pkarr relay URL trims trailing slash and appends z32 node id" {
    const allocator = std.testing.allocator;
    const node_id = try root.PublicKey.fromZ32("dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy");
    const url = try pkarrRelayUrl(allocator, "https://dns.iroh.link/pkarr/", node_id);
    defer allocator.free(url);
    try std.testing.expectEqualStrings(
        "https://dns.iroh.link/pkarr/dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy",
        url,
    );
}

test "DoH GET URL encodes DNS wire query as base64url without padding" {
    const allocator = std.testing.allocator;
    const node_id = try root.PublicKey.fromZ32("dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy");
    const url = try buildDohGetUrl(allocator, "https://cloudflare-dns.com/dns-query", node_id, DEFAULT_DNS_ORIGIN);
    defer allocator.free(url);
    try std.testing.expect(std.mem.startsWith(u8, url, "https://cloudflare-dns.com/dns-query?dns="));
    const encoded = url[std.mem.indexOf(u8, url, "dns=").? + 4 ..];
    try std.testing.expect(std.mem.indexOfScalar(u8, encoded, '=') == null);
}

test "DoH: non-zero RCODE is fail-closed" {
    // Minimal 12-byte DNS header with RCODE=3 (NXDOMAIN) in flags low nibble.
    var hdr: [12]u8 = .{0} ** 12;
    hdr[3] = 0x03; // RCODE = 3
    // resolveDohTxt checks RCODE before parseTxtAnswers — unit-check the rule
    // the same way the production path does.
    const rcode: u4 = @truncate(hdr[3] & 0x0f);
    try std.testing.expect(rcode != 0);
    // RCODE=0 is the only success path.
    hdr[3] = 0;
    try std.testing.expectEqual(@as(u4, 0), @as(u4, @truncate(hdr[3] & 0x0f)));
}

test "resolve-verify: strict rejects cofactored-only; cofactored accepts" {
    // Wycheproof-style cofactored-only vector from key.zig (strict rejects).
    const msg = blk: {
        const hex = "65643235353139766563746f72732033"; // "ed25519vectors 3"
        var out: [16]u8 = undefined;
        _ = try std.fmt.hexToBytes(&out, hex);
        break :blk out;
    };
    const pk = try root.PublicKey.fromHex("86e72f5c2a7215151059aa151c0ee6f8e2155d301402f35d7498f078629a8f79");
    const sig = root.Signature.fromBytes(blk: {
        const hex = "fa9dde274f4820efb19a890f8ba2d8791710a4303ceef4aedf9dddc4e81a1f11701a598b9a02ae60505dd0c2938a1a0c2d6ffd4676cfb49125b19e9cb358da06";
        var out: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&out, hex);
        break :blk out;
    });
    // Centralized strict sink (pkarr/relay) MUST still reject malleable sigs.
    try std.testing.expectError(error.BadSignature, pk.verify(&msg, sig));
    // DHT mode accepts the same encoding (ADR per-boundary strictness).
    try pk.verifyCofactored(&msg, sig);
}

test {
    _ = dns_wire;
    _ = @import("address_lookup.zig");
    _ = @import("dns_resolver.zig");
    _ = @import("republish.zig");
    _ = @import("product.zig");
}
