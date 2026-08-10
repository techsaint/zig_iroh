//! Port mapping at iroh protocol parity: NAT-PMP + PCP + UPnP (IGD).
//!
//! iroh's `portmapper` crate probes ALL THREE protocols and maps with the
//! best one that answers (preference PCP, then NAT-PMP, then UPnP — the
//! most-deployed but least-reliable). The protocols iroh implements are not
//! a menu: this module replicates the full feature set, probe-all-use-
//! what-answers, plus the mapping lifecycle (renew at half the granted
//! lifetime, delete on release). NAT-PMP/PCP share UDP port 5351
//! (RFC 6887 §19); UPnP discovery is SSDP + SOAP/XML over HTTP.

const std = @import("std");
const net = std.Io.net;

// ==========================================================================
// Constants — the upstream `portmapper` crate's `defaults` and RFC values.
// ==========================================================================

/// NAT-PMP and PCP share UDP port 5351 (RFC 6887 §19).
pub const nat_pmp_port: u16 = 5351;
/// PCP's well-known server port (the IANA-shared NAT-PMP port).
pub const pcp_port: u16 = nat_pmp_port;

/// Maximum duration a UPnP search can take (crate UPNP_SEARCH_TIMEOUT).
pub const upnp_search_timeout_ms: u64 = 1_000;
/// Timeout for a PCP server response (crate PCP_RECV_TIMEOUT).
pub const pcp_recv_timeout_ms: u64 = 500;
/// Timeout for a NAT-PMP server response (crate NAT_PMP_RECV_TIMEOUT).
pub const nat_pmp_recv_timeout_ms: u64 = 500;

/// NAT-PMP mapping lifetime asked from the gateway (RFC 6886 recommends 2h).
pub const nat_pmp_requested_lifetime_seconds: u32 = 2 * 60 * 60;
/// PCP mapping lifetime asked from the gateway (the crate asks 1h).
pub const pcp_requested_lifetime_seconds: u32 = 60 * 60;
/// UPnP lease requested from the IGD (crate PORT_MAPPING_LEASE_DURATION_SECONDS).
pub const upnp_lease_duration_seconds: u32 = 2 * 60 * 60;
/// UPnP mappings assume a fixed half-lifetime of 1h (crate HALF_LIFETIME).
pub const upnp_half_lifetime_ms: u64 = 60 * 60 * 1000;
/// Description the mapping registers under on the IGD.
pub const upnp_mapping_description: []const u8 = "iroh-portmap";
/// Backoff before re-acquiring after a renewal expired the mapping.
/// Upstream waits for the next external procure; the retry loop is a
/// hardening superset (the endpoint re-establishes without outside prods).
pub const renew_failure_backoff_ms: u64 = 5_000;

/// Standard SSDP discovery target (UPnP Device Architecture).
pub const ssdp_default_target: []const u8 = "239.255.255.250:1900";

pub const ProbeError = error{
    MissingGatewayEnv,
    InvalidGatewayEnv,
    NatPmpIpv4Only,
    UnsupportedVersion,
    UnsupportedOpcode,
    GatewayRefused,
    ShortResponse,
    UnexpectedSource,
    UnexpectedResponse,
    NonceMismatch,
    ProtocolMismatch,
    PortMismatch,
    ZeroExternalPort,
    NotIpv4,
    InvalidAnnounce,
    InvalidUrl,
    HttpFailed,
    UpnpDiscoveryFailed,
    UpnpInvalidResponse,
    UpnpFault,
    UpnpNoPorts,
    AlreadyReleased,
    AllProtocolsFailed,
} || net.IpAddress.BindError || net.Socket.SendError || net.Socket.ReceiveTimeoutError;

// ==========================================================================
// NAT-PMP (RFC 6886)
// ==========================================================================

pub const NatPmpExternalAddressRequest = [2]u8{ 0, 0 };

pub const NatPmpExternalAddress = struct {
    gateway: net.IpAddress,
    public_ip: [4]u8,
    epoch_seconds: u32,
    latency_us: u64,
};

pub const NatPmpUdpMapping = struct {
    gateway: net.IpAddress,
    internal_port: u16,
    external_port: u16,
    lifetime_seconds: u32,
    epoch_seconds: u32,
    latency_us: u64,
};

/// Gateway text is either a bare IP ("192.0.2.1" → NAT-PMP's well-known
/// port) or IPv4-with-port ("192.0.2.1:5352"). The explicit-port form keeps
/// loopback test responders off the fixed well-known port, which collides
/// under the parallel test runner. (std's IpAddress.parse rejects "ip:port".)
pub fn parseGatewayText(text: []const u8) ProbeError!net.IpAddress {
    if (std.mem.count(u8, text, ":") == 1) {
        const colon = std.mem.indexOfScalar(u8, text, ':').?;
        const port = std.fmt.parseUnsigned(u16, text[colon + 1 ..], 10) catch return error.InvalidGatewayEnv;
        return net.IpAddress.parseIp4(text[0..colon], port) catch return error.InvalidGatewayEnv;
    }
    return net.IpAddress.parse(text, nat_pmp_port) catch return error.InvalidGatewayEnv;
}

/// UPnP SSDP discovery target text ("ip" → port 1900, or "ip:port").
pub fn parseUpnpTargetText(text: []const u8) ProbeError!net.IpAddress {
    if (std.mem.count(u8, text, ":") == 1) {
        const colon = std.mem.indexOfScalar(u8, text, ':').?;
        const port = std.fmt.parseUnsigned(u16, text[colon + 1 ..], 10) catch return error.InvalidGatewayEnv;
        return net.IpAddress.parseIp4(text[0..colon], port) catch return error.InvalidGatewayEnv;
    }
    return net.IpAddress.parse(text, 1900) catch return error.InvalidGatewayEnv;
}

pub fn gatewayFromEnv() ProbeError!?net.IpAddress {
    const raw = std.c.getenv("IROH_PORTMAPPER_GATEWAY") orelse return null;
    const text = std.mem.span(raw);
    if (text.len == 0) return null;
    return try parseGatewayText(text);
}

fn msTimeout(ms: u64) std.Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(@intCast(ms)), .clock = .awake } };
}

pub fn probeNatPmpFromEnv(io: std.Io) ProbeError!NatPmpExternalAddress {
    const gateway = (try gatewayFromEnv()) orelse return error.MissingGatewayEnv;
    return probeNatPmpExternalAddress(io, gateway, msTimeout(2000));
}

pub fn probeNatPmpExternalAddress(
    io: std.Io,
    gateway: net.IpAddress,
    timeout: std.Io.Timeout,
) ProbeError!NatPmpExternalAddress {
    if (gateway != .ip4) return error.NatPmpIpv4Only;
    var gw = gateway;
    // NAT-PMP's well-known port is the default; an explicit port on the
    // configured gateway is honored so loopback responders can live on
    // ephemeral ports (fixed-port responders collide under parallel tests).
    if (gw.getPort() == 0) gw.setPort(nat_pmp_port);

    var bind: net.IpAddress = .{ .ip4 = .unspecified(0) };
    const socket = try bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    const before = std.Io.Clock.Timestamp.now(io, .awake).raw.toMicroseconds();
    try socket.send(io, &gw, &NatPmpExternalAddressRequest);
    var buf: [64]u8 = undefined;
    const msg = try socket.receiveTimeout(io, &buf, timeout);
    const after = std.Io.Clock.Timestamp.now(io, .awake).raw.toMicroseconds();
    if (!sameHost(msg.from, gw)) return error.UnexpectedSource;
    const parsed = try parseNatPmpExternalAddressResponse(msg.data);
    return .{
        .gateway = gw,
        .public_ip = parsed.public_ip,
        .epoch_seconds = parsed.epoch_seconds,
        .latency_us = if (after >= before) @intCast(after - before) else 0,
    };
}

/// Encode an RFC 6886 §3.3 mapping request (opcode 1).
/// `requested_external_port` 0 lets the gateway choose; `lifetime_seconds`
/// 0 requests deletion (§3.4 — then the suggested external port MUST be 0).
pub fn encodeNatPmpMappingRequest(
    out: *[12]u8,
    internal_port: u16,
    requested_external_port: u16,
    lifetime_seconds: u32,
) void {
    out[0] = 0; // version
    out[1] = 1; // UDP mapping opcode
    std.mem.writeInt(u16, out[2..4], 0, .big); // reserved
    std.mem.writeInt(u16, out[4..6], internal_port, .big);
    std.mem.writeInt(u16, out[6..8], requested_external_port, .big);
    std.mem.writeInt(u32, out[8..12], lifetime_seconds, .big);
}

/// Real NAT-PMP UDP port-mapping request (RFC 6886 §3.3, opcode 1): asks the
/// gateway to map `internal_port` (requested external port 0 = gateway picks)
/// and returns the granted external port + lifetime.
pub fn probeNatPmpUdpMapping(
    io: std.Io,
    gateway: net.IpAddress,
    internal_port: u16,
    requested_external_port: u16,
    lifetime_seconds: u32,
    timeout: std.Io.Timeout,
) ProbeError!NatPmpUdpMapping {
    if (gateway != .ip4) return error.NatPmpIpv4Only;
    var gw = gateway;
    // Same explicit-port honor as probeNatPmpExternalAddress.
    if (gw.getPort() == 0) gw.setPort(nat_pmp_port);

    var request: [12]u8 = undefined;
    encodeNatPmpMappingRequest(&request, internal_port, requested_external_port, lifetime_seconds);

    var bind: net.IpAddress = .{ .ip4 = .unspecified(0) };
    const socket = try bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    const before = std.Io.Clock.Timestamp.now(io, .awake).raw.toMicroseconds();
    try socket.send(io, &gw, &request);
    var buf: [64]u8 = undefined;
    const msg = try socket.receiveTimeout(io, &buf, timeout);
    const after = std.Io.Clock.Timestamp.now(io, .awake).raw.toMicroseconds();
    if (!sameHost(msg.from, gw)) return error.UnexpectedSource;
    const parsed = try parseNatPmpUdpMappingResponse(msg.data);
    return .{
        .gateway = gw,
        .internal_port = parsed.internal_port,
        .external_port = parsed.external_port,
        .lifetime_seconds = parsed.lifetime_seconds,
        .epoch_seconds = parsed.epoch_seconds,
        .latency_us = if (after >= before) @intCast(after - before) else 0,
    };
}

/// RFC 6886 §3.4 delete notification: a mapping request with lifetime 0 and
/// suggested external port 0. Fire-and-forget, as upstream.
pub fn releaseNatPmpUdpMapping(io: std.Io, gateway: net.IpAddress, internal_port: u16) void {
    if (gateway != .ip4) return;
    var gw = gateway;
    if (gw.getPort() == 0) gw.setPort(nat_pmp_port);

    var request: [12]u8 = undefined;
    encodeNatPmpMappingRequest(&request, internal_port, 0, 0);

    var bind: net.IpAddress = .{ .ip4 = .unspecified(0) };
    const socket = bind.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch return;
    defer socket.close(io);
    socket.send(io, &gw, &request) catch {};
}

const ParsedNatPmpUdpMapping = struct {
    internal_port: u16,
    external_port: u16,
    lifetime_seconds: u32,
    epoch_seconds: u32,
};

pub fn parseNatPmpUdpMappingResponse(bytes: []const u8) ProbeError!ParsedNatPmpUdpMapping {
    if (bytes.len < 16) return error.ShortResponse;
    if (bytes[0] != 0) return error.UnsupportedVersion;
    if (bytes[1] != 129) return error.UnsupportedOpcode;
    const result = std.mem.readInt(u16, bytes[2..4], .big);
    if (result != 0) return error.GatewayRefused;
    return .{
        .epoch_seconds = std.mem.readInt(u32, bytes[4..8], .big),
        .internal_port = std.mem.readInt(u16, bytes[8..10], .big),
        .external_port = std.mem.readInt(u16, bytes[10..12], .big),
        .lifetime_seconds = std.mem.readInt(u32, bytes[12..16], .big),
    };
}

const ParsedNatPmpExternalAddress = struct {
    public_ip: [4]u8,
    epoch_seconds: u32,
};

pub fn parseNatPmpExternalAddressResponse(bytes: []const u8) ProbeError!ParsedNatPmpExternalAddress {
    if (bytes.len < 12) return error.ShortResponse;
    if (bytes[0] != 0) return error.UnsupportedVersion;
    if (bytes[1] != 128) return error.UnsupportedOpcode;
    const result = std.mem.readInt(u16, bytes[2..4], .big);
    if (result != 0) return error.GatewayRefused;
    return .{
        .epoch_seconds = std.mem.readInt(u32, bytes[4..8], .big),
        .public_ip = bytes[8..12].*,
    };
}

fn sameHost(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| std.mem.eql(u8, &a4.bytes, &b4.bytes),
            .ip6 => false,
        },
        .ip6 => |a6| switch (b) {
            .ip4 => false,
            .ip6 => |b6| std.mem.eql(u8, &a6.bytes, &b6.bytes),
        },
    };
}

fn udpRequestResponse(
    io: std.Io,
    gateway: net.IpAddress,
    request: []const u8,
    buffer: []u8,
    timeout: std.Io.Timeout,
) ProbeError![]u8 {
    if (gateway != .ip4) return error.NatPmpIpv4Only;
    var gw = gateway;
    if (gw.getPort() == 0) gw.setPort(nat_pmp_port);

    var bind: net.IpAddress = .{ .ip4 = .unspecified(0) };
    const socket = try bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    try socket.send(io, &gw, request);
    const msg = try socket.receiveTimeout(io, buffer, timeout);
    if (!sameHost(msg.from, gw)) return error.UnexpectedSource;
    return msg.data;
}

// ==========================================================================
// PCP (RFC 6887) — MAP + ANNOUNCE opcodes over the shared port 5351.
// ==========================================================================

pub const PcpMapProtocol = enum(u8) { udp = 17, tcp = 6 };

const pcp_version: u8 = 2;
pub const pcp_response_indicator: u8 = 0x80;

fn writeIpv4Mapped(dst: []u8, ip: [4]u8) void {
    @memset(dst[0..16], 0);
    dst[10] = 0xff;
    dst[11] = 0xff;
    @memcpy(dst[12..16], &ip);
}

/// PCP ANNOUNCE request: 24-byte header, lifetime 0, no opcode payload.
/// Used as the availability probe (a PCP server answers with an ANNOUNCE).
pub fn encodePcpAnnounceRequest(out: *[24]u8, local_ip: [4]u8) void {
    out[0] = pcp_version;
    out[1] = 0; // ANNOUNCE opcode
    out[2] = 0;
    out[3] = 0;
    std.mem.writeInt(u32, out[4..8], 0, .big);
    writeIpv4Mapped(out[8..24], local_ip);
}

pub const PcpMapRequestOptions = struct {
    nonce: [12]u8,
    protocol: PcpMapProtocol,
    local_ip: [4]u8,
    local_port: u16,
    preferred_external_port: u16 = 0,
    preferred_external_ip: [4]u8 = .{ 0, 0, 0, 0 },
    lifetime_seconds: u32,
};

/// PCP MAP request (RFC 6887 §11): 24-byte header + 36-byte MAP payload.
pub fn encodePcpMapRequest(out: *[60]u8, opts: PcpMapRequestOptions) void {
    out[0] = pcp_version;
    out[1] = 1; // MAP opcode
    out[2] = 0;
    out[3] = 0;
    std.mem.writeInt(u32, out[4..8], opts.lifetime_seconds, .big);
    writeIpv4Mapped(out[8..24], opts.local_ip);
    // MAP opcode-specific payload:
    @memcpy(out[24..36], &opts.nonce);
    out[36] = @intFromEnum(opts.protocol);
    out[37] = 0;
    out[38] = 0;
    out[39] = 0;
    std.mem.writeInt(u16, out[40..42], opts.local_port, .big);
    std.mem.writeInt(u16, out[42..44], opts.preferred_external_port, .big);
    writeIpv4Mapped(out[44..60], opts.preferred_external_ip);
}

pub const PcpMapData = struct {
    nonce: [12]u8,
    protocol: u8,
    local_port: u16,
    external_port: u16,
    external_ip: [4]u8,
};

pub const PcpResponse = struct {
    /// Opcode WITHOUT the response-indicator bit.
    opcode: u8,
    lifetime_seconds: u32,
    epoch_seconds: u32,
    map: ?PcpMapData,
};

pub fn parsePcpResponse(bytes: []const u8) ProbeError!PcpResponse {
    if (bytes.len < 24) return error.ShortResponse;
    if (bytes[0] != pcp_version) return error.UnsupportedVersion;
    const opcode_raw = bytes[1];
    if (opcode_raw & pcp_response_indicator == 0) return error.UnsupportedOpcode;
    const opcode = opcode_raw & ~pcp_response_indicator;
    const result = bytes[3];
    if (result == 1) return error.UnsupportedVersion; // UNSUPP_VERSION
    if (result != 0) return error.GatewayRefused;
    const lifetime = std.mem.readInt(u32, bytes[4..8], .big);
    const epoch = std.mem.readInt(u32, bytes[8..12], .big);
    if (opcode == 0) {
        return .{ .opcode = 0, .lifetime_seconds = lifetime, .epoch_seconds = epoch, .map = null };
    }
    if (opcode != 1) return error.UnsupportedOpcode;
    if (bytes.len < 24 + 36) return error.ShortResponse;
    const md = bytes[24..];
    const ext = md[20..36];
    for (ext[0..10]) |b| {
        if (b != 0) return error.UnexpectedResponse;
    }
    if (ext[10] != 0xff or ext[11] != 0xff) return error.UnexpectedResponse;
    return .{
        .opcode = 1,
        .lifetime_seconds = lifetime,
        .epoch_seconds = epoch,
        .map = .{
            .nonce = md[0..12].*,
            .protocol = md[12],
            .local_port = std.mem.readInt(u16, md[16..18], .big),
            .external_port = std.mem.readInt(u16, md[18..20], .big),
            .external_ip = ext[12..16].*,
        },
    };
}

/// PCP availability probe (upstream pcp::probe_available): an ANNOUNCE
/// request that a PCP server answers with an ANNOUNCE response.
pub fn probePcpAnnounce(
    io: std.Io,
    gateway: net.IpAddress,
    local_ip: [4]u8,
    timeout: std.Io.Timeout,
) ProbeError!void {
    var request: [24]u8 = undefined;
    encodePcpAnnounceRequest(&request, local_ip);
    var buf: [1100]u8 = undefined;
    const data = try udpRequestResponse(io, gateway, &request, &buf, timeout);
    const parsed = try parsePcpResponse(data);
    if (parsed.opcode != 0) return error.InvalidAnnounce;
}

pub const PcpUdpMapping = struct {
    nonce: [12]u8,
    external_ip: [4]u8,
    external_port: u16,
    lifetime_seconds: u32,
};

/// Create or renew a PCP UDP mapping with the supplied mapping identity.
/// RFC 6887 MAP renewal and lifetime-zero deletion must retain the original
/// nonce; only the lifecycle owner may mint a nonce for a new acquisition.
/// Validates the echoed nonce/protocol/local port and rejects a zero external
/// port, as upstream pcp::Mapping::new.
pub fn pcpMapUdp(
    io: std.Io,
    gateway: net.IpAddress,
    local_ip: [4]u8,
    local_port: u16,
    nonce: [12]u8,
    preferred_external_ip: ?[4]u8,
    preferred_external_port: u16,
    timeout: std.Io.Timeout,
) ProbeError!PcpUdpMapping {
    var request: [60]u8 = undefined;
    encodePcpMapRequest(&request, .{
        .nonce = nonce,
        .protocol = .udp,
        .local_ip = local_ip,
        .local_port = local_port,
        .preferred_external_port = preferred_external_port,
        .preferred_external_ip = preferred_external_ip orelse .{ 0, 0, 0, 0 },
        .lifetime_seconds = pcp_requested_lifetime_seconds,
    });

    var buf: [1100]u8 = undefined;
    const data = try udpRequestResponse(io, gateway, &request, &buf, timeout);
    const parsed = try parsePcpResponse(data);
    const map = parsed.map orelse return error.InvalidAnnounce;
    if (!std.mem.eql(u8, &map.nonce, &nonce)) return error.NonceMismatch;
    if (map.protocol != @intFromEnum(PcpMapProtocol.udp)) return error.ProtocolMismatch;
    if (map.local_port != local_port) return error.PortMismatch;
    if (map.external_port == 0) return error.ZeroExternalPort;
    return .{
        .nonce = nonce,
        .external_ip = map.external_ip,
        .external_port = map.external_port,
        .lifetime_seconds = parsed.lifetime_seconds,
    };
}

/// PCP delete: a MAP with the mapping's nonce and lifetime 0. Fire-and-
/// forget, as upstream pcp::Mapping::release.
pub fn releasePcpUdpMapping(
    io: std.Io,
    gateway: net.IpAddress,
    local_ip: [4]u8,
    local_port: u16,
    nonce: [12]u8,
) void {
    if (gateway != .ip4) return;
    var gw = gateway;
    if (gw.getPort() == 0) gw.setPort(pcp_port);

    var request: [60]u8 = undefined;
    encodePcpMapRequest(&request, .{
        .nonce = nonce,
        .protocol = .udp,
        .local_ip = local_ip,
        .local_port = local_port,
        .lifetime_seconds = 0,
    });

    var bind: net.IpAddress = .{ .ip4 = .unspecified(0) };
    const socket = bind.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch return;
    defer socket.close(io);
    socket.send(io, &gw, &request) catch {};
}

// ==========================================================================
// UPnP IGD — SSDP discovery + device description + SOAP/XML control.
// ==========================================================================

/// The exact SSDP M-SEARCH the igd crate puts on the wire (searching for
/// InternetGatewayDevice:1).
pub const ssdp_search_request: []const u8 =
    "M-SEARCH * HTTP/1.1\r\n" ++
    "Host:239.255.255.250:1900\r\n" ++
    "ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" ++
    "Man:\"ssdp:discover\"\r\n" ++
    "MX:3\r\n" ++
    "\r\n";

const wan_connection_services = [_][]const u8{
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
};

const wan_service_namespace = "urn:schemas-upnp-org:service:WANIPConnection:1";

// --- minimal XML extraction (UPnP control is well-formed XML; the parser
// --- matches tag LOCAL names, so namespace prefixes don't matter) ---

fn isTagDelim(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == '>' or c == '/';
}

fn tagLocalName(name: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, name, ':')) |colon| return name[colon + 1 ..];
    return name;
}

pub const XmlElement = struct {
    inner: []const u8,
    end: usize,
};

/// Find the next `<local_name>` element at or after `start` (any namespace
/// prefix, any attributes). Returns its inner text and the offset past the
/// closing tag. Comments/declarations are skipped; a non-matching tag is
/// descended into (document-order scan).
pub fn xmlFindElement(buf: []const u8, start: usize, local_name: []const u8) ?XmlElement {
    var pos = start;
    while (pos < buf.len) {
        const open = std.mem.indexOfScalarPos(u8, buf, pos, '<') orelse return null;
        if (open + 1 >= buf.len) return null;
        if (buf[open + 1] == '!' or buf[open + 1] == '?') {
            const close = std.mem.indexOfScalarPos(u8, buf, open, '>') orelse return null;
            pos = close + 1;
            continue;
        }
        if (buf[open + 1] == '/') {
            // A closing tag encountered while descending; not a match here.
            const close = std.mem.indexOfScalarPos(u8, buf, open, '>') orelse return null;
            pos = close + 1;
            continue;
        }
        var i = open + 1;
        while (i < buf.len and !isTagDelim(buf[i])) i += 1;
        const tag = buf[open + 1 .. i];
        const content_start = (std.mem.indexOfScalarPos(u8, buf, i, '>') orelse return null) + 1;
        const self_closing = content_start >= 2 and buf[content_start - 2] == '/';
        if (std.ascii.eqlIgnoreCase(tagLocalName(tag), local_name)) {
            if (self_closing) return .{ .inner = "", .end = content_start };
            var scan = content_start;
            while (scan < buf.len) {
                const lt = std.mem.indexOfScalarPos(u8, buf, scan, '<') orelse return null;
                if (lt + 1 < buf.len and buf[lt + 1] == '/') {
                    var j = lt + 2;
                    while (j < buf.len and buf[j] != '>' and !isTagDelim(buf[j])) j += 1;
                    const close_name = buf[lt + 2 .. j];
                    const gt = std.mem.indexOfScalarPos(u8, buf, j, '>') orelse return null;
                    if (std.ascii.eqlIgnoreCase(tagLocalName(close_name), local_name)) {
                        return .{ .inner = buf[content_start..lt], .end = gt + 1 };
                    }
                    scan = gt + 1;
                    continue;
                }
                const gt = std.mem.indexOfScalarPos(u8, buf, lt, '>') orelse return null;
                scan = gt + 1;
            }
            return null;
        }
        pos = content_start;
    }
    return null;
}

/// First `<local_name>` element's trimmed inner text in `buf`.
pub fn xmlElementText(buf: []const u8, local_name: []const u8) ?[]const u8 {
    const el = xmlFindElement(buf, 0, local_name) orelse return null;
    return std.mem.trim(u8, el.inner, " \t\r\n");
}

fn ssdpLocationUrl(datagram: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, datagram, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len < 9) continue;
        if (!std.ascii.eqlIgnoreCase(line[0..9], "location:")) continue;
        return std.mem.trim(u8, line[9..], " \t\r");
    }
    return null;
}

const HttpUrlParts = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

fn splitHttpUrl(url: []const u8) ProbeError!HttpUrlParts {
    const uri = std.Uri.parse(url) catch return error.InvalidUrl;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.InvalidUrl;
    const host_comp = uri.host orelse return error.InvalidUrl;
    const host = switch (host_comp) {
        .raw => |s| s,
        .percent_encoded => |s| s,
    };
    if (host.len == 0) return error.InvalidUrl;
    const path = switch (uri.path) {
        .raw => |s| s,
        .percent_encoded => |s| s,
    };
    return .{
        .host = host,
        .port = uri.port orelse 80,
        .path = if (path.len == 0) "/" else path,
    };
}

fn httpGetBody(allocator: std.mem.Allocator, io: std.Io, url: []const u8) ProbeError![]u8 {
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const result = client.fetch(.{
        .location = .{ .url = url },
        .keep_alive = false,
        .response_writer = &out.writer,
    }) catch return error.HttpFailed;
    if (result.status != .ok) return error.HttpFailed;
    return out.toOwnedSlice() catch return error.HttpFailed;
}

const SoapReply = struct {
    ok_status: bool,
    body: []u8,
};

fn httpSoapPost(
    allocator: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    soap_action: []const u8,
    body: []const u8,
) ProbeError!SoapReply {
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = body,
        .keep_alive = false,
        .headers = .{ .content_type = .{ .override = "text/xml" } },
        .extra_headers = &.{.{ .name = "SOAPAction", .value = soap_action }},
        .response_writer = &out.writer,
    }) catch return error.HttpFailed;
    return .{
        // SOAP faults arrive as HTTP 500 with an error envelope; the caller
        // parses the body either way.
        .ok_status = result.status == .ok,
        .body = out.toOwnedSlice() catch return error.HttpFailed,
    };
}

const ControlUrls = struct {
    control: []const u8,
    scpd: []const u8,
};

/// First `<service>` whose serviceType is a WAN connection service; returns
/// its controlURL + SCPDURL (slices into `desc`).
fn parseControlUrls(desc: []const u8) ?ControlUrls {
    var pos: usize = 0;
    while (xmlFindElement(desc, pos, "service")) |svc| : (pos = svc.end) {
        const st = xmlElementText(svc.inner, "serviceType") orelse continue;
        var supported = false;
        for (wan_connection_services) |urn| {
            if (std.mem.eql(u8, st, urn)) {
                supported = true;
                break;
            }
        }
        if (!supported) continue;
        const control = xmlElementText(svc.inner, "controlURL") orelse continue;
        const scpd = xmlElementText(svc.inner, "SCPDURL") orelse continue;
        if (control.len == 0 or scpd.len == 0) continue;
        return .{ .control = control, .scpd = scpd };
    }
    return null;
}

const UpnpSchema = struct {
    add_port_mapping: []const []const u8,
    add_any_port_mapping: ?[]const []const u8,
    delete_port_mapping: ?[]const []const u8,
};

fn collectInArgs(aa: std.mem.Allocator, action_inner: []const u8) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(aa);
    var pos: usize = 0;
    while (xmlFindElement(action_inner, pos, "argument")) |arg| : (pos = arg.end) {
        const dir = xmlElementText(arg.inner, "direction") orelse continue;
        if (!std.mem.eql(u8, dir, "in")) continue;
        const name = xmlElementText(arg.inner, "name") orelse continue;
        try list.append(aa, try aa.dupe(u8, name));
    }
    return try list.toOwnedSlice(aa);
}

fn parseSchema(aa: std.mem.Allocator, scpd: []const u8) ProbeError!UpnpSchema {
    var schema = UpnpSchema{
        .add_port_mapping = &.{},
        .add_any_port_mapping = null,
        .delete_port_mapping = null,
    };
    var saw_add_port_mapping = false;
    var pos: usize = 0;
    while (xmlFindElement(scpd, pos, "action")) |act| : (pos = act.end) {
        const name = xmlElementText(act.inner, "name") orelse continue;
        const args = collectInArgs(aa, act.inner) catch return error.UpnpInvalidResponse;
        if (std.mem.eql(u8, name, "AddPortMapping")) {
            schema.add_port_mapping = args;
            saw_add_port_mapping = true;
        } else if (std.mem.eql(u8, name, "AddAnyPortMapping")) {
            schema.add_any_port_mapping = args;
        } else if (std.mem.eql(u8, name, "DeletePortMapping")) {
            schema.delete_port_mapping = args;
        }
    }
    if (!saw_add_port_mapping) return error.UpnpInvalidResponse;
    return schema;
}

/// A discovered UPnP IGD (WAN connection service): everything needed to map
/// and release without re-searching. All strings are arena-owned.
pub const UpnpGateway = struct {
    arena: std.heap.ArenaAllocator,
    control_url: []const u8,
    add_port_mapping_args: []const []const u8,
    add_any_port_mapping_args: ?[]const []const u8,
    delete_port_mapping_args: ?[]const []const u8,

    pub fn deinit(self: *UpnpGateway) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn joinUrl(aa: std.mem.Allocator, base: []const u8, path: []const u8) ![]const u8 {
    if (std.ascii.startsWithIgnoreCase(path, "http://") or std.ascii.startsWithIgnoreCase(path, "https://")) {
        return try aa.dupe(u8, path);
    }
    if (path.len > 0 and path[0] == '/') {
        return try std.fmt.allocPrint(aa, "{s}{s}", .{ base, path });
    }
    return try std.fmt.allocPrint(aa, "{s}/{s}", .{ base, path });
}

/// SSDP discovery + description + SCPD fetch (upstream upnp::probe_available
/// followed by igd's gateway resolution, fused).
pub fn upnpDiscoverGateway(
    allocator: std.mem.Allocator,
    io: std.Io,
    search_target: net.IpAddress,
    budget_ms: u64,
) ProbeError!UpnpGateway {
    var bind: net.IpAddress = .{ .ip4 = .unspecified(0) };
    const socket = try bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try socket.send(io, &search_target, ssdp_search_request);

    const start_ms = nowMs(io);
    var datagram_buf: [1500]u8 = undefined;

    while (true) {
        const elapsed_ms = nowMs(io) -| start_ms;
        if (elapsed_ms >= budget_ms) break;
        const remaining_ms = budget_ms - elapsed_ms;
        const chunk_ms = @max(@min(remaining_ms, 250), 1);
        const msg = socket.receiveTimeout(io, &datagram_buf, msTimeout(chunk_ms)) catch continue;

        const loc = ssdpLocationUrl(msg.data) orelse continue;
        const parts = splitHttpUrl(loc) catch continue;

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const aa = arena.allocator();

        const base = std.fmt.allocPrint(aa, "http://{s}:{d}", .{ parts.host, parts.port }) catch {
            arena.deinit();
            continue;
        };
        const desc_url = std.fmt.allocPrint(aa, "{s}{s}", .{ base, parts.path }) catch {
            arena.deinit();
            continue;
        };
        const desc = httpGetBody(allocator, io, desc_url) catch {
            arena.deinit();
            continue;
        };
        // Copy the control/SCPD paths into the arena BEFORE freeing `desc`:
        // parseControlUrls slices point into it.
        const u = parseControlUrls(desc) orelse {
            allocator.free(desc);
            arena.deinit();
            continue;
        };
        const scpd_path = aa.dupe(u8, u.scpd) catch {
            allocator.free(desc);
            arena.deinit();
            continue;
        };
        const control_path = aa.dupe(u8, u.control) catch {
            allocator.free(desc);
            arena.deinit();
            continue;
        };
        allocator.free(desc);
        const scpd_url = joinUrl(aa, base, scpd_path) catch {
            arena.deinit();
            continue;
        };
        const scpd = httpGetBody(allocator, io, scpd_url) catch {
            arena.deinit();
            continue;
        };
        defer allocator.free(scpd);
        const schema = parseSchema(aa, scpd) catch {
            arena.deinit();
            continue;
        };
        const control_url = joinUrl(aa, base, control_path) catch {
            arena.deinit();
            continue;
        };
        return .{
            .arena = arena,
            .control_url = control_url,
            .add_port_mapping_args = schema.add_port_mapping,
            .add_any_port_mapping_args = schema.add_any_port_mapping,
            .delete_port_mapping_args = schema.delete_port_mapping,
        };
    }
    return error.UpnpDiscoveryFailed;
}

fn soapActionHeaderValue(comptime action: []const u8) []const u8 {
    return "\"" ++ wan_service_namespace ++ "#" ++ action ++ "\"";
}

/// One SOAP request. Returns ok/fault-code plus the raw response body
/// (caller frees) for response-specific fields.
const SoapResult = struct {
    ok: bool,
    fault_code: ?u16,
    /// Caller-owned copy of the response body.
    body: []u8,
};

fn dupeBody(allocator: std.mem.Allocator, body: []const u8) ProbeError![]u8 {
    return allocator.dupe(u8, body) catch return error.HttpFailed;
}

fn nowMs(io: std.Io) u64 {
    const ns = std.Io.Clock.Timestamp.now(io, .awake).raw.toNanoseconds();
    return @intCast(@divTrunc(ns, std.time.ns_per_ms));
}

fn soapEnvelopeAlloc(
    allocator: std.mem.Allocator,
    action: []const u8,
    args_xml: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\<?xml version="1.0"?>
        \\<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
        \\<s:Body>
        \\<u:{s} xmlns:u="{s}">
        \\{s}
        \\</u:{s}>
        \\</s:Body>
        \\</s:Envelope>
    , .{ action, wan_service_namespace, args_xml, action });
}

fn upnpSoapAction(
    allocator: std.mem.Allocator,
    io: std.Io,
    control_url: []const u8,
    comptime action: []const u8,
    args_xml: []const u8,
    expect_response_tag: []const u8,
) ProbeError!SoapResult {
    const envelope = soapEnvelopeAlloc(allocator, action, args_xml) catch return error.HttpFailed;
    defer allocator.free(envelope);
    const reply = try httpSoapPost(allocator, io, control_url, soapActionHeaderValue(action), envelope);
    defer allocator.free(reply.body);

    // The reply body is owned by this function's defer; a caller-facing
    // result needs its own copy regardless of the outcome.
    if (xmlFindElement(reply.body, 0, expect_response_tag) != null) {
        return .{ .ok = true, .fault_code = null, .body = try dupeBody(allocator, reply.body) };
    }
    if (xmlFindElement(reply.body, 0, "Fault") != null) {
        var code: ?u16 = null;
        if (xmlElementText(reply.body, "errorCode")) |t| {
            code = std.fmt.parseInt(u16, t, 10) catch null;
        }
        return .{ .ok = false, .fault_code = code, .body = try dupeBody(allocator, reply.body) };
    }
    return error.UpnpInvalidResponse;
}

const UpnpArgValues = struct {
    external_port: u16,
    local_ip: [4]u8,
    local_port: u16,
    lease_seconds: u32,
    description: []const u8,
};

/// Append `<Name>value</Name>` for known UPnP mapping arguments (the igd
/// crate renders schema arguments in the device's declared order and skips
/// unknown ones); returns false for an unrecognized argument name.
fn appendUpnpArg(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    name: []const u8,
    v: UpnpArgValues,
) !bool {
    var tmp: [48]u8 = undefined;
    const text: []const u8 = if (std.mem.eql(u8, name, "NewEnabled"))
        "1"
    else if (std.mem.eql(u8, name, "NewExternalPort"))
        try std.fmt.bufPrint(&tmp, "{d}", .{v.external_port})
    else if (std.mem.eql(u8, name, "NewInternalClient"))
        try std.fmt.bufPrint(&tmp, "{d}.{d}.{d}.{d}", .{ v.local_ip[0], v.local_ip[1], v.local_ip[2], v.local_ip[3] })
    else if (std.mem.eql(u8, name, "NewInternalPort"))
        try std.fmt.bufPrint(&tmp, "{d}", .{v.local_port})
    else if (std.mem.eql(u8, name, "NewLeaseDuration"))
        try std.fmt.bufPrint(&tmp, "{d}", .{v.lease_seconds})
    else if (std.mem.eql(u8, name, "NewPortMappingDescription"))
        v.description
    else if (std.mem.eql(u8, name, "NewProtocol"))
        "UDP"
    else if (std.mem.eql(u8, name, "NewRemoteHost"))
        ""
    else
        return false;
    try out.print(allocator, "<{s}>{s}</{s}>", .{ name, text, name });
    return true;
}

fn buildArgsXml(
    allocator: std.mem.Allocator,
    schema: []const []const u8,
    v: UpnpArgValues,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (schema) |name| {
        _ = try appendUpnpArg(&out, allocator, name, v);
    }
    return try out.toOwnedSlice(allocator);
}

fn randomExternalPort(io: std.Io) u16 {
    var b: [2]u8 = undefined;
    io.random(&b);
    const raw = std.mem.readInt(u16, &b, .little);
    return 32768 + raw % (65535 - 32768);
}

fn upnpGetExternalIp(
    allocator: std.mem.Allocator,
    io: std.Io,
    gateway: *const UpnpGateway,
) ProbeError![4]u8 {
    const r = try upnpSoapAction(allocator, io, gateway.control_url, "GetExternalIPAddress", "", "GetExternalIPAddressResponse");
    defer allocator.free(r.body);
    if (!r.ok) return error.UpnpFault;
    const text = xmlElementText(r.body, "NewExternalIPAddress") orelse return error.UpnpInvalidResponse;
    const addr = net.IpAddress.parse(text, 0) catch return error.UpnpInvalidResponse;
    switch (addr) {
        .ip4 => |a| return a.bytes,
        .ip6 => return error.NotIpv4,
    }
}

fn upnpDeleteArgsXml(
    allocator: std.mem.Allocator,
    schema: []const []const u8,
    external_port: u16,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (schema) |name| {
        var tmp: [16]u8 = undefined;
        const text: []const u8 = if (std.mem.eql(u8, name, "NewExternalPort"))
            try std.fmt.bufPrint(&tmp, "{d}", .{external_port})
        else if (std.mem.eql(u8, name, "NewProtocol"))
            "UDP"
        else if (std.mem.eql(u8, name, "NewRemoteHost"))
            ""
        else
            continue;
        try out.print(allocator, "<{s}>{s}</{s}>", .{ name, text, name });
    }
    return try out.toOwnedSlice(allocator);
}

pub const UpnpMapping = struct {
    /// Owned; released with the mapping (DeletePortMapping) at release time.
    gateway: UpnpGateway,
    external_ip: [4]u8,
    external_port: u16,
};

pub const UpnpMapOptions = struct {
    search_target: net.IpAddress,
    local_ip: [4]u8,
    local_port: u16,
    preferred_external_port: u16 = 0,
    budget_ms: u64 = upnp_search_timeout_ms,
};

/// Create a UPnP IGD mapping (upstream upnp::Mapping::new): discover a
/// gateway (unless one is passed in — ownership transfers either way),
/// GetExternalIPAddress, then AddPortMapping with the preferred external
/// port when provided, else the AddAnyPortMapping / random-port retry
/// machinery from the igd crate.
pub fn upnpMap(
    allocator: std.mem.Allocator,
    io: std.Io,
    opts: UpnpMapOptions,
    discovered: ?UpnpGateway,
) ProbeError!UpnpMapping {
    var gw = discovered orelse try upnpDiscoverGateway(allocator, io, opts.search_target, opts.budget_ms);
    errdefer if (discovered == null) gw.deinit();

    const external_ip = try upnpGetExternalIp(allocator, io, &gw);
    const values = UpnpArgValues{
        .external_port = undefined,
        .local_ip = opts.local_ip,
        .local_port = opts.local_port,
        .lease_seconds = upnp_lease_duration_seconds,
        .description = upnp_mapping_description,
    };

    if (opts.preferred_external_port != 0) {
        var v = values;
        v.external_port = opts.preferred_external_port;
        const args = buildArgsXml(allocator, gw.add_port_mapping_args, v) catch return error.HttpFailed;
        defer allocator.free(args);
        const r = upnpSoapAction(allocator, io, gw.control_url, "AddPortMapping", args, "AddPortMappingResponse") catch |err| {
            if (discovered == null) gw.deinit();
            return err;
        };
        defer allocator.free(r.body);
        if (r.ok) {
            return .{ .gateway = gw, .external_ip = external_ip, .external_port = opts.preferred_external_port };
        }
        // fall through to any-port, as igd does
    }

    if (gw.add_any_port_mapping_args) |schema| {
        var v = values;
        v.external_port = randomExternalPort(io);
        const args = buildArgsXml(allocator, schema, v) catch return error.HttpFailed;
        defer allocator.free(args);
        const r = upnpSoapAction(allocator, io, gw.control_url, "AddAnyPortMapping", args, "AddAnyPortMappingResponse") catch |err| {
            if (discovered == null) gw.deinit();
            return err;
        };
        defer allocator.free(r.body);
        if (!r.ok) {
            if (r.fault_code != null and r.fault_code.? == 728) return error.UpnpNoPorts;
            return error.UpnpFault;
        }
        const port_text = xmlElementText(r.body, "NewReservedPort") orelse return error.UpnpInvalidResponse;
        const port = std.fmt.parseInt(u16, port_text, 10) catch return error.UpnpInvalidResponse;
        if (port == 0) return error.ZeroExternalPort;
        return .{ .gateway = gw, .external_ip = external_ip, .external_port = port };
    }

    // No AddAnyPortMapping on this device: AddPortMapping with random ports
    // (retry on 718 ConflictInMappingEntry; 724 → retry once with identical
    // internal/external ports), up to 20 attempts — the igd crate's fallback.
    var attempts: u8 = 0;
    while (attempts < 20) : (attempts += 1) {
        var v = values;
        v.external_port = randomExternalPort(io);
        const args = buildArgsXml(allocator, gw.add_port_mapping_args, v) catch return error.HttpFailed;
        defer allocator.free(args);
        const r = upnpSoapAction(allocator, io, gw.control_url, "AddPortMapping", args, "AddPortMappingResponse") catch |err| {
            if (discovered == null) gw.deinit();
            return err;
        };
        defer allocator.free(r.body);
        if (r.ok) {
            return .{ .gateway = gw, .external_ip = external_ip, .external_port = v.external_port };
        }
        if (r.fault_code) |code| {
            if (code == 718) continue; // conflict → new random port
            if (code == 724) {
                // SamePortValuesRequired → once with internal as external.
                var sv = values;
                sv.external_port = opts.local_port;
                const sargs = buildArgsXml(allocator, gw.add_port_mapping_args, sv) catch return error.HttpFailed;
                defer allocator.free(sargs);
                const sr = upnpSoapAction(allocator, io, gw.control_url, "AddPortMapping", sargs, "AddPortMappingResponse") catch |err| {
                    if (discovered == null) gw.deinit();
                    return err;
                };
                defer allocator.free(sr.body);
                if (sr.ok) {
                    return .{ .gateway = gw, .external_ip = external_ip, .external_port = opts.local_port };
                }
                return error.UpnpFault;
            }
        }
        return error.UpnpFault;
    }
    return error.UpnpNoPorts;
}

/// DeletePortMapping — best-effort (release is a notification path).
pub fn upnpRelease(
    allocator: std.mem.Allocator,
    io: std.Io,
    gateway: *const UpnpGateway,
    external_port: u16,
) void {
    const schema = gateway.delete_port_mapping_args orelse return;
    const args = upnpDeleteArgsXml(allocator, schema, external_port) catch return;
    defer allocator.free(args);
    const r = upnpSoapAction(allocator, io, gateway.control_url, "DeletePortMapping", args, "DeletePortMappingResponse") catch return;
    allocator.free(r.body);
}

fn ssdpDefaultTargetAddress() net.IpAddress {
    return net.IpAddress.parse(ssdp_default_target[0..ssdp_default_target.len], 0) catch unreachable;
}

// ==========================================================================
// Client — the mapping lifecycle: probe ALL protocols, map with the best
// that answers, renew at half the granted lifetime, delete on release.
// ==========================================================================

pub const MappingProtocol = enum { nat_pmp, pcp, upnp };

pub const ProbeOutput = struct {
    upnp: bool = false,
    pcp: bool = false,
    nat_pmp: bool = false,
};

pub const ExternalAddr = struct {
    ip: [4]u8,
    port: u16,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// NAT-PMP/PCP gateway (the established env/option seam).
    gateway: net.IpAddress,
    local_ip: [4]u8,
    local_port: u16,
    /// SSDP search target; null → the standard 239.255.255.250:1900
    /// multicast. An explicit target is the hermetic test seam.
    upnp_search_target: ?net.IpAddress = null,
    recv_timeout_ms: u64 = pcp_recv_timeout_ms,
    upnp_search_budget_ms: u64 = upnp_search_timeout_ms,
    renew_backoff_ms: u64 = renew_failure_backoff_ms,

    mu: std.Io.Mutex = .init,
    published: ?ExternalAddr = null,
    mapping: ?ActiveMapping = null,

    probe_result: ProbeOutput = .{},
    probe_upnp_gateway: ?UpnpGateway = null,

    group: std.Io.Group = .init,
    stop_requested: std.atomic.Value(bool) = .init(false),
    loop_running: bool = false,
    released: bool = false,

    pub const ActiveMapping = struct {
        protocol: MappingProtocol,
        external_ip: [4]u8,
        external_port: u16,
        lifetime_seconds: u32,
        pcp_nonce: [12]u8 = .{0} ** 12,
        upnp_gateway: ?UpnpGateway = null,

        fn halfLifetimeMs(self: *const ActiveMapping) u64 {
            if (self.protocol == .upnp) return upnp_half_lifetime_ms;
            return @as(u64, self.lifetime_seconds) * 500;
        }
    };

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        gateway: net.IpAddress,
        local_ip: [4]u8,
        local_port: u16,
    ) Client {
        return .{
            .allocator = allocator,
            .io = io,
            .gateway = gateway,
            .local_ip = local_ip,
            .local_port = local_port,
        };
    }

    /// Probe all three protocols and map with the best that answers:
    /// available-first (PCP, then NAT-PMP, then UPnP — upstream priority),
    /// with the remaining protocols as fallback attempts (a mapping attempt
    /// that fails falls through to the next protocol rather than waiting
    /// for an outside re-procure).
    pub fn acquire(self: *Client) ProbeError!ExternalAddr {
        self.mu.lockUncancelable(self.io);
        const already = self.released;
        self.mu.unlock(self.io);
        if (already) return error.AlreadyReleased;

        self.probeAll();

        const order = self.candidateOrder();
        var last_err: ProbeError = error.AllProtocolsFailed;
        var len: usize = 0;
        const list = order.list;
        len = order.len;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            const m = self.attempt(list[i], null, null) catch |err| {
                last_err = err;
                continue;
            };
            self.mu.lockUncancelable(self.io);
            if (self.released) {
                self.mu.unlock(self.io);
                var mm = m;
                freeMappingResources(&mm);
                return error.AlreadyReleased;
            }
            self.setMappingLocked(m);
            self.startLoopLocked();
            const ext = ExternalAddr{ .ip = m.external_ip, .port = m.external_port };
            self.mu.unlock(self.io);
            return ext;
        }
        return last_err;
    }

    /// The observed external address (lock-free-ish read under the client
    /// mutex); null when nothing is currently mapped/published.
    pub fn externalAddress(self: *Client) ?ExternalAddr {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.published;
    }

    /// Stop the renewal loop, delete the mapping on the gateway (protocol-
    /// specific), and clear the published address. Idempotent.
    pub fn release(self: *Client) void {
        self.mu.lockUncancelable(self.io);
        if (self.released) {
            self.mu.unlock(self.io);
            return;
        }
        self.released = true;
        self.stop_requested.store(true, .release);
        const was_loop = self.loop_running;
        self.loop_running = false;
        const m_opt = self.mapping;
        self.mapping = null;
        self.published = null;
        var probe_gw_opt = self.probe_upnp_gateway;
        self.probe_upnp_gateway = null;
        self.mu.unlock(self.io);

        if (was_loop) self.group.cancel(self.io);

        if (m_opt) |m| {
            var mm = m;
            defer freeMappingResources(&mm);
            switch (m.protocol) {
                .nat_pmp => releaseNatPmpUdpMapping(self.io, self.gateway, self.local_port),
                .pcp => releasePcpUdpMapping(self.io, self.gateway, self.local_ip, self.local_port, m.pcp_nonce),
                .upnp => if (mm.upnp_gateway) |*g| upnpRelease(self.allocator, self.io, g, m.external_port),
            }
        }
        if (probe_gw_opt) |*g| g.deinit();
    }

    // ------- internals -------

    fn probeAll(self: *Client) void {
        const t = msTimeout(self.recv_timeout_ms);
        var result = ProbeOutput{};
        result.nat_pmp = blk: {
            _ = probeNatPmpExternalAddress(self.io, self.gateway, t) catch break :blk false;
            break :blk true;
        };
        result.pcp = blk: {
            probePcpAnnounce(self.io, self.gateway, self.local_ip, t) catch break :blk false;
            break :blk true;
        };

        const target = self.upnp_search_target orelse ssdpDefaultTargetAddress();
        const discovered = upnpDiscoverGateway(self.allocator, self.io, target, self.upnp_search_budget_ms) catch null;
        result.upnp = discovered != null;

        self.mu.lockUncancelable(self.io);
        if (self.probe_upnp_gateway) |*g| g.deinit();
        self.probe_upnp_gateway = discovered;
        self.probe_result = result;
        self.mu.unlock(self.io);
    }

    /// Availability-first order (upstream preference PCP > NAT-PMP > UPnP)
    /// with the remaining protocols appended as fallback attempts. With no
    /// probe signal at all: UPnP first (its discovery is gateway-less),
    /// then PCP, then NAT-PMP.
    fn candidateOrder(self: *Client) struct { list: [3]MappingProtocol, len: usize } {
        var list: [3]MappingProtocol = undefined;
        var n: usize = 0;
        const add = struct {
            fn f(l: *[3]MappingProtocol, count: *usize, p: MappingProtocol) void {
                for (l[0..count.*]) |existing| {
                    if (existing == p) return;
                }
                l[count.*] = p;
                count.* += 1;
            }
        }.f;

        self.mu.lockUncancelable(self.io);
        const probe = self.probe_result;
        self.mu.unlock(self.io);

        if (probe.pcp) add(&list, &n, .pcp);
        if (probe.nat_pmp) add(&list, &n, .nat_pmp);
        add(&list, &n, .upnp); // enable_upnp is default-true upstream: always eligible
        add(&list, &n, .pcp);
        add(&list, &n, .nat_pmp);
        return .{ .list = list, .len = n };
    }

    /// Attempt one mapping protocol. A PCP nonce is supplied only for a
    /// renewal; initial procurement and post-loss reacquisition pass null and
    /// mint a new mapping identity here at the lifecycle boundary.
    fn attempt(
        self: *Client,
        protocol: MappingProtocol,
        preferred: ?ExternalAddr,
        renewal_pcp_nonce: ?[12]u8,
    ) ProbeError!ActiveMapping {
        const t = msTimeout(self.recv_timeout_ms);
        switch (protocol) {
            .pcp => {
                var minted_nonce: [12]u8 = undefined;
                const nonce = renewal_pcp_nonce orelse blk: {
                    self.io.random(&minted_nonce);
                    break :blk minted_nonce;
                };
                const m = try pcpMapUdp(
                    self.io,
                    self.gateway,
                    self.local_ip,
                    self.local_port,
                    nonce,
                    if (preferred) |p| p.ip else null,
                    if (preferred) |p| p.port else 0,
                    t,
                );
                return .{
                    .protocol = .pcp,
                    .external_ip = m.external_ip,
                    .external_port = m.external_port,
                    .lifetime_seconds = m.lifetime_seconds,
                    // Preserve the active mapping identity on renewal rather
                    // than accepting a newly generated request nonce.
                    .pcp_nonce = nonce,
                };
            },
            .nat_pmp => {
                const suggested: u16 = if (preferred) |p| p.port else 0;
                const m = try probeNatPmpUdpMapping(
                    self.io,
                    self.gateway,
                    self.local_port,
                    suggested,
                    nat_pmp_requested_lifetime_seconds,
                    t,
                );
                if (m.internal_port != self.local_port) return error.PortMismatch;
                if (m.external_port == 0) return error.ZeroExternalPort;
                const ext = try probeNatPmpExternalAddress(self.io, self.gateway, t);
                return .{
                    .protocol = .nat_pmp,
                    .external_ip = ext.public_ip,
                    .external_port = m.external_port,
                    .lifetime_seconds = m.lifetime_seconds,
                };
            },
            .upnp => {
                self.mu.lockUncancelable(self.io);
                const cached = self.probe_upnp_gateway;
                self.probe_upnp_gateway = null;
                self.mu.unlock(self.io);

                const target = self.upnp_search_target orelse ssdpDefaultTargetAddress();
                const m = upnpMap(self.allocator, self.io, .{
                    .search_target = target,
                    .local_ip = self.local_ip,
                    .local_port = self.local_port,
                    .preferred_external_port = if (preferred) |p| p.port else 0,
                    .budget_ms = self.upnp_search_budget_ms,
                }, cached) catch |err| {
                    if (cached) |c| {
                        var owned = c;
                        owned.deinit();
                    }
                    return err;
                };
                return .{
                    .protocol = .upnp,
                    .external_ip = m.external_ip,
                    .external_port = m.external_port,
                    .lifetime_seconds = upnp_lease_duration_seconds,
                    .upnp_gateway = m.gateway,
                };
            },
        }
    }

    fn attemptAny(self: *Client, preferred: ?ExternalAddr) ?ActiveMapping {
        const order = self.candidateOrder();
        var i: usize = 0;
        while (i < order.len) : (i += 1) {
            const m = self.attempt(order.list[i], preferred, null) catch continue;
            return m;
        }
        return null;
    }

    /// Set `self.mapping` (caller holds `mu`), publishing the external
    /// address. Frees any replaced mapping's owned resources.
    fn setMappingLocked(self: *Client, m: ActiveMapping) void {
        if (self.mapping) |*old| freeMappingResources(old);
        self.mapping = m;
        self.published = .{ .ip = m.external_ip, .port = m.external_port };
    }

    fn startLoopLocked(self: *Client) void {
        if (self.loop_running) return;
        self.stop_requested.store(false, .release);
        self.group.async(self.io, runLoop, .{self});
        self.loop_running = true;
    }

    fn freeMappingResources(m: *ActiveMapping) void {
        if (m.upnp_gateway) |*g| g.deinit();
        m.upnp_gateway = null;
    }

    fn sleepInterruptible(self: *Client, ms_value: u64) bool {
        msTimeout(ms_value).sleep(self.io) catch return false;
        return true;
    }

    /// Renewal loop (upstream CurrentMapping/Service semantics): renew at
    /// half the granted lifetime (suggesting the current external so the
    /// gateway keeps the port); a failed renewal holds until the full
    /// lifetime, then clears the published address and re-acquires (with a
    /// backoff retry until success — a hardening superset of upstream,
    /// which waits for an external procure).
    fn runLoop(self: *Client) void {
        while (!self.stop_requested.load(.acquire)) {
            var current: ActiveMapping = undefined;
            var half_ms: u64 = undefined;
            var current_ext: ExternalAddr = undefined;
            {
                self.mu.lockUncancelable(self.io);
                current = self.mapping orelse {
                    self.mu.unlock(self.io);
                    return;
                };
                half_ms = current.halfLifetimeMs();
                current_ext = .{ .ip = current.external_ip, .port = current.external_port };
                self.mu.unlock(self.io);
            }

            if (!self.sleepInterruptible(half_ms)) return;
            if (self.stop_requested.load(.acquire)) return;

            // Renewal stays on the active protocol and suggests the active
            // external address. PCP's stored MAP nonce is the mapping
            // identity, so it is passed verbatim instead of minting a nonce.
            // Network I/O runs cancel-blocked: canceling mid-request leaves
            // the socket in a state its close cannot clean up (observed
            // panic); the sleeps above are the loop's cancellation points.
            const prev_prot = self.io.swapCancelProtection(.blocked);
            const renewal = self.attempt(
                current.protocol,
                current_ext,
                if (current.protocol == .pcp) current.pcp_nonce else null,
            ) catch null;
            _ = self.io.swapCancelProtection(prev_prot);
            if (renewal) |new_m| {
                self.mu.lockUncancelable(self.io);
                if (self.released) {
                    self.mu.unlock(self.io);
                    var mm = new_m;
                    freeMappingResources(&mm);
                    return;
                }
                self.setMappingLocked(new_m);
                self.mu.unlock(self.io);
                continue;
            }
            // (renewal failed — expire path below)

            // Renewal failed: the mapping is still assumed valid until its
            // full lifetime (upstream Expired event).
            if (!self.sleepInterruptible(half_ms)) return;
            if (self.stop_requested.load(.acquire)) return;

            self.mu.lockUncancelable(self.io);
            self.published = null;
            self.mu.unlock(self.io);

            var reacquired = false;
            while (!self.stop_requested.load(.acquire) and !reacquired) {
                const prev_prot2 = self.io.swapCancelProtection(.blocked);
                const reattempt = self.attemptAny(current_ext);
                _ = self.io.swapCancelProtection(prev_prot2);
                if (reattempt) |new_m| {
                    self.mu.lockUncancelable(self.io);
                    if (self.released) {
                        self.mu.unlock(self.io);
                        var mm = new_m;
                        freeMappingResources(&mm);
                        return;
                    }
                    if (self.mapping) |*old| freeMappingResources(old);
                    self.mapping = new_m;
                    self.published = .{ .ip = new_m.external_ip, .port = new_m.external_port };
                    self.mu.unlock(self.io);
                    reacquired = true;
                } else if (!self.sleepInterruptible(self.renew_backoff_ms)) {
                    return;
                }
            }
        }
    }
};

// ==========================================================================
// Tests
// ==========================================================================

test "NAT-PMP external address request is the real two-byte opcode" {
    try std.testing.expectEqualSlices(u8, &.{ 0, 0 }, &NatPmpExternalAddressRequest);
}

test "NAT-PMP external address response parser accepts success response" {
    const parsed = try parseNatPmpExternalAddressResponse(&.{
        0,   128,
        0,   0,
        0,   0,
        0,   7,
        203, 0,
        113, 9,
    });
    try std.testing.expectEqual(@as(u32, 7), parsed.epoch_seconds);
    try std.testing.expectEqualSlices(u8, &.{ 203, 0, 113, 9 }, &parsed.public_ip);
}

test "NAT-PMP UDP mapping response parser accepts success response" {
    const parsed = try parseNatPmpUdpMappingResponse(&.{
        0, 129,
        0, 0,
        0, 0,
        0, 9,
        0x1F, 0x90, // internal 8080
        0x9C, 0x40, // external 40000
        0,    0,
        0,    60,
    });
    try std.testing.expectEqual(@as(u16, 8080), parsed.internal_port);
    try std.testing.expectEqual(@as(u16, 40000), parsed.external_port);
    try std.testing.expectEqual(@as(u32, 60), parsed.lifetime_seconds);
    try std.testing.expectError(
        error.UnsupportedOpcode,
        parseNatPmpUdpMappingResponse(&.{ 0, 128, 0, 0, 0, 0, 0, 9, 0x1F, 0x90, 0x9C, 0x40, 0, 0, 0, 60 }),
    );
}

// Real wire exercising over loopback UDP sockets: a responder speaking the
// real NAT-PMP wire format answers the external-address and UDP-mapping
// probes; the probes must parse what a real gateway would send. A probe that
// skipped the network or hardcoded the answer fails here.
test "NAT-PMP probes complete against a real loopback responder" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Responder = struct {
        io: std.Io,
        socket: net.Socket,
        stopped: std.atomic.Value(bool) = .init(false),
        saw_external_request: std.atomic.Value(bool) = .init(false),
        saw_mapping_request: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            defer self.socket.close(self.io);
            var buf: [64]u8 = undefined;
            while (!self.stopped.load(.acquire)) {
                const msg = self.socket.receiveTimeout(self.io, &buf, .{
                    .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake },
                }) catch continue;
                if (msg.data.len >= 2 and msg.data[0] == 0 and msg.data[1] == 0) {
                    _ = self.saw_external_request.swap(true, .acq_rel);
                    var resp: [12]u8 = .{ 0, 128, 0, 0, 0, 0, 0, 42, 203, 0, 113, 7 };
                    self.socket.send(self.io, &msg.from, &resp) catch {};
                } else if (msg.data.len >= 12 and msg.data[0] == 0 and msg.data[1] == 1) {
                    _ = self.saw_mapping_request.swap(true, .acq_rel);
                    var resp: [16]u8 = undefined;
                    resp[0] = 0;
                    resp[1] = 129;
                    @memset(resp[2..4], 0);
                    std.mem.writeInt(u32, resp[4..8], 42, .big); // epoch
                    @memcpy(resp[8..10], msg.data[4..6]); // echo internal port
                    std.mem.writeInt(u16, resp[10..12], 40000, .big);
                    std.mem.writeInt(u32, resp[12..16], 60, .big);
                    self.socket.send(self.io, &msg.from, &resp) catch {};
                }
            }
        }
    };

    // The responder socket is bound by the MAIN thread on an ephemeral port
    // before the thread spawns: a fixed 5351 bind races other tests'
    // responders under the parallel runner, and a thread-side bind races the
    // first probe request (single shot, lost packet → timeout).
    var responder_bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const responder_socket = try responder_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });

    var responder: Responder = .{ .io = io, .socket = responder_socket };
    const thread = try std.Thread.spawn(.{}, Responder.run, .{&responder});
    defer {
        responder.stopped.store(true, .release);
        thread.join();
    }

    const gateway = net.IpAddress{ .ip4 = .loopback(responder_socket.address.getPort()) };
    const timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(2), .clock = .awake } };

    const ext = try probeNatPmpExternalAddress(io, gateway, timeout);
    try std.testing.expectEqualSlices(u8, &.{ 203, 0, 113, 7 }, &ext.public_ip);
    try std.testing.expectEqual(@as(u32, 42), ext.epoch_seconds);

    const mapping = try probeNatPmpUdpMapping(io, gateway, 5361, 0, 60, timeout);
    try std.testing.expectEqual(@as(u16, 5361), mapping.internal_port);
    try std.testing.expectEqual(@as(u16, 40000), mapping.external_port);
    try std.testing.expectEqual(@as(u32, 60), mapping.lifetime_seconds);

    try std.testing.expect(responder.saw_external_request.load(.acquire));
    try std.testing.expect(responder.saw_mapping_request.load(.acquire));
}

test "NAT-PMP release encodes the RFC 6886 §3.4 delete request" {
    var req: [12]u8 = undefined;
    encodeNatPmpMappingRequest(&req, 8080, 0, 0);
    try std.testing.expectEqualSlices(u8, &.{
        0, 1, // version 0, UDP mapping opcode
        0, 0, // reserved
        0x1F, 0x90, // internal 8080
        0, 0, // suggested external MUST be 0 on delete
        0, 0,
        0, 0, // lifetime 0 = delete
    }, &req);
}

test "PCP ANNOUNCE request is the RFC 6887 header with IPv4-mapped client" {
    var req: [24]u8 = undefined;
    encodePcpAnnounceRequest(&req, .{ 192, 168, 1, 50 });
    var expected: [24]u8 = .{
        2, 0, // version 2, ANNOUNCE opcode
        0, 0, // reserved
        0, 0,
        0,    0, // lifetime 0
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0,    0,
        0xff, 0xff,
        192,  168,
        1,    50,
    };
    try std.testing.expectEqualSlices(u8, &expected, &req);
}

test "PCP MAP request is the RFC 6887 header + 36-byte MAP payload" {
    var req: [60]u8 = undefined;
    encodePcpMapRequest(&req, .{
        .nonce = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 },
        .protocol = .udp,
        .local_ip = .{ 192, 168, 1, 50 },
        .local_port = 5361,
        .preferred_external_port = 0,
        .lifetime_seconds = 3600,
    });
    try std.testing.expectEqual(@as(u8, 2), req[0]); // version
    try std.testing.expectEqual(@as(u8, 1), req[1]); // MAP opcode
    try std.testing.expectEqual(@as(u32, 3600), std.mem.readInt(u32, req[4..8], .big));
    // client ip is IPv4-mapped
    try std.testing.expectEqual(@as(u8, 0xff), req[18]);
    try std.testing.expectEqual(@as(u8, 0xff), req[19]);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 50 }, req[20..24]);
    // MAP payload
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }, req[24..36]);
    try std.testing.expectEqual(@as(u8, 17), req[36]); // UDP protocol number
    try std.testing.expectEqual(@as(u16, 5361), std.mem.readInt(u16, req[40..42], .big));
}

test "PCP response parser accepts ANNOUNCE and MAP, rejects errors" {
    // ANNOUNCE response (24 bytes): version 2, R|0, result 0.
    // 24-byte response header: [0]=ver [1]=R|ANNOUNCE [2]=reserved
    // [3]=result [4..8]=lifetime [8..12]=epoch [12..24]=reserved.
    var announce: [24]u8 = undefined;
    announce[0] = 2;
    announce[1] = 128; // R|ANNOUNCE
    announce[2] = 0;
    announce[3] = 0; // success
    std.mem.writeInt(u32, announce[4..8], 0, .big); // lifetime
    std.mem.writeInt(u32, announce[8..12], 7, .big); // epoch
    @memset(announce[12..24], 0);
    const parsed_announce = try parsePcpResponse(&announce);
    try std.testing.expectEqual(@as(u8, 0), parsed_announce.opcode);
    try std.testing.expect(parsed_announce.map == null);

    // MAP response: header + 36-byte MAP payload.
    var map_resp: [60]u8 = undefined;
    @memset(&map_resp, 0);
    map_resp[0] = 2;
    map_resp[1] = 129; // R|MAP
    map_resp[3] = 0; // success
    std.mem.writeInt(u32, map_resp[4..8], 3600, .big); // lifetime
    std.mem.writeInt(u32, map_resp[8..12], 7, .big); // epoch
    @memcpy(map_resp[24..36], &[12]u8{ 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9 }); // nonce
    map_resp[36] = 17; // UDP
    std.mem.writeInt(u16, map_resp[40..42], 5361, .big); // internal
    std.mem.writeInt(u16, map_resp[42..44], 40001, .big); // external
    map_resp[54] = 0xff;
    map_resp[55] = 0xff;
    @memcpy(map_resp[56..60], &[4]u8{ 198, 51, 100, 9 });
    const parsed_map = try parsePcpResponse(&map_resp);
    try std.testing.expectEqual(@as(u8, 1), parsed_map.opcode);
    const m = parsed_map.map.?;
    try std.testing.expectEqual(@as(u16, 5361), m.local_port);
    try std.testing.expectEqual(@as(u16, 40001), m.external_port);
    try std.testing.expectEqualSlices(u8, &.{ 198, 51, 100, 9 }, &m.external_ip);

    // Non-zero result code → refused.
    var refused = map_resp;
    refused[3] = 2;
    try std.testing.expectError(error.GatewayRefused, parsePcpResponse(&refused));
    // UNSUPP_VERSION (1) maps to UnsupportedVersion.
    refused[3] = 1;
    try std.testing.expectError(error.UnsupportedVersion, parsePcpResponse(&refused));
    // Missing response indicator → not a response.
    var notresp = map_resp;
    notresp[1] = 1;
    try std.testing.expectError(error.UnsupportedOpcode, parsePcpResponse(&notresp));
}

test "SSDP M-SEARCH request matches the igd discovery bytes" {
    try std.testing.expectEqualStrings(
        "M-SEARCH * HTTP/1.1\r\n" ++
            "Host:239.255.255.250:1900\r\n" ++
            "ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" ++
            "Man:\"ssdp:discover\"\r\n" ++
            "MX:3\r\n" ++
            "\r\n",
        ssdp_search_request,
    );
}

test "XML element finder matches local names across namespace prefixes" {
    const doc =
        \\<?xml version="1.0"?>
        \\<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
        \\<s:Body>
        \\<u:AddPortMappingResponse xmlns:u="urn:foo">
        \\</u:AddPortMappingResponse>
        \\</s:Body>
        \\</s:Envelope>
    ;
    try std.testing.expect(xmlFindElement(doc, 0, "Envelope") != null);
    try std.testing.expect(xmlFindElement(doc, 0, "Body") != null);
    try std.testing.expect(xmlFindElement(doc, 0, "AddPortMappingResponse") != null);
    try std.testing.expect(xmlFindElement(doc, 0, "Missing") == null);
}

test "SSDP LOCATION parser extracts the device description URL" {
    const datagram = "HTTP/1.1 200 OK\r\n" ++
        "CACHE-CONTROL: max-age=1800\r\n" ++
        "EXT:\r\n" ++
        "LOCATION: http://192.0.2.1:49152/rootDesc.xml\r\n" ++
        "SERVER: Linux/3.4 UPnP/1.0\r\n" ++
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" ++
        "\r\n";
    const loc = ssdpLocationUrl(datagram).?;
    try std.testing.expectEqualStrings("http://192.0.2.1:49152/rootDesc.xml", loc);
    const parts = try splitHttpUrl(loc);
    try std.testing.expectEqualStrings("192.168.1.1", parts.host);
    try std.testing.expectEqual(@as(u16, 49152), parts.port);
    try std.testing.expectEqualStrings("/rootDesc.xml", parts.path);
}

test "control URL parser finds the WAN connection service" {
    const desc =
        \\<root>
        \\<device>
        \\<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
        \\<serviceList>
        \\<service>
        \\<serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
        \\<controlURL>/ctl/Common</controlURL>
        \\<SCPDURL>/scpd/Common.xml</SCPDURL>
        \\</service>
        \\<service>
        \\<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        \\<controlURL>/ctl/IPConn</controlURL>
        \\<SCPDURL>/scpd/IPConn.xml</SCPDURL>
        \\</service>
        \\</serviceList>
        \\</device>
        \\</root>
    ;
    const urls = parseControlUrls(desc).?;
    try std.testing.expectEqualStrings("/ctl/IPConn", urls.control);
    try std.testing.expectEqualStrings("/scpd/IPConn.xml", urls.scpd);
}

test "schema parser extracts in-arguments per action" {
    const scpd =
        \\<scpd xmlns="urn:schemas-upnp-org:service-1-0">
        \\<actionList>
        \\<action>
        \\<name>AddPortMapping</name>
        \\<argumentList>
        \\<argument><name>NewRemoteHost</name><direction>in</direction></argument>
        \\<argument><name>NewExternalPort</name><direction>in</direction></argument>
        \\<argument><name>NewProtocol</name><direction>in</direction></argument>
        \\<argument><name>NewInternalPort</name><direction>in</direction></argument>
        \\<argument><name>NewInternalClient</name><direction>in</direction></argument>
        \\<argument><name>NewEnabled</name><direction>in</direction></argument>
        \\<argument><name>NewPortMappingDescription</name><direction>in</direction></argument>
        \\<argument><name>NewLeaseDuration</name><direction>in</direction></argument>
        \\</argumentList>
        \\</action>
        \\<action>
        \\<name>DeletePortMapping</name>
        \\<argumentList>
        \\<argument><name>NewRemoteHost</name><direction>in</direction></argument>
        \\<argument><name>NewExternalPort</name><direction>in</direction></argument>
        \\<argument><name>NewProtocol</name><direction>in</direction></argument>
        \\</argumentList>
        \\</action>
        \\</actionList>
        \\</scpd>
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const schema = try parseSchema(arena.allocator(), scpd);
    try std.testing.expectEqual(@as(usize, 8), schema.add_port_mapping.len);
    try std.testing.expectEqualStrings("NewRemoteHost", schema.add_port_mapping[0]);
    try std.testing.expectEqualStrings("NewLeaseDuration", schema.add_port_mapping[7]);
    try std.testing.expect(schema.add_any_port_mapping == null);
    try std.testing.expectEqual(@as(usize, 3), schema.delete_port_mapping.?.len);
}

test "SOAP fault errorCode is surfaced" {
    const fault_body =
        \\<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
        \\<s:Body>
        \\<s:Fault>
        \\<faultcode>s:Client</faultcode>
        \\<faultstring>UPnPError</faultstring>
        \\<detail>
        \\<UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
        \\<errorCode>718</errorCode>
        \\<errorDescription>ConflictInMappingEntry</errorDescription>
        \\</UPnPError>
        \\</detail>
        \\</s:Fault>
        \\</s:Body>
        \\</s:Envelope>
    ;
    try std.testing.expect(xmlFindElement(fault_body, 0, "Fault") != null);
    const code_text = xmlElementText(fault_body, "errorCode").?;
    try std.testing.expectEqual(@as(u16, 718), try std.fmt.parseInt(u16, code_text, 10));
}

// --- PCP loopback responder: speaks the real RFC 6887 wire. ---
const PcpResponder = struct {
    io: std.Io,
    socket: net.Socket,
    stopped: std.atomic.Value(bool) = .init(false),
    saw_announce: std.atomic.Value(bool) = .init(false),
    saw_delete: std.atomic.Value(bool) = .init(false),
    map_count: std.atomic.Value(u32) = .init(0),
    last_suggested_external: std.atomic.Value(u16) = .init(0),
    /// Captured from the first non-zero-lifetime MAP. The responder owns this
    /// field; tests read the atomically-published equality results below.
    initial_map_nonce: [12]u8 = undefined,
    renewal_nonce_matches_initial: std.atomic.Value(bool) = .init(false),
    release_nonce_matches_initial: std.atomic.Value(bool) = .init(false),
    grant_lifetime: u32,
    external_port: u16,
    external_ip: [4]u8,

    fn run(self: *@This()) void {
        defer self.socket.close(self.io);
        var buf: [1100]u8 = undefined;
        while (!self.stopped.load(.acquire)) {
            const msg = self.socket.receiveTimeout(self.io, &buf, .{
                .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake },
            }) catch continue;
            const d = msg.data;
            if (d.len < 24 or d[0] != 2) continue; // not PCP v2
            const opcode = d[1] & 0x7f;
            if (opcode == 0) {
                // ANNOUNCE probe → ANNOUNCE response.
                _ = self.saw_announce.swap(true, .acq_rel);
                var resp: [24]u8 = undefined;
                resp[0] = 2;
                resp[1] = 0x80; // R|ANNOUNCE
                resp[2] = 0;
                resp[3] = 0; // success
                std.mem.writeInt(u32, resp[4..8], 0, .big);
                std.mem.writeInt(u32, resp[8..12], 7, .big);
                @memset(resp[12..24], 0);
                self.socket.send(self.io, &msg.from, &resp) catch {};
            } else if (opcode == 1 and d.len >= 60) {
                const lifetime = std.mem.readInt(u32, d[4..8], .big);
                const nonce = d[24..36].*;
                if (lifetime == 0) {
                    _ = self.saw_delete.swap(true, .acq_rel);
                    _ = self.release_nonce_matches_initial.swap(
                        std.mem.eql(u8, &nonce, &self.initial_map_nonce),
                        .acq_rel,
                    );
                } else {
                    const count = self.map_count.fetchAdd(1, .acq_rel) + 1;
                    if (count == 1) {
                        self.initial_map_nonce = nonce;
                    } else {
                        _ = self.renewal_nonce_matches_initial.swap(
                            std.mem.eql(u8, &nonce, &self.initial_map_nonce),
                            .acq_rel,
                        );
                    }
                }
                const suggested = std.mem.readInt(u16, d[42..44], .big);
                self.last_suggested_external.store(suggested, .release);
                const granted_port = if (suggested != 0) suggested else self.external_port;
                var resp: [60]u8 = undefined;
                @memset(&resp, 0);
                resp[0] = 2;
                resp[1] = 0x81; // R|MAP
                resp[3] = 0; // success
                std.mem.writeInt(u32, resp[4..8], self.grant_lifetime, .big);
                std.mem.writeInt(u32, resp[8..12], 7, .big);
                @memcpy(resp[24..36], d[24..36]); // echo nonce
                resp[36] = d[36]; // echo protocol
                std.mem.writeInt(u16, resp[40..42], std.mem.readInt(u16, d[40..42], .big), .big); // internal
                std.mem.writeInt(u16, resp[42..44], granted_port, .big);
                resp[54] = 0xff;
                resp[55] = 0xff;
                @memcpy(resp[56..60], &self.external_ip);
                self.socket.send(self.io, &msg.from, &resp) catch {};
            }
        }
    }
};

test "PCP probe, map and release complete against a real loopback responder" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const socket = try bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var responder: PcpResponder = .{
        .io = io,
        .socket = socket,
        .grant_lifetime = 3600,
        .external_port = 40001,
        .external_ip = .{ 198, 51, 100, 9 },
    };
    const thread = try std.Thread.spawn(.{}, PcpResponder.run, .{&responder});
    defer {
        responder.stopped.store(true, .release);
        thread.join();
    }

    const gateway = net.IpAddress{ .ip4 = .loopback(socket.address.getPort()) };
    const timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(2), .clock = .awake } };
    const local_ip: [4]u8 = .{ 192, 168, 1, 50 };

    // ANNOUNCE probe proves availability on the real wire.
    try probePcpAnnounce(io, gateway, local_ip, timeout);
    try std.testing.expect(responder.saw_announce.load(.acquire));

    // MAP creates a mapping with a caller-owned nonce; response
    // nonce/protocol/port echo is validated by pcpMapUdp.
    const nonce: [12]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const mapping = try pcpMapUdp(io, gateway, local_ip, 5361, nonce, null, 0, timeout);
    try std.testing.expectEqual(@as(u16, 40001), mapping.external_port);
    try std.testing.expectEqualSlices(u8, &.{ 198, 51, 100, 9 }, &mapping.external_ip);
    try std.testing.expectEqual(@as(u32, 3600), mapping.lifetime_seconds);
    try std.testing.expectEqual(@as(u32, 1), responder.map_count.load(.acquire));

    // Release sends a lifetime-0 MAP; fire-and-forget, so poll for arrival.
    releasePcpUdpMapping(io, gateway, local_ip, 5361, mapping.nonce);
    var waited: u64 = 0;
    while (!responder.saw_delete.load(.acquire) and waited < 2000) : (waited += 50) {
        io.sleep(std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    }
    try std.testing.expect(responder.saw_delete.load(.acquire));
}

// --- UPnP IGD loopback gateway: SSDP (UDP) + SOAP/XML control (HTTP). ---
const UpnpIgd = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    http_listener: net.Server,
    http_port: u16,
    ssdp_socket: net.Socket,
    stopped: std.atomic.Value(bool) = .init(false),
    saw_ssdp_search: std.atomic.Value(bool) = .init(false),
    saw_get_external_ip: std.atomic.Value(bool) = .init(false),
    saw_add_port: std.atomic.Value(bool) = .init(false),
    saw_add_any_port: std.atomic.Value(bool) = .init(false),
    saw_delete_port: std.atomic.Value(bool) = .init(false),
    external_ip_str: []const u8,
    any_port_grant: u16,
    http_thread: ?std.Thread = null,
    ssdp_thread: ?std.Thread = null,

    const igd_desc =
        \\<root xmlns="urn:schemas-upnp-org:device-1-0">
        \\<specVersion><major>1</major><minor>0</minor></specVersion>
        \\<URLBase>http://127.0.0.1:1</URLBase>
        \\<device>
        \\<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
        \\<friendlyName>Test IGD</friendlyName>
        \\<manufacturer>zig-iroh</manufacturer>
        \\<modelName>loopback-igd</modelName>
        \\<UDN>uuid:loopback-igd-0001</UDN>
        \\<serviceList>
        \\<service>
        \\<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        \\<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
        \\<SCPDURL>/scpd.xml</SCPDURL>
        \\<controlURL>/ctl</controlURL>
        \\<eventSubURL>/evt</eventSubURL>
        \\</service>
        \\</serviceList>
        \\</device>
        \\</root>
    ;

    const igd_scpd =
        \\<scpd xmlns="urn:schemas-upnp-org:service-1-0">
        \\<specVersion><major>1</major><minor>0</minor></specVersion>
        \\<actionList>
        \\<action>
        \\<name>GetExternalIPAddress</name>
        \\<argumentList>
        \\<argument><name>NewExternalIPAddress</name><direction>out</direction></argument>
        \\</argumentList>
        \\</action>
        \\<action>
        \\<name>AddPortMapping</name>
        \\<argumentList>
        \\<argument><name>NewRemoteHost</name><direction>in</direction></argument>
        \\<argument><name>NewExternalPort</name><direction>in</direction></argument>
        \\<argument><name>NewProtocol</name><direction>in</direction></argument>
        \\<argument><name>NewInternalPort</name><direction>in</direction></argument>
        \\<argument><name>NewInternalClient</name><direction>in</direction></argument>
        \\<argument><name>NewEnabled</name><direction>in</direction></argument>
        \\<argument><name>NewPortMappingDescription</name><direction>in</direction></argument>
        \\<argument><name>NewLeaseDuration</name><direction>in</direction></argument>
        \\</argumentList>
        \\</action>
        \\<action>
        \\<name>AddAnyPortMapping</name>
        \\<argumentList>
        \\<argument><name>NewRemoteHost</name><direction>in</direction></argument>
        \\<argument><name>NewExternalPort</name><direction>in</direction></argument>
        \\<argument><name>NewProtocol</name><direction>in</direction></argument>
        \\<argument><name>NewInternalPort</name><direction>in</direction></argument>
        \\<argument><name>NewInternalClient</name><direction>in</direction></argument>
        \\<argument><name>NewEnabled</name><direction>in</direction></argument>
        \\<argument><name>NewPortMappingDescription</name><direction>in</direction></argument>
        \\<argument><name>NewLeaseDuration</name><direction>in</direction></argument>
        \\<argument><name>NewReservedPort</name><direction>out</direction></argument>
        \\</argumentList>
        \\</action>
        \\<action>
        \\<name>DeletePortMapping</name>
        \\<argumentList>
        \\<argument><name>NewRemoteHost</name><direction>in</direction></argument>
        \\<argument><name>NewExternalPort</name><direction>in</direction></argument>
        \\<argument><name>NewProtocol</name><direction>in</direction></argument>
        \\</argumentList>
        \\</action>
        \\</actionList>
        \\</scpd>
    ;

    fn start(self: *@This()) !void {
        var http_addr: net.IpAddress = .{ .ip4 = .loopback(0) };
        self.http_listener = try http_addr.listen(self.io, .{});
        self.http_port = self.http_listener.socket.address.getPort();

        var ssdp_addr: net.IpAddress = .{ .ip4 = .loopback(0) };
        self.ssdp_socket = try ssdp_addr.bind(self.io, .{ .mode = .dgram, .protocol = .udp });

        self.http_thread = try std.Thread.spawn(.{}, UpnpIgd.httpLoop, .{self});
        self.ssdp_thread = try std.Thread.spawn(.{}, UpnpIgd.ssdpLoop, .{self});
    }

    fn stopAndJoin(self: *@This()) void {
        self.stopped.store(true, .release);
        // shutdown (not mere close) is the documented way to wake a blocked
        // accept; close alone can leave the thread parked on Linux.
        const listener_stream = net.Stream{ .socket = self.http_listener.socket };
        listener_stream.shutdown(self.io, .both) catch {};
        if (self.http_thread) |t| t.join();
        self.http_listener.deinit(self.io);
        // The SSDP loop wakes within its 50ms receive chunk and observes
        // `stopped`; joining BEFORE the close avoids closing an fd a worker
        // is blocked on (a fatal BADF under the threaded Io backend).
        if (self.ssdp_thread) |t| t.join();
        self.ssdp_socket.close(self.io);
    }

    fn ssdpLoop(self: *@This()) void {
        var buf: [1500]u8 = undefined;
        var loc: [128]u8 = undefined;
        while (!self.stopped.load(.acquire)) {
            const msg = self.ssdp_socket.receiveTimeout(self.io, &buf, .{
                .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake },
            }) catch continue;
            if (!std.mem.startsWith(u8, msg.data, "M-SEARCH")) continue;
            _ = self.saw_ssdp_search.swap(true, .acq_rel);
            const line = std.fmt.bufPrint(
                &loc,
                "HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:{d}/rootDesc.xml\r\nST: upnp:rootdevice\r\nUSN: uuid:loopback\r\n\r\n",
                .{self.http_port},
            ) catch continue;
            self.ssdp_socket.send(self.io, &msg.from, line) catch {};
        }
    }

    fn httpLoop(self: *@This()) void {
        while (!self.stopped.load(.acquire)) {
            var stream = self.http_listener.accept(self.io) catch return;
            self.handleConn(stream) catch {};
            stream.close(self.io);
        }
    }

    fn respondXml(request: *std.http.Server.Request, sw: *std.Io.Writer, body: []const u8) !void {
        try request.respond(body, .{
            .extra_headers = &.{.{ .name = "content-type", .value = "text/xml" }},
        });
        try sw.flush();
    }

    fn handleConn(self: *@This(), stream: net.Stream) !void {
        var read_buf: [8192]u8 = undefined;
        var write_buf: [8192]u8 = undefined;
        var stream_reader = stream.reader(self.io, &read_buf);
        var stream_writer = stream.writer(self.io, &write_buf);
        var server = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
        var request = try server.receiveHead();
        const target = request.head.target;

        if (request.head.method == .GET and std.mem.startsWith(u8, target, "/rootDesc")) {
            try respondXml(&request, &stream_writer.interface, igd_desc);
            return;
        }
        if (request.head.method == .GET and std.mem.startsWith(u8, target, "/scpd")) {
            try respondXml(&request, &stream_writer.interface, igd_scpd);
            return;
        }
        if (request.head.method == .POST and std.mem.startsWith(u8, target, "/ctl")) {
            var body_buf: [4096]u8 = undefined;
            var body: std.Io.Writer = .fixed(&body_buf);
            const body_reader = request.readerExpectNone(&read_buf);
            _ = body_reader.streamRemaining(&body) catch return error.HttpFailed;
            const soap = body.buffered();

            if (std.mem.indexOf(u8, soap, "GetExternalIPAddress") != null) {
                _ = self.saw_get_external_ip.swap(true, .acq_rel);
                var out: [512]u8 = undefined;
                const resp = std.fmt.bufPrint(&out,
                    \\<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                    \\<s:Body>
                    \\<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
                    \\<NewExternalIPAddress>{s}</NewExternalIPAddress>
                    \\</u:GetExternalIPAddressResponse>
                    \\</s:Body>
                    \\</s:Envelope>
                , .{self.external_ip_str}) catch return error.HttpFailed;
                try respondXml(&request, &stream_writer.interface, resp);
                return;
            }
            if (std.mem.indexOf(u8, soap, "AddAnyPortMapping") != null) {
                _ = self.saw_add_any_port.swap(true, .acq_rel);
                var out: [512]u8 = undefined;
                const resp = std.fmt.bufPrint(&out,
                    \\<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                    \\<s:Body>
                    \\<u:AddAnyPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
                    \\<NewReservedPort>{d}</NewReservedPort>
                    \\</u:AddAnyPortMappingResponse>
                    \\</s:Body>
                    \\</s:Envelope>
                , .{self.any_port_grant}) catch return error.HttpFailed;
                try respondXml(&request, &stream_writer.interface, resp);
                return;
            }
            if (std.mem.indexOf(u8, soap, "AddPortMapping") != null) {
                _ = self.saw_add_port.swap(true, .acq_rel);
                const resp =
                    \\<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                    \\<s:Body>
                    \\<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
                    \\</u:AddPortMappingResponse>
                    \\</s:Body>
                    \\</s:Envelope>
                ;
                try respondXml(&request, &stream_writer.interface, resp);
                return;
            }
            if (std.mem.indexOf(u8, soap, "DeletePortMapping") != null) {
                _ = self.saw_delete_port.swap(true, .acq_rel);
                const resp =
                    \\<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
                    \\<s:Body>
                    \\<u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
                    \\</u:DeletePortMappingResponse>
                    \\</s:Body>
                    \\</s:Envelope>
                ;
                try respondXml(&request, &stream_writer.interface, resp);
                return;
            }
        }
        // Unknown request: 404.
        try request.respond("not found", .{ .status = .not_found });
        try stream_writer.interface.flush();
    }
};

test "UPnP mapping is discovered, created and released against a real loopback IGD" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var igd: UpnpIgd = .{
        .io = io,
        .allocator = allocator,
        .http_listener = undefined,
        .http_port = 0,
        .ssdp_socket = undefined,
        .external_ip_str = "198.51.100.7",
        .any_port_grant = 40210,
    };
    try igd.start();
    defer igd.stopAndJoin();

    const search_target = net.IpAddress{ .ip4 = .loopback(igd.ssdp_socket.address.getPort()) };
    const mapping = try upnpMap(allocator, io, .{
        .search_target = search_target,
        .local_ip = .{ 192, 168, 1, 50 },
        .local_port = 5361,
        .budget_ms = 2000,
    }, null);
    defer {
        var g = mapping.gateway;
        g.deinit();
    }

    try std.testing.expect(igd.saw_ssdp_search.load(.acquire));
    try std.testing.expect(igd.saw_get_external_ip.load(.acquire));
    // preferred_external_port==0 → AddAnyPortMapping path, NewReservedPort.
    try std.testing.expect(igd.saw_add_any_port.load(.acquire));
    try std.testing.expectEqual(@as(u16, 40210), mapping.external_port);
    try std.testing.expectEqualSlices(u8, &.{ 198, 51, 100, 7 }, &mapping.external_ip);

    upnpRelease(allocator, io, &mapping.gateway, mapping.external_port);
    var waited: u64 = 0;
    while (!igd.saw_delete_port.load(.acquire) and waited < 2000) : (waited += 50) {
        io.sleep(std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    }
    try std.testing.expect(igd.saw_delete_port.load(.acquire));
}

test "UPnP preferred external port uses AddPortMapping" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var igd: UpnpIgd = .{
        .io = io,
        .allocator = allocator,
        .http_listener = undefined,
        .http_port = 0,
        .ssdp_socket = undefined,
        .external_ip_str = "198.51.100.7",
        .any_port_grant = 40210,
    };
    try igd.start();
    defer igd.stopAndJoin();

    const search_target = net.IpAddress{ .ip4 = .loopback(igd.ssdp_socket.address.getPort()) };
    const mapping = try upnpMap(allocator, io, .{
        .search_target = search_target,
        .local_ip = .{ 192, 168, 1, 50 },
        .local_port = 5361,
        .preferred_external_port = 40333,
        .budget_ms = 2000,
    }, null);
    defer {
        var g = mapping.gateway;
        g.deinit();
    }
    try std.testing.expect(igd.saw_add_port.load(.acquire));
    try std.testing.expectEqual(@as(u16, 40333), mapping.external_port);
}

// --- NAT-PMP loopback responder with lifecycle counters. ---
const NatPmpResponder = struct {
    io: std.Io,
    socket: net.Socket,
    stopped: std.atomic.Value(bool) = .init(false),
    grant_lifetime: u32,
    external_port: u16,
    public_ip: [4]u8,
    saw_external_request: std.atomic.Value(bool) = .init(false),
    saw_mapping_request: std.atomic.Value(bool) = .init(false),
    saw_delete: std.atomic.Value(bool) = .init(false),
    map_count: std.atomic.Value(u32) = .init(0),
    last_suggested_external: std.atomic.Value(u16) = .init(0),

    fn run(self: *@This()) void {
        var buf: [64]u8 = undefined;
        while (!self.stopped.load(.acquire)) {
            const msg = self.socket.receiveTimeout(self.io, &buf, .{
                .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake },
            }) catch continue;
            const d = msg.data;
            if (d.len >= 2 and d[0] == 0 and d[1] == 0) {
                _ = self.saw_external_request.swap(true, .acq_rel);
                var resp: [12]u8 = undefined;
                resp[0] = 0;
                resp[1] = 128;
                @memset(resp[2..4], 0);
                std.mem.writeInt(u32, resp[4..8], 42, .big);
                @memcpy(resp[8..12], &self.public_ip);
                self.socket.send(self.io, &msg.from, &resp) catch {};
            } else if (d.len >= 12 and d[0] == 0 and d[1] == 1) {
                _ = self.saw_mapping_request.swap(true, .acq_rel);
                const lifetime = std.mem.readInt(u32, d[8..12], .big);
                const suggested = std.mem.readInt(u16, d[6..8], .big);
                self.last_suggested_external.store(suggested, .release);
                if (lifetime == 0) {
                    _ = self.saw_delete.swap(true, .acq_rel);
                } else {
                    _ = self.map_count.fetchAdd(1, .acq_rel);
                }
                var resp: [16]u8 = undefined;
                resp[0] = 0;
                resp[1] = 129;
                @memset(resp[2..4], 0);
                std.mem.writeInt(u32, resp[4..8], 42, .big);
                @memcpy(resp[8..10], d[4..6]); // echo internal port
                const granted = if (suggested != 0) suggested else self.external_port;
                std.mem.writeInt(u16, resp[10..12], granted, .big);
                std.mem.writeInt(u32, resp[12..16], self.grant_lifetime, .big);
                self.socket.send(self.io, &msg.from, &resp) catch {};
            }
        }
    }
};

// --- Combined NAT-PMP + PCP responder: real gateways share UDP 5351 and
// --- demultiplex on the version byte (RFC 6887 §19). Used to prove the
// --- client's protocol PRIORITY when several protocols answer. ---
const NatPmpPcpResponder = struct {
    io: std.Io,
    socket: net.Socket,
    stopped: std.atomic.Value(bool) = .init(false),
    pcp_map_count: std.atomic.Value(u32) = .init(0),
    pcp_saw_delete: std.atomic.Value(bool) = .init(false),
    pmp_saw_mapping: std.atomic.Value(bool) = .init(false),
    pmp_saw_external: std.atomic.Value(bool) = .init(false),

    fn run(self: *@This()) void {
        var buf: [1100]u8 = undefined;
        while (!self.stopped.load(.acquire)) {
            const msg = self.socket.receiveTimeout(self.io, &buf, .{
                .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake },
            }) catch continue;
            const d = msg.data;
            if (d.len >= 2 and d[0] == 0) {
                self.handleNatPmp(d, msg.from);
            } else if (d.len >= 24 and d[0] == 2 and d[1] & 0x80 == 0) {
                self.handlePcp(d, msg.from);
            }
        }
    }

    fn handleNatPmp(self: *@This(), d: []const u8, from: net.IpAddress) void {
        if (d.len >= 2 and d[1] == 0) {
            _ = self.pmp_saw_external.swap(true, .acq_rel);
            var resp: [12]u8 = undefined;
            resp[0] = 0;
            resp[1] = 128;
            @memset(resp[2..4], 0);
            std.mem.writeInt(u32, resp[4..8], 42, .big);
            @memcpy(resp[8..12], &[4]u8{ 203, 0, 113, 7 });
            self.socket.send(self.io, &from, &resp) catch {};
        } else if (d.len >= 12 and d[1] == 1) {
            _ = self.pmp_saw_mapping.swap(true, .acq_rel);
            var resp: [16]u8 = undefined;
            resp[0] = 0;
            resp[1] = 129;
            @memset(resp[2..4], 0);
            std.mem.writeInt(u32, resp[4..8], 42, .big);
            @memcpy(resp[8..10], d[4..6]);
            std.mem.writeInt(u16, resp[10..12], 40000, .big);
            std.mem.writeInt(u32, resp[12..16], 3600, .big);
            self.socket.send(self.io, &from, &resp) catch {};
        }
    }

    fn handlePcp(self: *@This(), d: []const u8, from: net.IpAddress) void {
        const opcode = d[1] & 0x7f;
        const lifetime = std.mem.readInt(u32, d[4..8], .big);
        if (opcode == 0) {
            var resp: [24]u8 = undefined;
            resp[0] = 2;
            resp[1] = 0x80;
            resp[2] = 0;
            resp[3] = 0;
            std.mem.writeInt(u32, resp[4..8], 0, .big);
            std.mem.writeInt(u32, resp[8..12], 7, .big);
            @memset(resp[12..24], 0);
            self.socket.send(self.io, &from, &resp) catch {};
        } else if (opcode == 1 and d.len >= 60) {
            if (lifetime == 0) {
                _ = self.pcp_saw_delete.swap(true, .acq_rel);
            } else {
                _ = self.pcp_map_count.fetchAdd(1, .acq_rel);
            }
            var resp: [60]u8 = undefined;
            @memset(&resp, 0);
            resp[0] = 2;
            resp[1] = 0x81;
            resp[3] = 0;
            std.mem.writeInt(u32, resp[4..8], 3600, .big);
            std.mem.writeInt(u32, resp[8..12], 7, .big);
            @memcpy(resp[24..36], d[24..36]);
            resp[36] = d[36];
            @memcpy(resp[40..42], d[40..42]);
            std.mem.writeInt(u16, resp[42..44], 40123, .big);
            resp[54] = 0xff;
            resp[55] = 0xff;
            @memcpy(resp[56..60], &[4]u8{ 198, 51, 100, 9 });
            self.socket.send(self.io, &from, &resp) catch {};
        }
    }
};

test "Client maps via NAT-PMP when only NAT-PMP answers; release deletes on the gateway" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const socket = try bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var responder: NatPmpResponder = .{
        .io = io,
        .socket = socket,
        .grant_lifetime = 3600,
        .external_port = 40000,
        .public_ip = .{ 203, 0, 113, 7 },
    };
    const thread = try std.Thread.spawn(.{}, NatPmpResponder.run, .{&responder});
    defer {
        responder.stopped.store(true, .release);
        thread.join();
        socket.close(io);
    }

    var client: Client = Client.init(
        allocator,
        io,
        net.IpAddress{ .ip4 = .loopback(socket.address.getPort()) },
        .{ 127, 0, 0, 1 },
        5361,
    );
    client.recv_timeout_ms = 200;
    client.upnp_search_budget_ms = 300;
    // No IGD on this network: discovery runs against the NAT-PMP responder
    // port, which ignores M-SEARCH (hermetic — no real multicast traffic).
    client.upnp_search_target = net.IpAddress{ .ip4 = .loopback(socket.address.getPort()) };
    defer client.release();

    const ext = try client.acquire();
    try std.testing.expectEqualSlices(u8, &.{ 203, 0, 113, 7 }, &ext.ip);
    try std.testing.expectEqual(@as(u16, 40000), ext.port);
    try std.testing.expect(responder.saw_external_request.load(.acquire));
    try std.testing.expect(responder.saw_mapping_request.load(.acquire));
    const live = client.externalAddress().?;
    try std.testing.expectEqual(@as(u16, 40000), live.port);

    client.release();
    var waited: u64 = 0;
    while (!responder.saw_delete.load(.acquire) and waited < 2000) : (waited += 50) {
        io.sleep(std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    }
    try std.testing.expect(responder.saw_delete.load(.acquire));
    try std.testing.expect(client.externalAddress() == null);
}

test "Client maps via UPnP when only an IGD answers" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var igd: UpnpIgd = .{
        .io = io,
        .allocator = allocator,
        .http_listener = undefined,
        .http_port = 0,
        .ssdp_socket = undefined,
        .external_ip_str = "198.51.100.7",
        .any_port_grant = 40210,
    };
    try igd.start();
    defer igd.stopAndJoin();

    const ssdp_target = net.IpAddress{ .ip4 = .loopback(igd.ssdp_socket.address.getPort()) };
    var client: Client = Client.init(allocator, io, ssdp_target, .{ 127, 0, 0, 1 }, 5361);
    client.recv_timeout_ms = 200;
    client.upnp_search_budget_ms = 2000;
    client.upnp_search_target = ssdp_target;
    defer client.release();

    // NAT-PMP/PCP probes hit the IGD's SSDP socket, which only answers
    // M-SEARCH → both fail; UPnP discovery succeeds and is used.
    const ext = try client.acquire();
    try std.testing.expectEqualSlices(u8, &.{ 198, 51, 100, 7 }, &ext.ip);
    try std.testing.expectEqual(@as(u16, 40210), ext.port);
    try std.testing.expect(igd.saw_ssdp_search.load(.acquire));
    try std.testing.expect(igd.saw_add_any_port.load(.acquire));

    client.release();
    var waited: u64 = 0;
    while (!igd.saw_delete_port.load(.acquire) and waited < 2000) : (waited += 50) {
        io.sleep(std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    }
    try std.testing.expect(igd.saw_delete_port.load(.acquire));
}

test "Client prefers PCP when NAT-PMP + PCP + UPnP all answer (iroh priority)" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const socket = try bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var combo: NatPmpPcpResponder = .{ .io = io, .socket = socket };
    const combo_thread = try std.Thread.spawn(.{}, NatPmpPcpResponder.run, .{&combo});
    defer {
        combo.stopped.store(true, .release);
        combo_thread.join();
        socket.close(io);
    }

    var igd: UpnpIgd = .{
        .io = io,
        .allocator = allocator,
        .http_listener = undefined,
        .http_port = 0,
        .ssdp_socket = undefined,
        .external_ip_str = "198.51.100.7",
        .any_port_grant = 40210,
    };
    try igd.start();
    defer igd.stopAndJoin();

    var client: Client = Client.init(
        allocator,
        io,
        net.IpAddress{ .ip4 = .loopback(socket.address.getPort()) },
        .{ 127, 0, 0, 1 },
        5361,
    );
    client.recv_timeout_ms = 200;
    client.upnp_search_budget_ms = 2000;
    client.upnp_search_target = net.IpAddress{ .ip4 = .loopback(igd.ssdp_socket.address.getPort()) };
    defer client.release();

    const ext = try client.acquire();
    // The PCP responder granted 198.51.100.9:40123 — proof the mapping came
    // from PCP even though NAT-PMP and UPnP also answered the probes.
    try std.testing.expectEqualSlices(u8, &.{ 198, 51, 100, 9 }, &ext.ip);
    try std.testing.expectEqual(@as(u16, 40123), ext.port);
    try std.testing.expectEqual(@as(u32, 1), combo.pcp_map_count.load(.acquire));
    try std.testing.expect(!combo.pmp_saw_mapping.load(.acquire)); // NAT-PMP NOT used for the map
    try std.testing.expect(igd.saw_ssdp_search.load(.acquire)); // UPnP WAS probed
    try std.testing.expect(!igd.saw_add_any_port.load(.acquire)); // but NOT used for the map

    client.release();
    var waited: u64 = 0;
    while (!combo.pcp_saw_delete.load(.acquire) and waited < 2000) : (waited += 50) {
        io.sleep(std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    }
    try std.testing.expect(combo.pcp_saw_delete.load(.acquire));
}

test "Client renews the mapping at half the granted lifetime" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const socket = try bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var responder: PcpResponder = .{
        .io = io,
        .socket = socket,
        .grant_lifetime = 2, // half-life 1s → renewal observable in-test
        .external_port = 40001,
        .external_ip = .{ 198, 51, 100, 9 },
    };
    const thread = try std.Thread.spawn(.{}, PcpResponder.run, .{&responder});
    // PcpResponder.run owns the socket close.
    defer {
        responder.stopped.store(true, .release);
        thread.join();
    }

    var client: Client = Client.init(
        allocator,
        io,
        net.IpAddress{ .ip4 = .loopback(socket.address.getPort()) },
        .{ 127, 0, 0, 1 },
        5361,
    );
    client.recv_timeout_ms = 200;
    client.upnp_search_budget_ms = 300;
    client.upnp_search_target = net.IpAddress{ .ip4 = .loopback(socket.address.getPort()) };
    client.renew_backoff_ms = 200;
    defer client.release();

    const ext = try client.acquire();
    try std.testing.expectEqual(@as(u16, 40001), ext.port);
    try std.testing.expectEqual(@as(u32, 1), responder.map_count.load(.acquire));

    // Poll for the renewal MAP (bounded budget, adaptive wait — no fixed
    // sleeps: the parallel runner slows thread wakeups).
    var waited: u64 = 0;
    while (responder.map_count.load(.acquire) < 2 and waited < 15000) : (waited += 100) {
        io.sleep(std.Io.Duration.fromMilliseconds(100), .awake) catch {};
    }
    try std.testing.expect(responder.map_count.load(.acquire) >= 2);
    // The renewal suggested the CURRENT external so the gateway keeps the port.
    try std.testing.expectEqual(@as(u16, 40001), responder.last_suggested_external.load(.acquire));
}

// PCP MAP's nonce identifies the mapping. A renewal with a new nonce creates a
// second mapping, and a lifetime-zero MAP with that new nonce releases the
// wrong one. Capture the initial nonce on the loopback wire and require both
// later lifecycle requests to reproduce it exactly.
test "PCP lifecycle renewal and release retain the initial mapping nonce" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const socket = try bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var responder: PcpResponder = .{
        .io = io,
        .socket = socket,
        .grant_lifetime = 2, // half-life 1s makes the renewal observable.
        .external_port = 40001,
        .external_ip = .{ 198, 51, 100, 9 },
    };
    const thread = try std.Thread.spawn(.{}, PcpResponder.run, .{&responder});
    defer {
        responder.stopped.store(true, .release);
        thread.join();
    }

    var client: Client = Client.init(
        allocator,
        io,
        net.IpAddress{ .ip4 = .loopback(socket.address.getPort()) },
        .{ 127, 0, 0, 1 },
        5361,
    );
    client.recv_timeout_ms = 200;
    client.upnp_search_budget_ms = 300;
    client.upnp_search_target = net.IpAddress{ .ip4 = .loopback(socket.address.getPort()) };
    client.renew_backoff_ms = 200;
    defer client.release();

    _ = try client.acquire();
    var waited: u64 = 0;
    while (responder.map_count.load(.acquire) < 2 and waited < 15_000) : (waited += 100) {
        io.sleep(std.Io.Duration.fromMilliseconds(100), .awake) catch {};
    }
    try std.testing.expect(responder.map_count.load(.acquire) >= 2);
    try std.testing.expect(responder.renewal_nonce_matches_initial.load(.acquire));
    try std.testing.expectEqual(@as(u16, 40001), responder.last_suggested_external.load(.acquire));

    client.release();
    waited = 0;
    while (!responder.saw_delete.load(.acquire) and waited < 2_000) : (waited += 50) {
        io.sleep(std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    }
    try std.testing.expect(responder.saw_delete.load(.acquire));
    try std.testing.expect(responder.release_nonce_matches_initial.load(.acquire));
}
