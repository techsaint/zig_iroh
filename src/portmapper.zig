//! Real NAT-PMP probe helper. No simulated gateway is scored as coverage.

const std = @import("std");
const net = std.Io.net;

pub const nat_pmp_port: u16 = 5351;
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

pub const ProbeError = error{
    MissingGatewayEnv,
    InvalidGatewayEnv,
    NatPmpIpv4Only,
    UnsupportedVersion,
    UnsupportedOpcode,
    GatewayRefused,
    ShortResponse,
    UnexpectedSource,
} || net.IpAddress.BindError || net.Socket.SendError || net.Socket.ReceiveTimeoutError;

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

pub fn gatewayFromEnv() ProbeError!?net.IpAddress {
    const raw = std.c.getenv("IROH_PORTMAPPER_GATEWAY") orelse return null;
    const text = std.mem.span(raw);
    if (text.len == 0) return null;
    return try parseGatewayText(text);
}

pub fn probeNatPmpFromEnv(io: std.Io) ProbeError!NatPmpExternalAddress {
    const gateway = (try gatewayFromEnv()) orelse return error.MissingGatewayEnv;
    return probeNatPmpExternalAddress(io, gateway, .{ .duration = .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    } });
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
    request[0] = 0; // version
    request[1] = 1; // UDP mapping opcode
    std.mem.writeInt(u16, request[2..4], 0, .big); // reserved
    std.mem.writeInt(u16, request[4..6], internal_port, .big);
    std.mem.writeInt(u16, request[6..8], requested_external_port, .big);
    std.mem.writeInt(u32, request[8..12], lifetime_seconds, .big);

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
        0,   129,
        0,   0,
        0,   0,
        0,   9,
        0x1F, 0x90, // internal 8080
        0x9C, 0x40, // external 40000
        0,   0,
        0,   60,
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
