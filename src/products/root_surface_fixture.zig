//! S7 public-root surface lock.
//!
//! This records the legacy `src/shared/root.zig` public declaration set verbatim and
//! is instantiated by every product root. It guards the cutover from silently
//! dropping or widening `zig_iroh.*` while the backing graph is replaced.

const std = @import("std");

pub const locked_surface = [_][]const u8{
    "product_flags",
    "hash",
    "Hash",
    "key",
    "PublicKey",
    "SecretKey",
    "NodeId",
    "EndpointId",
    "Signature",
    "addr",
    "EndpointAddr",
    "NodeAddr",
    "TransportAddr",
    "RelayUrl",
    "CustomAddr",
    "ticket",
    "base_postcard",
    "discovery",
    "discovery_connect",
    "discovery_product",
    "discovery_server",
    "discovery_address_lookup",
    "discovery_dns_resolver",
    "discovery_republish",
    "discovery_mdns",
    "dns_wire",
    "dns_server",
    "discovery_dht",
    "net_report",
    "net_report_stun",
    "portmapper",
    "transport",
    "Transport",
    "Connection",
    "BiStream",
    "endpoint",
    "endpoint_relay",
    "defaults",
    "Endpoint",
    "EndpointConnection",
    "EndpointOptions",
    "Builder",
    "ConnectOptions",
    "EndpointMetrics",
    "EndpointAddressSnapshot",
    "HomeRelayStatus",
    "HomeRelayState",
    "ProductDiscovery",
    "StaticDiscoveryResolver",
    "AddressLookup",
    "MemoryLookup",
    "StaticLookup",
    "CompositeLookup",
    "DiscoveryDnsResolver",
    "DnsTransportMode",
    "BackgroundRepublish",
    "BackgroundRepublishTask",
    "RelayMode",
    "protocol",
    "Router",
    "ProtocolHandler",
    "relay",
    "blobs",
    "connection",
    "transport_endpoint",
    "quic",
    "transport_factory",
    "magicsock",
    "path_observability",
    "SelectedPath",
    "SelectedPathKind",
    "noq_quic",
    "stream_capability_vectors",
    "transport_noq",
    "udp_cmsg",
    "quic_crypto",
    "quic_crypto_zigtls",
    "quic_crypto_picotls",
    "tls_name",
    "gossip",
};

pub fn assertExact(comptime root: type) void {
    @setEvalBranchQuota(10_000);
    const decls = @typeInfo(root).@"struct".decls;
    for (decls) |decl| {
        for (locked_surface) |name| {
            if (std.mem.eql(u8, decl.name, name)) break;
        } else @compileError("S7 root surface widened beyond legacy root: " ++ decl.name);
    }
    if (decls.len != locked_surface.len) {
        @compileError(std.fmt.comptimePrint(
            "S7 root surface count {d} != legacy root count {d}",
            .{ decls.len, locked_surface.len },
        ));
    }
}
