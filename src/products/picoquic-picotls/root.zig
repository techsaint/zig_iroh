//! picoquic-picotls public `zig_iroh` product root (S7).
//! All historic public names are preserved; transport is bound directly to the
//! selected engine door and this root never reaches a legacy facade.

const std = @import("std");
const shared = @import("shared");
const door = @import("transport");
const engine = @import("engine");
const tls_backend = @import("tls_backend");
const root_surface = @import("root_surface");

const has_noq = engine.bundle.engine == .noq;
const has_picoquic = engine.bundle.engine == .picoquic;

pub const product_flags = shared.product_flags;
pub const hash = shared.hash;
pub const Hash = hash.Hash;
pub const key = shared.key;
pub const PublicKey = key.PublicKey;
pub const SecretKey = key.SecretKey;
pub const NodeId = key.NodeId;
pub const EndpointId = key.EndpointId;
pub const Signature = key.Signature;
pub const addr = shared.addr;
pub const EndpointAddr = addr.EndpointAddr;
pub const NodeAddr = addr.NodeAddr;
pub const TransportAddr = addr.TransportAddr;
pub const RelayUrl = addr.RelayUrl;
pub const CustomAddr = addr.CustomAddr;
pub const ticket = shared.ticket;
pub const base_postcard = shared.base_postcard;
pub const discovery = shared.discovery;
pub const discovery_connect = shared.discovery_connect;
pub const discovery_product = shared.discovery_product;
pub const discovery_server = shared.discovery_server;
pub const discovery_address_lookup = shared.discovery_address_lookup;
pub const discovery_dns_resolver = shared.discovery_dns_resolver;
pub const discovery_republish = shared.discovery_republish;
pub const discovery_mdns = shared.discovery_mdns;
pub const dns_wire = shared.dns_wire;
pub const dns_server = shared.dns_server;
pub const discovery_dht = shared.discovery_dht;
pub const net_report = shared.net_report;
pub const net_report_stun = shared.net_report_stun;
pub const portmapper = shared.portmapper;
pub const transport = door;
pub const Transport = transport.Transport;
pub const Connection = transport.Connection;
pub const BiStream = transport.BiStream;
pub const endpoint = shared.endpoint;
pub const endpoint_relay = shared.endpoint_relay;
pub const defaults = shared.defaults;
pub const Endpoint = endpoint.Endpoint;
pub const EndpointConnection = endpoint.Connection;
pub const EndpointOptions = endpoint.Options;
pub const Builder = endpoint.Builder;
pub const ConnectOptions = endpoint.ConnectOptions;
pub const EndpointMetrics = endpoint.EndpointMetrics;
pub const EndpointAddressSnapshot = endpoint.AddressSnapshot;
pub const HomeRelayStatus = endpoint.HomeRelayStatus;
pub const HomeRelayState = endpoint.HomeRelayState;
pub const ProductDiscovery = discovery_product.ProductDiscovery;
pub const StaticDiscoveryResolver = discovery_connect.StaticResolver;
pub const AddressLookup = discovery_address_lookup.AddressLookup;
pub const MemoryLookup = discovery_address_lookup.MemoryLookup;
pub const StaticLookup = discovery_address_lookup.StaticLookup;
pub const CompositeLookup = discovery_address_lookup.CompositeLookup;
pub const DiscoveryDnsResolver = discovery_dns_resolver.DnsResolver;
pub const DnsTransportMode = discovery_dns_resolver.TransportMode;
pub const BackgroundRepublish = discovery_republish.BackgroundRepublish;
pub const BackgroundRepublishTask = discovery_republish.BackgroundRepublishTask;
pub const RelayMode = endpoint.RelayMode;
pub const protocol = shared.protocol;
pub const Router = protocol.Router;
pub const ProtocolHandler = protocol.ProtocolHandler;
pub const relay = struct {
    pub const proto = shared.relay.proto;
    pub const handshake = shared.relay.handshake;
    pub const access = shared.relay.access;
    pub const client = shared.relay.client;
    pub const relay_map = shared.relay.relay_map;
    pub const server = shared.relay.server;
    pub const tls_wrapper = shared.relay.tls_wrapper;
    pub const config = shared.relay.config;
    pub const metrics = shared.relay.metrics;
    pub const qad = if (has_noq) engine.qad else struct {};
    pub const acme = shared.relay.acme;
};
pub const blobs = shared.blobs;
pub const connection = if (has_picoquic) engine.connection else struct {};
pub const transport_endpoint = if (has_picoquic) engine.transport_endpoint else struct {};
pub const quic = transport_endpoint;
pub const transport_factory = transport.factory;
pub const magicsock = shared.magicsock;
pub const path_observability = shared.path_observability;
pub const SelectedPath = path_observability.SelectedPath;
pub const SelectedPathKind = path_observability.PathKind;
pub const noq_quic = if (has_noq) engine.quic else struct {};
pub const stream_capability_vectors = if (has_noq) engine.stream_capability_vectors else struct {};
pub const transport_noq = if (has_noq) engine.transport_noq else struct {};
pub const udp_cmsg = if (has_noq) shared.udp_cmsg else struct {};
pub const quic_crypto = struct {
    pub const zigtls_enabled = product_flags.has_zigtls;
    pub const picotls_enabled = product_flags.has_picotls;
    pub const Error = tls_backend.Error;
    pub const Role = tls_backend.Role;
    pub const Backend = tls_backend.Backend;
    pub const Direction = tls_backend.Direction;
    pub const Epoch = tls_backend.Epoch;
    pub const max_epoch = tls_backend.max_epoch;
    pub const max_secret_len = tls_backend.max_secret_len;
    pub const TrafficSecret = tls_backend.TrafficSecret;
    pub const quic_transport_parameters_ext = tls_backend.quic_transport_parameters_ext;
    pub const SignatureScheme = tls_backend.SignatureScheme;
    pub const SigningKey = tls_backend.SigningKey;
    pub const X509ServerIdentity = shared.tls_contract.X509ServerIdentity;
    pub const HandshakeOutput = tls_backend.HandshakeOutput;
    pub const ZigtlsResumptionTicket = tls_backend.ZigtlsResumptionTicket;
    pub const ZigtlsTicketKeyManager = tls_backend.ZigtlsTicketKeyManager;
    pub const ZigtlsReplayFilter = tls_backend.ZigtlsReplayFilter;
    pub const ZigtlsTrustStore = tls_backend.ZigtlsTrustStore;
    pub const ZigtlsOcspResponseView = tls_backend.ZigtlsOcspResponseView;
    pub const Config = tls_backend.Config;
    pub const PicotlsSession = struct {};
};
pub const quic_crypto_zigtls = struct {
    pub const session = struct {};
    pub const ZigtlsSession = struct {};
    pub const EndpointHandshake = struct {};
};
pub const quic_crypto_picotls = struct {
    pub const PicotlsSession = struct {};
    pub const EndpointHandshake = struct {};
};
pub const tls_name = if (has_picoquic) engine.tls_name else shared.tls_name;
pub const gossip = shared.gossip;

comptime {
    root_surface.assertExact(@This());
}

fn testId(seed: u8) shared.key.NodeId {
    return shared.key.SecretKey.fromBytes(.{seed} ** 32).public();
}

test "S7 product root: blobs crosses the selected shared-to-door seam over mock transport" {
    const allocator = std.testing.allocator;
    const pair = shared.transport_mock.Pair.init(allocator, std.testing.io, testId(1), testId(2));
    defer pair.deinit(allocator);
    const data = try blobs.fixtures.makeTestData(allocator, 4096);
    defer allocator.free(data);
    const content_hash = hash.Hash.of(data);
    var stream = try blobs.observe_push.observe(allocator, pair.client(), blobs.protocol.ObserveRequest.all(content_hash));
    defer stream.deinit();
    const updates = [_]blobs.protocol.ObserveItem{
        .{ .size = 0, .ranges = blobs.bao.ChunkRanges.empty() },
        .{ .size = @intCast(data.len), .ranges = blobs.bao.ChunkRanges.all() },
    };
    try blobs.observe_push.serveObserve(allocator, pair.server(), content_hash, &updates);
    const initial = try stream.next(allocator);
    defer initial.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), initial.size);
    const complete = try stream.next(allocator);
    defer complete.deinit(allocator);
    try std.testing.expectEqual(@as(u64, data.len), complete.size);
    try std.testing.expect(complete.ranges.is_all());
}

test "S7 product root: selected door factory surface compiles" {
    _ = transport.factory.AnyEndpoint;
    _ = transport.factory.createForProduct;
}

test "S7 product root: public transport aliases retain selected seam identity" {
    try std.testing.expect(transport.Error == shared.transport_contract.Error);
    try std.testing.expect(transport.ConnectionStats == shared.transport_contract.ConnectionStats);
    try std.testing.expect(transport.CongestionController == shared.transport_contract.CongestionController);
    try std.testing.expect(Transport == transport.Transport);
    try std.testing.expect(Connection == transport.Connection);
    try std.testing.expect(BiStream == transport.BiStream);
}
