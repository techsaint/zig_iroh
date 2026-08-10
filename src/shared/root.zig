//! shared — the engine- and TLS-agnostic iroh app port (fork-isolation S1-S3).
//!
//! Module boundary (compiler-enforced + build-asserted): `shared` imports ONLY
//! the named door module `transport` (per-product
//! `src/products/<id>/transport_api.zig`), `build_options`, and the external
//! `tls` package (relay WS/TLS data plane). No engine and no concrete TLS
//! backend is
//! nameable or path-reachable from here — see
//! the fork-isolation module boundary design (§1/§3).
//!
//! S1 contents: the blobs subsystem + its transitive `@import` closure
//! (`transport/mock.zig`, `hash`, `key`, `addr`, `ticket`,
//! `iroh_base_fixtures`) + the neutral transport contract types.
//! S2 contents: the protocol leaves — `gossip/`, `discovery/`,
//! `discovery_dht/`, `dns_server/`, `magicsock/`, `relay/`, `net_report*`,
//! `portmapper`, and `product_flags`.
//! S3 contents: the wire prims + public facade — `base_postcard`, `defaults`,
//! `path_observability`, `limits` (CP-2), `endpoint`, `endpoint_relay` (+ its
//! `transport/relay_fallback` closure), `protocol` (whose noq early-accept
//! gate became the injected door capability
//! `factory.supports_accept_early`/`waitEstablished`), `gossip/api`, and
//! `oracle/{report,shape}`. Engine-touching facade tests live in
//! `src/engine-noq/harness/facade_zero_rtt.zig`.

pub const transport_contract = @import("transport_contract.zig");
/// S6: backend-agnostic TLS contract (names no backend).
pub const tls_contract = @import("tls_contract.zig");
/// Engine-neutral UDP ancillary-data (ECN/GSO) codec, promoted in S5 because
/// both picoquic and noq consume the same kernel ABI surface.
pub const udp_cmsg = @import("transport/udp_cmsg.zig");

/// Semantic product-flag facade. Feature elision (gossip/discovery) stays
/// legitimately flag-gated inside shared; engine flags gate nothing here.
pub const product_flags = @import("product_flags.zig");

pub const hash = @import("hash.zig");
pub const key = @import("key.zig");
pub const addr = @import("addr.zig");
pub const ticket = @import("ticket.zig");
pub const iroh_base_fixtures = @import("iroh_base_fixtures.zig");

/// In-memory loopback mock transport (Tier-0 leaf-protocol harness).
pub const transport_mock = @import("transport/mock.zig");

pub const blobs = @import("blobs/blobs.zig");

// ── S2: the clean protocol leaves ────────────────────────────────────────
pub const discovery = @import("discovery/discovery.zig");
pub const discovery_connect = @import("discovery/connect.zig");
pub const discovery_product = @import("discovery/product.zig");
pub const discovery_server = @import("discovery/server.zig");
pub const discovery_address_lookup = @import("discovery/address_lookup.zig");
pub const discovery_dns_resolver = @import("discovery/dns_resolver.zig");
pub const discovery_republish = @import("discovery/republish.zig");
pub const discovery_mdns = @import("discovery/mdns.zig");
pub const dns_wire = @import("discovery/dns_wire.zig");
pub const dns_server = @import("dns_server/dns_server.zig");
pub const discovery_dht = @import("discovery_dht/discovery_dht.zig");
pub const net_report = @import("net_report.zig");
pub const net_report_stun = @import("net_report_stun.zig");
pub const portmapper = @import("portmapper.zig");
pub const relay = @import("relay/relay.zig");
pub const magicsock = @import("magicsock/magicsock.zig");
pub const gossip = if (product_flags.has_gossip) @import("gossip/gossip.zig") else struct {};

// ── S3: the wire prims + the public facade ───────────────────────────────
pub const base_postcard = @import("base_postcard.zig");
pub const defaults = @import("defaults.zig");
pub const path_observability = @import("path_observability.zig");
/// Neutral engine-ceiling constants (CP-2 home).
pub const limits = @import("limits.zig");
/// Pure SNI encoder, shared by both engines; picoquic's C-decoder test tail
/// lives in engine-picoquic/ after S5.
pub const tls_name = @import("tls_name.zig");
/// Engine-neutral relay-datagram seam (`Client` handle both engines take).
pub const transport_relay_fallback = @import("transport/relay_fallback.zig");
pub const endpoint_relay = @import("endpoint_relay.zig");
pub const endpoint = @import("endpoint.zig");
pub const protocol = @import("protocol.zig");
/// Oracle scenario/report SHAPE — engine-agnostic data consumed by the
/// iroh-oracle consumer module (and the engine oracle roots after S4).
pub const oracle_shape = @import("oracle/shape.zig");
pub const oracle_report = @import("oracle/report.zig");

// Flat prim aliases preserve the historical shared type identities after the
// former top-level forwarding root was retired.
pub const Hash = hash.Hash;
pub const PublicKey = key.PublicKey;
pub const SecretKey = key.SecretKey;
pub const NodeId = key.NodeId;
pub const EndpointId = key.EndpointId;
pub const Signature = key.Signature;
pub const EndpointAddr = addr.EndpointAddr;
pub const NodeAddr = addr.NodeAddr;
pub const TransportAddr = addr.TransportAddr;
pub const RelayUrl = addr.RelayUrl;
pub const CustomAddr = addr.CustomAddr;

test {
    // Per-module test collection (migration P5): a `b.addTest` on another
    // module does NOT collect these; the shared test binary is their home.
    _ = transport_contract;
    _ = tls_contract;
    _ = udp_cmsg;
    _ = hash;
    _ = key;
    _ = addr;
    _ = ticket;
    _ = iroh_base_fixtures;
    _ = transport_mock;
    _ = blobs;
    // S2 subsystem coverage stays explicit so the per-product aggregate test
    // count cannot silently drop.
    _ = discovery;
    _ = discovery_connect;
    _ = discovery_server;
    _ = discovery_address_lookup;
    _ = discovery_dns_resolver;
    _ = discovery_republish;
    _ = discovery_mdns;
    _ = dns_server;
    _ = discovery_dht;
    _ = net_report;
    _ = net_report_stun;
    _ = portmapper;
    _ = relay;
    _ = magicsock;
    if (product_flags.has_gossip) _ = gossip;
    // S3 facade + prim coverage. Engine-touching facade tests live in
    // src/engine-noq/harness/facade_zero_rtt.zig and are collected by the
    // NoQ engine test binary.
    _ = base_postcard;
    _ = defaults;
    _ = path_observability;
    _ = limits;
    _ = tls_name;
    _ = transport_relay_fallback;
    _ = endpoint_relay;
    _ = endpoint;
    _ = protocol;
    _ = oracle_shape;
    _ = oracle_report;
    // Door guards (§3.3 surface-lock + A4 manifest API fixture) run in every
    // product's shared test binary against that product's door.
    _ = @import("door_surface_lock.zig");
    _ = @import("door_api_fixture.zig");
}
