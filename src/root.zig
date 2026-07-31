//! zig_iroh — a Zig + C port of iroh's connectivity stack.
//!
//! Motivation: memory footprint/predictability, build experience, and a
//! pure-Zig+C steady state (no Rust runtime/FFI). See
//! the design thesis and the
//! measurement-first validation gate.
//!
//! Scope (plan Q-F): transport subset + gossip. Wire interop with Rust-iroh
//! peers is required (plan Q-A = yes), so ported formats must match iroh
//! byte-for-byte.

const std = @import("std");
/// Semantic product-flag facade (re-export). SoT for the BUILD is `products.zig`;
/// this is the src-side mirror of the derived `build_options` flags. Bench
/// adapters and leaves import this to product-gate engine-specific types.
pub const product_flags = @import("product_flags.zig");

pub const hash = @import("hash.zig");
pub const Hash = hash.Hash;

pub const key = @import("key.zig");
pub const PublicKey = key.PublicKey;
pub const SecretKey = key.SecretKey;
pub const NodeId = key.NodeId;
pub const EndpointId = key.EndpointId;
pub const Signature = key.Signature;

pub const addr = @import("addr.zig");
pub const EndpointAddr = addr.EndpointAddr;
pub const NodeAddr = addr.NodeAddr;
pub const TransportAddr = addr.TransportAddr;
pub const RelayUrl = addr.RelayUrl;
pub const CustomAddr = addr.CustomAddr;
pub const ticket = @import("ticket.zig");
pub const base_postcard = @import("base_postcard.zig");

pub const discovery = @import("discovery/discovery.zig");
pub const discovery_connect = @import("discovery/connect.zig");
pub const discovery_product = @import("discovery/product.zig");
pub const discovery_server = @import("discovery/server.zig");
pub const discovery_address_lookup = @import("discovery/address_lookup.zig");
pub const discovery_dns_resolver = @import("discovery/dns_resolver.zig");
pub const discovery_republish = @import("discovery/republish.zig");
pub const discovery_mdns = @import("discovery/mdns.zig");
pub const dns_wire = @import("discovery/dns_wire.zig");
pub const dns_server = @import("dns_server/mod.zig");
pub const discovery_dht = @import("discovery_dht/mod.zig");
pub const net_report = @import("net_report.zig");
pub const portmapper = @import("portmapper.zig");

pub const transport = @import("transport.zig");
pub const Transport = transport.Transport;
pub const Connection = transport.Connection;
pub const BiStream = transport.BiStream;

/// Public endpoint facade. Zig callers configure it with `Endpoint.Options`
/// / `Builder` (an alias to the same defaulted struct), not a Rust-style
/// chained builder.
pub const endpoint = @import("endpoint.zig");
pub const endpoint_relay = @import("endpoint_relay.zig");
pub const defaults = @import("defaults.zig");
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

/// Public accept-side composition surface (Router / ProtocolHandler) above
/// the frozen transport vtable — the upstream `protocol.rs` counterpart.
pub const protocol = @import("protocol.zig");
pub const Router = protocol.Router;
pub const ProtocolHandler = protocol.ProtocolHandler;

pub const relay = @import("relay/relay.zig");

pub const blobs = @import("blobs/blobs.zig");

// Picoquic engine surface — comptime-gated (component-repo restructure). A
// product with `picoquic=false` (e.g. noq-picotls / noq-zigtls) never imports
// these, so their `connection/c.zig` picoquic cImport (→ libpicoquic) is elided.
pub const connection = if (product_flags.has_picoquic) @import("connection/mod.zig") else struct {};
pub const quic = if (product_flags.has_picoquic) @import("transport/quic.zig") else struct {};
pub const transport_endpoint = if (product_flags.has_picoquic) @import("transport/endpoint.zig") else struct {};
/// Engine-select factory over the frozen transport vtable (picoquic | noq).
/// Always imported; gates its own engine dependencies internally.
pub const transport_factory = @import("transport/factory.zig");
pub const magicsock = @import("magicsock/mod.zig");
/// Selected-path observability (patchbay / NAT / path-migration assertions).
pub const path_observability = @import("path_observability.zig");
pub const SelectedPath = path_observability.SelectedPath;
pub const SelectedPathKind = path_observability.PathKind;
pub const noq_quic = if (product_flags.has_noq) @import("quic/mod.zig") else struct {};
/// The noq production endpoint (real UDP socket + pump). Exported so the
/// behavioral oracle can drive PRODUCTION endpoints over loopback rather than
/// the simulated pair harness — a socket-level capability (ECN cmsg ingest,
/// kernel GSO) cannot be proven by an in-process harness.
pub const transport_noq = if (product_flags.has_noq) @import("transport/transport_noq.zig") else struct {};
/// UDP ancillary-data (cmsg) plumbing: the ECN codepoint enum + encode/decode.
pub const udp_cmsg = if (product_flags.has_noq) @import("transport/udp_cmsg.zig") else struct {};

pub const gossip = if (product_flags.has_gossip) @import("gossip/gossip.zig") else struct {};

test {
    // Pull in sub-module tests.
    _ = hash;
    _ = key;
    _ = addr;
    _ = base_postcard;
    _ = ticket;
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
    _ = portmapper;
    _ = transport;
    _ = endpoint;
    _ = endpoint_relay;
    _ = defaults;
    _ = protocol;
    _ = relay;
    _ = blobs;
    if (product_flags.has_picoquic) {
        _ = connection;
        _ = quic;
        _ = transport_endpoint;
        // characterization pins the two picoquic backends against each other —
        // frozen file, picoquic-only, so excluded from mono-noq products.
        _ = @import("transport/characterization.zig");
    }
    _ = transport_factory;
    _ = magicsock;
    _ = path_observability;
    if (product_flags.has_noq) _ = noq_quic;
    if (product_flags.has_gossip) _ = gossip;
}
