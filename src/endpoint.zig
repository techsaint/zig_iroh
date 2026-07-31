//! Public Endpoint facade above the product-selected transport engine.
//!
//! The feature set follows iroh's public endpoint surface; the shape is Zig:
//! one `Options` struct with defaults and named-field initialization instead
//! of a chained builder object.

const std = @import("std");
const key = @import("key.zig");
const addr_mod = @import("addr.zig");
const tr = @import("transport.zig");
const factory = @import("transport/factory.zig");
const discovery = @import("discovery/discovery.zig");
const discovery_connect = @import("discovery/connect.zig");
const discovery_product = @import("discovery/product.zig");
const discovery_address_lookup = @import("discovery/address_lookup.zig");
const product_flags = @import("product_flags.zig");
const discovery_mdns = @import("discovery/mdns.zig");
const endpoint_relay = @import("endpoint_relay.zig");
const defaults = @import("defaults.zig");
const net_report_mod = @import("net_report.zig");
const portmapper_mod = @import("portmapper.zig");

const net = std.Io.net;
const EndpointAddr = addr_mod.EndpointAddr;
const TransportAddr = addr_mod.TransportAddr;

pub const RelayMode = endpoint_relay.RelayMode;
pub const defaults_mod = defaults;

pub const max_alpns = 8;
pub const max_alpn_len = 64;
pub const max_proxy_url_len = 256;
pub const default_alpn: [:0]const u8 = "iroh-interop-test";
pub const default_alpns: []const []const u8 = &.{default_alpn};

pub const DatagramError = factory.DatagramError;

pub const ConnectOptions = struct {
    /// Public guard matching the upstream observable behavior, expressed as a
    /// plain option instead of a separate Rust future/Connecting state.
    reject_self_connect: bool = true,
    /// For `connectWithOpts`, false rejects a caller-supplied direct IP. For
    /// `connectByIdWithOpts`, false rejects a resolver-returned direct IP
    /// before dialing so relay-only rows cannot pass through direct fallback.
    allow_direct_addresses: bool = true,
};

pub const DnsResolver = enum {
    system,
    custom,
};

pub const CaTlsConfig = enum {
    system_roots,
    insecure_skip_verify,
};

pub const EndpointMetrics = struct {
    engine: factory.Engine,
    connect_attempts: u64 = 0,
    connect_successes: u64 = 0,
    accept_successes: u64 = 0,
    datagrams_sent: u64 = 0,
    datagrams_received: u64 = 0,
};

pub const HomeRelayState = enum {
    disabled,
    disconnected,
    connected,
    failed,
};

pub const HomeRelayStatus = struct {
    mode: RelayMode,
    url: ?[]const u8,
    state: HomeRelayState,
    last_error: ?anyerror = null,
};

pub const AddressSnapshot = struct {
    endpoint_addr: EndpointAddr,
    version: u64,

    pub fn deinit(self: *AddressSnapshot, allocator: std.mem.Allocator) void {
        self.endpoint_addr.deinit(allocator);
        self.* = undefined;
    }
};

/// Blocking change feed over the endpoint address set (upstream
/// `Endpoint::watch_addr` watcher semantics): `get()` snapshots the current
/// `EndpointAddr`; `updated()` parks the caller until the address set differs
/// from the version of the last snapshot this watcher returned (home relay
/// learned or lost, external addresses added/removed), then returns the new
/// snapshot. Endpoint close terminates the feed with `error.EndpointClosed`.
pub const AddressWatcher = struct {
    ep: *Endpoint,
    version: u64,

    /// Current address snapshot; advances the watcher's version marker.
    pub fn get(self: *AddressWatcher) !AddressSnapshot {
        const snap = try self.ep.addressSnapshot();
        self.version = snap.version;
        return snap;
    }

    /// Block until the address set differs from the last snapshot this
    /// watcher returned, then return the new snapshot.
    pub fn updated(self: *AddressWatcher) !AddressSnapshot {
        const io_inst = self.ep.io_inst;
        self.ep.state_mu.lockUncancelable(io_inst);
        while (self.ep.address_version == self.version and !self.ep.closed_state) {
            self.ep.state_cond.waitUncancelable(io_inst, &self.ep.state_mu);
        }
        const terminated = self.ep.closed_state;
        self.ep.state_mu.unlock(io_inst);
        if (terminated) return error.EndpointClosed;
        return self.get();
    }
};

const RuntimeConfig = struct {
    dns_resolver: ?DnsResolver = null,
    proxy_from_env: bool = false,
    proxy_url_set: bool = false,
    proxy_url_storage: [max_proxy_url_len]u8 = undefined,
    proxy_url_len: usize = 0,
    ca_tls_config: ?CaTlsConfig = null,

    fn init(options: EndpointOptions) !RuntimeConfig {
        var config: RuntimeConfig = .{
            .dns_resolver = options.dns_resolver,
            .proxy_from_env = options.proxy_from_env,
            .ca_tls_config = options.ca_tls_config,
        };
        if (options.proxy_url) |url| {
            try config.copyProxyUrl(url);
        } else if (options.proxy_from_env) {
            const env_names = [_][*:0]const u8{ "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy" };
            inline for (env_names) |name| {
                if (std.c.getenv(name)) |ptr| {
                    try config.copyProxyUrl(std.mem.span(ptr));
                    break;
                }
            }
        }
        return config;
    }

    fn copyProxyUrl(self: *RuntimeConfig, value: []const u8) !void {
        if (value.len > self.proxy_url_storage.len) return error.InvalidProxyUrl;
        @memcpy(self.proxy_url_storage[0..value.len], value);
        self.proxy_url_len = value.len;
        self.proxy_url_set = true;
    }

    fn proxyUrl(self: *const RuntimeConfig) ?[]const u8 {
        if (!self.proxy_url_set) return null;
        return self.proxy_url_storage[0..self.proxy_url_len];
    }
};

/// Endpoint-aware address-lookup provider factory (upstream iroh builder-passed
/// discovery services, e.g. `Endpoint::builder().address_lookup(...)`): the
/// builder is invoked with the constructed `*Endpoint` during `Endpoint.init`,
/// so providers that need the endpoint's own identity (mDNS self-exclusion,
/// DHT key reuse) can read it before their resolver joins the registry.
pub const AddressLookupBuilder = struct {
    context: *anyopaque,
    buildFn: *const fn (context: *anyopaque, ep: *Endpoint) anyerror!discovery_address_lookup.AddressLookup,

    pub fn build(self: AddressLookupBuilder, ep: *Endpoint) !discovery_address_lookup.AddressLookup {
        return self.buildFn(self.context, ep);
    }
};

pub const EndpointOptions = struct {
    engine: factory.Engine = factory.productEngine(),
    secret_key: ?key.SecretKey = null,
    bind_address: net.IpAddress = .{ .ip4 = .loopback(0) },
    expected_peer: ?key.NodeId = null,
    accept_unknown_peer: bool = false,
    tls_backend: factory.TlsBackend = factory.productTlsBackend(),
    congestion_kind: factory.CongestionKind = .cubic,
    alpns: []const []const u8 = default_alpns,
    /// Optional caller-owned concrete discovery client for `connectById*`.
    /// Type is product-selected (`DiscoveryClient` when `has_discovery`); there
    /// is no runtime `*anyopaque` resolver vtable. Single-source sugar:
    /// registered into the endpoint's address-lookup registry ahead of
    /// `address_lookup_services`.
    discovery_client: ?*const discovery_product.ProductDiscovery = null,
    /// Multi-source discovery composition (upstream `AddressLookupServices`):
    /// every provider listed here is registered at construction and lookups
    /// merge (union of addresses) across all sources. Providers may also be
    /// added/cleared at runtime via `Endpoint.addAddressLookupService` /
    /// `Endpoint.clearAddressLookupServices`.
    address_lookup_services: []const discovery_address_lookup.AddressLookup = &.{},
    /// Endpoint-aware provider factories: invoked with the constructed
    /// `*Endpoint` during init (after the transport exists), each returned
    /// provider is registered into the address-lookup registry behind
    /// `discovery_client` + `address_lookup_services`.
    address_lookup_builders: []const AddressLookupBuilder = &.{},
    dns_resolver: ?DnsResolver = null,
    proxy_url: ?[]const u8 = null,
    proxy_from_env: bool = false,
    ca_tls_config: ?CaTlsConfig = null,
    /// Home-relay policy. `.custom` requires `home_relay_url`. `.default` /
    /// `.staging` resolve from `defaults.{prod,staging}`. All relay modes
    /// other than `.disabled` need an engine that can attach a relay client.
    relay_mode: RelayMode = .disabled,
    home_relay_url: ?[]const u8 = null,
    /// Optional pkarr HTTP base (`…/pkarr`). When set (or when mode is
    /// `.default`/`.staging` and `publish_on_online` is true), `online()`
    /// publishes the home relay plus any advertised external addresses as an
    /// `EndpointInfo` after the home relay connects.
    /// Local tests pass a loopback pkarr base; production uses n0 defaults.
    pkarr_relay_url: ?[]const u8 = null,
    /// Publish home-relay address via pkarr after a successful online().
    /// Default true — matches upstream PkarrPublisher-on-online. Set false
    /// to connect the home relay without publishing (e.g. pure transport tests).
    publish_on_online: bool = true,
    /// NAT port-mapping (upstream `portmapper_config`): when true, online()
    /// probes the configured/env NAT-PMP gateway for the public address plus a
    /// UDP mapping of the bind port, and publishes the learned external
    /// address. Best-effort: probe failures never fail online(); inspect
    /// `portmapperLastError()`.
    portmapper: bool = false,
    /// NAT-PMP gateway IPv4 literal; falls back to the IROH_PORTMAPPER_GATEWAY
    /// environment variable when null.
    portmapper_gateway: ?[]const u8 = null,
};

/// Compatibility symbol for callers scanning for iroh's public `Builder`.
/// In Zig this is deliberately the same defaulted-options value, not a chained
/// builder workaround.
pub const Options = EndpointOptions;
pub const Builder = EndpointOptions;

pub const Endpoint = struct {
    allocator: std.mem.Allocator,
    io_inst: std.Io,
    inner: factory.AnyEndpoint,
    config: RuntimeConfig,
    discovery_client: ?*const discovery_product.ProductDiscovery,
    /// Composable address-lookup registry used by `connectById` (upstream
    /// `AddressLookupServices`): seeded from `options.discovery_client` +
    /// `options.address_lookup_services` (+ builders), runtime-mutable via
    /// `addAddressLookupService` / `clearAddressLookupServices`.
    address_lookup: discovery_connect.AddressLookupServices,
    /// Endpoint-owned adapter that registers `discovery_client` into the
    /// address-lookup registry as its first (tie-winning) provider. Owned
    /// here so the registry's borrowed context stays valid for the
    /// endpoint's lifetime.
    discovery_lookup: ?discovery_address_lookup.PkarrLookup,
    alpn_storage: [max_alpns][max_alpn_len:0]u8,
    alpn_lens: [max_alpns]usize,
    alpn_z: [max_alpns][:0]const u8,
    alpn_slices: [max_alpns][]const u8,
    alpn_count: usize,
    metrics_state: EndpointMetrics,
    secret_key: key.SecretKey,
    relay_mode: RelayMode,
    home_relay_url_storage: ?[]u8,
    pkarr_relay_url_storage: ?[]u8,
    publish_on_online: bool,
    portmapper_enabled: bool,
    portmapper_gateway_storage: ?[]u8,
    port_mapping_state: ?TransportAddr,
    portmapper_probe_error: ?anyerror,
    home_relay: ?*endpoint_relay.HomeRelay,
    home_relay_last_error: ?anyerror,
    online_state: bool,
    published_on_online: bool,
    closed_state: bool,
    address_version: u64,
    external_addrs: std.ArrayList(TransportAddr),
    /// Runtime relay set (upstream relay map): owned canonical URL strings,
    /// seeded from the relay mode's static map and mutated by
    /// addRelay/removeRelay after construction.
    relay_urls: std.ArrayList([]u8),
    remote_infos: std.AutoHashMap([32]u8, discovery.EndpointInfo),
    /// Guards `closed_state` + `address_version`: `close()` from any thread
    /// wakes `waitClosed()` waiters deterministically, and every published
    /// address-set change wakes parked `AddressWatcher.updated()` callers
    /// (relay/server.zig idiom).
    state_mu: std.Io.Mutex,
    state_cond: std.Io.Condition,

    pub const Options = EndpointOptions;

    pub fn init(allocator: std.mem.Allocator, io: std.Io, options: EndpointOptions) !*Endpoint {
        try validateAlpns(options.alpns);
        if (options.relay_mode == .custom and options.home_relay_url == null)
            return error.HomeRelayUrlRequired;

        const endpoint = try allocator.create(Endpoint);
        errdefer allocator.destroy(endpoint);

        const secret = options.secret_key orelse key.SecretKey.generate(io);
        var home_url: ?[]u8 = null;
        errdefer if (home_url) |u| allocator.free(u);
        if (options.home_relay_url) |u| home_url = try allocator.dupe(u8, u);
        var pkarr_url: ?[]u8 = null;
        errdefer if (pkarr_url) |u| allocator.free(u);
        if (options.pkarr_relay_url) |u| pkarr_url = try allocator.dupe(u8, u);
        var portmapper_gateway: ?[]u8 = null;
        errdefer if (portmapper_gateway) |u| allocator.free(u);
        if (options.portmapper_gateway) |u| portmapper_gateway = try allocator.dupe(u8, u);

        // Force-staging env remaps Default → Staging (upstream force_staging_infra).
        var mode = options.relay_mode;
        if (mode == .default and defaults.forceStagingInfra()) mode = .staging;

        endpoint.* = .{
            .allocator = allocator,
            .io_inst = io,
            .inner = undefined,
            .config = try RuntimeConfig.init(options),
            .discovery_client = if (comptime product_flags.has_discovery) options.discovery_client else null,
            .address_lookup = discovery_connect.AddressLookupServices.init(allocator),
            .discovery_lookup = null,
            .alpn_storage = undefined,
            .alpn_lens = [_]usize{0} ** max_alpns,
            .alpn_z = undefined,
            .alpn_slices = undefined,
            .alpn_count = 0,
            .metrics_state = .{ .engine = options.engine },
            .secret_key = secret,
            .relay_mode = mode,
            .home_relay_url_storage = home_url,
            .pkarr_relay_url_storage = pkarr_url,
            .publish_on_online = options.publish_on_online,
            .portmapper_enabled = options.portmapper,
            .portmapper_gateway_storage = portmapper_gateway,
            .port_mapping_state = null,
            .portmapper_probe_error = null,
            .home_relay = null,
            .home_relay_last_error = null,
            .online_state = false,
            .published_on_online = false,
            .closed_state = false,
            .address_version = 0,
            .external_addrs = .empty,
            .relay_urls = .empty,
            .remote_infos = std.AutoHashMap([32]u8, discovery.EndpointInfo).init(allocator),
            .state_mu = .init,
            .state_cond = .init,
        };
        errdefer endpoint.address_lookup.deinit();
        if (comptime product_flags.has_discovery) {
            if (endpoint.discovery_client) |client| {
                endpoint.discovery_lookup = .{ .client = client };
                try endpoint.address_lookup.add((&endpoint.discovery_lookup.?).asLookup());
            }
        }
        for (options.address_lookup_services) |service| try endpoint.address_lookup.add(service);
        try endpoint.loadAlpns(options.alpns);
        errdefer {
            for (endpoint.relay_urls.items) |u| allocator.free(u);
            endpoint.relay_urls.deinit(allocator);
        }
        try endpoint.seedRelayUrls();

        endpoint.inner = try factory.create(options.engine, allocator, io, secret, endpoint.alpn_z[0], .{
            .bind_address = options.bind_address,
            .expected_peer = options.expected_peer,
            .accept_unknown_peer = options.accept_unknown_peer,
            .tls_backend = options.tls_backend,
            .congestion_kind = options.congestion_kind,
        });
        errdefer endpoint.inner.deinit();
        if (endpoint.alpn_count > 1) try endpoint.inner.setAlpns(endpoint.alpns());
        for (options.address_lookup_builders) |builder| {
            try endpoint.address_lookup.add(try builder.build(endpoint));
        }
        return endpoint;
    }

    pub fn deinit(self: *Endpoint) void {
        self.inner.deinit();
        if (self.home_relay) |relay| relay.deinit();
        for (self.external_addrs.items) |item| item.deinit(self.allocator);
        self.external_addrs.deinit(self.allocator);
        for (self.relay_urls.items) |u| self.allocator.free(u);
        self.relay_urls.deinit(self.allocator);
        var remote_it = self.remote_infos.valueIterator();
        while (remote_it.next()) |info| info.deinit(self.allocator);
        self.remote_infos.deinit();
        self.address_lookup.deinit();
        if (self.home_relay_url_storage) |u| self.allocator.free(u);
        if (self.pkarr_relay_url_storage) |u| self.allocator.free(u);
        if (self.portmapper_gateway_storage) |u| self.allocator.free(u);
        if (self.port_mapping_state) |pm| pm.deinit(self.allocator);
        self.secret_key.deinit();
        self.allocator.destroy(self);
    }

    /// Request endpoint shutdown. Idempotent. On return:
    /// - future dial/accept/mutation through the public API fails closed;
    /// - every live backend connection has been deterministically closed
    ///   (CONNECTION_CLOSE flushed toward each peer), not merely marked at
    ///   the facade;
    /// - threads parked in `waitClosed()` have been woken.
    /// `deinit` remains the owner of backend resource destruction.
    pub fn close(self: *Endpoint) void {
        self.state_mu.lockUncancelable(self.io_inst);
        if (self.closed_state) {
            self.state_mu.unlock(self.io_inst);
            return;
        }
        self.closed_state = true;
        self.online_state = false;
        self.address_version +%= 1;
        self.state_cond.broadcast(self.io_inst);
        self.state_mu.unlock(self.io_inst);
        if (self.home_relay) |relay| {
            relay.deinit();
            self.home_relay = null;
        }
        self.inner.closeAllConnections();
    }

    pub fn closed(self: *const Endpoint) bool {
        return self.closed_state;
    }

    /// Block until `close()` has run (upstream `closed().await`). Returns
    /// immediately when the endpoint is already closed.
    pub fn waitClosed(self: *Endpoint) void {
        self.state_mu.lockUncancelable(self.io_inst);
        while (!self.closed_state) {
            self.state_cond.waitUncancelable(self.io_inst, &self.state_mu);
        }
        self.state_mu.unlock(self.io_inst);
    }

    pub fn wait_closed(self: *Endpoint) void {
        return self.waitClosed();
    }

    /// Wait until the home relay client is connected (upstream `online()`).
    ///
    /// - `relay_mode=.disabled`: immediate success (direct-only endpoint).
    /// - `relay_mode=.default`/`.staging`: pick the first n0 map URL (prod or
    ///   staging), connect it, optionally publish via pkarr.
    /// - `relay_mode=.custom`: connect `home_relay_url`, applying `ca_tls_config`
    ///   to DERP TLS verification, and attach the client to the selected engine.
    /// When `publish_on_online` is true and a pkarr base is known, publishes a
    /// **relay-only** EndpointInfo (no direct IP) after the home relay is up.
    pub fn online(self: *Endpoint) !void {
        if (self.closed_state) return error.EndpointClosed;
        if (self.online_state) return;
        self.home_relay_last_error = null;
        self.portmapper_probe_error = null;
        if (self.portmapper_enabled) self.probePortMapping();
        switch (self.relay_mode) {
            .disabled => {
                self.online_state = true;
                return;
            },
            .default, .staging, .custom => {},
        }

        // NOTE: the custom-dns_resolver refusal is NOT here. It lives at the actual lookup boundary
        // (`relay/client.zig:connectRelayHost`), because DNS use is path-dependent: a literal-IP
        // relay URL is dialled without any lookup, and under an HTTP proxy only the proxy host is
        // resolved locally. An earlier version of this merge refused here, which rejected working
        // configurations AND masked `HomeRelayUrlRequired` / `ProtocolError` / `OutOfMemory` behind
        // `CustomDnsResolverUnwired` — a regression test covered a literal-IP
        // case that passed in isolation and failed after integration. The knob is still refused
        // observably (mutation-RED); it is refused where it would actually be consulted.
        const relay_url = try self.resolveHomeRelayUrl();
        // resolveHomeRelayUrl may allocate into home_relay_url_storage for default/staging.

        const insecure = switch (self.config.ca_tls_config orelse .system_roots) {
            .insecure_skip_verify => true,
            .system_roots => false,
        };
        // OWNERSHIP TRANSFER IS SCOPED, and this is load-bearing.
        //
        // The cleanup below must cover exactly the window in which `home` is owned by NOBODY but
        // this frame: after `connect` returns and before the endpoint takes it. A function-level
        // `errdefer home.deinit()` spans too much — it stays ARMED past the two transfers below, so
        // a later failure (publication) frees a relay that `self.home_relay` AND the noq client's
        // context both still point at, while `online_state` remains true so a retry reports success
        // without repairing either pointer. `deinit()` then double-frees.
        //
        // That was not hypothetical: a regression test forced publication to
        // fail against a real local relay and reproduced a SEGFAULT in `Endpoint.deinit()` —
        // `614 pass, 4 skip, 1 crash ... terminated with signal ABRT`. The comment that used to sit
        // below claimed "publication failure does not unwind a successful home-relay connect"; the
        // code did precisely the opposite of its own comment.
        //
        // The block scopes the guard: it disarms at the closing brace, once BOTH transfers have
        // succeeded and the endpoint owns the relay.
        {
            const home = endpoint_relay.HomeRelay.connect(
                self.allocator,
                self.io_inst,
                relay_url,
                self.secret_key,
                insecure,
                self.config.proxyUrl(),
                (self.config.dns_resolver orelse .system) == .custom,
            ) catch |err| {
                self.home_relay_last_error = err;
                return err;
            };
            errdefer home.deinit(); // covers ONLY relay attachment failure below
            switch (self.inner.engine()) {
                .noq => factory.setNoqRelay(self.inner, home.noqClient()) catch |err| {
                    self.home_relay_last_error = err;
                    return err;
                },
                .picoquic => factory.setPicoquicRelay(self.inner, home.relayClient()) catch |err| {
                    self.home_relay_last_error = err;
                    return err;
                },
            }
            self.home_relay = home; // endpoint now owns it; `deinit` is the only freer from here
        }
        self.online_state = true;
        self.state_mu.lockUncancelable(self.io_inst);
        self.address_version +%= 1;
        self.state_cond.broadcast(self.io_inst);
        self.state_mu.unlock(self.io_inst);

        if (self.publish_on_online) {
            self.publishHomeRelay() catch |err| {
                // Publication failure does NOT unwind a successful home-relay connect — the endpoint
                // is genuinely online and usable; the error is surfaced so callers that REQUIRE
                // publication can observe it. This is only true because the cleanup above is scoped;
                // with a function-level errdefer this path freed the live relay.
                return err;
            };
        }
    }

    /// The NAT-PMP learned external address from the last successful online()
    /// probe; null when portmapping is disabled or the gateway probe failed.
    pub fn portMapping(self: *const Endpoint) ?TransportAddr {
        return self.port_mapping_state;
    }

    pub fn port_mapping(self: *const Endpoint) ?TransportAddr {
        return self.portMapping();
    }

    pub fn portmapperLastError(self: *const Endpoint) ?anyerror {
        return self.portmapper_probe_error;
    }

    pub fn portmapper_last_error(self: *const Endpoint) ?anyerror {
        return self.portmapperLastError();
    }

    /// Best-effort NAT port-mapping probe (upstream magicsock portmapper
    /// task): resolve the gateway (option, else IROH_PORTMAPPER_GATEWAY), ask
    /// it for the public address and a UDP mapping of this endpoint's bind
    /// port, and publish the learned external address (address-watcher bump +
    /// pkarr inclusion are the existing addExternalAddr semantics). Failures
    /// never fail online(); they land in `portmapper_probe_error`.
    fn probePortMapping(self: *Endpoint) void {
        self.probePortMappingInner() catch |err| {
            self.portmapper_probe_error = err;
        };
    }

    fn probePortMappingInner(self: *Endpoint) !void {
        const gateway = if (self.portmapper_gateway_storage) |text|
            try portmapper_mod.parseGatewayText(text)
        else
            (try portmapper_mod.gatewayFromEnv()) orelse return error.MissingGatewayEnv;
        const local = self.localAddress();
        if (local != .ip4) return error.NatPmpIpv4Only;
        const timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(2), .clock = .awake } };
        const ext = try portmapper_mod.probeNatPmpExternalAddress(self.io_inst, gateway, timeout);
        const mapping = try portmapper_mod.probeNatPmpUdpMapping(self.io_inst, gateway, local.getPort(), 0, 60, timeout);
        const learned: TransportAddr = .{ .ip = .{ .ip4 = .{ .bytes = ext.public_ip, .port = mapping.external_port } } };
        self.port_mapping_state = try learned.clone(self.allocator);
        _ = try self.addExternalAddr(learned);
    }

    /// Seed the runtime relay set from the relay mode's static map (called
    /// once from init; later mutations go through addRelay/removeRelay).
    fn seedRelayUrls(self: *Endpoint) !void {
        switch (self.relay_mode) {
            .disabled => return,
            .custom => {
                if (self.home_relay_url_storage) |u| {
                    try self.relay_urls.append(self.allocator, try self.allocator.dupe(u8, u));
                }
            },
            .default, .staging => {
                var map = switch (self.relay_mode) {
                    .default => try defaults.prod.defaultRelayMap(self.allocator),
                    else => try defaults.staging.defaultRelayMap(self.allocator),
                };
                defer map.deinit();
                for (map.urls()) |url| {
                    try self.relay_urls.append(self.allocator, try self.allocator.dupe(u8, url.asString()));
                }
            },
        }
    }

    /// Resolve the DERP/home-relay URL for this mode. For default/staging the
    /// first entry of the RUNTIME relay set is selected (home-relay probing is
    /// a later refinement); a set emptied via removeRelay resolves no home
    /// relay, which is exactly the upstream relay-map removal behavior.
    fn resolveHomeRelayUrl(self: *Endpoint) ![]const u8 {
        if (self.home_relay_url_storage) |u| return u;
        switch (self.relay_mode) {
            .disabled, .custom => return error.HomeRelayUrlRequired,
            .default, .staging => {},
        }
        if (self.relay_urls.items.len == 0) return error.HomeRelayUrlRequired;
        const text = try self.allocator.dupe(u8, self.relay_urls.items[0]);
        self.home_relay_url_storage = text;
        return text;
    }

    /// Publish a relay-only EndpointInfo for this endpoint's home relay via
    /// the configured (or mode-default) pkarr HTTP base.
    fn publishHomeRelay(self: *Endpoint) !void {
        const home = self.home_relay_url_storage orelse return error.HomeRelayUrlRequired;
        const pkarr_base = self.pkarr_relay_url_storage orelse switch (self.relay_mode) {
            .default => defaults.prod.PKARR_RELAY_URL,
            .staging => defaults.staging.PKARR_RELAY_URL,
            // Custom without an explicit pkarr base: skip (local transport tests).
            .custom, .disabled => {
                return;
            },
        };

        var relay_url = try addr_mod.RelayUrl.parse(self.allocator, home);
        defer relay_url.deinit(self.allocator);
        // The published record advertises the home relay plus every external
        // address the operator added at runtime (upstream: the endpoint's
        // advertised direct addresses travel in the discovery record). The
        // raw bind address is NOT included — it is an interface address, not
        // an advertised external one.
        var publish_addrs: std.ArrayList(TransportAddr) = .empty;
        defer publish_addrs.deinit(self.allocator);
        try publish_addrs.append(self.allocator, .{ .relay = relay_url });
        for (self.external_addrs.items) |item| {
            try publish_addrs.append(self.allocator, item);
        }
        const info = try discovery.EndpointInfo.fromParts(
            self.allocator,
            self.secret_key.public(),
            publish_addrs.items,
            null,
        );
        defer info.deinit(self.allocator);

        var client: std.http.Client = .{ .allocator = self.allocator, .io = self.io_inst };
        defer client.deinit();

        try discovery.publishPkarrRelayWithOptions(
            self.allocator,
            &client,
            pkarr_base,
            self.secret_key,
            info,
            discovery.DEFAULT_TTL,
            discovery.Timestamp.now(),
            .{ .address_filter = .unfiltered },
        );
        self.published_on_online = true;
    }

    pub fn isOnline(self: *const Endpoint) bool {
        return self.online_state;
    }

    /// True when `online()` completed a pkarr publish of the home relay.
    pub fn didPublishOnOnline(self: *const Endpoint) bool {
        return self.published_on_online;
    }

    pub fn homeRelayUrl(self: *const Endpoint) ?[]const u8 {
        return self.home_relay_url_storage;
    }

    pub fn home_relay_url(self: *const Endpoint) ?[]const u8 {
        return self.homeRelayUrl();
    }

    pub fn homeRelayStatus(self: *const Endpoint) HomeRelayStatus {
        const state: HomeRelayState = if (self.relay_mode == .disabled)
            .disabled
        else if (self.home_relay != null)
            .connected
        else if (self.home_relay_last_error != null)
            .failed
        else
            .disconnected;
        return .{
            .mode = self.relay_mode,
            .url = self.home_relay_url_storage,
            .state = state,
            .last_error = self.home_relay_last_error,
        };
    }

    pub fn home_relay_status(self: *const Endpoint) HomeRelayStatus {
        return self.homeRelayStatus();
    }

    pub fn relayMode(self: *const Endpoint) RelayMode {
        return self.relay_mode;
    }

    pub fn pkarrRelayUrl(self: *const Endpoint) ?[]const u8 {
        return self.pkarr_relay_url_storage;
    }

    pub fn transport(self: *Endpoint) tr.Transport {
        return self.inner.transport();
    }

    pub fn localAddress(self: *Endpoint) net.IpAddress {
        return self.inner.localAddress();
    }

    pub fn endpointAddr(self: *Endpoint) !EndpointAddr {
        var list: std.ArrayList(TransportAddr) = .empty;
        defer list.deinit(self.allocator);

        try list.append(self.allocator, .{ .ip = self.localAddress() });
        if (self.home_relay_url_storage) |url| {
            try list.append(self.allocator, .{ .relay = addr_mod.RelayUrl.borrowed(url) });
        }
        for (self.external_addrs.items) |item| {
            try list.append(self.allocator, item);
        }
        return EndpointAddr.fromParts(self.allocator, self.id(), list.items);
    }

    pub fn endpoint_addr(self: *Endpoint) !EndpointAddr {
        return self.endpointAddr();
    }

    pub fn addr(self: *Endpoint) !EndpointAddr {
        return self.endpointAddr();
    }

    fn addressSnapshot(self: *Endpoint) !AddressSnapshot {
        return .{
            .endpoint_addr = try self.endpointAddr(),
            .version = self.address_version,
        };
    }

    /// Watch the endpoint address set (upstream `Endpoint::watch_addr`). The
    /// returned watcher starts at the current version, so every relay or
    /// direct-address change published after this call wakes `updated()`.
    pub fn watchAddr(self: *Endpoint) AddressWatcher {
        self.state_mu.lockUncancelable(self.io_inst);
        const version = self.address_version;
        self.state_mu.unlock(self.io_inst);
        return .{ .ep = self, .version = version };
    }

    pub fn watch_addr(self: *Endpoint) AddressWatcher {
        return self.watchAddr();
    }

    pub fn addExternalAddr(self: *Endpoint, item: TransportAddr) !bool {
        if (self.closed_state) return error.EndpointClosed;
        for (self.external_addrs.items) |existing| {
            if (existing.eql(item)) return false;
        }
        try self.external_addrs.append(self.allocator, try item.clone(self.allocator));
        self.state_mu.lockUncancelable(self.io_inst);
        self.address_version +%= 1;
        self.state_cond.broadcast(self.io_inst);
        self.state_mu.unlock(self.io_inst);
        return true;
    }

    pub fn add_external_addr(self: *Endpoint, item: TransportAddr) !bool {
        return self.addExternalAddr(item);
    }

    pub fn removeExternalAddr(self: *Endpoint, item: TransportAddr) !bool {
        if (self.closed_state) return error.EndpointClosed;
        for (self.external_addrs.items, 0..) |existing, i| {
            if (existing.eql(item)) {
                var removed = self.external_addrs.orderedRemove(i);
                removed.deinit(self.allocator);
                self.state_mu.lockUncancelable(self.io_inst);
                self.address_version +%= 1;
                self.state_cond.broadcast(self.io_inst);
                self.state_mu.unlock(self.io_inst);
                return true;
            }
        }
        return false;
    }

    pub fn remove_external_addr(self: *Endpoint, item: TransportAddr) !bool {
        return self.removeExternalAddr(item);
    }

    /// Add a relay to the endpoint's runtime relay set (upstream
    /// `Endpoint::add_relay`). The URL is canonicalized before comparison and
    /// storage; returns false when it is already present. The set is seeded
    /// from the relay mode's static map at construction and consulted when
    /// resolving the home relay for `.default` / `.staging` modes.
    pub fn addRelay(self: *Endpoint, url: []const u8) !bool {
        if (self.closed_state) return error.EndpointClosed;
        const parsed = try addr_mod.RelayUrl.parse(self.allocator, url);
        defer parsed.deinit(self.allocator);
        const canonical = parsed.asString();
        for (self.relay_urls.items) |existing| {
            if (std.mem.eql(u8, existing, canonical)) return false;
        }
        try self.relay_urls.append(self.allocator, try self.allocator.dupe(u8, canonical));
        self.state_mu.lockUncancelable(self.io_inst);
        self.address_version +%= 1;
        self.state_cond.broadcast(self.io_inst);
        self.state_mu.unlock(self.io_inst);
        return true;
    }

    pub fn add_relay(self: *Endpoint, url: []const u8) !bool {
        return self.addRelay(url);
    }

    /// Remove a relay from the runtime relay set (upstream
    /// `Endpoint::remove_relay`). Returns false when absent.
    pub fn removeRelay(self: *Endpoint, url: []const u8) !bool {
        if (self.closed_state) return error.EndpointClosed;
        const parsed = try addr_mod.RelayUrl.parse(self.allocator, url);
        defer parsed.deinit(self.allocator);
        const canonical = parsed.asString();
        for (self.relay_urls.items, 0..) |existing, i| {
            if (std.mem.eql(u8, existing, canonical)) {
                self.allocator.free(self.relay_urls.orderedRemove(i));
                self.state_mu.lockUncancelable(self.io_inst);
                self.address_version +%= 1;
                self.state_cond.broadcast(self.io_inst);
                self.state_mu.unlock(self.io_inst);
                return true;
            }
        }
        return false;
    }

    pub fn remove_relay(self: *Endpoint, url: []const u8) !bool {
        return self.removeRelay(url);
    }

    /// Owned snapshot of the runtime relay set. Caller frees each string and
    /// the slice with `allocator`.
    pub fn relayMap(self: *Endpoint, allocator: std.mem.Allocator) ![][]u8 {
        const out = try allocator.alloc([]u8, self.relay_urls.items.len);
        var filled: usize = 0;
        errdefer {
            for (out[0..filled]) |s| allocator.free(s);
            allocator.free(out);
        }
        for (self.relay_urls.items, 0..) |item, i| {
            out[i] = try allocator.dupe(u8, item);
            filled += 1;
        }
        return out;
    }

    pub fn relay_map(self: *Endpoint, allocator: std.mem.Allocator) ![][]u8 {
        return self.relayMap(allocator);
    }

    /// Register an additional address-lookup provider at runtime (upstream
    /// `AddressLookupServices` composition). Lookups merge across all
    /// registered sources. The provider's context is borrowed — it must
    /// outlive its registration.
    pub fn addAddressLookupService(self: *Endpoint, service: discovery_address_lookup.AddressLookup) !void {
        if (self.closed_state) return error.EndpointClosed;
        try self.address_lookup.add(service);
    }

    pub fn add_address_lookup_service(self: *Endpoint, service: discovery_address_lookup.AddressLookup) !void {
        return self.addAddressLookupService(service);
    }

    /// Drop every registered address-lookup provider (upstream
    /// `AddressLookupServices::clear`). Subsequent `connectById` fails with
    /// `error.DiscoveryUnavailable` until a provider is re-added.
    pub fn clearAddressLookupServices(self: *Endpoint) !void {
        if (self.closed_state) return error.EndpointClosed;
        self.address_lookup.clear();
    }

    pub fn clear_address_lookup_services(self: *Endpoint) !void {
        return self.clearAddressLookupServices();
    }

    pub fn addressLookupServiceCount(self: *const Endpoint) usize {
        return self.address_lookup.len();
    }

    pub fn address_lookup_service_count(self: *const Endpoint) usize {
        return self.addressLookupServiceCount();
    }

    pub fn id(self: *Endpoint) key.NodeId {
        return self.transport().localNodeId();
    }

    pub fn metrics(self: *const Endpoint) EndpointMetrics {
        return self.metrics_state;
    }

    /// Network-condition report for THIS endpoint (upstream `Endpoint::net_report`):
    /// the endpoint's configured home relay URL, whether a live home-relay
    /// session is held right now, and a measured handshake latency against
    /// that configured relay — plus local UDP path facts. Relay-disabled
    /// endpoints report `relay_url == null`.
    pub fn netReport(self: *Endpoint) !net_report_mod.Report {
        const url: ?[]const u8 = switch (self.relay_mode) {
            .disabled => null,
            else => self.resolveHomeRelayUrl() catch null,
        };
        const connected = self.online_state and self.home_relay != null;
        return net_report_mod.runEndpointReport(
            self.allocator,
            self.io_inst,
            url,
            connected,
            self.config.ca_tls_config == .insecure_skip_verify,
        );
    }

    pub fn net_report(self: *Endpoint) !net_report_mod.Report {
        return self.netReport();
    }

    pub fn dns_resolver(self: *const Endpoint) ?DnsResolver {
        return self.config.dns_resolver;
    }

    pub fn proxy_url(self: *const Endpoint) ?[]const u8 {
        return self.config.proxyUrl();
    }

    pub fn ca_tls_config(self: *const Endpoint) ?CaTlsConfig {
        return self.config.ca_tls_config;
    }

    pub fn setAlpns(self: *Endpoint, new_alpns: []const []const u8) factory.AnyEndpoint.SetAlpnsError!void {
        if (self.closed_state) return error.EndpointClosed;
        try validateAlpns(new_alpns);
        try self.inner.setAlpns(new_alpns);
        try self.loadAlpns(new_alpns);
    }

    pub fn connect(self: *Endpoint, peer: EndpointAddr, alpn: []const u8) !Connection {
        return self.connectWithOpts(peer, alpn, .{});
    }

    pub fn connectWithOpts(self: *Endpoint, peer: EndpointAddr, alpn: []const u8, options: ConnectOptions) !Connection {
        if (self.closed_state) return error.EndpointClosed;
        self.metrics_state.connect_attempts += 1;
        if (options.reject_self_connect and peer.id.eql(self.id())) return error.SelfConnect;
        if (!options.allow_direct_addresses and peer.firstIpAddr() != null) return error.DirectAddressDisabled;
        if (!self.connectAlpnMatches(alpn)) return error.InvalidAlpn;

        const inner_conn = self.inner.transport().connect(peer) catch |err| blk: {
            // Upstream magicsock path racing, serialized: when the caller-
            // supplied address carries BOTH direct and relay reachability and
            // the direct dial fails, retry once via the relay-only subset.
            if (peer.firstIpAddr() == null or peer.firstRelayUrl() == null) return err;
            var relay_only = discovery_connect.relayOnlySubset(self.allocator, peer) catch return err;
            defer relay_only.deinit(self.allocator);
            break :blk try self.inner.transport().connect(relay_only);
        };
        errdefer inner_conn.close();
        try self.rememberRemoteAddr(peer, "connect");
        if (inner_conn.remoteAddress()) |ip| {
            try self.rememberRemoteObservedAddr(inner_conn.remoteNodeId(), ip, "connect");
        }
        self.metrics_state.connect_successes += 1;
        return .{ .endpoint = self, .inner = inner_conn };
    }

    pub fn connect_with_opts(self: *Endpoint, peer: EndpointAddr, alpn: []const u8, options: ConnectOptions) !Connection {
        return self.connectWithOpts(peer, alpn, options);
    }

    pub fn connectById(self: *Endpoint, node_id: key.NodeId, alpn: []const u8) !Connection {
        return self.connectByIdWithOpts(node_id, alpn, .{});
    }

    pub fn connectByIdWithOpts(self: *Endpoint, node_id: key.NodeId, alpn: []const u8, options: ConnectOptions) !Connection {
        if (comptime !product_flags.has_discovery) {
            @compileError("connectById requires a discovery-enabled product");
        }
        if (self.closed_state) return error.EndpointClosed;
        self.metrics_state.connect_attempts += 1;
        if (options.reject_self_connect and node_id.eql(self.id())) return error.SelfConnect;
        if (!self.connectAlpnMatches(alpn)) return error.InvalidAlpn;
        // The composable address-lookup registry is the resolution source:
        // the product discovery client (when wired) is its first provider,
        // so a client-only endpoint resolves exactly as before, and runtime
        // providers union-merge on top. Empty registry means not wired.
        if (self.address_lookup.isEmpty()) return error.DiscoveryUnavailable;

        var resolved: EndpointAddr = undefined;
        const inner_conn = try discovery_connect.connectByIdWithOpts(
            self.allocator,
            self.inner.transport(),
            &self.address_lookup,
            node_id,
            &resolved,
            .{ .allow_resolved_direct_addresses = options.allow_direct_addresses, .fallback_to_relay_on_failure = true },
        );
        defer resolved.deinit(self.allocator);
        errdefer inner_conn.close();
        try self.rememberRemoteAddr(resolved, "connect-by-id");
        if (inner_conn.remoteAddress()) |ip| {
            try self.rememberRemoteObservedAddr(inner_conn.remoteNodeId(), ip, "connect-by-id");
        }

        self.metrics_state.connect_successes += 1;
        return .{ .endpoint = self, .inner = inner_conn };
    }

    pub fn connect_by_id(self: *Endpoint, node_id: key.NodeId, alpn: []const u8) !Connection {
        return self.connectById(node_id, alpn);
    }

    pub fn accept(self: *Endpoint) !Connection {
        if (self.closed_state) return error.EndpointClosed;
        const inner_conn = try self.inner.transport().accept();
        errdefer inner_conn.close();
        try self.rememberRemoteNode(inner_conn.remoteNodeId(), "accept");
        if (inner_conn.remoteAddress()) |ip| {
            try self.rememberRemoteObservedAddr(inner_conn.remoteNodeId(), ip, "accept");
        }
        self.metrics_state.accept_successes += 1;
        return .{ .endpoint = self, .inner = inner_conn };
    }

    pub fn tryAcceptReady(self: *Endpoint) !?Connection {
        if (self.closed_state) return error.EndpointClosed;
        const inner_conn = (try self.inner.tryAcceptReady()) orelse return null;
        errdefer inner_conn.close();
        try self.rememberRemoteNode(inner_conn.remoteNodeId(), "accept-ready");
        if (inner_conn.remoteAddress()) |ip| {
            try self.rememberRemoteObservedAddr(inner_conn.remoteNodeId(), ip, "accept-ready");
        }
        self.metrics_state.accept_successes += 1;
        return .{ .endpoint = self, .inner = inner_conn };
    }

    pub fn alpns(self: *const Endpoint) []const []const u8 {
        return self.alpn_slices[0..self.alpn_count];
    }

    fn validateAlpns(source: []const []const u8) error{InvalidAlpn}!void {
        if (source.len == 0 or source.len > max_alpns) return error.InvalidAlpn;
        for (source) |alpn| {
            if (alpn.len == 0 or alpn.len > max_alpn_len) return error.InvalidAlpn;
        }
    }

    fn loadAlpns(self: *Endpoint, source: []const []const u8) error{InvalidAlpn}!void {
        try validateAlpns(source);
        self.alpn_count = source.len;
        for (source, 0..) |alpn, i| {
            @memcpy(self.alpn_storage[i][0..alpn.len], alpn);
            self.alpn_storage[i][alpn.len] = 0;
            self.alpn_lens[i] = alpn.len;
            self.alpn_z[i] = self.alpn_storage[i][0..alpn.len :0];
            self.alpn_slices[i] = self.alpn_storage[i][0..alpn.len];
        }
    }

    fn connectAlpnMatches(self: *const Endpoint, alpn: []const u8) bool {
        // The frozen transport seam dials with the endpoint's configured ALPN.
        // Until that seam grows per-connect ALPN selection, reject other
        // advertised server ALPNs instead of silently dialing the wrong bytes.
        return self.alpn_count > 0 and std.mem.eql(u8, self.alpn_slices[0], alpn);
    }

    fn rememberRemoteAddr(self: *Endpoint, remote_addr: EndpointAddr, provenance: []const u8) !void {
        const info = try discovery.EndpointInfo.fromNodeAddrWithMetadata(self.allocator, remote_addr, null, .{
            .provenance = provenance,
            .last_updated = discovery.Timestamp.now(),
        });
        try self.putRemoteInfo(info);
    }

    fn rememberRemoteNode(self: *Endpoint, node_id: key.NodeId, provenance: []const u8) !void {
        const info = try discovery.EndpointInfo.fromPartsWithMetadata(self.allocator, node_id, &.{}, null, .{
            .provenance = provenance,
            .last_updated = discovery.Timestamp.now(),
        });
        try self.putRemoteInfo(info);
    }

    /// Merge a transport-observed peer socket address into the remote-info
    /// cache: the observed address AUGMENTS the record (union with already
    /// known addrs, existing user_data preserved) rather than replacing it,
    /// so a relay-URL record from discovery is never clobbered by the direct
    /// path observation.
    fn rememberRemoteObservedAddr(self: *Endpoint, node_id: key.NodeId, ip: net.IpAddress, provenance: []const u8) !void {
        const observed: TransportAddr = .{ .ip = ip };
        var addrs: std.ArrayList(TransportAddr) = .empty;
        defer addrs.deinit(self.allocator);
        try addrs.append(self.allocator, observed);
        var user_data: ?[]const u8 = null;
        if (self.remote_infos.get(node_id.bytes)) |existing| {
            for (existing.addrs) |item| {
                if (!item.eql(observed)) try addrs.append(self.allocator, item);
            }
            user_data = existing.user_data;
        }
        const info = try discovery.EndpointInfo.fromPartsWithMetadata(self.allocator, node_id, addrs.items, user_data, .{
            .provenance = provenance,
            .last_updated = discovery.Timestamp.now(),
        });
        try self.putRemoteInfo(info);
    }

    fn putRemoteInfo(self: *Endpoint, info: discovery.EndpointInfo) !void {
        var owned = info;
        errdefer owned.deinit(self.allocator);
        const gop = try self.remote_infos.getOrPut(owned.node_id.bytes);
        if (gop.found_existing) gop.value_ptr.deinit(self.allocator);
        gop.value_ptr.* = owned;
    }

    pub fn remoteInfo(self: *Endpoint, node_id: key.NodeId) !?discovery.EndpointInfo {
        const info = self.remote_infos.get(node_id.bytes) orelse return null;
        const owned = try info.clone(self.allocator);
        return owned;
    }

    pub fn remote_info(self: *Endpoint, node_id: key.NodeId) !?discovery.EndpointInfo {
        return self.remoteInfo(node_id);
    }
};

pub const Connection = struct {
    endpoint: *Endpoint,
    inner: tr.Connection,

    pub fn openBi(self: Connection) tr.Error!tr.BiStream {
        return self.inner.openBi();
    }

    pub fn acceptBi(self: Connection) tr.Error!tr.BiStream {
        return self.inner.acceptBi();
    }

    pub fn openUni(self: Connection) tr.Error!tr.SendStream {
        return self.inner.openUni();
    }

    pub fn acceptUni(self: Connection) tr.Error!tr.RecvStream {
        return self.inner.acceptUni();
    }

    pub fn remoteNodeId(self: Connection) key.NodeId {
        return self.inner.remoteNodeId();
    }

    pub fn alpn(self: Connection) ?[]const u8 {
        return self.inner.alpn();
    }

    /// The peer's socket address as observed by the transport, or null when
    /// the path has none (e.g. pure relay).
    pub fn remoteAddress(self: Connection) ?net.IpAddress {
        return self.inner.remoteAddress();
    }

    pub fn close(self: Connection) void {
        self.inner.close();
    }

    pub fn io(self: Connection) std.Io {
        return self.inner.io();
    }

    pub fn sendDatagram(self: Connection, bytes: []const u8) DatagramError!void {
        try factory.connectionSendDatagram(self.endpoint.inner, self.inner, bytes);
        self.endpoint.metrics_state.datagrams_sent += 1;
    }

    pub fn send_datagram(self: Connection, bytes: []const u8) DatagramError!void {
        return self.sendDatagram(bytes);
    }

    /// Reads one DATAGRAM into caller-owned storage. The returned slice points
    /// into `buffer`; null means the bounded wait elapsed without a datagram.
    pub fn readDatagram(self: Connection, buffer: []u8, timeout_ns: i64) DatagramError!?[]u8 {
        const out = try factory.connectionReadDatagram(self.endpoint.inner, self.inner, buffer, timeout_ns);
        if (out != null) self.endpoint.metrics_state.datagrams_received += 1;
        return out;
    }

    pub fn read_datagram(self: Connection, buffer: []u8, timeout_ns: i64) DatagramError!?[]u8 {
        return self.readDatagram(buffer, timeout_ns);
    }

    pub fn maxDatagramSize(self: Connection) ?usize {
        return factory.connectionMaxDatagramSize(self.endpoint.inner, self.inner);
    }

    /// Currently selected path (relay vs direct IP), or null if the engine
    /// has not selected one / does not yet expose selection. Required by
    /// patchbay NAT/path-migration oracle rows — connectivity alone is not
    /// enough evidence for those scenarios.
    pub fn selectedPath(self: Connection) ?factory.SelectedPath {
        return factory.connectionSelectedPath(self.endpoint.inner, self.inner);
    }

    pub fn selected_path(self: Connection) ?factory.SelectedPath {
        return self.selectedPath();
    }

    pub fn stats(self: Connection) tr.ConnectionStats {
        return self.inner.stats();
    }
};

test "public Endpoint Options are a Zig-native builder/config facade" {
    const opts = Options{
        .engine = factory.productEngine(),
        .secret_key = key.SecretKey.fromBytes([_]u8{0xAB} ** 32),
        .congestion_kind = .new_reno,
        .alpns = &.{ "one", "two" },
        .dns_resolver = .system,
        .proxy_url = "http://127.0.0.1:8080",
        .ca_tls_config = .insecure_skip_verify,
    };
    var config = try RuntimeConfig.init(opts);
    try std.testing.expectEqual(@as(usize, 2), opts.alpns.len);
    try std.testing.expectEqual(factory.CongestionKind.new_reno, opts.congestion_kind);
    try std.testing.expectEqual(DnsResolver.system, config.dns_resolver.?);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080", config.proxyUrl().?);
    try std.testing.expectEqual(CaTlsConfig.insecure_skip_verify, config.ca_tls_config.?);
    try std.testing.expect(@TypeOf(Builder{}) == Options);
}

test "public Endpoint connectById requires a configured discovery client" {
    const allocator = std.testing.allocator;
    const ep = try Endpoint.init(allocator, std.testing.io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xCD} ** 32),
        .alpns = &.{default_alpn},
    });
    defer ep.deinit();

    const remote = key.SecretKey.fromBytes([_]u8{0xCE} ** 32).public();
    try std.testing.expectError(error.DiscoveryUnavailable, ep.connectById(remote, default_alpn));
    try std.testing.expectEqual(@as(u64, 1), ep.metrics().connect_attempts);
    try std.testing.expectEqual(@as(u64, 0), ep.metrics().connect_successes);
}

test "public Endpoint address watch, runtime external addrs, relay status, and close waiter" {
    const allocator = std.testing.allocator;
    const ep = try Endpoint.init(allocator, std.testing.io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xC1} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .disabled,
    });
    defer ep.deinit();

    var watcher = ep.watchAddr();
    var initial = try watcher.get();
    defer initial.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), initial.version);
    try std.testing.expect(initial.endpoint_addr.id.eql(ep.id()));
    try std.testing.expect(initial.endpoint_addr.firstIpAddr() != null);
    try std.testing.expectEqual(HomeRelayState.disabled, ep.homeRelayStatus().state);

    const external_ip = try net.IpAddress.parse("203.0.113.7", 12345);
    try std.testing.expect(try ep.addExternalAddr(.{ .ip = external_ip }));
    try std.testing.expect(!try ep.addExternalAddr(.{ .ip = external_ip }));

    // The external-addr add published version 1 while the watcher sat at
    // version 0, so updated() returns it without blocking.
    var changed = try watcher.updated();
    defer changed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), changed.version);
    var ips = changed.endpoint_addr.ipAddrs();
    var saw_external = false;
    while (ips.next()) |ip| {
        if (std.meta.eql(ip, external_ip)) saw_external = true;
    }
    try std.testing.expect(saw_external);

    try std.testing.expect(try ep.removeExternalAddr(.{ .ip = external_ip }));
    var removed = try ep.addr();
    defer removed.deinit(allocator);
    var after_ips = removed.ipAddrs();
    while (after_ips.next()) |ip| {
        try std.testing.expect(!std.meta.eql(ip, external_ip));
    }

    ep.close();
    try std.testing.expect(ep.closed());
    ep.wait_closed();
    try std.testing.expectEqual(HomeRelayState.disabled, ep.home_relay_status().state);
    try std.testing.expectError(error.EndpointClosed, ep.setAlpns(&.{default_alpn}));
    // Post-close address mutation is rejected too (close-waiter parity: the
    // public API fails closed on every mutation path, not just dial/accept).
    try std.testing.expectError(error.EndpointClosed, ep.addExternalAddr(.{ .ip = external_ip }));
    try std.testing.expectError(error.EndpointClosed, ep.removeExternalAddr(.{ .ip = external_ip }));
}

test "public Endpoint netReport is endpoint-composed" {
    const allocator = std.testing.allocator;
    const ep = try Endpoint.init(allocator, std.testing.io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xCF} ** 32),
        .alpns = &.{default_alpn},
    });
    defer ep.deinit();

    // Relay-disabled endpoint: the report names no relay and still collects
    // real UDP path facts (never a throwaway-relay stand-in).
    const report = try ep.netReport();
    defer report.deinit(allocator);
    try std.testing.expect(report.relay_url == null);
    try std.testing.expect(!report.relay_connected);
    try std.testing.expect(report.relay_latency_us == null);
    try std.testing.expect(report.udp_ipv4_loopback);
}

// Mutation-red control for core-net-report: the report MUST reflect the
// endpoint's live state — a throwaway-relay probe would report a URL the
// endpoint never configured and connected=false after online(); both are
// asserted against the endpoint's real configured home relay.
test "Endpoint netReport reflects the live configured home relay" {
    const allocator = std.testing.allocator;
    const relay_server = @import("relay/server.zig");
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try relay_server.Server.init(allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .tls_cert_path = "relay-testdata/test-cert.pem",
        .tls_key_path = "relay-testdata/test-key.pem",
    });
    const relay_accept = try std.Thread.spawn(.{}, struct {
        fn run(srv: *relay_server.Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        relay_accept.join();
    }

    var url_buf: [64]u8 = undefined;
    const relay_url = try std.fmt.bufPrint(&url_buf, "wss://127.0.0.1:{d}/relay", .{server.localAddress().getPort()});

    const ep = try Endpoint.init(allocator, io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xD0} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .custom,
        .home_relay_url = relay_url,
        .ca_tls_config = .insecure_skip_verify,
        .publish_on_online = false,
    });
    defer ep.deinit();

    // Pre-online: configured but not connected.
    {
        const report = try ep.netReport();
        defer report.deinit(allocator);
        try std.testing.expectEqualStrings(relay_url, report.relay_url.?);
        try std.testing.expect(!report.relay_connected);
        try std.testing.expect(report.relay_latency_us != null);
    }

    try ep.online();
    try std.testing.expect(ep.isOnline());

    // Post-online: the live session shows through.
    {
        const report = try ep.netReport();
        defer report.deinit(allocator);
        try std.testing.expectEqualStrings(relay_url, report.relay_url.?);
        try std.testing.expect(report.relay_connected);
        try std.testing.expect(report.relay_latency_us != null);
        try std.testing.expect(report.udp_ipv4_loopback);
    }
}

test "Endpoint.online disabled mode is immediate" {
    const allocator = std.testing.allocator;
    const ep = try Endpoint.init(allocator, std.testing.io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xD1} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .disabled,
    });
    defer ep.deinit();
    try ep.online();
    try std.testing.expect(ep.isOnline());
}

test "Endpoint.online custom home relay applies ca_tls_config (wss effect)" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const relay_server = @import("relay/server.zig");

    var server = try relay_server.Server.init(allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .tls_cert_path = "relay-testdata/test-cert.pem",
        .tls_key_path = "relay-testdata/test-key.pem",
    });
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *relay_server.Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        accept_thread.join();
    }

    var url_buf: [64]u8 = undefined;
    const relay_url = try std.fmt.bufPrint(&url_buf, "wss://127.0.0.1:{d}/relay", .{server.localAddress().getPort()});

    // system_roots must REJECT the self-signed test cert.
    // publish_on_online=false: this test isolates DERP TLS, not pkarr.
    const strict = try Endpoint.init(allocator, io, .{
        .engine = factory.productEngine(),
        .secret_key = key.SecretKey.fromBytes([_]u8{0xD2} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .custom,
        .home_relay_url = relay_url,
        .ca_tls_config = .system_roots,
        .publish_on_online = false,
    });
    defer strict.deinit();
    try std.testing.expectError(error.TlsHandshakeFailed, strict.online());
    try std.testing.expect(!strict.isOnline());
    const failed_status = strict.home_relay_status();
    try std.testing.expectEqual(HomeRelayState.failed, failed_status.state);
    try std.testing.expectEqual(error.TlsHandshakeFailed, failed_status.last_error.?);

    // insecure_skip_verify must ACCEPT the same cert — effect, not retention.
    const loose = try Endpoint.init(allocator, io, .{
        .engine = factory.productEngine(),
        .secret_key = key.SecretKey.fromBytes([_]u8{0xD3} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .custom,
        .home_relay_url = relay_url,
        .ca_tls_config = .insecure_skip_verify,
        .publish_on_online = false,
    });
    defer loose.deinit();
    try loose.online();
    try std.testing.expect(loose.isOnline());
    try std.testing.expectEqualStrings(relay_url, loose.homeRelayUrl().?);
    try std.testing.expect(!loose.didPublishOnOnline());
}

test "Endpoint.online custom + local pkarr publishes relay-only record" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const relay_server = @import("relay/server.zig");
    const discovery_server = @import("discovery/server.zig");

    var server = try relay_server.Server.init(allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .tls_cert_path = "relay-testdata/test-cert.pem",
        .tls_key_path = "relay-testdata/test-key.pem",
    });
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *relay_server.Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        accept_thread.join();
    }

    var store = discovery.PacketStore.init(allocator);
    defer store.deinit();
    var pkarr_listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer pkarr_listener.deinit(io);
    const pkarr_port = pkarr_listener.socket.address.getPort();
    const ServeCtx = struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        listener: *std.Io.net.Server,
        store: *discovery.PacketStore,
        count: usize,
    };
    var sctx: ServeCtx = .{
        .io = io,
        .allocator = allocator,
        .listener = &pkarr_listener,
        .store = &store,
        .count = 2, // PUT + GET
    };
    const pkarr_thread = try std.Thread.spawn(.{}, struct {
        fn run(c: *ServeCtx) void {
            var i: usize = 0;
            while (i < c.count) : (i += 1) {
                const stream = c.listener.accept(c.io) catch continue;
                defer stream.close(c.io);
                discovery_server.handleStream(c.io, c.allocator, c.store, stream) catch {};
            }
        }
    }.run, .{&sctx});
    defer pkarr_thread.join();

    var url_buf: [64]u8 = undefined;
    const relay_url = try std.fmt.bufPrint(&url_buf, "wss://127.0.0.1:{d}/relay", .{server.localAddress().getPort()});
    var pkarr_buf: [64]u8 = undefined;
    const pkarr_url = try std.fmt.bufPrint(&pkarr_buf, "http://127.0.0.1:{d}/pkarr", .{pkarr_port});

    const ep = try Endpoint.init(allocator, io, .{
        .engine = factory.productEngine(),
        .secret_key = key.SecretKey.fromBytes([_]u8{0xD4} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .custom,
        .home_relay_url = relay_url,
        .pkarr_relay_url = pkarr_url,
        .ca_tls_config = .insecure_skip_verify,
        .publish_on_online = true,
    });
    defer ep.deinit();
    try ep.online();
    try std.testing.expect(ep.isOnline());
    try std.testing.expect(ep.didPublishOnOnline());

    // Resolve what was published — must be relay-only (no IP).
    var http: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http.deinit();
    var resolved = try discovery.resolvePkarrRelay(allocator, &http, pkarr_url, ep.id());
    defer resolved.deinit(allocator);
    try std.testing.expect(resolved.firstRelayUrl() != null);
    var ip_it = resolved.ipAddrs();
    try std.testing.expect(ip_it.next() == null);
}

test "Endpoint.online default mode resolves first prod map URL without dialing n0" {
    // Structural: resolveHomeRelayUrl path for .default without network.
    // We do not call online() here (would dial public n0).
    const allocator = std.testing.allocator;
    const first = try defaults.prod.firstRelayUrl(allocator);
    defer first.deinit(allocator);
    try std.testing.expect(std.mem.indexOf(u8, first.asString(), "relay.n0.iroh.link") != null);

    const ep = try Endpoint.init(allocator, std.testing.io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xD5} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .default,
        .publish_on_online = false,
    });
    defer ep.deinit();
    try std.testing.expect(ep.relayMode() == .default or ep.relayMode() == .staging);
}

// REAL NodeId-only path: local wss home relay + local pkarr + two public
// Endpoints. Client dials server.id() with allow_direct_addresses=false and
// completes a bi-stream transfer. No caller-supplied direct IP.
test "Endpoint NodeId-only connect via home relay + pkarr (no direct address)" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const relay_server = @import("relay/server.zig");
    const discovery_server = @import("discovery/server.zig");

    var server = try relay_server.Server.init(allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .tls_cert_path = "relay-testdata/test-cert.pem",
        .tls_key_path = "relay-testdata/test-key.pem",
    });
    const relay_accept = try std.Thread.spawn(.{}, struct {
        fn run(srv: *relay_server.Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        relay_accept.join();
    }

    var store = discovery.PacketStore.init(allocator);
    defer store.deinit();
    var pkarr_listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer pkarr_listener.deinit(io);
    const pkarr_port = pkarr_listener.socket.address.getPort();
    // Serve several HTTP requests (server publish PUT, client resolve GET, retries).
    const ServeCtx = struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        listener: *std.Io.net.Server,
        store: *discovery.PacketStore,
        stopped: *std.atomic.Value(bool),
    };
    var stopped = std.atomic.Value(bool).init(false);
    var sctx: ServeCtx = .{
        .io = io,
        .allocator = allocator,
        .listener = &pkarr_listener,
        .store = &store,
        .stopped = &stopped,
    };
    const pkarr_thread = try std.Thread.spawn(.{}, struct {
        fn run(c: *ServeCtx) void {
            while (!c.stopped.load(.acquire)) {
                const stream = c.listener.accept(c.io) catch continue;
                defer stream.close(c.io);
                discovery_server.handleStream(c.io, c.allocator, c.store, stream) catch {};
            }
        }
    }.run, .{&sctx});
    defer {
        stopped.store(true, .release);
        // Unblock accept with a dummy connection.
        if (pkarr_listener.socket.address.connect(io, .{ .mode = .stream }) catch null) |s| {
            s.close(io);
        }
        pkarr_thread.join();
    }

    var url_buf: [64]u8 = undefined;
    const relay_url = try std.fmt.bufPrint(&url_buf, "wss://127.0.0.1:{d}/relay", .{server.localAddress().getPort()});
    var pkarr_buf: [64]u8 = undefined;
    const pkarr_url = try std.fmt.bufPrint(&pkarr_buf, "http://127.0.0.1:{d}/pkarr", .{pkarr_port});

    const node_id_alpn: [:0]const u8 = "iroh-node-id-only/0";
    const server_ep = try Endpoint.init(allocator, io, .{
        .engine = factory.productEngine(),
        .secret_key = key.SecretKey.fromBytes([_]u8{0xE0} ** 32),
        .bind_address = .{ .ip4 = .loopback(0) },
        .alpns = &.{node_id_alpn},
        .accept_unknown_peer = true,
        .relay_mode = .custom,
        .home_relay_url = relay_url,
        .pkarr_relay_url = pkarr_url,
        .ca_tls_config = .insecure_skip_verify,
        .publish_on_online = true,
    });
    defer server_ep.deinit();
    try server_ep.online();
    try std.testing.expect(server_ep.didPublishOnOnline());
    const server_id = server_ep.id();

    var http: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http.deinit();
    var discovery_client = discovery.DiscoveryClient{
        .allocator = allocator,
        .http_client = &http,
        .pkarr_relay_url = pkarr_url,
        .doh_url = null, // force pkarr path only
    };

    const client_ep = try Endpoint.init(allocator, io, .{
        .engine = factory.productEngine(),
        .secret_key = key.SecretKey.fromBytes([_]u8{0xE1} ** 32),
        .bind_address = .{ .ip4 = .loopback(0) },
        .alpns = &.{node_id_alpn},
        .discovery_client = &discovery_client,
        .relay_mode = .custom,
        .home_relay_url = relay_url,
        .pkarr_relay_url = pkarr_url,
        .ca_tls_config = .insecure_skip_verify,
        .publish_on_online = false, // client need not publish for this proof
    });
    defer client_ep.deinit();
    try client_ep.online();

    // Preflight: resolve is relay-only.
    {
        var info = try discovery_client.resolve(server_id);
        defer info.deinit(allocator);
        try std.testing.expect(info.firstRelayUrl() != null);
        var ip_it = info.ipAddrs();
        try std.testing.expect(ip_it.next() == null);
    }

    var accept_future = io.async(struct {
        fn run(ep: *Endpoint) !Connection {
            return ep.accept();
        }
    }.run, .{server_ep});

    const client_conn = try client_ep.connectByIdWithOpts(server_id, node_id_alpn, .{
        .allow_direct_addresses = false,
    });
    defer client_conn.close();

    const server_conn = try accept_future.await(io);
    defer server_conn.close();

    const payload = "node-id-only-hello";
    const client_stream = try client_conn.openBi();
    try client_stream.send.writer().writeAll(payload);
    try client_stream.send.finish();

    const server_stream = try server_conn.acceptBi();
    var buf: [64]u8 = undefined;
    const n = try server_stream.recv.reader().readSliceShort(&buf);
    try std.testing.expectEqualStrings(payload, buf[0..n]);

    var client_remote = (try client_ep.remoteInfo(server_id)).?;
    defer client_remote.deinit(allocator);
    try std.testing.expectEqualStrings("connect-by-id", client_remote.provenance.?);
    try std.testing.expect(client_remote.last_updated != null);
    try std.testing.expect(client_remote.firstRelayUrl() != null);

    var server_remote = (try server_ep.remoteInfo(client_ep.id())).?;
    defer server_remote.deinit(allocator);
    try std.testing.expectEqualStrings("accept", server_remote.provenance.?);
    try std.testing.expect(server_remote.last_updated != null);
}

// Mutation-red control for core-close-waiters: close() must deterministically
// close LIVE backend connections (peer observes ConnectionLost, not a
// facade-only flag), wake waitClosed() waiters, and reject post-close
// mutation. A facade-only close leaves the peer's acceptBi blocking to its
// deadline (error.Timeout), which this test distinguishes.
test "Endpoint.close closes live backend connections, wakes waiters, rejects mutation" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for ([_]factory.Engine{ .picoquic, .noq }) |eng| {
        const compiled = switch (eng) {
            .picoquic => product_flags.has_picoquic,
            .noq => product_flags.has_noq,
        };
        if (compiled) {
            const close_alpn: [:0]const u8 = "iroh-close-waiters/0";
            const server_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xF0} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{close_alpn},
                .accept_unknown_peer = true,
            });
            defer server_ep.deinit();
            const client_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xF1} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{close_alpn},
            });
            defer client_ep.deinit();

            var accept_future = io.async(struct {
                fn run(ep: *Endpoint) !Connection {
                    return ep.accept();
                }
            }.run, .{server_ep});

            var remote = try EndpointAddr.fromParts(
                allocator,
                server_ep.id(),
                &.{.{ .ip = server_ep.localAddress() }},
            );
            defer remote.deinit(allocator);
            const client_conn = try client_ep.connect(remote, close_alpn);
            defer client_conn.close();
            const server_conn = try accept_future.await(io);
            defer server_conn.close();

            // A waiter parked in waitClosed() before close() must be woken.
            var done = std.atomic.Value(bool).init(false);
            const waiter_thread = try std.Thread.spawn(.{}, struct {
                fn run(ep: *Endpoint, flag: *std.atomic.Value(bool)) void {
                    ep.waitClosed();
                    flag.store(true, .release);
                }
            }.run, .{ server_ep, &done });

            server_ep.close();
            try std.testing.expect(server_ep.closed());
            try std.testing.expectError(error.EndpointClosed, server_ep.accept());
            const post_close_addr = try net.IpAddress.parse("203.0.113.9", 9999);
            try std.testing.expectError(error.EndpointClosed, server_ep.addExternalAddr(.{ .ip = post_close_addr }));

            var waited: usize = 0;
            while (!done.load(.acquire) and waited < 200) : (waited += 1) {
                io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
            }
            try std.testing.expect(done.load(.acquire));
            waiter_thread.join();

            // The peer observes the deterministic backend close, never the
            // Timeout a facade-only close would leave it to. The error is
            // engine-defined: ConnectionLost (picoquic waiter sweep) or
            // NotConnected (noq reclaims the entry before the accept runs).
            if (client_conn.acceptBi()) |_| {
                return error.TestUnexpectedResult; // close did not reach the backend
            } else |err| switch (err) {
                error.ConnectionLost, error.NotConnected => {},
                else => return err,
            }
        }
    }
}

// Mutation-red control for core-endpoint-address-watch: updated() must BLOCK
// until a real mutation publishes a new address version — a snapshot-only
// stub or a missing condvar broadcast leaves the watcher thread parked and
// fails the bounded-wait assertion — and close() must terminate the feed.
test "Endpoint address watcher blocks until mutation and terminates on close" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ep = try Endpoint.init(allocator, io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xC3} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .disabled,
    });
    defer ep.deinit();

    var watcher = ep.watchAddr();
    var initial = try watcher.get();
    defer initial.deinit(allocator);

    const WatchCtx = struct {
        watcher: *AddressWatcher,
        result: ?AddressSnapshot = null,
        // 0 = still parked/running, 1 = woke with a snapshot, 2 = feed terminated.
        state: std.atomic.Value(u8) = .init(0),

        fn run(ctx: *@This()) void {
            const got = ctx.watcher.updated() catch {
                ctx.state.store(2, .release);
                return;
            };
            ctx.result = got;
            ctx.state.store(1, .release);
        }
    };

    // Phase 1: a parked watcher wakes with the new version on mutation.
    var ctx1: WatchCtx = .{ .watcher = &watcher };
    const t1 = try std.Thread.spawn(.{}, WatchCtx.run, .{&ctx1});
    io.sleep(std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    try std.testing.expectEqual(@as(u8, 0), ctx1.state.load(.acquire)); // no spurious wake
    const watched_ip = try net.IpAddress.parse("203.0.113.8", 12345);
    try std.testing.expect(try ep.addExternalAddr(.{ .ip = watched_ip }));
    var waited: usize = 0;
    while (ctx1.state.load(.acquire) == 0 and waited < 200) : (waited += 1) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    try std.testing.expectEqual(@as(u8, 1), ctx1.state.load(.acquire));
    t1.join();
    try std.testing.expect(ctx1.result != null);
    var snap1 = ctx1.result.?;
    defer snap1.deinit(allocator);
    try std.testing.expect(snap1.version > initial.version);
    var saw_watched = false;
    var ips = snap1.endpoint_addr.ipAddrs();
    while (ips.next()) |ip| {
        if (std.meta.eql(ip, watched_ip)) saw_watched = true;
    }
    try std.testing.expect(saw_watched);

    // Phase 2: close() terminates a parked feed with error.EndpointClosed.
    var ctx2: WatchCtx = .{ .watcher = &watcher };
    const t2 = try std.Thread.spawn(.{}, WatchCtx.run, .{&ctx2});
    io.sleep(std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    try std.testing.expectEqual(@as(u8, 0), ctx2.state.load(.acquire)); // still parked
    ep.close();
    waited = 0;
    while (ctx2.state.load(.acquire) == 0 and waited < 200) : (waited += 1) {
        io.sleep(std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    try std.testing.expectEqual(@as(u8, 2), ctx2.state.load(.acquire));
    t2.join();
    try std.testing.expect(ctx2.result == null);
}


// Mutation-red control for core-endpoint-remote-info-cache: after a real
// connect/accept, the ACCEPT side's remote-info record must carry the
// transport-observed peer socket address — pre-seam it was NodeId-only, so
// an assertion on the observed loopback addr fails without the seam.
test "Endpoint remote info caches transport-observed accept-side addresses" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for ([_]factory.Engine{ .picoquic, .noq }) |eng| {
        const compiled = switch (eng) {
            .picoquic => product_flags.has_picoquic,
            .noq => product_flags.has_noq,
        };
        if (compiled) {
            const info_alpn: [:0]const u8 = "iroh-remote-info/0";
            const server_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xF2} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{info_alpn},
                .accept_unknown_peer = true,
            });
            defer server_ep.deinit();
            const client_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xF3} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{info_alpn},
            });
            defer client_ep.deinit();

            var accept_future = io.async(struct {
                fn run(ep: *Endpoint) !Connection {
                    return ep.accept();
                }
            }.run, .{server_ep});

            var remote = try EndpointAddr.fromParts(
                allocator,
                server_ep.id(),
                &.{.{ .ip = server_ep.localAddress() }},
            );
            defer remote.deinit(allocator);
            const client_conn = try client_ep.connect(remote, info_alpn);
            defer client_conn.close();
            const server_conn = try accept_future.await(io);
            defer server_conn.close();

            // The transport-observed address is also readable off the conn.
            try std.testing.expect(server_conn.remoteAddress() != null);

            // Accept side: the server record carries the client's observed
            // socket address (its bound loopback addr), not just the NodeId.
            var server_rec = (try server_ep.remoteInfo(client_ep.id())) orelse return error.TestUnexpectedResult;
            defer server_rec.deinit(allocator);
            const client_local = client_ep.localAddress();
            var found_observed = false;
            var server_ips = server_rec.ipAddrs();
            while (server_ips.next()) |ip| {
                if (std.meta.eql(ip, client_local)) found_observed = true;
            }
            try std.testing.expect(found_observed);

            // Connect side: the client record carries the server's address
            // (dialed == observed on loopback).
            var client_rec = (try client_ep.remoteInfo(server_ep.id())) orelse return error.TestUnexpectedResult;
            defer client_rec.deinit(allocator);
            var found_server = false;
            var client_ips = client_rec.ipAddrs();
            while (client_ips.next()) |ip| {
                if (std.meta.eql(ip, server_ep.localAddress())) found_server = true;
            }
            try std.testing.expect(found_server);
        }
    }
}


// Mutation-red control for core-endpoint-runtime-relay-map: addRelay must
// actually store (the relayMap snapshot proves it — a registry that stores
// nothing fails), removeRelay must actually drop it, the watcher feed must
// wake on both, and post-close mutation must fail closed.
test "Endpoint runtime relay map add/remove, watcher wake, close guard" {
    const allocator = std.testing.allocator;
    const ep = try Endpoint.init(allocator, std.testing.io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xC4} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .disabled,
    });
    defer ep.deinit();

    // Disabled mode seeds an empty set.
    {
        const urls = try ep.relayMap(allocator);
        defer {
            for (urls) |u| allocator.free(u);
            allocator.free(urls);
        }
        try std.testing.expectEqual(@as(usize, 0), urls.len);
    }

    var watcher = ep.watchAddr();
    var before = try watcher.get();
    defer before.deinit(allocator);

    const relay_url = "https://relay.example.com";
    try std.testing.expect(try ep.addRelay(relay_url));
    try std.testing.expect(!try ep.addRelay(relay_url)); // dedup, no version bump

    // The add published a new address version; the parked feed observes it.
    var after_add = try watcher.updated();
    defer after_add.deinit(allocator);
    try std.testing.expectEqual(before.version + 1, after_add.version);

    // The stored URL is the canonicalized form.
    {
        const urls = try ep.relayMap(allocator);
        defer {
            for (urls) |u| allocator.free(u);
            allocator.free(urls);
        }
        try std.testing.expectEqual(@as(usize, 1), urls.len);
        try std.testing.expect(std.mem.startsWith(u8, urls[0], "https://relay.example.com"));
    }

    try std.testing.expect(try ep.removeRelay(relay_url));
    try std.testing.expect(!try ep.removeRelay(relay_url)); // already gone
    var after_remove = try watcher.updated();
    defer after_remove.deinit(allocator);
    try std.testing.expectEqual(after_add.version + 1, after_remove.version);

    ep.close();
    try std.testing.expectError(error.EndpointClosed, ep.addRelay(relay_url));
    try std.testing.expectError(error.EndpointClosed, ep.removeRelay(relay_url));
}

// The runtime set is seeded from the mode's static map and is what home-relay
// resolution consults: emptying it resolves no home relay (upstream relay-map
// removal behavior).
test "Endpoint runtime relay map seeded from mode map and consulted" {
    const allocator = std.testing.allocator;
    const ep = try Endpoint.init(allocator, std.testing.io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xC5} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .staging,
        .publish_on_online = false,
    });
    defer ep.deinit();

    const urls = try ep.relayMap(allocator);
    defer {
        for (urls) |u| allocator.free(u);
        allocator.free(urls);
    }
    try std.testing.expect(urls.len > 0);

    // Remove every seeded relay; home-relay resolution then has nothing to
    // pick from and online() cannot proceed.
    for (urls) |u| {
        try std.testing.expect(try ep.remove_relay(u));
    }
    const empty = try ep.relayMap(allocator);
    defer allocator.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
    try std.testing.expectError(error.HomeRelayUrlRequired, ep.online());
}


// Mutation-red control for core-endpoint-runtime-external-addrs: a runtime
// external address added before online() must travel in the published pkarr
// record — a relay-only publish (the pre-change behavior, or a missing
// .unfiltered filter) resolves back with zero IP addrs and fails here.
test "Endpoint.online publishes advertised external addresses via pkarr" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const relay_server = @import("relay/server.zig");
    const discovery_server = @import("discovery/server.zig");

    var server = try relay_server.Server.init(allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .tls_cert_path = "relay-testdata/test-cert.pem",
        .tls_key_path = "relay-testdata/test-key.pem",
    });
    const accept_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: *relay_server.Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        accept_thread.join();
    }

    var store = discovery.PacketStore.init(allocator);
    defer store.deinit();
    var pkarr_listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer pkarr_listener.deinit(io);
    const pkarr_port = pkarr_listener.socket.address.getPort();
    const ServeCtx = struct {
        io: std.Io,
        allocator: std.mem.Allocator,
        listener: *std.Io.net.Server,
        store: *discovery.PacketStore,
        count: usize,
    };
    var sctx: ServeCtx = .{
        .io = io,
        .allocator = allocator,
        .listener = &pkarr_listener,
        .store = &store,
        .count = 2, // PUT + GET
    };
    const pkarr_thread = try std.Thread.spawn(.{}, struct {
        fn run(c: *ServeCtx) void {
            var i: usize = 0;
            while (i < c.count) : (i += 1) {
                const stream = c.listener.accept(c.io) catch continue;
                defer stream.close(c.io);
                discovery_server.handleStream(c.io, c.allocator, c.store, stream) catch {};
            }
        }
    }.run, .{&sctx});
    defer pkarr_thread.join();

    var url_buf: [64]u8 = undefined;
    const relay_url = try std.fmt.bufPrint(&url_buf, "wss://127.0.0.1:{d}/relay", .{server.localAddress().getPort()});
    var pkarr_buf: [64]u8 = undefined;
    const pkarr_url = try std.fmt.bufPrint(&pkarr_buf, "http://127.0.0.1:{d}/pkarr", .{pkarr_port});

    const ep = try Endpoint.init(allocator, io, .{
        .engine = factory.productEngine(),
        .secret_key = key.SecretKey.fromBytes([_]u8{0xD6} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .custom,
        .home_relay_url = relay_url,
        .pkarr_relay_url = pkarr_url,
        .ca_tls_config = .insecure_skip_verify,
        .publish_on_online = true,
    });
    defer ep.deinit();

    const external_ip = try net.IpAddress.parse("203.0.113.20", 4321);
    try std.testing.expect(try ep.addExternalAddr(.{ .ip = external_ip }));
    try ep.online();
    try std.testing.expect(ep.didPublishOnOnline());

    // Resolve what was published: the advertised external address must be in
    // the record alongside the home relay.
    var http: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http.deinit();
    var resolved = try discovery.resolvePkarrRelay(allocator, &http, pkarr_url, ep.id());
    defer resolved.deinit(allocator);
    try std.testing.expect(resolved.firstRelayUrl() != null);
    var found_external = false;
    var ip_it = resolved.ipAddrs();
    while (ip_it.next()) |ip| {
        if (std.meta.eql(ip, external_ip)) found_external = true;
    }
    try std.testing.expect(found_external);
}

// Mutation-red control for core-address-lookup-services-runtime-merge +
// core-discovery-composition: two providers each holding HALF the reachability
// (one the direct IP, one a relay URL + a duplicate of the IP) must merge into
// one dialed address set — a "first provider only" stub connects but the
// remoteInfo record would lack the relay kind, and missing dedup would record
// the IP twice; both are asserted on the merged record.
test "Endpoint connectById merges composed address-lookup services over a real loopback" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for ([_]factory.Engine{ .picoquic, .noq }) |eng| {
        const compiled = switch (eng) {
            .picoquic => product_flags.has_picoquic,
            .noq => product_flags.has_noq,
        };
        if (compiled) {
            const compose_alpn: [:0]const u8 = "iroh-discovery-compose/0";
            const server_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xA0} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{compose_alpn},
                .accept_unknown_peer = true,
            });
            defer server_ep.deinit();
            const server_id = server_ep.id();

            // Provider 1: direct IP only. Provider 2: (inert) loopback relay
            // URL + the SAME direct IP (cross-provider dedup proof).
            var ip_only = discovery_address_lookup.StaticLookup.init(allocator);
            defer ip_only.deinit();
            {
                var ea = try EndpointAddr.fromParts(allocator, server_id, &.{.{ .ip = server_ep.localAddress() }});
                defer ea.deinit(allocator);
                try ip_only.setEndpointAddr(ea, null);
            }
            const dead_relay = try addr_mod.RelayUrl.parse(allocator, "wss://127.0.0.1:1/relay");
            defer dead_relay.deinit(allocator);
            var relay_plus_ip = discovery_address_lookup.StaticLookup.init(allocator);
            defer relay_plus_ip.deinit();
            {
                var ea = try EndpointAddr.fromParts(allocator, server_id, &.{
                    .{ .relay = dead_relay },
                    .{ .ip = server_ep.localAddress() },
                });
                defer ea.deinit(allocator);
                try relay_plus_ip.setEndpointAddr(ea, null);
            }

            const client_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xA1} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{compose_alpn},
                .address_lookup_services = &.{ ip_only.asLookup(), relay_plus_ip.asLookup() },
            });
            defer client_ep.deinit();
            try std.testing.expectEqual(@as(usize, 2), client_ep.addressLookupServiceCount());

            var accept_future = io.async(struct {
                fn run(ep: *Endpoint) !Connection {
                    return ep.accept();
                }
            }.run, .{server_ep});

            const client_conn = try client_ep.connectById(server_id, compose_alpn);
            defer client_conn.close();
            const server_conn = try accept_future.await(io);
            defer server_conn.close();

            const payload = "composed-discovery-hello";
            const client_stream = try client_conn.openBi();
            try client_stream.send.writer().writeAll(payload);
            try client_stream.send.finish();
            const server_stream = try server_conn.acceptBi();
            var buf: [64]u8 = undefined;
            const n = try server_stream.recv.reader().readSliceShort(&buf);
            try std.testing.expectEqualStrings(payload, buf[0..n]);

            // The merged record carries BOTH kinds exactly once each.
            var merged = (try client_ep.remoteInfo(server_id)).?;
            defer merged.deinit(allocator);
            var relay_count: usize = 0;
            var ip_count: usize = 0;
            for (merged.addrs) |ta| {
                if (ta.isRelay()) relay_count += 1;
                if (ta.isIp()) ip_count += 1;
            }
            try std.testing.expectEqual(@as(usize, 1), relay_count);
            try std.testing.expectEqual(@as(usize, 1), ip_count);
            try std.testing.expectEqualStrings("connect-by-id", merged.provenance.?);
        }
    }
}

// Mutation-red control for runtime add/clear: connectById must fail closed
// with DiscoveryUnavailable when the registry is empty, succeed after a
// runtime addAddressLookupService, fail again after clearAddressLookupServices,
// and reject registry mutation after close(). A registry that ignores runtime
// mutation fails at least one of these transitions.
test "Endpoint runtime address-lookup add and clear gate connectById" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for ([_]factory.Engine{ .picoquic, .noq }) |eng| {
        const compiled = switch (eng) {
            .picoquic => product_flags.has_picoquic,
            .noq => product_flags.has_noq,
        };
        if (compiled) {
            const runtime_alpn: [:0]const u8 = "iroh-discovery-runtime/0";
            const server_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xA2} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{runtime_alpn},
                .accept_unknown_peer = true,
            });
            defer server_ep.deinit();
            const server_id = server_ep.id();

            var static = discovery_address_lookup.StaticLookup.init(allocator);
            defer static.deinit();
            {
                var ea = try EndpointAddr.fromParts(allocator, server_id, &.{.{ .ip = server_ep.localAddress() }});
                defer ea.deinit(allocator);
                try static.setEndpointAddr(ea, null);
            }

            const client_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xA3} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{runtime_alpn},
            });
            defer client_ep.deinit();

            // Empty registry: explicit DiscoveryUnavailable, no dial attempted.
            try std.testing.expectEqual(@as(usize, 0), client_ep.addressLookupServiceCount());
            try std.testing.expectError(
                error.DiscoveryUnavailable,
                client_ep.connectById(server_id, runtime_alpn),
            );

            // Runtime add makes the same call connect for real.
            try client_ep.addAddressLookupService(static.asLookup());
            try std.testing.expectEqual(@as(usize, 1), client_ep.addressLookupServiceCount());
            var accept_future = io.async(struct {
                fn run(ep: *Endpoint) !Connection {
                    return ep.accept();
                }
            }.run, .{server_ep});
            const client_conn = try client_ep.connectById(server_id, runtime_alpn);
            defer client_conn.close();
            const server_conn = try accept_future.await(io);
            defer server_conn.close();

            // Clear returns to the fail-closed state.
            try client_ep.clearAddressLookupServices();
            try std.testing.expectEqual(@as(usize, 0), client_ep.addressLookupServiceCount());
            try std.testing.expectError(
                error.DiscoveryUnavailable,
                client_ep.connectById(server_id, runtime_alpn),
            );

            // Post-close registry mutation is rejected.
            client_ep.close();
            try std.testing.expectError(error.EndpointClosed, client_ep.addAddressLookupService(static.asLookup()));
            try std.testing.expectError(error.EndpointClosed, client_ep.clearAddressLookupServices());
        }
    }
}

// Mutation-red control for core-address-lookup-endpoint-aware-builder: the
// builder MUST be invoked with the fully-constructed endpoint during init —
// asserted by capturing the endpoint's own NodeId inside buildFn — and its
// resolver must actually join the registry (a skipped registration leaves
// connectById at DiscoveryUnavailable).
test "Endpoint address-lookup builder receives the constructed endpoint and joins the registry" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const BuilderProbe = struct {
        allocator: std.mem.Allocator,
        server_id: key.NodeId,
        server_ip: net.IpAddress,
        static: discovery_address_lookup.StaticLookup,
        saw_endpoint_id: ?key.NodeId = null,
        build_calls: usize = 0,

        fn build(context: *anyopaque, ep: *Endpoint) anyerror!discovery_address_lookup.AddressLookup {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.build_calls += 1;
            self.saw_endpoint_id = ep.id();
            var ea = try EndpointAddr.fromParts(self.allocator, self.server_id, &.{.{ .ip = self.server_ip }});
            defer ea.deinit(self.allocator);
            try self.static.setEndpointAddr(ea, null);
            return self.static.asLookup();
        }
    };

    inline for ([_]factory.Engine{ .picoquic, .noq }) |eng| {
        const compiled = switch (eng) {
            .picoquic => product_flags.has_picoquic,
            .noq => product_flags.has_noq,
        };
        if (compiled) {
            const builder_alpn: [:0]const u8 = "iroh-discovery-builder/0";
            const server_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xA4} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{builder_alpn},
                .accept_unknown_peer = true,
            });
            defer server_ep.deinit();

            var probe: BuilderProbe = .{
                .allocator = allocator,
                .server_id = server_ep.id(),
                .server_ip = server_ep.localAddress(),
                .static = discovery_address_lookup.StaticLookup.init(allocator),
            };
            defer probe.static.deinit();

            const client_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xA5} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{builder_alpn},
                .address_lookup_builders = &.{.{ .context = &probe, .buildFn = BuilderProbe.build }},
            });
            defer client_ep.deinit();

            try std.testing.expectEqual(@as(usize, 1), probe.build_calls);
            try std.testing.expect(probe.saw_endpoint_id.?.eql(client_ep.id()));
            try std.testing.expectEqual(@as(usize, 1), client_ep.addressLookupServiceCount());

            var accept_future = io.async(struct {
                fn run(ep: *Endpoint) !Connection {
                    return ep.accept();
                }
            }.run, .{server_ep});
            const client_conn = try client_ep.connectById(server_ep.id(), builder_alpn);
            defer client_conn.close();
            const server_conn = try accept_future.await(io);
            defer server_conn.close();
        }
    }
}

// Mutation-red control for core-portmapper: online() must REALLY probe the
// configured NAT-PMP gateway and publish the learned mapping — a no-op probe
// leaves portMapping() null and the address snapshot without the external
// addr; a probe that skips the gateway never trips the responder's saw-flags.
// The responder speaks the real NAT-PMP wire format over loopback UDP sockets.
test "Endpoint online with portmapper probes the gateway and publishes the learned mapping" {
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
                    std.mem.writeInt(u32, resp[4..8], 42, .big);
                    @memcpy(resp[8..10], msg.data[4..6]);
                    std.mem.writeInt(u16, resp[10..12], 40000, .big);
                    std.mem.writeInt(u32, resp[12..16], 60, .big);
                    self.socket.send(self.io, &msg.from, &resp) catch {};
                }
            }
        }
    };

    // Ephemeral responder port: two fixed-port (5351) responders collide
    // when the runner schedules this test alongside portmapper.zig's probe
    // test; the endpoint is pointed at the explicit host:port instead.
    var responder_bind: net.IpAddress = .{ .ip4 = .loopback(0) };
    const responder_socket = try responder_bind.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var gateway_buf: [24]u8 = undefined;
    const gateway_text = try std.fmt.bufPrint(&gateway_buf, "127.0.0.1:{d}", .{responder_socket.address.getPort()});

    var responder: Responder = .{ .io = io, .socket = responder_socket };
    const responder_thread = try std.Thread.spawn(.{}, Responder.run, .{&responder});
    defer {
        responder.stopped.store(true, .release);
        responder_thread.join();
    }

    const ep = try Endpoint.init(allocator, io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xB0} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .disabled,
        .portmapper = true,
        .portmapper_gateway = gateway_text,
    });
    defer ep.deinit();

    try ep.online();
    try std.testing.expect(ep.portmapperLastError() == null);
    const learned = ep.portMapping().?;
    const learned_ip: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 7 }, .port = 40000 } };
    try std.testing.expect(learned.eql(.{ .ip = learned_ip }));
    try std.testing.expect(responder.saw_external_request.load(.acquire));
    try std.testing.expect(responder.saw_mapping_request.load(.acquire));

    // The learned mapping rides the endpoint's advertised address set.
    var watcher = ep.watchAddr();
    var snap = try watcher.get();
    defer snap.deinit(allocator);
    var found = false;
    for (snap.endpoint_addr.addrs) |ta| {
        if (ta.eql(learned)) found = true;
    }
    try std.testing.expect(found);

    // Portmapper disabled (default): no probe, no mapping.
    const ep_plain = try Endpoint.init(allocator, io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xB1} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .disabled,
    });
    defer ep_plain.deinit();
    try ep_plain.online();
    try std.testing.expect(ep_plain.portMapping() == null);
    try std.testing.expect(ep_plain.portmapperLastError() == null);

    // Enabled with no gateway configured anywhere: online() still succeeds
    // (best-effort), and the failure is observable.
    const ep_nogw = try Endpoint.init(allocator, io, .{
        .secret_key = key.SecretKey.fromBytes([_]u8{0xB2} ** 32),
        .alpns = &.{default_alpn},
        .relay_mode = .disabled,
        .portmapper = true,
    });
    defer ep_nogw.deinit();
    try ep_nogw.online();
    try std.testing.expect(ep_nogw.portMapping() == null);
    try std.testing.expectEqual(error.MissingGatewayEnv, ep_nogw.portmapperLastError().?);
}

// Mutation-red control for core-relay-fallback: the resolved record points
// the direct dial at a DECOY endpoint (bound but never online, so the direct
// path blackholes into an unread socket and the dial fails at the connect
// deadline) and the relay URL at the real server. Without the fallback retry
// the connect returns the direct-dial error; with it, the client lands on
// the REAL server through the relay — proven by a bi-stream echo with the
// real server while the decoy holds no accepted connection. A fallback that
// redials the direct address (or never retries) fails here.
test "Endpoint connectById falls back to relay when the direct path fails" {
    const allocator = std.testing.allocator;
    const relay_server = @import("relay/server.zig");
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try relay_server.Server.init(allocator, io, .{
        .bind_host = "127.0.0.1",
        .bind_port = 0,
        .tls_cert_path = "relay-testdata/test-cert.pem",
        .tls_key_path = "relay-testdata/test-key.pem",
    });
    const relay_accept = try std.Thread.spawn(.{}, struct {
        fn run(srv: *relay_server.Server) void {
            while (srv.running.load(.acquire)) srv.acceptAndSpawn() catch {};
        }
    }.run, .{&server});
    defer {
        server.deinit();
        relay_accept.join();
    }

    var url_buf: [64]u8 = undefined;
    const relay_url = try std.fmt.bufPrint(&url_buf, "wss://127.0.0.1:{d}/relay", .{server.localAddress().getPort()});
    const relay_url_owned = try addr_mod.RelayUrl.parse(allocator, relay_url);
    defer relay_url_owned.deinit(allocator);

    inline for ([_]factory.Engine{ .picoquic, .noq }) |eng| {
        const compiled = switch (eng) {
            .picoquic => product_flags.has_picoquic,
            .noq => product_flags.has_noq,
        };
        if (compiled) {
            const fb_alpn: [:0]const u8 = "iroh-relay-fallback/0";

            // Decoy: live direct listener with the WRONG identity — the
            // direct handshake dies fast at peer validation.
            const decoy_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xD0} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{fb_alpn},
                .accept_unknown_peer = true,
            });
            defer decoy_ep.deinit();

            const real_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xD1} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{fb_alpn},
                .accept_unknown_peer = true,
                .relay_mode = .custom,
                .home_relay_url = relay_url,
                .ca_tls_config = .insecure_skip_verify,
                .publish_on_online = false,
            });
            defer real_ep.deinit();
            try real_ep.online();
            const real_id = real_ep.id();

            var static = discovery_address_lookup.StaticLookup.init(allocator);
            defer static.deinit();
            {
                var ea = try EndpointAddr.fromParts(allocator, real_id, &.{
                    .{ .ip = decoy_ep.localAddress() },
                    .{ .relay = relay_url_owned },
                });
                defer ea.deinit(allocator);
                try static.setEndpointAddr(ea, null);
            }

            const client_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xD2} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{fb_alpn},
                .relay_mode = .custom,
                .home_relay_url = relay_url,
                .ca_tls_config = .insecure_skip_verify,
                .publish_on_online = false,
                .address_lookup_services = &.{static.asLookup()},
            });
            defer client_ep.deinit();
            try client_ep.online();

            // Park the accept BEFORE the dial: noq drives its pump from
            // foreground calls only, so the server never sees the relay
            // retry unless an accept (or another drive call) is active.
            // Re-park on Timeout: the accept deadline equals the shorter
            // connect timeout, so one parked accept can expire before the
            // fallback relay dial lands; established conns stay queued for
            // handoff, so the retry loop picks the conn up deterministically.
            var accept_future = io.async(struct {
                fn run(ep: *Endpoint) !Connection {
                    var attempts: u8 = 0;
                    while (true) {
                        return ep.accept() catch |err| switch (err) {
                            error.Timeout => {
                                attempts += 1;
                                if (attempts >= 8) return err;
                                continue;
                            },
                            else => return err,
                        };
                    }
                }
            }.run, .{real_ep});

            // The direct dial targets the decoy and MUST fail; the relay
            // fallback must carry the connect to the real server. The failed
            // direct dial only surfaces at the client's handshake deadline
            // (the engine does not fail the connect waiter early on a
            // blackholed direct path), so this takes one connect-timeout.
            const client_conn = try client_ep.connectById(real_id, fb_alpn);
            defer client_conn.close();
            const server_conn = try accept_future.await(io);
            defer server_conn.close();

            const payload = "fell-back-to-relay";
            const client_stream = try client_conn.openBi();
            try client_stream.send.writer().writeAll(payload);
            try client_stream.send.finish();
            const server_stream = try server_conn.acceptBi();
            var buf: [64]u8 = undefined;
            const n = try server_stream.recv.reader().readSliceShort(&buf);
            try std.testing.expectEqualStrings(payload, buf[0..n]);

            // The resolved record gave the client no other direct address,
            // so reaching the real server proves the relay carried it — and
            // the direct dial must NOT have landed on the decoy (no
            // established connection may be waiting there).
            try std.testing.expect(client_conn.remoteNodeId().eql(real_id));
            try std.testing.expect((try decoy_ep.tryAcceptReady()) == null);
        }
    }
}

// Mutation-red control for core-mdns-discovery at the endpoint seam: the
// client is seeded with NO direct addresses and NO static resolver — the only
// path to the server's address is a real multicast mDNS exchange. A provider
// that never answers (or a resolver that never ingests) leaves the bare
// control client at DiscoveryUnavailable and the mDNS client without a route.
test "Endpoint connectById resolves a peer over real mDNS multicast" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    inline for ([_]factory.Engine{ .picoquic, .noq }) |eng| {
        const compiled = switch (eng) {
            .picoquic => product_flags.has_picoquic,
            .noq => product_flags.has_noq,
        };
        if (compiled) {
            const mdns_alpn: [:0]const u8 = "iroh-discovery-mdns/0";
            const server_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xE0} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{mdns_alpn},
                .accept_unknown_peer = true,
            });
            defer server_ep.deinit();
            const server_id = server_ep.id();

            // Server-side provider advertises ONLY its loopback address.
            const server_mdns = try discovery_mdns.MdnsAddressLookup.init(allocator, server_id, .{});
            defer server_mdns.deinit();
            {
                var ea = try EndpointAddr.fromParts(allocator, server_id, &.{.{ .ip = server_ep.localAddress() }});
                defer ea.deinit(allocator);
                try server_mdns.publish(ea, "mdns-e2e");
            }

            const client_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xE1} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{mdns_alpn},
            });
            defer client_ep.deinit();

            // Client-side provider resolves server_id over the wire; its own
            // advertised id is irrelevant (publish is never called on it) but
            // must differ from the server's so it never answers itself.
            const client_mdns = try discovery_mdns.MdnsAddressLookup.init(
                allocator,
                key.SecretKey.fromBytes([_]u8{0xE2} ** 32).public(),
                .{},
            );
            defer client_mdns.deinit();
            try client_ep.addAddressLookupService(client_mdns.asLookup());

            var accept_future = io.async(struct {
                fn run(ep: *Endpoint) !Connection {
                    return ep.accept();
                }
            }.run, .{server_ep});

            const client_conn = try client_ep.connectById(server_id, mdns_alpn);
            defer client_conn.close();
            const server_conn = try accept_future.await(io);
            defer server_conn.close();

            const payload = "mdns-carried-this-address";
            const client_stream = try client_conn.openBi();
            try client_stream.send.writer().writeAll(payload);
            try client_stream.send.finish();
            const server_stream = try server_conn.acceptBi();
            var buf: [64]u8 = undefined;
            const n = try server_stream.recv.reader().readSliceShort(&buf);
            try std.testing.expectEqualStrings(payload, buf[0..n]);

            // The mDNS record is what the client merged: exactly one ip addr,
            // the server's own loopback address.
            var info = (try client_ep.remoteInfo(server_id)).?;
            defer info.deinit(allocator);
            var ip_count: usize = 0;
            for (info.addrs) |ta| {
                if (ta.isIp()) ip_count += 1;
            }
            try std.testing.expectEqual(@as(usize, 1), ip_count);

            // Bare control: no lookup services -> fail closed, proving the
            // connect above really went through the mDNS resolver.
            const bare_ep = try Endpoint.init(allocator, io, .{
                .engine = eng,
                .secret_key = key.SecretKey.fromBytes([_]u8{0xE3} ** 32),
                .bind_address = .{ .ip4 = .loopback(0) },
                .alpns = &.{mdns_alpn},
            });
            defer bare_ep.deinit();
            try std.testing.expectError(
                error.DiscoveryUnavailable,
                bare_ep.connectById(server_id, mdns_alpn),
            );
        }
    }
}
