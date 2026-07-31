//! Thin engine-select factory over the frozen `transport.zig` vtable.
//!
//! Both backends `.transport()` to the identical `tr.Transport` seam, so leaves
//! (blobs/gossip) never see which engine is live. The default all-in-one
//! product still selects picoquic for compatibility; mono products select their
//! own engine through `createForProduct`. The `engine` tag is a distinguishing
//! field so a gate can prove which backend it actually exercised
//! (harness-fake resistance).

const std = @import("std");
const product_flags = @import("../product_flags.zig");
const tr = @import("../transport.zig");
const key = @import("../key.zig");
const quic_crypto = @import("../quic/crypto.zig");
const congestion = @import("../quic/congestion.zig");
const path_observability = @import("../path_observability.zig");
const uni_poll = @import("uni_poll.zig");
const relay_fallback = @import("relay_fallback.zig");
// Engine backends are comptime-gated (component-repo restructure). A disabled
// engine collapses to `struct {}` so its transitive imports (picoquic's
// `connection/c.zig`; noq's `quic/*`) are never pulled into a narrower product.
const picoquic_ep = if (product_flags.has_picoquic) @import("endpoint.zig") else struct {};
const noq_ep = if (product_flags.has_noq) @import("transport_noq.zig") else struct {};

pub const SelectedPath = path_observability.SelectedPath;

pub const Engine = enum { picoquic, noq };
pub const TlsBackend = quic_crypto.Backend;
pub const CongestionKind = congestion.Kind;
pub const InboundUniEvent = uni_poll.InboundUniEvent;
pub const DatagramError = tr.Error || error{
    DatagramTooLarge,
    DatagramUnsupported,
};

pub const Options = struct {
    bind_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) },
    /// noq accept path pins its RPK verifier to this peer (ignored by picoquic,
    /// which accepts any peer). null => dial-only.
    expected_peer: ?key.NodeId = null,
    /// Server-only: permit a peer not known in advance, but require its raw
    /// public key to pass TLS CertificateVerify before accept exposes it.
    accept_unknown_peer: bool = false,
    /// Test-only adversarial RPK certificate key; the handshake still signs
    /// with `secret`, so a mismatch must be rejected by the remote verifier.
    certificate_public_key_override: ?key.NodeId = null,
    /// zigtls-only adversarial certificate bytes; the handshake still signs
    /// with `secret`, so malformed SPKI must be rejected by the remote verifier.
    certificate_der_override: ?[]const u8 = null,
    /// noq-only: require Retry-based address validation for inbound connections
    /// (iroh deployment default OFF). Ignored by picoquic.
    retry: bool = false,
    /// noq-only TLS backend (picotls default; `.zigtls` selects pure-Zig TLS).
    /// Picoquic ignores this — it runs its own picotls C stack.
    tls_backend: TlsBackend = .picotls,
    /// noq-only congestion controller selection. Picoquic ignores this.
    congestion_kind: CongestionKind = .cubic,
    /// zigtls-only server CertificateRequest offer policy; null uses the TLS default.
    certificate_request_signature_algorithms: ?[]const u16 = null,
};

/// A live endpoint of either engine. Owns the concrete backend; call `deinit`.
/// The `Engine` tag is retained for both variants; a compiled-out engine's
/// payload collapses to `void` and its arms become comptime-unreachable.
pub const AnyEndpoint = union(Engine) {
    picoquic: if (product_flags.has_picoquic) *picoquic_ep.Endpoint else void,
    noq: if (product_flags.has_noq) *noq_ep.Endpoint else void,

    pub fn engine(self: AnyEndpoint) Engine {
        return self;
    }

    pub fn transport(self: AnyEndpoint) tr.Transport {
        return switch (self) {
            .picoquic => |e| if (comptime product_flags.has_picoquic) e.transport() else unreachable,
            .noq => |e| if (comptime product_flags.has_noq) e.transport() else unreachable,
        };
    }

    pub fn localAddress(self: AnyEndpoint) std.Io.net.IpAddress {
        return switch (self) {
            .picoquic => |e| if (comptime product_flags.has_picoquic) e.localAddress() else unreachable,
            .noq => |e| if (comptime product_flags.has_noq) e.localAddress() else unreachable,
        };
    }

    /// The backend actually serving this endpoint. Picoquic always owns its
    /// picotls stack; noq honors `Options.tls_backend`.
    pub fn tlsBackend(self: AnyEndpoint) TlsBackend {
        return switch (self) {
            .picoquic => if (comptime product_flags.has_picoquic) TlsBackend.picotls else unreachable,
            .noq => |e| if (comptime product_flags.has_noq) e.tlsBackend() else unreachable,
        };
    }

    pub fn tryAcceptReady(self: AnyEndpoint) tr.Error!?tr.Connection {
        return switch (self) {
            .picoquic => |e| if (comptime product_flags.has_picoquic) picoquic_ep.tryAcceptReady(e) else unreachable,
            .noq => |e| if (comptime product_flags.has_noq) e.tryAcceptReady() else unreachable,
        };
    }

    pub const SetAlpnsError = error{
        InvalidAlpn,
        OutOfMemory,
        EndpointClosed,
        PicoquicDisabled,
        NoqDisabled,
    };

    /// Replace the server-advertised ALPN set (new inbound handshakes only).
    pub fn setAlpns(self: AnyEndpoint, alpns: []const []const u8) SetAlpnsError!void {
        return switch (self) {
            .picoquic => |e| if (comptime product_flags.has_picoquic) picoquic_ep.setAlpns(e, alpns) else error.PicoquicDisabled,
            .noq => |e| if (comptime product_flags.has_noq) e.setAlpns(alpns) else error.NoqDisabled,
        };
    }

    pub fn pollOnce(self: AnyEndpoint) tr.Error!void {
        return switch (self) {
            .picoquic => |e| if (comptime product_flags.has_picoquic) e.pollOnce() else unreachable,
            .noq => |e| if (comptime product_flags.has_noq) e.pollOnce() else unreachable,
        };
    }

    pub fn connectionIsClosed(self: AnyEndpoint, conn: tr.Connection) bool {
        return switch (self) {
            .picoquic => if (comptime product_flags.has_picoquic) picoquic_ep.connectionIsClosed(conn) else unreachable,
            .noq => if (comptime product_flags.has_noq) noq_ep.connectionIsClosed(conn) else unreachable,
        };
    }

    pub fn nextInboundUniEvent(self: AnyEndpoint, conn: tr.Connection, buffer: []u8) tr.Error!?InboundUniEvent {
        return switch (self) {
            .picoquic => if (comptime product_flags.has_picoquic) picoquic_ep.connectionNextInboundUniEvent(conn, buffer) else unreachable,
            .noq => if (comptime product_flags.has_noq) noq_ep.connectionNextInboundUniEvent(conn, buffer) else unreachable,
        };
    }

    /// Close every live backend connection (Endpoint-close composition).
    /// Deterministic on return: each connection has been told to close and
    /// its CONNECTION_CLOSE flushed toward the peer; outstanding connection
    /// handles read as closed and a later per-conn close is a no-op.
    pub fn closeAllConnections(self: AnyEndpoint) void {
        switch (self) {
            .picoquic => |e| {
                if (comptime product_flags.has_picoquic) picoquic_ep.closeAllConnections(e);
            },
            .noq => |e| {
                if (comptime product_flags.has_noq) e.closeAllConnections();
            },
        }
    }

    pub fn deinit(self: AnyEndpoint) void {
        switch (self) {
            .picoquic => |e| {
                if (comptime product_flags.has_picoquic) e.deinit();
            },
            .noq => |e| {
                if (comptime product_flags.has_noq) e.deinit();
            },
        }
    }
};

/// Attach an endpoint-owned DERP datagram client to a noq engine.
pub fn setNoqRelay(endpoint: AnyEndpoint, relay: anytype) error{RelayUnsupported}!void {
    if (comptime !product_flags.has_noq) return error.RelayUnsupported;
    switch (endpoint) {
        .noq => |e| e.setRelay(relay),
        .picoquic => return error.RelayUnsupported,
    }
}

pub const RelayAttachError = tr.Error || error{RelayUnsupported};

/// Attach an endpoint-owned DERP datagram client to a picoquic G2 endpoint.
pub fn setPicoquicRelay(endpoint: AnyEndpoint, relay: relay_fallback.Client) RelayAttachError!void {
    if (comptime !product_flags.has_picoquic) return error.RelayUnsupported;
    switch (endpoint) {
        .picoquic => |e| try picoquic_ep.setRelay(e, relay),
        .noq => return error.RelayUnsupported,
    }
}

pub fn productEngine() Engine {
    if (comptime product_flags.is_mono_noq) return .noq;
    return .picoquic;
}

pub fn productTlsBackend() TlsBackend {
    if (comptime product_flags.has_zigtls and !product_flags.has_picotls) return .zigtls;
    return .picotls;
}

pub fn createForProduct(
    allocator: std.mem.Allocator,
    io: std.Io,
    secret: key.SecretKey,
    alpn: [:0]const u8,
    options: Options,
) !AnyEndpoint {
    var resolved = options;
    resolved.tls_backend = productTlsBackend();
    return create(productEngine(), allocator, io, secret, alpn, resolved);
}

/// Construct an endpoint for the selected engine.
pub fn create(
    engine_kind: Engine,
    allocator: std.mem.Allocator,
    io: std.Io,
    secret: key.SecretKey,
    alpn: [:0]const u8,
    options: Options,
) !AnyEndpoint {
    if (engine_kind == .noq and options.tls_backend == .zigtls and !quic_crypto.zigtls_enabled) {
        return error.ZigtlsDisabled;
    }

    return switch (engine_kind) {
        .picoquic => if (comptime product_flags.has_picoquic)
            .{ .picoquic = try picoquic_ep.Endpoint.initOptions(allocator, io, secret, alpn, .{
                .bind_address = options.bind_address,
            }) }
        else
            error.PicoquicDisabled,
        .noq => if (comptime product_flags.has_noq)
            .{ .noq = try noq_ep.Endpoint.initOptions(allocator, io, secret, alpn, .{
                .bind_address = options.bind_address,
                .expected_peer = options.expected_peer,
                .accept_unknown_peer = options.accept_unknown_peer,
                .certificate_public_key_override = options.certificate_public_key_override,
                .certificate_der_override = options.certificate_der_override,
                .tls_backend = options.tls_backend,
                .congestion_kind = options.congestion_kind,
                .certificate_request_signature_algorithms = options.certificate_request_signature_algorithms,
                .retry = options.retry,
            }) }
        else
            error.NoqDisabled,
    };
}

pub fn connectionSendDatagram(endpoint: AnyEndpoint, conn: tr.Connection, bytes: []const u8) DatagramError!void {
    return switch (endpoint) {
        .picoquic => if (comptime product_flags.has_picoquic) error.DatagramUnsupported else unreachable,
        .noq => if (comptime product_flags.has_noq) noq_ep.connectionSendDatagram(conn, bytes) else error.DatagramUnsupported,
    };
}

pub fn connectionReadDatagram(
    endpoint: AnyEndpoint,
    conn: tr.Connection,
    buffer: []u8,
    timeout_ns: i64,
) DatagramError!?[]u8 {
    return switch (endpoint) {
        .picoquic => if (comptime product_flags.has_picoquic) error.DatagramUnsupported else unreachable,
        .noq => if (comptime product_flags.has_noq) noq_ep.connectionReadDatagram(conn, buffer, timeout_ns) else error.DatagramUnsupported,
    };
}

pub fn connectionMaxDatagramSize(endpoint: AnyEndpoint, conn: tr.Connection) ?usize {
    return switch (endpoint) {
        .picoquic => if (comptime product_flags.has_picoquic) null else unreachable,
        .noq => if (comptime product_flags.has_noq) noq_ep.connectionMaxDatagramSize(conn) else null,
    };
}

/// Selected-path snapshot for patchbay / path-migration assertions.
///
/// - noq: reads magicsock's selected candidate on the concrete connection.
/// - picoquic G2: reports relay when the connection is currently using the
///   endpoint-owned relay fallback path.
pub fn connectionSelectedPath(endpoint: AnyEndpoint, conn: tr.Connection) ?SelectedPath {
    return switch (endpoint) {
        .picoquic => if (comptime product_flags.has_picoquic) picoquic_ep.connectionSelectedPath(conn) else null,
        .noq => if (comptime product_flags.has_noq) noq_ep.connectionSelectedPath(conn) else null,
    };
}
