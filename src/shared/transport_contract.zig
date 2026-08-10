//! Engine-blind transport contract and product-monomorphized seam.
//!
//! `Seam(engine.bundle)` is the only product-specific transport surface shared
//! code may use. It resolves directly to the selected engine at comptime: no
//! runtime union, tag, vtable, or legacy module survives the S7 cutover.

const std = @import("std");
const build_options = @import("build_options");
const key = @import("key.zig");
const addr = @import("addr.zig");
const tls = @import("tls_contract.zig");
const path_observability = @import("path_observability.zig");

pub const Error = error{
    ConnectionLost,
    StreamReset,
    Timeout,
    NotConnected,
    OutOfMemory,
};

pub const CongestionController = enum { unknown, new_reno, cubic, bbr3 };

pub const ConnectionStats = struct {
    smoothed_rtt_ns: ?i64 = null,
    latest_rtt_ns: ?i64 = null,
    path_mtu: ?u16 = null,
    congestion_window: ?u64 = null,
    bytes_in_flight: ?u64 = null,
    congestion_controller: CongestionController = .unknown,
    app_limited_acks: u64 = 0,
    spurious_congestion_events: u64 = 0,
    abandoned_recv_bytes: u64 = 0,
};

// Internal spellings avoid a declaration-name ambiguity inside the generated
// public seam, whose historic surface itself exports `Error` and
// `ConnectionStats`.
const contract_error = Error;
const contract_congestion_controller = CongestionController;
const contract_connection_stats = ConnectionStats;
const contract_congestion_kind = CongestionKind;
const contract_inbound_uni_event = InboundUniEvent;

/// Engine-axis identity. Kept engine-blind so the product door can expose the
/// historic factory selection API without an engine path import from shared.
pub const EngineId = enum { picoquic, noq };

/// Selection enum for the noq congestion controller. Picoquic accepts it in
/// the stable factory Options shape and preserves its historic no-op behavior.
pub const CongestionKind = enum { new_reno, cubic, bbr3 };

pub const InboundUniChunk = struct {
    stream_id: u64,
    bytes: []const u8,
    fin: bool,
};

pub const InboundUniEvent = union(enum) {
    chunk: InboundUniChunk,
    reset: u64,
};

/// Engine-neutral relay datagram contract. The concrete DERP adapters remain
/// in `shared/transport/relay_fallback.zig`; engines and the door share this
/// exact declaration without introducing a shared-root import cycle.
pub const RelayDatagram = struct {
    src: key.NodeId,
    data: []u8,
};

pub const RelayClient = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (*anyopaque, key.NodeId, []const u8) contract_error!void,
        recv: *const fn (*anyopaque, []u8) contract_error!?RelayDatagram,
    };

    pub fn send(self: RelayClient, dst: key.NodeId, data: []const u8) contract_error!void {
        return self.vtable.send(self.context, dst, data);
    }

    pub fn recv(self: RelayClient, buffer: []u8) contract_error!?RelayDatagram {
        return self.vtable.recv(self.context, buffer);
    }
};

/// Per-engine product composition bundle. Each engine root materializes one;
/// `Seam` is instantiated by the product door with that selected bundle.
pub const EngineBundle = struct {
    ConnImpl: type,
    SendImpl: type,
    RecvImpl: type,
    Endpoint: type,
    /// Engine-owned static helpers for the stable factory namespace.
    Factory: type,
    engine: EngineId,
    relay_datagram_capacity: usize,
};

/// Bind the frozen public transport/factory surface to one selected engine.
/// `E.engine` is comptime-known, so every conditional below collapses to the
/// same straight-line calls the old mono factory selected, with no runtime
/// dispatch residue.
pub fn Seam(comptime E: EngineBundle) type {
    return struct {
        const Self = @This();

        pub const NodeId = key.NodeId;
        pub const EndpointAddr = addr.EndpointAddr;
        pub const NodeAddr = addr.NodeAddr;
        pub const TransportAddr = addr.TransportAddr;
        pub const RelayUrl = addr.RelayUrl;
        pub const CustomAddr = addr.CustomAddr;
        pub const Error = contract_error;
        pub const CongestionController = contract_congestion_controller;
        pub const ConnectionStats = contract_connection_stats;

        pub const SendStream = struct {
            impl: *E.SendImpl,

            pub fn writer(self: SendStream) *std.Io.Writer {
                return self.impl.pubWriter();
            }
            pub fn pendingFailure(self: SendStream) ?contract_error {
                return self.impl.pubPendingFailure();
            }
            pub fn resetCode(self: SendStream) ?u64 {
                return self.impl.pubResetCode();
            }
            pub fn flush(self: SendStream) contract_error!void {
                return self.impl.pubFlush();
            }
            pub fn finish(self: SendStream) contract_error!void {
                return self.impl.pubFinish();
            }
            pub fn reset(self: SendStream) void {
                self.impl.pubReset();
            }
            pub fn resetWithCode(self: SendStream, code: u64) void {
                self.impl.pubResetWithCode(code);
            }
        };

        pub const RecvStream = struct {
            impl: *E.RecvImpl,

            pub fn reader(self: RecvStream) *std.Io.Reader {
                return self.impl.pubReader();
            }
            pub fn stop(self: RecvStream) contract_error!void {
                return self.impl.pubStop();
            }
            pub fn resetCode(self: RecvStream) ?u64 {
                return self.impl.pubResetCode();
            }
        };

        pub const BiStream = struct {
            send: SendStream,
            recv: RecvStream,
        };

        pub const Connection = struct {
            impl: *E.ConnImpl,

            pub fn openBi(self: Connection) contract_error!BiStream {
                return self.impl.pubOpenBi();
            }
            pub fn acceptBi(self: Connection) contract_error!BiStream {
                return self.impl.pubAcceptBi();
            }
            pub fn openUni(self: Connection) contract_error!SendStream {
                return self.impl.pubOpenUni();
            }
            pub fn acceptUni(self: Connection) contract_error!RecvStream {
                return self.impl.pubAcceptUni();
            }
            pub fn remoteNodeId(self: Connection) NodeId {
                return self.impl.pubRemoteNodeId();
            }
            pub fn alpn(self: Connection) ?[]const u8 {
                return self.impl.pubAlpn();
            }
            pub fn remoteAddress(self: Connection) ?std.Io.net.IpAddress {
                return self.impl.pubRemoteAddress();
            }
            pub fn close(self: Connection) void {
                self.impl.pubClose();
            }
            pub fn io(self: Connection) std.Io {
                return self.impl.pubIo();
            }
            pub fn stats(self: Connection) contract_connection_stats {
                return self.impl.pubStats();
            }
        };

        pub const Transport = struct {
            impl: *E.Endpoint,

            pub fn connect(self: Transport, peer: NodeAddr) contract_error!Connection {
                return self.impl.pubConnect(peer);
            }
            pub fn accept(self: Transport) contract_error!Connection {
                return self.impl.pubAccept();
            }
            pub fn localNodeId(self: Transport) NodeId {
                return self.impl.pubLocalNodeId();
            }
            pub fn io(self: Transport) std.Io {
                return self.impl.pubIo();
            }
        };

        /// The historic `transport.factory` namespace, now a direct product
        /// composition over `E` rather than a legacy ladder or union.
        pub const factory = struct {
            pub const SelectedPath = path_observability.SelectedPath;
            pub const Engine = EngineId;
            pub const TlsBackend = tls.Backend;
            pub const CongestionKind = contract_congestion_kind;
            pub const InboundUniEvent = contract_inbound_uni_event;
            pub const DatagramError = contract_error || error{
                DatagramTooLarge,
                DatagramUnsupported,
            };

            pub const Options = struct {
                bind_address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) },
                expected_peer: ?key.NodeId = null,
                accept_unknown_peer: bool = false,
                certificate_public_key_override: ?key.NodeId = null,
                certificate_der_override: ?[]const u8 = null,
                retry: bool = false,
                tls_backend: TlsBackend = .picotls,
                congestion_kind: contract_congestion_kind = .cubic,
                certificate_request_signature_algorithms: ?[]const u16 = null,
                zero_rtt: bool = false,
                background_pump: bool = false,
            };

            pub const AnyEndpoint = struct {
                const AnySelf = @This();

                inner: *E.Endpoint,

                pub fn engine(_: AnySelf) Engine {
                    return productEngine();
                }
                pub fn transport(self: AnySelf) Transport {
                    return self.inner.transport();
                }
                pub fn localAddress(self: AnySelf) std.Io.net.IpAddress {
                    return self.inner.localAddress();
                }
                pub fn tlsBackend(self: AnySelf) TlsBackend {
                    if (comptime E.engine == .picoquic) return .picotls;
                    return self.inner.tlsBackend();
                }
                pub fn tryAcceptReady(self: AnySelf) contract_error!?Connection {
                    if (comptime E.engine == .picoquic) return E.Factory.tryAcceptReady(self.inner);
                    return self.inner.tryAcceptReady();
                }
                pub fn tryAcceptReadyZeroRtt(self: AnySelf) contract_error!?Connection {
                    if (comptime E.engine == .picoquic) return null;
                    return self.inner.tryAcceptReadyZeroRtt();
                }
                pub fn canOfferZeroRtt(self: AnySelf, peer: key.NodeId) bool {
                    if (comptime E.engine == .picoquic) return false;
                    return self.inner.canOfferZeroRtt(peer);
                }
                pub fn connectZeroRtt(self: AnySelf, peer: key.NodeId, ip: std.Io.net.IpAddress) contract_error!?Connection {
                    if (comptime E.engine == .picoquic) return null;
                    return self.inner.connectZeroRtt(peer, ip);
                }

                pub const SetAlpnsError = error{
                    InvalidAlpn,
                    OutOfMemory,
                    EndpointClosed,
                    PicoquicDisabled,
                    NoqDisabled,
                };

                pub fn setAlpns(self: AnySelf, alpns: []const []const u8) SetAlpnsError!void {
                    if (comptime E.engine == .picoquic) return E.Factory.setAlpns(self.inner, alpns);
                    return self.inner.setAlpns(alpns);
                }
                pub fn pollOnce(self: AnySelf) contract_error!void {
                    return self.inner.pollOnce();
                }
                pub fn connectionIsClosed(_: AnySelf, conn: Connection) bool {
                    return E.Factory.connectionIsClosed(conn);
                }
                pub fn connectionTryAcceptBi(_: AnySelf, conn: Connection) contract_error!?BiStream {
                    if (comptime E.engine == .picoquic) return null;
                    return E.Factory.connectionTryAcceptBi(conn);
                }
                pub fn sendQueueFinish(_: AnySelf, send: SendStream) contract_error!void {
                    if (comptime E.engine == .picoquic) return send.finish();
                    return E.Factory.sendQueueFinish(send);
                }
                pub fn sendPollFinishComplete(_: AnySelf, send: SendStream) contract_error!bool {
                    if (comptime E.engine == .picoquic) return true;
                    return E.Factory.sendPollFinishComplete(send);
                }
                pub fn nextInboundUniEvent(_: AnySelf, conn: Connection, buffer: []u8) contract_error!?contract_inbound_uni_event {
                    return E.Factory.connectionNextInboundUniEvent(conn, buffer);
                }
                pub fn closeAllConnections(self: AnySelf) void {
                    if (comptime E.engine == .picoquic) return E.Factory.closeAllConnections(self.inner);
                    return self.inner.closeAllConnections();
                }
                pub fn deinit(self: AnySelf) void {
                    return self.inner.deinit();
                }
                pub fn noqPtr(self: AnySelf) *E.Endpoint {
                    if (comptime E.engine != .noq) @compileError("noqPtr() unavailable: product has no noq engine");
                    return self.inner;
                }
                pub fn picoquicPtr(self: AnySelf) *E.Endpoint {
                    if (comptime E.engine != .picoquic) @compileError("picoquicPtr() unavailable: product has no picoquic engine");
                    return self.inner;
                }
            };

            pub fn setNoqRelay(endpoint: AnyEndpoint, relay: RelayClient) error{RelayUnsupported}!void {
                if (comptime E.engine == .noq) {
                    endpoint.inner.setRelay(relay);
                    return;
                }
                return error.RelayUnsupported;
            }

            pub const IncomingFilterOutcome = if (E.engine == .noq) E.Factory.IncomingFilterOutcome else enum { accept, retry, reject, ignore };
            pub const IncomingInfo = if (E.engine == .noq) E.Factory.IncomingInfo else struct {
                remote: std.Io.net.IpAddress,
                remote_addr_validated: bool,
                first_datagram: []const u8,
            };
            pub const IncomingFilter = if (E.engine == .noq) E.Factory.IncomingFilter else struct {
                context: *anyopaque,
                callback: *const fn (context: *anyopaque, info: *const IncomingInfo) IncomingFilterOutcome,
            };

            pub fn setNoqIncomingFilter(endpoint: AnyEndpoint, filter: ?IncomingFilter) void {
                if (comptime E.engine == .noq) endpoint.inner.setIncomingFilter(filter);
            }

            pub const supports_accept_early: bool = E.engine == .noq;

            pub fn waitEstablished(conn: Connection) contract_error!void {
                if (comptime E.engine == .noq) return E.Endpoint.waitEstablished(conn);
            }

            pub const RelayAttachError = contract_error || error{RelayUnsupported};

            pub fn setPicoquicRelay(endpoint: AnyEndpoint, relay: RelayClient) RelayAttachError!void {
                if (comptime E.engine == .picoquic) {
                    try E.Factory.setRelay(endpoint.inner, relay);
                    return;
                }
                return error.RelayUnsupported;
            }

            pub fn productEngine() Engine {
                return E.engine;
            }

            pub fn productTlsBackend() TlsBackend {
                return if (build_options.zigtls) .zigtls else .picotls;
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

            pub fn create(
                engine_kind: Engine,
                allocator: std.mem.Allocator,
                io: std.Io,
                secret: key.SecretKey,
                alpn: [:0]const u8,
                options: Options,
            ) !AnyEndpoint {
                if (engine_kind == .noq and options.tls_backend == .zigtls and !build_options.zigtls) {
                    return error.ZigtlsDisabled;
                }
                if (comptime E.engine == .picoquic) {
                    if (engine_kind != .picoquic) return error.PicoquicDisabled;
                    return .{ .inner = try E.Endpoint.initOptions(allocator, io, secret, alpn, .{
                        .bind_address = options.bind_address,
                    }) };
                }
                if (engine_kind != .noq) return error.NoqDisabled;
                return .{ .inner = try E.Endpoint.initOptions(allocator, io, secret, alpn, .{
                    .bind_address = options.bind_address,
                    .expected_peer = options.expected_peer,
                    .accept_unknown_peer = options.accept_unknown_peer,
                    .certificate_public_key_override = options.certificate_public_key_override,
                    .certificate_der_override = options.certificate_der_override,
                    .tls_backend = options.tls_backend,
                    .congestion_kind = options.congestion_kind,
                    .certificate_request_signature_algorithms = options.certificate_request_signature_algorithms,
                    .retry = options.retry,
                    .zero_rtt = options.zero_rtt,
                    .background_pump = options.background_pump,
                }) };
            }

            pub fn connectionSendDatagram(_: AnyEndpoint, conn: Connection, bytes: []const u8) DatagramError!void {
                if (comptime E.engine == .picoquic) return error.DatagramUnsupported;
                return E.Endpoint.connectionSendDatagram(conn, bytes);
            }
            pub fn connectionReadDatagram(_: AnyEndpoint, conn: Connection, buffer: []u8, timeout_ns: i64) DatagramError!?[]u8 {
                if (comptime E.engine == .picoquic) return error.DatagramUnsupported;
                return E.Endpoint.connectionReadDatagram(conn, buffer, timeout_ns);
            }
            pub fn connectionMaxDatagramSize(_: AnyEndpoint, conn: Connection) ?usize {
                if (comptime E.engine == .picoquic) return null;
                return E.Endpoint.connectionMaxDatagramSize(conn);
            }
            pub fn connectionSelectedPath(_: AnyEndpoint, conn: Connection) ?SelectedPath {
                return E.Factory.connectionSelectedPath(conn);
            }
        };
    };
}

test {
    _ = Error;
    _ = RelayClient;
}
