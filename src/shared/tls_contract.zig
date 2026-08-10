//! Backend-agnostic TLS contract (fork-isolation S6).
//!
//! Names NO concrete TLS backend. Moved verbatim from the pre-S6
//! `quic/crypto.zig` surface, plus the Caps / BackendTypes / ConfigFor /
//! verifyBackend seam that lets each `tls-*` module present a uniform Session.
//! Field names keep their historical `zigtls_*` prefixes in S6 (layout-only;
//! capability renames are post-migration cleanup).

const std = @import("std");
const key = @import("key.zig");

pub const Error = error{
    PicotlsError,
    ZigtlsDisabled,
    AllocationFailed,
    InvalidEpoch,
    MissingPeerPublicKey,
    MissingTrafficSecret,
    IncompleteHandshake,
};

pub const Role = enum {
    client,
    server,
};

pub const Backend = enum {
    picotls,
    zigtls,
};

pub const Direction = enum {
    read,
    write,
};

pub const Epoch = enum(u3) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    application = 3,
};

pub const max_epoch = 4;
pub const max_secret_len = 64;

pub const TrafficSecret = struct {
    bytes: [max_secret_len]u8,
    len: usize,

    pub fn slice(self: *const TrafficSecret) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// TLS extension id for `quic_transport_parameters` (RFC 9001 §8.2 / RFC 9000 §18).
pub const quic_transport_parameters_ext: u16 = 0x39;

/// TLS 1.3 signature schemes the X.509 server identity can sign with
/// (RFC 8446 §4.2.3). RSA is deliberately unsupported (honest config error
/// at startup, not a silent fallback).
pub const SignatureScheme = enum(u16) {
    ed25519 = 0x0807,
    ecdsa_secp256r1_sha256 = 0x0403,
};

/// Private key material for an X.509 leaf cert.
pub const SigningKey = union(enum) {
    ed25519: key.SecretKey,
    /// SEC1/PKCS#8 P-256 private key scalar (32 bytes, big-endian).
    ecdsa_p256: [32]u8,
};

/// X.509 server identity for QUIC listeners that must speak to rustls/webpki
/// clients (QAD). Server role only; when set, the session presents this chain
/// instead of the RPK SPKI. zigtls backend only (picotls glue is RPK-only).
pub const X509ServerIdentity = struct {
    /// DER cert chain, leaf first. The session copies what it needs at create.
    chain_der: []const []const u8,
    scheme: SignatureScheme,
    key: SigningKey,
};

/// Per-backend type table. On picotls every slot is a zero-size `struct {}` —
/// exactly today's `else struct {}` collapse, relocated out of the selector.
/// Shared zero-size stand-in used by backends that lack a capability type.
/// Named (not `struct {}`) so ConfigFor identity is stable across modules.
pub const EmptyType = struct {};

pub const BackendTypes = struct {
    ResumptionTicket: type,
    TicketKeyManager: type,
    ReplayFilter: type,
    TrustStore: type,
    OcspResponseView: type,
    NewSessionTicketInfo: type,
};

/// Capability flags for the selected TLS backend. Call sites that care about
/// 0-RTT / tickets / X.509 read these instead of hardcoding a backend name.
pub const Caps = struct {
    zero_rtt: bool,
    session_tickets: bool,
    x509_server_identity: bool,
    x509_trust_store: bool,
    ocsp: bool,
    client_cert_request_algs: bool,
};

/// Existing Config surface with the zigtls-only field TYPES swapped to `T.*`.
/// Field NAMES keep their historical `zigtls_*` prefixes in S6.
pub fn ConfigFor(comptime T: BackendTypes) type {
    return struct {
        /// Experimental selection seam. Picotls remains the shipping default.
        backend: Backend = .picotls,
        role: Role,
        secret_key: key.SecretKey,
        /// A pre-pinned RPK peer. Null enables the server-only learned-peer path:
        /// the C verifier still checks CertificateVerify against the presented key
        /// before this session may expose that identity.
        peer_public_key: ?key.PublicKey,
        /// Test-only adversarial input: advertise this RPK while signing with
        /// `secret_key`. It produces a CertificateVerify key-possession failure.
        certificate_public_key: ?key.PublicKey = null,
        /// zigtls-only adversarial input: advertise these certificate bytes while
        /// signing with `secret_key`. Used to prove malformed RPK/SPKI rejection.
        certificate_der_override: ?[]const u8 = null,
        /// Test-only adversarial input: ship these transport-parameter bytes
        /// verbatim (no role-gate normalization). Used to prove the peer's
        /// rejection of protocol-illegal TP blocks (e.g. F17 server-only params
        /// from a client).
        adversarial_transport_params: ?[]const u8 = null,
        require_client_authentication: bool = false,
        /// ALPN protocol to offer (client) / select (server), e.g. "iroh-interop-test".
        alpn: ?[]const u8 = null,
        /// Server-only: preferred ALPN list for selection among client offers.
        /// When set, overrides singular `alpn` for server selection (first match wins).
        server_alpns: ?[]const []const u8 = null,
        /// SNI server name the client sends (iroh: base32 node id). Server ignores.
        server_name: ?[]const u8 = null,
        /// Encoded QUIC transport-parameters (the 0x39 extension body). Sent in
        /// ClientHello (client) / EncryptedExtensions (server). Required for real
        /// quinn/rustls interop (RFC 9001 §8.2 MUST).
        transport_params: ?[]const u8 = null,
        /// zigtls-only TLS 1.3 session resumption ticket.
        zigtls_resumption_ticket: ?T.ResumptionTicket = null,
        /// zigtls-only server-side ticket protector for issuing/opening TLS
        /// NewSessionTicket identities.
        zigtls_ticket_key_manager: ?*T.TicketKeyManager = null,
        /// zigtls-only: issue a post-handshake NewSessionTicket after a completed
        /// server handshake using the configured key manager.
        zigtls_auto_issue_new_session_ticket: bool = false,
        /// zigtls-only: enable 0-RTT early data secret derivation (c e traffic).
        zigtls_enable_early_data: bool = false,
        /// zigtls-only: the replay strike register protecting 0-RTT acceptance
        /// (single-use tickets). Required whenever `zigtls_enable_early_data` is on.
        zigtls_replay_filter: ?*T.ReplayFilter = null,
        /// zigtls-only: replay-filter scope keys.
        zigtls_replay_node_id: u32 = 0,
        zigtls_replay_epoch: u64 = 0,
        /// zigtls server CertificateRequest offer policy; null uses the TLS default.
        certificate_request_signature_algorithms: ?[]const u16 = null,
        /// X.509 server identity (QAD). Server role only; zigtls backend only.
        x509_server: ?X509ServerIdentity = null,
        /// zigtls-only, client role: X.509 trust anchors + hostname policy.
        x509_trust_store: ?*const T.TrustStore = null,
        /// zigtls-only X.509 client: require stapled-OCSP acceptance during peer
        /// certificate policy. Product default is OFF.
        x509_enforce_ocsp: bool = false,
        x509_allow_soft_fail_ocsp: bool = false,
        /// Injected stapled-OCSP view applied when `x509_enforce_ocsp` is set.
        x509_stapled_ocsp: ?T.OcspResponseView = null,
        /// Test-only mutation hooks for the X.509 cert-validation matrix.
        x509_bypass_chain_verify: bool = false,
        x509_bypass_hostname_verify: bool = false,
        x509_bypass_trust_anchor: bool = false,
        x509_bypass_ocsp_check: bool = false,
    };
}

/// Compile-time check that a backend module exports the uniform surface.
/// Missing names become a named `@compileError` rather than a late type error.
pub fn verifyBackend(comptime B: type) void {
    comptime {
        if (!@hasDecl(B, "backend_id")) @compileError("tls_backend missing: backend_id");
        if (!@hasDecl(B, "caps")) @compileError("tls_backend missing: caps");
        if (!@hasDecl(B, "Types")) @compileError("tls_backend missing: Types");
        if (!@hasDecl(B, "Config")) @compileError("tls_backend missing: Config");
        if (!@hasDecl(B, "Session")) @compileError("tls_backend missing: Session");
        if (!@hasDecl(B, "EndpointHandshake")) @compileError("tls_backend missing: EndpointHandshake");
        // Session surface (16 methods verified vs connection.zig:434-720 pre-S6).
        const S = B.Session;
        for (.{
            "create",
            "destroy",
            "start",
            "handleMessage",
            "lastAlertCode",
            "isComplete",
            "trafficSecret",
            "exportSecret",
            "peerTransportParams",
            "serverName",
            "peerPublicKey",
            "negotiatedProtocol",
            "earlyDataAccepted",
            "resumptionTransportParams",
            "popNewSessionTicket",
            "wasResumed",
        }) |name| {
            if (!@hasDecl(S, name)) {
                @compileError("tls_backend.Session missing method: " ++ name);
            }
        }
        _ = B.caps;
        _ = B.Types;
        _ = B.Config;
    }
}

pub const HandshakeOutput = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    epoch_offsets: [max_epoch + 1]usize,
    ret: c_int,

    pub fn deinit(self: *HandshakeOutput) void {
        std.crypto.secureZero(u8, self.bytes);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn epochSlice(self: HandshakeOutput, epoch: Epoch) []const u8 {
        const idx: usize = @intFromEnum(epoch);
        return self.bytes[self.epoch_offsets[idx]..self.epoch_offsets[idx + 1]];
    }
};

test "tls_contract surface is importable" {
    try std.testing.expect(@typeInfo(Backend) == .@"enum");
    try std.testing.expectEqual(@as(u16, 0x39), quic_transport_parameters_ext);
}
