//! Shared noq TLS handshake surface + backend selection.
//!
//! This module owns the backend-agnostic types the QUIC connection driver codes
//! against (`Config` / `Backend` / `HandshakeOutput` / `TrafficSecret` /
//! `Epoch` / …). The concrete TLS backends live in sibling files and are
//! comptime-selected here (component-repo restructure Phase 1):
//!   - picotls → `crypto_picotls.zig` (C picotls + libcrypto), gated on
//!     `build_options.picotls`.
//!   - zigtls  → `crypto_zigtls.zig` (pure-Zig TLS), gated on
//!     `build_options.zigtls`.
//!
//! When a backend is compiled out its session type collapses to `struct {}` so
//! nothing downstream pulls the disabled backend's imports (picotls' `c.zig`
//! cImport → libpicotls/libcrypto; zigtls' module). A noq-zigtls product thus
//! links neither picotls nor libcrypto.

const std = @import("std");
const product_flags = @import("../product_flags.zig");
const key = @import("../key.zig");

pub const zigtls_enabled = product_flags.has_zigtls;
const zigtls = if (zigtls_enabled) @import("zigtls") else struct {};

/// picotls backend availability. When false the picotls C stack
/// (`crypto_picotls.zig` → `c.zig` → libpicotls/libcrypto) is never imported.
pub const picotls_enabled = product_flags.has_picotls;

pub const ZigtlsResumptionTicket = if (zigtls_enabled) zigtls.tls13.session.ResumptionTicket else struct {};
pub const ZigtlsTicketKeyManager = if (zigtls_enabled) zigtls.tls13.ticket_keys.Manager else struct {};

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
/// clients (QAD, draft-seemann-quic-address-discovery: RPK is not negotiable
/// with a stock rustls client). Server role only; when set, the session
/// presents this chain instead of the RPK SPKI and signs CertificateVerify
/// with `key`. zigtls backend only (the picotls glue is RPK-only; selecting
/// X.509 with picotls is an error).
pub const X509ServerIdentity = struct {
    /// DER cert chain, leaf first. The session copies what it needs at create.
    chain_der: []const []const u8,
    scheme: SignatureScheme,
    key: SigningKey,
};

pub const Config = struct {
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
    /// zigtls-only TLS 1.3 session resumption ticket. The TLS library owns
    /// binder/key-schedule semantics; this config only carries the selected
    /// cached ticket across the QUIC adapter boundary.
    zigtls_resumption_ticket: ?ZigtlsResumptionTicket = null,
    /// zigtls-only server-side ticket protector for issuing/opening TLS
    /// NewSessionTicket identities.
    zigtls_ticket_key_manager: ?*ZigtlsTicketKeyManager = null,
    /// zigtls-only: issue a post-handshake NewSessionTicket after a completed
    /// server handshake using the configured key manager.
    zigtls_auto_issue_new_session_ticket: bool = false,
    /// zigtls server CertificateRequest offer policy; null uses the TLS default.
    certificate_request_signature_algorithms: ?[]const u16 = null,
    /// X.509 server identity (QAD). Server role only; zigtls backend only.
    x509_server: ?X509ServerIdentity = null,
};

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

/// The picotls-backed session. Collapses to an empty struct when picotls is
/// compiled out so its `c.zig` cImport (and thus libpicotls/libcrypto) is never
/// pulled — mirrors the zigtls gate above.
pub const PicotlsSession = if (picotls_enabled) @import("crypto_picotls.zig").PicotlsSession else struct {};

test {
    if (picotls_enabled) _ = @import("crypto_picotls.zig");
}
