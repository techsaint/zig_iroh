//! tls-picotls — the picotls TLS backend module (`tls_backend` role).
//!
//! Fork-isolation S6: presents the uniform Session surface over the relocated
//! picotls adapter. Capability methods that zigtls alone implements return
//! TODAY'S EXACT `false`/`null` values — zero crypto-semantic change.

const shared = @import("shared");
const tls = shared.tls_contract;

pub const backend_id: tls.Backend = .picotls;

pub const caps: tls.Caps = .{
    .zero_rtt = false,
    .session_tickets = false,
    .x509_server_identity = false,
    .x509_trust_store = false,
    .ocsp = false,
    .client_cert_request_algs = false,
};

/// Zero-size stand-ins — exactly today's `else struct {}` collapse for a
/// picotls product, relocated into the backend module.
pub const Types: tls.BackendTypes = .{
    .ResumptionTicket = tls.EmptyType,
    .TicketKeyManager = tls.EmptyType,
    .ReplayFilter = tls.EmptyType,
    .TrustStore = tls.EmptyType,
    .OcspResponseView = tls.EmptyType,
    .NewSessionTicketInfo = tls.EmptyType,
};

pub const Config = tls.ConfigFor(Types);

const picotls_adapter = @import("crypto_picotls.zig");

/// Uniform Session surface = the existing PicotlsSession (capability shims
/// added on the struct itself; values match the pre-S6 TlsSession picotls arm).
pub const Session = picotls_adapter.PicotlsSession;
pub const PicotlsSession = picotls_adapter.PicotlsSession;
pub const EndpointHandshake = picotls_adapter.EndpointHandshake;

// Re-export contract types so engine-noq/crypto.zig can alias one place.
pub const Error = tls.Error;
pub const Role = tls.Role;
pub const Backend = tls.Backend;
pub const Direction = tls.Direction;
pub const Epoch = tls.Epoch;
pub const max_epoch = tls.max_epoch;
pub const max_secret_len = tls.max_secret_len;
pub const TrafficSecret = tls.TrafficSecret;
pub const quic_transport_parameters_ext = tls.quic_transport_parameters_ext;
pub const SignatureScheme = tls.SignatureScheme;
pub const SigningKey = tls.SigningKey;
pub const X509ServerIdentity = tls.X509ServerIdentity;
pub const HandshakeOutput = tls.HandshakeOutput;
pub const Caps = tls.Caps;
pub const BackendTypes = tls.BackendTypes;

// Historical type names (collapse to zero-size on picotls).
pub const ZigtlsResumptionTicket = Types.ResumptionTicket;
pub const ZigtlsTicketKeyManager = Types.TicketKeyManager;
pub const ZigtlsReplayFilter = Types.ReplayFilter;
pub const ZigtlsTrustStore = Types.TrustStore;
pub const ZigtlsOcspResponseView = Types.OcspResponseView;

comptime {
    tls.verifyBackend(@This());
}

test {
    _ = picotls_adapter;
    _ = Session;
}
