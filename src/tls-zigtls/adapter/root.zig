//! tls-zigtls adapter — the zigtls TLS backend module (`tls_backend` role).
//!
//! Fork-isolation S6: presents the uniform Session surface over the relocated
//! pure-Zig zigtls adapter. Full capability set (0-RTT, tickets, X.509, OCSP).

const std = @import("std");
const shared = @import("shared");
const tls = shared.tls_contract;
const zigtls = @import("zigtls");

pub const backend_id: tls.Backend = .zigtls;

pub const caps: tls.Caps = .{
    .zero_rtt = true,
    .session_tickets = true,
    .x509_server_identity = true,
    .x509_trust_store = true,
    .ocsp = true,
    .client_cert_request_algs = true,
};

pub const Types: tls.BackendTypes = .{
    .ResumptionTicket = zigtls.tls13.session.ResumptionTicket,
    .TicketKeyManager = zigtls.tls13.ticket_keys.Manager,
    .ReplayFilter = zigtls.tls13.early_data.ReplayFilter,
    .TrustStore = zigtls.tls13.trust_store.TrustStore,
    .OcspResponseView = zigtls.tls13.ocsp.ResponseView,
    .NewSessionTicketInfo = zigtls.tls13.session.NewSessionTicketInfo,
};

pub const Config = tls.ConfigFor(Types);

const zigtls_adapter = @import("crypto_zigtls.zig");

/// Uniform Session surface. ZigtlsSession already implements every method of
/// the 15-method surface, including the capability methods.
pub const Session = zigtls_adapter.ZigtlsSession;
pub const EndpointHandshake = zigtls_adapter.EndpointHandshake;
pub const ZigtlsSession = zigtls_adapter.ZigtlsSession;
/// Historical re-export used by Connection.popZigtlsNewSessionTicket's return type.
pub const session = zigtls_adapter.session;

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

// Historical type names.
pub const ZigtlsResumptionTicket = Types.ResumptionTicket;
pub const ZigtlsTicketKeyManager = Types.TicketKeyManager;
pub const ZigtlsReplayFilter = Types.ReplayFilter;
pub const ZigtlsTrustStore = Types.TrustStore;
pub const ZigtlsOcspResponseView = Types.OcspResponseView;

comptime {
    tls.verifyBackend(@This());
}

test {
    _ = zigtls_adapter;
    _ = @import("noq_zigtls_gate.zig");
    _ = Session;
}
