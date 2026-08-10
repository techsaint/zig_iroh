//! engine-noq crypto shim (fork-isolation S6).
//!
//! `@import("tls_backend")` re-export of the product-selected TLS backend so
//! every existing comptime gate in `connection.zig` / `transport_noq.zig`
//! compiles UNCHANGED. The A2 transitional legacy-backed facade is retired;
//! this is the real tls_backend cutover of plan §6.

const B = @import("tls_backend");

// Backend availability (comptime gates ride these, unchanged).
pub const zigtls_enabled = (B.backend_id == .zigtls);
pub const picotls_enabled = (B.backend_id == .picotls);

// Capability + type table from the selected backend.
pub const caps = B.caps;
pub const Types = B.Types;
pub const backend = B.backend_id;

// Historical zigtls-only type names (collapse to zero-size when zigtls is off).
pub const ZigtlsResumptionTicket = B.ZigtlsResumptionTicket;
pub const ZigtlsTicketKeyManager = B.ZigtlsTicketKeyManager;
pub const ZigtlsReplayFilter = B.ZigtlsReplayFilter;
pub const ZigtlsTrustStore = B.ZigtlsTrustStore;
pub const ZigtlsOcspResponseView = B.ZigtlsOcspResponseView;

// Backend-agnostic contract surface (exact Config/type surface).
pub const Error = B.Error;
pub const Role = B.Role;
pub const Backend = B.Backend;
pub const Direction = B.Direction;
pub const Epoch = B.Epoch;
pub const max_epoch = B.max_epoch;
pub const max_secret_len = B.max_secret_len;
pub const TrafficSecret = B.TrafficSecret;
pub const quic_transport_parameters_ext = B.quic_transport_parameters_ext;
pub const SignatureScheme = B.SignatureScheme;
pub const SigningKey = B.SigningKey;
pub const X509ServerIdentity = B.X509ServerIdentity;
pub const Config = B.Config;
pub const HandshakeOutput = B.HandshakeOutput;

// Uniform Session (the selected backend's Session).
pub const Session = B.Session;
pub const EndpointHandshake = B.EndpointHandshake;

// Historical names kept so remaining references compile (A5).
pub const PicotlsSession = if (picotls_enabled) B.PicotlsSession else struct {};
