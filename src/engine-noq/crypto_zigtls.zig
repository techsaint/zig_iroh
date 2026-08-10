//! engine-noq zigtls facade (S6): re-exports the selected tls_backend when it is
//! zigtls. Historical `@import("crypto_zigtls.zig")` sibling imports resolve here.
//! Only analyzed when `crypto.zigtls_enabled` is true at the call site.

const B = @import("tls_backend");

pub const session = B.session;
pub const ZigtlsSession = B.ZigtlsSession;
pub const EndpointHandshake = B.EndpointHandshake;
