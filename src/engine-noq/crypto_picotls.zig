//! engine-noq picotls facade (S6): re-exports the selected tls_backend when it is
//! picotls. Historical `@import("crypto_picotls.zig")` sibling imports resolve here.
//! Only analyzed when `crypto.picotls_enabled` is true at the call site.

const B = @import("tls_backend");

pub const PicotlsSession = B.PicotlsSession;
pub const EndpointHandshake = B.EndpointHandshake;
