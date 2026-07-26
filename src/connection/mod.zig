//! Connection-core implementation surface.
//!
//! S1 starts with the picoquic/picotls binding and the TLS name rules. The real
//! endpoint implementation lives here so the frozen Tier-0 transport contract
//! stays unchanged.

pub const c = @import("c.zig");
pub const context = @import("context.zig");
pub const loopback = @import("loopback.zig");
pub const tls_name = @import("tls_name.zig");

test {
    _ = c;
    _ = context;
    _ = loopback;
    _ = tls_name;
}
