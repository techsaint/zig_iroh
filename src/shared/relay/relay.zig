//! Relay module entry point — DERP protocol codec, client, and server.

pub const proto = @import("proto.zig");
pub const handshake = @import("handshake.zig");
pub const access = @import("access.zig");
pub const client = @import("client.zig");
pub const relay_map = @import("relay_map.zig");
pub const server = @import("server.zig");
/// WebSocket framing codec. Exported for the relay round-trip harness
/// (relay_roundtrip_test.zig), which used to path-import src/relay/ws.zig;
/// post-S2 it consumes the shared module instead. Not on the public
/// `zig_iroh.relay` compat surface (it never was). Test collection unchanged:
/// ws.zig was never referenced from a test block and still is not.
pub const ws = @import("ws.zig");
pub const tls_wrapper = @import("tls_wrapper.zig");
pub const config = @import("config.zig");
pub const metrics = @import("metrics.zig");
// `qad` is deliberately not here: it imports the concrete NoQ engine and
// crypto selector. It is engine-noq-owned and product roots compose it into
// their conditional public relay namespace; shared structurally cannot reach it.
pub const acme = @import("acme/acme.zig");

test {
    _ = proto;
    _ = handshake;
    _ = access;
    _ = client;
    _ = relay_map;
    _ = server;
    _ = tls_wrapper;
    _ = config;
    _ = metrics;
    _ = acme;
}
