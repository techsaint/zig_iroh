//! Relay module entry point — DERP protocol codec, client, and server.

pub const proto = @import("proto.zig");
pub const handshake = @import("handshake.zig");
pub const access = @import("access.zig");
pub const client = @import("client.zig");
pub const server = @import("server.zig");
pub const tls_wrapper = @import("tls_wrapper.zig");

test {
    _ = proto;
    _ = handshake;
    _ = access;
    _ = client;
    _ = server;
    _ = tls_wrapper;
}
