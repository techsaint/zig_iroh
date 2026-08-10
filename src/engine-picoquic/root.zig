//! engine-picoquic — the picoquic QUIC engine module root (fork-isolation S5).
//!
//! The `engine` module for picoquic-picotls. It owns the Picoquic Zig binding,
//! its RPK C glue, and the picoquic-specific SNI C-decoder cross-check. The
//! product door binds this engine directly through `Seam(bundle)`.

const std = @import("std");
const shared = @import("shared");

/// Picoquic endpoint and its frozen transport-contract implementation types.
pub const transport_endpoint = @import("transport/endpoint.zig");
pub const transport_stream = @import("transport/stream.zig");
pub const transport_pump = @import("transport/pump.zig");
pub const transport_characterization = @import("transport/characterization.zig");
pub const connection = @import("connection/connection.zig");
pub const tls_name = @import("tls_name.zig");

/// A6/CP-2 — picoquic's bundle. Its declared ceiling is bound directly into
/// the selected product door.
pub const bundle: shared.transport_contract.EngineBundle = .{
    .ConnImpl = transport_endpoint.ConnectionImpl,
    .SendImpl = transport_stream.SendImpl,
    .RecvImpl = transport_stream.RecvImpl,
    .Endpoint = transport_endpoint.Endpoint,
    .Factory = transport_endpoint,
    .engine = .picoquic,
    .relay_datagram_capacity = shared.limits.max_datagram,
};

comptime {
    // EXACT declared semantics: the engine capacity must EQUAL (not merely
    // exceed) the shared relay budget, so a drift fails at compile time.
    if (bundle.relay_datagram_capacity != shared.limits.max_datagram)
        @compileError("A6/CP-2 drift: picoquic relay_datagram_capacity != shared.limits.max_datagram (the relay budget)");
}

test "A6/CP-2: picoquic bundle.relay_datagram_capacity equals the shared relay budget (exact, not >=)" {
    try std.testing.expectEqual(shared.limits.max_datagram, bundle.relay_datagram_capacity);
}

test {
    // Per-module test collection (migration P5): this engine's unit tests are
    // collected by its own binary in `zig build test` for picoquic-picotls.
    _ = transport_endpoint;
    _ = transport_stream;
    _ = transport_pump;
    _ = transport_characterization;
    _ = connection;
    _ = tls_name;
}
