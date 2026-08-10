//! engine-noq — the noq QUIC engine module root (fork-isolation migration S4).
//!
//! The `engine` module: the pure-Zig NoQ QUIC port, extracted as one cohesive
//! subtree. Wiring (build.zig `createSeamModules`):
//!   engine → { shared, transport (the product door), tls_backend, zigtls }
//! The product door binds `Seam(bundle)` directly. `crypto.zig` is the
//! `@import("tls_backend")` shim.
//!
//! The picoquic product never wires this module: no picoquic compilation
//! claims or compiles any file in this directory — the MONO claim now holds
//! at the source-graph level (the S4 headline; see the module-list diff in
//! the slice evidence).

const std = @import("std");
const shared = @import("shared");

/// The engine transport surface (vtable impl + UDP pump + CID router).
pub const transport_noq = @import("transport_noq.zig");
/// The noq QUIC codec/driver namespace (varint … connection, oracle_pair).
pub const quic = @import("quic.zig");
/// S6 crypto shim (`@import("tls_backend")`).
pub const crypto = @import("crypto.zig");
/// CP-1 home (A6): the QAD (`/iroh-qad/0`) server — noq-engine-only. Its
/// X.509/zigtls paths are comptime-gated on the backend caps, so it compiles
/// under noq-picotls too (the §8 placement probe that selected `engine-noq/`
/// over `products/`).
pub const qad = @import("qad.zig");
/// Engine-side congestion-controller namespace (`Kind` aliases the shared
/// contract's `CongestionKind` — the factory Options surface names it).
pub const congestion = @import("congestion.zig");
/// QUIC transport-parameters codec (also consumed by the picotls N3b5-5a
/// handshake test through `@import("engine")`).
pub const transport_parameters = @import("transport_parameters.zig");
/// Deterministic noq-engine wire vectors (Tier-0; `zig_iroh.stream_capability_vectors`).
pub const stream_capability_vectors = @import("stream_capability_vectors.zig");

/// A6/CP-2 — the engine bundle, first materialized here in S4 and now bound
/// directly into the selected product door. Its `relay_datagram_capacity` is
/// cross-checked below.
pub const bundle: shared.transport_contract.EngineBundle = .{
    .ConnImpl = transport_noq.ConnectionImpl,
    .SendImpl = transport_noq.SendImpl,
    .RecvImpl = transport_noq.RecvImpl,
    .Endpoint = transport_noq.Endpoint,
    .Factory = transport_noq,
    .engine = .noq,
    .relay_datagram_capacity = quic.connection.max_datagram,
};

comptime {
    // A6/CP-2 per-product cross-check (this root compiles once per product
    // that selects the noq engine, including the relay-server variant):
    // EXACT declared semantics — the engine's datagram ceiling must EQUAL the
    // shared relay budget (`shared/limits.zig max_datagram`), not merely
    // exceed it. The cap/cap+1 relay-queue boundary tests in
    // `shared/endpoint_relay.zig` (accept exactly `limits.max_datagram`,
    // drop `max_datagram + 1`) are bound to THIS bundle's declared capacity
    // through this equality: drift fails the build, never the wire.
    if (bundle.relay_datagram_capacity != shared.limits.max_datagram)
        @compileError("A6/CP-2 drift: engine max_datagram != shared.limits.max_datagram (the relay budget)");
}

test "A6/CP-2: bundle.relay_datagram_capacity equals the shared relay budget (exact, not >=)" {
    try std.testing.expectEqual(shared.limits.max_datagram, bundle.relay_datagram_capacity);
    try std.testing.expectEqual(quic.connection.max_datagram, bundle.relay_datagram_capacity);
}

test {
    // Per-module test collection (migration P5): the engine's tests are
    // collected by its OWN test binary (`zig build test` aggregates it for
    // noq products); a reference from another module's root collects nothing.
    _ = transport_noq;
    _ = quic; // chains varint…connection, oracle_pair + the crypto facades
    _ = qad;
    _ = stream_capability_vectors;
    // CC tests: explicit reference-block collection (P5 discipline).
    _ = @import("congestion.zig");
    _ = @import("congestion/bbr3.zig");
    _ = @import("congestion/cubic.zig");
    _ = @import("congestion/new_reno.zig");
    // Engine-side harness files: the 5c/5d-B real-socket gate (also filtered
    // by the `interop-noq` step), the S3 facade tests, the probe library.
    _ = @import("harness/noq_gate.zig");
    _ = @import("harness/facade_zero_rtt.zig");
    _ = @import("harness/harness_probes.zig");
    // S6 composition tests (relocated out of tls_backend to break the
    // test-only tls→engine cycle; collected here so P5 count holds).
    if (comptime shared.product_flags.has_zigtls) {
        _ = @import("harness/noq_zigtls_gate.zig");
    }
    if (comptime shared.product_flags.has_picotls) {
        _ = @import("harness/picotls_tp_handshake_test.zig");
    }
}

// Preserves the historic mono-noq collected skip that lived in the S7-retired
// `connection/tls_name.zig` compatibility forwarder. The real C decoder test
// remains engine-picoquic-owned; this records its deliberate non-applicability.
test "SNI encode/decode roundtrip via C iroh_decode_iroh_sni" {
    return error.SkipZigTest;
}
