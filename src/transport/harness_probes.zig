//! Owning-layer probe library for driver-grade security gates (S2-A3).
//!
//! Extracted from the proven frozen-oracle patterns in `noq_zigtls_gate.zig`
//! (READ-ONLY — do not edit that file from this library's consumers for SOLVE
//! work). Use these probes so attack #N does not re-derive attack #2's lesson:
//! server-auth fail-closed lives at NOQ reject/verified flags (and/or zigtls
//! typed errors), **not** at client `connect()` alone.
//!
//! Doctrine: `docs/guidance/driver-grade-harness/owning-layer-probe-doctrine.md`
//!
//! This module is **test/harness infrastructure only**. It does not change
//! production security enforcement.

const std = @import("std");
const tr = @import("../transport.zig");
const factory = @import("factory.zig");
const noq_ep = @import("transport_noq.zig");

/// Options for the reject pump. Defaults match the zigtls SECURITY-PREP gate:
/// a fixed iteration cap is too short for zigtls (handshake reaches
/// CertificateVerify after picotls would already have rejected).
pub const PumpOpts = struct {
    /// Wall-clock deadline (awake clock). 10s ≈ transport_noq.handshake_timeout_ns.
    limit_ns: i64 = 10 * std.time.ns_per_s,
    /// Sleep between pumps (cooperative single-threaded).
    sleep_ms: i64 = 1,
};

/// Narrow a factory `AnyEndpoint` known to be noq. Panic on picoquic — probes
/// are NOQ transport-layer by design.
pub fn asNoq(any: factory.AnyEndpoint) *noq_ep.Endpoint {
    return switch (any) {
        .noq => |e| e,
        .picoquic => unreachable,
    };
}

/// Time-bounded pump until `serverHandshakeRejected()` is true.
/// Returns `error.Timeout` if the deadline elapses without a reject flag.
pub fn pumpUntilServerRejects(server: *noq_ep.Endpoint, opts: PumpOpts) tr.Error!void {
    const io = std.testing.io;
    const started_ns = std.Io.Clock.now(.awake, io).nanoseconds;
    while (true) {
        try server.pumpForTest();
        if (server.serverHandshakeRejected()) return;
        const now_ns = std.Io.Clock.now(.awake, io).nanoseconds;
        if (now_ns - started_ns >= opts.limit_ns) return error.Timeout;
        io.sleep(std.Io.Duration.fromMilliseconds(opts.sleep_ms), .awake) catch {};
    }
}

/// Owning-layer negative assertion for server-auth reject (glue layer).
/// Asserts reject flag **and** that no verified peer was published.
/// Does **not** assert a zigtls reason code (TlsSession flattens to PicotlsError).
pub fn expectServerAuthReject(server: *const noq_ep.Endpoint) !void {
    try std.testing.expect(server.serverHandshakeRejected());
    try std.testing.expect(!server.serverHasVerifiedPeer());
}

/// Owning-layer positive assertion: a used server conn completed peer verify.
pub fn expectServerAuthAccept(server: *const noq_ep.Endpoint) !void {
    try std.testing.expect(server.serverHasVerifiedPeer());
}
