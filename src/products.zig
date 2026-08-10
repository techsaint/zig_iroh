//! Product configuration — the build.zig SOURCE OF TRUTH for the
//! component-repo restructure (Phase 1: comptime-gate the base so a single
//! source tree compiles into narrower products via `-Dproduct=<id>`).
//!
//! This is PURE DATA. It is `@import`ed by `build.zig` to drive the native
//! link/C-source selection (gate (b): product-conditional build.zig) AND it is
//! mirrored into `build_options` so Zig comptime can elide disabled subsystems
//! (gate (a): zig comptime elision). The two gates MUST agree — this file is the
//! single place both read from.
//!
//! Every product is MONO: exactly one QUIC engine compiles in, so `src/` never
//! carries a runtime engine union. Omitting `-Dproduct` selects
//! `picoquic-picotls`; CI covers both engines by running each id explicitly
//! (`zig build test-all-mono-products`).
//!
//! Feature axes:
//!   - `picoquic` — the picoquic C engine (`transport/endpoint.zig`,
//!     `connection/*`, `src/connection/rpk.c`).
//!     Pulls libpicoquic + libpicotls (static) + libcrypto (system).
//!   - `noq`      — the greenfield pure-Zig noq engine (`quic/*`,
//!     `transport/transport_noq.zig`). No C engine of its own; borrows a TLS
//!     backend (picotls or zigtls).
//!   - `picotls`  — the picotls C TLS backend (`quic/crypto_picotls.zig`,
//!     `src/quic/rpk_picotls.c`). Pulls libpicotls + libcrypto (system).
//!   - `zigtls`   — the experimental pure-Zig TLS backend (no C, no libcrypto).
//!     Every shipped product pins it; `null` (inherit `-Dzigtls`) remains
//!     available for a future product that wants the build-flag opt-in.
//!   - `gossip`   — the gossip layer (`gossip/*`). It owns a product-selected
//!     factory endpoint and uses only the neutral transport/factory surface.
//!   - `discovery` — client-side DNS/pkarr discovery composition. When false,
//!     `Endpoint.connectById` is comptime-unavailable; when true, the product
//!     monomorphizes against a concrete `DiscoveryClient` (no runtime resolver
//!     vtable). Configuration data (pkarr/DoH URLs) remains runtime data.

pub const Product = struct {
    picoquic: bool,
    noq: bool,
    picotls: bool,
    /// null = inherit `-Dzigtls`; a bool pins the backend for this product.
    zigtls: ?bool,
    gossip: bool,
    discovery: bool,
};

pub const Id = enum {
    /// picoquic engine only (no noq), picotls, gossip on. The `-Dproduct`
    /// default when the flag is omitted.
    @"picoquic-picotls",
    /// noq engine only, picotls TLS, no picoquic, gossip on. (Pilot A)
    @"noq-picotls",
    /// noq engine only, zigtls TLS forced on, no picoquic/picotls/libcrypto,
    /// gossip on. (Pilot B)
    @"noq-zigtls",
};

pub fn get(id: Id) Product {
    return switch (id) {
        .@"picoquic-picotls" => .{
            .picoquic = true,
            .noq = false,
            .picotls = true,
            .zigtls = false,
            .gossip = true,
            .discovery = true,
        },
        .@"noq-picotls" => .{
            .picoquic = false,
            .noq = true,
            .picotls = true,
            .zigtls = false,
            .gossip = true,
            .discovery = true,
        },
        .@"noq-zigtls" => .{
            .picoquic = false,
            .noq = true,
            .picotls = false,
            .zigtls = true,
            .gossip = true,
            .discovery = true,
        },
    };
}

/// Parse a `-Dproduct=<name>` string into an `Id`. Returns null on an unknown
/// name so build.zig can fail with a listing of the valid product ids.
pub fn parseId(name: []const u8) ?Id {
    inline for (@typeInfo(Id).@"enum".fields) |field| {
        if (eql(name, field.name)) return @field(Id, field.name);
    }
    return null;
}

/// A comma-free listing of the valid product ids for error messages.
pub const id_list = blk: {
    var s: []const u8 = "";
    for (@typeInfo(Id).@"enum".fields, 0..) |field, i| {
        s = s ++ (if (i == 0) "" else ", ") ++ field.name;
    }
    break :blk s;
};

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}
