//! Comptime discovery product axis — concrete type, zero runtime dispatch.
//!
//! Selected by `product_flags.has_discovery` (sourced from `products.zig` via
//! `build_options`). Production products monomorphize against `DiscoveryClient`.
//! Unit tests pass `*StaticResolver` / `*MemoryLookup` / fakes as `anytype` into
//! `connect.connectById*` — no `*anyopaque` resolver vtable.

const product_flags = @import("../product_flags.zig");
const discovery = @import("discovery.zig");

/// Product-selected concrete discovery type. `void` when the product has none.
pub const ProductDiscovery = if (product_flags.has_discovery)
    discovery.DiscoveryClient
else
    void;

pub const has_discovery = product_flags.has_discovery;
