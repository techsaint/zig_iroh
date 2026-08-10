//! Semantic product-flag facade for `src/` (component-repo-restructure tail #1).
//!
//! `products.zig` is PURE DATA `@import`ed by `build.zig` — it must NOT import
//! `build_options` (that would break the build.zig import graph). `build.zig`
//! derives the per-product `build_options` flags FROM `products.zig`; this
//! module is the src-only re-export of those already-derived comptime flags
//! under semantic names so call sites do not scatter raw `build_options.*`.
//!
//! This is NOT a second config source. SoT for the BUILD remains `products.zig`.

const build_options = @import("build_options");

/// The `-Dproduct=<id>` string this binary was built with (e.g.
/// "picoquic-picotls", "noq-zigtls"). Harness adapters surface this so a
/// measurement names the SHIPPED product.
pub const product_name = build_options.product;

pub const has_picoquic = build_options.picoquic;
pub const has_noq = build_options.noq;
pub const has_picotls = build_options.picotls;
/// Plain bool — matches `build.zig` `addOption(bool, "zigtls", ...)` (no optional, no `orelse`).
pub const has_zigtls = build_options.zigtls;
pub const has_gossip = build_options.gossip;
/// Client DNS/pkarr discovery composition is compiled in for this product.
pub const has_discovery = build_options.discovery;

/// No native C in this build (full-zig / noq-zigtls).
pub const is_pure_zig = !has_picoquic and !has_picotls;

/// Every product is MONO: exactly one QUIC engine compiles in, so nothing in
/// `src/` needs a runtime engine union or a type-erased transport vtable.
pub const is_mono_picoquic = has_picoquic and !has_noq;
pub const is_mono_noq = has_noq and !has_picoquic;

comptime {
    if (has_picoquic == has_noq) @compileError("product must build exactly one QUIC engine (picoquic XOR noq)");
}
