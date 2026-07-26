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

/// The `-Dproduct=<id>` string this binary was built with (e.g. "default",
/// "noq-zigtls"). Harness adapters surface this so a measurement names the
/// SHIPPED product, not a runtime-selected engine inside an all-in-one binary.
pub const product_name = build_options.product;

pub const has_picoquic = build_options.picoquic;
pub const has_noq = build_options.noq;
pub const has_picotls = build_options.picotls;
/// Plain bool — matches `build.zig` `addOption(bool, "zigtls", ...)` (no optional, no `orelse`).
pub const has_zigtls = build_options.zigtls;
pub const has_gossip = build_options.gossip;

/// No native C in this build (full-zig / noq-zigtls).
pub const is_pure_zig = !has_picoquic and !has_picotls;

/// All-in-one residual (`-Dproduct=default`): both engines compile in. Mono
/// products (`picoquic-picotls` / `noq-picotls` / `noq-zigtls`) hard-build one.
pub const is_default_product = has_picoquic and has_noq;
pub const is_mono_picoquic = has_picoquic and !has_noq;
pub const is_mono_noq = has_noq and !has_picoquic;
