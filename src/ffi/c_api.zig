//! C-ABI export surface for the iroh-ffi language packages (Kotlin / Python /
//! Swift). This is an ADDITIVE layer over the public `Endpoint` facade: it
//! does not change the core API, and it never exposes secret-key material
//! across the ABI — the only identity a caller can read back is the public
//! node id.
//!
//! Ownership contract (see src/ffi/iroh_ffi.h):
//!   - `iroh_endpoint_create` returns an OWNED opaque handle;
//!   - `iroh_endpoint_close` is the only reaper (close + deinit + free);
//!   - no other function frees or retains caller memory.
//!
//! The error surface is a per-thread static string (`iroh_ffi_last_error`),
//! so no heap allocation ever crosses the boundary.

const std = @import("std");
const zig_iroh = @import("zig_iroh");
const build_options = @import("build_options");

const Endpoint = zig_iroh.Endpoint;

/// `zig-iroh-ffi/<product>+<git-hash>`, e.g. `zig-iroh-ffi/noq-zigtls+a1523381`.
const version_string: [:0]const u8 = build_options.version ++ "\x00";

/// ABI status codes (mirrored in iroh_ffi.h).
const IROH_OK: c_int = 0;
const IROH_ERR_INVALID: c_int = -1; // null handle / null out-pointer
const IROH_ERR_BUFFER_TOO_SMALL: c_int = -2; // caller buffer < needed
const IROH_ERR_INIT: c_int = -3; // endpoint construction failed (see last_error)
const IROH_ERR_NOMEM: c_int = -4; // allocator failure

/// Owned per-handle state. The endpoint holds an `std.Io` by value, so the
/// `Threaded` instance it derives from must share the handle's lifetime.
const FfiEndpoint = struct {
    io: std.Io.Threaded,
    ep: *Endpoint,
};

threadlocal var last_error_buf: [192:0]u8 = [_:0]u8{0} ** 192;

fn setLastError(comptime fmt: []const u8, args: anytype) void {
    _ = std.fmt.bufPrintZ(&last_error_buf, fmt, args) catch {};
}

/// Library/product version, e.g. for package-side diagnostics. The returned
/// pointer is to static storage; do not free it.
pub export fn iroh_ffi_version() [*:0]const u8 {
    return version_string.ptr;
}

/// Static per-thread description of the most recent failure on this thread,
/// or "" if none. The pointer is to static storage; do not free it.
pub export fn iroh_ffi_last_error() [*:0]const u8 {
    return &last_error_buf;
}

/// Create an endpoint with default options (generated keypair, loopback bind,
/// relay disabled) — this performs a real socket bind through the product
/// engine. On success `out_endpoint` holds an owned handle (IROH_OK); on
/// failure it is null and a negative status is returned.
pub export fn iroh_endpoint_create(out_endpoint: ?*?*anyopaque) c_int {
    const out = out_endpoint orelse {
        setLastError("iroh_endpoint_create: null out-pointer", .{});
        return IROH_ERR_INVALID;
    };
    out.* = null;
    const allocator = std.heap.c_allocator;
    const handle = allocator.create(FfiEndpoint) catch {
        setLastError("iroh_endpoint_create: out of memory", .{});
        return IROH_ERR_NOMEM;
    };
    handle.io = std.Io.Threaded.init(allocator, .{});
    handle.ep = Endpoint.init(allocator, handle.io.io(), .{}) catch |err| {
        setLastError("iroh_endpoint_create: endpoint init failed: {s}", .{@errorName(err)});
        handle.io.deinit();
        allocator.destroy(handle);
        return IROH_ERR_INIT;
    };
    out.* = handle;
    setLastError("", .{});
    return IROH_OK;
}

/// Write the endpoint's public node id as a NUL-terminated z32 string
/// (52 chars + NUL ⇒ `out_cap` must be >= 53). Read-only on the handle.
pub export fn iroh_endpoint_node_id(endpoint: ?*anyopaque, out_buf: ?[*]u8, out_cap: usize) c_int {
    const handle: *FfiEndpoint = @ptrCast(@alignCast(endpoint orelse {
        setLastError("iroh_endpoint_node_id: null endpoint handle", .{});
        return IROH_ERR_INVALID;
    }));
    const buf = out_buf orelse {
        setLastError("iroh_endpoint_node_id: null out-buffer", .{});
        return IROH_ERR_INVALID;
    };
    const z32 = handle.ep.id().toZ32();
    if (out_cap < z32.len + 1) {
        setLastError("iroh_endpoint_node_id: need {d} bytes, got {d}", .{ z32.len + 1, out_cap });
        return IROH_ERR_BUFFER_TOO_SMALL;
    }
    @memcpy(buf[0..z32.len], &z32);
    buf[z32.len] = 0;
    return IROH_OK;
}

/// Close and reap an endpoint handle created by `iroh_endpoint_create`.
/// Null-safe; every handle must pass through here exactly once.
pub export fn iroh_endpoint_close(endpoint: ?*anyopaque) void {
    const handle: *FfiEndpoint = @ptrCast(@alignCast(endpoint orelse return));
    handle.ep.close();
    handle.ep.deinit();
    handle.io.deinit();
    std.heap.c_allocator.destroy(handle);
}
