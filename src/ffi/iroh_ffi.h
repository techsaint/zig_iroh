/*
 * iroh_ffi.h — C-ABI surface of the Zig iroh port for the language-binding
 * packages (Kotlin / Python / Swift). This is the stable contract the
 * packages bind; it is NOT the optional stable-C-ABI/pkg-config row
 * (ffi-stable-c-abi-pkgconfig), just the bridge's current export header.
 *
 * Ownership contract:
 *   - iroh_endpoint_create() returns an OWNED opaque handle;
 *   - iroh_endpoint_close() is the only reaper — call it exactly once per
 *     handle (NULL-safe);
 *   - strings returned by iroh_ffi_version() / iroh_ffi_last_error() point to
 *     static storage — never free them;
 *   - no secret-key material ever crosses this boundary; the only identity
 *     exposed is the public node id.
 *
 * Status codes: IROH_OK (0) on success; negative on failure, with a
 * per-thread static description available via iroh_ffi_last_error().
 */
#ifndef IROH_FFI_H
#define IROH_FFI_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IROH_OK 0
#define IROH_ERR_INVALID (-1)        /* null handle / null out-pointer */
#define IROH_ERR_BUFFER_TOO_SMALL (-2) /* caller buffer smaller than needed */
#define IROH_ERR_INIT (-3)           /* endpoint construction failed */
#define IROH_ERR_NOMEM (-4)          /* allocator failure */

/** Opaque owned endpoint handle. */
typedef struct iroh_endpoint iroh_endpoint_t;

/** Library/product version ("zig-iroh-ffi/<product>+<git-hash>"). Static storage. */
const char *iroh_ffi_version(void);

/** Per-thread static description of the most recent failure ("" if none). */
const char *iroh_ffi_last_error(void);

/**
 * Create an endpoint with default options (generated keypair, loopback bind,
 * relay disabled). Performs a real socket bind through the product engine.
 * On success *out_endpoint holds an owned handle and IROH_OK is returned;
 * on failure *out_endpoint is NULL and a negative status is returned.
 */
int iroh_endpoint_create(iroh_endpoint_t **out_endpoint);

/**
 * Write the endpoint's public node id as a NUL-terminated z32 string
 * (52 chars + NUL => out_cap must be >= 53). Read-only on the handle.
 */
int iroh_endpoint_node_id(iroh_endpoint_t *endpoint, char *out_buf, size_t out_cap);

/** Close and reap an endpoint handle. NULL-safe; call exactly once per handle. */
void iroh_endpoint_close(iroh_endpoint_t *endpoint);

#ifdef __cplusplus
}
#endif

#endif /* IROH_FFI_H */
