#ifndef IROH_QUIC_RPK_PICOTLS_H
#define IROH_QUIC_RPK_PICOTLS_H

#include <stddef.h>
#include <stdint.h>
#include <picotls.h>

int iroh_ptls_configure_raw_public_key(
    ptls_context_t* ctx,
    const uint8_t* local_private_seed,
    const uint8_t* local_public_key,
    const uint8_t* expected_peer_public_key,
    int require_client_authentication);

void iroh_ptls_clear_raw_public_key(ptls_context_t* ctx);

int iroh_ptls_last_verified_peer_public_key(ptls_context_t* ctx, uint8_t* out_public_key);

ptls_context_t* iroh_ptls_context_create(ptls_update_traffic_key_t* update_traffic_key);

void iroh_ptls_context_destroy(ptls_context_t* ctx);

void iroh_ptls_context_set_quic_defaults(ptls_context_t* ctx);

size_t iroh_ptls_secret_size(ptls_t* tls);

ptls_iovec_t iroh_ptls_iovec_init(const void* p, size_t len);

ptls_handshake_properties_t* iroh_ptls_props_new(void);

void iroh_ptls_props_free(ptls_handshake_properties_t* props);

void iroh_ptls_props_set_client_alpn(
    ptls_handshake_properties_t* props,
    const ptls_iovec_t* list,
    size_t count);

void iroh_ptls_props_set_additional_extensions(
    ptls_handshake_properties_t* props,
    ptls_raw_extension_t* extensions);

void iroh_ptls_client_hello_server_name(
    ptls_on_client_hello_parameters_t* params,
    const uint8_t** base,
    size_t* len);

void iroh_ptls_client_hello_negotiated_protocols(
    ptls_on_client_hello_parameters_t* params,
    ptls_iovec_t** list_out,
    size_t* count_out);

void iroh_ptls_ctx_set_on_client_hello(ptls_context_t* ctx, ptls_on_client_hello_t* cb);

void iroh_ptls_props_set_collect_callbacks(
    ptls_handshake_properties_t* props,
    int (*collect_extension)(ptls_t*, ptls_handshake_properties_t*, uint16_t),
    int (*collected_extensions)(ptls_t*, ptls_handshake_properties_t*, ptls_raw_extension_t*));

void iroh_ptls_buffer_init(ptls_buffer_t* buf, void* smallbuf, size_t smallbuf_size);

void iroh_ptls_buffer_dispose(ptls_buffer_t* buf);

#endif
