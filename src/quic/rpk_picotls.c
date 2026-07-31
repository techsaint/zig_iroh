#include "quic/rpk_picotls.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <picotls/openssl.h>
#include <stdlib.h>
#include <string.h>

#define IROH_PTLS_RPK_MAGIC 0x69726b70u

typedef struct {
    ptls_verify_certificate_t super;
    ptls_openssl_raw_pubkey_verify_certificate_t raw;
    uint32_t magic;
    int learn_peer;
    int has_peer;
    uint8_t peer[32];
    int has_candidate;
    uint8_t candidate[32];
    int (*inner_verifier)(void*, uint16_t, ptls_iovec_t, ptls_iovec_t);
    void* inner_verify_data;
} iroh_ptls_raw_pubkey_verifier_t;

typedef struct {
    ptls_context_t ctx;
    ptls_key_exchange_algorithm_t* key_exchanges[3];
    ptls_cipher_suite_t* cipher_suites[2];
} iroh_ptls_context_storage_t;

static void free_certificates(ptls_iovec_t* certs, size_t count)
{
    if (certs == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(certs[i].base);
    }
    free(certs);
}

static EVP_PKEY* load_private_key(const uint8_t* seed)
{
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, 32);
}

static EVP_PKEY* load_public_key(const uint8_t* bytes)
{
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, bytes, 32);
}

static int public_key_to_der(EVP_PKEY* key, ptls_iovec_t* out)
{
    int len = i2d_PUBKEY(key, NULL);
    if (len <= 0) {
        return -1;
    }

    uint8_t* bytes = malloc((size_t)len);
    if (bytes == NULL) {
        return -1;
    }

    uint8_t* cursor = bytes;
    int actual = i2d_PUBKEY(key, &cursor);
    if (actual != len || cursor != bytes + len) {
        free(bytes);
        return -1;
    }

    *out = ptls_iovec_init(bytes, (size_t)len);
    return 0;
}

static int bind_presented_raw_public_key(
    iroh_ptls_raw_pubkey_verifier_t* self,
    ptls_iovec_t* certs,
    size_t num_certs)
{
    if (num_certs != 1) {
        return -1;
    }

    const uint8_t* der = certs[0].base;
    EVP_PKEY* pubkey = d2i_PUBKEY(NULL, &der, (long)certs[0].len);
    if (pubkey == NULL) {
        return -1;
    }

    size_t raw_len = sizeof(self->candidate);
    if (EVP_PKEY_get_raw_public_key(pubkey, self->candidate, &raw_len) != 1 || raw_len != sizeof(self->candidate)) {
        EVP_PKEY_free(pubkey);
        return -1;
    }

    self->has_candidate = 1;
    if (self->learn_peer) {
        // Rebind the stock raw-key verifier to the DER key just presented by
        // this peer. Its callback will still install picotls' verify_sign,
        // so CertificateVerify proves possession of this exact key.
        EVP_PKEY_free(self->raw.expected_pubkey);
        self->raw.expected_pubkey = pubkey;
    } else {
        EVP_PKEY_free(pubkey);
    }
    return 0;
}

static int verify_raw_pubkey_and_publish(
    void* verify_ctx,
    uint16_t algo,
    ptls_iovec_t data,
    ptls_iovec_t signature)
{
    iroh_ptls_raw_pubkey_verifier_t* self = verify_ctx;
    if (self->inner_verifier == NULL || self->inner_verify_data == NULL) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    int (*inner)(void*, uint16_t, ptls_iovec_t, ptls_iovec_t) = self->inner_verifier;
    void* inner_data = self->inner_verify_data;
    self->inner_verifier = NULL;
    self->inner_verify_data = NULL;
    int ret = inner(inner_data, algo, data, signature);

    // B8 (noq crypto/rustls.rs:98-108 parity): picotls' stock verify_sign
    // flattens an Ed25519 CertificateVerify mismatch to PTLS_ERROR_LIBRARY
    // (internal class, no alert code), where rustls — the noq reference —
    // raises the decrypt_error alert. Remap so the caller can emit a
    // CRYPTO_ERROR (0x0100 + alert) transport close like noq does. The
    // teardown probe below passes data.base == NULL and returns 0 from the
    // inner call, so it is unaffected.
    if (ret == PTLS_ERROR_LIBRARY && data.base != NULL) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
    }

    // picotls calls the verifier with a null data pointer while tearing down an
    // unfinished handshake. That frees the OpenSSL key but never authenticates
    // it, so it must not populate the peer identity.
    if (data.base == NULL) {
        self->has_candidate = 0;
        return ret;
    }
    if (ret == 0 && self->has_candidate) {
        memcpy(self->peer, self->candidate, sizeof(self->peer));
        self->has_peer = 1;
    } else {
        self->has_peer = 0;
    }
    self->has_candidate = 0;
    return ret;
}

static int verify_raw_pubkey_and_store(
    ptls_verify_certificate_t* base,
    ptls_t* tls,
    const char* server_name,
    int (**verifier)(void*, uint16_t, ptls_iovec_t, ptls_iovec_t),
    void** verify_data,
    ptls_iovec_t* certs,
    size_t num_certs)
{
    (void)tls;
    iroh_ptls_raw_pubkey_verifier_t* self = (iroh_ptls_raw_pubkey_verifier_t*)base;
    if (bind_presented_raw_public_key(self, certs, num_certs) != 0) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
    int ret = self->raw.super.cb(&self->raw.super, tls, server_name, verifier, verify_data, certs, num_certs);
    if (ret != 0 || *verifier == NULL || *verify_data == NULL) {
        self->has_candidate = 0;
        return ret == 0 ? PTLS_ALERT_BAD_CERTIFICATE : ret;
    }
    self->inner_verifier = *verifier;
    self->inner_verify_data = *verify_data;
    *verifier = verify_raw_pubkey_and_publish;
    *verify_data = self;
    return 0;
}

static iroh_ptls_raw_pubkey_verifier_t* create_raw_pubkey_verifier(EVP_PKEY* expected_peer, int learn_peer)
{
    iroh_ptls_raw_pubkey_verifier_t* verifier = calloc(1, sizeof(*verifier));
    if (verifier == NULL) {
        return NULL;
    }
    if (ptls_openssl_raw_pubkey_init_verify_certificate(&verifier->raw, expected_peer) != 0) {
        free(verifier);
        return NULL;
    }

    verifier->super.cb = verify_raw_pubkey_and_store;
    verifier->super.algos = verifier->raw.super.algos;
    verifier->magic = IROH_PTLS_RPK_MAGIC;
    verifier->learn_peer = learn_peer;
    return verifier;
}

static void free_raw_pubkey_verifier(iroh_ptls_raw_pubkey_verifier_t* verifier)
{
    if (verifier == NULL) {
        return;
    }
    ptls_openssl_raw_pubkey_dispose_verify_certificate(&verifier->raw);
    free(verifier);
}

void iroh_ptls_clear_raw_public_key(ptls_context_t* ctx)
{
    if (ctx == NULL) {
        return;
    }

    free_certificates(ctx->certificates.list, ctx->certificates.count);
    ctx->certificates.list = NULL;
    ctx->certificates.count = 0;

    if (ctx->sign_certificate != NULL) {
        ptls_openssl_dispose_sign_certificate((ptls_openssl_sign_certificate_t*)ctx->sign_certificate);
        free(ctx->sign_certificate);
        ctx->sign_certificate = NULL;
    }

    if (ctx->verify_certificate != NULL && ctx->verify_certificate->cb == verify_raw_pubkey_and_store) {
        iroh_ptls_raw_pubkey_verifier_t* verifier =
            (iroh_ptls_raw_pubkey_verifier_t*)ctx->verify_certificate;
        if (verifier->magic == IROH_PTLS_RPK_MAGIC) {
            free_raw_pubkey_verifier(verifier);
            ctx->verify_certificate = NULL;
        }
    }

    ctx->use_raw_public_keys = 0;
    ctx->require_client_authentication = 0;
}

int iroh_ptls_configure_raw_public_key(
    ptls_context_t* ctx,
    const uint8_t* local_private_seed,
    const uint8_t* local_public_key,
    const uint8_t* expected_peer_public_key,
    int require_client_authentication)
{
    if (ctx == NULL || local_private_seed == NULL || local_public_key == NULL) {
        return -1;
    }

    EVP_PKEY* private_key = load_private_key(local_private_seed);
    EVP_PKEY* public_key = load_public_key(local_public_key);
    EVP_PKEY* expected_peer = expected_peer_public_key == NULL ? NULL : load_public_key(expected_peer_public_key);
    ptls_openssl_sign_certificate_t* signer = NULL;
    iroh_ptls_raw_pubkey_verifier_t* verifier = NULL;
    ptls_iovec_t* certs = NULL;
    int signer_initialized = 0;
    int ret = 0;

    if (private_key == NULL || public_key == NULL || (expected_peer_public_key != NULL && expected_peer == NULL)) {
        ret = -1;
        goto Exit;
    }

    signer = malloc(sizeof(*signer));
    // The stock verifier needs a key up front to advertise its signature
    // algorithms. In learned-peer mode it is replaced with the presented key
    // before the certificate callback delegates to it, so this local key is
    // only a safe bootstrap value, never a trust decision.
    verifier = create_raw_pubkey_verifier(
        expected_peer_public_key == NULL ? public_key : expected_peer,
        expected_peer_public_key == NULL);
    certs = calloc(1, sizeof(*certs));
    if (signer == NULL || verifier == NULL || certs == NULL) {
        ret = -1;
        goto Exit;
    }

    if (ptls_openssl_init_sign_certificate(signer, private_key) != 0) {
        ret = -1;
        goto Exit;
    }
    signer_initialized = 1;
    if (public_key_to_der(public_key, certs) != 0) {
        ret = -1;
        goto Exit;
    }

    iroh_ptls_clear_raw_public_key(ctx);
    ctx->certificates.list = certs;
    ctx->certificates.count = 1;
    certs = NULL;
    ctx->sign_certificate = &signer->super;
    signer = NULL;
    ctx->verify_certificate = &verifier->super;
    verifier = NULL;
    ctx->use_raw_public_keys = 1;
    ctx->require_client_authentication = require_client_authentication != 0;

Exit:
    if (private_key != NULL) {
        EVP_PKEY_free(private_key);
    }
    if (public_key != NULL) {
        EVP_PKEY_free(public_key);
    }
    if (expected_peer != NULL) {
        EVP_PKEY_free(expected_peer);
    }
    if (ret != 0) {
        if (signer != NULL) {
            if (signer_initialized) {
                ptls_openssl_dispose_sign_certificate(signer);
            }
            free(signer);
        }
        if (verifier != NULL) {
            free_raw_pubkey_verifier(verifier);
        }
        if (certs != NULL) {
            free_certificates(certs, certs[0].base == NULL ? 0 : 1);
        }
    }
    return ret;
}

int iroh_ptls_last_verified_peer_public_key(ptls_context_t* ctx, uint8_t* out_public_key)
{
    if (ctx == NULL || ctx->verify_certificate == NULL || out_public_key == NULL) {
        return -1;
    }

    iroh_ptls_raw_pubkey_verifier_t* verifier =
        (iroh_ptls_raw_pubkey_verifier_t*)ctx->verify_certificate;
    if (verifier->magic != IROH_PTLS_RPK_MAGIC || !verifier->has_peer) {
        return -1;
    }

    memcpy(out_public_key, verifier->peer, sizeof(verifier->peer));
    return 0;
}

void iroh_ptls_context_set_quic_defaults(ptls_context_t* ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->use_exporter = 1;
    ctx->omit_end_of_early_data = 1;
}

ptls_context_t* iroh_ptls_context_create(ptls_update_traffic_key_t* update_traffic_key)
{
    iroh_ptls_context_storage_t* storage = calloc(1, sizeof(*storage));
    if (storage == NULL) {
        return NULL;
    }

    /* rustls/iroh offers X25519 in its first QUIC ClientHello. Prefer it so the
     * server can answer in one flight, while retaining P-256 for existing peers. */
    storage->key_exchanges[0] = &ptls_openssl_x25519;
    storage->key_exchanges[1] = &ptls_openssl_secp256r1;
    storage->key_exchanges[2] = NULL;
    storage->cipher_suites[0] = &ptls_openssl_aes128gcmsha256;
    storage->cipher_suites[1] = NULL;

    storage->ctx.random_bytes = ptls_openssl_random_bytes;
    storage->ctx.get_time = &ptls_get_time;
    storage->ctx.key_exchanges = storage->key_exchanges;
    storage->ctx.cipher_suites = storage->cipher_suites;
    storage->ctx.update_traffic_key = update_traffic_key;
    iroh_ptls_context_set_quic_defaults(&storage->ctx);
    return &storage->ctx;
}

void iroh_ptls_context_destroy(ptls_context_t* ctx)
{
    if (ctx == NULL) {
        return;
    }
    iroh_ptls_clear_raw_public_key(ctx);
    free((iroh_ptls_context_storage_t*)ctx);
}

size_t iroh_ptls_secret_size(ptls_t* tls)
{
    ptls_cipher_suite_t* cipher = ptls_get_cipher(tls);
    if (cipher == NULL || cipher->hash == NULL) {
        return 0;
    }
    return cipher->hash->digest_size;
}

ptls_iovec_t iroh_ptls_iovec_init(const void* p, size_t len)
{
    return ptls_iovec_init(p, len);
}

ptls_handshake_properties_t* iroh_ptls_props_new(void)
{
    return calloc(1, sizeof(ptls_handshake_properties_t));
}

void iroh_ptls_props_free(ptls_handshake_properties_t* props)
{
    free(props);
}

void iroh_ptls_props_set_client_alpn(
    ptls_handshake_properties_t* props,
    const ptls_iovec_t* list,
    size_t count)
{
    if (props == NULL) {
        return;
    }
    props->client.negotiated_protocols.list = list;
    props->client.negotiated_protocols.count = count;
}

void iroh_ptls_props_set_additional_extensions(
    ptls_handshake_properties_t* props,
    ptls_raw_extension_t* extensions)
{
    if (props == NULL) {
        return;
    }
    props->additional_extensions = extensions;
}

void iroh_ptls_client_hello_server_name(
    ptls_on_client_hello_parameters_t* params,
    const uint8_t** base,
    size_t* len)
{
    if (params == NULL) {
        *base = NULL;
        *len = 0;
        return;
    }
    *base = params->server_name.base;
    *len = params->server_name.len;
}

void iroh_ptls_client_hello_negotiated_protocols(
    ptls_on_client_hello_parameters_t* params,
    ptls_iovec_t** list_out,
    size_t* count_out)
{
    if (list_out == NULL || count_out == NULL) {
        return;
    }
    if (params == NULL) {
        *list_out = NULL;
        *count_out = 0;
        return;
    }
    *list_out = params->negotiated_protocols.list;
    *count_out = params->negotiated_protocols.count;
}

void iroh_ptls_ctx_set_on_client_hello(ptls_context_t* ctx, ptls_on_client_hello_t* cb)
{
    if (ctx == NULL) {
        return;
    }
    ctx->on_client_hello = cb;
}

void iroh_ptls_props_set_collect_callbacks(
    ptls_handshake_properties_t* props,
    int (*collect_extension)(ptls_t*, ptls_handshake_properties_t*, uint16_t),
    int (*collected_extensions)(ptls_t*, ptls_handshake_properties_t*, ptls_raw_extension_t*))
{
    if (props == NULL) {
        return;
    }
    props->collect_extension = collect_extension;
    props->collected_extensions = collected_extensions;
}

void iroh_ptls_buffer_init(ptls_buffer_t* buf, void* smallbuf, size_t smallbuf_size)
{
    ptls_buffer_init(buf, smallbuf, smallbuf_size);
}

void iroh_ptls_buffer_dispose(ptls_buffer_t* buf)
{
    ptls_buffer_dispose(buf);
}
