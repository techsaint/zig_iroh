#include "connection/rpk.h"

#include <openssl/evp.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include <string.h>
#include <stdlib.h>
#include "picoquic_internal.h"

typedef struct {
    picoquic_cnx_t* cnx;
    int has_expected;
    uint8_t expected[32];
    int has_verified;
    uint8_t peer[32];
} iroh_rpk_cnx_peer_t;

typedef struct {
    ptls_verify_certificate_t super;
    iroh_rpk_cnx_peer_t* cnx_peers;
    size_t cnx_peer_count;
    size_t cnx_peer_capacity;
} iroh_raw_pubkey_verifier_t;

static void free_raw_pubkey_verifier(ptls_verify_certificate_t* verifier)
{
    iroh_raw_pubkey_verifier_t* self = (iroh_raw_pubkey_verifier_t*)verifier;
    free(self->cnx_peers);
    free(verifier);
}

static const uint16_t ed25519_signature_schemes[] = { PTLS_SIGNATURE_ED25519, UINT16_MAX };

static iroh_rpk_cnx_peer_t* find_cnx_peer(iroh_raw_pubkey_verifier_t* self, picoquic_cnx_t* cnx)
{
    for (size_t i = 0; i < self->cnx_peer_count; i++) {
        if (self->cnx_peers[i].cnx == cnx) {
            return &self->cnx_peers[i];
        }
    }
    return NULL;
}

static int set_cnx_peer(iroh_raw_pubkey_verifier_t* self, picoquic_cnx_t* cnx, const uint8_t* peer)
{
    iroh_rpk_cnx_peer_t* entry = find_cnx_peer(self, cnx);
    if (entry != NULL) {
        memcpy(entry->peer, peer, 32);
        entry->has_verified = 1;
        return 0;
    }

    if (self->cnx_peer_count == self->cnx_peer_capacity) {
        size_t new_capacity = (self->cnx_peer_capacity == 0) ? 4 : self->cnx_peer_capacity * 2;
        iroh_rpk_cnx_peer_t* grown =
            realloc(self->cnx_peers, new_capacity * sizeof(*self->cnx_peers));
        if (grown == NULL) {
            return -1;
        }
        self->cnx_peers = grown;
        self->cnx_peer_capacity = new_capacity;
    }

    entry = &self->cnx_peers[self->cnx_peer_count++];
    memset(entry, 0, sizeof(*entry));
    entry->cnx = cnx;
    memcpy(entry->peer, peer, 32);
    entry->has_verified = 1;
    return 0;
}

static int set_cnx_expected(iroh_raw_pubkey_verifier_t* self, picoquic_cnx_t* cnx, const uint8_t* expected)
{
    iroh_rpk_cnx_peer_t* entry = find_cnx_peer(self, cnx);
    if (entry == NULL) {
        if (self->cnx_peer_count == self->cnx_peer_capacity) {
            size_t new_capacity = (self->cnx_peer_capacity == 0) ? 4 : self->cnx_peer_capacity * 2;
            iroh_rpk_cnx_peer_t* grown =
                realloc(self->cnx_peers, new_capacity * sizeof(*self->cnx_peers));
            if (grown == NULL) {
                return -1;
            }
            self->cnx_peers = grown;
            self->cnx_peer_capacity = new_capacity;
        }
        entry = &self->cnx_peers[self->cnx_peer_count++];
        memset(entry, 0, sizeof(*entry));
        entry->cnx = cnx;
    }
    if (expected != NULL) {
        memcpy(entry->expected, expected, 32);
        entry->has_expected = 1;
    } else {
        entry->has_expected = 0;
    }
    return 0;
}

static int get_cnx_peer(iroh_raw_pubkey_verifier_t* self, picoquic_cnx_t* cnx, uint8_t* out)
{
    iroh_rpk_cnx_peer_t* entry = find_cnx_peer(self, cnx);
    if (entry == NULL || !entry->has_verified) {
        return -1;
    }
    memcpy(out, entry->peer, 32);
    return 0;
}

static void forget_cnx_peer(iroh_raw_pubkey_verifier_t* self, picoquic_cnx_t* cnx)
{
    for (size_t i = 0; i < self->cnx_peer_count; i++) {
        if (self->cnx_peers[i].cnx != cnx) {
            continue;
        }

        size_t last = self->cnx_peer_count - 1;
        memset(&self->cnx_peers[i], 0, sizeof(self->cnx_peers[i]));
        if (i != last) {
            self->cnx_peers[i] = self->cnx_peers[last];
            memset(&self->cnx_peers[last], 0, sizeof(self->cnx_peers[last]));
        }
        self->cnx_peer_count = last;
        return;
    }
}

static int verify_ed25519_sign(void* verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign)
{
    EVP_PKEY* pubkey = (EVP_PKEY*)verify_ctx;
    if (data.base == NULL && data.len == 0 && sign.base == NULL && sign.len == 0) {
        EVP_PKEY_free(pubkey);
        return 0;
    }
    if (algo != PTLS_SIGNATURE_ED25519) {
        return PTLS_ALERT_HANDSHAKE_FAILURE;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return PTLS_ALERT_INTERNAL_ERROR;
    }
    int ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pubkey) == 1 &&
        EVP_DigestVerify(ctx, sign.base, sign.len, data.base, data.len) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    return ok ? 0 : PTLS_ALERT_DECRYPT_ERROR;
}

/* BASE32_DNSSEC alphabet (data-encoding / iroh tls/name.rs). */
static const char IROH_BASE32_DNSSEC[] = "0123456789abcdefghijklmnopqrstuv";
static const char IROH_SNI_SUFFIX[] = ".iroh.invalid";
enum { IROH_SNI_LABEL_LEN = 52, IROH_SNI_TOTAL_LEN = 52 + 13 }; /* label + ".iroh.invalid" */

/** Decode iroh SNI (`base32dnssec(node_id).iroh.invalid`) → 32-byte NodeId.
 *  Mirrors iroh/iroh/src/tls/name.rs::decode. Returns 0 on success.
 *  Non-static (iroh_decode_iroh_sni) so Zig tests can exercise the production
 *  decoder against the Zig SNI encoder without a parallel test-only decoder. */
int iroh_decode_iroh_sni(const char* server_name, uint8_t out[32])
{
    if (server_name == NULL) {
        return -1;
    }
    size_t name_len = strlen(server_name);
    if (name_len != (size_t)IROH_SNI_TOTAL_LEN) {
        return -1;
    }
    if (memcmp(server_name + IROH_SNI_LABEL_LEN, IROH_SNI_SUFFIX, sizeof(IROH_SNI_SUFFIX)) != 0) {
        return -1;
    }

    int values[IROH_SNI_LABEL_LEN];
    for (size_t i = 0; i < IROH_SNI_LABEL_LEN; i++) {
        const char* p = strchr(IROH_BASE32_DNSSEC, server_name[i]);
        if (p == NULL) {
            return -1;
        }
        values[i] = (int)(p - IROH_BASE32_DNSSEC);
    }

    /* 52 × 5 bits = 260 bits → 32 bytes + 4 pad bits that must be zero. */
    uint32_t acc = 0;
    int nbits = 0;
    size_t oi = 0;
    for (size_t i = 0; i < IROH_SNI_LABEL_LEN; i++) {
        acc = (acc << 5) | (uint32_t)values[i];
        nbits += 5;
        if (nbits >= 8) {
            nbits -= 8;
            if (oi >= 32) {
                return -1;
            }
            out[oi++] = (uint8_t)((acc >> nbits) & 0xff);
        }
    }
    if (oi != 32 || nbits != 4 || (acc & ((1u << nbits) - 1u)) != 0) {
        return -1;
    }
    return 0;
}

static int verify_raw_pubkey(
    ptls_verify_certificate_t* base,
    ptls_t* tls,
    const char* server_name,
    int (**verifier)(void*, uint16_t, ptls_iovec_t, ptls_iovec_t),
    void** verify_data,
    ptls_iovec_t* certs,
    size_t num_certs)
{
    iroh_raw_pubkey_verifier_t* self = (iroh_raw_pubkey_verifier_t*)base;
    picoquic_cnx_t* cnx = NULL;
    if (tls != NULL) {
        void** data_ptr = ptls_get_data_ptr(tls);
        if (data_ptr != NULL && *data_ptr != NULL) {
            cnx = (picoquic_cnx_t*)*data_ptr;
        }
    }
    /* picoquic always sets *ptls_get_data_ptr(tls) = cnx at TLS context
     * creation (deps/picoquic/picoquic/tls_api.c) before handshake verify.
     * Fail closed if that invariant is broken so a missing cnx cannot skip
     * a client pin. */
    if (cnx == NULL) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
    if (num_certs != 1) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    const uint8_t* der = certs[0].base;
    EVP_PKEY* pubkey = d2i_PUBKEY(NULL, &der, (long)certs[0].len);
    if (pubkey == NULL) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    uint8_t raw[32];
    size_t raw_len = sizeof(raw);
    if (EVP_PKEY_get_raw_public_key(pubkey, raw, &raw_len) != 1 || raw_len != sizeof(raw)) {
        EVP_PKEY_free(pubkey);
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    const int is_client = picoquic_is_client(cnx) != 0;

    /* Per-cnx expected peer: concurrent dials must not share one endpoint-global key. */
    iroh_rpk_cnx_peer_t* entry = find_cnx_peer(self, cnx);
    if (entry != NULL && entry->has_expected && memcmp(raw, entry->expected, sizeof(raw)) != 0) {
        EVP_PKEY_free(pubkey);
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    /* Client→server defense-in-depth (iroh verify_server_cert shape): the SNI
     * already carries the dialed NodeId; require the presented RPK match it.
     * Server→client TOFU is intentionally unpinned (iroh verify_client_cert) —
     * do NOT SNI-pin when we are the server (SNI is our own name, not the peer's). */
    if (is_client) {
        uint8_t sni_expected[32];
        if (iroh_decode_iroh_sni(server_name, sni_expected) == 0) {
            if (memcmp(raw, sni_expected, sizeof(raw)) != 0) {
                EVP_PKEY_free(pubkey);
                return PTLS_ALERT_BAD_CERTIFICATE;
            }
        }
    }

    if (set_cnx_peer(self, cnx, raw) != 0) {
        EVP_PKEY_free(pubkey);
        return PTLS_ALERT_INTERNAL_ERROR;
    }
    *verify_data = pubkey;
    *verifier = verify_ed25519_sign;
    return 0;
}

static iroh_raw_pubkey_verifier_t* create_raw_pubkey_verifier(void)
{
    iroh_raw_pubkey_verifier_t* verifier = malloc(sizeof(*verifier));
    if (verifier == NULL) {
        return NULL;
    }
    memset(verifier, 0, sizeof(*verifier));
    verifier->super.cb = verify_raw_pubkey;
    verifier->super.algos = ed25519_signature_schemes;
    return verifier;
}

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

static void clear_raw_public_key_context(ptls_context_t* ctx)
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
    ctx->use_raw_public_keys = 0;
}

void iroh_picoquic_clear_raw_public_key(picoquic_quic_t* quic)
{
    if (quic == NULL || quic->tls_master_ctx == NULL) {
        return;
    }
    clear_raw_public_key_context((ptls_context_t*)quic->tls_master_ctx);
    picoquic_set_verify_certificate_callback(quic, NULL, NULL);
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

int iroh_picoquic_configure_raw_public_key(
    picoquic_quic_t* quic,
    const uint8_t* local_private_seed,
    const uint8_t* local_public_key,
    const uint8_t* expected_peer_public_key,
    int require_client_authentication)
{
    if (quic == NULL || quic->tls_master_ctx == NULL || local_private_seed == NULL || local_public_key == NULL) {
        return -1;
    }

    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    EVP_PKEY* private_key = load_private_key(local_private_seed);
    EVP_PKEY* public_key = load_public_key(local_public_key);
    ptls_openssl_sign_certificate_t* signer = NULL;
    iroh_raw_pubkey_verifier_t* verifier = NULL;
    ptls_iovec_t* certs = NULL;
    int signer_initialized = 0;
    int ret = 0;

    if (private_key == NULL || public_key == NULL) {
        ret = -1;
        goto Exit;
    }

    signer = malloc(sizeof(*signer));
    /* expected_peer_public_key is ignored here: per-cnx expectations are
     * registered via iroh_picoquic_set_cnx_expected_peer after create_cnx. */
    (void)expected_peer_public_key;
    verifier = create_raw_pubkey_verifier();
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

    EVP_PKEY_free(private_key);
    private_key = NULL;
    EVP_PKEY_free(public_key);
    public_key = NULL;
    iroh_picoquic_clear_raw_public_key(quic);
    ctx->certificates.list = certs;
    ctx->certificates.count = 1;
    certs = NULL;
    ctx->sign_certificate = &signer->super;
    signer = NULL;
    picoquic_set_verify_certificate_callback(quic, &verifier->super, free_raw_pubkey_verifier);
    verifier = NULL;
    ctx->use_raw_public_keys = 1;
    picoquic_set_client_authentication(quic, require_client_authentication != 0);
    picoquic_enforce_client_only(quic, 0);

Exit:
    if (private_key != NULL) {
        EVP_PKEY_free(private_key);
    }
    if (public_key != NULL) {
        EVP_PKEY_free(public_key);
    }
    if (ret != 0) {
        if (signer != NULL) {
            if (signer_initialized) {
                ptls_openssl_dispose_sign_certificate(signer);
            }
            free(signer);
        }
        if (verifier != NULL) {
            free(verifier->cnx_peers);
            free(verifier);
        }
        if (certs != NULL) {
            free_certificates(certs, certs[0].base == NULL ? 0 : 1);
        }
    }
    return ret;
}

int iroh_picoquic_last_verified_peer_public_key(picoquic_cnx_t* cnx, uint8_t* out_public_key)
{
    if (cnx == NULL || cnx->quic == NULL || cnx->quic->tls_master_ctx == NULL || out_public_key == NULL) {
        return -1;
    }
    ptls_context_t* ctx = (ptls_context_t*)cnx->quic->tls_master_ctx;
    iroh_raw_pubkey_verifier_t* verifier = (iroh_raw_pubkey_verifier_t*)ctx->verify_certificate;
    if (verifier == NULL) {
        return -1;
    }
    return get_cnx_peer(verifier, cnx, out_public_key);
}

int iroh_picoquic_set_cnx_expected_peer(picoquic_cnx_t* cnx, const uint8_t* expected_peer_public_key)
{
    if (cnx == NULL || cnx->quic == NULL || cnx->quic->tls_master_ctx == NULL) {
        return -1;
    }
    ptls_context_t* ctx = (ptls_context_t*)cnx->quic->tls_master_ctx;
    iroh_raw_pubkey_verifier_t* verifier = (iroh_raw_pubkey_verifier_t*)ctx->verify_certificate;
    if (verifier == NULL) {
        return -1;
    }
    return set_cnx_expected(verifier, cnx, expected_peer_public_key);
}

void iroh_picoquic_forget_cnx_peer(picoquic_cnx_t* cnx)
{
    if (cnx == NULL || cnx->quic == NULL || cnx->quic->tls_master_ctx == NULL) {
        return;
    }
    ptls_context_t* ctx = (ptls_context_t*)cnx->quic->tls_master_ctx;
    iroh_raw_pubkey_verifier_t* verifier = (iroh_raw_pubkey_verifier_t*)ctx->verify_certificate;
    if (verifier != NULL) {
        forget_cnx_peer(verifier, cnx);
    }
}

size_t iroh_picoquic_cnx_peer_count(picoquic_quic_t* quic)
{
    if (quic == NULL || quic->tls_master_ctx == NULL) {
        return 0;
    }
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    iroh_raw_pubkey_verifier_t* verifier = (iroh_raw_pubkey_verifier_t*)ctx->verify_certificate;
    return verifier == NULL ? 0 : verifier->cnx_peer_count;
}

int iroh_picoquic_stream_send_flushed(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    if (cnx == NULL) {
        return 1;
    }
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
    if (stream == NULL) {
        /* No stream head means picoquic already retired the stream: everything we
         * queued was transmitted (and acknowledged), then the stream was deleted. */
        return 1;
    }
    /* picoquic sends the FIN only in the frame carrying the final offset, i.e. after
     * every preceding data byte has been put on the wire, so `fin_sent` is exactly
     * "all queued stream data + FIN transmitted". This preserves the send path's
     * return-after-flush contract (it does NOT wait for the peer to acknowledge) while
     * still driving a congestion-window-paced large send all the way out instead of
     * stopping after the first window. Reports the SEND direction only, so a
     * request/response stream (Get) reports flushed as soon as its request is on the
     * wire, without blocking on the peer's response half. */
    return stream->fin_sent ? 1 : 0;
}

int iroh_picoquic_stream_send_drained(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    if (cnx == NULL) {
        return 1;
    }
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
    if (stream == NULL) {
        /* Retired stream: nothing left queued. */
        return 1;
    }
    /* send_queue holds data segments until the packet builder pulls them; empty
     * means every queued byte has been packetized (cwnd-bounded in flight). FIN
     * handling is unchanged — see iroh_picoquic_stream_send_flushed. */
    return stream->send_queue == NULL ? 1 : 0;
}

size_t iroh_picoquic_stream_send_queued(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    if (cnx == NULL) {
        return 0;
    }
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
    if (stream == NULL) {
        return 0;
    }
    size_t queued = 0;
    for (picoquic_stream_queue_node_t* node = stream->send_queue; node != NULL; node = node->next_stream_data) {
        if (node->length > node->offset) {
            queued += node->length - node->offset;
        }
    }
    return queued;
}
