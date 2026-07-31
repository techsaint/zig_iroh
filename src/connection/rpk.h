#ifndef IROH_CONNECTION_RPK_H
#define IROH_CONNECTION_RPK_H

#include <stddef.h>
#include "picoquic.h"

int iroh_picoquic_configure_raw_public_key(
    picoquic_quic_t* quic,
    const uint8_t* local_private_seed,
    const uint8_t* local_public_key,
    const uint8_t* expected_peer_public_key,
    int require_client_authentication);

void iroh_picoquic_clear_raw_public_key(picoquic_quic_t* quic);

int iroh_picoquic_last_verified_peer_public_key(picoquic_cnx_t* cnx, uint8_t* out_public_key);

/** Register the expected peer RPK for one connection. */
int iroh_picoquic_set_cnx_expected_peer(picoquic_cnx_t* cnx, const uint8_t* expected_peer_public_key);

/** Forget all verifier state owned by one connection before deleting it. */
void iroh_picoquic_forget_cnx_peer(picoquic_cnx_t* cnx);

/** Returns 1 once every byte queued on this send stream — including the FIN — has been
 *  transmitted (put on the wire), independent of the stream's receive/response half and
 *  WITHOUT waiting for the peer's acknowledgement; 0 while data is still queued to send.
 *  Used by the Zig send path to drive a large (multi-window) stream send fully out
 *  instead of returning after the first idle pump round. A stream that picoquic has
 *  already retired (find returns NULL) counts as flushed. */
int iroh_picoquic_stream_send_flushed(picoquic_cnx_t* cnx, uint64_t stream_id);

/** 1 when every byte queued on the stream has been packetized (the stream's
 *  send_queue is empty), independent of FIN and of peer acknowledgement — the
 *  open-stream drain condition for wire-pacing a streaming sender (flush()
 *  alone only hands bytes to picoquic's queue). A stream that picoquic has
 *  already retired (find returns NULL) counts as drained. */
int iroh_picoquic_stream_send_drained(picoquic_cnx_t* cnx, uint64_t stream_id);

/** Bytes still sitting in the stream's send_queue (remaining segment lengths,
 *  excluding bytes already packetized from a partially consumed head node), 0
 *  for a retired stream. The low-water pacing variant waits on this dropping
 *  below a threshold instead of on full drain, so the packet builder never
 *  starves between chunks. */
size_t iroh_picoquic_stream_send_queued(picoquic_cnx_t* cnx, uint64_t stream_id);

/** Diagnostic count used to prove per-connection verifier state is reclaimed. */
size_t iroh_picoquic_cnx_peer_count(picoquic_quic_t* quic);

/** Decode iroh SNI (`base32dnssec(node_id).iroh.invalid`) → 32-byte NodeId.
 *  Load-bearing decoder used by the client pin verify path. Returns 0 on success.
 *  Exported so Zig tests can prove the production encoder↔decoder pair (Zig
 *  `tls_name.serverName` + this C decoder) without a parallel Zig-only decoder. */
int iroh_decode_iroh_sni(const char* server_name, uint8_t out[32]);

#endif
