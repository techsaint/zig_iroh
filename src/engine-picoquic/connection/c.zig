//! C binding surface for vendored picoquic + picotls.

pub const c = @cImport({
    // translate-c cannot represent picotls' thread-local global; the runtime C
    // objects are still compiled with the header's real __thread definition.
    @cDefine("__thread", "");
    @cInclude("picoquic.h");
    @cInclude("tls_api.h");
    @cInclude("picotls.h");
    @cInclude("picotls/openssl.h");
    @cInclude("rpk.h");
});

test "picoquic and picotls headers expose the S1 binding surface" {
    const testing = @import("std").testing;

    try testing.expect(@hasDecl(c, "picoquic_create"));
    try testing.expect(@hasDecl(c, "picoquic_create_client_cnx"));
    try testing.expect(@hasDecl(c, "picoquic_start_client_cnx"));
    try testing.expect(@hasDecl(c, "picoquic_incoming_packet"));
    try testing.expect(@hasDecl(c, "picoquic_prepare_next_packet"));
    try testing.expect(@hasDecl(c, "picoquic_queue_misc_frame"));
    try testing.expect(@hasDecl(c, "picoquic_tls_set_verify_certificate_callback"));
    try testing.expect(@hasDecl(c, "ptls_openssl_raw_pubkey_init_verify_certificate"));
    try testing.expect(@hasDecl(c, "iroh_picoquic_forget_cnx_peer"));
    try testing.expect(@hasDecl(c, "iroh_picoquic_cnx_peer_count"));
    try testing.expect(@hasDecl(c, "iroh_decode_iroh_sni"));
    try testing.expect(@hasDecl(c, "picoquic_tls_get_negotiated_alpn"));
    try testing.expect(@hasDecl(c, "picoquic_set_alpn_select_fn_v2"));
}
