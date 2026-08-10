pub const c = @cImport({
    // translate-c cannot represent picotls' thread-local global; the runtime C
    // objects are still compiled with the header's real __thread definition.
    @cDefine("__thread", "");
    @cInclude("picotls.h");
    @cInclude("picotls/openssl.h");
    // S6: header lives beside this file under tls-picotls/; include path is the
    // tls module root (see configureTlsBackendNativeDeps).
    @cInclude("rpk_picotls.h");
});
