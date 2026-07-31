pub const c = @cImport({
    // translate-c cannot represent picotls' thread-local global; the runtime C
    // objects are still compiled with the header's real __thread definition.
    @cDefine("__thread", "");
    @cInclude("picotls.h");
    @cInclude("picotls/openssl.h");
    @cInclude("quic/rpk_picotls.h");
});
