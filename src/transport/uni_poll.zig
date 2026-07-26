//! Neutral inbound uni-stream polling surface for protocol layers that need
//! incremental framing without amending the frozen transport vtable.

pub const InboundUniChunk = struct {
    stream_id: u64,
    bytes: []const u8,
    fin: bool,
};

pub const InboundUniEvent = union(enum) {
    chunk: InboundUniChunk,
    reset: u64,
};
