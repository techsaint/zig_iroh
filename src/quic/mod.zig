//! New noq/QUIC codec surface. This is not wired into the shipping picoquic
//! transport path; it exists for the N3a wire-diff oracle.

const product_flags = @import("../product_flags.zig");

pub const varint = @import("varint.zig");
pub const coding = @import("coding.zig");
pub const frame = @import("frame.zig");
pub const packet = @import("packet.zig");
pub const transport_parameters = @import("transport_parameters.zig");
pub const crypto = @import("crypto.zig");
pub const crypto_zigtls = if (crypto.zigtls_enabled) @import("crypto_zigtls.zig") else struct {};
pub const crypto_picotls = if (crypto.picotls_enabled) @import("crypto_picotls.zig") else struct {};
pub const endpoint = @import("endpoint.zig");
pub const packet_crypto = @import("packet_crypto.zig");
pub const packet_builder = @import("packet_builder.zig");
pub const spaces = @import("spaces.zig");
pub const initial_keys = @import("initial_keys.zig");
pub const connection = @import("connection.zig");
pub const stream_state = @import("stream_state.zig");
pub const path_cid = @import("path_cid.zig");
pub const timers_events = @import("timers_events.zig");
pub const congestion = @import("congestion.zig");
pub const loss = @import("loss.zig");
pub const token = @import("token.zig");
/// Public deterministic pair harness for the noq BEHAVIORAL oracle (D5).
/// Generalizes the private TestPair pattern in connection.zig with a simulated link.
pub const oracle_pair = if (product_flags.has_internal_harnesses) @import("oracle_pair.zig") else struct {};

test {
    _ = varint;
    _ = coding;
    _ = frame;
    _ = packet;
    _ = transport_parameters;
    _ = crypto;
    _ = crypto_zigtls;
    _ = crypto_picotls;
    _ = endpoint;
    _ = packet_crypto;
    _ = packet_builder;
    _ = spaces;
    _ = initial_keys;
    _ = connection;
    _ = stream_state;
    _ = path_cid;
    _ = timers_events;
    _ = congestion;
    _ = loss;
    _ = token;
    if (comptime product_flags.has_internal_harnesses) _ = oracle_pair;
}
