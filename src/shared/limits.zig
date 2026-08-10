//! Neutral product-agnostic size / capacity constants.
//!
//! Home for values that shared modules must not read from a concrete engine
//! (CP-2). It became the canonical home in fork-isolation S3; the former
//! top-level forwarder was retired in the S7 cutover.
//!
//! Do NOT put engine policy here that diverges per product without an
//! accompanying per-product assert (see migration plan A6 / EngineBundle).

/// Largest UDP datagram the QUIC engine builds or accepts (F19). Raised from
/// the Ethernet-only 1472 to 8192 so DPLPMTUD can discover larger path MTUs
/// (loopback, jumbo frames) while keeping the per-connection scratch buffers
/// cache-friendly (3 × 8 KiB vs 3 × 64 KiB at the RFC ceiling of 65527).
///
/// Also the HomeRelay datagram queue cap: the relay path must track this
/// ceiling so a raised PMTUD budget cannot silently drop on the relay.
pub const max_datagram: usize = 8192;
