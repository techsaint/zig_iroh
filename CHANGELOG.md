# Changelog

All notable public-distribution changes to `zig_iroh` are documented here.

`zig_iroh` is an alpha-stage Zig port of iroh. It targets wire compatibility with upstream iroh for the implemented surfaces, but it is still a feature subset and is not yet a complete replacement for the Rust implementation. APIs, build options, and product behavior may change between alpha releases.

Versions in this file are public source-distribution versions.

Supported product builds:

- `picoquic-picotls` — C QUIC + C TLS
- `noq-picotls` — native Zig QUIC + C TLS
- `noq-zigtls` — native Zig QUIC + native Zig TLS, with no libcrypto dependency

## [0.4.0-alpha] — 2026-08-10

### Added
- DNS discovery across UDP, TCP, DNS-over-TLS, and DNS-over-HTTPS.
- DNS / pkarr publication controls: publish enablement, configurable TTLs, relay-record filtering, and republish lifecycle handling.
- Cross-implementation DNS visibility coverage for Rust iroh clients publishing through the Zig DNS server path.
- Substantially expanded blobs support: durable filesystem-backed content storage; content-addressed publication; read-time hash verification; durable named tags and reopen; backend-generic blobs facade APIs; downloader orchestration; tag-aware garbage collection; seekable complete-blob readers; partial BAO lifecycle and durable partial resume; blob ticket and Observe wire fixes; real interoperability coverage against `iroh-blobs`.
- Opt-in 0-RTT early data for the native `noq` transport (connection options, router accept hooks, protocol-handler accept hooks), with anti-replay protection. 0-RTT is default-off.
- Native `noq` datagram support for `noq-picotls` and `noq-zigtls`, with bounded outbound datagram queues.
- Byte-identical wire coverage for additional native `noq` packet types (protected Handshake and 0-RTT packets).
- ACME TLS-ALPN-01 certificate provisioning for relay deployments with multiple hostnames, with fail-closed certificate selection for unprovisioned hostnames.
- Explicit X.509 trust-store support and production certificate-validation coverage for the native TLS path.
- Network-reporting improvements: STUN/UDP server-reflexive address evidence and bounded NAT-classification heuristics.
- Relay runtime-map behavior so online relay selection can probe past an unavailable relay candidate.

### Changed
- Shipped products now use concrete product-specific transport builds instead of a runtime-swappable transport engine; the previous catch-all default transport product was retired — select one of the three explicit products.
- `picoquic-picotls` uses an event-driven receive loop, reducing busy polling.
- Native `noq` relay-path datagram sizing follows the QUIC engine's negotiated packet capacity instead of a smaller independent cap.
- Native `noq` PTO deadline tracking keeps maintained per-space state instead of rescanning sent packets.
- x86_64 builds requesting AES/AVX complete the CPU feature set for hardware-accelerated AES-GCM.
- BBR3 and Cubic congestion-control arithmetic use widened intermediates and saturating clamps to avoid overflow while preserving wire behavior.
- Endpoint ticket encoding handles valid larger endpoint-address tickets.
- pkarr timestamps use wall-clock microseconds with same-process monotonicity.

### Fixed
- Native `noq` throughput regression from large per-send zeroing after the receive ceiling was raised.
- `picoquic-picotls` cross-host throughput regression from holding the receive-pump mutex across a blocking wait.
- Native `noq` responder stalls where server-side data-space PTO was not armed after handshake establishment.
- Idle-timeout issue where local keep-alive / PTO probes could re-arm idle state against a silent peer.
- Gossip API self-deadlock (serialized mutable gossip state without re-entering the public lock).
- DNS server handler lifetime so detached TCP / DoH handlers cannot outlive shared resolver storage.
- Discovery server idle-client behavior so one idle client cannot starve later clients.
- zigtls pending-handshake cleanup on error paths; ALPN readout timing; a native TLS client handshake-key discard that could strand the Finished flight.
- Relay candidate selection so runtime relay maps are authoritative over a pinned home relay URL.

### Security
- Hardened `SecretKey`: key material scrubbed on deinit and fallible-init unwind; optimizer-safe zeroization; debug/structural formatting no longer exposes raw key bytes.
- Strict rejection of malformed textual signatures and malformed STUN length fields (previously panic-prone).
- TLS handshake record handling fails closed on oversized malformed records instead of aborting the relay process.
- ACME validation is CA-pinned (not skip-verify); challenge-certificate serving is limited to the expected TLS-ALPN-01 path; incompatible static-cert-plus-ACME config fails hard.
- Pre-handshake admission hardening in the native `noq` transport to reduce pre-state-allocation denial-of-service surface.
- Mutation-backed negative coverage for 0-RTT anti-replay and certificate-validation defenses.
- Observable counters for relay/endpoint backpressure drops (queue-full and allocation-failure drops are no longer silent).

### Alpha notes
- `zig_iroh` remains alpha and feature-subset — many iroh-compatible surfaces, not yet full parity.
- 0-RTT is opt-in and proven for Zig-to-Zig native `noq`; Rust-peer 0-RTT resumption interop is not yet claimed.
- ACME issuance was validated against an ACME test environment; production CA issuance and live renewal are not yet claimed.
- Native datagram additions are for the `noq` products; `picoquic-picotls` native datagram plumbing is unchanged.
- Treat published benchmark ratios separately from this changelog.

## [0.3.0-alpha] — 2026-07-31

### Added
- First public source distribution of `zig_iroh`, with three product builds (`picoquic-picotls`, `noq-picotls`, `noq-zigtls`).
- Alpha feature subset: identity, QUIC + TLS / raw-public-key transport, relay fallback, pkarr / DoH discovery, mainline-DHT discovery, blobs, and gossip, with real iroh interoperability coverage for the implemented surfaces.

### Alpha notes
- A hardened feature subset, not full iroh parity. Beta is reserved for broader feature completeness.
