> **zig_iroh** is an independent Zig port of **[iroh](https://github.com/n0-computer/iroh)** by n0 — the original production-grade Rust p2p stack. This component reimplements a subset of iroh's functionality in Zig, aiming for byte-for-byte wire compatibility. Full credit to the iroh authors; this port exists because iroh is excellent and worth learning from.
> iroh: https://github.com/n0-computer/iroh · https://www.iroh.computer
>
> **No warranty.** A community contribution / example of what's possible in Zig, provided as-is. The author may not keep it current; with enough interest they'll consider maintaining wire-compatibility with iroh. Not affiliated with or endorsed by n0.

# Transport / Connection-Core Architecture

The central component of zig_iroh: the QUIC engine, magicsock NAT traversal,
Raw-Public-Key TLS, and relay fallback. This is the seam every other component
(blobs, gossip, …) codes against, and the one milestone that proves the whole
port is real — a Zig endpoint that completes a genuine QUIC + TLS handshake with
a live `iroh::Endpoint`.

---

## 1. What this component ports

In iroh, the connection core is `iroh::Endpoint` plus magicsock. An `Endpoint`
is a QUIC endpoint that:

- speaks **QUIC v1** with **TLS 1.3** and **Raw Public Keys (RFC 7250)** — peers
  authenticate by their Ed25519 `NodeId`, not by an X.509 chain;
- runs **magicsock**, which does NAT traversal / hole-punching: it learns a
  peer's candidate addresses (via DISCO / custom QUIC frames), probes them,
  observes its own public address, and selects the best path;
- falls back to a **relay** (DERP-style WebSocket server) when no direct path
  validates, tunnelling QUIC packets as relay datagrams.

iroh builds this on **quinn** (specifically iroh's vendored quinn fork, `noq`)
over **rustls**, driven by **tokio**.

**The Zig port deliberately chose a different baseline engine** (and later added a
Zig-native portfolio alongside it). Rather than reimplement a QUIC state machine in
Zig first, the original path drives a **picoquic fork + picotls + OpenSSL** as a
no-I/O C core, with Zig owning the event loop. That pairing remains the shipped
baseline stack (`-Dproduct=picoquic-picotls`) and one arm of the all-in-one
`-Dproduct=default` build. A greenfield Zig QUIC engine (`noq`, under `src/quic`)
and a Zig TLS backend (`zigtls`) now ship **alongside** the C stack — not as a
replacement/retirement of picoquic.

| Concern        | iroh (Rust)              | zig_iroh portfolio                                         |
| :------------- | :----------------------- | :--------------------------------------------------------- |
| QUIC engine    | quinn / `noq`            | **picoquic** (fork) **and/or** Zig **`noq`** (`src/quic`)  |
| TLS 1.3        | rustls                   | **picotls** **and/or** Zig **`zigtls`**                    |
| Crypto         | rustls / ring            | **OpenSSL** (picotls products) **or** pure-Zig (noq-zigtls)|
| Async runtime  | tokio                    | **`std.Io`** UDP pump (Zig owns the loop)                  |
| Wire target    | —                        | byte-for-byte vs iroh / `noq-proto`                        |
| Build select   | —                        | **comptime** `zig build -Dproduct=<id>` (`src/products.zig`)|

**Why picoquic, not a hand-rolled QUIC?** QUIC is a large, security-sensitive
state machine (loss recovery, congestion control, multipath, key schedule). The
engine spike (`plans/quic-engine-spike/`) concluded a tested C core is the
pragmatic base, and picoquic is **no-I/O** — `picoquic_prepare_next_packet` /
`picoquic_incoming_packet` move bytes in and out of buffers and never touch a
socket. That lets Zig keep the entire event loop, sockets, and async model in
`std.Io`, with no tokio-equivalent embedded in C and no function-coloring across
the FFI boundary. picotls comes bundled with picoquic and already supports the
TLS-1.3 / RPK machinery we need (with two small patches, §4).

The cost: the engine is C, and the boundary needs targeted **fork patches** to
picoquic and picotls plus a small C shim (`rpk.c`) for RFC 7250. Those patches
are tracked under `patches/` (§4, §5).

---

## 2. What it does — and the thesis

The job of this component is to take a `NodeId` (plus candidate addresses and/or
a relay URL) and produce a live, mutually-authenticated `Connection` you can open
bi/uni streams on:

1. **Establish** a QUIC + TLS-1.3 connection whose certificate is a Raw Public
   Key — both sides verify the peer's Ed25519 key matches the expected `NodeId`.
2. **Traverse NAT** via magicsock: exchange address candidates over custom QUIC
   frames, probe new paths through picoquic's multipath machinery, and select the
   lowest-RTT validated path (with an IPv6 bias and switch hysteresis).
3. **Fall back to relay** when no direct path validates: route QUIC packets
   through a DERP-style relay client as relay datagrams, and feed relay-delivered
   datagrams back into picoquic.

### The thesis: CC-i1

> **CC-i1** — a Zig picoquic endpoint completes a real QUIC + TLS (Raw Public
> Key) handshake with a real `iroh::Endpoint`.

This is the project's core thesis milestone. The interop peer
(`interop/rust-peer/interop_peer.rs`) uses the actual `iroh::Endpoint`
(bind / accept / accept_bi) — **not a mock** — and `zig build interop` runs the
live handshake green. The proof it was a real Rust TLS stack in the loop: an
early run hit `IncorrectCertificateTypeExtension` from real **rustls**, which is
exactly what drove the picotls `client_certificate_type` patch (§4). See
`docs/changelog/entries/2026-06-22-promote-interop-cc-i1.md`.

If the engine choice were wrong, CC-i1 could not exist. It does. That is the
load-bearing evidence for picoquic + picotls + RPK + the Zig binding.

---

## 2b. Since connection-core — the product portfolio (engines + TLS backends)

The transport seam is no longer a single C stack. After connection-core + the
`noq` port + `zigtls` landing + the component-repo-restructure:

- **Two QUIC engines** live behind the transport seam: picoquic (C fork) and
  **noq** (Zig, `src/quic`). Both ship; the portfolio is **keep-both**, not
  "picoquic being replaced."
- **Two TLS backends**: picotls (+ libcrypto) and **zigtls** (Zig). Full-zig
  (`-Dproduct=noq-zigtls`) has **no libcrypto by construction** — the S4
  file-deletion / picoquic-retirement lane is dissolved for that product.
- **Primary selection is comptime:** `zig build -Dproduct=<id>` with ids
  `default`, `picoquic-picotls`, `noq-picotls`, `noq-zigtls` (SoT:
  `src/products.zig`). Mono-products compile a single dep closure — no runtime
  engine choice.
- **Runtime `factory.zig` `union(Engine)` applies only in the `default`
  all-in-one product** (both engines compiled; select at runtime). Do not read
  "selectable via factory" onto a mono-product build.
- **`default` product ≠ baseline stack.** The shipped baseline *stack* is
  `picoquic-picotls`; the product id `default` is the all-in-one runtime-selectable
  build.

Cards + membership: `docs/product/stacks/` and module homes under
`docs/llm/modules/{picoquic,noq,picotls,zigtls,tls,transport}.md`.

---

## 3. Code map

All paths relative to repo root unless noted.

### `zig_iroh/src/transport.zig` — the FROZEN contract (Tier-0)

The vtable seam every leaf codes against — the analog of iroh's `Endpoint` API.
Leaves consume `Connection` / `BiStream` and never reference picoquic. It is
**frozen** at the Tier-0 freeze; changes go through `plans/port-00-core/`.

- `Transport` vtable (`transport.zig:141`): `connect(NodeAddr)`, `accept()`,
  `localNodeId()`, `io()`.
- `Connection` vtable (`transport.zig:97`): `openBi`, `acceptBi`, `openUni`,
  `acceptUni`, `remoteNodeId`, `close`, `io`.
- `SendStream` / `RecvStream` (`transport.zig:48`, `:73`) expose
  `std.Io.Writer` / `std.Io.Reader` — byte I/O flows through the standard
  std.Io interfaces, so async lives entirely on the implementation side (no
  function coloring crosses the seam). Construction captures a `std.Io` (the
  tokio-handle equivalent), so dial/accept take no `io` parameter.

### `zig_iroh/src/transport/quic.zig` — the picoquic-backed Endpoint

The real implementation. ~945 lines, the heart of the component.

- `Endpoint` (`quic.zig:64`) owns the `*picoquic_quic_t`, the UDP `Socket`,
  per-stream state, the `magicsock.State`, and the optional relay client.
- `Endpoint.init` (`quic.zig:83`) creates the picoquic context, applies iroh
  transport params (`context.applyTransportParams`), enables path callbacks, and
  configures local RPK via `iroh_picoquic_configure_raw_public_key`
  (`quic.zig:111`).
- **The UDP pump** is the heart of "Zig owns the loop":
  - `pumpOutgoing` (`quic.zig:236`) loops `picoquic_prepare_next_packet` and
    sends each packet either over the UDP socket or — if magicsock's selected
    path is `.relay` — through the relay client (`quic.zig:250-258`).
  - `pumpIncoming` (`quic.zig:269`) does a 1 ms `receiveTimeout` on the socket;
    on a real packet it calls `picoquic_incoming_packet`; on timeout it falls
    through to the relay pump.
  - `driveUntilReady` (`quic.zig:305`) / `driveUntilStreamFin` (`quic.zig:315`)
    are the synchronous "pump until X" drivers the connect/stream paths use.
- **The relay-datagram pump:** `pumpRelayIncoming` (`quic.zig:287`) pulls one
  datagram from the relay client, registers a relay candidate, selects the relay
  fallback, and feeds the datagram into `picoquic_incoming_packet` with a
  synthetic relay source address (`magicsock.relayAddress()`), then re-drives
  `pumpOutgoing` so ACK/handshake packets actually leave.
- **RPK config + dial:** `endpointConnect` (`quic.zig:393`) reconfigures RPK with
  the *expected* peer public key, builds the base32-dnssec SNI
  (`tls_name.serverName`), creates and starts the client connection, and pumps
  until ready. `endpointAccept` (`quic.zig:423`) pumps until a connection reaches
  `ready`, then reads the verified peer key via
  `iroh_picoquic_last_verified_peer_public_key`.
- **Custom-frame intake:** the picoquic `callback` (`quic.zig:349`) routes
  `picoquic_callback_iroh_custom_frame` into `pushCustomFrame` (`quic.zig:203`),
  which decodes the NAT frame, feeds magicsock, and probes new candidate paths
  (`probeMagicsockCandidates` → `picoquic_probe_new_path`, `quic.zig:214`).
- **Relay clients:** `DerpRelayDatagramClient` (`quic.zig:56`) and the threaded
  `QueuedRelayClient` (`quic.zig:587`) adapt the promoted DERP `relay.Client` to
  the `RelayDatagramClient` vtable. `QueuedRelayClient` runs a background
  receiver thread that enqueues relay datagrams (the S4 test path).

### `zig_iroh/src/connection/` — picoquic context + the RPK C shim

- `c.zig` (`:3`) — the `@cImport` surface (picoquic.h, tls_api.h, picotls.h,
  picotls/openssl.h, connection/rpk.h).
- `context.zig` (`:28`) — `applyTransportParams`: iroh QUIC transport params
  (streams, idle timeout, flow-control windows, multipath, grease-bit off).
- `tls_name.zig` (`:11`) — `serverName`: the base32-dnssec SNI
  `<52-char base32>.iroh.invalid`, snapshot-matched against iroh's zero-key
  vector (`tls_name.zig:42`).
- **`rpk.c`** — the RFC 7250 shim over picotls + OpenSSL:
  - `iroh_picoquic_configure_raw_public_key` (`rpk.c:136`) loads the local
    Ed25519 seed/public key, builds a DER `SubjectPublicKeyInfo` cert
    (`public_key_to_der`, `rpk.c:113`), installs an OpenSSL sign-certificate,
    registers a raw-pubkey verifier, sets `ctx->use_raw_public_keys = 1`, and
    toggles client-auth.
  - `verify_raw_pubkey` (`rpk.c:47`) parses the peer's DER SPKI, extracts the
    raw 32-byte Ed25519 key, and **fails closed** if it doesn't match the
    expected `NodeId` (`PTLS_ALERT_BAD_CERTIFICATE`).
  - `iroh_picoquic_last_verified_peer_public_key` (`rpk.c:206`) hands the
    verified peer key back to Zig for `remoteNodeId`.

### `zig_iroh/src/magicsock/` — NAT frame codec + path selection

- `frames.zig` — the noq/iroh custom QUIC frame codec. `FrameType`
  (`frames.zig:5`) defines the frame IDs: `add_ipv4/6_address` (0x3d7f90/91),
  `reach_out_at_ipv4/6` (0x3d7f92/93), `remove_address` (0x3d7f94),
  `observed_ipv4/6_addr` (0x9f81a6/a7). `encode`/`decode` use QUIC varints;
  byte-for-byte snapshot tests against fixed vectors (`frames.zig:146`).
- `mod.zig` — the magicsock state machine and path selector:
  - `State.handleFrame` (`mod.zig:42`) upserts remote candidates from
    add/reach-out frames and records observed addresses.
  - `selectPath` (`mod.zig:161`) — the routing authority: lowest-RTT validated
    path wins, with a **3 ms IPv6 bias** (`ipv6_bias_us`), **5 ms switch
    hysteresis** (`switch_hysteresis_us`), and relay scored as a last-resort
    backup (`+1e9`).
  - `selectRelayFallback` (`mod.zig:90`) picks the relay only when no direct path
    has validated.

### The fork patches — `patches/`

The custom NAT frames don't exist in stock picoquic, and RPK client-auth
negotiation doesn't exist in stock picotls. Both live as tracked patch files
(`dependancies/` is gitignored):

- **`patches/picoquic-iroh-nat-frames.patch`** — patches `picoquic/frames.c` so
  the frame dispatcher *tolerates* the iroh NAT frame IDs (0x3d7f90–94) instead
  of closing the connection with `PROTOCOL_VIOLATION`, and *delivers* them to the
  Zig callback via a new `picoquic_callback_iroh_custom_frame` event
  (`picoquic.h`). Two commits: skip-frames + deliver-to-callback.
- **`patches/picotls-iroh-rpk.patch`** — adds `client_certificate_type` (TLS
  extension 19, RFC 7250) negotiation to picotls's ClientHello and
  EncryptedExtensions handling. This is the patch CC-i1 forced: without it, iroh's
  rustls server rejected the handshake with `IncorrectCertificateTypeExtension`.

---

## 4. Wire format & fidelity

| Layer            | What                                                            | Proven                                   |
| :--------------- | :------------------------------------------------------------- | :--------------------------------------- |
| QUIC v1          | picoquic fork, iroh transport params (`context.zig`)            | CC-i1 handshake vs real iroh             |
| TLS 1.3 + RPK    | picotls + OpenSSL, RFC 7250 raw public keys                     | CC-i1; rustls accepted the cert type     |
| SNI              | base32-dnssec `<key>.iroh.invalid` (`tls_name.zig`)            | snapshot vs iroh zero-key vector         |
| ALPN             | application-supplied (no fixed iroh ALPN); emitted verbatim     | passed through picoquic ALPN             |
| NAT frames       | 0x3d7f90–94, 0x9f81a6/a7 varint codec (`frames.zig`)           | byte-for-byte snapshot tests             |
| Relay datagrams  | DERP-style frames over WS/WSS via `relay.Client`               | S4 relay-fallback stream round-trip      |

**RPK details that matter for fidelity:** the cert is a 12-byte SPKI prefix +
32-byte Ed25519 key (DER `SubjectPublicKeyInfo`), the signature scheme is
`PTLS_SIGNATURE_ED25519`, and `client_certificate_type` ext 19 must be offered so
mutual RPK auth interops with rustls. The SNI base32 alphabet is the lowercase
DNSSEC alphabet (`0123456789abcdefghijklmnopqrstuv`), matching iroh's `tls/name.rs`.

**What's proven against real iroh:** CC-i1 — the QUIC + TLS + RPK handshake — runs
against a live `iroh::Endpoint`. Historical interop gates were same-host, but
cross-host reliability is now proven by the promoted lab evidence: 5/5 DIRECT,
5/5 HOLE-PUNCH, and a 30/30 persistent-anchor soak. NAT frame codec, SNI, path
selection, relay fallback, and large-transfer flow control are covered by fixed
vectors, local gates, and the cross-host/large-transfer regression evidence.

---

## 5. Design notes / differences from iroh

- **picoquic (fork) + picotls vs quinn + rustls.** Same protocol, different
  engine. The wire target is iroh / `noq-proto`; the engine is whatever produces
  those bytes. picoquic was chosen because it is mature, tested, and **no-I/O**.
- **No-I/O C core + Zig `std.Io` pump.** picoquic never touches a socket; Zig
  drives it with `pumpOutgoing` / `pumpIncoming` over a `std.Io` UDP socket. This
  keeps the async model entirely in Zig (`std.Io.Threaded` for correctness,
  `Io.Evented`/io_uring later for perf), the tokio-handle equivalent, with no
  embedded runtime in C.
- **Fork patches preserved as tracked `patches/` files.** `dependancies/` is
  gitignored, so the two picoquic/picotls patches and the `rpk.c` shim are the
  reproducible record of the engine fork. Long-term option: fork-and-pin a hosted
  picoquic (`patches/README.md`).
- **Synchronous drive model.** The current connect/stream paths pump
  synchronously to a deadline (`driveUntilReady`, `driveUntilStreamFin`). This is
  simple and correct for the gates; it is *not* the final concurrency model and is
  part of why the relay pump has rough edges (§6).
- **Datagrams are out of scope** — not in the frozen Tier-0 `transport.zig`
  contract.

---

## 6. Status — honest

### Implemented (connection-core S1-S4 complete)

A Zig node connects **directly or via relay**:

- **S1/S2** — QUIC transport: dial/accept, bi/uni streams over real picoquic UDP.
- **S3** — magicsock NAT custom-frame delivery (the picoquic fork patch) + codec.
- **S3.5** — magicsock is the routing authority for selected paths.
- **S4** — relay fallback routes QUIC through the DERP relay client when no direct
  path validates.

### Validated and reliability state

**CC-i1** remains the core proof: a real QUIC + TLS Raw-Public-Key handshake vs a
real `iroh::Endpoint` (`zig build interop`, env-gated). The historical same-host
transport caveat is no longer the current state. Cross-host QUIC is reliable on the
promoted evidence: 5/5 DIRECT, 5/5 HOLE-PUNCH, and a 30/30 persistent-anchor soak
with no stall/drift. Large transfers are reliable at 64 MiB and 256 MiB after the
flow-control fix.

The S4 relay-fallback flake gate is also closed for release purposes: the flake did
not reproduce over 0/300 runs under 6-CPU load after hardening. This is evidence of
a low observed rate, not a mathematical proof that the path can never flake.

### Remaining work

This module is M4-reliable, not M5/production:

- **Performance/topology/footprint characterization remains M5.** The controlled
  ReleaseFast same-host number is ~1.5-1.6x slower than iroh, and S2 attribution
  says the gap is not QUIC-engine-dominated. The active optimization home is
  `plans/transport-pump-perf`.
- **`rpk-cnx-peers-unbounded-growth` remains P3.** The Slice-D per-connection peer
  table fixes identity misattribution, but long-lived server cleanup still needs
  per-connection eviction.
- **`relay-server-hardening-salvage` remains P2.** The S4-r2 salvage items have
  standalone value but are not bundled with the now-moot S4 flake fix.
- **`relay-proof-queue-overflow-observed` remains a telemetry watch item.**
  Successful relay proof observed a nonzero overflow counter that should be trended
  in future measurement runs.

### Foundation

This component builds on **Tier-0 identity** (hash / key / addr), which is the
**FROZEN** foundation — `transport.zig`, `key.zig`, `addr.zig` do not change
except by amendment through `plans/port-00-core/`. See the top-level
`ARCHITECTURE.md` for the Tier-0 contract.

---

## 7. See also

- **Plans:** `plans/port-connection-core/README.md` (S1–S4 + CC-i1),
  `plans/port-00-core/README.md` (the frozen Tier-0 contract),
  `plans/port-hardening/README.md` (**H5** — connection robustness),
  `plans/quic-engine-spike/` (the picoquic engine decision).
- **Changelog:** `docs/changelog/entries/2026-06-22-promote-interop-cc-i1.md`
  (the thesis), `…/2026-06-23-promote-connection-core-s4.md` (relay fallback
  complete).
- **Audit:** `docs/research/zig-port-audit/2026-06-23-connection-core-audit.md`
  (score 76/100, the source of §6); `…/2026-06-23-core-audit.md` (Tier-0 identity).
- **Issues:** `docs/issues/zig/2026-06-23-s4-relay-fallback-rare-flake.md`.
- **Patches:** `patches/picoquic-iroh-nat-frames.patch`,
  `patches/picotls-iroh-rpk.patch`, `patches/README.md`.
- **Tests:** `S2`/`S3.5`/`S4` in `zig_iroh/src/transport/quic.zig`; magicsock
  codec/selection in `zig_iroh/src/magicsock/{frames,mod}.zig`; SNI snapshot in
  `zig_iroh/src/connection/tls_name.zig`; loopback handshake in
  `zig_iroh/src/connection/loopback.zig`; `zig build interop` (CC-i1, env-gated).
