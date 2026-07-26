> **zig_iroh** is an independent Zig port of **[iroh](https://github.com/n0-computer/iroh)** by n0 — the original production-grade Rust p2p stack. This component reimplements a subset of iroh's functionality in Zig, aiming for byte-for-byte wire compatibility. Full credit to the iroh authors; this port exists because iroh is excellent and worth learning from.
> iroh: https://github.com/n0-computer/iroh · https://www.iroh.computer
>
> **No warranty.** A community contribution / example of what's possible in Zig, provided as-is. The author may not keep it current; with enough interest they'll consider maintaining wire-compatibility with iroh. Not affiliated with or endorsed by n0.

# Relay — Architecture

## 1. What this ports

This component ports **iroh-relay** — the DERP-style relay crate in iroh
(`original/iroh/iroh-relay/`). A relay is the fallback path used when two iroh
nodes cannot establish a direct, hole-punched QUIC connection: instead of
talking peer-to-peer, both peers connect to a shared, publicly reachable relay
server, and the relay forwards their (already end-to-end-encrypted) datagrams.

The relay is deliberately a *dumb packet forwarder*. It does not decrypt traffic;
it only routes opaque datagrams keyed by **node id** (the 32-byte Ed25519 public
key, `EndpointId` in iroh terms). The transport stack, bottom to top, is:

```
TCP → TLS (wss:// only) → HTTP/1.1 Upgrade → WebSocket → binary WS messages
```

Each WebSocket **binary** message carries exactly one DERP protocol frame — there
is no separate relay-level length field; the WS message boundary *is* the frame
boundary (`proto.zig:1-7`).

zig_iroh ships the relay as a **first-class client and server** (per
`plans/port-relay/README.md:22-27`):

- **Client** — reaches the live iroh / n0 relay network (interop), and is the
  fallback path that the connection core's magicsock drives.
- **Server** — lets a pure-Zig network self-host its own relay with no Rust iroh
  / n0 dependency, and can also serve real iroh clients (same wire).

## 2. What it does (runtime flow)

1. **Connect.** Client dials `ws://host:port/relay` (plain) or `wss://...` (TLS),
   then sends a hand-rolled HTTP/1.1 WebSocket upgrade
   (`client.zig:134-181`). The upgrade offers
   `Sec-WebSocket-Protocol: iroh-relay-v2, iroh-relay-v1`; the server replies
   `101 Switching Protocols` and echoes the negotiated version
   (`server.zig:274-325`).
2. **Authenticate.** A challenge/response handshake proves the client owns its
   node id: server sends 16 random bytes (`ServerChallenge`), client signs a
   Blake3-derived message and replies `ClientAuth`, server verifies and replies
   `ServerConfirmsAuth` / `ServerDeniesAuth` (`server.zig:327-357`,
   `client.zig:183-214`, `handshake.zig`).
3. **Forward.** A client sends `ClientToRelayDatagram(s)` addressed to a
   destination node id; the server looks up that node's connection and re-emits
   it as `RelayToClientDatagram(s)` tagged with the *source* node id, dropping
   silently if the destination is absent (`server.zig:454-498`).
4. **Notify on leave.** When a client disconnects, every peer it has sent to
   receives `EndpointGone(src)` (`server.zig:268-271`).
5. **Keepalive.** The server sends `Ping(random 8 bytes)` every ~15 s (+ jitter)
   and drops the connection if no matching `Pong` arrives within 5 s
   (`server.zig:359-398`). Either side answers any inbound `Ping` with a `Pong`
   echoing the 8 bytes (`server.zig:442-450`, `client.zig:122-125`).

## 3. Code map

All paths under `zig_iroh/src/relay/` unless noted.

| File | Role | Key symbols |
|---|---|---|
| `relay.zig` | Module entry point — re-exports `proto`, `handshake`, `client`, `server`, `tls_wrapper` (`relay.zig:3-7`). | — |
| `proto.zig` | DERP frame codec. Pure, no I/O. | `FrameType` (tags 0–13), `ProtocolVersion`, `Datagrams`, `ClientToRelayMsg` / `RelayToClientMsg` unions, `Status`, QUIC varint `writeVarint`/`readVarint`, `encode*`/`decode*`, `MAX_PACKET_SIZE=64KiB`, and `MAX_FRAME_SIZE=64KiB+8` for the largest post-tag payload plus a full-width tag. |
| `handshake.zig` | Challenge/auth frames + signing. | `CHALLENGE_CONTEXT` Blake3 KDF context (`:14`), `messageToSign` (`:52`, `Blake3.initKdf`), `clientAuthFor` (`:63`), `verifyClientAuth` (`:74`), `encode*`/`decodeHandshakeFrame` (`:82-178`), `postcardVarintSize` (`:179`). |
| `client.zig` | Relay client: connect → WS upgrade → handshake → send/recv. | `Client.connect` (`:46-81`), `wsUpgrade` (`:134-181`), `challengeHandshake` (`:183-214`), `send` (`:93-103`, masks outbound), `recv` (`:105-128`, auto-`Pong`), `parseRelayUrl` (`:237-259`). |
| `server.zig` | Relay server: accept → auth → route, plus the `Clients` table and keepalive. | `Server` (`:144`), `acceptAndSpawn` / `handleClient` (`:185-272`), `wsServerUpgrade` (`:274-325`), `challengeHandshake` (`:327-357`), `keepaliveThread` (`:359-398`), `clientLoop` (`:428-484`), `forwardDatagram` (`:486-498`). `Clients` table: `register` (dup-endpoint eviction, `:107-118`), `unregister`/`get`/`sendTo` (`:120-141`). `ClientConn` (`:24-75`). `ServerConfig` (`:14-22`). |
| `ws.zig` | RFC 6455 WebSocket framing + masking. | `OpCode` (`:8-16`), `writeFrame` (`:31-62`, XOR-masks when `mask=true`), `readFrameHeader` (`:71-95`), `readFrame` with role-based mask enforcement (`:119-163`), `readMaskKey`/`unmaskPayload` (`:97-107`). |
| `tls_wrapper.zig` | wss:// TLS via the pure-Zig `tls` (ianic/tls.zig) library. | `TlsClient.connect` (`:36-76`), `TlsServer.accept` (`:117-155`). Heap-allocated; exposes cleartext `reader()`/`writer()`. |
| `../../relay_main.zig` | `zig build relay` server binary entry. | `main`. |
| `../../relay_roundtrip_test.zig` | `zig build test-relay` standalone ws:// + wss:// round-trip. | `testWsRoundtrip`, TLS echo. |
| `../../relay_interop_test.zig` | `zig build relay-interop` gate vs **real Rust iroh-relay**. | `proveForwardedDatagram` (`:128-164`). |

### Protocol versions (`iroh-relay-v2` / `iroh-relay-v1`)

V2 is preferred (`proto.zig:39`). The only frame-level differences are version
gating: `Health` (tag 11) is V1-only, `Status` (tag 13) is V2-only
(`proto.zig:60-67`). The server negotiates by picking V2 if the client's offered
`Sec-WebSocket-Protocol` list contains `iroh-relay-v2`, else V1
(`server.zig:302-307`).

## 4. Wire format & fidelity

The DERP wire format is reproduced from iroh's `protos/` snapshot tests
byte-for-byte. The three layers:

- **WebSocket upgrade.** Client `GET /relay HTTP/1.1` with `Upgrade: websocket`,
  `Sec-WebSocket-Version: 13`, a base64 `Sec-WebSocket-Key`, and
  `Sec-WebSocket-Protocol: iroh-relay-v2, iroh-relay-v1`
  (`client.zig:143-153`). Server replies `101` with
  `Sec-WebSocket-Accept = base64(SHA1(key ++ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`
  (`server.zig:309-321`; GUID at `server.zig:501`). After upgrade, **clients
  mask** outbound frames and **servers send unmasked** per RFC 6455 §5.1
  (`ws.zig:25-29`, role enforcement at `ws.zig:126-134`).
- **Challenge/response handshake.** Postcard-like layout. `ServerChallenge`
  (tag 0) = `00` + 16 raw challenge bytes. `ClientAuth` (tag 1) =
  `01` + pubkey(32) + `0x40` + signature(64). The signed message is **not** the
  raw challenge but
  `blake3::derive_key("iroh-relay handshake v1 challenge signature", challenge)`
  → 32 bytes, Ed25519-signed (`handshake.zig:14,52-63`). `ServerConfirmsAuth`
  (tag 2) = single byte `02`. zig_iroh implements only the **challenge path**;
  the optional TLS-exporter (RFC 5705) fast path is omitted (always safe to skip
  — the server falls back to challenge; see `2026-06-23-relay-audit.md` row
  "Handshake (Fast-path) — Missing-in-Scope").
- **DERP frame codec.** `[FrameType: QUIC varint][payload...]`, big-endian
  integers, no trailing length. Tags 0–13 all encode as a single byte
  (`proto.zig:74-85`). Data frames are raw-byte encoded; the only structural
  single-vs-batch difference is a `u16` `segment_size` present for batch tags
  (5/7) only (`proto.zig:129-135`).

### The interop gate — strongest validation in the port

`zig build relay-interop` (`relay_interop_test.zig`) is the load-bearing fidelity
proof. It **spawns the real Rust `iroh-relay` binary** from `original/iroh`
(`cargo run -p iroh-relay --features server --bin iroh-relay`,
`relay_interop_test.zig:43-54`), waits for it to bind (`:109-126`), connects
**two Zig relay clients** over ws://, completes the v2 challenge handshake on
both, and proves a 35-byte datagram is forwarded
`Zig client A → real iroh-relay → Zig client B` with `src == A`
(`:128-164`). Per the changelog
(`docs/changelog/entries/2026-06-23-promote-relay-interop.md`), this passed with
**zero edits to `src/relay/*`** — the promoted client code talks to real iroh out
of the box — and ran **10/10 consecutive** on the main-line layout. This is the
first (and one of the strongest-validated) lanes in the port to interoperate with
a live iroh binary. **Scope note:** the real `iroh-relay` binary is spawned on the
same machine and the Zig clients connect over loopback. That proves relay
wire/client fidelity; broader cross-host transport reliability is tracked by the
transport module and is now separately proven by the Remote Host Lab evidence.

## 5. Design notes / differences from iroh

- **TLS is pure-Zig, not wolfSSL.** The plan originally decided wolfSSL (an
  external C lib), but the port instead wraps **ianic/tls.zig** — a pure-Zig
  TLS 1.2/1.3 library — via `tls_wrapper.zig`. No C dependency; both `TlsClient`
  and `TlsServer` are **heap-allocated** (`allocator.create`,
  `tls_wrapper.zig:43,124`) because they hold large per-connection encryption
  buffers (`[17000]u8` cleartext + `tls.input/output_buffer_len` ciphertext).
  Trade-off vs wolfSSL is unevaluated under high load
  (`2026-06-23-relay-audit.md` §6).
- **Thread-per-connection.** The server spawns one OS thread per client via
  `acceptAndSpawn` (`server.zig:185-189`) plus a **second** thread per client for
  keepalive (`server.zig:254-262`) — two threads per connection, vs iroh's
  single async actor per client (`server/client.rs`). Higher resource overhead.
- **`Clients` table.** A `std.AutoHashMapUnmanaged(PublicKey, *ClientConn)` under
  a `std.atomic.Mutex` (`server.zig:77-142`), mirroring iroh's `clients.rs`. Dup
  endpoint id → new connection replaces old, old gets
  `Status(SameEndpointIdConnected)` (`server.zig:247-253`).
- **Hand-rolled HTTP/WS.** Both the client upgrade request and the server `101`
  response are hand-rolled (no `std.http`), so the exact header set and accept-key
  computation are visible and controllable for wire fidelity.

## 6. Status — honest

**Implemented.** Complete relay: DERP codec + challenge handshake + client
(connect/send/recv) + server forwarding (`Clients` table, datagram routing,
`EndpointGone`, duplicate-endpoint eviction) + keepalive ping/pong, over both
**ws://** and **wss:// (real TLS)**. `zig build relay` (binary), `zig build
test-relay` (standalone round-trip), and `zig build relay-interop` (real-iroh
gate) all exist. Per `plans/port-relay/README.md:1-19`, the track is **Promoted**;
codec unit tests reproduce every iroh snapshot vector byte-for-byte.

**Validated against real iroh? YES.** The `relay-interop` gate (Zig client ↔ real
Rust `iroh-relay`) passes (`relay_interop_test.zig`;
`2026-06-23-promote-relay-interop.md`), with the real iroh-relay binary spawned on
the same machine and the clients connecting over loopback. This is one of the
strongest-validated lanes in the whole port.

**Known issues (current).** The relay-audit UAF/teardown-race class is fixed and
promoted by hardening Slice C; `relay-adversarial-no-crash` is an M4 met
criterion. Remaining relay items are refinement/watch work:

- **`relay-server-hardening-salvage` (P2):** standalone S4-r2 server-hardening
  items such as stream-close-on-spawn-fail, race-free unregister-if-match, and a
  pre-auth timeout thread. Valuable, but not an alpha2 blocker.
- **`relay-proof-queue-overflow-observed` (low telemetry watch):** a successful
  remote relay proof observed a nonzero overflow counter; future benchmark runs
  should trend it.
- **`proto.zig` enum/status hardening:** a possible L-3 sibling around
  `@enumFromInt` validation remains a follow-up.

## 7. See also

- **Plan:** `plans/port-relay/README.md` — the slice plan + the pre-digested DERP
  wire spec (so you need not re-read `original/iroh/iroh-relay/`).
- **Interop gate:** `zig_iroh/relay_interop_test.zig` + `zig build relay-interop`;
  promoted in `docs/changelog/entries/2026-06-23-promote-relay-interop.md`. Other
  relay changelog entries:
  `2026-06-22-promote-relay-complete.md`,
  `2026-06-23-promote-relay-keepalive.md`,
  `2026-06-22-relay-cert-path-fix-and-keepalive-review.md`.
- **Audit:** `docs/research/zig-port-audit/2026-06-23-relay-audit.md` (score
  65/100; feature table + findings by severity).
- **Hardening:** `plans/port-hardening/README.md` (item **H3**, the relay
  UAF/teardown-race fix).
- **Tests:** `zig_iroh/relay_roundtrip_test.zig` (ws:// + wss:// standalone),
  `src/relay/*.zig` inline unit tests (codec snapshot vectors, ws round-trips,
  keepalive timeout).
- **iroh reference:** `original/iroh/iroh-relay/src/` —
  `protos/{common,relay,handshake,streams}.rs`, `client.rs`, `client/conn.rs`,
  `server.rs`, `server/{client,clients,http_server}.rs`, `ping_tracker.rs`.
