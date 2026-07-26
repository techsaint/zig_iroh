> **zig_iroh** is an independent Zig port of **[iroh](https://github.com/n0-computer/iroh)** by n0 — the original production-grade Rust p2p stack. This component reimplements a subset of iroh's functionality in Zig, aiming for byte-for-byte wire compatibility. Full credit to the iroh authors; this port exists because iroh is excellent and worth learning from.
> iroh: https://github.com/n0-computer/iroh · https://www.iroh.computer
>
> **No warranty.** A community contribution / example of what's possible in Zig, provided as-is. The author may not keep it current; with enough interest they'll consider maintaining wire-compatibility with iroh. Not affiliated with or endorsed by n0.

# Gossip — Architecture

## 1. What this ports

This component ports **[iroh-gossip](https://github.com/n0-computer/iroh-gossip)**:
an epidemic-broadcast pub/sub overlay. A node subscribes to a 32-byte `TopicId`,
broadcasts a message, and the message floods to every other subscriber of that
topic via a self-healing mesh. It is two cooperating sub-protocols, both scoped
per topic:

- **HyParView** — partial-view membership. Maintains a small bounded *active
  view* (peers we hold live connections to) and a larger *passive view* (an
  address book), repairing the overlay as peers come and go.
- **Plumtree** — epidemic broadcast over that membership. Builds an efficient
  spanning tree (eager-push edges carry payloads; lazy-push edges carry only
  `IHave` digests), and repairs the tree with graft/prune when messages go
  missing.

ALPN: `"/iroh-gossip/1"` — `net.zig:10`, matching iroh's `GOSSIP_ALPN`
(`original/iroh-gossip/src/net.rs:45`).

The single most important structural decision, mirrored from iroh
(`original/iroh-gossip/src/proto.rs:1-3`): the protocol is an **IO-less state
machine**. The core takes `InEvent`s and returns `OutEvent`s; it never touches
sockets, the clock, or the RNG directly. Time and randomness are injected
(`now: u64` parameter, a seeded `*Rng`); timers surface as `schedule_timer`
out-events. This split lets the entire algorithm be tested deterministically
without a network, and lets the transport be bolted on last.

## 2. What it does (the lifecycle)

1. **Join** a topic with a bootstrap peer list — `topic::Command.join`
   (`state.zig:93-103`, `net.zig:63-69`). HyParView dials the bootstrap peers and
   negotiates active-view membership; on each successful link it emits
   `neighbor_up`, which Plumtree turns into an eager-push edge.
2. **Broadcast** a message — `Command.broadcast{content, scope}`
   (`net.zig:71-75`). Plumtree hashes the content to a `MessageId`
   (`blake3(content)`, `types.zig:12-16`), eager-pushes the payload to tree
   children, and lazy-pushes `IHave(id)` digests to the rest.
3. **Gossip / repair** — receivers re-push to their own children, dedup by
   `MessageId`, and emit a `received` event to the application. A node that sees
   an `IHave` for a message it lacks schedules a `Graft` to pull the payload;
   redundant eager edges are pruned. Membership keeps churning via periodic
   `Shuffle` walks.

## 3. Code map

All paths under `zig_iroh/src/gossip/`. The Zig layout mirrors iroh's `proto/`
module split file-for-file.

| Zig file | iroh reference | Responsibility |
|---|---|---|
| `gossip.zig` | `lib.rs` | Module root; re-exports (`gossip.zig:4-21`). |
| `types.zig` | `proto.rs` | Wire types + postcard codec for every message. |
| `postcard.zig` | `postcard` crate | Hand-written minimal postcard encoder/decoder. |
| `frame.zig` | `net/util.rs:336-393` | Stream framing: `[u32-BE len][postcard body]`. |
| `proto/hyparview.zig` | `proto/hyparview.rs` | Membership state machine. |
| `proto/plumtree.zig` | `proto/plumtree.rs` | Broadcast-tree state machine. |
| `proto/topic.zig` | `proto/topic.rs` | Per-topic wiring of HyParView + Plumtree. |
| `proto/state.zig` | `proto/state.rs` | Multi-topic router / global `State`. |
| `util.zig` | `proto/util.rs` | `IndexSet`, `TimeBoundCache`, `TimerMap` helpers. |
| `net.zig` | `net.rs` + `net/util.rs` | In-memory `MockTransport` mesh harness (deterministic tests; see §6). |
| `quic_net.zig` | `net.rs` | **Production** QUIC-backed `Net` — drives the protocol over real `quic.Endpoint` uni-streams (see §6). |
| `sim.zig` | `proto/sim.rs` | Discrete-event mesh simulator for tests. |
| `fixtures.zig` | — | Golden wire byte vectors (anchored to iroh 0.101.0). |

Key symbols to anchor on:

- **Codec** — `HyparviewMessage(PI)` tagged union + `encodeInto`/`decodeFrom`
  (`types.zig:104-244`), `PlumtreeMessage` (`types.zig:297-387`),
  `TopicMessage(PI)` = `swarm | gossip` (`types.zig:389-444`),
  `WireMessage(PI){topic, message}` (`types.zig:446-480`), `StreamHeader{topic_id}`
  (`types.zig:482-497`).
- **State machine** — `State(PI, Rng)` with its `InEvent`/`OutEvent` unions and the
  `handle(allocator, event, now) ![]OutEvent` entry point (`state.zig:40-195`).
  `peer_topics` bookkeeping and the join/quit topic lifecycle live there
  (`state.zig:93-114`, `119-130`).
- **Configs** — HyParView defaults (active cap 5, passive cap 30, ARWL 6, shuffle
  interval 60s, neighbor-request timeout 500ms) at `hyparview.zig:11-21`,
  matching `original/iroh-gossip/src/proto/hyparview.rs:197-221`. Plumtree
  defaults (graft timeouts 80/40ms, dispatch 5ms, optimization threshold round 7,
  cache retentions 30s/90s) at `plumtree.zig:16-24`.
- **`PI` (peer identity)** is generic: production uses Tier-0 `NodeId` (32-byte
  ed25519 key); tests use `u32` exactly as iroh's tests do. `encodePeer`/`decodePeer`
  (`types.zig:62-82`) special-case `u32` (varint) vs key types (raw 32 bytes).

## 4. Wire format & fidelity

Codec is **postcard** (iroh locks `postcard 1.1.3`). The Zig port does *not* pull
a serde framework; `postcard.zig` implements only the constructs gossip uses:
unsigned varints (u16/u32/usize), fixed `[u8;32]` arrays (no length prefix),
`Option` as a `0x00`/`0x01`-tagged enum, `Vec`/bytes as varint-length-prefixed,
enum discriminant as a varint of the declaration-order index, and `bool`.

**Per-frame layout on a uni stream** (`frame.zig:12-38`):

```
[ u32 length, BIG-ENDIAN ] [ postcard body ]
```

The length prefix is a fixed 4-byte big-endian `u32` *outside* postcard (matching
tokio `write_u32`/`read_u32`, `net/util.rs:359,390`); the body is postcard.
`readFrame` rejects `len > max_message_size` (default 4096, `types.zig:6`).

**Stream model** — one uni stream per topic per direction. The *first* frame on
each stream is a `StreamHeader{topic_id}` (`net.zig:152-156`); every subsequent
frame is an inner `topic::Message<PI>`. Consequence: the `TopicId` rides the
header once, not per message — so the wire body is the inner `TopicMessage`, never
the outer `WireMessage`. This matches iroh (`net/util.rs:58-89, 282-293`).

**Message set** (discriminant order is wire-significant — do not reorder):

- `TopicMessage` = `0:Swarm(HyparviewMessage)` | `1:Gossip(PlumtreeMessage)`
  (`types.zig:389-419`).
- `HyparviewMessage` = `0:Join` `1:ForwardJoin` `2:Shuffle` `3:ShuffleReply`
  `4:Neighbor` `5:Disconnect` (`types.zig:104-187`). `Disconnect` carries an
  obsolete-but-still-serialized `respond` bool kept for wire compatibility
  (`types.zig:123-126, 181-185`).
- `PlumtreeMessage` = `0:Gossip{id,content,scope}` `1:Prune` `2:Graft{id?,round}`
  `3:IHave([{id,round}])` (`types.zig:297-347`).

**Fidelity evidence** — `fixtures.zig` pins golden bytes verified against
iroh-gossip 0.101.0:

- `blake3("hi")` / `blake3("hi2")` content hashes (`fixtures.zig:3-11`, asserted
  `types.zig:499-502`).
- `topic::Gossip(Prune)` → `01 01` (`fixtures.zig:16`).
- `IHave([{blake3("hi"), round 2}])` (`fixtures.zig:19-23`).
- `Gossip{blake3("hi2"), "hi2", Swarm(9)}` (`fixtures.zig:26-30`).
- `Disconnect{alive:true, respond:false}` → `05 01 00` (`fixtures.zig:33`).
- `postcard_header_size = 33` (`fixtures.zig:13`), derived via
  `WireMessage.postcardHeaderSize` (`types.zig:451-459`).
- Full frame `00 00 00 02 01 01` (`fixtures.zig:36`, gated in `net.zig:277-286`
  and `gossip.zig:37-51`).

The gossip audit scored **Wire/Protocol Fidelity 20/20** — "byte-for-byte
equivalence against iroh 0.101.0 (postcard 1.1.3)"
(`docs/research/zig-port-audit/2026-06-23-gossip-audit.md:142-143`).

## 5. Design notes / differences

- **IO-less core, injected effects.** Exactly mirrors iroh. `handle` returns a
  freshly `dupe`d `[]OutEvent` from an internal `outbox` cleared each call
  (`state.zig:84-140`). The caller owns draining time, randomness, and transport.
- **Sets.** iroh's `IndexSet` (insertion-ordered, `swap_remove`) maps to Zig's
  `AutoArrayHashMapUnmanaged`; plain maps to `AutoHashMapUnmanaged`. Plumtree's
  eager/lazy peer order is not wire-visible, so a deterministic hashmap suffices.
- **Generic `PI`.** Same generic-over-peer-identity design as iroh, so the pure
  state machine is unit-tested with `u32` ids and run with `NodeId` in `net.zig`.
- **No `api.rs` / `metrics.rs` / address-lookup port.** The public `GossipApi`
  handle, RPC channels, metrics counters, and the discovery→pkarr/DNS linkage are
  out of scope for now (audit table,
  `docs/research/zig-port-audit/2026-06-23-gossip-audit.md:81-85`).

## 6. Status — honest assessment

**Gossip now runs over real QUIC and is validated live against real iroh-gossip
(same-host).** The protocol is done and golden-vector tested *and* the production
network driver (`quic_net.zig`) is in place — this doc previously described the
lane as MockTransport-only; that is no longer true.

### Implemented (and tested)

- **S1–S6 promoted to the main line** (HyParView + Plumtree; the codec/protocol
  was first proven over MockTransport, `plans/port-gossip/README.md:6`). Postcard
  codec + framing, all three message enums, both state machines, topic +
  multi-topic wiring, and a mesh test.
- **QUIC-backed `Net` promoted** (`quic_net.zig`): the protocol now drives over a
  real `quic.Endpoint` via uni-streams — `net.zig`'s `MockTransport` mesh is
  retained only as the deterministic in-memory test harness, not the production
  path.
- Behavioral parity tests port iroh's own unit/smoke tests (optimize-tree,
  spoofed-message drop, cache eviction, hyparview/plumtree smoke). `zig build
  test` green at promotion.
- Audit score **74/100**, confidence High — "the protocol state machine appears
  faithful" (`docs/research/zig-port-audit/2026-06-23-gossip-audit.md:24-25`).
  (That audit predates `quic_net.zig`; the QUIC driver was re-audited in audit-2,
  below.)

### Networking: real QUIC, live vs real iroh-gossip — SAME-HOST only

Gossip runs over real QUIC and is **validated live against a real
`iroh_gossip::Gossip` peer**: the `gossip-interop` lane is two gates — **3a**
(`gossip-quic-interop`, Zig↔Zig broadcast over real `quic.Endpoint` uni-streams)
and **3b** (live broadcast vs real iroh-gossip, **10/10**). `quic_net.zig` drives
the IO-less protocol core over `openUni`/`acceptUni` on a real
`transport.Connection`; the protocol core was kept intact — only the transport
binding changed.

The 3b root cause worth recording: the Zig uni-stream initially waited for FIN,
but iroh-gossip keeps per-topic uni-streams **open** with multiple framed
messages, so the reader was changed to **incremental uni-chunk reading**
(additive change in `quic.zig`). See the `gossip-interop` changelog
(`docs/changelog/entries/2026-06-24-promote-gossip-interop.md`).

> **Scope note.** The 3b live gate ran the real iroh-gossip peer on the same machine
> over loopback, which proves the gossip protocol/driver against real iroh-gossip.
> Broader cross-host transport reliability is tracked by the transport module and is
> now separately proven by the Remote Host Lab evidence.

### Current gaps / issues

The audit-2 QUIC-driver findings and older protocol/codec leak findings are fixed
or accounted for in promoted hardening:

- Slice B landed the memory/lifetime fixes called out by audit-2.
- GO1 fixed the `IHave` max size, neighbor-scoped broadcast, and graceful
  leave/shutdown over the real QUIC driver.
- The historical 3b root cause is fixed: Zig now reads uni-stream data
  incrementally because iroh-gossip keeps per-topic uni-streams open with multiple
  framed messages.

Remaining refinement: the current driver caches per pump; full per-topic
long-lived uni-stream reuse needs transport `flush()` support and is tracked as
post-alpha2 work. This does not block the M4 alpha2 release.

## 7. See also

- `plans/port-gossip/README.md` — the gossip plan: implementation recipe (a
  pre-digested read of `original/iroh-gossip`), slice gates, invariants.
- `plans/port-interop/runs/20260623-gossip-interop-kickoff.md` — the QUIC-backed
  Net (3a) + live iroh-gossip interop (3b) slice (now promoted).
- `docs/changelog/entries/2026-06-24-promote-gossip-interop.md` — the live
  gossip-interop promotion (same-host).
- `docs/research/zig-port-audit/2026-06-23-gossip-audit.md` — the verified audit
  (score 74/100, line-by-line vs the Rust references; predates `quic_net.zig`).
- `docs/issues/zig/2026-06-24-gossip-quic-net-inbound-lifetime-and-scale.md` —
  the audit-2 `quic_net.zig` inbound-lifetime + scale findings.
- `plans/port-hardening/README.md` — historical hardening context.
- Tests: `net.zig:252-286` (mesh broadcast + frame golden), `types.zig:499-580`
  (blake3 + golden bytes + round-trip), `sim.zig` (discrete-event mesh),
  `plumtree.zig` / `hyparview.zig` ported unit tests.
- iroh reference: `original/iroh-gossip/src/` (`proto.rs`, `proto/hyparview.rs`,
  `proto/plumtree.rs`, `proto/state.rs`, `proto/topic.rs`, `net.rs`,
  `net/util.rs`).
