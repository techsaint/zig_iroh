> **zig_iroh** is an independent Zig port of **[iroh](https://github.com/n0-computer/iroh)** by n0 — the original production-grade Rust p2p stack. This component reimplements a subset of iroh's functionality in Zig, aiming for byte-for-byte wire compatibility. Full credit to the iroh authors; this port exists because iroh is excellent and worth learning from.
> iroh: https://github.com/n0-computer/iroh · https://www.iroh.computer
>
> **No warranty.** A community contribution / example of what's possible in Zig, provided as-is. The author may not keep it current; with enough interest they'll consider maintaining wire-compatibility with iroh. Not affiliated with or endorsed by n0.

# DISCOVERY-DHT — Mainline DHT (BEP-44) discovery

## 1. Ports

This component ports the **fully-decentralized** node-discovery path of iroh /
[pkarr](https://github.com/pubky/pkarr): publish and resolve a node's signed
record as a **BEP-44 mutable item on the public BitTorrent mainline DHT**.

In iroh, a node announces its `EndpointInfo` (relay URL + direct socket
addresses) as a pkarr `SignedPacket` — a signed DNS packet keyed by the node's
Ed25519 public key. There are two ways to publish that packet:

- **pkarr / DoH path** (ported separately in `../discovery/`): publish through a
  pkarr relay and resolve via DNS-over-HTTPS against an n0 (or self-hosted)
  resolver. Centralized on a resolver, but cheap and reliable. This is the v1
  interop path.
- **mainline DHT path** (this component): publish the *same* `SignedPacket`
  directly onto the public mainline DHT as a BEP-44 mutable item. A resolving
  node fetches it back by Kademlia lookup. **No n0 resolver, no DoH, no relay** —
  pure decentralization. pkarr's Rust stack does this via
  [`pubky/mainline`](https://github.com/pubky/mainline); this is the Zig analog.

The two paths are complementary and share the **promoted `discovery.SignedPacket`
codec** (`../discovery/discovery.zig`) for the record body, so a record published
to the DHT is bit-identical to one published over DoH. This component only owns
the DHT transport and BEP-44 framing around that shared body.

Reference oracle: pkarr (`pubky/pkarr`) and its DHT engine `pubky/mainline`.

## 2. What it does

End-to-end, the DHT path is:

- **bencode + KRPC over UDP** (BEP-3 / BEP-5). All wire messages are bencoded
  KRPC dicts (`{t, y, q|r|e, a|r|e}`) sent on an ephemeral UDP socket.
- **iterative closest-node lookup.** Kademlia XOR-distance lookup toward a target
  ID, sorting candidates by distance and querying the closest unqueried node each
  round (`krpc.xorDistance`, `krpc.compareDistance`).
- **bootstrap via `find_node` then `get`.** Cold start has no routing table, so
  the client sends `find_node` to a set of well-known bootstrap routers (which
  answer `find_node` but ignore BEP-44 `get`), learns closer real nodes from the
  compact `nodes` field, then sends BEP-44 `get` to those known-id nodes to
  collect write tokens / locate the value.
- **BEP-44 put/get of mutable items.** `target = SHA-1(pubkey)` (no salt). The
  **signable** buffer is `3:seqi<seq>e1:v<len>:<value>` (`discovery.signable`,
  `discovery.zig:287`), signed with Ed25519. `put` carries
  `{id, k, seq, sig, token, v}`; `get` returns `{id, token, [v, k, sig, seq]}`.
- **resolve** reconstructs a `SignedPacket` from the returned `(k, seq, sig, v)`,
  re-verifies the Ed25519 signature, and decodes back to `EndpointInfo`.

## 3. Code map

`mod.zig` (`mod.zig:1-11`) re-exports the four modules and aggregates their tests.

### `bencode.zig` — BEP-3 codec
- `Value` (`bencode.zig:3`) — tagged union: `integer | string | list | dict`,
  with `KV` and typed accessors (`get`, `getAsString`, `getAsInteger`,
  `getAsList`, `getAsDict`).
- `Parser.parse` (`bencode.zig:120`) — recursive-descent decoder for `i…e`, `l…e`,
  `d…e`, and length-prefixed strings. Dict keys are **sorted on decode**
  (`bencode.zig:169-174`).
- `encode` / `encodeAlloc` (`bencode.zig:207`, `:249`) — encoder; **re-sorts dict
  keys before emitting** (`bencode.zig:230-235`) so output is canonical
  regardless of input ordering. Tests anchor to canonical BEP-3 vectors
  (`d3:cow3:moo4:spam4:eggse`, `l4:spami42ee`, etc., `bencode.zig:256-320`).

### `krpc.zig` — BEP-5 messages + compact node info
- `Id = [20]u8` (`krpc.zig:5`) — Kademlia 160-bit node/target ID.
- `NodeInfo.encodeCompact` / `decodeCompact` (`krpc.zig:11`, `:29`) — 26-byte IPv4
  and 38-byte IPv6 compact node format (20-byte id + addr + big-endian port).
- `parseCompactNodes` / `parseCompactNodes6` (`krpc.zig:68`, `:80`) — split the
  concatenated `nodes` / `nodes6` blobs.
- `xorDistance` / `compareDistance` (`krpc.zig:92`, `:100`) — Kademlia metric.
- `Message` (`krpc.zig:106`) — `{transaction_id, msg_type, body}` over
  query/response/error, with `encode` (`:129`) and `parse` (`:158`) translating
  to/from the bencode KRPC dict shape (`y=q|r|e`).

### `client.zig` — UDP transport, lookup, put/get, bootstrap
- `BOOTSTRAP_NODES` (`client.zig:12`) — the pubky/mainline default set:
  `router.bittorrent.com:6881`, `dht.transmissionbt.com:6881`,
  `dht.libtorrent.org:25401`, `relay.pkarr.org:6881`.
- `Client` (`client.zig:98`) — ephemeral UDP socket bound on an IPv4 wildcard
  ephemeral port (`client.zig:112`), random 160-bit node id (`client.zig:108`),
  `known_nodes` + resolved `bootstrap_addresses`.
- `resolveBootstrapNodes` (`client.zig:145`) — DNS-resolves the bootstrap hosts.
- `sendQuery` (`client.zig:181`) — encode → send → receive-with-timeout, matching
  on the 2-byte transaction id and **draining** stale / wrong-txid datagrams until
  timeout so a delayed reply can't poison the next query (`client.zig:234-269`).
- `addCandidate` (`client.zig:296`) — dedup-aware insert; **zero-id bootstrap
  addresses are kept distinct** (deduped by address, not id) so all bootstraps get
  queried (`client.zig:300`, regression test at `client.zig:605`).
- `get` (`client.zig:334`) — derives `target = SHA-1(pubkey)`, runs the iterative
  lookup (`find_node` to zero-id bootstraps, BEP-44 `get` to known-id nodes),
  verifies the signature, returns `GetResult{ value, signature, seq, k }`.
- `put` (`client.zig:457`) — same lookup to collect write tokens, then sends
  BEP-44 `put` to the closest token-bearing nodes; remembers storage nodes
  (`rememberNode`) for an immediate post-publish resolve. Distinct error returns:
  `NoLookupResponses`, `NoWriteTokens`, `PutFailedAllNodes`.

### `wiring.zig` — the `DhtDiscovery` facade
- `DhtDiscovery` (`wiring.zig:16`) — thin adapter over the promoted
  `discovery.SignedPacket`.
  - `publish` (`wiring.zig:19`) — builds a `SignedPacket` via
    `fromEndpointInfoAt`, then calls `client.put(pubkey, micros, encodedPacket,
    signature)`.
  - `resolve` (`wiring.zig:43`) — calls `client.get(node_id.bytes)`, splices the
    relay payload (`sig ++ seq ++ v`), rebuilds the `SignedPacket`, and decodes to
    `EndpointInfo`.
- `MockDhtServer` (`wiring.zig:68`) — loopback test double answering `find_node`,
  `get`, and `put` so the cold-start path is exercised offline (`wiring.zig:228`
  round-trip test).

## 4. Wire format & fidelity

What is anchored, and against what:

- **bencode (BEP-3).** Encode/decode is anchored to canonical BEP-3 vectors in the
  unit tests (`bencode.zig:256-320`), including the dict-key sorting invariant
  (unsorted input encodes to sorted canonical output, `bencode.zig:311-319`).
- **KRPC (BEP-5).** Message envelope (`t/y/q/a/r/e`) and **compact node info**
  (26-byte v4 / 38-byte v6, big-endian port) match the spec; tested at
  `krpc.zig:209-268`.
- **BEP-44 signable.** The signing buffer is `3:seqi<seq>e1:v<len>:<value>`
  produced by `discovery.signable` (`discovery.zig:287-291`), and `target =
  SHA-1(pubkey)`. The audit confirms the signing buffer and target derivation
  **match the spec byte-for-byte** (audit §3, §5: wire/protocol fidelity 19/20).
- **Shared record body.** The `v` field is the exact `discovery.SignedPacket`
  encoded DNS packet, identical to the DoH path — so DHT and DoH publish the same
  bytes.

Note on salt: this implementation uses `target = SHA-1(pubkey)` with **no salt**,
matching iroh/pkarr's saltless node records. The provisional plan text mentions a
salted form (`SHA-1(pubkey ++ salt)` and a `4:salt…` signable prefix); the shipped
code is the saltless case, which is what iroh actually publishes.

## 5. Design notes / differences

These are deliberate, right-sized deviations from the full Rust `mainline` engine —
appropriate for an ephemeral resolving client, not a long-lived DHT participant:

- **Ephemeral client, no routing table.** No persistent K-buckets or bucket
  maintenance; each lookup builds an ad-hoc candidate list from bootstraps +
  remembered storage nodes (`client.zig:124`, `Candidate` at `:274`). Right-sized
  for publish-then-resolve.
- **IPv4-only.** The socket binds IPv4 and IPv6 candidates are skipped
  (`supportsCandidateAddress`, `client.zig:289-294`) to avoid
  `AddressFamilyUnsupported` socket churn. Compact v6 parsing exists in `krpc.zig`
  but is unused by the client.
- **Sequential queries.** Closest-unqueried node is queried one at a time; the Rust
  engine fans out with concurrency α=3. Slower under loss, simpler.
- **Zero retries / fixed 500 ms timeout** per query (`client.zig:359-360`).
- **`find_node`-then-`get` bootstrap.** Bootstrap routers answer `find_node` but
  ignore BEP-44 `get`, so the client only sends `get` to known-id nodes learned
  from `find_node` responses — see the D5 changelog for why this was a real fix.

## 6. Status — honest

**Implemented:** all slices **D1-D5** are promoted (bencode, KRPC, BEP-44 put/get,
the `DhtDiscovery` wiring, and live interop). Plan status: **Complete**
(`plans/port-discovery-dht/README.md`).

**Validated:** invariant DHT-i2 (live `put` → `get` round-trip on the **public**
mainline DHT) was reproduced independently under `IROH_PORT_DHT_LIVE=1`. The
reviewer's wire log captured a real `put` accepted by `<redacted-peer-a>` and a
`len=586` record read back from `<redacted-peer-b>` — a genuine BEP-44 mutable item
published to and resolved from the public DHT (D5-live changelog,
`docs/changelog/entries/2026-06-23-promote-discovery-dht-d5-live.md`). Plain `zig
build test` is 128/129 (the live test is env-gated/skipped); 129/129 with the gate
on.

> Note: this gate exercises a real remote network, but it runs over the DHT's own
> UDP/KRPC socket (`client.zig`), not the Zig QUIC transport. QUIC cross-host
> reliability is tracked separately by the transport module and is now proven by
> the Remote Host Lab evidence.

### Security state

The former P0 identity-spoofing bug is fixed and promoted. `resolve` now binds a
returned mutable item to the queried `NodeId` instead of trusting the responder's
`res.k`, and the hardening differential vector `dht-wrong-key-spoof` now passes
with `observed: reject`.

The H7 follow-up is also promoted: `get()` returns the highest-seq verified
response instead of the first valid response, and bencode parsing has depth/leak
hardening.

### Remaining gaps

- **IPv4-only** — deliberate current partial; compact IPv6 parsing exists but the
  client skips IPv6 candidates.
- **Sequential queries** — deliberate current partial; the Rust engine fans out
  with more concurrency.
- **BEP-44 verification strictness** — the DHT boundary deliberately uses
  `verifyCofactored` to match the Rust mainline crate. Do not change this to
  strict verification without revisiting
  `docs/decisions/2026-06-27-ed25519-per-boundary-verify-strictness.md`.

## 7. See also

- `plans/port-discovery-dht/README.md` — plan, slices D1-D5, invariants (DHT-i1/i2/i3).
- `docs/changelog/entries/2026-06-23-promote-discovery-dht-d5-live.md` — the live
  publish/resolve promotion and the real bug fixes behind it.
- `docs/changelog/entries/2026-06-22-promote-discovery-dht-d1-d4.md` — D1-D4.
- `docs/research/zig-port-audit/2026-06-23-discovery-dht-audit.md` — the verified
  audit (score 74/100; historical spoofing finding).
- `plans/port-hardening/README.md` — H1 (spoof hardening) and H7 (seq / bencode).
- Tests: `wiring.zig:228` (loopback mock round-trip), `wiring.zig:283` (env-gated
  live mainline round-trip), `bencode.zig:256-320`, `krpc.zig:209-268`,
  `client.zig:605` (distinct zero-id bootstrap regression).
- Upstream oracle: pkarr (`pubky/pkarr`) and mainline (`pubky/mainline`).
