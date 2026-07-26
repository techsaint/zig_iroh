> **zig_iroh** is an independent Zig port of **[iroh](https://github.com/n0-computer/iroh)** by n0 — the original production-grade Rust p2p stack. This component reimplements a subset of iroh's functionality in Zig, aiming for byte-for-byte wire compatibility. Full credit to the iroh authors; this port exists because iroh is excellent and worth learning from.
> iroh: https://github.com/n0-computer/iroh · https://www.iroh.computer
>
> **No warranty.** A community contribution / example of what's possible in Zig, provided as-is. The author may not keep it current; with enough interest they'll consider maintaining wire-compatibility with iroh. Not affiliated with or endorsed by n0.

# Discovery (pkarr + DoH)

Node discovery answers one question: given a 32-byte Ed25519 `NodeId`, where on
the network is that node reachable (which relay, which direct IP:port pairs)?
iroh solves this by having each node *publish* a signed record under its own
public key and letting any peer *resolve* it. This component ports that
publish/resolve machinery.

This document covers the **pkarr signed-packet codec + the pkarr-relay/DoH
client + a self-hostable resolver server**. The decentralized Mainline-DHT
(BEP-44) transport is a separate component — see `src/discovery_dht/`
(plan: `plans/port-discovery-dht/`).

## 1. What it ports

iroh's node discovery lives in `original/iroh/iroh-dns/` (the codec + resolve
client) and `original/iroh/iroh-dns-server/` (the self-hostable resolver). The
mechanism, in iroh's own words (`iroh-dns/src/pkarr.rs:1-5`), is the
[pkarr](https://github.com/pubky/pkarr) signed-DNS-packet format: a node encodes
its `EndpointInfo` (relay URL + direct addresses) as DNS TXT records, signs the
DNS packet with its `SecretKey`, and publishes the signed blob. Because the
record is keyed by — and signed by — the node's public key, anyone who knows the
`NodeId` can fetch and verify it. iroh ships two resolve transports over the same
signed bytes:

- a **pkarr relay** (plain HTTPS `GET`/`PUT {relay}/{z32}`), default
  `https://dns.iroh.link/pkarr` (`iroh/src/address_lookup/pkarr.rs`), and
- **DNS-over-HTTPS** (RFC 8484) against the published TXT records at
  `_iroh.<z32>.dns.iroh.link` (`iroh-dns/src/dns.rs`).

iroh also ships a **self-hostable resolver** (`iroh-dns-server`) so a pure-Zig
network can run its own relay endpoint with no dependency on n0. This port
covers all three: codec, both client transports, and the resolver server.

The signed-packet *concept* comes from the external `pkarr` crate, but iroh
re-implements the wire format itself in `iroh-dns/src/pkarr.rs` — it does not
call pkarr's encoder. So every byte in the signed packet is knowable from iroh's
source, and that is what this port anchors against.

## 2. What it does

The data path, end to end:

1. **Build** an `EndpointInfo` (`discovery.zig:35`) from a `NodeAddr` —
   relay URL, direct addresses, optional user-data.
2. **Encode** it as RFC 1464 `key=value` TXT strings under the DNS name
   `_iroh.<z32-nodeid>` (`EndpointInfo.toTxtStrings`, `discovery.zig:68`). The
   publish DEFAULT is **relay-only** (`PublishAddressFilter.relay_only`, matching
   iroh's `AddrFilter::relay_only()`): only `relay=` + `user-data=` are emitted;
   `addr=` direct addresses are published ONLY when the caller opts in with
   `.unfiltered` (`toTxtStringsWithOptions`).
3. **Serialize** those TXT records into an RFC 1035 DNS reply packet with
   compressed answer-owner names (`dns_wire.buildTxtReply`,
   `dns_wire.zig:39`).
4. **Sign** the BEP-44 signable bytes over `(timestamp, dns_packet)` with the
   node's Ed25519 secret key, and frame the result as
   `pubkey(32) || sig(64) || timestamp_be(8) || dns_packet`
   (`SignedPacket.fromTxtStringsAt`, `discovery.zig:200`).
5. **Publish** the bytes-after-the-pubkey (the "relay payload") via HTTPS `PUT`
   to a pkarr relay (`publishPkarrRelay`, `discovery.zig:391`), or store them
   locally (`PacketStore.putRelayPayload`, `discovery.zig:307`).
6. **Resolve** by `GET {relay}/{z32}` and re-verifying the signature
   (`resolvePkarrRelay`, `discovery.zig:363`), or via a DoH TXT query
   (`resolveDohTxt`, `discovery.zig:478`). Either path yields an
   `EndpointInfo`, convertible to a Tier-0 `NodeAddr`
   (`EndpointInfo.toNodeAddr`, `discovery.zig:47`).

`DiscoveryClient` (`discovery.zig:420`) is the facade: `publish()` goes to the
pkarr relay; `resolve()` tries the relay first and falls back to DoH if a
`doh_url` is configured (`discovery.zig:445-457`).

## 3. Code map

### `discovery.zig` (codec + clients + store) — ~640 lines

| Symbol | Lines | Role |
|---|---|---|
| Constants (`HEADER_SIZE=104`, `MAX_DNS_PACKET_SIZE=1000`, relay/DoH URLs, content types) | `9-17` | Mirror `pkarr.rs:18-24` and iroh's default endpoints |
| `EndpointInfo` | `35-140` | Record model; `toTxtStrings`/`fromTxtStrings`/`fromSignedPacket`/`fromTxtLookup`; `<->NodeAddr` |
| `relayTxtString` | `141-154` | **Relay-URL trailing-slash canonicalization** (see §4) |
| `Timestamp` | `156-173` | micros since epoch, big-endian 8 bytes; `now()`/`toBytes`/`fromBytes` |
| `SignedPacket` | `175-285` | Framing: `fromTxtStringsAt`/`fromEndpointInfoAt`/`fromBytes`/`fromRelayPayload`/`relayPayload`/`encodedPacket`/`moreRecentThan`; eager verify in `fromBytesOwned` (`258`) |
| `signable` | `287-291` | BEP-44 signable string `3:seqi{ts}e1:v{len}:` ++ packet |
| `PacketStore` | `293-328` | In-memory `[32]u8 -> bytes` map with recency-checked upsert |
| `publishToStore`/`resolveFromStore` | `330-349` | Standalone (no-network) publish/resolve |
| `pkarrRelayUrl` | `351-361` | `{relay}/{z32}` URL building (trims trailing `/`) |
| `resolvePkarrRelay`/`publishPkarrRelay` | `363-418` | `std.http.Client` GET/PUT pkarr-relay transport |
| `DiscoveryClient` | `420-458` | Facade: relay publish, relay-then-DoH resolve |
| `buildDohGetUrl`/`resolveDohTxt` | `460-507` | RFC 8484 DoH: base64url-no-pad DNS query in `?dns=`, parse TXT answers |
| `txtLookupName`/`normalizedTxtName`/`nodeIdFromTxtName` | `509-527` | Name construction: `_iroh.<z32>[.<origin>]` |

### `dns_wire.zig` (RFC 1035 subset) — ~240 lines

Deliberately minimal: id=0 TXT query/reply, class IN, RFC 1035 names with
answer-name compression. Not a general DNS library (file header `dns_wire.zig:1-5`).

| Symbol | Lines | Role |
|---|---|---|
| `buildTxtQuery` | `23-37` | DoH query packet (id 0, RD set, one TXT question) |
| `buildTxtReply` | `39-73` | TXT reply; first answer carries the name, rest use a compression pointer (`appendPointer`, `152`) |
| `parseTxtAnswers` | `75-133` | Parse answers, filter by type/class/name, split RDATA character-strings |
| `parseNameInto` | `157-194` | Name decoder with pointer-jump cap of 16 (`178`, anti-loop) |
| `appendName`/`dnsNameEql` | `135-199` | Encode/case-insensitive-compare DNS names |

### `server.zig` (self-host resolver) — ~240 lines

| Symbol | Lines | Role |
|---|---|---|
| `serve` | `13-25` | Listen loop: accept → `handleStream` (see §6 — **serial, `try`-propagating**) |
| `handleStream` | `27-42` | One request per connection over `std.http.Server` |
| `handleRequest` | `44-66` | Route `/pkarr/{z32}` by method; 404 otherwise |
| `handlePut` | `68-104` | Content-type check → read body → `putRelayPayload` → `204`; `error.OlderPacket` → `409` |
| `handleGet` | `106-128` | `getRelayPayload` → body + pkarr content-type; miss → `404` |

Entrypoints: `resolver_main.zig` (the `zig build pkarr-resolver` binary) and
`live_interop_main.zig` (the `zig build discovery-live-interop` gate).

## 4. Wire format & fidelity

This is the component's strongest evidence. The pkarr signed packet is anchored
**byte-for-byte to iroh's real `EndpointInfo::to_pkarr_signed_packet`**, and a
live DoH path was reproduced against real iroh production DNS.

**Signed packet layout** (`pkarr.rs:28`, ported at `discovery.zig:200-225`):

```
[ 32 ] Ed25519 public key  (== NodeId bytes)
[ 64 ] Ed25519 signature
[  8 ] timestamp, micros since UNIX epoch, BIG-ENDIAN u64
[  N ] DNS packet (RFC 1035 wire format), N <= 1000
```

Total `<= 1104`; `HEADER_SIZE = 104`. These constants match `pkarr.rs:18-24`
exactly (`discovery.zig:9-11`).

**BEP-44 signable** (`pkarr.rs:291-295`): the Ed25519 message is *not* the raw
packet but `b"3:seqi" ++ ascii(ts_micros) ++ b"e1:v" ++ ascii(packet.len) ++
b":" ++ dns_packet`. Ported verbatim at `discovery.zig:287-291`; a unit test
pins `signable(42, "PAYLOAD") == "3:seqi42e1:v7:PAYLOAD"` (`discovery.zig:534`),
matching iroh's `format!("3:seqi{}e1:v{}:", ...)`.

**Relay payload** = signed bytes after the 32-byte pubkey
(`sig || ts_be || dns_packet`) — `relayPayload()` (`discovery.zig:243`) mirrors
iroh's `to_relay_payload`. `fromRelayPayload` (`discovery.zig:231`) prepends the
known pubkey and runs full verification, exactly as `pkarr.rs:120` /
`http/pkarr.rs:22`.

**TXT records** are RFC 1464 `key=value` under the name `_iroh.<z32>`
(`IROH_TXT_NAME = "_iroh"`, `attrs.rs:20`; normalized name at
`discovery.zig:515`). Keys: `relay=<url>`, `addr=<ip:port>` (multiple allowed,
order = priority; emitted only under `.unfiltered` — the publish default is
relay-only), `user-data=<utf8>` (`discovery.zig:74-82`,
`fromTxtStrings:118-131`). The `.<origin-domain>` suffix is added by the
resolver/DNS layer, not baked into the signed packet — matching iroh.

**z-base-32 origin**: the record name uses the node id's z32 form
(`NodeId.toZ32`, alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`), already ported in
Tier-0 `src/key.zig`.

### The byte-match gate

`interop_tests.zig:9-35` (`expectPkarrMatchesIrohReference`) rebuilds a Zig
`SignedPacket` from semantic inputs (secret `0x11`, `relay=https://example.com`,
`addr=127.0.0.1:1234`, ttl 30) **reusing the Rust peer's runtime timestamp**, and
asserts `expectEqualSlices(rust_pkarr_bytes, packet.bytes)` (`:34`). The Rust
side now produces the reference via iroh's *real production path* —
`EndpointInfo::to_pkarr_signed_packet(&secret_key, 30)` + `SignedPacket::as_bytes()`
— not a hand-assembled record set (changelog
`docs/changelog/entries/2026-06-23-promote-pkarr-interop-anchor.md`). So the gate
proves **Zig output == iroh's actual serialization**, not == a reconstruction.
`zig build interop` passes (131 pass / 1 skip / 0 fail); the byte-match is in the
ungated, non-skipped CC-i1 test (`interop_tests.zig:86`), so it ran.

### Fidelity bug this anchoring surfaced

Switching the reference to iroh's real serializer caught a genuine bug: iroh's
`Url` serialization **canonicalizes an authority-only relay URL with a trailing
slash** — `https://example.com` is emitted as `relay=https://example.com/`. The
Zig encoder had emitted it with no slash, which changed the RDATA length, the
DNS packet bytes, and therefore the BEP-44 signature — a real wire divergence,
not cosmetic. Fixed in `relayTxtString` (`discovery.zig:141-154`), which inserts
`/` after an authority that has no path. Parse is symmetric: the round-trip test
now asserts the canonical `https://example.com/` (`discovery.zig:583`,
`server.zig:188`).

### Live DoH interop

`zig build discovery-live-interop` (`live_interop_main.zig`) performs a real
public DoH lookup (Cloudflare `/dns-query`) for the live iroh node
`dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy` under origin
`dns.iroh.link.`, parses the returned TXT records, and asserts node-id match plus
at least one reachability hint. Last run observed
`relay=https://euc1-1.relay.n0.iroh-canary.iroh.link./`. Exact historical TXT
values are pinned in deterministic parser tests (`discovery.zig:540`); the live
gate asserts only stable invariants so it does not flake on mutable relay data.
Current caveat: the static live canary now returns DNS NXDOMAIN/no TXT before
exercising Zig record parsing. That is tracked as an external fixture issue; the
deterministic pkarr byte-match and other live gates remain green.

## 5. Design notes / differences

- **Tier-0 reuse.** Ed25519 sign/verify, `PublicKey`/`Signature`/`NodeId`, and
  z32 come from the frozen Tier-0 `src/key.zig`; the codec never re-derives
  crypto. `EndpointInfo` produces a Tier-0 `NodeAddr`.
- **Single DNS name per packet.** Like iroh, all TXT answers share one owner
  name; `buildTxtReply` writes the name once and points subsequent answers at it
  with a compression pointer (`dns_wire.zig:55-62`) — required to reproduce
  iroh's `build_bytes_vec_compressed` bytes.
- **No `simple_dns` dependency.** iroh leans on the `simple_dns` crate;
  `dns_wire.zig` is a hand-written RFC 1035 subset (only what discovery needs).
  Fidelity is guaranteed by the byte-match gate, not by sharing a library.
- **DoH endpoint choice.** iroh delegates DNS to `hickory` with no hardcoded DoH
  URL; this port defaults to Cloudflare (`DEFAULT_DOH_URL`, `discovery.zig:15`).
  This works for n0 interop because n0 serves `_iroh.<z32>.dns.iroh.link` as real
  public DNS, resolvable by any DoH provider.
- **Recency rule.** `moreRecentThan` (`discovery.zig:251`) is a direct port of
  `pkarr.rs:270`: newer timestamp wins; on a tie, the greater DNS-packet bytes
  win.
- **Resolve fallback.** `DiscoveryClient.resolve` is relay-first with optional
  DoH fallback (`discovery.zig:445`). iroh runs multiple discovery services
  concurrently with stagger/jitter; this port keeps a simpler sequential
  fallback.
- **In-memory store only.** `PacketStore` is a hash map; iroh's server has a
  persistent store with a 7-day eviction TTL (`store/signed_packets.rs`). Fine
  for v1; not durable.

## 6. Status — honest

**Implemented (S1-S5, promoted to main 2026-06-22, merge `90aebccb`;
`plans/port-discovery/` `remaining: []`):**

- S1 signed-packet + TXT/DNS codec; S2 pkarr-relay HTTPS client; S3 DoH (RFC
  8484) resolver; S4 self-host resolver server + `pkarr-resolver` binary; S5
  `DiscoveryClient` facade + live DoH interop gate.

**Validated against real iroh — YES on the client/codec side:**

- Byte-for-byte vs iroh's real `to_pkarr_signed_packet` (the `zig build interop`
  byte-match gate; §4). **Offline** — a serialization match, no live peer.
- Live DoH resolve uses the real public network (HTTPS DoH against `dns.iroh.link`)
  and does not depend on the Zig QUIC endpoint.
- Standalone publish→resolve round-trips through the Zig server in-process
  (`server.zig:147`, `:192`).

> Note: this lane's "validated vs real iroh" is the **codec byte-match + live DoH**.
> The DoH path is not a QUIC transport gate; it exercises public DNS/HTTPS instead.

**Known issues (current).** The resolver-server hardening gaps from the discovery
audit are fixed and promoted: the accept/stream error path continues instead of
killing the server, stale PUT now matches iroh's `204`, and a process-local rate
limit is in place. DI1 also fixed default publish semantics: default pkarr publish
is relay-only while `.unfiltered` remains available for raw `EndpointInfo`
serialization and Rust byte fixtures.

Remaining caveats:

- **Static live DoH canary fixture:** `discovery-live-interop` currently gets DNS
  NXDOMAIN/no TXT for its static `_iroh...dns.iroh.link` record. Refresh the
  fixture or move the live canary to a controlled record.
- **`Timestamp.now()` monotonicity:** still dead code, but should be fixed before
  any caller uses it for production publish timestamps.
- **Resolver surface:** no standard port-53 DNS / `/dns-query` DoH frontend; the
  Zig resolver exposes the `/pkarr/{z32}` HTTP endpoint.

## 7. See also

- **Plan:** `plans/port-discovery/README.md` — slice breakdown S1-S5, recipe,
  invariants (D-i1/D-i2/D-i3), execution amendments.
- **Audit:** `docs/research/zig-port-audit/2026-06-23-discovery-audit.md` —
  verified findings, scoring, and the server-robustness deductions.
- **Changelog:** `docs/changelog/entries/2026-06-23-promote-pkarr-interop-anchor.md`
  — the pkarr byte-anchor + the trailing-slash fidelity fix.
- **Hardening:** `plans/port-hardening/README.md` (H6) — the resolver-server
  robustness work.
- **Tests:** `src/interop_tests.zig` (byte-match + deterministic construction),
  `src/discovery/discovery.zig` tests (signable, TXT parse, sign/verify/tamper,
  standalone store, relay URL, DoH URL), `src/discovery/server.zig` tests
  (HTTP round-trip), `live_interop_main.zig` (live DoH gate).
- **iroh reference:** `original/iroh/iroh-dns/src/{pkarr,attrs,endpoint_info,dns}.rs`,
  `original/iroh/iroh-dns-server/src/http/pkarr.rs`.
- **Mainline DHT discovery is a separate component** — `src/discovery_dht/`
  (plan `plans/port-discovery-dht/`). That track owns the BEP-44 mutable-item
  put/get over Kademlia/UDP; this one owns only pkarr codec + relay/DoH + the
  resolver server.
