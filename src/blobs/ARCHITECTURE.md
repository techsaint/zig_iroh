> **zig_iroh** is an independent Zig port of **[iroh](https://github.com/n0-computer/iroh)** by n0 — the original production-grade Rust p2p stack. This component reimplements a subset of iroh's functionality in Zig, aiming for byte-for-byte wire compatibility. Full credit to the iroh authors; this port exists because iroh is excellent and worth learning from.
> iroh: https://github.com/n0-computer/iroh · https://www.iroh.computer
>
> **No warranty.** A community contribution / example of what's possible in Zig, provided as-is. The author may not keep it current; with enough interest they'll consider maintaining wire-compatibility with iroh. Not affiliated with or endorsed by n0.

# BLOBS — Architecture

## 1. Ports

This component ports **[iroh-blobs](https://github.com/n0-computer/iroh-blobs)** — iroh's
content-addressed blob transfer crate (vendored read-only under `original/iroh-blobs/`). It
reimplements the get/provide subset of three protocol layers:

- **BLAKE3 + bao verified streaming** — n0-flavored bao with 1024-byte chunks and 16 KiB chunk
  groups (`IROH_BLOCK_SIZE = from_chunk_log(4)`, `original/iroh-blobs/src/store/mod.rs:18`). A
  blob's content hash *is* the BLAKE3 root of its bao tree.
- **postcard request codec** — `Request::Get(GetRequest)` / `GetMany` framing over unsigned
  LEB128 varints (`original/iroh-blobs/src/protocol.rs`).
- **collections / hashseq** — a `HashSeq` is concatenated 32-byte hashes
  (`original/iroh-blobs/src/hashseq.rs`); a `Collection` adds a `CollectionV0.` metadata header
  (`original/iroh-blobs/src/format/collection.rs`).

## 2. What it does

Verified streaming blob transfer. A **getter** opens a bidirectional QUIC stream, postcard-encodes
a `GetRequest{hash, ranges}`, finishes the send half, then reads back an 8-byte little-endian size
header followed by a bao-encoded byte stream. A **provider** serves the bao encoding (parent nodes
= two child hashes, leaves = raw data) prefixed by that size header. The getter recomputes every
parent and leaf hash bottom-up and compares against the expected hash propagated down from the
BLAKE3 **root** — rejecting on the first mismatch. Because the n0 flavor uses 16 KiB chunk groups,
any corrupted byte is detected within ≤ 16 KiB (invariant B-i2).

Multi-blob transfer reuses the same primitive: a `GetRequest::all(hashSeqHash)` returns the hashseq
blob first (whose body is the list of child hashes), then each child blob in sequence, each with
its own size header and bao stream. `GetMany` sends an explicit list of hashes and gets each blob
back in request order.

## 3. Code map

All paths are under `zig_iroh/src/blobs/`. The module root is `blobs.zig:1-25` (re-exports +
test aggregation).

| File | Responsibility | Key symbols |
|---|---|---|
| `postcard.zig` | Minimal postcard codec: unsigned LEB128 varints, slice headers, enum discriminant as `varint(u32)`. | `writeU64`/`readU64` (`:16-40`), `writeSliceHeader`/`readSliceHeader` (`:52-59`) |
| `range_spec.zig` | `RangeSpec` (alternating span widths) + `ChunkRangesSeq` (delta + RLE per-blob ranges) encode/decode. Constructors `singleBlob()`, `all()`, `empty`. | `RangeSpec`, `ChunkRangesSeq` |
| `protocol.zig` | Request framing. `GetRequest{hash, ranges}` and `GetManyRequest{hashes, ranges}` postcard encode/decode; `RequestType` enum. | `RequestType` (`:19-25`), `GetRequest.encode`/`decode` (`:39-53`), `GetManyRequest` (`:56-87`), `readRequest` (`:90-100`) |
| `blake3_hazmat.zig` | BLAKE3 internals std's high-level API doesn't expose: offset-counter chunk hashing, non-root chaining values, parent combine. Extracted from std's blake3 source. | `hashSubtree`, `parentCv` |
| `bao.zig` | n0-flavored bao: outboard + root encode (`createOutboard`), wire encode (`encodeAll`), and verified streaming decode (`decodeVerified`). Tree-node arithmetic mirrors the `bao-tree` crate. | `BaoTree` (`:189`), `createOutboard` (`:414`), `encodeAll` (`:515`), `ResponseIter` (`:536`), `decodeVerified` (`:680`) |
| `hashseq.zig` | `HashSeq` = concatenated 32-byte hashes; `len = bytes/32`, `get(i)` slices `[i*32..(i+1)*32]`. | `HashSeq` (`:6-29`) |
| `collection.zig` | `CollectionMeta` (`CollectionV0.` header + names) and `Collection` (name+hash entries → hashseq with meta-hash first). | `CollectionMeta` (`:19`), `Collection` (`:62`), `toBlobs` (`:120`) |
| `get.zig` | Get protocol over a `transport.Connection`. Single-blob, hashseq, and GetMany client/provider pairs. | `getBlob`/`serveBlob` (`:34`/`:52`), `getAll`/`serveAll` (`:74`/`:110`), `getMany`/`serveMany` (`:145`/`:174`) |
| `fixtures.zig` | Golden constants (root hashes + outboard hex for sizes 0/1024/16384/16385) and deterministic `makeTestData` (byte `i` = `i % 256`). | `golden` (`:26-32`), `makeTestData` (`:20`) |

## 4. Wire format & fidelity

The following are matched against iroh **byte-for-byte** and asserted by golden tests:

- **`GetRequest` encoding** — `[discriminant 0x00][32 raw hash bytes][ChunkRangesSeq]`. The
  `blob()` form for `0xda`×32 is `00 da..da 020001000100`; the `all()` form is `00 da..da
  01000100`. These exact vectors are pasted from `original/iroh-blobs/src/protocol.rs:1040-1066`
  and asserted in `protocol.zig:108-129` (encode) and `:131-149` (decode round-trip).
- **`GetManyRequest`** — `09` discriminant, then a LEB128-counted list of raw 32-byte hashes, then
  the `ChunkRangesSeq` (`protocol.zig:151-190`).
- **`RangeSpec` / `ChunkRangesSeq`** — every hex vector from `range_spec.rs:553-658` round-trips
  (`range_spec.zig` tests).
- **bao outboard + root** — `createOutboard` is golden-tested against vectors generated by Rust
  `PreOrderMemOutboard::create` + `encode_ranges_validated` from `bao-tree 0.16`. For the 16385-byte
  blob the root hash (`2fa27eb0…`) and the single 64-byte outboard pair (`a4480fcd…`) are asserted
  byte-for-byte, and the full wire (`size header || outboard || data`, 16449 bytes) is checked
  (`bao.zig:738-777`, `fixtures.zig:26-32`). The root hash is independently cross-checked against
  `Hash.of(data)` (which is itself anchored on iroh's `Hash::EMPTY` in Tier-0 `hash.zig`).
- **Response framing** — 8-byte little-endian `u64` size header (`std.mem.writeInt(..., .little)`,
  `get.zig:67`), then the bao stream: parent = 64 bytes (`left_hash || right_hash`), leaf = raw
  data, matching `original/iroh-blobs/src/api/blobs.rs:1145-1157`.
- **`CollectionV0.`** header — 13 bytes, golden-tested (`collection.zig:165-176`).

**Anchored vs not.** The request codec, bao outboard/root, and collection header are anchored to
iroh-produced vectors and are the highest-confidence parts. The **ALPN string `/iroh-bytes/4`**
(`protocol.rs:406`) is *not* defined anywhere in the blobs module — see §6. The over-the-wire
response is now proven **both** Zig-to-Zig over real QUIC **and** against a **real iroh-blobs
provider** (the promoted `blobs-interop` gate, byte-for-byte, no codec divergence — see §6) —
though, like every QUIC live gate, only **same-host (loopback)**.

## 5. Design notes / how it differs from iroh

- **Explicit allocators, no global runtime.** Codec functions take `std.mem.Allocator` and write to
  `std.Io.Writer` / read from `std.Io.Reader` (the non-generic Zig 0.16 interfaces). There is no
  tokio-style async runtime; transfers run synchronously over a `transport.Connection`. The
  `blobs_quic_interop.zig` test drives concurrency with `io.async`/`await` rather than a scheduler.
- **No store layer.** iroh-blobs has a pluggable content store (mem/fs) with an index. The Zig
  provider has none — `serveBlob`/`serveAll`/`serveMany` are fed the exact bytes to serve as
  arguments. They behave as single-stream, single-use channels, not a service (audit §3, §4
  Medium-1).
- **bao tree as flat arithmetic.** `bao.zig` reimplements `bao-tree`'s `TreeNode` math (post-order
  offsets, restricted parents, shifted roots) as standalone Zig functions (`:77-260`) instead of
  pulling the crate, which is not vendored.
- **hazmat extraction.** std's `std.crypto.hash.Blake3` exposes only the high-level hash; bao needs
  flag-aware chunk/parent hashing, so `blake3_hazmat.zig` reproduces those internals.
- **Postcard hand-rolled.** No serde; `postcard.zig` is a minimal LEB128 codec covering only the
  subset iroh-blobs uses.

## 6. Status — be honest

### Implemented (slices S1–S7, all promoted; trunk green)

- **S1** `range_spec.zig` — RangeSpec + ChunkRangesSeq codec; all hex vectors round-trip.
- **S2** `protocol.zig` — Request/GetRequest framing; `0xda`-hash vectors encode+decode.
- **S3** `bao.zig` outboard encode + root hash; golden-tested vs `bao-tree 0.16` for sizes
  {0, 1024, 16384, 16385}.
- **S4** `bao.zig` `decodeVerified`; corrupt-byte rejection within first 16 KiB (B-i2).
- **S5** `get.zig` single-blob `getBlob`/`serveBlob` over MockTransport.
- **S6** hashseq + multi-blob `getAll`/`serveAll`.
- **S7** `GetMany` + `collection.zig` (`CollectionMeta`, `Collection`).

### Validated vs real iroh — YES (same-host)

bao outboard/root and the request bytes are golden-tested against **iroh's own generated vectors**
(via `PreOrderMemOutboard::create` and the pasted `protocol.rs` vectors) — strong evidence the
*codec* is byte-compatible — **and** there is now a **live blob transfer against a real iroh-blobs
provider**. The promoted `zig build blobs-interop` gate (`blobs_interop.zig`;
`docs/changelog/entries/2026-06-23-promote-blob-transfer-interop.md`) spawns a **real**
`iroh_blobs::BlobsProtocol` provider (MemStore, `iroh_blobs::ALPN` = `/iroh-bytes/4`) serving a
65,537-byte multi-chunk-group blob; the Zig getter (`get.getBlob`) connects over `/iroh-bytes/4`,
reads the 8-byte LE size + bao stream, bao-verifies, and asserts byte-for-byte content equality.
It passed **9/9** with **zero `src/blobs/*.zig` changes** — the Zig bao verifier accepted real
iroh's `export_bao` output with **no codec divergence**. (The earlier Zig-to-Zig
`zig build blobs-quic-interop` gate, `blobs_quic_interop.zig:11-124`, still exists; it uses private
ALPNs `iroh-blobs-quic-interop`/`iroh-blobs-quic-hs` — `:16`, `:64`.)

> **Scope note.** `blobs-interop` ran the real iroh-blobs provider on the same machine over loopback,
> which proves codec/stream fidelity against real iroh-blobs. Transport-level cross-host reliability is
> tracked by the transport module and is now separately proven by the Remote Host Lab evidence.

### Current gaps / issues

The H2 P0 memory-safety bugs are fixed and promoted: bounded bao stacks, wire-size
caps, checked pushes, and filled-counter errdefers are in place, and the three
blob P0 differential vectors now pass. BL1 also promoted range execution and
provider hash-binding, so range requests execute and the provider rejects
content-addressability mismatches before serving.

Remaining blob work is post-alpha2 full-parity refinement (the road to beta):

- **Observe/Push:** request types 1 and 8 have real-iroh-grounded codecs (byte-parity vs
  real iroh-blobs proven via the writer-bytes oracle), bounded supplied-update Observe
  handling, and complete raw-root Push handling. Live **Get and Push** interop are proven
  end-to-end against a real iroh-blobs peer (the `sendFinish` drain fix —
  `iroh_picoquic_stream_send_flushed` — drives a multi-window Push fully out instead of
  abandoning it after the first idle pump). Live streaming **Observe** is post-alpha2: the
  observe reader hits end-of-stream against a real peer (a streaming-reader transport
  limitation, tracked in `docs/issues/zig/2026-07-21-blobs-observe-live-streaming.md`).
  Storage-backed long-lived Observe and ranged/hash-sequence Push import remain outside
  the current subset.
- **Allocator ergonomics and service shape** remain simpler than iroh-blobs'
  production store/index model.
- **Coverage depth:** a >=64 MiB blobs-over-QUIC regression should eventually
  complement the current smaller blobs-quic-interop coverage.

Honest summary: the codecs are byte-faithful and well-tested, live Get and Push interop
vs real iroh-blobs is proven (Observe is byte-parity-proven at the wire; live streaming
Observe is post-alpha2), and the former release-blocking P0s are fixed. Treat this as a
reliable alpha2 subset, not full iroh-blobs production parity.

## 7. See also

- `plans/port-blobs/README.md` — slice plan, recipe, execution amendments (S1–S7 promoted).
- `docs/research/zig-port-audit/2026-06-23-blobs-audit.md` — the verified audit this §6 is grounded
  in (score 68/100, High confidence).
- `plans/port-hardening/README.md` — slice **H2** contains the historical memory-safety + range
  hardening work.
- `plans/port-interop/runs/20260623-blob-transfer-interop-kickoff.md` — the real-iroh cross-impl
  gate kickoff; `docs/changelog/entries/2026-06-23-promote-blob-transfer-interop.md` — its promotion
  (live vs real iroh-blobs, byte-for-byte, same-host).
- `docs/research/zig-port-baseline/` — the pre-hardening quantitative/gate baseline.
- Tests: `bao.zig:738-792`, `protocol.zig:108-194`, `get.zig:195-311`, `collection.zig:165-205`,
  `blobs_quic_interop.zig` (real-QUIC, Zig-to-Zig).
- `original/iroh-blobs/src/{protocol.rs, get.rs, hashseq.rs, format/collection.rs, api/blobs.rs}`,
  `original/iroh-blobs/DESIGN.md`.
