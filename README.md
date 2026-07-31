# zig_iroh

A [Zig](https://ziglang.org) port of [iroh](https://github.com/n0-computer/iroh) — dial another peer by
its public key and get a direct, authenticated, encrypted QUIC connection, with relay fallback and hole
punching when the network is unkind.

zig_iroh is **wire-compatible** with iroh: it speaks the same protocols on the same sockets, and its
gates include real-peer interop against upstream iroh. It is a **feature subset** of iroh today — it
implements the core connection, discovery, relay, and transfer surfaces. there are quite a few gaps but its working!

- **Ports iroh at:** `255a939b1a` (`v1.0.0-2-g255a939b1a`)

- **Toolchain:** Zig `0.16.0`

- **Status:** `1.0.0-zig-alpha2` / package `0.3.0-alpha` — subset alpha

## Dependencies (picoquic-picotls)

Vendored, patched, and shipped under `deps/`:

- **picoquic** — pinned `91405da4d966966f74e03ddd89a6bb8be599aa73` (MIT)
- **picotls** — pinned `a096f85363edfd9d4f019412232fb6293af504f7` (MIT); bundles **cifra** (CC0-1.0) and **micro-ecc** (BSD-2-Clause); picotls-fusion carries Apache-2.0 + MIT notices

Not vendored: the host's **OpenSSL `libcrypto`** — development headers are required to build every product **except** `noq-zigtls`. The hash-pinned `tls.zig` Zig package is fetched by the package manager on a cold cache. Full attribution: `NOTICE`.

## Requirements

- **Zig 0.16.0** — pinned exactly.
- A **C toolchain**, for the vendored engines under `deps/`.
- **OpenSSL development headers** (e.g. `libssl-dev`) — required by every product **except** `noq-zigtls`, which links no libcrypto.
- **Linux** is the tested platform.

## Build

```sh
zig build test      # library + unit tests
zig build           # default product
zig build relay     # relay server binary
```

Select the QUIC engine + TLS backend at compile time:

```sh
zig build -Dproduct=picoquic-picotls    # C QUIC engine + C TLS
zig build -Dproduct=noq-zigtls          # Zig QUIC engine + Zig TLS, no libcrypto
```

## Feature completeness

zig_iroh implements **225 of 381** required rows of iroh's user-facing feature surface (**59%**) — a working subset that names the gaps it does not yet cover. Full per-subsystem detail is in [`docs/COMPLETION_MATRIX.md`](./docs/COMPLETION_MATRIX.md).

## License

Dual-licensed under [MIT](./LICENSE-MIT) and [Apache 2.0](./LICENSE-APACHE), matching iroh. Vendored C
dependencies retain their own licenses — see [`NOTICE`](./NOTICE).
