# zig_iroh

A [Zig](https://ziglang.org) port of [iroh](https://github.com/n0-computer/iroh).

**Alpha** (`0.2.0-alpha.2`).

## Requirements

- **Zig 0.16.0** — pinned exactly.
- A C toolchain, for the vendored engines under `deps/`.
- Linux is the tested platform.

## Build

```sh
zig build test      # library + unit tests
zig build           # default product
zig build relay     # relay server binary
```

## Products

The QUIC engine and TLS backend are selected at compile time:

```sh
zig build -Dproduct=picoquic-picotls    # C QUIC engine + C TLS
zig build -Dproduct=noq-zigtls          # Zig QUIC engine + Zig TLS, no libcrypto
```

Each product is a distinct monomorphized build. Passing engine or TLS flags at runtime to a product
build is rejected — the product pins both at compile time.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
See [NOTICE](NOTICE) for vendored-component attribution.
