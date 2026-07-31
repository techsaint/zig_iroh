# Versions & build

- **Ports iroh:** `255a939b1a` (`v1.0.0-2-g255a939b1a`)
- **Zig:** `0.16.0`
- **Products:** `picoquic-picotls` (C QUIC + C TLS), `noq-picotls` (Zig QUIC + C TLS), `noq-zigtls` (Zig QUIC + Zig TLS, no libcrypto)

## Compile-time selection

The QUIC engine and TLS backend are selected **at compile time**. Each product is a **distinct
monomorphized build** — passing engine or TLS flags at runtime to a product build is **rejected**; the
product pins both at compile time.
