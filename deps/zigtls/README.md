# ⚡ zigtls

`zigtls` is a Zig-first TLS termination library for load balancers and edge proxies.
It is built to be imported by other Zig projects.

## What this library provides

- TLS termination primitives for event-loop integrations (`zigtls.termination`)
- Non-blocking adapter for transport I/O loops (`zigtls.adapter`)
- Cert reload, ticket key management, metrics, and handshake policy hooks

## Using it

This package is vendored as a dependency of the parent project and exposes a single
`zigtls` module:

```zig
const zigtls = @import("zigtls");
```

It is built as part of the parent package (`zig build`). The upstream development build
— tools, examples, and the interop / timing / reliability test harnesses — is not part
of this source mirror, which vendors zigtls as a library rather than a standalone project.

## License

MIT — see [`LICENSE`](./LICENSE).
