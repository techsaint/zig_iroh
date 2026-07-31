# Completion matrix

Per-subsystem status of the iroh feature surface that zig_iroh ports, from the committed feature ledgers. Counts are required rows; the QUIC/TLS transport engine is tracked separately.

| subsystem | rows | implemented | partial | absent | % |
|---|---:|---:|---:|---:|---:|
| iroh-base | 23 | 20 | 3 | 0 | 87% |
| iroh-core | 38 | 31 | 4 | 3 | 82% |
| iroh-relay | 15 | 11 | 2 | 2 | 73% |
| iroh-dns-server | 40 | 35 | 5 | 0 | 88% |
| iroh-dns-discovery | 49 | 44 | 5 | 0 | 90% |
| iroh-gossip | 75 | 75 | 0 | 0 | 100% |
| iroh-docs | 56 | 0 | 6 | 50 | 0% |
| iroh-blobs | 75 | 6 | 26 | 43 | 8% |
| iroh-ffi | 3 | 0 | 0 | 3 | 0% |
| release-surface | 7 | 3 | 2 | 2 | 43% |
| **total** | **381** | **225** | **53** | **103** | **59%** |
