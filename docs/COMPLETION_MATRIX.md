# Completion matrix

Per-subsystem status of the iroh feature surface that zig_iroh ports, from the committed feature ledgers. Counts are required rows; the QUIC/TLS transport engine is tracked separately.

| subsystem | rows | implemented | partial | absent | % |
|---|---:|---:|---:|---:|---:|
| iroh-base | 23 | 23 | 0 | 0 | 100% |
| iroh-core | 38 | 35 | 2 | 1 | 92% |
| iroh-relay | 15 | 15 | 0 | 0 | 100% |
| iroh-dns-server | 40 | 38 | 2 | 0 | 95% |
| iroh-dns-discovery | 49 | 49 | 0 | 0 | 100% |
| iroh-gossip | 75 | 75 | 0 | 0 | 100% |
| iroh-docs | 56 | 0 | 6 | 50 | 0% |
| iroh-blobs | 75 | 20 | 27 | 28 | 27% |
| iroh-ffi | 3 | 1 | 2 | 0 | 33% |
| release-surface | 7 | 3 | 2 | 2 | 43% |
| **total** | **381** | **259** | **41** | **81** | **68%** |
