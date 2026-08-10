# Performance

## Throughput

`ReleaseFast` `stack-self` goodput from the committed ledger; rendering reads committed records only and never starts a live benchmark.

| stack | goodput (Mbps) | vs iroh | host | measured (date) |
|---|---:|---:|:--:|---|
| `picoquic-picotls` | 275.48 | 1.580x | A | 2026-07-15 |
| `noq-picotls` | 2244.33 | 2.018x | B | 2026-08-07 |
| `noq-zigtls` | 2232.81 | 2.008x | B | 2026-08-07 |

**Absolute goodput is comparable only within the same `host` column.** The host letters denote distinct machines; rows with different letters were measured on different hardware, so their raw Mbps must not be compared directly. Use the `vs iroh` ratio — it normalizes each row to a Rust iroh reference measured on that same host.

## Ratio to Rust iroh

Each ratio divides the product goodput by the Rust `rust-iroh` reference row with the same `version_id`, `env_id`, and 64 MiB payload — a same-host, same-config denominator. The ratio is the only figure comparable across products; the raw goodput columns are not.

Not all rows were measured on the same machine (see the `host` column in the throughput table). Absolute goodput is therefore NOT comparable across products — only the same-host ratio is. A product running on slower hardware shows lower raw Mbps even at an equal or better ratio, so read the ratios, not the megabits.

The latest canonical stack-self row is also older for `picoquic-picotls` (2026-07-15); it is still shown because the newer rows for that stack are non-self scenarios. It is reprinted from the committed ledger as-is — not re-measured for this release.

Only throughput is shown here. The committed measurement ledger currently has no binary-size, RSS, memory, or latency metrics for these stack headline rows, so those dimensions are intentionally omitted.

Updating the numbers is a separate, provenance-stamped measurement act that writes the ledger; this doc only reprints committed records.
