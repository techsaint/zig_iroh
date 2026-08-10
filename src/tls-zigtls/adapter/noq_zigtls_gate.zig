//! Ownership note (fork-isolation S6).
//!
//! The live `noq_zigtls_gate` composition tests need the noq endpoint probes
//! (`transport_noq`) plus the transport door factory, so they cannot live inside
//! the pure `tls_backend → shared` module without introducing a tls→engine
//! cycle. The tests live at `engine-noq/harness/noq_zigtls_gate.zig` and are
//! collected by the engine test binary when zigtls is enabled. This file remains
//! as the plan-named path so greps for the S6 move set stay honest.
