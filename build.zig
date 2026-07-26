const std = @import("std");
const manifest = @import("build.zig.zon");
const products = @import("src/products.zig");

/// True when a DEV-ONLY source is present in this tree.
///
/// The public source mirror (dist/) ships src/ + deps/ + licenses and deliberately EXCLUDES
/// the dev harnesses (bench/, fuzz/, tools/, testutil/). Zig resolves `b.path(...)` at
/// configure/build time, so any target unconditionally declared against a missing source
/// breaks the whole build for consumers. Gate such targets on this instead of maintaining a
/// second build.zig — one file, correct in both trees.
///
/// NOTE (Zig 0.16): `Dir` moved under `std.Io` and `access` takes an `io` param; there is no
/// `std.fs.cwd()` in a build script.
fn devSourcePresent(b: *std.Build, rel: []const u8) bool {
    b.build_root.handle.access(b.graph.io, rel, .{}) catch return false;
    return true;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    // ── Product selection (component-repo restructure Phase 1) ──────────────
    // `-Dproduct=<id>` chooses which engines/features compile in. The resolved
    // profile drives BOTH the native link/C-source selection below AND the
    // `build_options` comptime flags Zig uses to elide disabled subsystems.
    const product_name = b.option([]const u8, "product", b.fmt("Product profile: {s}", .{products.id_list})) orelse "default";
    const product_id = products.parseId(product_name) orelse {
        std.debug.panic("unknown -Dproduct='{s}'; valid: {s}", .{ product_name, products.id_list });
    };
    const product = products.get(product_id);
    // The release package carries picoquic + picotls under deps/. Monorepo
    // development can continue to select the sibling tree explicitly.
    const deps_path = b.option([]const u8, "deps_path", "Path to dependency tree; default deps, use ../dependancies for monorepo development") orelse "deps";
    const deps: std.Build.LazyPath = if (std.fs.path.isAbsolute(deps_path))
        .{ .cwd_relative = deps_path }
    else
        b.path(deps_path);
    const zigtls_opt = b.option(bool, "zigtls", "Enable the experimental pure-Zig TLS backend (all-in-one build); products may pin it") orelse false;
    // `product.zigtls == null` means "inherit -Dzigtls"; a concrete bool pins it
    // (noq-zigtls forces on, noq-picotls/picoquic-picotls force off).
    const zigtls_enabled = product.zigtls orelse zigtls_opt;
    const zigtls_path = b.option(
        []const u8,
        "zigtls_path",
        "Path to the experimental zigtls source tree",
    ) orelse "../dependancies/zigtls";
    const zigtls_root: std.Build.LazyPath = if (std.fs.path.isAbsolute(zigtls_path))
        .{ .cwd_relative = zigtls_path }
    else
        b.path(zigtls_path);

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "product", product_name);
    build_options.addOption(bool, "picoquic", product.picoquic);
    build_options.addOption(bool, "noq", product.noq);
    build_options.addOption(bool, "picotls", product.picotls);
    build_options.addOption(bool, "zigtls", zigtls_enabled);
    build_options.addOption(bool, "gossip", product.gossip);

    // Native C engines are constructed ONLY when the product needs them
    // (component-repo restructure). picotls is required whenever picoquic is
    // (picoquic bundles it) OR when picotls is the selected TLS backend; a
    // noq-zigtls product constructs neither, so nothing pulls libpicotls/
    // libpicoquic/libcrypto.
    const need_picotls = product.picotls or product.picoquic;
    const picotls: ?*std.Build.Step.Compile = if (need_picotls)
        addPicotls(b, target, optimize, deps)
    else
        null;
    const picoquic: ?*std.Build.Step.Compile = if (product.picoquic)
        addPicoquic(b, target, optimize, deps, picotls.?)
    else
        null;
    const safety_picotls: ?*std.Build.Step.Compile = if (need_picotls)
        addPicotlsWithOptions(b, target, .ReleaseSafe, deps, .{
            .name = "picotls-iroh-safety",
            .c_flags = &c_flags,
            .sanitize_c = .full,
        })
    else
        null;
    const safety_picoquic: ?*std.Build.Step.Compile = if (product.picoquic)
        addPicoquicWithOptions(b, target, .ReleaseSafe, deps, safety_picotls.?, .{
            .name = "picoquic-iroh-safety",
            .c_flags = &c_flags,
            .sanitize_c = .full,
        })
    else
        null;

    // tls.zig dependency
    const tls_dep = b.dependency("tls", .{
        .target = target,
        .optimize = optimize,
    });
    const safety_tls_dep = b.dependency("tls", .{
        .target = target,
        .optimize = .ReleaseSafe,
    });
    const zigtls_mod: ?*std.Build.Module = if (zigtls_enabled)
        b.createModule(.{
            .root_source_file = zigtls_root.path(b, "src/root.zig"),
            .target = target,
            .optimize = optimize,
        })
    else
        null;
    const safety_zigtls_mod: ?*std.Build.Module = if (zigtls_enabled)
        b.createModule(.{
            .root_source_file = zigtls_root.path(b, "src/root.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
        })
    else
        null;
    const zigtls_disabled_step = b.addFail("zigtls is disabled; monorepo development can enable it with -Dzigtls=true");

    // H2: explicit ASan runtime location override (default: gcc probe → linker default
    // paths; see linkAsanRuntime). Declared once — b.option panics on redeclaration.
    const asan_lib_path = b.option(
        []const u8,
        "asan_lib_path",
        "Directory containing libasan.a (default: probe `gcc -print-file-name=libasan.a`, then linker default paths)",
    );

    // The public `zig_iroh` library module.
    const root_mod = b.addModule("zig_iroh", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    root_mod.addImport("tls", tls_dep.module("tls"));
    configureZigtlsFeature(root_mod, build_options, zigtls_mod);
    configureProductNativeDeps(b, root_mod, deps, product, picoquic, picotls, &c_flags);

    // Compile/link the released library test graph without running tests. This
    // is the clean-extract package-consumer proof used by package-check.
    const unit_tests = b.addTest(.{ .root_module = root_mod });
    const package_compile_step = b.step(
        "package-compile",
        "Compile and link the released package graph without running tests",
    );
    package_compile_step.dependOn(&unit_tests.step);

    // `zig build test` — run the library unit tests.
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // `zig build -Dproduct=<id> check-product-linkmap` — steering guardrail
    // (component-repo restructure). For a NO-native-C product (no picoquic AND
    // no picotls, e.g. noq-zigtls) the unit-test binary MUST NOT link libcrypto;
    // this fails the build if it does. For products that legitimately link
    // libcrypto it is a no-op (N/A). Complements the manual `ldd` proof.
    const linkmap_step = b.step(
        "check-product-linkmap",
        "Assert a no-native-C product (e.g. noq-zigtls) links no libcrypto",
    );
    if (need_picotls) {
        const linkmap_na = b.addSystemCommand(&.{ "sh", "-c", "echo \"check-product-linkmap: N/A for product '$0' (links libcrypto by design)\"", product_name });
        linkmap_step.dependOn(&linkmap_na.step);
    } else {
        const linkmap_check = b.addSystemCommand(&.{
            "sh",         "-c",
            \\if ldd "$1" | grep -qi crypto; then
            \\  echo "check-product-linkmap FAIL: product '$0' links libcrypto but must not" >&2
            \\  ldd "$1" | grep -i crypto >&2
            \\  exit 1
            \\fi
            \\echo "check-product-linkmap OK: product '$0' links no libcrypto"
            ,
            product_name,
        });
        linkmap_check.addArtifactArg(unit_tests);
        linkmap_step.dependOn(&linkmap_check.step);
    }

    const native_leaks_step = b.step(
        "check-product-native-leaks",
        "Assert product binaries do not leak disabled native engine/TLS symbols",
    );

    // Focused transport stability gates for the S2/S4 real-QUIC paths.
    const s2_transport_tests = b.addTest(.{
        .root_module = root_mod,
        .filters = &.{"S2: Transport connect/accept and bi stream use real picoquic over UDP"},
    });
    const run_s2_transport_tests = b.addRunArtifact(s2_transport_tests);
    const s2_transport_step = b.step("test-transport-s2", "Run focused S2 real-QUIC transport test");
    s2_transport_step.dependOn(&run_s2_transport_tests.step);

    const s4_transport_tests = b.addTest(.{
        .root_module = root_mod,
        .filters = &.{"S4: relay fallback transfers a bi stream when direct paths are unavailable"},
    });
    const run_s4_transport_tests = b.addRunArtifact(s4_transport_tests);
    const s4_transport_step = b.step("test-transport-s4", "Run focused S4 relay fallback transport test");
    s4_transport_step.dependOn(&run_s4_transport_tests.step);

    const transport_stability_tests = b.addTest(.{
        .root_module = root_mod,
        .filters = &.{
            "S2: Transport connect/accept and bi stream use real picoquic over UDP",
            "S4: relay fallback transfers a bi stream when direct paths are unavailable",
        },
    });
    const run_transport_stability_tests = b.addRunArtifact(transport_stability_tests);
    const transport_stability_step = b.step("test-transport-stability", "Run focused S2/S4 transport stability tests");
    transport_stability_step.dependOn(&run_transport_stability_tests.step);

    // VC carryover regressions (recvReader / path isolation / lockPump).
    const vc_carryover_tests = b.addTest(.{
        .root_module = root_mod,
        .filters = &.{
            "VC-1 C1: recvReader survives peer stream reset without process abort",
            "VC-3 H1: two dials keep isolated magicsock path state",
            "VC-3 H2: lockPump acquires under contention with bounded backoff",
        },
    });
    const run_vc_carryover_tests = b.addRunArtifact(vc_carryover_tests);
    const vc_carryover_step = b.step("test-vc-carryover", "Run port-hardening-v3-carryover regression tests");
    vc_carryover_step.dependOn(&run_vc_carryover_tests.step);

    // Transport characterization suite (G2 picoquic-backend completion driver):
    // pins the legacy backend's current-correct vtable behavior as the live
    // differential oracle the greenfield endpoint must match.
    const char_legacy_tests = b.addTest(.{
        .root_module = root_mod,
        .filters = &.{"CHAR legacy"},
    });
    const run_char_legacy_tests = b.addRunArtifact(char_legacy_tests);
    const char_legacy_step = b.step("test-transport-char-legacy", "Run the transport characterization suite against the legacy backend (oracle)");
    char_legacy_step.dependOn(&run_char_legacy_tests.step);

    const char_greenfield_tests = b.addTest(.{
        .root_module = root_mod,
        .filters = &.{"CHAR greenfield"},
    });
    const run_char_greenfield_tests = b.addRunArtifact(char_greenfield_tests);
    const char_greenfield_step = b.step("test-transport-char-greenfield", "Run the transport characterization suite against the greenfield backend");
    char_greenfield_step.dependOn(&run_char_greenfield_tests.step);

    const char_step = b.step("test-transport-char", "Run the full transport characterization suite (both backends)");
    char_step.dependOn(&run_char_legacy_tests.step);
    char_step.dependOn(&run_char_greenfield_tests.step);
    const one_tests = b.addTest(.{
        .root_module = root_mod,
        .filters = &.{"CHAR greenfield: bi echo"},
    });
    const run_one_tests = b.addRunArtifact(one_tests);
    const one_step = b.step("test-one", "one");
    one_step.dependOn(&run_one_tests.step);

    // C4 preflight (audit-v4 testinfra): prove the reference trees are pinned, the
    // Cargo wiring + C patches are applied, and the peer mirrors are current BEFORE
    // any cargo-spawning gate runs — fail fast with the exact materialization remedy
    // (interop/rust-peer/README.md#fresh-materialization-recipe), not an opaque cargo error.
    // --root=.. : trees root = the zig package's parent (monorepo root in a plain
    // checkout; in a jj lane it is the lane parent whose original//dependancies are
    // symlinks to the shared trees). Tracked inputs resolve from the script's own root.
    const reference_preflight = b.addSystemCommand(&.{"python3"});
    reference_preflight.addFileArg(b.path("../scripts/check_reference_sha.py"));
    reference_preflight.addArg("--root=..");
    const reference_preflight_step = b.step(
        "reference-preflight",
        "Verify reference trees are pinned, patched, and mirrored (interop C4 preflight)",
    );
    reference_preflight_step.dependOn(&reference_preflight.step);

    // C4 probe (gate-integrity): the preflight itself must go RED on wrong-SHA /
    // missing-cargo-wiring / missing-mirror / missing-C-patch mutations. The script's
    // hermetic --self-test synthesizes each broken state in a temp dir; a preflight
    // that cannot go red is theater.
    const reference_preflight_selftest = b.addSystemCommand(&.{"python3"});
    reference_preflight_selftest.addFileArg(b.path("../scripts/check_reference_sha.py"));
    reference_preflight_selftest.addArg("--root=..");
    reference_preflight_selftest.addArg("--self-test");

    // Shared interop peer lifecycle helper (audit-v4 H3): deadline-on-read watchdog,
    // group kill + reap, bounded stderr capture, cargo/manifest probes. Imported by
    // every cargo-spawning gate (a ReleaseSafe variant serves the sanitized gates).
    const interop_lifecycle_mod = b.createModule(.{
        .root_source_file = b.path("testutil/interop_lifecycle.zig"),
        .target = target,
        .optimize = optimize,
    });
    const safety_interop_lifecycle_mod = b.createModule(.{
        .root_source_file = b.path("testutil/interop_lifecycle.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });

    // `zig build bench` — emit smoke BENCH lines from Zig and the Rust peer.
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_mod.addImport("zig_iroh", root_mod);
    bench_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    const bench_exe = b.addExecutable(.{ .name = "bench", .root_module = bench_mod });
    const run_bench = b.addRunArtifact(bench_exe);
    const rust_peer_sync_check = b.addSystemCommand(&.{"python3"});
    rust_peer_sync_check.addFileArg(b.path("../scripts/sync_rust_peer_examples.py"));
    rust_peer_sync_check.addArg("--check");
    // Trees root = the zig package's parent (monorepo root; lane parent in jj lanes —
    // same split as the C4 preflight). Sources resolve from the script's own root.
    rust_peer_sync_check.addArg("--root");
    rust_peer_sync_check.addArg("..");
    const rust_peer_sync_step = b.step("rust-peer-sync-check", "Check Rust peer examples mirror the source examples");
    rust_peer_sync_step.dependOn(&rust_peer_sync_check.step);
    run_bench.step.dependOn(&rust_peer_sync_check.step);
    const bench_step = b.step("bench", "Run benchmark smoke telemetry (monorepo-only: needs ../original + ../scripts)");
    bench_step.dependOn(&reference_preflight.step);
    bench_step.dependOn(&run_bench.step);

    // `zig build cross-host-bench` — install the B8 anchor/requester runner.
    const cross_host_mod = b.createModule(.{
        .root_source_file = b.path("bench/cross_host.zig"),
        .target = target,
        .optimize = optimize,
    });
    cross_host_mod.addImport("zig_iroh", root_mod);
    const cross_host_exe = b.addExecutable(.{ .name = "cross-host-bench", .root_module = cross_host_mod });
    const install_cross_host = b.addInstallArtifact(cross_host_exe, .{});
    const cross_host_test_mod = b.createModule(.{
        .root_source_file = b.path("bench/cross_host.zig"),
        .target = target,
        .optimize = optimize,
    });
    cross_host_test_mod.addImport("zig_iroh", root_mod);
    const cross_host_tests = b.addTest(.{ .root_module = cross_host_test_mod });
    const run_cross_host_tests = b.addRunArtifact(cross_host_tests);
    const cross_host_step = b.step("cross-host-bench", "Build the B8 cross-host anchor/requester runner");
    cross_host_step.dependOn(&install_cross_host.step);
    cross_host_step.dependOn(&run_cross_host_tests.step);

    // `zig build transfer-node` — the netsim/chuck transfer-example adapter node
    // (ALPN n0/iroh/transfer/example/1 + postcard Request + NDJSON; harness
    // adapter, not a product feature).
    const transfer_node_mod = b.createModule(.{
        .root_source_file = b.path("bench/transfer_node.zig"),
        .target = target,
        .optimize = optimize,
    });
    transfer_node_mod.addImport("zig_iroh", root_mod);
    const transfer_node_exe = b.addExecutable(.{ .name = "transfer-node", .root_module = transfer_node_mod });
    const install_transfer_node = b.addInstallArtifact(transfer_node_exe, .{});
    const transfer_node_test_mod = b.createModule(.{
        .root_source_file = b.path("bench/transfer_node.zig"),
        .target = target,
        .optimize = optimize,
    });
    transfer_node_test_mod.addImport("zig_iroh", root_mod);
    const transfer_node_tests = b.addTest(.{ .root_module = transfer_node_test_mod });
    const run_transfer_node_tests = b.addRunArtifact(transfer_node_tests);
    const transfer_node_step = b.step("transfer-node", "Build the netsim transfer-example adapter node");
    transfer_node_step.dependOn(&install_transfer_node.step);
    transfer_node_step.dependOn(&run_transfer_node_tests.step);

    // `zig build bench-analyze -- --a <file> --b <file>` — diff BENCH lines.
    const bench_analyze_mod = b.createModule(.{
        .root_source_file = b.path("bench/analyze.zig"),
        .target = target,
        .optimize = optimize,
    });
    const bench_analyze_exe = b.addExecutable(.{ .name = "bench-analyze", .root_module = bench_analyze_mod });
    const run_bench_analyze = b.addRunArtifact(bench_analyze_exe);
    if (b.args) |args| run_bench_analyze.addArgs(args);
    const bench_analyze_step = b.step("bench-analyze", "Diff two BENCH line files");
    bench_analyze_step.dependOn(&run_bench_analyze.step);
    const bench_analyze_proof = b.addSystemCommand(&.{"python3"});
    bench_analyze_proof.addFileArg(b.path("bench/analyze_proof.py"));
    bench_analyze_proof.addArtifactArg(bench_analyze_exe);
    const bench_analyze_proof_step = b.step("bench-analyze-proof", "Prove BENCH analyzer multi-row and missing-row behavior");
    bench_analyze_proof_step.dependOn(&bench_analyze_proof.step);

    // `zig build differential` — replay committed decision vectors.
    const differential_mod = b.createModule(.{
        .root_source_file = b.path("bench/differential.zig"),
        .target = target,
        .optimize = optimize,
    });
    differential_mod.addImport("zig_iroh", root_mod);
    const differential_exe = b.addExecutable(.{ .name = "differential", .root_module = differential_mod });
    const run_differential = b.addRunArtifact(differential_exe);
    if (b.args) |args| {
        run_differential.addArgs(args);
    } else {
        run_differential.addArg("vectors/differential");
    }
    const differential_step = b.step("differential", "Replay differential decision vectors");
    differential_step.dependOn(&run_differential.step);

    // `zig build noq-wire-diff` — generate Rust noq fixtures, check Zig decode/re-encode,
    // then re-validate the Zig-emitted bytes through noq's public parsers/recognizers.
    const noq_fixture_gen_target_dir = ".zig-cache/noq-fixture-gen-target";
    const noq_fixture_gen = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        "tools/noq_fixture_gen/Cargo.toml",
        "--",
        "generate",
    });
    noq_fixture_gen.setEnvironmentVariable("CARGO_TARGET_DIR", noq_fixture_gen_target_dir);
    const noq_rust_fixtures = noq_fixture_gen.captureStdOut(.{
        .basename = "noq-rust-fixtures.json",
        .trim_whitespace = .none,
    });

    const noq_wire_diff_mod = b.createModule(.{
        .root_source_file = b.path("tools/noq_wire_diff.zig"),
        .target = target,
        .optimize = optimize,
    });
    noq_wire_diff_mod.addImport("zig_iroh", root_mod);
    const noq_wire_diff_exe = b.addExecutable(.{ .name = "noq-wire-diff", .root_module = noq_wire_diff_mod });
    const run_noq_wire_diff = b.addRunArtifact(noq_wire_diff_exe);
    run_noq_wire_diff.addFileArg(noq_rust_fixtures);
    const noq_zig_fixtures = run_noq_wire_diff.addOutputFileArg("noq-zig-fixtures.json");

    const noq_verify_zig_fixtures = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        "tools/noq_fixture_gen/Cargo.toml",
        "--",
        "verify",
    });
    noq_verify_zig_fixtures.setEnvironmentVariable("CARGO_TARGET_DIR", noq_fixture_gen_target_dir);
    noq_verify_zig_fixtures.addFileArg(noq_zig_fixtures);

    const noq_wire_diff_step = b.step("noq-wire-diff", "Run noq Rust<->Zig codec byte-diff oracle");
    noq_wire_diff_step.dependOn(&noq_verify_zig_fixtures.step);

    // `zig build addr-ticket-diff` — ID1b: Rust iroh-base/iroh-tickets fixtures ↔ Zig library model.
    const addr_fixture_gen_target_dir = ".zig-cache/addr-ticket-fixture-gen-target";
    const addr_fixture_gen = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        "tools/addr_ticket_fixture_gen/Cargo.toml",
        "--",
        "generate",
    });
    addr_fixture_gen.setEnvironmentVariable("CARGO_TARGET_DIR", addr_fixture_gen_target_dir);
    const addr_rust_fixtures = addr_fixture_gen.captureStdOut(.{
        .basename = "addr-ticket-rust-fixtures.json",
        .trim_whitespace = .none,
    });

    const addr_ticket_diff_mod = b.createModule(.{
        .root_source_file = b.path("tools/addr_ticket_diff.zig"),
        .target = target,
        .optimize = optimize,
    });
    addr_ticket_diff_mod.addImport("zig_iroh", root_mod);
    const addr_ticket_diff_exe = b.addExecutable(.{ .name = "addr-ticket-diff", .root_module = addr_ticket_diff_mod });
    const run_addr_ticket_diff = b.addRunArtifact(addr_ticket_diff_exe);
    run_addr_ticket_diff.addFileArg(addr_rust_fixtures);

    const addr_ticket_diff_step = b.step("addr-ticket-diff", "Run EndpointAddr postcard + EndpointTicket vector gate (ID1b)");
    addr_ticket_diff_step.dependOn(&run_addr_ticket_diff.step);

    // `zig build blobs-observe-push-diff` — real Rust writer/provider fixtures vs Zig production encoders.
    const blobs_observe_push_fixture_gen_target_dir = ".zig-cache/blobs-observe-push-fixture-target";
    const blobs_observe_push_fixture_gen = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--quiet",
        "--locked",
        "--manifest-path",
    });
    blobs_observe_push_fixture_gen.addFileArg(b.path("tools/blobs_observe_push_fixture_gen/Cargo.toml"));
    // The source is not part of the manifest path the build system tracks, so pass it as a
    // no-op program argument after `--` to ensure the step reruns when main.rs changes.
    blobs_observe_push_fixture_gen.addArg("--");
    blobs_observe_push_fixture_gen.addFileArg(b.path("tools/blobs_observe_push_fixture_gen/src/main.rs"));
    blobs_observe_push_fixture_gen.setEnvironmentVariable("CARGO_TARGET_DIR", blobs_observe_push_fixture_gen_target_dir);
    const blobs_observe_push_rust_fixture = blobs_observe_push_fixture_gen.captureStdOut(.{
        .basename = "blobs-observe-push-rust-fixture.json",
        .trim_whitespace = .none,
    });

    const blobs_observe_push_diff_mod = b.createModule(.{
        .root_source_file = b.path("tools/blobs_observe_push_diff.zig"),
        .target = target,
        .optimize = optimize,
    });
    blobs_observe_push_diff_mod.addImport("zig_iroh", root_mod);
    const blobs_observe_push_diff_exe = b.addExecutable(.{
        .name = "blobs-observe-push-diff",
        .root_module = blobs_observe_push_diff_mod,
    });
    const run_blobs_observe_push_diff = b.addRunArtifact(blobs_observe_push_diff_exe);
    run_blobs_observe_push_diff.addFileArg(blobs_observe_push_rust_fixture);

    const blobs_observe_push_diff_step = b.step("blobs-observe-push-diff", "Diff Rust blobs Observe/Push writer bytes against Zig production encoders");
    blobs_observe_push_diff_step.dependOn(&run_blobs_observe_push_diff.step);

    // `zig build test-releasesafe` — run the unit suite under ReleaseSafe.
    // H4 truthful naming (audit-v4 testinfra): this graph builds the C engine
    // UN-sanitized, so C-side UAF is invisible here (Zig-side safety + the Zig test
    // allocator's leak checks only). The sanitized-C UNIT gate is `test-safe-c`
    // (below); the sanitized INTEROP gate is `safety-sanitizers`.
    const safe_root_mod = b.addModule("zig_iroh_safe", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
    });
    safe_root_mod.addImport("tls", tls_dep.module("tls"));
    configureZigtlsFeature(safe_root_mod, build_options, safety_zigtls_mod);
    configureProductNativeDeps(b, safe_root_mod, deps, product, picoquic, picotls, &c_flags);
    const safe_unit_tests = b.addTest(.{ .root_module = safe_root_mod });
    safe_unit_tests.bundle_ubsan_rt = true;
    const run_safe_unit_tests = b.addRunArtifact(safe_unit_tests);
    const test_releasesafe_step = b.step(
        "test-releasesafe",
        "Run unit tests under ReleaseSafe (Zig-side safety only; C engine unsanitized — see test-safe-c / safety-sanitizers)",
    );
    test_releasesafe_step.dependOn(&run_safe_unit_tests.step);
    // Compat ALIAS (do NOT hard-rename — the standing promote command and historical
    // invocations name `test-safe`; the v1 kickoff's hard-rename was a pre-fire FAIL).
    const test_safe_step = b.step("test-safe", "Compatibility alias for test-releasesafe");
    test_safe_step.dependOn(&run_safe_unit_tests.step);

    const safety_root_mod = b.addModule("zig_iroh_safety", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
        .sanitize_c = .full,
    });
    safety_root_mod.addImport("tls", safety_tls_dep.module("tls"));
    configureZigtlsFeature(safety_root_mod, build_options, safety_zigtls_mod);
    configureProductNativeDeps(b, safety_root_mod, deps, product, safety_picoquic, safety_picotls, &c_sanitizer_flags);
    linkAsanRuntime(b, safety_root_mod, asan_lib_path);

    // V3-0: `test-safe-c` — unit suite under ReleaseSafe + sanitized C (ASan).
    // `test-releasesafe` still links the UN-sanitized `picoquic` (above); C-side UAF is
    // invisible there. V3-A/V3-C UAF gates use this target. The mutation control: rewiring
    // THIS graph to the ordinary (unsanitized) picoquic must turn `uaf-inject-probe` RED —
    // the probe imports this same safety_root_mod, so the rewire removes its SIGABRT.
    const safety_unit_tests = b.addTest(.{ .root_module = safety_root_mod });
    safety_unit_tests.bundle_ubsan_rt = true;
    const run_safety_unit_tests = b.addRunArtifact(safety_unit_tests);
    configureAsanRun(run_safety_unit_tests);
    const test_safe_c_step = b.step("test-safe-c", "Run unit tests under ReleaseSafe + sanitized C (ASan)");
    test_safe_c_step.dependOn(&run_safety_unit_tests.step);

    const safety_bench_telemetry_mod = b.createModule(.{
        .root_source_file = b.path("bench/telemetry.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });

    // `zig build relay` — relay server binary.
    const relay_mod = b.createModule(.{
        .root_source_file = b.path("relay_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    relay_mod.addImport("zig_iroh", root_mod);
    relay_mod.addImport("tls", tls_dep.module("tls"));
    const relay_exe = b.addExecutable(.{ .name = "relay", .root_module = relay_mod });
    const install_relay = b.addInstallArtifact(relay_exe, .{});
    const relay_step = b.step("relay", "Build the relay server binary");
    relay_step.dependOn(&install_relay.step);

    // `zig build test-relay` — standalone relay round-trip test (ws:// + wss://).
    const rt_mod = b.createModule(.{
        .root_source_file = b.path("relay_roundtrip_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    rt_mod.addImport("tls", tls_dep.module("tls"));
    const rt_exe = b.addExecutable(.{ .name = "relay_roundtrip_test", .root_module = rt_mod });
    const run_rt = b.addRunArtifact(rt_exe);
    const rt_step = b.step("test-relay", "Run standalone relay round-trip test");
    rt_step.dependOn(&run_rt.step);

    // `zig build relay-interop` — Zig relay clients through a real Rust iroh-relay.
    const relay_interop_mod = b.createModule(.{
        .root_source_file = b.path("relay_interop_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    relay_interop_mod.addImport("zig_iroh", root_mod);
    relay_interop_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    const relay_interop_exe = b.addExecutable(.{ .name = "relay-interop", .root_module = relay_interop_mod });
    const run_relay_interop = b.addRunArtifact(relay_interop_exe);
    const relay_interop_step = b.step("relay-interop", "Run real iroh-relay interop gate");
    relay_interop_step.dependOn(&reference_preflight.step);
    relay_interop_step.dependOn(&run_relay_interop.step);

    // `zig build pkarr-resolver` — self-hostable discovery resolver.
    const resolver_mod = b.createModule(.{
        .root_source_file = b.path("src/discovery/resolver_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    resolver_mod.addImport("zig_iroh", root_mod);
    const resolver_exe = b.addExecutable(.{ .name = "pkarr-resolver", .root_module = resolver_mod });
    const install_resolver = b.addInstallArtifact(resolver_exe, .{});
    const resolver_step = b.step("pkarr-resolver", "Build pkarr resolver executable");
    resolver_step.dependOn(&install_resolver.step);

    // `zig build blobs-quic-interop` — blobs over real QUIC gate.
    const blobs_quic_mod = b.createModule(.{
        .root_source_file = b.path("src/blobs_quic_interop.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    blobs_quic_mod.addImport("tls", tls_dep.module("tls"));
    configureZigtlsFeature(blobs_quic_mod, build_options, zigtls_mod);
    configureProductNativeDeps(b, blobs_quic_mod, deps, product, picoquic, picotls, &c_flags);
    const blobs_quic_tests = b.addTest(.{ .root_module = blobs_quic_mod });
    const run_blobs_quic_tests = b.addRunArtifact(blobs_quic_tests);
    const blobs_quic_step = b.step("blobs-quic-interop", "Run blobs-over-real-QUIC integration gate");
    blobs_quic_step.dependOn(&run_blobs_quic_tests.step);

    // `zig build blobs-interop` — Zig getter pulls from a real Rust iroh-blobs provider.
    const blobs_interop_mod = b.createModule(.{
        .root_source_file = b.path("src/blobs_interop.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const bench_telemetry_mod = b.createModule(.{
        .root_source_file = b.path("bench/telemetry.zig"),
        .target = target,
        .optimize = optimize,
    });
    blobs_interop_mod.addImport("bench_telemetry", bench_telemetry_mod);
    blobs_interop_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    blobs_interop_mod.addImport("tls", tls_dep.module("tls"));
    configureZigtlsFeature(blobs_interop_mod, build_options, zigtls_mod);
    configureProductNativeDeps(b, blobs_interop_mod, deps, product, picoquic, picotls, &c_flags);
    // Exe form (W2 #4): a zig test binary's stdout is the runner's --listen protocol
    // channel — raw BENCH writes from a test deadlock the runner. Exe = real stdout.
    const blobs_interop_exe = b.addExecutable(.{ .name = "blobs-interop", .root_module = blobs_interop_mod });
    const run_blobs_interop = b.addRunArtifact(blobs_interop_exe);
    const blobs_interop_step = b.step("blobs-interop", "Run real iroh-blobs provider interop gate");
    blobs_interop_step.dependOn(&reference_preflight.step);
    blobs_interop_step.dependOn(&run_blobs_interop.step);

    // `zig build discovery-live-interop` — live iroh DoH interop gate.
    const live_interop_mod = b.createModule(.{
        .root_source_file = b.path("src/discovery/live_interop_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    live_interop_mod.addImport("zig_iroh", root_mod);
    const live_interop_exe = b.addExecutable(.{ .name = "discovery-live-interop", .root_module = live_interop_mod });
    const run_live_interop = b.addRunArtifact(live_interop_exe);
    const live_interop_step = b.step("discovery-live-interop", "Run live iroh DoH discovery interop gate");
    live_interop_step.dependOn(&run_live_interop.step);

    // `zig build iroh-oracle` — honest iroh integration-suite oracle floor.
    // N-row report card: control green (overlap/control) + converted rows with
    // honest pass|fail|blocked. False green / control regression / harness crash
    // fails the step; honest reds do not.
    // Native C sources live on root_mod only — do NOT re-apply
    // configureProductNativeDeps here (double-links rpk*.c → duplicate symbols).
    const iroh_oracle_mod = b.createModule(.{
        .root_source_file = b.path("src/oracle/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    iroh_oracle_mod.addImport("zig_iroh", root_mod);
    iroh_oracle_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    const iroh_oracle_exe = b.addExecutable(.{ .name = "iroh-oracle", .root_module = iroh_oracle_mod });
    const run_iroh_oracle = b.addRunArtifact(iroh_oracle_exe);
    // cwd = package root so relative original/ + src/ structural checks resolve.
    run_iroh_oracle.setCwd(b.path("."));
    const iroh_oracle_step = b.step("iroh-oracle", "Run iroh integration-suite oracle multi-row report-card gate");
    iroh_oracle_step.dependOn(&run_iroh_oracle.step);

    // Unit tests for the N-row oracleGateOk predicate (conversion-sweep acceptance).
    const iroh_oracle_test_mod = b.createModule(.{
        .root_source_file = b.path("src/oracle/runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    iroh_oracle_test_mod.addImport("zig_iroh", root_mod);
    iroh_oracle_test_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    const iroh_oracle_tests = b.addTest(.{ .root_module = iroh_oracle_test_mod });
    const run_iroh_oracle_tests = b.addRunArtifact(iroh_oracle_tests);
    const iroh_oracle_test_step = b.step("test-iroh-oracle", "Unit-test iroh-oracle N-row gate predicate");
    iroh_oracle_test_step.dependOn(&run_iroh_oracle_tests.step);


    // `zig build noq-oracle` — noq BEHAVIORAL oracle floor (D5 trajectory harness).
    // Control stream-echo green + honest fail/blocked for absent engine capabilities.
    // False green (GSO/0-RTT pass) or control non-pass fails the step.
    // Native C sources live on root_mod only (same pattern as iroh-oracle). Re-applying
    // configureProductNativeDeps here double-links rpk*.c → duplicate symbols.
    const noq_oracle_mod = b.createModule(.{
        .root_source_file = b.path("src/noq_oracle/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    noq_oracle_mod.addImport("zig_iroh", root_mod);
    const noq_oracle_exe = b.addExecutable(.{ .name = "noq-oracle", .root_module = noq_oracle_mod });
    const run_noq_oracle = b.addRunArtifact(noq_oracle_exe);
    run_noq_oracle.setCwd(b.path("."));
    const noq_oracle_step = b.step("noq-oracle", "Run noq BEHAVIORAL oracle scaffold/control gate");
    noq_oracle_step.dependOn(&run_noq_oracle.step);

    // `zig build interop` — live interop handshake + byte checks.
    const interop_mod = b.createModule(.{
        .root_source_file = b.path("src/interop_tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    interop_mod.addImport("tls", tls_dep.module("tls"));
    interop_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    configureZigtlsFeature(interop_mod, build_options, zigtls_mod);
    configureProductNativeDeps(b, interop_mod, deps, product, picoquic, picotls, &c_flags);
    const interop_tests = b.addTest(.{ .root_module = interop_mod });
    const run_interop_tests = b.addRunArtifact(interop_tests);
    const interop_step = b.step("interop", "Run cross-impl interop integration gate");
    interop_step.dependOn(&reference_preflight.step);
    interop_step.dependOn(&run_interop_tests.step);

    // `zig build interop-noq` — N3b-5d: greenfield noq client against the
    // same cargo-spawned real iroh server. Keep `interop` on picoquic.
    const noq_interop_mod = b.createModule(.{
        .root_source_file = b.path("src/noq_interop_tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    noq_interop_mod.addImport("tls", tls_dep.module("tls"));
    noq_interop_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    configureZigtlsFeature(noq_interop_mod, build_options, zigtls_mod);
    configureProductNativeDeps(b, noq_interop_mod, deps, product, picoquic, picotls, &c_flags);

    // The mirror check lives in the C4 reference-preflight now (all four peers,
    // lane-aware) — the old single-file `cmp` was both redundant and fragile outside
    // the monorepo-root layout (a jj lane has no ../interop sibling).
    const rust_peer_prebuild = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--locked",
        "--manifest-path",
        "../original/iroh/Cargo.toml",
        "--example",
        "interop_peer",
    });
    configureRustPeerRun(rust_peer_prebuild);
    rust_peer_prebuild.step.dependOn(&reference_preflight.step);

    // Prebuild the raw-noq hostile peer used by realpeer H1/M1/H3 legs.
    const hostile_peer_prebuild = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--locked",
        "--manifest-path",
        "../original/iroh/Cargo.toml",
        "--example",
        "noq_hostile_peer",
    });
    configureRustPeerRun(hostile_peer_prebuild);
    hostile_peer_prebuild.step.dependOn(&reference_preflight.step);

    // Keep picotls interop-noq as the regression anchor; zigtls probe is separate.
    // realpeer H1/M1/H3(+mutation-RED)/H5/H2 close the audit-v4 real-peer verification
    // legs against the raw-noq hostile peer (or frame-level for H5/H2).
    const noq_interop_tests = b.addTest(.{
        .root_module = noq_interop_mod,
        .filters = &.{
            "5d-A: Zig-noq client completes RPK handshake and echo with real Rust iroh server",
            "5d-B: server learns a verified peer, mints a fresh CID, and rejects a spoofed RPK",
            "5f-A: real Rust iroh client completes RPK handshake and echo with Zig-noq server",
            "realpeer H1: smoothed RTT not inflated after handshake with raw-noq peer",
            "realpeer M1: non-v1 long header inject during live conn does not kill it",
            "realpeer H3: raw-noq peer induces real RFC 9000 §10.3 reset → Zig drains",
            "realpeer H3 mutation-RED: disable peer-token match misses the real reset",
            "realpeer H5 decode: ACK with 32 ranges accepted (cap is 64)",
            "realpeer H2 forTest: data-space PTO includes max_ack_delay (peer-load ready)",
        },
    });
    const run_noq_interop_tests = b.addRunArtifact(noq_interop_tests);
    configureRustPeerRun(run_noq_interop_tests);
    run_noq_interop_tests.step.dependOn(&rust_peer_prebuild.step);
    run_noq_interop_tests.step.dependOn(&hostile_peer_prebuild.step);
    const noq_interop_step = b.step("interop-noq", "Run bidirectional Zig-noq interop against the real Rust iroh peer");
    noq_interop_step.dependOn(&reference_preflight.step);
    noq_interop_step.dependOn(&run_noq_interop_tests.step);

    // Informational: Zig-noq-zigtls client → real iroh. NOT a promotion gate
    // (wire-compat vs rustls is unproven; red is diagnostic, not a S3-core fail).
    const noq_interop_zigtls_tests = b.addTest(.{
        .root_module = noq_interop_mod,
        .filters = &.{"S3-probe: Zig-noq-zigtls client vs real Rust iroh server"},
    });
    const run_noq_interop_zigtls_tests = b.addRunArtifact(noq_interop_zigtls_tests);
    configureRustPeerRun(run_noq_interop_zigtls_tests);
    run_noq_interop_zigtls_tests.step.dependOn(&rust_peer_prebuild.step);
    const noq_interop_zigtls_step = b.step("interop-noq-zigtls", "INFORMATIONAL: Zig-noq-zigtls client vs real Rust iroh (not a promotion gate)");
    if (zigtls_enabled) {
        noq_interop_zigtls_step.dependOn(&run_noq_interop_zigtls_tests.step);
    } else {
        noq_interop_zigtls_step.dependOn(&zigtls_disabled_step.step);
    }

    const zigtls_resumption_interop_tests = b.addTest(.{
        .root_module = noq_interop_mod,
        .filters = &.{"B1-resumption: Zig-noq-zigtls resumes a second connection with real Rust iroh"},
    });
    const run_zigtls_resumption_interop_tests = b.addRunArtifact(zigtls_resumption_interop_tests);
    configureRustPeerRun(run_zigtls_resumption_interop_tests);
    run_zigtls_resumption_interop_tests.step.dependOn(&rust_peer_prebuild.step);
    const zigtls_resumption_interop_step = b.step(
        "test-zigtls-resumption-interop",
        "Run real rustls/iroh two-connection zigtls PSK resumption oracle",
    );
    if (zigtls_enabled) {
        zigtls_resumption_interop_step.dependOn(&run_zigtls_resumption_interop_tests.step);
    } else {
        zigtls_resumption_interop_step.dependOn(&zigtls_disabled_step.step);
    }

    const f2_certreq_oracle_tests = b.addTest(.{
        .root_module = noq_interop_mod,
        .filters = &.{
            "F2-positive: real Rust iroh client completes client auth with Zig-noq-zigtls server",
            "F2-negative: zigtls server rejects Rust client when CertificateRequest has no common signature schemes",
            "F2-negative: Zig-noq-zigtls client rejects CertificateRequest without offered Ed25519 through NOQ",
        },
    });
    const run_f2_certreq_oracle_tests = b.addRunArtifact(f2_certreq_oracle_tests);
    configureRustPeerRun(run_f2_certreq_oracle_tests);
    run_f2_certreq_oracle_tests.step.dependOn(&rust_peer_prebuild.step);
    const f2_certreq_oracle_step = b.step("test-f2-certreq-oracle", "Run zigtls F2 CertificateRequest Rust-client oracle");
    if (zigtls_enabled) {
        f2_certreq_oracle_step.dependOn(&run_f2_certreq_oracle_tests.step);
    } else {
        f2_certreq_oracle_step.dependOn(&zigtls_disabled_step.step);
    }

    const malformed_spki_oracle_tests = b.addTest(.{
        .root_module = noq_interop_mod,
        .filters = &.{
            "SPKI-negative: zigtls server rejects malformed client raw public key certificate",
        },
    });
    const run_malformed_spki_oracle_tests = b.addRunArtifact(malformed_spki_oracle_tests);
    configureRustPeerRun(run_malformed_spki_oracle_tests);
    const malformed_spki_oracle_step = b.step("test-zigtls-malformed-spki-oracle", "Run zigtls malformed-SPKI live reject oracle");
    if (zigtls_enabled) {
        malformed_spki_oracle_step.dependOn(&run_malformed_spki_oracle_tests.step);
    } else {
        malformed_spki_oracle_step.dependOn(&zigtls_disabled_step.step);
    }

    // `zig build test-zigtls-noq` — S3 core + SECURITY-PREP live spoof-reject:
    // Zig↔Zig zigtls over real UDP (positive smoke) + forged-RPK reject (negative).
    const zigtls_noq_tests = b.addTest(.{
        .root_module = root_mod,
        .filters = &.{
            "Zig-noq <-> Zig-noq zigtls real-socket",
            "S3-diag: zigtls Connection TestPair",
            "zigtls-sec: live connection rejects forged-RPK",
        },
    });
    const run_zigtls_noq_tests = b.addRunArtifact(zigtls_noq_tests);
    const zigtls_noq_step = b.step("test-zigtls-noq", "Run Zig-noq↔Zig-noq zigtls smoke + live forged-RPK reject (S3 + SECURITY-PREP)");
    if (zigtls_enabled) {
        zigtls_noq_step.dependOn(&run_zigtls_noq_tests.step);
    } else {
        zigtls_noq_step.dependOn(&zigtls_disabled_step.step);
    }

    // B1 feature-driver composite oracle. The standalone `interop-noq-zigtls`
    // remains diagnostic; this bundle is the run's real-grounded security
    // steering oracle and deliberately reuses, rather than edits, the frozen
    // `test-zigtls-noq` SECURITY-PREP surface.
    const zigtls_library_security_oracle_step = b.step(
        "test-zigtls-library-security-oracle",
        "Run B1 zigtls library security oracle bundle (real Rust peer + live NOQ negatives)",
    );
    if (zigtls_enabled) {
        zigtls_library_security_oracle_step.dependOn(&run_noq_interop_zigtls_tests.step);
        zigtls_library_security_oracle_step.dependOn(&run_zigtls_resumption_interop_tests.step);
        zigtls_library_security_oracle_step.dependOn(&run_f2_certreq_oracle_tests.step);
        zigtls_library_security_oracle_step.dependOn(&run_malformed_spki_oracle_tests.step);
        zigtls_library_security_oracle_step.dependOn(&run_zigtls_noq_tests.step);
    } else {
        zigtls_library_security_oracle_step.dependOn(&zigtls_disabled_step.step);
    }

    // `zig build test-noq-large-transfer` — N-0 production-boundary gate:
    // large stream transfers must cross factory -> transport.zig vtable ->
    // transport_noq socket pump, not the raw sans-io driver. F2 requires
    // LOSSY / BDP-THROTTLED / NEVER-DRAIN discriminating variants (not lossless-only).
    const noq_large_transfer_mod = b.createModule(.{
        .root_source_file = b.path("src/noq_large_transfer_gate.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    noq_large_transfer_mod.addImport("tls", tls_dep.module("tls"));
    configureZigtlsFeature(noq_large_transfer_mod, build_options, zigtls_mod);
    configureProductNativeDeps(b, noq_large_transfer_mod, deps, product, picoquic, picotls, &c_flags);
    const noq_large_transfer_tests = b.addTest(.{
        .root_module = noq_large_transfer_mod,
        .filters = &.{"N-0"},
    });
    const run_noq_large_transfer_tests = b.addRunArtifact(noq_large_transfer_tests);
    const noq_large_transfer_step = b.step("test-noq-large-transfer", "Run production-boundary noq large-transfer gate (lossy/BDP/never-drain)");
    noq_large_transfer_step.dependOn(&run_noq_large_transfer_tests.step);

    // `zig build gossip-quic-interop` — Zig-to-Zig gossip over real QUIC (3a).
    const gossip_quic_mod = b.createModule(.{
        .root_source_file = b.path("src/gossip_quic_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    gossip_quic_mod.addImport("zig_iroh", root_mod);
    const gossip_quic_exe = b.addExecutable(.{ .name = "gossip-quic-interop", .root_module = gossip_quic_mod });
    const run_gossip_quic = b.addRunArtifact(gossip_quic_exe);
    const gossip_quic_step = b.step("gossip-quic-interop", "Run Zig-to-Zig gossip-over-QUIC gate");
    gossip_quic_step.dependOn(&run_gossip_quic.step);

    // `zig build safety-sanitizers` — run interop gates under the best sanitizer substitute
    // available in this Zig build. C ASan/UBSan link attempts are recorded in the report.
    const safety_blobs_interop_mod = b.createModule(.{
        .root_source_file = b.path("src/blobs_interop.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
    });
    safety_blobs_interop_mod.addImport("bench_telemetry", safety_bench_telemetry_mod);
    safety_blobs_interop_mod.addImport("interop_lifecycle", safety_interop_lifecycle_mod);
    safety_blobs_interop_mod.addImport("tls", safety_tls_dep.module("tls"));
    configureZigtlsFeature(safety_blobs_interop_mod, build_options, safety_zigtls_mod);
    configureProductNativeDeps(b, safety_blobs_interop_mod, deps, product, safety_picoquic, safety_picotls, &c_sanitizer_flags);
    linkAsanRuntime(b, safety_blobs_interop_mod, asan_lib_path);
    const safety_blobs_interop_exe = b.addExecutable(.{ .name = "blobs-interop-safety", .root_module = safety_blobs_interop_mod });
    safety_blobs_interop_exe.bundle_ubsan_rt = true;
    const run_safety_blobs_interop = b.addRunArtifact(safety_blobs_interop_exe);
    configureAsanRun(run_safety_blobs_interop);

    const safety_relay_interop_mod = b.createModule(.{
        .root_source_file = b.path("relay_interop_test.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });
    safety_relay_interop_mod.addImport("zig_iroh", safety_root_mod);
    safety_relay_interop_mod.addImport("interop_lifecycle", safety_interop_lifecycle_mod);
    const safety_relay_interop_exe = b.addExecutable(.{ .name = "relay-interop-safety", .root_module = safety_relay_interop_mod });
    safety_relay_interop_exe.bundle_ubsan_rt = true;
    const run_safety_relay_interop = b.addRunArtifact(safety_relay_interop_exe);
    configureAsanRun(run_safety_relay_interop);

    const safety_gossip_quic_mod = b.createModule(.{
        .root_source_file = b.path("src/gossip_quic_test.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
    });
    safety_gossip_quic_mod.addImport("zig_iroh", safety_root_mod);
    const safety_gossip_quic_exe = b.addExecutable(.{ .name = "gossip-quic-interop-safety", .root_module = safety_gossip_quic_mod });
    safety_gossip_quic_exe.bundle_ubsan_rt = true;
    const run_safety_gossip_quic = b.addRunArtifact(safety_gossip_quic_exe);
    configureAsanRun(run_safety_gossip_quic);

    const safety_sanitizers_step = b.step("safety-sanitizers", "Run ReleaseSafe interop sanitizer substitute gates");
    safety_sanitizers_step.dependOn(&run_safety_blobs_interop.step);
    safety_sanitizers_step.dependOn(&run_safety_relay_interop.step);
    safety_sanitizers_step.dependOn(&run_safety_gossip_quic.step);

    // `zig build safety-leaks` — run debug allocator interop leak checks.
    // Honest coverage (W2 #2, audit-v3 H-5): blobs via the Zig test allocator (leaks
    // fail the test binary), relay + gossip via their own DebugAllocator with
    // leak=fail at exit (they used page_allocator before, which made the old
    // "GPA leak checking for all 3 targets" claim false).
    const safety_leaks_step = b.step(
        "safety-leaks",
        "Run interop gates under Zig GPA leak checking (blobs: test allocator; relay/gossip: DebugAllocator, leak=fail)",
    );
    safety_leaks_step.dependOn(&run_blobs_interop.step);
    safety_leaks_step.dependOn(&run_relay_interop.step);
    safety_leaks_step.dependOn(&run_gossip_quic.step);

    // `zig build fuzz-decoders -- --iters 256` — bounded corpus fuzz for wire decoders.
    const fuzz_decoders_mod = b.createModule(.{
        .root_source_file = b.path("bench/fuzz_decoders.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_decoders_mod.addImport("zig_iroh", safety_root_mod);
    const fuzz_decoders_exe = b.addExecutable(.{ .name = "fuzz-decoders", .root_module = fuzz_decoders_mod });
    fuzz_decoders_exe.bundle_ubsan_rt = true;
    const run_fuzz_decoders = b.addRunArtifact(fuzz_decoders_exe);
    configureAsanRun(run_fuzz_decoders);
    // #8 (audit-v4 testinfra): explicit package-relative corpus path — the harness's
    // built-in default ("fuzz/corpus") is cwd-relative and silently breaks from any
    // other cwd. A user --corpus still wins (parseArgs takes the last occurrence).
    run_fuzz_decoders.addArg("--corpus");
    run_fuzz_decoders.addFileArg(b.path("fuzz/corpus"));
    if (b.args) |args| run_fuzz_decoders.addArgs(args);
    const fuzz_decoders_step = b.step("fuzz-decoders", "Run bounded decoder fuzz harness");
    fuzz_decoders_step.dependOn(&run_fuzz_decoders.step);

    // V3-0 gate-integrity: prove the nets catch injected defects (not theater).
    // (1) C-side double picoquic_delete_cnx → ASan abort under safety_picoquic.
    const uaf_inject_mod = b.createModule(.{
        .root_source_file = b.path("bench/uaf_inject_probe.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });
    uaf_inject_mod.addImport("zig_iroh", safety_root_mod);
    const uaf_inject_exe = b.addExecutable(.{ .name = "uaf-inject-probe", .root_module = uaf_inject_mod });
    uaf_inject_exe.bundle_ubsan_rt = true;
    const run_uaf_inject = b.addRunArtifact(uaf_inject_exe);
    configureAsanRun(run_uaf_inject);
    // Sanitized C traps the double-free (UBSan illegal-instruction → ABRT). That
    // is the catch; exit-0 / UAF_INJECT_MISS would mean the net is blind.
    run_uaf_inject.addCheck(.{ .expect_term = .{ .signal = std.posix.SIG.ABRT } });
    const uaf_inject_step = b.step("uaf-inject-probe", "V3-0: injected C-side UAF must be caught by sanitized build (expect SIGABRT)");
    uaf_inject_step.dependOn(&run_uaf_inject.step);

    // GATED: absent in the public mirror (bench/ is not shipped). See devSourcePresent().
    if (devSourcePresent(b, "bench/quic_ownership_probe.zig")) {
        // Ownership-precondition probe (audit-v4 #2 stopgap): two threads drive one
        // quic.Endpoint concurrently; runtime_safety guard MUST abort. Link against
        // safe_root_mod (ReleaseSafe Zig — same mode as `test-safe`) and bundle the
        // ubsan RT the same way safe_unit_tests does.
        const ownership_probe_mod = b.createModule(.{
            .root_source_file = b.path("bench/quic_ownership_probe.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
        });
        ownership_probe_mod.addImport("zig_iroh", safe_root_mod);
        const ownership_probe_exe = b.addExecutable(.{
            .name = "quic-ownership-probe",
            .root_module = ownership_probe_mod,
        });
        ownership_probe_exe.bundle_ubsan_rt = true;
        b.installArtifact(ownership_probe_exe);
        const run_ownership_probe = b.addRunArtifact(ownership_probe_exe);
        // std.debug.panic → SIGABRT. Exit-0 / OWNERSHIP_PROBE_MISS = blind guard.
        run_ownership_probe.addCheck(.{ .expect_term = .{ .signal = std.posix.SIG.ABRT } });
        const ownership_probe_step = b.step(
            "quic-ownership-probe",
            "Ownership stopgap: concurrent Endpoint use must panic under runtime_safety (expect SIGABRT)",
        );
        ownership_probe_step.dependOn(&run_ownership_probe.step);
    }

    // (2) Fuzz harness must exit nonzero when crashes > 0 (self-check path).
    const run_fuzz_crash_exit = b.addRunArtifact(fuzz_decoders_exe);
    configureAsanRun(run_fuzz_crash_exit);
    run_fuzz_crash_exit.addArg("--self-check-nonzero-on-crash");
    run_fuzz_crash_exit.expectExitCode(1);
    const fuzz_crash_exit_step = b.step("fuzz-crash-exit-probe", "V3-0: fuzz step must fail when crashes > 0 (expect exit 1)");
    fuzz_crash_exit_step.dependOn(&run_fuzz_crash_exit.step);

    const gate_integrity_step = b.step("gate-integrity", "V3-0: sanitized-C UAF catch + fuzz fail-on-crash + C4 preflight self-test");
    gate_integrity_step.dependOn(&run_uaf_inject.step);
    gate_integrity_step.dependOn(&run_fuzz_crash_exit.step);
    gate_integrity_step.dependOn(&reference_preflight_selftest.step);

    // W2 #10 (audit-v3 M-valgrind): best-effort valgrind/memcheck second opinion on
    // the C engine path — the non-sanitized blobs-quic-interop test binary (real QUIC
    // workload). Explicitly NOT a mandatory gate: an absent valgrind prints
    // VALGRIND_UNAVAILABLE and exits 0; that is the honest "unavailable" outcome,
    // not a pass and not a fail.
    const valgrind_probe = b.addSystemCommand(&.{
        "sh",
        "-c",
        "if command -v valgrind >/dev/null 2>&1; then exec valgrind --tool=memcheck --error-exitcode=99 --errors-for-leak-kinds=none --num-callers=20 \"$1\"; else echo 'VALGRIND_UNAVAILABLE: valgrind not on PATH; memcheck second opinion not run (best-effort, not a mandatory gate)' >&2; fi",
        "sh",
    });
    valgrind_probe.addArtifactArg(blobs_quic_tests);
    const valgrind_memcheck_step = b.step(
        "valgrind-memcheck",
        "Best-effort valgrind memcheck second opinion on the C-engine QUIC path (honest unavailable when absent)",
    );
    valgrind_memcheck_step.dependOn(&valgrind_probe.step);

    // V3-H / VC-2: build the release archive only from build.zig.zon
    // `.paths`, then regenerate it canonically, compare it byte-for-byte,
    // clean-extract it, and compile/run package-local gates with fresh caches.
    const package_release_mod = b.createModule(.{
        .root_source_file = b.path("package_release_main.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
    });
    const package_release_exe = b.addExecutable(.{
        .name = "package-release",
        .root_module = package_release_mod,
    });
    const package_archive_path = b.fmt(
        "zig-out/{s}-{s}.tar",
        .{ @tagName(manifest.name), manifest.version },
    );

    const create_package_archive = b.addRunArtifact(package_release_exe);
    create_package_archive.addArgs(&.{ "create", package_archive_path });
    const package_release_step = b.step(
        "package-release",
        "Create the deterministic release archive from build.zig.zon .paths",
    );
    package_release_step.dependOn(&create_package_archive.step);

    const check_package_archive = b.addRunArtifact(package_release_exe);
    check_package_archive.addArgs(&.{ "check", package_archive_path });
    check_package_archive.step.dependOn(&create_package_archive.step);
    const package_check_step = b.step(
        "package-check",
        "Package-local: verify, clean-extract, compile, and exercise the archive",
    );
    package_check_step.dependOn(&check_package_archive.step);

    const package_paths_step = b.step(
        "package-paths-check",
        "Compatibility alias for package-check",
    );
    package_paths_step.dependOn(package_check_step);

    // RB-3 is green only when the clean package and the monorepo-hosted
    // behavioral NAT/RPK oracles all pass against the default vendored C root.
    const release_buildability_step = b.step(
        "release-buildability",
        "Run package-local and vendored-source WIRE/AUTH release gates",
    );
    release_buildability_step.dependOn(package_check_step);
    release_buildability_step.dependOn(s2_transport_step);
    release_buildability_step.dependOn(noq_wire_diff_step);
    release_buildability_step.dependOn(interop_step);
    release_buildability_step.dependOn(noq_interop_step);

    // `zig build gossip-interop` — live gate vs real iroh-gossip (3b).
    const gossip_interop_mod = b.createModule(.{
        .root_source_file = b.path("src/gossip_interop_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    gossip_interop_mod.addImport("zig_iroh", root_mod);
    gossip_interop_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    const gossip_interop_exe = b.addExecutable(.{ .name = "gossip-interop", .root_module = gossip_interop_mod });
    const run_gossip_interop = b.addRunArtifact(gossip_interop_exe);
    const gossip_interop_step = b.step("gossip-interop", "Run real iroh-gossip interop gate");
    gossip_interop_step.dependOn(&reference_preflight.step);
    gossip_interop_step.dependOn(&run_gossip_interop.step);

    const native_leaks_check = b.addSystemCommand(&.{
        "sh",         "-c",
        \\set -eu
        \\product="$0"
        \\case "$product" in
        \\  noq-picotls)
        \\    sym_re='picoquic_|iroh_picoquic'
        \\    soname_re='a^'
        \\    ;;
        \\  noq-zigtls)
        \\    sym_re='picoquic_|iroh_picoquic|ptls_|SSL_|EVP_|OPENSSL_'
        \\    soname_re='crypto|ssl|picotls|picoquic'
        \\    ;;
        \\  *)
        \\    echo "check-product-native-leaks: N/A for product '$product'"
        \\    exit 0
        \\    ;;
        \\esac
        \\fail=0
        \\for bin in "$@"; do
        \\  echo "check-product-native-leaks: inspect $bin"
        \\  if [ "$soname_re" != "a^" ]; then
        \\    sonames="$(ldd "$bin" 2>/dev/null | grep -Ei "$soname_re" || true)"
        \\    if [ -n "$sonames" ]; then
        \\      echo "check-product-native-leaks FAIL: product '$product' links forbidden native library in $bin" >&2
        \\      printf '%s\n' "$sonames" >&2
        \\      fail=1
        \\    fi
        \\  fi
        \\  undef="$(nm -u "$bin" 2>/dev/null | grep -E "$sym_re" || true)"
        \\  if [ -n "$undef" ]; then
        \\    echo "check-product-native-leaks FAIL: product '$product' has forbidden undefined symbols in $bin" >&2
        \\    printf '%s\n' "$undef" >&2
        \\    fail=1
        \\  fi
        \\  syms="$(readelf -Ws "$bin" 2>/dev/null | grep -E "$sym_re" || true)"
        \\  if [ -n "$syms" ]; then
        \\    echo "check-product-native-leaks FAIL: product '$product' has forbidden symbols in $bin" >&2
        \\    printf '%s\n' "$syms" >&2
        \\    fail=1
        \\  fi
        \\done
        \\if [ "$fail" -ne 0 ]; then
        \\  exit 1
        \\fi
        \\echo "check-product-native-leaks OK: product '$product'"
        ,
        product_name,
    });
    native_leaks_check.addArtifactArg(unit_tests);
    native_leaks_check.addArtifactArg(gossip_quic_exe);
    native_leaks_check.addArtifactArg(gossip_interop_exe);
    native_leaks_step.dependOn(&native_leaks_check.step);
}

fn configureZigtlsFeature(
    module: *std.Build.Module,
    build_options: *std.Build.Step.Options,
    zigtls_mod: ?*std.Build.Module,
) void {
    module.addOptions("build_options", build_options);
    if (zigtls_mod) |mod| module.addImport("zigtls", mod);
}

/// Product-conditional native dependency wiring (component-repo restructure).
/// Applies exactly the include paths, C glue sources, and library links the
/// resolved product needs — this is gate (b) (the build side), kept in lockstep
/// with gate (a) (the `build_options` comptime flags). Layout:
///   - picoquic ⇒ picoquic includes + `src/connection/rpk.c` + libpicoquic
///     (which transitively links libpicotls) + libcrypto.
///   - picotls-only (noq-picotls) ⇒ picotls includes + `src/quic/rpk_picotls.c`
///     + libpicotls + libcrypto (NO picoquic, NO rpk.c).
///   - neither (noq-zigtls) ⇒ no includes, no C glue, no libpicotls/libcrypto.
/// `picoquic_lib` / `picotls_lib` are `null` when their engine is compiled out;
/// they are dereferenced only on the matching branch.
fn configureProductNativeDeps(
    b: *std.Build,
    mod: *std.Build.Module,
    deps: std.Build.LazyPath,
    product: products.Product,
    picoquic_lib: ?*std.Build.Step.Compile,
    picotls_lib: ?*std.Build.Step.Compile,
    c_flags_slice: []const []const u8,
) void {
    // Include paths: picoquic pulls both header trees; picotls-only pulls just
    // picotls. `-Isrc` resolves the quoted glue headers (rpk.h / rpk_picotls.h).
    if (product.picoquic) {
        addPicoquicIncludes(mod, b, deps);
    } else if (product.picotls) {
        addPicotlsIncludes(mod, b, deps);
    }
    if (product.picoquic or product.picotls) {
        mod.addIncludePath(b.path("src"));
    }

    // C glue sources, split by engine dependency (see `connection_c_sources`).
    var c_files: [2][]const u8 = undefined;
    var n: usize = 0;
    if (product.picoquic) {
        c_files[n] = "src/connection/rpk.c"; // picoquic RPK verify glue
        n += 1;
    }
    if (product.picotls) {
        c_files[n] = "src/quic/rpk_picotls.c"; // picotls RPK setup (picotls-only)
        n += 1;
    }
    if (n > 0) {
        mod.addCSourceFiles(.{
            .root = b.path("."),
            .files = c_files[0..n],
            .flags = c_flags_slice,
        });
    }

    // Native libraries. picoquic bundles picotls (transitive); a picotls-only
    // product links picotls directly. libcrypto (openssl) is required by BOTH
    // (picotls' openssl.c / rpk_picotls.c); zigtls-only links neither.
    if (product.picoquic) {
        mod.linkLibrary(picoquic_lib.?);
    } else if (product.picotls) {
        mod.linkLibrary(picotls_lib.?);
    }
    if (product.picoquic or product.picotls) {
        mod.linkSystemLibrary("crypto", .{});
    }
}

fn addPicotls(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    deps: std.Build.LazyPath,
) *std.Build.Step.Compile {
    return addPicotlsWithOptions(b, target, optimize, deps, .{
        .name = "picotls-iroh",
        .c_flags = &c_flags,
        .sanitize_c = null,
    });
}

const CBuildOptions = struct {
    name: []const u8,
    c_flags: []const []const u8,
    sanitize_c: ?std.zig.SanitizeC,
};

fn addPicotlsWithOptions(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    deps: std.Build.LazyPath,
    options: CBuildOptions,
) *std.Build.Step.Compile {
    const with_fusion = hasFusionCpuFeatures(target);
    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addPicotlsIncludes(mod, b, deps);
    const lib = b.addLibrary(.{ .name = options.name, .linkage = .static, .root_module = mod });
    lib.root_module.addCSourceFiles(.{
        .root = deps,
        .files = if (options.sanitize_c == null) &picotls_sources else &picotls_non_wire_decode_sources,
        .flags = options.c_flags,
    });
    if (with_fusion) {
        lib.root_module.addCSourceFiles(.{
            .root = deps,
            .files = &picotls_fusion_sources,
            .flags = options.c_flags,
        });
    }
    if (options.sanitize_c) |sanitize_c| {
        const sanitize_mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .sanitize_c = sanitize_c,
        });
        addPicotlsIncludes(sanitize_mod, b, deps);
        const sanitize_lib = b.addLibrary(.{
            .name = b.fmt("{s}-wire-decode", .{options.name}),
            .linkage = .static,
            .root_module = sanitize_mod,
        });
        sanitize_lib.root_module.addCSourceFiles(.{
            .root = deps,
            .files = &picotls_wire_decode_sources,
            .flags = &c_sanitizer_flags,
        });
        lib.root_module.linkLibrary(sanitize_lib);
    }
    return lib;
}

fn addPicoquic(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    deps: std.Build.LazyPath,
    picotls: *std.Build.Step.Compile,
) *std.Build.Step.Compile {
    return addPicoquicWithOptions(b, target, optimize, deps, picotls, .{
        .name = "picoquic-iroh",
        .c_flags = &c_flags,
        .sanitize_c = null,
    });
}

fn addPicoquicWithOptions(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    deps: std.Build.LazyPath,
    picotls: *std.Build.Step.Compile,
    options: CBuildOptions,
) *std.Build.Step.Compile {
    const with_fusion = hasFusionCpuFeatures(target);
    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addPicoquicIncludes(mod, b, deps);
    if (!with_fusion) {
        mod.addCMacro("PTLS_WITHOUT_FUSION", "1");
    }
    const lib = b.addLibrary(.{ .name = options.name, .linkage = .static, .root_module = mod });
    lib.root_module.addCSourceFiles(.{
        .root = deps,
        .files = if (options.sanitize_c == null) &picoquic_sources else &picoquic_non_wire_decode_sources,
        .flags = options.c_flags,
    });
    if (with_fusion) {
        lib.root_module.addCSourceFiles(.{
            .root = deps,
            .files = &picoquic_fusion_sources,
            .flags = options.c_flags,
        });
    }
    lib.root_module.linkLibrary(picotls);
    if (options.sanitize_c) |sanitize_c| {
        const sanitize_mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .sanitize_c = sanitize_c,
        });
        addPicoquicIncludes(sanitize_mod, b, deps);
        if (!with_fusion) {
            sanitize_mod.addCMacro("PTLS_WITHOUT_FUSION", "1");
        }
        const sanitize_lib = b.addLibrary(.{
            .name = b.fmt("{s}-wire-decode", .{options.name}),
            .linkage = .static,
            .root_module = sanitize_mod,
        });
        sanitize_lib.root_module.addCSourceFiles(.{
            .root = deps,
            .files = &picoquic_wire_decode_sources,
            .flags = &c_sanitizer_flags,
        });
        lib.root_module.linkLibrary(sanitize_lib);
    }
    return lib;
}

fn addPicoquicIncludes(mod: *std.Build.Module, b: *std.Build, deps: std.Build.LazyPath) void {
    mod.addIncludePath(deps.path(b, "picoquic/picoquic"));
    addPicotlsIncludes(mod, b, deps);
}

fn addPicotlsIncludes(mod: *std.Build.Module, b: *std.Build, deps: std.Build.LazyPath) void {
    mod.addIncludePath(deps.path(b, "picotls/include"));
    mod.addIncludePath(deps.path(b, "picotls/deps/cifra/src/ext"));
    mod.addIncludePath(deps.path(b, "picotls/deps/cifra/src"));
    mod.addIncludePath(deps.path(b, "picotls/deps/micro-ecc"));
}

fn linkAsanRuntime(b: *std.Build, mod: *std.Build.Module, asan_lib_path: ?[]const u8) void {
    // H2 (audit-v4 testinfra): locate the GCC ASan runtime WITHOUT a host-hardcoded
    // path (was /usr/lib/gcc/x86_64-linux-gnu/15 — broke any other host/compiler).
    // Order: explicit -Dasan_lib_path → `gcc -print-file-name=libasan.a` probe
    // (precise — NOT -print-libgcc-file-name, which names a different archive) →
    // the linker's default search paths (a missing -lasan then fails the LINK with a
    // clear error naming the -Dasan_lib_path override, never a build-graph panic).
    if (asan_lib_path orelse probeGccLibDir(b)) |dir| {
        mod.addLibraryPath(.{ .cwd_relative = dir });
    }
    mod.linkSystemLibrary("asan", .{ .preferred_link_mode = .static });
    mod.linkSystemLibrary("gcc_s", .{});
}

/// Best-effort libasan.a directory probe; null when gcc is absent or cannot find it.
fn probeGccLibDir(b: *std.Build) ?[]const u8 {
    var code: u8 = 0;
    const out = b.runAllowFail(&.{ "gcc", "-print-file-name=libasan.a" }, &code, .ignore) catch return null;
    const trimmed = std.mem.trim(u8, out, &std.ascii.whitespace);
    // gcc echoes the bare name back when it cannot find the file.
    if (code == 0 and trimmed.len != 0 and !std.mem.eql(u8, trimmed, "libasan.a") and std.fs.path.isAbsolute(trimmed)) {
        return std.fs.path.dirname(trimmed);
    }
    return null;
}

fn configureAsanRun(run: *std.Build.Step.Run) void {
    run.setEnvironmentVariable("ASAN_OPTIONS", "use_sigaltstack=0");
}

fn configureRustPeerRun(run: *std.Build.Step.Run) void {
    // The pinned Rust source carries a host-local clang/lld override. Keep the
    // interop oracle reproducible on hosts where that linker pair is absent.
    run.setEnvironmentVariable("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER", "cc");
    run.setEnvironmentVariable("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "");
}

fn hasFusionCpuFeatures(target: std.Build.ResolvedTarget) bool {
    if (target.result.cpu.arch != .x86_64) return false;
    return std.Target.x86.featureSetHasAll(target.result.cpu.features, .{ .vaes, .vpclmulqdq });
}

const c_flags = [_][]const u8{
    "-std=c99",
    "-D_GNU_SOURCE",
    "-Wall",
    "-Wno-unused-parameter",
    "-Wno-unused-function",
    "-Wno-sign-compare",
    "-Wno-shift-count-overflow",
    "-Wno-typedef-redefinition",
};

const c_sanitizer_flags = c_flags ++ [_][]const u8{
    "-fsanitize=address",
    "-fno-omit-frame-pointer",
};

const picotls_sources = [_][]const u8{
    "picotls/deps/micro-ecc/uECC.c",
    "picotls/deps/cifra/src/aes.c",
    "picotls/deps/cifra/src/blockwise.c",
    "picotls/deps/cifra/src/chacha20.c",
    "picotls/deps/cifra/src/chash.c",
    "picotls/deps/cifra/src/curve25519.c",
    "picotls/deps/cifra/src/drbg.c",
    "picotls/deps/cifra/src/hmac.c",
    "picotls/deps/cifra/src/gcm.c",
    "picotls/deps/cifra/src/gf128.c",
    "picotls/deps/cifra/src/modes.c",
    "picotls/deps/cifra/src/poly1305.c",
    "picotls/deps/cifra/src/sha256.c",
    "picotls/deps/cifra/src/sha512.c",
    "picotls/lib/hpke.c",
    "picotls/lib/picotls.c",
    "picotls/lib/pembase64.c",
    "picotls/lib/cifra.c",
    "picotls/lib/cifra/x25519.c",
    "picotls/lib/cifra/chacha20.c",
    "picotls/lib/cifra/aes128.c",
    "picotls/lib/cifra/aes256.c",
    "picotls/lib/cifra/random.c",
    "picotls/lib/minicrypto-pem.c",
    "picotls/lib/uecc.c",
    "picotls/lib/asn1.c",
    "picotls/lib/ffx.c",
    "picotls/lib/openssl.c",
};

const picotls_wire_decode_sources = [_][]const u8{
    "picotls/lib/picotls.c",
    "picotls/lib/asn1.c",
};

const picotls_non_wire_decode_sources = [_][]const u8{
    "picotls/deps/micro-ecc/uECC.c",
    "picotls/deps/cifra/src/aes.c",
    "picotls/deps/cifra/src/blockwise.c",
    "picotls/deps/cifra/src/chacha20.c",
    "picotls/deps/cifra/src/chash.c",
    "picotls/deps/cifra/src/curve25519.c",
    "picotls/deps/cifra/src/drbg.c",
    "picotls/deps/cifra/src/hmac.c",
    "picotls/deps/cifra/src/gcm.c",
    "picotls/deps/cifra/src/gf128.c",
    "picotls/deps/cifra/src/modes.c",
    "picotls/deps/cifra/src/poly1305.c",
    "picotls/deps/cifra/src/sha256.c",
    "picotls/deps/cifra/src/sha512.c",
    "picotls/lib/hpke.c",
    "picotls/lib/pembase64.c",
    "picotls/lib/cifra.c",
    "picotls/lib/cifra/x25519.c",
    "picotls/lib/cifra/chacha20.c",
    "picotls/lib/cifra/aes128.c",
    "picotls/lib/cifra/aes256.c",
    "picotls/lib/cifra/random.c",
    "picotls/lib/minicrypto-pem.c",
    "picotls/lib/uecc.c",
    "picotls/lib/ffx.c",
    "picotls/lib/openssl.c",
};

const picotls_fusion_sources = [_][]const u8{
    "picotls/lib/fusion.c",
};

// Reference list of the C RPK glue sources. These are NO LONGER added as a
// single bundle — `configureProductNativeDeps` selects them per product:
//   "src/connection/rpk.c"   → picoquic RPK verify glue (needs picoquic).
//   "src/quic/rpk_picotls.c" → picotls RPK setup (picotls-only).
const connection_c_sources = [_][]const u8{
    "src/connection/rpk.c",
    "src/quic/rpk_picotls.c",
};

const picoquic_sources = [_][]const u8{
    "picoquic/picoquic/bbr.c",
    "picoquic/picoquic/bbr1.c",
    "picoquic/picoquic/bytestream.c",
    "picoquic/picoquic/cc_common.c",
    "picoquic/picoquic/config.c",
    "picoquic/picoquic/cubic.c",
    "picoquic/picoquic/c4.c",
    "picoquic/picoquic/dualq_aqm.c",
    "picoquic/picoquic/ech.c",
    "picoquic/picoquic/error_names.c",
    "picoquic/picoquic/fastcc.c",
    "picoquic/picoquic/frames.c",
    "picoquic/picoquic/frame_names.c",
    "picoquic/picoquic/intformat.c",
    "picoquic/picoquic/logger.c",
    "picoquic/picoquic/logwriter.c",
    "picoquic/picoquic/loss_recovery.c",
    "picoquic/picoquic/newreno.c",
    "picoquic/picoquic/pacing.c",
    "picoquic/picoquic/packet.c",
    "picoquic/picoquic/packet_names.c",
    "picoquic/picoquic/paths.c",
    "picoquic/picoquic/performance_log.c",
    "picoquic/picoquic/picohash.c",
    "picoquic/picoquic/picoquic_lb.c",
    "picoquic/picoquic/picoquic_ptls_minicrypto.c",
    "picoquic/picoquic/picoquic_ptls_openssl.c",
    "picoquic/picoquic/picoquic_mbedtls.c",
    "picoquic/picoquic/picosocks.c",
    "picoquic/picoquic/picosplay.c",
    "picoquic/picoquic/port_blocking.c",
    "picoquic/picoquic/prague.c",
    "picoquic/picoquic/qmux.c",
    "picoquic/picoquic/quicctx.c",
    "picoquic/picoquic/register_all_cc_algorithms.c",
    "picoquic/picoquic/sacks.c",
    "picoquic/picoquic/sender.c",
    "picoquic/picoquic/sim_link.c",
    "picoquic/picoquic/siphash.c",
    "picoquic/picoquic/sockloop.c",
    "picoquic/picoquic/spinbit.c",
    "picoquic/picoquic/streams.c",
    "picoquic/picoquic/ticket_store.c",
    "picoquic/picoquic/timing.c",
    "picoquic/picoquic/token_store.c",
    "picoquic/picoquic/tls_api.c",
    "picoquic/picoquic/tp_names.c",
    "picoquic/picoquic/transport.c",
    "picoquic/picoquic/unified_log.c",
    "picoquic/picoquic/util.c",
};

const picoquic_wire_decode_sources = [_][]const u8{
    "picoquic/picoquic/frames.c",
    "picoquic/picoquic/intformat.c",
    "picoquic/picoquic/packet.c",
    "picoquic/picoquic/tls_api.c",
    "picoquic/picoquic/transport.c",
};

const picoquic_non_wire_decode_sources = [_][]const u8{
    "picoquic/picoquic/bbr.c",
    "picoquic/picoquic/bbr1.c",
    "picoquic/picoquic/bytestream.c",
    "picoquic/picoquic/cc_common.c",
    "picoquic/picoquic/config.c",
    "picoquic/picoquic/cubic.c",
    "picoquic/picoquic/c4.c",
    "picoquic/picoquic/dualq_aqm.c",
    "picoquic/picoquic/ech.c",
    "picoquic/picoquic/error_names.c",
    "picoquic/picoquic/fastcc.c",
    "picoquic/picoquic/frame_names.c",
    "picoquic/picoquic/logger.c",
    "picoquic/picoquic/logwriter.c",
    "picoquic/picoquic/loss_recovery.c",
    "picoquic/picoquic/newreno.c",
    "picoquic/picoquic/pacing.c",
    "picoquic/picoquic/packet_names.c",
    "picoquic/picoquic/paths.c",
    "picoquic/picoquic/performance_log.c",
    "picoquic/picoquic/picohash.c",
    "picoquic/picoquic/picoquic_lb.c",
    "picoquic/picoquic/picoquic_ptls_minicrypto.c",
    "picoquic/picoquic/picoquic_ptls_openssl.c",
    "picoquic/picoquic/picoquic_mbedtls.c",
    "picoquic/picoquic/picosocks.c",
    "picoquic/picoquic/picosplay.c",
    "picoquic/picoquic/port_blocking.c",
    "picoquic/picoquic/prague.c",
    "picoquic/picoquic/qmux.c",
    "picoquic/picoquic/quicctx.c",
    "picoquic/picoquic/register_all_cc_algorithms.c",
    "picoquic/picoquic/sacks.c",
    "picoquic/picoquic/sender.c",
    "picoquic/picoquic/sim_link.c",
    "picoquic/picoquic/siphash.c",
    "picoquic/picoquic/sockloop.c",
    "picoquic/picoquic/spinbit.c",
    "picoquic/picoquic/streams.c",
    "picoquic/picoquic/ticket_store.c",
    "picoquic/picoquic/timing.c",
    "picoquic/picoquic/token_store.c",
    "picoquic/picoquic/tp_names.c",
    "picoquic/picoquic/unified_log.c",
    "picoquic/picoquic/util.c",
};

const picoquic_fusion_sources = [_][]const u8{
    "picoquic/picoquic/picoquic_ptls_fusion.c",
};
