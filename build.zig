const std = @import("std");
const manifest = @import("build.zig.zon");
const products = @import("src/products.zig");

// SHA-256 of the generated pruned C tree, encoded as sorted
// `<mode> <relative path> <file SHA-256>` lines. Keep these values in sync with
// owner-local C patches: materialization must recreate the pre-F1 patched deps/
// contents exactly, rather than merely applying patches without an output check.
const materialized_c_deps_tree_hash = .{
    .picotls = "b7c9416c9bc4b9ab5875752d5d0040784f843f18ec8ff69adac146efd19373c9",
    .picoquic_picotls = "40a35474a95911f957befdf78b43f43b23e966b7e91589748b9935acb882f47e",
};

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

/// One filtered unit-test gate = one call: compiles
/// root_mod once per distinct filter set (0.16 filters are compile-time —
/// there is no runtime --filter), wires the run artifact and the named step.
fn addFilteredTestStep(
    b: *std.Build,
    root_mod: *std.Build.Module,
    name: []const u8,
    description: []const u8,
    filters: []const []const u8,
) *std.Build.Step {
    const tests = b.addTest(.{ .root_module = root_mod, .filters = filters });
    const run = b.addRunArtifact(tests);
    const step = b.step(name, description);
    step.dependOn(&run.step);
    return step;
}

/// F1 keeps the C vendor repositories as pristine source inputs. Native products
/// consume only this generated root: a build-cache-local copy plus its owner-local
/// patch sources. The shell step intentionally refuses a dirty Git checkout, so a
/// caller cannot silently retain the old shared-working-tree patch model.
fn materializePatchedCDeps(
    b: *std.Build,
    deps: std.Build.LazyPath,
    include_picoquic: bool,
) std.Build.LazyPath {
    const materialize = b.addSystemCommand(&.{
        "sh",
        "-eu",
        "-c",
        \\output=$1
        \\source=$2
        \\include_picoquic=$3
        \\picotls_patch=$4
        \\picoquic_nat_patch=$5
        \\picoquic_initial_ack_patch=$6
        \\expected_tree_hash=$7
        \\
        \\tree_hash() {
        \\    (
        \\        cd "$1"
        \\        LC_ALL=C find . -type f -printf '%m %P\n' | LC_ALL=C sort | while IFS=' ' read -r mode path; do
        \\            printf '%s %s %s\n' "$mode" "$path" "$(sha256sum "$path" | cut -d ' ' -f1)"
        \\        done | sha256sum | cut -d ' ' -f1
        \\    )
        \\}
        \\
        \\require_pristine() {
        \\    tree=$1
        \\    if [ -e "$tree/.git" ] && [ -n "$(git -C "$tree" status --porcelain)" ]; then
        \\        printf 'F1 C mirror must be pristine before materialization: %s\\n' "$tree" >&2
        \\        exit 1
        \\    fi
        \\}
        \\
        \\test -d "$source/picotls"
        \\require_pristine "$source/picotls"
        \\if [ "$include_picoquic" = true ]; then
        \\    test -d "$source/picoquic"
        \\    require_pristine "$source/picoquic"
        \\fi
        \\
        \\# Zig may retain an output directory after a failed or interrupted command.
        \\# Recreate it so a stale pristine tree cannot shadow freshly applied patches.
        \\rm -rf "$output"
        \\mkdir -p "$output"
        \\cp -a "$source/picotls" "$output/picotls"
        \\rm -rf "$output/picotls/.git"
        \\patch --directory="$output/picotls" --strip=1 --batch --forward --input="$picotls_patch"
        \\if [ "$include_picoquic" = true ]; then
        \\    cp -a "$source/picoquic" "$output/picoquic"
        \\    rm -rf "$output/picoquic/.git"
        \\    patch --directory="$output/picoquic" --strip=1 --batch --forward --input="$picoquic_nat_patch"
        \\    patch --directory="$output/picoquic" --strip=1 --batch --forward --input="$picoquic_initial_ack_patch"
        \\fi
        \\
        \\tree_root="$output"
        \\if [ "$include_picoquic" != true ]; then
        \\    tree_root="$output/picotls"
        \\fi
        \\actual_tree_hash=$(tree_hash "$tree_root")
        \\if [ "$actual_tree_hash" != "$expected_tree_hash" ]; then
        \\    printf 'F1 C materialization content mismatch: expected %s, got %s\\n' "$expected_tree_hash" "$actual_tree_hash" >&2
        \\    exit 1
        \\fi
        ,
        "materialize-patched-c-deps",
    });
    const expected_tree_hash = if (include_picoquic)
        materialized_c_deps_tree_hash.picoquic_picotls
    else
        materialized_c_deps_tree_hash.picotls;
    // The output identity includes the asserted content digest. That prevents a
    // cache entry produced before a patch change from satisfying this materializer.
    const output = materialize.addOutputDirectoryArg(
        b.fmt("patched-c-deps-{s}", .{expected_tree_hash}),
    );
    materialize.addDirectoryArg(deps);
    materialize.addArg(if (include_picoquic) "true" else "false");
    materialize.addFileArg(b.path("src/tls-picotls/patches/picotls-iroh-rpk.patch"));
    materialize.addFileArg(b.path("src/engine-picoquic/patches/picoquic-iroh-nat-frames.patch"));
    materialize.addFileArg(b.path("src/engine-picoquic/patches/picoquic-initial-ack-scan-underflow.patch"));
    materialize.addArg(expected_tree_hash);

    const materialize_step = b.step(
        "materialize-c-deps",
        "Materialize pristine C mirrors and owner-local patches into the build cache",
    );
    materialize_step.dependOn(&materialize.step);
    return output;
}

pub fn build(b: *std.Build) void {
    const requested_target = b.standardTargetOptions(.{});
    const target = completeAesGcmCpuFeatures(requested_target);
    const optimize = b.standardOptimizeOption(.{});
    // ── Product selection (component-repo restructure Phase 1) ──────────────
    // `-Dproduct=<id>` chooses which engines/features compile in. The resolved
    // profile drives BOTH the native link/C-source selection below AND the
    // `build_options` comptime flags Zig uses to elide disabled subsystems.
    // Every product is mono (one QUIC engine). An omitted `-Dproduct` picks
    // picoquic-picotls; `test-all-mono-products` covers both engines by
    // re-invoking this build once per id.
    const product_name = b.option([]const u8, "product", b.fmt("Product profile: {s}", .{products.id_list})) orelse "picoquic-picotls";
    const product_id = products.parseId(product_name) orelse {
        std.debug.panic("unknown -Dproduct='{s}'; valid: {s}", .{ product_name, products.id_list });
    };
    const product = products.get(product_id);
    // The release package carries picoquic + picotls under deps/. Local
    // development can continue to select the sibling tree explicitly.
    const deps_path = b.option([]const u8, "deps_path", "Path to dependency tree; default deps") orelse "deps";
    const deps: std.Build.LazyPath = if (std.fs.path.isAbsolute(deps_path))
        .{ .cwd_relative = deps_path }
    else
        b.path(deps_path);
    const zigtls_opt = b.option(bool, "zigtls", "Enable the experimental pure-Zig TLS backend; every shipped product pins it") orelse false;
    // `product.zigtls == null` means "inherit -Dzigtls"; a concrete bool pins it.
    // All three shipped products pin (noq-zigtls on, the other two off), so
    // -Dzigtls is inert today — select `-Dproduct=noq-zigtls` to get zigtls.
    const zigtls_enabled = product.zigtls orelse zigtls_opt;
    // F2 owns the maintained zigtls fork in the release closure. The pristine
    // dependency mirror is provenance-only; no build path may resolve it.
    const zigtls_root = b.path("src/tls-zigtls/zigtls");

    // Short commit stamped into product `/healthz` payloads. `-Dgit_hash=` lets a
    // release pipeline pin it when the source is exported without a .git dir.
    const git_hash = b.option([]const u8, "git_hash", "Short commit to report in /healthz") orelse
        resolveGitHash(b);

    const build_options = b.addOptions();
    // Experimental: `-Deventing=true` enables the Evented (Uring) Io probe path.
    // Default OFF — the product still uses Threaded + Part-B ppoll waits. The
    // Evented backend needs a patched std overlay (tools/patch_evented_std.py);
    // see the `evented-probe` step. Default builds are byte-unchanged.
    const eventing = b.option(bool, "eventing", "EXPERIMENTAL: enable std.Io.Evented probe path (default off)") orelse false;

    build_options.addOption([]const u8, "product", product_name);
    build_options.addOption(bool, "picoquic", product.picoquic);
    build_options.addOption(bool, "noq", product.noq);
    build_options.addOption(bool, "picotls", product.picotls);
    build_options.addOption(bool, "zigtls", zigtls_enabled);
    build_options.addOption(bool, "gossip", product.gossip);
    build_options.addOption([]const u8, "git_hash", git_hash);
    build_options.addOption(bool, "discovery", product.discovery);
    build_options.addOption(bool, "eventing", eventing);
    // Fork-isolation S1: ONE build_options module instance, shared by every
    // module wired from this Options step — module instances of the same
    // generated options.zig may not coexist in one compilation.
    const build_options_module = build_options.createModule();

    // Native C engines are constructed ONLY when the product needs them
    // (component-repo restructure). picotls is required whenever picoquic is
    // (picoquic bundles it) OR when picotls is the selected TLS backend; a
    // noq-zigtls product constructs neither, so nothing pulls libpicotls/
    // libpicoquic/libcrypto.
    const need_picotls = product.picotls or product.picoquic;
    const materialized_c_deps = materializePatchedCDeps(b, deps, product.picoquic);
    const picotls: ?*std.Build.Step.Compile = if (need_picotls)
        addPicotls(b, target, optimize, materialized_c_deps)
    else
        null;
    const picoquic: ?*std.Build.Step.Compile = if (product.picoquic)
        addPicoquic(b, target, optimize, materialized_c_deps, picotls.?)
    else
        null;
    const safety_picotls: ?*std.Build.Step.Compile = if (need_picotls)
        addPicotlsWithOptions(b, target, .ReleaseSafe, materialized_c_deps, .{
            .name = "picotls-iroh-safety",
            .c_flags = &c_flags,
            .sanitize_c = .full,
        })
    else
        null;
    const safety_picoquic: ?*std.Build.Step.Compile = if (product.picoquic)
        addPicoquicWithOptions(b, target, .ReleaseSafe, materialized_c_deps, safety_picotls.?, .{
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
            .root_source_file = zigtls_root.path(b, "root.zig"),
            .target = target,
            .optimize = optimize,
        })
    else
        null;
    const safety_zigtls_mod: ?*std.Build.Module = if (zigtls_enabled)
        b.createModule(.{
            .root_source_file = zigtls_root.path(b, "root.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
        })
    else
        null;
    const zigtls_disabled_step = b.addFail("zigtls is disabled; enable it with -Dzigtls=true");

    // Explicit ASan runtime location override (default: gcc probe → linker default
    // paths; see linkAsanRuntime). Declared once — b.option panics on redeclaration.
    const asan_lib_path = b.option(
        []const u8,
        "asan_lib_path",
        "Directory containing libasan.a (default: probe `gcc -print-file-name=libasan.a`, then linker default paths)",
    );

    // The public `zig_iroh` library is now the selected product root. Its
    // imports are direct product composition; the retired legacy root is not
    // part of this closure.
    const root_mod = b.addModule("zig_iroh", .{
        .root_source_file = b.path(b.fmt("src/products/{s}/root.zig", .{product_name})),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const seam = createSeamModules(b, product_name, target, optimize, build_options_module, tls_dep.module("tls"), product.noq, zigtls_mod, null, product);
    const root_surface_mod = b.createModule(.{
        .root_source_file = b.path("src/products/root_surface_fixture.zig"),
        .target = target,
        .optimize = optimize,
    });
    const shared_mod = seam.shared;
    const door_mod = seam.door;
    root_mod.addImport("root_surface", root_surface_mod);
    root_mod.addImport("shared", shared_mod);
    root_mod.addImport("transport", door_mod);
    root_mod.addImport("engine", seam.engine);
    if (seam.tls_backend) |tb| root_mod.addImport("tls_backend", tb);
    if (seam.tls_backend) |tb| {
        // Any picotls product that materializes tls_backend needs the RPK C
        // glue + libpicotls + libcrypto on that module (adapter unit tests and
        // noq engine both call into it).
        if (product.picotls) {
            configureTlsBackendPicotlsNativeDeps(b, tb, materialized_c_deps, picotls, &c_flags);
        }
    }
    if (product.picoquic) {
        configurePicoquicEngineNativeDeps(b, seam.engine, materialized_c_deps, picoquic.?, &c_flags);
    }
    // Fork-isolation S4: the S1 DOORLESS harness_shared_mod is RETIRED. The
    // four tree-compiling harness roots (interop / interop-noq /
    // test-noq-large-transfer / test-relay) converted to module style — they
    // consume `zig_iroh` + `shared` + (noq roots) `engine` by name, so one
    // compilation holds exactly one instance of every file.

    // RELAY-SERVER ROOT VARIANT: the relay server binary always builds on the
    // pure-Zig stack (noq engine + zigtls TLS), whatever the selected product.
    // Its QAD listener needs X.509 server certs — only the pure-Zig TLS
    // backend supports them — and the relay data plane (TCP/WS) is
    // engine-independent, so one uniform stack beats per-product QAD
    // divergence. No C/native deps are added to any product by this variant.
    const relay_build_options = b.addOptions();
    relay_build_options.addOption([]const u8, "product", product_name);
    relay_build_options.addOption(bool, "picoquic", false);
    relay_build_options.addOption(bool, "noq", true);
    relay_build_options.addOption(bool, "picotls", false);
    relay_build_options.addOption(bool, "zigtls", true);
    relay_build_options.addOption(bool, "gossip", product.gossip);
    relay_build_options.addOption([]const u8, "git_hash", git_hash);
    relay_build_options.addOption(bool, "discovery", product.discovery);
    const relay_build_options_module = relay_build_options.createModule();
    const relay_zigtls_mod = b.createModule(.{
        .root_source_file = zigtls_root.path(b, "root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const relay_root_mod = b.createModule(.{
        .root_source_file = b.path("src/products/relay-server/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const relay_seam = createSeamModules(b, "relay-server", target, optimize, relay_build_options_module, tls_dep.module("tls"), true, relay_zigtls_mod, null, .{ .picoquic = false, .noq = true, .picotls = false, .zigtls = true, .gossip = product.gossip, .discovery = product.discovery });
    const relay_root_surface_mod = b.createModule(.{
        .root_source_file = b.path("src/products/root_surface_fixture.zig"),
        .target = target,
        .optimize = optimize,
    });
    relay_root_mod.addImport("root_surface", relay_root_surface_mod);
    relay_root_mod.addImport("shared", relay_seam.shared);
    relay_root_mod.addImport("transport", relay_seam.door);
    relay_root_mod.addImport("engine", relay_seam.engine);
    if (relay_seam.tls_backend) |tb| relay_root_mod.addImport("tls_backend", tb);

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

    // Per-module test binaries (P5: `b.addTest` does NOT collect another
    // module's tests). `zig build test` aggregates the final product root,
    // shared, engine, and TLS-backend suites; the committed floor
    // (zig_iroh/test-counts.yaml via scripts/check_test_counts.py) grades the
    // aggregate Build Summary, so coverage cannot silently drop.
    const shared_unit_tests = b.addTest(.{ .root_module = shared_mod });
    const run_shared_unit_tests = b.addRunArtifact(shared_unit_tests);
    test_step.dependOn(&run_shared_unit_tests.step);
    package_compile_step.dependOn(&shared_unit_tests.step);

    // Fork-isolation S5: every mono product owns a real ENGINE module. Its
    // tests must be collected by this binary; another module's root cannot
    // collect them (P5).
    const engine_unit_tests = b.addTest(.{ .root_module = seam.engine });
    const run_engine_unit_tests = b.addRunArtifact(engine_unit_tests);
    test_step.dependOn(&run_engine_unit_tests.step);
    package_compile_step.dependOn(&engine_unit_tests.step);

    // S6: per-module tls_backend test binary (P5 — adapter unit tests live there).
    if (seam.tls_backend) |tls_backend_mod| {
        const tls_unit_tests = b.addTest(.{ .root_module = tls_backend_mod });
        const run_tls_unit_tests = b.addRunArtifact(tls_unit_tests);
        test_step.dependOn(&run_tls_unit_tests.step);
        package_compile_step.dependOn(&tls_unit_tests.step);
    }

    // ── FFI C-ABI shared library (iroh-ffi language packages) ────────────
    // `zig build ffi` — the native artifact the Kotlin / Python / Swift
    // packages bind: libiroh_ffi.so plus its C header. Additive layer over
    // the public Endpoint facade (src/ffi/c_api.zig); the core API and the
    // key-material surface are unchanged (only the public node id crosses).
    const ffi_version = b.fmt("zig-iroh-ffi/{s}+{s}", .{ product_name, git_hash });
    const ffi_build_options = b.addOptions();
    ffi_build_options.addOption([]const u8, "version", ffi_version);
    const ffi_mod = b.createModule(.{
        .root_source_file = b.path("src/ffi/c_api.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ffi_mod.addImport("zig_iroh", root_mod);
    ffi_mod.addOptions("build_options", ffi_build_options);
    const ffi_lib = b.addLibrary(.{
        .name = "iroh_ffi",
        .linkage = .dynamic,
        .root_module = ffi_mod,
    });
    const ffi_install = b.addInstallArtifact(ffi_lib, .{});
    const ffi_header = b.addInstallHeaderFile(b.path("src/ffi/iroh_ffi.h"), "iroh_ffi.h");
    const ffi_step = b.step("ffi", "Build the iroh C-ABI shared library (libiroh_ffi) + C header");
    ffi_step.dependOn(&ffi_install.step);
    ffi_step.dependOn(&ffi_header.step);

    // `zig build test-all-mono-products` — the engine-coverage gate that
    // replaced `-Dproduct=default`. Every product is mono now, so no single
    // build compiles both engines; this re-invokes the build once per product
    // id so CI still exercises picoquic AND noq (and both TLS backends).
    const all_products_step = b.step(
        "test-all-mono-products",
        "Run `test` once per product id (both engines, both TLS backends)",
    );
    inline for (@typeInfo(products.Id).@"enum".fields) |field| {
        const per_product = b.addSystemCommand(&.{
            b.graph.zig_exe,
            "build",
            "-Dproduct=" ++ field.name,
            "test",
        });
        per_product.setCwd(b.path("."));
        per_product.has_side_effects = true;
        all_products_step.dependOn(&per_product.step);
    }

    // S7 closure guard: the named-module assertions in createSeamModules cover
    // build wiring; this source lint catches forbidden direct imports that
    // bypass that table and would let shared depend on an engine or legacy.
    const module_closure_check = b.addSystemCommand(&.{
        "python3",
        "scripts/check_module_closure.py",
    });
    module_closure_check.setCwd(b.path("."));
    const module_closure_step = b.step(
        "check-module-closure",
        "Assert shared imports neither an engine nor the retired legacy module",
    );
    module_closure_step.dependOn(&module_closure_check.step);

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
    // (one filtered gate = one helper call; the
    // combined gates depend on the per-test steps instead of compiling a
    // duplicate filtered root_mod binary — 0.16 filters are compile-time, so
    // every distinct filter set is a full library recompile.)
    const s2_transport_step = addFilteredTestStep(b, root_mod, "test-transport-s2", "Run focused S2 real-QUIC transport test", &.{"S2: Transport connect/accept and bi stream use real picoquic over UDP"});
    const s4_transport_step = addFilteredTestStep(b, root_mod, "test-transport-s4", "Run focused S4 relay fallback transport test", &.{"S4: relay fallback transfers a bi stream when direct paths are unavailable"});
    const transport_stability_step = b.step("test-transport-stability", "Run focused S2/S4 transport stability tests");
    transport_stability_step.dependOn(s2_transport_step);
    transport_stability_step.dependOn(s4_transport_step);

    // G2 greenfield endpoint lifecycle tests (transport/endpoint.zig): the
    // focal subset for the G2 TLS-handshake/close flake hunt
    // — iterate them much
    // faster than the full suite to establish a repro rate. (The "G2:"
    // prefix also matches the frame/connection G2 unit tests; they are fast
    // and harmless to include.)
    _ = addFilteredTestStep(b, root_mod, "test-endpoint-g2", "Run G2 greenfield endpoint lifecycle tests", &.{"G2:"});

    // VC carryover regressions (recvReader / path isolation / lockPump).
    _ = addFilteredTestStep(b, root_mod, "test-vc-carryover", "Run port-hardening-v3-carryover regression tests", &.{
        "recvReader survives peer stream reset without process abort",
        "two dials keep isolated magicsock path state",
        "lockPump acquires under contention with bounded backoff",
    });

    // Protocol accept-path tests (Router accept/on_accepting/reaping). Focused
    // target for the poll-with-timeout flake-hardening gate (N>=20 reruns).
    // Fork-isolation S3: protocol.zig moved to shared/ — its tests are
    // collected by the SHARED module, so this step filters shared_mod.
    _ = addFilteredTestStep(b, shared_mod, "test-protocol-accept", "Run protocol accept-path tests", &.{
        "ProtocolHandler.on_accepting",
        "router serves the registered ALPN",
        "router serves two distinct ALPNs",
        "router reaps completed handler threads",
    });

    // Transport characterization belongs to the extracted picoquic engine;
    // filter its OWN test root so the moved tests remain collected (P5).
    const char_greenfield_step: *std.Build.Step = if (product.picoquic)
        addFilteredTestStep(b, seam.engine, "test-transport-char-greenfield", "Run the transport characterization suite against the greenfield backend", &.{"CHAR greenfield"})
    else
        &b.addFail("test-transport-char requires -Dproduct=picoquic-picotls").step;

    const char_step = b.step("test-transport-char", "Run the full transport characterization suite");
    char_step.dependOn(char_greenfield_step);
    _ = addFilteredTestStep(b, root_mod, "test-one", "one", &.{"CHAR greenfield: bi echo"});

    // F13 QAD client vs a real Zig QAD server. zigtls is product-pinned, so run
    // this under `-Dproduct=noq-zigtls`; other products skip the zigtls cases.
    // Filters match both the happy-path observe test and the wrong-trust
    // mutation-red control (prefix "F13 QAD client").
    const qad_client_tests = b.addTest(.{
        .root_module = root_mod,
        .filters = &.{"F13 QAD client"},
    });
    const run_qad_client_tests = b.addRunArtifact(qad_client_tests);
    const qad_client_step = b.step(
        "test-qad-client",
        "Run the QAD Client-vs-Zig-QAD-Server address-discovery tests (use -Dproduct=noq-zigtls)",
    );
    qad_client_step.dependOn(&run_qad_client_tests.step);

    // Certificate-validation production matrix (chain/hostname/trust/OCSP
    // positive+negative+mutation-red on the real QAD X.509 path).
    const cert_matrix_tests = b.addTest(.{
        .root_module = root_mod,
        .filters = &.{"cert-matrix:"},
    });
    const run_cert_matrix_tests = b.addRunArtifact(cert_matrix_tests);
    const cert_matrix_step = b.step(
        "test-cert-val-matrix",
        "Run the X.509 cert-validation production matrix (use -Dproduct=noq-zigtls)",
    );
    cert_matrix_step.dependOn(&run_cert_matrix_tests.step);

    // Multi-relay map probe gate (relay-multi-relay-map-config mutation-red).
    // Fork-isolation S3: the test lives in endpoint.zig, now in shared/.
    _ = addFilteredTestStep(
        b,
        shared_mod,
        "test-multi-relay-map",
        "Run multi-relay map selection/probe gate (dead-first → live-second)",
        &.{"online probes past a dead first relay to a live second"},
    );

    // Pkarr publication lifecycle + relay publication controls
    // (core-pkarr-address-lookup-provider): TTL observed on the wire record,
    // relay-only filter default, republish-on-interval vs far-interval-stale,
    // plus the two endpoint publish gates they compose with.
    // Fork-isolation S3: these tests live in endpoint.zig, now in shared/.
    _ = addFilteredTestStep(
        b,
        shared_mod,
        "test-pkarr-publish-controls",
        "Run pkarr publish controls + republish lifecycle gates",
        &.{
            "Endpoint.online pkarr publish controls",
            "Endpoint.online pkarr republish",
            "Endpoint.online custom + local pkarr publishes relay-only record",
            "Endpoint.online publishes advertised external addresses via pkarr",
        },
    );

    // Frame-by-frame audit tag density + version gates.
    _ = addFilteredTestStep(
        b,
        root_mod,
        "test-relay-frame-audit",
        "Run relay wire frame-by-frame tag 0..13 audit coverage",
        &.{"frame-by-frame audit: tags 0..13 dense and version-gated"},
    );

    // C4 preflight: prove the reference trees are pinned, the
    // Cargo wiring + C patches are applied, and the peer mirrors are current BEFORE
    // any cargo-spawning gate runs — fail fast with the exact materialization remedy
    // (interop/rust-peer/README.md#fresh-materialization-recipe), not an opaque cargo error.
    // --root=.. : trees root = the zig package's parent (in a plain
    // checkout; in a jj lane it is the lane parent whose reference trees are
    // symlinks to the shared trees). Tracked inputs resolve from the script's own root.
    const reference_preflight = b.addSystemCommand(&.{"python3"});
    reference_preflight.addFileArg(b.path("scripts/check_reference_sha.py"));
    reference_preflight.addArg("--root=..");
    // The C patch sources belong to this inner workspace, not the shared outer root.
    reference_preflight.addArg("--source-root=.");
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
    reference_preflight_selftest.addFileArg(b.path("scripts/check_reference_sha.py"));
    reference_preflight_selftest.addArg("--root=..");
    reference_preflight_selftest.addArg("--source-root=.");
    reference_preflight_selftest.addArg("--self-test");

    // Shared interop peer lifecycle helper: deadline-on-read watchdog,
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
    rust_peer_sync_check.addFileArg(b.path("scripts/sync_rust_peer_examples.py"));
    rust_peer_sync_check.addArg("--check");
    // Trees root = the zig package's parent (lane parent in jj lanes —
    // same split as the C4 preflight). Sources resolve from the script's own root.
    rust_peer_sync_check.addArg("--root");
    rust_peer_sync_check.addArg("..");
    const rust_peer_sync_step = b.step("rust-peer-sync-check", "Check Rust peer examples mirror the source examples");
    rust_peer_sync_step.dependOn(&rust_peer_sync_check.step);
    run_bench.step.dependOn(&rust_peer_sync_check.step);
    const bench_step = b.step("bench", "Run benchmark smoke telemetry (needs the reference and script trees)");
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

    // `zig build test-pico-single-cpu` — product-level regression for the
    // 2026-08-09 single-CPU deadlock: under a 1-CPU taskset pin the pico
    // greenfield actor loop used to inline via Io.async (async_limit=0) and
    // hang with zero OutDatagrams. Wire-observable handshake under the pin
    // is the floor. Pico-only; other products report N/A.
    const pico_single_cpu_step = b.step(
        "test-pico-single-cpu",
        "Pico product: cross-host-bench transfer under taskset -c 3 (single-CPU deadlock regression)",
    );
    if (product.picoquic) {
        const run_single_cpu = b.addSystemCommand(&.{
            "bash", "-c",
            // bash -c sets the first post-script arg as $0 (not $1).
            \\set -euo pipefail
            \\BIN="$0"
            \\test -x "$BIN"
            \\PORT=$((18780 + ($$ % 200)))
            \\SCRATCH="$(mktemp -d)"
            \\trap 'kill $APID 2>/dev/null || true; wait $APID 2>/dev/null || true; rm -rf "$SCRATCH"' EXIT
            \\taskset -c 3 "$BIN" anchor --bind "127.0.0.1:$PORT" --public "127.0.0.1:$PORT" --bytes 65536 --trials 1 \
            \\  >"$SCRATCH/anchor.log" 2>&1 &
            \\APID=$!
            \\# give the pinned anchor a moment to bind
            \\for _ in 1 2 3 4 5 6 7 8 9 10; do
            \\  if grep -q 'ANCHOR_BOUND_PORT' "$SCRATCH/anchor.log" 2>/dev/null; then break; fi
            \\  sleep 0.2
            \\done
            \\timeout 30 taskset -c 3 "$BIN" requester --peer "127.0.0.1:$PORT" --bytes 65536 --trials 1 \
            \\  >"$SCRATCH/req.log" 2>&1
            \\grep -q '"success":true' "$SCRATCH/req.log"
            \\grep -q 'BENCH' "$SCRATCH/req.log"
            \\echo "test-pico-single-cpu OK (taskset -c 3, 64 KiB transfer, success:true)"
            ,
        });
        run_single_cpu.addArtifactArg(cross_host_exe);
        run_single_cpu.has_side_effects = true;
        run_single_cpu.step.dependOn(&install_cross_host.step);
        pico_single_cpu_step.dependOn(&run_single_cpu.step);
    } else {
        const na = b.addSystemCommand(&.{
            "sh", "-c",
            "echo \"test-pico-single-cpu: N/A for product '$0' (picoquic only)\"",
            product_name,
        });
        pico_single_cpu_step.dependOn(&na.step);
    }

    // `zig build evented-probe` — EXPERIMENTAL std.Io.Evented (Uring) probe.
    // Patches a local std overlay (does NOT touch the shared toolchain), then
    // builds+runs tools/evented_probe.zig against it. Default `-Deventing=false`
    // leaves product builds byte-identical; this step is opt-in only and is
    // never a dependency of `test` / package / default.
    // (`eventing` is also exported via build_options for consumers.)
    {
        const evented_step = b.step(
            "evented-probe",
            "EXPERIMENTAL: patch std overlay + build/run std.Io.Evented UDP probe (opt-in)",
        );
        const run_evented = b.addSystemCommand(&.{
            "bash", "-c",
            \\set -euo pipefail
            \\ROOT="$(pwd)"
            \\OVERLAY="$ROOT/zig-cache/evented-std"
            \\mkdir -p "$ROOT/zig-out/bin"
            \\python3 "$ROOT/tools/patch_evented_std.py" --out "$OVERLAY"
            \\zig build-exe "$ROOT/tools/evented_probe.zig" \
            \\  --zig-lib-dir "$OVERLAY" \
            \\  -femit-bin="$ROOT/zig-out/bin/evented-probe" \
            \\  -OReleaseSafe
            \\"$ROOT/zig-out/bin/evented-probe"
        });
        evented_step.dependOn(&run_evented.step);
    }

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

    // `zig build -Dproduct=<mono> check-mono-differential-compile` — COMPILE-ONLY
    // assertion that bench/differential.zig builds under a mono product. This
    // class hid because package-check previously bailed at the missing packaged
    // zigtls source; F2 unmasked it when differential began compiling under a
    // mono `tr.Connection` (no `context` field). Depending on the exe's compile
    // step (NOT the run) makes this a durable compile gate with no peer/env
    // sensitivity. Run once per mono product that ships package-check.
    const check_mono_differential_compile_step = b.step(
        "check-mono-differential-compile",
        "Compile-only gate: differential benchmark under a mono product Connection seam",
    );
    check_mono_differential_compile_step.dependOn(&differential_exe.step);

    // `zig build gen-stream-vectors` — regenerate the committed noq-engine stream
    // capability wire vectors. A reviewed golden amendment (Tier-0: goldens are
    // never auto-updated); the replay gate runs in `zig build test`.
    const stream_vec_gen_mod = b.createModule(.{
        .root_source_file = b.path("tools/stream_capability_vector_gen.zig"),
        .target = target,
        .optimize = optimize,
    });
    stream_vec_gen_mod.addImport("zig_iroh", root_mod);
    const stream_vec_gen_exe = b.addExecutable(.{ .name = "stream-capability-vector-gen", .root_module = stream_vec_gen_mod });
    const run_stream_vec_gen = b.addRunArtifact(stream_vec_gen_exe);
    const stream_vec_gen_step = b.step("gen-stream-vectors", "Regenerate vectors/transport/stream-capabilities.json (reviewed golden amendment)");
    stream_vec_gen_step.dependOn(&run_stream_vec_gen.step);

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
    // Surface the diff report (per-fixture NOQ_WIRE_DIFF pass lines + the
    // NOQ_WIRE_DIFF_SUMMARY total=N unexpected=M line the floor's diff-count marker policy
    // grades) in gate.log. Do NOT rely on the Run child writing to an inherited fd under
    // the remote gate's plain `> gate.log 2>&1` redirect: std.Io.File.writer defaults to
    // positional pwrite, which does NOT advance the shared file position, so a later
    // child's plain write(2) silently overwrites earlier output (measured locally: the
    // cargo verify step clobbered the exe's first 1426 bytes; the summary survived only by
    // byte-count luck). Capture to an artifact instead (pipe -> single-writer cache file,
    // immune to fd-position games) and re-emit via a system-command step, the same output
    // class as the cargo verify below whose lines provably land intact and ordered.
    const noq_wire_diff_stdout = run_noq_wire_diff.captureStdOut(.{
        .basename = "noq-wire-diff.stdout",
        .trim_whitespace = .none,
    });
    const noq_wire_diff_echo = b.addSystemCommand(&.{"cat"});
    noq_wire_diff_echo.addFileArg(noq_wire_diff_stdout);

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
    noq_wire_diff_step.dependOn(&noq_wire_diff_echo.step);

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

    // `zig build blobs-ticket-diff` — real iroh-blobs BlobTicket bytes/string.
    const blobs_ticket_fixture_gen = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
    });
    blobs_ticket_fixture_gen.addFileArg(b.path("tools/blobs_observe_push_fixture_gen/Cargo.toml"));
    blobs_ticket_fixture_gen.addArgs(&.{ "--", "--ticket-only" });
    blobs_ticket_fixture_gen.setEnvironmentVariable("CARGO_TARGET_DIR", ".zig-cache/blobs-observe-push-fixture-target");
    const blobs_ticket_fixture = blobs_ticket_fixture_gen.captureStdOut(.{
        .basename = "blobs-ticket-rust-fixture.json",
    });
    const blobs_ticket_diff_mod = b.createModule(.{
        .root_source_file = b.path("tools/blobs_ticket_diff.zig"),
        .target = target,
        .optimize = optimize,
    });
    blobs_ticket_diff_mod.addImport("zig_iroh", root_mod);
    const blobs_ticket_diff_exe = b.addExecutable(.{
        .name = "blobs-ticket-diff",
        .root_module = blobs_ticket_diff_mod,
    });
    const run_blobs_ticket_diff = b.addRunArtifact(blobs_ticket_diff_exe);
    run_blobs_ticket_diff.addFileArg(blobs_ticket_fixture);
    const blobs_ticket_diff_step = b.step("blobs-ticket-diff", "Diff BlobTicket bytes/string against real iroh-blobs");
    blobs_ticket_diff_step.dependOn(&run_blobs_ticket_diff.step);

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
    // Truthful naming: this graph builds the C engine
    // UN-sanitized, so C-side UAF is invisible here (Zig-side safety + the Zig test
    // allocator's leak checks only). The sanitized-C UNIT gate is `test-safe-c`
    // (below); the sanitized INTEROP gate is `safety-sanitizers`.
    const safe_root_mod = b.addModule("zig_iroh_safe", .{
        .root_source_file = b.path(b.fmt("src/products/{s}/root.zig", .{product_name})),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
    });
    const safe_seam = createSeamModules(b, product_name, target, .ReleaseSafe, build_options_module, tls_dep.module("tls"), product.noq, safety_zigtls_mod, null, product);
    const safe_root_surface_mod = b.createModule(.{
        .root_source_file = b.path("src/products/root_surface_fixture.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });
    safe_root_mod.addImport("root_surface", safe_root_surface_mod);
    safe_root_mod.addImport("shared", safe_seam.shared);
    safe_root_mod.addImport("transport", safe_seam.door);
    safe_root_mod.addImport("engine", safe_seam.engine);
    if (safe_seam.tls_backend) |tb| safe_root_mod.addImport("tls_backend", tb);
    if (safe_seam.tls_backend) |tb| {
        if (product.picotls and product.noq) {
            configureTlsBackendPicotlsNativeDeps(b, tb, materialized_c_deps, picotls, &c_flags);
        }
    }
    if (product.picoquic) {
        configurePicoquicEngineNativeDeps(b, safe_seam.engine, materialized_c_deps, picoquic.?, &c_flags);
    }
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
        .root_source_file = b.path(b.fmt("src/products/{s}/root.zig", .{product_name})),
        .target = target,
        .optimize = .ReleaseSafe,
        .link_libc = true,
        .sanitize_c = .full,
    });
    const safety_seam = createSeamModules(b, product_name, target, .ReleaseSafe, build_options_module, safety_tls_dep.module("tls"), product.noq, safety_zigtls_mod, .full, product);
    const safety_root_surface_mod = b.createModule(.{
        .root_source_file = b.path("src/products/root_surface_fixture.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });
    safety_root_mod.addImport("root_surface", safety_root_surface_mod);
    safety_root_mod.addImport("shared", safety_seam.shared);
    safety_root_mod.addImport("transport", safety_seam.door);
    safety_root_mod.addImport("engine", safety_seam.engine);
    if (safety_seam.tls_backend) |tb| safety_root_mod.addImport("tls_backend", tb);
    if (safety_seam.tls_backend) |tb| {
        if (product.picotls and product.noq) {
            configureTlsBackendPicotlsNativeDeps(b, tb, materialized_c_deps, safety_picotls, &c_sanitizer_flags);
        }
    }
    if (product.picoquic) {
        configurePicoquicEngineNativeDeps(b, safety_seam.engine, materialized_c_deps, safety_picoquic.?, &c_sanitizer_flags);
        linkAsanRuntime(b, safety_seam.engine, asan_lib_path);
    }

    // `test-safe-c` — unit suite under ReleaseSafe + sanitized C (ASan).
    // `test-releasesafe` still links the UN-sanitized `picoquic` (above); C-side UAF is
    // invisible there. The sanitized-C UAF gates use this target. The mutation control: rewiring
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
    relay_mod.addImport("zig_iroh", relay_root_mod);
    relay_mod.addImport("tls", tls_dep.module("tls"));
    const relay_exe = b.addExecutable(.{ .name = "relay", .root_module = relay_mod });
    const install_relay = b.addInstallArtifact(relay_exe, .{});
    const relay_step = b.step("relay", "Build the relay server binary");
    relay_step.dependOn(&install_relay.step);

    // Compatibility target retained for automation: it now compiles the final
    // relay-server public root, not an S1 legacy scaffold.
    const relay_scaffold_tests = b.addTest(.{ .root_module = relay_root_mod });
    const run_relay_scaffold_tests = b.addRunArtifact(relay_scaffold_tests);
    const relay_scaffold_step = b.step("test-relay-scaffold", "Run the relay-server final product-root seam proof");
    relay_scaffold_step.dependOn(&run_relay_scaffold_tests.step);
    // The relay binary is a shipped product surface: its compile must hold
    // from a clean package extract too (the 2026-07-23 parity scan caught the
    // archive shipping relay_main.zig without anything compiling it).
    package_compile_step.dependOn(&relay_exe.step);

    // `zig build test-relay` — standalone relay round-trip test (ws:// + wss://).
    const rt_mod = b.createModule(.{
        .root_source_file = b.path("relay_roundtrip_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    rt_mod.addImport("tls", tls_dep.module("tls"));
    // S4: module-style (the doorless harness_shared_mod is retired) — the
    // doored shared instance serves this root; it path-imports nothing.
    rt_mod.addImport("shared", shared_mod);
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
    const install_relay_interop = b.addInstallArtifact(relay_interop_exe, .{});
    const run_relay_interop = b.addRunArtifact(relay_interop_exe);
    const relay_interop_step = b.step("relay-interop", "Run real iroh-relay interop gate");
    relay_interop_step.dependOn(&reference_preflight.step);
    relay_interop_step.dependOn(&run_relay_interop.step);

    // `zig build pkarr-resolver` — self-hostable discovery resolver.
    const resolver_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/discovery/resolver_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    resolver_mod.addImport("zig_iroh", root_mod);
    const resolver_exe = b.addExecutable(.{ .name = "pkarr-resolver", .root_module = resolver_mod });
    const install_resolver = b.addInstallArtifact(resolver_exe, .{});
    const resolver_step = b.step("pkarr-resolver", "Build pkarr resolver executable");
    resolver_step.dependOn(&install_resolver.step);

    // `zig build iroh-dns-server` — pkarr relay + authoritative DNS + DoH product.
    const dns_server_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/dns_server/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    dns_server_mod.addImport("zig_iroh", root_mod);
    const dns_server_exe = b.addExecutable(.{ .name = "iroh-dns-server", .root_module = dns_server_mod });
    const install_dns_server = b.addInstallArtifact(dns_server_exe, .{});
    const dns_server_step = b.step("iroh-dns-server", "Build the iroh-dns-server product binary");
    dns_server_step.dependOn(&install_dns_server.step);
    package_compile_step.dependOn(&dns_server_exe.step);

    // `zig build iroh-dns-pkarr` — operator CLI that publishes/resolves signed
    // packets against a pkarr relay (the client side of `/pkarr/{z32}`).
    const pkarr_cli_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/dns_server/pkarr_cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    pkarr_cli_mod.addImport("zig_iroh", root_mod);
    const pkarr_cli_exe = b.addExecutable(.{ .name = "iroh-dns-pkarr", .root_module = pkarr_cli_mod });
    const install_pkarr_cli = b.addInstallArtifact(pkarr_cli_exe, .{});
    const pkarr_cli_step = b.step("iroh-dns-pkarr", "Build the pkarr publish/resolve CLI");
    pkarr_cli_step.dependOn(&install_pkarr_cli.step);
    // Shipped alongside the server, so a clean package extract must compile it.
    package_compile_step.dependOn(&pkarr_cli_exe.step);
    dns_server_step.dependOn(&install_pkarr_cli.step);

    // `zig build dns-server-serve-gate` — UAF guard: serve real UDP+DoH under ReleaseSafe.
    const serve_gate_optimize: std.builtin.OptimizeMode = if (b.option(bool, "dns_serve_gate_debug", "Run dns-server-serve-gate in Debug") orelse false)
        .Debug
    else
        .ReleaseSafe;
    const serve_gate_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/dns_server/serve_gate.zig"),
        .target = target,
        .optimize = serve_gate_optimize,
    });
    // serve_gate pulls server.zig (+ siblings) directly; they import ../root via dns.zig.
    // Provide the same module graph as unit tests by compiling against root.
    serve_gate_mod.addImport("zig_iroh", root_mod);
    const serve_gate_exe = b.addExecutable(.{ .name = "dns-server-serve-gate", .root_module = serve_gate_mod });
    const run_serve_gate = b.addRunArtifact(serve_gate_exe);
    // The gate drives the CLI as a child process, so it needs the built binary's path.
    run_serve_gate.addFileArg(pkarr_cli_exe.getEmittedBin());
    const serve_gate_step = b.step("dns-server-serve-gate", "Serve UDP+DoH against returned Server (ReleaseSafe UAF guard)");
    serve_gate_step.dependOn(&run_serve_gate.step);

    // `zig build dns-cross-impl-oracle` — absent-012: the REAL Rust
    // `PkarrRelayClient` (iroh crate example `dns_pkarr_cross_impl`) against a
    // LIVE Zig iroh-dns-server: Rust verifies a Zig-signed record, then Rust
    // signs+publishes+re-resolves its own record, and Zig verifies it + serves
    // it through the authoritative DNS TXT path. Prebuild the example (cold
    // cargo is minutes) as a build step; the gate warm-launches via cargo run.
    const rust_pkarr_peer_prebuild = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--locked",
        "--manifest-path",
        "../iroh/Cargo.toml",
        "--example",
        "dns_pkarr_cross_impl",
    });
    configureRustPeerRun(rust_pkarr_peer_prebuild);
    rust_pkarr_peer_prebuild.step.dependOn(&reference_preflight.step);
    rust_pkarr_peer_prebuild.step.dependOn(&rust_peer_sync_check.step);

    const dns_cross_impl_mod = b.createModule(.{
        .root_source_file = b.path("dns_cross_impl_oracle.zig"),
        .target = target,
        .optimize = optimize,
    });
    dns_cross_impl_mod.addImport("zig_iroh", root_mod);
    dns_cross_impl_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    const dns_cross_impl_exe = b.addExecutable(.{ .name = "dns-cross-impl-oracle", .root_module = dns_cross_impl_mod });
    const run_dns_cross_impl = b.addRunArtifact(dns_cross_impl_exe);
    run_dns_cross_impl.step.dependOn(&rust_pkarr_peer_prebuild.step);
    const dns_cross_impl_step = b.step("dns-cross-impl-oracle", "Real Rust PkarrRelayClient vs LIVE Zig iroh-dns-server (cross-impl pkarr oracle)");
    dns_cross_impl_step.dependOn(&run_dns_cross_impl.step);

    // `zig build blobs-quic-interop` — blobs over real QUIC gate.
    const blobs_quic_mod = b.createModule(.{
        .root_source_file = b.path("src/blobs_quic_interop.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    // Fork-isolation S1: consumes the library via the `zig_iroh` module (its
    // compilation now contains root_mod+shared+door; path-importing the tree
    // from here would dual-member files). Native deps flow from root_mod.
    blobs_quic_mod.addImport("zig_iroh", root_mod);
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
    // Fork-isolation S1: module-import conversion (see blobs_quic_mod note).
    blobs_interop_mod.addImport("zig_iroh", root_mod);
    // Exe form (W2 #4): a zig test binary's stdout is the runner's --listen protocol
    // channel — raw BENCH writes from a test deadlock the runner. Exe = real stdout.
    const blobs_interop_exe = b.addExecutable(.{ .name = "blobs-interop", .root_module = blobs_interop_mod });
    const install_blobs_interop = b.addInstallArtifact(blobs_interop_exe, .{});
    const run_blobs_interop = b.addRunArtifact(blobs_interop_exe);
    const blobs_interop_step = b.step("blobs-interop", "Run real iroh-blobs provider interop gate");
    blobs_interop_step.dependOn(&reference_preflight.step);
    blobs_interop_step.dependOn(&run_blobs_interop.step);

    // `zig build blobs-policy-deny-interop` — reverse-direction deny path:
    // Zig provider under policy deny/rate-limit; real rust iroh-blobs client
    // observes RESET_STREAM application codes 1/2 on the wire.
    const blobs_policy_deny_mod = b.createModule(.{
        .root_source_file = b.path("src/blobs_policy_deny_interop.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    blobs_policy_deny_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    // Fork-isolation S1: module-import conversion (see blobs_quic_mod note).
    blobs_policy_deny_mod.addImport("zig_iroh", root_mod);
    const blobs_policy_deny_exe = b.addExecutable(.{
        .name = "blobs-policy-deny-interop",
        .root_module = blobs_policy_deny_mod,
    });
    const run_blobs_policy_deny = b.addRunArtifact(blobs_policy_deny_exe);
    const blobs_policy_deny_step = b.step(
        "blobs-policy-deny-interop",
        "Run real-peer blobs policy deny interop (Zig provider → rust client, codes 1/2)",
    );
    blobs_policy_deny_step.dependOn(&reference_preflight.step);
    blobs_policy_deny_step.dependOn(&run_blobs_policy_deny.step);

    // `zig build discovery-live-interop` — live iroh DoH interop gate.
    const live_interop_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/discovery/live_interop_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    live_interop_mod.addImport("zig_iroh", root_mod);
    const live_interop_exe = b.addExecutable(.{ .name = "discovery-live-interop", .root_module = live_interop_mod });
    const run_live_interop = b.addRunArtifact(live_interop_exe);
    const live_interop_step = b.step("discovery-live-interop", "Run live iroh DoH discovery interop gate");
    live_interop_step.dependOn(&run_live_interop.step);

    // `zig build discovery-live-canary` — publish a project-owned record to
    // the REAL dns.iroh.link pkarr relay, then resolve `_iroh.<z32>.dns.iroh.link`
    // via PUBLIC DoH (cloudflare-dns.com, dns.google) on the production path.
    const live_canary_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/discovery/live_canary_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    live_canary_mod.addImport("zig_iroh", root_mod);
    const live_canary_exe = b.addExecutable(.{ .name = "discovery-live-canary", .root_module = live_canary_mod });
    const run_live_canary = b.addRunArtifact(live_canary_exe);
    const live_canary_step = b.step("discovery-live-canary", "Run live public discovery canary (real dns.iroh.link publish + public DoH resolve)");
    live_canary_step.dependOn(&run_live_canary.step);

    // `zig build iroh-oracle` — honest iroh integration-suite oracle floor.
    // N-row report card: control green (overlap/control) + converted rows with
    // honest pass|fail|blocked. False green / control regression / harness crash
    // fails the step; honest reds do not.
    // Native C sources live on their owning library module (legacy for
    // noq-picotls, engine-picoquic for picoquic); do not re-apply either
    // native helper here or the RPK glue would link twice.
    const iroh_oracle_mod = b.createModule(.{
        .root_source_file = b.path("src/oracle/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    iroh_oracle_mod.addImport("zig_iroh", root_mod);
    iroh_oracle_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    // Fork-isolation S3: oracle/{shape,report}.zig moved to shared/oracle/;
    // the consumer module reaches them as @import("shared").oracle_{shape,report}
    // (same shared_mod instance root_mod already wires — one type graph).
    iroh_oracle_mod.addImport("shared", shared_mod);
    const iroh_oracle_exe = b.addExecutable(.{ .name = "iroh-oracle", .root_module = iroh_oracle_mod });
    const run_iroh_oracle = b.addRunArtifact(iroh_oracle_exe);
    // cwd = package root so relative original/ + src/ structural checks resolve.
    run_iroh_oracle.setCwd(b.path("."));
    const iroh_oracle_step = b.step("iroh-oracle", "Run iroh integration-suite oracle multi-row report-card gate");
    // The oracle EXECUTES the peers from the reference tree, not the tracked copies. If the
    // two have diverged, every real-peer row is measuring a peer nobody reviewed —
    // which on 2026-07-26 reported a product RED for a peer that simply predated the
    // lane's own `--datagram-server` support. Gate the divergence check ON the oracle,
    // where the mirror is actually load-bearing (it was previously wired only to `bench`).
    //
    // ORDERING MATTERS: this is a dependency of the RUN, not a sibling of the step.
    // Two `iroh_oracle_step.dependOn(...)` edges let Zig run both concurrently, so the
    // rows still execute against the stale peer and merely exit non-zero afterwards —
    // measured. Making the run depend on the check means a divergence STOPS the gate
    // before a single row is measured.
    run_iroh_oracle.step.dependOn(&rust_peer_sync_check.step);

    // `zig build -Dproduct=<mono> check-mono-iroh-oracle-compile` — COMPILE-ONLY
    // assertion that the datagram/path-instantiating oracle module builds under a
    // mono product. This class hid because `zig build test` (default product) keeps
    // `tr.Connection.context` and `noq-oracle` never instantiates the datagram API;
    // only `iroh-oracle` instantiates `connectionSendDatagram` & co. through
    // `src/oracle/runner.zig` under a mono `tr.Connection` (no `context` field).
    // Depending on the exe's compile step (NOT the run) makes this a durable
    // compile gate with no peer/environment sensitivity. Run once per mono product:
    //   noq-zigtls, noq-picotls, picoquic-picotls.
    const check_mono_iroh_oracle_compile_step = b.step(
        "check-mono-iroh-oracle-compile",
        "Compile-only gate: iroh-oracle datagram/path module under a mono product",
    );
    check_mono_iroh_oracle_compile_step.dependOn(&iroh_oracle_exe.step);

    // relay_operator_config spawns the production binary; keep it built.
    iroh_oracle_step.dependOn(&install_relay.step);
    // control_relay_datagram_forward executes the real relay-interop gate binary.
    iroh_oracle_step.dependOn(&install_relay_interop.step);
    // control_blobs_wire_get_push_observe: install-then-spawn (runner.runInstalledGateControl).
    // gossip-interop / gossip-sim / store+tags smokes install below (declared later).
    iroh_oracle_step.dependOn(&install_blobs_interop.step);
    iroh_oracle_step.dependOn(&run_iroh_oracle.step);

    // `zig build blobs-store-api-smoke` — Mem/Fs shared API + reopen durability.
    const blobs_store_smoke_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/blobs/store_api_smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    blobs_store_smoke_mod.addImport("zig_iroh", root_mod);
    const blobs_store_smoke_exe = b.addExecutable(.{ .name = "blobs-store-api-smoke", .root_module = blobs_store_smoke_mod });
    const install_blobs_store_smoke = b.addInstallArtifact(blobs_store_smoke_exe, .{});
    const run_blobs_store_smoke = b.addRunArtifact(blobs_store_smoke_exe);
    const blobs_store_smoke_step = b.step("blobs-store-api-smoke", "Run Mem/Fs Store API and durability smoke (blobs_store_api)");
    blobs_store_smoke_step.dependOn(&run_blobs_store_smoke.step);
    iroh_oracle_step.dependOn(&install_blobs_store_smoke.step);

    // `zig build blobs-tags-api-smoke` — Tags public API (oracle blobs_tags_api).
    const blobs_tags_smoke_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/blobs/tags_api_smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    blobs_tags_smoke_mod.addImport("zig_iroh", root_mod);
    const blobs_tags_smoke_exe = b.addExecutable(.{ .name = "blobs-tags-api-smoke", .root_module = blobs_tags_smoke_mod });
    const install_blobs_tags_smoke = b.addInstallArtifact(blobs_tags_smoke_exe, .{});
    const run_blobs_tags_smoke = b.addRunArtifact(blobs_tags_smoke_exe);
    const blobs_tags_smoke_step = b.step("blobs-tags-api-smoke", "Run Tags public API smoke (blobs_tags_api)");
    blobs_tags_smoke_step.dependOn(&run_blobs_tags_smoke.step);
    iroh_oracle_step.dependOn(&install_blobs_tags_smoke.step);

    // Unit tests for the N-row oracleGateOk predicate (conversion-sweep acceptance).
    const iroh_oracle_test_mod = b.createModule(.{
        .root_source_file = b.path("src/oracle/runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    iroh_oracle_test_mod.addImport("zig_iroh", root_mod);
    iroh_oracle_test_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    iroh_oracle_test_mod.addImport("shared", shared_mod); // S3: oracle shape/report in shared/
    const iroh_oracle_tests = b.addTest(.{ .root_module = iroh_oracle_test_mod });
    const run_iroh_oracle_tests = b.addRunArtifact(iroh_oracle_tests);
    const iroh_oracle_test_step = b.step("test-iroh-oracle", "Unit-test iroh-oracle N-row gate predicate");
    iroh_oracle_test_step.dependOn(&run_iroh_oracle_tests.step);

    // `zig build noq-oracle` — noq BEHAVIORAL oracle floor (D5 trajectory harness).
    // Control stream-echo green + honest fail/blocked for absent engine capabilities.
    // False green (GSO/0-RTT pass) or control non-pass fails the step.
    // Native C sources stay on their owning library module; re-applying a
    // native helper here would double-link the RPK glue.
    const noq_oracle_mod = b.createModule(.{
        .root_source_file = b.path("src/engine-noq/oracle/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    noq_oracle_mod.addImport("zig_iroh", root_mod);
    const noq_oracle_exe = b.addExecutable(.{ .name = "noq-oracle", .root_module = noq_oracle_mod });
    const run_noq_oracle = b.addRunArtifact(noq_oracle_exe);
    run_noq_oracle.setCwd(b.path("."));
    const noq_oracle_step = b.step("noq-oracle", "Run noq BEHAVIORAL oracle scaffold/control gate");
    noq_oracle_step.dependOn(&run_noq_oracle.step);

    // `zig build interop` — live picoquic interop handshake + byte checks.
    const interop_mod = b.createModule(.{
        .root_source_file = b.path("src/engine-picoquic/interop_tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    interop_mod.addImport("tls", tls_dep.module("tls"));
    interop_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    // Fork-isolation S5: module-style conversion (harness_shared_mod retired).
    // The root consumes the library via `zig_iroh`; picoquic native C flows
    // transitively from its selected engine module. Re-applying the engine
    // helper here would double-link rpk.c.
    interop_mod.addImport("shared", shared_mod);
    interop_mod.addImport("zig_iroh", root_mod);
    const interop_tests = b.addTest(.{ .root_module = interop_mod });
    const run_interop_tests = b.addRunArtifact(interop_tests);
    const interop_step = b.step("interop", "Run cross-impl interop integration gate");
    interop_step.dependOn(&reference_preflight.step);
    interop_step.dependOn(&run_interop_tests.step);

    // `zig build interop-noq` — greenfield noq client against the
    // same cargo-spawned real iroh server. Keep `interop` on picoquic.
    const noq_interop_mod = b.createModule(.{
        .root_source_file = b.path("src/engine-noq/harness/noq_interop_tests.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    noq_interop_mod.addImport("tls", tls_dep.module("tls"));
    noq_interop_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    // Fork-isolation S4: module-style conversion (harness_shared_mod retired).
    // The root consumes `zig_iroh` + `shared` + the selected `engine` by name.
    // Native C remains attached to its owning library module; re-applying a
    // native helper here would double-link RPK glue. This harness names engine
    // only on noq products; under picoquic the step remains non-functional.
    noq_interop_mod.addImport("shared", shared_mod);
    noq_interop_mod.addImport("zig_iroh", root_mod);
    if (product.noq) noq_interop_mod.addImport("engine", seam.engine);
    configureZigtlsFeature(noq_interop_mod, build_options_module, zigtls_mod);

    // The mirror check lives in the C4 reference-preflight now (all four peers,
    // lane-aware) — the old single-file `cmp` was both redundant and fragile outside
    // the shared-root layout (a jj lane has no ../interop sibling).
    const rust_peer_prebuild = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--locked",
        "--manifest-path",
        "../iroh/Cargo.toml",
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
        "../iroh/Cargo.toml",
        "--example",
        "noq_hostile_peer",
    });
    configureRustPeerRun(hostile_peer_prebuild);
    hostile_peer_prebuild.step.dependOn(&reference_preflight.step);

    // Keep picotls interop-noq as the regression anchor; zigtls probe is separate.
    // realpeer H1/M1/H3(+mutation-RED)/H5/H2 close the real-peer verification
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
    // Fork-isolation S4: the 5d-B server-side RPK spoof oracle lives in the
    // ENGINE module (engine-noq/harness/noq_gate.zig — the interop root can
    // no longer path-claim it without dual-membering the file). Same test,
    // same step, run from a FILTERED engine-module test artifact.
    if (product.noq) {
        const noq_gate_5db_tests = b.addTest(.{
            .root_module = seam.engine,
            .filters = &.{"5d-B: server learns a verified peer, mints a fresh CID, and rejects a spoofed RPK"},
        });
        const run_noq_gate_5db_tests = b.addRunArtifact(noq_gate_5db_tests);
        noq_interop_step.dependOn(&run_noq_gate_5db_tests.step);
    }

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
        .root_source_file = b.path("src/engine-noq/harness/noq_large_transfer_gate.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    noq_large_transfer_mod.addImport("tls", tls_dep.module("tls"));
    // Fork-isolation S4: module-style conversion (harness_shared_mod retired;
    // native deps flow from their owning module; this harness needs `engine`
    // only on noq products).
    noq_large_transfer_mod.addImport("shared", shared_mod);
    noq_large_transfer_mod.addImport("zig_iroh", root_mod);
    if (product.noq) noq_large_transfer_mod.addImport("engine", seam.engine);
    const noq_large_transfer_tests = b.addTest(.{
        .root_module = noq_large_transfer_mod,
        .filters = &.{"N-0"},
    });
    const run_noq_large_transfer_tests = b.addRunArtifact(noq_large_transfer_tests);
    const noq_large_transfer_step = b.step("test-noq-large-transfer", "Run production-boundary noq large-transfer gate (lossy/BDP/never-drain)");
    noq_large_transfer_step.dependOn(&run_noq_large_transfer_tests.step);

    // `zig build gossip-quic-interop` — Zig-to-Zig gossip over real QUIC (3a).
    const gossip_quic_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/gossip/gates/gossip_quic_test.zig"),
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
    // Fork-isolation S1: module-import conversion; the sanitized tree, native
    // deps, and ASan runtime all flow from safety_root_mod.
    safety_blobs_interop_mod.addImport("zig_iroh", safety_root_mod);
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
        .root_source_file = b.path("src/shared/gossip/gates/gossip_quic_test.zig"),
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
    // Serialize the three safety legs so their stdout cannot interleave under
    // parallel -jN (marker grading needs each PASS line intact in gate.log).
    run_safety_relay_interop.step.dependOn(&run_safety_blobs_interop.step);
    run_safety_gossip_quic.step.dependOn(&run_safety_relay_interop.step);
    safety_sanitizers_step.dependOn(&run_safety_gossip_quic.step);

    // `zig build safety-leaks` — run debug allocator interop leak checks.
    // Honest coverage: blobs via the Zig test allocator (leaks
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
    // Explicit package-relative corpus path — the harness's
    // built-in default ("fuzz/corpus") is cwd-relative and silently breaks from any
    // other cwd. A user --corpus still wins (parseArgs takes the last occurrence).
    run_fuzz_decoders.addArg("--corpus");
    run_fuzz_decoders.addFileArg(b.path("fuzz/corpus"));
    if (b.args) |args| run_fuzz_decoders.addArgs(args);
    const fuzz_decoders_step = b.step("fuzz-decoders", "Run bounded decoder fuzz harness");
    fuzz_decoders_step.dependOn(&run_fuzz_decoders.step);

    // Gate-integrity: prove the nets catch injected defects (not theater).
    // Nested gates (rebase onto lyntqrpm): product.picoquic OUTER (engine present?)
    // then devSourcePresent INNER (source present?). Both required.
    // These two probes intentionally import picoquic-only surfaces; do not pull
    // them into noq-only product builds where the engine is correctly elided.
    var uaf_inject_gate_dep: ?*std.Build.Step = null;
    if (product.picoquic) {
        // (1) C-side double picoquic_delete_cnx → ASan abort under safety_picoquic.
        // GATED: absent in the released package (bench/ is not shipped).
        if (devSourcePresent(b, "bench/uaf_inject_probe.zig")) {
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
            const uaf_inject_step = b.step("uaf-inject-probe", "injected C-side UAF must be caught by sanitized build (expect SIGABRT)");
            uaf_inject_step.dependOn(&run_uaf_inject.step);
            uaf_inject_gate_dep = &run_uaf_inject.step;
        }

        // The `quic-ownership-probe` step lived here. It pinned the exclusive-owner
        // panic of the legacy `transport/quic.zig` Endpoint (stopgap);
        // both the guard and the endpoint were retired with the default product, so
        // there is nothing left for it to mutate-RED against. The greenfield actor
        // owns its own loop instead of policing caller threads.
    } else {
        const uaf_disabled = b.addFail("uaf-inject-probe requires a product with picoquic enabled");
        const uaf_inject_step = b.step("uaf-inject-probe", "Picoquic-only UAF probe (disabled for this product)");
        uaf_inject_step.dependOn(&uaf_disabled.step);
    }

    // (2) Fuzz harness must exit nonzero when crashes > 0 (self-check path).
    const run_fuzz_crash_exit = b.addRunArtifact(fuzz_decoders_exe);
    configureAsanRun(run_fuzz_crash_exit);
    run_fuzz_crash_exit.addArg("--self-check-nonzero-on-crash");
    run_fuzz_crash_exit.expectExitCode(1);
    const fuzz_crash_exit_step = b.step("fuzz-crash-exit-probe", "fuzz step must fail when crashes > 0 (expect exit 1)");
    fuzz_crash_exit_step.dependOn(&run_fuzz_crash_exit.step);

    const gate_integrity_step = b.step("gate-integrity", "sanitized-C UAF catch + fuzz fail-on-crash + C4 preflight self-test");
    if (uaf_inject_gate_dep) |dep| gate_integrity_step.dependOn(dep);
    gate_integrity_step.dependOn(&run_fuzz_crash_exit.step);
    gate_integrity_step.dependOn(&reference_preflight_selftest.step);

    // Best-effort valgrind/memcheck second opinion on
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

    // Build the release archive only from build.zig.zon
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

    // Release-buildability is green only when the clean package and the
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
        .root_source_file = b.path("src/shared/gossip/gates/gossip_interop_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    gossip_interop_mod.addImport("zig_iroh", root_mod);
    gossip_interop_mod.addImport("interop_lifecycle", interop_lifecycle_mod);
    const gossip_interop_exe = b.addExecutable(.{ .name = "gossip-interop", .root_module = gossip_interop_mod });
    const install_gossip_interop = b.addInstallArtifact(gossip_interop_exe, .{});
    const run_gossip_interop = b.addRunArtifact(gossip_interop_exe);
    const gossip_interop_step = b.step("gossip-interop", "Run real iroh-gossip interop gate");
    gossip_interop_step.dependOn(&reference_preflight.step);
    gossip_interop_step.dependOn(&run_gossip_interop.step);
    // control_gossip_live_broadcast receipt-ingest (iroh-oracle declared earlier).
    iroh_oracle_step.dependOn(&install_gossip_interop.step);

    // `zig build gossip-sim` — in-process HyParView/PlumTree sim gate (oracle gossip_simulator).
    const gossip_sim_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/gossip/gates/gossip_sim_gate.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    gossip_sim_mod.addImport("zig_iroh", root_mod);
    const gossip_sim_exe = b.addExecutable(.{ .name = "gossip-sim", .root_module = gossip_sim_mod });
    const install_gossip_sim = b.addInstallArtifact(gossip_sim_exe, .{});
    const run_gossip_sim = b.addRunArtifact(gossip_sim_exe);
    const gossip_sim_step = b.step("gossip-sim", "Run in-process gossip simulator smoke gate");
    gossip_sim_step.dependOn(&run_gossip_sim.step);
    iroh_oracle_step.dependOn(&install_gossip_sim.step);

    // `zig build gossip-api` — public GossipApi / handles / lag / control / metrics gate.
    const gossip_api_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/gossip/gates/gossip_api_gate.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    gossip_api_mod.addImport("zig_iroh", root_mod);
    const gossip_api_exe = b.addExecutable(.{ .name = "gossip-api", .root_module = gossip_api_mod });
    const run_gossip_api = b.addRunArtifact(gossip_api_exe);
    const gossip_api_step = b.step("gossip-api", "Run public GossipApi topic-handle/lifecycle/control/metrics gate");
    gossip_api_step.dependOn(&run_gossip_api.step);

    // `zig build gossip-router` — Router + gossip ProtocolHandler composition gate.
    const gossip_router_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/gossip/gates/gossip_router_gate.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    gossip_router_mod.addImport("zig_iroh", root_mod);
    const gossip_router_exe = b.addExecutable(.{ .name = "gossip-router", .root_module = gossip_router_mod });
    const run_gossip_router = b.addRunArtifact(gossip_router_exe);
    const gossip_router_step = b.step("gossip-router", "Run Router+gossip multi-ALPN composition gate");
    gossip_router_step.dependOn(&run_gossip_router.step);

    // `zig build gossip-example` — runnable public-API example over real QUIC.
    const gossip_example_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/gossip/gates/gossip_example.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    gossip_example_mod.addImport("zig_iroh", root_mod);
    const gossip_example_exe = b.addExecutable(.{ .name = "gossip-example", .root_module = gossip_example_mod });
    const run_gossip_example = b.addRunArtifact(gossip_example_exe);
    const gossip_example_step = b.step("gossip-example", "Run gossip public-API example (two local peers)");
    gossip_example_step.dependOn(&run_gossip_example.step);

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

/// Short HEAD commit, or "unknown" when neither VCS can answer (exported
/// tarball, no git/jj on PATH).
///
/// `git rev-parse` first — it covers plain checkouts and the colocated root.
/// A `jj workspace add` tree has only `.jj`, so git fails there and the jj probe
/// is what makes the stamp work in a lane workspace. Both commands are read-only,
/// which the jj-colocation rule requires of anything `git`-shaped.
/// Fork-isolation §3.6: the declared module graph stays the intended graph.
/// Reads the import table beside the wiring it checks — it cannot go stale —
/// and runs at configure time of EVERY build of EVERY product (including the
/// default, closing the five-default-only-verifier gap class).
fn assertImportClosure(mod: *std.Build.Module, comptime allowed: []const []const u8) void {
    var it = mod.import_table.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        for (allowed) |ok| {
            if (std.mem.eql(u8, name, ok)) break;
        } else {
            std.debug.panic(
                "module-closure violation: module imports '{s}' outside its allowed set",
                .{name},
            );
        }
    }
}

const SeamModules = struct {
    shared: *std.Build.Module,
    door: *std.Build.Module,
    /// Fork-isolation S5: every mono product has one real selected engine.
    engine: *std.Build.Module,
    /// Fork-isolation S6: product-selected TLS backend (null on pico-only path
    /// that does not wire the noq crypto adapter).
    tls_backend: ?*std.Build.Module,
};

/// Create one selected product's shared/door/engine composition. S7 gives the
/// door direct `shared` + `engine` imports; neither side names a legacy root.
fn createSeamModules(
    b: *std.Build,
    product_name: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    build_options_module: *std.Build.Module,
    tls_module: *std.Build.Module,
    noq_engine: bool,
    zigtls_module: ?*std.Build.Module,
    sanitize_c: ?std.zig.SanitizeC,
    /// Product TLS axis: picotls backend vs zigtls backend vs none (pico only).
    product: products.Product,
) SeamModules {
    const shared_mod = b.createModule(.{
        .root_source_file = b.path("src/shared/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const door_mod = b.createModule(.{
        .root_source_file = b.path(b.fmt("src/products/{s}/transport_api.zig", .{product_name})),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    shared_mod.addImport("transport", door_mod);
    shared_mod.addImport("build_options", build_options_module);
    // S2: the relay data plane (WS/TLS wrapper) lives in shared; the external
    // `tls` package is engine-agnostic and inside shared's allowed set (§3.6).
    shared_mod.addImport("tls", tls_module);
    // The only shared-code seam: shared → transport door. The door in turn
    // binds its concrete product engine below.
    door_mod.addImport("shared", shared_mod);

    // S6: product-selected TLS backend module (`tls_backend` role name).
    // Picotls products (noq-picotls AND picoquic-picotls) both collect the
    // relocated adapter unit tests via a per-module binary (P5). Only the noq
    // engine imports `tls_backend` as a dependency — pico keeps its C-engine
    // TLS path and uses the module solely for test collection + future seams.
    const tls_backend_root: ?[]const u8 = if (product.zigtls == true)
        "src/tls-zigtls/adapter/root.zig"
    else if (product.picotls)
        "src/tls-picotls/root.zig"
    else
        null;

    const tls_backend_mod: ?*std.Build.Module = if (tls_backend_root) |root_path| blk: {
        const m = b.createModule(.{
            .root_source_file = b.path(root_path),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .sanitize_c = sanitize_c,
        });
        m.addImport("shared", shared_mod);
        m.addImport("build_options", build_options_module);
        if (zigtls_module) |zm| m.addImport("zigtls", zm);
        // Cycle-free: tls_backend → {shared, build_options, zigtls}
        assertImportClosure(m, &.{ "shared", "build_options", "zigtls" });
        break :blk m;
    } else null;

    const engine_root = if (noq_engine) "src/engine-noq/root.zig" else "src/engine-picoquic/root.zig";
    const engine_mod = b.createModule(.{
        .root_source_file = b.path(engine_root),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .sanitize_c = sanitize_c,
    });
    engine_mod.addImport("shared", shared_mod);
    engine_mod.addImport("transport", door_mod);
    if (noq_engine) {
        if (zigtls_module) |zm| engine_mod.addImport("zigtls", zm);
        if (tls_backend_mod) |tb| engine_mod.addImport("tls_backend", tb);
    }
    door_mod.addImport("engine", engine_mod);
    assertImportClosure(engine_mod, &.{ "shared", "transport", "zigtls", "tls_backend" });

    // The boundary IS this table (§3.2): shared may name nothing else.
    assertImportClosure(shared_mod, &.{ "transport", "build_options", "tls" });
    assertImportClosure(door_mod, &.{ "shared", "engine" });
    return .{ .shared = shared_mod, .door = door_mod, .engine = engine_mod, .tls_backend = tls_backend_mod };
}

fn resolveGitHash(b: *std.Build) []const u8 {
    const probes = [_][]const []const u8{
        &.{ "git", "rev-parse", "--short=12", "HEAD" },
        &.{ "jj", "log", "--no-graph", "-r", "@", "-T", "commit_id.short(12)" },
    };
    for (probes) |argv| {
        var code: u8 = 0;
        const out = b.runAllowFail(argv, &code, .ignore) catch continue;
        if (code != 0) continue;
        const trimmed = std.mem.trim(u8, out, " \t\r\n");
        if (trimmed.len == 0) continue;
        return b.dupe(trimmed);
    }
    return "unknown";
}

fn configureZigtlsFeature(
    module: *std.Build.Module,
    build_options_module: *std.Build.Module,
    zigtls_mod: ?*std.Build.Module,
) void {
    module.addImport("build_options", build_options_module);
    if (zigtls_mod) |mod| module.addImport("zigtls", mod);
}

/// S6: picotls RPK setup glue + libpicotls + OpenSSL attach to the
/// `tls_backend` module (noq-picotls). Picoquic products attach their own
/// natives via configurePicoquicEngineNativeDeps.
fn configureTlsBackendPicotlsNativeDeps(
    b: *std.Build,
    mod: *std.Build.Module,
    deps: std.Build.LazyPath,
    picotls_lib: ?*std.Build.Step.Compile,
    c_flags_slice: []const []const u8,
) void {
    addPicotlsIncludes(mod, b, deps);
    // Resolves `rpk_picotls.h` from the tls-picotls module root.
    mod.addIncludePath(b.path("src/tls-picotls"));
    mod.addCSourceFiles(.{
        .root = b.path("."),
        .files = &.{"src/tls-picotls/rpk_picotls.c"},
        .flags = c_flags_slice,
    });
    mod.linkLibrary(picotls_lib.?);
    mod.linkSystemLibrary("crypto", .{});
}

/// S5 moves every picoquic-specific native edge to engine-picoquic: picoquic
/// and picotls header trees, local RPK C glue, libpicoquic (and its transitive
/// picotls dependency), and OpenSSL libcrypto. No public/legacy root module
/// owns a picoquic native input after this call.
fn configurePicoquicEngineNativeDeps(
    b: *std.Build,
    engine_mod: *std.Build.Module,
    deps: std.Build.LazyPath,
    picoquic_lib: *std.Build.Step.Compile,
    c_flags_slice: []const []const u8,
) void {
    addPicoquicIncludes(engine_mod, b, deps);
    // rpk.c includes the colocated rpk.h after the S5 relocation.
    engine_mod.addIncludePath(b.path("src/engine-picoquic"));
    engine_mod.addCSourceFiles(.{
        .root = b.path("."),
        .files = &.{"src/engine-picoquic/rpk.c"},
        .flags = c_flags_slice,
    });
    engine_mod.linkLibrary(picoquic_lib);
    engine_mod.linkSystemLibrary("crypto", .{});
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
    // Locate the GCC ASan runtime WITHOUT a host-hardcoded
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

fn completeAesGcmCpuFeatures(target: std.Build.ResolvedTarget) std.Build.ResolvedTarget {
    if (target.result.cpu.arch != .x86_64) return target;

    // Product benchmark builds deliberately target `baseline+aes+avx+avx2` rather
    // than `native` to stay portable across the shared x86 bench hosts. AES-GCM's
    // AES path uses `aes`, but GHASH separately needs carryless multiply; Zig
    // std.crypto selects its hardware GHASH path only when both `pclmul` and `avx`
    // are present. Complete that product target here while preserving a bare
    // `-Dcpu=baseline` software fallback and respecting explicit `-pclmul`.
    //
    // ONLY complete an explicitly-requested baseline-derived product target
    // (`-Dcpu=baseline+…`, cpu_model == .baseline). We must NOT touch a
    // host-detected target: `.native` (`-Dcpu=native`) AND the DEFAULT
    // `.determined_by_arch_os` (a bare `zig build` with no `-Dcpu`, which the
    // native arch resolves to the native CPU) both already carry the host's OWN
    // authoritative `pclmul` bit — as does a named model (`.explicit`). Adding
    // `pclmul` to a host/VM whose CPUID reports `aes`+`avx` but MASKS `pclmul`
    // would make std.crypto's GHASH emit PCLMULQDQ and SIGILL at runtime. The
    // product deploy contract is the operator's assertion (any real x86 with
    // `aes`+`avx` also has `pclmul`); a masked-pclmul fleet must build bare
    // `-Dcpu=baseline`. (protected-floor crypto review, 2026-08-01: the prior
    // `== .native`-only guard missed the default `.determined_by_arch_os` query.)
    if (target.query.cpu_model != .baseline) return target;
    if (std.Target.x86.featureSetHas(target.query.cpu_features_sub, .pclmul)) return target;
    if (std.Target.x86.featureSetHas(target.result.cpu.features, .pclmul)) return target;
    if (!std.Target.x86.featureSetHasAll(target.result.cpu.features, .{ .aes, .avx })) return target;

    var adjusted = target;
    const pclmul = std.Target.x86.featureSet(&.{.pclmul});
    adjusted.query.cpu_features_add.addFeatureSet(pclmul);
    adjusted.result.cpu.features.addFeatureSet(pclmul);
    adjusted.result.cpu.features.populateDependencies(adjusted.result.cpu.arch.allFeaturesList());
    return adjusted;
}

test "completeAesGcmCpuFeatures upgrades only a baseline-derived product target" {
    const has = std.Target.x86.featureSetHas;
    const aes_avx = std.Target.x86.featureSet(&.{ .aes, .avx });
    const none = std.Target.Cpu.Feature.Set.empty;
    const mk = struct {
        fn f(model: std.Target.Query.CpuModel, features: std.Target.Cpu.Feature.Set) std.Build.ResolvedTarget {
            var result = @import("builtin").target;
            result.cpu.arch = .x86_64;
            result.cpu.features = features;
            return .{
                .query = .{ .cpu_arch = .x86_64, .cpu_model = model },
                .result = result,
            };
        }
    }.f;

    // The regression the protected-floor review caught: a bare `zig build` (no `-Dcpu`)
    // resolves to `.determined_by_arch_os`, NOT `.native`. On a host/VM that reports
    // aes+avx but masks pclmul it must stay software — force-adding pclmul would SIGILL.
    try std.testing.expect(!has(completeAesGcmCpuFeatures(mk(.determined_by_arch_os, aes_avx)).result.cpu.features, .pclmul));
    // Explicit `-Dcpu=native` is likewise host-authoritative: never upgrade.
    try std.testing.expect(!has(completeAesGcmCpuFeatures(mk(.native, aes_avx)).result.cpu.features, .pclmul));
    // The product recipe `-Dcpu=baseline+aes+avx+avx2` (cpu_model == .baseline) IS completed.
    try std.testing.expect(has(completeAesGcmCpuFeatures(mk(.baseline, aes_avx)).result.cpu.features, .pclmul));
    // Bare `-Dcpu=baseline` (no aes/avx) stays software.
    try std.testing.expect(!has(completeAesGcmCpuFeatures(mk(.baseline, none)).result.cpu.features, .pclmul));
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

// Reference list of C RPK glue after S5 native ownership split. The two
// helpers above add their own owner-specific source, never this as a bundle:
//   "src/engine-picoquic/rpk.c" → engine-picoquic RPK verification glue.
//   "src/tls-picotls/rpk_picotls.c"   → legacy picotls-backend RPK setup until S6.
const connection_c_sources = [_][]const u8{
    "src/engine-picoquic/rpk.c",
    "src/tls-picotls/rpk_picotls.c",
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
