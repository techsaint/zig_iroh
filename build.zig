const std = @import("std");
const products = @import("src/products.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const product_name = b.option([]const u8, "product", "Product profile") orelse "picoquic-picotls";
    const product_id = products.parseId(product_name) orelse {
        std.debug.panic("unknown -Dproduct='{s}'; valid: picoquic-picotls, noq-picotls, noq-zigtls", .{product_name});
    };
    if (!isShippedProduct(product_id)) {
        std.debug.panic("unsupported -Dproduct='{s}'; valid: picoquic-picotls, noq-picotls, noq-zigtls", .{product_name});
    }
    const product = products.get(product_id);
    const deps = b.path("deps");
    const git_hash = b.option([]const u8, "git_hash", "Commit identifier") orelse "unknown";

    const build_options = addBuildOptions(b, product_name, product, product.zigtls.?, git_hash, false);

    const need_picotls = product.picotls or product.picoquic;
    const picotls: ?*std.Build.Step.Compile = if (need_picotls)
        addPicotls(b, target, optimize, deps)
    else
        null;
    const picoquic: ?*std.Build.Step.Compile = if (product.picoquic)
        addPicoquic(b, target, optimize, deps, picotls.?)
    else
        null;

    const tls_dep = b.dependency("tls", .{
        .target = target,
        .optimize = optimize,
    });
    const zigtls_mod: ?*std.Build.Module = if (product.zigtls.?)
        zigtlsModule(b, target, optimize)
    else
        null;

    const root_mod = b.addModule("zig_iroh", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    root_mod.addImport("tls", tls_dep.module("tls"));
    configureZigtlsFeature(root_mod, build_options, zigtls_mod);
    configureProductNativeDeps(b, root_mod, deps, product, picoquic, picotls, &c_flags);

    const lib = b.addLibrary(.{
        .name = "zig_iroh",
        .linkage = .static,
        .root_module = root_mod,
    });
    b.installArtifact(lib);

    const unit_tests = b.addTest(.{ .root_module = root_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    run_unit_tests.setCwd(testRunCwd(b));
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const relay_build_options = addBuildOptions(b, product_name, .{
        .picoquic = false,
        .noq = true,
        .picotls = false,
        .zigtls = true,
        .gossip = product.gossip,
        .discovery = product.discovery,
    }, true, git_hash, false);
    const relay_root_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    relay_root_mod.addImport("tls", tls_dep.module("tls"));
    configureZigtlsFeature(relay_root_mod, relay_build_options, zigtlsModule(b, target, optimize));

    const relay_mod = b.createModule(.{
        .root_source_file = b.path("relay_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    relay_mod.addImport("zig_iroh", relay_root_mod);
    relay_mod.addImport("tls", tls_dep.module("tls"));
    const relay_exe = b.addExecutable(.{ .name = "relay", .root_module = relay_mod });
    const install_relay = b.addInstallArtifact(relay_exe, .{});
    const relay_step = b.step("relay", "Build relay");
    relay_step.dependOn(&install_relay.step);
}

fn isShippedProduct(product_id: products.Id) bool {
    return switch (product_id) {
        .@"picoquic-picotls", .@"noq-picotls", .@"noq-zigtls" => true,
        else => false,
    };
}

fn addBuildOptions(
    b: *std.Build,
    product_name: []const u8,
    product: products.Product,
    zigtls_enabled: bool,
    git_hash: []const u8,
    internal_harnesses: bool,
) *std.Build.Step.Options {
    const opts = b.addOptions();
    opts.addOption([]const u8, "product", product_name);
    opts.addOption(bool, "picoquic", product.picoquic);
    opts.addOption(bool, "noq", product.noq);
    opts.addOption(bool, "picotls", product.picotls);
    opts.addOption(bool, "zigtls", zigtls_enabled);
    opts.addOption(bool, "gossip", product.gossip);
    opts.addOption([]const u8, "git_hash", git_hash);
    opts.addOption(bool, "discovery", product.discovery);
    opts.addOption(bool, "internal_harnesses", internal_harnesses);
    return opts;
}

fn configureZigtlsFeature(
    module: *std.Build.Module,
    build_options: *std.Build.Step.Options,
    zigtls_mod: ?*std.Build.Module,
) void {
    module.addOptions("build_options", build_options);
    if (zigtls_mod) |mod| module.addImport("zigtls", mod);
}

fn testRunCwd(b: *std.Build) std.Build.LazyPath {
    const files = b.addWriteFiles();
    _ = files.add("relay-testdata/test-cert.pem", relay_test_cert_pem);
    _ = files.add("relay-testdata/test-key.pem", relay_test_key_pem);
    _ = files.add("dns_server.example.toml", dns_server_example_toml);
    _ = files.add("deploy/iroh-dns-server/Dockerfile", dns_server_dockerfile);
    return files.getDirectory();
}

fn zigtlsModule(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const zigtls_dep = b.dependency("zigtls", .{
        .target = target,
        .optimize = optimize,
    });
    return zigtls_dep.module("zigtls");
}

fn configureProductNativeDeps(
    b: *std.Build,
    mod: *std.Build.Module,
    deps: std.Build.LazyPath,
    product: products.Product,
    picoquic_lib: ?*std.Build.Step.Compile,
    picotls_lib: ?*std.Build.Step.Compile,
    c_flags_slice: []const []const u8,
) void {
    if (product.picoquic) {
        addPicoquicIncludes(mod, b, deps);
    } else if (product.picotls) {
        addPicotlsIncludes(mod, b, deps);
    }
    if (product.picoquic or product.picotls) {
        mod.addIncludePath(b.path("src"));
    }

    var c_files: [2][]const u8 = undefined;
    var n: usize = 0;
    if (product.picoquic) {
        c_files[n] = "src/connection/rpk.c";
        n += 1;
    }
    if (product.picotls) {
        c_files[n] = "src/quic/rpk_picotls.c";
        n += 1;
    }
    if (n > 0) {
        mod.addCSourceFiles(.{
            .root = b.path("."),
            .files = c_files[0..n],
            .flags = c_flags_slice,
        });
    }

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
    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addPicotlsIncludes(mod, b, deps);
    const lib = b.addLibrary(.{ .name = "picotls-iroh", .linkage = .static, .root_module = mod });
    lib.root_module.addCSourceFiles(.{
        .root = deps,
        .files = &picotls_sources,
        .flags = &c_flags,
    });
    if (hasFusionCpuFeatures(target)) {
        lib.root_module.addCSourceFiles(.{
            .root = deps,
            .files = &picotls_fusion_sources,
            .flags = &c_flags,
        });
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
    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    addPicoquicIncludes(mod, b, deps);
    if (!hasFusionCpuFeatures(target)) {
        mod.addCMacro("PTLS_WITHOUT_FUSION", "1");
    }
    const lib = b.addLibrary(.{ .name = "picoquic-iroh", .linkage = .static, .root_module = mod });
    lib.root_module.addCSourceFiles(.{
        .root = deps,
        .files = &picoquic_sources,
        .flags = &c_flags,
    });
    if (hasFusionCpuFeatures(target)) {
        lib.root_module.addCSourceFiles(.{
            .root = deps,
            .files = &picoquic_fusion_sources,
            .flags = &c_flags,
        });
    }
    lib.root_module.linkLibrary(picotls);
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

fn hasFusionCpuFeatures(target: std.Build.ResolvedTarget) bool {
    if (target.result.cpu.arch != .x86_64) return false;
    return std.Target.x86.featureSetHasAll(target.result.cpu.features, .{ .vaes, .vpclmulqdq });
}

const relay_test_cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDJTCCAg2gAwIBAgIUecNUHdZyu98oeJ9NOG8Db7SB4OswDQYJKoZIhvcNAQEL
    \\BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYyMTE5MjUzMFoXDTM2MDYx
    \\ODE5MjUzMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
    \\AAOCAQ8AMIIBCgKCAQEAmB3uSxLnKRxDghXJJv3bxpcdf53UtL5yov5xvd22DP2A
    \\pBpsMPP/EdXWg4tyOyr5JUTivWq5JFm1M9ngDhfwAkOivaNg6nMqFjIR9YCYTBzC
    \\Qg5p6acJe42JG3mJDQua2CDq5a1VuetszSZtB/0rv9y9bACAQO02fnY2Xxx3PNOv
    \\GrLIEHZq8itLoXNtLpuQSVXPGhYf6lP8CKp4y8yHuAUVU43HcTOD9FD6+j/znB4B
    \\25v+xYV4DzqUWbhElKlY9hm/7IA8gzoslnNvQkxwRpzJVDAbZAVM/7OfAocVpQ/0
    \\ohzmNMFEA+9tTk5OH8rG4NjmhnHWoULD32ANt10CcQIDAQABo28wbTAdBgNVHQ4E
    \\FgQU9XAMe1nqSMaN+u5UaBL9NjwJ7A4wHwYDVR0jBBgwFoAU9XAMe1nqSMaN+u5U
    \\aBL9NjwJ7A4wDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
    \\BH8AAAEwDQYJKoZIhvcNAQELBQADggEBABxbpBLuvX0AKzqpBPXyMIb1bDaEU2EA
    \\LxkKkS+uKxfQMIXnj/O56LCtlfzezQHxTMbhndzukS6O+pNHknP46icq4Snsnafm
    \\RXv0Ti3SF35xikyk9AOzWb5ADdcVKmwV46biPpTdhdrBk1PcuXH95Mr9wLdorVMf
    \\PkI4xaVYJywJcBvezZ0vWjuKjqW7XLNYHytCtljZZNeVaXfq/XxDOcH62F71UEl6
    \\/b/r8hW+nXKmTg4ZGAtiLVnQ/ogh9K1Gj2GG6iShKtUPc2f5hQNWE/fG21ZsxLxK
    \\ehozYXEpNtpqNsEDxrzbOv885cd/JXXRze30PTFwNdlNlvdTV71Doo8=
    \\-----END CERTIFICATE-----
    \\
;

const relay_test_key_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCYHe5LEucpHEOC
    \\Fckm/dvGlx1/ndS0vnKi/nG93bYM/YCkGmww8/8R1daDi3I7KvklROK9arkkWbUz
    \\2eAOF/ACQ6K9o2DqcyoWMhH1gJhMHMJCDmnppwl7jYkbeYkNC5rYIOrlrVW562zN
    \\Jm0H/Su/3L1sAIBA7TZ+djZfHHc8068assgQdmryK0uhc20um5BJVc8aFh/qU/wI
    \\qnjLzIe4BRVTjcdxM4P0UPr6P/OcHgHbm/7FhXgPOpRZuESUqVj2Gb/sgDyDOiyW
    \\c29CTHBGnMlUMBtkBUz/s58ChxWlD/SiHOY0wUQD721OTk4fysbg2OaGcdahQsPf
    \\YA23XQJxAgMBAAECggEALzq7zdtkokMAQtd4yP5wykwJAKKEdEndVfYiYo0ABTCA
    \\THNXvCtFusfl/pnBMdW53XRx4dXM/hhMRnkTM80C2/EcCj07zg9LtfB92ve+UYNs
    \\XQ4UnFMcgpwDQeCOSNqdjRVLWVxkDYGnGlsf5ycX+k4TEgFl0MLV9JXHc+hmrR+h
    \\ko8CvmgSD2JhxbcgFqc5YgXpVZTOQ5D9Zl4lWP4jQLH//kvY2jQB9mCZI/XPHcz2
    \\fhQM5ATNFGx6nSw6r5VbpLA05yzEVhiwdWON5MCh7kSlcw3lWEzNRhxOWcZY8fSH
    \\LGlNDNndTiyHI8Qkh00BugVeV1cQayo/a0+Kv9xUMQKBgQDUcsSHxYfNGZ8nmQ/2
    \\FjkCYvlYqFcHbDe6lEGgd0qc+fcsw9s5qOoIfcLOe2qrbQADe9806avkVVYF0nb+
    \\vsa3Iy6yGH/aG06PhhjR8vA66j1wqtWnRzOETQpIUNhYFufAULirsDLotm7CZV7z
    \\HtgiofC1Ud5ZUpoFOKxVp8SXKwKBgQC3TPy6aX5wDr2++vDNuz5FHXmorKY8xZSR
    \\rgliIQg6xda+iWiwOpAV1AabJtQ8nUazzircYJWTNR4W79fyGR450/oUuvgjKZsc
    \\3JHuE6TK8EsreVolh1RBVsy1+3MFg+w0GtV9hdPtmFy4MRvwbHi+Oa9FU4IHq9OJ
    \\yn7nHyg+0wKBgQCoByW9pNOlulAQx5TCNA1e/9zq7Cn5KvRg04WcXv1abrG6bCXl
    \\0t1XXfBH04EomItcNgryFKbpbz0cWbvX/Be7HU5/ebUVUmeuSIc09opebomtpNBa
    \\/4uVZkFttNOHyIX/q1iEIlYBjNjJU9fnPkwACEkTf+72gshivNJA5PIuBQKBgCGU
    \\YwArb1RL/wrLoe2ujbvPqIf0CQg9EfiWL3Xgo0dREwQY3Crcr6SwEP2/YUYxcdBi
    \\xotUzlIHexmsmpzpaRYi9T9y+R5H8viYl8tLofbjioHOW2tgnVjS8/GqvOmXv1/U
    \\QqQaLjbqoKHFrV6gIIaIvskugTWyjrBBfnoMxSytAoGAfd8fuQRYuMwsCrgKU7tJ
    \\GEpBipvSHXoL4VuGPcFZ75tbr0/g2SEsDD9uNWdZuZiq/j0v05oPsRoARNthe/vV
    \\H9VaFy5sbEvCch9Cs7tFHcJpNld1h4eNFUqlk2YEfUmU41CH3gw/gBImHbZQKOCg
    \\5EwOewoWnQj2LxUsnQervmU=
    \\-----END PRIVATE KEY-----
    \\
;

const dns_server_example_toml =
    \\[http]
    \\port = 8080
    \\
    \\[dns]
    \\port = 5300
    \\
    \\[metrics]
    \\bind_addr = "127.0.0.1:9117"
    \\
;

const dns_server_dockerfile =
    \\EXPOSE 5300/udp 5300/tcp 8080 9117
    \\
;

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

const picotls_fusion_sources = [_][]const u8{
    "picotls/lib/fusion.c",
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

const picoquic_fusion_sources = [_][]const u8{
    "picoquic/picoquic/picoquic_ptls_fusion.c",
};
