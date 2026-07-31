const std = @import("std");

// Minimal build for the vendored `zigtls` dependency in this source mirror.
//
// It exposes ONLY the `zigtls` module that the parent package imports (identical
// to the module the upstream build declares: `src/root.zig`). The upstream
// development build graph — tools, examples, and the BoGo / interop / timing /
// reliability harnesses together with their `scripts/` — is intentionally not
// part of this source mirror, which vendors zigtls as a library, not a project.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    _ = b.standardOptimizeOption(.{});

    _ = b.addModule("zigtls", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });
}
