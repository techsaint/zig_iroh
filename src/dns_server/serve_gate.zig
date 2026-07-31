//! ReleaseSafe serve-a-query gate for the dns-server UAF class.
//!
//! Build/run: `zig build dns-server-serve-gate` (defaults to ReleaseSafe).
//! Constructs a Server via out-pointer init, serves a real UDP A query and a
//! real DoH query, asserts NOERROR answers, then shuts down.
//!
//! `argv[1]`, when present, is the `iroh-dns-pkarr` binary; the build step passes
//! it so the CLI is driven as a real child process against a live server.

const std = @import("std");
const builtin = @import("builtin");
const zig_iroh = @import("zig_iroh");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.arena.allocator();
    try zig_iroh.dns_server.server.serveUdpAndDohOnce(allocator, io);
    try zig_iroh.dns_server.server.serveHunterGatesOnce(allocator, io);
    try zig_iroh.dns_server.server.checkDockerPortCoherence(allocator, io);
    try zig_iroh.dns_server.server.serveSlowClientGateOnce(allocator, io);
    try zig_iroh.dns_server.server.serveHttpsSelfSignedGateOnce(allocator, io);
    try zig_iroh.dns_server.server.serveMainlineBackgroundGateOnce(allocator, io);

    const argv = try init.minimal.args.toSlice(allocator);
    var cli_note: []const u8 = "cli skipped (no binary arg)";
    if (argv.len > 1) {
        try zig_iroh.dns_server.server.serveCliRoundTripOnce(allocator, io, argv[1]);
        cli_note = "cli publish/resolve";
    }

    var stdout_buf: [384]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    try stdout_writer.interface.print(
        "dns-server-serve-gate: PASS (UDP A + TCP DNS + DoH; AXFR refused, " ++
            "pkarr PUT/resolve, forged-PUT rejected, non-TXT zone, JSON DoH, " ++
            "CORS, cache-control, healthz stamp, reload, per-IP PUT limit, " ++
            "slow-client deadline, docker port coherence, HTTPS self_signed DoH, " ++
            "mainline background ZoneStore, {s} exercised under {s})\n",
        .{ cli_note, @tagName(builtin.mode) },
    );
    try stdout_writer.interface.flush();
}
