//! Real iroh-blobs provider interop gate (exe form).
//!
//! Exe form is load-bearing (W2 #4): this gate emits BENCH telemetry rows, and BENCH
//! rows belong on the REAL stdout. A zig TEST binary's stdout is the build runner's
//! `--listen` protocol channel — writing raw BENCH bytes to it from inside a test
//! deadlocks the runner (observed 2026-07-17). Relay/gossip already run as exes for the
//! same reason. The DebugAllocator leak=fail also makes the `safety-leaks` blobs leg
//! honest by construction (W2 #2).

const std = @import("std");
const key = @import("key.zig");
const factory = @import("transport/factory.zig");
const Hash = @import("hash.zig").Hash;
const get = @import("blobs/get.zig");
const observe_push = @import("blobs/observe_push.zig");
const protocol = @import("blobs/protocol.zig");
const bao = @import("blobs/bao.zig");
const fixtures = @import("blobs/fixtures.zig");
const telemetry = @import("bench_telemetry");
const lifecycle = @import("interop_lifecycle");

const blob_size: usize = 65_537; // happy path only; large/corrupt-provider legs are an
// explicit defer: docs/issues/zig/2026-07-17-blobs-interop-coverage-large-corrupt.md (W2 #7)

const InteropError = error{
    MissingBlobHash,
    MissingServerNodeId,
    MissingServerBound,
    MissingProviderBench,
    BlobHashMismatch,
    BlobContentMismatch,
    ObserveMismatch,
    PushFailed,
};

/// Provider startup readiness: BLOB_HASH + SERVER_NODE_ID + SERVER_BOUND (the port-0
/// dynamic-bind contract — the provider prints its actual bound socket).
const ProviderReady = struct {
    hash: ?Hash = null,
    node_id: ?key.PublicKey = null,
    addr: ?std.Io.net.IpAddress = null,
};

fn providerPredicate(ctx: *ProviderReady, line: []const u8) !bool {
    if (std.mem.startsWith(u8, line, "BLOB_HASH: ")) {
        var raw: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&raw, line["BLOB_HASH: ".len..]);
        ctx.hash = Hash.fromBytes(raw);
    } else if (std.mem.startsWith(u8, line, "SERVER_NODE_ID: ")) {
        ctx.node_id = try key.PublicKey.parse(line["SERVER_NODE_ID: ".len..]);
    } else if (std.mem.startsWith(u8, line, "SERVER_BOUND: ")) {
        ctx.addr = try lifecycle.parseHostPort(line["SERVER_BOUND: ".len..]);
    }
    return ctx.hash != null and ctx.node_id != null and ctx.addr != null;
}

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer {
        if (gpa.deinit() == .leak) {
            std.debug.print("FAIL: blobs interop leaked (see reports above)\n", .{});
            std.process.exit(1);
        }
    }
    const allocator = gpa.allocator();
    const io = init.io;

    var out_buf: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &out_buf);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch {};

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh-blobs/Cargo.toml");
    var peer: lifecycle.Peer = undefined;
    try peer.spawn(allocator, io, .{
        .argv = &.{
            "cargo",     "run",           "--manifest-path", manifest,
            "--example", "blob_provider", "--",              "--mode",
            "all",
        },
        .tee_drain = true,
    });
    defer peer.deinit();

    // Phase 1: startup readiness — bounded by the helper's inactivity watchdog (W2 #5).
    var ready: ProviderReady = .{};
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, providerPredicate);

    const hash = ready.hash orelse return InteropError.MissingBlobHash;
    const node_id = ready.node_id orelse return InteropError.MissingServerNodeId;
    const addr = ready.addr orelse return InteropError.MissingServerBound;

    const expected = try fixtures.makeTestData(allocator, blob_size);
    defer allocator.free(expected);
    if (!Hash.of(expected).eql(hash)) return InteropError.BlobHashMismatch;

    const client_key = key.SecretKey.fromBytes([_]u8{0xA1} ** 32);
    const alpn: [:0]const u8 = "/iroh-bytes/4";
    const client_ep = try factory.createForProduct(allocator, io, client_key, alpn, .{});
    defer client_ep.deinit();

    const client_conn = try client_ep.transport().connect(.{
        .id = node_id,
        .addrs = &.{.{ .ip = addr }},
    });
    // W2 #6: exception-safe connection cleanup (an error between connect and close
    // used to leak the connection).
    defer client_conn.close();

    // Phase 2: Get the fixed blob and mirror the provider's BENCH row.
    const got = try runGet(allocator, io, stdout, init.minimal.environ, client_conn, hash, expected);
    defer allocator.free(got);
    try waitForProviderBench(stdout, init.minimal.environ, allocator, &peer, "blobs-interop-get");

    // Phase 3: Push the same blob back to the provider and verify it accepts it.
    // Runs before Observe so a transport limitation in the streaming observe reader
    // does not hide Push results.
    try runPush(allocator, io, stdout, init.minimal.environ, client_conn, hash, expected);
    try waitForProviderBench(stdout, init.minimal.environ, allocator, &peer, "blobs-interop-push");

    // Phase 4: Observe the already-present blob and verify the provider reports completion.
    try runObserve(allocator, io, stdout, init.minimal.environ, client_conn, hash);
    try waitForProviderBench(stdout, init.minimal.environ, allocator, &peer, "blobs-interop-observe");

    std.debug.print("PASS: Zig getter/pusher/observer exercised the real iroh-blobs provider\n", .{});
}

fn runGet(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    environ: std.process.Environ,
    conn: @import("transport.zig").Connection,
    hash: Hash,
    expected: []const u8,
) ![]u8 {
    const start_ts = std.Io.Clock.Timestamp.now(io, .awake);
    const got = try get.getBlob(allocator, conn, hash, hash);
    const elapsed_i = start_ts.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toNanoseconds();
    const transfer_ns: u64 = if (elapsed_i > 0) @intCast(elapsed_i) else 0;

    if (!std.mem.eql(u8, expected, got)) return InteropError.BlobContentMismatch;

    try telemetry.emitWithEnviron(stdout, environ, .{
        .event = "transfer_done",
        .role = "getter",
        .impl = "zig_iroh",
        .scenario = "blobs-interop-get",
        .transfer_ns = transfer_ns,
        .app_bytes = got.len,
    });
    try stdout.flush();
    return got;
}

fn runObserve(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    environ: std.process.Environ,
    conn: @import("transport.zig").Connection,
    hash: Hash,
) !void {
    const start_ts = std.Io.Clock.Timestamp.now(io, .awake);
    var stream = try observe_push.observe(conn, protocol.ObserveRequest.all(hash));
    defer stream.deinit();

    const item = try stream.next(allocator);
    defer item.deinit(allocator);

    if (item.size != blob_size or !item.ranges.is_all()) {
        return InteropError.ObserveMismatch;
    }

    // Close the receive direction so the provider's observe handler completes and emits
    // a transfer completion event.
    stream.close();

    const elapsed_i = start_ts.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toNanoseconds();
    const transfer_ns: u64 = if (elapsed_i > 0) @intCast(elapsed_i) else 0;

    try telemetry.emitWithEnviron(stdout, environ, .{
        .event = "transfer_done",
        .role = "observer",
        .impl = "zig_iroh",
        .scenario = "blobs-interop-observe",
        .transfer_ns = transfer_ns,
        .app_bytes = blob_size,
    });
    try stdout.flush();
}

fn runPush(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    environ: std.process.Environ,
    conn: @import("transport.zig").Connection,
    hash: Hash,
    data: []const u8,
) !void {
    const start_ts = std.Io.Clock.Timestamp.now(io, .awake);
    try observe_push.pushBlob(allocator, conn, hash, data);
    const elapsed_i = start_ts.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw.toNanoseconds();
    const transfer_ns: u64 = if (elapsed_i > 0) @intCast(elapsed_i) else 0;

    try telemetry.emitWithEnviron(stdout, environ, .{
        .event = "transfer_done",
        .role = "pusher",
        .impl = "zig_iroh",
        .scenario = "blobs-interop-push",
        .transfer_ns = transfer_ns,
        .app_bytes = data.len,
    });
    try stdout.flush();
}

fn waitForProviderBench(
    stdout: *std.Io.Writer,
    environ: std.process.Environ,
    allocator: std.mem.Allocator,
    peer: *lifecycle.Peer,
    scenario: []const u8,
) !void {
    peer.armWatchdog(lifecycle.post_startup_window);
    defer peer.disarmWatchdog();
    while (try peer.nextLine()) |line| {
        if (std.mem.startsWith(u8, line, "BENCH ")) {
            const parsed = try telemetry.parseLine(allocator, line);
            defer parsed.deinit();
            if (std.mem.eql(u8, parsed.value.scenario, scenario)) {
                try telemetry.emitWithEnviron(stdout, environ, parsed.value);
                try stdout.flush();
                return;
            }
            // Ignore BENCH rows for other phases (e.g. out-of-order completions).
        }
    }
    return InteropError.MissingProviderBench;
}
