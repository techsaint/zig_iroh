//! Deterministic wire-behavior vectors for the six frozen transport stream
//! capabilities (Tier-0 coverage hardening, tier0-coverage-hardening-p1-gaps).
//!
//! Each scenario drives an `oracle_pair.Pair` — the noq engine in-process pair
//! harness: fixed keys/CIDs, seeded CSPRNG, virtual time, no sockets — so the
//! transcript is byte-stable across runs and machines. Recorded events are
//! PEER-OBSERVABLE stream semantics (bytes, offsets, FIN/final-size, reset/stop
//! codes), never ciphertext and never pump/ACK scheduling noise.
//!
//! Golden: vectors/transport/stream-capabilities.json
//!   - REGENERATE (an explicit, reviewed golden amendment — never a test side
//!     effect, per the Tier-0 no-auto-golden-update rule):
//!       zig build gen-stream-vectors > vectors/transport/stream-capabilities.json
//!   - GATE: the test at the bottom replays every scenario and requires a
//!     byte-exact transcript match (runs under `zig build test`).

const std = @import("std");
const oracle_pair = @import("oracle_pair.zig");

/// The committed golden, read at test runtime: @embedFile cannot reach outside
/// the src/ package, and the canonical artifact lives at vectors/ (the repo's
/// committed-vector convention). Candidates are portable relative paths — the
/// gate runs from the zig_iroh root (or the outer repo root).
const golden_path_candidates = [_][]const u8{
    "vectors/transport/stream-capabilities.json",
    "zig_iroh/vectors/transport/stream-capabilities.json",
};

fn readGolden(allocator: std.mem.Allocator) ![]u8 {
    const io = std.testing.io;
    for (golden_path_candidates) |path| {
        const contents = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(1 << 16)) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        return contents;
    }
    std.debug.print("stream-capability golden not found; tried:\n", .{});
    for (golden_path_candidates) |path| std.debug.print("  {s}\n", .{path});
    return error.FileNotFound;
}

pub const generated_by = "zig build gen-stream-vectors — src/quic/stream_capability_vectors.zig over the noq engine (oracle_pair.Pair: fixed keys/CIDs, seeded CSPRNG, virtual time); events are peer-observable stream semantics, never ciphertext";

const Events = std.ArrayList([]const u8);
const ScenarioFn = *const fn (allocator: std.mem.Allocator, p: *oracle_pair.Pair, events: *Events) anyerror!void;

/// The six frozen `transport:*` capabilities, in canonical golden order.
pub const scenarios = [_]struct { name: []const u8, run: ScenarioFn }{
    .{ .name = "sendstream-writer", .run = sendstreamWriter },
    .{ .name = "sendstream-finish", .run = sendstreamFinish },
    .{ .name = "sendstream-reset", .run = sendstreamReset },
    .{ .name = "sendstream-flush", .run = sendstreamFlush },
    .{ .name = "recvstream-reader", .run = recvstreamReader },
    .{ .name = "recvstream-stop", .run = recvstreamStop },
};

fn rec(events: *Events, allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    try events.append(allocator, try std.fmt.allocPrint(allocator, fmt, args));
}

fn recWrite(events: *Events, allocator: std.mem.Allocator, sid: u64, data: []const u8, fin: bool) !void {
    try rec(events, allocator, "write stream={d} len={d} fin={} data={s}", .{ sid, data.len, fin, data });
}

fn recRead(events: *Events, allocator: std.mem.Allocator, sid: u64, off: u64, data: []const u8) !void {
    try rec(events, allocator, "peer_read stream={d} off={d} len={d} data={s}", .{ sid, off, data.len, data });
}

fn freshEstablishedPair(allocator: std.mem.Allocator) !oracle_pair.Pair {
    var p = try oracle_pair.makePair(allocator, .{});
    errdefer p.deinit();
    try p.establish(32);
    return p;
}

/// transport:sendstream-writer — bytes written are delivered to the peer's
/// reader reliably and in order; a second write continues at the next offset.
fn sendstreamWriter(allocator: std.mem.Allocator, p: *oracle_pair.Pair, events: *Events) !void {
    const sid = try p.client.openStream(.bidi);
    var off: u64 = 0;
    try p.client.writeStream(sid, "hello stream", false);
    try recWrite(events, allocator, sid, "hello stream", false);
    try p.drive(1);
    const r1 = p.server.readStream(sid);
    try recRead(events, allocator, sid, off, r1);
    off += r1.len;

    try p.client.writeStream(sid, " round two", false);
    try recWrite(events, allocator, sid, " round two", false);
    try p.drive(1);
    const r2 = p.server.readStream(sid);
    try recRead(events, allocator, sid, off, r2);
}

/// transport:sendstream-finish — FIN is delivered after the final bytes; an
/// empty finished stream yields an immediate FIN with final size 0.
fn sendstreamFinish(allocator: std.mem.Allocator, p: *oracle_pair.Pair, events: *Events) !void {
    const sid = try p.client.openStream(.bidi);
    try p.client.writeStream(sid, "final bytes", true);
    try recWrite(events, allocator, sid, "final bytes", true);
    try p.drive(1);
    const r = p.server.readStream(sid);
    try recRead(events, allocator, sid, 0, r);
    if (!p.server.streamRecvFin(sid)) return error.FinNotDelivered;
    // Contiguous delivery reached the FIN, so delivered bytes == the final size.
    try rec(events, allocator, "peer_fin stream={d} final_size={d}", .{ sid, p.server.streamRecvBytes(sid).len });

    const sid2 = try p.client.openStream(.bidi);
    try p.client.writeStream(sid2, "", true);
    try recWrite(events, allocator, sid2, "", true);
    try p.drive(1);
    if (!p.server.streamRecvFin(sid2)) return error.FinNotDelivered;
    try rec(events, allocator, "peer_fin stream={d} final_size={d}", .{ sid2, p.server.streamRecvBytes(sid2).len });
}

/// transport:sendstream-reset — reset aborts the send half: the peer observes
/// RESET_STREAM with the app code; the unsent buffered tail is never delivered
/// (peer final size is 0).
fn sendstreamReset(allocator: std.mem.Allocator, p: *oracle_pair.Pair, events: *Events) !void {
    const sid = try p.client.openStream(.bidi);
    try p.client.writeStream(sid, "unsent tail", false); // buffered, never driven onto the wire
    try p.client.resetStream(sid, 77);
    try rec(events, allocator, "reset stream={d} code={d}", .{ sid, 77 });
    var rounds: usize = 0;
    while (rounds < 8 and p.server.streamRecvResetCode(sid) == null) : (rounds += 1) {
        try p.drive(1);
    }
    const code = p.server.streamRecvResetCode(sid) orelse return error.ResetNotPeerVisible;
    try rec(events, allocator, "peer_recv_reset stream={d} code={d} final_size={d}", .{ sid, code, p.server.streamRecvBytes(sid).len });
}

/// transport:sendstream-flush — written bytes are wire-visible to the peer
/// WITHOUT a FIN: the peer reads them mid-stream and the stream stays open.
/// (The engine has no flush call — a pump round emits promptly; the vtable
/// flush() is pinned by the CHAR "flush visibility mid-stream" test.)
fn sendstreamFlush(allocator: std.mem.Allocator, p: *oracle_pair.Pair, events: *Events) !void {
    const sid = try p.client.openStream(.bidi);
    var off: u64 = 0;
    try p.client.writeStream(sid, "part-one", false);
    try recWrite(events, allocator, sid, "part-one", false);
    try p.drive(1);
    const r1 = p.server.readStream(sid);
    try recRead(events, allocator, sid, off, r1);
    off += r1.len;
    // The stream is still open: no end-of-stream observed after the delivered prefix.
    try std.testing.expect(!p.server.streamRecvFin(sid));
    try rec(events, allocator, "peer_fin_pending stream={d}", .{sid});

    try p.client.writeStream(sid, "part-two", false);
    try recWrite(events, allocator, sid, "part-two", false);
    try p.drive(1);
    const r2 = p.server.readStream(sid);
    try recRead(events, allocator, sid, off, r2);
    try std.testing.expect(!p.server.streamRecvFin(sid));
    try rec(events, allocator, "peer_fin_pending stream={d}", .{sid});
}

/// transport:recvstream-reader — the reader yields exactly the peer's bytes in
/// order across incremental deliveries; end-of-stream coincides with peer FIN.
fn recvstreamReader(allocator: std.mem.Allocator, p: *oracle_pair.Pair, events: *Events) !void {
    const sid = try p.client.openStream(.bidi);
    const chunks = [_][]const u8{ "a", "bb", "ccc" };
    var off: u64 = 0;
    for (chunks) |chunk| {
        try p.client.writeStream(sid, chunk, false);
        try p.drive(1);
        const r = p.server.readStream(sid);
        try recRead(events, allocator, sid, off, r);
        off += r.len;
    }
    try p.client.writeStream(sid, "", true);
    try recWrite(events, allocator, sid, "", true);
    try p.drive(1);
    if (!p.server.streamRecvFin(sid)) return error.FinNotDelivered;
    try rec(events, allocator, "peer_fin stream={d} final_size={d}", .{ sid, p.server.streamRecvBytes(sid).len });
}

/// transport:recvstream-stop — stop() emits STOP_SENDING; the peer's engine
/// answers by resetting its send half (send.reset_code becomes the stop code).
fn recvstreamStop(allocator: std.mem.Allocator, p: *oracle_pair.Pair, events: *Events) !void {
    const sid = try p.client.openStream(.bidi);
    try p.client.writeStream(sid, "discard-me", false);
    try recWrite(events, allocator, sid, "discard-me", false);
    try p.drive(1);
    const r = p.server.readStream(sid);
    try recRead(events, allocator, sid, 0, r);

    try p.server.stopStream(sid, 0);
    try rec(events, allocator, "stop stream={d} code={d}", .{ sid, 0 });
    var rounds: usize = 0;
    while (rounds < 8 and p.client.streamSendResetCode(sid) == null) : (rounds += 1) {
        try p.drive(1);
    }
    const code = p.client.streamSendResetCode(sid) orelse return error.StopNotPeerVisible;
    try rec(events, allocator, "peer_send_reset stream={d} code={d}", .{ sid, code });
}

fn appendJsonEscaped(allocator: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            else => try out.append(allocator, c),
        }
    }
}

/// Run all six scenarios on fresh pairs and render the golden JSON document.
/// Byte-stable: fixed inputs, virtual time, canonical ordering. The returned
/// slice is owned by the caller (allocated from `gpa`); scenario scratch lives
/// in an arena that dies here.
pub fn buildTranscriptJson(gpa: std.mem.Allocator) ![]const u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, "{\n  \"generated_by\": \"");
    try appendJsonEscaped(a, &out, generated_by);
    try out.appendSlice(a, "\",\n  \"scenarios\": {\n");
    for (scenarios, 0..) |sc, i| {
        var p = try freshEstablishedPair(a);
        defer p.deinit();
        var events: Events = .empty;
        try sc.run(a, &p, &events);
        try out.appendSlice(a, "    \"");
        try appendJsonEscaped(a, &out, sc.name);
        try out.appendSlice(a, "\": [\n");
        for (events.items, 0..) |line, j| {
            try out.appendSlice(a, "      \"");
            try appendJsonEscaped(a, &out, line);
            try out.appendSlice(a, "\"");
            if (j + 1 < events.items.len) try out.appendSlice(a, ",");
            try out.appendSlice(a, "\n");
        }
        try out.appendSlice(a, "    ]");
        if (i + 1 < scenarios.len) try out.appendSlice(a, ",");
        try out.appendSlice(a, "\n");
    }
    try out.appendSlice(a, "  }\n}\n");
    return try gpa.dupe(u8, out.items);
}

test "stream capability wire vectors match the committed golden (noq deterministic pair)" {
    const allocator = std.testing.allocator;
    const committed = try readGolden(allocator);
    defer allocator.free(committed);

    // Structural sanity of the committed golden: parses, names exactly the six
    // frozen capabilities (a hand-mangled or truncated golden fails here).
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, committed, .{});
    defer parsed.deinit();
    const scenarios_obj = parsed.value.object.get("scenarios").?.object;
    try std.testing.expectEqual(@as(usize, scenarios.len), scenarios_obj.count());
    for (scenarios) |sc| try std.testing.expect(scenarios_obj.get(sc.name) != null);

    // The replay gate: re-run every scenario deterministically and require a
    // byte-exact transcript. Any wire-visible drift (ordering, offsets, FIN /
    // final-size, reset/stop codes) flips this RED; a legitimate behavior
    // change regenerates the golden via `zig build gen-stream-vectors` as a
    // reviewed amendment.
    const live = try buildTranscriptJson(allocator);
    defer allocator.free(live);
    if (!std.mem.eql(u8, committed, live)) {
        var committed_lines = std.mem.splitScalar(u8, committed, '\n');
        var live_lines = std.mem.splitScalar(u8, live, '\n');
        var line_no: usize = 1;
        while (committed_lines.next()) |cl| {
            const ll = live_lines.next() orelse "<missing>";
            if (!std.mem.eql(u8, cl, ll)) {
                std.debug.print("first golden divergence at line {d}:\n  committed: {s}\n  live:      {s}\n", .{ line_no, cl, ll });
                break;
            }
            line_no += 1;
        }
    }
    try std.testing.expectEqualStrings(committed, live);
}
