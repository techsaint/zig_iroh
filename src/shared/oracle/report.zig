//! Durable report-card recorder for the iroh integration-suite oracle.
//!
//! Writes a machine-readable JSON report with pass|fail|blocked truth.
//! Honest red/blocked is success for scaffolding; a false green is not.

const std = @import("std");
const shape = @import("shape.zig");

pub const ReportCard = struct {
    /// 2 as of 2026-07-28: adds `measured_change` / `measured_commit`. A v1 card is still valid
    /// input — it simply cannot answer the ancestry question, which is exactly what v2 fixes.
    schema_version: u32 = 2,
    run_id: []const u8,
    gate_command: []const u8,
    generated_at: []const u8,
    manifest_path: []const u8,
    registry_size: usize,
    /// WHICH TREE THIS CARD MEASURED. Absent until 2026-07-28, and that absence was load-bearing:
    ///
    ///   * the roll-up could not prefer the ANCESTRALLY-later card over the newest-by-clock one, so
    ///     two lanes forking from one base silently overwrote each other — 16 of 120 multiply-
    ///     reported keys disagreed, 12 resolving against the majority of observations;
    ///   * `check_lane_closure.py` resolves its contested keys by the same clock heuristic;
    ///   * a promote cannot ask "does this lane's evidence describe the tree I am landing?", so it
    ///     regenerates all four products' cards unconditionally — even when nothing moved;
    ///   * the promote receipt has no `candidate_parent` to record;
    ///   * the same field is missing from the measurement ledger.
    ///
    /// ONE FIELD, FIVE CONSUMERS. `null` means "this runner did not know its own tree" — an honest
    /// unknown that a consumer must handle, NOT a claim about an empty tree. Never synthesise a
    /// value here: a wrong provenance is worse than none, because it makes a stale card look fresh.
    measured_change: ?[]const u8 = null,
    /// The commit id for the same tree. Kept alongside the change id because a jj change is stable
    /// across rewrites while the commit is the exact content — ancestry needs the change, integrity
    /// needs the commit.
    measured_commit: ?[]const u8 = null,
    rows: []const shape.ReportRow,

    pub fn summary(self: ReportCard) struct { pass: usize, fail: usize, blocked: usize } {
        var pass: usize = 0;
        var fail: usize = 0;
        var blocked: usize = 0;
        for (self.rows) |row| {
            switch (row.result) {
                .pass => pass += 1,
                .fail => fail += 1,
                .blocked => blocked += 1,
            }
        }
        return .{ .pass = pass, .fail = fail, .blocked = blocked };
    }
};

/// Write the report-card JSON to `path` using std.Io.
pub fn writeReportCard(io: std.Io, path: []const u8, card: ReportCard) !void {
    const cwd = std.Io.Dir.cwd();
    const file = try cwd.createFile(io, path, .{});
    defer file.close(io);

    var buf: [8192]u8 = undefined;
    var file_writer = file.writer(io, &buf);
    const w = &file_writer.interface;

    const counts = card.summary();

    try w.writeAll("{\n");
    try w.print("  \"schema_version\": {d},\n", .{card.schema_version});
    try w.print("  \"run_id\": {f},\n", .{std.json.fmt(card.run_id, .{})});
    try w.print("  \"gate_command\": {f},\n", .{std.json.fmt(card.gate_command, .{})});
    try w.print("  \"generated_at\": {f},\n", .{std.json.fmt(card.generated_at, .{})});
    try w.print("  \"manifest_path\": {f},\n", .{std.json.fmt(card.manifest_path, .{})});
    // Emitted ALWAYS, as JSON null when unknown — never omitted. A missing key and a null value are
    // different facts: "written by a v1 runner" vs "a v2 runner that could not resolve its tree".
    // A consumer that must distinguish them (the roll-up's ancestry preference does) needs both.
    if (card.measured_change) |c| {
        try w.print("  \"measured_change\": {f},\n", .{std.json.fmt(c, .{})});
    } else {
        try w.writeAll("  \"measured_change\": null,\n");
    }
    if (card.measured_commit) |c| {
        try w.print("  \"measured_commit\": {f},\n", .{std.json.fmt(c, .{})});
    } else {
        try w.writeAll("  \"measured_commit\": null,\n");
    }
    try w.writeAll("  \"summary\": {\n");
    try w.print("    \"pass\": {d},\n", .{counts.pass});
    try w.print("    \"fail\": {d},\n", .{counts.fail});
    try w.print("    \"blocked\": {d},\n", .{counts.blocked});
    try w.print("    \"total_rows\": {d},\n", .{card.rows.len});
    try w.print("    \"registry_size\": {d}\n", .{card.registry_size});
    try w.writeAll("  },\n");
    try w.writeAll("  \"rows\": [\n");

    for (card.rows, 0..) |row, i| {
        try w.writeAll("    {\n");
        try w.print("      \"scenario_id\": {f},\n", .{std.json.fmt(row.scenario_id, .{})});
        try w.print("      \"source_ref\": {f},\n", .{std.json.fmt(row.source_ref, .{})});
        try w.print("      \"product\": {f},\n", .{std.json.fmt(row.product, .{})});
        try w.print("      \"gate_command\": {f},\n", .{std.json.fmt(row.gate_command, .{})});
        try w.print("      \"result\": {f},\n", .{std.json.fmt(row.result.asString(), .{})});
        try w.print("      \"coverage_disposition\": {f},\n", .{std.json.fmt(row.coverage_disposition.asString(), .{})});
        try w.print("      \"reason\": {f},\n", .{std.json.fmt(row.reason, .{})});
        if (row.missing_capability) |cap| {
            try w.print("      \"missing_capability\": {f},\n", .{std.json.fmt(cap, .{})});
        } else {
            try w.writeAll("      \"missing_capability\": null,\n");
        }
        try w.writeAll("      \"artifacts\": [");
        for (row.artifacts, 0..) |art, j| {
            if (j > 0) try w.writeAll(", ");
            try w.print("{f}", .{std.json.fmt(art, .{})});
        }
        try w.writeAll("]\n");
        try w.writeAll("    }");
        if (i + 1 < card.rows.len) try w.writeAll(",");
        try w.writeAll("\n");
    }

    try w.writeAll("  ]\n");
    try w.writeAll("}\n");
    try w.flush();
}

test "result strings" {
    try std.testing.expectEqualStrings("pass", shape.Result.pass.asString());
    try std.testing.expectEqualStrings("blocked", shape.Result.blocked.asString());
    try std.testing.expectEqualStrings("overlap/control", shape.CoverageDisposition.@"overlap/control".asString());
}
