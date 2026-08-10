//! Gossip subsystem metrics — counters that move under real join/broadcast/lag/error events.
const std = @import("std");

pub const Metrics = struct {
    joins: u64 = 0,
    leaves: u64 = 0,
    broadcasts: u64 = 0,
    neighbor_only_broadcasts: u64 = 0,
    neighbor_ups: u64 = 0,
    neighbor_downs: u64 = 0,
    messages_received: u64 = 0,
    lagged: u64 = 0,
    control_ops: u64 = 0,
    control_errors: u64 = 0,
    pumps: u64 = 0,
    shutdowns: u64 = 0,

    pub fn renderPrometheus(self: *const Metrics, w: *std.Io.Writer) !void {
        inline for (.{
            .{ "joins", "Topic join/subscribe calls.", self.joins },
            .{ "leaves", "Topic leave/close calls.", self.leaves },
            .{ "broadcasts", "Swarm broadcast publishes.", self.broadcasts },
            .{ "neighbor_only_broadcasts", "Neighbor-scope publishes.", self.neighbor_only_broadcasts },
            .{ "neighbor_ups", "NeighborUp events delivered to subscribers.", self.neighbor_ups },
            .{ "neighbor_downs", "NeighborDown events delivered to subscribers.", self.neighbor_downs },
            .{ "messages_received", "Received message events delivered to subscribers.", self.messages_received },
            .{ "lagged", "Lagged signals delivered to slow subscribers.", self.lagged },
            .{ "control_ops", "RPC/control-plane operations accepted.", self.control_ops },
            .{ "control_errors", "RPC/control-plane operations rejected.", self.control_errors },
            .{ "pumps", "Actor pump iterations.", self.pumps },
            .{ "shutdowns", "Graceful shutdown calls.", self.shutdowns },
        }) |row| {
            try w.print(
                "# HELP iroh_gossip_{s} {s}\n# TYPE iroh_gossip_{s} counter\niroh_gossip_{s} {d}\n",
                .{ row[0], row[1], row[0], row[0], row[2] },
            );
        }
    }
};

test "gossip metrics renderPrometheus emits counters" {
    var m: Metrics = .{ .joins = 2, .broadcasts = 3, .lagged = 1 };
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try m.renderPrometheus(&w);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "iroh_gossip_joins 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "iroh_gossip_broadcasts 3") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "iroh_gossip_lagged 1") != null);
}
