const std = @import("std");
const root = @import("zig_iroh");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    const node_id = try root.PublicKey.fromZ32("dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy");
    const info = try root.discovery.resolveDohTxt(
        allocator,
        &client,
        root.discovery.DEFAULT_DOH_URL,
        node_id,
        root.discovery.DEFAULT_DNS_ORIGIN,
    );
    defer info.deinit(allocator);

    if (!info.node_id.eql(node_id)) return error.LiveInteropNodeIdMismatch;
    if (info.addrs.len == 0) return error.LiveInteropMissingReachabilityHints;

    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    try stdout_writer.interface.writeAll("discovery live DoH interop: pass\n");
    var relay_it = info.relayUrls();
    while (relay_it.next()) |relay| try stdout_writer.interface.print("relay={s}\n", .{relay.asString()});
    var ip_it = info.ipAddrs();
    while (ip_it.next()) |address| {
        try stdout_writer.interface.print("addr={f}\n", .{address});
    }
    try stdout_writer.interface.flush();
}
