//! `zig build discovery-live-interop` — DoH resolution control against a
//! PROJECT-OWNED local nameserver fixture.
//!
//! Historical form hit Cloudflare DoH for the public canary
//! `dgjpkxyn…dns.iroh.link`, which is NXDOMAIN (Status=3) on Google and
//! Cloudflare — an environment failure, not a Zig DoH gap. Fixture ownership
//! (local DoH serving real DNS-wire TXT answers for a known EndpointId) is the
//! honest control; the Zig path under test remains resolveDohTxt.

const std = @import("std");
const root = @import("zig_iroh");

const owned_dns_origin = "fixture.iroh-port.local.";

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    const secret = root.SecretKey.fromBytes(.{0xD0} ** 32);
    const node_id = secret.public();
    const query_name = try root.discovery.txtLookupName(allocator, node_id, owned_dns_origin);
    defer allocator.free(query_name);

    const txt_values = [_][]const u8{
        "relay=https://relay.fixture.iroh-port.local./",
        "addr=127.0.0.1:4242",
    };
    const reply_packet = try root.dns_wire.buildTxtReply(allocator, query_name, &txt_values, 60);
    defer allocator.free(reply_packet);

    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const ServeCtx = struct {
        io: std.Io,
        listener: *std.Io.net.Server,
        packet: []const u8,
    };
    var ctx: ServeCtx = .{
        .io = io,
        .listener = &listener,
        .packet = reply_packet,
    };
    const serveFn = struct {
        fn run(c: *ServeCtx) void {
            var stream = c.listener.accept(c.io) catch return;
            defer stream.close(c.io);
            var read_buf: [8192]u8 = undefined;
            var write_buf: [4096]u8 = undefined;
            var stream_reader = stream.reader(c.io, &read_buf);
            var stream_writer = stream.writer(c.io, &write_buf);
            var http_server = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
            var request = http_server.receiveHead() catch return;
            request.respond(c.packet, .{
                .status = .ok,
                .keep_alive = false,
                .extra_headers = &.{
                    .{ .name = "content-type", .value = root.discovery.DNS_MESSAGE_CONTENT_TYPE },
                },
            }) catch return;
            stream_writer.interface.flush() catch {};
        }
    }.run;
    const thread = try std.Thread.spawn(.{}, serveFn, .{&ctx});
    defer thread.join();

    const port = listener.socket.address.getPort();
    const doh_url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/dns-query", .{port});
    defer allocator.free(doh_url);

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    const info = try root.discovery.resolveDohTxt(
        allocator,
        &client,
        doh_url,
        node_id,
        owned_dns_origin,
    );
    defer info.deinit(allocator);

    if (!info.node_id.eql(node_id)) return error.LiveInteropNodeIdMismatch;
    if (info.addrs.len == 0) return error.LiveInteropMissingReachabilityHints;

    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    try stdout_writer.interface.writeAll("discovery live DoH interop: pass (owned local fixture)\n");
    var relay_it = info.relayUrls();
    while (relay_it.next()) |relay| try stdout_writer.interface.print("relay={s}\n", .{relay.asString()});
    var ip_it = info.ipAddrs();
    while (ip_it.next()) |address| {
        try stdout_writer.interface.print("addr={f}\n", .{address});
    }
    try stdout_writer.interface.flush();
}
