//! Relay server binary entry point.

const std = @import("std");
const zig_iroh = @import("zig_iroh");
const Server = zig_iroh.relay.server.Server;
const ServerConfig = zig_iroh.relay.server.ServerConfig;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    const config = ServerConfig{};

    std.debug.print("Starting relay server on {s}:{d}\n", .{ config.bind_host, config.bind_port });

    var server = try Server.init(std.heap.page_allocator, io, config);
    defer server.deinit();

    std.debug.print("Relay server listening\n", .{});

    while (true) {
        server.acceptAndSpawn() catch |err| {
            std.debug.print("Connection error: {}\n", .{err});
        };
    }
}
