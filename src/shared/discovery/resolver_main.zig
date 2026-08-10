const std = @import("std");
const root = @import("zig_iroh");

pub fn main(init: std.process.Init) !void {
    try root.discovery_server.serve(init.io, init.gpa, .{});
}
