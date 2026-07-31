//! `iroh-dns-pkarr` — publish and fetch signed packets against a pkarr relay.
//!
//! The operator-side counterpart to `iroh-dns-server`: it exercises the same
//! `PUT`/`GET /pkarr/{z32}` surface a real iroh endpoint uses, which makes it the
//! tool for checking a deployment from outside the process.
//!
//! Usage:
//!   iroh-dns-pkarr --publish --relay http://127.0.0.1:8080 --secret <hex64> \
//!                  [--relay-url https://relay.example] [--addr 192.0.2.44:1234]
//!   iroh-dns-pkarr --resolve --relay http://127.0.0.1:8080 --key <z32>

const std = @import("std");
const zig_iroh = @import("zig_iroh");

const discovery = zig_iroh.discovery;
const dns_server = zig_iroh.dns_server;

const usage_text =
    \\Usage: iroh-dns-pkarr <--publish|--resolve> --relay URL [options]
    \\
    \\Modes:
    \\  --publish                 sign an endpoint packet and PUT it to the relay
    \\  --resolve                 GET a packet from the relay and print its records
    \\
    \\Options:
    \\      --relay URL           pkarr relay base URL (e.g. http://127.0.0.1:8080)
    \\      --secret HEX          32-byte secret key as 64 hex chars (--publish)
    \\      --key Z32             endpoint id in z-base-32 (--resolve)
    \\      --relay-url URL       relay URL to advertise in the packet (--publish)
    \\      --addr HOST:PORT      direct address to advertise, repeatable (--publish)
    \\      --ttl SECS            record TTL to publish (default 30)
    \\  -h, --help                print this text
    \\
;

const Mode = enum { publish, resolve };

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.arena.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const out = &stdout_writer.interface;
    defer out.flush() catch {};

    const argv = try init.minimal.args.toSlice(allocator);
    var mode: ?Mode = null;
    var relay_base: ?[]const u8 = null;
    var secret_hex: ?[]const u8 = null;
    var key_z32: ?[]const u8 = null;
    var advertise_relay: ?[]const u8 = null;
    var ttl: u32 = 30;
    var addrs: std.ArrayList([]const u8) = .empty;

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try out.writeAll(usage_text);
            return;
        } else if (std.mem.eql(u8, arg, "--publish")) {
            mode = .publish;
        } else if (std.mem.eql(u8, arg, "--resolve")) {
            mode = .resolve;
        } else if (std.mem.eql(u8, arg, "--relay")) {
            relay_base = try nextArg(out, argv, &i);
        } else if (std.mem.eql(u8, arg, "--secret")) {
            secret_hex = try nextArg(out, argv, &i);
        } else if (std.mem.eql(u8, arg, "--key")) {
            key_z32 = try nextArg(out, argv, &i);
        } else if (std.mem.eql(u8, arg, "--relay-url")) {
            advertise_relay = try nextArg(out, argv, &i);
        } else if (std.mem.eql(u8, arg, "--addr")) {
            try addrs.append(allocator, try nextArg(out, argv, &i));
        } else if (std.mem.eql(u8, arg, "--ttl")) {
            ttl = std.fmt.parseInt(u32, try nextArg(out, argv, &i), 10) catch {
                try out.writeAll("error: --ttl must be a non-negative integer\n");
                std.process.exit(2);
            };
        } else {
            try out.print("error: unknown argument {s}\n", .{arg});
            try out.writeAll(usage_text);
            std.process.exit(2);
        }
    }

    const selected = mode orelse {
        try out.writeAll("error: one of --publish or --resolve is required\n");
        try out.writeAll(usage_text);
        std.process.exit(2);
    };
    const base = relay_base orelse {
        try out.writeAll("error: --relay is required\n");
        std.process.exit(2);
    };

    switch (selected) {
        .publish => {
            const hex = secret_hex orelse {
                try out.writeAll("error: --publish requires --secret\n");
                std.process.exit(2);
            };
            const secret = zig_iroh.SecretKey.parse(hex) catch {
                try out.writeAll("error: --secret must be 64 hex chars or 52 base32 chars\n");
                std.process.exit(2);
            };
            try publish(allocator, io, out, base, secret, advertise_relay, addrs.items, ttl);
        },
        .resolve => {
            const z32 = key_z32 orelse {
                try out.writeAll("error: --resolve requires --key\n");
                std.process.exit(2);
            };
            try resolve(allocator, io, out, base, z32);
        },
    }
}

fn nextArg(out: *std.Io.Writer, argv: []const []const u8, i: *usize) ![]const u8 {
    i.* += 1;
    if (i.* >= argv.len) {
        try out.print("error: {s} requires a value\n", .{argv[i.* - 1]});
        try out.flush();
        std.process.exit(2);
    }
    return argv[i.*];
}

fn publish(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    base: []const u8,
    secret: zig_iroh.SecretKey,
    advertise_relay: ?[]const u8,
    addrs: []const []const u8,
    ttl: u32,
) !void {
    var parts: std.ArrayList(zig_iroh.TransportAddr) = .empty;
    defer parts.deinit(allocator);

    var relay_url: ?zig_iroh.RelayUrl = null;
    defer if (relay_url) |*r| r.deinit(allocator);
    if (advertise_relay) |url| {
        relay_url = try zig_iroh.RelayUrl.parse(allocator, url);
        try parts.append(allocator, .{ .relay = relay_url.? });
    }
    for (addrs) |addr| {
        const split = try dns_server.config.splitBindAddr(addr);
        const parsed = try std.Io.net.IpAddress.parse(split.host, split.port);
        try parts.append(allocator, .{ .ip = parsed });
    }
    if (parts.items.len == 0) {
        try out.writeAll("error: --publish needs at least one --relay-url or --addr\n");
        std.process.exit(2);
    }

    const info = try discovery.EndpointInfo.fromParts(allocator, secret.public(), parts.items, null);
    defer info.deinit(allocator);
    var packet = try discovery.SignedPacket.fromEndpointInfoAt(
        allocator,
        secret,
        info,
        ttl,
        .{ .micros = dns_server.store.ZoneStore.nowMicros(io) },
    );
    defer packet.deinit(allocator);

    const z32 = secret.public().toZ32();
    const url = try std.fmt.allocPrint(allocator, "{s}/pkarr/{s}", .{ trimSlash(base), &z32 });
    defer allocator.free(url);

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    var body: std.Io.Writer.Allocating = .init(allocator);
    defer body.deinit();
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = .PUT,
        .payload = packet.relayPayload(),
        .headers = .{ .content_type = .{ .override = discovery.RELAY_CONTENT_TYPE } },
        .response_writer = &body.writer,
    });

    try out.print("PUT {s} -> {d} {s}\n", .{ url, @intFromEnum(result.status), result.status.phrase() orelse "" });
    if (result.status != .no_content) {
        try out.print("body: {s}\n", .{body.writer.buffered()});
        try out.flush();
        std.process.exit(1);
    }
    try out.print("published {d} record(s) for {s} (ttl {d}s)\n", .{ parts.items.len, &z32, ttl });
}

fn resolve(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    base: []const u8,
    z32: []const u8,
) !void {
    const public_key = zig_iroh.PublicKey.fromZ32(z32) catch {
        try out.writeAll("error: --key must be a z-base-32 endpoint id\n");
        std.process.exit(2);
    };
    const url = try std.fmt.allocPrint(allocator, "{s}/pkarr/{s}", .{ trimSlash(base), z32 });
    defer allocator.free(url);

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    var body: std.Io.Writer.Allocating = .init(allocator);
    defer body.deinit();
    const result = try client.fetch(.{
        .location = .{ .url = url },
        .method = .GET,
        .response_writer = &body.writer,
    });
    try out.print("GET {s} -> {d} {s}\n", .{ url, @intFromEnum(result.status), result.status.phrase() orelse "" });
    if (result.status != .ok) {
        try out.flush();
        std.process.exit(1);
    }

    // Verifies the signature against --key; a relay cannot hand back a forged zone.
    var packet = try discovery.SignedPacket.fromRelayPayload(allocator, public_key, body.writer.buffered());
    defer packet.deinit(allocator);
    try out.print("timestamp: {d}\n", .{packet.timestamp.micros});

    const answers = try dns_server.dns.parseRawAnswers(allocator, packet.encodedPacket());
    defer dns_server.dns.freeRawAnswers(allocator, answers);
    for (answers) |a| {
        try out.print("{s} {d} type={d} rdlen={d}\n", .{ a.name, a.ttl, a.typ, a.rdata.len });
        if (a.typ == zig_iroh.dns_wire.TYPE_TXT) {
            var off: usize = 0;
            while (off < a.rdata.len) {
                const len = a.rdata[off];
                off += 1;
                if (off + len > a.rdata.len) break;
                try out.print("  txt: {s}\n", .{a.rdata[off .. off + len]});
                off += len;
            }
        }
    }
}

fn trimSlash(url: []const u8) []const u8 {
    return std.mem.trimEnd(u8, url, "/");
}
