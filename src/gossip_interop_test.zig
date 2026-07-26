//! Live gossip interop gate: Zig gossip node vs real iroh-gossip (part 3b).
//! Cooperative QUIC pump while waiting for Rust bootstrap stdout — the pump runs
//! inside the readiness predicate (once per arrived line), and the peer lifecycle is
//! owned by testutil/interop_lifecycle.zig (H3): inactivity-window watchdog, group
//! kill + reap, no std.process.exit anywhere.

const std = @import("std");
const zig_iroh = @import("zig_iroh");
const lifecycle = @import("interop_lifecycle");

const key = zig_iroh.key;
const factory = zig_iroh.transport_factory;
const product_flags = zig_iroh.product_flags;
const quic_net = zig_iroh.gossip.quic_net;

const TopicId = quic_net.TopicId;
const Node = quic_net.Node;
const GOSSIP_ALPN: [:0]const u8 = "/iroh-gossip/1";

const topic: TopicId = .{0x42} ** 32;
const hang_ns: u64 = 30 * std.time.ns_per_s;

const InteropError = error{
    HangWatchdog,
    MissingRustNodeId,
    MissingRustBind,
    InvalidBindAddr,
    UnexpectedRustMessage,
    MissingUniProbe,
    UnexpectedUniProbe,
};

fn nowNs(io: std.Io) u64 {
    return @intCast(std.Io.Clock.now(.awake, io).nanoseconds);
}

fn assertProductIdentity(node: *const Node) !void {
    if (!node.gossipEnabled()) return error.GossipDisabled;
    if (node.engine() != factory.productEngine()) return error.WrongGossipEngine;
    if (node.tlsBackend() != factory.productTlsBackend()) return error.WrongGossipTls;
}

/// Startup readiness for the main gossip peer: node id + bound addr (+ TOPIC check),
/// pumping the Zig node once per arrived line (the cooperative-pump contract).
const GossipReady = struct {
    node: *Node,
    node_id: ?key.NodeId = null,
    bound_buf: [64]u8 = undefined,
    bound_len: ?usize = null,
};

fn gossipStartupPredicate(ctx: *GossipReady, line: []const u8) !bool {
    try ctx.node.pump();
    if (std.mem.startsWith(u8, line, "SERVER_NODE_ID: ")) {
        const hex = line["SERVER_NODE_ID: ".len..];
        var bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, hex);
        ctx.node_id = try key.PublicKey.fromBytes(bytes);
    } else if (std.mem.startsWith(u8, line, "SERVER_BOUND: ")) {
        const bound = line["SERVER_BOUND: ".len..];
        if (bound.len > ctx.bound_buf.len) return InteropError.InvalidBindAddr;
        @memcpy(ctx.bound_buf[0..bound.len], bound);
        ctx.bound_len = bound.len;
    } else if (std.mem.startsWith(u8, line, "TOPIC: ")) {
        const hex = line["TOPIC: ".len..];
        var topic_bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&topic_bytes, hex);
        if (!std.mem.eql(u8, &topic, &topic_bytes)) return InteropError.UnexpectedRustMessage;
    } else if (std.mem.startsWith(u8, line, "GOSSIP_RECEIVED: ")) {
        const msg = line["GOSSIP_RECEIVED: ".len..];
        if (!std.mem.eql(u8, msg, "hello-from-zig")) return InteropError.UnexpectedRustMessage;
    }
    return ctx.node_id != null and ctx.bound_len != null;
}

pub fn main(init: std.process.Init) !void {
    // Own DebugAllocator with leak=fail (safety-leaks honesty — W2 #2; this gate used
    // page_allocator, which made the "GPA leak checking" claim false for it). init.io
    // carries the REAL process environment (a hand-rolled Threaded io defaults to an
    // empty environ — bare `cargo` would resolve against default_PATH and fail).
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer {
        if (gpa.deinit() == .leak) {
            std.debug.print("FAIL: gossip interop leaked (see reports above)\n", .{});
            std.process.exit(1);
        }
    }
    const alloc = gpa.allocator();
    const io = init.io;

    try runUniProbe(alloc, io);

    const zig_key = key.SecretKey.fromBytes(.{0xA1} ** 32);
    const zig_id = zig_key.public();

    var zig_node = try Node.init(alloc, io, zig_key, GOSSIP_ALPN);
    defer zig_node.deinit();
    try assertProductIdentity(&zig_node);
    std.debug.print("GOSSIP_PRODUCT={s} ENGINE={s} TLS={s} ENABLED={}\n", .{
        product_flags.product_name,
        @tagName(zig_node.engine()),
        @tagName(zig_node.tlsBackend()),
        product_flags.has_gossip,
    });
    const zig_local = zig_node.localAddress();
    var zig_bound_buf: [32]u8 = undefined;
    const zig_bound = try std.fmt.bufPrint(&zig_bound_buf, "127.0.0.1:{d}", .{zig_local.getPort()});

    var zig_id_buf: [64]u8 = undefined;
    for (zig_id.toBytes(), 0..) |byte, i| {
        _ = std.fmt.bufPrint(zig_id_buf[i * 2 ..][0..2], "{x:0>2}", .{byte}) catch unreachable;
    }

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var cmd_buf: [896]u8 = undefined;
    // sh -c only to pass ZIG_NODE_ID/ZIG_BOUND; cargo resolves via the inherited PATH
    // (no host-specific PATH override — H2). `exec` keeps one process in the group.
    const cmd = try std.fmt.bufPrint(
        &cmd_buf,
        "ZIG_NODE_ID={s} ZIG_BOUND={s} exec cargo run --manifest-path {s} --example gossip_interop_peer",
        .{ zig_id_buf[0..64], zig_bound, manifest },
    );

    var peer: lifecycle.Peer = undefined;
    try peer.spawn(alloc, io, .{ .argv = &.{ "sh", "-c", cmd } });
    defer peer.deinit();

    var got_rust_received = std.atomic.Value(bool).init(false);
    var unexpected_rust_stdout = std.atomic.Value(bool).init(false);

    var ready: GossipReady = .{ .node = &zig_node };
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, gossipStartupPredicate);
    // The startup phase is done on the main path; a result thread takes over the
    // reader (sequential handoff) to watch for the rust-side GOSSIP_RECEIVED.
    const stdout_thread = try std.Thread.spawn(.{}, rustReceiveThread, .{ &peer, &got_rust_received, &unexpected_rust_stdout });
    defer {
        peer.killReap(); // EOF unblocks the thread's nextLine (defer #2 runs first)
        stdout_thread.join();
    }

    const rust_id = ready.node_id orelse return InteropError.MissingRustNodeId;
    const bound_str = if (ready.bound_len) |len| ready.bound_buf[0..len] else return InteropError.MissingRustBind;

    const rust_addr = try lifecycle.parseHostPort(bound_str);

    try zig_node.registerPeer(rust_id, .{
        .id = rust_id,
        .addrs = &.{.{ .ip = rust_addr }},
    });
    _ = try zig_node.connectTo(rust_id);

    try zig_node.join(topic, &.{rust_id});

    const join_start = nowNs(io);
    while (!zig_node.isJoined(topic)) {
        if (nowNs(io) - join_start > hang_ns) return InteropError.HangWatchdog;
        try zig_node.pump();
        if (unexpected_rust_stdout.load(.acquire)) return InteropError.UnexpectedRustMessage;
    }

    try zig_node.broadcast(topic, "hello-from-zig");

    const gate_start = nowNs(io);
    while (!got_rust_received.load(.acquire) or !zig_node.hasReceived(topic, "hello-from-rust")) {
        if (nowNs(io) - gate_start > hang_ns) {
            std.debug.print("gossip timeout: rust_received={} zig_received={}\n", .{
                got_rust_received.load(.acquire),
                zig_node.hasReceived(topic, "hello-from-rust"),
            });
            return InteropError.HangWatchdog;
        }
        try zig_node.pump();
        if (unexpected_rust_stdout.load(.acquire)) return InteropError.UnexpectedRustMessage;
    }

    std.debug.print("PASS: Zig gossip interoperated with real iroh-gossip (bidirectional)\n", .{});
}

fn runUniProbe(alloc: std.mem.Allocator, io: std.Io) !void {
    const secret = key.SecretKey.fromBytes(.{0xA1} ** 32);
    const endpoint = try factory.createForProduct(alloc, io, secret, GOSSIP_ALPN, .{});
    defer endpoint.deinit();

    try lifecycle.probeCargo(io);
    const manifest = try lifecycle.findManifest(io, "iroh/Cargo.toml");
    var cmd_buf: [768]u8 = undefined;
    const cmd = try std.fmt.bufPrint(
        &cmd_buf,
        "exec cargo run --manifest-path {s} --example gossip_interop_peer -- --uni-probe",
        .{manifest},
    );

    var peer: lifecycle.Peer = undefined;
    try peer.spawn(alloc, io, .{ .argv = &.{ "sh", "-c", cmd } });
    defer peer.deinit();

    var ready: ServerReady = .{};
    try peer.waitLines(lifecycle.cargo_startup_window, &ready, serverPredicate);

    const rust_id = ready.node_id orelse return InteropError.MissingUniProbe;
    const rust_bound = if (ready.bound_len) |len| ready.bound_buf[0..len] else return InteropError.MissingUniProbe;
    const rust_addr = try lifecycle.parseHostPort(rust_bound);
    const conn = try endpoint.transport().connect(.{
        .id = rust_id,
        .addrs = &.{.{ .ip = rust_addr }},
    });
    defer conn.close();

    const send = try conn.openUni();
    try send.writer().writeAll("zig-to-rust-uni");
    try send.finish();

    peer.armWatchdog(lifecycle.post_startup_window);
    var rust_received = false;
    while (!rust_received) {
        const line = (try peer.nextLine()) orelse return InteropError.MissingUniProbe;
        if (std.mem.startsWith(u8, line, "UNI_RECEIVED: ")) {
            const msg = line["UNI_RECEIVED: ".len..];
            if (!std.mem.eql(u8, msg, "zig-to-rust-uni")) return InteropError.UnexpectedUniProbe;
            rust_received = true;
        }
    }
    peer.disarmWatchdog();

    var got_reply = false;
    const reply_deadline = nowNs(io) + hang_ns;
    var reply_buf: [64]u8 = undefined;
    var reply_len: usize = 0;
    var scratch: [1024]u8 = undefined;
    while (!got_reply) {
        if (nowNs(io) > reply_deadline) return InteropError.MissingUniProbe;
        const event = (try endpoint.nextInboundUniEvent(conn, &scratch)) orelse continue;
        const chunk = switch (event) {
            .chunk => |chunk| chunk,
            .reset => return InteropError.UnexpectedUniProbe,
        };
        if (chunk.bytes.len == 0) {
            continue;
        }
        if (reply_len + chunk.bytes.len > reply_buf.len) return InteropError.UnexpectedUniProbe;
        @memcpy(reply_buf[reply_len..][0..chunk.bytes.len], chunk.bytes);
        reply_len += chunk.bytes.len;
        if (std.mem.eql(u8, reply_buf[0..reply_len], "rust-to-zig-uni")) got_reply = true;
    }

    std.debug.print("PASS: real iroh uni-stream probe passed\n", .{});
}

/// Uni-probe startup readiness (node id + bound addr).
const ServerReady = struct {
    node_id: ?key.NodeId = null,
    bound_buf: [64]u8 = undefined,
    bound_len: ?usize = null,
};

fn serverPredicate(ctx: *ServerReady, line: []const u8) !bool {
    if (std.mem.startsWith(u8, line, "SERVER_NODE_ID: ")) {
        const hex = line["SERVER_NODE_ID: ".len..];
        var bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, hex);
        ctx.node_id = try key.PublicKey.fromBytes(bytes);
    } else if (std.mem.startsWith(u8, line, "SERVER_BOUND: ")) {
        const bound = line["SERVER_BOUND: ".len..];
        if (bound.len > ctx.bound_buf.len) return InteropError.InvalidBindAddr;
        @memcpy(ctx.bound_buf[0..bound.len], bound);
        ctx.bound_len = bound.len;
    }
    return ctx.node_id != null and ctx.bound_len != null;
}

fn rustReceiveThread(
    peer: *lifecycle.Peer,
    got_rust_received: *std.atomic.Value(bool),
    unexpected_rust_stdout: *std.atomic.Value(bool),
) void {
    while (true) {
        const line = peer.nextLine() catch return;
        const l = line orelse return;
        if (std.mem.startsWith(u8, l, "GOSSIP_RECEIVED: ")) {
            const msg = l["GOSSIP_RECEIVED: ".len..];
            if (!std.mem.eql(u8, msg, "hello-from-zig")) {
                unexpected_rust_stdout.store(true, .release);
                return;
            }
            got_rust_received.store(true, .release);
            return;
        }
    }
}
