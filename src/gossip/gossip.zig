//! Gossip module root.
const std = @import("std");

pub const postcard = @import("postcard.zig");
pub const frame = @import("frame.zig");
pub const fixtures = @import("fixtures.zig");
pub const types = @import("types.zig");
pub const util = @import("util.zig");
pub const hyparview = @import("proto/hyparview.zig");
pub const plumtree = @import("proto/plumtree.zig");
pub const topic = @import("proto/topic.zig");
pub const state = @import("proto/state.zig");
pub const sim = @import("sim.zig");
pub const net = @import("net.zig");
pub const quic_net = @import("quic_net.zig");

pub const TopicId = types.TopicId;
pub const MessageId = types.MessageId;
pub const Scope = types.Scope;
pub const Config = topic.Config;
pub const Command = topic.Command;
pub const Event = topic.Event;

test {
    _ = postcard;
    _ = frame;
    _ = fixtures;
    _ = types;
    _ = util;
    _ = hyparview;
    _ = plumtree;
    _ = topic;
    _ = state;
    _ = sim;
    _ = net;
    _ = quic_net;
}

test "postcard framing gate" {
    const alloc = std.testing.allocator;
    const golden = @import("fixtures.zig");
    const frame_mod = @import("frame.zig");

    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try frame_mod.writeFrame(&w, &golden.topic_gossip_prune);
    try std.testing.expectEqualSlices(u8, &golden.frame_topic_gossip_prune, w.buffered());

    var r: std.Io.Reader = .fixed(w.buffered());
    const body = try frame_mod.readFrame(&r, alloc, 4096);
    defer alloc.free(body);
    try std.testing.expectEqualSlices(u8, &golden.topic_gossip_prune, body);
}
