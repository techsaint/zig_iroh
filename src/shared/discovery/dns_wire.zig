//! Minimal DNS wire helpers for iroh discovery.
//!
//! This intentionally implements only the subset discovery needs:
//! id=0 TXT queries/replies, IN class, RFC 1035 names, and compressed
//! answer-owner names. It is not a general DNS library.

const std = @import("std");

pub const Error = error{
    NameTooLong,
    LabelTooLong,
    PacketTooShort,
    BadPointer,
    PointerLoop,
    BadName,
    UnsupportedRecord,
    TruncatedRecord,
    NoQuestion,
} || std.mem.Allocator.Error;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_AXFR: u16 = 252;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u4 = 0;
pub const RCODE_NXDOMAIN: u4 = 3;
pub const RCODE_REFUSED: u4 = 5;

pub const Question = struct {
    id: u16,
    name: []u8,
    typ: u16,
    class: u16,
};

/// Parse the first question from a DNS query packet. Caller frees `question.name`.
pub fn parseQuestion(allocator: std.mem.Allocator, packet: []const u8) Error!Question {
    if (packet.len < 12) return error.PacketTooShort;
    const qdcount = readU16(packet, 4);
    if (qdcount == 0) return error.NoQuestion;
    var name_buf: std.ArrayList(u8) = .empty;
    errdefer name_buf.deinit(allocator);
    const after_name = try parseNameInto(allocator, packet, 12, &name_buf);
    if (after_name + 4 > packet.len) return error.PacketTooShort;
    return .{
        .id = readU16(packet, 0),
        .name = try name_buf.toOwnedSlice(allocator),
        .typ = readU16(packet, after_name),
        .class = readU16(packet, after_name + 2),
    };
}

/// Build a response that echoes the question and optionally appends TXT answers.
pub fn buildResponse(
    allocator: std.mem.Allocator,
    query_id: u16,
    question_name: []const u8,
    question_type: u16,
    rcode: u4,
    txt_values: []const []const u8,
    ttl: u32,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const flags: u16 = 0x8000 | @as(u16, rcode); // QR=1, AA unset here (caller may OR later)
    try writeU16(&out, allocator, query_id);
    try writeU16(&out, allocator, flags | 0x0400); // AA=1
    try writeU16(&out, allocator, 1); // qdcount
    const ancount: u16 = if (rcode == RCODE_NOERROR) @intCast(txt_values.len) else 0;
    try writeU16(&out, allocator, ancount);
    try writeU16(&out, allocator, 0);
    try writeU16(&out, allocator, 0);

    const qname_offset = out.items.len;
    try appendName(&out, allocator, question_name);
    try writeU16(&out, allocator, question_type);
    try writeU16(&out, allocator, CLASS_IN);

    if (ancount == 0) return out.toOwnedSlice(allocator);

    // TXT answers only (the dns-server product's primary pkarr path).
    if (question_type != TYPE_TXT) return out.toOwnedSlice(allocator);

    for (txt_values, 0..) |value, i| {
        if (i == 0) {
            try appendName(&out, allocator, question_name);
        } else {
            try appendPointer(&out, allocator, qname_offset);
        }
        try writeU16(&out, allocator, TYPE_TXT);
        try writeU16(&out, allocator, CLASS_IN);
        try writeU32(&out, allocator, ttl);
        if (value.len > 255) return error.LabelTooLong;
        try writeU16(&out, allocator, @intCast(value.len + 1));
        try out.append(allocator, @intCast(value.len));
        try out.appendSlice(allocator, value);
    }
    return out.toOwnedSlice(allocator);
}

/// Minimal SOA answer for an origin apex.
pub fn buildSoaResponse(
    allocator: std.mem.Allocator,
    query_id: u16,
    question_name: []const u8,
    soa_mname: []const u8,
    soa_rname: []const u8,
    serial: u32,
    ttl: u32,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try writeU16(&out, allocator, query_id);
    try writeU16(&out, allocator, 0x8400); // QR+AA
    try writeU16(&out, allocator, 1);
    try writeU16(&out, allocator, 1);
    try writeU16(&out, allocator, 0);
    try writeU16(&out, allocator, 0);
    try appendName(&out, allocator, question_name);
    try writeU16(&out, allocator, TYPE_SOA);
    try writeU16(&out, allocator, CLASS_IN);
    try appendName(&out, allocator, question_name);
    try writeU16(&out, allocator, TYPE_SOA);
    try writeU16(&out, allocator, CLASS_IN);
    try writeU32(&out, allocator, ttl);
    // rdlength filled after rdata
    const rdlen_at = out.items.len;
    try writeU16(&out, allocator, 0);
    const rdata_start = out.items.len;
    try appendName(&out, allocator, soa_mname);
    try appendName(&out, allocator, soa_rname);
    try writeU32(&out, allocator, serial);
    try writeU32(&out, allocator, 10800); // refresh
    try writeU32(&out, allocator, 3600); // retry
    try writeU32(&out, allocator, 604800); // expire
    try writeU32(&out, allocator, 3600); // minimum
    const rdlen: u16 = @intCast(out.items.len - rdata_start);
    std.mem.writeInt(u16, out.items[rdlen_at..][0..2], rdlen, .big);
    return out.toOwnedSlice(allocator);
}

pub fn buildTxtQuery(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try writeU16(&out, allocator, 0); // id
    try writeU16(&out, allocator, 0x0100); // recursion desired
    try writeU16(&out, allocator, 1); // qdcount
    try writeU16(&out, allocator, 0); // ancount
    try writeU16(&out, allocator, 0); // nscount
    try writeU16(&out, allocator, 0); // arcount
    try appendName(&out, allocator, name);
    try writeU16(&out, allocator, TYPE_TXT);
    try writeU16(&out, allocator, CLASS_IN);
    return out.toOwnedSlice(allocator);
}

pub fn buildTxtReply(
    allocator: std.mem.Allocator,
    name: []const u8,
    values: []const []const u8,
    ttl: u32,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try writeU16(&out, allocator, 0); // id
    try writeU16(&out, allocator, 0x8000); // response
    try writeU16(&out, allocator, 0); // qdcount
    try writeU16(&out, allocator, @intCast(values.len)); // ancount
    try writeU16(&out, allocator, 0); // nscount
    try writeU16(&out, allocator, 0); // arcount

    var name_offset: ?usize = null;
    for (values, 0..) |value, i| {
        if (i == 0) {
            name_offset = out.items.len;
            try appendName(&out, allocator, name);
        } else {
            try appendPointer(&out, allocator, name_offset.?);
        }
        try writeU16(&out, allocator, TYPE_TXT);
        try writeU16(&out, allocator, CLASS_IN);
        try writeU32(&out, allocator, ttl);
        if (value.len > 255) return error.LabelTooLong;
        try writeU16(&out, allocator, @intCast(value.len + 1));
        try out.append(allocator, @intCast(value.len));
        try out.appendSlice(allocator, value);
    }

    return out.toOwnedSlice(allocator);
}

pub fn parseTxtAnswers(
    allocator: std.mem.Allocator,
    packet: []const u8,
    expected_name: []const u8,
) ![][]u8 {
    if (packet.len < 12) return error.PacketTooShort;

    const qdcount = readU16(packet, 4);
    const ancount = readU16(packet, 6);
    var offset: usize = 12;

    var i: usize = 0;
    while (i < qdcount) : (i += 1) {
        var scratch: std.ArrayList(u8) = .empty;
        defer scratch.deinit(allocator);
        offset = try parseNameInto(allocator, packet, offset, &scratch);
        if (offset + 4 > packet.len) return error.PacketTooShort;
        offset += 4;
    }

    var values: std.ArrayList([]u8) = .empty;
    errdefer {
        for (values.items) |v| allocator.free(v);
        values.deinit(allocator);
    }

    i = 0;
    while (i < ancount) : (i += 1) {
        var name: std.ArrayList(u8) = .empty;
        defer name.deinit(allocator);
        offset = try parseNameInto(allocator, packet, offset, &name);
        if (offset + 10 > packet.len) return error.PacketTooShort;

        const typ = readU16(packet, offset);
        offset += 2;
        const class = readU16(packet, offset);
        offset += 2;
        offset += 4; // ttl
        const rdlen = readU16(packet, offset);
        offset += 2;
        if (offset + rdlen > packet.len) return error.TruncatedRecord;
        const rdata = packet[offset .. offset + rdlen];
        offset += rdlen;

        if (typ != TYPE_TXT or class != CLASS_IN) continue;
        if (!dnsNameEql(name.items, expected_name)) continue;
        if (rdata.len == 0) return error.TruncatedRecord;
        var rdoff: usize = 0;
        while (rdoff < rdata.len) {
            const len = rdata[rdoff];
            rdoff += 1;
            if (rdoff + len > rdata.len) return error.TruncatedRecord;
            try values.append(allocator, try allocator.dupe(u8, rdata[rdoff .. rdoff + len]));
            rdoff += len;
        }
    }

    return values.toOwnedSlice(allocator);
}

/// Read the TTL of the FIRST answer record off a DNS reply packet, or `null`
/// when the packet carries no answers. The pkarr signed packet embeds a TXT
/// reply (§ buildTxtReply), so this is the wire-observable TTL of a published
/// record — the evidence that a configured publish TTL reached the wire.
pub fn parseFirstAnswerTtl(allocator: std.mem.Allocator, packet: []const u8) Error!?u32 {
    if (packet.len < 12) return error.PacketTooShort;
    const qdcount = readU16(packet, 4);
    const ancount = readU16(packet, 6);
    if (ancount == 0) return null;

    var offset: usize = 12;
    var i: usize = 0;
    while (i < qdcount) : (i += 1) {
        var scratch: std.ArrayList(u8) = .empty;
        defer scratch.deinit(allocator);
        offset = try parseNameInto(allocator, packet, offset, &scratch);
        if (offset + 4 > packet.len) return error.PacketTooShort;
        offset += 4;
    }

    var name: std.ArrayList(u8) = .empty;
    defer name.deinit(allocator);
    offset = try parseNameInto(allocator, packet, offset, &name);
    if (offset + 10 > packet.len) return error.PacketTooShort;
    // answer: name | typ(2) | class(2) | ttl(4) | rdlen(2) | rdata
    return std.mem.readInt(u32, packet[offset + 4 ..][0..4], .big);
}

pub fn appendName(out: *std.ArrayList(u8), allocator: std.mem.Allocator, name_in: []const u8) !void {
    const name = std.mem.trimEnd(u8, name_in, ".");
    if (name.len == 0) {
        try out.append(allocator, 0);
        return;
    }
    if (name.len > 253) return error.NameTooLong;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0) return error.BadName;
        if (label.len > 63) return error.LabelTooLong;
        try out.append(allocator, @intCast(label.len));
        try out.appendSlice(allocator, label);
    }
    try out.append(allocator, 0);
}

fn appendPointer(out: *std.ArrayList(u8), allocator: std.mem.Allocator, target: usize) !void {
    if (target > 0x3fff) return error.BadPointer;
    try writeU16(out, allocator, 0xc000 | @as(u16, @intCast(target)));
}

fn parseNameInto(
    allocator: std.mem.Allocator,
    packet: []const u8,
    start: usize,
    out: *std.ArrayList(u8),
) !usize {
    var offset = start;
    var next = start;
    var jumped = false;
    var jumps: usize = 0;

    while (true) {
        if (offset >= packet.len) return error.PacketTooShort;
        const len = packet[offset];
        if ((len & 0xc0) == 0xc0) {
            if (offset + 1 >= packet.len) return error.PacketTooShort;
            const ptr = (@as(usize, len & 0x3f) << 8) | packet[offset + 1];
            if (ptr >= packet.len) return error.BadPointer;
            if (!jumped) next = offset + 2;
            jumped = true;
            jumps += 1;
            if (jumps > 16) return error.PointerLoop;
            offset = ptr;
            continue;
        }
        if ((len & 0xc0) != 0) return error.BadName;
        offset += 1;
        if (len == 0) {
            if (!jumped) next = offset;
            break;
        }
        if (len > 63 or offset + len > packet.len) return error.BadName;
        if (out.items.len != 0) try out.append(allocator, '.');
        try out.appendSlice(allocator, packet[offset .. offset + len]);
        offset += len;
    }
    return next;
}

fn dnsNameEql(a: []const u8, b_in: []const u8) bool {
    const b = std.mem.trimEnd(u8, b_in, ".");
    return std.ascii.eqlIgnoreCase(a, b);
}

fn writeU16(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    try out.appendSlice(allocator, &buf);
}

fn writeU32(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    try out.appendSlice(allocator, &buf);
}

fn readU16(packet: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, packet[offset..][0..2], .big);
}

test "TXT reply encodes compressed answer names and parses values" {
    const allocator = std.testing.allocator;
    const values = [_][]const u8{ "relay=https://example.com", "addr=127.0.0.1:1234" };
    const packet = try buildTxtReply(allocator, "_iroh.example", &values, 30);
    defer allocator.free(packet);
    try std.testing.expect(std.mem.indexOfScalar(u8, packet, 0xc0) != null);

    const parsed = try parseTxtAnswers(allocator, packet, "_iroh.example");
    defer {
        for (parsed) |v| allocator.free(v);
        allocator.free(parsed);
    }
    try std.testing.expectEqual(@as(usize, 2), parsed.len);
    try std.testing.expectEqualStrings(values[0], parsed[0]);
    try std.testing.expectEqualStrings(values[1], parsed[1]);
}

test "parseFirstAnswerTtl reads the TTL off the wire answer bytes" {
    const allocator = std.testing.allocator;
    const values = [_][]const u8{"relay=https://example.com"};

    const packet = try buildTxtReply(allocator, "_iroh.example", &values, 3600);
    defer allocator.free(packet);
    try std.testing.expectEqual(@as(?u32, 3600), try parseFirstAnswerTtl(allocator, packet));

    const zero = try buildTxtReply(allocator, "_iroh.example", &values, 0);
    defer allocator.free(zero);
    try std.testing.expectEqual(@as(?u32, 0), try parseFirstAnswerTtl(allocator, zero));

    // No answers -> null (not an error): an empty reply has no TTL to observe.
    const empty = try buildResponse(allocator, 0, "example.", TYPE_TXT, RCODE_NXDOMAIN, &.{}, 30);
    defer allocator.free(empty);
    try std.testing.expectEqual(@as(?u32, null), try parseFirstAnswerTtl(allocator, empty));
}

test "DoH TXT query uses DNS id 0" {
    const allocator = std.testing.allocator;
    const query = try buildTxtQuery(allocator, "_iroh.example.");
    defer allocator.free(query);
    try std.testing.expectEqual(@as(u16, 0), readU16(query, 0));
    try std.testing.expectEqual(@as(u16, 1), readU16(query, 4));
}
