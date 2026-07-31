const std = @import("std");

pub const max_ticket_keys: usize = 8;

const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const protected_ticket_version: u8 = 1;
pub const protected_ticket_key_id_offset: usize = 1;
pub const protected_ticket_nonce_offset: usize = protected_ticket_key_id_offset + 4;
pub const protected_ticket_nonce_len: usize = Aead.nonce_length;
pub const protected_ticket_tag_len: usize = Aead.tag_length;
pub const protected_ticket_header_len: usize = protected_ticket_nonce_offset + protected_ticket_nonce_len;
pub const protected_ticket_overhead: usize = protected_ticket_header_len + protected_ticket_tag_len;

pub const TicketNonce = [protected_ticket_nonce_len]u8;

pub const TicketKey = struct {
    key_id: u32,
    material: [32]u8,
    not_before_unix: i64,
    not_after_unix: i64,
    can_encrypt: bool = true,
};

const Slot = struct {
    key: TicketKey,
    generation: u64,
};

pub const Manager = struct {
    slots: [max_ticket_keys]?Slot = [_]?Slot{null} ** max_ticket_keys,
    generation_counter: u64 = 0,

    pub fn init() Manager {
        return .{};
    }

    pub fn rotate(self: *Manager, key: TicketKey) Error!void {
        try validateKey(key);

        // Existing active key remains decrypt-only after rotation.
        var i: usize = 0;
        while (i < self.slots.len) : (i += 1) {
            if (self.slots[i]) |*slot| {
                slot.key.can_encrypt = false;
            }
        }

        const idx = self.findInsertIndex();
        self.generation_counter += 1;
        self.slots[idx] = Slot{ .key = key, .generation = self.generation_counter };
    }

    pub fn currentEncryptKey(self: Manager, now_unix: i64) Error!TicketKey {
        var best: ?Slot = null;

        for (self.slots) |opt| {
            const slot = opt orelse continue;
            if (!slot.key.can_encrypt) continue;
            if (!isValidAt(slot.key, now_unix)) continue;
            if (best == null or slot.generation > best.?.generation) {
                best = slot;
            }
        }

        if (best == null) return error.NoEncryptKeyAvailable;
        return best.?.key;
    }

    pub fn findDecryptKey(self: Manager, key_id: u32, now_unix: i64) ?TicketKey {
        var best: ?Slot = null;
        for (self.slots) |opt| {
            const slot = opt orelse continue;
            if (slot.key.key_id != key_id) continue;
            if (!isValidAt(slot.key, now_unix)) continue;
            if (best == null or slot.generation > best.?.generation) {
                best = slot;
            }
        }
        return if (best) |slot| slot.key else null;
    }

    pub fn protect(
        self: Manager,
        io: std.Io,
        allocator: std.mem.Allocator,
        now_unix: i64,
        plaintext: []const u8,
        aad: ?[]const u8,
    ) Error![]u8 {
        var nonce: TicketNonce = undefined;
        io.random(&nonce);
        return self.protectWithNonce(allocator, now_unix, nonce, plaintext, aad);
    }

    pub fn protectWithNonce(
        self: Manager,
        allocator: std.mem.Allocator,
        now_unix: i64,
        nonce: TicketNonce,
        plaintext: []const u8,
        aad: ?[]const u8,
    ) Error![]u8 {
        const key = try self.currentEncryptKey(now_unix);
        const out_len = try protectedTicketLen(plaintext.len);
        var out = try allocator.alloc(u8, out_len);
        errdefer allocator.free(out);

        const header = writeProtectedHeader(out, key.key_id, nonce);
        const caller_aad = aad orelse "";
        const auth_data = try buildAssociatedData(allocator, header, caller_aad);
        defer auth_data.deinit(allocator);

        const ciphertext_end = protected_ticket_header_len + plaintext.len;
        const ciphertext = out[protected_ticket_header_len..ciphertext_end];
        const tag = out[ciphertext_end..][0..protected_ticket_tag_len];
        Aead.encrypt(ciphertext, tag, plaintext, auth_data.bytes, nonce, key.material);
        return out;
    }

    pub fn unprotect(
        self: Manager,
        allocator: std.mem.Allocator,
        now_unix: i64,
        protected_ticket: []const u8,
        aad: ?[]const u8,
    ) Error!UnprotectedTicket {
        if (protected_ticket.len < protected_ticket_overhead) return error.InvalidProtectedTicket;

        const header_slice = protected_ticket[0..protected_ticket_header_len];
        const header = try parseProtectedHeader(header_slice);
        const key = self.findDecryptKey(header.key_id, now_unix) orelse return error.NoDecryptKeyAvailable;

        const caller_aad = aad orelse "";
        const auth_data = try buildAssociatedData(allocator, header_slice, caller_aad);
        defer auth_data.deinit(allocator);

        const ciphertext_end = protected_ticket.len - protected_ticket_tag_len;
        const ciphertext = protected_ticket[protected_ticket_header_len..ciphertext_end];
        const tag = protected_ticket[ciphertext_end..][0..protected_ticket_tag_len].*;

        const plaintext = try allocator.alloc(u8, ciphertext.len);
        errdefer {
            std.crypto.secureZero(u8, plaintext);
            allocator.free(plaintext);
        }

        Aead.decrypt(plaintext, ciphertext, tag, auth_data.bytes, header.nonce, key.material) catch |err| switch (err) {
            error.AuthenticationFailed => return error.AuthenticationFailed,
        };

        return .{
            .key_id = header.key_id,
            .plaintext = plaintext,
        };
    }

    pub fn count(self: Manager) usize {
        var n: usize = 0;
        for (self.slots) |slot| {
            if (slot != null) n += 1;
        }
        return n;
    }

    fn findInsertIndex(self: Manager) usize {
        var empty_index: ?usize = null;
        var oldest_index: usize = 0;
        var oldest_generation: u64 = std.math.maxInt(u64);

        var i: usize = 0;
        while (i < self.slots.len) : (i += 1) {
            if (self.slots[i] == null) {
                empty_index = i;
                break;
            }
            const generation = self.slots[i].?.generation;
            if (generation < oldest_generation) {
                oldest_generation = generation;
                oldest_index = i;
            }
        }

        return empty_index orelse oldest_index;
    }
};

pub const Error = error{
    InvalidValidityWindow,
    InvalidProtectedTicket,
    NoDecryptKeyAvailable,
    NoEncryptKeyAvailable,
    ProtectedTicketTooLarge,
    AuthenticationFailed,
    OutOfMemory,
};

pub const UnprotectedTicket = struct {
    key_id: u32,
    plaintext: []u8,

    pub fn deinit(self: *UnprotectedTicket, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.plaintext);
        allocator.free(self.plaintext);
        self.* = undefined;
    }
};

const ProtectedHeader = struct {
    key_id: u32,
    nonce: TicketNonce,
};

const AssociatedData = struct {
    bytes: []const u8,
    owned: ?[]u8 = null,

    fn deinit(self: AssociatedData, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
    }
};

fn protectedTicketLen(plaintext_len: usize) Error!usize {
    const header_and_body = std.math.add(usize, protected_ticket_header_len, plaintext_len) catch return error.ProtectedTicketTooLarge;
    return std.math.add(usize, header_and_body, protected_ticket_tag_len) catch return error.ProtectedTicketTooLarge;
}

fn writeProtectedHeader(out: []u8, key_id: u32, nonce: TicketNonce) []const u8 {
    std.debug.assert(out.len >= protected_ticket_header_len);
    out[0] = protected_ticket_version;
    std.mem.writeInt(u32, out[protected_ticket_key_id_offset..protected_ticket_nonce_offset], key_id, .big);
    @memcpy(out[protected_ticket_nonce_offset..][0..protected_ticket_nonce_len], nonce[0..]);
    return out[0..protected_ticket_header_len];
}

fn parseProtectedHeader(header: []const u8) Error!ProtectedHeader {
    if (header.len != protected_ticket_header_len) return error.InvalidProtectedTicket;
    if (header[0] != protected_ticket_version) return error.InvalidProtectedTicket;
    return .{
        .key_id = std.mem.readInt(u32, header[protected_ticket_key_id_offset..protected_ticket_nonce_offset], .big),
        .nonce = header[protected_ticket_nonce_offset..][0..protected_ticket_nonce_len].*,
    };
}

fn buildAssociatedData(allocator: std.mem.Allocator, header: []const u8, caller_aad: []const u8) Error!AssociatedData {
    if (caller_aad.len == 0) return .{ .bytes = header };

    const len = std.math.add(usize, header.len, caller_aad.len) catch return error.ProtectedTicketTooLarge;
    const bytes = try allocator.alloc(u8, len);
    @memcpy(bytes[0..header.len], header);
    @memcpy(bytes[header.len..], caller_aad);
    return .{ .bytes = bytes, .owned = bytes };
}

fn validateKey(key: TicketKey) Error!void {
    if (key.not_after_unix <= key.not_before_unix) return error.InvalidValidityWindow;
}

fn isValidAt(key: TicketKey, now_unix: i64) bool {
    return key.not_before_unix <= now_unix and now_unix <= key.not_after_unix;
}

fn mkMaterial(byte: u8) [32]u8 {
    return [_]u8{byte} ** 32;
}

fn mkNonce(byte: u8) TicketNonce {
    return [_]u8{byte} ** protected_ticket_nonce_len;
}

test "rotate selects newest valid encrypt key" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 1, .material = mkMaterial(1), .not_before_unix = 0, .not_after_unix = 100 });
    try m.rotate(.{ .key_id = 2, .material = mkMaterial(2), .not_before_unix = 0, .not_after_unix = 100 });

    const active = try m.currentEncryptKey(10);
    try std.testing.expectEqual(@as(u32, 2), active.key_id);
}

test "rotation keeps prior keys decrypt-capable" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 10, .material = mkMaterial(0xaa), .not_before_unix = 0, .not_after_unix = 50 });
    try m.rotate(.{ .key_id = 20, .material = mkMaterial(0xbb), .not_before_unix = 0, .not_after_unix = 100 });

    const old = m.findDecryptKey(10, 10) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 10), old.key_id);

    const active = try m.currentEncryptKey(10);
    try std.testing.expectEqual(@as(u32, 20), active.key_id);
    try std.testing.expect(active.can_encrypt);
    try std.testing.expect(!(old.can_encrypt));
}

test "expired key is not selected" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 1, .material = mkMaterial(1), .not_before_unix = 0, .not_after_unix = 5 });

    try std.testing.expectError(error.NoEncryptKeyAvailable, m.currentEncryptKey(6));
    try std.testing.expect(m.findDecryptKey(1, 6) == null);
}

test "invalid validity window is rejected" {
    var m = Manager.init();
    try std.testing.expectError(error.InvalidValidityWindow, m.rotate(.{
        .key_id = 1,
        .material = mkMaterial(1),
        .not_before_unix = 10,
        .not_after_unix = 10,
    }));
}

test "manager evicts oldest generation when full" {
    var m = Manager.init();
    var i: usize = 0;
    while (i < max_ticket_keys) : (i += 1) {
        try m.rotate(.{
            .key_id = @as(u32, @intCast(i + 1)),
            .material = mkMaterial(@as(u8, @intCast(i + 1))),
            .not_before_unix = 0,
            .not_after_unix = 100,
        });
    }

    try std.testing.expectEqual(max_ticket_keys, m.count());
    const first_old = m.findDecryptKey(1, 10) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 1), first_old.key_id);

    try m.rotate(.{ .key_id = 99, .material = mkMaterial(99), .not_before_unix = 0, .not_after_unix = 100 });
    try std.testing.expectEqual(max_ticket_keys, m.count());
    try std.testing.expect(m.findDecryptKey(1, 10) == null);
    try std.testing.expectEqual(@as(u32, 99), (try m.currentEncryptKey(10)).key_id);
}

test "protect and unprotect round-trip with aad" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 7, .material = mkMaterial(0x7a), .not_before_unix = 10, .not_after_unix = 100 });

    const protected = try m.protectWithNonce(std.testing.allocator, 20, mkNonce(0x42), "ticket-state", "quic tls13");
    defer std.testing.allocator.free(protected);

    try std.testing.expectEqual(protected_ticket_overhead + "ticket-state".len, protected.len);
    try std.testing.expectEqual(protected_ticket_version, protected[0]);
    try std.testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, protected[protected_ticket_key_id_offset..protected_ticket_nonce_offset], .big));

    var opened = try m.unprotect(std.testing.allocator, 20, protected, "quic tls13");
    defer opened.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 7), opened.key_id);
    try std.testing.expectEqualSlices(u8, "ticket-state", opened.plaintext);
}

test "protect uses io nonce source" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 8, .material = mkMaterial(0x08), .not_before_unix = 0, .not_after_unix = 100 });

    const protected = try m.protect(std.testing.io, std.testing.allocator, 50, "state", null);
    defer std.testing.allocator.free(protected);

    var opened = try m.unprotect(std.testing.allocator, 50, protected, null);
    defer opened.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 8), opened.key_id);
    try std.testing.expectEqualSlices(u8, "state", opened.plaintext);
}

test "unprotect rejects wrong aad and modified ciphertext" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 11, .material = mkMaterial(0x11), .not_before_unix = 0, .not_after_unix = 100 });

    const protected = try m.protectWithNonce(std.testing.allocator, 1, mkNonce(0x99), "secret ticket", "aad-a");
    defer std.testing.allocator.free(protected);

    try std.testing.expectError(error.AuthenticationFailed, m.unprotect(std.testing.allocator, 1, protected, "aad-b"));

    var modified = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(modified);
    modified[protected_ticket_header_len] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, m.unprotect(std.testing.allocator, 1, modified, "aad-a"));
}

test "unprotect validates key id and time window" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 21, .material = mkMaterial(0x21), .not_before_unix = 0, .not_after_unix = 10 });

    const protected = try m.protectWithNonce(std.testing.allocator, 5, mkNonce(0x21), "state", null);
    defer std.testing.allocator.free(protected);

    try std.testing.expectError(error.NoDecryptKeyAvailable, m.unprotect(std.testing.allocator, 11, protected, null));

    var unknown_key_id = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(unknown_key_id);
    std.mem.writeInt(u32, unknown_key_id[protected_ticket_key_id_offset..protected_ticket_nonce_offset], 99, .big);
    try std.testing.expectError(error.NoDecryptKeyAvailable, m.unprotect(std.testing.allocator, 5, unknown_key_id, null));
}

test "unprotect authenticates key id header when alternate key exists" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 31, .material = mkMaterial(0x31), .not_before_unix = 0, .not_after_unix = 100 });
    try m.rotate(.{ .key_id = 32, .material = mkMaterial(0x32), .not_before_unix = 0, .not_after_unix = 100 });

    const protected = try m.protectWithNonce(std.testing.allocator, 5, mkNonce(0x32), "state", null);
    defer std.testing.allocator.free(protected);

    var tampered = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(tampered);
    std.mem.writeInt(u32, tampered[protected_ticket_key_id_offset..protected_ticket_nonce_offset], 31, .big);
    try std.testing.expectError(error.AuthenticationFailed, m.unprotect(std.testing.allocator, 5, tampered, null));
}

test "unprotect rejects malformed envelopes" {
    var m = Manager.init();
    try m.rotate(.{ .key_id = 41, .material = mkMaterial(0x41), .not_before_unix = 0, .not_after_unix = 100 });

    try std.testing.expectError(error.InvalidProtectedTicket, m.unprotect(std.testing.allocator, 1, "", null));

    const protected = try m.protectWithNonce(std.testing.allocator, 1, mkNonce(0x41), "", null);
    defer std.testing.allocator.free(protected);

    var bad_version = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(bad_version);
    bad_version[0] = protected_ticket_version + 1;
    try std.testing.expectError(error.InvalidProtectedTicket, m.unprotect(std.testing.allocator, 1, bad_version, null));
}
