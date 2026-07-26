//! Experimental pure-Zig TLS 1.3 adapter. Picotls remains the shipping default.

const std = @import("std");
const zigtls = @import("zigtls");
const crypto = @import("crypto.zig");
const key = @import("../key.zig");

pub const session = zigtls.tls13.session;
const rpk = zigtls.tls13.rpk;
const max_server_name_len = 256;

pub const ZigtlsSession = struct {
    allocator: std.mem.Allocator,
    role: crypto.Role,
    secret_key: key.SecretKey,
    engine: session.Engine,
    certificate_der_storage: [rpk.ed25519_spki_length]u8,
    certificate_der_len: usize,
    certificate_chain: [1][]const u8,
    alpn_storage: [64]u8 = undefined,
    alpn_len: usize = 0,
    server_name_storage: [max_server_name_len]u8 = undefined,
    server_name_len: usize = 0,
    /// Owned copy of QUIC transport-params — Connection.create encodes into a
    /// stack scratch; picotls copies into session storage for the same reason.
    tp_storage: [1024]u8 = undefined,
    tp_len: usize = 0,
    pin: *ZigtlsSession = undefined,

    pub fn create(allocator: std.mem.Allocator, config: crypto.Config) !*ZigtlsSession {
        const self = try allocator.create(ZigtlsSession);
        errdefer allocator.destroy(self);

        self.* = undefined;
        self.allocator = allocator;
        self.role = config.role;
        self.secret_key = config.secret_key;
        self.certificate_der_len = 0;
        if (config.certificate_der_override) |certificate_der| {
            if (certificate_der.len == 0 or certificate_der.len > self.certificate_der_storage.len) return error.PicotlsError;
            @memcpy(self.certificate_der_storage[0..certificate_der.len], certificate_der);
            self.certificate_der_len = certificate_der.len;
        } else {
            const advertised_key = config.certificate_public_key orelse config.secret_key.public();
            const spki = rpk.encodeEd25519SubjectPublicKeyInfo(advertised_key.toBytes());
            @memcpy(self.certificate_der_storage[0..spki.len], &spki);
            self.certificate_der_len = spki.len;
        }
        self.certificate_chain = .{self.certificate_der_storage[0..self.certificate_der_len]};
        self.alpn_len = 0;
        if (config.alpn) |alpn| {
            if (alpn.len == 0 or alpn.len > self.alpn_storage.len) return error.PicotlsError;
            @memcpy(self.alpn_storage[0..alpn.len], alpn);
            self.alpn_len = alpn.len;
        }
        self.server_name_len = 0;
        if (config.server_name) |server_name| {
            if (server_name.len == 0 or server_name.len > self.server_name_storage.len) return error.PicotlsError;
            @memcpy(self.server_name_storage[0..server_name.len], server_name);
            self.server_name_len = server_name.len;
        }
        self.tp_len = 0;
        if (config.transport_params) |tp| {
            if (tp.len > self.tp_storage.len) return error.PicotlsError;
            @memcpy(self.tp_storage[0..tp.len], tp);
            self.tp_len = tp.len;
        }

        const common = session.Config{
            .role = switch (config.role) {
                .client => .client,
                .server => .server,
            },
            .suite = .tls_aes_128_gcm_sha256,
            .quic_mode = true,
            .quic_transport_parameters = if (self.tp_len == 0) "" else self.tp_storage[0..self.tp_len],
            .ticket_key_manager = config.zigtls_ticket_key_manager,
            .resumption_ticket = config.zigtls_resumption_ticket,
            .auto_issue_new_session_ticket = config.zigtls_auto_issue_new_session_ticket,
            .certificate_request_signature_algorithms = config.certificate_request_signature_algorithms,
            .server_credentials = .{
                .certificate_type = .raw_public_key,
                .cert_chain_der = self.certificate_chain[0..],
                .signature_scheme = 0x0807,
                .sign_certificate_verify = signCertificateVerify,
                .signer_userdata = @intFromPtr(self),
            },
            .peer_validation = if (config.role == .client) .{
                .enforce_certificate_verify = true,
                .require_peer_certificate = true,
                .expected_server_name = self.configuredServerName(),
                .expected_raw_public_key = if (config.peer_public_key) |peer| peer.toBytes() else null,
            } else if (config.require_client_authentication) .{
                .enforce_certificate_verify = true,
                .require_peer_certificate = true,
                .expected_raw_public_key = if (config.peer_public_key) |peer| peer.toBytes() else null,
            } else .{ .enforce_certificate_verify = false, .require_peer_certificate = false },
        };
        self.engine = try session.Engine.initChecked(allocator, common);
        self.pin = self;
        return self;
    }

    pub fn destroy(self: *ZigtlsSession) void {
        self.assertPinned();
        const allocator = self.allocator;
        self.engine.deinit();
        self.secret_key.zeroize();
        std.crypto.secureZero(u8, self.certificate_der_storage[0..self.certificate_der_len]);
        std.crypto.secureZero(u8, self.server_name_storage[0..self.server_name_len]);
        std.crypto.secureZero(u8, self.tp_storage[0..self.tp_len]);
        allocator.destroy(self);
    }

    pub fn assertPinned(self: *const ZigtlsSession) void {
        std.debug.assert(self.pin == self);
    }

    pub fn start(self: *ZigtlsSession, allocator: std.mem.Allocator) !crypto.HandshakeOutput {
        self.assertPinned();
        if (self.role == .client) {
            try self.engine.beginQuicClientHandshake(.{
                .server_name = self.configuredServerName(),
                .alpn_protocol = if (self.alpn_len == 0) null else self.alpn_storage[0..self.alpn_len],
            });
        }
        return self.collectOutput(allocator);
    }

    pub fn handleMessage(
        self: *ZigtlsSession,
        allocator: std.mem.Allocator,
        in_epoch: crypto.Epoch,
        input: []const u8,
    ) !crypto.HandshakeOutput {
        self.assertPinned();
        if (input.len != 0) {
            _ = try self.engine.ingestQuicHandshake(encryptionLevelForEpoch(in_epoch), input);
        }
        if (self.role == .client and self.engine.machine.state == .connected) {
            try self.engine.queueQuicClientFinished();
        }
        return self.collectOutput(allocator);
    }

    pub fn handleOutput(
        self: *ZigtlsSession,
        allocator: std.mem.Allocator,
        input: crypto.HandshakeOutput,
    ) !crypto.HandshakeOutput {
        var result = try emptyOutput(allocator);
        errdefer result.deinit();
        for (0..4) |i| {
            const epoch: crypto.Epoch = @enumFromInt(i);
            const bytes = input.epochSlice(epoch);
            if (bytes.len == 0) continue;
            var next = try self.handleMessage(allocator, epoch, bytes);
            defer next.deinit();
            try appendOutput(allocator, &result, next);
        }
        result.ret = if (self.isComplete()) 0 else 1;
        return result;
    }

    pub fn isComplete(self: *const ZigtlsSession) bool {
        return self.engine.machine.state == .connected;
    }

    pub fn wasResumed(self: *const ZigtlsSession) bool {
        return self.engine.wasResumed();
    }

    pub fn popNewSessionTicket(self: *ZigtlsSession) ?session.NewSessionTicketInfo {
        return self.engine.popNewSessionTicket();
    }

    fn configuredServerName(self: *const ZigtlsSession) ?[]const u8 {
        if (self.server_name_len == 0) return null;
        return self.server_name_storage[0..self.server_name_len];
    }

    pub fn exportSecret(self: *ZigtlsSession, label: [:0]const u8, context_value: []const u8, out: []u8) !void {
        try self.engine.exportSecret(label, context_value, out);
    }

    pub fn peerPublicKey(self: *ZigtlsSession) !key.PublicKey {
        return key.PublicKey.fromBytes(self.engine.peerRawPublicKey() orelse return error.MissingPeerPublicKey);
    }

    pub fn peerTransportParams(self: *const ZigtlsSession) ?[]const u8 {
        return self.engine.peerQuicTransportParameters();
    }

    pub fn negotiatedProtocol(self: *ZigtlsSession) ?[]const u8 {
        if (!self.isComplete() or self.alpn_len == 0) return null;
        return self.alpn_storage[0..self.alpn_len];
    }

    pub fn serverName(_: *ZigtlsSession) ?[]const u8 {
        return null;
    }

    pub fn trafficSecret(self: *const ZigtlsSession, direction: crypto.Direction, epoch: crypto.Epoch) !crypto.TrafficSecret {
        const snapshot = self.engine.snapshotQuicSecrets();
        const value = snapshotSecret(snapshot, direction, epoch) orelse return error.MissingTrafficSecret;
        var out: crypto.TrafficSecret = .{ .bytes = [_]u8{0} ** 64, .len = value.len };
        @memcpy(out.bytes[0..value.len], value.bytes[0..value.len]);
        return out;
    }

    fn signCertificateVerify(payload: []const u8, algorithm: u16, out: []u8, userdata: usize) anyerror!usize {
        if (algorithm != 0x0807 or out.len < 64) return error.InvalidCertificateVerifyMessage;
        const self: *ZigtlsSession = @ptrFromInt(userdata);
        const signature = self.secret_key.sign(payload).toBytes();
        @memcpy(out[0..64], &signature);
        return 64;
    }

    fn collectOutput(self: *ZigtlsSession, allocator: std.mem.Allocator) !crypto.HandshakeOutput {
        var per_epoch = [_]std.ArrayList(u8){ .empty, .empty, .empty, .empty };
        defer for (&per_epoch) |*bytes| bytes.deinit(allocator);
        while (self.engine.popOutboundQuicHandshake()) |raw_frame| {
            var frame = raw_frame;
            defer frame.deinit(self.allocator);
            const epoch: usize = @intFromEnum(epochForEncryptionLevel(frame.level));
            try per_epoch[epoch].appendSlice(allocator, frame.payload);
        }

        var total: usize = 0;
        var offsets = [_]usize{0} ** 5;
        for (per_epoch, 0..) |bytes, i| {
            offsets[i] = total;
            total += bytes.items.len;
        }
        offsets[4] = total;
        const combined = try allocator.alloc(u8, total);
        var cursor: usize = 0;
        for (per_epoch) |bytes| {
            @memcpy(combined[cursor .. cursor + bytes.items.len], bytes.items);
            cursor += bytes.items.len;
        }
        return .{ .allocator = allocator, .bytes = combined, .epoch_offsets = offsets, .ret = if (self.isComplete()) 0 else 1 };
    }
};

fn encryptionLevelForEpoch(epoch: crypto.Epoch) session.QuicEncryptionLevel {
    return switch (epoch) {
        .initial => .initial,
        .zero_rtt => .zero_rtt,
        .handshake => .handshake,
        .application => .application,
    };
}

fn epochForEncryptionLevel(level: session.QuicEncryptionLevel) crypto.Epoch {
    return switch (level) {
        .initial => .initial,
        .zero_rtt => .zero_rtt,
        .handshake => .handshake,
        .application => .application,
    };
}

fn snapshotSecret(
    snapshot: session.QuicSecretsSnapshot,
    direction: crypto.Direction,
    epoch: crypto.Epoch,
) ?session.QuicTrafficSecret {
    return switch (epoch) {
        .initial => null,
        .zero_rtt => switch (direction) {
            .read => snapshot.zero_rtt_read,
            .write => snapshot.zero_rtt_write,
        },
        .handshake => switch (direction) {
            .read => snapshot.handshake_read,
            .write => snapshot.handshake_write,
        },
        .application => switch (direction) {
            .read => snapshot.application_read,
            .write => snapshot.application_write,
        },
    };
}

fn emptyOutput(allocator: std.mem.Allocator) !crypto.HandshakeOutput {
    return .{ .allocator = allocator, .bytes = try allocator.alloc(u8, 0), .epoch_offsets = [_]usize{0} ** 5, .ret = 1 };
}

fn appendOutput(allocator: std.mem.Allocator, target: *crypto.HandshakeOutput, source: crypto.HandshakeOutput) !void {
    var per_epoch = [_]std.ArrayList(u8){ .empty, .empty, .empty, .empty };
    defer for (&per_epoch) |*bytes| bytes.deinit(allocator);
    inline for (0..4) |i| {
        const epoch: crypto.Epoch = @enumFromInt(i);
        try per_epoch[i].appendSlice(allocator, target.epochSlice(epoch));
        try per_epoch[i].appendSlice(allocator, source.epochSlice(epoch));
    }
    std.crypto.secureZero(u8, target.bytes);
    allocator.free(target.bytes);
    var total: usize = 0;
    for (per_epoch, 0..) |bytes, i| {
        target.epoch_offsets[i] = total;
        total += bytes.items.len;
    }
    target.epoch_offsets[4] = total;
    target.bytes = try allocator.alloc(u8, total);
    var cursor: usize = 0;
    for (per_epoch) |bytes| {
        @memcpy(target.bytes[cursor .. cursor + bytes.items.len], bytes.items);
        cursor += bytes.items.len;
    }
}

pub const EndpointHandshake = struct {
    pub fn complete(allocator: std.mem.Allocator, client: *ZigtlsSession, server: *ZigtlsSession) !void {
        var client_hello = try client.start(allocator);
        defer client_hello.deinit();
        var server_flight = try server.handleOutput(allocator, client_hello);
        defer server_flight.deinit();
        var client_finished = try client.handleOutput(allocator, server_flight);
        defer client_finished.deinit();
        var server_done = try server.handleOutput(allocator, client_finished);
        defer server_done.deinit();
        if (!client.isComplete() or !server.isComplete()) return error.IncompleteHandshake;
    }
};

test "tls-zig-native client start uses configured server_name in ClientHello" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x41} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x42} ** 32);
    const configured_name = "node-under-test.example";

    var client = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .server_name = configured_name,
        .transport_params = "client-tp",
    });
    defer client.destroy();

    var client_hello = try client.start(allocator);
    defer client_hello.deinit();
    const initial = client_hello.epochSlice(.initial);
    try std.testing.expect(std.mem.indexOf(u8, initial, configured_name) != null);
    try std.testing.expect(std.mem.indexOf(u8, initial, "iroh-rpk") == null);
}

test "tls-zig-native maps zigtls zero-rtt level and traffic secrets" {
    try std.testing.expectEqual(session.QuicEncryptionLevel.zero_rtt, encryptionLevelForEpoch(.zero_rtt));
    try std.testing.expectEqual(crypto.Epoch.zero_rtt, epochForEncryptionLevel(.zero_rtt));

    var read_secret: session.QuicTrafficSecret = .{ .len = 4 };
    @memcpy(read_secret.bytes[0..4], "read");
    var write_secret: session.QuicTrafficSecret = .{ .len = 4 };
    @memcpy(write_secret.bytes[0..4], "writ");
    const snapshot: session.QuicSecretsSnapshot = .{
        .suite = .tls_aes_128_gcm_sha256,
        .zero_rtt_read = read_secret,
        .zero_rtt_write = write_secret,
    };

    const selected_read = snapshotSecret(snapshot, .read, .zero_rtt) orelse return error.MissingTrafficSecret;
    try std.testing.expectEqualSlices(u8, "read", selected_read.bytes[0..selected_read.len]);
    const selected_write = snapshotSecret(snapshot, .write, .zero_rtt) orelse return error.MissingTrafficSecret;
    try std.testing.expectEqualSlices(u8, "writ", selected_write.bytes[0..selected_write.len]);
    try std.testing.expect(snapshotSecret(snapshot, .read, .initial) == null);
}

test "tls-zig-native S2 session pair authenticates RPK and agrees on QUIC secrets" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x71} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x72} ** 32);
    const client_tp = "client-tp";
    const server_tp = "server-tp";

    var client = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = "iroh-interop-test",
        .server_name = "zigtls-s2.example",
        .transport_params = client_tp,
    });
    defer client.destroy();
    var server = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .alpn = "iroh-interop-test",
        .transport_params = server_tp,
    });
    defer server.destroy();

    try EndpointHandshake.complete(allocator, client, server);
    try std.testing.expectEqualSlices(u8, &server_key.public().toBytes(), &(try client.peerPublicKey()).toBytes());
    try std.testing.expectEqualSlices(u8, &client_key.public().toBytes(), &(try server.peerPublicKey()).toBytes());
    try std.testing.expectEqualSlices(u8, server_tp, client.peerTransportParams().?);
    try std.testing.expectEqualSlices(u8, client_tp, server.peerTransportParams().?);
    var client_exporter: [32]u8 = undefined;
    var server_exporter: [32]u8 = undefined;
    try client.exportSecret("EXPORTER-iroh-zigtls", "session-pair", &client_exporter);
    try server.exportSecret("EXPORTER-iroh-zigtls", "session-pair", &server_exporter);
    try std.testing.expectEqualSlices(u8, &client_exporter, &server_exporter);
    inline for (&.{ crypto.Epoch.handshake, crypto.Epoch.application }) |epoch| {
        const client_read = try client.trafficSecret(.read, epoch);
        const server_write = try server.trafficSecret(.write, epoch);
        try std.testing.expectEqualSlices(u8, client_read.slice(), server_write.slice());
        const client_write = try client.trafficSecret(.write, epoch);
        const server_read = try server.trafficSecret(.read, epoch);
        try std.testing.expectEqualSlices(u8, client_write.slice(), server_read.slice());
    }
}

test "tls-zig-native protected ticket resumes second session" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x91} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x92} ** 32);
    const server_name = "zigtls-resume.example";
    const client_tp = "client-tp-resume";
    const server_tp = "server-tp-resume";
    var manager = zigtls.tls13.ticket_keys.Manager.init();
    try manager.rotate(.{
        .key_id = 0x51525354,
        .material = [_]u8{0x93} ** 32,
        .not_before_unix = 0,
        .not_after_unix = std.math.maxInt(i64),
    });

    var client1 = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = "iroh-interop-test",
        .server_name = server_name,
        .transport_params = client_tp,
    });
    defer client1.destroy();
    var server1 = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .alpn = "iroh-interop-test",
        .transport_params = server_tp,
        .zigtls_ticket_key_manager = &manager,
        .zigtls_auto_issue_new_session_ticket = true,
    });
    defer server1.destroy();

    var client_hello = try client1.start(allocator);
    defer client_hello.deinit();
    var server_flight = try server1.handleOutput(allocator, client_hello);
    defer server_flight.deinit();
    var client_finished = try client1.handleOutput(allocator, server_flight);
    defer client_finished.deinit();
    var server_ticket = try server1.handleOutput(allocator, client_finished);
    defer server_ticket.deinit();
    var client_ticket_ack = try client1.handleOutput(allocator, server_ticket);
    defer client_ticket_ack.deinit();
    try std.testing.expect(client1.isComplete());
    try std.testing.expect(server1.isComplete());

    var captured = client1.popNewSessionTicket() orelse return error.TestUnexpectedResult;
    defer captured.deinit(allocator);
    const resumption_ticket = captured.asResumptionTicket() orelse return error.TestUnexpectedResult;

    var client2 = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = "iroh-interop-test",
        .server_name = server_name,
        .transport_params = client_tp,
        .zigtls_resumption_ticket = resumption_ticket,
    });
    defer client2.destroy();
    var server2 = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .alpn = "iroh-interop-test",
        .transport_params = server_tp,
        .zigtls_ticket_key_manager = &manager,
    });
    defer server2.destroy();

    try EndpointHandshake.complete(allocator, client2, server2);
    try std.testing.expect(client2.wasResumed());
    try std.testing.expect(server2.wasResumed());
    try std.testing.expectEqualSlices(u8, &server_key.public().toBytes(), &(try client2.peerPublicKey()).toBytes());
    try std.testing.expectEqualSlices(u8, &client_key.public().toBytes(), &(try server2.peerPublicKey()).toBytes());
}

test "tls-zig-native S2 does not publish RPK before valid CertificateVerify" {
    const allocator = std.testing.allocator;
    const signing_key = key.SecretKey.fromBytes([_]u8{0x81} ** 32);
    const advertised_key = key.SecretKey.fromBytes([_]u8{0x82} ** 32);
    const client_key = key.SecretKey.fromBytes([_]u8{0x83} ** 32);
    var client = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = advertised_key.public(),
        .server_name = "zigtls-bad-certverify.example",
        .transport_params = "c",
    });
    defer client.destroy();
    var server = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = signing_key,
        .certificate_public_key = advertised_key.public(),
        .peer_public_key = null,
        .transport_params = "s",
    });
    defer server.destroy();
    try std.testing.expectError(error.InvalidCertificateVerifyMessage, EndpointHandshake.complete(allocator, client, server));
    try std.testing.expectError(error.MissingPeerPublicKey, client.peerPublicKey());
}

test "malformed RPK SubjectPublicKeyInfo is rejected before peer key publication" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x84} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x85} ** 32);
    var malformed_spki = rpk.encodeEd25519SubjectPublicKeyInfo(client_key.public().toBytes());
    malformed_spki[0] = 0x31;

    var client = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .certificate_der_override = malformed_spki[0..],
        .peer_public_key = server_key.public(),
        .server_name = "zigtls-malformed-spki.example",
        .transport_params = "c",
    });
    defer client.destroy();
    var server = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .transport_params = "s",
    });
    defer server.destroy();

    try std.testing.expectError(error.InvalidCertificateMessage, EndpointHandshake.complete(allocator, client, server));
    try std.testing.expectError(error.MissingPeerPublicKey, server.peerPublicKey());
}
