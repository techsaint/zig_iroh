//! Experimental pure-Zig TLS 1.3 adapter. Picotls remains the shipping default.

const std = @import("std");
const zigtls = @import("zigtls");
const shared = @import("shared");
const key = shared.key;
// S6: backend-agnostic types live in shared/tls_contract; this adapter is the
// zigtls backend and uses ConfigFor with the real zigtls type table.
const tls = shared.tls_contract;
const crypto = struct {
    pub const Role = tls.Role;
    pub const Direction = tls.Direction;
    pub const Epoch = tls.Epoch;
    pub const TrafficSecret = tls.TrafficSecret;
    pub const HandshakeOutput = tls.HandshakeOutput;
    pub const SigningKey = tls.SigningKey;
    pub const SignatureScheme = tls.SignatureScheme;
    pub const X509ServerIdentity = tls.X509ServerIdentity;
    pub const max_epoch = tls.max_epoch;
    pub const max_secret_len = tls.max_secret_len;
    pub const quic_transport_parameters_ext = tls.quic_transport_parameters_ext;
    pub const Error = tls.Error;
    pub const Backend = tls.Backend;
    pub const Config = tls.ConfigFor(.{
        .ResumptionTicket = zigtls.tls13.session.ResumptionTicket,
        .TicketKeyManager = zigtls.tls13.ticket_keys.Manager,
        .ReplayFilter = zigtls.tls13.early_data.ReplayFilter,
        .TrustStore = zigtls.tls13.trust_store.TrustStore,
        .OcspResponseView = zigtls.tls13.ocsp.ResponseView,
        .NewSessionTicketInfo = zigtls.tls13.session.NewSessionTicketInfo,
    });
};

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
    /// Server preference-ordered ALPNs (owned concatenated copies + slice table).
    /// When set, `negotiatedProtocol` returns the TLS-negotiated value and
    /// rejects a client offer that is not in this list.
    server_alpn_storage: []u8 = &.{},
    server_alpn_list: []const []const u8 = &.{},
    /// X.509 server identity (QAD): owned concatenated DER copies + slice
    /// table into them, the signing key, and its TLS 1.3 scheme. Empty when
    /// the session is a plain RPK session.
    x509_storage: []u8 = &.{},
    x509_chain: []const []const u8 = &.{},
    x509_key: ?crypto.SigningKey = null,
    x509_scheme: u16 = 0,
    server_name_storage: [max_server_name_len]u8 = undefined,
    server_name_len: usize = 0,
    /// Owned copy of QUIC transport-params — Connection.create encodes into a
    /// stack scratch; picotls copies into session storage for the same reason.
    tp_storage: [1024]u8 = undefined,
    tp_len: usize = 0,
    /// B8: the TLS alert code classifying the last failed handshake ingest
    /// (zigtls `classifyErrorAlert`, tls13/session.zig:3364). Read after an
    /// error to build the CRYPTO_ERROR transport close code (noq
    /// crypto/rustls.rs:98-108).
    last_alert: ?u8 = null,
    pin: *ZigtlsSession = undefined,

    pub fn create(allocator: std.mem.Allocator, config: crypto.Config) !*ZigtlsSession {
        const self = try allocator.create(ZigtlsSession);
        errdefer allocator.destroy(self);

        self.* = undefined;
        self.allocator = allocator;
        self.role = config.role;
        self.last_alert = null;
        self.secret_key = config.secret_key;
        errdefer self.secret_key.zeroize();
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
        self.server_alpn_storage = &.{};
        self.server_alpn_list = &.{};
        if (config.server_alpns) |list| {
            if (config.role != .server) return error.InvalidConfiguration;
            if (list.len == 0) return error.PicotlsError;
            var total: usize = 0;
            for (list) |alpn| {
                if (alpn.len == 0 or alpn.len > self.alpn_storage.len) return error.PicotlsError;
                total += alpn.len;
            }
            self.server_alpn_storage = try allocator.alloc(u8, total);
            errdefer allocator.free(self.server_alpn_storage);
            const slices = try allocator.alloc([]const u8, list.len);
            errdefer allocator.free(slices);
            var off: usize = 0;
            for (list, 0..) |alpn, i| {
                @memcpy(self.server_alpn_storage[off..][0..alpn.len], alpn);
                slices[i] = self.server_alpn_storage[off..][0..alpn.len];
                off += alpn.len;
            }
            self.server_alpn_list = slices;
            // First preference remains the client-offer / fallback singular.
            @memcpy(self.alpn_storage[0..list[0].len], list[0]);
            self.alpn_len = list[0].len;
        } else if (config.alpn) |alpn| {
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

        self.x509_storage = &.{};
        self.x509_chain = &.{};
        self.x509_key = null;
        self.x509_scheme = 0;
        if (config.x509_server) |x509| {
            if (config.role != .server) return error.InvalidConfiguration;
            switch (x509.scheme) {
                .ed25519 => if (x509.key != .ed25519) return error.InvalidConfiguration,
                .ecdsa_secp256r1_sha256 => if (x509.key != .ecdsa_p256) return error.InvalidConfiguration,
            }
            if (x509.chain_der.len == 0 or x509.chain_der.len > 8) return error.InvalidConfiguration;
            var total: usize = 0;
            for (x509.chain_der) |der| {
                if (der.len == 0) return error.InvalidConfiguration;
                total += der.len;
            }
            if (total > 64 * 1024) return error.InvalidConfiguration;
            self.x509_storage = try allocator.alloc(u8, total);
            errdefer allocator.free(self.x509_storage);
            const slices = try allocator.alloc([]const u8, x509.chain_der.len);
            errdefer allocator.free(slices);
            var off: usize = 0;
            for (x509.chain_der, 0..) |der, i| {
                @memcpy(self.x509_storage[off..][0..der.len], der);
                slices[i] = self.x509_storage[off..][0..der.len];
                off += der.len;
            }
            self.x509_chain = slices;
            self.x509_key = x509.key;
            self.x509_scheme = @intFromEnum(x509.scheme);
        }
        errdefer self.scrubX509Key();
        // Function-scope: the block-scoped frees above expire with the x509
        // block, so an `Engine.initChecked` failure below would otherwise leak
        // the (non-secret) public DER storage + pointer-table allocations.
        errdefer {
            if (self.x509_chain.len > 0) allocator.free(self.x509_chain);
            if (self.x509_storage.len > 0) allocator.free(self.x509_storage);
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
            .server_credentials = if (self.x509_key != null) .{
                // QAD path: present the operator X.509 chain (rustls/webpki
                // clients cannot negotiate RPK).
                .certificate_type = .x509,
                .cert_chain_der = self.x509_chain,
                .signature_scheme = self.x509_scheme,
                .sign_certificate_verify = signCertificateVerify,
                .signer_userdata = @intFromPtr(self),
            } else .{
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
                // F13 QAD client: the X.509 chain-of-trust path (RPK pin
                // stays authoritative when both are somehow set — engine
                // policy checks the RPK pin first, see
                // `ensureClientPeerValidationPolicy`).
                .trust_store = config.x509_trust_store,
                .enforce_ocsp = config.x509_enforce_ocsp,
                .allow_soft_fail_ocsp = config.x509_allow_soft_fail_ocsp,
                .stapled_ocsp = config.x509_stapled_ocsp,
                .bypass_chain_verify = config.x509_bypass_chain_verify,
                .bypass_hostname_verify = config.x509_bypass_hostname_verify,
                .bypass_trust_anchor = config.x509_bypass_trust_anchor,
                .bypass_ocsp_check = config.x509_bypass_ocsp_check,
            } else if (config.require_client_authentication) .{
                .enforce_certificate_verify = true,
                .require_peer_certificate = true,
                .expected_raw_public_key = if (config.peer_public_key) |peer| peer.toBytes() else null,
            } else .{ .enforce_certificate_verify = false, .require_peer_certificate = false },
            .early_data = .{
                .enabled = config.zigtls_enable_early_data,
                .replay_filter = config.zigtls_replay_filter,
                .replay_node_id = config.zigtls_replay_node_id,
                .replay_epoch = config.zigtls_replay_epoch,
            },
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
        self.scrubX509Key();
        if (self.x509_chain.len > 0) allocator.free(self.x509_chain);
        if (self.x509_storage.len > 0) {
            std.crypto.secureZero(u8, self.x509_storage);
            allocator.free(self.x509_storage);
        }
        if (self.server_alpn_list.len > 0) allocator.free(self.server_alpn_list);
        if (self.server_alpn_storage.len > 0) {
            std.crypto.secureZero(u8, self.server_alpn_storage);
            allocator.free(self.server_alpn_storage);
        }
        std.crypto.secureZero(u8, self.certificate_der_storage[0..self.certificate_der_len]);
        std.crypto.secureZero(u8, self.alpn_storage[0..self.alpn_len]);
        std.crypto.secureZero(u8, self.server_name_storage[0..self.server_name_len]);
        std.crypto.secureZero(u8, self.tp_storage[0..self.tp_len]);
        allocator.destroy(self);
    }

    fn scrubX509Key(self: *ZigtlsSession) void {
        if (self.x509_key) |*xkey| {
            switch (xkey.*) {
                .ed25519 => |*sk| sk.zeroize(),
                .ecdsa_p256 => |*scalar| std.crypto.secureZero(u8, scalar),
            }
        }
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
            // Reject a Router ALPN miss before the zigtls engine queues its server
            // handshake flight. The late guard below is still kept as a belt-and-
            // suspenders check, but running this preflight first prevents a server
            // from sending EncryptedExtensions for an ALPN it will immediately
            // close, which made the client report a successful dial before seeing
            // the close and skipped public ConnectOptions fallback.
            try self.rejectDisallowedClientHelloAlpn(in_epoch, input);
            _ = self.engine.ingestQuicHandshake(encryptionLevelForEpoch(in_epoch), input) catch |err| {
                // B8: zigtls classifies every engine failure to a TLS alert
                // (tls13/session.zig classifyErrorAlert); carry its wire code.
                self.last_alert = @intFromEnum(session.classifyErrorAlert(err).description);
                return err;
            };
            try self.rejectDisallowedServerAlpn();
        }
        if (self.role == .client and self.engine.machine.state == .connected) {
            try self.engine.queueQuicClientFinished();
        }
        return self.collectOutput(allocator);
    }

    const tls_handshake_client_hello: u8 = 1;
    const tls_ext_alpn: u16 = 0x0010;

    fn readU16(bytes: []const u8) u16 {
        return std.mem.readInt(u16, bytes[0..2], .big);
    }

    fn readU24(bytes: []const u8) usize {
        return (@as(usize, bytes[0]) << 16) |
            (@as(usize, bytes[1]) << 8) |
            @as(usize, bytes[2]);
    }

    fn rejectNoApplicationProtocol(self: *ZigtlsSession) !void {
        self.last_alert = 120; // TLS no_application_protocol
        return error.InvalidAlpnExtension;
    }

    /// Preflight server-side ClientHello ALPN against the Router's advertised set
    /// before zigtls emits any server handshake bytes. The engine currently selects
    /// the first client-offered ALPN; mirror that selection rule here and fail the
    /// candidate early when it is not one of the Router handlers.
    fn rejectDisallowedClientHelloAlpn(self: *ZigtlsSession, in_epoch: crypto.Epoch, input: []const u8) !void {
        if (self.role != .server or self.server_alpn_list.len == 0 or in_epoch != .initial) return;

        var offset: usize = 0;
        while (offset + 4 <= input.len) {
            const typ = input[offset];
            const len = readU24(input[offset + 1 .. offset + 4]);
            const body_start = offset + 4;
            const body_end = body_start + len;
            if (body_end > input.len) return; // fragmented; let the engine buffer/classify it.
            if (typ == tls_handshake_client_hello) {
                const offered = firstClientHelloAlpn(input[body_start..body_end]) orelse return self.rejectNoApplicationProtocol();
                for (self.server_alpn_list) |allowed| {
                    if (std.mem.eql(u8, allowed, offered)) return;
                }
                return self.rejectNoApplicationProtocol();
            }
            offset = body_end;
        }
    }

    fn firstClientHelloAlpn(body: []const u8) ?[]const u8 {
        var i: usize = 2 + 32;
        if (i + 1 > body.len) return null;
        const session_id_len = body[i];
        i += 1;
        if (i + session_id_len + 2 > body.len) return null;
        i += session_id_len;
        const cipher_suites_len = readU16(body[i..][0..2]);
        i += 2;
        if (cipher_suites_len == 0 or cipher_suites_len % 2 != 0 or i + cipher_suites_len + 1 > body.len) return null;
        i += cipher_suites_len;
        const compression_methods_len = body[i];
        i += 1;
        if (compression_methods_len == 0 or i + compression_methods_len + 2 > body.len) return null;
        i += compression_methods_len;
        const extensions_len = readU16(body[i..][0..2]);
        i += 2;
        if (i + extensions_len != body.len) return null;
        const end = body.len;
        while (i + 4 <= end) {
            const ext_type = readU16(body[i..][0..2]);
            const ext_len = readU16(body[i + 2 ..][0..2]);
            i += 4;
            if (i + ext_len > end) return null;
            if (ext_type == tls_ext_alpn) return firstClientAlpnProtocol(body[i .. i + ext_len]);
            i += ext_len;
        }
        return null;
    }

    fn firstClientAlpnProtocol(extension_data: []const u8) ?[]const u8 {
        if (extension_data.len < 3) return null;
        const list_len = readU16(extension_data[0..2]);
        if (list_len == 0 or list_len + 2 != extension_data.len) return null;
        const proto_len = extension_data[2];
        if (proto_len == 0 or 3 + proto_len > extension_data.len) return null;
        return extension_data[3 .. 3 + proto_len];
    }

    /// zigtls' QUIC engine records the client's first offered ALPN; the iroh
    /// adapter owns the server's advertised Router ALPN set. Enforce that set at
    /// the TLS boundary so a primary-miss dial fails and ConnectOptions can try
    /// its fallback instead of accepting a connection the Router later drops.
    fn rejectDisallowedServerAlpn(self: *ZigtlsSession) !void {
        if (self.role != .server or self.server_alpn_list.len == 0) return;
        if (self.engine.negotiated_alpn_len == 0) return;
        const negotiated = self.engine.negotiated_alpn[0..self.engine.negotiated_alpn_len];
        for (self.server_alpn_list) |allowed| {
            if (std.mem.eql(u8, allowed, negotiated)) return;
        }
        return self.rejectNoApplicationProtocol();
    }

    /// The TLS alert code classifying the last handshake ingest failure.
    pub fn lastAlertCode(self: *const ZigtlsSession) ?u8 {
        return self.last_alert;
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

    /// 0-RTT accept verdict (RFC 8446 §4.2.10): client = the server accepted
    /// our offer via EncryptedExtensions; server = we accepted the client's
    /// offer at ClientHello time. False until that verdict exists.
    pub fn earlyDataAccepted(self: *const ZigtlsSession) bool {
        return self.engine.earlyDataAccepted();
    }

    /// Client: the ClientHello offered 0-RTT early data.
    pub fn earlyDataOffered(self: *const ZigtlsSession) bool {
        return self.engine.earlyDataOffered();
    }

    /// The remembered QUIC transport parameters carried by the resumption
    /// ticket (RFC 9001 §4.6), for the client's 0-RTT flight. Null when the
    /// ticket does not permit 0-RTT.
    pub fn resumptionTransportParams(self: *const ZigtlsSession) ?[]const u8 {
        return self.engine.resumptionQuicTransportParameters();
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
        // No isComplete() gate: the ALPN is readable as soon as the engine
        // selects it — the server during ClientHello processing, the client
        // once it knows its offer — matching picotls's ptls_get_negotiated_-
        // protocol timing. noq's HandshakeDataReady (C22) fires mid-handshake
        // and requires the ALPN to already be readable at that point.
        // Prefer the TLS-negotiated ALPN (what the peer actually offered and
        // the engine selected). Returning the configured singular preference
        // here made Router multi-ALPN dispatch always see the first setAlpns
        // entry on noq-zigtls — client B speaking echo-b was mis-dispatched.
        if (self.engine.negotiated_alpn_len != 0) {
            const negotiated = self.engine.negotiated_alpn[0..self.engine.negotiated_alpn_len];
            if (self.server_alpn_list.len > 0) {
                for (self.server_alpn_list) |allowed| {
                    if (std.mem.eql(u8, allowed, negotiated)) return negotiated;
                }
                return null;
            }
            return negotiated;
        }
        if (self.alpn_len == 0) return null;
        return self.alpn_storage[0..self.alpn_len];
    }

    pub fn serverName(self: *ZigtlsSession) ?[]const u8 {
        return self.engine.peer_server_name;
    }

    pub fn trafficSecret(self: *const ZigtlsSession, direction: crypto.Direction, epoch: crypto.Epoch) !crypto.TrafficSecret {
        const snapshot = self.engine.snapshotQuicSecrets();
        const value = snapshotSecret(snapshot, direction, epoch) orelse return error.MissingTrafficSecret;
        var out: crypto.TrafficSecret = .{ .bytes = [_]u8{0} ** 64, .len = value.len };
        @memcpy(out.bytes[0..value.len], value.bytes[0..value.len]);
        return out;
    }

    fn signCertificateVerify(payload: []const u8, algorithm: u16, out: []u8, userdata: usize) anyerror!usize {
        const self: *ZigtlsSession = @ptrFromInt(userdata);
        if (self.x509_key) |x509_key| {
            if (algorithm != self.x509_scheme) return error.InvalidCertificateVerifyMessage;
            switch (x509_key) {
                .ed25519 => |sk| {
                    if (out.len < 64) return error.InvalidCertificateVerifyMessage;
                    const signature = sk.sign(payload).toBytes();
                    @memcpy(out[0..64], &signature);
                    return 64;
                },
                .ecdsa_p256 => |scalar| {
                    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
                    const sk = Ecdsa.SecretKey.fromBytes(scalar) catch return error.InvalidCertificateVerifyMessage;
                    const kp = Ecdsa.KeyPair.fromSecretKey(sk) catch return error.InvalidCertificateVerifyMessage;
                    const signature = kp.sign(payload, null) catch return error.InvalidCertificateVerifyMessage;
                    // TLS 1.3 ECDSA CertificateVerify signatures are
                    // ASN.1 DER (RFC 8446 §4.3.2), NOT the raw r||s
                    // concatenation — the client side (zigtls
                    // `verifyEcdsaCertificateVerify`) parses with
                    // `Ecdsa.Signature.fromDer`, so a raw encoding here
                    // fails to decode on the peer with `decode_error`.
                    var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
                    const bytes = signature.toDer(&der_buf);
                    if (out.len < bytes.len) return error.InvalidCertificateVerifyMessage;
                    @memcpy(out[0..bytes.len], bytes);
                    return bytes.len;
                },
            }
        }
        if (algorithm != 0x0807 or out.len < 64) return error.InvalidCertificateVerifyMessage;
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
    try std.testing.expectEqualStrings("zigtls-s2.example", server.serverName().?);
    try std.testing.expect(client.serverName() == null);
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

fn replayFilterForTest(allocator: std.mem.Allocator) !zigtls.tls13.early_data.ReplayFilter {
    return try zigtls.tls13.early_data.ReplayFilter.init(allocator, 4096);
}

test "tls-zig-native 0-RTT offer/accept pair derives early keys on PSK resumption" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x91} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x92} ** 32);
    var manager = zigtls.tls13.ticket_keys.Manager.init();
    try manager.rotate(.{
        .key_id = 0x51525354,
        .material = [_]u8{0x93} ** 32,
        .not_before_unix = 0,
        .not_after_unix = std.math.maxInt(i64),
    });
    var replay_server = try replayFilterForTest(allocator);
    defer replay_server.deinit();
    var replay_client = try replayFilterForTest(allocator);
    defer replay_client.deinit();

    var client1 = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = "iroh-0rtt-test",
        .server_name = "zigtls-0rtt.example",
        .transport_params = "c",
    });
    defer client1.destroy();
    var server1 = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .alpn = "iroh-0rtt-test",
        .transport_params = "s",
        .zigtls_ticket_key_manager = &manager,
        .zigtls_auto_issue_new_session_ticket = true,
        .zigtls_enable_early_data = true,
        .zigtls_replay_filter = &replay_server,
    });
    defer server1.destroy();
    var ch1 = try client1.start(allocator);
    defer ch1.deinit();
    var sf1 = try server1.handleOutput(allocator, ch1);
    defer sf1.deinit();
    var cf1 = try client1.handleOutput(allocator, sf1);
    defer cf1.deinit();
    var st1 = try server1.handleOutput(allocator, cf1);
    defer st1.deinit();
    var ca1 = try client1.handleOutput(allocator, st1);
    defer ca1.deinit();
    try std.testing.expect(client1.isComplete());
    try std.testing.expect(server1.isComplete());
    var captured = client1.popNewSessionTicket() orelse return error.TestUnexpectedResult;
    defer captured.deinit(allocator);
    const ticket = captured.asResumptionTicket() orelse return error.TestUnexpectedResult;
    // The NST is 0-RTT-capable and carries the remembered transport params.
    try std.testing.expect(ticket.quic_0rtt_allowed);
    try std.testing.expectEqualSlices(u8, "s", ticket.quic_transport_parameters.?);

    var client2 = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = "iroh-0rtt-test",
        .server_name = "zigtls-0rtt.example",
        .transport_params = "c",
        .zigtls_resumption_ticket = ticket,
        .zigtls_enable_early_data = true,
        .zigtls_replay_filter = &replay_client,
    });
    defer client2.destroy();

    var ch = try client2.start(allocator);
    defer ch.deinit();

    // The client OFFERED early data: its early WRITE secret is derived from the
    // ClientHello transcript, and the remembered TPs are exposed for the flight.
    try std.testing.expect(client2.earlyDataOffered());
    const snap = client2.engine.snapshotQuicSecrets();
    try std.testing.expect(snap.zero_rtt_write != null);
    try std.testing.expect(snap.zero_rtt_read == null);
    try std.testing.expectEqualSlices(u8, "s", client2.resumptionTransportParams().?);

    var server2 = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .alpn = "iroh-0rtt-test",
        .transport_params = "s",
        .zigtls_ticket_key_manager = &manager,
        .zigtls_enable_early_data = true,
        .zigtls_replay_filter = &replay_server,
    });
    defer server2.destroy();
    var sf2 = try server2.handleOutput(allocator, ch);
    defer sf2.deinit();

    // The server ACCEPTED the offer at ClientHello time: the early READ secret
    // exists and matches the client's WRITE secret (same "c e traffic" label).
    try std.testing.expect(server2.earlyDataAccepted());
    const snap2 = server2.engine.snapshotQuicSecrets();
    try std.testing.expect(snap2.zero_rtt_read != null);
    try std.testing.expect(snap2.zero_rtt_write == null);
    const client_write = try client2.trafficSecret(.write, .zero_rtt);
    const server_read = try server2.trafficSecret(.read, .zero_rtt);
    try std.testing.expectEqualSlices(u8, client_write.slice(), server_read.slice());

    // Drive the resumption to completion: the client learns the acceptance
    // from EncryptedExtensions, not from local config.
    var cf2 = try client2.handleOutput(allocator, sf2);
    defer cf2.deinit();
    try std.testing.expect(client2.earlyDataAccepted());
    var st2 = try server2.handleOutput(allocator, cf2);
    defer st2.deinit();
    var ca2 = try client2.handleOutput(allocator, st2);
    defer ca2.deinit();
    try std.testing.expect(client2.isComplete());
    try std.testing.expect(server2.isComplete());
    try std.testing.expect(client2.wasResumed());
    try std.testing.expect(server2.wasResumed());
}

test "tls-zig-native 0-RTT replayed ticket flight is rejected by the replay filter" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x94} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x95} ** 32);
    var manager = zigtls.tls13.ticket_keys.Manager.init();
    try manager.rotate(.{
        .key_id = 0x51525354,
        .material = [_]u8{0x96} ** 32,
        .not_before_unix = 0,
        .not_after_unix = std.math.maxInt(i64),
    });
    var replay_server = try replayFilterForTest(allocator);
    defer replay_server.deinit();
    var replay_client = try replayFilterForTest(allocator);
    defer replay_client.deinit();

    var client1 = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = "iroh-0rtt-replay",
        .server_name = "zigtls-0rtt-replay.example",
        .transport_params = "c",
    });
    defer client1.destroy();
    var server1 = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .alpn = "iroh-0rtt-replay",
        .transport_params = "s",
        .zigtls_ticket_key_manager = &manager,
        .zigtls_auto_issue_new_session_ticket = true,
        .zigtls_enable_early_data = true,
        .zigtls_replay_filter = &replay_server,
    });
    defer server1.destroy();
    var ch1 = try client1.start(allocator);
    defer ch1.deinit();
    var sf1 = try server1.handleOutput(allocator, ch1);
    defer sf1.deinit();
    var cf1 = try client1.handleOutput(allocator, sf1);
    defer cf1.deinit();
    var st1 = try server1.handleOutput(allocator, cf1);
    defer st1.deinit();
    var ca1 = try client1.handleOutput(allocator, st1);
    defer ca1.deinit();
    var captured = client1.popNewSessionTicket() orelse return error.TestUnexpectedResult;
    defer captured.deinit(allocator);
    const ticket = captured.asResumptionTicket() orelse return error.TestUnexpectedResult;

    // First resumption with the ticket: accepted (strike register records it).
    var client2 = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = "iroh-0rtt-replay",
        .server_name = "zigtls-0rtt-replay.example",
        .transport_params = "c",
        .zigtls_resumption_ticket = ticket,
        .zigtls_enable_early_data = true,
        .zigtls_replay_filter = &replay_client,
    });
    defer client2.destroy();
    var ch2 = try client2.start(allocator);
    defer ch2.deinit();
    var server2 = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .alpn = "iroh-0rtt-replay",
        .transport_params = "s",
        .zigtls_ticket_key_manager = &manager,
        .zigtls_enable_early_data = true,
        .zigtls_replay_filter = &replay_server,
    });
    defer server2.destroy();
    var sf2 = try server2.handleOutput(allocator, ch2);
    defer sf2.deinit();
    try std.testing.expect(server2.earlyDataAccepted());

    // Second resumption with the SAME ticket (the replay): the strike register
    // refuses 0-RTT — no early read secret, no EE acceptance — but the PSK
    // handshake itself still completes (silent 0-RTT rejection, rustls-style).
    var client3 = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = "iroh-0rtt-replay",
        .server_name = "zigtls-0rtt-replay.example",
        .transport_params = "c",
        .zigtls_resumption_ticket = ticket,
        .zigtls_enable_early_data = true,
        .zigtls_replay_filter = &replay_client,
    });
    defer client3.destroy();
    var ch3 = try client3.start(allocator);
    defer ch3.deinit();
    try std.testing.expect(client3.earlyDataOffered());
    var server3 = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .alpn = "iroh-0rtt-replay",
        .transport_params = "s",
        .zigtls_ticket_key_manager = &manager,
        .zigtls_enable_early_data = true,
        .zigtls_replay_filter = &replay_server,
    });
    defer server3.destroy();
    var sf3 = try server3.handleOutput(allocator, ch3);
    defer sf3.deinit();
    try std.testing.expect(!server3.earlyDataAccepted());
    try std.testing.expect(server3.engine.snapshotQuicSecrets().zero_rtt_read == null);

    var cf3 = try client3.handleOutput(allocator, sf3);
    defer cf3.deinit();
    try std.testing.expect(!client3.earlyDataAccepted());
    var st3 = try server3.handleOutput(allocator, cf3);
    defer st3.deinit();
    var ca3 = try client3.handleOutput(allocator, st3);
    defer ca3.deinit();
    try std.testing.expect(client3.isComplete());
    try std.testing.expect(server3.isComplete());
    try std.testing.expect(client3.wasResumed());
}

test "tls-zig-native 0-RTT without a replay filter fails closed at session create" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x97} ** 32);
    const result = ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = client_key,
        .peer_public_key = null,
        .alpn = "iroh-0rtt-failclosed",
        .transport_params = "s",
        .zigtls_enable_early_data = true,
        .zigtls_replay_filter = null,
    });
    try std.testing.expectError(error.InvalidConfiguration, result);
}

test "tls-zig-native 0-RTT offer requires early data enabled (no keys without offer)" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0x98} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0x99} ** 32);
    var manager = zigtls.tls13.ticket_keys.Manager.init();
    try manager.rotate(.{
        .key_id = 0x51525354,
        .material = [_]u8{0x9A} ** 32,
        .not_before_unix = 0,
        .not_after_unix = std.math.maxInt(i64),
    });
    var replay_server = try replayFilterForTest(allocator);
    defer replay_server.deinit();

    var client1 = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = "iroh-0rtt-nooffer",
        .server_name = "zigtls-0rtt-nooffer.example",
        .transport_params = "c",
    });
    defer client1.destroy();
    var server1 = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .alpn = "iroh-0rtt-nooffer",
        .transport_params = "s",
        .zigtls_ticket_key_manager = &manager,
        .zigtls_auto_issue_new_session_ticket = true,
        .zigtls_enable_early_data = true,
        .zigtls_replay_filter = &replay_server,
    });
    defer server1.destroy();
    var ch1 = try client1.start(allocator);
    defer ch1.deinit();
    var sf1 = try server1.handleOutput(allocator, ch1);
    defer sf1.deinit();
    var cf1 = try client1.handleOutput(allocator, sf1);
    defer cf1.deinit();
    var st1 = try server1.handleOutput(allocator, cf1);
    defer st1.deinit();
    var ca1 = try client1.handleOutput(allocator, st1);
    defer ca1.deinit();
    var captured = client1.popNewSessionTicket() orelse return error.TestUnexpectedResult;
    defer captured.deinit(allocator);
    const ticket = captured.asResumptionTicket() orelse return error.TestUnexpectedResult;

    // Resuming with a 0-RTT-capable ticket but WITHOUT enabling early data:
    // the client never offers, and the server derives NO early read secret.
    var client2 = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = "iroh-0rtt-nooffer",
        .server_name = "zigtls-0rtt-nooffer.example",
        .transport_params = "c",
        .zigtls_resumption_ticket = ticket,
    });
    defer client2.destroy();
    var ch2 = try client2.start(allocator);
    defer ch2.deinit();
    try std.testing.expect(!client2.earlyDataOffered());
    try std.testing.expect(client2.engine.snapshotQuicSecrets().zero_rtt_write == null);

    var server2 = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .alpn = "iroh-0rtt-nooffer",
        .transport_params = "s",
        .zigtls_ticket_key_manager = &manager,
        .zigtls_enable_early_data = true,
        .zigtls_replay_filter = &replay_server,
    });
    defer server2.destroy();
    var sf2 = try server2.handleOutput(allocator, ch2);
    defer sf2.deinit();
    try std.testing.expect(!server2.earlyDataAccepted());
    try std.testing.expect(server2.engine.snapshotQuicSecrets().zero_rtt_read == null);
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

test "server_alpns: negotiatedProtocol returns the client's offered ALPN" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes([_]u8{0xA1} ** 32);
    const server_key = key.SecretKey.fromBytes([_]u8{0xA2} ** 32);
    const alpn_a = "iroh-example/echo/0";
    const alpn_b = "iroh-example/echo-b/0";

    var client = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
        .alpn = alpn_b,
        .server_name = "zigtls-multi-alpn.example",
        .transport_params = "c",
    });
    defer client.destroy();
    var server = try ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
        .server_alpns = &.{ alpn_a, alpn_b },
        .transport_params = "s",
    });
    defer server.destroy();

    try EndpointHandshake.complete(allocator, client, server);
    const negotiated = server.negotiatedProtocol() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, alpn_b, negotiated);
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

test "ZigtlsSession destroy zeroizes stored secret_key without touching caller copy" {
    const backing = try std.heap.page_allocator.alloc(u8, @sizeOf(ZigtlsSession) + (1 << 20));
    defer std.heap.page_allocator.free(backing);
    var fba = std.heap.FixedBufferAllocator.init(backing);
    const allocator = fba.allocator();

    const seed = [_]u8{0x42} ** 32;
    const caller_secret = key.SecretKey.fromBytes(seed);
    const peer = key.SecretKey.fromBytes([_]u8{0x43} ** 32).public();
    const zsession = try ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = caller_secret,
        .peer_public_key = peer,
        .server_name = "zigtls-zeroize-destroy.example",
        .transport_params = "c",
    });
    try std.testing.expectEqual(seed, zsession.secret_key.toBytes());
    zsession.destroy();

    try std.testing.expectEqual([_]u8{0} ** 32, zsession.secret_key.toBytes());
    try std.testing.expectEqual(seed, caller_secret.toBytes());
}

test "ZigtlsSession create-failure zeroizes secret_key without touching caller copy" {
    const backing = try std.heap.page_allocator.alloc(u8, @sizeOf(ZigtlsSession) + 4096);
    defer std.heap.page_allocator.free(backing);
    var fba = std.heap.FixedBufferAllocator.init(backing);
    const allocator = fba.allocator();

    const seed = [_]u8{0x77} ** 32;
    const caller_secret = key.SecretKey.fromBytes(seed);
    const long_name = [_]u8{'n'} ** (max_server_name_len + 1);
    const result = ZigtlsSession.create(allocator, .{
        .role = .client,
        .secret_key = caller_secret,
        .peer_public_key = null,
        .server_name = &long_name,
    });
    try std.testing.expectError(error.PicotlsError, result);

    const zsession: *ZigtlsSession = @ptrCast(@alignCast(backing.ptr));
    try std.testing.expectEqual([_]u8{0} ** 32, zsession.secret_key.toBytes());
    try std.testing.expectEqual(seed, caller_secret.toBytes());
}

test "ZigtlsSession create-failure zeroizes populated x509 signing key without touching caller copy" {
    const backing = try std.heap.page_allocator.alloc(u8, @sizeOf(ZigtlsSession) + 4096);
    defer std.heap.page_allocator.free(backing);
    var fba = std.heap.FixedBufferAllocator.init(backing);
    const allocator = fba.allocator();

    const seed = [_]u8{0x78} ** 32;
    const caller_secret = key.SecretKey.fromBytes(seed);
    const x509_seed = [_]u8{0x99} ** 32;
    const x509_secret = key.SecretKey.fromBytes(x509_seed);
    const der = [_]u8{ 0x30, 0x82, 0x00, 0x01, 0x00 };
    const chain = [_][]const u8{&der};
    const result = ZigtlsSession.create(allocator, .{
        .role = .server,
        .secret_key = caller_secret,
        .peer_public_key = null,
        .x509_server = .{
            .chain_der = &chain,
            .scheme = .ed25519,
            .key = .{ .ed25519 = x509_secret },
        },
        .certificate_request_signature_algorithms = &.{},
    });
    try std.testing.expectError(error.InvalidConfiguration, result);

    const zsession: *ZigtlsSession = @ptrCast(@alignCast(backing.ptr));
    try std.testing.expectEqual([_]u8{0} ** 32, zsession.x509_key.?.ed25519.toBytes());
    try std.testing.expectEqual([_]u8{0} ** 32, zsession.secret_key.toBytes());
    try std.testing.expectEqual(x509_seed, x509_secret.toBytes());
    try std.testing.expectEqual(seed, caller_secret.toBytes());
}

test "ZigtlsSession create-failure after x509 storage frees DER storage and chain slices" {
    // std.testing.allocator fails the test on leaked allocations. The config
    // below allocates x509_storage + the chain slice table, then fails inside
    // `Engine.initChecked` (empty signature algorithms) — after the
    // block-scoped errdefers have expired.
    const seed = [_]u8{0x78} ** 32;
    const caller_secret = key.SecretKey.fromBytes(seed);
    const x509_seed = [_]u8{0x99} ** 32;
    const x509_secret = key.SecretKey.fromBytes(x509_seed);
    const der = [_]u8{ 0x30, 0x82, 0x00, 0x01, 0x00 };
    const chain = [_][]const u8{&der};
    const result = ZigtlsSession.create(std.testing.allocator, .{
        .role = .server,
        .secret_key = caller_secret,
        .peer_public_key = null,
        .x509_server = .{
            .chain_der = &chain,
            .scheme = .ed25519,
            .key = .{ .ed25519 = x509_secret },
        },
        .certificate_request_signature_algorithms = &.{},
    });
    try std.testing.expectError(error.InvalidConfiguration, result);
}
