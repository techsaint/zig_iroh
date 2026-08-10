//! Picotls-backed noq TLS 1.3 handshake adapter.
//!
//! Split out of `crypto.zig` for the component-repo restructure: THIS file owns
//! the picotls `c.zig` cImport (`@cInclude("picotls.h")` + openssl + rpk), so it
//! is imported ONLY when `build_options.picotls` is true (see the
//! `crypto.PicotlsSession` gate). A noq-zigtls product never pulls libpicotls or
//! libcrypto through here.
//!
//! API touchpoints are pinned to `deps/picotls/include/picotls.h`:
//! `ptls_client_new` / `ptls_server_new`, `ptls_handle_message`,
//! `ptls_get_data_ptr`, `ptls_update_traffic_key_t`, and
//! `ptls_export_secret`. Raw public key setup is in `rpk_picotls.c` and uses
//! `ptls_context_t` directly, not picoquic connection types.

const std = @import("std");
const shared = @import("shared");
const key = shared.key;
const c = @import("c.zig").c;
const contract = shared.tls_contract;

// Shared handshake types live in shared/tls_contract.zig (S6). Config uses the
// same named EmptyType slots as tls-picotls/root.zig so type identity holds.
const Config = contract.ConfigFor(.{
    .ResumptionTicket = contract.EmptyType,
    .TicketKeyManager = contract.EmptyType,
    .ReplayFilter = contract.EmptyType,
    .TrustStore = contract.EmptyType,
    .OcspResponseView = contract.EmptyType,
    .NewSessionTicketInfo = contract.EmptyType,
});
const Role = contract.Role;
const Epoch = contract.Epoch;
const Direction = contract.Direction;
const TrafficSecret = contract.TrafficSecret;
const HandshakeOutput = contract.HandshakeOutput;
const max_epoch = contract.max_epoch;
const max_secret_len = contract.max_secret_len;
/// TLS extension id for `quic_transport_parameters` (RFC 9001 §8.2 / RFC 9000 §18).
const quic_transport_parameters_ext = contract.quic_transport_parameters_ext;

const SecretSlot = struct {
    set: bool = false,
    len: usize = 0,
    bytes: [max_secret_len]u8 = [_]u8{0} ** max_secret_len,
};

/// picotls terminates `additional_extensions` on a `type == UINT16_MAX` sentinel.
const ext_list_terminator: u16 = 0xffff;

const max_alpn_len = 64;
const max_sni_len = 256;
const max_tp_len = 1024;

pub const PicotlsSession = struct {
    allocator: std.mem.Allocator,
    role: Role,
    ctx: ?*c.ptls_context_t,
    tls: ?*c.ptls_t,
    update_traffic_key: c.ptls_update_traffic_key_t,
    secrets: [2][max_epoch]SecretSlot,

    // ── 5a handshake extensions ─────────────────────────────────────────────
    // Persist across every ptls_handle_message call — picotls holds raw pointers
    // into these until the flight that carries the extension has been emitted.
    // The properties struct is opaque to translate-c (anonymous union), so it is
    // C-allocated and its fields are set through iroh_ptls_props_* helpers.
    hs_props: ?*c.ptls_handshake_properties_t,
    alpn_storage: [max_alpn_len]u8,
    alpn_len: usize,
    /// Server selection list (owned copies). Empty => use singular alpn_storage.
    server_alpn_storage: [8][max_alpn_len]u8 = undefined,
    server_alpn_lens: [8]usize = .{0} ** 8,
    server_alpn_count: usize = 0,
    alpn_iovec: [1]c.ptls_iovec_t,
    tp_storage: [max_tp_len]u8,
    additional_ext: [2]c.ptls_raw_extension_t,
    on_client_hello: c.ptls_on_client_hello_t,
    // Peer's collected transport-parameters (the 0x39 extension body).
    peer_tp_storage: [max_tp_len]u8,
    peer_tp_len: usize,
    peer_tp_set: bool,

    /// B8: the TLS alert code of the last failed `ptls_handle_message`
    /// (picotls alert-class errors: self-alert 0x000-0x0ff, peer-alert
    /// 0x100-0x1ff, picotls.h PTLS_ERROR_CLASS_*), null for internal-class
    /// errors. Read after an `error.PicotlsError` to build the CRYPTO_ERROR
    /// transport close code (noq crypto/rustls.rs:98-108).
    last_alert: ?u8 = null,

    /// Non-copyable single-owner pin (v3 cross-apply). Picotls holds raw pointers
    /// into this struct; a by-value move would dangle them. `create` returns a
    /// heap `*PicotlsSession` and `pin` must always equal `self`.
    pin: *PicotlsSession = undefined,

    pub fn create(allocator: std.mem.Allocator, config: Config) !*PicotlsSession {
        const self = try allocator.create(PicotlsSession);
        errdefer allocator.destroy(self);
        try self.init(allocator, config);
        self.pin = self;
        return self;
    }

    pub fn destroy(self: *PicotlsSession) void {
        self.assertPinned();
        const allocator = self.allocator;
        self.deinit();
        allocator.destroy(self);
    }

    /// Compile/runtime guard: owners must be heap-stable pointers, never copies.
    pub fn assertPinned(self: *const PicotlsSession) void {
        std.debug.assert(self.pin == self);
    }

    pub fn init(self: *PicotlsSession, allocator: std.mem.Allocator, config: Config) !void {
        self.* = .{
            .allocator = allocator,
            .role = config.role,
            .ctx = null,
            .tls = null,
            .update_traffic_key = .{ .cb = updateTrafficKey },
            .secrets = std.mem.zeroes([2][max_epoch]SecretSlot),
            .hs_props = null,
            .alpn_storage = undefined,
            .alpn_len = 0,
            .server_alpn_storage = undefined,
            .server_alpn_lens = .{0} ** 8,
            .server_alpn_count = 0,
            .alpn_iovec = undefined,
            .tp_storage = undefined,
            .additional_ext = undefined,
            .on_client_hello = .{ .cb = onClientHello },
            .peer_tp_storage = undefined,
            .peer_tp_len = 0,
            .peer_tp_set = false,
        };
        errdefer self.deinit();

        self.ctx = c.iroh_ptls_context_create(&self.update_traffic_key);
        if (self.ctx == null) return error.AllocationFailed;

        const private_seed = config.secret_key.toBytes();
        const local_public_key = (config.certificate_public_key orelse config.secret_key.public()).toBytes();
        var peer_public_key: [32]u8 = undefined;
        const peer_ptr: [*c]const u8 = if (config.peer_public_key) |peer| blk: {
            peer_public_key = peer.toBytes();
            break :blk peer_public_key[0..].ptr;
        } else null;
        const auth: c_int = if (config.require_client_authentication) 1 else 0;
        if (c.iroh_ptls_configure_raw_public_key(
            self.ctx.?,
            &private_seed,
            &local_public_key,
            peer_ptr,
            auth,
        ) != 0) return error.PicotlsError;

        self.tls = switch (config.role) {
            .client => c.ptls_client_new(self.ctx.?),
            .server => c.ptls_server_new(self.ctx.?),
        };
        if (self.tls == null) return error.AllocationFailed;

        const data_ptr = c.ptls_get_data_ptr(self.tls.?);
        if (data_ptr == null) return error.PicotlsError;
        data_ptr.?.* = self;

        try self.setupHandshakeExtensions(config);
    }

    /// Wire ALPN / SNI / QUIC transport-parameters into the picotls handshake.
    /// picotls holds raw pointers into `self`-owned storage until the carrying
    /// flight is emitted, so every buffer lives in the session (stable address).
    fn setupHandshakeExtensions(self: *PicotlsSession, config: Config) !void {
        const wants_props = config.transport_params != null or
            (config.alpn != null and self.role == .client);
        if (wants_props) {
            self.hs_props = c.iroh_ptls_props_new() orelse return error.AllocationFailed;
        }

        // QUIC transport parameters (ext 0x39) — sent in CH (client) / EE (server),
        // and collected from the peer for flow-control enforcement (5b).
        if (config.transport_params) |tp| {
            if (tp.len > max_tp_len) return error.PicotlsError;
            @memcpy(self.tp_storage[0..tp.len], tp);
            self.additional_ext[0] = .{
                .type = quic_transport_parameters_ext,
                .data = c.iroh_ptls_iovec_init(&self.tp_storage, tp.len),
            };
            self.additional_ext[1] = .{
                .type = ext_list_terminator,
                .data = c.iroh_ptls_iovec_init(null, 0),
            };
            c.iroh_ptls_props_set_additional_extensions(self.hs_props.?, &self.additional_ext);
            c.iroh_ptls_props_set_collect_callbacks(self.hs_props.?, collectExtension, collectedExtensions);
        }

        // ALPN. Client offers a list; server selects via on_client_hello.
        if (config.server_alpns) |list| {
            if (list.len == 0 or list.len > self.server_alpn_storage.len) return error.PicotlsError;
            for (list, 0..) |alpn, i| {
                if (alpn.len == 0 or alpn.len > max_alpn_len) return error.PicotlsError;
                @memcpy(self.server_alpn_storage[i][0..alpn.len], alpn);
                self.server_alpn_lens[i] = alpn.len;
            }
            self.server_alpn_count = list.len;
            // Keep singular storage as the first preference (negotiatedProtocol before select).
            @memcpy(self.alpn_storage[0..list[0].len], list[0]);
            self.alpn_len = list[0].len;
        } else if (config.alpn) |alpn| {
            if (alpn.len == 0 or alpn.len > max_alpn_len) return error.PicotlsError;
            @memcpy(self.alpn_storage[0..alpn.len], alpn);
            self.alpn_len = alpn.len;
        }
        if (self.alpn_len > 0 or self.server_alpn_count > 0) {
            switch (self.role) {
                .client => {
                    self.alpn_iovec[0] = c.iroh_ptls_iovec_init(&self.alpn_storage, self.alpn_len);
                    c.iroh_ptls_props_set_client_alpn(self.hs_props.?, &self.alpn_iovec[0], 1);
                },
                .server => {
                    c.iroh_ptls_ctx_set_on_client_hello(self.ctx.?, &self.on_client_hello);
                },
            }
        }

        // SNI (client only; server receives it via ptls_get_server_name).
        if (config.server_name) |name| {
            if (self.role == .client) {
                if (name.len > max_sni_len) return error.PicotlsError;
                if (c.ptls_set_server_name(self.tls.?, name.ptr, name.len) != 0) {
                    return error.PicotlsError;
                }
            }
        }
    }

    pub fn deinit(self: *PicotlsSession) void {
        for (&self.secrets) |*direction| {
            for (direction) |*slot| {
                std.crypto.secureZero(u8, slot.bytes[0..]);
                slot.len = 0;
                slot.set = false;
            }
        }
        std.crypto.secureZero(u8, self.alpn_storage[0..]);
        std.crypto.secureZero(u8, self.tp_storage[0..]);
        std.crypto.secureZero(u8, self.peer_tp_storage[0..]);
        if (self.tls) |tls| {
            c.ptls_free(tls);
            self.tls = null;
        }
        if (self.ctx) |ctx| {
            c.iroh_ptls_context_destroy(ctx);
            self.ctx = null;
        }
        if (self.hs_props) |props| {
            c.iroh_ptls_props_free(props);
            self.hs_props = null;
        }
    }

    pub fn start(self: *PicotlsSession, allocator: std.mem.Allocator) !HandshakeOutput {
        return self.handleMessage(allocator, .initial, &.{});
    }

    pub fn handleMessage(
        self: *PicotlsSession,
        allocator: std.mem.Allocator,
        in_epoch: Epoch,
        input: []const u8,
    ) !HandshakeOutput {
        var smallbuf: [16 * 1024]u8 = undefined;
        var sendbuf: c.ptls_buffer_t = undefined;
        c.iroh_ptls_buffer_init(&sendbuf, &smallbuf, smallbuf.len);
        defer c.iroh_ptls_buffer_dispose(&sendbuf);

        var epoch_offsets = [_]usize{0} ** (max_epoch + 1);
        const ret = try self.handleInto(&sendbuf, &epoch_offsets, in_epoch, input);
        return outputFromBuffer(allocator, &sendbuf, epoch_offsets, ret);
    }

    pub fn handleOutput(
        self: *PicotlsSession,
        allocator: std.mem.Allocator,
        input: HandshakeOutput,
    ) !HandshakeOutput {
        var smallbuf: [16 * 1024]u8 = undefined;
        var sendbuf: c.ptls_buffer_t = undefined;
        c.iroh_ptls_buffer_init(&sendbuf, &smallbuf, smallbuf.len);
        defer c.iroh_ptls_buffer_dispose(&sendbuf);

        var epoch_offsets = [_]usize{0} ** (max_epoch + 1);
        var ret: c_int = c.PTLS_ERROR_IN_PROGRESS;
        inline for (0..max_epoch) |i| {
            const input_epoch: Epoch = @enumFromInt(i);
            const slice = input.epochSlice(input_epoch);
            if (slice.len != 0) {
                ret = try self.handleInto(&sendbuf, &epoch_offsets, input_epoch, slice);
            }
        }
        return outputFromBuffer(allocator, &sendbuf, epoch_offsets, ret);
    }

    pub fn isComplete(self: *const PicotlsSession) bool {
        return self.tls != null and c.ptls_handshake_is_complete(self.tls.?) != 0;
    }

    pub fn exportSecret(
        self: *PicotlsSession,
        label: [:0]const u8,
        context_value: []const u8,
        out: []u8,
    ) !void {
        const context_ptr: ?*const anyopaque = if (context_value.len == 0) null else context_value.ptr;
        const context = c.iroh_ptls_iovec_init(context_ptr, context_value.len);
        if (c.ptls_export_secret(self.tls.?, out.ptr, out.len, label.ptr, context, 0) != 0) {
            return error.PicotlsError;
        }
    }

    pub fn peerPublicKey(self: *PicotlsSession) !key.PublicKey {
        var out: [32]u8 = undefined;
        if (c.iroh_ptls_last_verified_peer_public_key(self.ctx.?, &out) != 0) {
            return error.MissingPeerPublicKey;
        }
        return key.PublicKey.fromBytes(out);
    }

    /// The peer's collected `quic_transport_parameters` (0x39) extension body,
    /// or null if the peer sent none / the handshake hasn't reached it yet.
    pub fn peerTransportParams(self: *const PicotlsSession) ?[]const u8 {
        if (!self.peer_tp_set) return null;
        return self.peer_tp_storage[0..self.peer_tp_len];
    }

    /// The ALPN protocol negotiated for this session (null until selected).
    pub fn negotiatedProtocol(self: *PicotlsSession) ?[]const u8 {
        const p = c.ptls_get_negotiated_protocol(self.tls.?);
        if (p == null) return null;
        return std.mem.span(p);
    }

    /// The SNI server name the peer sent (server side; null if none).
    pub fn serverName(self: *PicotlsSession) ?[]const u8 {
        const n = c.ptls_get_server_name(self.tls.?);
        if (n == null) return null;
        return std.mem.span(n);
    }

    pub fn trafficSecret(self: *const PicotlsSession, direction: Direction, epoch: Epoch) !TrafficSecret {
        const dir_idx: usize = switch (direction) {
            .read => 0,
            .write => 1,
        };
        const epoch_idx: usize = @intFromEnum(epoch);
        const slot = self.secrets[dir_idx][epoch_idx];
        if (!slot.set) return error.MissingTrafficSecret;
        return .{ .bytes = slot.bytes, .len = slot.len };
    }

    fn handleInto(
        self: *PicotlsSession,
        sendbuf: *c.ptls_buffer_t,
        epoch_offsets: *[max_epoch + 1]usize,
        in_epoch: Epoch,
        input: []const u8,
    ) !c_int {
        const input_ptr: ?*const anyopaque = if (input.len == 0) null else input.ptr;
        const ret = c.ptls_handle_message(
            self.tls.?,
            sendbuf,
            epoch_offsets,
            @intFromEnum(in_epoch),
            input_ptr,
            input.len,
            self.hs_props,
        );
        if (ret != 0 and ret != c.PTLS_ERROR_IN_PROGRESS) {
            // B8: alert-class failures carry the TLS alert code (self-alert
            // class 0x000 / peer-alert class 0x100); internal-class failures
            // (>= PTLS_ERROR_CLASS_INTERNAL) carry none.
            if (ret > 0 and ret < c.PTLS_ERROR_CLASS_INTERNAL) {
                self.last_alert = @intCast(ret & 0xff);
            }
            return error.PicotlsError;
        }
        return ret;
    }

    /// The TLS alert code of the last handshake failure, if it was alert-class.
    pub fn lastAlertCode(self: *const PicotlsSession) ?u8 {
        return self.last_alert;
    }

    /// Capability shims (S6 uniform Session surface). Values match the pre-S6
    /// TlsSession picotls arm exactly — early data disabled, no tickets.
    pub fn earlyDataAccepted(self: *const PicotlsSession) bool {
        _ = self;
        return false;
    }

    pub fn resumptionTransportParams(self: *const PicotlsSession) ?[]const u8 {
        _ = self;
        return null;
    }

    pub fn popNewSessionTicket(self: *PicotlsSession) ?contract.EmptyType {
        _ = self;
        return null;
    }

    pub fn wasResumed(self: *const PicotlsSession) bool {
        _ = self;
        return false;
    }

    fn outputFromBuffer(
        allocator: std.mem.Allocator,
        sendbuf: *const c.ptls_buffer_t,
        epoch_offsets: [max_epoch + 1]usize,
        ret: c_int,
    ) !HandshakeOutput {
        const len = sendbuf.off;
        const bytes = try allocator.alloc(u8, len);
        if (len != 0) {
            @memcpy(bytes, sendbuf.base[0..len]);
        }
        return .{
            .allocator = allocator,
            .bytes = bytes,
            .epoch_offsets = epoch_offsets,
            .ret = ret,
        };
    }
};

pub const EndpointHandshake = struct {
    pub fn complete(
        allocator: std.mem.Allocator,
        client: *PicotlsSession,
        server: *PicotlsSession,
    ) !void {
        var client_hello = try client.start(allocator);
        defer client_hello.deinit();

        var server_flight = try server.handleOutput(allocator, client_hello);
        defer server_flight.deinit();

        var client_finished = try client.handleOutput(allocator, server_flight);
        defer client_finished.deinit();

        var server_done = try server.handleOutput(allocator, client_finished);
        defer server_done.deinit();

        if (!client.isComplete() or !server.isComplete()) {
            return error.IncompleteHandshake;
        }
    }
};

fn sessionFromTls(tls: ?*c.ptls_t) ?*PicotlsSession {
    if (tls == null) return null;
    const data_ptr = c.ptls_get_data_ptr(tls.?);
    if (data_ptr == null or data_ptr.?.* == null) return null;
    return @ptrCast(@alignCast(data_ptr.?.*));
}

/// Server-side ALPN selection (RFC 7301): pick first configured protocol the client offered.
fn onClientHello(
    _: [*c]c.ptls_on_client_hello_t,
    tls: ?*c.ptls_t,
    params: ?*c.ptls_on_client_hello_parameters_t,
) callconv(.c) c_int {
    const self = sessionFromTls(tls) orelse return c.PTLS_ALERT_INTERNAL_ERROR;
    var selected = false;
    if (params != null and self.server_alpn_count > 0) {
        var offered_list: ?[*]c.ptls_iovec_t = null;
        var offered_count: usize = 0;
        c.iroh_ptls_client_hello_negotiated_protocols(params, &offered_list, &offered_count);
        if (offered_list != null and offered_count > 0) {
            var si: usize = 0;
            while (si < self.server_alpn_count) : (si += 1) {
                const ours = self.server_alpn_storage[si][0..self.server_alpn_lens[si]];
                var ci: usize = 0;
                while (ci < offered_count) : (ci += 1) {
                    const item = offered_list.?[ci];
                    if (item.base == null or item.len == 0) continue;
                    const theirs = item.base[0..item.len];
                    if (std.mem.eql(u8, ours, theirs)) {
                        @memcpy(self.alpn_storage[0..ours.len], ours);
                        self.alpn_len = ours.len;
                        if (c.ptls_set_negotiated_protocol(tls.?, &self.alpn_storage, self.alpn_len) != 0) {
                            return c.PTLS_ALERT_NO_APPLICATION_PROTOCOL;
                        }
                        selected = true;
                        break;
                    }
                }
                if (selected) break;
            }
            if (!selected) return c.PTLS_ALERT_NO_APPLICATION_PROTOCOL;
        }
    }
    if (!selected and self.alpn_len > 0) {
        if (c.ptls_set_negotiated_protocol(tls.?, &self.alpn_storage, self.alpn_len) != 0) {
            return c.PTLS_ALERT_NO_APPLICATION_PROTOCOL;
        }
    }
    // Record the received SNI so ptls_get_server_name() observes it server-side.
    if (params != null) {
        var base: [*c]const u8 = null;
        var len: usize = 0;
        c.iroh_ptls_client_hello_server_name(params, &base, &len);
        if (len > 0 and base != null) {
            _ = c.ptls_set_server_name(tls.?, base, len);
        }
    }
    return 0;
}

/// Collect only the QUIC transport-parameters extension (0x39).
fn collectExtension(
    _: ?*c.ptls_t,
    _: ?*c.ptls_handshake_properties_t,
    ext_type: u16,
) callconv(.c) c_int {
    return if (ext_type == quic_transport_parameters_ext) 1 else 0;
}

/// Store the peer's transport-parameters bytes for flow-control enforcement (5b).
fn collectedExtensions(
    tls: ?*c.ptls_t,
    _: ?*c.ptls_handshake_properties_t,
    extensions: [*c]c.ptls_raw_extension_t,
) callconv(.c) c_int {
    const self = sessionFromTls(tls) orelse return c.PTLS_ALERT_INTERNAL_ERROR;
    var i: usize = 0;
    while (extensions[i].type != ext_list_terminator) : (i += 1) {
        if (extensions[i].type == quic_transport_parameters_ext) {
            const data = extensions[i].data;
            if (data.len > max_tp_len) return c.PTLS_ALERT_DECODE_ERROR;
            if (data.len != 0) {
                const src: [*]const u8 = @ptrCast(data.base);
                @memcpy(self.peer_tp_storage[0..data.len], src[0..data.len]);
            }
            self.peer_tp_len = data.len;
            self.peer_tp_set = true;
        }
    }
    return 0;
}

fn updateTrafficKey(
    _: [*c]c.ptls_update_traffic_key_t,
    tls: ?*c.ptls_t,
    is_enc: c_int,
    epoch: usize,
    secret: ?*const anyopaque,
) callconv(.c) c_int {
    if (tls == null or secret == null or epoch >= max_epoch) {
        return c.PTLS_ALERT_INTERNAL_ERROR;
    }
    const data_ptr = c.ptls_get_data_ptr(tls.?);
    if (data_ptr == null or data_ptr.?.* == null) {
        return c.PTLS_ALERT_INTERNAL_ERROR;
    }

    const session: *PicotlsSession = @ptrCast(@alignCast(data_ptr.?.*));
    const secret_len = c.iroh_ptls_secret_size(tls.?);
    if (secret_len == 0) return c.PTLS_ALERT_INTERNAL_ERROR;
    if (secret_len > max_secret_len) {
        return c.PTLS_ALERT_INTERNAL_ERROR;
    }

    const dir_idx: usize = if (is_enc != 0) 1 else 0;
    const secret_bytes: [*]const u8 = @ptrCast(secret.?);
    var slot = &session.secrets[dir_idx][epoch];
    @memset(&slot.bytes, 0);
    @memcpy(slot.bytes[0..secret_len], secret_bytes[0..secret_len]);
    slot.len = secret_len;
    slot.set = true;
    return 0;
}

test "N3b1 picotls RPK handshake exposes exporter and QUIC traffic secrets" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes(.{0x11} ** 32);
    const server_key = key.SecretKey.fromBytes(.{0x22} ** 32);

    var client = try PicotlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
    });
    defer client.destroy();

    var server = try PicotlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = client_key.public(),
        .require_client_authentication = true,
    });
    defer server.destroy();

    try EndpointHandshake.complete(allocator, client, server);

    try std.testing.expect(client.isComplete());
    try std.testing.expect(server.isComplete());
    try std.testing.expectEqualSlices(u8, &server_key.public().toBytes(), &(try client.peerPublicKey()).toBytes());
    try std.testing.expectEqualSlices(u8, &client_key.public().toBytes(), &(try server.peerPublicKey()).toBytes());

    var client_exporter: [32]u8 = undefined;
    var server_exporter: [32]u8 = undefined;
    try client.exportSecret("EXPORTER-iroh-noq-n3b1", "handshake-smoke", &client_exporter);
    try server.exportSecret("EXPORTER-iroh-noq-n3b1", "handshake-smoke", &server_exporter);
    try std.testing.expectEqualSlices(u8, &client_exporter, &server_exporter);

    const client_read_hs = try client.trafficSecret(.read, .handshake);
    const server_write_hs = try server.trafficSecret(.write, .handshake);
    try std.testing.expectEqualSlices(u8, client_read_hs.slice(), server_write_hs.slice());

    const client_write_hs = try client.trafficSecret(.write, .handshake);
    const server_read_hs = try server.trafficSecret(.read, .handshake);
    try std.testing.expectEqualSlices(u8, client_write_hs.slice(), server_read_hs.slice());

    const client_read_app = try client.trafficSecret(.read, .application);
    const server_write_app = try server.trafficSecret(.write, .application);
    try std.testing.expectEqualSlices(u8, client_read_app.slice(), server_write_app.slice());

    const client_write_app = try client.trafficSecret(.write, .application);
    const server_read_app = try server.trafficSecret(.read, .application);
    try std.testing.expectEqualSlices(u8, client_write_app.slice(), server_read_app.slice());
}

test "N3b5-5d learned RPK peer is published only after CertificateVerify" {
    const allocator = std.testing.allocator;
    const client_key = key.SecretKey.fromBytes(.{0x51} ** 32);
    const server_key = key.SecretKey.fromBytes(.{0x52} ** 32);

    var client = try PicotlsSession.create(allocator, .{
        .role = .client,
        .secret_key = client_key,
        .peer_public_key = server_key.public(),
    });
    defer client.destroy();
    var server = try PicotlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
    });
    defer server.destroy();

    try EndpointHandshake.complete(allocator, client, server);
    try std.testing.expect((try server.peerPublicKey()).eql(client_key.public()));
}

test "N3b5-5d rejects an RPK CertificateVerify signed by another key" {
    const allocator = std.testing.allocator;
    const signing_key = key.SecretKey.fromBytes(.{0x61} ** 32);
    const advertised_key = key.SecretKey.fromBytes(.{0x62} ** 32);
    const server_key = key.SecretKey.fromBytes(.{0x63} ** 32);

    var client = try PicotlsSession.create(allocator, .{
        .role = .client,
        .secret_key = signing_key,
        .certificate_public_key = advertised_key.public(),
        .peer_public_key = server_key.public(),
    });
    defer client.destroy();
    var server = try PicotlsSession.create(allocator, .{
        .role = .server,
        .secret_key = server_key,
        .peer_public_key = null,
        .require_client_authentication = true,
    });
    defer server.destroy();

    try std.testing.expectError(error.PicotlsError, EndpointHandshake.complete(allocator, client, server));
    try std.testing.expectError(error.MissingPeerPublicKey, server.peerPublicKey());
}

test "N3b5-5a handshake carries ALPN, SNI, and QUIC transport parameters" {
    // S6: the pre-slice body imported engine.transport_parameters (a test-only
    // tls→engine cycle). Relocated to the composition test root
    // `engine-noq/harness/picotls_tp_handshake_test.zig`, collected by the
    // engine module. This stub preserves the test NAME so count-identity
    // tooling can see the rename rather than a silent drop.
    return error.SkipZigTest;
}

test "N-2 PicotlsSession is heap-stable non-copyable (pin == self)" {
    const allocator = std.testing.allocator;
    const sk = key.SecretKey.fromBytes([_]u8{0x42} ** 32);
    var session = try PicotlsSession.create(allocator, .{
        .role = .client,
        .secret_key = sk,
        .peer_public_key = sk.public(),
    });
    defer session.destroy();
    session.assertPinned();
    try std.testing.expect(session.pin == session);
}
