//! ACME client (RFC 8555) for the relay: directory discovery, ES256 account
//! key with JWS request signing, multi-identifier newOrder, TLS-ALPN-01
//! challenge selection + response, finalize with a SAN CSR, and certificate
//! download. Challenge installation is delegated to a callback so the ACME
//! manager owns the live cert table the relay's TLS selector serves from.
//!
//! Trust discipline: every directory request goes through `http.request`
//! pinned to the configured CA bundle — no system roots, no skip-verify.
//! Fail-closed: any protocol violation, ACME problem document, or unexpected
//! status aborts the order; nothing is retried past one badNonce refresh.

const std = @import("std");
const http = @import("http.zig");
const jws = @import("jws.zig");
const x509 = @import("x509.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const acme_challenge_alpn = "tls-alpn-01";

pub const Error = error{
    InvalidDirectoryUrl,
    DirectoryFailed,
    NonceFailed,
    AccountFailed,
    OrderFailed,
    AuthorizationFailed,
    ChallengeFailed,
    FinalizeFailed,
    CertificateFetchFailed,
    NoTlsAlpnChallenge,
    OutOfMemory,
} || http.Error || x509.Error;

/// Absolute https:// URL split for the dial layer.
pub const Url = struct {
    host: []const u8,
    port: u16,
    path: []const u8, // includes query when present

    pub fn parse(url: []const u8) Error!Url {
        if (!std.mem.startsWith(u8, url, "https://")) return error.InvalidDirectoryUrl;
        const rest = url["https://".len..];
        const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
        const authority = rest[0..slash];
        if (authority.len == 0) return error.InvalidDirectoryUrl;
        const path = if (slash == rest.len) "/" else rest[slash..];
        if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
            // A colon after a ']' is an IPv6 literal port; bare v6 literals
            // are out of scope for the ACME directory (hostnames in practice).
            if (authority[colon - 1] == ']' or std.mem.indexOfScalar(u8, authority, ']') == null) {
                const host = authority[0..colon];
                const port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch
                    return error.InvalidDirectoryUrl;
                return .{ .host = host, .port = port, .path = path };
            }
        }
        return .{ .host = authority, .port = 443, .path = path };
    }
};

const Directory = struct {
    newNonce: []const u8,
    newAccount: []const u8,
    newOrder: []const u8,
};

pub const Order = struct {
    url: []const u8,
    status: []const u8,
    authorizations: []const []const u8,
    finalize: []const u8,
    certificate: ?[]const u8 = null,
};

pub const Authorization = struct {
    status: []const u8,
    identifier_value: []const u8,
    challenge_url: []const u8, // the selected tls-alpn-01 challenge
    challenge_token: []const u8,
};

/// Installs/removes the live TLS-ALPN-01 responder state. Called by the ACME
/// flow BEFORE the challenge POST (the CA validates immediately after) and
/// after the authorization settles either way.
pub const ChallengeSink = struct {
    context: *anyopaque,
    install_fn: *const fn (context: *anyopaque, hostname: []const u8, key_authorization: []const u8) anyerror!void,
    remove_fn: *const fn (context: *anyopaque, hostname: []const u8) void,

    pub fn install(self: ChallengeSink, hostname: []const u8, key_authorization: []const u8) !void {
        try self.install_fn(self.context, hostname, key_authorization);
    }
    pub fn remove(self: ChallengeSink, hostname: []const u8) void {
        self.remove_fn(self.context, hostname);
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    root_ca: *const std.crypto.Certificate.Bundle,
    directory_url: []const u8,
    account_key: Ecdsa.KeyPair,
    thumbprint: [43]u8,
    directory: ?Directory = null,
    account_url: ?[]const u8 = null,
    nonce: ?[]const u8 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        root_ca: *const std.crypto.Certificate.Bundle,
        directory_url: []const u8,
        account_key: Ecdsa.KeyPair,
    ) Client {
        var thumbprint: [43]u8 = undefined;
        const public = account_key.public_key.toUncompressedSec1();
        jws.jwkThumbprint(&public, &thumbprint);
        return .{
            .allocator = allocator,
            .io = io,
            .root_ca = root_ca,
            .directory_url = directory_url,
            .account_key = account_key,
            .thumbprint = thumbprint,
        };
    }

    /// GET the directory (and the first nonce). Idempotent.
    pub fn discover(self: *Client) Error!void {
        const dir_url = try Url.parse(self.directory_url);
        var resp = try http.request(self.allocator, self.io, self.root_ca, .get, dir_url.host, dir_url.port, dir_url.path, null, "");
        defer resp.deinit(self.allocator);
        if (resp.status != 200) return error.DirectoryFailed;

        const parsed = std.json.parseFromSlice(Directory, self.allocator, resp.body, .{
            .ignore_unknown_fields = true,
        }) catch return error.DirectoryFailed;
        defer parsed.deinit();
        self.directory = .{
            .newNonce = try self.allocator.dupe(u8, parsed.value.newNonce),
            .newAccount = try self.allocator.dupe(u8, parsed.value.newAccount),
            .newOrder = try self.allocator.dupe(u8, parsed.value.newOrder),
        };
        try self.refreshNonce();
    }

    /// HEAD newNonce — the nonce bootstrap path (RFC 8555 §7.2).
    pub fn refreshNonce(self: *Client) Error!void {
        const dir = self.directory orelse return error.DirectoryFailed;
        const url = try Url.parse(dir.newNonce);
        var resp = try http.request(self.allocator, self.io, self.root_ca, .head, url.host, url.port, url.path, null, "");
        defer resp.deinit(self.allocator);
        if (resp.status != 200 and resp.status != 204) return error.NonceFailed;
        self.storeNonce(resp);
    }

    fn storeNonce(self: *Client, resp: http.Response) void {
        if (resp.replay_nonce) |n| {
            if (self.nonce) |old| self.allocator.free(old);
            self.nonce = self.allocator.dupe(u8, n) catch null;
        }
    }

    /// newAccount (idempotent: an existing account returns 200 + Location).
    pub fn ensureAccount(self: *Client, contact: ?[]const u8) Error!void {
        if (self.account_url != null) return;
        const dir = self.directory orelse return error.DirectoryFailed;

        var payload_buf: [512]u8 = undefined;
        const payload = if (contact) |c|
            std.fmt.bufPrint(&payload_buf, "{{\"termsOfServiceAgreed\":true,\"contact\":[\"mailto:{s}\"]}}", .{c}) catch
                return error.AccountFailed
        else
            "{\"termsOfServiceAgreed\":true}";

        const body = try self.signedPostBody(dir.newAccount, payload, .jwk);
        defer self.allocator.free(body);
        var resp = try self.post(dir.newAccount, body);
        defer resp.deinit(self.allocator);
        if (resp.status != 200 and resp.status != 201) {
            self.logProblem("newAccount", resp.body);
            return error.AccountFailed;
        }
        const location = resp.location orelse return error.AccountFailed;
        self.account_url = try self.allocator.dupe(u8, location);
    }

    /// newOrder for `hostnames` (each becomes a dns identifier). Returns the
    /// order; slices are owned by the caller's allocator (free with
    /// `freeOrder`).
    pub fn newOrder(self: *Client, hostnames: []const []const u8) Error!Order {
        const dir = self.directory orelse return error.DirectoryFailed;
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);
        try payload.appendSlice(self.allocator, "{\"identifiers\":[");
        for (hostnames, 0..) |h, i| {
            if (i > 0) try payload.append(self.allocator, ',');
            var id_buf: [300]u8 = undefined;
            const ident = std.fmt.bufPrint(&id_buf, "{{\"type\":\"dns\",\"value\":\"{s}\"}}", .{h}) catch
                return error.OrderFailed;
            try payload.appendSlice(self.allocator, ident);
        }
        try payload.appendSlice(self.allocator, "]}");

        const body = try self.signedPostBody(dir.newOrder, payload.items, .kid);
        defer self.allocator.free(body);
        var resp = try self.post(dir.newOrder, body);
        defer resp.deinit(self.allocator);
        if (resp.status != 201) {
            self.logProblem("newOrder", resp.body);
            return error.OrderFailed;
        }
        const order_url = resp.location orelse return error.OrderFailed;
        return self.parseOrderBody(try self.allocator.dupe(u8, order_url), resp.body);
    }

    const OrderJson = struct {
        status: []const u8,
        authorizations: []const []const u8,
        finalize: []const u8,
        certificate: ?[]const u8 = null,
    };

    fn parseOrderBody(self: *Client, order_url: []const u8, body: []const u8) Error!Order {
        const parsed = std.json.parseFromSlice(OrderJson, self.allocator, body, .{
            .ignore_unknown_fields = true,
        }) catch return error.OrderFailed;
        defer parsed.deinit();
        const authzs = try self.allocator.alloc([]const u8, parsed.value.authorizations.len);
        for (parsed.value.authorizations, 0..) |a, i|
            authzs[i] = try self.allocator.dupe(u8, a);
        return .{
            .url = order_url,
            .status = try self.allocator.dupe(u8, parsed.value.status),
            .authorizations = authzs,
            .finalize = try self.allocator.dupe(u8, parsed.value.finalize),
            .certificate = if (parsed.value.certificate) |c| try self.allocator.dupe(u8, c) else null,
        };
    }

    pub fn freeOrder(self: *Client, order: *Order) void {
        self.allocator.free(order.url);
        self.allocator.free(order.status);
        for (order.authorizations) |a| self.allocator.free(a);
        self.allocator.free(order.authorizations);
        self.allocator.free(order.finalize);
        if (order.certificate) |c| self.allocator.free(c);
    }

    const AuthzJson = struct {
        status: []const u8,
        identifier: struct { type: []const u8, value: []const u8 },
        challenges: []const struct {
            type: []const u8,
            url: []const u8,
            // Optional: some challenge types (e.g. dns-persist-01) carry no
            // token. Required for tls-alpn-01 — enforced at selection.
            token: ?[]const u8 = null,
            status: []const u8,
        },
    };

    /// POST-as-GET an authorization and select its tls-alpn-01 challenge.
    pub fn fetchAuthorization(self: *Client, authz_url: []const u8) Error!Authorization {
        var resp = try self.postAsGet(authz_url);
        defer resp.deinit(self.allocator);
        if (resp.status != 200) {
            std.debug.print("[acme] authz fetch got status {d}: {s}\n", .{ resp.status, resp.body[0..@min(resp.body.len, 4000)] });
            return error.AuthorizationFailed;
        }
        const parsed = std.json.parseFromSlice(AuthzJson, self.allocator, resp.body, .{
            .ignore_unknown_fields = true,
        }) catch |err| {
            std.debug.print("[acme] authz json parse failed ({}): {s}\n", .{ err, resp.body[0..@min(resp.body.len, 4000)] });
            return error.AuthorizationFailed;
        };
        defer parsed.deinit();
        for (parsed.value.challenges) |ch| {
            if (std.mem.eql(u8, ch.type, acme_challenge_alpn)) {
                return .{
                    .status = try self.allocator.dupe(u8, parsed.value.status),
                    .identifier_value = try self.allocator.dupe(u8, parsed.value.identifier.value),
                    .challenge_url = try self.allocator.dupe(u8, ch.url),
                    .challenge_token = try self.allocator.dupe(u8, ch.token orelse
                        return error.NoTlsAlpnChallenge),
                };
            }
        }
        return error.NoTlsAlpnChallenge;
    }

    pub fn freeAuthorization(self: *Client, authz: *Authorization) void {
        self.allocator.free(authz.status);
        self.allocator.free(authz.identifier_value);
        self.allocator.free(authz.challenge_url);
        self.allocator.free(authz.challenge_token);
    }

    /// RFC 8555 §8.1: token + "." + base64url(JWK thumbprint).
    pub fn keyAuthorization(self: *Client, token: []const u8) Error![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ token, self.thumbprint });
    }

    /// Runs one authorization to completion: install the challenge via
    /// `sink`, tell the CA, poll until valid/invalid, always uninstall.
    pub fn completeAuthorization(
        self: *Client,
        authz_url: []const u8,
        sink: ChallengeSink,
        poll_interval_ns: u64,
        deadline_ns: u64,
    ) Error!void {
        var authz = try self.fetchAuthorization(authz_url);
        defer self.freeAuthorization(&authz);
        if (std.mem.eql(u8, authz.status, "valid")) return; // already valid (re-use)
        std.debug.print("[acme] authorizing {s} via tls-alpn-01 ({s})\n", .{ authz.identifier_value, authz.challenge_url });

        const key_authz = try self.keyAuthorization(authz.challenge_token);
        defer self.allocator.free(key_authz);

        sink.install(authz.identifier_value, key_authz) catch return error.ChallengeFailed;
        defer sink.remove(authz.identifier_value);

        // Challenge response: empty JSON object (RFC 8555 §7.5.1).
        const body = try self.signedPostBody(authz.challenge_url, "{}", .kid);
        defer self.allocator.free(body);
        var challenge_resp = try self.post(authz.challenge_url, body);
        defer challenge_resp.deinit(self.allocator);
        if (challenge_resp.status != 200) {
            self.logProblem("challenge", challenge_resp.body);
            return error.ChallengeFailed;
        }
        std.debug.print("[acme] challenge posted for {s}, polling\n", .{authz.identifier_value});

        // Poll the authorization until it settles.
        var waited: u64 = 0;
        while (waited < deadline_ns) {
            self.io.sleep(std.Io.Duration.fromNanoseconds(@intCast(poll_interval_ns)), .awake) catch {};
            waited += poll_interval_ns;
            var poll = try self.fetchAuthorization(authz_url);
            defer self.freeAuthorization(&poll);
            if (std.mem.eql(u8, poll.status, "valid")) {
                std.debug.print("[acme] {s} validated\n", .{poll.identifier_value});
                return;
            }
            if (std.mem.eql(u8, poll.status, "invalid")) {
                std.debug.print("[acme] {s} validation FAILED (authz invalid)\n", .{poll.identifier_value});
                return error.ChallengeFailed;
            }
            if (std.mem.eql(u8, poll.status, "deactivated") or std.mem.eql(u8, poll.status, "expired") or
                std.mem.eql(u8, poll.status, "revoked")) return error.AuthorizationFailed;
            // pending/processing → keep polling
        }
        return error.ChallengeFailed; // timed out still pending
    }

    /// finalize with a CSR, then poll the order until the certificate URL
    /// appears. Returns the certificate URL (caller frees).
    pub fn finalizeOrder(
        self: *Client,
        order: *const Order,
        csr_der: []const u8,
        poll_interval_ns: u64,
        deadline_ns: u64,
    ) Error![]u8 {
        const csr_b64 = try jws.b64urlEncode(self.allocator, csr_der);
        defer self.allocator.free(csr_b64);
        const payload = try std.fmt.allocPrint(self.allocator, "{{\"csr\":\"{s}\"}}", .{csr_b64});
        defer self.allocator.free(payload);

        const body = try self.signedPostBody(order.finalize, payload, .kid);
        defer self.allocator.free(body);
        var resp = try self.post(order.finalize, body);
        defer resp.deinit(self.allocator);
        if (resp.status != 200) {
            self.logProblem("finalize", resp.body);
            return error.FinalizeFailed;
        }

        var waited: u64 = 0;
        while (waited < deadline_ns) {
            var poll_resp = try self.postAsGet(order.url);
            defer poll_resp.deinit(self.allocator);
            if (poll_resp.status == 200) {
                var polled = self.parseOrderBody(try self.allocator.dupe(u8, order.url), poll_resp.body) catch
                    return error.FinalizeFailed;
                defer self.freeOrder(&polled);
                if (polled.certificate) |cert_url| return try self.allocator.dupe(u8, cert_url);
                if (std.mem.eql(u8, polled.status, "invalid")) return error.FinalizeFailed;
                // ready/processing → keep polling
            }
            self.io.sleep(std.Io.Duration.fromNanoseconds(@intCast(poll_interval_ns)), .awake) catch {};
            waited += poll_interval_ns;
        }
        return error.FinalizeFailed;
    }

    /// POST-as-GET the certificate URL; returns the PEM chain text.
    pub fn downloadCertificate(self: *Client, certificate_url: []const u8) Error![]u8 {
        var resp = try self.postAsGet(certificate_url);
        defer resp.deinit(self.allocator);
        if (resp.status != 200 or resp.body.len == 0) return error.CertificateFetchFailed;
        if (!std.mem.startsWith(u8, resp.body, "-----BEGIN CERTIFICATE-----"))
            return error.CertificateFetchFailed;
        return try self.allocator.dupe(u8, resp.body);
    }

    // -- JWS plumbing ---------------------------------------------------------

    const ProtectedKind = enum { jwk, kid };

    fn signedPostBody(self: *Client, url: []const u8, payload: []const u8, kind: ProtectedKind) Error![]u8 {
        if (self.nonce == null) try self.refreshNonce();
        const nonce = self.nonce orelse return error.NonceFailed;

        var protected_buf: [1024]u8 = undefined;
        const protected = switch (kind) {
            .jwk => blk: {
                const public = self.account_key.public_key.toUncompressedSec1();
                const jwk_json = jws.jwkJson(self.allocator, &public) catch return error.OutOfMemory;
                defer self.allocator.free(jwk_json);
                break :blk std.fmt.bufPrint(&protected_buf, "{{\"alg\":\"ES256\",\"jwk\":{s},\"nonce\":\"{s}\",\"url\":\"{s}\"}}", .{ jwk_json, nonce, url }) catch return error.OutOfMemory;
            },
            .kid => std.fmt.bufPrint(&protected_buf, "{{\"alg\":\"ES256\",\"kid\":\"{s}\",\"nonce\":\"{s}\",\"url\":\"{s}\"}}", .{ self.account_url orelse return error.AccountFailed, nonce, url }) catch return error.OutOfMemory,
        };
        return jws.signFlattened(self.allocator, self.account_key, protected, payload);
    }

    /// POST a JWS body, refreshing the nonce once on badNonce (RFC 8555 §6.5).
    fn post(self: *Client, url_str: []const u8, body: []const u8) Error!http.Response {
        const url = try Url.parse(url_str);
        var resp = try http.request(self.allocator, self.io, self.root_ca, .post, url.host, url.port, url.path, "application/jose+json", body);
        if (isBadNonce(resp)) {
            resp.deinit(self.allocator);
            try self.refreshNonce();
            // Re-sign with the fresh nonce: the caller's body embeds the old one.
            const payload_json = try self.extractPayload(body);
            defer self.allocator.free(payload_json);
            const kind: ProtectedKind = if (self.account_url != null and std.mem.indexOf(u8, body, "\"kid\"") != null) .kid else .jwk;
            const fresh_body = try self.signedPostBody(url_str, payload_json, kind);
            defer self.allocator.free(fresh_body);
            resp = try http.request(self.allocator, self.io, self.root_ca, .post, url.host, url.port, url.path, "application/jose+json", fresh_body);
        }
        self.storeNonce(resp);
        return resp;
    }

    /// POST-as-GET (RFC 8555 §6.3): empty payload, kid-protected JWS.
    fn postAsGet(self: *Client, url_str: []const u8) Error!http.Response {
        const body = try self.signedPostBody(url_str, "", .kid);
        defer self.allocator.free(body);
        return self.post(url_str, body);
    }

    fn isBadNonce(resp: http.Response) bool {
        if (resp.status != 400) return false;
        return std.mem.indexOf(u8, resp.body, "badNonce") != null;
    }

    fn extractPayload(self: *Client, jws_body: []const u8) Error![]u8 {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, jws_body, .{}) catch
            return error.InvalidDirectoryUrl;
        defer parsed.deinit();
        const payload_b64 = parsed.value.object.get("payload") orelse return error.InvalidDirectoryUrl;
        const decoded = try self.allocator.alloc(u8, jws.b64url_dec.calcSizeForSlice(payload_b64.string) catch
            return error.InvalidDirectoryUrl);
        jws.b64url_dec.decode(decoded, payload_b64.string) catch return error.InvalidDirectoryUrl;
        return decoded;
    }

    fn logProblem(self: *Client, what: []const u8, body: []const u8) void {
        _ = self;
        std.debug.print("[acme] {s} failed, server said: {s}\n", .{ what, body[0..@min(body.len, 512)] });
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "authz json tolerates tokenless challenge types (real pebble shape)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Captured from a real Pebble authz (2026-08-03): dns-persist-01 has no
    // token field; challenge order varies per authorization.
    const body =
        \\{
        \\   "status": "pending",
        \\   "identifier": { "type": "dns", "value": "relay-b.localhost" },
        \\   "challenges": [
        \\      { "type": "dns-01", "url": "https://localhost:14000/chalZ/a", "token": "t1", "status": "pending" },
        \\      { "type": "dns-persist-01", "url": "https://localhost:14000/chalZ/b", "status": "pending",
        \\        "accounturi": "https://localhost:14000/my-account/x", "issuer-domain-names": ["pebble.letsencrypt.org"] },
        \\      { "type": "tls-alpn-01", "url": "https://localhost:14000/chalZ/c", "token": "tok-alpn", "status": "pending" }
        \\   ],
        \\   "expires": "2026-08-03T09:48:11Z"
        \\}
    ;
    const parsed = try std.json.parseFromSlice(Client.AuthzJson, a, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var found: ?[]const u8 = null;
    for (parsed.value.challenges) |ch| {
        if (std.mem.eql(u8, ch.type, acme_challenge_alpn)) found = ch.token;
    }
    try std.testing.expectEqualStrings("tok-alpn", found.?);
}

test "url parse splits host port path" {
    const url1 = try Url.parse("https://localhost:14000/dir");
    try std.testing.expectEqualStrings("localhost", url1.host);
    try std.testing.expectEqual(@as(u16, 14000), url1.port);
    try std.testing.expectEqualStrings("/dir", url1.path);

    const url2 = try Url.parse("https://acme-v02.api.letsencrypt.org/directory");
    try std.testing.expectEqual(@as(u16, 443), url2.port);
    try std.testing.expectEqualStrings("acme-v02.api.letsencrypt.org", url2.host);

    const url3 = try Url.parse("https://pebble:14000/authZ/abc?x=1");
    try std.testing.expectEqualStrings("/authZ/abc?x=1", url3.path);

    try std.testing.expectError(error.InvalidDirectoryUrl, Url.parse("http://localhost:14000/dir"));
    try std.testing.expectError(error.InvalidDirectoryUrl, Url.parse("https:///dir"));
    try std.testing.expectError(error.InvalidDirectoryUrl, Url.parse("https://localhost:notaport/dir"));
}

test "key authorization format is token dot thumbprint" {
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(@splat(21));
    var bundle = std.crypto.Certificate.Bundle.empty;
    var client = Client.init(std.testing.allocator, std.testing.io, &bundle, "https://localhost:14000/dir", key_pair);
    const ka = try client.keyAuthorization("tok123");
    defer std.testing.allocator.free(ka);
    try std.testing.expect(std.mem.startsWith(u8, ka, "tok123."));
    // thumbprint is 43 base64url chars
    try std.testing.expectEqual(@as(usize, "tok123.".len + 43), ka.len);
}
