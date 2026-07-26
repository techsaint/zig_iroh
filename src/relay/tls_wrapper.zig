//! TLS wrapper for DERP relay — wraps tls.zig (ianic/tls.zig).
//!
//! Provides TLS client/server streams for wss:// relay connections.
//! tls.zig is a pure Zig TLS 1.2/1.3 library that upgrades a
//! std.Io.net.Stream to a TLS Connection.

const std = @import("std");
pub const tls = @import("tls");

pub const TlsError = error{
    TlsHandshakeFailed,
    CertificateError,
};

fn activeCipherStorage(cipher: *tls.Cipher) []u8 {
    return switch (cipher.*) {
        inline else => |*state| std.mem.asBytes(state),
    };
}

fn zeroizeTrafficKeys(cipher: *tls.Cipher) void {
    // The pinned ianic/tls Connection.close only writes close_notify and has
    // no deinit/secret wipe. Its active cipher payload owns the traffic keys,
    // IVs, and TLS 1.3 traffic secrets, so scrub that payload after all I/O.
    // Keep the union tag intact so repeated teardown remains well-defined.
    std.crypto.secureZero(u8, activeCipherStorage(cipher));
}

/// A TLS client connection wrapping a TCP stream.
pub const TlsClient = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,

    enc_rdbuf: [tls.input_buffer_len]u8,
    enc_wrbuf: [tls.output_buffer_len]u8,
    enc_reader: std.Io.net.Stream.Reader,
    enc_writer: std.Io.net.Stream.Writer,

    tls_conn: tls.Connection,

    tls_rdbuf: [17000]u8,
    tls_wrbuf: [17000]u8,
    cleartext_reader: @TypeOf((@as(*tls.Connection, undefined)).reader(@as([]u8, undefined))),
    cleartext_writer: @TypeOf((@as(*tls.Connection, undefined)).writer(@as([]u8, undefined))),
    closed: bool,

    /// Upgrade a TCP stream to TLS (client side).
    /// `host` is the SNI hostname for certificate verification.
    /// Set `insecure_skip_verify` to true for self-signed certs (testing).
    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: std.Io.net.Stream,
        host: []const u8,
        insecure_skip_verify: bool,
    ) !*TlsClient {
        const self = try allocator.create(TlsClient);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.io = io;
        self.stream = stream;

        self.enc_rdbuf = undefined;
        self.enc_wrbuf = undefined;
        self.enc_reader = self.stream.reader(self.io, &self.enc_rdbuf);
        self.enc_writer = self.stream.writer(self.io, &self.enc_wrbuf);

        var rng_impl: std.Random.IoSource = .{ .io = io };
        const rng = rng_impl.interface();

        var root_ca = std.crypto.Certificate.Bundle.empty;
        defer root_ca.deinit(allocator);
        try root_ca.rescan(allocator, io, std.Io.Clock.real.now(io));

        self.tls_conn = tls.client(&self.enc_reader.interface, &self.enc_writer.interface, .{
            .host = host,
            .root_ca = root_ca,
            .insecure_skip_verify = insecure_skip_verify,
            .now = std.Io.Clock.real.now(io),
            .rng = rng,
        }) catch return error.TlsHandshakeFailed;

        self.tls_rdbuf = undefined;
        self.tls_wrbuf = undefined;
        self.cleartext_reader = self.tls_conn.reader(&self.tls_rdbuf);
        self.cleartext_writer = self.tls_conn.writer(&self.tls_wrbuf);
        self.closed = false;

        return self;
    }

    pub fn reader(self: *TlsClient) *std.Io.Reader {
        return &self.cleartext_reader.interface;
    }

    pub fn writer(self: *TlsClient) *std.Io.Writer {
        return &self.cleartext_writer.interface;
    }

    pub fn close(self: *TlsClient) void {
        if (self.closed) return;
        self.closed = true;
        // A peer that stopped reading must not make close_notify block
        // teardown forever. Shutting the transport first wakes any pending
        // TLS I/O; close() below then performs best-effort TLS cleanup.
        self.stream.shutdown(self.io, .both) catch {};
        self.tls_conn.close() catch {};
        self.stream.close(self.io);
        zeroizeTrafficKeys(&self.tls_conn.cipher);
    }

    pub fn deinit(self: *TlsClient) void {
        self.close();
        self.allocator.destroy(self);
    }
};

/// A TLS server connection wrapping a TCP stream.
pub const TlsServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,

    enc_rdbuf: [tls.input_buffer_len]u8,
    enc_wrbuf: [tls.output_buffer_len]u8,
    enc_reader: std.Io.net.Stream.Reader,
    enc_writer: std.Io.net.Stream.Writer,

    tls_conn: tls.Connection,

    tls_rdbuf: [17000]u8,
    tls_wrbuf: [17000]u8,
    cleartext_reader: @TypeOf((@as(*tls.Connection, undefined)).reader(@as([]u8, undefined))),
    cleartext_writer: @TypeOf((@as(*tls.Connection, undefined)).writer(@as([]u8, undefined))),
    closed: bool,

    /// Upgrade a TCP stream to TLS (server side).
    /// `cert_path` and `key_path` are PEM files for the server certificate.
    pub fn accept(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: std.Io.net.Stream,
        cert_path: []const u8,
        key_path: []const u8,
    ) !*TlsServer {
        const self = try allocator.create(TlsServer);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.io = io;
        self.stream = stream;

        self.enc_rdbuf = undefined;
        self.enc_wrbuf = undefined;
        self.enc_reader = self.stream.reader(self.io, &self.enc_rdbuf);
        self.enc_writer = self.stream.writer(self.io, &self.enc_wrbuf);

        var rng_impl: std.Random.IoSource = .{ .io = io };
        const rng = rng_impl.interface();

        const cwd = std.Io.Dir.cwd();
        // `&auth` is stack-local but only passed into the synchronous tls.server()
        // handshake; tls.zig copies cert material during handshake and does not
        // retain the pointer on the returned Connection (verified L-15 / false positive).
        var auth = try tls.config.CertKeyPair.fromFilePath(allocator, io, cwd, cert_path, key_path);
        defer auth.deinit(allocator);

        self.tls_conn = tls.server(&self.enc_reader.interface, &self.enc_writer.interface, .{
            .auth = &auth,
            .now = std.Io.Clock.real.now(io),
            .rng = rng,
        }) catch return error.TlsHandshakeFailed;

        self.tls_rdbuf = undefined;
        self.tls_wrbuf = undefined;
        self.cleartext_reader = self.tls_conn.reader(&self.tls_rdbuf);
        self.cleartext_writer = self.tls_conn.writer(&self.tls_wrbuf);
        self.closed = false;

        return self;
    }

    pub fn reader(self: *TlsServer) *std.Io.Reader {
        return &self.cleartext_reader.interface;
    }

    pub fn writer(self: *TlsServer) *std.Io.Writer {
        return &self.cleartext_writer.interface;
    }

    pub fn close(self: *TlsServer) void {
        if (self.closed) return;
        self.closed = true;
        self.stream.shutdown(self.io, .both) catch {};
        self.tls_conn.close() catch {};
        self.stream.close(self.io);
        zeroizeTrafficKeys(&self.tls_conn.cipher);
    }

    pub fn deinit(self: *TlsServer) void {
        self.close();
        self.allocator.destroy(self);
    }
};

test "traffic cipher zeroization scrubs active storage idempotently" {
    var cipher: tls.Cipher = @unionInit(tls.Cipher, "AES_128_GCM_SHA256", undefined);
    const storage = activeCipherStorage(&cipher);
    @memset(storage, 0xa5);

    zeroizeTrafficKeys(&cipher);
    for (storage) |byte| try std.testing.expectEqual(@as(u8, 0), byte);

    zeroizeTrafficKeys(&cipher);
    for (storage) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}
