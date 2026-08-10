//! Minimal X.509 / PKCS#10 / SEC1 DER builders for the relay ACME lane.
//!
//! The ACME TLS-ALPN-01 flow needs three artifacts the std library does not
//! build: a self-signed challenge certificate carrying the critical
//! id-pe-acmeIdentifier extension (RFC 8737 §3), a PKCS#10 CSR whose SAN list
//! covers every ordered hostname (RFC 8555 §7.4), and a SEC1 "EC PRIVATE KEY"
//! PEM so generated P-256 keys persist in the format `tls.zig` parses back.
//!
//! Everything here is ECDSA P-256 / SHA-256 only — the one key type the ACME
//! client generates. DER is encoded with a tiny length-backpatching writer;
//! decoding for validity checks uses `std.crypto.Certificate.der`.

const std = @import("std");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const der = std.crypto.Certificate.der;

pub const Error = error{InvalidEncoding} || std.mem.Allocator.Error;

// OID content bytes (DER value octets, tag/length excluded).
const oid_ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 }; // 1.2.840.10045.4.3.2
const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 }; // 1.2.840.10045.2.1
const oid_prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 }; // 1.2.840.10045.3.1.7
const oid_common_name = [_]u8{ 0x55, 0x04, 0x03 }; // id-at-commonName
const oid_subject_alt_name = [_]u8{ 0x55, 0x1D, 0x11 }; // id-ce-subjectAltName
const oid_basic_constraints = [_]u8{ 0x55, 0x1D, 0x13 }; // id-ce-basicConstraints
const oid_key_usage = [_]u8{ 0x55, 0x1D, 0x0F }; // id-ce-keyUsage
const oid_ext_key_usage = [_]u8{ 0x55, 0x1D, 0x25 }; // id-ce-extKeyUsage
const oid_eku_server_auth = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 }; // 1.3.6.1.5.5.7.3.1
const oid_acme_identifier = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1F }; // 1.3.6.1.5.5.7.1.31 (id-pe-acmeIdentifier)
const oid_extension_request = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E }; // 1.2.840.113549.1.9.14

/// DER encoder over an ArrayList. Compound elements (SEQUENCE, tags) are
/// built by appending a placeholder header and backpatching the length once
/// the content is complete (`start`/`end`).
pub const DerWriter = struct {
    buf: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) DerWriter {
        return .{ .allocator = allocator };
    }

    pub fn deinit(w: *DerWriter) void {
        w.buf.deinit(w.allocator);
    }

    pub fn bytes(w: *const DerWriter) []const u8 {
        return w.buf.items;
    }

    pub fn toOwnedSlice(w: *DerWriter) Error![]u8 {
        return w.buf.toOwnedSlice(w.allocator);
    }

    /// Marks the start of a TLV whose length is not yet known. Returns an
    /// opaque position for `end`.
    pub fn start(w: *DerWriter, tag: u8) Error!usize {
        try w.buf.append(w.allocator, tag);
        // Reserve the long-form slot; `end` shrinks to short form when possible.
        const pos = w.buf.items.len;
        try w.buf.append(w.allocator, 0x82); // placeholder: two-octet length
        try w.buf.appendSlice(w.allocator, &[_]u8{ 0, 0 });
        return pos;
    }

    /// Backpatches the length of a TLV opened with `start`.
    pub fn end(w: *DerWriter, pos: usize) Error!void {
        const content_len = w.buf.items.len - (pos + 3);
        std.debug.assert(w.buf.items[pos] == 0x82);
        if (content_len < 128) {
            // Collapse the 3-octet placeholder to a single short-form length.
            w.buf.items[pos] = @intCast(content_len);
            _ = w.buf.orderedRemove(pos + 1);
            _ = w.buf.orderedRemove(pos + 1);
        } else if (content_len < 256) {
            w.buf.items[pos] = 0x81;
            w.buf.items[pos + 1] = @intCast(content_len);
            _ = w.buf.orderedRemove(pos + 2);
        } else {
            std.debug.assert(content_len < 65536);
            w.buf.items[pos + 1] = @intCast(content_len >> 8);
            w.buf.items[pos + 2] = @intCast(content_len & 0xff);
        }
    }

    /// Writes a complete TLV from pre-encoded content.
    pub fn tlv(w: *DerWriter, tag: u8, content: []const u8) Error!void {
        const pos = try w.start(tag);
        try w.buf.appendSlice(w.allocator, content);
        try w.end(pos);
    }

    pub fn sequence(w: *DerWriter, content: []const u8) Error!void {
        try w.tlv(0x30, content);
    }

    pub fn oid(w: *DerWriter, content: []const u8) Error!void {
        try w.tlv(0x06, content);
    }

    /// DER INTEGER: two's-complement, minimal, positive (leading 0x00 when the
    /// high bit would otherwise read as negative).
    pub fn integer(w: *DerWriter, value: []const u8) Error!void {
        var v = value;
        while (v.len > 1 and v[0] == 0) v = v[1..];
        if (v.len == 0) v = "\x00";
        const pos = try w.start(0x02);
        if (v[0] & 0x80 != 0) try w.buf.append(w.allocator, 0);
        try w.buf.appendSlice(w.allocator, v);
        try w.end(pos);
    }

    pub fn octetString(w: *DerWriter, value: []const u8) Error!void {
        try w.tlv(0x04, value);
    }

    /// BIT STRING with zero unused bits.
    pub fn bitString(w: *DerWriter, value: []const u8) Error!void {
        const pos = try w.start(0x03);
        try w.buf.append(w.allocator, 0);
        try w.buf.appendSlice(w.allocator, value);
        try w.end(pos);
    }

    pub fn utf8String(w: *DerWriter, value: []const u8) Error!void {
        try w.tlv(0x0C, value);
    }

    pub fn booleanTrue(w: *DerWriter) Error!void {
        try w.tlv(0x01, "\xff");
    }

    pub fn utcTime(w: *DerWriter, value: []const u8) Error!void {
        try w.tlv(0x17, value); // "YYMMDDHHMMSSZ"
    }

    pub fn generalizedTime(w: *DerWriter, value: []const u8) Error!void {
        try w.tlv(0x18, value); // "YYYYMMDDHHMMSSZ"
    }

    /// Context-specific constructed tag n (e.g. [0], [3]).
    pub fn explicit(w: *DerWriter, n: u8, content: []const u8) Error!void {
        std.debug.assert(n < 31);
        try w.tlv(0xa0 + n, content);
    }

    /// Context-specific primitive tag n — used for SAN dNSName ([2] IA5String).
    pub fn contextPrimitive(w: *DerWriter, n: u8, content: []const u8) Error!void {
        std.debug.assert(n < 31);
        try w.tlv(0x80 + n, content);
    }
};

/// Seconds since the Unix epoch → "YYMMDDHHMMSSZ" (UTCTime, years 1950–2049)
/// or "YYYYMMDDHHMMSSZ" (GeneralizedTime). Callers pick the writer.
pub const Civil = struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
};

/// Howard Hinnant's days-from-civil, inverted (civil-from-days).
pub fn civilFromEpochSeconds(secs_in: i64) Civil {
    const days_floor = @divFloor(secs_in, 86400);
    const rem = @mod(secs_in, 86400);
    const z = days_floor + 719468;
    const era = @divFloor(z, 146097);
    const doe: u64 = @intCast(z - era * 146097);
    const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y_i: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp = (5 * doy + 2) / 153;
    const d: u8 = @intCast(doy - (153 * mp + 2) / 5 + 1);
    const m: u8 = @intCast(if (mp < 10) mp + 3 else mp - 9);
    const year: u16 = @intCast(if (m <= 2) y_i + 1 else y_i);
    return .{
        .year = year,
        .month = m,
        .day = d,
        .hour = @intCast(@divFloor(rem, 3600)),
        .minute = @intCast(@mod(@divFloor(rem, 60), 60)),
        .second = @intCast(@mod(rem, 60)),
    };
}

pub fn formatUtcTime(c: Civil, out: *[13]u8) []const u8 {
    std.debug.assert(c.year >= 1950 and c.year <= 2049);
    const yy = c.year % 100;
    return std.fmt.bufPrint(out, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{ yy, c.month, c.day, c.hour, c.minute, c.second }) catch unreachable;
}

/// days-from-civil (Howard Hinnant) — civil date → days since 1970-01-01.
fn daysFromCivil(year: i64, month: i64, day: i64) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp = @mod(month + 9, 12);
    const doy = @divTrunc(153 * mp + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// UTCTime / GeneralizedTime content → epoch seconds (Zulu suffix required).
pub fn epochFromAsn1Time(content: []const u8) error{InvalidEncoding}!i64 {
    if (content.len != 13 and content.len != 15) return error.InvalidEncoding;
    if (content[content.len - 1] != 'Z') return error.InvalidEncoding;
    const digits = content[0 .. content.len - 1];
    for (digits) |ch| if (!std.ascii.isDigit(ch)) return error.InvalidEncoding;
    var year: i64 = undefined;
    var off: usize = 0;
    if (digits.len == 12) {
        const yy = std.fmt.parseInt(i64, digits[0..2], 10) catch return error.InvalidEncoding;
        year = if (yy < 50) 2000 + yy else 1900 + yy;
        off = 2;
    } else {
        year = std.fmt.parseInt(i64, digits[0..4], 10) catch return error.InvalidEncoding;
        off = 4;
    }
    const month = std.fmt.parseInt(i64, digits[off .. off + 2], 10) catch return error.InvalidEncoding;
    const day = std.fmt.parseInt(i64, digits[off + 2 .. off + 4], 10) catch return error.InvalidEncoding;
    const hour = std.fmt.parseInt(i64, digits[off + 4 .. off + 6], 10) catch return error.InvalidEncoding;
    const minute = std.fmt.parseInt(i64, digits[off + 6 .. off + 8], 10) catch return error.InvalidEncoding;
    const second = std.fmt.parseInt(i64, digits[off + 8 .. off + 10], 10) catch return error.InvalidEncoding;
    if (month < 1 or month > 12 or day < 1 or day > 31 or hour > 23 or minute > 59 or second > 60)
        return error.InvalidEncoding;
    const days = daysFromCivil(year, month, day);
    return days * 86400 + hour * 3600 + minute * 60 + second;
}

fn algorithmIdentifierEcdsaSha256(w: *DerWriter) Error!void {
    const pos = try w.start(0x30);
    try w.oid(&oid_ecdsa_sha256);
    try w.end(pos);
}

/// Name ::= SEQUENCE { SET { SEQUENCE { OID commonName, UTF8String h } } }.
fn distinguishedNameCn(w: *DerWriter, hostname: []const u8) Error!void {
    const name_pos = try w.start(0x30);
    const set_pos = try w.start(0x31);
    const atv_pos = try w.start(0x30);
    try w.oid(&oid_common_name);
    try w.utf8String(hostname);
    try w.end(atv_pos);
    try w.end(set_pos);
    try w.end(name_pos);
}

/// SubjectPublicKeyInfo for an uncompressed P-256 point.
fn subjectPublicKeyInfo(w: *DerWriter, public_sec1: *const [65]u8) Error!void {
    const spki_pos = try w.start(0x30);
    const alg_pos = try w.start(0x30);
    try w.oid(&oid_ec_public_key);
    try w.oid(&oid_prime256v1);
    try w.end(alg_pos);
    try w.bitString(public_sec1);
    try w.end(spki_pos);
}

/// Extension ::= SEQUENCE { OID subjectAltName, OCTET STRING GeneralNames }.
fn sanExtension(w: *DerWriter, hostnames: []const []const u8) Error!void {
    // GeneralNames ::= SEQUENCE OF GeneralName; dNSName is [2] IA5String.
    var names = DerWriter.init(w.allocator);
    defer names.deinit();
    for (hostnames) |h| try names.contextPrimitive(2, h);
    var san = DerWriter.init(w.allocator);
    defer san.deinit();
    try san.sequence(names.bytes());

    const ext_pos = try w.start(0x30);
    try w.oid(&oid_subject_alt_name);
    try w.octetString(san.bytes());
    try w.end(ext_pos);
}

fn ecdsaSignDer(key_pair: Ecdsa.KeyPair, message: []const u8, w: *DerWriter) Error!void {
    const sig = key_pair.sign(message, null) catch return error.InvalidEncoding;
    const raw = sig.toBytes(); // r || s, 32 bytes each
    const pos = try w.start(0x30);
    try w.integer(raw[0..32]);
    try w.integer(raw[32..64]);
    try w.end(pos);
}

/// RFC 8737 §3 self-signed challenge certificate (DER). `digest` is the
/// SHA-256 of the ACME key authorization; it lands in the CRITICAL
/// id-pe-acmeIdentifier extension. SAN contains exactly `hostname`.
pub fn buildChallengeCert(
    allocator: std.mem.Allocator,
    hostname: []const u8,
    key_authorization_digest: *const [Sha256.digest_length]u8,
    key_pair: Ecdsa.KeyPair,
    now_epoch_secs: i64,
) Error![]u8 {
    var tbs = DerWriter.init(allocator);
    defer tbs.deinit();
    const public = key_pair.public_key.toUncompressedSec1();

    const tbs_pos = try tbs.start(0x30);
    {
        // version [0] EXPLICIT INTEGER 2 (v3)
        var ver = DerWriter.init(allocator);
        defer ver.deinit();
        try ver.integer("\x02");
        try tbs.explicit(0, ver.bytes());

        // serial: 16 random-ish bytes derived from the digest + time; only
        // uniqueness within this CA-less self-signed use matters.
        var serial: [16]u8 = undefined;
        var h = Sha256.init(.{});
        h.update(key_authorization_digest);
        h.update(hostname);
        var time_bytes: [8]u8 = undefined;
        std.mem.writeInt(i64, &time_bytes, now_epoch_secs, .big);
        h.update(&time_bytes);
        const digest_full = h.finalResult();
        @memcpy(&serial, digest_full[0..16]);
        serial[0] &= 0x7f; // keep the INTEGER positive
        try tbs.integer(&serial);

        try algorithmIdentifierEcdsaSha256(&tbs);
        try distinguishedNameCn(&tbs, hostname);

        // validity: notBefore = now - 1h (clock skew), notAfter = now + 7d.
        var validity = DerWriter.init(allocator);
        defer validity.deinit();
        var time_buf: [13]u8 = undefined;
        try validity.utcTime(formatUtcTime(civilFromEpochSeconds(now_epoch_secs - 3600), &time_buf));
        try validity.utcTime(formatUtcTime(civilFromEpochSeconds(now_epoch_secs + 7 * 86400), &time_buf));
        try tbs.sequence(validity.bytes());

        try distinguishedNameCn(&tbs, hostname);
        try subjectPublicKeyInfo(&tbs, &public);

        // extensions [3] EXPLICIT SEQUENCE OF Extension
        var exts = DerWriter.init(allocator);
        defer exts.deinit();
        // basicConstraints (critical, CA:FALSE) — keeps strict validators
        // from treating the self-signed challenge cert as a CA.
        {
            var bc_content = DerWriter.init(allocator);
            defer bc_content.deinit();
            try bc_content.sequence("");
            const ext_pos = try exts.start(0x30);
            try exts.oid(&oid_basic_constraints);
            try exts.booleanTrue();
            try exts.octetString(bc_content.bytes());
            try exts.end(ext_pos);
        }
        // keyUsage (critical, digitalSignature)
        {
            var ku_content = DerWriter.init(allocator);
            defer ku_content.deinit();
            try ku_content.bitString("\x80"); // bit 0 = digitalSignature
            const ext_pos = try exts.start(0x30);
            try exts.oid(&oid_key_usage);
            try exts.booleanTrue();
            try exts.octetString(ku_content.bytes());
            try exts.end(ext_pos);
        }
        // subjectAltName: exactly the validated dNSName.
        try sanExtension(&exts, &.{hostname});
        // acmeIdentifier (CRITICAL): extnValue wraps DER OCTET STRING(digest).
        {
            var acme_value = DerWriter.init(allocator);
            defer acme_value.deinit();
            try acme_value.octetString(key_authorization_digest);
            const ext_pos = try exts.start(0x30);
            try exts.oid(&oid_acme_identifier);
            try exts.booleanTrue();
            try exts.octetString(acme_value.bytes());
            try exts.end(ext_pos);
        }
        // extensions [3] EXPLICIT Extensions ::= SEQUENCE OF Extension — the
        // [3] wraps the whole Extensions SEQUENCE, not bare children.
        var ext_seq = DerWriter.init(allocator);
        defer ext_seq.deinit();
        try ext_seq.sequence(exts.bytes());
        try tbs.explicit(3, ext_seq.bytes());
    }
    try tbs.end(tbs_pos);

    var cert = DerWriter.init(allocator);
    defer cert.deinit();
    const cert_pos = try cert.start(0x30);
    try cert.buf.appendSlice(allocator, tbs.bytes());
    try algorithmIdentifierEcdsaSha256(&cert);

    var sig = DerWriter.init(allocator);
    defer sig.deinit();
    try ecdsaSignDer(key_pair, tbs.bytes(), &sig);
    try cert.bitString(sig.bytes());
    try cert.end(cert_pos);

    return cert.toOwnedSlice();
}

/// PKCS#10 CSR (DER) with a SAN extensionRequest covering `hostnames`,
/// signed by `key_pair`. Subject CN is the first hostname.
pub fn buildCsr(
    allocator: std.mem.Allocator,
    hostnames: []const []const u8,
    key_pair: Ecdsa.KeyPair,
) Error![]u8 {
    std.debug.assert(hostnames.len > 0);
    const public = key_pair.public_key.toUncompressedSec1();

    var cri = DerWriter.init(allocator);
    defer cri.deinit();
    const cri_pos = try cri.start(0x30);
    try cri.integer("\x00"); // version v1
    try distinguishedNameCn(&cri, hostnames[0]);
    try subjectPublicKeyInfo(&cri, &public);
    {
        // attributes [0] IMPLICIT SET OF Attribute — the [0] tag replaces the
        // SET tag, so its content is the Attribute SEQUENCE(s) directly.
        var exts = DerWriter.init(allocator);
        defer exts.deinit();
        try sanExtension(&exts, hostnames);
        var ext_seq = DerWriter.init(allocator);
        defer ext_seq.deinit();
        try ext_seq.sequence(exts.bytes());

        var attr = DerWriter.init(allocator);
        defer attr.deinit();
        const attr_pos = try attr.start(0x30);
        try attr.oid(&oid_extension_request);
        try attr.tlv(0x31, ext_seq.bytes()); // SET OF { Extensions }
        try attr.end(attr_pos);

        try cri.explicit(0, attr.bytes());
    }
    try cri.end(cri_pos);

    var csr = DerWriter.init(allocator);
    defer csr.deinit();
    const csr_pos = try csr.start(0x30);
    try csr.buf.appendSlice(allocator, cri.bytes());
    try algorithmIdentifierEcdsaSha256(&csr);
    var sig = DerWriter.init(allocator);
    defer sig.deinit();
    try ecdsaSignDer(key_pair, cri.bytes(), &sig);
    try csr.bitString(sig.bytes());
    try csr.end(csr_pos);

    return csr.toOwnedSlice();
}

/// SEC1 (RFC 5915) "EC PRIVATE KEY" PEM for a P-256 key pair — the exact
/// shape `tls.zig` `PrivateKey.parseEcDer` reads back.
pub fn ecPrivateKeyPem(allocator: std.mem.Allocator, key_pair: Ecdsa.KeyPair) Error![]u8 {
    var w = DerWriter.init(allocator);
    defer w.deinit();
    const pos = try w.start(0x30);
    try w.integer("\x01");
    const secret = key_pair.secret_key.toBytes();
    try w.octetString(&secret);
    {
        var params = DerWriter.init(allocator);
        defer params.deinit();
        try params.oid(&oid_prime256v1);
        try w.explicit(0, params.bytes());
    }
    {
        const public = key_pair.public_key.toUncompressedSec1();
        var pubw = DerWriter.init(allocator);
        defer pubw.deinit();
        try pubw.bitString(&public);
        try w.explicit(1, pubw.bytes());
    }
    try w.end(pos);
    return pemEncode(allocator, "EC PRIVATE KEY", w.bytes());
}

/// PEM armor with 64-column base64 lines.
pub fn pemEncode(allocator: std.mem.Allocator, label: []const u8, der_bytes: []const u8) Error![]u8 {
    const enc = std.base64.standard.Encoder;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "-----BEGIN ");
    try out.appendSlice(allocator, label);
    try out.appendSlice(allocator, "-----\n");
    var i: usize = 0;
    while (i < der_bytes.len) {
        const n = @min(48, der_bytes.len - i); // 48 bytes → 64 base64 chars
        var line: [64]u8 = undefined;
        const encoded = enc.encode(line[0..enc.calcSize(n)], der_bytes[i .. i + n]);
        try out.appendSlice(allocator, encoded);
        try out.append(allocator, '\n');
        i += n;
    }
    try out.appendSlice(allocator, "-----END ");
    try out.appendSlice(allocator, label);
    try out.appendSlice(allocator, "-----\n");
    return out.toOwnedSlice(allocator);
}

/// Extracts the leaf certificate's notAfter (epoch seconds) from a DER
/// certificate. Walks: Certificate → tbsCertificate → [0] version, serial,
/// signature, issuer, validity{notBefore, notAfter}.
pub fn notAfterFromCertDer(cert_der: []const u8) error{InvalidEncoding}!i64 {
    const cert = der.Element.parse(cert_der, 0) catch return error.InvalidEncoding;
    const tbs = der.Element.parse(cert_der, cert.slice.start) catch return error.InvalidEncoding;
    var idx = tbs.slice.start;
    // [0] version
    var el = der.Element.parse(cert_der, idx) catch return error.InvalidEncoding;
    const id = el.identifier;
    if (id.class != .context_specific or id.pc != .constructed or id.tag != @as(der.Tag, @enumFromInt(0)))
        return error.InvalidEncoding;
    idx = el.slice.end;
    // serial, signature, issuer
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        el = der.Element.parse(cert_der, idx) catch return error.InvalidEncoding;
        idx = el.slice.end;
    }
    // validity
    const validity = der.Element.parse(cert_der, idx) catch return error.InvalidEncoding;
    const not_before = der.Element.parse(cert_der, validity.slice.start) catch return error.InvalidEncoding;
    const not_after = der.Element.parse(cert_der, not_before.slice.end) catch return error.InvalidEncoding;
    return epochFromAsn1Time(cert_der[not_after.slice.start..not_after.slice.end]);
}

/// First DER certificate block inside a PEM chain (base64-decoded).
pub fn firstCertDerFromPem(allocator: std.mem.Allocator, pem: []const u8) Error![]u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end_m = "-----END CERTIFICATE-----";
    const s = std.mem.indexOf(u8, pem, begin) orelse return error.InvalidEncoding;
    const body_start = s + begin.len;
    const e = std.mem.indexOfPos(u8, pem, body_start, end_m) orelse return error.InvalidEncoding;
    const b64 = std.mem.trim(u8, pem[body_start..e], " \t\r\n");
    // Interior line breaks are part of PEM armor, not the base64 stream.
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const out = try allocator.alloc(u8, decoder.calcSizeUpperBound(b64.len));
    errdefer allocator.free(out);
    const n = decoder.decode(out, b64) catch return error.InvalidEncoding;
    return out[0..n];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "DerWriter short and long form lengths" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var w = DerWriter.init(a);
    const pos = try w.start(0x30);
    try w.integer("\x01");
    try w.end(pos);
    // SEQ len 3: 30 03 02 01 01
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 }, w.bytes());

    var w2 = DerWriter.init(a);
    const pos2 = try w2.start(0x30);
    try w2.buf.appendSlice(a, &[_]u8{0xaa} ** 200);
    try w2.end(pos2);
    try std.testing.expectEqual(@as(u8, 0x30), w2.bytes()[0]);
    try std.testing.expectEqual(@as(u8, 0x81), w2.bytes()[1]);
    try std.testing.expectEqual(@as(u8, 200), w2.bytes()[2]);
    try std.testing.expectEqual(@as(usize, 203), w2.bytes().len);
}

test "epoch time conversion round trips through civil" {
    const cases = [_]i64{ 0, 951782400, 1735689600, 1767225600, 4102444800 };
    for (cases) |secs| {
        const c = civilFromEpochSeconds(secs);
        var buf: [15]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{ c.year, c.month, c.day, c.hour, c.minute, c.second }) catch unreachable;
        try std.testing.expectEqual(secs, try epochFromAsn1Time(text));
    }
    try std.testing.expectEqual(@as(i64, 951782400), try epochFromAsn1Time("000229000000Z")); // UTCTime 2000
    try std.testing.expectError(error.InvalidEncoding, epochFromAsn1Time("000229000000"));
}

test "challenge cert parses, is self-signed-valid, carries critical acmeIdentifier" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [Ecdsa.KeyPair.seed_length]u8 = @splat(7);
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(seed);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash("token.thumbprint", &digest, .{});

    const cert_der = try buildChallengeCert(a, "relay-a.localhost", &digest, key_pair, 1_754_000_000);

    // Structural walk: Certificate{ tbs, alg, sig }.
    const cert = try der.Element.parse(cert_der, 0);
    const tbs = try der.Element.parse(cert_der, cert.slice.start);
    const alg_el = try der.Element.parse(cert_der, tbs.slice.end);
    const sig_el = try der.Element.parse(cert_der, alg_el.slice.end);
    try std.testing.expectEqual(der.Tag.bitstring, sig_el.identifier.tag);

    // Signature verifies over the TBS bytes with the same key.
    const tbs_full = cert_der[cert.slice.start..tbs.slice.end];
    const sig_content = cert_der[sig_el.slice.start..sig_el.slice.end];
    const sig_der = sig_content[1..]; // skip unused-bits octet
    const signature = try Ecdsa.Signature.fromDer(sig_der);
    try signature.verify(tbs_full, key_pair.public_key);

    // The critical acmeIdentifier extension carries the digest, wrapped in an
    // inner OCTET STRING per RFC 8737.
    const oid_needle = [_]u8{ 0x06, 0x08 } ++ oid_acme_identifier;
    const oid_pos = std.mem.indexOf(u8, cert_der, &oid_needle).?;
    // after OID: BOOLEAN TRUE (01 01 FF), OCTET STRING len, inner OCTET STRING
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x01, 0xff, 0x04, 34, 0x04, 32 }, cert_der[oid_pos + oid_needle.len ..][0..7]);
    try std.testing.expectEqualSlices(u8, &digest, cert_der[oid_pos + oid_needle.len + 7 ..][0..32]);

    // SAN [2] dNSName with the hostname is present (tag 0x82 + length + name).
    // The hostname also appears as issuer/subject CN, so anchor the search
    // after the subjectAltName OID.
    const san_oid_needle = [_]u8{ 0x06, 0x03 } ++ oid_subject_alt_name;
    const san_oid_pos = std.mem.indexOf(u8, cert_der, &san_oid_needle).?;
    const host_pos = std.mem.indexOfPos(u8, cert_der, san_oid_pos, "relay-a.localhost").?;
    try std.testing.expectEqual(@as(u8, 0x82), cert_der[host_pos - 2]);
    try std.testing.expectEqual(@as(u8, @intCast("relay-a.localhost".len)), cert_der[host_pos - 1]);

    // Parses as a std Bundle certificate and notAfter is ~7 days out.
    try std.testing.expectEqual(@as(i64, 1_754_000_000 + 7 * 86400), try notAfterFromCertDer(cert_der));

    const full = std.crypto.Certificate.parse(.{ .buffer = cert_der, .index = 0 }) catch |err| {
        std.debug.print("std full parse error: {}\n", .{err});
        return err;
    };
    _ = full;
}

test "csr covers all hostnames and verifies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [Ecdsa.KeyPair.seed_length]u8 = @splat(9);
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(seed);
    const hosts = [_][]const u8{ "relay-a.localhost", "relay-b.localhost" };
    const csr_der = try buildCsr(a, &hosts, key_pair);

    // Signature verifies over CertificationRequestInfo.
    const csr = try der.Element.parse(csr_der, 0);
    const cri = try der.Element.parse(csr_der, csr.slice.start);
    const cri_full = csr_der[csr.slice.start..cri.slice.end];
    const alg_el = try der.Element.parse(csr_der, cri.slice.end);
    const sig_el = try der.Element.parse(csr_der, alg_el.slice.end);
    const sig_content = csr_der[sig_el.slice.start..sig_el.slice.end];
    const signature = try Ecdsa.Signature.fromDer(sig_content[1..]);
    try signature.verify(cri_full, key_pair.public_key);

    for (hosts) |h| try std.testing.expect(std.mem.indexOf(u8, csr_der, h) != null);
    // extensionRequest OID present
    try std.testing.expect(std.mem.indexOf(u8, csr_der, &oid_extension_request) != null);
}

test "ec private key pem round trips through tls-style SEC1 shape" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const seed: [Ecdsa.KeyPair.seed_length]u8 = @splat(5);
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(seed);
    const pem = try ecPrivateKeyPem(a, key_pair);
    try std.testing.expect(std.mem.startsWith(u8, pem, "-----BEGIN EC PRIVATE KEY-----\n"));

    // Decode and walk the SEC1 structure the way PrivateKey.parseEcDer does:
    // SEQUENCE { INTEGER 1, OCTET STRING secret, [0] { OID prime256v1 } }.
    const begin = "-----BEGIN EC PRIVATE KEY-----";
    const s = std.mem.indexOf(u8, pem, begin).? + begin.len;
    const e = std.mem.indexOf(u8, pem, "-----END EC PRIVATE KEY-----").?;
    const b64 = std.mem.trim(u8, pem[s..e], " \t\r\n");
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const sec1 = try a.alloc(u8, decoder.calcSizeUpperBound(b64.len));
    const n = try decoder.decode(sec1, b64);
    const sec1_bytes = sec1[0..n];

    const seq = try der.Element.parse(sec1_bytes, 0);
    const version = try der.Element.parse(sec1_bytes, seq.slice.start);
    const key_el = try der.Element.parse(sec1_bytes, version.slice.end);
    const params = try der.Element.parse(sec1_bytes, key_el.slice.end);
    const curve = try der.Element.parse(sec1_bytes, params.slice.start);
    try std.testing.expectEqualSlices(u8, &oid_prime256v1, sec1_bytes[curve.slice.start..curve.slice.end]);

    const secret_bytes = sec1_bytes[key_el.slice.start..key_el.slice.end];
    const secret_key = try Ecdsa.SecretKey.fromBytes(secret_bytes[0..32].*);
    const round_tripped = try Ecdsa.KeyPair.fromSecretKey(secret_key);
    try std.testing.expectEqualSlices(u8, &key_pair.public_key.toUncompressedSec1(), &round_tripped.public_key.toUncompressedSec1());
}

test "notAfter parses a real-ish leaf from a pem chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const key_pair = try Ecdsa.KeyPair.generateDeterministic(@splat(11));
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash("x", &digest, .{});
    const cert_der = try buildChallengeCert(a, "h.example", &digest, key_pair, 1_754_000_000);
    const pem = try pemEncode(a, "CERTIFICATE", cert_der);
    const leaf = try firstCertDerFromPem(a, pem);
    try std.testing.expectEqualSlices(u8, cert_der, leaf);
    try std.testing.expectEqual(@as(i64, 1_754_000_000 + 7 * 86400), try notAfterFromCertDer(leaf));
}
