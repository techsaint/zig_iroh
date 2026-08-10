//! GENERATED FILE — do not edit by hand.
//! Source of truth: vectors/iroh-base/fixtures.json (tools/iroh_base_probe,
//! pinned iroh-base path dep) and
//! vectors/iroh-base/endpoint-addr-fixtures.json
//! (tools/addr_ticket_fixture_gen `generate`).
//! Regenerate: python3 tools/addr_ticket_fixture_gen/json_to_zig.py

pub const PubkeyValidationCase = struct {
    name: []const u8,
    hex: []const u8,
    accepted: bool,
};
pub const pubkey_validation: []const PubkeyValidationCase = &.{
    .{ .name = "all_zero", .hex = "0000000000000000000000000000000000000000000000000000000000000000", .accepted = true },
    .{ .name = "all_ff", .hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", .accepted = true },
    .{ .name = "identity_y1_x0", .hex = "0100000000000000000000000000000000000000000000000000000000000000", .accepted = true },
    .{ .name = "y_equals_p", .hex = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", .accepted = true },
    .{ .name = "y_equals_p_plus_1", .hex = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", .accepted = true },
    .{ .name = "y_equals_2pow255_minus_1", .hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", .accepted = true },
    .{ .name = "valid_key", .hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737", .accepted = true },
    .{ .name = "no_square_root", .hex = "0200000000000000000000000000000000000000000000000000000000000000", .accepted = false },
};

pub const ParseClassCase = struct {
    name: []const u8,
    input: []const u8,
    secret: bool,
    /// parse = FromStr (hex/base32); from_z32 = the explicit z-base-32 path.
    via: enum { parse, from_z32 },
    /// null = parses; otherwise the Zig KeyError member for the iroh error class.
    expected: ?key.KeyError,
};
pub const parse_class: []const ParseClassCase = &.{
    .{ .name = "hex_lower_ok", .input = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737", .secret = false, .via = .parse, .expected = null },
    .{ .name = "hex_upper", .input = "D04AB232742BB4AB3A1368BD4615E4E6D0224AB71A016BAF8520A332C9778737", .secret = false, .via = .parse, .expected = error.InvalidHex },
    .{ .name = "hex_upper_secret", .input = "1111111111111111111111111111111111111111111111111111111111111111", .secret = true, .via = .parse, .expected = null },
    .{ .name = "hex_bad_alphabet_64", .input = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg", .secret = false, .via = .parse, .expected = error.InvalidHex },
    .{ .name = "hex_63_chars", .input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", .secret = false, .via = .parse, .expected = error.InvalidLength },
    .{ .name = "base32_upper_ok", .input = "2BFLEMTUFO2KWOQTNC6UMFPE43ICESVXDIAWXL4FECRTFSLXQ43Q", .secret = false, .via = .parse, .expected = null },
    .{ .name = "base32_lower_ok", .input = "2bflemtufo2kwoqtnc6umfpe43icesvxdiawxl4fecrtfslxq43q", .secret = false, .via = .parse, .expected = null },
    .{ .name = "base32_padded", .input = "2BFLEMTUFO2KWOQTNC6UMFPE43ICESVXDIAWXL4FECRTFSLXQ43Q=", .secret = false, .via = .parse, .expected = error.InvalidLength },
    .{ .name = "base32_51_chars", .input = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", .secret = false, .via = .parse, .expected = error.InvalidLength },
    .{ .name = "base32_53_chars", .input = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", .secret = false, .via = .parse, .expected = error.InvalidLength },
    .{ .name = "z32_via_fromstr", .input = "4bfmrcuwfq4ksqoupn6wcfxrh5enr1izdeyszmhfrntuf1mzoh5o", .secret = false, .via = .parse, .expected = error.InvalidBase32 },
    .{ .name = "garbage_short", .input = "foobarbaz", .secret = false, .via = .parse, .expected = error.InvalidLength },
    .{ .name = "hex_of_all_ff", .input = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", .secret = false, .via = .parse, .expected = null },
    .{ .name = "secret_hex_ok", .input = "1111111111111111111111111111111111111111111111111111111111111111", .secret = true, .via = .parse, .expected = null },
    .{ .name = "secret_base32_ok", .input = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIQ", .secret = true, .via = .parse, .expected = null },
    .{ .name = "base32_noncanonical_trailing_bits", .input = "2BFLEMTUFO2KWOQTNC6UMFPE43ICESVXDIAWXL4FECRTFSLXQ43R", .secret = false, .via = .parse, .expected = error.InvalidBase32 },
    .{ .name = "secret_base32_noncanonical_trailing_bits", .input = "CEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIR", .secret = true, .via = .parse, .expected = error.InvalidBase32 },
    .{ .name = "z32_noncanonical_trailing_bits", .input = "4bfmrcuwfq4ksqoupn6wcfxrh5enr1izdeyszmhfrntuf1mzoh5t", .secret = false, .via = .from_z32, .expected = error.InvalidBase32 },
};

pub const postcard = struct {
    pub const public_hex: []const u8 = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
    pub const public_json: []const u8 = "\"d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737\"";
    pub const public_postcard_hex: []const u8 = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
    pub const relay_url: []const u8 = "https://relay.example.com./";
    pub const relay_url_postcard_hex: []const u8 = "1b68747470733a2f2f72656c61792e6578616d706c652e636f6d2e2f";
    pub const secret_postcard_hex: []const u8 = "201111111111111111111111111111111111111111111111111111111111111111";
    pub const seed_hex: []const u8 = "1111111111111111111111111111111111111111111111111111111111111111";
    pub const signature_hex: []const u8 = "c7566ca8ad14c4c9d52a510463b0b86ebd25778214038a830d6a8621079a28eafeaa123ee7e016df995bc254c676fdd10151002b819680f237a3d442d12d5600";
    pub const signature_postcard_hex: []const u8 = "c7566ca8ad14c4c9d52a510463b0b86ebd25778214038a830d6a8621079a28eafeaa123ee7e016df995bc254c676fdd10151002b819680f237a3d442d12d5600";
};

pub const RelayUrlCase = struct {
    input: []const u8,
    ok: bool,
    canonical: []const u8 = "",
    domain: ?[]const u8 = null,
};
pub const relay_url: []const RelayUrlCase = &.{
    .{ .input = "https://example.com", .ok = true, .canonical = "https://example.com/", .domain = "example.com" },
    .{ .input = "https://example.com.", .ok = true, .canonical = "https://example.com./", .domain = "example.com." },
    .{ .input = "https://example.com./", .ok = true, .canonical = "https://example.com./", .domain = "example.com." },
    .{ .input = "https://example.com/", .ok = true, .canonical = "https://example.com/", .domain = "example.com" },
    .{ .input = "https://EXAMPLE.COM", .ok = true, .canonical = "https://example.com/", .domain = "example.com" },
    .{ .input = "HTTPS://example.com", .ok = true, .canonical = "https://example.com/", .domain = "example.com" },
    .{ .input = "https://example.com:443", .ok = true, .canonical = "https://example.com/", .domain = "example.com" },
    .{ .input = "https://example.com:443/path", .ok = true, .canonical = "https://example.com/path", .domain = "example.com" },
    .{ .input = "https://example.com:444", .ok = true, .canonical = "https://example.com:444/", .domain = "example.com" },
    .{ .input = "http://example.com:80", .ok = true, .canonical = "http://example.com/", .domain = "example.com" },
    .{ .input = "http://example.com:8080", .ok = true, .canonical = "http://example.com:8080/", .domain = "example.com" },
    .{ .input = "ws://example.com", .ok = true, .canonical = "ws://example.com/", .domain = "example.com" },
    .{ .input = "ws://example.com:80", .ok = true, .canonical = "ws://example.com/", .domain = "example.com" },
    .{ .input = "wss://example.com:443", .ok = true, .canonical = "wss://example.com/", .domain = "example.com" },
    .{ .input = "https://example.com?x=1", .ok = true, .canonical = "https://example.com/?x=1", .domain = "example.com" },
    .{ .input = "https://example.com/path", .ok = true, .canonical = "https://example.com/path", .domain = "example.com" },
    .{ .input = "https://example.com/path/", .ok = true, .canonical = "https://example.com/path/", .domain = "example.com" },
    .{ .input = "https://user@example.com", .ok = true, .canonical = "https://user@example.com/", .domain = "example.com" },
    .{ .input = "https://192.0.2.1:4443", .ok = true, .canonical = "https://192.0.2.1:4443/", .domain = null },
    .{ .input = "https://[2001:db8::1]:4443", .ok = true, .canonical = "https://[2001:db8::1]:4443/", .domain = null },
    .{ .input = "example.com", .ok = false },
    .{ .input = "https://", .ok = false },
    .{ .input = "https://exa mple.com", .ok = false },
    .{ .input = "https://example.com:abc", .ok = false },
    .{ .input = "https://example.com:99999", .ok = false },
    .{ .input = "ftp://example.com", .ok = true, .canonical = "ftp://example.com/", .domain = "example.com" },
    .{ .input = "https://example.com/%7Euser", .ok = true, .canonical = "https://example.com/%7Euser", .domain = "example.com" },
    .{ .input = "https://example.com/./a/../b", .ok = true, .canonical = "https://example.com/b", .domain = "example.com" },
};

pub const CustomAddrCase = struct {
    id: u64,
    data_hex: []const u8,
    display: []const u8,
    to_vec_hex: []const u8,
    postcard_hex: []const u8,
};
pub const custom_addr: []const CustomAddrCase = &.{
    .{ .id = 1, .data_hex = "a1b2c3d4e5f6", .display = "1_a1b2c3d4e5f6", .to_vec_hex = "0100000000000000a1b2c3d4e5f6", .postcard_hex = "010006a1b2c3d4e5f6000000000000000000000000000000000000000000000000" },
    .{ .id = 42, .data_hex = "abababababababababababababababababababababababababababababababab", .display = "2a_abababababababababababababababababababababababababababababababab", .to_vec_hex = "2a00000000000000abababababababababababababababababababababababababababababababab", .postcard_hex = "2a0120abababababababababababababababababababababababababababababababab" },
    .{ .id = 0, .data_hex = "", .display = "0_", .to_vec_hex = "0000000000000000", .postcard_hex = "000000000000000000000000000000000000000000000000000000000000000000" },
    .{ .id = 3735928559, .data_hex = "0102", .display = "deadbeef_0102", .to_vec_hex = "efbeadde000000000102", .postcard_hex = "effdb6f50d0002010200000000000000000000000000000000000000000000000000000000" },
    .{ .id = 30, .data_hex = "303030303030303030303030303030303030303030303030303030303030", .display = "1e_303030303030303030303030303030303030303030303030303030303030", .to_vec_hex = "1e00000000000000303030303030303030303030303030303030303030303030303030303030", .postcard_hex = "1e001e303030303030303030303030303030303030303030303030303030303030" },
    .{ .id = 31, .data_hex = "31313131313131313131313131313131313131313131313131313131313131", .display = "1f_31313131313131313131313131313131313131313131313131313131313131", .to_vec_hex = "1f0000000000000031313131313131313131313131313131313131313131313131313131313131", .postcard_hex = "1f011f31313131313131313131313131313131313131313131313131313131313131" },
    .{ .id = 7, .data_hex = "07070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707", .display = "7_07070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707", .to_vec_hex = "070000000000000007070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707", .postcard_hex = "07016407070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707" },
};
pub const CustomAddrParseCase = struct { input: []const u8, ok: bool };
pub const custom_addr_parse: []const CustomAddrParseCase = &.{
    .{ .input = "abc123", .ok = false },
    .{ .input = "xyz_0102", .ok = false },
    .{ .input = "1_ghij", .ok = false },
    .{ .input = "1_abc", .ok = false },
    .{ .input = "1_ABCD", .ok = false },
    .{ .input = "0x1_ab", .ok = false },
    .{ .input = "1_", .ok = true },
    .{ .input = "", .ok = false },
};

pub const signature_bytes_hex: []const u8 = "776f3ee93432ac2d24dadc3a034e7415ffc4e9c8f5cbee8a7d19a11529fa06bea6f59f7f6aec2e873fad285d55185c38625debce39b695420e777e46eb3fd107";
pub const signature_display: []const u8 = "776F3EE93432AC2D24DADC3A034E7415FFC4E9C8F5CBEE8A7D19A11529FA06BEA6F59F7F6AEC2E873FAD285D55185C38625DEBCE39B695420E777E46EB3FD107";
pub const SignatureLengthCase = struct { len: usize, ok: bool };
pub const signature_length: []const SignatureLengthCase = &.{
    .{ .len = 63, .ok = false },
    .{ .len = 64, .ok = true },
    .{ .len = 65, .ok = false },
};

pub const display = struct {
    pub const public_debug: []const u8 = "PublicKey(d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737)";
    pub const public_display: []const u8 = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
    pub const public_fmt_short: []const u8 = "d04ab23274";
    pub const secret_debug: []const u8 = "SecretKey(..)";
    pub const secret_debug_leaks_seed: bool = false;
};

pub const EndpointFixtureAddr = struct {
    kind: enum { relay, ip, custom },
    /// relay: url string; ip: "a.b.c.d:port" or "[v6]:port"; custom: data hex.
    value: []const u8,
    /// custom only.
    id: u64 = 0,
};
pub const EndpointFixture = struct {
    id: []const u8,
    endpoint_id_hex: []const u8,
    addrs: []const EndpointFixtureAddr,
    postcard_hex: []const u8,
    ticket_string: []const u8,
    ticket_bytes_hex: []const u8,
};
pub const endpoint_fixtures: []const EndpointFixture = &.{
    .{
        .id = "endpoint/relay", .endpoint_id_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        .addrs = &.{ .{ .kind = .relay, .value = "https://relay.example.com." } },
        .postcard_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701001b68747470733a2f2f72656c61792e6578616d706c652e636f6d2e2f",
        .ticket_string = "endpointadievmrsoqv3jkz2cnul2rqv4ttnaiskw4nac25pquqkgmwjo6dtoaiadnuhi5dqom5c6l3smvwgc6jomv4gc3lqnrss4y3pnuxc6",
        .ticket_bytes_hex = "00d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701001b68747470733a2f2f72656c61792e6578616d706c652e636f6d2e2f",
    },
    .{
        .id = "endpoint/ipv4", .endpoint_id_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        .addrs = &.{ .{ .kind = .ip, .value = "192.0.2.1:4242" } },
        .postcard_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737010100c00002019221",
        .ticket_string = "endpointadievmrsoqv3jkz2cnul2rqv4ttnaiskw4nac25pquqkgmwjo6dtoaibadaaaaqbsiqq",
        .ticket_bytes_hex = "00d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737010100c00002019221",
    },
    .{
        .id = "endpoint/ipv6", .endpoint_id_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        .addrs = &.{ .{ .kind = .ip, .value = "[2001:db8::1]:443" } },
        .postcard_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701010120010db8000000000000000000000001bb03",
        .ticket_string = "endpointadievmrsoqv3jkz2cnul2rqv4ttnaiskw4nac25pquqkgmwjo6dtoaibaeqacdnyaaaaaaaaaaaaaaaaaaa3way",
        .ticket_bytes_hex = "00d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701010120010db8000000000000000000000001bb03",
    },
    .{
        .id = "endpoint/custom", .endpoint_id_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        .addrs = &.{ .{ .kind = .custom, .value = "deadbeef", .id = 66 } },
        .postcard_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370102420004deadbeef0000000000000000000000000000000000000000000000000000",
        .ticket_string = "endpointadievmrsoqv3jkz2cnul2rqv4ttnaiskw4nac25pquqkgmwjo6dtoaiciiaajxvnx3xqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .ticket_bytes_hex = "00d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370102420004deadbeef0000000000000000000000000000000000000000000000000000",
    },
    .{
        .id = "endpoint/ordering-dedup", .endpoint_id_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        .addrs = &.{ .{ .kind = .ip, .value = "192.0.2.1:4242" }, .{ .kind = .relay, .value = "https://relay.example.com." } },
        .postcard_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873702001b68747470733a2f2f72656c61792e6578616d706c652e636f6d2e2f0100c00002019221",
        .ticket_string = "endpointadievmrsoqv3jkz2cnul2rqv4ttnaiskw4nac25pquqkgmwjo6dtoaqadnuhi5dqom5c6l3smvwgc6jomv4gc3lqnrss4y3pnuxc6aiayaaaeamsee",
        .ticket_bytes_hex = "00d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873702001b68747470733a2f2f72656c61792e6578616d706c652e636f6d2e2f0100c00002019221",
    },
    .{
        .id = "endpoint/ticket-roundtrip", .endpoint_id_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        .addrs = &.{ .{ .kind = .relay, .value = "https://relay.example.com." }, .{ .kind = .ip, .value = "192.0.2.1:4242" } },
        .postcard_hex = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873702001b68747470733a2f2f72656c61792e6578616d706c652e636f6d2e2f0100c00002019221",
        .ticket_string = "endpointadievmrsoqv3jkz2cnul2rqv4ttnaiskw4nac25pquqkgmwjo6dtoaqadnuhi5dqom5c6l3smvwgc6jomv4gc3lqnrss4y3pnuxc6aiayaaaeamsee",
        .ticket_bytes_hex = "00d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873702001b68747470733a2f2f72656c61792e6578616d706c652e636f6d2e2f0100c00002019221",
    },
};

pub const HashCase = struct {
    name: []const u8,
    /// Input is the official BLAKE3 test-vector pattern input[i] = i % 251,
    /// truncated to `len` bytes (regenerated procedurally by the consumer).
    len: usize,
    digest_hex: []const u8,
    base32_nopad: []const u8,
};
pub const hash: []const HashCase = &.{
    .{ .name = "len_0", .len = 0, .digest_hex = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", .base32_nopad = "V4JUTOPV7GQ2NICAJXVDNXGJJGN4WJOJVXARFN6MTKJ4VZA7GJRA" },
    .{ .name = "len_1", .len = 1, .digest_hex = "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", .base32_nopad = "FU5N5X7RDNQ7CTEINY227IBWONW43B5HJUT3LQKRAIS5B5MS4IJQ" },
    .{ .name = "len_2", .len = 2, .digest_hex = "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63", .base32_nopad = "PNYBLO4SZ4FTDABXOAVGZXMB33SBEJHXGRUEYLASFTLDLHFR5ZRQ" },
    .{ .name = "len_3", .len = 3, .digest_hex = "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f", .base32_nopad = "4G7E26UKWVLAVJAZT3VDHGCJXKHCSPKVZIFICADHE3IYIUM6MR7Q" },
    .{ .name = "len_63", .len = 63, .digest_hex = "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b", .base32_nopad = "5G6DPJMU3KWYHPUUODPX66ZXTAUXYPMDJTUAXKC5NYQHMJ5X3N5Q" },
    .{ .name = "len_64", .len = 64, .digest_hex = "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98", .base32_nopad = "J3WXCQPKJJONJN4IMBV5EP2G4IJK7HFM5OWNY7I7JRW4P4SRDOMA" },
    .{ .name = "len_65", .len = 65, .digest_hex = "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee", .base32_nopad = "3YPF7IF6ODPW2K7I776Q5GOOVKHLN2GJHJR7FWGRYMHMW2ZGHXXA" },
    .{ .name = "len_127", .len = 127, .digest_hex = "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d", .base32_nopad = "3AJJH7NIMPYARQE6SL6DQKUB6WQLJIJFDS5BMNABNIHYNJV5MQGQ" },
    .{ .name = "len_128", .len = 128, .digest_hex = "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef", .base32_nopad = "6F7FOBLEWJSXRQZ3W72EMQ7VHFREWBO7DJ3MQHZQVTKURRCLIXXQ" },
    .{ .name = "len_129", .len = 129, .digest_hex = "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12", .base32_nopad = "NA5KV2PTYW5DP2VPA4VO2D46GC5MBBSRG65ONCY73ZGKFLV5ZMJA" },
    .{ .name = "len_1023", .len = 1023, .digest_hex = "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11", .base32_nopad = "CAIIS4HO3I7LSMV2VQKCRR5CCY5Q5ESMTKPCLM23XJZLFD3QXUIQ" },
    .{ .name = "len_1024", .len = 1024, .digest_hex = "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", .base32_nopad = "IIQUOOPQSWSAN474QPPLRCLUJLAA36BRYEG2UVIYTNOREHEFLL3Q" },
    .{ .name = "len_1025", .len = 1025, .digest_hex = "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444", .base32_nopad = "2ABHRLSH5MT3GT5OZ5T3J7RGH6BNKQJJC3A77WL4RS37XAKLQRCA" },
    .{ .name = "len_2048", .len = 2048, .digest_hex = "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a", .base32_nopad = "453LMAUMPTJCUTILUGBKRP3CEBOS55LWIZ7IHDWW6JJJXBP3UJFA" },
    .{ .name = "len_2049", .len = 2049, .digest_hex = "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030", .base32_nopad = "L5GXF5ANPJPYFMK4UKZOISY54PBO7BWEE3EVYGXQW2DZKISWGAYA" },
    .{ .name = "len_3072", .len = 3072, .digest_hex = "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2", .base32_nopad = "XGGLB7ZWEO7AGMTLG466NOIJKIMFCPTE6HXC5XJFEXD22HS477JA" },
    .{ .name = "len_3073", .len = 3073, .digest_hex = "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3", .base32_nopad = "OESLJFIBAEXYDTD7CHFANHWJEJWOZOFCZBIM7ZSE4MT5ELJ6DTJQ" },
};

const key = @import("key.zig");
