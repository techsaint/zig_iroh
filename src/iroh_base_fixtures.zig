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

const key = @import("key.zig");
