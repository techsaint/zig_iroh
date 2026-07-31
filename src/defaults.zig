//! Default / staging relay maps — wire-compatible hostnames with upstream
//! `iroh::defaults::{prod,staging}`.
//!
//! These are the n0-operated public relays. `RelayMode.default` / `.staging`
//! resolve home-relay URLs from here; Custom mode never touches this module.

const std = @import("std");
const addr = @import("addr.zig");
const relay_map = @import("relay/relay_map.zig");

pub const RelayMap = relay_map.RelayMap;
pub const RelayConfig = relay_map.RelayConfig;
pub const RelayUrl = addr.RelayUrl;

/// Upstream `iroh::defaults::prod`.
pub const prod = struct {
    pub const NA_EAST_RELAY_HOSTNAME = "use1-1.relay.n0.iroh.link.";
    pub const NA_WEST_RELAY_HOSTNAME = "usw1-1.relay.n0.iroh.link.";
    pub const EU_RELAY_HOSTNAME = "euc1-1.relay.n0.iroh.link.";
    pub const AP_RELAY_HOSTNAME = "aps1-1.relay.n0.iroh.link.";

    pub const hostnames = [_][]const u8{
        NA_EAST_RELAY_HOSTNAME,
        NA_WEST_RELAY_HOSTNAME,
        EU_RELAY_HOSTNAME,
        AP_RELAY_HOSTNAME,
    };

    /// Production pkarr HTTP relay (upstream `N0_DNS_PKARR_RELAY_PROD` path).
    pub const PKARR_RELAY_URL = "https://dns.iroh.link/pkarr";

    pub fn defaultRelayMap(allocator: std.mem.Allocator) addr.AddrError!RelayMap {
        return mapFromHttpsHostnames(allocator, &hostnames);
    }

    pub fn firstRelayUrl(allocator: std.mem.Allocator) addr.AddrError!RelayUrl {
        return httpsRelayUrl(allocator, NA_EAST_RELAY_HOSTNAME);
    }
};

/// Upstream `iroh::defaults::staging` — tests and pre-release infra.
pub const staging = struct {
    pub const NA_EAST_RELAY_HOSTNAME = "use1-1.staging-relay.n0.iroh.link.";
    pub const EU_RELAY_HOSTNAME = "euc1-1.staging-relay.n0.iroh.link.";

    pub const hostnames = [_][]const u8{
        NA_EAST_RELAY_HOSTNAME,
        EU_RELAY_HOSTNAME,
    };

    /// Staging pkarr HTTP relay (upstream `N0_DNS_PKARR_RELAY_STAGING`).
    pub const PKARR_RELAY_URL = "https://staging-dns.iroh.link/pkarr";

    pub fn defaultRelayMap(allocator: std.mem.Allocator) addr.AddrError!RelayMap {
        return mapFromHttpsHostnames(allocator, &hostnames);
    }

    pub fn firstRelayUrl(allocator: std.mem.Allocator) addr.AddrError!RelayUrl {
        return httpsRelayUrl(allocator, NA_EAST_RELAY_HOSTNAME);
    }
};

/// Environment variable matching upstream `IROH_FORCE_STAGING_RELAYS`.
pub const force_staging_env = "IROH_FORCE_STAGING_RELAYS";

/// Returns true when staging infra is forced (upstream `force_staging_infra`).
pub fn forceStagingInfra() bool {
    // Zig 0.16: process env is via libc `getenv` (same pattern as portmapper).
    const raw = std.c.getenv(force_staging_env) orelse return false;
    const v = std.mem.span(raw);
    if (v.len == 0) return false;
    if (std.mem.eql(u8, v, "0") or std.mem.eql(u8, v, "false") or std.mem.eql(u8, v, "False"))
        return false;
    return true;
}

fn httpsRelayUrl(allocator: std.mem.Allocator, hostname: []const u8) addr.AddrError!RelayUrl {
    // Upstream RelayUrl from `https://{hostname}` — keep trailing DNS dot in host.
    const raw = try std.fmt.allocPrint(allocator, "https://{s}", .{hostname});
    defer allocator.free(raw);
    return RelayUrl.parse(allocator, raw);
}

fn mapFromHttpsHostnames(allocator: std.mem.Allocator, hostnames: []const []const u8) addr.AddrError!RelayMap {
    var map = RelayMap.init(allocator);
    errdefer map.deinit();
    for (hostnames) |host| {
        const url = try httpsRelayUrl(allocator, host);
        // insert clones the URL key; free the temporary owned parse.
        defer url.deinit(allocator);
        _ = try map.insert(url, RelayConfig.fromUrl(url));
    }
    return map;
}

test "prod default map has four n0 relays" {
    const allocator = std.testing.allocator;
    var map = try prod.defaultRelayMap(allocator);
    defer map.deinit();
    try std.testing.expectEqual(@as(usize, 4), map.len());
    const first = try prod.firstRelayUrl(allocator);
    defer first.deinit(allocator);
    try std.testing.expect(map.contains(first));
    try std.testing.expect(std.mem.startsWith(u8, first.asString(), "https://use1-1.relay.n0.iroh.link"));
}

test "staging default map has two n0 relays" {
    const allocator = std.testing.allocator;
    var map = try staging.defaultRelayMap(allocator);
    defer map.deinit();
    try std.testing.expectEqual(@as(usize, 2), map.len());
    const first = try staging.firstRelayUrl(allocator);
    defer first.deinit(allocator);
    try std.testing.expect(map.contains(first));
    try std.testing.expect(std.mem.indexOf(u8, first.asString(), "staging-relay") != null);
}
