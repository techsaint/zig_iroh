//! iroh-dns-server product surface — pkarr relay + authoritative DNS + DoH.
//!
//! Reference: `iroh/iroh-dns-server/` at pin 255a939b.

pub const config = @import("config.zig");
pub const mainline = @import("mainline.zig");
pub const metrics = @import("metrics.zig");
pub const store = @import("store.zig");
pub const dns = @import("dns.zig");
pub const http = @import("http.zig");
pub const server = @import("server.zig");
pub const tls = @import("tls.zig");

pub const Config = config.Config;
pub const Metrics = metrics.Metrics;
pub const ZoneStore = store.ZoneStore;
pub const Server = server.Server;

test {
    _ = config;
    _ = mainline;
    _ = metrics;
    _ = store;
    _ = dns;
    _ = http;
    _ = server;
    _ = tls;
}
