//! Relay map — the set of relay servers an endpoint dials, with per-relay
//! config.
//!
//! Port of upstream `iroh-relay/src/relay_map.rs`. Upstream stores
//! `Arc<RwLock<BTreeMap<RelayUrl, Arc<RelayConfig>>>>`; the idiomatic Zig
//! equivalent here is a plain owned struct over an insertion-ordered
//! `ArrayHashMap`: explicit allocator instead of `Arc`, caller-side
//! synchronization instead of an internal `RwLock`, and insertion order
//! instead of BTreeMap's URL-sorted order. Traversal order is a local
//! iteration choice — nothing about it is wire-observable.
//!
//! Ownership: the map clones and owns every key's URL text and frees it on
//! `remove`/`deinit`. A stored `RelayConfig.url` always borrows the map-owned
//! key text (normalized on `insert`), so configs are valid exactly as long as
//! their entry lives in the map. `auth_token` is a borrowed slice
//! (upstream `String`); the caller keeps it alive. `RelayMap` owns its
//! storage — treat it as move-only: pass by pointer, do not copy.

const std = @import("std");
const addr = @import("../addr.zig");

const RelayUrl = addr.RelayUrl;

/// Upstream `defaults::DEFAULT_RELAY_QUIC_PORT`.
pub const default_quic_port: u16 = 7842;

/// Configuration for speaking to the QUIC endpoint on the relay server to do
/// QUIC address discovery. Defaults to `default_quic_port`.
pub const RelayQuicConfig = struct {
    /// The port on which the connection should be bound to.
    port: u16 = default_quic_port,
};

/// Information on a specific relay server — where it can be dialed and how.
pub const RelayConfig = struct {
    /// The URL where this relay server can be dialed.
    url: RelayUrl,
    /// Configuration to speak to the QUIC endpoint on the relay server. When
    /// null, no QUIC address discovery is attempted with this relay.
    quic: ?RelayQuicConfig,
    /// Optional authorization token sent to the relay.
    ///
    /// Wire contract: the token travels as an `Authorization: Bearer TOKEN`
    /// header on the WebSocket upgrade request (see `client.zig` wsUpgrade).
    /// Borrowed slice; the caller keeps it alive.
    auth_token: ?[]const u8,

    /// Upstream `From<RelayUrl> for RelayConfig`: default QUIC config, no
    /// auth token.
    pub fn fromUrl(url: RelayUrl) RelayConfig {
        return .{ .url = url, .quic = .{}, .auth_token = null };
    }

    /// Upstream `RelayConfig::new`: explicit QUIC config, no auth token.
    pub fn init(url: RelayUrl, quic: ?RelayQuicConfig) RelayConfig {
        return .{ .url = url, .quic = quic, .auth_token = null };
    }

    /// Sets the authorization token, consuming-builder style. See the
    /// `auth_token` field docs for the wire contract.
    pub fn withAuthToken(self: RelayConfig, token: []const u8) RelayConfig {
        var out = self;
        out.auth_token = token;
        return out;
    }
};

/// List of relay server configurations to be used in an iroh endpoint.
pub const RelayMap = struct {
    allocator: std.mem.Allocator,
    entries: Map = .empty,

    const Map = std.array_hash_map.Custom(RelayUrl, RelayConfig, UrlContext, true);

    const UrlContext = struct {
        pub fn hash(_: @This(), url: RelayUrl) u32 {
            return @truncate(std.hash.Wyhash.hash(0, url.text));
        }
        pub fn eql(_: @This(), a: RelayUrl, b: RelayUrl, _: usize) bool {
            return a.eql(b);
        }
    };

    /// Creates an empty relay map (upstream `RelayMap::empty`).
    pub fn init(allocator: std.mem.Allocator) RelayMap {
        return .{ .allocator = allocator };
    }

    /// Frees every owned key URL and the map storage.
    pub fn deinit(self: *RelayMap) void {
        for (self.entries.keys()) |url| url.deinit(self.allocator);
        self.entries.deinit(self.allocator);
    }

    /// Creates a `RelayMap` from a slice of URLs. Each relay gets the default
    /// QUIC config (upstream `FromIterator<RelayUrl>`).
    pub fn fromUrls(allocator: std.mem.Allocator, relay_urls: []const RelayUrl) std.mem.Allocator.Error!RelayMap {
        var map = RelayMap.init(allocator);
        errdefer map.deinit();
        for (relay_urls) |url| _ = try map.insert(url, RelayConfig.fromUrl(url));
        return map;
    }

    /// Creates a `RelayMap` by parsing URL strings (upstream
    /// `RelayMap::try_from_iter`). Returns `error.InvalidRelayUrl` on the
    /// first unparseable entry.
    pub fn tryFromIter(allocator: std.mem.Allocator, strings: []const []const u8) addr.AddrError!RelayMap {
        var map = RelayMap.init(allocator);
        errdefer map.deinit();
        for (strings) |s| {
            const url = try RelayUrl.parse(allocator, s);
            defer url.deinit(allocator);
            _ = try map.insert(url, RelayConfig.fromUrl(url));
        }
        return map;
    }

    /// The URLs of all relays in this map, in insertion order. Borrows the
    /// map's keys — valid until the map is mutated or deinitialized.
    pub fn urls(self: *const RelayMap) []const RelayUrl {
        return self.entries.keys();
    }

    /// Returns true if a relay with `url` is in this map.
    pub fn contains(self: *const RelayMap, url: RelayUrl) bool {
        return self.entries.contains(url);
    }

    /// Returns the config for a relay, or null. A copy — the stored
    /// `url` slice still borrows the map-owned key text.
    pub fn get(self: *const RelayMap, url: RelayUrl) ?RelayConfig {
        return self.entries.get(url);
    }

    /// The number of relays in this map.
    pub fn len(self: *const RelayMap) usize {
        return self.entries.count();
    }

    /// Returns true if this map is empty.
    pub fn isEmpty(self: *const RelayMap) bool {
        return self.entries.count() == 0;
    }

    /// Inserts a relay, returning the replaced config if the URL was already
    /// present. The map clones and owns the key; the stored config's `url` is
    /// normalized to borrow that key.
    pub fn insert(self: *RelayMap, url: RelayUrl, config: RelayConfig) std.mem.Allocator.Error!?RelayConfig {
        const gop = try self.entries.getOrPut(self.allocator, url);
        if (gop.found_existing) {
            const old = gop.value_ptr.*;
            gop.value_ptr.* = config;
            gop.value_ptr.url = RelayUrl.borrowed(gop.key_ptr.text);
            return old;
        }
        const key_clone = url.clone(self.allocator) catch {
            self.entries.orderedRemoveAt(self.entries.getIndex(url).?);
            return error.OutOfMemory;
        };
        gop.key_ptr.* = key_clone;
        gop.value_ptr.* = config;
        gop.value_ptr.url = RelayUrl.borrowed(key_clone.text);
        return null;
    }

    /// Removes a relay by its URL, returning its config if present.
    pub fn remove(self: *RelayMap, url: RelayUrl) ?RelayConfig {
        const index = self.entries.getIndex(url) orelse return null;
        const key = self.entries.keys()[index];
        const old = self.entries.values()[index];
        self.entries.orderedRemoveAt(index);
        key.deinit(self.allocator);
        return old;
    }

    /// Extends this map with another one's entries (upstream
    /// `RelayMap::extend`); existing URLs are replaced.
    pub fn extend(self: *RelayMap, other: *const RelayMap) std.mem.Allocator.Error!void {
        for (other.entries.keys(), other.entries.values()) |url, config| {
            _ = try self.insert(url, config);
        }
    }

    /// Sets an authorization token for all relays CURRENTLY in this map
    /// (upstream `RelayMap::with_auth_token`): entries added AFTER this call
    /// do not get the token. Consuming-builder style — returns the same map
    /// storage by value.
    pub fn withAuthToken(self: RelayMap, token: []const u8) RelayMap {
        for (self.entries.values()) |*config| config.auth_token = token;
        return self;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "empty map has no relays" {
    var map = RelayMap.init(testing.allocator);
    defer map.deinit();
    try testing.expectEqual(@as(usize, 0), map.len());
    try testing.expect(map.isEmpty());
    try testing.expect(!map.contains(RelayUrl.borrowed("https://relay.example.org/")));
}

test "fromUrls applies default quic config" {
    const urls = [_]RelayUrl{
        RelayUrl.borrowed("https://relay-a.example.org/"),
        RelayUrl.borrowed("https://relay-b.example.org/"),
    };
    var map = try RelayMap.fromUrls(testing.allocator, &urls);
    defer map.deinit();

    try testing.expectEqual(@as(usize, 2), map.len());
    try testing.expect(!map.isEmpty());
    try testing.expectEqualStrings("https://relay-a.example.org/", map.urls()[0].text);
    try testing.expectEqualStrings("https://relay-b.example.org/", map.urls()[1].text);

    const config = map.get(urls[0]).?;
    try testing.expectEqualStrings("https://relay-a.example.org/", config.url.text);
    try testing.expectEqual(@as(u16, default_quic_port), config.quic.?.port);
    try testing.expect(config.auth_token == null);
}

test "insert returns replaced config, remove returns removed" {
    var map = RelayMap.init(testing.allocator);
    defer map.deinit();
    const url = RelayUrl.borrowed("https://relay.example.org/");

    try testing.expect(try map.insert(url, RelayConfig.fromUrl(url)) == null);
    const replaced = (try map.insert(url, RelayConfig.init(url, null))).?;
    try testing.expect(replaced.quic != null);
    try testing.expect(map.get(url).?.quic == null);
    try testing.expectEqual(@as(usize, 1), map.len());

    const removed = map.remove(url).?;
    try testing.expect(removed.quic == null);
    try testing.expect(map.isEmpty());
    try testing.expect(map.remove(url) == null);
}

test "extend combines maps (upstream relay_map_extend)" {
    const urls1 = [_]RelayUrl{
        RelayUrl.borrowed("https://hello-a-01.com/"),
        RelayUrl.borrowed("https://hello-b-01.com/"),
        RelayUrl.borrowed("https://hello-c-01-.com/"),
    };
    const urls2 = [_]RelayUrl{
        RelayUrl.borrowed("https://hello-a-02.com/"),
        RelayUrl.borrowed("https://hello-b-02.com/"),
        RelayUrl.borrowed("https://hello-c-02-.com/"),
    };
    var map1 = try RelayMap.fromUrls(testing.allocator, &urls1);
    defer map1.deinit();
    var map2 = try RelayMap.fromUrls(testing.allocator, &urls2);
    defer map2.deinit();

    try map1.extend(&map2);
    try testing.expectEqual(@as(usize, 6), map1.len());
    for (urls1 ++ urls2) |url| try testing.expect(map1.contains(url));
}

test "withAuthToken rewrites current entries only" {
    const urls = [_]RelayUrl{
        RelayUrl.borrowed("https://relay-a.example.org/"),
        RelayUrl.borrowed("https://relay-b.example.org/"),
    };
    var map = try RelayMap.fromUrls(testing.allocator, &urls);
    defer map.deinit();
    map = map.withAuthToken("sekrit");

    for (map.urls()) |url|
        try testing.expectEqualStrings("sekrit", map.get(url).?.auth_token.?);

    // Entries added after withAuthToken are unaffected (upstream semantics).
    const late = RelayUrl.borrowed("https://relay-c.example.org/");
    _ = try map.insert(late, RelayConfig.fromUrl(late));
    try testing.expect(map.get(late).?.auth_token == null);
}

test "tryFromIter parses and rejects bad URLs" {
    var map = try RelayMap.tryFromIter(testing.allocator, &.{
        "https://relay_0.cool.com",
        "https://relay_1.cool.com",
    });
    defer map.deinit();
    try testing.expectEqual(@as(usize, 2), map.len());
    // Parsing canonicalizes with a trailing slash.
    try testing.expectEqualStrings("https://relay_0.cool.com/", map.urls()[0].text);

    try testing.expectError(error.InvalidRelayUrl, RelayMap.tryFromIter(testing.allocator, &.{
        "https://fine.example.org",
        "not a url",
    }));
}
