//! Provider-side request policy (ACL / event / throttle seam).
//!
//! Idiomatic Zig control plane for authorize / observe / throttle / abort of
//! blobs provider requests. Wire framing is unchanged — a deny aborts via the
//! existing stream reset/stop path and the blobs application error codes.
//!
//! Feature contract (not a transliteration of Rust EventMask/irpc):
//! - per-kind modes: allow / notify / intercept / deny
//! - default disables push (writes the local store)
//! - optional intercept + throttle hooks for callers

const std = @import("std");
const protocol = @import("protocol.zig");

pub const RequestKind = enum {
    connect,
    get,
    get_many,
    push,
    observe,
};

/// Per-request authorization mode.
/// - allow: serve without consulting a hook
/// - notify: invoke hook for observation, always serve (hook cannot deny)
/// - intercept: invoke hook; hook may allow or deny
/// - deny: refuse without serving (iroh RequestMode::Disabled)
pub const Mode = enum {
    allow,
    notify,
    intercept,
    deny,
};

pub const ThrottleMode = enum {
    none,
    intercept,
};

pub const AbortReason = enum {
    permission,
    rate_limited,

    pub fn errorCode(self: AbortReason) u64 {
        return switch (self) {
            .permission => protocol.ERR_PERMISSION,
            .rate_limited => protocol.ERR_LIMIT,
        };
    }

    pub fn toError(self: AbortReason) PolicyError {
        return switch (self) {
            .permission => error.PermissionDenied,
            .rate_limited => error.RateLimited,
        };
    }
};

pub const PolicyError = error{
    PermissionDenied,
    RateLimited,
};

pub const Decision = union(enum) {
    allow,
    deny: AbortReason,
};

pub const RequestHook = *const fn (ctx: ?*anyopaque, kind: RequestKind) Decision;
pub const ThrottleHook = *const fn (ctx: ?*anyopaque, size: u64) Decision;

/// Provider policy value. Copyable; hooks are optional function pointers.
pub const Policy = struct {
    connect: Mode = .allow,
    get: Mode = .allow,
    get_many: Mode = .allow,
    /// Default is deny — push can write the local store (iroh EventMask::DEFAULT).
    push: Mode = .deny,
    observe: Mode = .allow,
    throttle: ThrottleMode = .none,
    hook_ctx: ?*anyopaque = null,
    on_request: ?RequestHook = null,
    on_throttle: ?ThrottleHook = null,

    /// iroh-aligned production default: reads allowed, push disabled, no hooks.
    pub const default: Policy = .{};

    /// Full allow — preserves pre-policy provider behavior (including push).
    pub const allow_all: Policy = .{
        .connect = .allow,
        .get = .allow,
        .get_many = .allow,
        .push = .allow,
        .observe = .allow,
        .throttle = .none,
    };

    pub fn modeFor(self: Policy, kind: RequestKind) Mode {
        return switch (kind) {
            .connect => self.connect,
            .get => self.get,
            .get_many => self.get_many,
            .push => self.push,
            .observe => self.observe,
        };
    }

    /// Decide whether a request of `kind` may proceed.
    pub fn authorize(self: Policy, kind: RequestKind) Decision {
        return switch (self.modeFor(kind)) {
            .allow => .allow,
            .deny => .{ .deny = .permission },
            .notify => {
                if (self.on_request) |hook| {
                    // Observation only — a deny from the hook is ignored.
                    _ = hook(self.hook_ctx, kind);
                }
                return .allow;
            },
            .intercept => {
                if (self.on_request) |hook| return hook(self.hook_ctx, kind);
                return .allow;
            },
        };
    }

    /// Throttle seam: when mode is intercept and a hook is set, the hook may
    /// delay/deny mid-transfer. Default is none (no-op).
    pub fn throttleChunk(self: Policy, size: u64) Decision {
        if (self.throttle != .intercept) return .allow;
        if (self.on_throttle) |hook| return hook(self.hook_ctx, size);
        return .allow;
    }

    pub fn require(self: Policy, kind: RequestKind) PolicyError!void {
        switch (self.authorize(kind)) {
            .allow => {},
            .deny => |reason| return reason.toError(),
        }
    }
};

/// Abort an accepted bi-stream without writing a response body.
/// Peer-observable via existing wire: send RESET (+ optional app code) and
/// stop receiving. Does not invent a new frame type.
pub fn abortBi(bi: anytype, reason: AbortReason) void {
    const code = reason.errorCode();
    const Send = @TypeOf(bi.send);
    if (@hasDecl(Send, "resetWithCode")) {
        bi.send.resetWithCode(code);
    } else {
        bi.send.reset();
    }
    bi.recv.stop() catch {};
}

/// Run authorize; on deny, abort the bi-stream and return the policy error.
pub fn gateBi(policy: Policy, kind: RequestKind, bi: anytype) PolicyError!void {
    switch (policy.authorize(kind)) {
        .allow => {},
        .deny => |reason| {
            abortBi(bi, reason);
            return reason.toError();
        },
    }
}

test "default policy allows reads and denies push" {
    const p = Policy.default;
    try std.testing.expect(p.authorize(.get) == .allow);
    try std.testing.expect(p.authorize(.get_many) == .allow);
    try std.testing.expect(p.authorize(.observe) == .allow);
    try std.testing.expect(p.authorize(.connect) == .allow);
    switch (p.authorize(.push)) {
        .deny => |r| try std.testing.expect(r == .permission),
        .allow => return error.TestUnexpectedResult,
    }
}

test "allow_all authorizes every request kind" {
    const p = Policy.allow_all;
    for (std.meta.tags(RequestKind)) |kind| {
        try std.testing.expect(p.authorize(kind) == .allow);
    }
}

test "deny mode refuses without calling the hook" {
    var called: usize = 0;
    const Hook = struct {
        fn on(ctx: ?*anyopaque, _: RequestKind) Decision {
            const c: *usize = @ptrCast(@alignCast(ctx.?));
            c.* += 1;
            return .allow;
        }
    };
    const p = Policy{
        .get = .deny,
        .hook_ctx = &called,
        .on_request = Hook.on,
    };
    switch (p.authorize(.get)) {
        .deny => |r| try std.testing.expect(r == .permission),
        .allow => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), called);
}

test "notify invokes hook but cannot deny" {
    var called: usize = 0;
    const Hook = struct {
        fn on(ctx: ?*anyopaque, _: RequestKind) Decision {
            const c: *usize = @ptrCast(@alignCast(ctx.?));
            c.* += 1;
            return .{ .deny = .permission };
        }
    };
    const p = Policy{
        .get = .notify,
        .hook_ctx = &called,
        .on_request = Hook.on,
    };
    try std.testing.expect(p.authorize(.get) == .allow);
    try std.testing.expectEqual(@as(usize, 1), called);
}

test "intercept hook can deny with rate_limited" {
    const Hook = struct {
        fn on(_: ?*anyopaque, _: RequestKind) Decision {
            return .{ .deny = .rate_limited };
        }
    };
    const p = Policy{
        .get = .intercept,
        .on_request = Hook.on,
    };
    switch (p.authorize(.get)) {
        .deny => |r| {
            try std.testing.expect(r == .rate_limited);
            try std.testing.expectEqual(protocol.ERR_LIMIT, r.errorCode());
        },
        .allow => return error.TestUnexpectedResult,
    }
}

test "throttle seam is no-op by default and consults hook when intercept" {
    const p0 = Policy.default;
    try std.testing.expect(p0.throttleChunk(16 * 1024) == .allow);

    const Hook = struct {
        fn on(_: ?*anyopaque, size: u64) Decision {
            if (size > 100) return .{ .deny = .rate_limited };
            return .allow;
        }
    };
    const p = Policy{
        .throttle = .intercept,
        .on_throttle = Hook.on,
    };
    try std.testing.expect(p.throttleChunk(50) == .allow);
    switch (p.throttleChunk(200)) {
        .deny => |r| try std.testing.expect(r == .rate_limited),
        .allow => return error.TestUnexpectedResult,
    }
}

test "AbortReason maps to iroh application error codes" {
    try std.testing.expectEqual(@as(u64, 1), AbortReason.permission.errorCode());
    try std.testing.expectEqual(@as(u64, 2), AbortReason.rate_limited.errorCode());
    try std.testing.expectEqual(@as(u64, 1), protocol.ERR_PERMISSION);
    try std.testing.expectEqual(@as(u64, 2), protocol.ERR_LIMIT);
    try std.testing.expectEqual(@as(u64, 3), protocol.ERR_INTERNAL);
}
