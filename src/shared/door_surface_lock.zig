//! The transport-door SURFACE LOCK (fork-isolation §3.3 / fable P4).
//!
//! Freezes the door's exact export list. The door's public surface is FINAL
//! from S1 (only its backing swaps from legacy re-exports to
//! `Seam(engine.bundle)` in S6/S7) — widening it requires editing THIS list in
//! `shared`, a diff a reviewer cannot miss, in the module the widening
//! endangers. Independent of the A4 manifest API fixture
//! (`door_api_fixture.zig`), which checks presence+signatures; this one
//! rejects ADDITIONS.

const std = @import("std");
const door = @import("transport");

const locked_surface = [_][]const u8{
    "NodeId",
    "EndpointAddr",
    "NodeAddr",
    "TransportAddr",
    "RelayUrl",
    "CustomAddr",
    "Error",
    "CongestionController",
    "ConnectionStats",
    "SendStream",
    "RecvStream",
    "BiStream",
    "Connection",
    "Transport",
    "factory",
};

test "door surface-lock: the transport door exposes exactly the locked surface" {
    comptime {
        const decls = @typeInfo(door).@"struct".decls;
        for (decls) |d| {
            var found = false;
            for (locked_surface) |name| {
                if (std.mem.eql(u8, d.name, name)) {
                    found = true;
                    break;
                }
            }
            if (!found) @compileError("transport door exports a decl outside the surface lock: " ++ d.name);
        }
        if (decls.len != locked_surface.len) {
            @compileError(std.fmt.comptimePrint(
                "transport door surface count {d} != locked {d} (a locked decl is missing)",
                .{ decls.len, locked_surface.len },
            ));
        }
    }
}
