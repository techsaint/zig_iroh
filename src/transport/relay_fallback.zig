//! Relay fallback placeholder for the greenfield endpoint.
//!
//! G0/G1 intentionally keeps relay disabled while proving the new direct
//! single-owner pump. The relay module exists so the actor boundary and module
//! layout match the design before relay behavior is moved over.

pub const Disabled = struct {
    pub fn init() Disabled {
        return .{};
    }

    pub fn available(_: Disabled) bool {
        return false;
    }
};
