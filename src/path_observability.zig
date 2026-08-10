// LEGACY FORWARDER (fork-isolation S3): the file moved to
// src/shared/path_observability.zig; this re-export keeps every legacy
// path-import (`transport/{endpoint,factory,transport_noq}.zig`) working
// unchanged (type identity preserved — aliases, not copies). Deleted at the
// S7 cutover.
const shared = @import("shared");
pub const PathKind = shared.path_observability.PathKind;
pub const SelectedPath = shared.path_observability.SelectedPath;
pub const PathPredicate = shared.path_observability.PathPredicate;
pub const predIsRelay = shared.path_observability.predIsRelay;
pub const predIsIp = shared.path_observability.predIsIp;
pub const predIsIpv4 = shared.path_observability.predIsIpv4;
pub const predIsIpv6 = shared.path_observability.predIsIpv6;
pub const scoreHolepunchTransition = shared.path_observability.scoreHolepunchTransition;
pub const scorePathMigration = shared.path_observability.scorePathMigration;
