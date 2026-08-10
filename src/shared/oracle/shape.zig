//! Uniform scenario shape for the iroh integration-suite oracle.
//!
//! One registry row = one upstream scenario (or one overlap/control gate).
//! See `oracle/README.md` for the human schema; this module is the Zig mirror.

const std = @import("std");

pub const CoverageDisposition = enum {
    converted,
    @"overlap/control",
    @"not-yet",
    @"post-beta",

    pub fn fromString(s: []const u8) ?CoverageDisposition {
        if (std.mem.eql(u8, s, "converted")) return .converted;
        if (std.mem.eql(u8, s, "overlap/control")) return .@"overlap/control";
        if (std.mem.eql(u8, s, "not-yet")) return .@"not-yet";
        if (std.mem.eql(u8, s, "post-beta")) return .@"post-beta";
        return null;
    }

    pub fn asString(self: CoverageDisposition) []const u8 {
        return switch (self) {
            .converted => "converted",
            .@"overlap/control" => "overlap/control",
            .@"not-yet" => "not-yet",
            .@"post-beta" => "post-beta",
        };
    }
};

pub const Result = enum {
    pass,
    fail,
    blocked,

    pub fn asString(self: Result) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .blocked => "blocked",
        };
    }
};

pub const DirectAddressPolicy = enum {
    required,
    forbidden,
    optional,

    pub fn fromString(s: []const u8) ?DirectAddressPolicy {
        if (std.mem.eql(u8, s, "required")) return .required;
        if (std.mem.eql(u8, s, "forbidden")) return .forbidden;
        if (std.mem.eql(u8, s, "optional")) return .optional;
        return null;
    }

    pub fn asString(self: DirectAddressPolicy) []const u8 {
        return switch (self) {
            .required => "required",
            .forbidden => "forbidden",
            .optional => "optional",
        };
    }
};

/// Machine-readable report-card row (one scenario evaluation).
pub const ReportRow = struct {
    scenario_id: []const u8,
    source_ref: []const u8,
    product: []const u8,
    gate_command: []const u8,
    result: Result,
    coverage_disposition: CoverageDisposition,
    reason: []const u8,
    missing_capability: ?[]const u8 = null,
    artifacts: []const []const u8 = &.{},
};

/// Forever-valid artifacts slice: every element MUST be a comptime-known
/// string. Passing a runtime `[]const u8` is a compile error — without this
/// guard, `&.{ "lit", runtime_str }` places the array on the returning stack
/// frame and the returned slice dangles (use-after-free at JSON encode).
pub fn frozenArtifacts(comptime arts: []const []const u8) []const []const u8 {
    return arts;
}

test "frozenArtifacts accepts comptime literals" {
    const arts = frozenArtifacts(&.{ "a", "b" });
    try std.testing.expectEqual(@as(usize, 2), arts.len);
    try std.testing.expectEqualStrings("a", arts[0]);
}

/// Build a returned `artifacts` slice that is guaranteed rodata-backed.
///
/// Every element MUST be a comptime-known string. Passing a runtime `[]const u8`
/// (e.g. a heap-duped manifest field) is a COMPILE ERROR — which is the point.
/// A runtime string stuffed into `&.{...}` and returned from a row constructor
/// places the array on the returning frame; the slice dangles and later GPF's
/// inside JSON utf8 validation (see backlog oracle-runtime-string-in-returned-
/// comptime-array). Prefer this helper over a bare `&.{...}` at new call sites.
pub fn staticArtifacts(comptime items: []const []const u8) []const []const u8 {
    return items;
}

test "staticArtifacts returns comptime string slice" {
    const arts = staticArtifacts(&.{ "src/shared/oracle/shape.zig", "oracle/manifest.json" });
    try std.testing.expectEqual(@as(usize, 2), arts.len);
    try std.testing.expectEqualStrings("src/shared/oracle/shape.zig", arts[0]);
}

test "staticArtifacts empty is valid" {
    const arts = staticArtifacts(&.{});
    try std.testing.expectEqual(@as(usize, 0), arts.len);
}

/// Typed gate input: report row + inspectable invariants the predicate needs
/// (not serialised into the report-card JSON — evaluator-only).
pub const GateEvalRow = struct {
    row: ReportRow,
    direct_address_policy: DirectAddressPolicy,
    /// True if this scenario's run used/injected a direct IP address.
    /// Only meaningful when `direct_path_observed` is true — otherwise the value is UNKNOWN,
    /// not a measured `false` (S2 / projection-provenance: declare-not-observe defect).
    used_direct_address: bool = false,
    /// True only when the production connection path was actually inspected.
    /// Unobserved scenarios must not report a measured-looking `used_direct_address=false`.
    direct_path_observed: bool = false,
};

/// Canonical control scenario id (direct-address interop overlap/control).
pub const control_scenario_id = "control_interop_direct_address_echo";

/// Canonical first endpoint/discovery skeleton id (upstream integration.rs).
pub const endpoint_skeleton_id = "simple_endpoint_id_based_connection_transfer";

/// Conversion-sweep scenario ids (capability-independent of node_id_only_connect).
pub const example_echo_id = "example_echo";
pub const example_echo_no_router_id = "example_echo_no_router";
pub const example_echo_multi_alpn_id = "example_echo_multi_alpn";
pub const endpoint_unreliable_datagrams_id = "endpoint_unreliable_datagrams";
pub const endpoint_connect_with_opts_id = "endpoint_connect_with_opts";
pub const endpoint_options_facade_id = "endpoint_options_facade";
pub const endpoint_metrics_config_id = "endpoint_metrics_config";
pub const endpoint_alpn_mutation_id = "endpoint_alpn_mutation";
pub const endpoint_relay_fallback_id = "endpoint_relay_fallback_on_direct_failure";
pub const example_listen_id = "example_listen";
pub const example_connect_id = "example_connect";
pub const example_transfer_id = "example_transfer";
pub const control_transfer_node_direct_id = "control_transfer_node_direct";
pub const control_interop_noq_direct_id = "control_interop_noq_direct";
pub const net_report_probe_id = "net_report_probe";
pub const portmapper_nat_pmp_gateway_probe_id = "portmapper_nat_pmp_gateway_probe";
pub const dual_stack_direct_quic_id = "dual_stack_direct_quic";
pub const example_dns_resolve_id = "example_dns_resolve";
pub const example_dns_publish_id = "example_dns_publish";
pub const relay_runtime_auth_id = "relay_runtime_auth";
pub const relay_acme_multi_hostname_id = "relay_acme_multi_hostname";
pub const relay_reverse_interop_id = "relay_reverse_interop";
pub const relay_operator_config_id = "relay_operator_config";
pub const relay_qad_id = "relay_qad";
pub const control_relay_datagram_forward_id = "control_relay_datagram_forward";
pub const relay_embed_axum_id = "relay_embed_axum";
pub const relay_embed_hyper_id = "relay_embed_hyper";

/// Patchbay / NAT / path-migration family (netsim substrate driver).
pub const patchbay_holepunch_simple_id = "patchbay_holepunch_simple";
pub const patchbay_faster_link_id = "patchbay_faster_link";
pub const patchbay_link_outage_recovery_id = "patchbay_link_outage_recovery";
pub const patchbay_hard_nat_replug_id = "patchbay_hard_nat_replug";
pub const patchbay_many_addrs_id = "patchbay_many_addrs";
pub const patchbay_degrade_id = "patchbay_degrade";
pub const patchbay_nat_matrix_id = "patchbay_nat_matrix";
pub const patchbay_switch_uplink_id = "patchbay_switch_uplink";

/// Dark / post-beta families (never previously scored). Standing them up with
/// honest blocked + named missing_capability converts unknown unknowns into tracked ones.
pub const blobs_store_api_id = "blobs_store_api";
pub const blobs_tags_api_id = "blobs_tags_api";
pub const docs_sync_id = "docs_sync";
pub const docs_gc_id = "docs_gc";
pub const docs_client_authors_id = "docs_client_authors";
pub const gossip_simulator_id = "gossip_simulator";
pub const control_blobs_wire_get_push_observe_id = "control_blobs_wire_get_push_observe";
pub const control_gossip_live_broadcast_id = "control_gossip_live_broadcast";
pub const control_discovery_live_doh_id = "control_discovery_live_doh";

pub const cap_blobs_store_public_api = "blobs_store_public_api";
pub const cap_blobs_tags_public_api = "blobs_tags_public_api";
pub const cap_docs_sync_engine = "docs_sync_engine";
pub const cap_docs_gc = "docs_gc";
pub const cap_docs_client_authors = "docs_client_authors";
pub const cap_gossip_simulator = "gossip_simulator";
pub const cap_blobs_wire_get_push_observe = "blobs_wire_get_push_observe";
pub const cap_gossip_live_broadcast = "gossip_live_broadcast";
pub const cap_relay_embed_axum = "relay_embed_axum_host";
pub const cap_relay_embed_hyper = "relay_embed_hyper_host";
pub const cap_docs_gossip_transport = "docs_depends_on_gossip_transport";

/// Capability tags.
pub const cap_direct_address_connect = "direct_address_connect";
pub const cap_node_id_only_connect = "node_id_only_connect";
pub const cap_endpoint_integrated_discovery = "endpoint_integrated_discovery";
pub const cap_endpoint_relay_connect = "endpoint_relay_connect";
pub const cap_online_publication = "online_publication";
pub const cap_doh_resolution = "doh_resolution";
pub const cap_protocol_handler_router = "protocol_handler_router";
pub const cap_protocol_handler_multi_alpn = "protocol_handler_multi_alpn";
pub const cap_example_alpn_echo_peer_harness = "example_alpn_echo_peer_harness";
pub const cap_endpoint_unreliable_datagrams = "endpoint_unreliable_datagrams";
pub const cap_endpoint_connect_with_opts = "endpoint_connect_with_opts";
pub const cap_endpoint_builder_facade = "endpoint_builder_facade";
pub const cap_endpoint_metrics_config_knobs = "endpoint_metrics_config_knobs";
pub const cap_endpoint_alpn_mutation = "endpoint_alpn_mutation";
pub const cap_endpoint_relay_fallback = "endpoint_relay_fallback";
pub const cap_relay_runtime_access_control = "relay_runtime_access_control";
pub const cap_relay_acme_tls_alpn_multi_hostname = "relay_acme_tls_alpn_multi_hostname";
pub const cap_relay_datagram_forwarding = "relay_datagram_forwarding";
pub const cap_relay_qad_quic_server = "relay_qad_quic_server";
pub const cap_net_report_probe = "net_report_probe";
pub const cap_portmapper_real_gateway = "portmapper_real_gateway";
pub const cap_dual_stack_bind_connect = "dual_stack_bind_connect";
pub const cap_patchbay_netsim_topology = "patchbay_netsim_topology";
pub const cap_selected_path_observability = "selected_path_observability";
