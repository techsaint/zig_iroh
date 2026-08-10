//! Product transport door. Its fifteen declarations are surface-locked by the
//! A4 fixture; relay-server uses the selected Picoquic engine seam, never legacy.
const shared = @import("shared");
const engine = @import("engine");
const seam = shared.transport_contract.Seam(engine.bundle);

pub const NodeId = seam.NodeId;
pub const EndpointAddr = seam.EndpointAddr;
pub const NodeAddr = seam.NodeAddr;
pub const TransportAddr = seam.TransportAddr;
pub const RelayUrl = seam.RelayUrl;
pub const CustomAddr = seam.CustomAddr;
pub const Error = seam.Error;
pub const CongestionController = seam.CongestionController;
pub const ConnectionStats = seam.ConnectionStats;
pub const SendStream = seam.SendStream;
pub const RecvStream = seam.RecvStream;
pub const BiStream = seam.BiStream;
pub const Connection = seam.Connection;
pub const Transport = seam.Transport;
pub const factory = seam.factory;
