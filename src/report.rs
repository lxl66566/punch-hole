//! Session report values.

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::{
    msg::{Nonce, StrategyId},
    nat::{FilterClass, NatClass, NatInfo},
};

/// Which side of an attempt a session drove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// What happened during one session, for logging and relay decisions.
#[derive(Debug, Clone)]
pub struct PunchReport {
    pub role: Role,
    pub nonce: Nonce,
    pub strategy: StrategyId,
    /// The local IPv4 mapping class, `None` when the side reported no IPv4
    /// evidence at all.
    pub local_class: Option<NatClass>,
    /// The peer's IPv4 mapping class, `None` when it reported no IPv4
    /// evidence at all.
    pub peer_class: Option<NatClass>,
    /// The local IPv4 filtering evidence, from the RFC 5780 change-request
    /// tests. `None` when the side reported no IPv4 evidence at all.
    pub local_filtering: Option<FilterClass>,
    /// The peer's IPv4 filtering evidence, `None` when it reported no IPv4
    /// evidence at all.
    pub peer_filtering: Option<FilterClass>,
    /// Local IPv4 reflexive address Probe observed. `None` when a cached
    /// classification carried no IPv4 evidence.
    pub local_reflexive_v4: Option<SocketAddrV4>,
    /// Local global IPv6 reflexive addresses Probe observed, capped at the
    /// wire limit.
    pub local_reflexive_v6: Vec<SocketAddrV6>,
    /// The STUN server the engine's refresh queries used, when the plan
    /// refreshed its V4 mapping.
    pub refresh_server: Option<SocketAddr>,
    /// Port-space width the model estimated over the initiator's own
    /// allocation sequence; stated when that side reads as symmetric.
    pub initiator_space: Option<usize>,
    /// Port-space width the model estimated over the responder's own
    /// allocation sequence; stated when that side reads as symmetric.
    pub responder_space: Option<usize>,
    /// Local port of the winner socket.
    pub winner_local_port: u16,
    /// Pool index of the peer's winner socket, from its packets or its
    /// Confirmed frame. Engine-local diagnostic with no cross-process
    /// meaning; `None` when the peer never reported one.
    pub peer_socket: Option<u16>,
    pub packets_sent: u32,
    pub stale_packets: u32,
    /// The birthday model's estimate, when the strategy is a burst.
    pub success_estimate: Option<f64>,
    pub phase_ms: PhaseDurations,
}

/// Wall time each phase consumed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhaseDurations {
    pub probe_ms: u64,
    pub exchange_ms: u64,
    pub negotiate_ms: u64,
    pub punch_ms: u64,
    pub confirm_ms: u64,
    pub total_ms: u64,
}

/// The plan Negotiate settled on, as both roles know it.
///
/// The Responder rebuilds its estimate from the local view, so both sides
/// report the same numbers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StrategySummary {
    /// The punching algorithm the Initiator picked.
    pub strategy: StrategyId,
    /// Sockets the Initiator opens.
    pub initiator_sockets: u16,
    /// Sockets the Responder opens.
    pub responder_sockets: u16,
    /// The success model's estimate, when the strategy carries one.
    pub estimate: Option<f64>,
}

/// Evidence a session collected before it failed, for on-site triage.
///
/// Each field appears as its phase completes, so the set of populated
/// fields names the phase the failure belongs to even before the error is
/// read. A failure before Probe leaves everything empty.
#[derive(Debug, Clone, Default)]
pub struct SessionDiagnostics {
    /// The local classification, present once Probe finished or a cached
    /// classification took its place.
    pub local: Option<NatInfo>,
    /// The peer classification, present once Exchange delivered its Hello.
    pub peer: Option<NatInfo>,
    /// The plan Negotiate settled, present once both sides agreed.
    pub selection: Option<StrategySummary>,
    /// The attempt nonce, drawn by the Initiator in Negotiate.
    pub nonce: Option<Nonce>,
    /// Wall time each completed phase consumed. `total_ms` covers the
    /// whole attempt; the punch and confirm fields stay zero, because a
    /// failed engine run reports no timings.
    pub phase_ms: PhaseDurations,
}
