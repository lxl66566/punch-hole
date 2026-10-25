//! Session report values.

use crate::{
    msg::{Nonce, StrategyId},
    nat::NatClass,
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
    pub local_class: NatClass,
    pub peer_class: NatClass,
    /// Local port of the winner socket.
    pub winner_local_port: u16,
    /// Pool index of the peer's winner socket, from its packets or its
    /// Confirmed frame.
    pub peer_socket: u16,
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
