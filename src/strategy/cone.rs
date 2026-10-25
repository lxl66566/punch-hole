//! Cone against Cone reflexive exchange.

use std::net::SocketAddr;

use super::StageSpec;
use crate::{config::PunchConfig, nat::NatInfo, socket::Family};

/// One socket aimed at the peer's single reflexive address.
///
/// Address-and-port-dependent filtering is handled by simultaneous sending
/// and the confirm retransmissions.
pub(crate) fn stage(peer: &NatInfo, cfg: &PunchConfig) -> Option<StageSpec> {
    let reflexive = peer.reflexive_v4()?;
    // The reflexive address belongs to the peer's closed probe socket, so
    // sweeps wait for its PortUpdate with the live punch port.
    Some(StageSpec::send(
        Family::V4,
        1,
        vec![SocketAddr::V4(reflexive)],
        true,
        cfg.punch_timeout,
    ))
}
