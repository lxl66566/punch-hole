//! The Direct stages that run before the NAT matrix.

use std::net::SocketAddr;

use super::{StageSpec, select::local_stage_reachable};
use crate::{config::PunchConfig, nat::NatInfo, socket::Family};

/// Builds the Direct stage from the addresses both sides reported.
///
/// A peer without any usable address yields None, which skips the stage.
pub(crate) fn stage(mine: &NatInfo, peer: &NatInfo, cfg: &PunchConfig) -> Option<StageSpec> {
    let v6_available = cfg.ipv6
        && mine.v6.as_ref().is_some_and(|v6| !v6.addrs.is_empty())
        && peer.v6.as_ref().is_some_and(|v6| !v6.addrs.is_empty());
    if v6_available {
        // IPv6 needs no NAT cooperation, so it goes first. The advertised
        // addresses carry the peer's probe port, so sweeps wait for its
        // PortUpdate with the live punch port.
        let targets: Vec<SocketAddr> = peer
            .v6
            .as_ref()
            .expect("v6 checked above")
            .addrs
            .iter()
            .map(|addr| SocketAddr::V6(*addr))
            .collect();
        Some(StageSpec::send(
            Family::V6,
            1,
            targets,
            true,
            cfg.direct_window,
        ))
    } else {
        // Both IPv4 paths are public; aim straight at the reflexive address
        // once the peer's PortUpdate names the live punch port. A peer that
        // reported no reflexive address has nothing to aim at.
        let reflexive = peer.reflexive_v4()?;
        Some(StageSpec::send(
            Family::V4,
            1,
            vec![SocketAddr::V4(reflexive)],
            true,
            cfg.direct_window,
        ))
    }
}

/// Builds the Local stage for two hosts behind one non-hairpinning NAT.
///
/// Datagrams between the two die at the NAT whichever matrix stage runs,
/// while the LAN underneath it delivers a datagram to a local address
/// with no NAT cooperation at all. The stage carries no targets of its
/// own: the engine builds them from the peer's reachable local addresses
/// once its PortUpdate names the local punch port, which is what a
/// local-only plan announces. A peer that reported no reachable local
/// address yields None, which skips the stage.
pub(crate) fn local_stage(peer: &NatInfo, cfg: &PunchConfig) -> Option<StageSpec> {
    if !peer.local.iter().any(|ip| local_stage_reachable(*ip)) {
        return None;
    }
    let mut stage = StageSpec::send(Family::V4, 1, Vec::new(), true, cfg.direct_window);
    stage.local_targets = true;
    Some(stage)
}
