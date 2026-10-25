//! The Direct stage that runs before the NAT matrix.

use std::net::SocketAddr;

use super::StageSpec;
use crate::{config::PunchConfig, nat::NatInfo, socket::Family};

/// Builds the Direct stage from the addresses both sides reported.
pub(crate) fn stage(mine: &NatInfo, peer: &NatInfo, cfg: &PunchConfig) -> StageSpec {
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
        StageSpec::send(Family::V6, 1, targets, true, cfg.direct_window)
    } else {
        // Both IPv4 paths are public; aim straight at the reflexive address
        // once the peer's PortUpdate names the live punch port.
        let reflexive = peer
            .reflexive_v4()
            .expect("public peer reported a reflexive address");
        StageSpec::send(
            Family::V4,
            1,
            vec![SocketAddr::V4(reflexive)],
            true,
            cfg.direct_window,
        )
    }
}
