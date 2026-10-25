//! Symmetric against Cone directed probing.

use std::net::SocketAddr;

use super::StageSpec;
use crate::{config::PunchConfig, nat::NatInfo, socket::Family};

/// The symmetric side shoots from many sockets at the cone side's single
/// reflexive address. The cone side binds one socket and only replies to
/// whatever source address it sees, which opens the reverse direction.
pub(crate) fn stage(
    i_am_symmetric: bool,
    my_sockets: u16,
    peer: &NatInfo,
    cfg: &PunchConfig,
) -> Option<StageSpec> {
    let reflexive = peer.reflexive_v4()?;
    if i_am_symmetric {
        // The cone side's live port arrives with its PortUpdate.
        Some(StageSpec::send(
            Family::V4,
            my_sockets as usize,
            vec![SocketAddr::V4(reflexive)],
            true,
            cfg.punch_timeout,
        ))
    } else {
        Some(StageSpec::reply(Family::V4, cfg.punch_timeout))
    }
}
