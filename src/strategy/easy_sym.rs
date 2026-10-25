//! EasySym against EasySym prediction exchange.

use std::net::SocketAddr;

use super::StageSpec;
use crate::{
    config::PunchConfig,
    nat::{NatInfo, PortPredictor},
    socket::Family,
};

/// Both sides fit the peer's sequence and send into a window of predicted
/// ports.
///
/// The peer allocates one port per socket and destination it sends to, so the
/// window covers both socket counts with margin. Both windows start at the
/// same fitted base, which guarantees overlap while the step holds.
pub(crate) fn stage(
    my_sockets: u16,
    peer: &NatInfo,
    window_len: usize,
    cfg: &PunchConfig,
) -> Option<StageSpec> {
    let v4 = peer.v4.as_ref()?;
    let predictor = PortPredictor::fit(&v4.alloc_seq)?;
    let targets: Vec<SocketAddr> = predictor
        .window(window_len)
        .into_iter()
        .map(|port| SocketAddr::V4(std::net::SocketAddrV4::new(*v4.reflexive.ip(), port)))
        .collect();
    Some(StageSpec::send(
        Family::V4,
        my_sockets as usize,
        targets,
        false,
        cfg.punch_timeout,
    ))
}
