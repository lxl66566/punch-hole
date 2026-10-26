//! Symmetric against Cone directed probing.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::{
    StageSpec, burst_len, distinct_ports, effective_class, observed_range, peer_space, spray_count,
};
use crate::{
    config::PunchConfig,
    msg::Nonce,
    nat::{NatClass, NatInfo, PortPredictor},
    socket::Family,
};

/// Unrelated allocations the prediction window tolerates besides the peer's
/// own punch sockets.
const PREDICTION_SLACK: usize = 16;

/// The symmetric side shoots from many sockets at the cone side's announced
/// port. The cone side answers every Syn it sees and additionally sprays
/// candidate ports at the symmetric peer.
pub(crate) fn stage(
    i_am_symmetric: bool,
    my_sockets: u16,
    peer_sockets: u16,
    peer: &NatInfo,
    nonce: Nonce,
    cfg: &PunchConfig,
) -> Option<StageSpec> {
    let v4 = peer.v4.as_ref()?;
    if i_am_symmetric {
        // The cone side's live port arrives with its PortUpdate.
        Some(StageSpec::send(
            Family::V4,
            my_sockets as usize,
            vec![SocketAddr::V4(v4.reflexive)],
            true,
            cfg.punch_timeout,
        ))
    } else {
        // A cone that filters on address and port drops the peer's Syn
        // pulses, because they arrive from source ports this socket never
        // wrote to. The spray writes first: when a spray Syn lands on a live
        // peer mapping, the SynAck returns from the peer's IP plus exactly
        // the candidate port this socket sent to, so the cone's own mapping
        // admits it. The reverse direction holds because the spray leaves
        // from the socket whose port the PortUpdate announced.
        let ip = *v4.reflexive.ip();
        let targets = match effective_class(peer) {
            NatClass::EasySym { .. } => predicted(ip, &v4.alloc_seq, peer_sockets)
                .unwrap_or_else(|| random_spray(ip, peer, peer_sockets, nonce, cfg)),
            _ => random_spray(ip, peer, peer_sockets, nonce, cfg),
        };
        let mut stage = StageSpec::send(Family::V4, 1, targets, false, cfg.punch_timeout);
        // A lone socket covers several ports per tick, so the spray runs at
        // the configured rate cap instead of one packet per tick.
        stage.per_sweep = burst_len(cfg);
        Some(stage)
    }
}

/// Predicted ports for an EasySym peer, continuing its observed sequence.
fn predicted(ip: Ipv4Addr, seq: &[u16], peer_sockets: u16) -> Option<Vec<SocketAddr>> {
    let predictor = PortPredictor::fit(seq)?;
    let window = peer_sockets as usize + PREDICTION_SLACK;
    Some(
        predictor
            .window(window)
            .into_iter()
            .map(|port| SocketAddr::V4(SocketAddrV4::new(ip, port)))
            .collect(),
    )
}

/// Distinct random candidates over the HardSym peer's observed span.
///
/// The peer's live mapping ports are fixed once its pulses begin, so the
/// stream advances through the span instead of repeating a few ports.
fn random_spray(
    ip: Ipv4Addr,
    peer: &NatInfo,
    peer_sockets: u16,
    nonce: Nonce,
    cfg: &PunchConfig,
) -> Vec<SocketAddr> {
    let seq = peer.v4.as_ref().map_or(&[][..], |v4| &v4.alloc_seq);
    let (lo, hi) = observed_range(seq);
    let span = usize::from(hi - lo) + 1;
    let count = spray_count(peer_sockets as usize, peer_space(peer), cfg).min(span);
    let seed = u64::from_be_bytes(nonce[..8].try_into().expect("nonce is 16 bytes"));
    distinct_ports(seed, lo, hi, count)
        .into_iter()
        .map(|port| SocketAddr::V4(SocketAddrV4::new(ip, port)))
        .collect()
}
