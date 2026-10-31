//! Prediction against random collision for a mixed symmetric pair.

use std::net::{SocketAddr, SocketAddrV4};

use super::{
    StageSpec, burst_len, distinct_ports, effective_class, size_predictive, span_estimate,
};
use crate::{
    config::PunchConfig,
    msg::Nonce,
    nat::{NatClass, NatInfo, PortPredictor},
    socket::Family,
};

/// One socket per side: the side facing the easy peer covers its whole
/// continuation window, the side facing the hard peer keeps the random
/// spray over its estimated span.
///
/// Either direction completes the handshake. A window Syn lands on a live
/// continuation mapping of the easy peer, whose answer returns from
/// exactly the covered port; a spray candidate that lands on one of the
/// window mappings answers the same way. Both stages fire from the shared
/// engine start with static targets. The easy side announces its current
/// allocation position, and the hard side re-bases its window onto that
/// mark, so drift between Probe and punch — silent probe destinations
/// included — moves the window instead of sliding the live block out of
/// it.
pub(crate) fn stage(
    i_am_easy: bool,
    my_sockets: u16,
    hard_space: usize,
    peer: &NatInfo,
    nonce: Nonce,
    salt: u64,
    cfg: &PunchConfig,
) -> Option<StageSpec> {
    let v4 = peer.v4.as_ref()?;
    let ip = *v4.reflexive.ip();
    let sized = size_predictive(hard_space, cfg);
    let ports = if i_am_easy {
        // Facing a HardSym peer: the one-directional spray of the model, a
        // distinct random stream over the peer's estimated span.
        let (lo, hi) = span_estimate(&v4.alloc_seq);
        let seed = u64::from_be_bytes(nonce[..8].try_into().expect("nonce is 16 bytes")) ^ salt;
        distinct_ports(seed, lo, hi, sized.easy)
    } else {
        // Facing an EasySym peer: its continuation window at the
        // classifier's step, covered whole. `step` divides port deltas by
        // send-index distance, so it holds the true stride over silent
        // probe destinations; the adjacent-delta fit only serves as the
        // fallback.
        let NatClass::EasySym { step } = effective_class(peer) else {
            return None;
        };
        PortPredictor::with_step(&v4.alloc_seq, step)
            .or_else(|| PortPredictor::fit(&v4.alloc_seq))?
            .window(sized.window)
    };
    let targets: Vec<SocketAddr> = ports
        .into_iter()
        .map(|port| SocketAddr::V4(SocketAddrV4::new(ip, port)))
        .collect();
    let mut stage = StageSpec::send(
        Family::V4,
        my_sockets as usize,
        targets,
        false,
        cfg.punch_timeout,
    );
    // A lone sender covers several ports per tick, at the configured rate
    // cap, without repeating a port inside one tick.
    stage.per_sweep = burst_len(cfg).min(stage.targets.len() as u16);
    Some(stage)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use super::*;
    use crate::{
        nat::{FilterClass, V4Nat},
        strategy::{PREDICTION_SLACK, model::spray_hit_chance, peer_space},
    };

    fn hard_peer(seq: &[u16]) -> NatInfo {
        NatInfo {
            v4: Some(V4Nat {
                class: NatClass::HardSym,
                reflexive: SocketAddrV4::new([203, 0, 113, 7].into(), 5000),
                alloc_seq: seq.to_vec(),
                distinct_probe_ips: 4,
                filtering: FilterClass::Unknown,
                hairpin: true,
            }),
            v6: None,
            local: Vec::new(),
        }
    }

    fn easy_peer(seq: &[u16], step: i16) -> NatInfo {
        let mut info = hard_peer(seq);
        let v4 = info.v4.as_mut().expect("v4 evidence");
        v4.class = NatClass::EasySym { step };
        info
    }

    /// The easy side sprays the sized coverage over the hard peer's span,
    /// and the hard side covers the window that continues the easy peer's
    /// sequence at the classifier's stride.
    #[test]
    fn stages_split_the_two_directions() {
        let cfg = PunchConfig::default();
        let hard = hard_peer(&[30_000, 30_100, 30_180, 30_250]);
        let easy = easy_peer(&[5000, 5002, 5004, 5006], 2);
        // Both sides size against the hard side's space, so one coverage
        // pair governs the pair.
        let hard_space = peer_space(&hard);
        let sized = size_predictive(hard_space, &cfg);

        let spray = stage(true, 1, hard_space, &hard, [0; 16], 1, &cfg).expect("easy side builds");
        // spray_count floors at one candidate, so the sized count is a
        // positive length.
        assert_eq!(spray.targets.len(), sized.easy);

        let window =
            stage(false, 1, hard_space, &easy, [0; 16], 0, &cfg).expect("hard side builds");
        assert_eq!(window.targets.len(), sized.window);
        let ports: Vec<u16> = window.targets.iter().map(SocketAddr::port).collect();
        assert_eq!(&ports[..4], &[5008, 5010, 5012, 5014]);
        // The window extends past the easy side's live count, so drift
        // inside the slack still lands on the covered span.
        assert_eq!(ports.len(), sized.easy + PREDICTION_SLACK);
    }

    /// The quadratic solve and the caps agree: whatever `spray_count`
    /// returns, the window covers the easy side's live ports plus slack,
    /// and the random direction reaches its target while unclamped.
    #[test]
    fn sizing_reaches_the_random_target() {
        let cfg = PunchConfig::default();
        let space = 30_000;
        let sized = size_predictive(space, &cfg);
        assert_eq!(sized.window, sized.easy + PREDICTION_SLACK);
        assert!(
            spray_hit_chance(sized.window, sized.easy, space) >= cfg.target_success - 1e-9,
            "random direction {}/{} on {}",
            sized.easy,
            sized.window,
            space
        );
    }
}
