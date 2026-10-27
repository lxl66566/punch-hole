//! EasySym against EasySym prediction exchange.

use std::net::SocketAddr;

use super::StageSpec;
use crate::{
    config::PunchConfig,
    nat::{NatClass, NatInfo, PortPredictor},
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
    // The classifier step divides port deltas by send-index distance, so it
    // stays true over silent probe destinations. The wire sequence drops a
    // silent destination's port, and adjacent-delta fitting reads a gap as a
    // multiple of the step, so the fit stays as the fallback only.
    let predictor = match v4.class {
        NatClass::EasySym { step } => PortPredictor::with_step(&v4.alloc_seq, step)
            .or_else(|| PortPredictor::fit(&v4.alloc_seq))?,
        _ => PortPredictor::fit(&v4.alloc_seq)?,
    };
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use super::*;
    use crate::nat::{FilterClass, V4Nat};

    fn easy_peer(seq: &[u16], step: i16) -> NatInfo {
        NatInfo {
            v4: Some(V4Nat {
                class: NatClass::EasySym { step },
                // The reflexive port plays no role in prediction, so an
                // empty sequence still carries a valid address.
                reflexive: SocketAddrV4::new([203, 0, 113, 7].into(), 5000),
                alloc_seq: seq.to_vec(),
                filtering: FilterClass::Unknown,
            }),
            v6: None,
        }
    }

    /// Two silent probe destinations compress their ports out of the wire
    /// sequence: the adjacent-delta median of 4, 4, 2 reads four while the
    /// classifier step carries the true stride of two.
    #[test]
    fn gapped_sequence_predicts_with_the_classifier_step() {
        let peer = easy_peer(&[5000, 5004, 5008, 5010], 2);
        let stage = stage(8, &peer, 4, &PunchConfig::default()).expect("stage builds");
        let ports: Vec<u16> = stage.targets.iter().map(SocketAddr::port).collect();
        assert_eq!(ports, vec![5012, 5014, 5016, 5018]);
    }

    /// A class with a zero step falls back to the adjacent-delta fit.
    #[test]
    fn degenerate_class_step_falls_back_to_the_fit() {
        let peer = easy_peer(&[5000, 5002, 5004], 0);
        let stage = stage(8, &peer, 2, &PunchConfig::default()).expect("stage builds");
        let ports: Vec<u16> = stage.targets.iter().map(SocketAddr::port).collect();
        assert_eq!(ports, vec![5006, 5008]);
    }

    #[test]
    fn sequences_without_a_base_or_step_build_no_stage() {
        // No observation to anchor the window on.
        assert!(stage(8, &easy_peer(&[], 2), 4, &PunchConfig::default()).is_none());
        // No class step and too little sequence for the fallback fit.
        assert!(stage(8, &easy_peer(&[5000], 0), 4, &PunchConfig::default()).is_none());
    }

    /// One observation plus the classifier step already spans the window,
    /// which the adjacent-delta fit alone could never do.
    #[test]
    fn single_observation_predicts_from_the_class_step() {
        let peer = easy_peer(&[5000], 2);
        let stage = stage(8, &peer, 2, &PunchConfig::default()).expect("stage builds");
        let ports: Vec<u16> = stage.targets.iter().map(SocketAddr::port).collect();
        assert_eq!(ports, vec![5002, 5004]);
    }
}
