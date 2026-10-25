//! Pure mapping classification from probe observations.

use super::NatClass;

/// Maps observed external ports to a mapping class.
///
/// `obs` holds `(send index, port)` pairs in send order, one entry per
/// destination that answered. A gap between two send indexes marks a
/// destination that stayed silent: the NAT allocated a port there that no
/// server reported. `public` marks a reflexive address equal to the local
/// address.
#[must_use]
pub fn classify(public: bool, obs: &[(usize, u16)]) -> NatClass {
    if public {
        return NatClass::Public;
    }
    // A single observation cannot separate mapping classes; assume the common
    // case and let confidence demotion handle the rest.
    if obs.len() < 2 {
        return NatClass::Cone;
    }
    if obs.windows(2).all(|w| w[0].1 == w[1].1) {
        return NatClass::Cone;
    }
    match constant_step(obs) {
        Some(step) => NatClass::EasySym { step },
        None => NatClass::HardSym,
    }
}

/// Whether an EasySym fit rests on enough observations to be trusted.
///
/// Two consistent deltas can be coincidence. Selection demotes an untrusted
/// fit to HardSym before it picks a strategy. The input is the wire
/// `alloc_seq`, which carries the answered samples only.
#[must_use]
pub fn easy_confident(seq: &[u16]) -> bool {
    // seq.len() observations carry seq.len() - 1 deltas.
    seq.len() >= 4
}

/// The constant delta per allocation between consecutive observations, when
/// there is one.
///
/// A hole between two observations spans several allocations, so the delta
/// divides by the send-index distance. A nonzero remainder, or two spans
/// that disagree on the quotient, means no constant step fits.
fn constant_step(obs: &[(usize, u16)]) -> Option<i16> {
    let per_allocation = |a: &(usize, u16), b: &(usize, u16)| -> Option<i32> {
        let dist = (b.0 - a.0) as i32;
        let delta = i32::from(b.1) - i32::from(a.1);
        (delta % dist == 0).then_some(delta / dist)
    };
    let first = per_allocation(&obs[0], &obs[1])?;
    // A step beyond the i16 range cannot repeat inside the u16 ports.
    if first == 0 || first.abs() > i32::from(i16::MAX) {
        return None;
    }
    let fits = obs
        .windows(2)
        .all(|w| per_allocation(&w[0], &w[1]) == Some(first));
    fits.then_some(first as i16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Observations for a fully answered probe: one port per send index.
    fn obs(ports: &[u16]) -> Vec<(usize, u16)> {
        ports
            .iter()
            .enumerate()
            .map(|(idx, port)| (idx, *port))
            .collect()
    }

    #[test]
    fn all_equal_ports_are_cone() {
        assert_eq!(
            classify(false, &obs(&[5000, 5000, 5000, 5000])),
            NatClass::Cone
        );
    }

    #[test]
    fn constant_positive_step_is_easy() {
        assert_eq!(
            classify(false, &obs(&[5000, 5002, 5004, 5006])),
            NatClass::EasySym { step: 2 }
        );
    }

    #[test]
    fn constant_negative_step_is_easy() {
        assert_eq!(
            classify(false, &obs(&[5006, 5005, 5004, 5003])),
            NatClass::EasySym { step: -1 }
        );
    }

    #[test]
    fn inconsistent_steps_are_hard() {
        assert_eq!(
            classify(false, &obs(&[5000, 5002, 5005, 5009])),
            NatClass::HardSym
        );
        assert_eq!(
            classify(false, &obs(&[5000, 5678, 12345, 60000])),
            NatClass::HardSym
        );
    }

    #[test]
    fn matching_reflexive_is_public() {
        assert_eq!(classify(true, &obs(&[5000, 5000])), NatClass::Public);
        assert_eq!(classify(true, &obs(&[5000, 6000])), NatClass::Public);
    }

    #[test]
    fn short_sequences_stay_cone() {
        assert_eq!(classify(false, &obs(&[5000])), NatClass::Cone);
        assert_eq!(classify(false, &[]), NatClass::Cone);
    }

    #[test]
    fn one_hole_keeps_a_constant_step() {
        // Send index 2 stayed silent; the ports still walk +2 per allocation.
        assert_eq!(
            classify(false, &[(0, 5000), (1, 5002), (3, 5006)]),
            NatClass::EasySym { step: 2 }
        );
    }

    #[test]
    fn several_holes_keep_a_constant_step() {
        assert_eq!(
            classify(false, &[(0, 5000), (2, 5004), (5, 5010)]),
            NatClass::EasySym { step: 2 }
        );
    }

    #[test]
    fn holes_that_disagree_are_hard() {
        // Index 1 to 3 spans two allocations but adds seven, which no
        // constant per-allocation step explains.
        assert_eq!(
            classify(false, &[(0, 5000), (1, 5002), (3, 5009)]),
            NatClass::HardSym
        );
    }

    #[test]
    fn confidence_needs_three_deltas() {
        assert!(!easy_confident(&[5000, 5002, 5004]));
        assert!(easy_confident(&[5000, 5002, 5004, 5006]));
    }
}
