//! Pure mapping classification from probe observations.

use super::NatClass;

/// Maps observed external ports to a mapping class.
///
/// `seq` holds the ports one socket observed, in send order, one entry per
/// distinct destination. `public` marks a reflexive address equal to the local
/// address.
#[must_use]
pub fn classify(public: bool, seq: &[u16]) -> NatClass {
    if public {
        return NatClass::Public;
    }
    // A single observation cannot separate mapping classes; assume the common
    // case and let confidence demotion handle the rest.
    if seq.len() < 2 {
        return NatClass::Cone;
    }
    if seq.windows(2).all(|w| w[0] == w[1]) {
        return NatClass::Cone;
    }
    match constant_step(seq) {
        Some(step) => NatClass::EasySym { step },
        None => NatClass::HardSym,
    }
}

/// Whether an EasySym fit rests on enough observations to be trusted.
///
/// Two consistent deltas can be coincidence. Selection demotes an untrusted
/// fit to HardSym before it picks a strategy.
#[must_use]
pub fn easy_confident(seq: &[u16]) -> bool {
    // seq.len() observations carry seq.len() - 1 deltas.
    seq.len() >= 4
}

/// The constant delta between consecutive observations, when there is one.
fn constant_step(seq: &[u16]) -> Option<i16> {
    let first = i32::from(seq[1]) - i32::from(seq[0]);
    // A step that leaves the u16 port range cannot repeat, so it is noise.
    if first == 0 || first.unsigned_abs() > u32::from(u16::MAX) {
        return None;
    }
    let fits = seq
        .windows(2)
        .all(|w| i32::from(w[1]) - i32::from(w[0]) == first);
    fits.then_some(first as i16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_equal_ports_are_cone() {
        assert_eq!(classify(false, &[5000, 5000, 5000, 5000]), NatClass::Cone);
    }

    #[test]
    fn constant_positive_step_is_easy() {
        assert_eq!(
            classify(false, &[5000, 5002, 5004, 5006]),
            NatClass::EasySym { step: 2 }
        );
    }

    #[test]
    fn constant_negative_step_is_easy() {
        assert_eq!(
            classify(false, &[5006, 5005, 5004, 5003]),
            NatClass::EasySym { step: -1 }
        );
    }

    #[test]
    fn inconsistent_steps_are_hard() {
        assert_eq!(
            classify(false, &[5000, 5002, 5005, 5009]),
            NatClass::HardSym
        );
        assert_eq!(
            classify(false, &[5000, 5678, 12345, 60000]),
            NatClass::HardSym
        );
    }

    #[test]
    fn matching_reflexive_is_public() {
        assert_eq!(classify(true, &[5000, 5000]), NatClass::Public);
        assert_eq!(classify(true, &[5000, 6000]), NatClass::Public);
    }

    #[test]
    fn short_sequences_stay_cone() {
        assert_eq!(classify(false, &[5000]), NatClass::Cone);
        assert_eq!(classify(false, &[]), NatClass::Cone);
    }

    #[test]
    fn confidence_needs_three_deltas() {
        assert!(!easy_confident(&[5000, 5002, 5004]));
        assert!(easy_confident(&[5000, 5002, 5004, 5006]));
    }
}
