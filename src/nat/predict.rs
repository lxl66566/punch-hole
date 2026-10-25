//! Pure fitting and prediction of port allocation sequences.

/// A linear fit over an observed allocation sequence.
///
/// The fit takes the median of the deltas as the step, so single outliers do
/// not break the prediction. The base is the last observed port.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PortPredictor {
    base: u16,
    step: i16,
}

impl PortPredictor {
    /// Fits `seq` as a linear sequence. Returns `None` when the sequence is
    /// constant or too short to carry a step.
    #[must_use]
    pub fn fit(seq: &[u16]) -> Option<Self> {
        if seq.len() < 2 {
            return None;
        }
        let step = median_delta(seq);
        if step == 0 {
            return None;
        }
        Some(Self {
            base: seq[seq.len() - 1],
            step,
        })
    }

    #[must_use]
    pub fn step(&self) -> i16 {
        self.step
    }

    /// The next `count` ports the NAT is expected to allocate.
    #[must_use]
    pub fn window(&self, count: usize) -> Vec<u16> {
        (1..=count).map(|i| self.at(i)).collect()
    }

    /// The port `offset` allocations past the last observation, clamped to the
    /// valid port range.
    #[must_use]
    pub fn at(&self, offset: usize) -> u16 {
        let v = i32::from(self.base) + i32::from(self.step) * offset as i32;
        v.clamp(0, i32::from(u16::MAX)) as u16
    }
}

/// The median delta, which tolerates outliers better than any single delta.
fn median_delta(seq: &[u16]) -> i16 {
    let mut deltas: Vec<i32> = seq
        .windows(2)
        .map(|w| i32::from(w[1]) - i32::from(w[0]))
        .collect();
    deltas.sort_unstable();
    deltas[deltas.len() / 2] as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fits_a_clean_sequence() {
        let p = PortPredictor::fit(&[5000, 5002, 5004, 5006]).unwrap();
        assert_eq!(p.step(), 2);
        assert_eq!(p.base, 5006);
        assert_eq!(p.at(1), 5008);
        assert_eq!(p.at(3), 5012);
    }

    #[test]
    fn windows_continue_the_sequence() {
        let p = PortPredictor::fit(&[5000, 4999, 4998]).unwrap();
        assert_eq!(p.window(3), vec![4997, 4996, 4995]);
    }

    #[test]
    fn median_ignores_outliers() {
        // The delta 9000 is noise; the median of [2, 9000, 2, 2] is 2.
        let p = PortPredictor::fit(&[5000, 5002, 14002, 14004, 14006]).unwrap();
        assert_eq!(p.step(), 2);
    }

    #[test]
    fn constant_or_short_sequences_do_not_fit() {
        assert!(PortPredictor::fit(&[5000]).is_none());
        assert!(PortPredictor::fit(&[]).is_none());
        assert!(PortPredictor::fit(&[5000, 5000, 5000]).is_none());
    }

    #[test]
    fn prediction_clamps_at_the_port_range() {
        let p = PortPredictor::fit(&[65530, 65533]).unwrap();
        assert_eq!(p.at(1), 65535);
        assert_eq!(p.at(10), 65535);
        let p = PortPredictor::fit(&[4, 2]).unwrap();
        assert_eq!(p.at(10), 0);
    }
}
