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
    /// Fits `seq` as a linear sequence. Returns `None` when the sequence
    /// is constant or carries fewer than three deltas: the median of one
    /// or two deltas is a single delta, so one outlier would decide the
    /// step. Three deltas match the confidence bar the classifier sets
    /// before it trusts an `EasySym` fit.
    #[must_use]
    pub fn fit(seq: &[u16]) -> Option<Self> {
        if seq.len() < 4 {
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

    /// Continues `seq` from its last port with a step derived outside the
    /// observed deltas, such as the classifier's send-index distance, which
    /// a silent probe destination cannot compress. Returns `None` when the
    /// sequence carries no base or the step is zero.
    #[must_use]
    pub fn with_step(seq: &[u16], step: i16) -> Option<Self> {
        if seq.is_empty() || step == 0 {
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
    ///
    /// The walk stops at the port range boundary: past it the next port
    /// depends on where the NAT rebinds, which no observation constrains,
    /// and a clamped stand-in would repeat one port at the boundary. The
    /// step is nonzero, so every emitted port is distinct and consecutive
    /// entries sit exactly one step apart in the plain port domain, which
    /// is the stride a re-based window reads back.
    #[must_use]
    pub fn window(&self, count: usize) -> Vec<u16> {
        let mut out = Vec::with_capacity(count);
        for i in 1..=count {
            let v = i32::from(self.base) + i32::from(self.step) * i as i32;
            if !(1..=i32::from(u16::MAX)).contains(&v) {
                break;
            }
            out.push(v as u16);
        }
        out
    }

    /// The port `offset` allocations past the last observation, clamped to
    /// the assignable port range `1..=65535`. Port 0 is never assignable,
    /// so the floor sits at one.
    #[must_use]
    pub fn at(&self, offset: usize) -> u16 {
        let v = i32::from(self.base) + i32::from(self.step) * offset as i32;
        v.clamp(1, i32::from(u16::MAX)) as u16
    }
}

/// The median delta, which tolerates outliers better than any single delta.
///
/// An even count takes the upper median: the step must stay an integer, and
/// at the three-delta minimum an exact tie between the two middles is one
/// draw in three, cheap enough that rounding up beats averaging.
fn median_delta(seq: &[u16]) -> i16 {
    let mut deltas: Vec<i16> = seq
        .windows(2)
        .map(|w| wrap_step(i32::from(w[1]) - i32::from(w[0])))
        .collect();
    deltas.sort_unstable();
    deltas[deltas.len() / 2]
}

/// The signed step a raw port delta represents, normalized into the signed
/// 16-bit wrap domain, so a jump across the port boundary ranks as the
/// signed step it represents instead of a large positive value.
fn wrap_step(delta: i32) -> i16 {
    ((delta + 32_768).rem_euclid(65_536) - 32_768) as i16
}

/// Shifts a constant-stride window so it continues from `fresh` instead of
/// the base it was fitted on.
///
/// The window's own first two ports carry its stride, so the shift moves
/// every port by the wrap-domain distance between the two bases. Returns
/// `None` for windows without a readable stride, which no predicted window
/// is. A fresh base from a later observation supersedes the fitted one,
/// because unrelated allocations behind the same NAT move the whole
/// sequence forward.
#[must_use]
pub(crate) fn rebased_window(window: &[u16], fresh: u16) -> Option<Vec<u16>> {
    if window.len() < 2 {
        return None;
    }
    let step = wrap_step(i32::from(window[1]) - i32::from(window[0]));
    if step == 0 {
        return None;
    }
    let base = window[0].wrapping_sub(step as u16);
    let shift = fresh.wrapping_sub(base);
    Some(window.iter().map(|p| p.wrapping_add(shift)).collect())
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
        let p = PortPredictor::fit(&[5000, 4999, 4998, 4997]).unwrap();
        assert_eq!(p.window(3), vec![4996, 4995, 4994]);
    }

    #[test]
    fn median_ignores_outliers() {
        // The delta 9000 is noise; the median of [2, 9000, 2, 2] is 2.
        let p = PortPredictor::fit(&[5000, 5002, 14002, 14004, 14006]).unwrap();
        assert_eq!(p.step(), 2);
    }

    #[test]
    fn constant_or_short_sequences_do_not_fit() {
        assert!(PortPredictor::fit(&[5000, 5002, 5004]).is_none());
        assert!(PortPredictor::fit(&[5000, 5002]).is_none());
        assert!(PortPredictor::fit(&[5000]).is_none());
        assert!(PortPredictor::fit(&[]).is_none());
        assert!(PortPredictor::fit(&[5000, 5000, 5000, 5000]).is_none());
    }

    /// Two deltas are one delta short of a majority: with [2, 9000] the
    /// upper median hands the outlier the win, so the fit refuses instead.
    #[test]
    fn two_deltas_never_decide_the_step() {
        assert!(PortPredictor::fit(&[5000, 5002, 14002]).is_none());
    }

    #[test]
    fn prediction_clamps_at_the_port_range() {
        let p = PortPredictor::fit(&[65521, 65524, 65527, 65530]).unwrap();
        assert_eq!(p.at(1), 65533);
        assert_eq!(p.at(2), 65535);
        assert_eq!(p.at(10), 65535);
        let p = PortPredictor::fit(&[20, 14, 8, 2]).unwrap();
        assert_eq!(p.at(1), 1);
        assert_eq!(p.at(10), 1);
    }

    /// A window stops at the range boundary instead of repeating a clamped
    /// port: past the boundary the next port depends on where the NAT
    /// rebinds, which no observation constrains.
    #[test]
    fn windows_stop_at_the_port_range_boundary() {
        let p = PortPredictor::fit(&[65521, 65524, 65527, 65530]).unwrap();
        // One in-range continuation, then the walk leaves the range.
        assert_eq!(p.window(4), vec![65533]);
        let p = PortPredictor::fit(&[65524, 65527, 65530, 65533]).unwrap();
        assert_eq!(p.window(3), Vec::<u16>::new());
        let p = PortPredictor::fit(&[20, 14, 8, 2]).unwrap();
        // The descending walk leaves through the floor just the same.
        assert_eq!(p.window(3), Vec::<u16>::new());
    }

    #[test]
    fn wrap_around_deltas_yield_the_signed_step() {
        // Raw deltas 2, 2, -2, 2 with the wrap written as 65534: the median
        // of the normalized deltas stays -2 and the fit continues below the
        // last observed port.
        let p = PortPredictor::fit(&[5, 3, 1, 65535, 65533]).unwrap();
        assert_eq!(p.step(), -2);
        assert_eq!(p.at(1), 65531);
    }

    #[test]
    fn wrap_deltas_sort_in_the_signed_domain() {
        // Raw deltas 100, 65300, 30: the wrap delta is -236 once normalized,
        // so it ranks below the small deltas and the median is 30 instead of
        // the pre-normalization median 100.
        let p = PortPredictor::fit(&[100, 200, 65500, 65530]).unwrap();
        assert_eq!(p.step(), 30);
    }

    #[test]
    fn with_step_continues_from_the_last_port() {
        // The classifier fit a step of 2 over send-index distances, while
        // the adjacent deltas over this gapped sequence are 4, 4, 2.
        let p = PortPredictor::with_step(&[5000, 5004, 5008, 5010], 2).unwrap();
        assert_eq!(p.step(), 2);
        assert_eq!(p.at(1), 5012);
        assert_eq!(p.window(3), vec![5012, 5014, 5016]);
    }

    #[test]
    fn with_step_rejects_empty_sequences_and_zero_steps() {
        assert!(PortPredictor::with_step(&[], 2).is_none());
        assert!(PortPredictor::with_step(&[5000, 5002], 0).is_none());
    }

    #[test]
    fn rebased_window_continues_from_the_fresh_port() {
        // The window walks +2 from a base of 5010; a fresh base of 6000
        // moves every port by the distance between the two bases.
        let window = [5012, 5014, 5016, 5018];
        assert_eq!(rebased_window(&window, 6000).expect("stride reads"), vec![
            6002, 6004, 6006, 6008
        ]);
        // A negative stride rebases the same way.
        let window = [5010, 5008, 5006];
        assert_eq!(rebased_window(&window, 6000).expect("stride reads"), vec![
            5998, 5996, 5994
        ]);
    }

    #[test]
    fn rebased_window_wraps_through_the_port_boundary() {
        let window = [65530, 65532];
        // The fresh base wraps past the top of the port range.
        assert_eq!(rebased_window(&window, 2).expect("stride reads"), vec![
            4, 6
        ]);
    }

    #[test]
    fn rebased_window_rejects_windows_without_a_stride() {
        assert!(rebased_window(&[5000], 6000).is_none());
        assert!(rebased_window(&[], 6000).is_none());
        assert!(rebased_window(&[5000, 5000], 6000).is_none());
    }
}
