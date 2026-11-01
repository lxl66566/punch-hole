//! Probability models and sizing solves for the punch strategies.

use crate::{
    config::PunchConfig,
    nat::{FilterClass, NatInfo},
};

/// Widening multiplier on the unbiased per-side extension of a span.
///
/// An unbiased width is not the honest rate input: a span estimate that
/// overshoots is modeled exactly, because candidates spread over the
/// estimate hit live mappings with probability 1/estimate per pair, while
/// an undershoot is optimistic by the coverage ratio. Doubling the
/// extension lands the estimate above the true span about nine runs in
/// ten at four samples (`r/S` is Beta(k-1, 2), so
/// `P[S <= r * (1 + 4/(k-1))] = 1 - F(3/7) ~ 0.89`), which leaves only
/// the thin undershoot tail optimistic.
const SPAN_CONFIDENCE: u16 = 2;

/// The port span a symmetric peer draws from, estimated from its probe.
///
/// `k` uniform samples over a span of width `S` show an expected range of
/// `S * (k - 1) / (k + 1)`, so the observed range widened by
/// `SPAN_CONFIDENCE * range / (k - 1)` on each side reads as an
/// upper-confidence estimate of `S`. One shared estimate feeds the
/// probability model and candidate sampling alike, so estimation and
/// sampling stay equally conservative. Fewer than two samples carry no
/// range at all, so the estimate falls back to the upper ephemeral half,
/// the range most NAT families draw from.
pub(crate) fn span_estimate(seq: &[u16]) -> (u16, u16) {
    const FALLBACK_LO: u16 = 32_768;
    if seq.len() < 2 {
        return (FALLBACK_LO, u16::MAX);
    }
    let min = *seq.iter().min().expect("len checked");
    let max = *seq.iter().max().expect("len checked");
    let ext = (max - min) / (seq.len() - 1) as u16 * SPAN_CONFIDENCE;
    (min.saturating_sub(ext), max.saturating_add(ext))
}

/// The port space a symmetric peer's fresh mappings draw from: the width
/// of its estimated span.
pub(crate) fn peer_space(peer: &NatInfo) -> usize {
    let seq = peer.v4.as_ref().map_or(&[][..], |v4| &v4.alloc_seq);
    let (lo, hi) = span_estimate(seq);
    (usize::from(hi - lo) + 1).min(u16::MAX as usize + 1)
}

/// Chance that a one-directional spray hits: `c` covered distinct ports
/// against `m` live mappings drawn at random from `space` values.
pub(crate) fn spray_hit_chance(m: usize, c: usize, space: usize) -> f64 {
    if space == 0 {
        return 1.0;
    }
    let lambda = m as f64 * c as f64 / space as f64;
    1.0 - (-lambda).exp()
}

/// Coverage a birthday burst is sized for, one socket per side.
///
/// Direction A covers ports of B's space, so each coverage belongs to the
/// space it shoots into: `initiator_coverage` draws from the responder's
/// span and lands on the initiator's target list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BurstSize {
    pub initiator_coverage: usize,
    pub responder_coverage: usize,
}

/// Chance that two synchronized bursts pair up, by measured filtering
/// regime.
///
/// Under one non-port-strict side — the regime `Unknown` also reads as — a
/// hit into side X needs the peer's coverage to land on one of X's live
/// mappings, `coverage_peer * sockets_X * coverage_X / space_X` in
/// expectation. Sockets and coverage enter only as their product, so the
/// sizing spends every mapping on coverage and this model carries one
/// socket per side: the expected hits add up to
/// `c_i * c_r * (1/space_i + 1/space_r)`.
///
/// With both sides measured address-and-port-dependent, a hit also needs
/// the sender's source port to pair with the destination the receiver's
/// mapping wrote. Per direction that prices the coverage product once per
/// space, so the expected hits read
/// `c_i * c_r * (c_i + c_r) / (space_i * space_r)` — the quadratic regime
/// a bounded budget cannot buy, which the `min_success` bar rejects.
pub(crate) fn burst_hit_chance(
    sized: &BurstSize,
    space_i: usize,
    space_r: usize,
    filter_i: FilterClass,
    filter_r: FilterClass,
) -> f64 {
    if space_i == 0 || space_r == 0 {
        return 1.0;
    }
    let (c_i, c_r) = (
        sized.initiator_coverage as f64,
        sized.responder_coverage as f64,
    );
    let hits = if filter_i == FilterClass::AddressPortDependent
        && filter_r == FilterClass::AddressPortDependent
    {
        c_i * c_r * (c_i + c_r) / (space_i as f64 * space_r as f64)
    } else {
        c_i * c_r * (1.0 / space_i as f64 + 1.0 / space_r as f64)
    };
    1.0 - (-hits).exp()
}

/// Headroom between the sized burst and the conntrack bound: the peer's
/// replies arrive from a fresh mapping port outside the target list.
const BURST_MAPPING_HEADROOM: usize = 2;

/// The space a symmetric pair effectively plays over: one hit into either
/// side completes the handshake, so the two directional terms add and the
/// pair behaves like a single space of `1 / (1/a + 1/b)`.
fn effective_space(a: usize, b: usize) -> f64 {
    (a as f64) * (b as f64) / (a + b) as f64
}

/// Coverage per side for a target success rate.
///
/// Sockets and coverage contribute to the hit rate only through their
/// product `sockets * coverage` — the live-mapping count — and the
/// conntrack bound caps that product, so one socket per side already
/// reaches any burst the bound admits and the solve spends every mapping
/// on coverage. With one socket per side the requirement is
/// `c_i * c_r >= ln(1 / (1 - target)) * S_eff` over `S_eff =
/// effective_space(space_i, space_r)`, met by the balanced solve
/// `c = ceil(sqrt(required * S_eff))`. Each coverage caps at the space it
/// shoots into (there are no more ports to cover), the conntrack bound
/// minus reply headroom, and a packet budget share because every covered
/// port costs one packet per rotation.
pub(crate) fn size_burst(space_i: usize, space_r: usize, cfg: &PunchConfig) -> BurstSize {
    // Reaching the target needs c_i * c_r >= ln(1/(1-target)) * S_eff
    // expected-hit products, carried as an integer so the estimate can
    // verify the sizing exactly.
    let required = -(1.0 - cfg.target_success).ln() * effective_space(space_i, space_r);
    let need = if required.is_finite() { required.ceil().max(1.0) as usize } else { usize::MAX };
    let mapping_cap = cfg
        .max_mappings
        .saturating_sub(BURST_MAPPING_HEADROOM)
        .min(cfg.packet_budget as usize / SPRAY_BUDGET_SHARE)
        .max(1);
    let balanced = ((need as f64).sqrt().ceil() as usize).max(1);
    BurstSize {
        initiator_coverage: balanced.min(space_r.max(1)).min(mapping_cap),
        responder_coverage: balanced.min(space_i.max(1)).min(mapping_cap),
    }
}

/// Share of the packet budget a spray may spend. Retransmissions keep the
/// rest.
const SPRAY_BUDGET_SHARE: usize = 4;

/// Unrelated allocations a prediction window tolerates besides the peer's
/// own punch allocations.
pub(crate) const PREDICTION_SLACK: usize = 16;

/// Coverage pair for a PredictiveBurst, one socket per side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PredictiveSize {
    /// Distinct ports the easy side sprays at the hard peer.
    pub easy: usize,
    /// Continuation ports the hard side covers over the easy side's
    /// sequence: its live window plus slack.
    pub window: usize,
}

/// Sizes a PredictiveBurst against the hard side's space.
///
/// The easy side holds one mapping per covered port and an EasySym mapping
/// walks its constant step, so its live ports fill exactly the first
/// `easy` ports of the continuation window the hard side covers. The
/// random direction shoots the easy coverage at the hard side's `window`
/// live mappings, so the window feeds back into the live count and the
/// solve is `easy * (easy + PREDICTION_SLACK) = L * space` with `L` the
/// one-directional target. The quadratic's positive root feeds
/// `spray_count` as the live count, so the budget and conntrack caps bind
/// exactly as they do for every other spray.
pub(crate) fn size_predictive(space: usize, cfg: &PunchConfig) -> PredictiveSize {
    let target = -(1.0 - cfg.target_success).ln();
    let slack = PREDICTION_SLACK as f64;
    let root = ((slack * slack + 4.0 * target * space as f64).sqrt() - slack) / 2.0;
    let live = (root as usize).saturating_add(PREDICTION_SLACK);
    let easy = spray_count(live, space, cfg);
    PredictiveSize {
        easy,
        window: easy + PREDICTION_SLACK,
    }
}

/// The estimate PredictiveBurst reports: certainty under its stated
/// regime.
///
/// The hard side covers the easy side's whole continuation window, so
/// while the easy NAT keeps stepping from its last observed port — the
/// assumption PredictiveExchange also acts on — a window Syn is certain
/// to land on a live mapping once both rotations run, and the regime
/// tolerates up to a window width of unrelated allocations before the
/// live block slides out. The estimate states that regime the way the
/// burst arithmetic states its filtering assumption; the random direction
/// is sized for `target_success` of its own and is the quantified
/// fallback a regime break leaves, so `min_success` has no number to
/// gate here.
pub(super) fn predictive_burst_estimate() -> f64 {
    1.0
}

/// Upper bound on one sender's per-sweep burst.
///
/// A sweep shares its tick with event polling, signaling, and the
/// deadline check, so one socket cannot spend the whole tick inside the
/// rate limiter. Thirty-two packets per tick cap a lone sender at 640
/// pps at the default 50 ms tick, above the default 400 pps rate limit,
/// so the bound only binds configurations that rate faster than that.
const MAX_BURST: u16 = 32;

/// Candidate ports the cone side sprays at a HardSym peer.
///
/// Solves `P = 1 - exp(-m * c / space) = target_success` for `c`. The caps
/// keep handshake retransmissions inside the packet budget and the spray
/// inside the conntrack bound.
pub(crate) fn spray_count(m: usize, space: usize, cfg: &PunchConfig) -> usize {
    let budget_cap = (cfg.packet_budget as usize / SPRAY_BUDGET_SHARE).max(1);
    // The spray socket is the pool's only socket, so every destination is
    // one mapping. Besides the candidates themselves, the cone side opens
    // one destination for the STUN refresh server and one reply destination
    // per peer symmetric socket, because every SynAck returns from a fresh
    // peer port. The cap leaves room for all of them.
    let dest_cap = cfg.max_mappings.saturating_sub(m + 1).max(1);
    let need = -((1.0 - cfg.target_success).ln()) * space as f64 / m.max(1) as f64;
    (need.ceil() as usize).clamp(1, budget_cap.min(dest_cap))
}

/// Packets one sender emits per sweep, so a lone socket runs at the rate cap.
pub(crate) fn burst_len(cfg: &PunchConfig) -> u16 {
    let per_tick = f64::from(cfg.packets_per_sec) * cfg.tick.as_secs_f64();
    per_tick.ceil().clamp(1.0, f64::from(MAX_BURST)) as u16
}

/// Spans at most this multiple of the count take the full shuffle. The
/// multiple bounds the wasted allocation on the shuffle side, while past
/// it the shuffle would pay the whole span for a few dozen ports.
const SAMPLE_SPAN_MULTIPLE: usize = 8;

/// Safety multiple on the two socket counts for a PredictiveExchange
/// window. Each side allocates one mapping per (own socket, peer port)
/// pair its pulses cross, so the peer's punch block spans
/// `my_sockets * peer_sockets` allocations; the multiple absorbs the
/// retry rounds and unrelated allocations that land between the probe
/// base and the live block before the announced position re-bases the
/// window.
pub(super) const PREDICTION_WINDOW_MULTIPLE: usize = 4;

/// Cap on a PredictiveExchange window. The window is also the stage's
/// target list, and a cross product that ran past half the port range
/// would spend the whole packet budget on prediction targets before a
/// single sweep completed.
pub(super) const PREDICTION_WINDOW_CAP: usize = 512;

/// Distinct random ports over a span.
///
/// Distinct draws carry a model's coverage exactly, so every path draws
/// without replacement instead of sampling with replacement. Narrow
/// spans shuffle the whole range and truncate. Wide spans rejection-
/// sample straight into a set sized by the count, which drops the cost
/// from the span, up to 32768, to roughly one draw per port.
pub(crate) fn distinct_ports(seed: u64, lo: u16, hi: u16, count: usize) -> Vec<u16> {
    use rand::{prelude::*, rngs::StdRng};
    if hi < lo || count == 0 {
        return Vec::new();
    }
    let span = usize::from(hi - lo) + 1;
    let mut rng = StdRng::seed_from_u64(seed);
    if span <= count.saturating_mul(SAMPLE_SPAN_MULTIPLE) {
        let mut ports: Vec<u16> = (lo..=hi).collect();
        ports.shuffle(&mut rng);
        ports.truncate(count);
        return ports;
    }
    // A wide span redraws a taken port rarely, so rejection costs about
    // one draw per port. Membership lives in a set — the count can reach
    // the thousand-port budget share, where a linear scan per draw turns
    // quadratic — and the push order keeps the draw sequence, which
    // preserves the shuffled path's uniform order. The set answers the
    // same taken-or-free question the scan did, so a seed repeats its
    // exact output either way.
    let mut ports: Vec<u16> = Vec::with_capacity(count);
    let mut taken: std::collections::HashSet<u16> = std::collections::HashSet::with_capacity(count);
    while ports.len() < count {
        let port = rng.random_range(lo..=hi);
        if taken.insert(port) {
            ports.push(port);
        }
    }
    ports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::FilterClass::Unknown;

    #[test]
    fn spray_model_is_monotonic() {
        let base = spray_hit_chance(4, 8, 1000);
        assert!(base > 0.0);
        assert!(spray_hit_chance(8, 8, 1000) > base);
        assert!(spray_hit_chance(4, 16, 1000) > base);
        assert!(spray_hit_chance(4, 8, 500) > base);
    }

    #[test]
    fn burst_model_reads_each_directions_space() {
        let narrow_wide = BurstSize {
            initiator_coverage: 15,
            responder_coverage: 15,
        };
        // A 300 x 20000 pair: the directional terms add, so the same
        // coverage buys far more than a shared 20000-wide space would.
        let directional = burst_hit_chance(&narrow_wide, 300, 20_000, Unknown, Unknown);
        let shared = burst_hit_chance(&narrow_wide, 20_000, 20_000, Unknown, Unknown);
        assert!(directional > 0.5, "got {directional}");
        assert!(shared < 0.05, "got {shared}");
        // Sockets and coverage enter the model only as their product, so
        // splits of one product are interchangeable.
        let balanced = burst_hit_chance(
            &BurstSize {
                initiator_coverage: 16,
                responder_coverage: 16,
            },
            1000,
            1000,
            Unknown,
            Unknown,
        );
        let skewed = burst_hit_chance(
            &BurstSize {
                initiator_coverage: 32,
                responder_coverage: 8,
            },
            1000,
            1000,
            Unknown,
            Unknown,
        );
        assert!((balanced - skewed).abs() < 1e-12);
        // Dense bursts saturate toward certainty.
        let dense = burst_hit_chance(
            &BurstSize {
                initiator_coverage: 64,
                responder_coverage: 64,
            },
            8,
            8,
            Unknown,
            Unknown,
        );
        assert!(dense > 0.999);
    }

    #[test]
    fn burst_sizing_reaches_the_target() {
        let cfg = PunchConfig {
            max_sockets: 64,
            packet_budget: 4096,
            ..PunchConfig::default()
        };
        // Required products are ln(2) * 500 = 347 over the effective space
        // of two 1000-wide spans, solved by 19 covered ports per side
        // (19^2 = 361).
        let sized = size_burst(1000, 1000, &cfg);
        assert_eq!(
            (sized.initiator_coverage, sized.responder_coverage),
            (19, 19)
        );
        assert!(
            burst_hit_chance(&sized, 1000, 1000, Unknown, Unknown) >= cfg.target_success - 1e-9,
            "estimate {} under the target",
            burst_hit_chance(&sized, 1000, 1000, Unknown, Unknown)
        );
    }

    /// An asymmetric pair solves per direction: the narrow side's span caps
    /// the coverage that shoots into it, and the estimate still reaches the
    /// target without inflating the wide side.
    #[test]
    fn asymmetric_pairs_solve_per_direction() {
        let cfg = PunchConfig::default();
        let sized = size_burst(300, 20_000, &cfg);
        // ln(2) * effective_space(300, 20000) = ln(2) * 295.6 = 204.9,
        // solved by 15 covered ports per side.
        assert_eq!(
            (sized.initiator_coverage, sized.responder_coverage),
            (15, 15)
        );
        assert!(
            burst_hit_chance(&sized, 300, 20_000, Unknown, Unknown) >= cfg.target_success - 1e-9
        );
    }

    #[test]
    fn starved_bursts_go_unpunchable() {
        let cfg = PunchConfig {
            packet_budget: 100,
            ..PunchConfig::default()
        };
        // The budget share caps the mappings at 25, so both coverages clamp
        // to 25 and the estimate reports the starve honestly:
        // lambda = 25 * 25 * 2 / 32768 = 0.038.
        let space = 32_768;
        let sized = size_burst(space, space, &cfg);
        assert_eq!(
            (sized.initiator_coverage, sized.responder_coverage),
            (25, 25)
        );
        assert!(burst_hit_chance(&sized, space, space, Unknown, Unknown) < cfg.min_success);
    }

    #[test]
    fn tiny_spaces_solve_inside_the_span() {
        let cfg = PunchConfig::default();
        // A 132-wide span still offers 132 ports of coverage, so the
        // balanced solve of ln(2) * 66 = 46 products fits at 7 ports per
        // side with no cap binding.
        let sized = size_burst(132, 132, &cfg);
        assert_eq!((sized.initiator_coverage, sized.responder_coverage), (7, 7));
        assert!(burst_hit_chance(&sized, 132, 132, Unknown, Unknown) >= cfg.target_success - 1e-9);
        // A conntrack bound below the solve clamps both coverages and the
        // estimate states the shortfall instead of hiding it.
        let cfg = PunchConfig {
            max_mappings: 7,
            ..cfg
        };
        let sized = size_burst(132, 132, &cfg);
        assert_eq!((sized.initiator_coverage, sized.responder_coverage), (5, 5));
        assert!(burst_hit_chance(&sized, 132, 132, Unknown, Unknown) < cfg.target_success);
    }

    #[test]
    fn short_sequences_fall_back_to_the_upper_half() {
        assert_eq!(span_estimate(&[1234]), (32_768, u16::MAX));
        assert_eq!(span_estimate(&[]), (32_768, u16::MAX));
    }

    #[test]
    fn spans_widen_by_the_confidence_share() {
        // k samples of a uniform span of width S show an expected range of
        // S * (k - 1) / (k + 1), so twice range / (k - 1) per side reads as
        // an upper-confidence estimate: four samples of a 100-wide span
        // average a 60-wide range and widen to 60 + 2 * 40 = 140, above
        // the truth nine runs in ten.
        assert_eq!(
            span_estimate(&[30_000, 30_020, 30_060, 30_060]),
            (29_960, 30_100)
        );
        assert_eq!(span_estimate(&[30_000, 30_050, 30_100]), (29_900, 30_200));
        // Two samples stretch sixfold, the weakest evidence the formula
        // accepts.
        assert_eq!(span_estimate(&[10, 20]), (0, 40));
        // Saturation clips the extension at the port range.
        assert_eq!(span_estimate(&[65_500, 65_530]), (65_440, u16::MAX));
    }

    #[test]
    fn distinct_ports_stay_inside_the_span() {
        let ports = distinct_ports(7, 100, 108, 5);
        assert_eq!(ports.len(), 5);
        assert!(ports.iter().all(|p| (100..=108).contains(p)));
        // A shuffle of one span never repeats a port.
        let unique = distinct_ports(7, 100, 108, 9);
        let mut sorted = unique.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), unique.len());
    }

    #[test]
    fn wide_spans_sample_distinct_ports_deterministically() {
        // A span far past the shuffle threshold takes the rejection path.
        let drawn = distinct_ports(42, 30_000, 40_000, 40);
        // The same seed repeats the exact sequence.
        assert_eq!(drawn, distinct_ports(42, 30_000, 40_000, 40));
        assert!(drawn.iter().all(|p| (30_000..=40_000).contains(p)));
        let mut sorted = drawn.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), drawn.len());
        // A count past the span returns the whole span, either path.
        assert_eq!(distinct_ports(7, 100, 108, 20).len(), 9);
    }

    #[test]
    fn spray_count_reaches_the_target_when_unclamped() {
        let cfg = PunchConfig::default();
        let (m, space) = (16, 200);
        let c = spray_count(m, space, &cfg);
        // The default target is 0.5 and both caps stay far away.
        assert!(spray_hit_chance(m, c, space) >= cfg.target_success - 1e-9);
    }

    #[test]
    fn spray_count_respects_budget_and_conntrack_caps() {
        let cfg = PunchConfig {
            packet_budget: 40,
            target_success: 0.999,
            ..PunchConfig::default()
        };
        // 40 / 4 = 10 by budget; the conntrack bound stays far away.
        assert_eq!(spray_count(16, 30_000, &cfg), 10);
        // Two peer sockets plus the refresh server leave 6 - 3 = 3 slots
        // for candidates under a bound of 6.
        let cfg = PunchConfig {
            max_mappings: 6,
            ..cfg
        };
        assert_eq!(spray_count(2, 30_000, &cfg), 3);
        // A peer socket count that already fills the bound leaves the floor
        // of one candidate.
        assert_eq!(spray_count(16, 30_000, &cfg), 1);
    }
}
