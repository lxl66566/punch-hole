//! Strategy selection, burst sizing, and the shared punch engine.

mod birthday;
mod cone;
mod direct;
mod easy_sym;
mod predictive_burst;
mod sym_cone;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use crate::{
    config::PunchConfig,
    error::{Phase, PunchError},
    msg::{DataPacket, DecodeError, Frame, Nonce, StrategyId, decode_packet, encode_packet},
    nat::{NatClass, NatInfo, classify::easy_confident},
    signaling::SigIo,
    socket::{Family, SocketPool, UdpFactory, UdpIo},
};

/// The plan the Initiator derived, sized per role.
pub(crate) struct Selection {
    pub strategy: StrategyId,
    pub initiator_sockets: u16,
    pub responder_sockets: u16,
    /// The success model's estimate, when the strategy carries one.
    pub estimate: Option<f64>,
}

impl Selection {
    /// Fills the model estimate over the local view of both NATs.
    ///
    /// The Offer carries no estimate, so the Responder rebuilds it with the
    /// same functions the Initiator used, which keeps both reports equal.
    pub(crate) fn fill_estimate(&mut self, mine: &NatInfo, peer: &NatInfo, cfg: &PunchConfig) {
        if self.estimate.is_some() {
            return;
        }
        self.estimate = match self.strategy {
            StrategyId::SymProbe => {
                // A pair routed here with no symmetric side came from a
                // low-confidence cone reading: success then rests on the
                // ambiguous NAT's inbound filtering, which the probe does
                // not measure, so no number is stated.
                let either_symmetric =
                    is_symmetric(effective_class(mine)) || is_symmetric(effective_class(peer));
                either_symmetric.then(|| sym_probe_estimate(mine, peer, self, cfg))
            },
            StrategyId::BirthdayBurst => {
                let (space_i, space_r) = (peer_space(mine), peer_space(peer));
                let sized = size_burst(space_i, space_r, cfg);
                Some(burst_hit_chance(&sized, space_i, space_r))
            },
            StrategyId::PredictiveBurst => Some(predictive_burst_estimate()),
            _ => None,
        };
    }
}

/// The mapping class after confidence demotion.
///
/// An EasySym fit without three consistent deltas is treated as HardSym by
/// every decision from here on. A side without IPv4 evidence has no IPv4
/// mapping behavior to read, and the matrix treats it as the non-symmetric
/// case; every stage builder then refuses for lack of a peer reflexive
/// address, so a pair with no IPv4 path on either side and no IPv6
/// addresses runs idle to its punch deadline instead of mistaking the
/// absence for a public path.
pub(crate) fn effective_class(info: &NatInfo) -> NatClass {
    let seq = info.v4.as_ref().map_or(&[][..], |v4| &v4.alloc_seq);
    match info.v4_class() {
        Some(NatClass::EasySym { .. }) if !easy_confident(seq) => NatClass::HardSym,
        other => other.unwrap_or(NatClass::Public),
    }
}

/// Whether a class reading separates cone from symmetric behavior.
///
/// A symmetric reading shows differing ports, which already proves the
/// mapping dimension was exercised. A cone reading shows identical ports,
/// which an address-dependent NAT also produces when the whole fan-out
/// crossed one mapping — the case of a single answered IP — and a single
/// answered sample says nothing either way. Public compares the reflexive
/// address with the local one and carries its own proof.
pub(crate) fn cone_confident(info: &NatInfo) -> bool {
    match info.v4_class() {
        Some(NatClass::Cone) => {
            let v4 = info.v4.as_ref().expect("a cone reading owns v4 evidence");
            v4.distinct_probe_ips >= 2 && v4.alloc_seq.len() >= 2
        },
        _ => true,
    }
}

/// Whether the initiator of a SymProbe pair holds the shooter sockets,
/// from the initiator's own view.
///
/// The symmetric side shoots. A pair routed here with no symmetric side
/// comes from a low-confidence cone reading, and the ambiguous side
/// shoots; with both readings ambiguous the responder shoots, a
/// deterministic pick that keeps one shooter when the peer's view cannot
/// break the tie.
fn initiator_shoots(mine: &NatInfo, peer: &NatInfo) -> bool {
    let mine_symmetric = is_symmetric(effective_class(mine));
    let peer_symmetric = is_symmetric(effective_class(peer));
    if mine_symmetric != peer_symmetric {
        return mine_symmetric;
    }
    !cone_confident(mine) && cone_confident(peer)
}

/// Applies the selection matrix to both classes.
pub(crate) fn select(
    mine: &NatInfo,
    peer: &NatInfo,
    cfg: &PunchConfig,
) -> Result<Selection, PunchError> {
    let mine_class = effective_class(mine);
    let peer_class = effective_class(peer);
    let i_am_symmetric = is_symmetric(mine_class);
    let peer_is_symmetric = is_symmetric(peer_class);

    if !i_am_symmetric && !peer_is_symmetric {
        if cone_confident(mine) && cone_confident(peer) {
            // Cone against cone, or public against either: one socket per
            // side aimed at the reflexive address.
            return Ok(Selection {
                strategy: StrategyId::ConeExchange,
                initiator_sockets: 1,
                responder_sockets: 1,
                estimate: None,
            });
        }
        // A cone reading from a single-IP fan-out or a single sample may
        // be an address-dependent symmetric NAT seen through one mapping,
        // and ConeExchange fails against that reading. SymProbe's shooter
        // shape survives either truth, because the shooter's sockets punch
        // whether the ambiguous side turns out to be a cone or symmetric.
        let shooter = cfg.assistant_sockets;
        let (initiator_sockets, responder_sockets) = if initiator_shoots(mine, peer) {
            (shooter, 1)
        } else {
            (1, shooter)
        };
        let mut sel = Selection {
            strategy: StrategyId::SymProbe,
            initiator_sockets,
            responder_sockets,
            estimate: None,
        };
        sel.fill_estimate(mine, peer, cfg);
        // The same bar BirthdayBurst faces: a spray capped by budget or
        // conntrack below min_success would burn the whole punch window on
        // a near miss, so Negotiate refuses the pair before any socket
        // opens.
        if sel.estimate.is_some_and(|est| est < cfg.min_success) {
            return Err(PunchError::Unpunchable {
                local: mine_class,
                peer: peer_class,
            });
        }
        return Ok(sel);
    }
    if i_am_symmetric != peer_is_symmetric {
        // Exactly one side is symmetric; that side shoots, the other replies.
        let shooter = cfg.assistant_sockets;
        let (initiator_sockets, responder_sockets) = if i_am_symmetric {
            (shooter, 1)
        } else {
            (1, shooter)
        };
        let mut sel = Selection {
            strategy: StrategyId::SymProbe,
            initiator_sockets,
            responder_sockets,
            estimate: None,
        };
        sel.fill_estimate(mine, peer, cfg);
        // The same bar BirthdayBurst faces: a spray capped by budget or
        // conntrack below min_success would burn the whole punch window on
        // a near miss, so Negotiate refuses the pair before any socket
        // opens.
        if sel.estimate.is_some_and(|est| est < cfg.min_success) {
            return Err(PunchError::Unpunchable {
                local: mine_class,
                peer: peer_class,
            });
        }
        return Ok(sel);
    }
    match (mine_class, peer_class) {
        (NatClass::EasySym { .. }, NatClass::EasySym { .. }) => Ok(Selection {
            strategy: StrategyId::PredictiveExchange,
            initiator_sockets: cfg.predictive_sockets,
            responder_sockets: cfg.predictive_sockets,
            estimate: None,
        }),
        // One predictable side is enough: the side facing the easy peer
        // aims its continuation window, the side facing the hard peer
        // keeps its random spray, and either direction completes the
        // handshake. A demoted easy fit lands here with its confident
        // peer, so the predictable side still gets used instead of a
        // birthday attack against it.
        (NatClass::EasySym { .. }, NatClass::HardSym)
        | (NatClass::HardSym, NatClass::EasySym { .. }) => Ok(Selection {
            strategy: StrategyId::PredictiveBurst,
            initiator_sockets: 1,
            responder_sockets: 1,
            estimate: Some(predictive_burst_estimate()),
        }),
        _ => {
            // The probe cannot read a symmetric peer's filtering class, so
            // the estimate assumes address-dependent filtering, the common
            // CGNAT shape; `burst_hit_chance` states what that costs.
            let (space_i, space_r) = (peer_space(mine), peer_space(peer));
            let sized = size_burst(space_i, space_r, cfg);
            let estimate = burst_hit_chance(&sized, space_i, space_r);
            if estimate < cfg.min_success {
                return Err(PunchError::Unpunchable {
                    local: mine_class,
                    peer: peer_class,
                });
            }
            Ok(Selection {
                strategy: StrategyId::BirthdayBurst,
                initiator_sockets: 1,
                responder_sockets: 1,
                estimate: Some(estimate),
            })
        },
    }
}

/// Whether the Direct stage runs before the matrix strategy.
///
/// Direct runs when both sides reported global IPv6 addresses, or when both
/// IPv4 paths are public.
pub(crate) fn direct_first(mine: &NatInfo, peer: &NatInfo, cfg: &PunchConfig) -> bool {
    let both_v6 = cfg.ipv6
        && mine.v6.as_ref().is_some_and(|v6| !v6.addrs.is_empty())
        && peer.v6.as_ref().is_some_and(|v6| !v6.addrs.is_empty());
    // A public path is an observed claim, so a side without IPv4 evidence
    // never qualifies: its v4 Direct stage would have skipped itself for
    // lack of a reflexive address anyway.
    let both_public = matches!(
        (mine.v4_class(), peer.v4_class()),
        (Some(NatClass::Public), Some(NatClass::Public))
    );
    both_v6 || both_public
}

fn is_symmetric(class: NatClass) -> bool {
    matches!(class, NatClass::EasySym { .. } | NatClass::HardSym)
}

/// Whether a peer-signaled IPv6 address can carry punch traffic.
///
/// The shared `nat::usable_v6` predicate also governs the probe's own v6
/// collection, so an address this filter admits is the same kind of
/// address a probe would have collected.
fn usable_peer_v6(ip: Ipv6Addr) -> bool {
    crate::nat::usable_v6(ip)
}

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

/// Chance that two synchronized bursts pair up under address-dependent
/// filtering, the regime selection assumes for a symmetric pair.
///
/// A hit into side X needs the peer's coverage to land on one of X's live
/// mappings, `coverage_peer * sockets_X * coverage_X / space_X` in
/// expectation. Sockets and coverage enter only as their product, so the
/// sizing spends every mapping on coverage and this model carries one
/// socket per side: the expected hits add up to
/// `c_i * c_r * (1/space_i + 1/space_r)`. A probe cannot read a symmetric
/// peer's filtering class, so the estimate states this regime instead of
/// measuring it. Port-strict filtering needs both directions to pair
/// exactly, which lands near `(c_i * c_r)^2 / (space_i * space_r)` and
/// stays negligible at any bounded budget.
pub(crate) fn burst_hit_chance(sized: &BurstSize, space_i: usize, space_r: usize) -> f64 {
    if space_i == 0 || space_r == 0 {
        return 1.0;
    }
    let hits = sized.initiator_coverage as f64 * sized.responder_coverage as f64;
    1.0 - (-hits * (1.0 / space_i as f64 + 1.0 / space_r as f64)).exp()
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
    let need = if required.is_finite() {
        required.ceil().max(1.0) as usize
    } else {
        usize::MAX
    };
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
fn predictive_burst_estimate() -> f64 {
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
const PREDICTION_WINDOW_MULTIPLE: usize = 4;

/// Cap on a PredictiveExchange window. The window is also the stage's
/// target list, and a cross product that ran past half the port range
/// would spend the whole packet budget on prediction targets before a
/// single sweep completed.
const PREDICTION_WINDOW_CAP: usize = 512;

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

/// SymProbe's hit chance from the one-directional spray model.
///
/// The cone side covers `c` candidate ports inside the symmetric peer's port
/// space, where the peer holds `m` live mappings, so the one-directional
/// formula gives the chance.
fn sym_probe_estimate(mine: &NatInfo, peer: &NatInfo, sel: &Selection, cfg: &PunchConfig) -> f64 {
    // Exactly one side is symmetric, and it holds the shooter count, which is
    // the larger of the two socket counts.
    let sym = if is_symmetric(effective_class(mine)) {
        mine
    } else {
        peer
    };
    let m = sel.initiator_sockets.max(sel.responder_sockets) as usize;
    let space = peer_space(sym);
    let c = spray_count(m, space, cfg);
    spray_hit_chance(m, c, space)
}

/// How a side learns the fresh external port of its punch socket.
///
/// The reflexive address from Probe belongs to the closed probe socket, so
/// strategies that aim at a fixed peer port need fresh ports from both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refresh {
    /// Nothing to announce; the strategy targets predicted or burst ports.
    None,
    /// The socket address is its own address, so the local port is the fact.
    Local,
    /// A STUN query on the punch socket yields the fresh mapped port.
    Stun,
}

/// Fresh own ports to announce over signaling, one slot per family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PortAnnounce {
    pub v4: Option<u16>,
    pub v6: Option<u16>,
}
/// One execution stage on one family.
// The four booleans are independent pulse policies a stage mixes freely,
// not states of one axis, so they stay flags.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct StageSpec {
    pub family: Family,
    pub duration: Duration,
    /// Sockets the pool binds for this stage.
    pub bind: usize,
    /// Sockets that emit Syn pulses.
    pub senders: u16,
    pub targets: Vec<SocketAddr>,
    /// A listen-and-reply stage sends nothing on its own.
    pub reply_only: bool,
    /// Sweeps wait for the peer's PortUpdate, because the built-in targets
    /// name the peer's dead probe socket.
    pub needs_peer_ports: bool,
    /// Targets one sender covers per sweep, so a lone socket can spray many
    /// ports per tick.
    pub per_sweep: u16,
    /// The peer's live mappings appear only once its own pulses begin,
    /// which wait for this side's PortUpdate; pulses hold until peer
    /// traffic proves them live, or one RTT plus a tick passes.
    pub hold_for_peer: bool,
    /// The peer's live ports are fixed once its first sweep lands, so
    /// pulses stop after the racing pass and one settled pass over the
    /// target list.
    pub fixed_peer_ports: bool,
}

impl StageSpec {
    fn send(
        family: Family,
        bind: usize,
        targets: Vec<SocketAddr>,
        needs_peer_ports: bool,
        duration: Duration,
    ) -> Self {
        Self {
            family,
            duration,
            bind,
            senders: bind as u16,
            targets,
            reply_only: false,
            needs_peer_ports,
            per_sweep: 1,
            hold_for_peer: false,
            fixed_peer_ports: false,
        }
    }

    fn reply(family: Family, duration: Duration) -> Self {
        Self {
            family,
            duration,
            bind: 1,
            senders: 0,
            targets: Vec::new(),
            reply_only: true,
            needs_peer_ports: false,
            per_sweep: 1,
            hold_for_peer: false,
            fixed_peer_ports: false,
        }
    }
}

/// The full stage list one side executes.
pub(crate) struct ExecPlan {
    pub stages: Vec<StageSpec>,
    /// How the announced V4 socket-0 port is learned.
    pub refresh_v4: Refresh,
    /// Whether a non-reply V6 stage runs, whose socket-0 port gets
    /// announced as its own address.
    pub announce_v6: bool,
    /// Resolved STUN server for a `Refresh::Stun` plan.
    pub refresh_server: Option<SocketAddr>,
    /// The V4 matrix stage continues the peer's allocation sequence, so a
    /// peer-announced allocation position re-bases its targets.
    pub predicts_peer: bool,
    /// The announced V4 port marks this side's current allocation position
    /// for the peer's prediction instead of being the port the peer aims
    /// at. A refresh that fails here degrades the prediction to its
    /// probe-time base instead of failing the session.
    pub sequence_marker: bool,
    /// The peer's IPv4 address behind its NAT, from its Hello.
    pub peer_ip: Ipv4Addr,
    /// The peer's global IPv6 addresses, from its Hello.
    pub peer_v6: Vec<SocketAddrV6>,
}

/// Builds the stage list for one side from the agreed selection.
pub(crate) fn build_plan(
    mine: &NatInfo,
    peer: &NatInfo,
    sel: &Selection,
    my_sockets: u16,
    nonce: Nonce,
    role: crate::report::Role,
    refresh_server: Option<SocketAddr>,
    cfg: &PunchConfig,
) -> ExecPlan {
    let mut stages = Vec::new();
    if direct_first(mine, peer, cfg) {
        stages.extend(direct::stage(mine, peer, cfg));
    }
    match sel.strategy {
        StrategyId::ConeExchange => stages.extend(cone::stage(peer, cfg)),
        StrategyId::SymProbe => {
            // The socket counts carry the shape: the shooter side holds
            // the assistant count, the replying side one socket. A tie is
            // one assistant socket per side, which the initiator shoots,
            // so the derivation stays role-keyed instead of re-reading
            // the classes the Offer may have crossed.
            let i_shoot = match role {
                crate::report::Role::Initiator => sel.initiator_sockets >= sel.responder_sockets,
                crate::report::Role::Responder => sel.responder_sockets > sel.initiator_sockets,
            };
            let peer_sockets = match role {
                crate::report::Role::Initiator => sel.responder_sockets,
                crate::report::Role::Responder => sel.initiator_sockets,
            };
            stages.extend(sym_cone::stage(
                i_shoot,
                my_sockets,
                peer_sockets,
                peer,
                nonce,
                cfg,
            ));
        },
        StrategyId::PredictiveExchange => {
            let peer_sockets = match role {
                crate::report::Role::Initiator => sel.responder_sockets,
                crate::report::Role::Responder => sel.initiator_sockets,
            };
            let window = (my_sockets as usize * peer_sockets as usize * PREDICTION_WINDOW_MULTIPLE)
                .min(PREDICTION_WINDOW_CAP);
            stages.extend(easy_sym::stage(my_sockets, peer, window, cfg));
        },
        StrategyId::PredictiveBurst => {
            let i_am_easy = matches!(effective_class(mine), NatClass::EasySym { .. });
            // The sizing always reads the hard side's space, whichever
            // side builds the stage, so both roles derive the same
            // coverage pair from the same views.
            let hard_space = if i_am_easy {
                peer_space(peer)
            } else {
                peer_space(mine)
            };
            stages.extend(predictive_burst::stage(
                i_am_easy,
                my_sockets,
                hard_space,
                peer,
                nonce,
                role as u64,
                cfg,
            ));
        },
        StrategyId::BirthdayBurst => {
            // Selection sized the same pure solve over the same pair of
            // views, so the role-keyed coverage here matches what the
            // estimate reported.
            let sized = size_burst(peer_space(mine), peer_space(peer), cfg);
            let coverage = match role {
                crate::report::Role::Initiator => sized.initiator_coverage,
                crate::report::Role::Responder => sized.responder_coverage,
            };
            stages.extend(birthday::stage(
                my_sockets,
                coverage,
                peer,
                nonce,
                role as u64,
                cfg,
            ));
        },
    }
    // A peer without any usable address leaves the plan empty; bind one idle
    // socket so the engine still runs and fails on its deadline.
    if stages.is_empty() {
        stages.push(StageSpec::reply(Family::V4, cfg.punch_timeout));
    }

    // The announced ports are per family, so a plan that runs both a V6
    // Direct stage and a V4 matrix stage publishes both socket-0 ports. A
    // public address knows its own socket address, a v6 address needs no
    // NAT cooperation, and a cone mapping needs a STUN query. A
    // symmetric side with a confident stride has no port the peer can aim
    // at, but its current allocation position lets the peer's prediction
    // track the drift the two phases between probe and punch leave behind,
    // so it announces that position instead.
    let announce_v6 = stages
        .iter()
        .any(|s| s.family == Family::V6 && !s.reply_only);
    let my_class = effective_class(mine);
    let peer_class = effective_class(peer);
    let my_sym = is_symmetric(my_class);
    let refresh_v4 = match sel.strategy {
        StrategyId::ConeExchange => {
            if my_class == NatClass::Public {
                Refresh::Local
            } else {
                Refresh::Stun
            }
        },
        StrategyId::SymProbe if !my_sym => Refresh::Stun,
        StrategyId::SymProbe | StrategyId::PredictiveExchange | StrategyId::PredictiveBurst
            if my_sym && matches!(my_class, NatClass::EasySym { .. }) =>
        {
            Refresh::Stun
        },
        _ => Refresh::None,
    };
    // The announce of a symmetric side marks its sequence position, while
    // every other announce names the port the peer aims at.
    let sequence_marker = refresh_v4 == Refresh::Stun && my_sym;
    // Prediction stages carry a fitted window over the peer's sequence:
    // PredictiveExchange always, the SymProbe cone side against an easy
    // symmetric peer, and the hard side of a PredictiveBurst pair, whose
    // window covers the easy peer's continuation and moves with its
    // announced position the same way.
    let predicts_peer = match sel.strategy {
        StrategyId::PredictiveExchange => true,
        StrategyId::SymProbe => !my_sym && matches!(peer_class, NatClass::EasySym { .. }),
        StrategyId::PredictiveBurst => matches!(peer_class, NatClass::EasySym { .. }),
        _ => false,
    };

    ExecPlan {
        stages,
        refresh_v4,
        announce_v6,
        refresh_server,
        predicts_peer,
        sequence_marker,
        peer_ip: peer
            .reflexive_v4()
            .map_or(Ipv4Addr::UNSPECIFIED, |a| *a.ip()),
        peer_v6: peer.v6.as_ref().map_or(Vec::new(), |v6| v6.addrs.clone()),
    }
}

/// What the engine hands the session on success.
pub(crate) struct Outcome {
    pub family: Family,
    pub winner: u16,
    pub peer_addr: SocketAddr,
    /// Engine-local diagnostic index of the peer's winner socket; `None`
    /// when the peer never reported one.
    pub peer_socket: Option<u16>,
    pub packets_sent: u32,
    pub stale_packets: u32,
    pub punch_ms: u64,
    pub confirm_ms: u64,
}

/// Pending STUN query for a refresh, retried on the confirm timer.
struct StunPending {
    txid: [u8; 12],
    request: Vec<u8>,
    socket: u16,
    server: SocketAddr,
    next_retry: tokio::time::Instant,
    attempts_left: u8,
}

/// Full passes over the target list a fixed-port spray runs before its
/// pulses stop.
///
/// One pass races the peer's own mapping creation, one runs against the
/// settled probe-derived set, and the handshake's answer chatter mints
/// the last fresh mappings: each side answers the other's sources on the
/// confirm_retry cadence, so the answer mappings close within a couple
/// of confirm windows, which at the throttled one-packet-per-tick sweep
/// is about two more passes. Past the fourth pass both live sets are
/// closed and every later pass repeats covered ports while spending the
/// rate budget handshake retransmissions need.
const FIXED_PORT_PASSES: usize = 4;

/// Refresh query attempts, one send plus retries on the confirm_retry
/// cadence. Four attempts at the default 200 ms cadence spend well under
/// a second of the punch window before the plan degrades to its
/// probe-time base or fails fast.
const REFRESH_ATTEMPTS: u8 = 4;

/// Upper bound on the Syn sources the engine tracks for reply gating.
///
/// An attacker holding the nonce can spoof fresh sources without limit,
/// so the map stays capped: past the bound, new sources wait for the
/// current window instead of claiming memory. Honest traffic stays far
/// below it, because real keys scale with both sides' socket counts.
const MAX_SYN_REPLY_KEYS: usize = 1024;

/// Drives one side through the Punch and Confirm phases.
///
/// The engine is a single task fed by three streams: pool receive events,
/// signaling frames, and a tick for pulses and retransmissions. The first
/// complete handshake elects the winner.
pub(crate) struct Engine<S: UdpIo> {
    cfg: PunchConfig,
    plan: ExecPlan,
    nonce: Nonce,
    syn_bufs: [Vec<Vec<u8>>; 2],
    start: Option<tokio::time::Instant>,
    punch_deadline: tokio::time::Instant,
    stage_idx: usize,
    sweep: usize,
    /// Position inside the current sweep round, where a tick stopped
    /// after spending its send share; the next tick resumes from it.
    sweep_off: usize,
    /// Set when budget or conntrack errors stopped outbound sends; handshake
    /// retransmissions keep retrying because replies matter more than new
    /// pulses.
    send_stalled: bool,
    /// The session's wall-clock deadline, from the session start.
    overall: tokio::time::Instant,
    candidate: Option<(Family, u16)>,
    confirmed: Option<(Family, u16)>,
    /// Winner index to announce over signaling before the loop exits.
    announce: Option<u16>,
    /// Fresh own ports to announce, or fresh peer ports to target.
    announce_ports: Option<PortAnnounce>,
    /// Ports announced so far, kept for the periodic retransmission.
    own_ports: Option<PortAnnounce>,
    next_announce: tokio::time::Instant,
    fresh_peer: Option<PortAnnounce>,
    stun: Option<StunPending>,
    finish_now: bool,
    peer_confirmed: bool,
    peer_socket: Option<u16>,
    peer_addr: Option<SocketAddr>,
    grace_end: Option<tokio::time::Instant>,
    next_reply: tokio::time::Instant,
    first_handshake: Option<tokio::time::Instant>,
    /// Syn sources already answered, mapped to the instant their window
    /// ends. Keyed by receiving socket and source address.
    syn_replies: HashMap<(u16, SocketAddr), tokio::time::Instant>,
    stale_packets: u32,
    /// Sweep targets for the active stage, cached with the key they were
    /// built for: the stage index and the fresh peer port that shaped them.
    target_cache: Option<(usize, Option<u16>, Arc<Vec<SocketAddr>>)>,
    /// Stage index and announce port the prediction targets were re-based
    /// on, so a retransmitted announce rebuilds nothing.
    rebased_for: Option<(usize, u16)>,
    /// Fallback open time for a held spray: one RTT plus a tick past the
    /// engine start, the latest the peer's first pulses can be due when
    /// every inbound packet of them was lost.
    peer_warm: tokio::time::Instant,
    _marker: std::marker::PhantomData<S>,
}

impl<S: UdpIo> Engine<S> {
    /// `overall` is the session's wall-clock deadline; every engine
    /// deadline stays at or before it.
    pub(crate) fn new(
        plan: ExecPlan,
        cfg: PunchConfig,
        nonce: Nonce,
        overall: tokio::time::Instant,
    ) -> Self {
        Self {
            cfg,
            plan,
            nonce,
            overall,
            syn_bufs: [Vec::new(), Vec::new()],
            start: None,
            punch_deadline: overall,
            stage_idx: 0,
            sweep: 0,
            sweep_off: 0,
            send_stalled: false,
            candidate: None,
            confirmed: None,
            announce: None,
            announce_ports: None,
            own_ports: None,
            next_announce: tokio::time::Instant::now(),
            fresh_peer: None,
            stun: None,
            finish_now: false,
            peer_confirmed: false,
            peer_socket: None,
            peer_addr: None,
            grace_end: None,
            next_reply: tokio::time::Instant::now(),
            first_handshake: None,
            syn_replies: HashMap::new(),
            stale_packets: 0,
            target_cache: None,
            rebased_for: None,
            peer_warm: tokio::time::Instant::now(),
            _marker: std::marker::PhantomData,
        }
    }

    /// Runs the phases and returns the elected winner socket.
    pub(crate) async fn run<F: UdpFactory<Socket = S>>(
        mut self,
        factory: &F,
        sig: &mut SigIo,
    ) -> Result<(S, Outcome), PunchError> {
        let v4 = self
            .plan
            .stages
            .iter()
            .filter(|s| s.family == Family::V4)
            .map(|s| s.bind)
            .max()
            .unwrap_or(0);
        let v6 = self
            .plan
            .stages
            .iter()
            .filter(|s| s.family == Family::V6)
            .map(|s| s.bind)
            .max()
            .unwrap_or(0);
        let (pool, mut events) = SocketPool::bind(factory, &self.cfg, v4, v6).await?;
        for (group, family) in [(0, Family::V4), (1, Family::V6)] {
            self.syn_bufs[group] = (0..pool.bound(family))
                .map(|i| {
                    encode_packet(&DataPacket::Syn {
                        nonce: self.nonce,
                        socket: i as u16,
                    })
                })
                .collect();
        }
        self.start_refresh(&pool);
        let result = self.drive(&pool, &mut events, sig).await;
        // The receiver must leave before the pool awaits its tasks, so a
        // receive task never sees a live channel while the engine stops
        // draining it.
        drop(events);
        match result {
            Ok(outcome) => {
                let socket = pool.elect(outcome.family, outcome.winner).await?;
                Ok((socket, outcome))
            },
            Err(e) => {
                pool.shutdown().await;
                Err(e)
            },
        }
    }

    /// Announces the fresh own ports of the punch sockets.
    ///
    /// A local refresh knows the port immediately; a STUN refresh fires the
    /// query and waits for the answer among the pool events.
    fn start_refresh(&mut self, pool: &SocketPool<S>) {
        let mut announce = PortAnnounce::default();
        // A V6 stage runs on global addresses, so the socket's own port is
        // the fact the peer needs.
        if self.plan.announce_v6
            && let Some(port) = pool.socket(Family::V6, 0).and_then(|s| s.local_addr().ok())
        {
            announce.v6 = Some(port.port());
        }
        match self.plan.refresh_v4 {
            Refresh::None => {},
            Refresh::Local => {
                if let Some(port) = pool.socket(Family::V4, 0).and_then(|s| s.local_addr().ok()) {
                    announce.v4 = Some(port.port());
                }
            },
            Refresh::Stun => {
                let Some(server) = self.plan.refresh_server else {
                    return
                };
                if pool.bound(Family::V4) == 0 {
                    return;
                }
                let txid: [u8; 12] = rand::random();
                self.stun = Some(StunPending {
                    request: crate::nat::probe::binding_request(&txid),
                    txid,
                    socket: 0,
                    server,
                    next_retry: tokio::time::Instant::now(),
                    attempts_left: REFRESH_ATTEMPTS,
                });
            },
        }
        if announce.v4.is_some() || announce.v6.is_some() {
            self.own_ports = Some(announce);
            self.next_announce = tokio::time::Instant::now();
            self.announce_ports = Some(announce);
        }
    }

    /// Marks the STUN answer as announced and arms the retransmission.
    fn refresh_answered(&mut self, port: u16) {
        let mut announce = self.own_ports.unwrap_or_default();
        announce.v4 = Some(port);
        self.own_ports = Some(announce);
        self.next_announce = tokio::time::Instant::now();
        self.announce_ports = Some(announce);
    }

    async fn drive(
        &mut self,
        pool: &SocketPool<S>,
        events: &mut tokio::sync::mpsc::Receiver<crate::socket::RecvEvent>,
        sig: &mut SigIo,
    ) -> Result<Outcome, PunchError> {
        let start = tokio::time::Instant::now();
        self.start = Some(start);
        self.punch_deadline = (start + self.cfg.punch_timeout).min(self.overall);
        self.peer_warm = start + sig.rtt() + self.cfg.tick;
        // A STUN refresh that never started has no server or no bound
        // socket, so the V4 port can never be announced. A sequence
        // marker only sharpens the peer's prediction base, so its plan
        // downgrades to the probe-time base instead of failing.
        if self.plan.refresh_v4 == Refresh::Stun && self.stun.is_none() {
            if self.plan.sequence_marker {
                self.plan.refresh_v4 = Refresh::None;
            } else {
                return Err(PunchError::Io {
                    phase: Phase::Punch,
                    source: std::io::Error::other("stun refresh has no server or bound socket"),
                });
            }
        }
        let mut ticker = tokio::time::interval_at(start + self.cfg.tick, self.cfg.tick);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let now = tokio::time::Instant::now();
            if self.finished(now) {
                break;
            }
            if self.confirmed.is_none() && now >= self.punch_deadline {
                return Err(PunchError::Timeout {
                    phase: if self.first_handshake.is_some() {
                        Phase::Confirm
                    } else {
                        Phase::Punch
                    },
                });
            }
            tokio::select! {
                ev = events.recv() => {
                    let Some(ev) = ev else {
                        // A pool whose every bind failed carries the real
                        // cause; any other stop keeps the generic reason.
                        let source = match (pool.live_sockets(), pool.last_bind_error()) {
                            (0, Some(e)) => std::io::Error::other(format!(
                                "pool receive tasks stopped: every bind failed: {e}"
                            )),
                            _ => std::io::Error::other("pool receive tasks stopped"),
                        };
                        return Err(PunchError::Io { phase: Phase::Punch, source });
                    };
                    self.on_data(pool, ev).await?;
                }
                frame = sig.recv() => {
                    match frame {
                        Ok(frame) => self.on_signaling(&frame.body)?,
                        // A closed bridge during grace means the peer went
                        // home after its handshake finished; that is a
                        // success on this side.
                        Err(PunchError::SignalingClosed) if self.confirmed.is_some() => break,
                        Err(e) => return Err(e),
                    }
                }
                _ = ticker.tick() => {
                    self.on_tick(pool).await?;
                }
            }
            // Signaling side effects leave the handlers, so the handlers
            // stay free of the signaling handle. The session wall bounds
            // both best-effort sends: a host that stops draining its
            // channel drops the frame instead of parking the loop, which
            // matches how a closed bridge is already treated.
            if let Some(socket) = self.announce.take() {
                let _ =
                    tokio::time::timeout_at(self.overall, sig.send(Frame::Confirmed { socket }))
                        .await;
            }
            if let Some(ports) = self.announce_ports.take() {
                let _ = tokio::time::timeout_at(
                    self.overall,
                    sig.send(Frame::PortUpdate {
                        v4: ports.v4,
                        v6: ports.v6,
                    }),
                )
                .await;
            }
        }
        let end = tokio::time::Instant::now();
        let (family, winner) = self
            .confirmed
            .or(self.candidate)
            .ok_or(PunchError::ConfirmFailed)?;
        Ok(Outcome {
            family,
            winner,
            peer_addr: self.peer_addr.ok_or(PunchError::ConfirmFailed)?,
            peer_socket: self.peer_socket,
            packets_sent: pool.sent(),
            stale_packets: self.stale_packets,
            punch_ms: self
                .first_handshake
                .map_or(0, |t| (t - start).as_millis() as u64),
            confirm_ms: self
                .first_handshake
                .map_or(0, |t| (end - t).as_millis() as u64),
        })
    }

    fn finished(&self, now: tokio::time::Instant) -> bool {
        self.confirmed.is_some()
            && (self.finish_now || self.peer_confirmed || self.grace_end.is_some_and(|g| now >= g))
    }

    /// Routes a handshake send failure.
    ///
    /// With no handshake traffic yet there is nothing to keep alive, so the
    /// session fails fast. Afterwards a working path exists and the grace
    /// mechanism decides the outcome, so the failure only stops new pulses.
    /// A full conntrack table skips its destination for this round only:
    /// replies to the sources already tracked keep the live path, and later
    /// rounds retry, so a session with one working path does not drag to
    /// its deadline.
    fn send_failed(&mut self, err: PunchError) -> Option<PunchError> {
        if self.first_handshake.is_none() {
            return Some(err);
        }
        if matches!(err, PunchError::ConntrackExhausted) {
            return None;
        }
        self.send_stalled = true;
        None
    }

    /// Records the peer's data-plane address from a Syn or SynAck.
    ///
    /// After a winner is elected, only its own handshake may move the
    /// delivered address: the peer's other sockets keep pulsing during
    /// grace, and their packets must not poison the winner's address.
    fn observe_peer(
        &mut self,
        peer_socket: u16,
        from: SocketAddr,
        now: tokio::time::Instant,
        family: Family,
        socket: u16,
    ) {
        self.first_handshake.get_or_insert(now);
        let tied_to_winner = match self.confirmed {
            Some((f, i)) => f == family && i == socket && self.peer_socket == Some(peer_socket),
            None => true,
        };
        if tied_to_winner {
            self.peer_addr = Some(from);
            self.peer_socket = Some(peer_socket);
        }
    }

    /// Records the peer's address from an Ack on an open or winning path.
    fn observe_addr(&mut self, from: SocketAddr, now: tokio::time::Instant) {
        self.first_handshake.get_or_insert(now);
        self.peer_addr = Some(from);
    }

    /// Whether this Syn still earns a direct SynAck.
    ///
    /// One reply per confirm window covers the peer, because the
    /// retransmission tick repeats the SynAck on that same cadence for a
    /// live candidate.
    fn syn_reply_due(&mut self, socket: u16, from: SocketAddr, now: tokio::time::Instant) -> bool {
        let key = (socket, from);
        if let Some(&mute_until) = self.syn_replies.get(&key)
            && now < mute_until
        {
            return false;
        }
        if self.syn_replies.len() >= MAX_SYN_REPLY_KEYS {
            // Expired keys leave first; a still-full map leaves fresh
            // keys unanswered until the window passes.
            self.syn_replies.retain(|_, &mut until| until > now);
            if self.syn_replies.len() >= MAX_SYN_REPLY_KEYS {
                return false;
            }
        }
        self.syn_replies.insert(key, now + self.cfg.confirm_retry);
        true
    }

    /// Whether this side aimed Syns at the host of `addr`.
    ///
    /// A SynAck answer carries no proof beyond the nonce, so it only
    /// counts from the peer this side probed. The check anchors on the
    /// peer's own addresses, the same ones every stage targets: the
    /// peer's replies leave through its NAT, so a cone answers from the
    /// announced port while a symmetric mapping answers from a fresh one
    /// no target list could name, and the port carries no evidence. A
    /// family with only port-dependent stages probed nothing until the
    /// peer announced its live port.
    fn syn_targeted(&self, addr: SocketAddr) -> bool {
        let (family, announced) = match addr {
            SocketAddr::V4(_) => (Family::V4, self.fresh_peer.and_then(|p| p.v4).is_some()),
            SocketAddr::V6(_) => (Family::V6, self.fresh_peer.and_then(|p| p.v6).is_some()),
        };
        let probed = self.plan.stages.iter().any(|s| {
            s.family == family
                && !s.reply_only
                && (if s.needs_peer_ports {
                    announced
                } else {
                    !s.targets.is_empty()
                })
        });
        if !probed {
            return false;
        }
        match family {
            Family::V4 => addr.ip() == IpAddr::from(self.plan.peer_ip),
            Family::V6 => self
                .plan
                .peer_v6
                .iter()
                .any(|a| addr.ip() == IpAddr::from(*a.ip())),
        }
    }

    async fn on_data(
        &mut self,
        pool: &SocketPool<S>,
        ev: crate::socket::RecvEvent,
    ) -> Result<(), PunchError> {
        // A pending refresh query collects its answer first: the answer must
        // come from the queried server onto the socket that sent the query.
        if let Some(pending) = &self.stun
            && ev.from == pending.server
            && ev.socket == pending.socket
        {
            if let Some(addr) = crate::nat::probe::parse_mapped(&ev.buf[..ev.len], &pending.txid) {
                self.refresh_answered(addr.port());
                self.stun = None;
            }
            return Ok(());
        }
        let pkt = match decode_packet(&ev.buf[..ev.len]) {
            Ok(pkt) => pkt,
            // A frame with our magic but a foreign version can only be a
            // peer running an incompatible protocol; fail the session now
            // instead of letting it burn to a phase timeout.
            Err(DecodeError::Version { local, peer }) => {
                return Err(PunchError::VersionMismatch { local, peer });
            },
            // Any other broken frame is foreign traffic on a fresh
            // ephemeral port and stays noise.
            Err(DecodeError::BadFrame) => return Ok(()),
        };
        let nonce = pkt.nonce();
        if nonce != self.nonce {
            self.stale_packets += 1;
            return Ok(());
        }
        let now = tokio::time::Instant::now();
        match pkt {
            DataPacket::Keepalive { .. } => {},
            DataPacket::Syn { socket, .. } => {
                // Peer state refreshes on every Syn, duplicates included;
                // only the reply is gated.
                self.observe_peer(socket, ev.from, now, ev.family, ev.socket);
                self.candidate.get_or_insert((ev.family, ev.socket));
                if self.syn_reply_due(ev.socket, ev.from, now) {
                    let buf = encode_packet(&DataPacket::SynAck {
                        nonce,
                        socket: ev.socket,
                    });
                    if let Err(e) = pool.send(ev.family, ev.socket, &buf, ev.from).await
                        && let Some(e) = self.send_failed(e)
                    {
                        return Err(e);
                    }
                    self.next_reply = now + self.cfg.confirm_retry;
                }
            },
            DataPacket::SynAck { socket, .. } => {
                // An answer from an address no Syn aimed at confirms
                // nothing and earns no Ack: the nonce alone cannot make an
                // unvisited source the peer.
                if !self.syn_targeted(ev.from) {
                    return Ok(());
                }
                self.observe_peer(socket, ev.from, now, ev.family, ev.socket);
                let resend_ack = if let Some((family, idx)) = self.confirmed {
                    // The peer missed our Ack; answer again while grace runs.
                    family == ev.family && idx == ev.socket
                } else {
                    self.confirmed = Some((ev.family, ev.socket));
                    self.announce = Some(ev.socket);
                    self.grace_end = Some((now + self.cfg.grace).min(self.overall));
                    true
                };
                if resend_ack {
                    let buf = encode_packet(&DataPacket::Ack { nonce });
                    if let Err(e) = pool.send(ev.family, ev.socket, &buf, ev.from).await
                        && let Some(e) = self.send_failed(e)
                    {
                        return Err(e);
                    }
                    self.next_reply = now + self.cfg.confirm_retry;
                }
            },
            DataPacket::Ack { .. } => self.on_ack(ev.from, ev.family, ev.socket, now),
        }
        Ok(())
    }

    /// Whether `socket` answered a Syn from the host of `addr`.
    ///
    /// A symmetric peer sends its Ack through a fresh mapping port, so
    /// the evidence keys on the host rather than the port: the socket
    /// ran a Syn-and-answer exchange with that host, and the Ack's
    /// landing socket is the one that exchange validated.
    fn answered_syn(&self, socket: u16, addr: SocketAddr) -> bool {
        self.syn_replies
            .keys()
            .any(|(s, from)| *s == socket && from.ip() == addr.ip())
    }

    /// Completes the handshake from the peer's Ack.
    ///
    /// An Ack only counts on a socket that answered a Syn from the
    /// Ack's host: the answer and the Ack together prove the exchange
    /// ran on that socket, and the socket the Ack landed on is the
    /// winner it proves. An Ack anywhere else answers a handshake this
    /// side never ran, so it moves nothing.
    fn on_ack(&mut self, from: SocketAddr, family: Family, socket: u16, now: tokio::time::Instant) {
        if self.confirmed.is_none() {
            if self.answered_syn(socket, from) {
                self.observe_addr(from, now);
                self.confirmed = Some((family, socket));
                self.announce = Some(socket);
                // The final Ack proves both directions, so no grace wait
                // applies on this path.
                self.finish_now = true;
            }
        } else if self.confirmed == Some((family, socket)) {
            self.observe_addr(from, now);
            self.finish_now = true;
        }
    }

    fn on_signaling(&mut self, body: &Frame) -> Result<(), PunchError> {
        match *body {
            Frame::Abort(reason) => Err(PunchError::PeerAborted(reason)),
            Frame::Confirmed { socket } => {
                self.peer_confirmed = true;
                self.peer_socket = Some(socket);
                Ok(())
            },
            Frame::PortUpdate { v4, v6 } => {
                // Retransmissions repeat the same values, so each family
                // slot overwrites with a stable port.
                let fresh = self.fresh_peer.get_or_insert_with(PortAnnounce::default);
                if v4.is_some() {
                    fresh.v4 = v4;
                }
                if v6.is_some() {
                    fresh.v6 = v6;
                }
                Ok(())
            },
            // Duplicates of earlier phases carry no action.
            _ => Ok(()),
        }
    }

    /// The nominal end of stage `idx`, never past the punch deadline: a
    /// Direct stage spends its window inside the punch budget, so the sum
    /// of the stage durations would otherwise outlive the deadline the
    /// top-level check enforces.
    fn stage_end(&self, idx: usize) -> tokio::time::Instant {
        let start = self.start.expect("drive sets the start");
        let elapsed: Duration = self.plan.stages[..=idx].iter().map(|s| s.duration).sum();
        (start + elapsed).min(self.punch_deadline)
    }

    /// Targets for the active stage, honoring the fresh peer port of the
    /// stage's own family.
    ///
    /// The vector is rebuilt only when the stage index or that port
    /// changes, because a BirthdayBurst stage carries hundreds of
    /// addresses that never move for the stage's lifetime. Addresses the
    /// peer cannot punch through are dropped here: a peer without a usable
    /// IPv4 address yields no V4 target at all, and its V6 list keeps only
    /// the addresses that can carry punch traffic. The shared handle
    /// outlives the borrow, so the caller can keep sending through
    /// `&mut self` while holding it.
    fn live_targets(&mut self) -> Option<Arc<Vec<SocketAddr>>> {
        let stage = &self.plan.stages[self.stage_idx];
        let port = match stage.family {
            Family::V4 => self.fresh_peer.and_then(|p| p.v4),
            Family::V6 => self.fresh_peer.and_then(|p| p.v6),
        };
        // Static stages carry no port dependency, so a `None` key covers
        // them; a peer-port stage without its port never caches below.
        let key = stage.needs_peer_ports.then_some(port).flatten();
        if let Some((idx, cached_key, targets)) = &self.target_cache
            && *idx == self.stage_idx
            && *cached_key == key
        {
            return Some(Arc::clone(targets));
        }
        let targets = if stage.needs_peer_ports {
            let port = port?;
            match stage.family {
                // An unspecified peer IP means the peer reported no usable
                // IPv4 address, so no V4 target is generated rather than an
                // unusable one.
                Family::V4 if self.plan.peer_ip.is_unspecified() => Vec::new(),
                Family::V4 => vec![SocketAddr::from((self.plan.peer_ip, port))],
                Family::V6 => self
                    .plan
                    .peer_v6
                    .iter()
                    .filter(|addr| usable_peer_v6(*addr.ip()))
                    .map(|addr| {
                        SocketAddr::V6(SocketAddrV6::new(
                            *addr.ip(),
                            port,
                            addr.flowinfo(),
                            addr.scope_id(),
                        ))
                    })
                    .collect(),
            }
        } else {
            stage.targets.clone()
        };
        let targets = Arc::new(targets);
        self.target_cache = Some((self.stage_idx, key, Arc::clone(&targets)));
        Some(targets)
    }

    /// Re-bases the active stage's prediction targets on the peer's
    /// announced allocation position.
    ///
    /// The announce leaves the peer's NAT at its engine start, so its port
    /// supersedes the probe-time base every fitted target still carries:
    /// the allocations that landed between Probe and Punch moved the whole
    /// sequence. The translated window keeps its length and stride, so the
    /// sweep rotation keeps its schedule and only the ports move. Stages
    /// without a fitted window, and announces from a peer nothing predicts,
    /// change nothing.
    fn apply_peer_base(&mut self) {
        if !self.plan.predicts_peer {
            return;
        }
        let Some(port) = self.fresh_peer.and_then(|p| p.v4) else {
            return;
        };
        if self.rebased_for == Some((self.stage_idx, port)) {
            return;
        }
        self.rebased_for = Some((self.stage_idx, port));
        let stage = &self.plan.stages[self.stage_idx];
        if stage.family != Family::V4 || stage.reply_only || stage.needs_peer_ports {
            return;
        }
        let ports: Vec<u16> = stage.targets.iter().map(SocketAddr::port).collect();
        let Some(rebased) = crate::nat::predict::rebased_window(&ports, port) else {
            return;
        };
        let targets = rebased
            .into_iter()
            .zip(&stage.targets)
            .map(|(port, target)| match target {
                SocketAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(*v4.ip(), port)),
                SocketAddr::V6(_) => *target,
            })
            .collect();
        // The cached list carries the static stage's `None` key, so
        // `live_targets` serves it until the stage or the port changes.
        self.target_cache = Some((self.stage_idx, None, Arc::new(targets)));
    }

    async fn on_tick(&mut self, pool: &SocketPool<S>) -> Result<(), PunchError> {
        let now = tokio::time::Instant::now();
        // A tick delayed by an event storm can land past several stage
        // boundaries at once, so the advance runs until the active stage
        // owns `now`. Plans hold at most two stages today and validation
        // keeps every stage longer than a tick, which makes one advance
        // per tick sufficient; the loop keeps that true for any plan.
        while now >= self.stage_end(self.stage_idx) && self.stage_idx + 1 < self.plan.stages.len() {
            self.stage_idx += 1;
            self.sweep = 0;
            self.sweep_off = 0;
        }

        // Refresh retries.
        if let Some(pending) = &self.stun
            && now >= pending.next_retry
            && pending.attempts_left == 0
        {
            // Without the announced port the peer has nothing to aim at.
            // With handshake traffic already flowing, the grace path
            // decides instead of the refresh. A sequence marker that never
            // crossed only leaves the peer's prediction on its probe-time
            // base, so the plan continues.
            if self.first_handshake.is_none() && !self.plan.sequence_marker {
                return Err(PunchError::Io {
                    phase: Phase::Punch,
                    source: std::io::Error::other("stun refresh retries exhausted"),
                });
            }
            self.stun = None;
        } else if let Some(pending) = &mut self.stun
            && now >= pending.next_retry
        {
            // A failed send burns a retry exactly like an unanswered query,
            // so persistent refresh failure surfaces through the
            // retries-exhausted path above instead of silence.
            let _ = pool
                .send_refresh(pending.socket, &pending.request, pending.server)
                .await;
            pending.attempts_left -= 1;
            pending.next_retry = now + self.cfg.confirm_retry;
        }

        // PortUpdate retransmits on the signaling retry cadence until the
        // handshake completes, because the frame carries no acknowledgement.
        if let Some(ports) = self.own_ports
            && self.confirmed.is_none()
            && now >= self.next_announce
        {
            self.announce_ports = Some(ports);
            self.next_announce = now + self.cfg.signaling_retry;
        }

        // Syn pulses. The handle is taken before the stage borrow, so the
        // sends below can work on `&mut self` without fighting it.
        self.apply_peer_base();
        let targets = self.live_targets();
        let stage = &self.plan.stages[self.stage_idx];
        // A held spray targets ports the peer's NAT has not allocated yet:
        // the peer's sockets bind at the shared start but their mappings
        // appear only when its pulses leave, and its pulses wait for this
        // side's PortUpdate. Inbound peer traffic is the direct proof the
        // mappings exist, and one RTT plus a tick is the fallback for a
        // path that loses every one of the peer's first packets.
        let held = stage.hold_for_peer && self.first_handshake.is_none() && now < self.peer_warm;
        if !stage.reply_only
            && !held
            && self.confirmed.is_none()
            && !self.send_stalled
            && let Some(targets) = targets
            && !targets.is_empty()
        {
            let group = match stage.family {
                Family::V4 => &self.syn_bufs[0],
                Family::V6 => &self.syn_bufs[1],
            };
            // Peer traffic observed means handshake replies and event
            // processing need the rate budget, so a multi-target spray backs
            // off to one packet per sweep. Single-pulse stages stay as they
            // are.
            let per_sweep = if self.peer_addr.is_some() {
                1
            } else {
                usize::from(stage.per_sweep)
            };
            let senders = usize::from(stage.senders.min(group.len() as u16));
            let sweep_len = senders * per_sweep;
            // A spray against fixed peer ports earns nothing past
            // FIXED_PORT_PASSES full passes; the constant derives the
            // window. Inbound-loss recovery rides the retransmission
            // tick, which re-answers the sources already tracked.
            let settled = stage.fixed_peer_ports
                && self.sweep.saturating_mul(sweep_len) >= FIXED_PORT_PASSES * targets.len();
            // One tick spends at most its share of the rate grid, the same
            // bound that caps a lone sender's burst. A sweep wider than the
            // share resumes where it stopped on the next tick, so the drive
            // loop keeps polling events, signaling, and the deadline
            // between bursts instead of sleeping a whole sweep inside the
            // limiter. The deadline check keeps a tick from entering another
            // limiter wait once the punch window is over.
            let quota = usize::from(burst_len(&self.cfg));
            let mut sent = 0;
            let mut failure = None;
            while !settled && self.sweep_off < sweep_len {
                if sent == quota || tokio::time::Instant::now() >= self.punch_deadline {
                    break;
                }
                let sender = (self.sweep_off / per_sweep) as u16;
                let target = targets[(self.sweep * sweep_len + self.sweep_off) % targets.len()];
                if let Err(e) = pool
                    .send(stage.family, sender, &group[sender as usize], target)
                    .await
                {
                    failure = Some(e);
                    break;
                }
                self.sweep_off += 1;
                sent += 1;
            }
            // A round that finished or failed starts the next round; a round
            // cut short by its quota boundary resumes on the next tick.
            if failure.is_some() || self.sweep_off >= sweep_len {
                self.sweep_off = 0;
                self.sweep += 1;
            }
            if let Some(e) = failure
                && let Some(e) = self.send_failed(e)
            {
                return Err(e);
            }
        }

        // Handshake retransmissions on the confirm timer.
        if let Some(peer) = self.peer_addr {
            if let Some((family, idx)) = self.candidate
                && self.confirmed.is_none()
                && now >= self.next_reply
            {
                let buf = encode_packet(&DataPacket::SynAck {
                    nonce: self.nonce,
                    socket: idx,
                });
                // A handshake already ran on this path, so a failed
                // retransmission waits for a later tick instead of failing
                // the session.
                if pool.send(family, idx, &buf, peer).await.is_ok() {
                    self.next_reply = now + self.cfg.confirm_retry;
                }
            }
            if let Some((family, idx)) = self.confirmed
                && self.grace_end.is_some()
                && !self.peer_confirmed
                && now >= self.next_reply
            {
                let buf = encode_packet(&DataPacket::Ack { nonce: self.nonce });
                if pool.send(family, idx, &buf, peer).await.is_ok() {
                    self.next_reply = now + self.cfg.confirm_retry;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let directional = burst_hit_chance(&narrow_wide, 300, 20_000);
        let shared = burst_hit_chance(&narrow_wide, 20_000, 20_000);
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
        );
        let skewed = burst_hit_chance(
            &BurstSize {
                initiator_coverage: 32,
                responder_coverage: 8,
            },
            1000,
            1000,
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
            burst_hit_chance(&sized, 1000, 1000) >= cfg.target_success - 1e-9,
            "estimate {} under the target",
            burst_hit_chance(&sized, 1000, 1000)
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
        assert!(burst_hit_chance(&sized, 300, 20_000) >= cfg.target_success - 1e-9);
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
        assert!(burst_hit_chance(&sized, space, space) < cfg.min_success);
    }

    #[test]
    fn tiny_spaces_solve_inside_the_span() {
        let cfg = PunchConfig::default();
        // A 132-wide span still offers 132 ports of coverage, so the
        // balanced solve of ln(2) * 66 = 46 products fits at 7 ports per
        // side with no cap binding.
        let sized = size_burst(132, 132, &cfg);
        assert_eq!((sized.initiator_coverage, sized.responder_coverage), (7, 7));
        assert!(burst_hit_chance(&sized, 132, 132) >= cfg.target_success - 1e-9);
        // A conntrack bound below the solve clamps both coverages and the
        // estimate states the shortfall instead of hiding it.
        let cfg = PunchConfig {
            max_mappings: 7,
            ..cfg
        };
        let sized = size_burst(132, 132, &cfg);
        assert_eq!((sized.initiator_coverage, sized.responder_coverage), (5, 5));
        assert!(burst_hit_chance(&sized, 132, 132) < cfg.target_success);
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

    /// A cone reading built from a single answered IP, or from a single
    /// sample, cannot separate a cone from an address-dependent symmetric
    /// NAT: the pair routes to SymProbe with the ambiguous side shooting
    /// instead of a ConeExchange that reading may doom.
    #[test]
    fn low_confidence_cone_readings_route_sym_probe() {
        let cone = sample_info(NatClass::Cone, &[50_000, 50_000, 50_000, 50_000]);
        let cfg = PunchConfig::default();
        assert_eq!(
            select(&cone, &cone, &cfg)
                .expect("confident cones select")
                .strategy,
            StrategyId::ConeExchange
        );
        let mut single_ip = sample_info(NatClass::Cone, &[50_000, 50_000, 50_000, 50_000]);
        single_ip
            .v4
            .as_mut()
            .expect("v4 evidence")
            .distinct_probe_ips = 1;
        let sel = select(&single_ip, &cone, &cfg).expect("ambiguous initiator selects");
        assert_eq!(sel.strategy, StrategyId::SymProbe);
        assert_eq!((sel.initiator_sockets, sel.responder_sockets), (16, 1));
        // The ambiguous responder shoots against a trusted initiator, and
        // a pair with no symmetric side states no spray model.
        let sel = select(&cone, &single_ip, &cfg).expect("ambiguous responder selects");
        assert_eq!(sel.estimate, None);
        assert_eq!((sel.initiator_sockets, sel.responder_sockets), (1, 16));
        // A single answered sample carries no range and no mapping
        // evidence; the pair still runs, with the responder shooting.
        let one_sample = sample_info(NatClass::Cone, &[50_000]);
        let sel = select(&one_sample, &one_sample, &cfg).expect("thin samples select");
        assert_eq!(sel.strategy, StrategyId::SymProbe);
        assert_eq!((sel.initiator_sockets, sel.responder_sockets), (1, 16));
    }

    #[test]
    fn sym_probe_estimate_is_role_symmetric() {
        let sym = sample_info(NatClass::HardSym, &[31_000, 33_000, 35_000, 37_000]);
        let cone = sample_info(NatClass::Cone, &[50_000, 50_000, 50_000, 50_000]);
        let cfg = PunchConfig::default();
        let sel = Selection {
            strategy: StrategyId::SymProbe,
            initiator_sockets: 16,
            responder_sockets: 1,
            estimate: None,
        };
        // Swapping the two views swaps the roles and nothing else.
        assert_eq!(
            sym_probe_estimate(&sym, &cone, &sel, &cfg),
            sym_probe_estimate(&cone, &sym, &sel, &cfg)
        );
    }

    /// The SymProbe estimate faces the same `min_success` bar as the
    /// birthday burst: a spray capped below the bar refuses the pair in
    /// Negotiate instead of burning the punch window on a near miss.
    #[test]
    fn starved_sym_probe_goes_unpunchable() {
        let sym = sample_info(NatClass::HardSym, &[31_000, 33_000, 35_000, 37_000]);
        let cone = sample_info(NatClass::Cone, &[50_000, 50_000, 50_000, 50_000]);
        // The span reads 10001 wide; a 64-packet budget caps the spray at
        // 16 candidates, so the estimate lands near 0.025.
        let cfg = PunchConfig {
            packet_budget: 64,
            ..PunchConfig::default()
        };
        assert!(matches!(
            select(&sym, &cone, &cfg),
            Err(PunchError::Unpunchable { .. })
        ));
        // The same pair under the default budget solves to ~0.5 and runs.
        let sel =
            select(&sym, &cone, &PunchConfig::default()).expect("default budget reaches the bar");
        assert_eq!(sel.strategy, StrategyId::SymProbe);
        assert!(sel.estimate.unwrap() >= 0.1);
    }

    #[cfg(feature = "test-util")]
    #[test]
    fn v6_fallback_aims_the_v4_stage_at_the_v4_port() {
        // A plan whose V6 Direct stage is followed by a V4 Cone stage, the
        // shape a dual-stack cone pair produces.
        let cfg = PunchConfig::default();
        let peer_v6 = SocketAddrV6::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into(), 9999, 0, 0);
        let plan = ExecPlan {
            stages: vec![
                StageSpec::send(
                    Family::V6,
                    1,
                    vec![SocketAddr::V6(peer_v6)],
                    true,
                    cfg.direct_window,
                ),
                StageSpec::send(
                    Family::V4,
                    1,
                    vec![SocketAddr::from(([203, 0, 113, 9], 40000))],
                    true,
                    cfg.punch_timeout,
                ),
            ],
            refresh_v4: Refresh::Stun,
            announce_v6: true,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: vec![peer_v6],
        };
        let mut engine: Engine<crate::sim::SimSocket> =
            Engine::new(plan, cfg, [0; 16], tokio::time::Instant::now());
        // One PortUpdate now carries both families' fresh ports.
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: Some(41000),
                v6: Some(51000),
            })
            .expect("update applies");
        engine.stage_idx = 0;
        let v6 = engine.live_targets().expect("v6 targets resolve");
        assert_eq!(
            v6.as_slice(),
            &[SocketAddr::V6(SocketAddrV6::new(
                [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into(),
                51000,
                0,
                0
            ))][..]
        );
        // The V4 stage aims at the peer's V4 port, not its V6 port.
        engine.stage_idx = 1;
        let v4 = engine.live_targets().expect("v4 targets resolve");
        assert_eq!(
            v4.as_slice(),
            &[SocketAddr::from(([203, 0, 113, 9], 41000))][..]
        );
        // An unchanged key serves the cached vector again.
        let cached = engine.live_targets().expect("cached targets resolve");
        assert!(Arc::ptr_eq(&v4, &cached));
        // A fresh V4 port rebuilds the stage's targets.
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: Some(41_001),
                v6: None,
            })
            .expect("update applies");
        let rebuilt = engine.live_targets().expect("rebuilt targets resolve");
        assert_eq!(
            rebuilt.as_slice(),
            &[SocketAddr::from(([203, 0, 113, 9], 41_001))][..]
        );
        assert!(!Arc::ptr_eq(&v4, &rebuilt));
    }

    /// A peer that reported no usable IPv4 address gets no V4 target at
    /// all, so no sweep can aim at an unspecified address.
    #[test]
    fn unspecified_peer_ip_generates_no_v4_targets() {
        let cfg = PunchConfig::default();
        let plan = ExecPlan {
            stages: vec![StageSpec::send(
                Family::V4,
                1,
                vec![SocketAddr::from(([203, 0, 113, 9], 1))],
                true,
                cfg.punch_timeout,
            )],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: Ipv4Addr::UNSPECIFIED,
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<tokio::net::UdpSocket> =
            Engine::new(plan, cfg, [0; 16], tokio::time::Instant::now());
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: Some(41000),
                v6: None,
            })
            .expect("update applies");
        engine.stage_idx = 0;
        let targets = engine.live_targets().expect("targets resolve");
        assert!(targets.is_empty(), "no target comes from an unspecified IP");
    }

    /// The peer's V6 list keeps only the addresses that can carry punch
    /// traffic; loopback survives the filter for the loopback smoke tests.
    #[test]
    fn peer_v6_targets_keep_only_usable_addresses() {
        use std::net::{IpAddr, Ipv6Addr};

        let v6 = |ip: Ipv6Addr| SocketAddrV6::new(ip, 9999, 0, 0);
        let cfg = PunchConfig::default();
        let plan = ExecPlan {
            stages: vec![StageSpec::send(
                Family::V6,
                1,
                vec![SocketAddr::V6(v6(Ipv6Addr::LOCALHOST))],
                true,
                cfg.direct_window,
            )],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: vec![
                v6("2001:db8::1".parse().expect("global address")),
                v6("ff02::1".parse().expect("multicast address")),
                v6("fe80::1".parse().expect("link-local address")),
                v6("::ffff:203.0.113.9".parse().expect("mapped address")),
                v6(Ipv6Addr::LOCALHOST),
            ],
        };
        let mut engine: Engine<tokio::net::UdpSocket> =
            Engine::new(plan, cfg, [0; 16], tokio::time::Instant::now());
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: None,
                v6: Some(51000),
            })
            .expect("update applies");
        engine.stage_idx = 0;
        let targets = engine.live_targets().expect("targets resolve");
        let ips: Vec<IpAddr> = targets.iter().map(SocketAddr::ip).collect();
        assert_eq!(ips, vec![
            IpAddr::V6("2001:db8::1".parse().expect("global address")),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]);
    }

    /// A malicious peer advertising multicast or port-zero targets produces
    /// no outbound packets: the pool rejects the destination and the
    /// engine, with no handshake yet, fails fast.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn malicious_peer_targets_never_leave_the_host() {
        use std::net::Ipv4Addr;

        use crate::socket::SocketPool;

        let cfg = PunchConfig::default();
        let net = crate::sim::Net::seeded("malicious_targets");
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");

        let syn = encode_packet(&DataPacket::Syn {
            nonce: [0; 16],
            socket: 0,
        });
        // A multicast reflexive address inside the plan's static targets.
        let multicast = ExecPlan {
            stages: vec![StageSpec::send(
                Family::V4,
                1,
                vec![SocketAddr::from((Ipv4Addr::new(224, 0, 0, 1), 40000))],
                false,
                cfg.punch_timeout,
            )],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            multicast,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        engine.syn_bufs[0] = vec![syn.clone()];
        engine.start = Some(tokio::time::Instant::now());
        assert!(
            engine.on_tick(&pool).await.is_err(),
            "the engine fails fast on an unusable target"
        );
        assert_eq!(pool.sent(), 0, "no packet left for the multicast target");

        // A PortUpdate announcing port 0 aims at nothing usable.
        let port_zero = ExecPlan {
            stages: vec![StageSpec::send(
                Family::V4,
                1,
                vec![SocketAddr::from(([203, 0, 113, 9], 40000))],
                true,
                cfg.punch_timeout,
            )],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            port_zero,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        engine.syn_bufs[0] = vec![syn];
        engine.start = Some(tokio::time::Instant::now());
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: Some(0),
                v6: None,
            })
            .expect("update applies");
        assert!(
            engine.on_tick(&pool).await.is_err(),
            "the engine fails fast on port zero"
        );
        assert_eq!(pool.sent(), 0, "no packet left for the port-zero target");
        pool.shutdown().await;
    }

    #[test]
    fn dual_stack_cone_plan_announces_both_families() {
        use crate::report::Role;
        let cfg = PunchConfig::default();
        let mut mine = sample_info(NatClass::Cone, &[5000, 5000]);
        let mut peer = sample_info(NatClass::Cone, &[6000, 6000]);
        let v6 = |port: u16| {
            Some(crate::nat::V6Nat {
                addrs: vec![SocketAddrV6::new(
                    [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into(),
                    port,
                    0,
                    0,
                )],
            })
        };
        mine.v6 = v6(1);
        peer.v6 = v6(1);
        let sel = select(&mine, &peer, &cfg).expect("cone pair selects");
        let plan = build_plan(
            &mine,
            &peer,
            &sel,
            1,
            [0; 16],
            Role::Initiator,
            Some(SocketAddr::from(([203, 0, 113, 1], 3478))),
            &cfg,
        );
        // The V6 stage publishes its own port; the cone V4 stage needs the
        // STUN refresh for its mapped port.
        assert!(plan.announce_v6);
        assert_eq!(plan.refresh_v4, Refresh::Stun);
        // The same pair without v6 keeps the single V4 refresh.
        mine.v6 = None;
        peer.v6 = None;
        let plan = build_plan(&mine, &peer, &sel, 1, [0; 16], Role::Initiator, None, &cfg);
        assert!(!plan.announce_v6);
        assert_eq!(plan.refresh_v4, Refresh::Stun);
    }

    /// A symmetric side with a confident stride announces its allocation
    /// position as a sequence marker, and the side predicting that sequence
    /// re-bases on it; a cone announce stays the port the peer aims at, and
    /// a hard symmetric side announces nothing.
    #[test]
    fn prediction_plans_announce_and_rebase() {
        use crate::report::Role;
        let cfg = PunchConfig::default();
        let easy = sample_info(NatClass::EasySym { step: 2 }, &[5000, 5002, 5004, 5006]);
        let cone = sample_info(NatClass::Cone, &[6000, 6000]);
        let hard = sample_info(NatClass::HardSym, &[5000, 5400, 5800, 6200]);

        // EasySym against cone: the cone announces the port the peer aims
        // at and predicts the easy peer's sequence; the easy side announces
        // its position as a marker.
        let sel = select(&easy, &cone, &cfg).expect("sym cone selects");
        let easy_plan = build_plan(&easy, &cone, &sel, 16, [0; 16], Role::Initiator, None, &cfg);
        assert_eq!(easy_plan.refresh_v4, Refresh::Stun);
        assert!(easy_plan.sequence_marker);
        assert!(!easy_plan.predicts_peer);
        let cone_plan = build_plan(&cone, &easy, &sel, 1, [0; 16], Role::Responder, None, &cfg);
        assert_eq!(cone_plan.refresh_v4, Refresh::Stun);
        assert!(!cone_plan.sequence_marker);
        assert!(cone_plan.predicts_peer);

        // EasySym against EasySym: both sides mark their sequence and
        // predict the peer's.
        let sel = select(&easy, &easy, &cfg).expect("easy pair selects");
        let plan = build_plan(&easy, &easy, &sel, 8, [0; 16], Role::Initiator, None, &cfg);
        assert_eq!(plan.refresh_v4, Refresh::Stun);
        assert!(plan.sequence_marker);
        assert!(plan.predicts_peer);

        // HardSym against cone: the hard side has no stride to mark, so it
        // announces nothing.
        let sel = select(&hard, &cone, &cfg).expect("hard cone selects");
        let hard_plan = build_plan(&hard, &cone, &sel, 16, [0; 16], Role::Initiator, None, &cfg);
        assert_eq!(hard_plan.refresh_v4, Refresh::None);
        assert!(!hard_plan.sequence_marker);
        let cone_plan = build_plan(&cone, &hard, &sel, 1, [0; 16], Role::Responder, None, &cfg);
        assert_eq!(cone_plan.refresh_v4, Refresh::Stun);
        assert!(!cone_plan.predicts_peer, "a hard peer carries no window");

        // PredictiveBurst: the easy side marks its sequence position, and
        // the hard side's continuation window re-bases on that mark.
        let sel = select(&easy, &hard, &cfg).expect("pred burst selects");
        let easy_plan = build_plan(&easy, &hard, &sel, 1, [0; 16], Role::Initiator, None, &cfg);
        assert_eq!(easy_plan.refresh_v4, Refresh::Stun);
        assert!(easy_plan.sequence_marker);
        assert!(!easy_plan.predicts_peer);
        let hard_plan = build_plan(&hard, &easy, &sel, 1, [0; 16], Role::Responder, None, &cfg);
        assert_eq!(hard_plan.refresh_v4, Refresh::None);
        assert!(!hard_plan.sequence_marker);
        assert!(hard_plan.predicts_peer);
    }

    /// A peer announce translates the fitted window onto the announced
    /// position without touching its length or order; a plan that predicts
    /// nothing, and an announce that repeats, rebuild nothing.
    #[test]
    fn peer_announce_rebases_the_prediction_window() {
        let cfg = PunchConfig::default();
        let at = |port: u16| SocketAddr::from(([203, 0, 113, 9], port));
        let window: Vec<SocketAddr> = (0..4).map(|i| at(5012 + i * 2)).collect();
        let plan = ExecPlan {
            stages: vec![StageSpec::send(
                Family::V4,
                1,
                window,
                false,
                cfg.punch_timeout,
            )],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: true,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<tokio::net::UdpSocket> =
            Engine::new(plan, cfg.clone(), [0; 16], tokio::time::Instant::now());
        engine.stage_idx = 0;

        // Without an announce the fitted window stands.
        let fitted = engine.live_targets().expect("fitted window resolves");
        assert_eq!(fitted[0], at(5012));

        // The announce moves the window onto the fresh position; the
        // stride and the order stay.
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: Some(6000),
                v6: None,
            })
            .expect("update applies");
        engine.apply_peer_base();
        let rebased = engine.live_targets().expect("rebased window resolves");
        let ports: Vec<u16> = rebased.iter().map(SocketAddr::port).collect();
        assert_eq!(ports, vec![6002, 6004, 6006, 6008]);
        assert_eq!(rebased.len(), fitted.len());

        // A retransmitted announce rebuilds nothing; a fresher port moves
        // the window again.
        engine.apply_peer_base();
        let again = engine.live_targets().expect("cached window resolves");
        assert!(Arc::ptr_eq(&rebased, &again));
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: Some(6010),
                v6: None,
            })
            .expect("update applies");
        engine.apply_peer_base();
        let moved = engine.live_targets().expect("moved window resolves");
        let ports: Vec<u16> = moved.iter().map(SocketAddr::port).collect();
        assert_eq!(ports, vec![6012, 6014, 6016, 6018]);

        // A plan that predicts nothing never re-bases.
        engine.plan.predicts_peer = false;
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: Some(7000),
                v6: None,
            })
            .expect("update applies");
        engine.apply_peer_base();
        let untouched = engine.live_targets().expect("window resolves");
        assert!(Arc::ptr_eq(&moved, &untouched));
    }

    /// The nominal end of a plan that runs Direct before the matrix stage
    /// lands at the punch deadline, not past it: the stage windows share
    /// the punch budget, so their sum never outlives the deadline the
    /// drive loop enforces.
    #[test]
    fn stage_ends_never_pass_the_punch_deadline() {
        let cfg = PunchConfig::default();
        let plan = ExecPlan {
            stages: vec![
                StageSpec::send(
                    Family::V6,
                    1,
                    vec![SocketAddr::V6(SocketAddrV6::new(
                        [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into(),
                        9999,
                        0,
                        0,
                    ))],
                    true,
                    cfg.direct_window,
                ),
                StageSpec::send(
                    Family::V4,
                    1,
                    vec![SocketAddr::from(([203, 0, 113, 9], 40000))],
                    true,
                    cfg.punch_timeout,
                ),
            ],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let punch_timeout = cfg.punch_timeout;
        let direct_window = cfg.direct_window;
        let mut engine: Engine<tokio::net::UdpSocket> =
            Engine::new(plan, cfg, [0; 16], tokio::time::Instant::now());
        let start = tokio::time::Instant::now();
        engine.start = Some(start);
        engine.punch_deadline = start + punch_timeout;
        assert_eq!(engine.stage_end(0), start + direct_window);
        assert_eq!(
            engine.stage_end(1),
            engine.punch_deadline,
            "the matrix stage ends at the deadline, not {direct_window:?} later"
        );
    }

    #[test]
    fn stray_packets_after_confirm_keep_the_winning_address() {
        use std::net::{Ipv4Addr, SocketAddrV4};
        let addr =
            |port: u16| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), port));
        let cfg = PunchConfig::default();
        // A multi-socket plan, the shape a SymProbe shooter runs.
        let plan = ExecPlan {
            stages: vec![StageSpec::send(
                Family::V4,
                4,
                vec![addr(40000)],
                true,
                cfg.punch_timeout,
            )],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<tokio::net::UdpSocket> =
            Engine::new(plan, cfg, [0; 16], tokio::time::Instant::now());
        let now = tokio::time::Instant::now();

        // Handshake traffic from two peer sockets on two local sockets.
        engine.observe_peer(5, addr(50_001), now, Family::V4, 1);
        engine.candidate = Some((Family::V4, 1));
        // The first complete handshake elects local socket 0 with peer
        // socket 2, mirroring the SynAck confirm path.
        engine.observe_peer(2, addr(50_002), now, Family::V4, 0);
        engine.confirmed = Some((Family::V4, 0));

        // Late Syn pulses from the peer's other sockets during grace.
        engine.observe_peer(9, addr(50_009), now, Family::V4, 3);
        engine.observe_peer(9, addr(50_009), now, Family::V4, 0);
        assert_eq!(engine.peer_addr, Some(addr(50_002)));
        assert_eq!(engine.peer_socket, Some(2));

        // A stray Ack for another local socket finishes nothing.
        engine.on_ack(addr(50_009), Family::V4, 3, now);
        assert!(!engine.finish_now);
        assert_eq!(engine.peer_addr, Some(addr(50_002)));

        // The winner's own handshake still refreshes and finishes.
        engine.on_ack(addr(50_002), Family::V4, 0, now);
        assert!(engine.finish_now);
        assert_eq!(engine.peer_addr, Some(addr(50_002)));
    }

    /// A budget that dies after the handshake started must stall the engine
    /// instead of failing it: the retransmission tick keeps its error and
    /// the grace mechanism decides the outcome.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn mid_handshake_budget_death_stalls_instead_of_failing() {
        use std::net::Ipv4Addr;

        use crate::socket::SocketPool;
        let peer = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 40000));
        // Every pool send fails on the budget check before touching a
        // socket.
        let cfg = PunchConfig {
            packet_budget: 0,
            ..PunchConfig::default()
        };
        let plan = ExecPlan {
            stages: vec![StageSpec::send(
                Family::V4,
                1,
                vec![peer],
                false,
                cfg.punch_timeout,
            )],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let net = crate::sim::Net::seeded("stall_grace");
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");
        // A handshake ran on socket 0 and its retransmission is due. The
        // pulse buffers normally come from `run`, which this test bypasses.
        engine.syn_bufs[0] = vec![encode_packet(&DataPacket::Syn {
            nonce: [0; 16],
            socket: 0,
        })];
        let now = tokio::time::Instant::now();
        engine.observe_peer(3, peer, now, Family::V4, 0);
        engine.candidate = Some((Family::V4, 0));
        engine.start = Some(now);
        engine.next_reply = now;

        engine.on_tick(&pool).await.expect("stall, not an error");
        assert!(engine.send_stalled, "sends stalled after the failure");
    }

    /// A SynAck reply that hits the conntrack bound skips only that
    /// destination: the sources already tracked keep their live path, and
    /// the engine never stalls on a bound the session can still work
    /// inside.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn conntrack_full_reply_skips_without_stalling() {
        use crate::socket::{RecvEvent, SocketPool};

        let cfg = PunchConfig {
            max_mappings: 1,
            ..PunchConfig::default()
        };
        let plan = ExecPlan {
            stages: vec![StageSpec::reply(Family::V4, cfg.punch_timeout)],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let net = crate::sim::Net::seeded("conntrack_reply_skip");
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");

        let syn = encode_packet(&DataPacket::Syn {
            nonce: [0; 16],
            socket: 4,
        });
        let event = |from: SocketAddr| {
            let mut buf = [0u8; crate::msg::MAX_DATA_PACKET];
            buf[..syn.len()].copy_from_slice(&syn);
            RecvEvent {
                family: Family::V4,
                socket: 0,
                from,
                len: syn.len(),
                buf,
            }
        };
        let a = SocketAddr::from(([203, 0, 113, 9], 50_001));
        let b = SocketAddr::from(([203, 0, 113, 9], 50_002));

        // Source A claims the only mapping slot with its reply.
        engine
            .on_data(&pool, event(a))
            .await
            .expect("first syn answers");
        assert_eq!(pool.sent(), 1);

        // Source B overflows the bound; its reply is skipped, nothing
        // stalls.
        engine
            .on_data(&pool, event(b))
            .await
            .expect("second syn skips the full bound");
        assert!(!engine.send_stalled, "conntrack exhaustion is no stall");
        assert_eq!(pool.sent(), 1);

        // The tracked source keeps its live path once the window passes.
        tokio::time::advance(cfg.confirm_retry).await;
        engine
            .on_data(&pool, event(a))
            .await
            .expect("tracked source answers again");
        assert_eq!(pool.sent(), 2);
    }

    /// A held spray emits nothing until the peer's traffic proves its
    /// mappings live, while the same stage without the hold pulses from
    /// the first tick; peer traffic and, failing that, one RTT plus a
    /// tick open the hold.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn held_spray_waits_for_peer_traffic() {
        use crate::socket::SocketPool;

        let cfg = PunchConfig::default();
        let addr = |port: u16| SocketAddr::from(([203, 0, 113, 9], port));
        let plan = |hold: bool| {
            let mut spec = StageSpec::send(
                Family::V4,
                1,
                vec![addr(40000), addr(40001)],
                false,
                cfg.punch_timeout,
            );
            spec.per_sweep = 1;
            spec.hold_for_peer = hold;
            ExecPlan {
                stages: vec![spec],
                refresh_v4: Refresh::None,
                announce_v6: false,
                refresh_server: None,
                predicts_peer: false,
                sequence_marker: false,
                peer_ip: [203, 0, 113, 9].into(),
                peer_v6: Vec::new(),
            }
        };
        let syn = encode_packet(&DataPacket::Syn {
            nonce: [0; 16],
            socket: 3,
        });
        let net = crate::sim::Net::seeded("held_spray");

        // The ungated stage spends every tick from the shared start.
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            plan(false),
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        engine.syn_bufs[0] = vec![syn.clone()];
        let start = tokio::time::Instant::now();
        engine.start = Some(start);
        engine.punch_deadline = start + cfg.punch_timeout;
        engine.peer_warm = start + cfg.punch_timeout;
        engine.on_tick(&pool).await.expect("tick runs");
        engine.on_tick(&pool).await.expect("tick runs");
        assert_eq!(pool.sent(), 2, "the ungated spray pulses every tick");
        pool.shutdown().await;

        // The held stage stays silent without peer traffic.
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            plan(true),
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        engine.syn_bufs[0] = vec![syn.clone()];
        let start = tokio::time::Instant::now();
        engine.start = Some(start);
        engine.punch_deadline = start + cfg.punch_timeout;
        engine.peer_warm = start + cfg.punch_timeout;
        engine.on_tick(&pool).await.expect("tick runs");
        engine.on_tick(&pool).await.expect("tick runs");
        assert_eq!(pool.sent(), 0, "no pulse before peer traffic");

        // Peer traffic opens the hold: the Syn earns its SynAck, and the
        // next tick pulses.
        let mut buf = [0u8; crate::msg::MAX_DATA_PACKET];
        buf[..syn.len()].copy_from_slice(&syn);
        let event = crate::socket::RecvEvent {
            family: Family::V4,
            socket: 0,
            from: addr(50_001),
            len: syn.len(),
            buf,
        };
        engine.on_data(&pool, event).await.expect("syn answered");
        assert_eq!(pool.sent(), 1, "the SynAck leaves immediately");
        engine.on_tick(&pool).await.expect("tick runs");
        assert_eq!(pool.sent(), 2, "pulses follow peer traffic");
        pool.shutdown().await;

        // Without any traffic, the RTT-plus-tick fallback opens the hold.
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            plan(true),
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        engine.syn_bufs[0] = vec![syn];
        let start = tokio::time::Instant::now();
        engine.start = Some(start);
        engine.punch_deadline = start + cfg.punch_timeout;
        engine.peer_warm = start + cfg.tick;
        engine.on_tick(&pool).await.expect("tick runs");
        assert_eq!(pool.sent(), 0, "the tick before the fallback holds");
        tokio::time::advance(cfg.tick).await;
        engine.on_tick(&pool).await.expect("tick runs");
        assert_eq!(pool.sent(), 1, "the fallback time opens the hold");
        pool.shutdown().await;
    }

    /// A sweep target that hits the conntrack bound is skipped for the
    /// round; later rounds keep pulsing the destinations already covered.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn conntrack_full_sweep_skips_new_targets_without_stalling() {
        use std::net::Ipv4Addr;

        use crate::socket::SocketPool;

        let addr = |port: u16| SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), port));
        let cfg = PunchConfig {
            max_mappings: 1,
            ..PunchConfig::default()
        };
        let plan = ExecPlan {
            stages: vec![StageSpec::send(
                Family::V4,
                1,
                vec![addr(40000), addr(40001)],
                false,
                cfg.punch_timeout,
            )],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let net = crate::sim::Net::seeded("conntrack_sweep_skip");
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");
        engine.syn_bufs[0] = vec![encode_packet(&DataPacket::Syn {
            nonce: [0; 16],
            socket: 0,
        })];
        // A handshake ran against the peer, so the session is past the
        // fail-fast point, and its retransmission timer stays out of the
        // way of the pulse accounting.
        let now = tokio::time::Instant::now();
        engine.observe_peer(3, addr(50_001), now, Family::V4, 0);
        engine.candidate = Some((Family::V4, 0));
        engine.start = Some(now);
        engine.next_reply = now + cfg.punch_timeout;

        // The first target takes the only mapping slot.
        engine.on_tick(&pool).await.expect("first tick pulses");
        assert_eq!(pool.sent(), 1);

        // The second target overflows the bound and is skipped; the sweep
        // still advances and nothing stalls.
        engine.on_tick(&pool).await.expect("second tick skips");
        assert!(!engine.send_stalled, "conntrack exhaustion is no stall");
        assert_eq!(pool.sent(), 1);

        // The rotation reaches the covered target again and pulses it.
        engine
            .on_tick(&pool)
            .await
            .expect("third tick pulses again");
        assert!(!engine.send_stalled);
        assert_eq!(pool.sent(), 2);
    }

    /// A sweep wider than the tick's rate share spans ticks: each tick emits
    /// at most its share of the rate grid and hands control back before the
    /// punch deadline, so events, signaling, and the deadline keep their
    /// cadence even at a rate cap far below the sweep width.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn low_rate_sweep_spans_ticks_without_blocking() {
        use crate::socket::SocketPool;

        // One packet per tick is the rate share: ceil(4 pps * 250 ms).
        let cfg = PunchConfig {
            packets_per_sec: 4,
            tick: Duration::from_millis(250),
            ..PunchConfig::default()
        };
        // Four senders covering four ports each: sixteen packets per sweep.
        let targets: Vec<SocketAddr> = (40_000..40_016)
            .map(|port| SocketAddr::from(([203, 0, 113, 9], port)))
            .collect();
        let mut spec = StageSpec::send(Family::V4, 4, targets, false, cfg.punch_timeout);
        spec.per_sweep = 4;
        let plan = ExecPlan {
            stages: vec![spec],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        engine.syn_bufs[0] = (0..4)
            .map(|i| {
                encode_packet(&DataPacket::Syn {
                    nonce: [0; 16],
                    socket: i,
                })
            })
            .collect();
        let net = crate::sim::Net::seeded("low_rate_sweep");
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 4, 0)
            .await
            .expect("pool binds");
        let start = tokio::time::Instant::now();
        engine.start = Some(start);
        engine.punch_deadline = start + cfg.punch_timeout;

        for tick in 0..16 {
            engine.on_tick(&pool).await.expect("tick runs");
            assert_eq!(
                pool.sent() as usize,
                tick + 1,
                "tick {tick} emitted its rate share only"
            );
            assert!(
                tokio::time::Instant::now() < engine.punch_deadline,
                "tick {tick} returned before the deadline"
            );
            tokio::time::advance(cfg.tick).await;
        }
        // The sweep finished across ticks; the next round starts over the
        // same rotation.
        engine.on_tick(&pool).await.expect("tick runs");
        assert_eq!(pool.sent(), 17, "the second round begins");
        pool.shutdown().await;
    }

    /// A binding response for the pending refresh only counts when it lands
    /// on the socket that sent the query; the same bytes on another socket
    /// answer nothing.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn refresh_answer_only_counts_on_the_querying_socket() {
        use crate::socket::{RecvEvent, SocketPool};

        /// One binding response reporting `port` for `txid`.
        fn binding_response(txid: [u8; 12], port: u16) -> Vec<u8> {
            let cookie = 0x2112_a442u32.to_be_bytes();
            let mut attr = vec![0x00, 0x01];
            attr.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
            let xip: Vec<u8> = [203u8, 0, 113, 30]
                .iter()
                .zip(cookie)
                .map(|(b, k)| b ^ k)
                .collect();
            attr.extend_from_slice(&xip);
            let mut resp = Vec::new();
            resp.extend_from_slice(&0x0101u16.to_be_bytes());
            // The length covers the cookie, transaction id, and attribute.
            let body_len = u16::try_from(4 + 12 + 4 + attr.len()).expect("fits a test message");
            resp.extend_from_slice(&body_len.to_be_bytes());
            resp.extend_from_slice(&cookie);
            resp.extend_from_slice(&txid);
            resp.extend_from_slice(&0x0020u16.to_be_bytes());
            resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
            resp.extend_from_slice(&attr);
            resp
        }

        let cfg = PunchConfig::default();
        let plan = ExecPlan {
            stages: vec![StageSpec::reply(Family::V4, cfg.punch_timeout)],
            refresh_v4: Refresh::Stun,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let server = SocketAddr::from(([203, 0, 113, 30], 3478));
        let txid = [7u8; 12];
        engine.stun = Some(StunPending {
            txid,
            request: Vec::new(),
            socket: 0,
            server,
            next_retry: tokio::time::Instant::now(),
            attempts_left: REFRESH_ATTEMPTS,
        });
        let net = crate::sim::Net::seeded("refresh_socket_guard");
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 2, 0)
            .await
            .expect("pool binds");
        let resp = binding_response(txid, 41_002);
        let event = |socket: u16| {
            let mut buf = [0u8; crate::msg::MAX_DATA_PACKET];
            buf[..resp.len()].copy_from_slice(&resp);
            RecvEvent {
                family: Family::V4,
                socket,
                from: server,
                len: resp.len(),
                buf,
            }
        };

        // The answer on socket 1 matches no query and changes nothing.
        engine
            .on_data(&pool, event(1))
            .await
            .expect("wrong-socket answer is ignored");
        assert!(engine.stun.is_some(), "the query stays pending");
        assert!(engine.own_ports.is_none(), "no port was announced");

        // The same answer on socket 0 completes the refresh.
        engine
            .on_data(&pool, event(0))
            .await
            .expect("querying socket accepts the answer");
        assert!(engine.stun.is_none(), "the query completed");
        assert_eq!(engine.own_ports.map(|ports| ports.v4), Some(Some(41_002)));
    }

    /// Refresh queries leave through the pool: they count in its stats, and
    /// a server that never answers exhausts the retries into an error
    /// instead of four silent failures.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn refresh_queries_flow_through_the_pool_and_surface_failure() {
        use crate::socket::SocketPool;

        let cfg = PunchConfig::default();
        let plan = ExecPlan {
            stages: vec![StageSpec::reply(Family::V4, cfg.punch_timeout)],
            refresh_v4: Refresh::Stun,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let server = SocketAddr::from(([203, 0, 113, 30], 3478));
        engine.stun = Some(StunPending {
            txid: [7u8; 12],
            request: crate::nat::probe::binding_request(&[7u8; 12]),
            socket: 0,
            server,
            next_retry: tokio::time::Instant::now(),
            attempts_left: REFRESH_ATTEMPTS,
        });
        let net = crate::sim::Net::seeded("refresh_via_pool");
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");
        engine.start = Some(tokio::time::Instant::now());

        // Every retry is a pool send and shows up in the stats.
        for sent in 1..=4 {
            engine.on_tick(&pool).await.expect("retry tick");
            assert_eq!(pool.sent(), sent, "retry {sent} went through the pool");
            tokio::time::advance(cfg.confirm_retry).await;
        }

        // A server that stays silent turns the exhausted retries into a
        // phase error for a session with no handshake traffic yet.
        let err = engine.on_tick(&pool).await.expect_err("retries exhausted");
        assert!(
            matches!(&err, PunchError::Io { phase: Phase::Punch, source }
                if source.to_string().contains("stun refresh")),
            "got {err:?}"
        );
        pool.shutdown().await;
    }

    /// Duplicate Syns share one SynAck per confirm window, so a flood
    /// cannot drain the reply budget; a second source still gets answered
    /// inside the same window, and the window passing re-arms a source.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn duplicate_syns_share_one_reply_per_window() {
        use crate::socket::{RecvEvent, SocketPool};

        let cfg = PunchConfig::default();
        let plan = ExecPlan {
            stages: vec![StageSpec::reply(Family::V4, cfg.punch_timeout)],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let net = crate::sim::Net::seeded("syn_reply_gate");
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");

        let syn = encode_packet(&DataPacket::Syn {
            nonce: [0; 16],
            socket: 4,
        });
        let event = |from: SocketAddr| {
            let mut buf = [0u8; crate::msg::MAX_DATA_PACKET];
            buf[..syn.len()].copy_from_slice(&syn);
            RecvEvent {
                family: Family::V4,
                socket: 0,
                from,
                len: syn.len(),
                buf,
            }
        };
        let a = SocketAddr::from(([203, 0, 113, 9], 50_001));
        let b = SocketAddr::from(([203, 0, 113, 9], 50_002));

        engine
            .on_data(&pool, event(a))
            .await
            .expect("first syn answers");
        let sent = pool.sent();
        // Duplicates inside the window stay silent but still refresh the
        // peer state.
        for _ in 0..4 {
            engine
                .on_data(&pool, event(a))
                .await
                .expect("duplicate syn");
        }
        assert_eq!(pool.sent(), sent);
        assert_eq!(engine.peer_addr, Some(a));
        assert_eq!(engine.candidate, Some((Family::V4, 0)));

        // A second distinct source earns its own reply inside the window.
        engine
            .on_data(&pool, event(b))
            .await
            .expect("second source answers");
        assert_eq!(pool.sent(), sent + 1);

        // The window passing re-arms the first source.
        tokio::time::advance(cfg.confirm_retry).await;
        engine
            .on_data(&pool, event(a))
            .await
            .expect("re-armed syn answers");
        assert_eq!(pool.sent(), sent + 2);
    }

    /// A SynAck from an address no stage targeted confirms nothing: no
    /// confirmation, no grace, no Ack reply, no recorded peer address.
    /// The same answer from the targeted address confirms, and grace
    /// alone still crowns that path when the peer's Confirmed frame never
    /// crosses the signaling channel.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn synack_from_unvisited_source_confirms_nothing() {
        use crate::socket::{RecvEvent, SocketPool};

        let cfg = PunchConfig::default();
        let target = SocketAddr::from(([203, 0, 113, 9], 40000));
        let plan = ExecPlan {
            stages: vec![StageSpec::send(
                Family::V4,
                1,
                vec![target],
                false,
                cfg.punch_timeout,
            )],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<crate::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let net = crate::sim::Net::seeded("synack_source_gate");
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");

        let synack = encode_packet(&DataPacket::SynAck {
            nonce: [0; 16],
            socket: 4,
        });
        let event = |from: SocketAddr| {
            let mut buf = [0u8; crate::msg::MAX_DATA_PACKET];
            buf[..synack.len()].copy_from_slice(&synack);
            RecvEvent {
                family: Family::V4,
                socket: 0,
                from,
                len: synack.len(),
                buf,
            }
        };
        let forged = SocketAddr::from(([198, 51, 100, 99], 50_009));
        // A symmetric peer answers from a fresh mapping port no target
        // list names, so the gate anchors on the peer's host.
        assert!(engine.syn_targeted(SocketAddr::from(([203, 0, 113, 9], 40_900))));
        assert!(!engine.syn_targeted(forged));
        engine
            .on_data(&pool, event(forged))
            .await
            .expect("forged synack is ignored");
        assert!(
            engine.confirmed.is_none(),
            "unvisited source confirms nothing"
        );
        assert!(engine.grace_end.is_none());
        assert!(engine.announce.is_none());
        assert_eq!(pool.sent(), 0, "no Ack answers an unvisited source");
        assert!(engine.peer_addr.is_none());
        assert!(engine.first_handshake.is_none());

        // The targeted address carries the confirmation, and its Ack leaves.
        engine
            .on_data(&pool, event(target))
            .await
            .expect("targeted synack confirms");
        assert_eq!(engine.confirmed, Some((Family::V4, 0)));
        assert_eq!(engine.announce, Some(0));
        assert_eq!(pool.sent(), 1, "the Ack answer left");

        // Grace alone crowns the confirmed path, which is what a peer
        // whose Confirmed frame was lost leaves this side with.
        let grace_end = engine.grace_end.expect("grace armed");
        assert!(!engine.finished(tokio::time::Instant::now()));
        assert!(engine.finished(grace_end));
    }

    /// A port-dependent stage earns its SynAcks from the peer's host once
    /// the peer announced a port: a cone answers from the announced port,
    /// an address-dependent mapping from a fresh one. Before the
    /// announcement, and from any other host, the answer confirms
    /// nothing.
    #[test]
    fn announced_port_opens_the_peer_host_for_synacks() {
        use std::net::{Ipv4Addr, SocketAddrV4};
        let peer_ip = Ipv4Addr::new(203, 0, 113, 9);
        let at = |ip: Ipv4Addr, port: u16| SocketAddr::V4(SocketAddrV4::new(ip, port));
        let cfg = PunchConfig::default();
        let plan = ExecPlan {
            // The stage carries the peer's dead probe address and waits on
            // its PortUpdate, the cone stage shape.
            stages: vec![StageSpec::send(
                Family::V4,
                1,
                vec![at(peer_ip, 40000)],
                true,
                cfg.punch_timeout,
            )],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip,
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<tokio::net::UdpSocket> =
            Engine::new(plan, cfg, [0; 16], tokio::time::Instant::now());

        // No announcement yet: the stage never sent, so nothing confirms.
        assert!(!engine.syn_targeted(at(peer_ip, 40000)));

        // The announcement starts the sweeps at the announced port.
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: Some(41000),
                v6: None,
            })
            .expect("update applies");
        assert!(engine.syn_targeted(at(peer_ip, 41000)));
        // A fresh mapping port of the same host still answered our sweeps.
        assert!(engine.syn_targeted(at(peer_ip, 41777)));
        // Any other host stayed unvisited.
        assert!(!engine.syn_targeted(at(Ipv4Addr::new(198, 51, 100, 99), 41000)));
    }

    /// An Ack proves the exchange only of the socket that answered a Syn
    /// from the Ack's host, which is the socket the Ack landed on. A
    /// landing socket with no answered Syn from that host confirms
    /// nothing, a fresh mapping port of an answered host still counts,
    /// and a proven landing socket wins over a candidate another source
    /// set first.
    #[test]
    fn ack_confirms_the_socket_that_answered_the_source() {
        use std::net::{Ipv4Addr, SocketAddrV4};
        let peer = Ipv4Addr::new(203, 0, 113, 9);
        let at = |ip: Ipv4Addr, port: u16| SocketAddr::V4(SocketAddrV4::new(ip, port));
        let cfg = PunchConfig::default();
        let plan = ExecPlan {
            stages: vec![StageSpec::reply(Family::V4, cfg.punch_timeout)],
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: peer,
            peer_v6: Vec::new(),
        };
        let mut engine: Engine<tokio::net::UdpSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let now = tokio::time::Instant::now();
        let first = at(peer, 50_001);
        let second = at(peer, 50_002);

        // Socket 1 answered the first source; socket 0 answered a second.
        engine.observe_peer(5, first, now, Family::V4, 1);
        engine.candidate = Some((Family::V4, 1));
        engine
            .syn_replies
            .insert((1, first), now + cfg.confirm_retry);
        engine
            .syn_replies
            .insert((0, second), now + cfg.confirm_retry);

        // An Ack from a host no socket answered moves nothing, whatever
        // socket it lands on.
        let foreign = at(Ipv4Addr::new(198, 51, 100, 99), 50_009);
        engine.on_ack(foreign, Family::V4, 0, now);
        assert!(engine.confirmed.is_none());
        assert!(!engine.finish_now);

        // The Ack on socket 0 crowns socket 0 through a fresh mapping
        // port of the answered host, the symmetric peer's shape, not the
        // candidate socket 1.
        let fresh_port = at(peer, 50_077);
        engine.on_ack(fresh_port, Family::V4, 0, now);
        assert_eq!(engine.confirmed, Some((Family::V4, 0)));
        assert_eq!(engine.announce, Some(0));
        assert!(engine.finish_now);
        assert_eq!(engine.peer_addr, Some(fresh_port));
    }

    #[test]
    fn peer_without_v4_skips_the_direct_stage() {
        use crate::report::Role;
        let cfg = PunchConfig::default();
        // A public local side against a peer that reported no v4 and no v6:
        // no IPv4 evidence is not a public claim, so Direct does not even
        // qualify, and no stage builder finds a target either way.
        let mine = sample_info(NatClass::Public, &[5000, 5000]);
        let peer = NatInfo { v4: None, v6: None };
        assert!(!direct_first(&mine, &peer, &cfg));
        let sel = select(&mine, &peer, &cfg).expect("both public select");
        let plan = build_plan(&mine, &peer, &sel, 1, [0; 16], Role::Initiator, None, &cfg);
        assert!(
            plan.stages.iter().all(|s| s.duration != cfg.direct_window),
            "no Direct stage without a peer address"
        );
        // The same peer with a reflexive address gets the Direct stage.
        let peer = sample_info(NatClass::Public, &[6000, 6000]);
        let plan = build_plan(&mine, &peer, &sel, 1, [0; 16], Role::Initiator, None, &cfg);
        assert!(
            plan.stages.iter().any(|s| s.duration == cfg.direct_window),
            "a public pair runs Direct"
        );
    }

    fn sample_info(class: NatClass, seq: &[u16]) -> NatInfo {
        use std::net::SocketAddrV4;
        NatInfo {
            v4: Some(crate::nat::V4Nat {
                class,
                reflexive: SocketAddrV4::new([203, 0, 113, 7].into(), seq[0]),
                alloc_seq: seq.to_vec(),
                distinct_probe_ips: 2,
                filtering: crate::nat::FilterClass::Unknown,
            }),
            v6: None,
        }
    }
}
