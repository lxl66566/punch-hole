//! Strategy selection over the pair of NAT readings.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use super::{
    birthday, cone, direct, easy_sym,
    engine::{Refresh, StageSpec},
    model::{
        PREDICTION_WINDOW_CAP, PREDICTION_WINDOW_MULTIPLE, burst_hit_chance, peer_space,
        predictive_burst_estimate, size_burst, spray_count, spray_hit_chance,
    },
    predictive_burst, sym_cone,
};
use crate::{
    config::{IpPolicy, PunchConfig},
    error::PunchError,
    msg::{Nonce, StrategyId},
    nat::{FilterClass, NatClass, NatInfo, classify::easy_confident},
    socket::Family,
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
                // ambiguous NAT's inbound filtering and allocation walk,
                // which the probe does not measure, so no number is stated.
                let either_symmetric =
                    is_symmetric(effective_class(mine)) || is_symmetric(effective_class(peer));
                either_symmetric.then(|| sym_probe_estimate(mine, peer, self, cfg))
            },
            StrategyId::BirthdayBurst => {
                let (space_i, space_r) = (peer_space(mine), peer_space(peer));
                let sized = size_burst(space_i, space_r, cfg);
                Some(burst_hit_chance(
                    &sized,
                    space_i,
                    space_r,
                    filter_of(mine),
                    filter_of(peer),
                ))
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

/// The filtering evidence a side's IPv4 probe carries.
///
/// A side without IPv4 evidence never reaches a symmetric-pair model, so
/// the missing reading reads as `Unknown`, the regime the models assumed
/// before the probe grew its filtering tests.
fn filter_of(info: &NatInfo) -> FilterClass {
    info.v4
        .as_ref()
        .map_or(FilterClass::Unknown, |v4| v4.filtering)
}

/// Whether both sides measured address-and-port-dependent filtering.
///
/// Under a port-strict filter, a hit into one side also needs the
/// sender's source port to pair with the destination the receiver's
/// mapping wrote, which is the regime no one-directional model describes.
/// One non-port-strict side suffices for a one-directional handshake: its
/// mapping admits any source on the peer's address, and the port-strict
/// side's own mapping admits the reply that names the destination it
/// wrote. `Unknown` reads as non-port-strict, the documented assumption.
fn pair_port_strict(mine: &NatInfo, peer: &NatInfo) -> bool {
    filter_of(mine) == FilterClass::AddressPortDependent
        && filter_of(peer) == FilterClass::AddressPortDependent
}

/// The shared-NAT reading over the pair's IPv4 evidence: whether both
/// reflexive addresses sit on one IP, and whether both sides measured
/// their NAT hairpinning.
///
/// A side without IPv4 evidence reports neither fact.
fn shared_nat_shape(mine: &NatInfo, peer: &NatInfo) -> (bool, bool) {
    match (&mine.v4, &peer.v4) {
        (Some(a), Some(b)) => (a.reflexive.ip() == b.reflexive.ip(), a.hairpin && b.hairpin),
        _ => (false, false),
    }
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

    // Two hosts whose reflexive addresses share one NAT that hairpins for
    // neither can only punch over the LAN underneath it or over IPv6:
    // every reflexive-aimed stage dies at the NAT's own loopback drop.
    // With neither path available the pair is honestly dead, and the
    // attempt aborts here instead of burning the punch window on targets
    // no packet can reach. One side's local list suffices for the LAN,
    // because the side that holds one aims and the other replies from the
    // source it observes.
    let both_v6 = cfg.ip_policy.allows_v6()
        && mine.v6.as_ref().is_some_and(|v6| !v6.addrs.is_empty())
        && peer.v6.as_ref().is_some_and(|v6| !v6.addrs.is_empty());
    let (same_ip, both_hairpin) = shared_nat_shape(mine, peer);
    let shared_dead_end =
        same_ip && !both_hairpin && !both_v6 && mine.local.is_empty() && peer.local.is_empty();
    if shared_dead_end {
        return Err(PunchError::Unpunchable {
            local: mine_class,
            peer: peer_class,
        });
    }

    // A v6-only policy drops the IPv4 matrix: the Direct stage over IPv6
    // is the whole plan, one socket per side, the same shape a public
    // IPv4 pair resolves to. A pair without a v6 path on both sides has
    // nothing to run and aborts here.
    if cfg.ip_policy == IpPolicy::Ipv6Only {
        if !both_v6 {
            return Err(PunchError::Unpunchable {
                local: mine_class,
                peer: peer_class,
            });
        }
        return Ok(Selection {
            strategy: StrategyId::ConeExchange,
            initiator_sockets: 1,
            responder_sockets: 1,
            estimate: None,
        });
    }

    // Two reflexive addresses on one IP that both hairpinned prove one
    // endpoint-independent mapping serves each socket: a per-destination
    // mapping fails the self-loop, so the cone reading needs no second
    // server IP, and the matrix shape that punches a shared NAT is the
    // mutual sweep.
    let hairpin_proven_cone = same_ip && both_hairpin;
    if !i_am_symmetric
        && !peer_is_symmetric
        && ((cone_confident(mine) && cone_confident(peer)) || hairpin_proven_cone)
    {
        // Cone against cone, or public against either: one socket per
        // side aimed at the reflexive address.
        return Ok(Selection {
            strategy: StrategyId::ConeExchange,
            initiator_sockets: 1,
            responder_sockets: 1,
            estimate: None,
        });
    }
    // Every remaining pair with at most one symmetric side runs SymProbe:
    // either exactly one side is symmetric, or both sides read as cones
    // without the confidence a ConeExchange needs. A cone reading from a
    // single-IP fan-out or a single sample may be an address-dependent
    // symmetric NAT seen through one mapping, and ConeExchange fails
    // against that reading; SymProbe's shooter shape survives either
    // truth, because the shooter's sockets punch whether the ambiguous
    // side turns out to be a cone or symmetric.
    if !i_am_symmetric || !peer_is_symmetric {
        // The shooter side holds the assistant sockets and the other side
        // replies one socket: the symmetric side shoots, or with no
        // symmetric side the ambiguous reading shoots.
        let shooter = cfg.assistant_sockets;
        let (initiator_sockets, responder_sockets) =
            if initiator_shoots(mine, peer) { (shooter, 1) } else { (1, shooter) };
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
        // Both port-strict filters invalidate the one-directional regime
        // every predictable-window strategy leans on, so the pair routes
        // to the burst sizing, whose arithmetic states the pairing penalty
        // and refuses the pair below `min_success`.
        (NatClass::EasySym { .. }, NatClass::EasySym { .. }) if !pair_port_strict(mine, peer) => {
            Ok(Selection {
                strategy: StrategyId::PredictiveExchange,
                initiator_sockets: cfg.predictive_sockets,
                responder_sockets: cfg.predictive_sockets,
                estimate: None,
            })
        },
        // One predictable side is enough: the side facing the easy peer
        // aims its continuation window, the side facing the hard peer
        // keeps its random spray, and either direction completes the
        // handshake. A demoted easy fit lands here with its confident
        // peer, so the predictable side still gets used instead of a
        // birthday attack against it.
        (NatClass::EasySym { .. }, NatClass::HardSym)
        | (NatClass::HardSym, NatClass::EasySym { .. })
            if !pair_port_strict(mine, peer) =>
        {
            Ok(Selection {
                strategy: StrategyId::PredictiveBurst,
                initiator_sockets: 1,
                responder_sockets: 1,
                estimate: Some(predictive_burst_estimate()),
            })
        },
        _ => {
            // The estimate picks its regime from the measured filters: one
            // non-port-strict side admits a one-directional hit, the
            // common CGNAT shape; two port-strict sides need both
            // directions to pair exactly, which the model prices honestly.
            let sized = size_burst(peer_space(mine), peer_space(peer), cfg);
            let estimate = burst_hit_chance(
                &sized,
                peer_space(mine),
                peer_space(peer),
                filter_of(mine),
                filter_of(peer),
            );
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
/// IPv4 paths are public, each family subject to the policy.
pub(crate) fn direct_first(mine: &NatInfo, peer: &NatInfo, cfg: &PunchConfig) -> bool {
    let both_v6 = cfg.ip_policy.allows_v6()
        && mine.v6.as_ref().is_some_and(|v6| !v6.addrs.is_empty())
        && peer.v6.as_ref().is_some_and(|v6| !v6.addrs.is_empty());
    // A public path is an observed claim, so a side without IPv4 evidence
    // never qualifies: its v4 Direct stage would have skipped itself for
    // lack of a reflexive address anyway. A cached reading under a v6-only
    // policy does not qualify either.
    let both_public = cfg.ip_policy.allows_v4()
        && matches!(
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
pub(super) fn usable_peer_v6(ip: Ipv6Addr) -> bool {
    crate::nat::usable_v6(ip)
}

/// Whether a peer-signaled local address is worth a Local stage packet.
///
/// The Local stage aims at the LAN underneath a shared NAT, so the list
/// keeps loopback, which lab tests stand in for a LAN with, and drops
/// the shapes that name no peer: unspecified, multicast, and broadcast.
/// One predicate decides both whether the stage exists and which
/// addresses the engine aims its sweeps at.
pub(super) fn local_stage_reachable(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

/// SymProbe's hit chance from the one-directional spray model.
///
/// The cone side covers `c` candidate ports inside the symmetric peer's port
/// space, where the peer holds `m` live mappings, so the one-directional
/// formula gives the chance.
fn sym_probe_estimate(mine: &NatInfo, peer: &NatInfo, sel: &Selection, cfg: &PunchConfig) -> f64 {
    // Exactly one side is symmetric, and it holds the shooter count, which is
    // the larger of the two socket counts.
    let sym = if is_symmetric(effective_class(mine)) { mine } else { peer };
    let m = sel.initiator_sockets.max(sel.responder_sockets) as usize;
    let space = peer_space(sym);
    let c = spray_count(m, space, cfg);
    spray_hit_chance(m, c, space)
}

/// The full stage list one side executes.
// The booleans are independent plan facts a strategy mixes freely, not
// states of one axis, so they stay flags.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ExecPlan {
    pub stages: Vec<StageSpec>,
    /// Whether this side is the attempt's Initiator. The handshake's pair
    /// arbitration ranks a pair with the Initiator's socket first, so both
    /// ends order their candidate pairs identically without exchanging
    /// anything beyond the Ack's socket field.
    pub initiator: bool,
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
    /// The peer's local interface addresses, from its Hello, for a stage
    /// with `local_targets`.
    pub peer_local: Vec<Ipv4Addr>,
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
    // Two hosts whose reflexive addresses share one NAT that hairpins for
    // neither reach each other only on the LAN underneath it: every matrix
    // stage aims at the shared public address, where the NAT drops its own
    // loopback traffic. The Local stage replaces the matrix for the pair,
    // and the announce that feeds it names the local punch port, which is
    // the port the peer aims at when no NAT sits between.
    let (same_ip, both_hairpin) = shared_nat_shape(mine, peer);
    // The Local stage is an IPv4 stage, so a v6-only policy drops it along
    // with the matrix; cached IPv4 evidence cannot revive either.
    let local_only = cfg.ip_policy.allows_v4() && same_ip && !both_hairpin;

    let mut stages = Vec::new();
    if direct_first(mine, peer, cfg) {
        stages.extend(direct::stage(mine, peer, cfg));
    }
    if local_only {
        stages.extend(direct::local_stage(peer, cfg));
    }
    if !local_only && cfg.ip_policy.allows_v4() {
        match sel.strategy {
            StrategyId::ConeExchange => stages.extend(cone::stage(peer, cfg)),
            StrategyId::SymProbe => {
                // The socket counts carry the shape: the shooter side holds
                // the assistant count, the replying side one socket. A tie is
                // one assistant socket per side, which the initiator shoots,
                // so the derivation stays role-keyed instead of re-reading
                // the classes the Offer may have crossed.
                let i_shoot = match role {
                    crate::report::Role::Initiator => {
                        sel.initiator_sockets >= sel.responder_sockets
                    },
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
                let window =
                    (my_sockets as usize * peer_sockets as usize * PREDICTION_WINDOW_MULTIPLE)
                        .min(PREDICTION_WINDOW_CAP);
                stages.extend(easy_sym::stage(my_sockets, peer, window, cfg));
            },
            StrategyId::PredictiveBurst => {
                let i_am_easy = matches!(effective_class(mine), NatClass::EasySym { .. });
                // The sizing always reads the hard side's space, whichever
                // side builds the stage, so both roles derive the same
                // coverage pair from the same views.
                let hard_space = if i_am_easy { peer_space(peer) } else { peer_space(mine) };
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
    // A local-only plan announces the pool socket's own port: the peer's
    // Local stage aims there, and no NAT sits between to remap it.
    let refresh_v4 = if local_only {
        Refresh::Local
    } else if !cfg.ip_policy.allows_v4() {
        Refresh::None
    } else {
        match sel.strategy {
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
        }
    };
    // The announce of a symmetric side marks its sequence position, while
    // every other announce names the port the peer aims at.
    let sequence_marker = refresh_v4 == Refresh::Stun && my_sym;
    // Prediction stages carry a fitted window over the peer's sequence:
    // PredictiveExchange always, the SymProbe cone side against an easy
    // symmetric peer, and the hard side of a PredictiveBurst pair, whose
    // window covers the easy peer's continuation and moves with its
    // announced position the same way. The SymProbe reply side against an
    // ambiguous cone peer carries a forward window from the peer's one
    // observed port, which the announce re-base moves onto the shooter's
    // live block the same way.
    let predicts_peer = match sel.strategy {
        StrategyId::PredictiveExchange => true,
        StrategyId::SymProbe => {
            !my_sym
                && matches!(
                    peer_class,
                    NatClass::EasySym { .. } | NatClass::Cone | NatClass::Public
                )
        },
        StrategyId::PredictiveBurst => matches!(peer_class, NatClass::EasySym { .. }),
        _ => false,
    };

    ExecPlan {
        stages,
        initiator: role == crate::report::Role::Initiator,
        refresh_v4,
        announce_v6,
        refresh_server,
        predicts_peer,
        sequence_marker,
        peer_ip: peer
            .reflexive_v4()
            .map_or(Ipv4Addr::UNSPECIFIED, |a| *a.ip()),
        peer_v6: peer.v6.as_ref().map_or(Vec::new(), |v6| v6.addrs.clone()),
        peer_local: peer.local.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use super::*;
    use crate::nat::FilterClass::Unknown;

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
        // The two sides sit behind different NATs: one reflexive IP on
        // both, with hairpin measured, would read as a shared-NAT pair.
        single_ip.v4.as_mut().expect("v4 evidence").reflexive =
            SocketAddrV4::new([203, 0, 113, 8].into(), 50_000);
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
        // Different reflexive IPs keep it off the shared-NAT reading.
        let mut one_sample = sample_info(NatClass::Cone, &[50_000]);
        one_sample.v4.as_mut().expect("v4 evidence").reflexive =
            SocketAddrV4::new([203, 0, 113, 9].into(), 50_000);
        let mut peer_sample = one_sample.clone();
        peer_sample.v4.as_mut().expect("v4 evidence").reflexive =
            SocketAddrV4::new([203, 0, 113, 10].into(), 50_000);
        let sel = select(&one_sample, &peer_sample, &cfg).expect("thin samples select");
        assert_eq!(sel.strategy, StrategyId::SymProbe);
        assert_eq!((sel.initiator_sockets, sel.responder_sockets), (1, 16));
    }

    /// One reflexive IP on both sides plus a measured hairpin proves one
    /// endpoint-independent mapping per socket — a per-destination mapping
    /// fails the self-loop — so a cone reading built from a single server
    /// IP routes to the mutual sweep instead of SymProbe, whose reply-side
    /// spray cannot punch a shared NAT.
    #[test]
    fn shared_nat_hairpin_proves_the_cone_reading() {
        let mut a = sample_info(NatClass::Cone, &[50_000, 50_000, 50_000, 50_000]);
        let mut b = a.clone();
        b.v4.as_mut().expect("v4 evidence").reflexive =
            SocketAddrV4::new([203, 0, 113, 7].into(), 50_001);
        a.v4.as_mut().expect("v4 evidence").distinct_probe_ips = 1;
        b.v4.as_mut().expect("v4 evidence").distinct_probe_ips = 1;
        let cfg = PunchConfig::default();
        assert_eq!(
            select(&a, &b, &cfg)
                .expect("hairpin evidence proves the cone")
                .strategy,
            StrategyId::ConeExchange
        );
    }

    /// Two hosts whose reflexive addresses share one NAT that hairpins
    /// for neither can only punch over the LAN underneath it: every
    /// reflexive-aimed stage dies at the NAT's own loopback drop. With no
    /// local addresses on either side and no IPv6 path, Negotiate aborts
    /// before any socket opens.
    #[test]
    fn same_nat_without_hairpin_or_lan_aborts_in_negotiate() {
        let mut a = sample_info(NatClass::Cone, &[50_000, 50_000, 50_000, 50_000]);
        let mut b = sample_info(NatClass::Cone, &[50_000, 50_000, 50_000, 50_000]);
        for info in [&mut a, &mut b] {
            info.v4.as_mut().expect("v4 evidence").hairpin = false;
        }
        let cfg = PunchConfig::default();
        assert!(matches!(
            select(&a, &b, &cfg),
            Err(PunchError::Unpunchable { .. })
        ));
        // A global IPv6 path on both sides rescues the pair: the Direct
        // stage needs no NAT cooperation.
        for info in [&mut a, &mut b] {
            info.v6 = Some(crate::nat::V6Nat {
                addrs: vec![SocketAddrV6::new(
                    "2001:db8::1".parse().expect("global address"),
                    5000,
                    0,
                    0,
                )],
            });
        }
        assert!(select(&a, &b, &cfg).is_ok(), "v6 rescues a dead v4 pair");
    }

    /// One side's local list is enough for the LAN: the side that holds
    /// one aims at the peer's local addresses and the other replies from the
    /// source it observes. The local-only plan announces the pool
    /// socket's own port, because no NAT sits between to remap it, and
    /// no matrix stage runs whose targets would die at the NAT.
    #[test]
    fn same_nat_without_hairpin_runs_the_local_stage() {
        use crate::report::Role;

        let mut a = sample_info(NatClass::Cone, &[50_000, 50_000, 50_000, 50_000]);
        let mut b = sample_info(NatClass::Cone, &[50_000, 50_000, 50_000, 50_000]);
        for info in [&mut a, &mut b] {
            info.v4.as_mut().expect("v4 evidence").hairpin = false;
        }
        a.local = vec![[192, 168, 1, 10].into()];
        b.local = vec![[192, 168, 1, 20].into()];
        let cfg = PunchConfig::default();
        let sel = select(&a, &b, &cfg).expect("the LAN rescues the pair");
        let plan = build_plan(&a, &b, &sel, 1, [0; 16], Role::Initiator, None, &cfg);
        let local = plan.stages.last().expect("the local stage");
        assert!(local.local_targets);
        assert!(local.needs_peer_ports);
        assert_eq!(local.duration, cfg.direct_window);
        assert_eq!(plan.refresh_v4, Refresh::Local);
        assert!(
            plan.stages.iter().all(|s| s.duration <= cfg.direct_window),
            "no matrix stage survives a local-only plan"
        );
        // Hairpinning measured on both sides restores the matrix and its
        // STUN refresh, and no local stage runs.
        for info in [&mut a, &mut b] {
            info.v4.as_mut().expect("v4 evidence").hairpin = true;
        }
        let sel = select(&a, &b, &cfg).expect("hairpin pair selects");
        let plan = build_plan(&a, &b, &sel, 1, [0; 16], Role::Initiator, None, &cfg);
        assert!(!plan.stages.iter().any(|s| s.local_targets));
        assert_eq!(plan.refresh_v4, Refresh::Stun);
    }

    /// Both port-strict filters invalidate the one-directional regime the
    /// burst model states: the estimate prices the pairing penalty, which
    /// the default budget cannot clear, so Negotiate refuses the pair.
    /// One relaxed filter — `Unknown` included — restores the historical
    /// assumption and the estimate with it.
    #[test]
    fn port_strict_symmetric_pairs_go_unpunchable() {
        use crate::nat::FilterClass;
        let seq = [31_000, 33_000, 35_000, 37_000];
        let mut a = sample_info(NatClass::HardSym, &seq);
        let mut b = sample_info(NatClass::HardSym, &seq);
        for info in [&mut a, &mut b] {
            info.v4.as_mut().expect("v4 evidence").filtering = FilterClass::AddressPortDependent;
        }
        let cfg = PunchConfig::default();
        assert!(matches!(
            select(&a, &b, &cfg),
            Err(PunchError::Unpunchable { .. })
        ));
        b.v4.as_mut().expect("v4 evidence").filtering = FilterClass::AddressDependent;
        let sel = select(&a, &b, &cfg).expect("one relaxed side selects");
        assert_eq!(sel.strategy, StrategyId::BirthdayBurst);
        assert!(sel.estimate.expect("burst estimate") >= cfg.min_success);
        b.v4.as_mut().expect("v4 evidence").filtering = Unknown;
        assert!(select(&a, &b, &cfg).is_ok(), "unknown reads as relaxed");
    }

    /// The predictable-window strategies lean on the same one-directional
    /// regime, so both port-strict filters demote the pair to the burst
    /// sizing. The quadratic regime still admits a narrow enough space,
    /// where full coverage buys the pairing honestly.
    #[test]
    fn port_strict_filters_demote_the_window_strategies() {
        use crate::nat::FilterClass;
        let cfg = PunchConfig::default();
        let mut easy = sample_info(NatClass::EasySym { step: 2000 }, &[
            31_000, 33_000, 35_000, 37_000,
        ]);
        let mut other = easy.clone();
        for info in [&mut easy, &mut other] {
            info.v4.as_mut().expect("v4 evidence").filtering = FilterClass::AddressPortDependent;
        }
        // A wide space prices the pairing below the bar for both window
        // strategies.
        assert!(matches!(
            select(&easy, &other, &cfg),
            Err(PunchError::Unpunchable { .. })
        ));
        let mut hard = sample_info(NatClass::HardSym, &[31_000, 33_000, 35_000, 37_000]);
        hard.v4.as_mut().expect("v4 evidence").filtering = FilterClass::AddressPortDependent;
        assert!(matches!(
            select(&easy, &hard, &cfg),
            Err(PunchError::Unpunchable { .. })
        ));
        // One relaxed side keeps the window strategies.
        other.v4.as_mut().expect("v4 evidence").filtering = FilterClass::AddressDependent;
        assert_eq!(
            select(&easy, &other, &cfg).expect("relaxed pair").strategy,
            StrategyId::PredictiveExchange
        );
        other.v4.as_mut().expect("v4 evidence").class = NatClass::HardSym;
        assert_eq!(
            select(&easy, &other, &cfg).expect("relaxed pair").strategy,
            StrategyId::PredictiveBurst
        );
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

        // Ambiguous cone against ambiguous cone, a single-IP fan-out on
        // both sides: neither reading is confident, the pair routes to
        // SymProbe, and the reply side's forward window re-bases on the
        // shooter's announce, which names its live block's first port.
        let ambiguous = |mut info: NatInfo| {
            info.v4.as_mut().expect("v4 evidence").distinct_probe_ips = 1;
            info
        };
        let (ac, mut bc) = (ambiguous(cone.clone()), ambiguous(cone));
        // Distinct reflexive IPs, or the pair reads as one shared hairpin
        // NAT and ConeExchange takes it.
        bc.v4.as_mut().expect("v4 evidence").reflexive = SocketAddrV4::new(
            [198, 51, 100, 9].into(),
            bc.v4.as_ref().expect("v4").reflexive.port(),
        );
        let sel = select(&ac, &bc, &cfg).expect("ambiguous cone pair selects");
        assert_eq!(sel.strategy, StrategyId::SymProbe);
        let plan = build_plan(&ac, &bc, &sel, 1, [0; 16], Role::Initiator, None, &cfg);
        assert_eq!(plan.refresh_v4, Refresh::Stun);
        assert!(!plan.sequence_marker);
        assert!(plan.predicts_peer, "the forward window rides the announce");
    }

    #[test]
    fn peer_without_v4_skips_the_direct_stage() {
        use crate::report::Role;
        let cfg = PunchConfig::default();
        // A public local side against a peer that reported no v4 and no v6:
        // no IPv4 evidence is not a public claim, so Direct does not even
        // qualify, and no stage builder finds a target either way.
        let mine = sample_info(NatClass::Public, &[5000, 5000]);
        let peer = NatInfo {
            v4: None,
            v6: None,
            local: Vec::new(),
        };
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

    /// A v6-only policy drops the IPv4 matrix wholesale: the plan is the
    /// v6 Direct stage alone with no v4 refresh to announce, and a pair
    /// without a v6 path on both sides aborts as unpunchable. Cached IPv4
    /// evidence cannot revive a v4 stage under the policy.
    #[test]
    fn v6_only_policy_plans_the_direct_stage_alone() {
        use crate::report::Role;

        let cfg = PunchConfig {
            ip_policy: IpPolicy::Ipv6Only,
            ..PunchConfig::default()
        };
        let mut mine = sample_info(NatClass::Cone, &[5000, 5000]);
        let mut peer = sample_info(NatClass::EasySym { step: 2 }, &[6000, 6002, 6004, 6006]);
        let v6 = || {
            Some(crate::nat::V6Nat {
                addrs: vec![SocketAddrV6::new(
                    [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into(),
                    5000,
                    0,
                    0,
                )],
            })
        };
        mine.v6 = v6();
        peer.v6 = v6();
        let sel = select(&mine, &peer, &cfg).expect("a v6 pair selects");
        assert_eq!(sel.strategy, StrategyId::ConeExchange);
        assert_eq!((sel.initiator_sockets, sel.responder_sockets), (1, 1));
        let plan = build_plan(&mine, &peer, &sel, 1, [0; 16], Role::Initiator, None, &cfg);
        assert_eq!(plan.stages.len(), 1, "the Direct stage alone");
        assert_eq!(plan.stages[0].family, Family::V6);
        assert_eq!(plan.refresh_v4, Refresh::None);
        assert!(!plan.sequence_marker);
        assert!(!plan.predicts_peer);

        peer.v6 = None;
        assert!(matches!(
            select(&mine, &peer, &cfg),
            Err(PunchError::Unpunchable { .. })
        ));
    }

    /// An IPv4-only policy ignores v6 evidence: no v6 Direct stage, no v6
    /// announce, the plain v4 matrix.
    #[test]
    fn v4_only_policy_ignores_v6_evidence() {
        use crate::report::Role;

        let cfg = PunchConfig {
            ip_policy: IpPolicy::Ipv4Only,
            ..PunchConfig::default()
        };
        let mut mine = sample_info(NatClass::Cone, &[5000, 5000]);
        let mut peer = sample_info(NatClass::Cone, &[6000, 6000]);
        let v6 = || {
            Some(crate::nat::V6Nat {
                addrs: vec![SocketAddrV6::new(
                    [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into(),
                    5000,
                    0,
                    0,
                )],
            })
        };
        mine.v6 = v6();
        peer.v6 = v6();
        assert!(!direct_first(&mine, &peer, &cfg));
        let sel = select(&mine, &peer, &cfg).expect("a cone pair selects");
        let plan = build_plan(&mine, &peer, &sel, 1, [0; 16], Role::Initiator, None, &cfg);
        assert!(plan.stages.iter().all(|s| s.family == Family::V4));
        assert!(!plan.announce_v6);
    }

    fn sample_info(class: NatClass, seq: &[u16]) -> NatInfo {
        use std::net::SocketAddrV4;
        NatInfo {
            v4: Some(crate::nat::V4Nat {
                class,
                reflexive: SocketAddrV4::new([203, 0, 113, 7].into(), seq[0]),
                alloc_seq: seq.to_vec(),
                distinct_probe_ips: 2,
                filtering: Unknown,
                hairpin: true,
            }),
            v6: None,
            local: Vec::new(),
        }
    }
}
