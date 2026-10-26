//! Strategy selection, burst sizing, and the shared punch engine.

mod birthday;
mod cone;
mod direct;
mod easy_sym;
mod sym_cone;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV6},
    time::Duration,
};

use crate::{
    config::PunchConfig,
    error::PunchError,
    msg::{DataPacket, Frame, Nonce, StrategyId, decode_packet, encode_packet},
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
            StrategyId::SymProbe => Some(sym_probe_estimate(mine, peer, self, cfg)),
            StrategyId::BirthdayBurst => {
                let space = burst_space(mine, peer);
                let (n, _m, c) = size_burst(space, cfg);
                Some(burst_hit_chance(n, c, n, c, space))
            },
            _ => None,
        };
    }
}

/// The mapping class after confidence demotion.
///
/// An EasySym fit without three consistent deltas is treated as HardSym by
/// every decision from here on.
pub(crate) fn effective_class(info: &NatInfo) -> NatClass {
    let seq = info.v4.as_ref().map_or(&[][..], |v4| &v4.alloc_seq);
    match info.v4_class() {
        NatClass::EasySym { .. } if !easy_confident(seq) => NatClass::HardSym,
        other => other,
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

    if !i_am_symmetric && !peer_is_symmetric {
        // Cone against cone, or public against either: one socket per side
        // aimed at the reflexive address.
        return Ok(Selection {
            strategy: StrategyId::ConeExchange,
            initiator_sockets: 1,
            responder_sockets: 1,
            estimate: None,
        });
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
        return Ok(sel);
    }
    if let (NatClass::EasySym { .. }, NatClass::EasySym { .. }) = (mine_class, peer_class) {
        Ok(Selection {
            strategy: StrategyId::PredictiveExchange,
            initiator_sockets: cfg.predictive_sockets,
            responder_sockets: cfg.predictive_sockets,
            estimate: None,
        })
    } else {
        // The probe cannot read a symmetric peer's filtering class, so the
        // estimate assumes address-dependent filtering, the common CGNAT
        // shape; `burst_hit_chance` states what that costs.
        let space = burst_space(mine, peer);
        let (n, m, c) = size_burst(space, cfg);
        let estimate = burst_hit_chance(n, c, m, c, space);
        if estimate < cfg.min_success {
            return Err(PunchError::Unpunchable {
                local: mine_class,
                peer: peer_class,
            });
        }
        Ok(Selection {
            strategy: StrategyId::BirthdayBurst,
            initiator_sockets: n as u16,
            responder_sockets: m as u16,
            estimate: Some(estimate),
        })
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
    let both_public =
        effective_class(mine) == NatClass::Public && effective_class(peer) == NatClass::Public;
    both_v6 || both_public
}

fn is_symmetric(class: NatClass) -> bool {
    matches!(class, NatClass::EasySym { .. } | NatClass::HardSym)
}

/// The port space a HardSym peer draws from, estimated from its probe.
///
/// A short observed span gets a margin on both ends; no observations fall
/// back to the upper ephemeral half.
pub(crate) fn peer_space(peer: &NatInfo) -> usize {
    let Some(seq) = peer.v4.as_ref().map(|v4| &v4.alloc_seq) else {
        return DEFAULT_SPACE;
    };
    if seq.len() < 2 {
        return DEFAULT_SPACE;
    }
    let min = *seq.iter().min().expect("len checked") as usize;
    let max = *seq.iter().max().expect("len checked") as usize;
    (max - min + 1 + 2 * SPACE_MARGIN).min(u16::MAX as usize + 1)
}

const DEFAULT_SPACE: usize = 32768;
const SPACE_MARGIN: usize = 64;

/// The port span the peer's NAT drew from, widened by a margin.
pub(crate) fn observed_range(seq: &[u16]) -> (u16, u16) {
    const MARGIN: u16 = 32;
    if seq.len() < 2 {
        return (32_768, u16::MAX);
    }
    let min = *seq.iter().min().expect("len checked");
    let max = *seq.iter().max().expect("len checked");
    (min.saturating_sub(MARGIN), max.saturating_add(MARGIN))
}

/// The port span a birthday burst is sized against.
///
/// Each direction's hit chance scales with the span of the side being
/// sprayed, so the wider of the two observed spans governs the pair. Both
/// roles compute the same value from their pair of views, which keeps the
/// sizing and the estimate equal on both sides.
pub(crate) fn burst_space(mine: &NatInfo, peer: &NatInfo) -> usize {
    peer_space(mine).max(peer_space(peer))
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

/// Chance that two synchronized bursts pair up under address-dependent
/// filtering, the regime selection assumes for a symmetric pair.
///
/// Side X holds `n_X * c_X` live mappings, one per sender and covered port,
/// and covers `c_X` distinct ports of the peer's space. One directional hit
/// completes the handshake, so the two expected-hit terms add up to
/// `(n_A * c_A * c_B + n_B * c_B * c_A) / space`. A probe cannot read a
/// symmetric peer's filtering class, so the estimate states this regime
/// instead of measuring it. Port-strict filtering needs both directions to
/// pair exactly, which lands near `n_A * c_A * n_B * c_B / space^2` and
/// stays negligible at any bounded budget.
pub(crate) fn burst_hit_chance(
    n_a: usize,
    c_a: usize,
    n_b: usize,
    c_b: usize,
    space: usize,
) -> f64 {
    if space == 0 {
        return 1.0;
    }
    let hits_a = (n_a * c_a) as f64 * c_b as f64;
    let hits_b = (n_b * c_b) as f64 * c_a as f64;
    1.0 - (-(hits_a + hits_b) / space as f64).exp()
}

/// Headroom between the sized burst and the conntrack bound: the peer's
/// replies arrive from a fresh mapping port outside the target list.
const BURST_MAPPING_HEADROOM: usize = 2;

/// Sockets and coverage per side for a target success rate.
///
/// Under the address-dependent model the expected hits are `2 * n * c^2 /
/// space`, so coverage is the leverage: a mapping spent on a wider covered
/// set buys more hit chance than the same mapping spent on another socket.
/// The derivation therefore opens one socket per side and raises the socket
/// count only once coverage sits at a cap. The caps: the peer's drawable port
/// window, the conntrack bound minus reply headroom, a packet budget share
/// because every mapping costs one packet per rotation, and `max_sockets`.
pub(crate) fn size_burst(space: usize, cfg: &PunchConfig) -> (usize, usize, usize) {
    // Reaching the target needs n * c^2 >= ln(1 / (1 - target)) * space / 2
    // expected-hit products.
    let required = -(1.0 - cfg.target_success).ln() * space as f64 / 2.0;
    // The drawable window is the modeled space without its two margins.
    let span_cap = space.saturating_sub(2 * SPACE_MARGIN).max(1);
    let mapping_cap = cfg
        .max_mappings
        .saturating_sub(BURST_MAPPING_HEADROOM)
        .min(cfg.packet_budget as usize / SPRAY_BUDGET_SHARE)
        .max(1);
    let coverage = (required.sqrt().ceil() as usize).clamp(1, span_cap.min(mapping_cap));
    // Sockets make up the remaining hit rate once coverage is capped.
    let max_sockets = (cfg.max_sockets as usize)
        .min(mapping_cap / coverage)
        .max(1);
    let sockets =
        ((required / (coverage as f64 * coverage as f64)).ceil() as usize).clamp(1, max_sockets);
    (sockets, sockets, coverage)
}

/// Share of the packet budget a spray may spend. Retransmissions keep the
/// rest.
const SPRAY_BUDGET_SHARE: usize = 4;

/// Upper bound on one sender's per-sweep burst.
const MAX_BURST: u16 = 32;

/// Candidate ports the cone side sprays at a HardSym peer.
///
/// Solves `P = 1 - exp(-m * c / space) = target_success` for `c`. The caps
/// keep handshake retransmissions inside the packet budget and the spray
/// inside the conntrack bound.
pub(crate) fn spray_count(m: usize, space: usize, cfg: &PunchConfig) -> usize {
    let budget_cap = (cfg.packet_budget as usize / SPRAY_BUDGET_SHARE).max(1);
    // The spray socket is the pool's only socket, so every candidate is one
    // mapping. One slot stays free for the peer's fresh reply port.
    let dest_cap = cfg.max_mappings.saturating_sub(1).max(1);
    let need = -((1.0 - cfg.target_success).ln()) * space as f64 / m.max(1) as f64;
    (need.ceil() as usize).clamp(1, budget_cap.min(dest_cap))
}

/// Packets one sender emits per sweep, so a lone socket runs at the rate cap.
pub(crate) fn burst_len(cfg: &PunchConfig) -> u16 {
    let per_tick = f64::from(cfg.packets_per_sec) * cfg.tick.as_secs_f64();
    per_tick.ceil().clamp(1.0, f64::from(MAX_BURST)) as u16
}

/// Distinct random ports over a span, drawn from a shuffled window.
///
/// Distinct draws carry a model's coverage exactly, so the span is shuffled
/// and truncated instead of sampled with replacement.
pub(crate) fn distinct_ports(seed: u64, lo: u16, hi: u16, count: usize) -> Vec<u16> {
    use rand::{prelude::*, rngs::StdRng};
    let mut ports: Vec<u16> = (lo..=hi).collect();
    ports.shuffle(&mut StdRng::seed_from_u64(seed));
    ports.truncate(count);
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

/// One execution stage on one family.
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
        }
    }
}

/// The full stage list one side executes.
pub(crate) struct ExecPlan {
    pub stages: Vec<StageSpec>,
    pub refresh: Refresh,
    /// Family of the socket whose port gets announced.
    pub refresh_family: Family,
    /// Resolved STUN server for a `Refresh::Stun` plan.
    pub refresh_server: Option<SocketAddr>,
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
            let i_am_symmetric = is_symmetric(effective_class(mine));
            let peer_sockets = match role {
                crate::report::Role::Initiator => sel.responder_sockets,
                crate::report::Role::Responder => sel.initiator_sockets,
            };
            stages.extend(sym_cone::stage(
                i_am_symmetric,
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
            let window = (my_sockets as usize * peer_sockets as usize * 4).min(512);
            stages.extend(easy_sym::stage(my_sockets, peer, window, cfg));
        },
        StrategyId::BirthdayBurst => {
            let space = burst_space(mine, peer);
            stages.extend(birthday::stage(
                my_sockets,
                peer,
                space,
                nonce,
                role as u64,
                cfg,
            ));
        },
        StrategyId::Direct => {},
    }
    // A peer without any usable address leaves the plan empty; bind one idle
    // socket so the engine still runs and fails on its deadline.
    if stages.is_empty() {
        stages.push(StageSpec::reply(Family::V4, cfg.punch_timeout));
    }

    // A public address or a v6 pair knows its own socket address; a cone
    // mapping needs a STUN query. Symmetric strategies have nothing stable
    // to announce.
    let refresh = if stages
        .iter()
        .any(|s| s.family == Family::V6 && !s.reply_only)
    {
        Refresh::Local
    } else {
        match sel.strategy {
            StrategyId::ConeExchange => {
                if effective_class(mine) == NatClass::Public {
                    Refresh::Local
                } else {
                    Refresh::Stun
                }
            },
            StrategyId::SymProbe if !is_symmetric(effective_class(mine)) => Refresh::Stun,
            _ => Refresh::None,
        }
    };
    let refresh_family = if refresh == Refresh::Local
        && stages
            .iter()
            .any(|s| s.family == Family::V6 && !s.reply_only)
    {
        Family::V6
    } else {
        Family::V4
    };

    ExecPlan {
        stages,
        refresh,
        refresh_family,
        refresh_server,
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
    pub peer_socket: u16,
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
    /// Set when budget or conntrack errors stopped the sweeps; the confirm
    /// path keeps running because replies matter more than new pulses.
    sweep_stalled: bool,
    candidate: Option<(Family, u16)>,
    confirmed: Option<(Family, u16)>,
    /// Winner index to announce over signaling before the loop exits.
    announce: Option<u16>,
    /// Fresh own ports to announce, or fresh peer ports to target.
    announce_ports: Option<Vec<u16>>,
    /// Ports announced so far, kept for the periodic retransmission.
    own_ports: Option<Vec<u16>>,
    next_announce: tokio::time::Instant,
    fresh_peer_ports: Option<Vec<u16>>,
    stun: Option<StunPending>,
    finish_now: bool,
    peer_confirmed: bool,
    peer_socket: Option<u16>,
    peer_addr: Option<SocketAddr>,
    grace_end: Option<tokio::time::Instant>,
    next_reply: tokio::time::Instant,
    first_handshake: Option<tokio::time::Instant>,
    stale_packets: u32,
    _marker: std::marker::PhantomData<S>,
}

impl<S: UdpIo> Engine<S> {
    pub(crate) fn new(plan: ExecPlan, cfg: PunchConfig, nonce: Nonce) -> Self {
        Self {
            cfg,
            plan,
            nonce,
            syn_bufs: [Vec::new(), Vec::new()],
            start: None,
            punch_deadline: tokio::time::Instant::now(),
            stage_idx: 0,
            sweep: 0,
            sweep_stalled: false,
            candidate: None,
            confirmed: None,
            announce: None,
            announce_ports: None,
            own_ports: None,
            next_announce: tokio::time::Instant::now(),
            fresh_peer_ports: None,
            stun: None,
            finish_now: false,
            peer_confirmed: false,
            peer_socket: None,
            peer_addr: None,
            grace_end: None,
            next_reply: tokio::time::Instant::now(),
            first_handshake: None,
            stale_packets: 0,
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

    /// Announces the fresh own port of the punch socket.
    ///
    /// A local refresh knows the port immediately; a STUN refresh fires the
    /// query and waits for the answer among the pool events.
    fn start_refresh(&mut self, pool: &SocketPool<S>) {
        let family = self.plan.refresh_family;
        match self.plan.refresh {
            Refresh::None => {},
            Refresh::Local => {
                if let Some(port) = pool.socket(family, 0).and_then(|s| s.local_addr().ok()) {
                    let ports = vec![port.port()];
                    self.own_ports = Some(ports.clone());
                    self.next_announce = tokio::time::Instant::now();
                    self.announce_ports = Some(ports);
                }
            },
            Refresh::Stun => {
                let Some(server) = self.plan.refresh_server else {
                    return
                };
                if pool.bound(family) == 0 {
                    return;
                }
                let txid: [u8; 12] = rand::random();
                self.stun = Some(StunPending {
                    request: crate::nat::probe::binding_request(&txid),
                    txid,
                    socket: 0,
                    server,
                    next_retry: tokio::time::Instant::now(),
                    attempts_left: 4,
                });
            },
        }
    }

    /// Marks the refresh answer as announced and arms the retransmission.
    fn refresh_answered(&mut self, port: u16) {
        let ports = vec![port];
        self.own_ports = Some(ports.clone());
        self.next_announce = tokio::time::Instant::now();
        self.announce_ports = Some(ports);
    }

    async fn drive(
        &mut self,
        pool: &SocketPool<S>,
        events: &mut tokio::sync::mpsc::Receiver<crate::socket::RecvEvent>,
        sig: &mut SigIo,
    ) -> Result<Outcome, PunchError> {
        let start = tokio::time::Instant::now();
        self.start = Some(start);
        self.punch_deadline = start + self.cfg.punch_timeout;
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
                        crate::error::Phase::Confirm
                    } else {
                        crate::error::Phase::Punch
                    },
                });
            }
            tokio::select! {
                ev = events.recv() => {
                    let Some(ev) = ev else {
                        return Err(PunchError::Io(std::io::Error::other("pool receive tasks stopped")));
                    };
                    self.on_data(pool, ev).await?;
                }
                frame = sig.recv() => {
                    match frame {
                        Ok(frame) => self.on_signaling(frame)?,
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
            // stay free of the signaling handle.
            if let Some(socket) = self.announce.take() {
                let _ = sig.send(Frame::Confirmed { socket }).await;
            }
            if let Some(ports) = self.announce_ports.take() {
                let _ = sig.send(Frame::PortUpdate { ports }).await;
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
            peer_socket: self.peer_socket.unwrap_or(0),
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

    fn observe_peer(&mut self, peer_socket: u16, from: SocketAddr, now: tokio::time::Instant) {
        self.first_handshake.get_or_insert(now);
        self.peer_addr = Some(from);
        self.peer_socket = Some(peer_socket);
    }

    async fn on_data(
        &mut self,
        pool: &SocketPool<S>,
        ev: crate::socket::RecvEvent,
    ) -> Result<(), PunchError> {
        // A pending refresh query collects its answer first.
        if let Some(pending) = &self.stun
            && ev.from == pending.server
        {
            if let Some(addr) = crate::nat::probe::parse_mapped(&ev.buf[..ev.len], &pending.txid) {
                self.refresh_answered(addr.port());
                self.stun = None;
            }
            return Ok(());
        }
        let Ok(pkt) = decode_packet(&ev.buf[..ev.len]) else {
            return Ok(())
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
                self.observe_peer(socket, ev.from, now);
                self.candidate.get_or_insert((ev.family, ev.socket));
                let buf = encode_packet(&DataPacket::SynAck {
                    nonce,
                    socket: ev.socket,
                });
                pool.send(ev.family, ev.socket, &buf, ev.from).await?;
                self.next_reply = now + self.cfg.confirm_retry;
            },
            DataPacket::SynAck { socket, .. } => {
                self.observe_peer(socket, ev.from, now);
                let resend_ack = if let Some((family, idx)) = self.confirmed {
                    // The peer missed our Ack; answer again while grace runs.
                    family == ev.family && idx == ev.socket
                } else {
                    self.confirmed = Some((ev.family, ev.socket));
                    self.announce = Some(ev.socket);
                    self.grace_end = Some(now + self.cfg.grace);
                    true
                };
                if resend_ack {
                    let buf = encode_packet(&DataPacket::Ack { nonce });
                    pool.send(ev.family, ev.socket, &buf, ev.from).await?;
                    self.next_reply = now + self.cfg.confirm_retry;
                }
            },
            DataPacket::Ack { .. } => {
                if self.confirmed.is_none() {
                    if let Some((family, idx)) = self.candidate {
                        self.observe_peer_from(ev.from, now);
                        self.confirmed = Some((family, idx));
                        self.announce = Some(idx);
                        // The final Ack proves both directions, so no grace
                        // wait applies on this path.
                        self.finish_now = true;
                    }
                } else {
                    self.observe_peer_from(ev.from, now);
                    self.finish_now = true;
                }
            },
        }
        Ok(())
    }

    fn observe_peer_from(&mut self, from: SocketAddr, now: tokio::time::Instant) {
        self.first_handshake.get_or_insert(now);
        self.peer_addr = Some(from);
    }

    fn on_signaling(&mut self, frame: crate::msg::SigFrame) -> Result<(), PunchError> {
        match frame.body {
            Frame::Abort(reason) => Err(PunchError::PeerAborted(reason)),
            Frame::Confirmed { socket } => {
                self.peer_confirmed = true;
                self.peer_socket = Some(socket);
                Ok(())
            },
            Frame::PortUpdate { ports } => {
                if !ports.is_empty() {
                    self.fresh_peer_ports = Some(ports);
                }
                Ok(())
            },
            // Duplicates of earlier phases carry no action.
            _ => Ok(()),
        }
    }

    fn stage_end(&self, idx: usize) -> tokio::time::Instant {
        let start = self.start.expect("drive sets the start");
        let elapsed: Duration = self.plan.stages[..=idx].iter().map(|s| s.duration).sum();
        start + elapsed
    }

    /// Targets for the active stage, honoring fresh peer ports.
    fn live_targets(&self, stage: &StageSpec) -> Option<Vec<SocketAddr>> {
        if !stage.needs_peer_ports {
            return Some(stage.targets.clone());
        }
        let ports = self.fresh_peer_ports.as_ref()?;
        let targets = match stage.family {
            Family::V4 => ports
                .iter()
                .map(|p| SocketAddr::from((self.plan.peer_ip, *p)))
                .collect(),
            Family::V6 => self
                .plan
                .peer_v6
                .iter()
                .flat_map(|addr| {
                    ports.iter().map(move |p| {
                        SocketAddr::V6(SocketAddrV6::new(
                            *addr.ip(),
                            *p,
                            addr.flowinfo(),
                            addr.scope_id(),
                        ))
                    })
                })
                .collect(),
        };
        Some(targets)
    }

    async fn on_tick(&mut self, pool: &SocketPool<S>) -> Result<(), PunchError> {
        let now = tokio::time::Instant::now();
        if now >= self.stage_end(self.stage_idx) && self.stage_idx + 1 < self.plan.stages.len() {
            self.stage_idx += 1;
            self.sweep = 0;
        }

        // Refresh retries.
        if let Some(pending) = &mut self.stun {
            if now >= pending.next_retry {
                if pending.attempts_left == 0 {
                    self.stun = None;
                } else {
                    let family = self.plan.refresh_family;
                    if let Some(sock) = pool.socket(family, pending.socket) {
                        let _ = sock.send_to(&pending.request, pending.server).await;
                        pending.attempts_left -= 1;
                    }
                    pending.next_retry = now + self.cfg.confirm_retry;
                }
            }
        }

        // PortUpdate retransmits on the signaling retry cadence until the
        // handshake completes, because the frame carries no acknowledgement.
        if let Some(ports) = self.own_ports.clone()
            && self.confirmed.is_none()
            && now >= self.next_announce
        {
            self.announce_ports = Some(ports);
            self.next_announce = now + self.cfg.signaling_retry;
        }

        // Syn pulses.
        let stage = &self.plan.stages[self.stage_idx];
        if !stage.reply_only
            && self.confirmed.is_none()
            && !self.sweep_stalled
            && let Some(targets) = self.live_targets(stage)
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
                stage.per_sweep as usize
            };
            let mut failure = None;
            'senders: for i in 0..stage.senders.min(group.len() as u16) {
                // Rotating by the sender count per sweep tracks the
                // peer's allocation rate, which also grows by one per
                // sending socket.
                let base = i as usize * per_sweep + self.sweep * stage.senders as usize * per_sweep;
                for k in 0..per_sweep {
                    let target = targets[(base + k) % targets.len()];
                    if let Err(e) = pool.send(stage.family, i, &group[i as usize], target).await {
                        failure = Some(e);
                        break 'senders;
                    }
                }
            }
            if let Some(e) = failure {
                // With no handshake traffic yet there is nothing to keep
                // alive, so the session fails fast instead of idling.
                if self.first_handshake.is_none() {
                    return Err(e);
                }
                self.sweep_stalled = true;
            }
            self.sweep += 1;
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
                pool.send(family, idx, &buf, peer).await?;
                self.next_reply = now + self.cfg.confirm_retry;
            }
            if let Some((family, idx)) = self.confirmed
                && self.grace_end.is_some()
                && !self.peer_confirmed
                && now >= self.next_reply
            {
                let buf = encode_packet(&DataPacket::Ack { nonce: self.nonce });
                pool.send(family, idx, &buf, peer).await?;
                self.next_reply = now + self.cfg.confirm_retry;
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
    fn burst_model_prefers_coverage_and_saturates() {
        // Every row holds 16 mappings per side; only the split differs.
        // Lambda is 2*n*c^2/space, so 1 socket over 16 ports buys four
        // times the hits of 4 sockets over 4 ports.
        let narrow = burst_hit_chance(4, 4, 4, 4, 1000);
        let wide = burst_hit_chance(1, 16, 1, 16, 1000);
        assert!(wide > narrow);
        // Sockets still add hits once coverage is fixed.
        assert!(burst_hit_chance(2, 16, 2, 16, 1000) > wide);
        // Dense bursts saturate toward certainty.
        assert!(burst_hit_chance(64, 64, 64, 64, 16) > 0.999);
    }

    #[test]
    fn burst_sizing_reaches_the_target() {
        let cfg = PunchConfig {
            max_sockets: 64,
            packet_budget: 4096,
            ..PunchConfig::default()
        };
        // Required products are ln(2) * 1000 / 2 = 347, solved by one socket
        // per side covering ceil(sqrt(347)) = 19 ports (19^2 = 361).
        let (n, m, c) = size_burst(1000, &cfg);
        assert_eq!((n, m, c), (1, 1, 19));
        assert!(burst_hit_chance(n, c, m, c, 1000) >= cfg.target_success - 1e-9);
    }

    #[test]
    fn starved_bursts_go_unpunchable() {
        let cfg = PunchConfig {
            packet_budget: 100,
            ..PunchConfig::default()
        };
        // The budget share caps the mappings at 25, so coverage clamps to 25
        // and one socket stays under it: lambda = 2 * 25^2 / 32768 = 0.038.
        let space = DEFAULT_SPACE;
        let (n, m, c) = size_burst(space, &cfg);
        assert_eq!((n, m, c), (1, 1, 25));
        assert!(burst_hit_chance(n, c, m, c, space) < cfg.min_success);
    }

    #[test]
    fn tiny_spaces_raise_the_socket_count() {
        let cfg = PunchConfig::default();
        // A 132-wide space leaves a 4-port drawable window, so coverage
        // clamps and sockets make up the rate: n * 4^2 >= ln(2) * 132 / 2.
        let (n, _m, c) = size_burst(132, &cfg);
        assert_eq!((n, c), (3, 4));
        assert!(burst_hit_chance(n, c, n, c, 132) >= cfg.target_success - 1e-9);
    }

    #[test]
    fn short_sequences_fall_back_to_the_upper_half() {
        assert_eq!(observed_range(&[1234]), (32_768, u16::MAX));
        assert_eq!(observed_range(&[]), (32_768, u16::MAX));
    }

    #[test]
    fn observed_spans_widen_by_the_margin() {
        assert_eq!(observed_range(&[30_000, 30_050, 30_100]), (29_968, 30_132));
        assert_eq!(observed_range(&[10, 20]), (0, 52));
        assert_eq!(observed_range(&[65_500, 65_530]), (65_468, 65_535));
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
        // 40 / 4 = 10 by budget, 5 by the conntrack bound.
        assert_eq!(spray_count(16, 30_000, &cfg), 10);
        let cfg = PunchConfig {
            max_mappings: 6,
            ..cfg
        };
        assert_eq!(spray_count(16, 30_000, &cfg), 5);
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

    #[test]
    fn peer_without_v4_skips_the_direct_stage() {
        use crate::report::Role;
        let cfg = PunchConfig::default();
        // A public local side against a peer that reported no v4 and no v6:
        // both classes read Public, so Direct qualifies but has no target.
        let mine = sample_info(NatClass::Public, &[5000, 5000]);
        let peer = NatInfo { v4: None, v6: None };
        assert!(direct_first(&mine, &peer, &cfg));
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
                filtering: crate::nat::FilterClass::Unknown,
            }),
            v6: None,
        }
    }
}
