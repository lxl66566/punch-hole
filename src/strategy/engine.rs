//! The shared engine that executes a punch plan.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use super::{
    model::burst_len,
    select::{ExecPlan, local_stage_reachable, usable_peer_v6},
};
use crate::{
    config::PunchConfig,
    error::{Phase, PunchError},
    msg::{DataPacket, DecodeError, Frame, Nonce, decode_packet, encode_packet},
    signaling::SigIo,
    socket::{Family, SocketPool, UdpFactory, UdpIo},
};

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
    /// Sockets the pool binds for this stage; a non-reply stage pulses
    /// from every one of them.
    pub bind: usize,
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
    /// Sweeps aim at the peer's reported local addresses instead of its
    /// reflexive one: two hosts behind one non-hairpinning NAT reach each
    /// other on the LAN underneath it and nowhere else.
    pub local_targets: bool,
}

impl StageSpec {
    pub(super) fn send(
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
            targets,
            reply_only: false,
            needs_peer_ports,
            per_sweep: 1,
            hold_for_peer: false,
            fixed_peer_ports: false,
            local_targets: false,
        }
    }

    pub(super) fn reply(family: Family, duration: Duration) -> Self {
        Self {
            family,
            duration,
            bind: 1,
            targets: Vec::new(),
            reply_only: true,
            needs_peer_ports: false,
            per_sweep: 1,
            hold_for_peer: false,
            fixed_peer_ports: false,
            local_targets: false,
        }
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

/// Stage progression: which stage runs and where its sweep stands.
struct Progress {
    stage_idx: usize,
    sweep: usize,
    /// Position inside the current sweep round, where a tick stopped
    /// after spending its send share; the next tick resumes from it.
    sweep_off: usize,
    /// Set when budget or conntrack errors stopped outbound sends; handshake
    /// retransmissions keep retrying because replies matter more than new
    /// pulses.
    send_stalled: bool,
}

/// The handshake race and the peer knowledge it produces.
///
/// `confirmed` is set once and never cleared; from that point the
/// candidate stays where the confirmation found it, and only the
/// winner's own exchange may still move `peer_addr` and `peer_socket`.
struct Handshake {
    candidate: Option<(Family, u16)>,
    confirmed: Option<(Family, u16)>,
    peer_confirmed: bool,
    peer_socket: Option<u16>,
    peer_addr: Option<SocketAddr>,
    grace_end: Option<tokio::time::Instant>,
    finish_now: bool,
    next_reply: tokio::time::Instant,
    first_traffic: Option<tokio::time::Instant>,
    /// Syn sources already answered, mapped to the instant their window
    /// ends. Keyed by receiving socket and source address.
    syn_replies: HashMap<(u16, SocketAddr), tokio::time::Instant>,
}

/// Signaling-side announcements: the winner confirm, the periodic
/// own-port updates with the refresh query that sources them, and the
/// peer's latest announced ports.
struct Announce {
    /// Winner index to announce over signaling before the loop exits.
    winner: Option<u16>,
    /// Own ports queued for the next PortUpdate send.
    pending: Option<PortAnnounce>,
    /// Ports announced so far, kept for the periodic retransmission.
    own: Option<PortAnnounce>,
    /// Time of the next own-port retransmission.
    next: tokio::time::Instant,
    fresh_peer: Option<PortAnnounce>,
    stun: Option<StunPending>,
}

/// Rebuild state for the active stage's sweep targets.
struct TargetCache {
    /// Sweep targets for the active stage, cached with the key they were
    /// built for: the stage index and the fresh peer port that shaped them.
    entries: Option<(usize, Option<u16>, Arc<Vec<SocketAddr>>)>,
    /// Stage index and announce port the prediction targets were re-based
    /// on, so a retransmitted announce rebuilds nothing.
    rebased_for: Option<(usize, u16)>,
    /// Fallback open time for a held spray: one RTT plus a tick past the
    /// engine start, the latest the peer's first pulses can be due when
    /// every inbound packet of them was lost.
    peer_warm: tokio::time::Instant,
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
    /// The session's wall-clock deadline, from the session start.
    overall: tokio::time::Instant,
    progress: Progress,
    handshake: Handshake,
    announce: Announce,
    targets: TargetCache,
    stale_packets: u32,
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
            progress: Progress {
                stage_idx: 0,
                sweep: 0,
                sweep_off: 0,
                send_stalled: false,
            },
            handshake: Handshake {
                candidate: None,
                confirmed: None,
                peer_confirmed: false,
                peer_socket: None,
                peer_addr: None,
                grace_end: None,
                finish_now: false,
                next_reply: tokio::time::Instant::now(),
                first_traffic: None,
                syn_replies: HashMap::new(),
            },
            announce: Announce {
                winner: None,
                pending: None,
                own: None,
                next: tokio::time::Instant::now(),
                fresh_peer: None,
                stun: None,
            },
            targets: TargetCache {
                entries: None,
                rebased_for: None,
                peer_warm: tokio::time::Instant::now(),
            },
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
        for family in [Family::V4, Family::V6] {
            self.syn_bufs[family.index()] = (0..pool.bound(family))
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
                self.announce.stun = Some(StunPending {
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
            self.announce.own = Some(announce);
            self.announce.next = tokio::time::Instant::now();
            self.announce.pending = Some(announce);
        }
    }

    /// Marks the STUN answer as announced and arms the retransmission.
    fn refresh_answered(&mut self, port: u16) {
        let mut announce = self.announce.own.unwrap_or_default();
        announce.v4 = Some(port);
        self.announce.own = Some(announce);
        self.announce.next = tokio::time::Instant::now();
        self.announce.pending = Some(announce);
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
        self.targets.peer_warm = start + sig.rtt() + self.cfg.tick;
        // A STUN refresh that never started has no server or no bound
        // socket, so the V4 port can never be announced. A sequence
        // marker only sharpens the peer's prediction base, so its plan
        // downgrades to the probe-time base instead of failing.
        if self.plan.refresh_v4 == Refresh::Stun && self.announce.stun.is_none() {
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
            if self.handshake.confirmed.is_none() && now >= self.punch_deadline {
                return Err(PunchError::Timeout {
                    phase: if self.handshake.first_traffic.is_some() {
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
                        Err(PunchError::SignalingClosed) if self.handshake.confirmed.is_some() => break,
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
            if let Some(socket) = self.announce.winner.take() {
                let _ =
                    tokio::time::timeout_at(self.overall, sig.send(Frame::Confirmed { socket }))
                        .await;
            }
            if let Some(ports) = self.announce.pending.take() {
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
            .handshake
            .confirmed
            .or(self.handshake.candidate)
            .ok_or(PunchError::ConfirmFailed)?;
        Ok(Outcome {
            family,
            winner,
            peer_addr: self.handshake.peer_addr.ok_or(PunchError::ConfirmFailed)?,
            peer_socket: self.handshake.peer_socket,
            packets_sent: pool.sent(),
            stale_packets: self.stale_packets,
            punch_ms: self
                .handshake
                .first_traffic
                .map_or(0, |t| (t - start).as_millis() as u64),
            confirm_ms: self
                .handshake
                .first_traffic
                .map_or(0, |t| (end - t).as_millis() as u64),
        })
    }

    fn finished(&self, now: tokio::time::Instant) -> bool {
        self.handshake.confirmed.is_some()
            && (self.handshake.finish_now
                || self.handshake.peer_confirmed
                || self.handshake.grace_end.is_some_and(|g| now >= g))
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
        if self.handshake.first_traffic.is_none() {
            return Some(err);
        }
        if matches!(err, PunchError::ConntrackExhausted) {
            return None;
        }
        self.progress.send_stalled = true;
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
        self.handshake.first_traffic.get_or_insert(now);
        let tied_to_winner = match self.handshake.confirmed {
            Some((f, i)) => {
                f == family && i == socket && self.handshake.peer_socket == Some(peer_socket)
            },
            None => true,
        };
        if tied_to_winner {
            self.handshake.peer_addr = Some(from);
            self.handshake.peer_socket = Some(peer_socket);
        }
    }

    /// Records the peer's address from an Ack on an open or winning path.
    fn observe_addr(&mut self, from: SocketAddr, now: tokio::time::Instant) {
        self.handshake.first_traffic.get_or_insert(now);
        self.handshake.peer_addr = Some(from);
    }

    /// Whether this Syn still earns a direct SynAck.
    ///
    /// One reply per confirm window covers the peer, because the
    /// retransmission tick repeats the SynAck on that same cadence for a
    /// live candidate.
    fn syn_reply_due(&mut self, socket: u16, from: SocketAddr, now: tokio::time::Instant) -> bool {
        let key = (socket, from);
        if let Some(&mute_until) = self.handshake.syn_replies.get(&key)
            && now < mute_until
        {
            return false;
        }
        if self.handshake.syn_replies.len() >= MAX_SYN_REPLY_KEYS {
            // Expired keys leave first; a still-full map leaves fresh
            // keys unanswered until the window passes.
            self.handshake
                .syn_replies
                .retain(|_, &mut until| until > now);
            if self.handshake.syn_replies.len() >= MAX_SYN_REPLY_KEYS {
                return false;
            }
        }
        self.handshake
            .syn_replies
            .insert(key, now + self.cfg.confirm_retry);
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
            SocketAddr::V4(_) => (
                Family::V4,
                self.announce.fresh_peer.and_then(|p| p.v4).is_some(),
            ),
            SocketAddr::V6(_) => (
                Family::V6,
                self.announce.fresh_peer.and_then(|p| p.v6).is_some(),
            ),
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
            // A local stage aims at the peer's reported local addresses, so
            // an answer from one of those names the aimed peer the same way
            // a reflexive answer does.
            Family::V4 => {
                addr.ip() == IpAddr::from(self.plan.peer_ip)
                    || (self
                        .plan
                        .stages
                        .iter()
                        .any(|s| s.family == Family::V4 && s.local_targets)
                        && self
                            .plan
                            .peer_local
                            .iter()
                            .any(|ip| IpAddr::V4(*ip) == addr.ip()))
            },
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
        if let Some(pending) = &self.announce.stun
            && ev.from == pending.server
            && ev.socket == pending.socket
        {
            if let Some(addr) = crate::nat::probe::parse_mapped(&ev.buf[..ev.len], &pending.txid) {
                self.refresh_answered(addr.port());
                self.announce.stun = None;
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
                self.handshake
                    .candidate
                    .get_or_insert((ev.family, ev.socket));
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
                    self.handshake.next_reply = now + self.cfg.confirm_retry;
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
                let resend_ack = if let Some((family, idx)) = self.handshake.confirmed {
                    // The peer missed our Ack; answer again while grace runs.
                    family == ev.family && idx == ev.socket
                } else {
                    self.handshake.confirmed = Some((ev.family, ev.socket));
                    self.announce.winner = Some(ev.socket);
                    self.handshake.grace_end = Some((now + self.cfg.grace).min(self.overall));
                    true
                };
                if resend_ack {
                    let buf = encode_packet(&DataPacket::Ack { nonce });
                    if let Err(e) = pool.send(ev.family, ev.socket, &buf, ev.from).await
                        && let Some(e) = self.send_failed(e)
                    {
                        return Err(e);
                    }
                    self.handshake.next_reply = now + self.cfg.confirm_retry;
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
        self.handshake
            .syn_replies
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
        if self.handshake.confirmed.is_none() {
            if self.answered_syn(socket, from) {
                self.observe_addr(from, now);
                self.handshake.confirmed = Some((family, socket));
                self.announce.winner = Some(socket);
                // The final Ack proves both directions, so no grace wait
                // applies on this path.
                self.handshake.finish_now = true;
            }
        } else if self.handshake.confirmed == Some((family, socket)) {
            self.observe_addr(from, now);
            self.handshake.finish_now = true;
        }
    }

    fn on_signaling(&mut self, body: &Frame) -> Result<(), PunchError> {
        match *body {
            Frame::Abort(reason) => Err(PunchError::PeerAborted(reason)),
            Frame::Confirmed { socket } => {
                self.handshake.peer_confirmed = true;
                self.handshake.peer_socket = Some(socket);
                Ok(())
            },
            Frame::PortUpdate { v4, v6 } => {
                // Retransmissions repeat the same values, so each family
                // slot overwrites with a stable port.
                let fresh = self
                    .announce
                    .fresh_peer
                    .get_or_insert_with(PortAnnounce::default);
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
        let stage = &self.plan.stages[self.progress.stage_idx];
        let port = match stage.family {
            Family::V4 => self.announce.fresh_peer.and_then(|p| p.v4),
            Family::V6 => self.announce.fresh_peer.and_then(|p| p.v6),
        };
        // Static stages carry no port dependency, so a `None` key covers
        // them; a peer-port stage without its port never caches below.
        let key = stage.needs_peer_ports.then_some(port).flatten();
        if let Some((idx, cached_key, targets)) = &self.targets.entries
            && *idx == self.progress.stage_idx
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
                Family::V4 if self.plan.peer_ip.is_unspecified() && !stage.local_targets => {
                    Vec::new()
                },
                Family::V4 if stage.local_targets => self
                    .plan
                    .peer_local
                    .iter()
                    .copied()
                    .filter(|ip| local_stage_reachable(*ip))
                    .map(|ip| SocketAddr::from((ip, port)))
                    .collect(),
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
        self.targets.entries = Some((self.progress.stage_idx, key, Arc::clone(&targets)));
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
        let Some(port) = self.announce.fresh_peer.and_then(|p| p.v4) else {
            return;
        };
        if self.targets.rebased_for == Some((self.progress.stage_idx, port)) {
            return;
        }
        self.targets.rebased_for = Some((self.progress.stage_idx, port));
        let stage = &self.plan.stages[self.progress.stage_idx];
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
        self.targets.entries = Some((self.progress.stage_idx, None, Arc::new(targets)));
    }

    async fn on_tick(&mut self, pool: &SocketPool<S>) -> Result<(), PunchError> {
        let now = tokio::time::Instant::now();
        // A tick delayed by an event storm can land past several stage
        // boundaries at once, so the advance runs until the active stage
        // owns `now`. Plans hold at most two stages today and validation
        // keeps every stage longer than a tick, which makes one advance
        // per tick sufficient; the loop keeps that true for any plan.
        while now >= self.stage_end(self.progress.stage_idx)
            && self.progress.stage_idx + 1 < self.plan.stages.len()
        {
            self.progress.stage_idx += 1;
            self.progress.sweep = 0;
            self.progress.sweep_off = 0;
        }

        // Refresh retries.
        if let Some(pending) = &self.announce.stun
            && now >= pending.next_retry
            && pending.attempts_left == 0
        {
            // Without the announced port the peer has nothing to aim at.
            // With handshake traffic already flowing, the grace path
            // decides instead of the refresh. A sequence marker that never
            // crossed only leaves the peer's prediction on its probe-time
            // base, so the plan continues.
            if self.handshake.first_traffic.is_none() && !self.plan.sequence_marker {
                return Err(PunchError::Io {
                    phase: Phase::Punch,
                    source: std::io::Error::other("stun refresh retries exhausted"),
                });
            }
            self.announce.stun = None;
        } else if let Some(pending) = &mut self.announce.stun
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
        if let Some(ports) = self.announce.own
            && self.handshake.confirmed.is_none()
            && now >= self.announce.next
        {
            self.announce.pending = Some(ports);
            self.announce.next = now + self.cfg.signaling_retry;
        }

        // Syn pulses. The handle is taken before the stage borrow, so the
        // sends below can work on `&mut self` without fighting it.
        self.apply_peer_base();
        let targets = self.live_targets();
        let stage = &self.plan.stages[self.progress.stage_idx];
        // A held spray targets ports the peer's NAT has not allocated yet:
        // the peer's sockets bind at the shared start but their mappings
        // appear only when its pulses leave, and its pulses wait for this
        // side's PortUpdate. Inbound peer traffic is the direct proof the
        // mappings exist, and one RTT plus a tick is the fallback for a
        // path that loses every one of the peer's first packets.
        let held = stage.hold_for_peer
            && self.handshake.first_traffic.is_none()
            && now < self.targets.peer_warm;
        if !stage.reply_only
            && !held
            && self.handshake.confirmed.is_none()
            && !self.progress.send_stalled
            && let Some(targets) = targets
            && !targets.is_empty()
        {
            let group = &self.syn_bufs[stage.family.index()];
            // Peer traffic observed means handshake replies and event
            // processing need the rate budget, so a multi-target spray backs
            // off to one packet per sweep. Single-pulse stages stay as they
            // are.
            let per_sweep = if self.handshake.peer_addr.is_some() {
                1
            } else {
                usize::from(stage.per_sweep)
            };
            // Every bound socket of a send stage pulses, capped by the
            // buffers `run` actually built.
            let senders = stage.bind.min(group.len());
            let sweep_len = senders * per_sweep;
            // A spray against fixed peer ports earns nothing past
            // FIXED_PORT_PASSES full passes; the constant derives the
            // window. Inbound-loss recovery rides the retransmission
            // tick, which re-answers the sources already tracked.
            let settled = stage.fixed_peer_ports
                && self.progress.sweep.saturating_mul(sweep_len)
                    >= FIXED_PORT_PASSES * targets.len();
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
            while !settled && self.progress.sweep_off < sweep_len {
                if sent == quota || tokio::time::Instant::now() >= self.punch_deadline {
                    break;
                }
                let sender = (self.progress.sweep_off / per_sweep) as u16;
                let target = targets
                    [(self.progress.sweep * sweep_len + self.progress.sweep_off) % targets.len()];
                if let Err(e) = pool
                    .send(stage.family, sender, &group[sender as usize], target)
                    .await
                {
                    failure = Some(e);
                    break;
                }
                self.progress.sweep_off += 1;
                sent += 1;
            }
            // A round that finished or failed starts the next round; a round
            // cut short by its quota boundary resumes on the next tick.
            if failure.is_some() || self.progress.sweep_off >= sweep_len {
                self.progress.sweep_off = 0;
                self.progress.sweep += 1;
            }
            if let Some(e) = failure
                && let Some(e) = self.send_failed(e)
            {
                return Err(e);
            }
        }

        // Handshake retransmissions on the confirm timer.
        if let Some(peer) = self.handshake.peer_addr {
            if let Some((family, idx)) = self.handshake.candidate
                && self.handshake.confirmed.is_none()
                && now >= self.handshake.next_reply
            {
                let buf = encode_packet(&DataPacket::SynAck {
                    nonce: self.nonce,
                    socket: idx,
                });
                // A handshake already ran on this path, so a failed
                // retransmission waits for a later tick instead of failing
                // the session.
                if pool.send(family, idx, &buf, peer).await.is_ok() {
                    self.handshake.next_reply = now + self.cfg.confirm_retry;
                }
            }
            if let Some((family, idx)) = self.handshake.confirmed
                && self.handshake.grace_end.is_some()
                && !self.handshake.peer_confirmed
                && now >= self.handshake.next_reply
            {
                let buf = encode_packet(&DataPacket::Ack { nonce: self.nonce });
                if pool.send(family, idx, &buf, peer).await.is_ok() {
                    self.handshake.next_reply = now + self.cfg.confirm_retry;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    /// An ExecPlan over `stages` with inert defaults; a test overrides the
    /// fields its scenario depends on.
    fn exec_plan(stages: Vec<StageSpec>) -> ExecPlan {
        ExecPlan {
            stages,
            refresh_v4: Refresh::None,
            announce_v6: false,
            refresh_server: None,
            predicts_peer: false,
            sequence_marker: false,
            peer_ip: [203, 0, 113, 9].into(),
            peer_v6: Vec::new(),
            peer_local: Vec::new(),
        }
    }

    #[cfg(feature = "test-util")]
    #[test]
    fn v6_fallback_aims_the_v4_stage_at_the_v4_port() {
        // A plan whose V6 Direct stage is followed by a V4 Cone stage, the
        // shape a dual-stack cone pair produces.
        let cfg = PunchConfig::default();
        let peer_v6 = SocketAddrV6::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into(), 9999, 0, 0);
        let mut plan = exec_plan(vec![
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
        ]);
        plan.refresh_v4 = Refresh::Stun;
        plan.announce_v6 = true;
        plan.peer_v6 = vec![peer_v6];
        let mut engine: Engine<nat_lab::sim::SimSocket> =
            Engine::new(plan, cfg, [0; 16], tokio::time::Instant::now());
        // One PortUpdate now carries both families' fresh ports.
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: Some(41000),
                v6: Some(51000),
            })
            .expect("update applies");
        engine.progress.stage_idx = 0;
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
        engine.progress.stage_idx = 1;
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
        let mut plan = exec_plan(vec![StageSpec::send(
            Family::V4,
            1,
            vec![SocketAddr::from(([203, 0, 113, 9], 1))],
            true,
            cfg.punch_timeout,
        )]);
        plan.peer_ip = Ipv4Addr::UNSPECIFIED;
        let mut engine: Engine<tokio::net::UdpSocket> =
            Engine::new(plan, cfg, [0; 16], tokio::time::Instant::now());
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: Some(41000),
                v6: None,
            })
            .expect("update applies");
        engine.progress.stage_idx = 0;
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
        let mut plan = exec_plan(vec![StageSpec::send(
            Family::V6,
            1,
            vec![SocketAddr::V6(v6(Ipv6Addr::LOCALHOST))],
            true,
            cfg.direct_window,
        )]);
        plan.peer_v6 = vec![
            v6("2001:db8::1".parse().expect("global address")),
            v6("ff02::1".parse().expect("multicast address")),
            v6("fe80::1".parse().expect("link-local address")),
            v6("::ffff:203.0.113.9".parse().expect("mapped address")),
            v6(Ipv6Addr::LOCALHOST),
        ];
        let mut engine: Engine<tokio::net::UdpSocket> =
            Engine::new(plan, cfg, [0; 16], tokio::time::Instant::now());
        engine
            .on_signaling(&Frame::PortUpdate {
                v4: None,
                v6: Some(51000),
            })
            .expect("update applies");
        engine.progress.stage_idx = 0;
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
        use crate::socket::SocketPool;

        let cfg = PunchConfig::default();
        let net = nat_lab::sim::Net::seeded("malicious_targets");
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");

        let syn = encode_packet(&DataPacket::Syn {
            nonce: [0; 16],
            socket: 0,
        });
        // A multicast reflexive address inside the plan's static targets.
        let multicast = exec_plan(vec![StageSpec::send(
            Family::V4,
            1,
            vec![SocketAddr::from((Ipv4Addr::new(224, 0, 0, 1), 40000))],
            false,
            cfg.punch_timeout,
        )]);
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
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
        let port_zero = exec_plan(vec![StageSpec::send(
            Family::V4,
            1,
            vec![SocketAddr::from(([203, 0, 113, 9], 40000))],
            true,
            cfg.punch_timeout,
        )]);
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
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

    /// A peer announce translates the fitted window onto the announced
    /// position without touching its length or order; a plan that predicts
    /// nothing, and an announce that repeats, rebuild nothing.
    #[test]
    fn peer_announce_rebases_the_prediction_window() {
        let cfg = PunchConfig::default();
        let at = |port: u16| SocketAddr::from(([203, 0, 113, 9], port));
        let window: Vec<SocketAddr> = (0..4).map(|i| at(5012 + i * 2)).collect();
        let mut plan = exec_plan(vec![StageSpec::send(
            Family::V4,
            1,
            window,
            false,
            cfg.punch_timeout,
        )]);
        plan.predicts_peer = true;
        let mut engine: Engine<tokio::net::UdpSocket> =
            Engine::new(plan, cfg.clone(), [0; 16], tokio::time::Instant::now());
        engine.progress.stage_idx = 0;

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
        let plan = exec_plan(vec![
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
        ]);
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
        use std::net::SocketAddrV4;
        let addr =
            |port: u16| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), port));
        let cfg = PunchConfig::default();
        // A multi-socket plan, the shape a SymProbe shooter runs.
        let plan = exec_plan(vec![StageSpec::send(
            Family::V4,
            4,
            vec![addr(40000)],
            true,
            cfg.punch_timeout,
        )]);
        let mut engine: Engine<tokio::net::UdpSocket> =
            Engine::new(plan, cfg, [0; 16], tokio::time::Instant::now());
        let now = tokio::time::Instant::now();

        // Handshake traffic from two peer sockets on two local sockets.
        engine.observe_peer(5, addr(50_001), now, Family::V4, 1);
        engine.handshake.candidate = Some((Family::V4, 1));
        // The first complete handshake elects local socket 0 with peer
        // socket 2, mirroring the SynAck confirm path.
        engine.observe_peer(2, addr(50_002), now, Family::V4, 0);
        engine.handshake.confirmed = Some((Family::V4, 0));

        // Late Syn pulses from the peer's other sockets during grace.
        engine.observe_peer(9, addr(50_009), now, Family::V4, 3);
        engine.observe_peer(9, addr(50_009), now, Family::V4, 0);
        assert_eq!(engine.handshake.peer_addr, Some(addr(50_002)));
        assert_eq!(engine.handshake.peer_socket, Some(2));

        // A stray Ack for another local socket finishes nothing.
        engine.on_ack(addr(50_009), Family::V4, 3, now);
        assert!(!engine.handshake.finish_now);
        assert_eq!(engine.handshake.peer_addr, Some(addr(50_002)));

        // The winner's own handshake still refreshes and finishes.
        engine.on_ack(addr(50_002), Family::V4, 0, now);
        assert!(engine.handshake.finish_now);
        assert_eq!(engine.handshake.peer_addr, Some(addr(50_002)));
    }

    /// A budget that dies after the handshake started must stall the engine
    /// instead of failing it: the retransmission tick keeps its error and
    /// the grace mechanism decides the outcome.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn mid_handshake_budget_death_stalls_instead_of_failing() {
        use crate::socket::SocketPool;
        let peer = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), 40000));
        // Every pool send fails on the budget check before touching a
        // socket.
        let cfg = PunchConfig {
            packet_budget: 0,
            ..PunchConfig::default()
        };
        let plan = exec_plan(vec![StageSpec::send(
            Family::V4,
            1,
            vec![peer],
            false,
            cfg.punch_timeout,
        )]);
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let net = nat_lab::sim::Net::seeded("stall_grace");
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
        engine.handshake.candidate = Some((Family::V4, 0));
        engine.start = Some(now);
        engine.handshake.next_reply = now;

        engine.on_tick(&pool).await.expect("stall, not an error");
        assert!(
            engine.progress.send_stalled,
            "sends stalled after the failure"
        );
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
        let plan = exec_plan(vec![StageSpec::reply(Family::V4, cfg.punch_timeout)]);
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let net = nat_lab::sim::Net::seeded("conntrack_reply_skip");
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
        assert!(
            !engine.progress.send_stalled,
            "conntrack exhaustion is no stall"
        );
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
            exec_plan(vec![spec])
        };
        let syn = encode_packet(&DataPacket::Syn {
            nonce: [0; 16],
            socket: 3,
        });
        let net = nat_lab::sim::Net::seeded("held_spray");

        // The ungated stage spends every tick from the shared start.
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
            plan(false),
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        engine.syn_bufs[0] = vec![syn.clone()];
        let start = tokio::time::Instant::now();
        engine.start = Some(start);
        engine.punch_deadline = start + cfg.punch_timeout;
        engine.targets.peer_warm = start + cfg.punch_timeout;
        engine.on_tick(&pool).await.expect("tick runs");
        engine.on_tick(&pool).await.expect("tick runs");
        assert_eq!(pool.sent(), 2, "the ungated spray pulses every tick");
        pool.shutdown().await;

        // The held stage stays silent without peer traffic.
        let host = net.public_host();
        let (pool, _events) = SocketPool::bind(&host, &cfg, 1, 0)
            .await
            .expect("pool binds");
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
            plan(true),
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        engine.syn_bufs[0] = vec![syn.clone()];
        let start = tokio::time::Instant::now();
        engine.start = Some(start);
        engine.punch_deadline = start + cfg.punch_timeout;
        engine.targets.peer_warm = start + cfg.punch_timeout;
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
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
            plan(true),
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        engine.syn_bufs[0] = vec![syn];
        let start = tokio::time::Instant::now();
        engine.start = Some(start);
        engine.punch_deadline = start + cfg.punch_timeout;
        engine.targets.peer_warm = start + cfg.tick;
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
        use crate::socket::SocketPool;

        let addr = |port: u16| SocketAddr::from((Ipv4Addr::new(203, 0, 113, 9), port));
        let cfg = PunchConfig {
            max_mappings: 1,
            ..PunchConfig::default()
        };
        let plan = exec_plan(vec![StageSpec::send(
            Family::V4,
            1,
            vec![addr(40000), addr(40001)],
            false,
            cfg.punch_timeout,
        )]);
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let net = nat_lab::sim::Net::seeded("conntrack_sweep_skip");
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
        engine.handshake.candidate = Some((Family::V4, 0));
        engine.start = Some(now);
        engine.handshake.next_reply = now + cfg.punch_timeout;

        // The first target takes the only mapping slot.
        engine.on_tick(&pool).await.expect("first tick pulses");
        assert_eq!(pool.sent(), 1);

        // The second target overflows the bound and is skipped; the sweep
        // still advances and nothing stalls.
        engine.on_tick(&pool).await.expect("second tick skips");
        assert!(
            !engine.progress.send_stalled,
            "conntrack exhaustion is no stall"
        );
        assert_eq!(pool.sent(), 1);

        // The rotation reaches the covered target again and pulses it.
        engine
            .on_tick(&pool)
            .await
            .expect("third tick pulses again");
        assert!(!engine.progress.send_stalled);
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
        let plan = exec_plan(vec![spec]);
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
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
        let net = nat_lab::sim::Net::seeded("low_rate_sweep");
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
        let mut plan = exec_plan(vec![StageSpec::reply(Family::V4, cfg.punch_timeout)]);
        plan.refresh_v4 = Refresh::Stun;
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let server = SocketAddr::from(([203, 0, 113, 30], 3478));
        let txid = [7u8; 12];
        engine.announce.stun = Some(StunPending {
            txid,
            request: Vec::new(),
            socket: 0,
            server,
            next_retry: tokio::time::Instant::now(),
            attempts_left: REFRESH_ATTEMPTS,
        });
        let net = nat_lab::sim::Net::seeded("refresh_socket_guard");
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
        assert!(engine.announce.stun.is_some(), "the query stays pending");
        assert!(engine.announce.own.is_none(), "no port was announced");

        // The same answer on socket 0 completes the refresh.
        engine
            .on_data(&pool, event(0))
            .await
            .expect("querying socket accepts the answer");
        assert!(engine.announce.stun.is_none(), "the query completed");
        assert_eq!(
            engine.announce.own.map(|ports| ports.v4),
            Some(Some(41_002))
        );
    }

    /// Refresh queries leave through the pool: they count in its stats, and
    /// a server that never answers exhausts the retries into an error
    /// instead of four silent failures.
    #[cfg(feature = "test-util")]
    #[tokio::test(start_paused = true)]
    async fn refresh_queries_flow_through_the_pool_and_surface_failure() {
        use crate::socket::SocketPool;

        let cfg = PunchConfig::default();
        let mut plan = exec_plan(vec![StageSpec::reply(Family::V4, cfg.punch_timeout)]);
        plan.refresh_v4 = Refresh::Stun;
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let server = SocketAddr::from(([203, 0, 113, 30], 3478));
        engine.announce.stun = Some(StunPending {
            txid: [7u8; 12],
            request: crate::nat::probe::binding_request(&[7u8; 12]),
            socket: 0,
            server,
            next_retry: tokio::time::Instant::now(),
            attempts_left: REFRESH_ATTEMPTS,
        });
        let net = nat_lab::sim::Net::seeded("refresh_via_pool");
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
        let plan = exec_plan(vec![StageSpec::reply(Family::V4, cfg.punch_timeout)]);
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let net = nat_lab::sim::Net::seeded("syn_reply_gate");
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
        assert_eq!(engine.handshake.peer_addr, Some(a));
        assert_eq!(engine.handshake.candidate, Some((Family::V4, 0)));

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
        let plan = exec_plan(vec![StageSpec::send(
            Family::V4,
            1,
            vec![target],
            false,
            cfg.punch_timeout,
        )]);
        let mut engine: Engine<nat_lab::sim::SimSocket> = Engine::new(
            plan,
            cfg.clone(),
            [0; 16],
            tokio::time::Instant::now() + cfg.punch_timeout,
        );
        let net = nat_lab::sim::Net::seeded("synack_source_gate");
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
            engine.handshake.confirmed.is_none(),
            "unvisited source confirms nothing"
        );
        assert!(engine.handshake.grace_end.is_none());
        assert!(engine.announce.winner.is_none());
        assert_eq!(pool.sent(), 0, "no Ack answers an unvisited source");
        assert!(engine.handshake.peer_addr.is_none());
        assert!(engine.handshake.first_traffic.is_none());

        // The targeted address carries the confirmation, and its Ack leaves.
        engine
            .on_data(&pool, event(target))
            .await
            .expect("targeted synack confirms");
        assert_eq!(engine.handshake.confirmed, Some((Family::V4, 0)));
        assert_eq!(engine.announce.winner, Some(0));
        assert_eq!(pool.sent(), 1, "the Ack answer left");

        // Grace alone crowns the confirmed path, which is what a peer
        // whose Confirmed frame was lost leaves this side with.
        let grace_end = engine.handshake.grace_end.expect("grace armed");
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
        use std::net::SocketAddrV4;
        let peer_ip = Ipv4Addr::new(203, 0, 113, 9);
        let at = |ip: Ipv4Addr, port: u16| SocketAddr::V4(SocketAddrV4::new(ip, port));
        let cfg = PunchConfig::default();
        let plan = exec_plan(vec![StageSpec::send(
            // The stage carries the peer's dead probe address and waits on
            // its PortUpdate, the cone stage shape.
            Family::V4,
            1,
            vec![at(peer_ip, 40000)],
            true,
            cfg.punch_timeout,
        )]);
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
        use std::net::SocketAddrV4;
        let peer = Ipv4Addr::new(203, 0, 113, 9);
        let at = |ip: Ipv4Addr, port: u16| SocketAddr::V4(SocketAddrV4::new(ip, port));
        let cfg = PunchConfig::default();
        let plan = exec_plan(vec![StageSpec::reply(Family::V4, cfg.punch_timeout)]);
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
        engine.handshake.candidate = Some((Family::V4, 1));
        engine
            .handshake
            .syn_replies
            .insert((1, first), now + cfg.confirm_retry);
        engine
            .handshake
            .syn_replies
            .insert((0, second), now + cfg.confirm_retry);

        // An Ack from a host no socket answered moves nothing, whatever
        // socket it lands on.
        let foreign = at(Ipv4Addr::new(198, 51, 100, 99), 50_009);
        engine.on_ack(foreign, Family::V4, 0, now);
        assert!(engine.handshake.confirmed.is_none());
        assert!(!engine.handshake.finish_now);

        // The Ack on socket 0 crowns socket 0 through a fresh mapping
        // port of the answered host, the symmetric peer's shape, not the
        // candidate socket 1.
        let fresh_port = at(peer, 50_077);
        engine.on_ack(fresh_port, Family::V4, 0, now);
        assert_eq!(engine.handshake.confirmed, Some((Family::V4, 0)));
        assert_eq!(engine.announce.winner, Some(0));
        assert!(engine.handshake.finish_now);
        assert_eq!(engine.handshake.peer_addr, Some(fresh_port));
    }
}
