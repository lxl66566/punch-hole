//! Puncher, the session state machine, and the Punched result.

use std::{future::Future, net::SocketAddr, time::Duration};

use tokio::{sync::mpsc, time::Instant};

use crate::{
    config::PunchConfig,
    error::{Phase, PunchError, PunchFailure},
    msg::{AbortReason, Frame, Nonce, Offer, new_nonce},
    nat::{NatClass, NatInfo, probe::lookup_server},
    report::{PhaseDurations, PunchReport, Role, SessionDiagnostics, StrategySummary},
    signaling::{LibEnd, SigIo},
    socket::{TokioFactory, UdpFactory, UdpIo},
    strategy::{self, Engine, Selection},
};

/// Entry point: configuration plus an optional cached classification.
pub struct Puncher<F: UdpFactory = TokioFactory> {
    config: PunchConfig,
    cached: Option<NatInfo>,
    factory: F,
    events: Option<mpsc::Sender<SessionEvent>>,
}

impl Puncher<TokioFactory> {
    /// Creates a puncher over real tokio sockets.
    pub fn new(config: PunchConfig) -> Result<Self, PunchError> {
        Self::with_factory(config, TokioFactory)
    }
}

impl<F: UdpFactory> Puncher<F> {
    /// Creates a puncher over a custom socket factory.
    pub fn with_factory(config: PunchConfig, factory: F) -> Result<Self, PunchError> {
        config.validate()?;
        Ok(Self {
            config,
            cached: None,
            factory,
            events: None,
        })
    }

    /// Reuses a NAT classification from an earlier session and skips Probe.
    #[must_use]
    pub fn with_cached_nat(mut self, nat: NatInfo) -> Self {
        self.cached = Some(clamp_nat_info(nat));
        self
    }

    /// Subscribes a channel to the session's progress events.
    ///
    /// Emission is best-effort: a full or closed channel loses the event
    /// and never stalls the session, which matches how the session treats
    /// signaling frames on a channel the host stopped draining.
    #[must_use]
    pub fn with_events(mut self, events: mpsc::Sender<SessionEvent>) -> Self {
        self.events = Some(events);
        self
    }

    /// Attaches the signaling bridge and creates the session.
    #[must_use]
    pub fn with_signaling(self, end: LibEnd) -> PunchSession<F> {
        PunchSession {
            config: self.config,
            cached: self.cached,
            factory: self.factory,
            sig: SigIo::new(end),
            events: self.events,
        }
    }
}

/// One attempt, driven to completion by `initiator` or `responder`.
pub struct PunchSession<F: UdpFactory> {
    config: PunchConfig,
    cached: Option<NatInfo>,
    factory: F,
    sig: SigIo,
    events: Option<mpsc::Sender<SessionEvent>>,
}

/// Progress updates from a running session.
///
/// One event per completed stage, in session order. Success needs no
/// event, because the returned [`Punched`] carries the full report;
/// failure needs none either, because the returned
/// [`PunchFailure`] carries the same evidence plus its own error.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// The local classification settled, from Probe or from the cache a
    /// cached session skipped Probe with.
    Probe(NatInfo),
    /// Exchange completed with the peer's classification.
    Exchange(NatInfo),
    /// Negotiate settled the plan both sides will run.
    Negotiate(StrategySummary),
}

/// The result of a successful session.
pub struct Punched<S = tokio::net::UdpSocket> {
    /// Winner socket, unconnected, ready for business traffic.
    pub socket: S,
    /// The peer's confirmed data-plane address.
    pub peer_addr: SocketAddr,
    /// What happened, for logging and relay decisions.
    pub report: PunchReport,
}

// The socket stays out of the debug output; host sockets rarely print.
impl<S> std::fmt::Debug for Punched<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Punched")
            .field("peer_addr", &self.peer_addr)
            .field("report", &self.report)
            .finish_non_exhaustive()
    }
}

impl<F: UdpFactory> PunchSession<F> {
    /// Tail of the start window kept free of Accept re-sends, so the caller
    /// gets uninterrupted time to build its plan before the shared start.
    const ACCEPT_RESEND_MARGIN: Duration = Duration::from_millis(100);
    /// Largest start delay the Responder honors. A larger value would park
    /// the session far past every deadline.
    const MAX_START_DELAY_MS: u64 = 10_000;

    /// Drives the session as the Initiator.
    pub async fn initiator(self) -> Result<Punched<F::Socket>, PunchFailure> {
        self.run(Role::Initiator).await
    }

    /// Drives the session as the Responder.
    pub async fn responder(self) -> Result<Punched<F::Socket>, PunchFailure> {
        self.run(Role::Responder).await
    }

    /// Runs the session and assembles the failure boundary: the phase
    /// error travels with whatever the failed session had learned.
    async fn run(self, role: Role) -> Result<Punched<F::Socket>, PunchFailure> {
        let start = Instant::now();
        let mut diag = SessionDiagnostics::default();
        match self.drive(role, &mut diag).await {
            Ok(punched) => Ok(punched),
            Err(error) => {
                diag.phase_ms.total_ms = elapsed_ms(start);
                Err(PunchFailure {
                    error,
                    diagnostics: diag,
                })
            },
        }
    }

    /// Emits one progress event best-effort: a full or closed channel
    /// loses the event instead of stalling the session.
    fn emit(&self, event: SessionEvent) {
        if let Some(events) = &self.events {
            let _ = events.try_send(event);
        }
    }

    /// Re-sends one previously encoded frame under the phase deadline, so
    /// every retransmission carries the same bound as the initial send.
    async fn resend(
        &mut self,
        raw: bytes::Bytes,
        deadline: Instant,
        phase: Phase,
    ) -> Result<(), PunchError> {
        send_deadlined(self.sig.send_raw(raw), deadline, phase).await
    }

    async fn drive(
        mut self,
        role: Role,
        diag: &mut SessionDiagnostics,
    ) -> Result<Punched<F::Socket>, PunchError> {
        let total_start = Instant::now();
        let overall = total_start + self.config.overall_deadline;

        // Probe. A cached classification skips the phase entirely.
        let t = Instant::now();
        let mine = match self.cached.take() {
            Some(cached) => cached,
            None => crate::nat::probe::probe(&self.config, &self.factory, overall).await?,
        };
        let probe_ms = elapsed_ms(t);
        diag.local = Some(mine.clone());
        self.emit(SessionEvent::Probe(mine.clone()));
        diag.phase_ms.probe_ms = probe_ms;

        // Exchange: both sides publish their evidence. The window opens when
        // the phase starts, so a slow Probe leaves the full budget here.
        let t = Instant::now();
        let exchange_deadline = t + self.config.exchange_timeout;
        let peer = self
            .exchange(role, &mine, exchange_deadline.min(overall))
            .await?;
        let exchange_ms = elapsed_ms(t);
        diag.peer = Some(peer.clone());
        self.emit(SessionEvent::Exchange(peer.clone()));
        diag.phase_ms.exchange_ms = exchange_ms;

        // Negotiate, then align both engines on the shared Accept event.
        // The window opens at session start and stays inside the overall wall.
        let t = Instant::now();
        let negotiate_deadline = (total_start + self.config.negotiate_timeout).min(overall);
        let (nonce, sel, engine_start) = match role {
            Role::Initiator => {
                self.negotiate_initiator(&mine, &peer, negotiate_deadline)
                    .await?
            },
            Role::Responder => {
                self.negotiate_responder(&mine, &peer, negotiate_deadline)
                    .await?
            },
        };
        let negotiate_ms = elapsed_ms(t);
        let summary = StrategySummary {
            strategy: sel.strategy,
            initiator_sockets: sel.initiator_sockets,
            responder_sockets: sel.responder_sockets,
            estimate: sel.estimate,
        };
        diag.nonce = Some(nonce);
        diag.selection = Some(summary);
        self.emit(SessionEvent::Negotiate(summary));
        diag.phase_ms.negotiate_ms = negotiate_ms;

        // A peer delay or a large measured RTT can push the shared start
        // past the session wall; the clamp keeps the sleep inside it, and
        // the engine then fails fast on its own deadline instead of the
        // session outliving every deadline first.
        let engine_start = engine_start.min(overall);

        // Punch and Confirm.
        let my_sockets = match role {
            Role::Initiator => sel.initiator_sockets,
            Role::Responder => sel.responder_sockets,
        };
        let mut plan = strategy::build_plan(
            &mine,
            &peer,
            &sel,
            my_sockets,
            nonce,
            role,
            None,
            &self.config,
        );

        // DNS for the refresh query depends on nothing from the negotiation,
        // so it resolves before the aligned sleep; a lookup that ran after
        // the shared start would shift this side's pulses by its own latency.
        // The plan settles first, so symmetric strategies that announce
        // nothing skip the lookups entirely, and the whole resolution fits
        // in the time left before the shared start.
        plan.refresh_server = if plan.refresh_v4 == strategy::Refresh::Stun {
            first_stun_addr(&self.config, engine_start).await
        } else {
            None
        };
        let refresh_server = plan.refresh_server;

        tokio::time::sleep_until(engine_start).await;

        let engine = Engine::new(plan, self.config.clone(), nonce, overall);
        let engine_result = engine.run(&self.factory, &mut self.sig).await;
        if let Err(e) = &engine_result {
            // The peer learns the failure instead of draining its deadline.
            let reason = match e {
                PunchError::BudgetExhausted | PunchError::ConntrackExhausted => {
                    AbortReason::BudgetExhausted
                },
                _ => AbortReason::Internal,
            };
            let _ =
                send_deadlined(self.sig.send(Frame::Abort(reason)), overall, Phase::Punch).await;
        }
        let (socket, outcome) = engine_result?;

        // The space estimate states the model's port-span input per side;
        // only a symmetric reading draws one, and each side's own view
        // feeds its span, so the roles map before measuring.
        let (initiator_nat, responder_nat) = match role {
            Role::Initiator => (&mine, &peer),
            Role::Responder => (&peer, &mine),
        };
        let span_of = |nat: &NatInfo| {
            matches!(
                strategy::effective_class(nat),
                NatClass::EasySym { .. } | NatClass::HardSym
            )
            .then(|| strategy::peer_space(nat))
        };

        let report = PunchReport {
            role,
            nonce,
            strategy: sel.strategy,
            local_class: mine.v4_class(),
            peer_class: peer.v4_class(),
            local_filtering: mine.v4.as_ref().map(|v4| v4.filtering),
            peer_filtering: peer.v4.as_ref().map(|v4| v4.filtering),
            local_reflexive_v4: mine.reflexive_v4(),
            local_reflexive_v6: mine
                .v6
                .as_ref()
                .map_or_else(Vec::new, |v6| v6.addrs.clone()),
            refresh_server,
            initiator_space: span_of(initiator_nat),
            responder_space: span_of(responder_nat),
            winner_local_port: socket.local_addr().map_or(0, |a| a.port()),
            peer_socket: outcome.peer_socket,
            packets_sent: outcome.packets_sent,
            stale_packets: outcome.stale_packets,
            success_estimate: sel.estimate,
            phase_ms: PhaseDurations {
                probe_ms,
                exchange_ms,
                negotiate_ms,
                punch_ms: outcome.punch_ms,
                confirm_ms: outcome.confirm_ms,
                total_ms: elapsed_ms(total_start),
            },
        };
        Ok(Punched {
            socket,
            peer_addr: outcome.peer_addr,
            report,
        })
    }

    /// Sends `Hello` until the peer's `Hello` arrives.
    async fn exchange(
        &mut self,
        role: Role,
        mine: &NatInfo,
        deadline: Instant,
    ) -> Result<NatInfo, PunchError> {
        let hello = send_deadlined(
            self.sig.send(Frame::Hello(mine.clone())),
            deadline,
            Phase::Exchange,
        )
        .await?;
        let mut retry = resend_ticker(self.config.signaling_retry);
        loop {
            tokio::select! {
                _ = retry.tick() => self.resend(hello.clone(), deadline, Phase::Exchange).await?,
                frame = self.sig.recv() => match frame?.body {
                    Frame::Hello(peer) => return Ok(peer),
                    // An Offer while we are ourselves the Initiator means
                    // both sides claimed the role.
                    Frame::Offer(_) if role == Role::Initiator => {
                        let _ = send_deadlined(self.sig.send(Frame::Abort(AbortReason::Internal)), deadline, Phase::Exchange).await;
                        return Err(PunchError::PeerAborted(AbortReason::Internal));
                    }
                    Frame::Abort(reason) => return Err(PunchError::PeerAborted(reason)),
                    _ => {}
                },
                () = tokio::time::sleep_until(deadline) => {
                    return Err(PunchError::Timeout { phase: Phase::Exchange });
                }
            }
        }
    }

    /// Picks the strategy and shepherds `Offer` through `Accept`.
    ///
    /// Returns the attempt nonce, the selection, and the instant this side
    /// should start punching.
    async fn negotiate_initiator(
        &mut self,
        mine: &NatInfo,
        peer: &NatInfo,
        deadline: Instant,
    ) -> Result<(Nonce, Selection, Instant), PunchError> {
        let sel = match strategy::select(mine, peer, &self.config) {
            Ok(sel) => sel,
            Err(e @ PunchError::Unpunchable { .. }) => {
                // The decision needs no packets, so the peer learns it before
                // any socket opens.
                let _ = send_deadlined(
                    self.sig.send(Frame::Abort(AbortReason::Unpunchable)),
                    deadline,
                    Phase::Negotiate,
                )
                .await;
                return Err(e);
            },
            Err(e) => return Err(e),
        };
        let nonce = new_nonce();
        let rtt = self.sig.rtt();
        // Both sides count this delay from the Responder sending Accept, and
        // it covers one full RTT plus a binding margin.
        let delay = rtt + Duration::from_millis(300);
        let offer = Frame::Offer(Offer {
            nonce,
            strategy: sel.strategy,
            local_sockets: sel.initiator_sockets,
            peer_sockets: sel.responder_sockets,
            start_delay_ms: delay.as_millis() as u32,
        });
        let offer = send_deadlined(self.sig.send(offer), deadline, Phase::Negotiate).await?;
        let mut retry = resend_ticker(self.config.signaling_retry);
        loop {
            tokio::select! {
                _ = retry.tick() => self.resend(offer.clone(), deadline, Phase::Negotiate).await?,
                frame = self.sig.recv() => match frame?.body {
                    Frame::Accept => {
                        // The Accept left the peer about half an RTT before
                        // we heard it, so we start that much earlier.
                        let skew = rtt / 2;
                        let start = Instant::now() + delay.saturating_sub(skew);
                        return Ok((nonce, sel, start));
                    }
                    Frame::Offer(_) => {
                        let _ = send_deadlined(self.sig.send(Frame::Abort(AbortReason::Internal)), deadline, Phase::Negotiate).await;
                        return Err(PunchError::PeerAborted(AbortReason::Internal));
                    }
                    Frame::Abort(reason) => return Err(PunchError::PeerAborted(reason)),
                    _ => {}
                },
                () = tokio::time::sleep_until(deadline) => {
                    return Err(PunchError::Timeout { phase: Phase::Negotiate });
                }
            }
        }
    }

    /// Waits for `Offer`, answers `Accept`, and schedules the start.
    async fn negotiate_responder(
        &mut self,
        mine: &NatInfo,
        peer: &NatInfo,
        deadline: Instant,
    ) -> Result<(Nonce, Selection, Instant), PunchError> {
        loop {
            tokio::select! {
                frame = self.sig.recv() => match frame?.body {
                    Frame::Offer(offer) => {
                        // The Offer crosses an untrusted wire with no
                        // send-side caps, so both fields are bounded before
                        // they reach the plan: socket counts are clamped, a
                        // start beyond the cap aborts instead of sleeping
                        // past every deadline, and a side with zero sockets
                        // aborts instead of running an empty plan to the
                        // phase deadline.
                        if u64::from(offer.start_delay_ms) > Self::MAX_START_DELAY_MS
                            || offer.local_sockets == 0
                            || offer.peer_sockets == 0
                        {
                            let _ = send_deadlined(self.sig.send(Frame::Abort(AbortReason::Internal)), deadline, Phase::Negotiate).await;
                            return Err(PunchError::PeerAborted(AbortReason::Internal));
                        }
                        let clamp = |sockets: u16| sockets.min(self.config.max_sockets);
                        let mut sel = Selection {
                            strategy: offer.strategy,
                            initiator_sockets: clamp(offer.local_sockets),
                            responder_sockets: clamp(offer.peer_sockets),
                            estimate: None,
                        };
                        // The Offer carries no estimate, so the report
                        // rebuilds it over the local view.
                        sel.fill_estimate(mine, peer, &self.config);
                        let accept =
                            send_deadlined(self.sig.send(Frame::Accept), deadline, Phase::Negotiate)
                                .await?;
                        // The shared event is this send; count from here.
                        let start = Instant::now() + Duration::from_millis(u64::from(offer.start_delay_ms));
                        // The Accept carries no acknowledgement, so it is
                        // re-sent until the punch window opens; a loss on the
                        // host channel then costs one cadence, not the whole
                        // attempt. The cadence is capped because the default
                        // signaling retry of 500 ms exceeds the whole start
                        // window, which would leave the re-sends no room.
                        // The window answers nothing but a peer Abort.
                        let resend_until = start
                            .checked_sub(Self::ACCEPT_RESEND_MARGIN)
                            .unwrap_or_else(Instant::now)
                            .min(deadline);
                        let cadence =
                            self.config.signaling_retry.min(Duration::from_millis(150));
                        let mut retry = resend_ticker(cadence);
                        loop {
                            tokio::select! {
                                _ = retry.tick() => self.resend(accept.clone(), resend_until, Phase::Negotiate).await?,
                                frame = self.sig.recv() => {
                                    // Only a peer Abort ends the window early.
                                    if let Frame::Abort(reason) = frame?.body {
                                        return Err(PunchError::PeerAborted(reason));
                                    }
                                }
                                () = tokio::time::sleep_until(resend_until) => {
                                    return Ok((offer.nonce, sel, start));
                                }
                            }
                        }
                    }
                    Frame::Abort(reason) => return Err(PunchError::PeerAborted(reason)),
                    // Duplicates of the Exchange phase carry no action.
                    _ => {}
                },
                () = tokio::time::sleep_until(deadline) => {
                    return Err(PunchError::Timeout { phase: Phase::Negotiate });
                }
            }
        }
    }
}

fn elapsed_ms(t: Instant) -> u64 {
    t.elapsed().as_millis() as u64
}

/// Builds the retransmission cadence every signaling loop shares.
///
/// The ticker starts one full cadence after the initial send, so the
/// first repeat never fires immediately, and a tick missed while another
/// select branch ran fires late instead of bursting.
fn resend_ticker(cadence: Duration) -> tokio::time::Interval {
    let mut ticker = tokio::time::interval_at(Instant::now() + cadence, cadence);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker
}

/// Runs one signaling send under its phase deadline.
///
/// The deadline branch of a select loop cannot preempt an await inside
/// another arm's body, and a send outside the loop has no branch at all,
/// so every signaling send carries its own bound: a host that holds its
/// end of the bridge but stops draining it fails the phase instead of
/// parking the session on a full channel.
async fn send_deadlined<T>(
    send: impl Future<Output = Result<T, PunchError>>,
    deadline: Instant,
    phase: Phase,
) -> Result<T, PunchError> {
    match tokio::time::timeout_at(deadline, send).await {
        Ok(result) => result,
        Err(_elapsed) => Err(PunchError::Timeout { phase }),
    }
}

/// Truncates a host-supplied classification to the wire limits, so the first
/// `Hello` always fits a signaling frame whatever the host cached.
fn clamp_nat_info(mut nat: NatInfo) -> NatInfo {
    if let Some(v4) = &mut nat.v4 {
        v4.alloc_seq.truncate(crate::msg::MAX_ALLOC_SEQ);
    }
    if let Some(v6) = &mut nat.v6 {
        v6.addrs.truncate(crate::msg::MAX_V6_ADDRS);
    }
    nat.local.truncate(crate::msg::MAX_LOCAL_ADDRS);
    nat
}

/// The first configured STUN server as a socket address, for refresh
/// queries. Literal addresses resolve without any network access, each
/// lookup runs under its own short budget inside `deadline`, and the
/// search stops at the first hit so the remaining servers cost no lookups.
async fn first_stun_addr(cfg: &PunchConfig, deadline: Instant) -> Option<SocketAddr> {
    for server in &cfg.stun_servers {
        if let Some(addr) = lookup_server(cfg, server, deadline)
            .await
            .into_iter()
            .find(SocketAddr::is_ipv4)
        {
            return Some(addr);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddrV4, SocketAddrV6},
        time::Duration,
    };

    use super::{Phase, PunchError, Puncher, TokioFactory, clamp_nat_info};
    use crate::{
        config::PunchConfig,
        nat::{FilterClass, NatClass, NatInfo, V4Nat, V6Nat},
    };

    #[test]
    fn cached_nat_is_clamped_to_wire_limits() {
        let nat = NatInfo {
            v4: Some(V4Nat {
                class: NatClass::EasySym { step: 2 },
                reflexive: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 40001),
                alloc_seq: vec![40001; crate::msg::MAX_ALLOC_SEQ * 2],
                distinct_probe_ips: 4,
                filtering: FilterClass::Unknown,
                hairpin: true,
            }),
            v6: Some(V6Nat {
                addrs: vec![
                    SocketAddrV6::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into(), 0, 0, 0);
                    crate::msg::MAX_V6_ADDRS * 2
                ],
            }),
            local: vec![Ipv4Addr::new(192, 168, 1, 10); crate::msg::MAX_LOCAL_ADDRS * 2],
        };
        let clamped = clamp_nat_info(nat);
        let v4 = clamped.v4.expect("v4 survives the clamp");
        assert_eq!(v4.alloc_seq.len(), crate::msg::MAX_ALLOC_SEQ);
        assert_eq!(
            clamped.v6.expect("v6 survives the clamp").addrs.len(),
            crate::msg::MAX_V6_ADDRS
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stuck_host_channel_fails_the_phase() {
        let (host, lib) = crate::signaling::bridge(1);
        let cfg = PunchConfig {
            exchange_timeout: Duration::from_millis(200),
            signaling_retry: Duration::from_millis(50),
            ..PunchConfig::default()
        };
        let session = Puncher::with_factory(cfg, TokioFactory)
            .expect("config valid")
            .with_cached_nat(cached_cone())
            .with_signaling(lib);
        // The held host end never drains: the first Hello fills the channel
        // and the resend inside the retry arm blocks, where the deadline
        // branch of the select cannot reach it.
        let stuck = tokio::time::timeout(Duration::from_secs(120), session.initiator());
        let failure = stuck
            .await
            .expect("session returns")
            .expect_err("exchange cannot complete");
        assert!(
            matches!(failure.error, PunchError::Timeout {
                phase: Phase::Exchange
            }),
            "got {:?}",
            failure.error
        );
        // The failure carries what Exchange had learned: the local
        // classification from the cache, and nothing from the peer.
        let d = &failure.diagnostics;
        assert!(d.local.is_some(), "the cached classification survives");
        assert!(d.peer.is_none(), "the peer never answered");
        assert!(d.selection.is_none() && d.nonce.is_none());
        assert_eq!(d.phase_ms.probe_ms, 0, "a cached session skips Probe");
        assert!(d.phase_ms.total_ms >= 200, "total covers the attempt");
        drop(host);
    }

    /// A cached cone reading the Negotiate phase can consume without Probe.
    fn cached_cone() -> NatInfo {
        NatInfo {
            v4: Some(V4Nat {
                class: NatClass::Cone,
                reflexive: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 40000),
                alloc_seq: vec![40000; 4],
                distinct_probe_ips: 2,
                filtering: FilterClass::Unknown,
                hairpin: true,
            }),
            v6: None,
            local: Vec::new(),
        }
    }

    /// An Offer that leaves a side with zero sockets aborts the attempt
    /// right away instead of running an empty plan into the phase deadline.
    #[tokio::test(start_paused = true)]
    async fn zero_socket_offer_aborts_instead_of_idling() {
        use crate::msg::{Frame, Offer, SigFrame, StrategyId, encode_sig};

        for (local_sockets, peer_sockets) in [(0, 4), (4, 0)] {
            let (mut host, lib) = crate::signaling::bridge(8);
            let session = Puncher::with_factory(PunchConfig::default(), TokioFactory)
                .expect("config valid")
                .with_cached_nat(cached_cone())
                .with_signaling(lib);
            let drive = tokio::spawn(session.responder());
            // Exchange consumes the peer Hello; the Offer follows in order.
            for body in [
                Frame::Hello(cached_cone()),
                Frame::Offer(Offer {
                    nonce: [1; 16],
                    strategy: StrategyId::ConeExchange,
                    local_sockets,
                    peer_sockets,
                    start_delay_ms: 500,
                }),
            ] {
                host.from_peer
                    .send(bytes::Bytes::from(encode_sig(&SigFrame {
                        ts: 1,
                        echo: 0,
                        body,
                    })))
                    .await
                    .expect("host frame send");
            }

            let err = drive
                .await
                .expect("task joins")
                .expect_err("zero-socket offer aborts");
            assert!(
                matches!(
                    err.error,
                    PunchError::PeerAborted(super::AbortReason::Internal)
                ),
                "got {:?}",
                err.error
            );
            // Both classifications crossed before the Offer aborted the
            // attempt, and the selection never settled.
            assert!(err.diagnostics.local.is_some());
            assert!(err.diagnostics.peer.is_some());
            assert!(err.diagnostics.selection.is_none());
            // The host channel saw our own Hello, then the Abort.
            let _ = host.to_peer.recv().await.expect("hello drains");
            let abort = host.to_peer.recv().await.expect("abort drains");
            let frame = crate::msg::decode_sig(&abort).expect("abort decodes");
            assert_eq!(frame.body, Frame::Abort(super::AbortReason::Internal));
        }
    }
}
