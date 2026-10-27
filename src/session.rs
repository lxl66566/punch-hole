//! Puncher, the session state machine, and the Punched result.

use std::{net::SocketAddr, time::Duration};

use tokio::time::Instant;

use crate::{
    config::PunchConfig,
    error::{Phase, PunchError},
    msg::{AbortReason, Frame, Nonce, Offer, new_nonce},
    nat::NatInfo,
    report::{PhaseDurations, PunchReport, Role},
    signaling::{LibEnd, SigIo},
    socket::{TokioFactory, UdpFactory, UdpIo},
    strategy::{self, Engine, Selection},
};

/// Entry point: configuration plus an optional cached classification.
pub struct Puncher<F: UdpFactory = TokioFactory> {
    config: PunchConfig,
    cached: Option<NatInfo>,
    factory: F,
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
        })
    }

    /// Reuses a NAT classification from an earlier session and skips Probe.
    #[must_use]
    pub fn with_cached_nat(mut self, nat: NatInfo) -> Self {
        self.cached = Some(clamp_nat_info(nat));
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
        }
    }
}

/// One attempt, driven to completion by `initiator` or `responder`.
pub struct PunchSession<F: UdpFactory> {
    config: PunchConfig,
    cached: Option<NatInfo>,
    factory: F,
    sig: SigIo,
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
    /// Drives the session as the Initiator.
    pub async fn initiator(self) -> Result<Punched<F::Socket>, PunchError> {
        self.run(Role::Initiator).await
    }

    /// Drives the session as the Responder.
    pub async fn responder(self) -> Result<Punched<F::Socket>, PunchError> {
        self.run(Role::Responder).await
    }

    async fn run(mut self, role: Role) -> Result<Punched<F::Socket>, PunchError> {
        let total_start = Instant::now();
        let overall = total_start + self.config.overall_deadline;

        // Probe. A cached classification skips the phase entirely.
        let t = Instant::now();
        let mine = match self.cached.take() {
            Some(cached) => cached,
            None => crate::nat::probe::probe(&self.config, &self.factory).await?,
        };
        let probe_ms = elapsed_ms(t);

        // Exchange: both sides publish their evidence. The window opens when
        // the phase starts, so a slow Probe leaves the full budget here.
        let t = Instant::now();
        let exchange_deadline = t + self.config.exchange_timeout;
        let peer = self
            .exchange(role, &mine, exchange_deadline.min(overall))
            .await?;
        let exchange_ms = elapsed_ms(t);

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

        // DNS for the refresh query depends on nothing from the negotiation,
        // so it resolves before the aligned sleep; a lookup that ran after
        // the shared start would shift this side's pulses by its own latency.
        let refresh_server = first_stun_addr(&self.config).await;

        tokio::time::sleep_until(engine_start).await;

        // Punch and Confirm.
        let my_sockets = match role {
            Role::Initiator => sel.initiator_sockets,
            Role::Responder => sel.responder_sockets,
        };
        let plan = strategy::build_plan(
            &mine,
            &peer,
            &sel,
            my_sockets,
            nonce,
            role,
            refresh_server,
            &self.config,
        );
        let engine = Engine::new(plan, self.config.clone(), nonce);
        let engine_result = engine.run(&self.factory, &mut self.sig).await;
        if let Err(e) = &engine_result {
            // The peer learns the failure instead of draining its deadline.
            let reason = match e {
                PunchError::BudgetExhausted | PunchError::ConntrackExhausted => {
                    AbortReason::BudgetExhausted
                },
                _ => AbortReason::Internal,
            };
            let _ = self.sig.send(Frame::Abort(reason)).await;
        }
        let (socket, outcome) = engine_result?;

        let report = PunchReport {
            role,
            nonce,
            strategy: sel.strategy,
            local_class: mine.v4_class(),
            peer_class: peer.v4_class(),
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
        let hello = Frame::Hello(mine.clone());
        self.sig.send(hello.clone()).await?;
        let mut retry = tokio::time::interval(self.config.signaling_retry);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = retry.tick() => self.sig.send(hello.clone()).await?,
                frame = self.sig.recv() => match frame?.body {
                    Frame::Hello(peer) => return Ok(peer),
                    // An Offer while we are ourselves the Initiator means
                    // both sides claimed the role.
                    Frame::Offer(_) if role == Role::Initiator => {
                        let _ = self.sig.send(Frame::Abort(AbortReason::Internal)).await;
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
                let _ = self.sig.send(Frame::Abort(AbortReason::Unpunchable)).await;
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
        self.sig.send(offer.clone()).await?;
        let mut retry = tokio::time::interval(self.config.signaling_retry);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = retry.tick() => self.sig.send(offer.clone()).await?,
                frame = self.sig.recv() => match frame?.body {
                    Frame::Accept => {
                        // The Accept left the peer about half an RTT before
                        // we heard it, so we start that much earlier.
                        let skew = rtt / 2;
                        let start = Instant::now() + delay.saturating_sub(skew);
                        return Ok((nonce, sel, start));
                    }
                    Frame::Offer(_) => {
                        let _ = self.sig.send(Frame::Abort(AbortReason::Internal)).await;
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
                        let mut sel = Selection {
                            strategy: offer.strategy,
                            initiator_sockets: offer.local_sockets,
                            responder_sockets: offer.peer_sockets,
                            estimate: None,
                        };
                        // The Offer carries no estimate, so the report
                        // rebuilds it over the local view.
                        sel.fill_estimate(mine, peer, &self.config);
                        self.sig.send(Frame::Accept).await?;
                        // The shared event is this send; count from here.
                        let start = Instant::now() + Duration::from_millis(u64::from(offer.start_delay_ms));
                        return Ok((offer.nonce, sel, start));
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

/// Truncates a host-supplied classification to the wire limits, so the first
/// `Hello` always fits a signaling frame whatever the host cached.
fn clamp_nat_info(mut nat: NatInfo) -> NatInfo {
    if let Some(v4) = &mut nat.v4 {
        v4.pub_ips.truncate(crate::msg::MAX_PUB_IPS);
        v4.alloc_seq.truncate(crate::msg::MAX_ALLOC_SEQ);
    }
    if let Some(v6) = &mut nat.v6 {
        v6.addrs.truncate(crate::msg::MAX_V6_ADDRS);
    }
    nat
}

/// The first configured STUN server as a socket address, for refresh
/// queries. Literal addresses resolve without any network access. Each
/// lookup runs under its own short budget, so a hung resolver cannot stall
/// the phase.
async fn first_stun_addr(cfg: &PunchConfig) -> Option<SocketAddr> {
    let per_lookup = cfg.probe_timeout.min(Duration::from_secs(2));
    for server in &cfg.stun_servers {
        let lookup = tokio::net::lookup_host(server);
        let Ok(list) = tokio::time::timeout(per_lookup, lookup).await else {
            continue;
        };
        if let Ok(list) = list {
            for addr in list {
                if addr.is_ipv4() {
                    return Some(addr);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

    use super::clamp_nat_info;
    use crate::nat::{FilterClass, NatClass, NatInfo, V4Nat, V6Nat};

    #[test]
    fn cached_nat_is_clamped_to_wire_limits() {
        let nat = NatInfo {
            v4: Some(V4Nat {
                class: NatClass::EasySym { step: 2 },
                reflexive: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 40001),
                pub_ips: vec![Ipv4Addr::LOCALHOST; crate::msg::MAX_PUB_IPS * 2],
                alloc_seq: vec![40001; crate::msg::MAX_ALLOC_SEQ * 2],
                filtering: FilterClass::Unknown,
            }),
            v6: Some(V6Nat {
                addrs: vec![
                    SocketAddrV6::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into(), 0, 0, 0);
                    crate::msg::MAX_V6_ADDRS * 2
                ],
            }),
        };
        let clamped = clamp_nat_info(nat);
        let v4 = clamped.v4.expect("v4 survives the clamp");
        assert_eq!(v4.pub_ips.len(), crate::msg::MAX_PUB_IPS);
        assert_eq!(v4.alloc_seq.len(), crate::msg::MAX_ALLOC_SEQ);
        assert_eq!(
            clamped.v6.expect("v6 survives the clamp").addrs.len(),
            crate::msg::MAX_V6_ADDRS
        );
    }
}
