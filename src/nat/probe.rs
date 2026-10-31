//! STUN binding prober.
//!
//! The prober resolves every address of every configured server and queries
//! all destinations from one socket in one fan-out round, which yields the
//! allocation sequence that classification fits. Before the fan-out, one
//! discovery probe asks the first server for OTHER-ADDRESS, and a
//! discovery-capable answer takes the two RFC 5780 filtering tests right
//! there: the tests need a mapping whose destination set holds only the
//! test target, and a fan-out that ran first would have written every grid
//! port, letting a port-strict filter admit the change-port reply through
//! an already-written destination. The wire subset the prober speaks lives
//! in `super::stun`.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use tokio::time::Instant;

#[cfg(test)]
use super::stun::binding_response;
// The strategy engine sends refresh queries and parses their answers
// through this module's historical path.
pub(crate) use super::stun::{binding_request, parse_mapped};
use super::stun::{change_request, is_binding_request, parse_response};
use crate::{
    config::PunchConfig,
    error::{Phase, PunchError},
    msg::{MAX_ALLOC_SEQ, MAX_V6_ADDRS},
    nat::{FilterClass, NatInfo, V4Nat, V6Nat, classify},
    socket::{Family, UdpFactory, UdpIo},
};

/// How long one filtering test waits for its answer.
///
/// Real servers answer within one RTT; the window only runs out against a
/// server that silently dropped the change request, which is exactly the
/// outcome the test records. Two tests plus the hairpin probe of the same
/// socket stay inside this many multiples of the window under the phase
/// deadline.
const FILTER_TEST_WAIT: Duration = Duration::from_millis(400);

/// Runs the Probe phase and returns the evidence it collected.
///
/// Both address families fit inside `cfg.probe_timeout`, and the whole
/// phase never outlives `overall`, the session's wall-clock deadline.
pub(crate) async fn probe<F: UdpFactory>(
    cfg: &PunchConfig,
    factory: &F,
    overall: Instant,
) -> Result<NatInfo, PunchError> {
    let start = Instant::now();
    let deadline = (start + cfg.probe_timeout).min(overall);

    let v4_dests = resolve(cfg, false, deadline).await;
    if v4_dests.is_empty() {
        return Err(PunchError::NoStunDestination);
    }
    let socket = factory
        .bind(Family::V4.any_addr())
        .await
        .map_err(|source| PunchError::Io {
            phase: Phase::Probe,
            source,
        })?;

    // The filter axis takes the two RFC 5780 tests against the first server
    // while its mapping holds one written destination; a server without
    // discovery support or a lost discovery probe leaves `Unknown`.
    let filtering = match discover_other(&socket, v4_dests[0], deadline).await {
        Some(other) => measure_filtering(&socket, v4_dests[0], other, deadline).await,
        None => FilterClass::Unknown,
    };

    // Destination count above the wire cap adds evidence the frames cannot
    // carry, so the fan-out stops there.
    let mut round = Fanout::new(v4_dests.into_iter().take(MAX_ALLOC_SEQ).collect());
    round.send_pending(&socket).await;
    round
        .collect(&socket, (start + cfg.probe_timeout / 2).min(deadline))
        .await;
    // One retry round for silent destinations, bounded by the phase deadline.
    if round.pending() > 0 {
        round.send_pending(&socket).await;
        round.collect(&socket, deadline).await;
    }

    // The first answered sample in send order fixes the reflexive address,
    // which keeps the result deterministic.
    let Some((first_idx, reflexive)) = round.first() else {
        return Err(PunchError::Timeout {
            phase: Phase::Probe,
        });
    };
    let observed = round.observed();
    let public = is_public(&socket, round.dest(first_idx), &reflexive);

    // The one-socket fan-out settles the class on its own: differing ports
    // across destinations already rule out a cone, while a port shared by two
    // sockets can still be coincidence inside a narrow allocation range, so
    // no socket-independence check overrides the sequence.
    let class = classify::classify(public, &observed);

    let v4 = V4Nat {
        class,
        reflexive: SocketAddrV4::new(
            match reflexive.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            },
            reflexive.port(),
        ),
        alloc_seq: observed.iter().map(|&(_, port)| port).collect(),
        distinct_probe_ips: distinct_answered_ips(&round.dests, &round.slots),
        filtering,
        hairpin: hairpin_test(&socket, reflexive, deadline).await,
    };

    let v6 = if cfg.ipv6 {
        probe_v6(cfg, factory, deadline).await
    } else {
        None
    };
    let local = local_candidates(&socket, round.dest(first_idx));

    Ok(NatInfo {
        v4: Some(v4),
        v6,
        local,
    })
}

/// Collects global IPv6 reflexive addresses when a server and a route exist.
///
/// One fan-out round inside what remains of the phase budget, at most half
/// of it, so a silent IPv6 path delays the session by half a budget at most.
async fn probe_v6<F: UdpFactory>(
    cfg: &PunchConfig,
    factory: &F,
    deadline: Instant,
) -> Option<V6Nat> {
    let servers = resolve(cfg, true, deadline).await;
    if servers.is_empty() {
        return None;
    }
    let socket = factory.bind(Family::V6.any_addr()).await.ok()?;
    let until = (Instant::now() + cfg.probe_timeout / 2).min(deadline);
    let mut round = Fanout::new(servers.into_iter().take(MAX_V6_ADDRS).collect());
    round.send_pending(&socket).await;
    round.collect(&socket, until).await;
    let addrs = global_v6(&round.slots);
    (!addrs.is_empty()).then_some(V6Nat { addrs })
}

/// The usable addresses among one fan-out's answers.
///
/// A V4 answer on the v6 socket carries no IPv6 address, and a non-global
/// v6 answer — an IPv4-mapped reflexive address under a dual-stack server,
/// an unspecified one — names no peer the Direct stage could reach.
fn global_v6(slots: &[Option<SocketAddr>]) -> Vec<SocketAddrV6> {
    slots
        .iter()
        .flatten()
        .filter_map(|addr| match addr {
            SocketAddr::V6(addr) if super::usable_v6(*addr.ip()) => Some(*addr),
            _ => None,
        })
        .collect()
}

/// One round set of binding queries over one socket.
///
/// Slot `i` holds the answer of `dests[i]`. Queries go out in index
/// order, so a symmetric NAT allocates in index order among the requests
/// that reached it, and the slots plus the per-destination send and round
/// records reconstruct the allocation sequence.
struct Fanout {
    dests: Vec<SocketAddr>,
    /// One transaction id per destination, kept stable across retry rounds,
    /// so a late answer to an earlier round still matches its slot.
    txids: Vec<[u8; 12]>,
    slots: Vec<Option<SocketAddr>>,
    /// Whether any send attempt to the destination left this host. A
    /// destination nothing left for holds no NAT allocation.
    sent: Vec<bool>,
    /// The collect round each answer arrived in, zero while silent.
    answered_in: Vec<u8>,
    /// The collect round in progress, one-based.
    collecting: u8,
}

impl Fanout {
    fn new(dests: Vec<SocketAddr>) -> Self {
        let count = dests.len();
        let slots = vec![None; count];
        let txids = dests.iter().map(|_| rand::random()).collect();
        let sent = vec![false; count];
        let answered_in = vec![0; count];
        Self {
            dests,
            txids,
            slots,
            sent,
            answered_in,
            collecting: 0,
        }
    }

    /// Destinations that have no answer yet.
    fn pending(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_none()).count()
    }

    /// The destination of one send index.
    fn dest(&self, idx: usize) -> SocketAddr {
        self.dests[idx]
    }

    /// Sends one request per still-silent destination, in send-index order.
    ///
    /// A retry targets the same destination from the same socket, so it
    /// reuses the mapping of the first send whenever that send reached the
    /// NAT. A first send that never reached the NAT leaves the allocation
    /// to the retry, which runs after every first-round allocation, so each
    /// answer also records the round it arrived in.
    async fn send_pending<S: UdpIo>(&mut self, socket: &S) {
        for idx in 0..self.dests.len() {
            if self.slots[idx].is_some() {
                continue;
            }
            let request = binding_request(&self.txids[idx]);
            if socket.send_to(&request, self.dests[idx]).await.is_ok() {
                self.sent[idx] = true;
            }
        }
    }

    /// Collects answers until no destination pends or `until` passes.
    async fn collect<S: UdpIo>(&mut self, socket: &S, until: Instant) {
        self.collecting = self.collecting.saturating_add(1);
        while self.pending() > 0 {
            // Servers prepend their own attributes ahead of XOR-MAPPED, so
            // the buffer leaves room beyond the minimal binding response.
            // The cap is 1024 bytes: a longer datagram arrives truncated,
            // the parser bounds its attribute scan by the received bytes,
            // and an XOR-MAPPED-ADDRESS living past the cap goes unread,
            // which counts that server as silent. Binding responses that
            // keep the mapped attribute inside a kilobyte are the norm.
            let mut buf = [0u8; 1024];
            // A deadline miss or a socket error ends the round; whatever
            // answered so far stands.
            let Ok(Ok((len, from))) =
                tokio::time::timeout_at(until, socket.recv_from(&mut buf)).await
            else {
                break;
            };
            self.absorb(&buf[..len], from);
        }
    }

    /// Places one answer datagram into the slot of its transaction id.
    ///
    /// Answers overtake each other; the transaction id selects the slot, so
    /// the slots keep send order whatever the arrival order is. A duplicate
    /// of an answered slot matches no pending slot and is dropped. RFC 5389
    /// section 7.1 requires the response source to equal the request
    /// destination, so a matching transaction id from any other source is
    /// dropped too.
    fn absorb(&mut self, buf: &[u8], from: SocketAddr) {
        for (idx, (slot, txid)) in self.slots.iter_mut().zip(&self.txids).enumerate() {
            if slot.is_none()
                && from == self.dests[idx]
                && let Some(answer) = parse_response(buf, txid)
            {
                *slot = Some(answer.mapped);
                self.answered_in[idx] = self.collecting;
                break;
            }
        }
    }

    /// The first answered sample in send order.
    fn first(&self) -> Option<(usize, SocketAddr)> {
        self.slots
            .iter()
            .enumerate()
            .find_map(|(idx, slot)| slot.map(|addr| (idx, addr)))
    }

    /// The `(allocation index, port)` pairs classification fits.
    ///
    /// The allocation index counts the destinations that reached the NAT,
    /// in send order. Two faults bend that count away from the send index:
    /// a destination whose sends all failed locally never allocated, and a
    /// round-two answer may report a mapping the retry allocated after
    /// every round-one mapping instead of the one its send position
    /// implies. When the straight reading holds no constant step, the
    /// round-two answers are re-read as late allocations before the fit
    /// gives up.
    fn observed(&self) -> Vec<(usize, u16)> {
        let straight = self.positions(false);
        let answered_in_retry = self.answered_in.iter().any(|&round| round > 1);
        if !answered_in_retry || classify::constant_step(&straight).is_some() {
            return straight;
        }
        let retried = self.positions(true);
        if classify::constant_step(&retried).is_some() {
            return retried;
        }
        straight
    }

    /// Answer positions under one fault hypothesis.
    ///
    /// With `retries_allocate`, every round-two answer leaves the
    /// first-round order and follows it: its retry ran after all
    /// first-round sends, so its mapping sits behind theirs. A destination
    /// that stayed silent keeps its position as a hole, an allocation
    /// whose port no server reported.
    fn positions(&self, retries_allocate: bool) -> Vec<(usize, u16)> {
        let mut out = Vec::new();
        let mut pos = 0;
        for idx in 0..self.dests.len() {
            if !self.sent[idx] {
                continue;
            }
            let late = retries_allocate && self.answered_in[idx] > 1;
            if !late {
                if let Some(addr) = self.slots[idx] {
                    out.push((pos, addr.port()));
                }
                pos += 1;
            }
        }
        if retries_allocate {
            for idx in 0..self.dests.len() {
                if self.sent[idx]
                    && self.answered_in[idx] > 1
                    && let Some(addr) = self.slots[idx]
                {
                    out.push((pos, addr.port()));
                    pos += 1;
                }
            }
        }
        out
    }
}

/// Distinct server IPs among the answered destinations of one fan-out.
///
/// The count measures how many mappings an address-dependent NAT could
/// have shown: a destination that stayed silent contributed no port, so
/// only the answered destinations count. The answer slots carry reflexive
/// addresses, so the count pairs each answer with its destination.
fn distinct_answered_ips(dests: &[SocketAddr], slots: &[Option<SocketAddr>]) -> u8 {
    let mut ips: Vec<IpAddr> = dests
        .iter()
        .zip(slots)
        .filter_map(|(dst, slot)| slot.is_some().then_some(dst.ip()))
        .collect();
    ips.sort_unstable();
    ips.dedup();
    ips.len().min(usize::from(u8::MAX)) as u8
}

/// The IPv4 address a probe socket's local end names.
///
/// A specific bind reports its own address, and an IPv6 local address
/// counts only where it canonicalizes to a specific IPv4 one. Every other
/// local address — the wildcard above all — resolves through the connect
/// trick toward `server`, which names the outgoing interface.
fn local_v4_ip(local: IpAddr, server: SocketAddr) -> Option<Ipv4Addr> {
    let bound = match local {
        IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip),
        IpAddr::V6(v6) => match v6.to_canonical() {
            IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
            _ => None,
        },
        IpAddr::V4(_) => None,
    };
    bound.or_else(|| crate::socket::sys::routed_local_ip(server).ok().flatten())
}

/// A socket is public when its reflexive address is its own address.
///
/// Sockets bound to the wildcard report `0.0.0.0`, so the interface address
/// toward the server stands in for the local one. A route the connect
/// trick cannot resolve leaves the unspecified address, which equals no
/// reflexive address the comparison accepts.
fn is_public<S: UdpIo>(socket: &S, server: SocketAddr, reflexive: &SocketAddr) -> bool {
    let Ok(local) = socket.local_addr() else {
        return false
    };
    let local_ip = local_v4_ip(local.ip(), server).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let IpAddr::V4(reflexive_ip) = reflexive.ip() else {
        return false
    };
    local_ip == reflexive_ip && local.port() == reflexive.port()
}

/// Whether a datagram aimed at the socket's own reflexive address loops
/// back (RFC 4787 §6 hairpinning).
///
/// One binding request leaves for the reflexive address itself, and a NAT
/// that hairpins delivers it back to the sending socket, where the
/// transaction id identifies it. A public path delivers trivially: the
/// reflexive address is the host's own. Silence costs one retry, a lost
/// datagram's worth; a NAT without loopback stays silent both times.
async fn hairpin_test<S: UdpIo>(socket: &S, reflexive: SocketAddr, deadline: Instant) -> bool {
    if reflexive.is_ipv6() {
        return false;
    }
    for _ in 0..2 {
        let txid: [u8; 12] = rand::random();
        let request = binding_request(&txid);
        if socket.send_to(&request, reflexive).await.is_err() {
            return false;
        }
        let until = (Instant::now() + FILTER_TEST_WAIT).min(deadline);
        loop {
            let mut buf = [0u8; 1024];
            let Ok(Ok((len, from))) =
                tokio::time::timeout_at(until, socket.recv_from(&mut buf)).await
            else {
                break;
            };
            // The looped request arrives from the translated source, which
            // is the reflexive address; any other datagram is noise to
            // drain.
            if from == reflexive && is_binding_request(&buf[..len], &txid) {
                return true;
            }
        }
    }
    false
}

/// The local interface addresses the Local stage can aim at.
///
/// A specifically bound socket reports its own address; a wildcard bind
/// falls back to the interface the route to the first server picks, via
/// the connect trick. Loopback stays eligible, so a lab without a real
/// interface can stand it in. The probe reads one route, so the list
/// holds at most one address here; the wire cap admits a peer that
/// enumerates more. A route the connect trick cannot resolve leaves the
/// list empty.
fn local_candidates<S: UdpIo>(socket: &S, server: SocketAddr) -> Vec<Ipv4Addr> {
    let Ok(local) = socket.local_addr() else {
        return Vec::new();
    };
    local_v4_ip(local.ip(), server).into_iter().collect()
}

/// Resolves one configured server to addresses, under a short budget
/// inside `deadline`.
///
/// A literal IP resolves on the first poll even with no budget left. A
/// failed or timed-out lookup yields no addresses, so a hung system
/// resolver costs one lookup, not the phase.
pub(crate) async fn lookup_server(
    cfg: &PunchConfig,
    server: &str,
    deadline: Instant,
) -> Vec<SocketAddr> {
    let per_lookup = cfg
        .probe_timeout
        .min(Duration::from_secs(2))
        .min(deadline.saturating_duration_since(Instant::now()));
    match tokio::time::timeout(per_lookup, tokio::net::lookup_host(server)).await {
        Ok(Ok(list)) => list.collect(),
        _ => Vec::new(),
    }
}

/// Resolves configured servers to addresses of one family.
///
/// Every address of a hostname joins the destination list, and a literal IP
/// resolves to itself. Duplicates drop out, so one destination means one
/// mapping.
async fn resolve(cfg: &PunchConfig, want_v6: bool, deadline: Instant) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for server in &cfg.stun_servers {
        for addr in lookup_server(cfg, server, deadline).await {
            if addr.is_ipv6() == want_v6 && !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}

/// The filtering verdict from the two RFC 5780 test outcomes.
///
/// A reply from the alternate IP names an address the mapping never wrote,
/// so only an endpoint-independent filter admits it. A reply from the
/// alternate port on the written address is what an address-dependent
/// filter admits and a port-strict one drops. Both silent reads as the
/// port-strict class.
fn filtering_class(alternate_ip: bool, alternate_port: bool) -> FilterClass {
    if alternate_ip {
        FilterClass::EndpointIndependent
    } else if alternate_port {
        FilterClass::AddressDependent
    } else {
        FilterClass::AddressPortDependent
    }
}

/// Asks one destination for a binding answer that advertises OTHER-ADDRESS.
///
/// The call runs before the fan-out, so the socket's mapping holds exactly
/// the destination this probe wrote — the state the filtering tests need.
/// Silence costs one retry, a datagram's worth of loss; an answer without
/// the attribute names a plain RFC 5389 server and ends the search, because
/// the other destinations face the same fan-out constraint and `Unknown`
/// beats a filter class the fan-out's written ports could corrupt.
async fn discover_other<S: UdpIo>(
    socket: &S,
    dest: SocketAddr,
    deadline: Instant,
) -> Option<SocketAddrV4> {
    for _ in 0..2 {
        let txid: [u8; 12] = rand::random();
        let request = binding_request(&txid);
        socket.send_to(&request, dest).await.ok()?;
        let until = (Instant::now() + FILTER_TEST_WAIT).min(deadline);
        loop {
            let mut buf = [0u8; 1024];
            let Ok(Ok((len, from))) =
                tokio::time::timeout_at(until, socket.recv_from(&mut buf)).await
            else {
                break;
            };
            if from == dest
                && let Some(answer) = parse_response(&buf[..len], &txid)
            {
                return answer.other;
            }
        }
    }
    None
}

/// Runs the two RFC 5780 filtering tests against one discovery server.
///
/// Test one carries CHANGE-IP: its answer must come back from the
/// alternate IP. Test two carries CHANGE-PORT and only runs when test one
/// stayed silent, so an endpoint-independent filter spends one request
/// where the stricter classes spend two. The answer source check accepts
/// either of the server's two IPs: the port partner of a wide port list
/// is unknowable to the client, and the transaction id plus the server
/// pair carry the match.
async fn measure_filtering<S: UdpIo>(
    socket: &S,
    dest: SocketAddr,
    other: SocketAddrV4,
    deadline: Instant,
) -> FilterClass {
    let server_ips = [dest.ip(), IpAddr::V4(*other.ip())];
    let alternate_ip = filter_test(socket, dest, &server_ips, true, deadline).await;
    let alternate_port =
        !alternate_ip && filter_test(socket, dest, &server_ips, false, deadline).await;
    filtering_class(alternate_ip, alternate_port)
}

/// Sends one change request and reports whether its answer came back.
async fn filter_test<S: UdpIo>(
    socket: &S,
    dest: SocketAddr,
    server_ips: &[IpAddr],
    change_ip: bool,
    deadline: Instant,
) -> bool {
    let txid: [u8; 12] = rand::random();
    let request = change_request(&txid, change_ip, !change_ip);
    if socket.send_to(&request, dest).await.is_err() {
        return false;
    }
    let until = (Instant::now() + FILTER_TEST_WAIT).min(deadline);
    loop {
        let mut buf = [0u8; 1024];
        let Ok(Ok((len, from))) = tokio::time::timeout_at(until, socket.recv_from(&mut buf)).await
        else {
            return false;
        };
        // A datagram of another probe — a late fan-out answer — is drained
        // and ignored; only the matching transaction from a server IP ends
        // the wait.
        if server_ips.contains(&from.ip()) && parse_response(&buf[..len], &txid).is_some() {
            return true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_land_in_send_order_slots() {
        let dests: Vec<SocketAddr> = (0..3u16)
            .map(|port| SocketAddr::V4(SocketAddrV4::new([1, 1, 1, 1].into(), 3478 + port)))
            .collect();
        let mut round = Fanout::new(dests);
        // Every destination received its request.
        round.sent = vec![true; 3];
        // Destination 2 answers first and destination 1 last.
        round.absorb(&binding_response(&round.txids[2], 5012), round.dest(2));
        round.absorb(&binding_response(&round.txids[0], 5010), round.dest(0));
        round.absorb(&binding_response(&round.txids[1], 5011), round.dest(1));
        // Ports sit at their send indexes, whatever the arrival order was.
        assert_eq!(round.observed(), vec![(0, 5010), (1, 5011), (2, 5012)]);
        assert_eq!(
            round.first().map(|(idx, addr)| (idx, addr.port())),
            Some((0, 5010))
        );
    }

    /// Four destinations on one server address, the default fan-out shape.
    fn four_dests() -> Vec<SocketAddr> {
        (0..4u16)
            .map(|port| SocketAddr::V4(SocketAddrV4::new([1, 1, 1, 1].into(), 3478 + port)))
            .collect()
    }

    /// Places one answer for `idx` while `round` is collecting.
    fn answer(round: &mut Fanout, idx: usize, port: u16) {
        let resp = binding_response(&round.txids[idx], port);
        let dest = round.dest(idx);
        round.absorb(&resp, dest);
    }

    #[test]
    fn unsent_destinations_leave_no_hole() {
        let mut round = Fanout::new(four_dests());
        // Destination 1 never left the host, so the NAT never allocated
        // for it and the stride of two must survive undivided.
        round.sent = vec![true, false, true, true];
        answer(&mut round, 0, 5000);
        answer(&mut round, 2, 5002);
        answer(&mut round, 3, 5004);
        assert_eq!(round.observed(), vec![(0, 5000), (1, 5002), (2, 5004)]);
    }

    #[test]
    fn lost_first_request_reorders_as_a_late_allocation() {
        let mut round = Fanout::new(four_dests());
        round.sent = vec![true; 4];
        // Destination 1's first request never reached the NAT, so its
        // retry allocates after the whole first round: the walk reads
        // 5000, 5001, 5002, then 5003 out of send position.
        round.collecting = 1;
        answer(&mut round, 0, 5000);
        answer(&mut round, 2, 5001);
        answer(&mut round, 3, 5002);
        round.collecting = 2;
        answer(&mut round, 1, 5003);
        assert_eq!(round.observed(), vec![
            (0, 5000),
            (1, 5001),
            (2, 5002),
            (3, 5003)
        ]);
    }

    #[test]
    fn late_answers_keep_their_position_when_the_walk_agrees() {
        let mut round = Fanout::new(four_dests());
        round.sent = vec![true; 4];
        // Response loss alone: the mapping existed from round one and the
        // answer arrived in round two, still on its send position.
        round.collecting = 1;
        answer(&mut round, 0, 5000);
        answer(&mut round, 2, 5002);
        answer(&mut round, 3, 5003);
        round.collecting = 2;
        answer(&mut round, 1, 5001);
        assert_eq!(round.observed(), vec![
            (0, 5000),
            (1, 5001),
            (2, 5002),
            (3, 5003)
        ]);
    }

    #[test]
    fn contradictory_rounds_stay_hard() {
        let mut round = Fanout::new(four_dests());
        round.sent = vec![true; 4];
        // Random-looking ports stay random under either hypothesis.
        round.collecting = 1;
        answer(&mut round, 0, 5000);
        answer(&mut round, 2, 5137);
        answer(&mut round, 3, 5288);
        round.collecting = 2;
        answer(&mut round, 1, 5303);
        let obs = round.observed();
        assert_eq!(obs.len(), 4);
        assert_eq!(classify::constant_step(&obs), None);
    }

    #[test]
    fn duplicate_and_foreign_answers_are_dropped() {
        let dest = vec![SocketAddr::V4(SocketAddrV4::new([1, 1, 1, 1].into(), 3478))];
        let mut round = Fanout::new(dest);
        round.sent = vec![true];
        round.absorb(&binding_response(&round.txids[0], 5010), round.dest(0));
        // A retransmitted answer and a foreign transaction change nothing.
        round.absorb(&binding_response(&round.txids[0], 5099), round.dest(0));
        round.absorb(&binding_response(&[9u8; 12], 5000), round.dest(0));
        assert_eq!(round.observed(), vec![(0, 5010)]);
        assert_eq!(round.pending(), 0);
    }

    #[test]
    fn answers_from_other_sources_are_dropped() {
        let dest = vec![SocketAddr::V4(SocketAddrV4::new([1, 1, 1, 1].into(), 3478))];
        let mut round = Fanout::new(dest);
        round.sent = vec![true];
        // Same transaction id, but the datagram left a different server; a
        // spoofed response has to come from the requested address.
        let other = SocketAddr::V4(SocketAddrV4::new([1, 1, 1, 1].into(), 9999));
        round.absorb(&binding_response(&round.txids[0], 5010), other);
        assert_eq!(round.pending(), 1);
    }

    #[test]
    fn filtering_verdict_reads_both_test_outcomes() {
        use FilterClass as F;
        assert_eq!(filtering_class(true, false), F::EndpointIndependent);
        assert_eq!(filtering_class(false, true), F::AddressDependent);
        assert_eq!(filtering_class(false, false), F::AddressPortDependent);
    }

    /// A dual-stack server can answer the v6 fan-out with an IPv4-mapped
    /// reflexive address; the collection keeps the global addresses only,
    /// the same predicate the peer's advertised list passes at target
    /// build.
    #[test]
    fn v6_collection_keeps_global_addresses_only() {
        let v6 = |ip: std::net::Ipv6Addr| SocketAddr::V6(SocketAddrV6::new(ip, 9999, 0, 0));
        let slots = vec![
            Some(v6("2001:db8::1".parse().expect("global address"))),
            Some(v6("::ffff:203.0.113.9".parse().expect("mapped address"))),
            Some(v6("::".parse().expect("unspecified address"))),
            Some(v6("fe80::1".parse().expect("link-local address"))),
            Some(v6("ff02::1".parse().expect("multicast address"))),
            Some(v6(std::net::Ipv6Addr::LOCALHOST)),
            Some(SocketAddr::V4(SocketAddrV4::new(
                [203, 0, 113, 9].into(),
                9999,
            ))),
            None,
        ];
        let addrs = global_v6(&slots);
        let ips: Vec<IpAddr> = addrs.iter().map(|a| (*a.ip()).into()).collect();
        // Loopback survives: smoke tests stand it in for a global address.
        assert_eq!(ips, vec![
            "2001:db8::1".parse().expect("global address"),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ]);
    }
}
