//! STUN binding prober.
//!
//! The wire subset is one binding request and one response, written in-tree
//! per the architecture notes. The prober resolves every address of every
//! configured server and queries all destinations from one socket in one
//! fan-out round, which yields the allocation sequence that classification
//! fits.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use tokio::time::Instant;

use crate::{
    config::PunchConfig,
    error::{Phase, PunchError},
    msg::{MAX_ALLOC_SEQ, MAX_V6_ADDRS},
    nat::{FilterClass, NatInfo, V4Nat, V6Nat, classify},
    socket::{Family, UdpFactory, UdpIo},
};

const COOKIE: [u8; 4] = 0x2112_a442u32.to_be_bytes();
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_XOR_MAPPED: u16 = 0x0020;

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
        return Err(PunchError::Io(io::Error::other(
            "no STUN server resolved to an IPv4 address",
        )));
    }
    let socket = factory.bind(Family::V4.any_addr()).await?;

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

    // One port shared across destinations proves endpoint-independent
    // mapping. Filtering is a separate axis that only a change-port or
    // third-party echo test measures, and the prober runs neither.
    let filtering = FilterClass::Unknown;

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
        filtering,
    };

    let v6 = if cfg.ipv6 {
        probe_v6(cfg, factory, deadline).await
    } else {
        None
    };

    Ok(NatInfo { v4: Some(v4), v6 })
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
    // A V4 answer on the v6 socket carries no IPv6 address.
    let addrs: Vec<_> = round
        .slots
        .iter()
        .flatten()
        .filter_map(|addr| match addr {
            SocketAddr::V6(addr) => Some(*addr),
            SocketAddr::V4(_) => None,
        })
        .collect();
    (!addrs.is_empty()).then_some(V6Nat { addrs })
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
        let slots = vec![None; dests.len()];
        let txids = dests.iter().map(|_| rand::random()).collect();
        let sent = vec![false; dests.len()];
        let answered_in = vec![0; dests.len()];
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
                && let Some(addr) = parse_mapped(buf, txid)
            {
                *slot = Some(addr);
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

/// A socket is public when its reflexive address is its own address.
///
/// Sockets bound to the wildcard report `0.0.0.0`, so the interface address
/// toward the server stands in for the local one.
fn is_public<S: UdpIo>(socket: &S, server: SocketAddr, reflexive: &SocketAddr) -> bool {
    let Ok(local) = socket.local_addr() else {
        return false
    };
    let local_ip: Option<Ipv4Addr> = match local.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(ip) => match ip.to_canonical() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        },
    };
    let local_ip = match local_ip {
        Some(ip) if !ip.is_unspecified() => ip,
        _ => crate::socket::sys::routed_local_ip(server)
            .ok()
            .flatten()
            .unwrap_or(Ipv4Addr::UNSPECIFIED),
    };
    let IpAddr::V4(reflexive_ip) = reflexive.ip() else {
        return false
    };
    local_ip == reflexive_ip && local.port() == reflexive.port()
}

/// Resolves configured servers to addresses of one family.
///
/// Every address of a hostname joins the destination list, and a literal IP
/// resolves to itself. Duplicates drop out, so one destination means one
/// mapping. Each lookup runs under its own short budget inside the phase
/// deadline, so a hung system resolver costs one lookup, not the session.
async fn resolve(cfg: &PunchConfig, want_v6: bool, deadline: Instant) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for server in &cfg.stun_servers {
        // A literal IP resolves on the first poll even with no budget left.
        let per_lookup = cfg
            .probe_timeout
            .min(Duration::from_secs(2))
            .min(deadline.saturating_duration_since(Instant::now()));
        let lookup = tokio::net::lookup_host(server);
        let Ok(list) = tokio::time::timeout(per_lookup, lookup).await else {
            continue
        };
        let Ok(list) = list else { continue };
        for addr in list {
            if addr.is_ipv6() == want_v6 && !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}

pub(crate) fn binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&COOKIE);
    out.extend_from_slice(txid);
    out
}

/// Parses a binding response with a matching transaction id.
pub(crate) fn parse_mapped(buf: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_RESPONSE || buf[4..8] != COOKIE || buf[8..20] != *txid {
        return None;
    }
    // The message length bounds the attribute area; datagram bytes past it
    // belong to no attribute and are never scanned.
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = (20 + msg_len).min(buf.len());
    let mut i = 20;
    while i + 4 <= end {
        let attr = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        // An attribute overrunning the declared message ends the scan.
        if i + 4 + len > end {
            return None;
        }
        let body = &buf[i + 4..i + 4 + len];
        if attr == ATTR_XOR_MAPPED && len >= 8 {
            let family = body[1];
            let xport = u16::from_be_bytes([body[2], body[3]]) ^ 0x2112;
            return match family {
                0x01 if len >= 8 => {
                    let mut ip = [body[4], body[5], body[6], body[7]];
                    for (b, k) in ip.iter_mut().zip(COOKIE) {
                        *b ^= k;
                    }
                    Some(SocketAddr::V4(SocketAddrV4::new(ip.into(), xport)))
                },
                0x02 if len >= 20 => {
                    let mut ip = [0u8; 16];
                    for (j, b) in ip.iter_mut().enumerate() {
                        let key = if j < 4 {
                            COOKIE[j]
                        } else {
                            txid[j - 4]
                        };
                        *b = body[4 + j] ^ key;
                    }
                    Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                        ip.into(),
                        xport,
                        0,
                        0,
                    )))
                },
                _ => None,
            };
        }
        i += 4 + len.div_ceil(4) * 4;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_layout_follows_the_header_format() {
        let txid = [7u8; 12];
        let req = binding_request(&txid);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(&req[4..8], &COOKIE);
        assert_eq!(&req[8..], &txid);
    }

    #[test]
    fn response_parser_reads_xor_mapped_v4() {
        let txid = [1u8; 12];
        let ip: Ipv4Addr = [203, 0, 113, 9].into();
        let port: u16 = 34567;
        let mut attr = vec![0x00, 0x01];
        attr.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
        let xip: Vec<u8> = ip.octets().iter().zip(COOKIE).map(|(b, k)| b ^ k).collect();
        attr.extend_from_slice(&xip);

        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        // Four attribute header bytes plus the eight-byte body.
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&COOKIE);
        resp.extend_from_slice(&txid);
        resp.extend_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
        resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        resp.extend_from_slice(&attr);

        let parsed = parse_mapped(&resp, &txid).unwrap();
        assert_eq!(parsed, SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }

    #[test]
    fn mismatched_transaction_ids_are_rejected() {
        let resp = binding_request(&[0u8; 12]);
        assert!(parse_mapped(&resp, &[9u8; 12]).is_none());
    }

    /// A binding response that reports `port` for the transaction `txid`.
    fn binding_response(txid: &[u8; 12], port: u16) -> Vec<u8> {
        let ip: Ipv4Addr = [203, 0, 113, 7].into();
        let mut attr = vec![0x00, 0x01];
        attr.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
        let xip: Vec<u8> = ip.octets().iter().zip(COOKIE).map(|(b, k)| b ^ k).collect();
        attr.extend_from_slice(&xip);

        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        // Four attribute header bytes plus the eight-byte body.
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&COOKIE);
        resp.extend_from_slice(txid);
        resp.extend_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
        resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        resp.extend_from_slice(&attr);
        resp
    }

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
    fn attributes_past_the_declared_length_are_ignored() {
        let txid = [3u8; 12];
        let mapped = binding_response(&txid, 5010);
        // The message length declares one four-byte attribute only; the
        // XOR-MAPPED bytes appended after it belong to no attribute.
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&COOKIE);
        resp.extend_from_slice(&txid);
        resp.extend_from_slice(&0x8028u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&mapped[20..]);
        assert!(parse_mapped(&resp, &txid).is_none());
    }

    #[test]
    fn leading_server_attributes_still_parse() {
        // A server that prepends a padded 200-byte attribute keeps
        // XOR-MAPPED well past a minimal response.
        let txid = [4u8; 12];
        let mapped = binding_response(&txid, 5010);
        let mut resp = Vec::with_capacity(256);
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&COOKIE);
        resp.extend_from_slice(&txid);
        resp.extend_from_slice(&0x8028u16.to_be_bytes());
        resp.extend_from_slice(&200u16.to_be_bytes());
        resp.resize(resp.len() + 200, 0);
        resp.extend_from_slice(&mapped[20..]);
        let msg_len = (resp.len() - 20) as u16;
        resp[2..4].copy_from_slice(&msg_len.to_be_bytes());
        let parsed = parse_mapped(&resp, &txid).expect("trailing attribute parses");
        assert_eq!(parsed.port(), 5010);
    }
}
