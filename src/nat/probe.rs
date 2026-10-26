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
};

use tokio::time::Instant;

use crate::{
    config::PunchConfig,
    error::{Phase, PunchError},
    msg::{MAX_ALLOC_SEQ, MAX_PUB_IPS, MAX_V6_ADDRS},
    nat::{FilterClass, NatInfo, V4Nat, V6Nat, classify},
    socket::{Family, UdpFactory, UdpIo},
};

const COOKIE: [u8; 4] = 0x2112_a442u32.to_be_bytes();
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_XOR_MAPPED: u16 = 0x0020;

/// Runs the Probe phase and returns the evidence it collected.
///
/// Both address families fit inside `cfg.probe_timeout`.
pub(crate) async fn probe<F: UdpFactory>(
    cfg: &PunchConfig,
    factory: &F,
) -> Result<NatInfo, PunchError> {
    let start = Instant::now();
    let deadline = start + cfg.probe_timeout;

    let v4_dests = resolve(cfg, false).await;
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
    round.collect(&socket, start + cfg.probe_timeout / 2).await;
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
        pub_ips: collect_pub_ips(&round.slots),
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
    let servers = resolve(cfg, true).await;
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
/// Slot `i` holds the answer of `dests[i]`. The slot index is the send
/// index: queries go out in index order, so a symmetric NAT allocates the
/// ports in index order and the slots record the allocation sequence.
struct Fanout {
    dests: Vec<SocketAddr>,
    /// One transaction id per destination, kept stable across retry rounds,
    /// so a late answer to an earlier round still matches its slot.
    txids: Vec<[u8; 12]>,
    slots: Vec<Option<SocketAddr>>,
}

impl Fanout {
    fn new(dests: Vec<SocketAddr>) -> Self {
        let slots = vec![None; dests.len()];
        let txids = dests.iter().map(|_| rand::random()).collect();
        Self {
            dests,
            txids,
            slots,
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
    /// A retry targets the same destination from the same socket, so the NAT
    /// reuses the mapping of the first send. Retries allocate nothing new,
    /// and the send indexes stay allocation indexes.
    async fn send_pending<S: UdpIo>(&self, socket: &S) {
        for ((slot, dst), txid) in self.slots.iter().zip(&self.dests).zip(&self.txids) {
            if slot.is_some() {
                continue;
            }
            let request = binding_request(txid);
            // A failed send leaves a hole the fit treats as an unknown port.
            let _ = socket.send_to(&request, *dst).await;
        }
    }

    /// Collects answers until no destination pends or `until` passes.
    async fn collect<S: UdpIo>(&mut self, socket: &S, until: Instant) {
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
            if slot.is_none() && from == self.dests[idx] {
                if let Some(addr) = parse_mapped(buf, txid) {
                    *slot = Some(addr);
                    break;
                }
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

    /// The `(send index, port)` pairs classification fits. A missing index
    /// marks an allocation whose port no server reported.
    fn observed(&self) -> Vec<(usize, u16)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(idx, slot)| slot.map(|addr| (idx, addr.port())))
            .collect()
    }
}

/// Collects the distinct public IPv4 addresses of the answers, in send
/// order, capped at `MAX_PUB_IPS`.
///
/// The first answered sample leads, so the first entry is the address the
/// reflexive field reports.
fn collect_pub_ips(slots: &[Option<SocketAddr>]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for addr in slots.iter().flatten() {
        if let IpAddr::V4(ip) = addr.ip()
            && !out.contains(&ip)
        {
            out.push(ip);
            if out.len() == MAX_PUB_IPS {
                break;
            }
        }
    }
    out
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
/// mapping.
async fn resolve(cfg: &PunchConfig, want_v6: bool) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for server in &cfg.stun_servers {
        let Ok(list) = tokio::net::lookup_host(server).await else {
            continue
        };
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

    #[test]
    fn duplicate_and_foreign_answers_are_dropped() {
        let dest = vec![SocketAddr::V4(SocketAddrV4::new([1, 1, 1, 1].into(), 3478))];
        let mut round = Fanout::new(dest);
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

    #[test]
    fn public_ips_stay_distinct_in_send_order() {
        let answer =
            |ip: [u8; 4], port: u16| Some(SocketAddr::V4(SocketAddrV4::new(ip.into(), port)));
        // A multi-homed path answers through several NATs; one slot stays
        // silent and one address repeats.
        let slots = vec![
            answer([203, 0, 113, 7], 5000),
            None,
            answer([198, 51, 100, 4], 5001),
            answer([203, 0, 113, 7], 5002),
            answer([192, 0, 2, 9], 5003),
            answer([198, 18, 0, 2], 5004),
            answer([203, 0, 113, 99], 5005),
        ];
        // Distinct addresses in send order, capped at MAX_PUB_IPS, first
        // entry from the first answered slot.
        assert_eq!(collect_pub_ips(&slots), vec![
            Ipv4Addr::new(203, 0, 113, 7),
            Ipv4Addr::new(198, 51, 100, 4),
            Ipv4Addr::new(192, 0, 2, 9),
            Ipv4Addr::new(198, 18, 0, 2),
        ]);
        // An all-silent fan-out reports no addresses.
        assert_eq!(collect_pub_ips(&[None]), Vec::<Ipv4Addr>::new());
    }
}
