//! STUN binding prober.
//!
//! The wire subset is one binding request and one response, written in-tree
//! per the architecture notes. The prober queries several distinct
//! destinations from one socket, which yields the allocation sequence that
//! classification fits.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use crate::{
    config::PunchConfig,
    error::PunchError,
    msg::{MAX_ALLOC_SEQ, MAX_V6_ADDRS},
    nat::{FilterClass, NatInfo, V4Nat, V6Nat, classify},
    socket::{Family, UdpFactory},
};

const COOKIE: [u8; 4] = 0x2112_a442u32.to_be_bytes();
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_XOR_MAPPED: u16 = 0x0020;

/// Runs the Probe phase and returns the evidence it collected.
pub(crate) async fn probe<F: UdpFactory>(
    cfg: &PunchConfig,
    factory: &F,
) -> Result<NatInfo, PunchError> {
    let v4_servers = resolve(cfg, false).await;
    if v4_servers.is_empty() {
        return Err(PunchError::Io(io::Error::other(
            "no STUN server resolved to an IPv4 address",
        )));
    }
    let socket = factory.bind(Family::V4.any_addr()).await?;

    // One answer per distinct destination, in send order.
    let per_server =
        (cfg.probe_timeout / v4_servers.len().max(1) as u32).max(Duration::from_millis(1));
    let mut reflexives = Vec::with_capacity(v4_servers.len());
    for server in &v4_servers {
        if let Some(addr) = stun_query(&socket, *server, per_server).await {
            reflexives.push(addr);
        }
    }
    if reflexives.is_empty() {
        return Err(PunchError::Timeout {
            phase: crate::error::Phase::Probe,
        });
    }

    let ports: Vec<u16> = reflexives.iter().map(SocketAddr::port).collect();
    let public = is_public(&socket, v4_servers[0], &reflexives[0]);

    // A second socket to the first destination confirms socket independence:
    // one shared external port for two local sockets outranks the sequence.
    let class = match factory.bind(Family::V4.any_addr()).await {
        Ok(second) => {
            let same = stun_query(&second, v4_servers[0], per_server)
                .await
                .is_some_and(|a| a.port() == ports[0]);
            let mut class = classify::classify(public, &ports);
            if same
                && matches!(
                    class,
                    crate::nat::NatClass::EasySym { .. } | crate::nat::NatClass::HardSym
                )
            {
                class = crate::nat::NatClass::Cone;
            }
            class
        },
        Err(_) => classify::classify(public, &ports),
    };

    let filtering = if class == crate::nat::NatClass::Cone && reflexives.len() >= 2 {
        // Multiple destinations answered through one port: the mapping is
        // endpoint independent, and precise filtering needs a third-party
        // echo the prober does not have.
        FilterClass::EndpointIndependent
    } else {
        FilterClass::Unknown
    };

    let v4 = V4Nat {
        class,
        reflexive: SocketAddrV4::new(
            match reflexives[0].ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            },
            ports[0],
        ),
        alloc_seq: ports.into_iter().take(MAX_ALLOC_SEQ).collect(),
        filtering,
    };

    let v6 = if cfg.ipv6 {
        probe_v6(cfg, factory, &v4_servers).await
    } else {
        None
    };

    Ok(NatInfo { v4: Some(v4), v6 })
}

/// Collects global IPv6 reflexive addresses when a server and a route exist.
async fn probe_v6<F: UdpFactory>(
    cfg: &PunchConfig,
    factory: &F,
    v4_servers: &[SocketAddr],
) -> Option<V6Nat> {
    let servers = resolve(cfg, true).await;
    if servers.is_empty() {
        return None;
    }
    let socket = factory.bind(Family::V6.any_addr()).await.ok()?;
    let per_server = (cfg.probe_timeout / (servers.len() + v4_servers.len()).max(1) as u32)
        .max(Duration::from_millis(1));
    let mut addrs = Vec::with_capacity(MAX_V6_ADDRS);
    for server in servers {
        if let Some(addr) = stun_query(&socket, server, per_server).await {
            if addrs.len() < MAX_V6_ADDRS {
                addrs.push(match addr {
                    SocketAddr::V6(a) => a,
                    SocketAddr::V4(_) => continue,
                });
            }
        }
    }
    (!addrs.is_empty()).then_some(V6Nat { addrs })
}

/// A socket is public when its reflexive address is its own address.
///
/// Sockets bound to the wildcard report `0.0.0.0`, so the interface address
/// toward the server stands in for the local one.
fn is_public<S: crate::socket::UdpIo>(
    socket: &S,
    server: SocketAddr,
    reflexive: &SocketAddr,
) -> bool {
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
async fn resolve(cfg: &PunchConfig, want_v6: bool) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for server in &cfg.stun_servers {
        let Ok(list) = tokio::net::lookup_host(server).await else {
            continue
        };
        for addr in list {
            if addr.is_ipv6() == want_v6 {
                out.push(addr);
                break;
            }
        }
    }
    out
}

/// Sends one binding request per timeout slice until a matching answer.
///
/// Shared with the punch engine, which re-queries a punch socket to learn
/// its fresh external port for a `PortUpdate`.
pub(crate) async fn stun_query<S: crate::socket::UdpIo>(
    socket: &S,
    server: SocketAddr,
    timeout: Duration,
) -> Option<SocketAddr> {
    let txid: [u8; 12] = rand::random();
    let request = binding_request(&txid);
    for _ in 0..2 {
        socket.send_to(&request, server).await.ok()?;
        let mut buf = [0u8; 128];
        if let Ok(Ok((len, _))) = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
            if let Some(addr) = parse_mapped(&buf[..len], &txid) {
                return Some(addr);
            }
        }
    }
    None
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
    let mut i = 20;
    while i + 4 <= buf.len() {
        let attr = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let body = buf.get(i + 4..i + 4 + len)?;
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
        resp.extend_from_slice(&8u16.to_be_bytes());
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
}
