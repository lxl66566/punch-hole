#![allow(clippy::field_reassign_with_default)]

//! Real-socket smoke tests on loopback.
//!
//! These validate the platform socket path, above all the Windows binding
//! rule, which the simulator cannot cover.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use punch_hole::{
    PunchConfig, Punched, Puncher,
    socket::{TokioFactory, UdpFactory},
};

const COOKIE: [u8; 4] = 0x2112_a442u32.to_be_bytes();

/// A loopback STUN endpoint that answers the library's binding requests.
struct LocalStun {
    addrs: Vec<String>,
}

async fn local_stun() -> std::io::Result<LocalStun> {
    Ok(LocalStun {
        addrs: stun_endpoints(IpAddr::from([127, 0, 0, 1]), 4).await?,
    })
}

/// Binds `count` STUN endpoints on one loopback address and serves them.
async fn stun_endpoints(ip: IpAddr, count: usize) -> std::io::Result<Vec<String>> {
    let mut addrs = Vec::new();
    for _ in 0..count {
        let sock = TokioFactory.bind(SocketAddr::new(ip, 0)).await?;
        let addr = sock.local_addr()?;
        addrs.push(addr.to_string());
        tokio::spawn(async move {
            let mut buf = [0u8; 128];
            loop {
                let Ok((len, from)) = sock.recv_from(&mut buf).await else {
                    break
                };
                let Some(reply) = binding_reply(&buf[..len], from) else {
                    continue
                };
                let _ = sock.send_to(&reply, from).await;
            }
        });
    }
    Ok(addrs)
}

/// Minimal binding response that echoes the request's transaction id and
/// maps the requester's address on either family.
fn binding_reply(request: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    if request.len() < 20
        || u16::from_be_bytes([request[0], request[1]]) != 0x0001
        || request[4..8] != COOKIE
    {
        return None;
    }
    // The XOR mask is the cookie for IPv4 and cookie plus transaction id
    // for IPv6, which is what the prober's parser expects.
    let (family, xaddr): (u8, Vec<u8>) = match from.ip() {
        IpAddr::V4(ip) => (
            0x01,
            ip.octets().iter().zip(COOKIE).map(|(b, k)| b ^ k).collect(),
        ),
        IpAddr::V6(ip) => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&COOKIE);
            mask[4..].copy_from_slice(&request[8..20]);
            (
                0x02,
                ip.octets().iter().zip(mask).map(|(b, k)| b ^ k).collect(),
            )
        },
    };
    let attr_len: u16 = if family == 0x01 {
        8
    } else {
        20
    };
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&0x0101u16.to_be_bytes());
    out.extend_from_slice(&attr_len.to_be_bytes());
    out.extend_from_slice(&COOKIE);
    out.extend_from_slice(&request[8..20]);
    out.extend_from_slice(&0x0020u16.to_be_bytes());
    out.extend_from_slice(&attr_len.to_be_bytes());
    out.push(0);
    out.push(family);
    out.extend_from_slice(&(from.port() ^ 0x2112).to_be_bytes());
    out.extend_from_slice(&xaddr);
    Some(out)
}

/// Forwards frames between the two host ends, standing in for the host
/// transport.
fn connect(a: punch_hole::signaling::HostEnd, b: punch_hole::signaling::HostEnd) {
    let mut a_to_b = a.to_peer;
    let b_from_a = b.from_peer;
    tokio::spawn(async move {
        while let Some(frame) = a_to_b.recv().await {
            let _ = b_from_a.send(frame).await;
        }
    });
    let mut b_to_a = b.to_peer;
    let a_from_b = a.from_peer;
    tokio::spawn(async move {
        while let Some(frame) = b_to_a.recv().await {
            let _ = a_from_b.send(frame).await;
        }
    });
}

fn loopback_config(stun: &LocalStun) -> PunchConfig {
    let mut cfg = PunchConfig::default();
    cfg.stun_servers = stun.addrs.clone();
    cfg.ipv6 = false;
    cfg.overall_deadline = Duration::from_secs(20);
    cfg
}

/// Reads until a business datagram arrives. Around handover the peer's
/// handshake retries may still land in the winner socket, so protocol
/// packets are skipped instead of failing the exchange.
async fn recv_business(sock: &tokio::net::UdpSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
    loop {
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(buf))
            .await
            .expect("business datagram within 2s")
            .expect("socket alive");
        if buf[0] != punch_hole::msg::DATA_MAGIC {
            return (n, from);
        }
    }
}

async fn punch_loopback() -> (Punched, Punched) {
    let stun = local_stun().await.expect("local stun binds");
    let cfg = loopback_config(&stun);
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    connect(ha, hb);
    let cfg_b = cfg.clone();
    let a = tokio::spawn(async move { Puncher::new(cfg)?.with_signaling(la).initiator().await });
    let b = tokio::spawn(async move { Puncher::new(cfg_b)?.with_signaling(lb).responder().await });
    (
        a.await.expect("initiator task").expect("loopback punch"),
        b.await.expect("responder task").expect("loopback punch"),
    )
}

#[tokio::test]
async fn loopback_punch_exchanges_business_bytes() {
    let (pa, pb) = punch_loopback().await;
    assert!(pa.peer_addr.ip().is_loopback());
    assert!(pb.peer_addr.ip().is_loopback());
    assert_eq!(pa.report.local_class, punch_hole::NatClass::Public);
    assert_eq!(pa.report.nonce, pb.report.nonce);

    let mut buf = [0u8; 64];
    pa.socket
        .send_to(b"PING", pa.peer_addr)
        .await
        .expect("ping");
    let (n, from) = recv_business(&pb.socket, &mut buf).await;
    assert_eq!(&buf[..n], b"PING");
    assert_eq!(from.ip(), pb.peer_addr.ip());
    pb.socket.send_to(b"PONG", from).await.expect("pong");
    let (n, _) = recv_business(&pa.socket, &mut buf).await;
    assert_eq!(&buf[..n], b"PONG");
}

#[tokio::test]
async fn assistant_sockets_bind_distinct_ports() {
    // Guards the Windows rule: no SO_REUSEADDR on punch sockets, because it
    // allows two sockets on one port with undefined delivery.
    let mut ports = HashSet::new();
    for _ in 0..8 {
        let sock = TokioFactory
            .bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
            .expect("bind");
        ports.insert(sock.local_addr().expect("local addr").port());
    }
    assert_eq!(ports.len(), 8, "every socket received its own port");
}

#[tokio::test]
async fn winner_socket_outlives_the_session() {
    let (pa, pb) = punch_loopback().await;
    // The result values go away; only the sockets stay.
    let target = pa.peer_addr;
    let Punched { socket, .. } = pa;
    let peer = pb.socket;

    socket
        .send_to(b"STILL ALIVE", target)
        .await
        .expect("winner still sends");
    let mut buf = [0u8; 64];
    let (n, _) = recv_business(&peer, &mut buf).await;
    assert_eq!(&buf[..n], b"STILL ALIVE");
}

#[tokio::test]
async fn keepalive_beats_and_stops_with_guard() {
    let (pa, pb) = punch_loopback().await;
    let nonce = pa.report.nonce;
    let sender = Arc::new(pa.socket);
    // The heartbeat travels from the sender to its peer's socket.
    let target = pa.peer_addr;
    let receiver = pb.socket;

    let guard = punch_hole::keepalive::spawn_with_interval(
        Arc::clone(&sender),
        target,
        nonce,
        Duration::from_millis(40),
    );

    let mut buf = [0u8; 64];
    let mut beats = 0;
    for _ in 0..12 {
        match tokio::time::timeout(Duration::from_millis(120), receiver.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                assert_eq!(buf[0], punch_hole::msg::DATA_MAGIC);
                assert!(n <= punch_hole::msg::MAX_DATA_PACKET);
                beats += 1;
            },
            _ => break,
        }
    }
    assert!(beats >= 3, "counted {beats} heartbeats");

    drop(guard);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), receiver.recv_from(&mut buf))
            .await
            .is_err(),
        "the heartbeat stopped with the guard"
    );
}

/// A full session whose Direct stage runs over IPv6.
///
/// The prober records any IPv6 reflexive address, so `::1` stands in for a
/// global one and the whole path runs on loopback: v6 probe, v6 PortUpdate,
/// v6 handshake, and a v6 winner socket. Routing and firewall behavior with
/// real global addresses stay untested here.
#[tokio::test]
async fn direct_v6_session_runs_on_loopback() {
    let v6 = match stun_endpoints(IpAddr::from(Ipv6Addr::LOCALHOST), 2).await {
        Ok(v6) => v6,
        Err(e) => {
            eprintln!("skipped, no IPv6 loopback available: {e}");
            return;
        },
    };
    let stun = local_stun().await.expect("local stun binds");
    let mut cfg = loopback_config(&stun);
    cfg.ipv6 = true;
    cfg.stun_servers.extend(v6);
    // Real time drives this test; the margin keeps the window from closing
    // before the PortUpdate pair crosses.
    cfg.direct_window = Duration::from_secs(2);

    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    connect(ha, hb);
    let cfg_b = cfg.clone();
    let a = tokio::spawn(async move { Puncher::new(cfg)?.with_signaling(la).initiator().await });
    let b = tokio::spawn(async move { Puncher::new(cfg_b)?.with_signaling(lb).responder().await });
    let pa = a.await.expect("initiator task").expect("v6 punch");
    let pb = b.await.expect("responder task").expect("v6 punch");

    // A v6 peer address can only come from the Direct stage, because the
    // matrix strategies bind IPv4 only.
    assert!(pa.peer_addr.is_ipv6(), "got {}", pa.peer_addr);
    assert!(pb.peer_addr.is_ipv6(), "got {}", pb.peer_addr);
    assert_eq!(pa.report.local_class, punch_hole::NatClass::Public);

    let mut buf = [0u8; 64];
    pa.socket
        .send_to(b"VPING", pa.peer_addr)
        .await
        .expect("v6 ping");
    let (n, from) = recv_business(&pb.socket, &mut buf).await;
    assert_eq!(&buf[..n], b"VPING");
    pb.socket.send_to(b"VPONG", from).await.expect("v6 pong");
    let (n, _) = recv_business(&pa.socket, &mut buf).await;
    assert_eq!(&buf[..n], b"VPONG");
}
