#![allow(clippy::field_reassign_with_default)]

//! Real-socket smoke tests on loopback.
//!
//! These validate the platform socket path, above all the Windows binding
//! rule, which the simulator cannot cover.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
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
    let mut addrs = Vec::new();
    for _ in 0..4 {
        let sock = TokioFactory
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await?;
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
    Ok(LocalStun { addrs })
}

/// Minimal binding response that echoes the request's transaction id and
/// maps the requester's address.
fn binding_reply(request: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    if request.len() < 20
        || u16::from_be_bytes([request[0], request[1]]) != 0x0001
        || request[4..8] != COOKIE
    {
        return None;
    }
    let ip = match from.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return None,
    };
    let port = from.port() ^ 0x2112;
    let xip: Vec<u8> = ip.octets().iter().zip(COOKIE).map(|(b, k)| b ^ k).collect();
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&0x0101u16.to_be_bytes());
    out.extend_from_slice(&12u16.to_be_bytes());
    out.extend_from_slice(&COOKIE);
    out.extend_from_slice(&request[8..20]);
    out.extend_from_slice(&0x0020u16.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.push(0);
    out.push(0x01);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&xip);
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
