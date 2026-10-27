//! Real-socket punch sessions across the loopback NAT lab.
//!
//! Both peers sit behind a `NatLab`, so the production path runs unmodified
//! over real OS sockets: the probe queries a real STUN responder through
//! the translated address, classification reads the NAT's mapping behavior,
//! and the punch plus business traffic cross both forwarders. These tests
//! run on real time, because real sockets have no paused clock.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use punch_hole::{
    NatClass, PunchConfig, Punched, Puncher, StrategyId,
    msg::{DATA_MAGIC, MAX_DATA_PACKET},
    natlab::{self, LabHost, LabSocket, NatLab, StunServer},
    signaling,
    sim::{self, NatSpec},
    socket::UdpIo,
};

/// Config tuned for local sockets: short probe budget, bounded session.
fn lab_config(stun: &StunServer) -> PunchConfig {
    PunchConfig {
        stun_servers: stun.addrs.clone(),
        ipv6: false,
        probe_timeout: Duration::from_secs(2),
        overall_deadline: Duration::from_secs(20),
        ..PunchConfig::default()
    }
}

/// Runs one initiator and one responder against each other over the
/// bridge, expecting both sides to punch.
async fn punch_pair(
    host_a: LabHost,
    cfg_a: PunchConfig,
    host_b: LabHost,
    cfg_b: PunchConfig,
) -> (Punched<LabSocket>, Punched<LabSocket>) {
    let (ha, la) = signaling::bridge(64);
    let (hb, lb) = signaling::bridge(64);
    sim::connect(ha, hb);
    let a = tokio::spawn(async move {
        Puncher::with_factory(cfg_a, host_a)
            .expect("config valid")
            .with_signaling(la)
            .initiator()
            .await
            .expect("lab punch")
    });
    let b = tokio::spawn(async move {
        Puncher::with_factory(cfg_b, host_b)
            .expect("config valid")
            .with_signaling(lb)
            .responder()
            .await
            .expect("lab punch")
    });
    (
        a.await.expect("initiator task"),
        b.await.expect("responder task"),
    )
}

/// Reads until a business datagram arrives, skipping handshake retries.
async fn recv_business(sock: &LabSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
    loop {
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(buf))
            .await
            .expect("business datagram within 2s")
            .expect("socket alive");
        if buf[0] != DATA_MAGIC {
            return (n, from);
        }
    }
}

/// Two cone NATs with port-strict filtering, the standard happy path.
#[tokio::test]
async fn cone_pair_punches_through_two_nat_labs() {
    let stun = natlab::stun_responder().expect("stun responder binds");
    let nat_a = NatLab::spawn("cone_pair_a", NatSpec::cone_apdf())
        .await
        .expect("lab a spawns");
    let nat_b = NatLab::spawn("cone_pair_b", NatSpec::cone_apdf())
        .await
        .expect("lab b spawns");
    let cfg = lab_config(&stun);
    let (pa, pb) = punch_pair(nat_a.host(), cfg.clone(), nat_b.host(), cfg).await;

    // Cone against cone selects the reflexive-address exchange.
    assert_eq!(pa.report.strategy, StrategyId::ConeExchange);
    assert_eq!(pb.report.strategy, StrategyId::ConeExchange);
    // Public would mean the probe saw no translation, so the lab failed.
    assert_eq!(pa.report.local_class, NatClass::Cone);
    assert_eq!(pb.report.local_class, NatClass::Cone);
    assert_eq!(pa.report.nonce, pb.report.nonce);

    // Each side aims at the other NAT's public address.
    assert_eq!(pa.peer_addr.ip(), IpAddr::from(nat_b.public_ip()));
    assert_eq!(pb.peer_addr.ip(), IpAddr::from(nat_a.public_ip()));

    // Business traffic crosses both NATs in both directions.
    let mut buf = [0u8; MAX_DATA_PACKET];
    pa.socket
        .send_to(b"PING", pa.peer_addr)
        .await
        .expect("ping send");
    let (n, from) = recv_business(&pb.socket, &mut buf).await;
    assert_eq!(&buf[..n], b"PING");
    // The responder sees the initiator's translated address.
    assert_eq!(from.ip(), pb.peer_addr.ip());
    pb.socket.send_to(b"PONG", from).await.expect("pong send");
    let (n, from) = recv_business(&pa.socket, &mut buf).await;
    assert_eq!(&buf[..n], b"PONG");
    // The initiator sees the responder's translated address.
    assert_eq!(from.ip(), pa.peer_addr.ip());

    assert!(nat_a.forwarded() > 0, "the initiator's lab forwarded");
    assert!(nat_b.forwarded() > 0, "the responder's lab forwarded");
}

/// Two cone NATs with endpoint-independent filtering, the loosest cones.
#[tokio::test]
async fn cone_eif_pair_punches_through_two_nat_labs() {
    let stun = natlab::stun_responder().expect("stun responder binds");
    let nat_a = NatLab::spawn("cone_eif_a", NatSpec::cone_eif())
        .await
        .expect("lab a spawns");
    let nat_b = NatLab::spawn("cone_eif_b", NatSpec::cone_eif())
        .await
        .expect("lab b spawns");
    let cfg = lab_config(&stun);
    let (pa, pb) = punch_pair(nat_a.host(), cfg.clone(), nat_b.host(), cfg).await;

    assert_eq!(pa.report.strategy, StrategyId::ConeExchange);
    assert_eq!(pa.report.local_class, NatClass::Cone);
    assert_eq!(pb.report.local_class, NatClass::Cone);
    assert_eq!(pa.report.nonce, pb.report.nonce);
    assert_eq!(pa.peer_addr.ip(), IpAddr::from(nat_b.public_ip()));
    assert_eq!(pb.peer_addr.ip(), IpAddr::from(nat_a.public_ip()));

    let mut buf = [0u8; MAX_DATA_PACKET];
    pa.socket
        .send_to(b"PING", pa.peer_addr)
        .await
        .expect("ping send");
    let (n, from) = recv_business(&pb.socket, &mut buf).await;
    assert_eq!(&buf[..n], b"PING");
    pb.socket.send_to(b"PONG", from).await.expect("pong send");
    let (n, _) = recv_business(&pa.socket, &mut buf).await;
    assert_eq!(&buf[..n], b"PONG");
}
