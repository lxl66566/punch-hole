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
    error::PunchError,
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
        punch_timeout: Duration::from_secs(8),
        overall_deadline: Duration::from_secs(15),
        ..PunchConfig::default()
    }
}

/// Config for the probabilistic strategies, which retry on a fresh lab
/// pair when the model's residual misses.
///
/// The punch loop resolves within a few hundred milliseconds on loopback,
/// so a short punch budget turns a miss into a fast failure. A retry then
/// draws a fresh nonce instead of waiting out a long deadline.
fn retried_config(stun: &StunServer) -> PunchConfig {
    PunchConfig {
        punch_timeout: Duration::from_secs(3),
        overall_deadline: Duration::from_secs(12),
        ..lab_config(stun)
    }
}

/// Runs one initiator and one responder against each other over the
/// bridge, returning both results.
async fn try_punch_pair(
    host_a: LabHost,
    cfg_a: PunchConfig,
    host_b: LabHost,
    cfg_b: PunchConfig,
) -> (
    Result<Punched<LabSocket>, PunchError>,
    Result<Punched<LabSocket>, PunchError>,
) {
    let (ha, la) = signaling::bridge(64);
    let (hb, lb) = signaling::bridge(64);
    sim::connect(ha, hb);
    let a = tokio::spawn(async move {
        Puncher::with_factory(cfg_a, host_a)
            .expect("config valid")
            .with_signaling(la)
            .initiator()
            .await
    });
    let b = tokio::spawn(async move {
        Puncher::with_factory(cfg_b, host_b)
            .expect("config valid")
            .with_signaling(lb)
            .responder()
            .await
    });
    (
        a.await.expect("initiator task"),
        b.await.expect("responder task"),
    )
}

/// Runs one initiator and one responder against each other over the
/// bridge, expecting both sides to punch.
async fn punch_pair(
    host_a: LabHost,
    cfg_a: PunchConfig,
    host_b: LabHost,
    cfg_b: PunchConfig,
) -> (Punched<LabSocket>, Punched<LabSocket>) {
    let (ra, rb) = try_punch_pair(host_a, cfg_a, host_b, cfg_b).await;
    (ra.expect("lab punch"), rb.expect("lab punch"))
}

/// Runs the pair on a fresh lab pair per try until both sides punch, and
/// returns the last results together with the labs that produced them.
///
/// A spray covers a fixed port set drawn from the attempt nonce, and every
/// sweep repeats that set, so the residual miss the model leaves below a
/// perfect target can only end the run in failure. A fresh session draws a
/// fresh nonce, so a few retries push the residual far below any single
/// target while each run keeps its full assertion. The STUN responder
/// stays across tries, because it answers statelessly.
async fn punch_pair_retried(
    seed: &str,
    spec_a: NatSpec,
    spec_b: NatSpec,
    cfg: PunchConfig,
    tries: usize,
) -> (
    (
        Result<Punched<LabSocket>, PunchError>,
        Result<Punched<LabSocket>, PunchError>,
    ),
    NatLab,
    NatLab,
) {
    let mut last = None;
    for _ in 0..tries {
        let nat_a = NatLab::spawn(&format!("{seed}_a"), spec_a.clone())
            .await
            .expect("lab a spawns");
        let nat_b = NatLab::spawn(&format!("{seed}_b"), spec_b.clone())
            .await
            .expect("lab b spawns");
        let pair = try_punch_pair(nat_a.host(), cfg.clone(), nat_b.host(), cfg.clone()).await;
        if pair.0.is_ok() && pair.1.is_ok() {
            return (pair, nat_a, nat_b);
        }
        last = Some((pair, nat_a, nat_b));
    }
    last.expect("tries is nonzero")
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

/// Exchanges one business datagram each way over the winner sockets.
async fn assert_business(pa: &Punched<LabSocket>, pb: &Punched<LabSocket>) {
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
}

/// Waits until the lab holds exactly `want` mappings, bounded by two
/// seconds.
///
/// A completed send only queued the gateway's work, so a Bye from a closed
/// socket releases its mappings once the gateway task was polled.
async fn wait_mapping_count(lab: &NatLab, want: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while lab.mapping_count() != want && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
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
    assert_business(&pa, &pb).await;

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
    assert_business(&pa, &pb).await;
}

/// Two stepped symmetric NATs, steps 2 and 3, punch on port predictions.
///
/// The stepped allocations of the emulated NATs must survive the whole
/// real pipeline: STUN round trips, classification, prediction, and the
/// punch itself.
#[tokio::test]
async fn easy_sym_pair_punches_via_predictions_over_two_nat_labs() {
    let stun = natlab::stun_responder().expect("stun responder binds");
    let nat_a = NatLab::spawn("easy_pair_a", NatSpec::sequential(2))
        .await
        .expect("lab a spawns");
    let nat_b = NatLab::spawn("easy_pair_b", NatSpec::sequential(3))
        .await
        .expect("lab b spawns");
    let cfg = lab_config(&stun);
    let (pa, pb) = punch_pair(nat_a.host(), cfg.clone(), nat_b.host(), cfg).await;

    // The classifier read the stepped allocations through the real probe
    // path, which proves the emulated walk reached it intact.
    assert_eq!(pa.report.local_class, NatClass::EasySym { step: 2 });
    assert_eq!(pb.report.local_class, NatClass::EasySym { step: 3 });
    assert_eq!(pa.report.strategy, StrategyId::PredictiveExchange);
    assert_eq!(pb.report.strategy, StrategyId::PredictiveExchange);
    assert_business(&pa, &pb).await;
}

/// A hard symmetric initiator against a port-filtered cone responder:
/// the cone-side spray carries the exchange.
#[tokio::test]
async fn hard_sym_cone_apdf_punches_via_spray_over_two_nat_labs() {
    let stun = natlab::stun_responder().expect("stun responder binds");
    let cfg = PunchConfig {
        target_success: 0.99,
        ..retried_config(&stun)
    };
    let ((ra, rb), _nat_a, _nat_b) = punch_pair_retried(
        "hard_cone_labs",
        NatSpec::random(30000..30100),
        NatSpec::cone_apdf(),
        cfg,
        3,
    )
    .await;
    let pa = ra.expect("spray punches");
    let pb = rb.expect("spray punches");
    assert_eq!(pa.report.local_class, NatClass::HardSym);
    assert_eq!(pb.report.local_class, NatClass::Cone);
    assert_eq!(pa.report.strategy, StrategyId::SymProbe);
    assert_eq!(pb.report.strategy, StrategyId::SymProbe);
    // The spray model sizes for the 0.99 target, so both roles carry an
    // estimate at or above it; 0.98 keeps float noise out of the bar.
    assert!(pa.report.success_estimate.unwrap_or(0.0) > 0.98);
    assert_eq!(pb.report.success_estimate, pa.report.success_estimate);
    assert_business(&pa, &pb).await;
}

/// Two hard symmetric NATs over a narrow port range: the birthday attack
/// over real OS sockets.
#[tokio::test]
async fn hard_sym_pair_punches_via_birthday_burst_over_two_nat_labs() {
    let stun = natlab::stun_responder().expect("stun responder binds");
    let cfg = PunchConfig {
        target_success: 0.95,
        ..retried_config(&stun)
    };
    let ((ra, rb), _nat_a, _nat_b) = punch_pair_retried(
        "birthday_labs",
        NatSpec::random(30000..30100),
        NatSpec::random(30000..30100),
        cfg,
        3,
    )
    .await;
    let pa = ra.expect("birthday punches");
    let pb = rb.expect("birthday punches");
    assert_eq!(pa.report.strategy, StrategyId::BirthdayBurst);
    assert_eq!(pb.report.strategy, StrategyId::BirthdayBurst);
    assert_eq!(pa.report.local_class, NatClass::HardSym);
    assert_eq!(pb.report.local_class, NatClass::HardSym);
    // The sizing solves for the target, so the estimate lands at or
    // slightly above it.
    assert!(pa.report.success_estimate.unwrap_or(0.0) >= 0.95 - 1e-9);
    // The burst space is symmetric in the two views, so both roles rebuild
    // the same estimate.
    assert_eq!(pb.report.success_estimate, pa.report.success_estimate);
    assert_business(&pa, &pb).await;
}

/// A finished session keeps only the winner mappings alive, and dropping
/// the handed-over sockets releases the rest through the Bye path.
#[tokio::test]
async fn election_closes_losers_and_drop_drains_the_labs() {
    let stun = natlab::stun_responder().expect("stun responder binds");
    let cfg = PunchConfig {
        target_success: 0.99,
        ..retried_config(&stun)
    };
    // SymProbe binds sixteen shooter sockets on the symmetric side, so the
    // election has real losers to close.
    let ((ra, rb), nat_a, nat_b) = punch_pair_retried(
        "hygiene_labs",
        NatSpec::random(30000..30100),
        NatSpec::cone_apdf(),
        cfg,
        3,
    )
    .await;
    let pa = ra.expect("spray punches");
    let pb = rb.expect("spray punches");
    assert_eq!(pa.report.strategy, StrategyId::SymProbe);

    // The winner shooter keeps its single mapping; the fifteen losers went
    // with their sockets.
    wait_mapping_count(&nat_a, 1).await;
    assert_eq!(nat_a.mapping_count(), 1);
    assert!(
        nat_a.peak_mappings() > nat_a.mapping_count(),
        "the election closed the loser shooters"
    );
    // The cone side ran one punch socket, whose mapping the winner holds.
    wait_mapping_count(&nat_b, 1).await;
    assert_eq!(nat_b.mapping_count(), 1);

    // Dropping the handed-over sockets sends their Byes, and the labs end
    // with no mapping left.
    drop(pa);
    drop(pb);
    nat_a.wait_mappings_drained().await;
    nat_b.wait_mappings_drained().await;
    assert_eq!(nat_a.mapping_count(), 0);
    assert_eq!(nat_b.mapping_count(), 0);
}
