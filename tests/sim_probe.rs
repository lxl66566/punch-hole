#![allow(clippy::field_reassign_with_default)]

//! NAT classification cases against the simulator.

mod common;

use std::net::SocketAddrV4;

use common::config;
use punch_hole::{
    StrategyId,
    error::PunchError,
    nat::{NatClass, NatInfo, V4Nat},
    sim::{Mapping, NatSpec, Net},
};

#[tokio::test(start_paused = true)]
async fn cone_detected() {
    let (_net, stun, a, b) = common::cone_net("cone_detected");
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("cone pair punches");
    let pb = rb.expect("cone pair punches");
    assert_eq!(pa.report.local_class, NatClass::Cone);
    assert_eq!(pb.report.local_class, NatClass::Cone);
}

#[tokio::test(start_paused = true)]
async fn easy_step_detected() {
    let net = Net::seeded("easy_step_detected");
    let stun = net.stun_server();
    let a = net.host(NatSpec::sequential(1));
    let b = net.host(NatSpec::sequential(1));
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("easy pair punches");
    let _ = rb.expect("easy pair punches");
    assert_eq!(pa.report.local_class, NatClass::EasySym { step: 1 });
    assert_eq!(pa.report.strategy, StrategyId::PredictiveExchange);
}

#[tokio::test(start_paused = true)]
async fn hard_detected() {
    let net = Net::seeded("hard_detected");
    let stun = net.stun_server();
    let a = net.host(NatSpec::random(30000..31000));
    let b = net.host(NatSpec::random(30000..31000));
    let (ra, _) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("birthday pair punches");
    assert_eq!(pa.report.local_class, NatClass::HardSym);
    assert_eq!(pa.report.strategy, StrategyId::BirthdayBurst);
}

#[tokio::test(start_paused = true)]
async fn public_detected() {
    let net = Net::seeded("public_detected");
    let stun = net.stun_server();
    let a = net.public_host();
    let b = net.public_host();
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("public pair punches");
    let pb = rb.expect("public pair punches");
    assert_eq!(pa.report.local_class, NatClass::Public);
    assert_eq!(pb.report.local_class, NatClass::Public);
}

#[tokio::test(start_paused = true)]
async fn stun_timeout_is_bounded() {
    let net = Net::seeded("stun_timeout");
    // No STUN server on this address; the router drops the queries.
    let mut cfg = punch_hole::PunchConfig::default();
    cfg.stun_servers = vec!["9.9.9.9:3478".to_owned()];
    let host = net.host(NatSpec::cone_eif());
    let (_, lib) = punch_hole::signaling::bridge(8);

    let t = tokio::time::Instant::now();
    let err = common::run_initiator(host, cfg, lib).await.unwrap_err();
    assert!(
        matches!(err, PunchError::Timeout {
            phase: punch_hole::Phase::Probe
        }),
        "got {err:?}"
    );
    // Two transact attempts per server against the probe timeout slice.
    assert!(t.elapsed() < std::time::Duration::from_secs(30));
}

#[tokio::test(start_paused = true)]
async fn cached_nat_info_skips_probe() {
    let (net, stun, a, b) = common::cone_net("cached_nat");
    // The first host attached sits behind 100.64.2.1. A cache from an
    // earlier session holds the right NAT but the dead port of a closed
    // probe socket; the PortUpdate exchange replaces the port.
    let cached = NatInfo {
        v4: Some(V4Nat {
            class: NatClass::Cone,
            reflexive: SocketAddrV4::new([100, 64, 2, 1].into(), 40000),
            alloc_seq: vec![40000, 40000, 40000, 40000],
            filtering: punch_hole::FilterClass::Unknown,
        }),
        v6: None,
    };
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    punch_hole::sim::connect(ha, hb);
    let session = punch_hole::Puncher::with_factory(config(&stun), a)
        .expect("config valid")
        .with_cached_nat(cached)
        .with_signaling(la);
    let a = tokio::spawn(session.initiator());
    let b = tokio::spawn(common::run_responder(b, config(&stun), lb));
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    let pa = ra.expect("cached session punches");
    rb.expect("cached session punches");
    assert_eq!(pa.report.phase_ms.probe_ms, 0, "Probe was skipped");
    let _ = net.mapping_count();
    let _ = Mapping::Cone;
}
