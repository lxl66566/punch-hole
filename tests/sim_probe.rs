#![allow(clippy::field_reassign_with_default)]

//! NAT classification cases against the simulator.

mod common;

use std::{
    net::SocketAddrV4,
    sync::{Arc, Mutex},
};

use common::config;
use punch_hole::{
    StrategyId,
    error::PunchError,
    msg::decode_sig,
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
    // The birthday sizing is honest for its target, so the 0.5 default
    // target leaves a coin flip. The 100-wide range with a 0.95 target
    // covers ceil(sqrt(ln(20) / 2 * space)) ports, 17 to 19 here, which
    // keeps the true chance above 0.99.
    let a = net.host(NatSpec::random(30000..30100));
    let b = net.host(NatSpec::random(30000..30100));
    let mut cfg = config(&stun);
    cfg.target_success = 0.95;
    let (ra, _) = common::punch_pair(a, cfg.clone(), b, cfg).await;
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
    // Fan-out round one waits half the budget, round two waits to the
    // deadline.
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
            pub_ips: vec![[100, 64, 2, 1].into()],
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

/// Runs one easy-symmetric pair against `servers` sim STUN servers and
/// returns every `Hello` the pair exchanged, seen through a tap on the
/// signaling bridge.
async fn easy_pair_hellos(name: &str, servers: usize) -> Vec<NatInfo> {
    let net = Net::seeded(name);
    let mut addrs = Vec::new();
    for _ in 0..servers {
        addrs.extend(net.stun_server().addrs);
    }
    let a = net.host(NatSpec::sequential(1));
    let b = net.host(NatSpec::sequential(1));
    let mut cfg = punch_hole::PunchConfig::default();
    cfg.stun_servers = addrs;

    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    let hellos: Arc<Mutex<Vec<NatInfo>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&hellos);
    punch_hole::sim::connect_with(ha, hb, move |frame| {
        if let Ok(sig) = decode_sig(frame) {
            if let punch_hole::msg::Frame::Hello(info) = sig.body {
                sink.lock().expect("hello tap lock").push(info);
            }
        }
        Some(frame.to_vec())
    });
    let a = tokio::spawn(common::run_initiator(a, cfg.clone(), la));
    let b = tokio::spawn(common::run_responder(b, cfg, lb));
    a.await.unwrap().expect("easy pair punches");
    b.await.unwrap().expect("easy pair punches");
    hellos.lock().expect("hello tap lock").clone()
}

/// The longest `alloc_seq` any side reported.
fn max_seq_len(infos: &[NatInfo]) -> usize {
    infos
        .iter()
        .map(|info| info.v4.as_ref().map_or(0, |v4| v4.alloc_seq.len()))
        .max()
        .unwrap_or(0)
}

#[tokio::test(start_paused = true)]
async fn two_stun_servers_double_the_samples() {
    // One sim server owns four ports, so two servers feed the fan-out eight
    // destinations and the probe collects eight ports instead of four.
    let one = easy_pair_hellos("two_servers_one", 1).await;
    let two = easy_pair_hellos("two_servers_two", 2).await;
    assert_eq!(max_seq_len(&one), 4);
    assert_eq!(max_seq_len(&two), 8);
    for info in &two {
        let v4 = info.v4.as_ref().expect("v4 evidence");
        assert_eq!(v4.class, NatClass::EasySym { step: 1 });
        // Send order equals allocation order, so the ports walk +1.
        assert!(v4.alloc_seq.windows(2).all(|w| w[1] == w[0] + 1));
        // One NAT means one public IP, and the first entry matches the
        // reflexive address.
        assert_eq!(v4.pub_ips.len(), 1);
        assert_eq!(v4.pub_ips[0], *v4.reflexive.ip());
    }
}

#[tokio::test(start_paused = true)]
async fn probe_phase_ends_at_its_deadline() {
    let net = Net::seeded("probe_deadline");
    // Silent literal destinations: the router drops every query.
    let mut cfg = punch_hole::PunchConfig::default();
    cfg.stun_servers = vec!["9.9.9.9:3478".to_owned(), "9.9.9.9:3479".to_owned()];
    cfg.probe_timeout = std::time::Duration::from_millis(600);
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
    // Round one waits half the budget, round two waits out the rest; paused
    // time makes the deadline exact.
    assert_eq!(t.elapsed(), std::time::Duration::from_millis(600));
}
