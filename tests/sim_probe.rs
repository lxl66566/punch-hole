#![allow(clippy::field_reassign_with_default)]

//! NAT classification cases against the simulator.

mod common;

use std::{
    net::SocketAddrV4,
    sync::{Arc, Mutex},
};

use common::config;
use nat_lab::sim::{NatSpec, Net};
use punch_hole::{
    StrategyId,
    error::PunchError,
    msg::decode_sig,
    nat::{NatClass, NatInfo, V4Nat},
};

#[tokio::test(start_paused = true)]
async fn cone_detected() {
    let (_net, stun, a, b) = common::cone_net("cone_detected");
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("cone pair punches");
    let pb = rb.expect("cone pair punches");
    assert_eq!(pa.report.local_class, Some(NatClass::Cone));
    assert_eq!(pb.report.local_class, Some(NatClass::Cone));
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
    assert_eq!(pa.report.local_class, Some(NatClass::EasySym { step: 1 }));
    assert_eq!(pa.report.strategy, StrategyId::PredictiveExchange);
}

#[tokio::test(start_paused = true)]
async fn hard_detected() {
    // The birthday sizing is honest for its target, so the 0.5 default
    // target leaves a coin flip. The 100-wide range with a 0.95 target
    // covers ceil(sqrt(ln(20) / 2 * space)) ports, 17 to 19 here, which
    // keeps the true chance above 0.99. The rest is the model's own
    // residual, so the pair reruns on a fresh nonce.
    let mut cfg = punch_hole::PunchConfig::default();
    cfg.target_success = 0.95;
    let (ra, _) = common::punch_pair_retried(
        "hard_detected",
        NatSpec::random(30000..30100),
        NatSpec::random(30000..30100),
        cfg,
        3,
    )
    .await;
    let pa = ra.expect("birthday pair punches");
    assert_eq!(pa.report.local_class, Some(NatClass::HardSym));
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
    assert_eq!(pa.report.local_class, Some(NatClass::Public));
    assert_eq!(pb.report.local_class, Some(NatClass::Public));
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
async fn probe_window_stays_under_overall_deadline() {
    let net = Net::seeded("probe_overall");
    // No STUN server on this address; the router drops the queries, so the
    // phase spends its whole window against the session wall.
    let mut cfg = punch_hole::PunchConfig::default();
    cfg.stun_servers = vec!["9.9.9.9:3478".to_owned()];
    cfg.probe_timeout = std::time::Duration::from_secs(2);
    cfg.overall_deadline = std::time::Duration::from_secs(2);
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
    // The phase deadline is clamped to the session wall, which the two
    // budgets share down to the boundary.
    assert!(
        t.elapsed() <= std::time::Duration::from_millis(2_100),
        "probe ran {} ms past the overall deadline",
        t.elapsed().as_millis()
    );
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
            distinct_probe_ips: 2,
            filtering: punch_hole::FilterClass::Unknown,
        }),
        v6: None,
    };
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    punch_hole::signaling::connect(ha, hb);
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
}

/// Runs one pair of `spec` hosts against `servers` sim STUN servers and
/// returns every `Hello` the pair exchanged, seen through a tap on the
/// signaling bridge.
async fn pair_hellos(name: &str, spec: NatSpec, servers: usize) -> Vec<NatInfo> {
    let net = Net::seeded(name);
    let mut addrs = Vec::new();
    for _ in 0..servers {
        addrs.extend(net.stun_server().addrs);
    }
    let a = net.host(spec.clone());
    let b = net.host(spec);
    let mut cfg = punch_hole::PunchConfig::default();
    cfg.stun_servers = addrs;

    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    let hellos: Arc<Mutex<Vec<NatInfo>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&hellos);
    punch_hole::signaling::connect_with(ha, hb, move |frame| {
        if let Ok(sig) = decode_sig(frame)
            && let punch_hole::msg::Frame::Hello(info) = sig.body
        {
            sink.lock().expect("hello tap lock").push(info);
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
async fn cone_filtering_stays_unknown() {
    // Four destinations answered through one port, the case an
    // endpoint-independent mapping used to be reported as. Filtering is a
    // separate axis the probe runs no test for, so it stays Unknown.
    let hellos = pair_hellos("cone_filtering", NatSpec::cone_eif(), 1).await;
    for info in &hellos {
        let v4 = info.v4.as_ref().expect("v4 evidence");
        assert_eq!(v4.class, NatClass::Cone);
        assert_eq!(v4.filtering, punch_hole::FilterClass::Unknown);
    }
}

#[tokio::test(start_paused = true)]
async fn address_dependent_mapping_keys_on_ip() {
    use punch_hole::socket::{UdpFactory, UdpIo};

    let net = Net::seeded("adm_mapping");
    let host = net.host(NatSpec::address_sequential(2));
    let sock = host.bind("0.0.0.0:0".parse().unwrap()).await.unwrap();
    let dst = |ip: [u8; 4], port: u16| std::net::SocketAddr::V4(SocketAddrV4::new(ip.into(), port));

    // Two ports of one address share one mapping.
    sock.send_to(b"x", dst([9, 9, 9, 9], 100)).await.unwrap();
    sock.send_to(b"x", dst([9, 9, 9, 9], 200)).await.unwrap();
    assert_eq!(net.mapping_count(), 1);

    // A second address opens its own mapping, two steps ahead whatever
    // the snapshot order is.
    sock.send_to(b"x", dst([8, 8, 8, 8], 100)).await.unwrap();
    let ext: Vec<u16> = net
        .mappings_snapshot()
        .into_iter()
        .map(|(_, ext)| ext.port())
        .collect();
    assert_eq!(ext.len(), 2);
    assert_eq!((i32::from(ext[1]) - i32::from(ext[0])).abs(), 2);
}

#[tokio::test(start_paused = true)]
async fn address_dependent_nat_reads_as_cone() {
    // The sim server puts all four ports on one address, so an ADM NAT
    // answers the whole fan-out through one mapping and the probe reports
    // the cone it cannot distinguish from address dependence.
    let spec =
        NatSpec::address_sequential(2).with_filtering(nat_lab::FilterClass::EndpointIndependent);
    let hellos = pair_hellos("adm_reads_cone", spec, 1).await;
    for info in &hellos {
        let v4 = info.v4.as_ref().expect("v4 evidence");
        assert_eq!(v4.class, NatClass::Cone);
        // One mapping means one port across all four samples.
        assert!(v4.alloc_seq.windows(2).all(|w| w[0] == w[1]));
    }
}

#[tokio::test(start_paused = true)]
async fn random_mappings_hold_distinct_ports() {
    use std::collections::HashSet;

    use punch_hole::socket::{UdpFactory, UdpIo};

    let net = Net::seeded("random_unique_ports");
    let host = net.host(NatSpec::random(30000..30010));
    let sock = host.bind("0.0.0.0:0".parse().unwrap()).await.unwrap();
    // Ten live mappings in a ten-port range: every port serves exactly one.
    for i in 0..10u16 {
        let dst = std::net::SocketAddr::V4(SocketAddrV4::new([9, 9, 9, 9].into(), 1000 + i));
        sock.send_to(b"x", dst).await.unwrap();
    }
    let ports: HashSet<u16> = net
        .mappings_snapshot()
        .into_iter()
        .map(|(_, ext)| ext.port())
        .collect();
    assert_eq!(ports.len(), 10, "every mapping holds its own port");
}

#[tokio::test(start_paused = true)]
async fn mappings_survive_close_until_the_expiry_passes() {
    use punch_hole::socket::{UdpFactory, UdpIo};

    let net = Net::seeded("mapping_expiry");
    net.set_mapping_expiry(std::time::Duration::from_secs(30));
    let host = net.host(NatSpec::cone_eif());
    let sock = host.bind("0.0.0.0:0".parse().unwrap()).await.unwrap();
    let dst = std::net::SocketAddr::V4(SocketAddrV4::new([9, 9, 9, 9].into(), 9));
    sock.send_to(b"x", dst).await.unwrap();
    assert_eq!(net.mapping_count(), 1);

    // The loser socket goes away; the expiry window keeps the mapping in
    // the table, which is what translates a late peer retransmit.
    drop(sock);
    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    assert_eq!(net.mapping_count(), 1, "mapping outlives the socket");

    tokio::time::sleep(std::time::Duration::from_secs(31)).await;
    assert_eq!(net.mapping_count(), 0, "expiry releases the mapping");
}

#[tokio::test(start_paused = true)]
async fn two_stun_servers_double_the_samples() {
    // One sim server owns four ports, so two servers feed the fan-out eight
    // destinations and the probe collects eight ports instead of four.
    let one = pair_hellos("two_servers_one", NatSpec::sequential(1), 1).await;
    let two = pair_hellos("two_servers_two", NatSpec::sequential(1), 2).await;
    assert_eq!(max_seq_len(&one), 4);
    assert_eq!(max_seq_len(&two), 8);
    for info in &two {
        let v4 = info.v4.as_ref().expect("v4 evidence");
        assert_eq!(v4.class, NatClass::EasySym { step: 1 });
        // Send order equals allocation order, so the ports walk +1.
        assert!(v4.alloc_seq.windows(2).all(|w| w[1] == w[0] + 1));
    }
}

/// One fan-out whose first request to one destination never reached the
/// NAT: the retry allocates that mapping after every first-round mapping,
/// which reorders the answers against their send positions.
#[tokio::test(start_paused = true)]
async fn outbound_probe_loss_keeps_easy_sym() {
    let net = Net::seeded("outbound_probe_loss");
    let mut addrs = Vec::new();
    for _ in 0..2 {
        addrs.extend(net.stun_server().addrs);
    }
    let a = net.host(NatSpec::sequential(1));
    let b = net.host(NatSpec::sequential(1));
    // Destination one loses its first request before the NAT, so only the
    // retry round creates its mapping.
    a.drop_first_send_to(addrs[1].parse().expect("sim server address"));
    let mut cfg = punch_hole::PunchConfig::default();
    cfg.stun_servers = addrs;
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    let pa = ra.expect("easy pair punches through one lost request");
    let _ = rb.expect("peer side punches");
    assert_eq!(pa.report.local_class, Some(NatClass::EasySym { step: 1 }));
    assert_eq!(pa.report.strategy, StrategyId::PredictiveExchange);
}

/// One destination whose sends never leave the host holds no NAT
/// allocation, so it must not sit between the answered samples as an
/// allocation whose port went unreported.
#[tokio::test(start_paused = true)]
async fn persistent_send_failure_keeps_the_stride() {
    let net = Net::seeded("send_failure_stride");
    let mut addrs = Vec::new();
    for _ in 0..2 {
        addrs.extend(net.stun_server().addrs);
    }
    let a = net.host(NatSpec::sequential(2));
    let b = net.host(NatSpec::sequential(2));
    // Every send to destination three fails locally, so the NAT never
    // allocates for it and the answered stride stays two.
    a.fail_sends_to(addrs[3].parse().expect("sim server address"));
    let mut cfg = punch_hole::PunchConfig::default();
    cfg.stun_servers = addrs;
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    let pa = ra.expect("easy pair punches through one failed destination");
    let _ = rb.expect("peer side punches");
    assert_eq!(pa.report.local_class, Some(NatClass::EasySym { step: 2 }));
    assert_eq!(pa.report.strategy, StrategyId::PredictiveExchange);
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

/// Wires the pair so every frame crosses, and walks `drift` hosts'
/// allocation sequences forward once the Offer leaves, which lands the
/// drift in the gap between Probe and the punch allocations.
async fn drift_pair(
    a: nat_lab::sim::Host,
    cfg: punch_hole::PunchConfig,
    b: nat_lab::sim::Host,
    drift: Vec<nat_lab::sim::Host>,
    allocations: usize,
) -> (
    Result<punch_hole::Punched<nat_lab::sim::SimSocket>, PunchError>,
    Result<punch_hole::Punched<nat_lab::sim::SimSocket>, PunchError>,
) {
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let armed = Arc::clone(&fired);
    punch_hole::signaling::connect_with(ha, hb, move |frame| {
        if !armed.load(std::sync::atomic::Ordering::Relaxed)
            && matches!(
                decode_sig(frame).map(|f| f.body),
                Ok(punch_hole::msg::Frame::Offer(_))
            )
        {
            armed.store(true, std::sync::atomic::Ordering::Relaxed);
            for host in &drift {
                let host = host.clone();
                tokio::spawn(async move {
                    host.external_allocations(allocations).await;
                });
            }
        }
        Some(frame.to_vec())
    });
    let a = tokio::spawn(common::run_initiator(a, cfg.clone(), la));
    let b = tokio::spawn(common::run_responder(b, cfg, lb));
    (
        a.await.expect("initiator task panicked"),
        b.await.expect("responder task panicked"),
    )
}

/// External allocations on the symmetric peer's NAT during the Negotiate
/// gap shift its sequence far past the spray's slack. The peer's announced
/// allocation position re-bases the cone's prediction, so the pair still
/// punches.
#[tokio::test(start_paused = true)]
async fn external_drift_rebases_the_sym_probe_spray() {
    let net = Net::seeded("external_drift_rebase");
    let stun = net.stun_server();
    let cone = net.host(NatSpec::cone_apdf());
    let sym = net.host(NatSpec::sequential(1));
    let (ra, rb) = drift_pair(cone, config(&stun), sym.clone(), vec![sym], 600).await;
    let pa = ra.expect("rebased spray punches");
    let pb = rb.expect("peer side punches");
    assert_eq!(pa.report.strategy, StrategyId::SymProbe);
    common::assert_business_traffic(&pa, &pb).await;
}

/// The same drift with the peer's announce dropped: the cone's prediction
/// stays on the probe-time base, the spray misses the peer's live
/// mappings, and the port-filtered cone drops every peer pulse, so the
/// attempt never completes.
#[tokio::test(start_paused = true)]
async fn external_drift_without_the_announce_misses() {
    let net = Net::seeded("external_drift_no_announce");
    let stun = net.stun_server();
    let cone = net.host(NatSpec::cone_apdf());
    let sym = net.host(NatSpec::sequential(1));
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    // The initiator side passes everything, so the responder learns the
    // port to aim at; the responder side drops its own PortUpdate, so the
    // initiator never sees the fresh allocation position.
    let mut a_out = ha.to_peer;
    let b_in = hb.from_peer;
    let mut b_out = hb.to_peer;
    let a_in = ha.from_peer;
    let drift = sym.clone();
    let mut fired = false;
    tokio::spawn(async move {
        while let Some(frame) = a_out.recv().await {
            if !fired
                && matches!(
                    decode_sig(&frame).map(|f| f.body),
                    Ok(punch_hole::msg::Frame::Offer(_))
                )
            {
                fired = true;
                drift.external_allocations(600).await;
            }
            let _ = b_in.send(frame).await;
        }
    });
    tokio::spawn(async move {
        while let Some(frame) = b_out.recv().await {
            let passthrough = !matches!(
                decode_sig(&frame).map(|f| f.body),
                Ok(punch_hole::msg::Frame::PortUpdate { .. })
            );
            if passthrough {
                let _ = a_in.send(frame).await;
            }
        }
    });
    let a = tokio::spawn(common::run_initiator(cone, config(&stun), la));
    let b = tokio::spawn(common::run_responder(sym, config(&stun), lb));
    let ra = a.await.expect("initiator task panicked");
    let rb = b.await.expect("responder task panicked");
    assert!(ra.is_err(), "a stale window never connects: {ra:?}");
    assert!(rb.is_err(), "the peer side cannot confirm: {rb:?}");
}

/// Both sides' sequences drift during Negotiate; the announced positions
/// keep both prediction windows anchored, so PredictiveExchange punches.
#[tokio::test(start_paused = true)]
async fn predictive_exchange_punches_under_external_drift() {
    let net = Net::seeded("predictive_drift");
    let stun = net.stun_server();
    let a = net.host(NatSpec::sequential(1));
    let b = net.host(NatSpec::sequential(1));
    let (ra, rb) = drift_pair(a.clone(), config(&stun), b.clone(), vec![a, b], 600).await;
    let pa = ra.expect("drifted easy pair punches");
    let _ = rb.expect("peer side punches");
    assert_eq!(pa.report.strategy, StrategyId::PredictiveExchange);
}

/// The easy side of a PredictiveBurst pair drifts during Negotiate, far
/// past the window's slack. Its announced allocation position re-bases
/// the hard side's continuation window, so the pair still punches; the
/// same drift with the announce dropped leaves the window on the
/// probe-time base and the attempt misses.
#[tokio::test(start_paused = true)]
async fn predictive_burst_rebases_under_external_drift() {
    let net = Net::seeded("pred_burst_drift");
    let stun = net.stun_server();
    let easy = net.host(NatSpec::sequential(2));
    let hard = net.host(NatSpec::random(30000..30400));
    let (ra, rb) = drift_pair(easy.clone(), config(&stun), hard.clone(), vec![easy], 600).await;
    let pa = ra.expect("rebased window punches");
    let pb = rb.expect("peer side punches");
    assert_eq!(pa.report.strategy, StrategyId::PredictiveBurst);
    common::assert_business_traffic(&pa, &pb).await;
}

/// A rebind that lands mid-probe splits the observed sequence, so the
/// stride fit fails and the class degrades to HardSym. The pair never
/// carries a confidently wrong step into the punch.
#[tokio::test(start_paused = true)]
async fn mid_probe_rebind_degrades_to_hard_sym() {
    let net = Net::seeded("mid_probe_rebind");
    let stun = net.stun_server();
    let a = net.host(NatSpec::sequential(2));
    a.rebind_sequence_after(3);
    let b = net.host(NatSpec::sequential(2));
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    let hellos: Arc<Mutex<Vec<NatInfo>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&hellos);
    punch_hole::signaling::connect_with(ha, hb, move |frame| {
        if let Ok(sig) = decode_sig(frame)
            && let punch_hole::msg::Frame::Hello(info) = sig.body
        {
            sink.lock().expect("hello tap lock").push(info);
        }
        Some(frame.to_vec())
    });
    let a = tokio::spawn(common::run_initiator(a, config(&stun), la));
    let b = tokio::spawn(common::run_responder(b, config(&stun), lb));
    // The pair may punch or fail on its degraded estimate; the pinned
    // behavior is the classification, which the Hello already carries.
    let _ = a.await;
    let _ = b.await;
    let hellos = hellos.lock().expect("hello tap lock").clone();
    let rebind_side = hellos
        .iter()
        .find(|info| {
            info.v4.as_ref().is_some_and(|v4| {
                v4.alloc_seq
                    .windows(2)
                    .any(|w| (i32::from(w[1]) - i32::from(w[0])).abs() > 100)
            })
        })
        .expect("the rebind side reported")
        .v4
        .as_ref()
        .expect("v4 evidence");
    assert_eq!(
        rebind_side.class,
        NatClass::HardSym,
        "a split sequence never carries a fitted stride"
    );
}
