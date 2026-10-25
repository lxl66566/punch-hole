#![allow(clippy::field_reassign_with_default)]

//! One suite per punch strategy.

mod common;

use common::config;
use punch_hole::{
    NatClass, StrategyId,
    error::PunchError,
    sim::{NatSpec, Net},
};

#[tokio::test(start_paused = true)]
async fn cone_cone_success() {
    let (_net, stun, a, b) = common::cone_net("cone_cone_success");
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("cone cone punches");
    let pb = rb.expect("cone cone punches");
    assert_eq!(pa.report.strategy, StrategyId::ConeExchange);
    assert_eq!(pb.report.strategy, StrategyId::ConeExchange);
    common::assert_business_traffic(&pa, &pb).await;
}

#[tokio::test(start_paused = true)]
async fn hard_sym_cone_uses_sym_probe() {
    let net = Net::seeded("hard_sym_cone");
    let stun = net.stun_server();
    let a = net.host(NatSpec::random(30000..60000));
    // Endpoint-independent filtering on the cone side: the classic
    // symmetric-to-cone technique relies on replies to observed sources.
    let b = net.host(NatSpec::cone_eif());
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("sym probe punches");
    let pb = rb.expect("sym probe punches");
    assert_eq!(pa.report.strategy, StrategyId::SymProbe);
    assert_eq!(pb.report.strategy, StrategyId::SymProbe);
    assert_eq!(pa.report.local_class, NatClass::HardSym);
    assert_eq!(pb.report.local_class, NatClass::Cone);
    common::assert_business_traffic(&pa, &pb).await;
    let _ = net.mapping_count();
}

#[tokio::test(start_paused = true)]
async fn hard_sym_cone_apdf_punches_via_spray() {
    let net = Net::seeded("hard_sym_cone_apdf");
    let stun = net.stun_server();
    let a = net.host(NatSpec::random(30000..30100));
    // Port-strict filtering on the cone side: the peer's Syn pulses arrive
    // from sources the cone never wrote to, so only the cone's own spray
    // opens the path.
    let b = net.host(NatSpec::cone_apdf());
    let mut cfg = config(&stun);
    // Model margin: the probe pins the HardSym space to the observed spread
    // plus 2 * 64 margin, at most 100 + 128 = 228. With m = 16 peer sockets
    // and target 0.99, c = ceil(ln(100) * 228 / 16) = 66 and the estimate
    // 1 - exp(-16 * 66 / 228) >= 0.99. A narrower observed spread only
    // raises it, so the 0.98 bar keeps float noise out of the assertion.
    cfg.target_success = 0.99;
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    let pa = ra.expect("spray punches");
    let pb = rb.expect("spray punches");
    assert_eq!(pa.report.strategy, StrategyId::SymProbe);
    assert_eq!(pb.report.strategy, StrategyId::SymProbe);
    // Both roles carry the estimate: the responder rebuilds it over its own
    // view of the two NATs.
    assert!(pa.report.success_estimate.unwrap_or(0.0) > 0.98);
    assert_eq!(pb.report.success_estimate, pa.report.success_estimate);
    common::assert_business_traffic(&pa, &pb).await;
    let _ = net.mapping_count();
}

#[tokio::test(start_paused = true)]
async fn easy_sym_cone_apdf_punches_via_prediction() {
    let net = Net::seeded("easy_sym_cone_apdf");
    let stun = net.stun_server();
    let a = net.host(NatSpec::sequential(2));
    let b = net.host(NatSpec::cone_apdf());
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("prediction spray punches");
    let pb = rb.expect("prediction spray punches");
    assert_eq!(pa.report.strategy, StrategyId::SymProbe);
    assert_eq!(pb.report.strategy, StrategyId::SymProbe);
    assert_eq!(pa.report.local_class, NatClass::EasySym { step: 2 });
    assert_eq!(pb.report.local_class, NatClass::Cone);
    common::assert_business_traffic(&pa, &pb).await;
    let _ = net.mapping_count();
}

#[tokio::test(start_paused = true)]
async fn easy_sym_pair_uses_predictions() {
    let net = Net::seeded("easy_sym_pair");
    let stun = net.stun_server();
    // Different steps on the two sides prove both predictors run.
    let a = net.host(NatSpec::sequential(2));
    let b = net.host(NatSpec::sequential(3));
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("easy pair punches");
    let pb = rb.expect("easy pair punches");
    assert_eq!(pa.report.strategy, StrategyId::PredictiveExchange);
    assert_eq!(pb.report.strategy, StrategyId::PredictiveExchange);
    common::assert_business_traffic(&pa, &pb).await;
    let _ = net.mapping_count();
}

#[tokio::test(start_paused = true)]
async fn birthday_burst_narrow_range() {
    let net = Net::seeded("birthday_narrow");
    let stun = net.stun_server();
    let a = net.host(NatSpec::random(30000..30100));
    let b = net.host(NatSpec::random(30000..30100));
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("birthday punches");
    let pb = rb.expect("birthday punches");
    assert_eq!(pa.report.strategy, StrategyId::BirthdayBurst);
    assert!(pa.report.success_estimate.unwrap_or(0.0) > 0.5);
    common::assert_business_traffic(&pa, &pb).await;
    let _ = net.mapping_count();
}

#[tokio::test(start_paused = true)]
async fn birthday_starved_goes_unpunchable() {
    let net = Net::seeded("birthday_starved");
    let stun = net.stun_server();
    let mut cfg_a = config(&stun);
    // A tiny budget and a high bar: whatever span the probe observes, the
    // model cannot reach the target, so Negotiate refuses without packets.
    cfg_a.packet_budget = 10;
    cfg_a.target_success = 0.95;
    cfg_a.min_success = 0.9;
    let cfg_b = cfg_a.clone();
    let a = net.host(NatSpec::random(32768..65535));
    let b = net.host(NatSpec::random(32768..65535));

    let forwarded_before = net.forwarded();
    let (ra, rb) = common::punch_pair(a, cfg_a, b, cfg_b).await;
    assert!(
        matches!(ra, Err(PunchError::Unpunchable { .. })),
        "got {ra:?}"
    );
    assert!(matches!(rb, Err(PunchError::PeerAborted(_))), "got {rb:?}");

    // The decision happened in Negotiate: only the probe traffic crossed.
    let spent = net.forwarded() - forwarded_before;
    assert!(spent < 60, "data plane sent {spent} packets");
}

#[tokio::test(start_paused = true)]
async fn public_pair_goes_direct() {
    let net = Net::seeded("public_pair");
    let stun = net.stun_server();
    let a = net.public_host();
    let b = net.public_host();
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("public pair punches");
    let pb = rb.expect("public pair punches");
    // No NAT devices attached, so the session created no mappings.
    assert_eq!(net.mapping_count(), 0);
    common::assert_business_traffic(&pa, &pb).await;
}
