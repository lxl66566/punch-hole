#![allow(clippy::field_reassign_with_default)]
// Success rates divide run counts in floating point.
#![allow(clippy::cast_precision_loss)]

//! One suite per punch strategy.

mod common;

use common::config;
use punch_hole::{
    NatClass, PunchConfig, StrategyId,
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
    // Port-strict filtering on the cone side: the peer's Syn pulses arrive
    // from sources the cone never wrote to, so only the cone's own spray
    // opens the path.
    let mut cfg = PunchConfig::default();
    // Model margin: the probe pins the HardSym space to the observed spread
    // plus 2 * 64 margin, at most 100 + 128 = 228. With m = 16 peer sockets
    // and target 0.99, c = ceil(ln(100) * 228 / 16) = 66 and the estimate
    // 1 - exp(-16 * 66 / 228) >= 0.99. A narrower observed spread only
    // raises it, so the 0.98 bar keeps float noise out of the assertion.
    // The percent below the target is the model's residual, covered by a
    // rerun on a fresh nonce.
    cfg.target_success = 0.99;
    let (ra, rb) = common::punch_pair_retried(
        "hard_sym_cone_apdf",
        NatSpec::random(30000..30100),
        NatSpec::cone_apdf(),
        cfg,
        3,
    )
    .await;
    let pa = ra.expect("spray punches");
    let pb = rb.expect("spray punches");
    assert_eq!(pa.report.strategy, StrategyId::SymProbe);
    assert_eq!(pb.report.strategy, StrategyId::SymProbe);
    // Both roles carry the estimate: the responder rebuilds it over its own
    // view of the two NATs.
    assert!(pa.report.success_estimate.unwrap_or(0.0) > 0.98);
    assert_eq!(pb.report.success_estimate, pa.report.success_estimate);
    common::assert_business_traffic(&pa, &pb).await;
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

/// Two silent STUN destinations interleave with answering ones, so each side
/// classifies over a gap-compressed sequence: the adjacent deltas read two
/// strides while the classifier step carries the true one. The pair must
/// still punch on predictions at the true step.
#[tokio::test(start_paused = true)]
async fn easy_sym_pair_with_gapped_allocations_punches() {
    let net = Net::seeded("easy_sym_gapped");
    let stun = net.stun_server();
    // Distinct literals, because the resolver drops duplicate destinations.
    let mut cfg = config(&stun);
    cfg.stun_servers = vec![
        stun.addrs[0].clone(),
        "203.0.113.77:3478".to_owned(),
        stun.addrs[1].clone(),
        "203.0.113.78:3478".to_owned(),
        stun.addrs[2].clone(),
        stun.addrs[3].clone(),
    ];
    let a = net.host(NatSpec::sequential(2));
    let b = net.host(NatSpec::sequential(2));
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    let pa = ra.expect("gapped easy pair punches");
    let pb = rb.expect("gapped easy pair punches");
    assert_eq!(pa.report.strategy, StrategyId::PredictiveExchange);
    assert_eq!(pb.report.strategy, StrategyId::PredictiveExchange);
    assert_eq!(pa.report.peer_class, NatClass::EasySym { step: 2 });
    common::assert_business_traffic(&pa, &pb).await;
    let _ = net.mapping_count();
}

#[tokio::test(start_paused = true)]
async fn birthday_burst_narrow_range() {
    let mut cfg = PunchConfig::default();
    // The sizing is honest for its target, so the 0.5 default target leaves
    // a coin flip. At 0.95 the sizing covers ceil(sqrt(ln(20) / 2 * space))
    // ports, 18 on a typical 200-wide space estimate, which keeps the true
    // chance above 0.99 on the 100-wide range. The rest is the model's
    // residual, covered by a rerun on a fresh nonce.
    cfg.target_success = 0.95;
    let (ra, rb) = common::punch_pair_retried(
        "birthday_narrow",
        NatSpec::random(30000..30100),
        NatSpec::random(30000..30100),
        cfg,
        3,
    )
    .await;
    let pa = ra.expect("birthday punches");
    let pb = rb.expect("birthday punches");
    assert_eq!(pa.report.strategy, StrategyId::BirthdayBurst);
    // The sizing solves 2 * n * c^2 / space = ln(1 / (1 - target)), so the
    // estimate lands at or slightly above the target.
    assert!(pa.report.success_estimate.unwrap_or(0.0) >= 0.95 - 1e-9);
    // The burst space is symmetric in the two views, so both roles report
    // the same estimate.
    assert_eq!(pb.report.success_estimate, pa.report.success_estimate);
    common::assert_business_traffic(&pa, &pb).await;
}

/// Birthday bursts across independent seeds: the measured success rate must
/// track the model's estimate.
#[tokio::test(start_paused = true)]
async fn birthday_measured_rate_tracks_the_estimate() {
    const RUNS: usize = 64;
    let mut wins = 0usize;
    for i in 0..RUNS as u64 {
        let net = Net::from_seed_u64(0x5eed_0000 + i);
        let stun = net.stun_server();
        // A 400-wide range keeps every run on BirthdayBurst: the sizing
        // solves for coverage around 13 ports, far under every cap, so each
        // run's estimate sits at the 0.5 default target up to ceil rounding.
        let a = net.host(NatSpec::random(30000..30400));
        let b = net.host(NatSpec::random(30000..30400));
        let (ra, _rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
        if let Ok(pa) = &ra {
            assert_eq!(pa.report.strategy, StrategyId::BirthdayBurst);
            assert!(pa.report.success_estimate.unwrap_or(0.0) >= 0.5 - 1e-9);
        }
        wins += usize::from(ra.is_ok());
    }
    let rate = wins as f64 / RUNS as f64;
    // Bound rationale: every estimate sits just above 0.5, so a true model
    // measures a rate near 0.5. The per-run outcomes vary with the attempt
    // nonce even at a fixed seed, which makes the count binomial: 64 runs
    // give a standard deviation near 0.06, and 0.25 covers more than four
    // standard deviations. The margin also absorbs the span estimation
    // slack: the model sizes against the observed span plus a 128 margin
    // while the real range is 400 wide, a bias of a few hundredths in
    // probability at this width.
    assert!(
        (rate - 0.5).abs() <= 0.25,
        "measured rate {rate} drifted from the estimated 0.5"
    );
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
