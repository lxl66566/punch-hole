#![allow(clippy::field_reassign_with_default)]
// Success rates divide run counts in floating point.
#![allow(clippy::cast_precision_loss)]

//! One suite per punch strategy.

mod common;

use common::config;
use nat_lab::sim::{NatSpec, Net};
use punch_hole::{
    NatClass, PunchConfig, StrategyId,
    error::{PunchError, PunchFailure},
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
    assert_eq!(pa.report.local_class, Some(NatClass::HardSym));
    assert_eq!(pb.report.local_class, Some(NatClass::Cone));
    common::assert_business_traffic(&pa, &pb).await;
    let _ = net.mapping_count();
}

#[tokio::test(start_paused = true)]
async fn hard_sym_cone_apdf_punches_via_spray() {
    // Port-strict filtering on the cone side: the peer's Syn pulses arrive
    // from sources the cone never wrote to, so only the cone's own spray
    // opens the path.
    let mut cfg = PunchConfig::default();
    // The span estimate reads upper-confidence: four samples of the
    // 100-wide range show a ~60-wide range and widen to ~140. With m = 16
    // peer sockets and target 0.99, c = ceil(ln(100) * space / 16) solves
    // the estimate to 1 - exp(-m * c / space) >= 0.99 against whatever
    // span the probe saw, so the 0.98 bar keeps float noise out of the
    // assertion. A run from the thin undershoot tail is covered by a
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
    assert_eq!(pa.report.local_class, Some(NatClass::EasySym { step: 2 }));
    assert_eq!(pb.report.local_class, Some(NatClass::Cone));
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

/// An easy symmetric initiator against a hard symmetric responder: the
/// easy side sprays the hard peer's span while the hard side covers the
/// easy peer's continuation window, and either direction completes the
/// handshake.
#[tokio::test(start_paused = true)]
async fn predictive_burst_easy_initiator_punches() {
    let net = Net::seeded("pred_burst_easy_init");
    let stun = net.stun_server();
    let a = net.host(NatSpec::sequential(2));
    let b = net.host(NatSpec::random(30000..30400));
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("prediction burst punches");
    let pb = rb.expect("prediction burst punches");
    assert_eq!(pa.report.strategy, StrategyId::PredictiveBurst);
    assert_eq!(pb.report.strategy, StrategyId::PredictiveBurst);
    assert_eq!(pa.report.local_class, Some(NatClass::EasySym { step: 2 }));
    assert_eq!(pb.report.local_class, Some(NatClass::HardSym));
    // The estimate states the continuation regime, which the sim holds.
    assert_eq!(pa.report.success_estimate, Some(1.0));
    assert_eq!(pb.report.success_estimate, Some(1.0));
    common::assert_business_traffic(&pa, &pb).await;
}

/// The same pair with the roles swapped: the matrix entry holds in both
/// orientations, and each side derives its stage from its own class.
#[tokio::test(start_paused = true)]
async fn predictive_burst_hard_initiator_punches() {
    let net = Net::seeded("pred_burst_hard_init");
    let stun = net.stun_server();
    let a = net.host(NatSpec::random(30000..30400));
    let b = net.host(NatSpec::sequential(3));
    let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
    let pa = ra.expect("prediction burst punches");
    let pb = rb.expect("prediction burst punches");
    assert_eq!(pa.report.strategy, StrategyId::PredictiveBurst);
    assert_eq!(pb.report.strategy, StrategyId::PredictiveBurst);
    assert_eq!(pa.report.local_class, Some(NatClass::HardSym));
    assert_eq!(pb.report.local_class, Some(NatClass::EasySym { step: 3 }));
    common::assert_business_traffic(&pa, &pb).await;
}

/// A demoted easy fit — three consistent samples, one short of a
/// confident fit — leaves exactly one predictable side, so the pair runs
/// PredictiveBurst instead of a birthday attack against the peer it could
/// predict.
#[tokio::test(start_paused = true)]
async fn predictive_burst_covers_a_demoted_easy_fit() {
    let net = Net::seeded("pred_burst_demoted");
    let stun = net.stun_server();
    // Three destinations answer for the initiator: enough for a constant
    // step, one short of the confident fit.
    let mut cfg_a = config(&stun);
    cfg_a.stun_servers.truncate(3);
    let a = net.host(NatSpec::sequential(2));
    let b = net.host(NatSpec::sequential(3));
    let (ra, rb) = common::punch_pair(a, cfg_a, b, config(&stun)).await;
    let pa = ra.expect("demoted pair punches on prediction");
    let pb = rb.expect("demoted pair punches on prediction");
    assert_eq!(pa.report.strategy, StrategyId::PredictiveBurst);
    assert_eq!(pb.report.strategy, StrategyId::PredictiveBurst);
    common::assert_business_traffic(&pa, &pb).await;
}

/// PredictiveBurst across independent seeds and both role orientations:
/// the measured success rate must track the model's estimate, which
/// states certainty under the continuation regime. The sim injects no
/// unrelated allocations, so the regime holds and every run must punch.
#[tokio::test(start_paused = true)]
async fn predictive_burst_measured_rate_tracks_the_estimate() {
    const RUNS: usize = 16;
    for i in 0..RUNS as u64 {
        let net = Net::from_seed_u64(0x5eed_600d + i);
        let stun = net.stun_server();
        let (a, b) = if i % 2 == 0 {
            (
                net.host(NatSpec::sequential(2)),
                net.host(NatSpec::random(30000..30400)),
            )
        } else {
            (
                net.host(NatSpec::random(30000..30400)),
                net.host(NatSpec::sequential(2)),
            )
        };
        let (ra, rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
        let pa = ra.unwrap_or_else(|e| panic!("run {i} punches: {e:?}"));
        rb.expect("peer punches");
        assert_eq!(pa.report.strategy, StrategyId::PredictiveBurst);
        assert_eq!(pa.report.success_estimate, Some(1.0));
    }
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
    assert_eq!(pa.report.peer_class, Some(NatClass::EasySym { step: 2 }));
    common::assert_business_traffic(&pa, &pb).await;
    let _ = net.mapping_count();
}

#[tokio::test(start_paused = true)]
async fn birthday_burst_narrow_range() {
    let mut cfg = PunchConfig::default();
    // The sizing is honest for its target, so the 0.5 default target leaves
    // a coin flip. At 0.95 the solve covers ceil(sqrt(ln(20) * S_eff))
    // ports, 15 on a typical ~140-wide span estimate (S_eff = 70), which
    // keeps the true chance above 0.95 while the estimate stays above the
    // true span. The rest is the estimator's variance, covered by a rerun
    // on a fresh nonce.
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
    // standard deviations. The margin also absorbs the span estimator's
    // variance: the estimate reads upper-confidence for the 400-wide
    // range, and the thin undershoot tail concentrates candidates inside
    // the true range, a swing of a few hundredths at this width.
    assert!(
        (rate - 0.5).abs() <= 0.25,
        "measured rate {rate} drifted from the estimated 0.5"
    );
}

/// A birthday side stops emitting new Syns after FIXED_PORT_PASSES full
/// passes over its candidate list, once both live sets are closed. Runs
/// that miss — which previously pulsed until the packet budget or the
/// deadline ran out, thousands of packets — now spend the probe fan-out
/// plus four passes per side, win or lose, and the measured success rate
/// is unchanged.
#[tokio::test(start_paused = true)]
async fn birthday_runs_stop_pulsing_after_the_settled_pass() {
    const RUNS: usize = 16;
    let mut max_packets = 0usize;
    let mut wins = 0usize;
    for i in 0..RUNS as u64 {
        let net = Net::from_seed_u64(0x5717_0000 + i);
        let stun = net.stun_server();
        let a = net.host(NatSpec::random(30000..30400));
        let b = net.host(NatSpec::random(30000..30400));
        let before = net.forwarded();
        let (ra, _rb) = common::punch_pair(a, config(&stun), b, config(&stun)).await;
        let spent = (net.forwarded() - before) as usize;
        max_packets = max_packets.max(spent);
        wins += usize::from(ra.is_ok());
    }
    // Probe fan-out and answers are ~64 packets, four passes of ~13
    // candidates per side are ~104, and a won run adds its handshake
    // exchange: every run stays under two hundred fifty. Before the
    // stop, a missing run pulsed to its packet budget, 2 x 4096.
    assert!(
        max_packets < 250,
        "the worst run spent {max_packets} packets"
    );
    assert!(wins > 0, "the stop must not cost every run");
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
        matches!(
            ra,
            Err(PunchFailure {
                error: PunchError::Unpunchable { .. },
                ..
            })
        ),
        "got {ra:?}"
    );
    assert!(
        matches!(
            rb,
            Err(PunchFailure {
                error: PunchError::PeerAborted(_),
                ..
            })
        ),
        "got {rb:?}"
    );

    // The decision happened in Negotiate: only the probe traffic crossed.
    let spent = net.forwarded() - forwarded_before;
    assert!(spent < 60, "data plane sent {spent} packets");
}

/// The shooter's mappings appear only once its pulses leave, and its
/// pulses wait for the cone's PortUpdate. Over a host channel that delays
/// each frame by 250 ms, the cone's spray holds through the delay and
/// opens on the shooter's first Syns, so the pair still punches and the
/// delay window spends its rate share on nothing.
#[tokio::test(start_paused = true)]
async fn sym_probe_spray_holds_through_a_slow_channel() {
    use std::time::Duration;

    let net = Net::seeded("sym_probe_slow_channel");
    let stun = net.stun_server();
    let a = net.host(NatSpec::random(30000..30100));
    let b = net.host(NatSpec::cone_apdf());
    let mut cfg = config(&stun);
    cfg.target_success = 0.99;

    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    // A pump that delays every frame by 250 ms in each direction, the
    // host transport the spray gate exists for.
    let mut a_out = ha.to_peer;
    let b_in = hb.from_peer;
    tokio::spawn(async move {
        while let Some(frame) = a_out.recv().await {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let _ = b_in.send(frame).await;
        }
    });
    let mut b_out = hb.to_peer;
    let a_in = ha.from_peer;
    tokio::spawn(async move {
        while let Some(frame) = b_out.recv().await {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let _ = a_in.send(frame).await;
        }
    });

    let cfg_b = cfg.clone();
    let a = tokio::spawn(common::run_initiator(a, cfg, la));
    let b = tokio::spawn(common::run_responder(b, cfg_b, lb));
    let ra = a.await.expect("initiator task panicked");
    let rb = b.await.expect("responder task panicked");
    let pa = ra.expect("slow-channel pair punches");
    let pb = rb.expect("peer side punches");
    assert_eq!(pa.report.strategy, StrategyId::SymProbe);
    assert_eq!(pb.report.strategy, StrategyId::SymProbe);
    common::assert_business_traffic(&pa, &pb).await;
}

/// A SymProbe pair whose spray the budget caps below `min_success` refuses
/// in Negotiate, the same bar the birthday burst faces: only the probe
/// traffic crosses.
#[tokio::test(start_paused = true)]
async fn sym_probe_starved_goes_unpunchable() {
    let net = Net::seeded("sym_probe_starved");
    let stun = net.stun_server();
    let mut cfg = config(&stun);
    // The HardSym side draws from most of the ephemeral half, and a tiny
    // budget caps the cone-side spray far below the default 0.1 bar.
    cfg.packet_budget = 64;
    let cfg_b = cfg.clone();
    let a = net.host(NatSpec::random(32768..65535));
    let b = net.host(NatSpec::cone_eif());

    let forwarded_before = net.forwarded();
    let (ra, rb) = common::punch_pair(a, cfg, b, cfg_b).await;
    assert!(
        matches!(
            ra,
            Err(PunchFailure {
                error: PunchError::Unpunchable { .. },
                ..
            })
        ),
        "got {ra:?}"
    );
    assert!(
        matches!(
            rb,
            Err(PunchFailure {
                error: PunchError::PeerAborted(_),
                ..
            })
        ),
        "got {rb:?}"
    );
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

/// An address-dependent symmetric NAT whose whole fan-out crossed one
/// server IP reads as a cone. The reading stays a cone — the probe cannot
/// tell — but the matrix stops trusting it blindly: the pair runs
/// SymProbe with the ambiguous side shooting, and it punches.
#[tokio::test(start_paused = true)]
async fn address_dependent_pair_routes_sym_probe() {
    let net = Net::seeded("adm_routes_sym_probe");
    // One server: all four destinations share one IP, so each ADM NAT
    // answers the whole fan-out through one mapping. Endpoint-independent
    // filtering admits the shooter's pulses, the shape the spray-free
    // routing relies on.
    let stun = net.stun_server();
    let spec =
        NatSpec::address_sequential(2).with_filtering(nat_lab::FilterClass::EndpointIndependent);
    let (ra, rb) = common::punch_pair(
        net.host(spec.clone()),
        config(&stun),
        net.host(spec),
        config(&stun),
    )
    .await;
    let pa = ra.expect("ambiguous pair punches");
    let pb = rb.expect("ambiguous pair punches");
    assert_eq!(pa.report.local_class, Some(NatClass::Cone));
    assert_eq!(pa.report.strategy, StrategyId::SymProbe);
    assert_eq!(pb.report.strategy, StrategyId::SymProbe);
    // No spray model exists without a symmetric side.
    assert_eq!(pa.report.success_estimate, None);
    common::assert_business_traffic(&pa, &pb).await;
}
