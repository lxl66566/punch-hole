#![allow(clippy::field_reassign_with_default)]

//! Rate limits, budgets, conntrack bounds, and cleanup.

mod common;

use common::config;
use punch_hole::{
    error::PunchError,
    sim::{NatSpec, Net},
};

#[tokio::test(start_paused = true)]
async fn budget_exhaustion_releases_sockets() {
    let net = Net::seeded("budget_exhausted");
    let stun = net.stun_server();
    let mut cfg = config(&stun);
    cfg.packet_budget = 4;
    let a = net.host(NatSpec::sequential(2));
    let b = net.host(NatSpec::sequential(2));

    let (ra, rb) = common::punch_pair(a, cfg, b, config(&stun)).await;
    assert!(matches!(ra, Err(PunchError::BudgetExhausted)), "got {ra:?}");
    // The initiator told the peer, so the responder fails fast too.
    assert!(matches!(rb, Err(PunchError::PeerAborted(_))), "got {rb:?}");

    net.wait_mappings_drained().await;
    assert_eq!(net.mapping_count(), 0, "both pools released their sockets");
}

#[tokio::test(start_paused = true)]
async fn conntrack_bound_stops_the_burst() {
    let net = Net::seeded("conntrack_bound");
    let stun = net.stun_server();
    let mut cfg = config(&stun);
    // PredictiveExchange sizes its window from the socket counts alone, so
    // the mapping cap can bite: 8 bound sockets reach a footprint of 16 on
    // their second distinct destination, past a cap of 8. The birthday burst
    // and the SymProbe spray derive their coverage from the cap itself, so
    // they stay inside it by construction.
    cfg.max_mappings = 8;
    let a = net.host(NatSpec::sequential(2));
    let b = net.host(NatSpec::sequential(2));

    let (ra, rb) = common::punch_pair(a, cfg, b, config(&stun)).await;
    assert!(
        matches!(ra, Err(PunchError::ConntrackExhausted)),
        "got {ra:?}"
    );
    assert!(matches!(rb, Err(PunchError::PeerAborted(_))), "got {rb:?}");
    net.wait_mappings_drained().await;
    assert_eq!(net.mapping_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn rate_cap_bounds_the_burst() {
    let net = Net::seeded("rate_cap");
    let stun = net.stun_server();
    let mut cfg = config(&stun);
    cfg.packets_per_sec = 40;
    cfg.max_sockets = 4;
    cfg.assistant_sockets = 4;
    cfg.predictive_sockets = 4;
    cfg.packet_budget = 5000;
    cfg.punch_timeout = std::time::Duration::from_secs(10);
    // Full-range random NATs keep the bursts hunting without success.
    let a = net.host(NatSpec::random(30000..60000));
    let b = net.host(NatSpec::random(30000..60000));

    let before = net.forwarded();
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    // Either outcome is fine; the bound is about packet volume.
    let _ = (ra, rb);
    let spent = net.forwarded() - before;
    // Two pools at 40 pps over a 10 second window, plus the probes and any
    // handshake. Without the cap, the 5000 packet budget would be spent.
    assert!(spent < 950, "sent {spent} packets through the cap");
}

#[tokio::test(start_paused = true)]
async fn cleanup_on_success_keeps_one_mapping_per_side() {
    let (net, stun, a, b) = common::cone_net("cleanup_success");
    let cfg = config(&stun);
    let (ra, rb) = common::punch_pair(a, cfg, b, config(&stun)).await;
    let pa = ra.expect("cone cone punches");
    let pb = rb.expect("cone cone punches");

    // The winners stay open, every loser and probe socket is gone.
    assert_eq!(net.mapping_count(), 2);

    drop(pa);
    drop(pb);
    net.wait_mappings_drained().await;
    assert_eq!(net.mapping_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn blackholed_signaling_times_out_and_releases() {
    let (net, stun, a, b) = common::cone_net("blackholed");
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    // Hellos, Offer, and Accept cross; every later frame is lost, so no
    // PortUpdate reaches either side and no sweep ever fires.
    common::connect_then_blackhole(ha, hb);

    let a = tokio::spawn(common::run_initiator(a, config(&stun), la));
    let b = tokio::spawn(common::run_responder(b, config(&stun), lb));
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    // Without PortUpdate no sweep ever fires, so both sides end on their own
    // deadline. Whoever times out first closes its bridge, and the other
    // then sees SignalingClosed instead of its own timeout.
    let bounded = |r: &Result<punch_hole::Punched<punch_hole::sim::SimSocket>, PunchError>| {
        matches!(
            r,
            Err(PunchError::Timeout { .. } | PunchError::SignalingClosed)
        )
    };
    assert!(bounded(&ra), "got {ra:?}");
    assert!(bounded(&rb), "got {rb:?}");
    net.wait_mappings_drained().await;
    assert_eq!(net.mapping_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn dropping_the_future_releases_sockets() {
    let (net, stun, a, b) = common::cone_net("drop_future");
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    common::connect_then_blackhole(ha, hb);

    let a = tokio::spawn(common::run_initiator(a, config(&stun), la));
    let b = tokio::spawn(common::run_responder(b, config(&stun), lb));

    // Both refresh STUN queries open one mapping per side.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while net.mapping_count() < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(net.mapping_count() >= 2, "punch sockets were never opened");

    // The host abandons the session futures mid-punch.
    a.abort();
    b.abort();
    net.wait_mappings_drained().await;
    assert_eq!(
        net.mapping_count(),
        0,
        "dropped sessions released every socket"
    );
}
