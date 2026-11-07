//! The punch session against a hostile data plane: loss, jitter, and
//! duplication on the wire, plus the start skew a delayed Accept produces.

#![allow(clippy::result_large_err)]

mod common;

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use common::{config, run_initiator, run_responder};
use nat_lab::sim::{NatSpec, Net};
use punch_hole::{
    PunchConfig, Punched, StrategyId,
    error::PunchFailure,
    msg::{Frame, decode_sig},
    signaling::HostEnd,
};

/// One direction of a forwarding pump that holds each frame for the
/// duration the frame itself names, so a test delays individual frames of
/// the host channel without losing or reordering the rest.
fn held_pump(
    mut from: tokio::sync::mpsc::Receiver<Bytes>,
    to: tokio::sync::mpsc::Sender<Bytes>,
    hold: Arc<dyn Fn(&Frame) -> Duration + Send + Sync>,
) {
    tokio::spawn(async move {
        while let Some(frame) = from.recv().await {
            let hold_for = decode_sig(&frame)
                .map(|f| hold(&f.body))
                .unwrap_or_default();
            if !hold_for.is_zero() {
                tokio::time::sleep(hold_for).await;
            }
            if to.send(frame).await.is_err() {
                break;
            }
        }
    });
}

/// Wires two host ends through one per-frame hold, both directions.
fn connect_held(a: HostEnd, b: HostEnd, hold: Arc<dyn Fn(&Frame) -> Duration + Send + Sync>) {
    held_pump(a.to_peer, b.from_peer, Arc::clone(&hold));
    held_pump(b.to_peer, a.from_peer, hold);
}

/// Holds only the Accept, so the Responder starts on time and the
/// Initiator lands `hold` late: the start skew of an asymmetric signaling
/// path, where the skew correction the Offer carries no longer matches the
/// transit it corrects.
fn accept_hold(hold: Duration) -> impl Fn(&Frame) -> Duration {
    move |frame| match frame {
        Frame::Accept => hold,
        _ => Duration::ZERO,
    }
}

/// Holds only the Offer, so the Initiator starts on time and the
/// Responder lands `hold` late: the mirrored skew, where the Initiator's
/// stages run against a peer that has not classified itself yet.
fn offer_hold(hold: Duration) -> impl Fn(&Frame) -> Duration {
    move |frame| match frame {
        Frame::Offer(_) => hold,
        _ => Duration::ZERO,
    }
}

/// A cone pair over a wire that drops a quarter of every crossing, both
/// directions: the handshake retransmissions must carry the session.
///
/// One STUN server leaves both cones short of mapping-dimension evidence,
/// so the pair legitimately routes to SymProbe instead of ConeExchange.
#[tokio::test(start_paused = true)]
async fn lossy_wire_still_punches() {
    let net = Net::seeded("lossy_wire_still_punches");
    net.set_loss(250);
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_apdf());
    let b = net.host(NatSpec::cone_apdf());
    let cfg = config(&stun);
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    let pa = ra.expect("a punches over a lossy wire");
    let pb = rb.expect("b punches over a lossy wire");
    assert_eq!(pa.report.strategy, StrategyId::SymProbe);
    assert!(net.dropped() > 0, "the wire dropped during the punch");
    net.set_loss(0);
    common::assert_business_traffic(&pa, &pb).await;
}

/// A cone pair over a wire whose crossings wait 50-250 ms: packets of one
/// exchange overtake each other, and the handshake rides its
/// retransmissions.
#[tokio::test(start_paused = true)]
async fn jittered_wire_still_punches() {
    let net = Net::seeded("jittered_wire_still_punches");
    net.set_delay(Duration::from_millis(50)..Duration::from_millis(250));
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_apdf());
    let b = net.host(NatSpec::cone_apdf());
    let cfg = config(&stun);
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    let pa = ra.expect("a punches over a jittered wire");
    let pb = rb.expect("b punches over a jittered wire");
    net.set_delay(Duration::ZERO..Duration::ZERO);
    common::assert_business_traffic(&pa, &pb).await;
}

/// An easy-symmetric pair over a wire that loses and delays at once: the
/// prediction exchange must survive both impairments together.
#[tokio::test(start_paused = true)]
async fn loss_and_jitter_pair_punches() {
    let net = Net::seeded("loss_and_jitter_pair_punches");
    net.set_loss(150);
    net.set_delay(Duration::from_millis(30)..Duration::from_millis(150));
    let stun = net.stun_server();
    let a = net.host(NatSpec::sequential(2));
    let b = net.host(NatSpec::sequential(3));
    let cfg = config(&stun);
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    let pa = ra.expect("a punches over a lossy jittered wire");
    let pb = rb.expect("b punches over a lossy jittered wire");
    assert_eq!(pa.report.strategy, StrategyId::PredictiveExchange);
    net.set_loss(0);
    net.set_delay(Duration::ZERO..Duration::ZERO);
    common::assert_business_traffic(&pa, &pb).await;
}

/// A cone pair over a wire that duplicates a third of its crossings: every
/// handshake packet may arrive twice, and the duplicate handling must keep
/// one attempt.
#[tokio::test(start_paused = true)]
async fn duplicated_wire_still_punches() {
    let net = Net::seeded("duplicated_wire_still_punches");
    net.set_dup(300);
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_apdf());
    let b = net.host(NatSpec::cone_apdf());
    let cfg = config(&stun);
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    let pa = ra.expect("a punches over a duplicating wire");
    let pb = rb.expect("b punches over a duplicating wire");
    net.set_dup(0);
    common::assert_business_traffic(&pa, &pb).await;
}

/// A cone pair whose STUN and data crossings wait 300-500 ms: the refresh
/// query's retry window, sized from `confirm_retry`, must still cover the
/// server's round trip.
#[tokio::test(start_paused = true)]
async fn slow_wire_refresh_survives() {
    let net = Net::seeded("slow_wire_refresh_survives");
    net.set_delay(Duration::from_millis(300)..Duration::from_millis(500));
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_apdf());
    let b = net.host(NatSpec::cone_apdf());
    let cfg = config(&stun);
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    let pa = ra.expect("a punches over a slow wire");
    let pb = rb.expect("b punches over a slow wire");
    net.set_delay(Duration::ZERO..Duration::ZERO);
    common::assert_business_traffic(&pa, &pb).await;
}

/// Runs the pair behind the held frame on a fresh net per try, until both
/// sides punch; returns the last results.
///
/// A spray against fixed ports carries the residual miss the model leaves
/// below a perfect target, so a single run can end in failure without the
/// skew being the cause. A fresh run redraws the nonce, separating the
/// residual from the skew.
async fn skew_pair_retried(
    name: &str,
    a: NatSpec,
    b: NatSpec,
    cfg: PunchConfig,
    hold: Arc<dyn Fn(&Frame) -> Duration + Send + Sync>,
    tries: usize,
) -> (
    Result<Punched<nat_lab::sim::SimSocket>, PunchFailure>,
    Result<Punched<nat_lab::sim::SimSocket>, PunchFailure>,
) {
    let mut cfg = cfg;
    let mut last = None;
    for _ in 0..tries {
        let net = Net::seeded(name);
        let stun = net.stun_server();
        cfg.stun_servers = stun.addrs.clone();
        let (ha, la) = punch_hole::signaling::bridge(64);
        let (hb, lb) = punch_hole::signaling::bridge(64);
        connect_held(ha, hb, Arc::clone(&hold));
        let init = tokio::spawn(run_initiator(net.host(a.clone()), cfg.clone(), la));
        let resp = tokio::spawn(run_responder(net.host(b.clone()), cfg.clone(), lb));
        let pair = (
            init.await.expect("initiator task panicked"),
            resp.await.expect("responder task panicked"),
        );
        if pair.0.is_ok() && pair.1.is_ok() {
            return pair;
        }
        last = Some(pair);
    }
    last.expect("tries is nonzero")
}

/// A cone pair whose Initiator starts about two seconds late: the
/// Responder's stage waits, and the late pulses still complete the
/// handshake.
#[tokio::test(start_paused = true)]
async fn late_initiator_cone_punches() {
    let cfg = PunchConfig {
        stun_servers: Net::seeded("late_initiator_cone_punches")
            .stun_server()
            .addrs
            .clone(),
        ..PunchConfig::default()
    };
    let (ra, rb) = skew_pair_retried(
        "late_initiator_cone_punches",
        NatSpec::cone_apdf(),
        NatSpec::cone_apdf(),
        cfg,
        Arc::new(accept_hold(Duration::from_secs(2))),
        3,
    )
    .await;
    let pa = ra.expect("a late initiator punches");
    let pb = rb.expect("b on-time responder punches");
    common::assert_business_traffic(&pa, &pb).await;
}

/// A hard-symmetric pair whose Initiator starts about two seconds late: the
/// Responder's fixed-port spray runs its pass budget against ports the
/// late peer has not mapped yet, and the late spray must still land one.
#[tokio::test(start_paused = true)]
async fn late_initiator_birthday_punches() {
    let cfg = PunchConfig {
        target_success: 0.99,
        stun_servers: Net::seeded("late_initiator_birthday_punches")
            .stun_server()
            .addrs
            .clone(),
        ..PunchConfig::default()
    };
    let (ra, rb) = skew_pair_retried(
        "late_initiator_birthday_punches",
        NatSpec::random(30000..30100),
        NatSpec::random(30000..30100),
        cfg,
        Arc::new(accept_hold(Duration::from_secs(2))),
        3,
    )
    .await;
    let pa = ra.expect("a late initiator punches");
    let pb = rb.expect("b on-time responder punches");
    common::assert_business_traffic(&pa, &pb).await;
}

/// A cone pair whose Responder starts about two seconds late because the
/// Offer crossed a held signaling path: the Initiator's stages wait, and
/// the late Responder still classifies and lands its side of the
/// handshake.
#[tokio::test(start_paused = true)]
async fn late_responder_cone_punches() {
    let cfg = PunchConfig {
        stun_servers: Net::seeded("late_responder_cone_punches")
            .stun_server()
            .addrs
            .clone(),
        ..PunchConfig::default()
    };
    let (ra, rb) = skew_pair_retried(
        "late_responder_cone_punches",
        NatSpec::cone_apdf(),
        NatSpec::cone_apdf(),
        cfg,
        Arc::new(offer_hold(Duration::from_secs(2))),
        3,
    )
    .await;
    let pa = ra.expect("a on-time initiator punches");
    let pb = rb.expect("b late responder punches");
    common::assert_business_traffic(&pa, &pb).await;
}

/// A cone pair over a wire that drops everything: the probe phase cannot
/// confirm a mapping, so both sides fail by their phase deadlines, and
/// every mapping and socket is released.
#[tokio::test(start_paused = true)]
async fn dead_wire_fails_fast_and_releases() {
    use punch_hole::error::PunchError;

    let net = Net::seeded("dead_wire_fails_fast_and_releases");
    net.set_loss(1000);
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_apdf());
    let b = net.host(NatSpec::cone_apdf());
    let cfg = config(&stun);
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    // The wire blackholes STUN both ways, so the probe phase misses its
    // deadline. Whoever ends first closes the bridge, and the peer then
    // sees SignalingClosed instead of its own timeout.
    let bounded = |r: &Result<Punched<nat_lab::sim::SimSocket>, PunchFailure>| {
        matches!(
            r,
            Err(PunchFailure {
                error: PunchError::Timeout { .. } | PunchError::SignalingClosed,
                ..
            })
        )
    };
    assert!(bounded(&ra), "got {ra:?}");
    assert!(bounded(&rb), "got {rb:?}");
    net.wait_mappings_drained().await;
    assert_eq!(net.mapping_count(), 0, "no mapping outlives the failure");
}

/// A cone pair over a wire that both duplicates and delays: a duplicated
/// copy can land after the reply to the original, so duplicate handling
/// must hold one attempt while reordering reshuffles the rest.
#[tokio::test(start_paused = true)]
async fn duplicated_and_delayed_wire_still_punches() {
    let net = Net::seeded("duplicated_and_delayed_wire_still_punches");
    net.set_dup(200);
    net.set_delay(Duration::from_millis(20)..Duration::from_millis(120));
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_apdf());
    let b = net.host(NatSpec::cone_apdf());
    let cfg = config(&stun);
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    let pa = ra.expect("a punches over a duplicating delayed wire");
    let pb = rb.expect("b punches over a duplicating delayed wire");
    net.set_dup(0);
    net.set_delay(Duration::ZERO..Duration::ZERO);
    common::assert_business_traffic(&pa, &pb).await;
}

/// The stacked CGNAT chains over a wire that loses a fifth of every
/// crossing: the handshake retransmissions must cross two translations
/// and the lossy wire, and the winner path still carries business
/// traffic.
#[tokio::test(start_paused = true)]
async fn cgnat_chain_over_lossy_wire_still_punches() {
    let net = Net::seeded("cgnat_chain_over_lossy_wire_still_punches");
    net.set_loss(200);
    let stun = net.stun_server();
    let carrier_a = net.host(NatSpec::cone_eif());
    let carrier_b = net.host(NatSpec::cone_eif());
    let a = net.host_behind(&carrier_a, NatSpec::cone_eif());
    let b = net.host_behind(&carrier_b, NatSpec::cone_eif());
    let cfg = config(&stun);
    let (ra, rb) = common::punch_pair(a, cfg.clone(), b, cfg).await;
    let pa = ra.expect("a punches across a lossy chain");
    let pb = rb.expect("b punches across a lossy chain");
    assert!(net.dropped() > 0, "the wire dropped during the punch");
    net.set_loss(0);
    common::assert_business_traffic(&pa, &pb).await;
}
