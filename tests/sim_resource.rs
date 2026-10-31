#![allow(clippy::field_reassign_with_default)]

//! Rate limits, budgets, conntrack bounds, and cleanup.

mod common;

use common::config;
use nat_lab::sim::{NatSpec, Net};
use punch_hole::error::{PunchError, PunchFailure};

type SimResult = Result<punch_hole::Punched<nat_lab::sim::SimSocket>, PunchFailure>;

#[tokio::test(start_paused = true)]
async fn budget_exhaustion_releases_sockets() {
    let net = Net::seeded("budget_exhausted");
    let stun = net.stun_server();
    let mut cfg = config(&stun);
    cfg.packet_budget = 4;
    let a = net.host(NatSpec::sequential(2));
    let b = net.host(NatSpec::sequential(2));

    let (ra, rb) = common::punch_pair(a, cfg, b, config(&stun)).await;
    let failure = ra.expect_err("budget runs out");
    assert!(
        matches!(failure.error, PunchError::BudgetExhausted),
        "got {:?}",
        failure.error
    );
    // The engine failed after every earlier phase completed, so the
    // diagnostics carry both classifications and the agreed plan.
    let d = &failure.diagnostics;
    assert!(d.local.is_some() && d.peer.is_some());
    assert!(d.selection.is_some() && d.nonce.is_some());
    assert!(d.phase_ms.total_ms > 0);
    // The initiator told the peer, so the responder fails fast too.
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
        matches!(
            ra,
            Err(PunchFailure {
                error: PunchError::ConntrackExhausted,
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
    let bounded = |r: &SimResult| {
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
    assert_eq!(net.mapping_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn overall_deadline_bounds_the_engine() {
    let (net, stun, a, b) = common::cone_net("overall_bounds");
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    // PortUpdate never crosses, so both engines would otherwise idle to
    // their 15 second punch timeout.
    common::connect_then_blackhole(ha, hb);
    let mut cfg = config(&stun);
    cfg.punch_timeout = std::time::Duration::from_secs(15);
    cfg.overall_deadline = std::time::Duration::from_secs(3);

    let start = tokio::time::Instant::now();
    let a = tokio::spawn(common::run_initiator(a, cfg.clone(), la));
    let b = tokio::spawn(common::run_responder(b, cfg, lb));
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    let bounded = |r: &SimResult| {
        matches!(
            r,
            Err(PunchFailure {
                error: PunchError::Timeout { .. }
                    | PunchError::SignalingClosed
                    | PunchError::PeerAborted(_),
                ..
            })
        )
    };
    assert!(bounded(&ra), "got {ra:?}");
    assert!(bounded(&rb), "got {rb:?}");
    // The session ends on its wall-clock limit, far under the punch timeout.
    assert!(
        start.elapsed() < std::time::Duration::from_secs(6),
        "session ran {} ms",
        start.elapsed().as_millis()
    );
    net.wait_mappings_drained().await;
    assert_eq!(net.mapping_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn stuck_host_channel_bounds_the_engine() {
    let (net, stun, a, b) = common::cone_net("stuck_engine");
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(4);
    // The initiator's pump relays the setup frames and drops the rest, so
    // no announced port ever crosses and neither engine can sweep.
    let mut a_out = ha.to_peer;
    let b_in = hb.from_peer;
    tokio::spawn(async move {
        while let Some(frame) = a_out.recv().await {
            let setup = punch_hole::msg::decode_sig(&frame).is_ok_and(|f| {
                matches!(
                    f.body,
                    punch_hole::msg::Frame::Hello(_) | punch_hole::msg::Frame::Offer(_)
                )
            });
            if setup {
                let _ = b_in.send(frame).await;
            }
        }
    });
    // The responder's pump drains through negotiation, then parks on the
    // first engine frame with the channel held: every later PortUpdate
    // resend queues into a channel nothing drains anymore.
    let mut b_out = hb.to_peer;
    let a_in = ha.from_peer;
    tokio::spawn(async move {
        while let Some(frame) = b_out.recv().await {
            let setup = punch_hole::msg::decode_sig(&frame).is_ok_and(|f| {
                matches!(
                    f.body,
                    punch_hole::msg::Frame::Hello(_) | punch_hole::msg::Frame::Accept
                )
            });
            if !setup {
                std::future::pending::<()>().await;
            }
            let _ = a_in.send(frame).await;
        }
    });

    let mut cfg = config(&stun);
    cfg.punch_timeout = std::time::Duration::from_secs(15);
    cfg.overall_deadline = std::time::Duration::from_secs(4);
    let start = tokio::time::Instant::now();
    let a = tokio::spawn(common::run_initiator(a, cfg.clone(), la));
    let b = tokio::spawn(common::run_responder(b, cfg, lb));
    // Without the send bound the responder parks forever inside its
    // PortUpdate resend and neither join handle settles.
    let ra = tokio::time::timeout(std::time::Duration::from_secs(120), a)
        .await
        .expect("initiator session ends")
        .unwrap();
    let rb = tokio::time::timeout(std::time::Duration::from_secs(120), b)
        .await
        .expect("responder session ends")
        .unwrap();
    let bounded = |r: &SimResult| {
        matches!(
            r,
            Err(PunchFailure {
                error: PunchError::Timeout { .. }
                    | PunchError::SignalingClosed
                    | PunchError::PeerAborted(_),
                ..
            })
        )
    };
    assert!(bounded(&ra), "got {ra:?}");
    assert!(bounded(&rb), "got {rb:?}");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(8),
        "sessions ran {} ms",
        start.elapsed().as_millis()
    );
    net.wait_mappings_drained().await;
    assert_eq!(net.mapping_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn engine_start_never_sleeps_past_overall() {
    let (net, stun, a, b) = common::cone_net("clamp_start");
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    // Rewrite the Offer's start delay to the honored 10 second cap, far
    // past the session wall, so the shared start has to clamp.
    punch_hole::signaling::connect_with(ha, hb, |frame| {
        let frame = punch_hole::msg::decode_sig(frame).ok()?;
        let body = match frame.body {
            punch_hole::msg::Frame::Offer(mut offer) => {
                offer.start_delay_ms = 10_000;
                punch_hole::msg::Frame::Offer(offer)
            },
            body => body,
        };
        Some(punch_hole::msg::encode_sig(&punch_hole::msg::SigFrame {
            ts: frame.ts,
            echo: frame.echo,
            body,
        }))
    });
    let mut cfg = config(&stun);
    cfg.probe_timeout = std::time::Duration::from_secs(1);
    cfg.overall_deadline = std::time::Duration::from_secs(2);

    let start = tokio::time::Instant::now();
    let a = tokio::spawn(common::run_initiator(a, cfg.clone(), la));
    let b = tokio::spawn(common::run_responder(b, cfg, lb));
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    let bounded = |r: &SimResult| {
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
    // Without the clamp the responder sleeps the full offered delay first
    // and only then times out, ten seconds past the wall.
    assert!(
        start.elapsed() < std::time::Duration::from_secs(4),
        "sessions ran {} ms",
        start.elapsed().as_millis()
    );
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
