#![allow(clippy::field_reassign_with_default)]

//! Signaling contract cases against the simulator.

mod common;

use std::sync::Arc;

use common::config;
use punch_hole::{
    PunchConfig, Puncher,
    error::PunchError,
    sim::{Mapping, NatSpec, Net},
};
use rand::SeedableRng;

#[tokio::test(start_paused = true)]
async fn bridge_closed_by_host_fails_fast() {
    let net = Net::seeded("bridge_closed_by_host");
    let stun = net.stun_server();
    let host = net.host(NatSpec::cone_eif());
    let (host_end, lib_end) = punch_hole::signaling::bridge(64);
    // The host transport disappears before the session sends anything.
    drop(host_end);

    let err = common::run_initiator(host, config(&stun), lib_end)
        .await
        .unwrap_err();
    assert!(matches!(err, PunchError::SignalingClosed), "got {err:?}");
}

#[tokio::test(start_paused = true)]
async fn both_sides_initiator_abort_with_role_conflict() {
    let net = Net::seeded("dual_initiator");
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_eif());
    let b = net.host(NatSpec::cone_eif());
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    punch_hole::sim::connect(ha, hb);

    let a = tokio::spawn(common::run_initiator(a, config(&stun), la));
    let b = tokio::spawn(common::run_initiator(b, config(&stun), lb));
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());

    assert!(matches!(ra, Err(PunchError::PeerAborted(_))), "got {ra:?}");
    assert!(matches!(rb, Err(PunchError::PeerAborted(_))), "got {rb:?}");
}

#[tokio::test(start_paused = true)]
async fn version_mismatch_fails_both_sides() {
    let net = Net::seeded("version_mismatch");
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_eif());
    let b = net.host(NatSpec::cone_eif());
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    punch_hole::sim::connect_with(ha, hb, |frame| {
        let mut bytes = frame.to_vec();
        bytes[0] = 9;
        Some(bytes)
    });

    let a = tokio::spawn(common::run_initiator(a, config(&stun), la));
    let b = tokio::spawn(common::run_responder(b, config(&stun), lb));
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());

    assert!(
        matches!(ra, Err(PunchError::VersionMismatch { .. })),
        "got {ra:?}"
    );
    assert!(
        matches!(rb, Err(PunchError::VersionMismatch { .. })),
        "got {rb:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn malformed_frame_fails_one_side() {
    let net = Net::seeded("malformed_frame");
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_eif());
    let b = net.host(NatSpec::cone_eif());
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let tap_seen = Arc::clone(&seen);
    punch_hole::sim::connect_with(ha, hb, move |frame| {
        // Replace the second frame that crosses in either direction.
        if tap_seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            Some(vec![1, 0xff, 0xfe])
        } else {
            Some(frame.to_vec())
        }
    });

    let a = tokio::spawn(common::run_initiator(a, config(&stun), la));
    let b = tokio::spawn(common::run_responder(b, config(&stun), lb));
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());

    // Exactly one side received the garbage; the other lost its peer.
    let a_bad = matches!(ra, Err(PunchError::BadFrame));
    let b_bad = matches!(rb, Err(PunchError::BadFrame));
    assert!(a_bad ^ b_bad, "got {ra:?} / {rb:?}");
    assert!(ra.is_err() && rb.is_err());
}

#[tokio::test(start_paused = true)]
async fn lossy_bridge_still_completes() {
    let net = Net::seeded("lossy_bridge");
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_eif());
    let b = net.host(NatSpec::cone_eif());
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    // 30 percent frame loss on the host channel, decided by a private
    // generator so the net's seed stays untouched.
    let rng = Arc::new(std::sync::Mutex::new(rand::rngs::StdRng::seed_from_u64(
        0x00c0_ffee,
    )));
    punch_hole::sim::connect_with(ha, hb, move |frame| {
        use rand::prelude::*;
        let keep = rng.lock().expect("loss rng").random::<f32>() >= 0.3;
        keep.then(|| frame.to_vec())
    });

    let a = tokio::spawn(common::run_initiator(a, config(&stun), la));
    let b = tokio::spawn(common::run_responder(b, config(&stun), lb));
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    ra.expect("initiator succeeds through loss");
    rb.expect("responder succeeds through loss");
}

#[tokio::test(start_paused = true)]
async fn duplicated_frames_run_one_attempt() {
    let net = Net::seeded("duplicated_frames");
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_eif());
    let b = net.host(NatSpec::cone_eif());

    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    duplicate_pump(ha, hb);

    let cfg = config(&stun);
    let a = tokio::spawn(common::run_initiator(a, cfg.clone(), la));
    let b = tokio::spawn(common::run_responder(b, cfg, lb));
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    let pa = ra.expect("duplicates do not break the initiator");
    let pb = rb.expect("duplicates do not break the responder");
    common::assert_business_traffic(&pa, &pb).await;
}

fn duplicate_pump(a: punch_hole::signaling::HostEnd, b: punch_hole::signaling::HostEnd) {
    let mut a_to_b = a.to_peer;
    let b_from_a = b.from_peer;
    tokio::spawn(async move {
        while let Some(frame) = a_to_b.recv().await {
            // Every frame crosses twice; handling is idempotent.
            let _ = b_from_a.send(frame.clone()).await;
            let _ = b_from_a.send(frame).await;
        }
    });
    let mut b_to_a = b.to_peer;
    let a_from_b = a.from_peer;
    tokio::spawn(async move {
        while let Some(frame) = b_to_a.recv().await {
            let _ = a_from_b.send(frame.clone()).await;
            let _ = a_from_b.send(frame).await;
        }
    });
}

#[tokio::test(start_paused = true)]
async fn bad_config_is_rejected() {
    let mut empty_stun = PunchConfig::default();
    empty_stun.stun_servers.clear();
    assert!(matches!(
        Puncher::new(empty_stun),
        Err(PunchError::InvalidConfig(_))
    ));

    let mut zero_budget = PunchConfig::default();
    zero_budget.packet_budget = 0;
    assert!(matches!(
        Puncher::new(zero_budget),
        Err(PunchError::InvalidConfig(_))
    ));

    let mut zero_sockets = PunchConfig::default();
    zero_sockets.assistant_sockets = 0;
    assert!(matches!(
        Puncher::new(zero_sockets),
        Err(PunchError::InvalidConfig(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn sequential_nat_produces_stepped_allocations() {
    // Sanity for the Mapping::Sequential engine of the simulator itself.
    let net = Net::seeded("sequential_alloc");
    let stun = net.stun_server();
    let host = net.host(NatSpec::sequential(2));
    let (ra, _) = {
        let b = net.host(NatSpec::sequential(2));
        common::punch_pair(host, config(&stun), b, config(&stun)).await
    };
    let report = ra.expect("easy pair punches").report;
    assert_eq!(report.local_class, punch_hole::NatClass::EasySym {
        step: 2
    });
    let _ = Mapping::Cone;
}
