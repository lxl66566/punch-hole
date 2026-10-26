#![allow(clippy::field_reassign_with_default)]

//! Signaling contract, data-plane isolation, and error cases.

mod common;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use common::config;
use punch_hole::{
    FilterClass, PunchConfig, Puncher,
    error::PunchError,
    msg::{DataPacket, Frame, encode_packet},
    sim::{Mapping, NatSpec, Net},
    socket::{UdpFactory, UdpIo},
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
        // Replace the second frame that crosses in either direction. The
        // version byte stays valid so the garbage reaches the body decoder.
        if tap_seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
            Some(vec![punch_hole::msg::VERSION, 0xff, 0xfe])
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

/// Foreign-attempt packets that reach a live punch socket are counted as
/// stale and ignored.
///
/// The gate holds the responder's PortUpdate back, which parks both engines
/// in the Punch phase: the initiator has no target to sweep at, and the
/// responder's pulses die in the initiator's port-dependent NAT. The
/// injection therefore lands on sockets that stay open, and the count on
/// the report is exact.
#[tokio::test(start_paused = true)]
async fn stale_attempt_injection_is_counted_and_ignored() {
    // Injection rounds, one Syn and one Ack per external endpoint each.
    const ROUNDS: u32 = 3;
    let net = Net::seeded("stale_attempt");
    let stun = net.stun_server();
    // The initiator NAT drops inbound from unknown sources, so it never
    // sees the injected packets. The responder NAT passes any source.
    // A distinct port range keeps the two external endpoints apart.
    let a = net.host(NatSpec::cone_apdf());
    let b = net.host(NatSpec {
        mapping: Mapping::Cone,
        filtering: FilterClass::EndpointIndependent,
        port_range: 2048..65535,
    });

    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    let (open_tx, open_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (port_tx, mut port_rx) = tokio::sync::mpsc::channel::<u16>(1);
    gate_port_updates(ha, hb, open_rx, port_tx);

    let a = tokio::spawn(common::run_initiator(a, config(&stun), la));
    let b = tokio::spawn(common::run_responder(b, config(&stun), lb));

    // The first held PortUpdate names the responder's punch port, so its
    // mapping is already live when this resolves.
    let b_port = port_rx.recv().await.expect("gate task alive");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while net.mappings_snapshot().len() < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let snap = net.mappings_snapshot();
    assert_eq!(snap.len(), 2, "one live punch mapping per side");
    let b_ext = snap
        .iter()
        .map(|(_, ext)| *ext)
        .find(|ext| ext.port() == b_port)
        .expect("responder mapping present");
    let a_ext = snap
        .iter()
        .map(|(_, ext)| *ext)
        .find(|ext| ext.port() != b_port)
        .expect("initiator mapping present");

    // A third public host injects well-formed packets of a foreign attempt.
    let attacker = net.public_host();
    let attacker = attacker
        .bind(SocketAddr::from(([0, 0, 0, 0], 0)))
        .await
        .expect("attacker socket binds");
    let wrong = [0x5a; 16];
    let syn = encode_packet(&DataPacket::Syn {
        nonce: wrong,
        socket: 9,
    });
    let ack = encode_packet(&DataPacket::Ack { nonce: wrong });
    for _ in 0..ROUNDS {
        attacker.send_to(&syn, b_ext).await.expect("syn injects");
        attacker.send_to(&ack, b_ext).await.expect("ack injects");
        attacker.send_to(&syn, a_ext).await.expect("syn injects");
        attacker.send_to(&ack, a_ext).await.expect("ack injects");
    }

    // The engines drain the injected packets before the handshake may run.
    tokio::time::sleep(Duration::from_millis(300)).await;
    open_tx.send(()).await.expect("gate task alive");

    let pa = a.await.expect("initiator task").expect("punch succeeds");
    let pb = b.await.expect("responder task").expect("punch succeeds");
    assert_eq!(pb.report.stale_packets, 2 * ROUNDS);
    assert_eq!(
        pa.report.stale_packets, 0,
        "the initiator NAT filtered them"
    );
    common::assert_business_traffic(&pa, &pb).await;
}

/// Forwards every frame, except PortUpdate frames from the second end,
/// which are held back until a message arrives on `open`.
///
/// The first held PortUpdate publishes its external port on `ports`, which
/// tells the test that the sender's punch socket and mapping are live.
fn gate_port_updates(
    a: punch_hole::signaling::HostEnd,
    b: punch_hole::signaling::HostEnd,
    mut open_rx: tokio::sync::mpsc::Receiver<()>,
    port_tx: tokio::sync::mpsc::Sender<u16>,
) {
    let mut a_to_b = a.to_peer;
    let b_from_a = b.from_peer;
    tokio::spawn(async move {
        while let Some(frame) = a_to_b.recv().await {
            let _ = b_from_a.send(frame).await;
        }
    });

    let mut b_to_a = b.to_peer;
    let a_from_b = a.from_peer;
    tokio::spawn(async move {
        let mut held = Vec::new();
        let mut opened = false;
        let mut reported = false;
        loop {
            tokio::select! {
                frame = b_to_a.recv() => {
                    let Some(frame) = frame else { break };
                    let update = punch_hole::msg::decode_sig(&frame).ok().filter(|f| {
                        matches!(f.body, Frame::PortUpdate { .. })
                    });
                    match update {
                        Some(f) if !opened => {
                            if let Frame::PortUpdate { ports: fresh } = f.body {
                                if let Some(port) = fresh.first() && !reported {
                                    // The test waits for this before injecting.
                                    let _ = port_tx.send(*port).await;
                                    reported = true;
                                }
                            }
                            held.push(frame);
                        },
                        _ => {
                            let _ = a_from_b.send(frame).await;
                        },
                    }
                },
                _ = open_rx.recv() => {
                    opened = true;
                    for frame in held.drain(..) {
                        let _ = a_from_b.send(frame).await;
                    }
                },
            }
        }
    });
}
