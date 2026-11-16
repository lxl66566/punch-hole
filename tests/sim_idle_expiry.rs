#![allow(clippy::field_reassign_with_default)]

//! Session-level idle-expiry coverage: the punch engine's STUN refresh
//! keeps a short-lived NAT mapping alive until its answer lands.

mod common;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use common::config;
use nat_lab::sim::{NatSpec, Net, StunServer};
use punch_hole::{
    NatClass, StrategyId,
    error::{PunchError, PunchFailure},
    msg::decode_sig,
};

/// One-way delay the signaling pump adds to every frame. The measured RTT
/// of ~500 ms pushes the cone spray's peer-warm hold (RTT plus one tick)
/// to ~550 ms past the engine start, which is what leaves the refresh
/// crossings as the cone mapping's only traffic.
const SIG_DELAY: Duration = Duration::from_millis(250);

/// Wire delay the data plane takes once the Offer crossed. Doubled on the
/// round trip, it lands the refresh answer 400 ms after the query.
const WIRE_DELAY: Duration = Duration::from_millis(200);

/// Two sim STUN servers, so the cone reading spans two server IPs and
/// stays confident: the pair routes to SymProbe with the easy side
/// shooting and the cone spraying.
fn two_server_stun(net: &Net) -> StunServer {
    let mut addrs = net.stun_server().addrs;
    addrs.extend(net.stun_server().addrs);
    StunServer {
        addrs,
        other_addrs: Vec::new(),
    }
}

/// Wires the pair through a pump that delays each frame `SIG_DELAY` per
/// direction. The pump arms the data-plane wire delay when the Offer
/// crosses and lifts it when the first Confirmed does: both probes ran at
/// zero delay, the punch window that follows carries the delay, and the
/// business round trip after Confirmed runs clean — one exchange has no
/// refresh crossings to bridge a silence longer than the idle expiry, so
/// a delayed PONG would die on an evicted winner mapping.
fn slow_delaying_channel(
    net: &Net,
    ha: punch_hole::signaling::HostEnd,
    hb: punch_hole::signaling::HostEnd,
) {
    let mut a_out = ha.to_peer;
    let b_in = hb.from_peer;
    let net_a = net.clone();
    let armed = Arc::new(AtomicBool::new(false));
    let armed_a = Arc::clone(&armed);
    tokio::spawn(async move {
        while let Some(frame) = a_out.recv().await {
            match decode_sig(&frame).map(|f| f.body) {
                Ok(punch_hole::msg::Frame::Offer(_)) if !armed_a.load(Ordering::Relaxed) => {
                    armed_a.store(true, Ordering::Relaxed);
                    net_a.set_delay(WIRE_DELAY..WIRE_DELAY);
                },
                // The first winner confirm ends the punch window the delay
                // exists to slow; the fastest confirm wins the lift.
                Ok(punch_hole::msg::Frame::Confirmed { .. }) => {
                    net_a.set_delay(Duration::ZERO..Duration::ZERO);
                },
                _ => {},
            }
            tokio::time::sleep(SIG_DELAY).await;
            let _ = b_in.send(frame).await;
        }
    });
    let mut b_out = hb.to_peer;
    let a_in = ha.from_peer;
    let net_b = net.clone();
    tokio::spawn(async move {
        while let Some(frame) = b_out.recv().await {
            if matches!(
                decode_sig(&frame).map(|f| f.body),
                Ok(punch_hole::msg::Frame::Confirmed { .. })
            ) {
                net_b.set_delay(Duration::ZERO..Duration::ZERO);
            }
            tokio::time::sleep(SIG_DELAY).await;
            let _ = a_in.send(frame).await;
        }
    });
}

/// Runs the easy-symmetric initiator against the cone responder over the
/// delayed channel, with the idle expiry armed before the session.
async fn delayed_pair(
    net: &Net,
    idle_expiry: Duration,
) -> (
    Result<punch_hole::Punched<nat_lab::sim::SimSocket>, PunchFailure>,
    Result<punch_hole::Punched<nat_lab::sim::SimSocket>, PunchFailure>,
) {
    net.set_idle_expiry(idle_expiry);
    let stun = two_server_stun(net);
    let a = net.host(NatSpec::sequential(2));
    let b = net.host(NatSpec::cone_apdf());
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    slow_delaying_channel(net, ha, hb);
    let a = tokio::spawn(common::run_initiator(a, config(&stun), la));
    let b = tokio::spawn(common::run_responder(b, config(&stun), lb));
    (
        a.await.expect("initiator task panicked"),
        b.await.expect("responder task panicked"),
    )
}

/// A cone NAT that evicts mappings after 320 ms of silence, against the
/// punch plan's refresh schedule. The engine sends the refresh query on
/// the first punch tick and retransmits on the confirm cadence of 200 ms;
/// with a 200 ms wire delay per direction the answer lands 400 ms after
/// the query, past the expiry. The cone's own sweep holds for the peer's
/// PortUpdate until RTT plus one tick (~550 ms), so in the critical
/// window the refresh crossings are the mapping's only traffic. Timeline
/// from the cone's engine start: t=50 query, t=250 and t=450 retransmits,
/// t=450 answer, t=550 own sweep — every gap under the 320 ms expiry.
/// Without the retransmissions the query's crossing alone would evict the
/// mapping at t=370 (reaper tick t=400), and the answer would find no
/// mapping to land on: no announce, no pulse to aim at, no punch.
#[tokio::test(start_paused = true)]
async fn refresh_keeps_a_short_lived_mapping_alive_until_its_answer() {
    let net = Net::seeded("refresh_idle_window");
    let (ra, rb) = delayed_pair(&net, Duration::from_millis(320)).await;
    let pa = ra.expect("the refresh crossings carry the pair");
    let pb = rb.expect("peer side punches");
    assert_eq!(pa.report.strategy, StrategyId::SymProbe);
    assert_eq!(pb.report.strategy, StrategyId::SymProbe);
    assert_eq!(pa.report.local_class, Some(NatClass::EasySym { step: 2 }));
    assert_eq!(pb.report.local_class, Some(NatClass::Cone));
    common::assert_business_traffic(&pa, &pb).await;
}

/// The same pair with the expiry at 50 ms, far below the refresh cadence:
/// every refresh mapping evicts before an answer can land, so the cone
/// never announces a port and the session fails fast on the exhausted
/// refresh instead of parking until the phase deadline.
#[tokio::test(start_paused = true)]
async fn expiry_below_the_refresh_cadence_fails_fast() {
    let net = Net::seeded("refresh_idle_too_short");
    let t = tokio::time::Instant::now();
    let (ra, rb) = delayed_pair(&net, Duration::from_millis(50)).await;
    // The cone side needs the answer and reports the exhaustion.
    assert!(
        matches!(
            rb,
            Err(PunchFailure {
                error: PunchError::RefreshExhausted,
                ..
            })
        ),
        "got {rb:?}"
    );
    // The shooter learns the failure through the cone's Abort.
    assert!(
        matches!(
            ra,
            Err(PunchFailure {
                error: PunchError::PeerAborted(_),
                ..
            })
        ),
        "got {ra:?}"
    );
    // Retries exhaust at four attempts; the failure is bounded far below
    // the punch window.
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "the failure parked {} ms",
        t.elapsed().as_millis()
    );
}
