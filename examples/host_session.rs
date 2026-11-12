//! One host side of a punch session, wired the way an application wires it.
//!
//! The library carries no signaling, so the host supplies the transport. This
//! example stands a pair of channels in for that transport and runs both sides
//! in one process; a real host dials its own ordered, authenticated channel and
//! runs one side per process. For an end-to-end run over real sockets behind
//! real NATs, use the `punch-demo` binary in `crates/punch-hole-demo`.

// The failure result carries the diagnostics inline on a path that runs at
// most once per attempt.
#![allow(clippy::result_large_err)]

use std::{future::Future, io, sync::Arc};

use bytes::Bytes;
use punch_hole::{
    NatInfo, PunchConfig, PunchError, PunchFailure, Punched, Puncher, Role, SessionEvent,
    keepalive::{KeepaliveGuard, spawn_io},
    msg,
};
use tokio::sync::mpsc;

/// The host's own channel to one peer: ordered, authenticated, replay-free.
///
/// The session never sees this type. It hands the host opaque frames and takes
/// peer frames back, which is the whole signaling contract.
trait Signaling {
    fn send(&mut self, frame: Bytes) -> impl Future<Output = io::Result<()>> + Send;
    fn recv(&mut self) -> impl Future<Output = io::Result<Bytes>> + Send;
}

/// A `Signaling` over a pair of channels, standing in for the host transport.
struct Channel {
    out: mpsc::Sender<Bytes>,
    inn: mpsc::Receiver<Bytes>,
}

impl Signaling for Channel {
    async fn send(&mut self, frame: Bytes) -> io::Result<()> {
        self.out
            .send(frame)
            .await
            .map_err(|_| io::Error::other("transport closed"))
    }

    async fn recv(&mut self) -> io::Result<Bytes> {
        self.inn
            .recv()
            .await
            .ok_or_else(|| io::Error::other("transport closed"))
    }
}

/// Moves frames between the bridge and the host transport until either closes.
///
/// A closed pump drops `HostEnd::from_peer`, which surfaces as
/// [`PunchError::SignalingClosed`] instead of stalling the session.
fn pump<S: Signaling + Send + 'static>(mut transport: S, host: punch_hole::HostEnd) {
    let punch_hole::HostEnd {
        mut to_peer,
        from_peer,
    } = host;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                frame = to_peer.recv() => {
                    let Some(frame) = frame else { break };
                    if transport.send(frame).await.is_err() {
                        break;
                    }
                },
                frame = transport.recv() => {
                    let Ok(frame) = frame else { break };
                    if from_peer.send(frame).await.is_err() {
                        break;
                    }
                },
            }
        }
    });
}

/// Drives one attempt and returns the winner.
///
/// Probe, Exchange, Negotiate, Punch, and Confirm run inside this call. A
/// failure comes back as [`PunchFailure`], which carries the evidence the
/// attempt had collected.
async fn attempt<S: Signaling + Send + 'static>(
    role: Role,
    config: PunchConfig,
    cached: Option<NatInfo>,
    transport: S,
) -> Result<Punched, PunchFailure> {
    // One bridge serves one attempt; a retry builds a fresh one.
    let (host_end, lib_end) = punch_hole::signaling::bridge(64);
    pump(transport, host_end);

    // Stage events are optional: they carry the progress a log line wants
    // without the host polling anything.
    let (events, mut received) = mpsc::channel(8);
    tokio::spawn(async move {
        while let Some(event) = received.recv().await {
            match event {
                SessionEvent::Probe(nat) => println!("{role:?}: local NAT {:?}", nat.v4_class()),
                SessionEvent::Exchange(nat) => println!("{role:?}: peer NAT {:?}", nat.v4_class()),
                SessionEvent::Negotiate(plan) => println!("{role:?}: plan {plan:?}"),
                _ => {},
            }
        }
    });

    let mut puncher = Puncher::new(config)?.with_events(events);
    if let Some(nat) = cached {
        // Skips Probe with a classification from an earlier attempt. The host
        // owns the freshness question.
        puncher = puncher.with_cached_nat(nat);
    }
    let session = puncher.with_signaling(lib_end);
    match role {
        Role::Initiator => session.initiator().await,
        Role::Responder => session.responder().await,
    }
}

/// What the host does after a failed attempt.
#[derive(Debug, Clone, Copy)]
enum Next {
    /// The failure was transient: a fresh attempt with a fresh nonce gets a
    /// new draw. Back off first, because the last attempt's mappings and
    /// conntrack entries age out in seconds.
    Retry,
    /// Another attempt cannot change this outcome. Fall back to the relay, or
    /// re-dial the peer.
    Stop,
}

fn next_step(failure: &PunchFailure) -> Next {
    match &failure.error {
        // No retry changes these: the model rates the pair below `min_success`,
        // the transport or the peer ended the attempt, there is no STUN
        // destination to query, the peer named an unusable target, or the
        // configuration is bad.
        PunchError::Unpunchable { .. }
        | PunchError::VersionMismatch { .. }
        | PunchError::SignalingClosed
        | PunchError::PeerAborted(_)
        | PunchError::NoStunDestination
        | PunchError::UnusableTarget { .. }
        | PunchError::InvalidConfig(_)
        | PunchError::Internal(_) => Next::Stop,
        // A burst that missed, a lossy wire, or resource pressure.
        _ => Next::Retry,
    }
}

/// The aftermath a successful attempt hands the host.
///
/// The winner is a plain UDP socket. Business traffic shares it with late
/// handshake retransmissions and heartbeat beats, so the receive side drops
/// packets that decode as this attempt's protocol before it parses its own.
async fn carry(role: Role, punched: Punched<tokio::net::UdpSocket>) -> io::Result<()> {
    let report = &punched.report;
    println!(
        "{role:?}: peer {} via {:?} (local {:?}, estimate {:?}, {} ms)",
        punched.peer_addr,
        report.strategy,
        report.local_class,
        report.success_estimate,
        report.phase_ms.total_ms
    );

    let socket = Arc::new(punched.socket);
    // Holds the mapping open while the business layer idles.
    let _keepalive: KeepaliveGuard = spawn_io(Arc::clone(&socket), punched.peer_addr, report.nonce);

    socket
        .send_to(b"hello over the punched path", punched.peer_addr)
        .await?;
    let mut buf = [0u8; 2048];
    let from = loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        if msg::is_attempt_packet(&buf[..n], report.nonce) {
            continue;
        }
        println!("{role:?}: [{from}] {}", String::from_utf8_lossy(&buf[..n]));
        break from;
    };
    // Answer once and leave on a send. A side that leaves right after a
    // receive closes its port while the peer may still be waiting.
    socket.send_to(b"ack", from).await?;
    Ok(())
}

/// One side: attempt, act on the outcome, then run business traffic.
async fn run<S: Signaling + Send + 'static>(
    role: Role,
    config: PunchConfig,
    cached: Option<NatInfo>,
    transport: S,
) -> Result<(), PunchFailure> {
    let punched = match attempt(role, config, cached, transport).await {
        Ok(punched) => punched,
        Err(failure) => {
            println!("{role:?}: {failure}");
            println!("{role:?}: evidence {:?}", failure.diagnostics);
            println!("{role:?}: next step {:?}", next_step(&failure));
            return Err(failure);
        },
    };
    if let Err(error) = carry(role, punched).await {
        println!("{role:?}: business traffic ended: {error}");
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    // A host that wants an attempt to land aims the burst sizing up; the
    // library default targets 0.5.
    let config = PunchConfig {
        target_success: 0.9,
        ..PunchConfig::default()
    };

    // The stand-in transport. Two channels in one process replace the host's
    // own control channel.
    let (to_responder, from_initiator) = mpsc::channel(64);
    let (to_initiator, from_responder) = mpsc::channel(64);
    let initiator = Channel {
        out: to_responder,
        inn: from_responder,
    };
    let responder = Channel {
        out: to_initiator,
        inn: from_initiator,
    };

    let initiator = tokio::spawn(run(Role::Initiator, config.clone(), None, initiator));
    let responder = tokio::spawn(run(Role::Responder, config, None, responder));
    for side in [initiator, responder] {
        match side.await.expect("the side task panicked") {
            Ok(()) => {},
            Err(failure) => println!("session ended: {failure}"),
        }
    }
}
