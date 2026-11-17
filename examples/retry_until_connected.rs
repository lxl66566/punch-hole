//! Retry until the peer shows up: the dialer loops, the answerer waits.
//!
//! One session is one attempt. A host that dials owns the retry loop
//! around it: a fresh bridge and a fresh nonce per try, backoff between
//! tries, and a triage of each failure that says whether a retry can
//! change the outcome at all. The answering side can instead run one
//! patient session, because every phase window is a config knob: an
//! exchange window long enough to cover the dialer's whole retry loop
//! needs no loop of its own.
//!
//! The stand-in rendezvous pairs each attempt's bridge with whatever waits
//! on the other side, newest registration wins, which is how a relay
//! retires a slot whose client went silent. The responder comes online
//! mid-loop, inside the second attempt's exchange window, so the first
//! attempt fails for real and the loop earns its keep.
//!
//! ```sh
//! cargo run --example retry_until_connected
//! ```

// The failure result carries the diagnostics inline on a path that runs at
// most once per attempt.
#![allow(clippy::result_large_err)]

use std::time::Duration;

use bytes::Bytes;
use punch_hole::{
    NatInfo, PunchConfig, PunchError, PunchFailure, Punched, Puncher, signaling::HostEnd,
};
use tokio::{sync::mpsc, time::sleep};

/// The dialer gives up after this many attempts.
const MAX_ATTEMPTS: usize = 5;
/// Pause between attempts. The NAT mappings and conntrack entries of the
/// last attempt age out in seconds, and a retry that lands inside their
/// lifetime inherits their noise.
const BACKOFF: Duration = Duration::from_secs(1);
/// The dialer's exchange window: how long one attempt waits for the peer
/// before failing over to the next.
const EXCHANGE: Duration = Duration::from_secs(2);
/// When the responder joins, counted from the shared start after the
/// one-time probe. The value lands inside the second attempt's window:
/// past the first attempt's death and its replacement by the second
/// registration, with margin to both sides, so the pairing is the live
/// second attempt and not the dead first end.
const RESPONDER_DELAY: Duration = Duration::from_millis(3_500);

/// One attempt's registration with the rendezvous.
enum Registration {
    Initiator(HostEnd),
    Responder(HostEnd),
}

/// Stands in for a rendezvous relay: an attempt registers its bridge on
/// arrival, the newest registration on each side replaces an unpaired
/// older one, and a matched pair wires together losslessly.
#[derive(Clone)]
struct Rendezvous {
    register: mpsc::UnboundedSender<Registration>,
}

impl Rendezvous {
    /// Creates the rendezvous and its pairing task.
    fn new() -> Self {
        let (register, mut queue) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (mut initiator, mut responder) = (None, None);
            while let Some(reg) = queue.recv().await {
                // An arriving end pairs with whatever waits on the other
                // side; otherwise it parks, and parking replaces the
                // previous unpaired end of its own side, whose attempt
                // already ended.
                match reg {
                    Registration::Initiator(end) => {
                        if let Some(waiting) = responder.take() {
                            wire(end, waiting);
                        } else {
                            initiator = Some(end);
                        }
                    },
                    Registration::Responder(end) => {
                        if let Some(waiting) = initiator.take() {
                            wire(waiting, end);
                        } else {
                            responder = Some(end);
                        }
                    },
                }
            }
        });
        Self { register }
    }

    /// Registers one attempt's host end with the rendezvous.
    fn register(&self, reg: Registration) {
        let _ = self.register.send(reg);
    }
}

/// Wires two host ends together losslessly, standing in for the paired
/// channel a relay hands its two clients.
fn wire(a: HostEnd, b: HostEnd) {
    forward(a.to_peer, b.from_peer);
    forward(b.to_peer, a.from_peer);
}

/// Carries frames one way between two channel ends until either drops.
fn forward(mut from: mpsc::Receiver<Bytes>, to: mpsc::Sender<Bytes>) {
    tokio::spawn(async move {
        while let Some(frame) = from.recv().await {
            if to.send(frame).await.is_err() {
                break;
            }
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), PunchFailure> {
    // Classify once, up front. Every attempt reuses the reading through
    // `with_cached_nat`, so a retry skips Probe and starts straight at
    // Exchange; a host refreshes the cache when the network may have
    // changed under it.
    let config = PunchConfig {
        exchange_timeout: EXCHANGE,
        ..PunchConfig::default()
    };
    let nat = Puncher::new(config.clone())?.probe().await?;
    println!(
        "local NAT {:?}; dialing with a {EXCHANGE:?} exchange window",
        nat.v4_class()
    );

    let rendezvous = Rendezvous::new();

    // The answering side joins late and then runs one patient session:
    // its exchange window is the 10 s default, so whatever attempt finds
    // it has time to land.
    let responder = {
        let rendezvous = rendezvous.clone();
        let nat = nat.clone();
        tokio::spawn(async move {
            sleep(RESPONDER_DELAY).await;
            println!("responder: joining");
            answer(rendezvous, nat).await
        })
    };

    let dialer = dial(rendezvous, config, nat).await?;
    let answerer = responder.await.expect("the responder task joined")?;
    for (side, punched) in [("dialer", dialer), ("answerer", answerer)] {
        println!(
            "{side}: peer {} via {:?} in {} ms",
            punched.peer_addr, punched.report.strategy, punched.report.phase_ms.total_ms
        );
    }
    Ok(())
}

/// Drives attempts until one lands, the triage says stop, or the attempts
/// run out.
async fn dial(
    rendezvous: Rendezvous,
    config: PunchConfig,
    mut cached: NatInfo,
) -> Result<Punched, PunchFailure> {
    let mut attempt = 1;
    loop {
        // Fresh bridge and fresh registration per attempt: the nonce is
        // drawn per attempt too, so a new attempt never reuses one.
        let (host_end, lib_end) = punch_hole::signaling::bridge(64);
        rendezvous.register(Registration::Initiator(host_end));

        let attempt_session = Puncher::new(config.clone())?.with_cached_nat(cached.clone());
        match attempt_session.with_signaling(lib_end).initiator().await {
            Ok(punched) => {
                println!(
                    "attempt {attempt}: connected via {:?}",
                    punched.report.strategy
                );
                return Ok(punched);
            },
            Err(failure) => {
                // The failure carries the classification it had, so the
                // next attempt reuses it instead of probing again.
                if let Some(nat) = &failure.diagnostics.local {
                    cached = nat.clone();
                }
                // The populated diagnostics name the failing phase: a
                // local reading with no peer says Exchange starved.
                println!(
                    "attempt {attempt}: {failure} (peer {:?}, plan {:?})",
                    failure.diagnostics.peer.as_ref().map(NatInfo::v4_class),
                    failure.diagnostics.selection,
                );
                if attempt == MAX_ATTEMPTS || !retryable(&failure.error) {
                    return Err(failure);
                }
                println!("attempt {attempt}: backing off {BACKOFF:?}");
                sleep(BACKOFF).await;
                attempt += 1;
            },
        }
    }
}

/// The answering side: register once, then wait out the whole dialer loop
/// inside one session.
async fn answer(rendezvous: Rendezvous, nat: NatInfo) -> Result<Punched, PunchFailure> {
    let (host_end, lib_end) = punch_hole::signaling::bridge(64);
    rendezvous.register(Registration::Responder(host_end));
    Puncher::new(PunchConfig::default())?
        .with_cached_nat(nat)
        .with_signaling(lib_end)
        .responder()
        .await
}

/// Whether a fresh attempt can change this outcome.
fn retryable(error: &PunchError) -> bool {
    match error {
        // A phase ran out of time, the burst missed its draw, or resources
        // ran out: a fresh attempt redraws and gets fresh budgets.
        PunchError::Timeout { .. }
        | PunchError::BudgetExhausted
        | PunchError::ConntrackExhausted
        | PunchError::ConfirmFailed
        | PunchError::PoolStopped
        | PunchError::RefreshUnavailable
        | PunchError::RefreshExhausted
        | PunchError::BindFailed { .. }
        | PunchError::Io { .. } => true,
        // The model rates the pair below `min_success`, the peer runs
        // another version or ended the attempt, the transport is gone, or
        // the configuration is bad: retries only burn budget.
        _ => false,
    }
}
