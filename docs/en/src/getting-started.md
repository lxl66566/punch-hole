# Getting started

This chapter drives one full session. The standing assumption of the whole library applies: the host already has a transport to the peer.

Add the crate to `Cargo.toml`:

```toml
[dependencies]
punch-hole = "0.1"
```

## The API in one screen

```rust,no_run
use std::sync::Arc;

use punch_hole::{PunchConfig, PunchFailure, Puncher};

async fn run_initiator_side() -> Result<(), PunchFailure> {
    let puncher = Puncher::new(PunchConfig::default())?;

    // One bridge per attempt. The host pumps host_end against its own
    // transport: to_peer frames go to the peer, frames from the peer
    // are pushed into from_peer.
    let (host_end, lib_end) = punch_hole::signaling::bridge(64);

    // Drives Probe, Exchange, Negotiate, Punch, Confirm, Handover.
    let punched = puncher.with_signaling(lib_end).initiator().await?;

    // The business layer owns the winner from here. Tokio sockets have
    // no Clone, so share it behind an Arc, and keep the NAT mapping open
    // with the optional heartbeat while the host idles.
    let socket = Arc::new(punched.socket);
    let _guard = punch_hole::keepalive::spawn_io(
        Arc::clone(&socket),
        punched.peer_addr,
        punched.report.nonce,
    );

    Ok(())
}
```

The Responder side runs the same code with `.responder()` in place of `.initiator()`. Both calls return the same `Punched` value.

## The signaling bridge

`signaling::bridge(capacity)` returns a host end and a library end, backed by two tokio channels.

- `HostEnd::to_peer` receives the frames the host must deliver to the peer.
- `HostEnd::from_peer` takes the frames that arrived from the peer.

Frames are opaque `Bytes`. A host with a message pump wires the two ends into its loop with a short spawn, and a host built on request-response RPC forwards frames inside its handler. One bridge serves exactly one attempt. Hosts that run parallel attempts wrap the frames in their own envelope and route them to separate bridges.

The channel should preserve order. Frame retransmission covers loss, so a lossy channel still completes a session. Frames that arrive out of order should be reordered by the host, and garbage frames are skipped rather than fatal, so a shared channel that catches stray datagrams survives. A version mismatch ends the session, because no productive exchange can follow it.

## Roles

Both roles run the same code and reach the same result. The Initiator owns the decisions that need one owner: it draws the attempt nonce, applies the strategy matrix, and schedules the pulse start. The Responder clamps the plan to its own limits and confirms. The role matters when the two hosts disagree about who calls first, so pick it per connection the way the application already orders its connections.

Both sides calling `initiator()` at once ends the attempt at once: each side reads the peer's `Offer` as its own role being taken and aborts with `PeerAborted(Internal)`. Assign the role before either side dials. Where no natural caller exists, derive it from data both sides hold after Exchange — the lower reflexive IPv4 address initiates, with the lower local address breaking a tie between equals — or let one side retry as the Responder: the collision is itself proof both transports work.

## The second attempt

A session is one attempt, and a second attempt is a fresh session with fresh state:

- A fresh bridge and a fresh session. The nonce is drawn per attempt, so a new attempt never reuses one.
- A fresh classification where the last one is stale. `Puncher::probe()` runs the Probe phase alone for a value to feed `with_cached_nat`; the last `SessionEvent::Probe` of the failed session serves when the network has not changed.
- A reason to expect a different outcome. A probabilistic miss redraws its covered port set on every attempt, so a retry has a fresh chance. An `Unpunchable` verdict does not: the model rates the pair below `min_success` and retries only burn budget against it.
- Backoff between attempts. The NAT mappings and conntrack entries of the last attempt age out in seconds, and a retry that lands inside their lifetime inherits their noise.
- A role swap where both sides claimed the Initiator role. One side moves to the Responder, or both fall back to the tie-break above.

## Reading the result

```rust
pub struct Punched<S = tokio::net::UdpSocket> {
    pub socket: S,
    pub peer_addr: SocketAddr,
    pub report: PunchReport,
}
```

The socket stays unconnected, so the host chooses its own receive pattern. `peer_addr` is the confirmed data-plane address of the peer. The report carries both NAT classes, the local reflexive addresses, the STUN server the engine's refresh queries used, the port-space estimate for each symmetric side, the strategy, the success estimate for burst strategies, packet counts, and the wall time of each phase, which covers logging, telemetry, and relay decisions.

Delivery can lag the handshake by `grace`. A side confirmed by the peer's `SynAck` keeps answering repeated handshake packets until the peer's closing `Ack` arrives or the grace window closes, which covers the loss of that one packet without a retry. Expect the winner socket up to `grace` past the handshake and tune the window to what that tail is worth.

## Failures and progress

A failed session returns `PunchFailure` instead of a bare error:

```rust
pub struct PunchFailure {
    pub error: PunchError,
    pub diagnostics: SessionDiagnostics,
}
```

`error` names the phase that failed; match on it as before. `Io` always carries a real OS error; states the library derives itself, such as no STUN destination, every pool bind failing, or the refresh running out of retries, carry dedicated variants, so matching separates socket failure from the session's own conclusions. `diagnostics` carries what the session had learned by then: the local and peer `NatInfo` once collected, the settled `StrategySummary`, the attempt nonce, and the wall time of each completed phase. Each field appears as its phase completes, so the populated set alone names the phase the failure belongs to. Errors from before the session, such as `Puncher::new` rejecting a config, convert with empty diagnostics.

Progress is observable without polling. `Puncher::with_events(sender)` feeds one `SessionEvent` per completed stage, Probe, Exchange, Negotiate in that order, into an `mpsc` channel. Emission is best-effort: a full or closed channel loses the event and never stalls the session, so no dedicated drain task is required.

Cancellation is drop. Dropping the session future cancels the attempt at its next await, and the socket pool closes every socket the attempt had opened on the way out, so a dropped attempt leaves no sockets behind. There is no separate cancel call.

## Host responsibilities

The library covers one attempt. The checklist around it:

- **Authenticate before forwarding.** The data plane tags packets with a 128-bit nonce, and the signaling plane trusts whatever the host channel delivers. Authenticate the peer and reject replays on the host transport before anything reaches `from_peer`.
- **Deliver frames in order.** Retransmission tolerates loss. Order is the one property the bridge expects.
- **Retry attempts.** One session is one attempt. A probabilistic burst against a hard symmetric NAT may need a second run, and the host owns the loop. [The second attempt](#the-second-attempt) lists the checklist.
- **Keep the cache fresh.** `with_cached_nat` skips the Probe phase with whatever the host hands it. Networks change, so a cache older than the current network is the host's call to make; `Puncher::probe()` runs the classification alone for a fresh value.

## The demo

`crates/punch-hole-demo` builds the `punch-demo` binary: one full session over real sockets, including its own minimal rendezvous relay. One binary serves all three roles, so build it once and copy it to each machine:

```sh
cargo build --release -p punch-hole-demo
# target/release/punch-demo, or punch-demo.exe on Windows
```

Three terminals, two of them on different networks:

```sh
# terminal 1, on any host both sides can reach
punch-demo relay 0.0.0.0:9000

# terminal 2
punch-demo client --relay <relay-host>:9000

# terminal 3, within 30 seconds of terminal 2
punch-demo server --relay <relay-host>:9000
```

Both sides wait 30 seconds for the other to join; `--exchange-timeout <s>` changes that. The relay frees an unpaired slot 60 seconds after it joined and a pair 60 seconds after both sides fall silent, so an unattended side that restarts after every attempt should wait longer and leave at least 60 seconds between starts: a registration arriving earlier pairs with the stale slot.

The client punches as the Initiator and the server as the Responder. Each side prints every stage as it completes, its own NAT class, the peer's, and the negotiated strategy, then the phase timings once the path is up. Both sides then chat over the punched socket: each line typed is one datagram to the peer, and `/quit` or end of input closes. The demo relay authenticates nobody, so it stays on a trusted network.

`examples/host_session.rs` runs both sides of one session inside a single process (`cargo run --example host_session`) and shows what the API screen leaves out: the transport pump, the failure triage, and the handover of the winner to business traffic.
