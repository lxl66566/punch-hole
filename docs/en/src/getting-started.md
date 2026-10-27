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

use punch_hole::{PunchConfig, PunchError, Puncher};

async fn run_initiator_side() -> Result<(), PunchError> {
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
    let _guard = punch_hole::keepalive::spawn(
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

## Reading the result

```rust
pub struct Punched<S = tokio::net::UdpSocket> {
    pub socket: S,
    pub peer_addr: SocketAddr,
    pub report: PunchReport,
}
```

The socket stays unconnected, so the host chooses its own receive pattern. `peer_addr` is the confirmed data-plane address of the peer. The report carries both NAT classes, the strategy, the success estimate for burst strategies, packet counts, and the wall time of each phase, which covers logging and relay decisions.

## Host responsibilities

The library covers one attempt. The checklist around it:

- **Authenticate before forwarding.** The data plane tags packets with a 128-bit nonce, and the signaling plane trusts whatever the host channel delivers. Authenticate the peer and reject replays on the host transport before anything reaches `from_peer`.
- **Deliver frames in order.** Retransmission tolerates loss. Order is the one property the bridge expects.
- **Retry attempts.** One session is one attempt. A probabilistic burst against a hard symmetric NAT may need a second run, and the host owns the loop.
- **Keep the cache fresh.** `with_cached_nat` skips the Probe phase with whatever the host hands it. Networks change, so a cache older than the current network is the host's call to make.

## The demo

`examples/punch-demo.rs` runs a full session over real sockets, including its own minimal rendezvous relay. Three terminals, two of them on different networks:

```sh
# terminal 1, on any host both sides can reach
cargo run --example punch-demo -- relay 0.0.0.0:9000

# terminal 2
cargo run --example punch-demo -- punch --role initiator --relay <relay-host>:9000

# terminal 3, within 30 seconds of terminal 2
cargo run --example punch-demo -- punch --role responder --relay <relay-host>:9000
```

Each side prints its NAT class, the chosen strategy, and the phase timings, then exchanges one business datagram over the punched socket. The demo relay authenticates nobody, so it stays on a trusted network.
