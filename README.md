# punch-hole

Signaling-agnostic UDP hole punching for Rust. One session classifies both peers' NATs, agrees on a strategy over the channel the application already runs, executes it, and returns a plain `tokio::net::UdpSocket`. No signaling code, no identity system, no relay: the host forwards the library's opaque frames and feeds peer frames back.

- BYOS. Frames are opaque `Bytes` on any ordered, authenticated transport.
- Two roles, no identities. One attempt nonce is the only credential.
- A raw socket out. Fail fast under `overall_deadline`, with every loser closed before the call returns.
- Bounded resources. The rate cap, packet budget, and conntrack bound gate every data packet.

## Quick start

`crates/punch-hole-demo` builds `punch-demo`: one session over real sockets with its own minimal rendezvous, so it needs nothing beyond STUN. Build once and copy it to each machine:

```sh
cargo build --release -p punch-hole-demo   # target/release/punch-demo
punch-demo relay 0.0.0.0:9000              # terminal 1, reachable by both sides
punch-demo client --relay <host>:9000      # terminal 2
punch-demo server --relay <host>:9000      # terminal 3, within 30 s
```

STUN defaults to four public servers (`--stun host:port,...` overrides), the burst sizing aims for `--target 0.9`, and `--exchange-timeout 30` is the join window. Each side prints every stage and both NAT classes, then chats over the punched socket: one line per datagram, `/quit` closes. The relay frees an unpaired slot 60 seconds after it joined and a pair 60 seconds after both sides fall silent. Two peers on one machine work too.

## Example

`examples/host_session.rs` is the complete program (`cargo run --example host_session`), with the transport pump, the failure triage, and the handover:

```rust,no_run
use std::sync::Arc;

use punch_hole::{PunchConfig, PunchFailure, Punched, Puncher, Role};

/// One attempt. A retry needs a fresh bridge and a fresh nonce.
async fn punch(role: Role) -> Result<Punched, PunchFailure> {
    let (host_end, lib_end) = punch_hole::signaling::bridge(64);
    // Host code: deliver `host_end.to_peer` frames to the peer and push the
    // peer's frames into `host_end.from_peer`.
    pump(host_end);

    let session = Puncher::new(PunchConfig::default())?.with_signaling(lib_end);
    match role {
        Role::Initiator => session.initiator().await,
        Role::Responder => session.responder().await,
    }
}

/// The business layer owns the winner, unconnected.
fn handover(punched: Punched) -> Arc<tokio::net::UdpSocket> {
    let socket = Arc::new(punched.socket);
    // Keeps the NAT mapping open while the host idles.
    let _keepalive = punch_hole::keepalive::spawn_io(
        Arc::clone(&socket),
        punched.peer_addr,
        punched.report.nonce,
    );
    socket
}
```

The winner shares its socket with late handshake retransmissions and heartbeat beats: drop them with `msg::is_attempt_packet(bytes, report.nonce)` before parsing business datagrams. The report covers both NAT classes, the reflexive addresses, the port-space estimates, the strategy, the burst estimate, packet counts, and per-phase timings. Progress events, a cached classification that skips Probe, and a standalone `Puncher::probe()` sit on the same builder.

## NAT coverage

Selection reads the effective classes, which means a weak `EasySym` fit has already demoted to `HardSym`:

| local \ peer   | cone or public | easy symmetric     | hard symmetric  |
| -------------- | -------------- | ------------------ | --------------- |
| cone or public | ConeExchange   | SymProbe           | SymProbe        |
| easy symmetric | SymProbe       | PredictiveExchange | PredictiveBurst |
| hard symmetric | SymProbe       | PredictiveBurst    | BirthdayBurst   |

A Direct stage runs first when the pair needs no NAT cooperation: both sides public, or both with global IPv6 addresses. Two hosts behind one NAT reach each other over the LAN underneath it, through the Local stage, or through the mutual sweep of ConeExchange when that NAT hairpins; a home router behind a carrier-grade NAT is classified across the chain. `IpPolicy::Ipv6Only` makes the IPv6 Direct stage the whole plan.

In SymProbe the symmetric side sprays: a predicted window against an easy symmetric peer, a random spread over the estimated port span against a hard one. The burst strategies size their coverage from a collision model against `target_success` and report the estimate; an estimate below `min_success` fails Negotiate with `Unpunchable` before any data packet is sent. A cone reading short of two server IPs routes to SymProbe rather than ConeExchange, and two easy symmetric sides that both filter port-strict go straight to the burst sizing.

## Scope and limits

- STUN is required. With plain RFC 5389 servers the filtering class stays `Unknown`, which the strategies read as the relaxed address-dependent case.
- Two port-strict symmetric NATs need both directions to pair on the exact ports, so a wide port space aborts as `Unpunchable`: that regime needs a relay.
- The port span is an estimate, and real CGNAT spaces vary.
- One attempt per session. Retries, backoff, role tie-break, relay fallback, and cache freshness are host work.
- No authentication or encryption. The host authenticates the peer and rejects replays; the business protocol brings its own crypto.

## Docs

`mdbook build docs/en && mdbook build docs/zh` and deployed to <https://lxl66566.github.io/punch-hole/>):

- `punch-hole`: this crate; crate docs carry the same API screen, compiled by `cargo test --doc`.
- `crates/nat-lab`: emulated NAT devices, a deterministic virtual network and a loopback NAT over real sockets, attaching through `Puncher::with_factory`. Standalone as the `nat-lab` crate, behind `test-util` here.
- `crates/punch-hole-demo`: the `punch-demo` binary.

License: MIT OR Apache-2.0.
