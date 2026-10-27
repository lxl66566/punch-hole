# punch-hole

Signaling-agnostic UDP hole punching primitives for Rust.

The library classifies both NATs, agrees on a punching strategy with the peer,
executes it, and hands back a plain `tokio::net::UdpSocket`. It ships zero
signaling code and zero identity system. The host application owns peer
discovery and the control channel: it forwards the library's opaque frames to
the peer and feeds peer frames back.

## Try it

`examples/punch-demo.rs` runs one full session over real sockets. It carries
its own minimal rendezvous, a `relay` subcommand that pairs the first two UDP
addresses that register, so nothing else is needed beyond STUN.

Run three terminals, two of them on different networks for a real NAT path:

```sh
# terminal 1, on any host both sides can reach
cargo run --example punch-demo -- relay 0.0.0.0:9000

# terminal 2
cargo run --example punch-demo -- punch --role initiator --relay <relay-host>:9000

# terminal 3, within 30 seconds of terminal 2
cargo run --example punch-demo -- punch --role responder --relay <relay-host>:9000
```

STUN defaults to four public servers, so the commands above need no other
setup. Pass `--stun host:port,...` to use your own. Each side prints its NAT
class, the chosen strategy, the phase timings, and then exchanges one business
datagram over the punched socket. `--target <p>` sets the success rate the
burst sizing aims for; the demo defaults to 0.9.

Two peers on one machine also work. They punch over the local IPv6 or
loopback path.

## NAT coverage

A Direct stage runs before the matrix strategy whenever both sides are public
or both report global IPv6 addresses.

| local \ peer | cone or public | easy symmetric | hard symmetric |
|--------------|----------------|----------------|----------------|
| cone or public | ConeExchange | SymProbe | SymProbe |
| easy symmetric | SymProbe | PredictiveExchange | BirthdayBurst |
| hard symmetric | SymProbe | BirthdayBurst | BirthdayBurst |

In SymProbe the symmetric side sprays and the cone side answers. A spray aims
at a predicted window on an easy symmetric peer and at a random spread on a
hard one.

BirthdayBurst sizes its sockets and port coverage from the collision model
against `target_success` and reports the estimate. An estimate below
`min_success` fails Negotiate with `Unpunchable` before any data packet is
sent. A burst stays probabilistic, so a hard against hard pair may need a
second attempt.

Two symmetric NATs that both filter on address and port are the one hard
case. The strategies chapter of the book covers the filtering assumption
the estimate states.

## Using the library

```rust,ignore
let puncher = punch_hole::Puncher::new(punch_hole::PunchConfig::default())?;
let (host_end, lib_end) = punch_hole::signaling::bridge(64);

// Pump host_end against your own transport to the peer.

let punched = puncher.with_signaling(lib_end).initiator().await?;
// punched.socket is a raw UDP socket; punched.peer_addr is the confirmed path.
```

The full walkthrough lives in the crate documentation (`cargo doc --open`).
The project book carries the UDP hole punching primer, the API guide, and
the architecture and protocol reference, in English and Chinese:

```sh
mdbook build docs/en && mdbook build docs/zh
```

Open `target/book/en/index.html` (English) or `target/book/zh/index.html`
(中文), or read the chapter sources under `docs/en/src/` and `docs/zh/src/`.

CI builds and deploys the book on every push to main, at
<https://lxl66566.github.io/punch-hole/>. The landing page picks the
language by browser locale, and the toolbar button switches languages
chapter for chapter.

License: MIT OR Apache-2.0.
