# punch-hole

Signaling-agnostic UDP hole punching primitives for Rust.

The library classifies both NATs, agrees on a punching strategy with the peer,
executes it, and hands back a plain `tokio::net::UdpSocket`. It ships zero
signaling code and zero identity system. The host application owns peer
discovery and the control channel: it forwards the library's opaque frames to
the peer and feeds peer frames back.

## Try it

`crates/punch-hole-demo` builds the `punch-demo` binary, which runs one full session over real sockets. It carries its own minimal rendezvous, a `relay` subcommand that pairs the first two UDP addresses that register, so nothing else is needed beyond STUN. One binary serves all three roles, so build it once and copy it to each machine:

```sh
cargo build --release -p punch-hole-demo
# target/release/punch-demo, or punch-demo.exe on Windows
```

Run three terminals, two of them on different networks for a real NAT path:

```sh
# terminal 1, on any host both sides can reach
punch-demo relay 0.0.0.0:9000

# terminal 2
punch-demo client --relay <relay-host>:9000

# terminal 3, within 30 seconds of terminal 2
punch-demo server --relay <relay-host>:9000
```

STUN defaults to four public servers, so the commands above need no other setup. Pass `--stun host:port,...` to use your own. The client punches as the Initiator and the server as the Responder. Each side prints every stage as it completes, its own NAT class, the peer's, and the negotiated strategy, then the phase timings once the path is up. Both sides then chat over the punched socket: each line typed is one datagram to the peer, and `/quit` or end of input closes. `--target <p>` sets the success rate the burst sizing aims for; the demo defaults to 0.9.

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

```rust,no_run
use std::sync::Arc;

use punch_hole::{PunchConfig, PunchError, Puncher};

async fn run_initiator_side() -> Result<(), PunchError> {
    let puncher = Puncher::new(PunchConfig::default())?;

    let (host_end, lib_end) = punch_hole::signaling::bridge(64);

    // The host pumps its own transport against the bridge: deliver
    // host_end.to_peer frames to the peer, and push frames that arrive
    // from the peer into host_end.from_peer.

    let punched = puncher.with_signaling(lib_end).initiator().await?;

    // The business layer owns the winner from here. Tokio sockets have
    // no Clone, so share it behind an Arc; the optional heartbeat keeps
    // the NAT mapping open while the host idles.
    let socket = Arc::new(punched.socket);
    let _guard = punch_hole::keepalive::spawn(
        Arc::clone(&socket),
        punched.peer_addr,
        punched.report.nonce,
    );
    let _ = socket; // send and receive business traffic

    Ok(())
}
```

This block mirrors the crate-level example in the library docs, which
`cargo test --doc` compiles, so the snippet cannot drift from the API.
The full walkthrough lives in the crate documentation
(`cargo doc --open`).
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
