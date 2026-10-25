# punch-hole

Signaling-agnostic UDP hole punching primitives for Rust.

The library classifies both NATs, agrees on a punching strategy with the peer,
executes it, and returns a plain `tokio::net::UdpSocket`. It ships zero
signaling code and zero identity system: the host application owns peer
discovery and the control channel, forwards the library's opaque frames to the
peer, and feeds peer frames back. See [ARCHITECTURE.md](ARCHITECTURE.md) for
the design, [PROTOCOL.md](PROTOCOL.md) for the wire formats, and
[TESTING.md](TESTING.md) for the test rings.

```rust,ignore
let puncher = punch_hole::Puncher::new(punch_hole::PunchConfig::default())?;
let (host_end, lib_end) = punch_hole::signaling::bridge(64);

// Pump host_end against your own transport to the peer.

let punched = puncher.with_signaling(lib_end).initiator().await?;
// punched.socket is a raw UDP socket; punched.peer_addr is the confirmed path.
```

License: MIT OR Apache-2.0.
