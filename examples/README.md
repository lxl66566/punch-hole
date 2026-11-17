# Examples

Runnable lessons, one concept each. Read them in this order.

| Example | Teaches | Run |
| --- | --- | --- |
| `nat_probe` | What NAT this machine sits behind. `Puncher::probe` standalone, and how to read a `NatInfo`. | `cargo run --example nat_probe` |
| `minimal_pair` | The smallest complete session: bridge, roles, and the handed-over socket, with an in-memory stand-in transport. | `cargo run --example minimal_pair` |
| `tcp_signaling_pair` | A real two-process run: signaling frames over a length-prefixed TCP stream, the shape most hosts face with a relay or WebSocket. | two terminals, see the file header |
| `retry_until_connected` | The host-owned retry loop: fresh bridge per attempt, backoff, failure triage, and a NAT classification reused across attempts. | `cargo run --example retry_until_connected` |
| `simulated_nat_pair` | A full session through simulated NATs with no network at all, and which strategy each NAT pair negotiates. | `cargo run --example simulated_nat_pair --features test-util -- cone-cone` |
| `host_session` | The complete program: transport pump, progress events, failure triage, keepalive, and business traffic sharing the winner socket. | `cargo run --example host_session` |

Everything except `simulated_nat_pair` needs outbound UDP to public STUN servers; pass your own with `-- stun-host:port` where the example accepts it. `simulated_nat_pair` runs fully offline behind the `test-util` feature. The `punch-demo` binary in `crates/punch-hole-demo` adds a rendezvous relay and a two-terminal chat for real machines on real networks.

## The model in five lines

1. **Bring your own signaling.** The library emits opaque frames on one channel and consumes peer frames from another; any ordered, authenticated transport works. `signaling::bridge` returns both ends: deliver `HostEnd::to_peer` frames to the peer, push frames that arrive from the peer into `HostEnd::from_peer`.
2. **One session is one attempt.** A retry is a fresh `bridge`, a fresh `Puncher`, and a fresh nonce; back off first, because the last attempt's NAT mappings age out in seconds.
3. **Roles, not identities.** The Initiator dials, the Responder answers; assign the role before either side starts, or both sides calling `initiator()` abort each other.
4. **The result is a raw socket.** A success returns `Punched { socket, peer_addr, report }`; the socket is a plain unconnected `tokio::net::UdpSocket` with every loser already closed.
5. **Filter the library's own traffic.** Late handshake retransmissions and heartbeat beats still arrive on the winner; drop them with `msg::is_attempt_packet(buf, nonce)` before parsing business datagrams, and hold the mapping open with `keepalive::spawn_io` while the business layer idles.

Failures return `PunchFailure`: the phase error plus the evidence the session had collected, which is what `retry_until_connected` triages. Progress is observable mid-session through `Puncher::with_events`, which `host_session` prints as each stage completes. Config knobs live in `PunchConfig`; the two most hosts touch are `target_success` (aim higher to land more attempts) and `exchange_timeout` (stretch it when the peer joins late).
