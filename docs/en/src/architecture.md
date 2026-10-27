# Architecture

The library splits into an algorithm layer that decides and a driver layer that acts. This chapter walks the split, the session lifecycle, the engine that runs the punch, and the socket pool that owns every socket.

## The two layers

The algorithm layer works on plain values, so tests drive it without sockets:

- `nat/classify.rs`: probe observations to a NAT class,
- `nat/predict.rs`: port sequence fitting and prediction,
- the selection matrix in `strategy/mod.rs`,
- the collision model and the sizing function that feeds both selection and execution.

The driver layer owns sockets, timers, and tasks. It feeds observations into the algorithm layer and executes what the algorithm layer decides:

- `nat/probe.rs`: the STUN prober,
- the punch engine in `strategy/mod.rs`,
- `socket/`: the socket pool, the rate limiter, and the platform options,
- `session.rs`: the phase state machine,
- `signaling.rs`: the bridge and the session-side frame IO.

```text
src/
├── lib.rs         public API and crate docs
├── config.rs      PunchConfig
├── error.rs       PunchError and Phase
├── report.rs      PunchReport and per-phase statistics
├── signaling.rs   the bridge, HostEnd and LibEnd, session frame IO
├── msg/           signaling frames and data packets, with their codecs
├── nat/           probe, classification, port prediction
├── strategy/      selection, sizing, the four strategies, the engine
├── socket/        UdpIo and UdpFactory, SocketPool, rate limiting, platform options
├── session.rs     Puncher, PunchSession, the phase state machine
├── keepalive.rs   optional post-handover heartbeat
└── sim/           test-only NAT simulator, behind `test-util`
```

Dependencies stay small: `tokio` and `tokio-util` for async IO and cancellation, `socket2` for platform options, `serde` plus `postcard` for frames, `rand` for nonces and burst draws, `bytes` for the bridge, and `thiserror` for the error type. The STUN subset the prober needs is small enough to live in-tree.

## The socket seam

The driver binds sockets through two small traits instead of calling tokio directly. `UdpIo` is one UDP socket with `&self` methods and internal mutability, because a receive task and the sender share it. `UdpFactory` creates sockets. Tokio sockets provide the default, and `Puncher::with_factory` accepts any other, which is how the test simulator and the NAT lab attach hosts. The public API keeps the same `tokio::net::UdpSocket` deliverable.

## Session lifecycle

```text
        +----------------------------------------------------------+
        |                       overall deadline                   |
        v                                                          v
Probe -> Exchange -> Negotiate -> Punch -> Confirm -> Handover -> Done
```

**Probe** runs on both sides in parallel. Each side probes STUN, classifies its own NAT, and collects its addresses. A cached `NatInfo` skips the phase.

**Exchange** publishes the evidence. Each side sends its `NatInfo` in a `Hello` frame, retransmitted until the peer's `Hello` arrives. The exchange also measures the signaling round-trip time, which the pulse schedule reuses. An `Offer` that arrives while a side has already claimed the Initiator role aborts both sides, because two Initiators cannot agree on a plan.

**Negotiate** turns two `NatInfo` values into one plan. The Initiator applies the matrix, draws the nonce, and sends an `Offer` with the strategy, the socket counts, and the start delay. The start delay equals one signaling RTT plus a 300 millisecond margin, counted from the Responder sending `Accept`, so both clocks anchor on one shared event and host clock skew stays irrelevant. The Initiator starts half an RTT early to compensate for the transit of the Accept. The Responder clamps the socket counts to `max_sockets`, rejects a start delay past ten seconds, rebuilds the estimate over its own view, and re-sends the Accept until the start window opens minus a 100 millisecond margin.

**Punch and Confirm** share one engine and one budget. Both sides execute the agreed strategy, and the three-way handshake confirms the path as soon as it works. The deadline is the smaller of `punch_timeout` and the session's overall wall.

**Handover** returns the winner. The engine closes every loser socket, joins every task, and the session returns the socket with its report.

The whole session runs under `overall_deadline`, and every phase deadline sits under it.

## The engine

The engine is a single task fed by three streams: pool receive events, signaling frames, and a 50 millisecond tick. Everything the punch does happens in `select!` over those streams.

Each strategy compiles into a list of stages. A stage names one address family, a socket count, a target list, and a duration. Stages run in order, and the stage list of a dual-stack plan may hold a V6 Direct stage followed by a V4 matrix stage. Targets that depend on the peer's fresh port stay empty until the peer's `PortUpdate` names it.

Each tick:

- advances the stage index when the current stage's duration ends,
- re-sends the local `PortUpdate` on the signaling cadence until the handshake completes,
- fires the sweep, which sends one Syn per socket over rotating targets,
- retransmits handshake packets on the `confirm_retry` cadence.

Inbound packets drive the handshake:

1. A `Syn` from the peer marks the receiving socket as a candidate and earns one `SynAck`. One reply per source per confirm window covers retransmission, and the reply gate caps its bookkeeping at 1024 keys.
2. A `SynAck` marks the path two-way. The side confirms its socket, announces it over signaling in a `Confirmed` frame, and opens a grace window of two seconds.
3. An `Ack` completes the peer's confirmation. The side that receives the final `Ack` finishes immediately, because the final Ack proves both directions.

After confirmation the grace responder keeps answering the peer's late handshake packets until the peer's `Confirmed` frame arrives or the grace passes. The winner socket reaches the host with no handshake traffic left in flight.

Two details keep failures honest. A send failure before any handshake traffic fails the session, and a send failure after handshake traffic merely stalls new pulses, because a working path exists and the grace mechanism decides the outcome. The session-wide deadline covers all of it, the grace included.

## The socket pool

`SocketPool` owns every socket a session opens, grouped per address family. A family that fails to bind proceeds empty, which simply disables the stages that needed it. One receive task per socket validates nothing itself and forwards every datagram as an event, tagged with the pool index. Events travel over a bounded channel that scales with `max_sockets`, and a full channel drops events, because every event is a handshake packet covered by retransmission and a blocking receive task would sit out of reach of cancellation.

Every outbound packet passes the three guards described in [Resource control](resources.md). The winner election cancels the receive tasks, waits for them, removes the winner from its group, and unwraps it from the pool. One winner, all others closed, no task left running. A failed session instead shuts the whole pool down.

## Post-handover keepalive

`keepalive::spawn` shares the winner behind an `Arc` and sends a small heartbeat every ten seconds, which holds the NAT mapping open while the host idles. The returned guard aborts the task on drop. The heartbeat carries the attempt nonce, and hosts discard any datagram whose first byte is the data-plane magic and whose length stays under the protocol limit.
