# Testing

The suite runs a full punch session in milliseconds and treats a flake as a defect. This chapter walks the test rings, the two test-only network layers, and the CI policy.

## The rings

| ring | what it proves | speed |
|---|---|---|
| unit tests | the algorithm layer on plain values | milliseconds |
| simulator integration | the full protocol against a deterministic virtual network | milliseconds of wall time |
| loopback NAT lab | the real socket path behind emulated NAT devices | real time, a few seconds |
| real-socket smoke | platform socket rules on loopback | real time |

Unit tests cover classification decisions, prediction fits, the collision model, sizing, and winner election on plain values.

## The socket seam

Real NAT translation cannot be intercepted at loopback, because plain UDP sockets send straight to their destination. The seam sits where sockets are created: `UdpIo` and `UdpFactory` describe a UDP socket and its factory, the tokio factory is the default, and a test plugs in any other factory through `Puncher::with_factory`. The two test engines live in the `nat-lab` crate, a workspace member behind the `test-util` feature: `nat_lab::socket` carries the same four-method trait shape, and `punch_hole::compat` bridges both engine hosts and sockets onto this crate's seam.

## The simulator

`nat_lab::sim::Net` owns one router task and an address table. Hosts, NATs, and STUN servers attach to it, every virtual socket sends through the router, and the router applies translation, filtering, and loss.

```rust,ignore
let net = nat_lab::Net::seeded("cone_cone_success");  // seed from the test name
let stun = net.stun_server();
let host = net.host(nat_lab::NatSpec::cone_apdf());  // behind a NAT
```

A `NatSpec` crosses two orthogonal RFC 4787 axes with a filtering class: the mapping behavior (`MappingBehavior::EndpointIndependent`, `AddressDependent`, or `AddressPortDependent`) decides which destinations reuse a mapping, and the allocation policy (`Allocation::Increment { step }`, `Random`, or `Preserve`) decides how a fresh external port is chosen. The presets `cone_eif()`, `cone_apdf()`, `sequential(step)`, `address_sequential(step)`, `random(range)`, `random_eif(range)`, and `preserved(filtering)` cover the common shapes, and `with_*` builders adjust single fields. A symmetric preset defaults to address-dependent filtering, the common CGNAT shape. Both engines' built-in STUN responders speak enough RFC 5780 for behavior discovery: each answers on a two-IP, multi-port grid, honors CHANGE-REQUEST, and reports RESPONSE-ORIGIN and OTHER-ADDRESS beside XOR-MAPPED-ADDRESS, so a suite can confirm the declared mapping behavior and filtering class straight off the wire.

One more `NatSpec` field decides hairpinning (RFC 4787 §6): a datagram a client sends to its own NAT's external address loops back through the target mapping, arriving as if from outside — the source is the sender's translated address, and the target mapping's filter applies to it, so an unsolicited loop is filtered and counted like any inbound one. `hairpin: false` models the broken no-loopback NAT instead: the sender's mapping still opens, the datagram is dropped, and the engine's `dropped_by_hairpin` counter ticks.

The simulator also hosts two clients behind one NAT: `net.host_sharing(&first)` attaches a second host to `first`'s NAT on the same /24, the shape the Local stage targets. A datagram between the two crosses no NAT — the router delivers it untranslated when the destination shares the sender's subnet — while a datagram aimed at the NAT's own external address still takes the hairpin path, so both the LAN and the loopback behavior are observable.

Both engines also stack one NAT behind an upstream: `net.host_behind(&uplink_host, spec)` and `NatLab::spawn_behind(&uplink, seed, spec)` build the shape a CGNAT gives every home router. The inner NAT's public side is realized as a set of client sockets of the upstream host, one per inner external port, so an outbound datagram opens the inner mapping and then leaves through that uplink socket, letting the upstream allocate the externally visible address under its own policy. The inner NAT's own public address is a display label only — probes learn the true external address through STUN across the chain — and inbound rides the uplink socket's receive path, so an inner filter sees the source the outer NAT assigned. The nested spec still governs the datagrams that cross it — mapping, allocation, filtering, and hairpinning — with its allocation policy picking the uplink client ports wherever the upstream host has them free, and releasing an inner mapping releases the upstream mapping with it.

The router exposes observation hooks for assertions: forwarded and dropped counters, the live mapping table, the peak mapping count, and a bounded wait until every mapping drains. Setting the `NAT_LAB_TRACE` environment variable prints every forwarded packet, which narrows failures fast.

Hosts carry fault injection for the paths a clean net never walks: `drop_first_send_to` and `fail_sends_to` break the uplink, `external_allocations` walks a NAT's sequence forward like unrelated traffic behind the same carrier NAT, and `rebind_sequence_after` jumps the port walk to a fresh base mid-session.

The wire itself is hostile too. `set_loss(permille)` drops a random share of every crossing, `set_dup(permille)` delivers a random share twice, and `set_delay(range)` holds each crossing for a drawn duration before it lands, so packets of one exchange overtake each other; every random decision is drawn in send order, so a run stays reproducible. Delayed crossings translate against the mapping state of the instant they arrive, which is what a NAT whose table moved mid-flight really does to a late packet.

Determinism comes from two pieces. All randomness flows through one `StdRng` seeded from the test name, and all tests run under `#[tokio::test(start_paused = true)]`, so a full session completes in milliseconds of wall time.

## The loopback NAT lab

The lab in `nat_lab::lab` is a userspace NAT forwarder over real OS sockets. Client sockets are plain loopback sockets, every outbound datagram crosses a gateway task that applies the mapping and filtering policy of a `NatSpec`, and each lab owns one dedicated address of the `127.0.0.0/8` space so labs never collide inside one process. Linux and Windows bind every address of that block; macOS binds only the addresses aliased onto `lo0`, so there the engines draw from `127.0.0.2-254` and need those aliases first: `for i in $(seq 2 254); do sudo ifconfig lo0 alias 127.0.0.$i up; done`. A lab spawned behind an upstream draws no address of its own — its public address reads `0.0.0.0` as a label — and its per-mapping external sockets are uplink client sockets of the upstream lab, so the OS keeps the port allocation honest.

What the lab covers and the simulator cannot:

- the real socket path: OS binds, buffer sizes, and descriptor lifetimes,
- the Windows reset behavior, where loopback ICMP port-unreachable surfaces as `ConnectionReset` on a later receive,
- real STUN round trips over datagram sockets,
- real allocation pressure and timing, because mapping creation follows actual datagram arrival.

A socket close releases its mappings through a Bye frame, so election and handover semantics are observable. The lab runs on real time, because real sockets have no paused clock.

## The suites

| suite | covers |
|---|---|
| `sim_contract.rs` | signaling contract: closed bridge, dual initiator, version mismatch, garbage frames, lossy and duplicated frames, oversized offers |
| `sim_hostile.rs` | punch sessions over a hostile data plane: loss, jitter, duplication, a duplicated-and-delayed wire, a dead wire that fails fast and releases, a slow wire, and the start skew of a delayed Accept or Offer, including a CGNAT chain over a lossy wire |
| `sim_probe.rs` | classification against the simulator: cone, easy, hard, public, timeouts, caching, fan-out ordering, plus full punch sessions for the shared-NAT and CGNAT-chain shapes |
| `sim_strategy.rs` | one suite per strategy, including a 64-seed Monte Carlo run that checks the measured birthday rate against the model estimate |
| `sim_resource.rs` | rate caps, budget and conntrack exhaustion, cleanup on every exit path, drop-the-future |
| `natlab_matrix.rs` | the same strategy matrix over real sockets behind two NAT labs, plus mapping hygiene, a lossy-forwarder pass, and a CGNAT chain over nested labs |
| `real_smoke.rs` | LocalStun helper, direct loopback punches, the IPv6 session case, the Windows distinct-port rule, winner handover |
| `decoder_corpus.rs` | thousands of mutated buffers through both decoders, no panic, no hang |

The matrix strategy cases run on both simulated and real NATs: cone pairs, the easy-symmetric prediction pair, the hard-symmetric spray against a port-filtered cone, and the birthday burst between two hard symmetric NATs.

## Fuzzing

Three `cargo-fuzz` targets decode arbitrary bytes: `fuzz_sig_frame` and `fuzz_data_packet` over the wire codecs, `fuzz_stun` over the STUN response parser. All three assert the same contract: any input produces either a valid message or an error, never a panic or a hang.

CI runs no fuzzer. `decoder_corpus.rs` covers the same property with a fixed corpus in every run. On Windows the fuzz targets need the MSVC AddressSanitizer runtime on `PATH`.

## CI policy

CI runs `cargo-nextest` on Linux, Windows, and macOS, plus a cargo check job pinned to the MSRV. Simulator tests are deterministic by construction, seeded by test name, so a failure reproduces with the same seed and flakes are triaged as defects instead of retried.
