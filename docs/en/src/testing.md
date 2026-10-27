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

Real NAT translation cannot be intercepted at loopback, because plain UDP sockets send straight to their destination. The seam sits where sockets are created: `UdpIo` and `UdpFactory` describe a UDP socket and its factory, the tokio factory is the default, and the simulator plugs in its own. The `test-util` feature exposes the seam, the simulator, and the NAT lab.

## The simulator

`sim::Net` owns one router task and an address table. Hosts, NATs, and STUN servers attach to it, every virtual socket sends through the router, and the router applies translation, filtering, loss, and delay.

```rust,ignore
let net = sim::Net::seeded("cone_cone_success");  // seed from the test name
let stun = net.stun_server();
let host = net.host(&sim::NatSpec::cone_apdf());  // behind a NAT
```

A `NatSpec` combines a mapping policy and a filtering class. The mapping policies are `Cone`, `Sequential { step }`, `AddressSequential { step }`, and `Random`, and the specs `cone_eif()`, `cone_apdf()`, `sequential(step)`, `address_sequential(step)`, and `random(range)` cover the common shapes. A symmetric spec defaults to address-dependent filtering, the common CGNAT shape.

The router exposes observation hooks for assertions: forwarded and dropped counters, the live mapping table, the peak mapping count, and a bounded wait until every mapping drains. Setting the `SIM_TRACE` environment variable prints every forwarded packet, which narrows failures fast.

Determinism comes from two pieces. All randomness flows through one `StdRng` seeded from the test name, and all tests run under `#[tokio::test(start_paused = true)]`, so a full session completes in milliseconds of wall time.

## The loopback NAT lab

The lab in `src/natlab.rs` is a userspace NAT forwarder over real OS sockets. Client sockets are plain loopback sockets, every outbound datagram crosses a gateway task that applies the mapping and filtering policy of a `NatSpec`, and each lab owns one dedicated address of the `127.0.0.0/8` space so labs never collide inside one process.

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
| `sim_probe.rs` | classification against the simulator: cone, easy, hard, public, timeouts, caching, fan-out ordering |
| `sim_strategy.rs` | one suite per strategy, including a 64-seed Monte Carlo run that checks the measured birthday rate against the model estimate |
| `sim_resource.rs` | rate caps, budget and conntrack exhaustion, cleanup on every exit path, drop-the-future |
| `natlab_matrix.rs` | the same strategy matrix over real sockets behind two NAT labs, plus mapping hygiene |
| `real_smoke.rs` | LocalStun helper, direct loopback punches, the IPv6 session case, the Windows distinct-port rule, winner handover |
| `decoder_corpus.rs` | thousands of mutated buffers through both decoders, no panic, no hang |

The matrix strategy cases run on both simulated and real NATs: cone pairs, the easy-symmetric prediction pair, the hard-symmetric spray against a port-filtered cone, and the birthday burst between two hard symmetric NATs.

## Fuzzing

Three `cargo-fuzz` targets decode arbitrary bytes: `fuzz_sig_frame` and `fuzz_data_packet` over the wire codecs, `fuzz_stun` over the STUN response parser. All three assert the same contract: any input produces either a valid message or an error, never a panic or a hang.

CI runs no fuzzer. `decoder_corpus.rs` covers the same property with a fixed corpus in every run. On Windows the fuzz targets need the MSVC AddressSanitizer runtime on `PATH`.

## CI policy

CI runs `cargo-nextest` on Linux, Windows, and macOS, plus a cargo check job pinned to the MSRV. Simulator tests are deterministic by construction, seeded by test name, so a failure reproduces with the same seed and flakes are triaged as defects instead of retried.
