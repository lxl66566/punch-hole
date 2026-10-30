# nat-lab

Emulated NAT devices for testing UDP traversal code on one machine.

Testing NAT traversal needs a NAT on the other side of the wire. `nat-lab` provides two engines that share one NAT specification, so a test suite runs the same scenario twice with different levels of realism:

- **Virtual engine** (`nat_lab::sim`): a deterministic virtual IPv4 network. Hosts attach directly or behind a NAT, STUN servers answer binding requests, and every packet crosses a router task that applies translation, filtering, and loss. All randomness flows through one seeded generator, and tests run under paused tokio time, so a full session reproduces from its seed in milliseconds of wall time.
- **Loopback engine** (`nat_lab::lab`): a userspace NAT forwarder over real OS sockets on the 127.0.0.0/8 space. Client sockets are real sockets; every outbound datagram crosses a gateway task that applies the mapping and filtering policy and leaves through a per-mapping public socket. The code under test runs unmodified, so OS bind rules, ICMP quirks (Windows surfaces loopback port-unreachable as `ConnectionReset`), and real timing all apply.

Both engines translate and filter datagrams according to one `NatSpec`: a mapping behavior per RFC 4787 (`MappingBehavior::EndpointIndependent`, `AddressDependent`, `AddressPortDependent`) crossed with an allocation policy (`Allocation::Increment { step }`, `Random`, `Preserve`) and an inbound filtering class (endpoint-independent, address-dependent, address-and-port-dependent) over a port range, plus a hairpinning switch that decides whether datagrams aimed at the NAT's own external address loop back to the sibling behind it (RFC 4787 §6) or drop as on a broken no-loopback NAT.

The built-in STUN responders of both engines support RFC 5780 behavior discovery: each answers on a two-IP, multi-port grid, honors CHANGE-REQUEST (the reply leaves the flag-selected alternate socket), and reports RESPONSE-ORIGIN and OTHER-ADDRESS beside XOR-MAPPED-ADDRESS. The handles expose the alternate addresses as `other_addrs`.

## Usage

```rust,ignore
// Deterministic: a virtual NAT queried through the built-in STUN server.
let net = nat_lab::Net::seeded("cone_cone_success");
let stun = net.stun_server();
let host = net.host(nat_lab::NatSpec::cone_apdf());
let sock = host.bind(nat_lab::Family::V4.any_addr()).await?;

// Realistic: a loopback NAT over real sockets, with a matching responder.
let stun = nat_lab::stun_responder()?;
let nat = nat_lab::NatLab::spawn("demo", nat_lab::NatSpec::cone_apdf()).await?;
let sock = nat.host().bind(nat_lab::Family::V4.any_addr()).await?;
```

Consumer code sees hosts and sockets through two small traits, `UdpFactory` and `UdpIo` (four methods total). Adapting another socket abstraction onto the seam is a few lines; see `src/socket.rs`.

## Fault injection and observation

Both engines expose the same fault surface: data-plane loss (`set_loss`) with a drop counter, uplink faults on the host (`drop_first_send_to`, `fail_sends_to`), allocation-sequence control (`external_allocations`, `rebind_sequence_after`), close expiry (`set_mapping_expiry`), idle expiry (`set_idle_expiry`) with its eviction counter, and a per-packet tap (`set_tap`) that forwards, drops, or rewrites any crossing. Observation covers forwarded and drop counters, the live mapping table, peak mappings, snapshots, and a bounded drain wait, with the `NAT_LAB_TRACE` environment variable printing every routing decision either engine makes.

## Non-goals

No signaling, no identity system, no relay, and no async-runtime interception: determinism comes from the seam, and the loopback engine keeps real wall-clock timing on purpose. Multi-layer (stacked) NATs and carrier-grade shared-address scenarios are roadmap items.
