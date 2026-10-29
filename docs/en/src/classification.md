# Measuring the NAT

The Probe phase collects the facts every later decision reads. One socket asks every configured STUN server for its reflexive address, the port pattern across the answers classifies the NAT, and the result travels to the peer as a `NatInfo`. This chapter walks the probe, the classification rules, and the port predictor.

## The probe

The prober resolves every configured server and keeps every resolved address as a destination, so one hostname with several records contributes one destination per record. Duplicates collapse, so one destination means one mapping. All destinations share one UDP socket, and the prober fires one STUN binding request at each in a single fan-out round.

The binding subset follows RFC 5389 and later: requests carry the magic cookie, and only an XOR-MAPPED-ADDRESS answer parses, so an RFC 3489-only server reads as silence. Answers longer than one kilobyte arrive truncated and their mapped attribute, when it lives past the cap, goes unread the same way.

Each request carries its own transaction id, and each answer fills the slot of the destination it belongs to. The slots record send order, whatever the arrival order was. Send order is allocation order only among the requests that reached the NAT, so the prober tracks two faults a retry round can hide: a destination whose sends all failed locally never allocated, and a first request lost on the uplink leaves its allocation to the retry, which runs after every first-round allocation. When the answers at their send positions hold no constant step, the fit re-reads the retry-round answers as late allocations before it gives up, so a single lost request keeps an `EasySym` reading instead of turning into `HardSym`. A destination that answers never the less leaves nothing behind; a silent one leaves a hole: an allocation whose port nobody reported.

The whole phase ends by `probe_timeout`, three seconds by default. The first round waits half the budget and the retry round waits until the deadline. A short IPv6 pass collects global addresses inside what remains.

## Reading the allocation sequence

The answer ports, in allocation order, form `alloc_seq`. The sequence is the NAT's allocation history for this socket, one port per outbound flow in the order the flows were created. Three rules turn it into a class:

- the reflexive address equals the local address: `Public`,
- every port in the sequence is equal, or fewer than two answers arrived: `Cone`,
- consecutive ports keep one constant step per allocation-index distance: `EasySym { step }`,
- anything else: `HardSym`.

The step divides each port delta by the allocation-index distance that produced it, which keeps the true stride across holes. The sequence `5000, 5002, 5006` with a silent destination at index 2 still reads as a step of two, because the last delta spans two allocations.

One socket against many destinations settles the class on its own. A port that two sockets share can be coincidence inside a narrow allocation range, so the prober reads the sequence rather than consulting a second socket.

## Confidence

Two consistent deltas can be coincidence. A fit needs three deltas, which means four or more observations, to count as confident. Selection demotes an unconfident `EasySym` to `HardSym` before it picks a strategy, so a weak fit costs the fallback path instead of a failed punch.

## What the probe measures, and what it leaves out

The port sequence measures mapping. Filtering stays unmeasured: telling endpoint-independent filtering from address-and-port-dependent filtering needs a change-port request or a third-party echo, and the probe sequence carries binding requests only. The probe reports `FilterClass::Unknown`, and the strategies make the decisions that need no filtering knowledge. The estimate arithmetic for symmetric pairs carries its filtering assumption explicitly, which the strategies chapter covers.

## Port prediction

`PortPredictor` turns a sequence into the next expected ports.

- `fit` takes the median of the deltas as the step, so single outliers bend the fit rather than break it. Deltas are normalized into the signed 16-bit domain first, so a walk across the port boundary still reads as the small negative step it represents. The fit needs at least three deltas, the same bar the confidence rule sets, so a two-sample outlier cannot decide the step.
- `with_step` continues a sequence at a step derived outside the observed deltas. The classifier's send-index step survives holes, while the adjacent deltas of a gapped sequence read wide, so the strategies prefer `with_step` and fall back to `fit`.

`window(count)` lists the next `count` ports past the last observation. The walk stops at the port range boundary, where the next port depends on where the NAT rebinds; `at` clamps single ports into `1..=65535`. The strategies aim sockets at these ports.

## IPv6

The IPv6 pass collects up to eight global addresses through the same STUN servers. A global address needs no translation, so any address in the list is a direct candidate, and the NAT question stays open for IPv4 only. Answers that name no reachable peer — an IPv4-mapped reflexive address from a dual-stack server, an unspecified, link-local, or multicast one — drop out at collection; loopback stays in so tests can stand it in for a global address.

## Caching

A host that punched recently can pass the previous `NatInfo` to `Puncher::with_cached_nat`, which skips the Probe phase. The cache is the host's judgment: networks change, and a stale classification steers the whole session. The constructor clamps the cached values to the wire limits, so an overlong cache cannot break the signaling frames.
