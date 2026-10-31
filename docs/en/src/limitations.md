# Scope and limits

The library is explicit about what it covers. This chapter lists the boundaries, so a host can plan around them before they show up.

## The filtering axis needs a discovery server

The probe measures filtering with the RFC 5780 change-request tests, which only a discovery server that advertises OTHER-ADDRESS can answer. A host whose server list speaks plain RFC 5389 keeps `FilterClass::Unknown`, and the strategies read that as the relaxed case: the symmetric-pair arithmetic assumes address-dependent filtering, the common CGNAT shape. Under address-and-port-dependent filtering on both sides of a symmetric pair, the collision chance falls with the square of the port space and a bounded budget buys effectively nothing; with the tests answered, the pair aborts as `Unpunchable` before any socket opens instead of burning the budget on a near miss. A host that expects that regime plans a relay from the start.

The estimate is a model value. Real CGNAT port spaces vary, and the model reads the peer's observed span, so a wide real space can land the measured rate below the estimate.

## Two ambiguous cone readings on different NATs

A cone reading from a single answered server IP can be an address-dependent mapping seen through one mapping, so a pair of such readings routes to SymProbe, whose reply-side spray writes the peer's observed ports. When the true shape is two address-dependent mappings on different NATs and the peer filters port-strict or address-strict, the shooter's pulses die on the peer's filter and the spray cannot name the peer's fresh punch ports. The hairpin self-test lifts this ambiguity only for hosts that share one NAT — a looped self-request proves one endpoint-independent mapping per socket — and the LAN underneath a shared NAT carries its own Local stage. Two single-IP cone readings on different NATs with strict filters keep the ambiguity: a host that serves single-address server lists behind such NATs plans a relay or a second discovery server.

## One attempt per session

A session is one attempt. The retry loop, the parallel attempts, and the relay fallback belong to the host. [Getting started](getting-started.md) lists the checklist, and the report gives the host the facts to decide: the success estimate, the packet counts, and the phase timings.

## Trust ends at the bridge

The data plane carries the 128-bit nonce as its only credential, and the signaling plane trusts whatever the host channel delivers. The library carries no authentication and no encryption. The host authenticates the peer and rejects replays before frames reach the bridge, and the business protocol on the delivered socket brings its own crypto.

## IPv6 stays minimal

The probe collects global IPv6 addresses and the Direct stage tries the v6 pair first, because a global address needs no NAT cooperation. There is no IPv6 NAT model beyond that, and the v6 case is exercised on loopback, so routing and firewall behavior with real global addresses rests on the general fail-fast path.

## Burst coverage repeats

The birthday burst draws its port list once per attempt, and sweeps repeat the same covered set. A residual miss after the first sweeps stays a miss through the whole budget. Redrawing the covered set per sweep, which would let later sweeps recover an early miss, is future work.

## The cache is the host's judgment

`with_cached_nat` skips Probe with whatever the host hands it. The constructor clamps the values to the wire limits, and the freshness question stays with the host, because only the host knows whether the network changed.
