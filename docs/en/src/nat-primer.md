# How UDP hole punching works

Two hosts behind NAT devices want to exchange UDP directly. A datagram crosses a NAT only when the NAT already holds a mapping that admits it. Hole punching creates those mappings on purpose, at the same moment on both sides. This chapter builds that idea step by step, from what a NAT does to why a pair of hostile NATs stays out of reach.

## What a NAT does

A home router owns one public IPv4 address for a whole LAN. When the laptop at `192.168.1.10:5000` sends a datagram to `1.2.3.4:3478`, the router rewrites the source to its own address with a fresh port, say `203.0.113.7:61000`, and writes the pair into its translation table:

```text
internal 192.168.1.10:5000  ↔  public 203.0.113.7:61000
```

That table entry is a mapping. Datagrams from the laptop keep it alive, and inbound datagrams that match it flow back to the laptop. The table has finite room, which is one reason a punch library must watch how many mappings it creates.

## Mapping and filtering are two behaviors

NAT behavior splits into two axes, and hole punching treats them separately.

The **mapping** decides which public address and port an outbound flow receives.

| mapping class | rule |
|---|---|
| endpoint-independent | one mapping per socket, reused for every destination |
| address-dependent | one mapping per destination address |
| address-and-port-dependent | one mapping per destination address and port |

The **filtering** decides which inbound datagrams the NAT forwards through an existing mapping.

| filtering class | rule |
|---|---|
| endpoint-independent | any source may send in |
| address-dependent | sources the socket has written to may send in |
| address-and-port-dependent | only the exact address and port the socket wrote to |

A **cone** NAT maps endpoint-independently, which makes one mapping serve every destination. A **symmetric** NAT maps per destination, so the port aimed at one server differs from the port aimed at another. The filtering classes cut across that split. The most common home router maps endpoint-independently and filters on address and port, the combination that older literature calls a port-restricted cone.

## The reflexive address

A host behind a NAT sees its private address and stays blind to its public one. A STUN server tells it. The host sends a binding request to the server, the server reads the source address the datagram arrived with, and that source, `203.0.113.7:61000` in the example, is the **reflexive address**.

The reflexive address is the fact hole punching exchanges first. It describes one specific socket, and each socket gets its own allocation, so every strategy re-checks the port it aims at. That detail returns throughout the book.

## The rendezvous problem

Punching needs each side to send datagrams at the other side's reflexive address. Neither side starts with that knowledge, so the two sides need a channel that already works. In punch-hole this is the host's signaling transport: any channel that carries small frames, ordered and authenticated, such as an RPC stream, a WebSocket, or a DHT record.

The library treats that channel as opaque bytes. The host pumps frames on both ends and the punching state machine does the rest.

## Simultaneous open

Here is the punch itself, between two cone NATs with address-and-port-dependent filtering:

1. Both sides learn each other's reflexive address over signaling.
2. Both sides start sending datagrams at the peer's reflexive address, at the agreed moment.
3. The first datagrams each way reach a NAT whose filtering has never seen the peer, so they drop.
4. Each datagram a side sends also writes outbound state into its own mapping. Once side A has sent to side B's public address, A's NAT admits datagrams that come back from that exact address and port.
5. The next crossing of packets lands. The hole is open.

Step 4 carries the trick. Filters read recent outbound traffic as permission, and simultaneous sending manufactures that permission on both sides at once. Retransmission covers the timing, because the first crossings land only after both mappings hold the right state.

## Why cone pairs punch easily

A cone NAT gives a socket one port for every destination. The reflexive address a STUN probe reported for the punch socket therefore stays valid. Each side opens one socket, aims it at the peer's reflexive address, and the exchange above finishes the job. One socket per side covers the whole case.

## Why symmetric NATs are hard

A symmetric NAT allocates a fresh port per destination. The port it gave the STUN probe serves the STUN server, and a peer aiming at that port hits a mapping that points elsewhere. The reflexive address goes stale the moment the peer writes to it.

The rescue depends on how the NAT picks its ports.

Some symmetric NATs allocate in a regular walk, two ports per allocation for example. The observed port sequence then continues into the future, and the peer can aim at the ports that do not exist yet. punch-hole calls this an **easy symmetric** NAT and predicts the next ports from the observed sequence.

Other symmetric NATs draw ports unpredictably. Prediction fails, so the strategy widens instead: many sockets, each covering a slice of the port space, both sides firing at once until two covered ports collide. This is the **hard symmetric** case, and the collision game is the birthday attack, named for the birthday paradox that makes shared finds likely once enough draws happen.

## What stays out of reach

Filtering has the final word. When both symmetric NATs filter on address and port, a datagram passes only if the sender had already written to that exact address and port. Both sides must then cover the same port pair from both directions, the chance of that match falls with the square of the port space, and any bounded packet budget lands near zero.

One asymmetric rescue remains: when a hard symmetric NAT faces a cone, the cone side writes first and the symmetric side's mapping then admits the reply. The strategies chapter shows how. A pair of port-strict symmetric NATs instead needs a relay, which the host provides.

## Glossary

| term | meaning |
|---|---|
| mapping | the NAT table entry that translates one internal flow to one public address and port |
| filtering | the rule that decides which inbound datagrams cross an existing mapping |
| reflexive address | the public address and port a STUN server observes for a socket |
| cone NAT | maps endpoint-independently, one port per socket |
| symmetric NAT | allocates per destination, one port per destination |
| easy symmetric | symmetric with a constant allocation step the sequence reveals |
| hard symmetric | symmetric with unpredictable allocation |
| conntrack | the NAT translation table, and its finite room |
| simultaneous open | both sides send at once so each mapping learns to admit the other |
| punch | the whole maneuver that turns a signaling agreement into a working UDP path |
