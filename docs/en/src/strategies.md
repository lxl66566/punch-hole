# The punching strategies

Selection reads both NAT classes and picks one strategy from a matrix. The two sides then execute the same plan on the data plane, each from its own view. This chapter walks the matrix, the five strategies from simplest to heaviest, and the arithmetic that sizes the heavy ones.

## The selection matrix

Selection runs on the **effective** classes, which means a weak EasySym fit has already demoted to HardSym:

| local \ peer | cone or public | easy symmetric | hard symmetric |
|---|---|---|---|
| cone or public | ConeExchange | SymProbe | SymProbe |
| easy symmetric | SymProbe | PredictiveExchange | PredictiveBurst |
| hard symmetric | SymProbe | PredictiveBurst | BirthdayBurst |

The Initiator applies the matrix and sends the result in an `Offer` that also carries the socket counts for both sides and the pulse schedule. The Responder clamps the socket counts to its own limits and answers `Accept`.

Cone readings enter the matrix with confidence. Identical ports across destinations also fall out of an address-dependent symmetric NAT when the whole fan-out crossed one server IP, and a probe that answered fewer than two destinations says nothing at all, so a cone reading counts only when its fan-out answered from at least two IPs with at least two samples. One exception needs no second IP: reflexive addresses on one IP whose hairpin tests both passed prove one endpoint-independent mapping per socket — a per-destination mapping fails the self-loop — so the shared-NAT cone reading is confident and the pair runs ConeExchange. When a cone reading falls short any other way, the pair runs SymProbe with the ambiguous side shooting: the shooter's sockets punch whether that side turns out to be a cone or symmetric, and the price is the port-strict corner of the trusted side, which ConeExchange would have covered.

## The Direct stage

Before the matrix strategy runs, a Direct stage checks whether the pair needs no NAT work at all. It runs whenever both sides reported global IPv6 addresses, or whenever both IPv4 paths are public. The stage gets `direct_window`, one second by default, counted inside the punch budget, and the matrix strategy spends whatever remains.

The addresses a `Hello` carries belong to the sender's probe socket, which is closed by then. So the stage, like every fixed-port stage, waits for the peer's `PortUpdate`, the frame that names the live punch socket's port.

## The Local stage

Two hosts whose reflexive addresses name one NAT may share the LAN underneath it, where a datagram to the peer's local address needs no NAT cooperation at all. When the reflexive IPs match, the plan grows a Local stage that aims at every local address the peer's `Hello` reported, once the peer's `PortUpdate` names its local punch port — a local-only plan announces the pool socket's own port, because no NAT sits between to remap it.

The probe's hairpin self-test decides between the LAN and the matrix. A datagram the probe sent to its own reflexive address looped back — hairpin measured — means the NAT translates between its own hosts and, one mapping per socket, admits the peer once the simultaneous open writes it: the matrix runs, and the mutual sweep of ConeExchange punches the shared NAT. Without the loop, every reflexive-aimed stage dies at the NAT's own loopback drop and the Local stage replaces the matrix outright. With no local addresses on either side, no IPv6 path, and no hairpin, the pair is honestly dead and Negotiate aborts it as `Unpunchable` before any socket opens.

## Estimating a symmetric peer's port span

SymProbe's spray and BirthdayBurst both aim at the ports a symmetric peer's NAT will hand its punch sockets, so both need a span estimate from the probe samples. `k` uniform samples over a span of width `S` show an expected range of `S * (k - 1) / (k + 1)`, so the observed range widened by twice `range / (k - 1)` on each side reads as an upper-confidence estimate of `S`. The confidence factor keeps the estimate above the true span about nine runs in ten at four samples, which is what an honest rate needs: candidates spread over an overshooting estimate hit live mappings exactly as the model states, while an undershoot would read optimistic. The probability model and the candidate sampling read the same estimate, so estimation and sampling stay equally conservative. Fewer than two samples carry no range at all; the estimate then falls back to the upper ephemeral half, the range most NAT families draw from.

## ConeExchange

Both sides open one socket and send Syn pulses at the peer's reflexive address. Simultaneous sending covers restricted filtering, as the primer chapter describes, and the three-way handshake confirms the path.

## SymProbe

Exactly one side is symmetric. The symmetric side shoots: it opens `assistant_sockets`, sixteen by default, and pulses Syn packets at the cone side's announced port from every one of them. The cone side opens one socket, answers every Syn it receives, and also sprays candidate ports at the symmetric peer's public address.

The spray exists for the cone side that filters on address and port. Such a cone drops the symmetric side's pulses, because they arrive from source ports the cone never wrote to. The cone's own spray writes first. When a spray packet lands on a live mapping of the symmetric peer, the SynAck comes back from the peer's address with exactly the candidate port the spray used, so the cone's mapping admits it and the handshake completes through that hit.

The candidate ports follow the peer's effective class:

- A confident easy symmetric peer gets the ports its observed sequence continues to. The window covers the peer's socket count plus a margin of sixteen for unrelated allocations behind the same NAT, and it walks at the classifier's step.
- A hard symmetric peer gets a distinct random stream over its estimated port span. The stream length solves the one-directional model for `target_success`, capped by a share of the packet budget and by the conntrack bound.

An estimate below `min_success` fails Negotiate with `Unpunchable` before any data packet is sent, the same bar BirthdayBurst faces, so a spray the budget or conntrack bound starves never burns the punch window.

The allocations that land between the peer's Probe and its punch sockets move its whole sequence, often past that margin. A symmetric peer with a confident stride therefore re-queries STUN on its punch socket at engine start and announces the observed port; the cone side reads that port as the sequence's current position and moves its fitted window onto it, keeping the window's stride and length.

The spray also holds its start: the shooter's mappings appear only when its pulses leave, and its pulses wait for the cone's PortUpdate, so the cone sprays nothing until peer traffic arrives — one measured RTT plus a tick is the fallback when every inbound packet of the peer's first pulses was lost. Once traffic from the peer arrives, the spray throttles to one packet per sweep so handshake replies keep the send rate.

## PredictiveExchange

Both sides are easy symmetric. Each side fits the peer's sequence, then sends into a window of predicted ports with `predictive_sockets`, eight by default. The window covers both socket counts with a fourfold margin, capped at 512 ports. Both windows start from the same fitted base, which guarantees overlap while the steps hold.

Both sides also announce their current allocation position the same way SymProbe's symmetric side does, and each side moves its fitted window onto the peer's announced position, so the windows overlap on the sequences as they stand at engine start instead of where Probe left them.

## PredictiveBurst

Exactly one side is easy symmetric; the other is hard symmetric, which includes an easy fit demoted for thin evidence. One predictable side is enough: the side facing the hard peer sprays a distinct random stream over its estimated span — the same one-directional spray SymProbe's replying side runs — while the side facing the easy peer covers its whole continuation window at the classifier's step. Either direction completes the handshake: a window Syn lands on a live continuation mapping, or a spray candidate lands on one of the window mappings, and the answer returns from exactly the port that was aimed at.

Each side opens one socket. The easy side's live mappings are exactly the first `easy` ports of the window the hard side covers, because an EasySym mapping walks its constant step and the easy side holds one mapping per covered port; the random direction therefore shoots `easy` candidates at the hard side's `window` live mappings, and the window feeds back into the live count. The solve `easy * (easy + 16) = ln(1 / (1 - target)) * space` runs through the shared spray sizing, so the budget and conntrack caps bind exactly as they do for every other spray.

The easy side announces its current allocation position the same way SymProbe's symmetric side does, and the hard side moves its window onto that mark. Drift between the peer's Probe and its punch sockets — unrelated allocations, and the ports of probe destinations that stayed silent, which the wire sequence never carries — then moves the window instead of sliding the live block out of it.

The estimate states its regime, the way the burst arithmetic states its filtering assumption: while the easy NAT keeps stepping from its last observed port, the window is certain to contain every live mapping, and drift tolerates up to a window width of unrelated allocations before the live block slides out. The random direction is sized for `target_success` on its own and is the quantified fallback when the regime breaks.

## BirthdayBurst

Both sides are symmetric with at least one hard side. Prediction is out of the picture, so the strategy plays the collision game: each side opens sockets, each socket covers distinct ports drawn from the peer's observed span, and both sides pulse at once until a covered port pair collides in both directions.

One sizing function feeds both the decision and the execution. Its regime comes from the measured filters: while at least one side filters non-port-strict — the common CGNAT shape, and the reading `Unknown` stands in for — one directional hit completes the handshake. A hit into side X needs the peer's coverage to land on one of X's live mappings, and sockets and coverage contribute to that only through their product — the live-mapping count — so each side opens one socket and spends its whole mapping share on coverage. The spaces are directional: A's live mappings sit inside A's own port space, so with `c_A` and `c_B` covered ports per side the hit chance is:

```text
chance = 1 - exp(-c_A * c_B * (1/space_A + 1/space_B))
```

An asymmetric pair therefore plays over the effective space `1 / (1/space_A + 1/space_B)`, which sits below the narrower side: a 300-by-20000 pair solves like a 296-wide space instead of a 20000-wide one. The balanced solve covers `ceil(sqrt(ln(1 / (1 - target)) * S_eff))` ports per side, capped by the span it shoots into, the conntrack bound minus reply headroom, and a quarter of the packet budget. When a cap binds, the estimate states the shortfall and the `min_success` gate refuses the pair. With defaults against a full 32768-wide space on both sides, the sizing covers 107 ports per side.

Port lists draw from a generator seeded by the attempt nonce, so both sides cover the space independently while a run stays reproducible from its seed. Sweeps repeat the same covered set, so the per-sweep chance equals the attempt chance, and a side stops emitting new Syns after four full passes: the peer's live set closes within that window — its own sweep, then the answer mappings the handshake chatter mints — and later passes would only repeat covered ports while spending the rate budget that retransmissions need. A run that misses therefore costs the probe fan-out plus four passes per side instead of pulsing to the packet budget.

An estimate below `min_success` fails Negotiate with `Unpunchable` before any data packet is sent, which keeps a hopeless pair cheap for both sides.

## Estimates

SymProbe, PredictiveBurst, and BirthdayBurst report `success_estimate` in `PunchReport`. Both sides compute the same value from their own pair of views, so the reports agree. A pair routed to SymProbe on low cone confidence carries no estimate; its outcome rests on the inbound filters the probe measured, which the selection reads but the spray arithmetic does not price. A host reads the estimate to decide early whether a relay path serves better than a punch attempt.

## The boundary the model states

The burst regime comes from the measured filters, and the two regimes price honestly different games. While at least one side filters non-port-strict, one directional hit completes the handshake and the estimate above holds. When both sides measure port-strict, a hit needs both directions to pair on the exact ports, the chance falls to:

```text
chance = 1 - exp(-c_A * c_B * (c_A + c_B) / (space_A * space_B))
```

which against the default budget clears `min_success` only for narrow spaces, and a wide space aborts the pair as `Unpunchable` in Negotiate before any data packet is sent. `Unknown` on either side reads as the relaxed regime, the historical assumption; the probe reports it when no server speaks RFC 5780 discovery. A host that expects port-strict symmetric peers on both sides and runs without discovery servers plans a relay from the start.
