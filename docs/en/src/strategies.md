# The punching strategies

Selection reads both NAT classes and picks one strategy from a matrix. The two sides then execute the same plan on the data plane, each from its own view. This chapter walks the matrix, the four strategies from simplest to heaviest, and the arithmetic that sizes the heavy ones.

## The selection matrix

Selection runs on the **effective** classes, which means a weak EasySym fit has already demoted to HardSym:

| local \ peer | cone or public | easy symmetric | hard symmetric |
|---|---|---|---|
| cone or public | ConeExchange | SymProbe | SymProbe |
| easy symmetric | SymProbe | PredictiveExchange | BirthdayBurst |
| hard symmetric | SymProbe | BirthdayBurst | BirthdayBurst |

The Initiator applies the matrix and sends the result in an `Offer` that also carries the socket counts for both sides and the pulse schedule. The Responder clamps the socket counts to its own limits and answers `Accept`.

## The Direct stage

Before the matrix strategy runs, a Direct stage checks whether the pair needs no NAT work at all. It runs whenever both sides reported global IPv6 addresses, or whenever both IPv4 paths are public. The stage gets `direct_window`, one second by default, counted inside the punch budget, and the matrix strategy spends whatever remains.

The addresses a `Hello` carries belong to the sender's probe socket, which is closed by then. So the stage, like every fixed-port stage, waits for the peer's `PortUpdate`, the frame that names the live punch socket's port.

## ConeExchange

Both sides open one socket and send Syn pulses at the peer's reflexive address. Simultaneous sending covers restricted filtering, as the primer chapter describes, and the three-way handshake confirms the path.

## SymProbe

Exactly one side is symmetric. The symmetric side shoots: it opens `assistant_sockets`, sixteen by default, and pulses Syn packets at the cone side's announced port from every one of them. The cone side opens one socket, answers every Syn it receives, and also sprays candidate ports at the symmetric peer's public address.

The spray exists for the cone side that filters on address and port. Such a cone drops the symmetric side's pulses, because they arrive from source ports the cone never wrote to. The cone's own spray writes first. When a spray packet lands on a live mapping of the symmetric peer, the SynAck comes back from the peer's address with exactly the candidate port the spray used, so the cone's mapping admits it and the handshake completes through that hit.

The candidate ports follow the peer's effective class:

- A confident easy symmetric peer gets the ports its observed sequence continues to. The window covers the peer's socket count plus a margin of sixteen for unrelated allocations behind the same NAT, and it walks at the classifier's step.
- A hard symmetric peer gets a distinct random stream over its observed port span. The stream length solves the one-directional model for `target_success`, capped by a share of the packet budget and by the conntrack bound.

Once traffic from the peer arrives, the spray throttles to one packet per sweep so handshake replies keep the send rate.

## PredictiveExchange

Both sides are easy symmetric. Each side fits the peer's sequence, then sends into a window of predicted ports with `predictive_sockets`, eight by default. The window covers both socket counts with a fourfold margin, capped at 512 ports. Both windows start from the same fitted base, which guarantees overlap while the steps hold.

## BirthdayBurst

Both sides are symmetric with at least one hard side. Prediction is out of the picture, so the strategy plays the collision game: each side opens sockets, each socket covers distinct ports drawn from the peer's observed span, and both sides pulse at once until a covered port pair collides in both directions.

One sizing function feeds both the decision and the execution. The model assumes address-dependent filtering, the common CGNAT shape, under which one directional hit completes the handshake. With `n` sockets and `c` covered ports per side against a port space of `space`, the hit chance is:

```text
chance = 1 - exp(-(n_A * c_A * c_B + n_B * c_B * c_A) / space)
```

Coverage is the leverage: every mapping spent on a wider covered set buys more chance than a mapping spent on another socket. The sizing therefore opens one socket per side and raises the socket count only when coverage hits a cap. The caps are the peer's drawable port window, the conntrack bound minus reply headroom, a quarter of the packet budget, and `max_sockets`. With defaults against a full 32768-wide space, the sizing picks one socket per side covering 107 ports.

Port lists draw from a generator seeded by the attempt nonce, so both sides cover the space independently while a run stays reproducible from its seed. Sweeps repeat the same covered set, so the per-sweep chance equals the attempt chance.

An estimate below `min_success` fails Negotiate with `Unpunchable` before any data packet is sent, which keeps a hopeless pair cheap for both sides.

## Estimates

SymProbe and BirthdayBurst report `success_estimate` in `PunchReport`. Both sides compute the same value from their own pair of views, so the reports agree. A host reads the estimate to decide early whether a relay path serves better than a punch attempt.

## The boundary the model states

The burst arithmetic states its assumption in the open: it assumes address-dependent filtering on both symmetric NATs. Under address-and-port-dependent filtering on both sides, a hit needs both directions to pair on the exact ports, the chance falls near `(n * c)² / space²`, and a bounded budget buys effectively nothing. A host that expects port-strict symmetric peers on both sides plans a relay from the start.
