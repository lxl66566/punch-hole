# Resource control

A punch fires many packets at many addresses, and a careless burst can strain the NAT's translation table or the host's descriptor budget. The send path carries three guards, every limit comes from `PunchConfig`, and cleanup runs on every exit path.

## The three guards on the send path

Every `SocketPool::send` walks the same sequence:

1. **Conntrack bound.** A new destination costs one mapping per live socket, so the pool checks `live sockets × distinct destinations` against `max_mappings` and fails with `ConntrackExhausted` past the bound.
2. **Packet budget.** One session-wide counter caps the total data-plane packets. A failed send returns its unit, so an unreachable route spends nothing.
3. **Rate cap.** A global token grid releases at most `packets_per_sec` packets across every pool socket.

The guards apply to every packet the session sends, handshake replies included. The engine's STUN refresh queries leave through the pool as well: they share the rate grid, count in the session stats, and draw from a small dedicated quota instead of the data-plane budget. They skip the conntrack table because the answer is matched to the querying socket rather than a tracked destination.

## Destination policy

Targets derive from peer-signaled data, so every send validates its destination first: the pool rejects unspecified addresses, port zero, multicast, and the IPv4 broadcast with an `InvalidInput` error, and a peer whose IPv4 address is unspecified yields no IPv4 targets at all. The peer's IPv6 list keeps only addresses that can be a global peer; multicast, link-local, IPv4-mapped, and unspecified entries drop out. Loopback stays allowed in the shipped configuration, because the smoke tests and the NAT lab exercise the engine over real loopback sockets.

## Classification probing

Probe runs before the pool exists, so its fan-out is the one path outside the three guards. The bound is structural: at most `MAX_ALLOC_SEQ` IPv4 plus `MAX_V6_ADDRS` IPv6 destinations, with one extra retry round for silent IPv4 destinations, so at most `2 * MAX_ALLOC_SEQ + MAX_V6_ADDRS` probe packets leave the host. Everything after Probe, refresh queries included, goes through the pool.

## Default footprints

The default footprint of each strategy stays small on purpose:

- BirthdayBurst holds 108 mappings against a 32768-wide port space, 107 covered ports plus the peer's reply port, about a third of one percent of the space.
- PredictiveExchange holds the largest default footprint at 2048 mappings, 8 sockets over a 256-port window, which is why `max_mappings` defaults to 4096.
- The SymProbe spray caps itself at a quarter of the packet budget, and leaves the conntrack bound room for the refresh server and the peer's reply ports.

## Socket counts and channels

`assistant_sockets`, `predictive_sockets`, and `max_sockets` bound the socket counts, with a hard limit of 4096 on `max_sockets`. The event channel between receive tasks and the engine scales with `max_sockets` between 64 and 1024, and the Syn reply gate keeps at most 1024 source keys.

## Cleanup

Every socket belongs to the pool. The winner election cancels the receive tasks, joins them, closes the losers, and hands out the winner as an owned socket. A failed session shuts the whole pool down. A host that drops a session future hits the pool's `Drop`, which cancels the tasks best effort; letting the session future run to completion remains the reliable cleanup path. A session whose every bind failed reports the recorded bind error rather than a generic stopped-stream message. The observation hooks of the simulator and the NAT lab assert the result directly: after handover, exactly one mapping per side survives.

## Platform sockets

`socket/sys.rs` centralizes the differences.

- Linux and macOS bind assistant sockets with `SO_REUSEADDR` and `SO_REUSEPORT`, which speeds up rebinds between attempts. Handover clears both options on the elected winner: bind conflict checks read the flags of the sockets already on a port, so after the clear no same-euid process can duplicate the delivered port with `SO_REUSEPORT`, and on Linux, which demands `SO_REUSEADDR` on both sides of a wildcard-against-specific overlap, none can bind a specific address over it either. macOS consults only the binding socket for that overlap, so there a same-euid `SO_REUSEADDR` bind on a specific address still shadows the wildcard-bound winner; the kernel refuses it from another uid. A process that grabbed the port before the clear keeps its share until it exits.
- Windows binds exclusive sockets with `SO_EXCLUSIVEADDRUSE`, because its `SO_REUSEADDR` lets two sockets claim one port with undefined delivery. Assistant sockets rely on distinct ephemeral ports. The option guards the delivered business socket against the classic local port hijack.
- The winner socket is never rebound; the reuse options matter only while the pool still cycles through attempts.

A connected UDP socket reports the address the OS would route through. The prober uses that trick to tell a public host from a translated one.
