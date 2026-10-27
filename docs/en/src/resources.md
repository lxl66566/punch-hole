# Resource control

A punch fires many packets at many addresses, and a careless burst can strain the NAT's translation table or the host's descriptor budget. The send path carries three guards, every limit comes from `PunchConfig`, and cleanup runs on every exit path.

## The three guards on the send path

Every `SocketPool::send` walks the same sequence:

1. **Conntrack bound.** A new destination costs one mapping per live socket, so the pool checks `live sockets × distinct destinations` against `max_mappings` and fails with `ConntrackExhausted` past the bound.
2. **Packet budget.** One session-wide counter caps the total data-plane packets. A failed send returns its unit, so an unreachable route spends nothing.
3. **Rate cap.** A global token grid releases at most `packets_per_sec` packets across every pool socket.

The guards apply to every packet the session sends, handshake replies included.

## Default footprints

The default footprint of each strategy stays small on purpose:

- BirthdayBurst holds 108 mappings against a 32768-wide port space, 107 covered ports plus the peer's reply port, about a third of one percent of the space.
- PredictiveExchange holds the largest default footprint at 2048 mappings, 8 sockets over a 256-port window, which is why `max_mappings` defaults to 4096.
- The SymProbe spray caps itself at a quarter of the packet budget and one slot below the conntrack bound.

## Socket counts and channels

`assistant_sockets`, `predictive_sockets`, and `max_sockets` bound the socket counts, with a hard limit of 4096 on `max_sockets`. The event channel between receive tasks and the engine scales with `max_sockets` between 64 and 1024, and the Syn reply gate keeps at most 1024 source keys.

## Cleanup

Every socket belongs to the pool. The winner election cancels the receive tasks, joins them, closes the losers, and hands out the winner as an owned socket. A failed session shuts the whole pool down. A host that drops a session future hits the pool's `Drop`, which cancels the tasks best effort. The observation hooks of the simulator and the NAT lab assert the result directly: after handover, exactly one mapping per side survives.

## Platform sockets

`socket/sys.rs` centralizes the differences.

- Linux and macOS bind assistant sockets with `SO_REUSEADDR` and `SO_REUSEPORT`, which speeds up rebinds between attempts.
- Windows binds exclusive sockets with `SO_EXCLUSIVEADDRUSE`, because its `SO_REUSEADDR` lets two sockets claim one port with undefined delivery. Assistant sockets rely on distinct ephemeral ports. The option guards the delivered business socket against the classic local port hijack.
- The winner socket is kept as-is and never rebound, so port reuse only matters for fast retry cycles.

A connected UDP socket reports the address the OS would route through. The prober uses that trick to tell a public host from a translated one.
