# Wire protocol

The protocol runs over two planes with different trust levels. This chapter specifies the encoding, the frames, the handshake, and the security posture. The struct definitions match the code in `src/msg/mod.rs`.

## Planes and roles

The **signaling plane** is the channel the host provides. It carries frames as opaque bytes. The channel should preserve order, and frame retransmission tolerates loss.

The **data plane** is plain UDP between the two NATs. It carries small packets that the network drops and reorders freely, and that any third party may write to.

Each attempt has two roles. The Initiator owns every decision that needs one owner: it draws the nonce, picks the strategy, and sets the pulse schedule. The Responder confirms and follows. Both roles run the same library code.

One signaling bridge serves exactly one attempt. Hosts that run parallel attempts wrap the frames in their own envelope and route them to separate bridges.

## Encoding

Frames and packets are serde structs encoded with postcard. A host that wants typed access can decode them into its own format, and the wire format stays compact.

```text
signaling: [version: u8][postcard SigFrame]
data:      [magic: 0x70][version: u8][postcard DataPacket]
```

The two planes treat garbage differently. A signaling frame that fails to decode is skipped and reception continues, which keeps a stray datagram on a shared host channel from ending the session. A data packet that fails to decode is dropped silently, because the data plane is hostile by design. A version mismatch on either plane ends the session, because no productive exchange can follow it.

Durations travel as plain millisecond integers. The API accepts `Duration` and converts at the boundary.

## Versioning

Both sides must run the same `VERSION`, currently 2. Enum variants are append-only across releases, and postcard encodes them as variant indices, so reordering or removing a variant requires a version bump.

## Shared values

```rust
/// Random 16 bytes drawn by the Initiator. Tags every packet of one attempt.
pub type Nonce = [u8; 16];

pub enum NatClass {
    /// The reflexive IPv4 address matches the local address.
    Public,
    /// One external port per internal socket, regardless of destination.
    Cone,
    /// A new port per destination, allocated with a constant step.
    EasySym { step: i16 },
    /// A new port per destination, allocated unpredictably.
    HardSym,
}

pub enum FilterClass {
    EndpointIndependent,
    AddressDependent,
    AddressPortDependent,
    /// The filtering behavior was not measured. A probe always reports this.
    Unknown,
}

pub enum StrategyId {
    ConeExchange,
    SymProbe,
    PredictiveExchange,
    BirthdayBurst,
}

pub enum AbortReason {
    Unpunchable,
    BudgetExhausted,
    Internal,
}
```

`NatInfo` is the evidence one side collected about itself during Probe:

```rust
pub struct NatInfo {
    pub v4: Option<V4Nat>,
    pub v6: Option<V6Nat>,
}

pub struct V4Nat {
    pub class: NatClass,
    /// The primary reflexive address.
    pub reflexive: SocketAddrV4,
    /// External ports observed at the NAT, in send order. Capped at 64 entries.
    pub alloc_seq: Vec<u16>,
    /// Inbound filtering evidence. A probe runs no filtering test, so the
    /// value is always `Unknown`.
    pub filtering: FilterClass,
}

pub struct V6Nat {
    /// Global addresses collected during Probe. Capped at 8 entries.
    pub addrs: Vec<SocketAddrV6>,
}
```

Both sides fit the peer's `alloc_seq` locally with the same predictor. A side sends observations only, and the predictions stay local.

## Signaling frames

```rust
pub struct SigFrame {
    /// Milliseconds on the sender's own monotonic clock.
    pub ts: u64,
    /// The ts field of the frame being answered, 0 when the frame answers none.
    pub echo: u64,
    pub body: Frame,
}

pub enum Frame {
    Hello(NatInfo),
    Offer(Offer),
    Accept,
    /// Fresh socket-0 ports of the sender, one slot per family it punches
    /// over. A family the plan leaves out carries None.
    PortUpdate { v4: Option<u16>, v6: Option<u16> },
    /// The sender finished the handshake on its winning socket.
    Confirmed { socket: u16 },
    Abort(AbortReason),
}

pub struct Offer {
    pub nonce: Nonce,
    pub strategy: StrategyId,
    /// Sockets the Initiator will open.
    pub local_sockets: u16,
    /// Sockets the Responder should open.
    pub peer_sockets: u16,
    /// Pulse start delay in milliseconds, counted from the Responder
    /// sending Accept.
    pub start_delay_ms: u32,
}
```

**Hello** carries the sender's `NatInfo`. Both sides send it during Exchange and repeat it until the peer's `Hello` arrives.

**Offer** carries the plan the Initiator derived from both `NatInfo` values. The nonce becomes the attempt's identity on the data plane.

**Accept** confirms the plan. The Responder starts counting `start_delay_ms` from the moment it sends `Accept`, and both sides anchor their clocks on that shared event.

**PortUpdate** names the fresh external port of the sender's punch socket, one slot per family. The reflexive address from Probe belongs to the closed probe socket, so fixed-port stages wait for this frame. A public or IPv6 sender reads its own local address, and a cone-mapped sender re-queries STUN on the punch socket itself. The frame re-sends on the signaling retry cadence until the sender's handshake completes.

**Confirmed** announces that the sender finished the data-plane handshake and names its winning socket index. It stops the peer's pulse phase early and ends the sender-side grace responder.

**Abort** tells the peer the sender stopped and why. The peer fails fast with `PeerAborted(reason)` instead of draining its deadlines.

Frame handling is idempotent. A duplicated frame is ignored, and a frame from a finished phase is ignored. One exception: an `Offer` that arrives while a side is itself the Initiator means both sides claimed the role, and the session aborts on both sides.

## Data-plane packets

```rust
pub enum DataPacket {
    Syn { nonce: Nonce, socket: u16 },
    SynAck { nonce: Nonce, socket: u16 },
    Ack { nonce: Nonce },
    Keepalive { nonce: Nonce },
}
```

Every packet carries the attempt nonce, and the receive path validates it before any handshake action, which discards stale packets from earlier attempts between the same hosts. The `socket` field names the sender's pool index, which the reports use to say which of the peer's sockets won.

The confirmation handshake runs on the winner path itself:

```text
Initiator socket k                    Responder socket m
   |---- Syn {nonce, k} -------------->|   repeated
   |<--- SynAck {nonce, m} ------------|   repeated
   |---- Ack {nonce} ----------------->|   repeated until Confirmed or grace end
```

`Syn` proves Initiator to Responder. `SynAck` proves the reverse direction, and the Initiator is confirmed the moment it arrives. The final `Ack` proves the forward direction again and confirms the Responder. `Syn` and `SynAck` repeat on the confirm retry timer, and the grace responder answers repeated `SynAck` after the Initiator is confirmed, so a peer that is still waiting always gets its answer.

Each side closes its loser sockets at its own confirmation.

**Keepalive** holds the NAT mapping open after handover. Hosts discard any datagram whose first byte is `0x70` and whose length stays under 64 bytes.

## Loss handling on the signaling plane

`Hello`, `Offer`, and `Accept` retransmit on the signaling retry timer, 500 milliseconds by default, until their phase completes. `PortUpdate` retransmits on the same timer until the sender's handshake completes. The frames are idempotent, so hosts with reliable channels simply deliver each frame once. `Confirmed` is covered by the grace expiry and `Abort` is best effort, so neither retransmits.

## Timestamps and pulse alignment

`ts` values come from each side's own monotonic clock and have no meaning across hosts. A side measures signaling RTT by sending a frame with `ts`, reading that value back in the answer's `echo`, and taking the difference against its local receive time. The Initiator derives `start_delay_ms` from the larger of the two RTT estimates plus a 300 millisecond margin, and both sides count the delay from the shared event of the Responder sending `Accept`.

## Limits and timers

| limit | value |
|---|---|
| signaling frame | 1024 B |
| data packet | 64 B |
| `alloc_seq` entries | 64 |
| IPv6 address entries | 8 |
| pool index | u16 |

| timer | default |
|---|---|
| signaling retry | 500 ms |
| confirm retry | 200 ms |
| grace period | 2 s |
| keepalive interval | 10 s |

## Security posture

The nonce keeps foreign and stale packets out of an attempt. An attacker who can guess a 128-bit nonce can inject handshake packets, which reduces to noise.

The protocol carries no authentication and no encryption of its own. Securing the signaling channel is the host's job: authenticate the peer, reject replays, and keep the channel confidential before feeding it into the bridge. Whoever can read the signaling frames holds the nonce and can forge the handshake packets of that attempt, so signaling confidentiality is part of the security of the data plane.

The packets are small and every rate is capped, so the protocol creates no amplification surface. An attacker on the path can deny service to any UDP flow by dropping packets, and retransmission hides brief loss while sustained loss ends the attempt on its phase deadline.
