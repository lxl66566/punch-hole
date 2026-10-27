# Configuration

`PunchConfig` carries every knob. The defaults fit a normal session against public STUN servers, and `Puncher::new` rejects a config that could never complete a session.

## Fields

| field | default | meaning |
|---|---|---|
| `stun_servers` | four public servers | STUN servers as `host:port`. A confident easy-symmetric fit wants at least four distinct destinations. |
| `probe_timeout` | 3 s | Time one STUN server has to answer before the prober moves on. |
| `assistant_sockets` | 16 | Sockets the symmetric side opens in SymProbe. |
| `predictive_sockets` | 8 | Sockets each side opens in PredictiveExchange. |
| `max_sockets` | 256 | Hard cap on sockets one session opens on either family. |
| `packets_per_sec` | 400 | Global send rate cap across every pool socket. |
| `packet_budget` | 4096 | Total data-plane packets one session may send. |
| `max_mappings` | 4096 | Cap on live sockets times distinct destinations, the session's conntrack footprint. |
| `signaling_retry` | 500 ms | Retransmission cadence for signaling frames. |
| `exchange_timeout` | 10 s | Budget for the Exchange phase, counted from its start. |
| `negotiate_timeout` | 10 s | Budget for Negotiate, counted from session start. |
| `punch_timeout` | 15 s | Time the Punch and Confirm phases share. |
| `confirm_retry` | 200 ms | Retransmission cadence for handshake packets. |
| `grace` | 2 s | How long a confirmed side answers repeated handshake packets before handing over. |
| `direct_window` | 1 s | Time the Direct stage gets, counted inside `punch_timeout`. |
| `target_success` | 0.5 | Success rate the burst sizing aims for. |
| `min_success` | 0.1 | Estimates below this fail Negotiate with `Unpunchable`. |
| `overall_deadline` | 60 s | Hard wall-clock limit for the whole session. |
| `ipv6` | true | Whether to probe and punch over IPv6. |
| `tick` | 50 ms | Engine heartbeat cadence. |

## Validation rules

`PunchConfig::validate` rejects:

- an empty STUN list,
- zero socket counts, rate, budget, or mappings,
- socket counts above their bounds, including `max_sockets` past 4096,
- any zero duration,
- a success target outside 0.0 to 1.0,
- `min_success` above `target_success`.

## Tuning notes

The phases stack: Probe runs up to `probe_timeout`, Exchange gets `exchange_timeout` from its own start, Negotiate gets `negotiate_timeout` from session start, and Punch plus Confirm share `punch_timeout`. Every deadline sits under `overall_deadline`, which is the wall to raise first when a slow network needs more room.

Compressed timers make tests fast. The simulator suites shrink `tick`, `confirm_retry`, `grace`, and the budgets by an order of magnitude and keep the session logic intact.
