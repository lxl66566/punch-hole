//! HardSym collision bursts.

use std::net::{SocketAddr, SocketAddrV4};

use super::{StageSpec, burst_len, distinct_ports, observed_range, size_burst};
use crate::{config::PunchConfig, msg::Nonce, nat::NatInfo, socket::Family};

/// Synchronized pulse bursts into the peer's observed port space.
///
/// The shared sizing function decides both the socket count and the covered
/// port count, so the stage executes what selection estimated. Port lists are
/// drawn from a generator seeded by the attempt nonce and the role salt, so
/// both sides cover the space independently while the run stays reproducible
/// for a seed.
pub(crate) fn stage(
    my_sockets: u16,
    peer: &NatInfo,
    space: usize,
    nonce: Nonce,
    salt: u64,
    cfg: &PunchConfig,
) -> Option<StageSpec> {
    let v4 = peer.v4.as_ref()?;
    let ip = *v4.reflexive.ip();
    // Selection sized the negotiated socket count with the same pure call,
    // so the bound count and the sized count agree whenever both sides run
    // the same config.
    let (_n, _m, coverage) = size_burst(space, cfg);
    let (lo, hi) = observed_range(&v4.alloc_seq);
    let seed = u64::from_be_bytes(nonce[..8].try_into().expect("nonce is 16 bytes")) ^ salt;
    let targets: Vec<SocketAddr> = distinct_ports(seed, lo, hi, coverage)
        .into_iter()
        .map(|port| SocketAddr::V4(SocketAddrV4::new(ip, port)))
        .collect();
    let mut stage = StageSpec::send(
        Family::V4,
        my_sockets as usize,
        targets,
        false,
        cfg.punch_timeout,
    );
    // A lone sender covers several ports per tick, so one rotation finishes
    // well inside the punch window at the configured rate cap. Capping at the
    // target count keeps a sweep from repeating ports it already covered.
    let per_sweep = (burst_len(cfg) as usize).min(stage.targets.len());
    stage.per_sweep = per_sweep as u16;
    Some(stage)
}
