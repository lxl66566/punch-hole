//! HardSym collision bursts.

use std::net::{SocketAddr, SocketAddrV4};

use rand::{prelude::*, rngs::StdRng};

use super::{StageSpec, observed_range};
use crate::{config::PunchConfig, msg::Nonce, nat::NatInfo, socket::Family};

/// Synchronized pulse bursts into the peer's observed port space.
///
/// The port list is drawn from a generator seeded by the attempt nonce and
/// the role salt, so both sides cover the space independently while the run
/// stays reproducible for a seed.
pub(crate) fn stage(
    my_sockets: u16,
    peer: &NatInfo,
    nonce: Nonce,
    salt: u64,
    cfg: &PunchConfig,
) -> Option<StageSpec> {
    let v4 = peer.v4.as_ref()?;
    let ip = *v4.reflexive.ip();
    let (lo, hi) = observed_range(&v4.alloc_seq);
    let seed = u64::from_be_bytes(nonce[..8].try_into().expect("nonce is 16 bytes")) ^ salt;
    let mut rng = StdRng::seed_from_u64(seed);
    let coverage = (my_sockets as usize * 4).min(256);
    let targets: Vec<SocketAddr> = (0..coverage)
        .map(|_| SocketAddr::V4(SocketAddrV4::new(ip, rng.random_range(lo..=hi))))
        .collect();
    Some(StageSpec::send(
        Family::V4,
        my_sockets as usize,
        targets,
        false,
        cfg.punch_timeout,
    ))
}
