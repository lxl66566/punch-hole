//! HardSym collision bursts.

use std::net::{SocketAddr, SocketAddrV4};

use rand::{prelude::*, rngs::StdRng};

use super::StageSpec;
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

/// The port span the peer's NAT drew from, widened by a margin.
fn observed_range(seq: &[u16]) -> (u16, u16) {
    const MARGIN: u16 = 32;
    if seq.len() < 2 {
        return (32_768, u16::MAX);
    }
    let min = *seq.iter().min().expect("len checked");
    let max = *seq.iter().max().expect("len checked");
    (min.saturating_sub(MARGIN), max.saturating_add(MARGIN))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_sequences_fall_back_to_the_upper_half() {
        assert_eq!(observed_range(&[1234]), (32_768, u16::MAX));
        assert_eq!(observed_range(&[]), (32_768, u16::MAX));
    }

    #[test]
    fn observed_spans_widen_by_the_margin() {
        assert_eq!(observed_range(&[30_000, 30_050, 30_100]), (29_968, 30_132));
        assert_eq!(observed_range(&[10, 20]), (0, 52));
        assert_eq!(observed_range(&[65_500, 65_530]), (65_468, 65_535));
    }
}
