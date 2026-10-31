//! NAT observation types shared by probing, signaling, and strategy selection.

pub mod classify;
pub mod predict;
pub mod probe;
pub(crate) mod stun;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

pub use predict::PortPredictor;
use serde::{Deserialize, Serialize};

/// Whether an IPv6 reflexive address can carry punch traffic between two
/// distinct hosts.
///
/// Multicast, link-local, unspecified, and IPv4-mapped addresses are not
/// global peer addresses: a mapped address is an IPv4 path in disguise
/// and would make the Direct stage believe a global v6 path exists.
/// Loopback stays usable, so tests without a global address can stand it
/// in for one end to end.
pub(crate) fn usable_v6(ip: Ipv6Addr) -> bool {
    !ip.is_multicast()
        && !ip.is_unicast_link_local()
        && !ip.is_unspecified()
        && ip.to_ipv4_mapped().is_none()
}

/// Behavior of a NAT's outbound address and port mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Behavior of a NAT's inbound filtering.
///
/// Mapping and filtering are separate axes. One external port across
/// destinations proves endpoint-independent mapping, while the filtering
/// class comes from the RFC 5780 change-request tests the probe runs
/// against a discovery-capable server. The simulator sets these variants
/// to model a NAT; probe results carry `Unknown` only when no server
/// advertised OTHER-ADDRESS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterClass {
    EndpointIndependent,
    AddressDependent,
    AddressPortDependent,
    /// The filtering behavior was not measured.
    Unknown,
}

/// Evidence one side collected about itself during Probe.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatInfo {
    pub v4: Option<V4Nat>,
    pub v6: Option<V6Nat>,
    /// The host's own interface addresses on the path the probe ran, for
    /// the Local stage: two hosts whose reflexive addresses name one NAT
    /// may still share the LAN underneath it, where datagrams to the
    /// peer's local address need no NAT cooperation at all. Capped at 8
    /// entries on the wire.
    pub local: Vec<Ipv4Addr>,
}

/// IPv4 NAT observations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct V4Nat {
    pub class: NatClass,
    /// The primary reflexive address.
    pub reflexive: SocketAddrV4,
    /// External ports observed at the NAT, in send order. Capped at 64 entries.
    pub alloc_seq: Vec<u16>,
    /// Distinct server IPs among the answered probe destinations. An
    /// address-dependent NAT gives the whole fan-out one mapping per IP,
    /// so a fan-out that answered from a single IP exercised the mapping
    /// dimension once and a cone reading built from it rests on one
    /// mapping's behavior.
    pub distinct_probe_ips: u8,
    /// Inbound filtering evidence from the RFC 5780 change-request tests.
    /// `Unknown` when no probe server advertised OTHER-ADDRESS.
    pub filtering: FilterClass,
    /// Whether the NAT loops a datagram aimed at its own external address
    /// back to the sender (RFC 4787 §6), measured by the probe's hairpin
    /// self-test. Two hosts whose reflexive addresses share one NAT punch
    /// through the matrix stages only when this holds for both.
    pub hairpin: bool,
}

/// Global IPv6 addresses collected during Probe. Capped at 8 entries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct V6Nat {
    pub addrs: Vec<SocketAddrV6>,
}

impl NatInfo {
    /// The IPv4 mapping class, when any IPv4 evidence exists.
    ///
    /// `None` marks a side that reported no IPv4 path at all, which is
    /// evidence absent, not evidence of a public host: `Public` asserts
    /// the reflexive address is the host's own, a claim only an observed
    /// probe can make.
    #[must_use]
    pub fn v4_class(&self) -> Option<NatClass> {
        self.v4.as_ref().map(|v4| v4.class)
    }

    /// The IPv4 reflexive address, when one was observed.
    #[must_use]
    pub fn reflexive_v4(&self) -> Option<SocketAddrV4> {
        self.v4.as_ref().map(|v4| v4.reflexive)
    }
}

/// Fuzzing entry to the STUN binding response parser, the one parser that
/// consumes raw network bytes outside the wire codecs.
#[cfg(fuzzing)]
#[must_use]
pub fn parse_stun_response(buf: &[u8], txid: &[u8; 12]) -> Option<std::net::SocketAddr> {
    stun::parse_mapped(buf, txid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Missing IPv4 evidence is the absence of a claim, not a public one:
    /// only an observed probe asserts `Public`.
    #[test]
    fn missing_v4_evidence_is_not_public() {
        let none = NatInfo::default();
        assert_eq!(none.v4_class(), None);
        let public = NatInfo {
            v4: Some(V4Nat {
                class: NatClass::Public,
                reflexive: SocketAddrV4::new([203, 0, 113, 7].into(), 5000),
                alloc_seq: vec![5000, 5000],
                distinct_probe_ips: 2,
                filtering: FilterClass::Unknown,
                hairpin: true,
            }),
            v6: None,
            local: Vec::new(),
        };
        assert_eq!(public.v4_class(), Some(NatClass::Public));
    }
}
