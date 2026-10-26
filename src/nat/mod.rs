//! NAT observation types shared by probing, signaling, and strategy selection.

pub mod classify;
pub mod predict;
pub mod probe;

use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

pub use predict::PortPredictor;
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterClass {
    EndpointIndependent,
    AddressDependent,
    AddressPortDependent,
    /// The probe servers could not answer the filtering tests.
    Unknown,
}

/// Evidence one side collected about itself during Probe.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NatInfo {
    pub v4: Option<V4Nat>,
    pub v6: Option<V6Nat>,
}

/// IPv4 NAT observations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct V4Nat {
    pub class: NatClass,
    /// The primary reflexive address.
    pub reflexive: SocketAddrV4,
    /// Distinct public IPv4 addresses across the probe answers, in send
    /// order. The first entry is the address `reflexive` reports. Capped at
    /// 4 entries.
    pub pub_ips: Vec<Ipv4Addr>,
    /// External ports observed at the NAT, in send order. Capped at 64 entries.
    pub alloc_seq: Vec<u16>,
    pub filtering: FilterClass,
}

/// Global IPv6 addresses collected during Probe. Capped at 8 entries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct V6Nat {
    pub addrs: Vec<SocketAddrV6>,
}

impl NatInfo {
    /// The IPv4 mapping class, defaulting to `Public` when no IPv4 path exists.
    #[must_use]
    pub fn v4_class(&self) -> NatClass {
        match &self.v4 {
            Some(v4) => v4.class,
            None => NatClass::Public,
        }
    }

    /// The IPv4 reflexive address, when one was observed.
    #[must_use]
    pub fn reflexive_v4(&self) -> Option<SocketAddrV4> {
        self.v4.as_ref().map(|v4| v4.reflexive)
    }
}
