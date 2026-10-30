//! Deterministic virtual network with simulated NAT devices.
//!
//! A [`Net`] owns one router task and a virtual IPv4 space. Hosts attach
//! directly or behind a [`NatSpec`], STUN servers answer binding requests,
//! and every packet crosses the router, which applies translation,
//! filtering, and loss. All randomness flows through one seeded generator,
//! and tests run under paused tokio time, so a run reproduces from its seed.
//! Hosts plug into consumer code through the [`UdpFactory`] seam.
// Trait signatures stay async even when a virtual operation never yields.
#![allow(clippy::unused_async_trait_impl)]

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::Range,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU32, Ordering},
    },
};

use rand::{prelude::*, rngs::StdRng};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    MAX_DATAGRAM,
    socket::{UdpFactory, UdpIo},
    stun::Grid,
};

/// Inbound filtering behavior of a simulated NAT, per RFC 4787.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterClass {
    /// Any source may reach the mapping.
    EndpointIndependent,
    /// Only sources on an address the mapping already sent to.
    AddressDependent,
    /// Only sources the mapping already sent to, address and port.
    AddressPortDependent,
}

/// RFC 4787 mapping behavior: which destinations reuse an existing mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingBehavior {
    /// One mapping per internal socket; every destination reuses it.
    EndpointIndependent,
    /// One mapping per destination address: the ports of one server share
    /// it, and a second server address opens its own. Common CGNAT shape.
    AddressDependent,
    /// A fresh mapping per destination address and port.
    AddressPortDependent,
}

/// RFC 4787 §4.1 allocation policy: how a fresh external port is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allocation {
    /// Sequential walk through `port_range`, advancing `step` per
    /// allocation.
    Increment { step: i16 },
    /// Uniform random draw from `port_range` per allocation, from the ports
    /// no live mapping holds.
    Random,
    /// Mirror the client's internal port; on collision fall back to the
    /// sequential walk through `port_range`.
    ///
    /// The walk starts at `port_range` and not at the internal port,
    /// because an OS-assigned client port usually sits outside the range
    /// the NAT allocates from.
    Preserve,
}

/// Configuration of one simulated NAT: the two orthogonal RFC 4787 axes
/// over a port range, plus the inbound filtering class and the hairpinning
/// switch.
#[derive(Debug, Clone)]
pub struct NatSpec {
    pub mapping: MappingBehavior,
    pub allocation: Allocation,
    pub filtering: FilterClass,
    pub port_range: Range<u16>,
    /// Whether datagrams aimed at one of this NAT's own external addresses
    /// loop back to the internal host behind the live mapping (RFC 4787 §6
    /// hairpinning). A hairpinned datagram arrives as if from outside: the
    /// source is the sender's translated address and the target mapping's
    /// filter applies to it. With `false`, the NAT still opens the sender's
    /// mapping, then drops the datagram like the broken no-loopback NATs a
    /// puncher must survive; [`Net::dropped_by_hairpin`] counts the drops.
    pub hairpin: bool,
}

impl NatSpec {
    /// A cone NAT with endpoint-independent filtering.
    #[must_use]
    pub fn cone_eif() -> Self {
        Self {
            mapping: MappingBehavior::EndpointIndependent,
            allocation: Allocation::Increment { step: 1 },
            filtering: FilterClass::EndpointIndependent,
            port_range: 1024..65535,
            hairpin: true,
        }
    }

    /// A cone NAT with address-and-port-dependent filtering.
    #[must_use]
    pub fn cone_apdf() -> Self {
        Self {
            mapping: MappingBehavior::EndpointIndependent,
            allocation: Allocation::Increment { step: 1 },
            filtering: FilterClass::AddressPortDependent,
            port_range: 1024..65535,
            hairpin: true,
        }
    }

    /// A sequential symmetric NAT with the given step.
    ///
    /// Address-dependent filtering matches common CGNAT behavior: symmetric
    /// mapping with port-strict filtering on both ends is the pathological
    /// pair that birthday bursts exist for.
    #[must_use]
    pub fn sequential(step: i16) -> Self {
        Self {
            mapping: MappingBehavior::AddressPortDependent,
            allocation: Allocation::Increment { step },
            filtering: FilterClass::AddressDependent,
            port_range: 30000..40000,
            hairpin: true,
        }
    }

    /// An address-dependent sequential symmetric NAT with the given step.
    ///
    /// One mapping covers every port of one destination address, so a
    /// fan-out over several ports of one server reads as a cone.
    #[must_use]
    pub fn address_sequential(step: i16) -> Self {
        Self {
            mapping: MappingBehavior::AddressDependent,
            allocation: Allocation::Increment { step },
            filtering: FilterClass::AddressDependent,
            port_range: 30000..40000,
            hairpin: true,
        }
    }

    /// A random symmetric NAT drawing from the given range.
    #[must_use]
    pub fn random(range: Range<u16>) -> Self {
        Self {
            mapping: MappingBehavior::AddressPortDependent,
            allocation: Allocation::Random,
            filtering: FilterClass::AddressDependent,
            port_range: range,
            hairpin: true,
        }
    }

    /// An endpoint-independent NAT drawing each socket's port at random
    /// from the given range: the common home-router shape, one
    /// unpredictable port per socket shared by every destination.
    #[must_use]
    pub fn random_eif(range: Range<u16>) -> Self {
        Self {
            mapping: MappingBehavior::EndpointIndependent,
            allocation: Allocation::Random,
            filtering: FilterClass::EndpointIndependent,
            port_range: range,
            hairpin: true,
        }
    }

    /// A port-preserving NAT with the given filtering.
    ///
    /// Each socket's first mapping mirrors its internal port while that
    /// port is free, which keeps port predictions exact; collisions fall
    /// back to the sequential walk.
    #[must_use]
    pub fn preserved(filtering: FilterClass) -> Self {
        Self {
            mapping: MappingBehavior::EndpointIndependent,
            allocation: Allocation::Preserve,
            filtering,
            port_range: 30000..40000,
            hairpin: true,
        }
    }

    /// Replaces the mapping behavior.
    #[must_use]
    pub fn with_mapping(mut self, mapping: MappingBehavior) -> Self {
        self.mapping = mapping;
        self
    }

    /// Replaces the allocation policy.
    #[must_use]
    pub fn with_allocation(mut self, allocation: Allocation) -> Self {
        self.allocation = allocation;
        self
    }

    /// Replaces the filtering class.
    #[must_use]
    pub fn with_filtering(mut self, filtering: FilterClass) -> Self {
        self.filtering = filtering;
        self
    }

    /// Replaces the port range.
    #[must_use]
    pub fn with_range(mut self, port_range: Range<u16>) -> Self {
        self.port_range = port_range;
        self
    }

    /// Replaces the hairpinning switch.
    #[must_use]
    pub fn with_hairpin(mut self, hairpin: bool) -> Self {
        self.hairpin = hairpin;
        self
    }
}

/// The reuse key one mapping lives under, chosen by the mapping behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReuseKey {
    /// One mapping per client socket.
    Socket(SocketAddr),
    /// One mapping per client socket and destination address.
    Address(SocketAddr, IpAddr),
    /// One mapping per client socket and destination.
    Dest(SocketAddr, SocketAddr),
}

impl ReuseKey {
    /// The key one outbound datagram translates under.
    pub(crate) fn new(behavior: MappingBehavior, local: SocketAddr, dst: SocketAddr) -> Self {
        match behavior {
            MappingBehavior::EndpointIndependent => Self::Socket(local),
            MappingBehavior::AddressDependent => Self::Address(local, dst.ip()),
            MappingBehavior::AddressPortDependent => Self::Dest(local, dst),
        }
    }
}

struct MappingEntry {
    local: SocketAddr,
    ext_port: u16,
    /// Destinations this mapping sent to, which inbound filtering checks.
    dests: HashSet<SocketAddr>,
    /// The uplink client socket of this mapping on the upstream host: the
    /// external side of a nested NAT. `None` for a flat NAT, whose
    /// external side is the router itself.
    uplink: Option<Arc<SimSocket>>,
    /// Fires when the mapping goes away, ending the uplink task so the
    /// uplink socket closes and the upstream mapping releases with it.
    cancel: Option<CancellationToken>,
}

struct NatShared {
    spec: NatSpec,
    public_ip: Ipv4Addr,
    /// Live mappings under their reuse key, chosen by the mapping
    /// behavior.
    mappings: StdMutex<HashMap<ReuseKey, MappingEntry>>,
    next_alloc: AtomicU32,
    peak: AtomicU32,
    /// Datagrams the filter rejected.
    filter_drops: AtomicU32,
    /// Datagrams dropped because hairpinning is disabled.
    hairpin_drops: AtomicU32,
    /// Allocation count at which the stepped port walk jumps to a fresh
    /// base, armed by a test and spent once.
    rebind: StdMutex<Option<u32>>,
    /// The upstream host this NAT rides, when nested.
    uplink: Option<UplinkHost>,
}

/// What becomes of one translated datagram aimed at this NAT's own
/// external address (RFC 4787 §6 hairpinning).
enum HairpinFate {
    /// No live mapping holds the destination port: not a hairpin, so the
    /// datagram keeps its ordinary outward emission.
    None,
    /// Hairpinning is disabled: dropped after the translation, counted by
    /// [`Net::dropped_by_hairpin`].
    Disabled,
    /// Every matching mapping's filter rejected the source: dropped and
    /// counted as a filter drop, like the router's inbound scan.
    Filtered,
    /// Deliver to this client address as if from outside.
    Deliver(SocketAddr),
}

/// The upstream host a nested NAT rides, reduced to what binding the
/// per-mapping uplink sockets needs: the router channel, the upstream NAT
/// if any, the upstream host's private address, and its faults.
struct UplinkHost {
    tx: mpsc::UnboundedSender<Msg>,
    nat: Option<Arc<NatShared>>,
    local_ip: Ipv4Addr,
    faults: Arc<StdMutex<UplinkFaults>>,
}

impl UplinkHost {
    /// Reduces one host handle to its uplink essentials.
    fn of(host: &Host) -> Self {
        Self {
            tx: host.inner.tx.clone(),
            nat: host.nat.clone(),
            local_ip: host.local_ip,
            faults: Arc::clone(&host.faults),
        }
    }
}

impl NatShared {
    fn new(spec: NatSpec, index: u32, uplink: Option<UplinkHost>) -> Self {
        // For a nested NAT the public address is a display label only: the
        // externally visible address is whatever the upstream allocates.
        let public_ip = Ipv4Addr::new(100, 64, index as u8, 1);
        Self {
            spec,
            public_ip,
            mappings: StdMutex::new(HashMap::new()),
            next_alloc: AtomicU32::new(0),
            peak: AtomicU32::new(0),
            filter_drops: AtomicU32::new(0),
            hairpin_drops: AtomicU32::new(0),
            rebind: StdMutex::new(None),
            uplink,
        }
    }

    fn translate_outbound(
        self: &Arc<Self>,
        inner_net: &Arc<Inner>,
        local: SocketAddr,
        dst: SocketAddr,
    ) -> io::Result<SocketAddr> {
        let key = ReuseKey::new(self.spec.mapping, local, dst);
        let mut mappings = self.mappings.lock().expect("mapping lock");
        // External ports of the live mappings, which a fresh allocation
        // avoids.
        let used: Vec<u16> = mappings.values().map(|e| e.ext_port).collect();
        if let std::collections::hash_map::Entry::Vacant(e) = mappings.entry(key) {
            e.insert(self.build_entry(inner_net, local, &used)?);
            self.note_mapping_count(mappings.len());
        }
        let entry = mappings.get_mut(&key).expect("entry just inserted");
        entry.dests.insert(dst);
        Ok(SocketAddr::V4(SocketAddrV4::new(
            self.public_ip,
            entry.ext_port,
        )))
    }

    /// Builds one fresh mapping: a plain allocation for a flat NAT, or —
    /// behind an upstream — an uplink client socket bound on the upstream
    /// host at the external port, plus the receive task that feeds its
    /// inbound.
    ///
    /// The external port is the uplink client's local port, so the inner
    /// spec's allocation picks it; a port the upstream host already holds
    /// moves the walk or the draw to the next candidate, like the lab's
    /// bind retry.
    fn build_entry(
        self: &Arc<Self>,
        inner_net: &Arc<Inner>,
        local: SocketAddr,
        used: &[u16],
    ) -> io::Result<MappingEntry> {
        let Some(up) = &self.uplink else {
            return Ok(MappingEntry {
                local,
                ext_port: self.alloc_port(&inner_net.rng, used, local),
                uplink: None,
                cancel: None,
                dests: HashSet::new(),
            });
        };
        let len = u64::from(self.spec.port_range.end - self.spec.port_range.start);
        let mut budget = len as usize + 8;
        loop {
            if budget == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "no uplink port of the range binds",
                ));
            }
            budget -= 1;
            let port = self.alloc_port(&inner_net.rng, used, local);
            let Ok(sock) = bind_uplink_port(up, inner_net, port) else {
                continue;
            };
            let uplink = Arc::new(sock);
            let cancel = CancellationToken::new();
            tokio::spawn(uplink_loop(
                Arc::clone(self),
                inner_net.tx.clone(),
                Arc::clone(&uplink),
                cancel.clone(),
            ));
            return Ok(MappingEntry {
                local,
                ext_port: port,
                uplink: Some(uplink),
                cancel: Some(cancel),
                dests: HashSet::new(),
            });
        }
    }

    /// The uplink socket of the mapping one outbound datagram uses, when
    /// this NAT rides an upstream. The datagram leaves through it, so the
    /// upstream NAT translates it under its own policy.
    fn uplink_socket(&self, local: SocketAddr, dst: SocketAddr) -> Option<Arc<SimSocket>> {
        let key = ReuseKey::new(self.spec.mapping, local, dst);
        self.mappings
            .lock()
            .expect("mapping lock")
            .get(&key)
            .and_then(|entry| entry.uplink.clone())
    }

    /// Delivers one datagram that arrived on an uplink socket to its
    /// mapping's client, under the mapping's filter.
    ///
    /// The source is whatever the upstream NAT assigned the correspondent,
    /// so the inner filter sees the apparent external address — correct
    /// RFC semantics for stacked translation.
    fn uplink_inbound(
        &self,
        tx: &mpsc::UnboundedSender<Msg>,
        uplink: &Arc<SimSocket>,
        from: SocketAddr,
        payload: &[u8],
    ) {
        let mappings = self.mappings.lock().expect("mapping lock");
        let Some(entry) = mappings.values().find(|entry| {
            entry
                .uplink
                .as_ref()
                .is_some_and(|sock| Arc::ptr_eq(sock, uplink))
        }) else {
            return;
        };
        if self.allows(entry, from) {
            // The private destination matches no NAT, so the router hands
            // the datagram to the client unchanged.
            let _ = tx.send(Msg::Packet {
                src: from,
                dst: entry.local,
                payload: payload.to_vec(),
            });
        } else {
            self.filter_drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn note_mapping_count(&self, current: usize) {
        self.peak.fetch_max(current as u32, Ordering::Relaxed);
    }

    /// Applies the armed rebind once the allocation count passes its
    /// arming point: the walk jumps forward and the fault disarms, so the
    /// sequence continues from a fresh base like a router rebind.
    fn apply_rebind(&self, n: i64, rng: &StdMutex<StdRng>) -> i64 {
        let mut fault = self.rebind.lock().expect("rebind fault lock");
        match *fault {
            Some(at) if n >= i64::from(at) => {
                // The jump stays clear of the range width so the walk
                // lands on a visibly fresh base instead of wrapping back
                // onto the ports it just left.
                let jump = i64::from(rng.lock().expect("rng lock").random_range(3_000..4_000u32));
                self.next_alloc.fetch_add(jump as u32, Ordering::Relaxed);
                *fault = None;
                n + jump
            },
            _ => n,
        }
    }

    fn alloc_port(&self, rng: &StdMutex<StdRng>, used: &[u16], client: SocketAddr) -> u16 {
        let start = self.spec.port_range.start;
        let end = self.spec.port_range.end;
        let len = u64::from(end - start);
        match self.spec.allocation {
            Allocation::Increment { step } => {
                let n = i64::from(self.next_alloc.fetch_add(1, Ordering::Relaxed));
                // The rebind fault models a router restart of the port
                // walk and stays armed for stepped walks only; the plain
                // step-one walk of the cone presets ignores it.
                let n = if step == 1 {
                    n
                } else {
                    self.apply_rebind(n, rng)
                };
                let offset = (n * i64::from(step)).rem_euclid(len as i64) as u16;
                start + offset
            },
            Allocation::Random => {
                let mut rng = rng.lock().expect("rng lock");
                // A real NAT never hands two live mappings the same port,
                // so the draw comes from the ports no live mapping holds.
                let free: Vec<u16> = (start..end).filter(|p| !used.contains(p)).collect();
                if free.is_empty() {
                    // Every port is taken, so the duplicate is unavoidable.
                    return rng.random_range(start..end);
                }
                free[rng.random_range(0..free.len())]
            },
            Allocation::Preserve => {
                // Mirror the client's internal port while no live mapping
                // holds it; the fallback walks the range like a step-one
                // increment. The rebind fault stays a no-op here: a
                // mirrored port does not follow the walk.
                let internal = client.port();
                if !used.contains(&internal) {
                    return internal;
                }
                let n = u64::from(self.next_alloc.fetch_add(1, Ordering::Relaxed));
                start + (n % len) as u16
            },
        }
    }

    fn translate_inbound(&self, dst: SocketAddr, src: SocketAddr) -> Option<SocketAddr> {
        // A nested NAT's inbound rides its uplink sockets; its own public
        // address is a display label no datagram routes to.
        if self.uplink.is_some() {
            return None;
        }
        // Only traffic aimed at this NAT's public address crosses it.
        let SocketAddr::V4(dst_v4) = dst else {
            return None
        };
        if *dst_v4.ip() != self.public_ip {
            return None;
        }
        let mappings = self.mappings.lock().expect("mapping lock");
        let mut matched = false;
        for entry in mappings.values() {
            if entry.ext_port != dst.port() {
                continue;
            }
            matched = true;
            if self.allows(entry, src) {
                return Some(entry.local);
            }
        }
        if matched {
            // A live mapping saw the datagram and its filter rejected the
            // source, like the loopback engine's counter.
            self.filter_drops.fetch_add(1, Ordering::Relaxed);
        }
        None
    }

    /// Resolves the hairpin fate of one translated datagram, counting the
    /// drop on this NAT when the fate is [`HairpinFate::Disabled`] or
    /// [`HairpinFate::Filtered`].
    ///
    /// One rule serves every shape of NAT: the destination is this NAT's
    /// own external address and a live mapping holds the port. The caller
    /// translated the sender first, so the sender's mapping exists either
    /// way, like a real NAT that emits toward its WAN before the loopback
    /// decision.
    fn hairpin_fate(&self, src: SocketAddr, dst: SocketAddr) -> HairpinFate {
        let SocketAddr::V4(dst) = dst else {
            return HairpinFate::None;
        };
        if *dst.ip() != self.public_ip {
            return HairpinFate::None;
        }
        let mappings = self.mappings.lock().expect("mapping lock");
        if !mappings.values().any(|entry| entry.ext_port == dst.port()) {
            // Nobody translates at this port: the datagram goes out and is
            // lost, not turned into a hairpin drop.
            return HairpinFate::None;
        }
        if !self.spec.hairpin {
            self.hairpin_drops.fetch_add(1, Ordering::Relaxed);
            return HairpinFate::Disabled;
        }
        if let Some(entry) = mappings
            .values()
            .filter(|entry| entry.ext_port == dst.port())
            .find(|entry| self.allows(entry, src))
        {
            return HairpinFate::Deliver(entry.local);
        }
        self.filter_drops.fetch_add(1, Ordering::Relaxed);
        HairpinFate::Filtered
    }

    fn allows(&self, entry: &MappingEntry, src: SocketAddr) -> bool {
        match self.spec.filtering {
            FilterClass::EndpointIndependent => true,
            FilterClass::AddressDependent => entry.dests.iter().any(|d| d.ip() == src.ip()),
            FilterClass::AddressPortDependent => entry.dests.contains(&src),
        }
    }

    fn forget_local(&self, local: SocketAddr) {
        let canceled = {
            let mut mappings = self.mappings.lock().expect("mapping lock");
            let canceled: Vec<CancellationToken> = mappings
                .values()
                .filter(|entry| entry.local == local)
                .filter_map(|entry| entry.cancel.clone())
                .collect();
            mappings.retain(|_, entry| entry.local != local);
            canceled
        };
        // Ending a mapping's uplink task closes the uplink socket, whose
        // unregister releases the upstream mapping of a nested NAT.
        for token in canceled {
            token.cancel();
        }
    }

    fn snapshot(&self) -> Vec<(SocketAddr, SocketAddr)> {
        self.mappings
            .lock()
            .expect("mapping lock")
            .values()
            .map(|e| {
                (
                    e.local,
                    SocketAddr::V4(SocketAddrV4::new(self.public_ip, e.ext_port)),
                )
            })
            .collect()
    }
}

/// Claims `addr` in the network's bound-address registry, so two binds of
/// one address never overwrite each other silently in the router.
fn claim_bound(inner_net: &Arc<Inner>, addr: SocketAddr) -> bool {
    inner_net.bound.lock().expect("bound lock").insert(addr)
}

/// Returns one bound address to the registry.
fn release_bound(inner_net: &Arc<Inner>, addr: SocketAddr) {
    inner_net.bound.lock().expect("bound lock").remove(&addr);
}

/// Binds one uplink client socket of the upstream host at an explicit
/// local port: the external side of a nested NAT's mapping.
///
/// The inner external port is the uplink client's local port, and the
/// bound-address registry keeps two nested NATs on one upstream host from
/// silently overwriting each other's registry entry; a taken port fails
/// the bind, which moves the nested allocation on.
fn bind_uplink_port(up: &UplinkHost, inner_net: &Arc<Inner>, port: u16) -> io::Result<SimSocket> {
    let local = SocketAddr::V4(SocketAddrV4::new(up.local_ip, port));
    if !claim_bound(inner_net, local) {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "uplink port already bound",
        ));
    }
    let (tx, rx) = mpsc::channel(32);
    if up
        .tx
        .send(Msg::Register {
            addr: local,
            inbox: tx,
        })
        .is_err()
    {
        release_bound(inner_net, local);
        return Err(io::Error::other("router stopped"));
    }
    Ok(SimSocket {
        inner: Arc::clone(inner_net),
        nat: up.nat.clone(),
        local,
        inbox: Mutex::new(rx),
        faults: Arc::clone(&up.faults),
    })
}

/// Serves one nested mapping's uplink socket: the receive side of the
/// nested NAT's external interface.
///
/// The upstream NAT delivers datagrams for the uplink socket's mapped
/// address here; each crosses its mapping's filter and reaches the client
/// with the upstream-assigned source. The task ends when the mapping goes
/// away, which closes the uplink socket, whose unregister releases the
/// upstream mapping in turn.
async fn uplink_loop(
    nat: Arc<NatShared>,
    tx: mpsc::UnboundedSender<Msg>,
    uplink: Arc<SimSocket>,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let recv = uplink.recv_from(&mut buf);
        tokio::select! {
            () = cancel.cancelled() => break,
            result = recv => match result {
                Ok((len, from)) => nat.uplink_inbound(&tx, &uplink, from, &buf[..len]),
                Err(_) => break,
            },
        }
    }
}

enum Msg {
    Packet {
        src: SocketAddr,
        dst: SocketAddr,
        payload: Vec<u8>,
    },
    Register {
        addr: SocketAddr,
        inbox: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    },
    Unregister {
        addr: SocketAddr,
    },
}

/// Uplink faults one test attaches to a host.
///
/// Both rules sit in front of the NAT: a datagram that never left the
/// host holds no mapping, and a datagram dropped on the uplink delays the
/// mapping until a retransmission follows.
#[derive(Default)]
struct UplinkFaults {
    /// Destinations whose first datagram is dropped before the NAT.
    drop_first: HashSet<SocketAddr>,
    /// Destinations no datagram ever leaves the host for.
    unreachable: HashSet<SocketAddr>,
}

struct Inner {
    tx: mpsc::UnboundedSender<Msg>,
    rng: StdMutex<StdRng>,
    nats: StdMutex<Vec<Arc<NatShared>>>,
    loss_permille: AtomicU32,
    forwarded: AtomicU32,
    dropped: AtomicU32,
    port_counter: AtomicU32,
    subnet_counter: AtomicU32,
    /// Socket addresses currently registered with the router, so two
    /// binds of one address fail loudly instead of overwriting the
    /// registry entry.
    bound: StdMutex<HashSet<SocketAddr>>,
    /// Delay between a socket closing and its mappings going away.
    mapping_expiry: StdMutex<std::time::Duration>,
}

/// One virtual network. Create with [`Net::seeded`].
///
/// Cloning shares the same network, so a stacked-NAT test can hold one
/// handle per layer while every layer rides one router.
#[derive(Clone)]
pub struct Net {
    inner: Arc<Inner>,
}

impl Net {
    /// Creates a network whose randomness derives from the seed string.
    ///
    /// Tests pass the test name, so a failure reproduces with the same seed.
    #[must_use]
    pub fn seeded(seed: &str) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut hasher);
        Self::from_seed_u64(hasher.finish())
    }

    #[must_use]
    pub fn from_seed_u64(seed: u64) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            tx,
            rng: StdMutex::new(StdRng::seed_from_u64(seed)),
            nats: StdMutex::new(Vec::new()),
            loss_permille: AtomicU32::new(0),
            forwarded: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
            port_counter: AtomicU32::new(20_000),
            subnet_counter: AtomicU32::new(1),
            bound: StdMutex::new(HashSet::new()),
            mapping_expiry: StdMutex::new(std::time::Duration::ZERO),
        });
        let router_inner = Arc::clone(&inner);
        tokio::spawn(async move {
            let mut registry: HashMap<SocketAddr, mpsc::Sender<(SocketAddr, Vec<u8>)>> =
                HashMap::new();
            while let Some(msg) = rx.recv().await {
                match msg {
                    Msg::Register { addr, inbox } => {
                        registry.insert(addr, inbox);
                    },
                    Msg::Unregister { addr } => {
                        registry.remove(&addr);
                        router_inner.bound.lock().expect("bound lock").remove(&addr);
                        let nats: Vec<_> = router_inner.nats.lock().expect("nat list lock").clone();
                        let expiry = *router_inner.mapping_expiry.lock().expect("expiry lock");
                        if expiry.is_zero() {
                            for nat in &nats {
                                nat.forget_local(addr);
                            }
                        } else {
                            // The mappings stay translated for the expiry
                            // window, like a router honoring its timer after
                            // the socket closed.
                            tokio::spawn(async move {
                                tokio::time::sleep(expiry).await;
                                for nat in &nats {
                                    nat.forget_local(addr);
                                }
                            });
                        }
                    },
                    Msg::Packet { src, dst, payload } => {
                        let loss = router_inner.loss_permille.load(Ordering::Relaxed);
                        if loss > 0
                            && router_inner
                                .rng
                                .lock()
                                .expect("rng lock")
                                .random_range(0..1000)
                                < loss
                        {
                            router_inner.dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        router_inner.forwarded.fetch_add(1, Ordering::Relaxed);
                        // Inbound traffic to a NAT address crosses the NAT;
                        // everything else lands on a public endpoint.
                        let target = router_inner
                            .nats
                            .lock()
                            .expect("nat list lock")
                            .iter()
                            .find_map(|nat| nat.translate_inbound(dst, src));
                        let deliver = target.unwrap_or(dst);
                        if std::env::var_os("NAT_LAB_TRACE").is_some() {
                            eprintln!("PKT {src} -> {dst} deliver={deliver} len={}", payload.len());
                        }
                        if let Some(inbox) = registry.get(&deliver) {
                            let _ = inbox.send((src, payload)).await;
                        }
                    },
                }
            }
        });
        Self { inner }
    }

    /// Attaches a host behind a new NAT built from `spec`.
    #[must_use]
    pub fn host(&self, spec: NatSpec) -> Host {
        let index = self.inner.subnet_counter.fetch_add(1, Ordering::Relaxed);
        let nat = Arc::new(NatShared::new(spec, index, None));
        self.inner
            .nats
            .lock()
            .expect("nat list lock")
            .push(Arc::clone(&nat));
        let local_ip = Ipv4Addr::new(192, 168, index as u8, 2);
        Host {
            inner: Arc::clone(&self.inner),
            nat: Some(nat),
            local_ip,
            faults: Arc::new(StdMutex::new(UplinkFaults::default())),
        }
    }

    /// Attaches a host behind a new NAT that itself rides `uplink`
    /// upstream, building the NAT-behind-NAT shape a CGNAT gives every
    /// home router.
    ///
    /// The nested NAT's public side is realized as client sockets of the
    /// uplink host, one per inner external port: an outbound datagram
    /// opens the mapping, then leaves through that uplink socket, so the
    /// upstream NAT allocates the externally visible address under its own
    /// policy. The nested NAT's own public address is a display label
    /// only; probes learn the true external address through STUN across
    /// the chain. The nested spec still governs the datagrams that cross
    /// it — mapping, allocation, filtering, and hairpinning — with its
    /// allocation policy picking the uplink client ports wherever the
    /// upstream host has them free. Inbound rides the uplink socket's
    /// receive path, so an inner filter sees the source the upstream
    /// assigned, and releasing an inner mapping releases the upstream
    /// mapping with it. `uplink` may itself sit behind a NAT, so chains
    /// recurse, or be a public host.
    #[must_use]
    pub fn host_behind(&self, uplink: &Host, spec: NatSpec) -> Host {
        let index = self.inner.subnet_counter.fetch_add(1, Ordering::Relaxed);
        let nat = Arc::new(NatShared::new(spec, index, Some(UplinkHost::of(uplink))));
        self.inner
            .nats
            .lock()
            .expect("nat list lock")
            .push(Arc::clone(&nat));
        let local_ip = Ipv4Addr::new(192, 168, index as u8, 2);
        Host {
            inner: Arc::clone(&self.inner),
            nat: Some(nat),
            local_ip,
            faults: Arc::new(StdMutex::new(UplinkFaults::default())),
        }
    }

    /// Attaches a host with a public address and no NAT.
    #[must_use]
    pub fn public_host(&self) -> Host {
        let index = self.inner.subnet_counter.fetch_add(1, Ordering::Relaxed);
        let local_ip = Ipv4Addr::new(100, 65, index as u8, 2);
        Host {
            inner: Arc::clone(&self.inner),
            nat: None,
            local_ip,
            faults: Arc::new(StdMutex::new(UplinkFaults::default())),
        }
    }

    /// Starts a STUN server that answers binding requests on four primary
    /// ports, which gives the prober four distinct destinations, and
    /// mirrors them on a second address for RFC 5780 discovery: a
    /// CHANGE-REQUEST reroutes the reply to the flag-selected socket of
    /// the grid, and every reply names its source and the OTHER-ADDRESS.
    #[must_use]
    pub fn stun_server(&self) -> StunServer {
        let index = self.inner.subnet_counter.fetch_add(1, Ordering::Relaxed);
        let grid = Grid::new(
            [
                Ipv4Addr::new(1, 1, 1, index as u8 + 1),
                Ipv4Addr::new(1, 1, 2, index as u8 + 1),
            ],
            &[3478, 3479, 3480, 3481],
        );
        let addrs = grid.addrs();
        let split = addrs.len() / 2;
        for addr in &addrs {
            let (tx, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(16);
            let _ = self.inner.tx.send(Msg::Register {
                addr: *addr,
                inbox: tx,
            });
            let router_tx = self.inner.tx.clone();
            let grid = grid.clone();
            let received = *addr;
            tokio::spawn(async move {
                while let Some((from, payload)) = rx.recv().await {
                    let Some(flags) = crate::stun::binding_request_flags(&payload) else {
                        continue;
                    };
                    let reply_src = grid.reply_source(received, flags);
                    let other = grid.other_address(received);
                    if let Some(reply) =
                        crate::stun::discovery_reply(&payload, from, reply_src, other)
                    {
                        // The router routes by address, so the reply
                        // surfaces from the flag-selected grid socket.
                        let _ = router_tx.send(Msg::Packet {
                            src: reply_src,
                            dst: from,
                            payload: reply,
                        });
                    }
                }
            });
        }
        let to_strings = |addrs: &[SocketAddr]| {
            addrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<String>>()
        };
        StunServer {
            addrs: to_strings(&addrs[..split]),
            other_addrs: to_strings(&addrs[split..]),
        }
    }

    /// Sets data-plane loss in permille, applied by the router.
    pub fn set_loss(&self, permille: u32) {
        self.inner.loss_permille.store(permille, Ordering::Relaxed);
    }

    /// Sets how long mappings survive the close of their socket.
    ///
    /// The default of zero releases mappings at close. A nonzero delay
    /// models the tens of seconds a real NAT keeps translating after the
    /// loser socket of a punch went away.
    pub fn set_mapping_expiry(&self, expiry: std::time::Duration) {
        *self.inner.mapping_expiry.lock().expect("expiry lock") = expiry;
    }

    /// Packets the router forwarded.
    #[must_use]
    pub fn forwarded(&self) -> u32 {
        self.inner.forwarded.load(Ordering::Relaxed)
    }

    /// Packets the router dropped, loss only.
    #[must_use]
    pub fn dropped(&self) -> u32 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// Inbound datagrams a NAT filter rejected.
    #[must_use]
    pub fn dropped_by_filter(&self) -> u32 {
        self.inner
            .nats
            .lock()
            .expect("nat list lock")
            .iter()
            .map(|nat| nat.filter_drops.load(Ordering::Relaxed))
            .sum()
    }

    /// Datagrams a NAT dropped because hairpinning is disabled.
    #[must_use]
    pub fn dropped_by_hairpin(&self) -> u32 {
        self.inner
            .nats
            .lock()
            .expect("nat list lock")
            .iter()
            .map(|nat| nat.hairpin_drops.load(Ordering::Relaxed))
            .sum()
    }

    /// Current mappings across every NAT.
    #[must_use]
    pub fn mapping_count(&self) -> usize {
        self.inner
            .nats
            .lock()
            .expect("nat list lock")
            .iter()
            .map(|nat| nat.snapshot().len())
            .sum()
    }

    /// Peak concurrent mappings across every NAT.
    #[must_use]
    pub fn peak_mappings(&self) -> usize {
        self.inner
            .nats
            .lock()
            .expect("nat list lock")
            .iter()
            .map(|nat| nat.peak.load(Ordering::Relaxed) as usize)
            .sum()
    }

    /// Every live mapping as (local, external) pairs.
    #[must_use]
    pub fn mappings_snapshot(&self) -> Vec<(SocketAddr, SocketAddr)> {
        let mut out = Vec::new();
        for nat in self.inner.nats.lock().expect("nat list lock").iter() {
            out.extend(nat.snapshot());
        }
        out
    }

    /// Waits until every mapping is gone, bounded by a virtual timeout.
    pub async fn wait_mappings_drained(&self) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while self.mapping_count() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}

/// Handle of a simulated STUN server.
pub struct StunServer {
    /// Primary `host:port` strings for `PunchConfig::stun_servers`.
    pub addrs: Vec<String>,
    /// Alternate-IP `host:port` strings the server answers RFC 5780
    /// discovery requests from: the OTHER-ADDRESS targets.
    pub other_addrs: Vec<String>,
}

/// A host on the network, usable as a socket factory.
#[derive(Clone)]
pub struct Host {
    inner: Arc<Inner>,
    nat: Option<Arc<NatShared>>,
    local_ip: Ipv4Addr,
    /// Fault rules every socket of this host consults before the NAT.
    faults: Arc<StdMutex<UplinkFaults>>,
}

impl Host {
    /// Drops the first datagram this host sends to `target` before it
    /// reaches the NAT, so the destination holds no mapping until the
    /// sender retransmits.
    pub fn drop_first_send_to(&self, target: SocketAddr) {
        self.faults
            .lock()
            .expect("uplink fault lock")
            .drop_first
            .insert(target);
    }

    /// Fails every send to `target` locally, like a route that never
    /// leaves the host.
    pub fn fail_sends_to(&self, target: SocketAddr) {
        self.faults
            .lock()
            .expect("uplink fault lock")
            .unreachable
            .insert(target);
    }

    /// Walks this host's NAT allocation sequence forward by `count`
    /// mappings, like other users of the same carrier NAT allocating
    /// between the phases of a session.
    ///
    /// The scratch socket closes at once, so only the sequence position
    /// moves; no mapping survives. One distinct destination per count
    /// keeps every allocation distinct for a per-destination NAT.
    pub async fn external_allocations(&self, count: usize) {
        let Ok(sock) = self
            .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
            .await
        else {
            return;
        };
        for i in 0..count {
            // Documentation-range addresses the router forwards to nobody,
            // varying the IP so an address-dependent NAT allocates per
            // destination too.
            let dst = SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(198, 51, 100, (i % 254 + 1) as u8),
                9000 + (i / 254) as u16,
            ));
            let _ = sock.send_to(b"x", dst).await;
        }
        drop(sock);
    }

    /// Jumps this host's NAT allocation sequence to a fresh base once
    /// `allocations` mappings exist, like a router rebind that restarts
    /// the port walk. Applies to stepped [`Allocation::Increment`] walks
    /// (a step other than one); [`Allocation::Random`] and
    /// [`Allocation::Preserve`] ignore it.
    pub fn rebind_sequence_after(&self, allocations: u32) {
        if let Some(nat) = &self.nat {
            *nat.rebind.lock().expect("rebind fault lock") = Some(allocations);
        }
    }
}

impl UdpFactory for Host {
    type Socket = SimSocket;

    async fn bind(&self, addr: SocketAddr) -> io::Result<SimSocket> {
        if addr.is_ipv6() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the simulator is IPv4 only",
            ));
        }
        let port = self.inner.port_counter.fetch_add(1, Ordering::Relaxed) as u16;
        let local = SocketAddr::V4(SocketAddrV4::new(self.local_ip, port));
        if !claim_bound(&self.inner, local) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "address already bound",
            ));
        }
        let (tx, rx) = mpsc::channel(32);
        if self
            .inner
            .tx
            .send(Msg::Register {
                addr: local,
                inbox: tx,
            })
            .is_err()
        {
            release_bound(&self.inner, local);
            return Err(io::Error::other("router stopped"));
        }
        Ok(SimSocket {
            inner: Arc::clone(&self.inner),
            nat: self.nat.clone(),
            local,
            inbox: Mutex::new(rx),
            faults: Arc::clone(&self.faults),
        })
    }
}

/// One socket on the simulated network.
pub struct SimSocket {
    inner: Arc<Inner>,
    nat: Option<Arc<NatShared>>,
    local: SocketAddr,
    inbox: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    faults: Arc<StdMutex<UplinkFaults>>,
}

impl UdpIo for SimSocket {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        // One hop per NAT of the stack: each hop checks its own host's
        // uplink faults, translates, resolves the hairpin fate, then
        // either emits or hands the datagram to its mapping's uplink
        // socket, whose own NAT repeats the rule.
        let mut hop: Option<Arc<SimSocket>> = None;
        loop {
            let sock = hop.as_deref().unwrap_or(self);
            {
                let mut faults = sock.faults.lock().expect("uplink fault lock");
                if faults.unreachable.contains(&target) {
                    return Err(io::Error::new(
                        io::ErrorKind::NetworkUnreachable,
                        "sim uplink fault: destination unreachable",
                    ));
                }
                if faults.drop_first.remove(&target) {
                    // The datagram reports success and never reaches the
                    // NAT, so the destination holds no mapping yet.
                    return Ok(buf.len());
                }
            }
            let Some(nat) = &sock.nat else {
                self.emit(buf, sock.local, target)?;
                return Ok(buf.len());
            };
            // The mapping opens and refreshes before its fate, like the
            // loss hook's order.
            let src = nat.translate_outbound(&self.inner, sock.local, target)?;
            match nat.hairpin_fate(src, target) {
                // Delivered as if from outside: the private destination
                // matches no NAT, so the router applies its loss roll and
                // hands the datagram to the target unchanged.
                HairpinFate::Deliver(local) => {
                    self.emit(buf, src, local)?;
                    return Ok(buf.len());
                },
                // The NAT dropped the datagram after the translation; the
                // fate call already counted it.
                HairpinFate::Disabled | HairpinFate::Filtered => return Ok(buf.len()),
                HairpinFate::None => {},
            }
            let next = nat.uplink_socket(sock.local, target);
            if let Some(uplink) = next {
                hop = Some(uplink);
            } else {
                self.emit(buf, src, target)?;
                return Ok(buf.len());
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut inbox = self.inbox.lock().await;
        let (from, data) = inbox
            .recv()
            .await
            .ok_or_else(|| io::Error::other("socket closed"))?;
        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok((len, from))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

impl SimSocket {
    /// Hands one datagram to the router.
    fn emit(&self, buf: &[u8], src: SocketAddr, dst: SocketAddr) -> io::Result<()> {
        self.inner
            .tx
            .send(Msg::Packet {
                src,
                dst,
                payload: buf.to_vec(),
            })
            .map_err(|_| io::Error::other("router stopped"))
    }
}

impl Drop for SimSocket {
    fn drop(&mut self) {
        // The router releases the mappings, at close by default or after
        // the configured expiry.
        let _ = self.inner.tx.send(Msg::Unregister { addr: self.local });
    }
}
