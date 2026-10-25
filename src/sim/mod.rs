//! Deterministic NAT simulator for integration tests.
//!
//! Feature `test-util`. A `Net` owns one router task and a virtual IPv4
//! space. Hosts attach directly or behind a `NatSpec`, STUN servers answer
//! binding requests, and every packet crosses the router, which applies
//! translation, filtering, and loss. All randomness flows through one seeded
//! generator, and tests run under paused tokio time, so a run reproduces from
//! its seed.
// Trait signatures stay async even when a virtual operation never yields.
#![allow(clippy::unused_async_trait_impl)]

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::Range,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU32, Ordering},
    },
};

use rand::{prelude::*, rngs::StdRng};
use tokio::sync::{Mutex, mpsc};

use crate::{
    nat::FilterClass,
    socket::{UdpFactory, UdpIo},
};

/// Outbound mapping behavior of a simulated NAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapping {
    /// One external port per internal socket.
    Cone,
    /// A new port per destination, walking a constant step.
    Sequential { step: i16 },
    /// A new port per destination, drawn at random.
    Random,
}

/// Configuration of one simulated NAT.
#[derive(Debug, Clone)]
pub struct NatSpec {
    pub mapping: Mapping,
    pub filtering: FilterClass,
    pub port_range: Range<u16>,
}

impl NatSpec {
    /// A cone NAT with endpoint-independent filtering.
    #[must_use]
    pub fn cone_eif() -> Self {
        Self {
            mapping: Mapping::Cone,
            filtering: FilterClass::EndpointIndependent,
            port_range: 1024..65535,
        }
    }

    /// A cone NAT with address-and-port-dependent filtering.
    #[must_use]
    pub fn cone_apdf() -> Self {
        Self {
            mapping: Mapping::Cone,
            filtering: FilterClass::AddressPortDependent,
            port_range: 1024..65535,
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
            mapping: Mapping::Sequential { step },
            filtering: FilterClass::AddressDependent,
            port_range: 30000..40000,
        }
    }

    /// A random symmetric NAT drawing from the given range.
    #[must_use]
    pub fn random(range: Range<u16>) -> Self {
        Self {
            mapping: Mapping::Random,
            filtering: FilterClass::AddressDependent,
            port_range: range,
        }
    }
}

struct MappingEntry {
    local: SocketAddr,
    ext_port: u16,
    /// Destinations this mapping sent to, which inbound filtering checks.
    dests: HashSet<SocketAddr>,
}

struct NatShared {
    spec: NatSpec,
    public_ip: Ipv4Addr,
    /// Cone mappings, keyed by local port.
    cone: StdMutex<HashMap<u16, MappingEntry>>,
    /// Symmetric mappings, keyed by local port and destination.
    sym: StdMutex<HashMap<(u16, SocketAddr), MappingEntry>>,
    next_alloc: AtomicU32,
    peak: AtomicU32,
}

impl NatShared {
    fn new(spec: NatSpec, index: u32) -> Self {
        let public_ip = Ipv4Addr::new(100, 64, index as u8, 1);
        Self {
            spec,
            public_ip,
            cone: StdMutex::new(HashMap::new()),
            sym: StdMutex::new(HashMap::new()),
            next_alloc: AtomicU32::new(0),
            peak: AtomicU32::new(0),
        }
    }

    fn translate_outbound(
        &self,
        rng: &StdMutex<StdRng>,
        local: SocketAddr,
        dst: SocketAddr,
    ) -> SocketAddr {
        let symmetric = !matches!(self.spec.mapping, Mapping::Cone);
        let mut cone = self.cone.lock().expect("cone lock");
        let mut sym = self.sym.lock().expect("sym lock");
        if symmetric {
            // Symmetric mappings key on the destination too.
            let key = (local.port(), dst);
            if let std::collections::hash_map::Entry::Vacant(e) = sym.entry(key) {
                let entry = MappingEntry {
                    local,
                    ext_port: self.alloc_port(rng),
                    dests: HashSet::new(),
                };
                e.insert(entry);
                self.note_mapping_count(cone.len() + sym.len());
            }
            let entry = sym.get_mut(&key).expect("entry just inserted");
            entry.dests.insert(dst);
            SocketAddr::V4(SocketAddrV4::new(self.public_ip, entry.ext_port))
        } else {
            let key = local.port();
            if let std::collections::hash_map::Entry::Vacant(e) = cone.entry(key) {
                let entry = MappingEntry {
                    local,
                    ext_port: self.alloc_port(rng),
                    dests: HashSet::new(),
                };
                e.insert(entry);
                self.note_mapping_count(cone.len() + sym.len());
            }
            let entry = cone.get_mut(&key).expect("entry just inserted");
            entry.dests.insert(dst);
            SocketAddr::V4(SocketAddrV4::new(self.public_ip, entry.ext_port))
        }
    }

    fn note_mapping_count(&self, current: usize) {
        self.peak.fetch_max(current as u32, Ordering::Relaxed);
    }

    fn alloc_port(&self, rng: &StdMutex<StdRng>) -> u16 {
        let start = self.spec.port_range.start;
        let end = self.spec.port_range.end;
        let len = u64::from(end - start);
        match self.spec.mapping {
            Mapping::Cone | Mapping::Sequential { step: 1 } => {
                let n = u64::from(self.next_alloc.fetch_add(1, Ordering::Relaxed));
                start + (n % len) as u16
            },
            Mapping::Sequential { step } => {
                let n = i64::from(self.next_alloc.fetch_add(1, Ordering::Relaxed));
                let offset = (n * i64::from(step)).rem_euclid(len as i64) as u16;
                start + offset
            },
            Mapping::Random => rng.lock().expect("rng lock").random_range(start..end),
        }
    }

    fn translate_inbound(&self, dst: SocketAddr, src: SocketAddr) -> Option<SocketAddr> {
        // Only traffic aimed at this NAT's public address crosses it.
        let SocketAddr::V4(dst_v4) = dst else {
            return None
        };
        if *dst_v4.ip() != self.public_ip {
            return None;
        }
        let cone = self.cone.lock().expect("cone lock");
        for entry in cone.values() {
            if entry.ext_port == dst.port() && self.allows(entry, src) {
                return Some(entry.local);
            }
        }
        drop(cone);
        let sym = self.sym.lock().expect("sym lock");
        for entry in sym.values() {
            if entry.ext_port == dst.port() && self.allows(entry, src) {
                return Some(entry.local);
            }
        }
        None
    }

    fn allows(&self, entry: &MappingEntry, src: SocketAddr) -> bool {
        match self.spec.filtering {
            FilterClass::EndpointIndependent | FilterClass::Unknown => true,
            FilterClass::AddressDependent => entry.dests.iter().any(|d| d.ip() == src.ip()),
            FilterClass::AddressPortDependent => entry.dests.contains(&src),
        }
    }

    fn forget_local(&self, local: SocketAddr) {
        self.cone.lock().expect("cone lock").remove(&local.port());
        self.sym
            .lock()
            .expect("sym lock")
            .retain(|_, entry| entry.local != local);
    }

    fn snapshot(&self) -> Vec<(SocketAddr, SocketAddr)> {
        let cone = self.cone.lock().expect("cone lock");
        let sym = self.sym.lock().expect("sym lock");
        cone.values()
            .chain(sym.values())
            .map(|e| {
                (
                    e.local,
                    SocketAddr::V4(SocketAddrV4::new(self.public_ip, e.ext_port)),
                )
            })
            .collect()
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

struct Inner {
    tx: mpsc::UnboundedSender<Msg>,
    rng: StdMutex<StdRng>,
    nats: StdMutex<Vec<Arc<NatShared>>>,
    loss_permille: AtomicU32,
    forwarded: AtomicU32,
    dropped: AtomicU32,
    port_counter: AtomicU32,
    subnet_counter: AtomicU32,
}

/// One virtual network. Create with [`Net::seeded`].
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
                        for nat in router_inner.nats.lock().expect("nat list lock").iter() {
                            nat.forget_local(addr);
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
                        if std::env::var_os("SIM_TRACE").is_some() {
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
        let nat = Arc::new(NatShared::new(spec, index));
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
        }
    }

    /// Starts a STUN server that answers binding requests on four ports,
    /// which gives the prober four distinct destinations.
    #[must_use]
    pub fn stun_server(&self) -> StunServer {
        let index = self.inner.subnet_counter.fetch_add(1, Ordering::Relaxed);
        let ip = Ipv4Addr::new(1, 1, 1, index as u8 + 1);
        let mut addrs = Vec::new();
        for port in [3478, 3479, 3480, 3481] {
            let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
            let (tx, mut rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(16);
            let _ = self.inner.tx.send(Msg::Register { addr, inbox: tx });
            let router_tx = self.inner.tx.clone();
            tokio::spawn(async move {
                while let Some((from, payload)) = rx.recv().await {
                    if let Some(reply) = stun_reply(&payload, from) {
                        let _ = router_tx.send(Msg::Packet {
                            src: addr,
                            dst: from,
                            payload: reply,
                        });
                    }
                }
            });
            addrs.push(format!("{ip}:{port}"));
        }
        StunServer { addrs }
    }

    /// Sets data-plane loss in permille, applied by the router.
    pub fn set_loss(&self, permille: u32) {
        self.inner.loss_permille.store(permille, Ordering::Relaxed);
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
    /// `host:port` strings for `PunchConfig::stun_servers`.
    pub addrs: Vec<String>,
}

/// A host on the network, usable as a socket factory.
#[derive(Clone)]
pub struct Host {
    inner: Arc<Inner>,
    nat: Option<Arc<NatShared>>,
    local_ip: Ipv4Addr,
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
        let (tx, rx) = mpsc::channel(32);
        self.inner
            .tx
            .send(Msg::Register {
                addr: local,
                inbox: tx,
            })
            .map_err(|_| io::Error::other("router stopped"))?;
        Ok(SimSocket {
            inner: Arc::clone(&self.inner),
            nat: self.nat.clone(),
            local,
            inbox: Mutex::new(rx),
        })
    }
}

/// One socket on the simulated network.
pub struct SimSocket {
    inner: Arc<Inner>,
    nat: Option<Arc<NatShared>>,
    local: SocketAddr,
    inbox: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
}

impl UdpIo for SimSocket {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        let src = match &self.nat {
            Some(nat) => nat.translate_outbound(&self.inner.rng, self.local, target),
            None => self.local,
        };
        self.inner
            .tx
            .send(Msg::Packet {
                src,
                dst: target,
                payload: buf.to_vec(),
            })
            .map_err(|_| io::Error::other("router stopped"))?;
        Ok(buf.len())
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

impl Drop for SimSocket {
    fn drop(&mut self) {
        // Releasing the socket releases its mappings, like a NAT expiry.
        let _ = self.inner.tx.send(Msg::Unregister { addr: self.local });
    }
}

/// Wires two host ends together losslessly, acting as the host transport.
pub fn connect(a: crate::signaling::HostEnd, b: crate::signaling::HostEnd) {
    connect_with(a, b, |frame| Some(frame.to_vec()));
}

/// Wires two host ends through a per-frame tap.
///
/// The tap sees each frame as bytes; returning `None` drops it, and the
/// returned buffer replaces it. Loss, duplication, and version-mangling tests
/// build their taps on this hook.
pub fn connect_with(
    a: crate::signaling::HostEnd,
    b: crate::signaling::HostEnd,
    tap: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
) {
    let tap = Arc::new(tap);
    let mut a_to_b = a.to_peer;
    let b_from_a = b.from_peer;
    let forward_tap = Arc::clone(&tap);
    tokio::spawn(async move {
        while let Some(frame) = a_to_b.recv().await {
            if let Some(bytes) = forward_tap(&frame) {
                let _ = b_from_a.send(bytes.into()).await;
            }
        }
    });
    let mut b_to_a = b.to_peer;
    let a_from_b = a.from_peer;
    tokio::spawn(async move {
        while let Some(frame) = b_to_a.recv().await {
            if let Some(bytes) = tap(&frame) {
                let _ = a_from_b.send(bytes.into()).await;
            }
        }
    });
}

/// Builds a STUN binding response for a valid request.
fn stun_reply(request: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    const COOKIE: [u8; 4] = 0x2112_a442u32.to_be_bytes();
    if request.len() < 20
        || u16::from_be_bytes([request[0], request[1]]) != 0x0001
        || request[4..8] != COOKIE
    {
        return None;
    }
    let port = from.port() ^ 0x2112;
    let ip = match from.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => return None,
    };
    let xip: Vec<u8> = ip.octets().iter().zip(COOKIE).map(|(b, k)| b ^ k).collect();

    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&0x0101u16.to_be_bytes());
    out.extend_from_slice(&12u16.to_be_bytes());
    out.extend_from_slice(&COOKIE);
    out.extend_from_slice(&request[8..20]);
    out.extend_from_slice(&0x0020u16.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.push(0);
    out.push(0x01);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&xip);
    Some(out)
}
