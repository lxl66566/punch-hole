//! Loopback NAT lab: one emulated NAT device over real OS sockets.
//!
//! A [`NatLab`] is a userspace NAT forwarder that lives on the 127.0.0.0/8
//! loopback space. Linux and Windows bind every address of the block; macOS
//! and the BSDs bind only the addresses aliased onto `lo0`, so there the
//! engines live on 127.0.0.2-254 and expect those aliases:
//! `for i in $(seq 2 254); do sudo ifconfig lo0 alias 127.0.0.$i up; done`.
//! Client sockets are real OS sockets; every outbound
//! datagram crosses a gateway task that applies the mapping and filtering
//! policy of a [`NatSpec`] and leaves through a per-mapping public socket
//! bound on the lab's dedicated loopback address. The code under test runs
//! unmodified: real STUN probes, classification, strategy, and punch all
//! observe a translated address, which the pure simulator covers only
//! without the OS and plain loopback tests cover only without a NAT.
//!
//! [`NatLab`] carries the same fault surface as the virtual engine:
//! data-plane loss, close and idle expiry, uplink faults,
//! allocation-sequence control, and a per-packet tap.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    fmt,
    future::Future,
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::Range,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, OnceLock,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use rand::{prelude::*, rngs::StdRng};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::{
    MAX_DATAGRAM,
    sim::{Allocation, FilterClass, NatSpec, ReuseKey},
    socket::{Family, UdpFactory, UdpIo},
    stun::Grid,
};

/// Lab addresses drawn in this process.
static LAB_IPS: StdMutex<Vec<Ipv4Addr>> = StdMutex::new(Vec::new());
/// Responder addresses drawn in this process.
static STUN_IPS: StdMutex<Vec<Ipv4Addr>> = StdMutex::new(Vec::new());

/// How much of the 127.0.0.0/8 block binds on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopbackSpace {
    /// Every address of the block binds, as on Linux and Windows.
    Wide,
    /// Only addresses aliased onto the loopback interface bind, as on macOS
    /// and the BSDs, where `lo0` carries 127.0.0.1 alone.
    Narrow,
}

/// Probes the loopback space once per process.
///
/// The probe binds a wildcard port on a random address outside the narrow
/// pools, so neither a twin process nor an alias can answer for it:
/// `AddrNotAvailable` means the host does not carry the address.
fn loopback_space() -> LoopbackSpace {
    static SPACE: OnceLock<LoopbackSpace> = OnceLock::new();
    *SPACE.get_or_init(|| {
        let n: u16 = rand::random();
        let probe = Ipv4Addr::new(127, 1 + ((n >> 8) as u8 % 255), (n & 0xff) as u8, 1);
        match std::net::UdpSocket::bind(SocketAddrV4::new(probe, 0)) {
            Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => LoopbackSpace::Narrow,
            _ => LoopbackSpace::Wide,
        }
    })
}

/// First host octet of the narrow lab pool, 127.0.0.3-128.
const NARROW_LAB_FIRST: u8 = 3;
/// First host octet of the narrow responder pool, 127.0.0.129-254.
const NARROW_STUN_FIRST: u8 = 129;
/// Addresses per narrow pool. 127.0.0.2 stays out of both, so a test can
/// bind a loopback address no engine draws.
const NARROW_POOL: u8 = 126;

/// One narrow-pool address, `n` folded onto the pool starting at `first`.
fn narrow_ip(first: u8, n: u16) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, first + (n % u16::from(NARROW_POOL)) as u8)
}

/// Draws one fresh address for this process from `taken`.
///
/// A process-global counter cannot keep test runners apart: cargo-nextest
/// runs every test in its own process, and all counters would start at the
/// same address. The draw reads OS entropy instead. A twin process holding
/// the drawn address refuses the claim a lab takes or the sockets a
/// responder binds, and the caller redraws.
fn draw_ip(
    taken: &StdMutex<Vec<Ipv4Addr>>,
    make: impl Fn(u16) -> Option<Ipv4Addr>,
) -> io::Result<Ipv4Addr> {
    let mut taken = taken.lock().expect("address draw lock");
    for _ in 0..32 {
        let n: u16 = rand::random();
        let Some(ip) = make(n) else {
            continue;
        };
        if !taken.contains(&ip) {
            taken.push(ip);
            return Ok(ip);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no loopback address left to draw",
    ))
}

/// One lab address: 127.hi.lo.1 on a wide loopback, where octet one skips
/// the responder space and zero would redraw the busy 127.0.0.1; a narrow
/// pool address otherwise.
fn draw_lab_ip() -> io::Result<Ipv4Addr> {
    match loopback_space() {
        LoopbackSpace::Wide => draw_ip(&LAB_IPS, |n| {
            (n != 0 && (n >> 8) != 50)
                .then(|| Ipv4Addr::new(127, (n >> 8) as u8, (n & 0xff) as u8, 1))
        }),
        LoopbackSpace::Narrow => draw_ip(&LAB_IPS, |n| Some(narrow_ip(NARROW_LAB_FIRST, n))),
    }
}

/// One responder address: 127.50.hi.lo on a wide loopback, the space no
/// lab draws; a narrow pool address otherwise.
fn draw_stun_ip() -> io::Result<Ipv4Addr> {
    match loopback_space() {
        LoopbackSpace::Wide => draw_ip(&STUN_IPS, |n| {
            Some(Ipv4Addr::new(127, 50, (n >> 8) as u8, (n & 0xff) as u8))
        }),
        LoopbackSpace::Narrow => draw_ip(&STUN_IPS, |n| Some(narrow_ip(NARROW_STUN_FIRST, n))),
    }
}

/// Returns one drawn lab address to the registry.
fn release_lab_ip(ip: Ipv4Addr) {
    LAB_IPS
        .lock()
        .expect("address draw lock")
        .retain(|v| *v != ip);
}

/// Returns drawn responder addresses to the registry.
fn release_stun_ips(ips: &[Ipv4Addr]) {
    STUN_IPS
        .lock()
        .expect("address draw lock")
        .retain(|ip| !ips.contains(ip));
}

/// Port a lab holds on its public address for its whole life, so a twin
/// process that draws the same address meets `AddrInUse` on its own claim
/// and redraws. No window ever holds this port: a `u16` range cannot end
/// past 65535, so the scan never includes it.
const CLAIM_PORT: u16 = u16::MAX;

/// Claims one drawn address for this process.
///
/// `AddrInUse` names a twin process holding the address, and
/// `AddrNotAvailable` an address the host does not carry: a missing alias
/// on a narrow loopback. Any other refusal, such as a Windows port
/// exclusion, leaves the address unclaimed; the wide space keeps a twin
/// draw improbable there.
fn claim_address(ip: Ipv4Addr) -> io::Result<Option<std::net::UdpSocket>> {
    match std::net::UdpSocket::bind(SocketAddrV4::new(ip, CLAIM_PORT)) {
        Ok(claim) => Ok(Some(claim)),
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => Err(e),
        Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable => Err(missing_alias(ip)),
        Err(_) => Ok(None),
    }
}

/// The error for a drawn address the host does not carry.
fn missing_alias(ip: Ipv4Addr) -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        format!(
            "{ip} is not a local address; a narrow loopback needs the aliases 127.0.0.2-254: for \
             i in $(seq 2 254); do sudo ifconfig lo0 alias 127.0.0.$i up; done"
        ),
    )
}

/// Frame tag of a client datagram on its way out.
const TAG_OUT: u8 = 1;
/// Frame tag of a translated datagram on its way back to a client.
const TAG_IN: u8 = 2;
/// Frame tag of a client socket close notice.
const TAG_BYE: u8 = 3;
/// Frame bytes before the payload: one tag, four address, two port.
const FRAME_HEADER: usize = 7;

/// Which way one datagram crosses the tap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client to network, seen after the frame parse and before
    /// translation.
    Out,
    /// Network to client, seen before the inbound filter.
    In,
}

/// One datagram at the tap, borrowed for the duration of the call.
///
/// `src` and `dst` are the addresses as the NAT sees them: on
/// [`Direction::Out`] the private client and the intended destination, on
/// [`Direction::In`] the external sender and the client the mapping
/// delivers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapEvent<'a> {
    /// Which way the datagram crosses.
    pub direction: Direction,
    /// Sender address as the NAT sees it.
    pub src: SocketAddr,
    /// Destination address as the NAT sees it.
    pub dst: SocketAddr,
    /// Datagram payload.
    pub payload: &'a [u8],
}

/// What the tap decides for one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapDecision {
    /// The datagram crosses unchanged.
    Forward,
    /// The datagram drops at the tap.
    Drop,
    /// The datagram crosses with this payload in place of the original.
    Replace(Vec<u8>),
}

/// A per-packet tap: one callable over every crossing of the lab.
pub type Tap = Arc<dyn Fn(&TapEvent<'_>) -> TapDecision + Send + Sync>;

/// Uplink faults the lab's host arms.
///
/// One lab hosts one peer, so the rules are lab-wide: every socket the
/// lab's hosts bound consults them before the gateway, and a datagram that
/// never left the host holds no mapping.
#[derive(Default)]
struct UplinkFaults {
    /// Destinations whose first datagram is dropped before the NAT.
    drop_first: HashSet<SocketAddr>,
    /// Destinations no datagram ever leaves the host for.
    unreachable: HashSet<SocketAddr>,
}

/// One emulated NAT device. Create with [`NatLab::spawn`].
pub struct NatLab {
    inner: Arc<LabInner>,
}

/// Shared state of one lab, touched by the gateway and mapping tasks.
struct LabInner {
    spec: NatSpec,
    public_ip: Ipv4Addr,
    /// Bindable window at or after `spec.port_range.start`.
    window: Range<u16>,
    /// Holds [`CLAIM_PORT`] on the public address for the lab's life. A
    /// nested lab draws no address and holds none; a platform port
    /// exclusion can leave a flat lab's empty too.
    _claim: Option<std::net::UdpSocket>,
    /// Receives client frames; mapping tasks share it to deliver In frames.
    gateway: Arc<UdpSocket>,
    table: StdMutex<MappingTable>,
    rng: StdMutex<StdRng>,
    /// Stops the gateway and reaper loops, and through the mapping tokens'
    /// child relationship every mapping loop too.
    cancel: CancellationToken,
    /// Uplink faults every client socket consults before the gateway.
    ///
    /// Arc'd beside the lab, so client sockets share the rules without
    /// holding the whole lab alive.
    faults: Arc<StdMutex<UplinkFaults>>,
    /// The per-packet tap, consulted on every crossing.
    tap: StdMutex<Option<Tap>>,
    /// Allocation count at which the stepped port walk jumps to a fresh
    /// base, armed by a test and spent once.
    rebind: StdMutex<Option<u32>>,
    forwarded: AtomicU32,
    dropped_by_filter: AtomicU32,
    dropped_by_hairpin: AtomicU32,
    dropped_by_loss: AtomicU32,
    idled: AtomicU32,
    loss_permille: AtomicU32,
    /// Delay between a socket close and its mappings going away.
    mapping_expiry: StdMutex<Duration>,
    /// Idle time after which an unused mapping is evicted.
    idle_expiry: StdMutex<Duration>,
    /// The upstream lab this NAT rides, when nested: the lab whose client
    /// sockets carry the mappings' external side.
    uplink: Option<NatLab>,
}

/// The mapping set of one lab, always behind one lock.
struct MappingTable {
    /// Live mappings under their reuse key, chosen by the mapping
    /// behavior.
    map: HashMap<ReuseKey, Arc<LabMapping>>,
    /// Allocation counter the sequential policies walk.
    next_alloc: u64,
    peak: usize,
}

impl MappingTable {
    /// Ports the live mappings hold.
    fn used_ports(&self) -> Vec<u16> {
        self.map.values().map(|m| m.ext_port).collect()
    }

    /// Records the concurrent mapping peak after one insert.
    fn note_count(&mut self) {
        self.peak = self.peak.max(self.map.len());
    }
}

/// One live NAT mapping: its external socket and bookkeeping.
struct LabMapping {
    client: SocketAddr,
    /// Kept beside the socket so snapshots need no syscall.
    ext_port: u16,
    /// The mapping's external side: a public socket bound on the lab's own
    /// address, or — behind an upstream lab — an uplink client socket of
    /// that upstream.
    ext: Box<dyn ExtSock>,
    /// Destinations this mapping sent to, which inbound filtering checks.
    dests: Arc<StdMutex<HashSet<SocketAddr>>>,
    /// Fires when the mapping goes away; the task then drops the socket.
    ///
    /// A child of the lab token, so the lab's drop releases every mapping
    /// at once.
    cancel: CancellationToken,
    /// Last crossing in either direction, which the idle reaper reads.
    last_seen: StdMutex<Instant>,
}

/// Object-safe send/receive view of one mapping's external socket.
///
/// [`UdpIo`]'s methods return `impl Future`, which no trait object can
/// carry, so the mapping side erases the socket behind boxed futures on
/// this trait. The trait is implemented only for the [`ExtAny`] wrapper —
/// implementing it for the sockets themselves would put a second
/// `send_to` into every socket's method resolution beside [`UdpIo`]'s. A
/// test crate: the allocation lands on the forwarding path by design.
trait ExtSock: Send + Sync {
    fn send_to<'a>(&'a self, buf: &'a [u8], dst: SocketAddr) -> ExtFut<'a, usize>;

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> ExtFut<'a, (usize, SocketAddr)>;
}

/// The boxed future one erased external call returns.
type ExtFut<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// Wraps any [`UdpIo`] socket for the erased [`ExtSock`] view.
struct ExtAny<S>(S);

impl<S: UdpIo> ExtSock for ExtAny<S> {
    fn send_to<'a>(&'a self, buf: &'a [u8], dst: SocketAddr) -> ExtFut<'a, usize> {
        Box::pin(UdpIo::send_to(&self.0, buf, dst))
    }

    fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> ExtFut<'a, (usize, SocketAddr)> {
        Box::pin(UdpIo::recv_from(&self.0, buf))
    }
}

/// A raw public socket viewed through [`UdpIo`].
struct PublicSock(UdpSocket);

impl UdpIo for PublicSock {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, &target).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl NatLab {
    /// Creates one NAT device with policy `spec` and randomness from `seed`.
    ///
    /// The gateway binds and the port window settles before the call
    /// returns, so a failed spawn leaves nothing behind.
    pub async fn spawn(seed: &str, spec: NatSpec) -> io::Result<Self> {
        let (public_ip, window, claim) = settle_address(&spec)?;
        let gateway = match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await {
            Ok(gateway) => gateway,
            Err(e) => {
                release_lab_ip(public_ip);
                return Err(e);
            },
        };
        Ok(Self {
            inner: start_lab(
                seed,
                spec,
                public_ip,
                window,
                claim,
                Arc::new(gateway),
                None,
            ),
        })
    }

    /// Creates one NAT device that itself rides `uplink` upstream,
    /// building the NAT-behind-NAT shape a CGNAT gives every home router.
    ///
    /// No dedicated address is drawn and no port window is scanned: the
    /// inner NAT's public side is a set of uplink client sockets of the
    /// upstream lab, one per inner external port, so the upstream
    /// allocates the externally visible address under its own policy. The
    /// inner NAT's own public address is a display label only — probes
    /// learn the true external address through STUN across the chain — and
    /// its port window is the requested range unverified, because there is
    /// no address to scan. The inner spec still governs the datagrams that
    /// cross it, with its allocation policy picking the uplink client
    /// ports wherever the OS and the upstream have them free. Releasing an
    /// inner mapping closes its uplink socket, whose Bye releases the
    /// upstream mapping in turn.
    pub async fn spawn_behind(uplink: &NatLab, seed: &str, spec: NatSpec) -> io::Result<Self> {
        let gateway = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
        // No scan backs the window in nested mode; the allocation walks
        // the requested range and the OS decides per bind.
        let window = spec.port_range.clone();
        Ok(Self {
            inner: start_lab(
                seed,
                spec,
                // The label reads as unspecified because no local address
                // belongs to a nested NAT.
                Ipv4Addr::UNSPECIFIED,
                window,
                None,
                Arc::new(gateway),
                Some(NatLab {
                    inner: Arc::clone(&uplink.inner),
                }),
            ),
        })
    }

    /// A cloneable factory that binds client sockets behind this NAT.
    #[must_use]
    pub fn host(&self) -> LabHost {
        LabHost {
            inner: Arc::clone(&self.inner),
        }
    }

    /// The public address every mapping of this lab sends from.
    ///
    /// A lab spawned behind an upstream has no address of its own: the
    /// externally visible address is whatever the upstream allocates, and
    /// this one reads `0.0.0.0` as a label.
    #[must_use]
    pub fn public_ip(&self) -> Ipv4Addr {
        self.inner.public_ip
    }

    /// The port window the lab allocates from.
    ///
    /// Discovery moves the window past ports the OS excludes and verifies
    /// at most [`MAX_WINDOW_PORTS`] of them, so tests read port positions
    /// relative to this range. A lab spawned behind an upstream scanned
    /// nothing — the window is the requested range, and the OS decides
    /// per bind.
    #[must_use]
    pub fn port_window(&self) -> Range<u16> {
        self.inner.window.clone()
    }

    /// Sets how long mappings survive the close of their socket.
    ///
    /// The default of zero releases mappings at close. A nonzero delay
    /// models the tens of seconds a real NAT keeps translating after the
    /// loser socket of a punch went away. Mappings a rebound socket opens
    /// on the same private port during the window outlive the release.
    pub fn set_mapping_expiry(&self, expiry: Duration) {
        *self.inner.mapping_expiry.lock().expect("expiry lock") = expiry;
    }

    /// Sets data-plane loss in permille, applied by the gateway.
    ///
    /// Each crossing drops with probability `permille`/1000, drawing from
    /// the lab's seeded generator. Outbound loss follows translation, so a
    /// dropped datagram still opened its mapping; inbound loss precedes
    /// the filter, like the virtual engine's router.
    pub fn set_loss(&self, permille: u32) {
        self.inner.loss_permille.store(permille, Ordering::Relaxed);
    }

    /// Sets how long a mapping survives without traffic in either
    /// direction, like a real NAT's UDP refresh timer per RFC 4787.
    ///
    /// The default of zero disables eviction. Every datagram the mapping
    /// translates out and every datagram arriving on its public socket
    /// restarts the timer; an expired mapping is evicted with its external
    /// port released, counted by [`NatLab::idled_mappings`].
    pub fn set_idle_expiry(&self, expiry: Duration) {
        *self.inner.idle_expiry.lock().expect("idle expiry lock") = expiry;
    }

    /// Installs or removes the per-packet tap.
    ///
    /// The tap sees every crossing once: outbound after the frame parse
    /// and before translation, inbound before the filter check. A `Drop`
    /// decision loses the datagram, and a `Replace` forwards the given
    /// payload instead; a replacement longer than [`MAX_DATAGRAM`] drops
    /// the datagram like an oversize one. Installing or removing takes
    /// effect between datagrams: each crossing consults the tap installed
    /// at that moment and never observes a torn decision.
    pub fn set_tap(&self, tap: Option<Tap>) {
        *self.inner.tap.lock().expect("tap lock") = tap;
    }

    /// Live mappings.
    #[must_use]
    pub fn mapping_count(&self) -> usize {
        self.inner
            .table
            .lock()
            .expect("mapping table lock")
            .map
            .len()
    }

    /// Peak concurrent mappings since the spawn.
    #[must_use]
    pub fn peak_mappings(&self) -> usize {
        self.inner.table.lock().expect("mapping table lock").peak
    }

    /// Every live mapping as (private, external) pairs.
    #[must_use]
    pub fn mappings_snapshot(&self) -> Vec<(SocketAddr, SocketAddr)> {
        let table = self.inner.table.lock().expect("mapping table lock");
        snapshot(&table, self.inner.public_ip)
    }

    /// Datagrams the lab forwarded, outbound plus inbound.
    #[must_use]
    pub fn forwarded(&self) -> u32 {
        self.inner.forwarded.load(Ordering::Relaxed)
    }

    /// Inbound datagrams the filter rejected.
    #[must_use]
    pub fn dropped_by_filter(&self) -> u32 {
        self.inner.dropped_by_filter.load(Ordering::Relaxed)
    }

    /// Datagrams dropped because hairpinning is disabled.
    #[must_use]
    pub fn dropped_by_hairpin(&self) -> u32 {
        self.inner.dropped_by_hairpin.load(Ordering::Relaxed)
    }

    /// Crossings the loss setting dropped, outbound plus inbound.
    #[must_use]
    pub fn dropped_by_loss(&self) -> u32 {
        self.inner.dropped_by_loss.load(Ordering::Relaxed)
    }

    /// Mappings the idle reaper evicted.
    #[must_use]
    pub fn idled_mappings(&self) -> u32 {
        self.inner.idled.load(Ordering::Relaxed)
    }

    /// Waits until every mapping is gone, bounded by five real seconds.
    pub async fn wait_mappings_drained(&self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while self.mapping_count() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for NatLab {
    fn drop(&mut self) {
        // Stops the gateway and reaper loops; the mapping tokens are
        // children, so their receive loops wind down with them.
        self.inner.cancel.cancel();
        // Releasing the table drops the table-side references, so the
        // public sockets close once the receive loops exit; a nested
        // lab's closing uplink sockets Bye the upstream, releasing its
        // mappings in turn.
        self.inner
            .table
            .lock()
            .expect("mapping table lock")
            .map
            .clear();
        // The drawn address returns to the registry, so a long-lived
        // process can spawn another lab on it. A nested lab drew none.
        if self.inner.uplink.is_none() {
            release_lab_ip(self.inner.public_ip);
        }
    }
}

/// Assembles one lab's shared state and starts its gateway and reaper
/// loops, for a flat spawn or a nested one.
fn start_lab(
    seed: &str,
    spec: NatSpec,
    public_ip: Ipv4Addr,
    window: Range<u16>,
    claim: Option<std::net::UdpSocket>,
    gateway: Arc<UdpSocket>,
    uplink: Option<NatLab>,
) -> Arc<LabInner> {
    let inner = Arc::new(LabInner {
        spec,
        public_ip,
        window,
        _claim: claim,
        gateway,
        table: StdMutex::new(MappingTable {
            map: HashMap::new(),
            next_alloc: 0,
            peak: 0,
        }),
        rng: StdMutex::new(seeded_rng(seed)),
        cancel: CancellationToken::new(),
        faults: Arc::new(StdMutex::new(UplinkFaults::default())),
        tap: StdMutex::new(None),
        rebind: StdMutex::new(None),
        forwarded: AtomicU32::new(0),
        dropped_by_filter: AtomicU32::new(0),
        dropped_by_hairpin: AtomicU32::new(0),
        dropped_by_loss: AtomicU32::new(0),
        idled: AtomicU32::new(0),
        loss_permille: AtomicU32::new(0),
        mapping_expiry: StdMutex::new(Duration::ZERO),
        idle_expiry: StdMutex::new(Duration::ZERO),
        uplink,
    });
    tokio::spawn(gateway_loop(Arc::clone(&inner)));
    // One reaper per lab, alive from the spawn: enabling the idle
    // timer needs no extra synchronization.
    tokio::spawn(idle_reaper(Arc::clone(&inner)));
    inner
}

/// Draws one lab address, claims it, and discovers its bindable port
/// window.
///
/// A twin process holding the drawn address refuses the claim, so the draw
/// repeats over fresh addresses, and a draw that fails returns to the
/// registry. An address the host does not carry fails every draw alike, so
/// that error ends the spawn at once.
fn settle_address(
    spec: &NatSpec,
) -> io::Result<(Ipv4Addr, Range<u16>, Option<std::net::UdpSocket>)> {
    let mut last = None;
    for _ in 0..8 {
        let ip = draw_lab_ip()?;
        let settled =
            claim_address(ip).and_then(|claim| Ok((discover_window(ip, &spec.port_range)?, claim)));
        match settled {
            Ok((window, claim)) => return Ok((ip, window, claim)),
            Err(e) => {
                release_lab_ip(ip);
                if e.kind() == io::ErrorKind::AddrNotAvailable {
                    return Err(e);
                }
                last = Some(e);
            },
        }
    }
    Err(last.expect("eight draws all failed"))
}

/// Collects (private, external) pairs of every live mapping.
fn snapshot(table: &MappingTable, public_ip: Ipv4Addr) -> Vec<(SocketAddr, SocketAddr)> {
    table
        .map
        .values()
        .map(|m| {
            (
                m.client,
                SocketAddr::V4(SocketAddrV4::new(public_ip, m.ext_port)),
            )
        })
        .collect()
}

/// The live mapping whose external port `dst` aims at, when `dst` is one
/// of this NAT's own external addresses.
///
/// One rule serves flat and stacked NATs alike: the destination is this
/// NAT's public address and a live mapping holds the port. A port nobody
/// translates at keeps the ordinary outward emission — the datagram goes
/// out and is lost, not turned into a hairpin drop.
fn hairpin_target(inner: &LabInner, dst: SocketAddr) -> Option<Arc<LabMapping>> {
    let SocketAddr::V4(dst) = dst else {
        return None;
    };
    if *dst.ip() != inner.public_ip {
        return None;
    }
    let table = inner.table.lock().expect("mapping table lock");
    table
        .map
        .values()
        .find(|mapping| mapping.ext_port == dst.port())
        .cloned()
}

/// The lab's forwarding core: one sequential receive loop.
///
/// Allocation order follows arrival order, and loopback preserves send
/// order per sender, so a probing socket reads the same allocation
/// sequence it would read behind a real NAT.
async fn gateway_loop(inner: Arc<LabInner>) {
    let mut buf = [0u8; FRAME_HEADER + MAX_DATAGRAM];
    loop {
        let (len, from) = tokio::select! {
            () = inner.cancel.cancelled() => break,
            result = inner.gateway.recv_from(&mut buf) => match result {
                Ok(v) => v,
                Err(e) if is_link_reset(&e) => continue,
                Err(_) => break,
            },
        };
        let Some((tag, addr, payload)) = parse_frame(&buf[..len]) else {
            continue;
        };
        match tag {
            TAG_OUT => {
                let Some(dst) = addr else { continue };
                // The tap sees the datagram before translation, so a tap
                // drop opens no mapping.
                let Some(payload) = apply_tap(&inner.tap, Direction::Out, from, dst, payload)
                else {
                    continue;
                };
                // A bind failure means the window ran dry; the datagram is
                // lost, as a full NAT would lose it.
                let _ = outbound(&inner, from, dst, &payload).await;
            },
            TAG_BYE => client_closed(&inner, from),
            // In frames travel to client sockets only.
            _ => {},
        }
    }
}

/// Translates one client datagram through its mapping and sends it out.
///
/// Loss follows translation, so a dropped datagram still opened its
/// mapping, like the virtual engine's send path. A datagram aimed at this
/// NAT's own external address loops back through the target mapping's
/// inbound path instead (RFC 4787 §6 hairpinning), or — with hairpinning
/// disabled — drops right after the translation and counts as
/// [`NatLab::dropped_by_hairpin`].
async fn outbound(
    inner: &Arc<LabInner>,
    client: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    let mapping = translate_outbound(inner, client, dst)?;
    if let Some(target) = hairpin_target(inner, dst) {
        if !inner.spec.hairpin {
            inner.dropped_by_hairpin.fetch_add(1, Ordering::Relaxed);
            trace(format_args!("LAB hairpin drop {client} -> {dst}"));
            return Ok(());
        }
        // The out crossing translated, refreshes the sender's idle timer,
        // and can drop, like any emission; the looped datagram then reads
        // as if it arrived on the target's public socket.
        touch(&mapping);
        if loses(inner) {
            inner.dropped_by_loss.fetch_add(1, Ordering::Relaxed);
            trace(format_args!("LAB loss drop out {client} -> {dst}"));
            return Ok(());
        }
        inner.forwarded.fetch_add(1, Ordering::Relaxed);
        let src = SocketAddr::V4(SocketAddrV4::new(inner.public_ip, mapping.ext_port));
        inbound(inner, &target, src, payload).await;
        return Ok(());
    }
    touch(&mapping);
    if loses(inner) {
        inner.dropped_by_loss.fetch_add(1, Ordering::Relaxed);
        trace(format_args!("LAB loss drop out {client} -> {dst}"));
        return Ok(());
    }
    mapping.ext.send_to(payload, dst).await?;
    inner.forwarded.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Finds or creates the mapping one outbound datagram uses.
///
/// The mapping behavior fixes the reuse key: endpoint-independent mappings
/// follow the client, address-dependent ones the destination address, and
/// address-and-port-dependent ones the full destination.
fn translate_outbound(
    inner: &Arc<LabInner>,
    client: SocketAddr,
    dst: SocketAddr,
) -> io::Result<Arc<LabMapping>> {
    let key = ReuseKey::new(inner.spec.mapping, client, dst);
    let mut table = inner.table.lock().expect("mapping table lock");
    if let Some(mapping) = table.map.get(&key) {
        add_dest(mapping, dst);
        return Ok(Arc::clone(mapping));
    }
    let mapping = allocate_mapping(inner, &mut table, client)?;
    add_dest(&mapping, dst);
    table.map.insert(key, Arc::clone(&mapping));
    table.note_count();
    Ok(mapping)
}

/// Records one destination on its mapping for the inbound filter.
fn add_dest(mapping: &LabMapping, dst: SocketAddr) {
    mapping.dests.lock().expect("dests lock").insert(dst);
}

/// Binds the external socket of one fresh mapping under the port policy.
fn allocate_mapping(
    inner: &Arc<LabInner>,
    table: &mut MappingTable,
    client: SocketAddr,
) -> io::Result<Arc<LabMapping>> {
    // Preserve claims the client's internal port exactly when it binds;
    // the walk below takes over only on collision.
    if let Allocation::Preserve = inner.spec.allocation
        && let Ok((ext, ext_port)) = bind_ext(inner, client.port())
    {
        return Ok(build_mapping(inner, client, ext, ext_port));
    }
    let start = inner.window.start;
    let end = inner.window.end;
    let len = u64::from(end - start);
    // Candidates are tried until one binds, which covers a port stolen
    // after the window discovery, or held by another uplink socket in
    // nested mode.
    let mut budget = len as usize + 8;
    loop {
        if budget == 0 {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "no port of the window binds",
            ));
        }
        budget -= 1;
        let port = match inner.spec.allocation {
            Allocation::Increment { step } => {
                let n = table.next_alloc as i64;
                table.next_alloc += 1;
                // The rebind fault models a router restart of the port
                // walk and stays armed for stepped walks only; the plain
                // step-one walk of the cone presets ignores it.
                let n = if step == 1 { n } else { apply_rebind(inner, table, n) };
                let offset = (n * i64::from(step)).rem_euclid(len as i64) as u16;
                start + offset
            },
            // A live mapping holds its port alone, so the draw comes from
            // the ports no live mapping holds, like the simulator's.
            Allocation::Random => {
                let used = table.used_ports();
                let mut rng = inner.rng.lock().expect("rng lock");
                if used.len() >= len as usize {
                    rng.random_range(start..end)
                } else {
                    let free: Vec<u16> = (start..end).filter(|p| !used.contains(p)).collect();
                    free[rng.random_range(0..free.len())]
                }
            },
            // The mirror lost the race; walk the window like a step-one
            // increment. The rebind fault stays a no-op here: a port the
            // walk handed out does not follow the stepped jump.
            Allocation::Preserve => {
                let n = table.next_alloc;
                table.next_alloc += 1;
                start + (n % len) as u16
            },
        };
        let Ok((ext, ext_port)) = bind_ext(inner, port) else {
            continue;
        };
        return Ok(build_mapping(inner, client, ext, ext_port));
    }
}

/// Binds one external socket at `port`: a public socket on the lab's own
/// address for a flat NAT, or an uplink client socket of the upstream lab
/// for a nested one.
fn bind_ext(inner: &Arc<LabInner>, port: u16) -> io::Result<(Box<dyn ExtSock>, u16)> {
    match &inner.uplink {
        None => {
            let sock = bind_public(inner.public_ip, port)?;
            let ext_port = sock
                .local_addr()
                .expect("bound socket reports its address")
                .port();
            Ok((Box::new(ExtAny(PublicSock(sock))), ext_port))
        },
        Some(uplink) => {
            let sock = bind_uplink(uplink, port)?;
            Ok((Box::new(ExtAny(sock)), port))
        },
    }
}

/// Wraps one bound external socket into a live mapping and starts its
/// receive loop.
fn build_mapping(
    inner: &Arc<LabInner>,
    client: SocketAddr,
    ext: Box<dyn ExtSock>,
    ext_port: u16,
) -> Arc<LabMapping> {
    trace(format_args!(
        "LAB alloc client={client} ext={}",
        SocketAddr::V4(SocketAddrV4::new(inner.public_ip, ext_port))
    ));
    let mapping = Arc::new(LabMapping {
        client,
        ext_port,
        ext,
        dests: Arc::new(StdMutex::new(HashSet::new())),
        last_seen: StdMutex::new(Instant::now()),
        // A child of the lab token, so the lab's drop releases every
        // mapping at once.
        cancel: inner.cancel.child_token(),
    });
    tokio::spawn(mapping_loop(Arc::clone(inner), Arc::clone(&mapping)));
    mapping
}

/// Applies the armed rebind once the allocation count passes its arming
/// point: the stepped walk jumps forward and the fault disarms, so the
/// sequence continues from a fresh base like a router rebind.
fn apply_rebind(inner: &LabInner, table: &mut MappingTable, n: i64) -> i64 {
    let mut fault = inner.rebind.lock().expect("rebind fault lock");
    match *fault {
        Some(at) if n >= i64::from(at) => {
            // The jump draws from the seeded generator and lands the walk
            // well clear of the ports it just left for common widths.
            let jump = i64::from(
                inner
                    .rng
                    .lock()
                    .expect("rng lock")
                    .random_range(3_000..4_000u32),
            );
            table.next_alloc += jump as u64;
            *fault = None;
            trace(format_args!("LAB rebind alloc={n} jump={jump}"));
            n + jump
        },
        _ => n,
    }
}

/// Serves the public socket of one mapping.
///
/// Inbound datagrams pass through the mapping's inbound pipeline: the
/// loss draw, the tap, and the filter check in that order, then reach the
/// client as In frames through the gateway socket.
async fn mapping_loop(inner: Arc<LabInner>, mapping: Arc<LabMapping>) {
    let mut buf = [0u8; MAX_DATAGRAM];
    loop {
        let recv = mapping.ext.recv_from(&mut buf);
        tokio::select! {
            () = mapping.cancel.cancelled() => break,
            result = recv => match result {
                Ok((len, src)) => inbound(&inner, &mapping, src, &buf[..len]).await,
                Err(e) if is_link_reset(&e) => {},
                Err(_) => break,
            },
        }
    }
}

/// The inbound pipeline of one mapping: idle refresh, loss draw, tap, and
/// filter check in that order, then delivery to the client as an In frame
/// through the gateway socket.
///
/// A hairpinned datagram crosses this pipeline on the target mapping, so
/// it reads exactly like an arrival on the target's public socket: the
/// source is the sender's external address and the target's filter
/// applies to it.
async fn inbound(inner: &Arc<LabInner>, mapping: &LabMapping, src: SocketAddr, payload: &[u8]) {
    // Any arrival on the public socket restarts the idle timer.
    touch(mapping);
    if loses(inner) {
        inner.dropped_by_loss.fetch_add(1, Ordering::Relaxed);
        trace(format_args!("LAB loss drop in {src} -> {}", mapping.client));
        return;
    }
    let Some(payload) = apply_tap(&inner.tap, Direction::In, src, mapping.client, payload) else {
        return;
    };
    if !allows(inner.spec.filtering, &mapping.dests, src) {
        inner.dropped_by_filter.fetch_add(1, Ordering::Relaxed);
        trace(format_args!(
            "LAB filter drop {src} ext={}",
            SocketAddr::V4(SocketAddrV4::new(inner.public_ip, mapping.ext_port))
        ));
        return;
    }
    // A v4 socket hears from v4 peers only.
    let SocketAddr::V4(src_v4) = src else {
        return;
    };
    let mut wire = vec![0u8; FRAME_HEADER + payload.len()];
    write_header(&mut wire, TAG_IN, src_v4);
    wire[FRAME_HEADER..].copy_from_slice(&payload);
    // A failed delivery only loses this datagram, like a NAT whose client
    // went away.
    if inner.gateway.send_to(&wire, mapping.client).await.is_ok() {
        inner.forwarded.fetch_add(1, Ordering::Relaxed);
    }
}

/// One inbound filter decision, with the simulator's semantics.
fn allows(filtering: FilterClass, dests: &StdMutex<HashSet<SocketAddr>>, src: SocketAddr) -> bool {
    let dests = dests.lock().expect("dests lock");
    match filtering {
        FilterClass::EndpointIndependent => true,
        FilterClass::AddressDependent => dests.iter().any(|d| d.ip() == src.ip()),
        FilterClass::AddressPortDependent => dests.contains(&src),
    }
}

/// Evicts mappings idle past the inactivity expiry.
///
/// The reaper runs from the spawn and idles while the expiry is zero, so
/// enabling the timer needs no extra synchronization.
async fn idle_reaper(inner: Arc<LabInner>) {
    loop {
        let expiry = *inner.idle_expiry.lock().expect("idle expiry lock");
        // The tick tracks the expiry, bounded so a huge setting still
        // polls and a tiny one still yields.
        let tick = if expiry.is_zero() {
            Duration::from_millis(200)
        } else {
            (expiry / 4).clamp(Duration::from_millis(10), Duration::from_secs(1))
        };
        tokio::select! {
            () = inner.cancel.cancelled() => break,
            () = tokio::time::sleep(tick) => {},
        }
        if expiry.is_zero() {
            continue;
        }
        let now = Instant::now();
        let expired: Vec<Arc<LabMapping>> = {
            let table = inner.table.lock().expect("mapping table lock");
            table
                .map
                .values()
                .filter(|mapping| {
                    let last = *mapping.last_seen.lock().expect("last seen lock");
                    now.saturating_duration_since(last) >= expiry
                })
                .cloned()
                .collect()
        };
        if expired.is_empty() {
            continue;
        }
        for mapping in &expired {
            trace(format_args!(
                "LAB idle evict client={} ext={}",
                mapping.client,
                SocketAddr::V4(SocketAddrV4::new(inner.public_ip, mapping.ext_port))
            ));
        }
        let removed = release_captured(&inner, &expired);
        inner.idled.fetch_add(removed as u32, Ordering::Relaxed);
    }
}

/// Releases a closed client's mappings, honoring the expiry setting.
fn client_closed(inner: &Arc<LabInner>, client: SocketAddr) {
    let expiry = *inner.mapping_expiry.lock().expect("expiry lock");
    if expiry.is_zero() {
        forget_client(inner, client);
        return;
    }
    // The mappings keep translating for the expiry window, like a router
    // honoring its timer after the socket closed. The capture holds the
    // mappings alive at Bye: the OS may reassign the private port during
    // the window, and a rebound socket's fresh mappings must outlive this
    // release.
    let captured = capture_client(inner, client);
    if captured.is_empty() {
        return;
    }
    let inner = Arc::clone(inner);
    tokio::spawn(async move {
        tokio::select! {
            () = inner.cancel.cancelled() => {},
            () = tokio::time::sleep(expiry) => {
                release_captured(&inner, &captured);
            },
        }
    });
}

/// The mappings of one client alive right now, left in the table.
fn capture_client(inner: &LabInner, client: SocketAddr) -> Vec<Arc<LabMapping>> {
    let table = inner.table.lock().expect("mapping table lock");
    table
        .map
        .values()
        .filter(|mapping| mapping.client == client)
        .cloned()
        .collect()
}

/// Removes exactly `captured` mappings from the table and cancels their
/// tokens, closing the public sockets.
///
/// The removal matches by identity, so a mapping a rebound socket opened
/// on the same private port during the wait survives. Returns how many
/// mappings left the table.
fn release_captured(inner: &LabInner, captured: &[Arc<LabMapping>]) -> usize {
    if captured.is_empty() {
        return 0;
    }
    let mut table = inner.table.lock().expect("mapping table lock");
    let before = table.map.len();
    table
        .map
        .retain(|_, mapping| !captured.iter().any(|c| Arc::ptr_eq(c, mapping)));
    let removed = before - table.map.len();
    drop(table);
    // Each receive task owns one socket reference; the token releases it.
    for mapping in captured {
        mapping.cancel.cancel();
    }
    removed
}

/// Removes every mapping of one client and closes its public sockets.
fn forget_client(inner: &LabInner, client: SocketAddr) {
    let mut table = inner.table.lock().expect("mapping table lock");
    let removed: Vec<Arc<LabMapping>> = table
        .map
        .values()
        .filter(|mapping| mapping.client == client)
        .cloned()
        .collect();
    table.map.retain(|_, mapping| mapping.client != client);
    // Each receive task owns one socket reference; the token releases it.
    for mapping in removed {
        mapping.cancel.cancel();
    }
}

/// Marks one crossing on the mapping's idle timer.
fn touch(mapping: &LabMapping) {
    *mapping.last_seen.lock().expect("last seen lock") = Instant::now();
}

/// Whether the lab drops one crossing, drawing from the seeded generator.
fn loses(inner: &LabInner) -> bool {
    let permille = inner.loss_permille.load(Ordering::Relaxed);
    permille > 0 && inner.rng.lock().expect("rng lock").random_range(0..1000) < permille
}

/// Consults the installed tap for one crossing and returns the payload to
/// forward, or `None` when the tap drops the datagram.
///
/// A `Replace` payload over [`MAX_DATAGRAM`] drops the datagram like an
/// oversize one. The tap clones out of its slot, so a tap that re-enters
/// the lab cannot deadlock the crossing, and an install or removal takes
/// effect between datagrams.
fn apply_tap<'a>(
    tap: &StdMutex<Option<Tap>>,
    direction: Direction,
    src: SocketAddr,
    dst: SocketAddr,
    payload: &'a [u8],
) -> Option<Cow<'a, [u8]>> {
    let tap = tap.lock().expect("tap lock").clone();
    let event = TapEvent {
        direction,
        src,
        dst,
        payload,
    };
    match tap.as_ref().map(|tap| tap(&event)) {
        Some(TapDecision::Forward) | None => Some(Cow::Borrowed(payload)),
        Some(TapDecision::Drop) => {
            trace(format_args!("LAB tap drop {direction:?} {src} -> {dst}"));
            None
        },
        Some(TapDecision::Replace(replacement)) if replacement.len() > MAX_DATAGRAM => {
            trace(format_args!(
                "LAB tap drop {direction:?} {src} -> {dst} oversize"
            ));
            None
        },
        Some(TapDecision::Replace(replacement)) => Some(Cow::Owned(replacement)),
    }
}

/// Prints one trace line when `NAT_LAB_TRACE` is set, like the simulator.
fn trace(args: fmt::Arguments<'_>) {
    if std::env::var_os("NAT_LAB_TRACE").is_some() {
        eprintln!("[lab] {args}");
    }
}

/// Factory that binds client sockets behind one lab NAT.
#[derive(Clone)]
pub struct LabHost {
    inner: Arc<LabInner>,
}

impl LabHost {
    /// Drops the first datagram this lab sends to `target` before it
    /// reaches the NAT, so the destination holds no mapping until the
    /// sender retransmits.
    ///
    /// One lab hosts one peer, so the rule covers every socket the lab's
    /// hosts bound, and it is one-shot: the next datagram to `target`
    /// crosses.
    pub fn drop_first_send_to(&self, target: SocketAddr) {
        self.inner
            .faults
            .lock()
            .expect("uplink fault lock")
            .drop_first
            .insert(target);
    }

    /// Fails every send to `target` locally, like a route that never
    /// leaves the host.
    ///
    /// One lab hosts one peer, so the rule covers every socket the lab's
    /// hosts bound.
    pub fn fail_sends_to(&self, target: SocketAddr) {
        self.inner
            .faults
            .lock()
            .expect("uplink fault lock")
            .unreachable
            .insert(target);
    }

    /// Walks the lab allocation sequence forward by `count` mappings, like
    /// other users of the same carrier NAT allocating between the phases
    /// of a session.
    ///
    /// One scratch socket sends a datagram to `count` distinct
    /// documentation-range destinations and closes at once, so only the
    /// sequence position moves; no mapping survives.
    pub async fn external_allocations(&self, count: usize) {
        let Ok(sock) = self.bind(Family::V4.any_addr()).await else {
            return;
        };
        for i in 0..count {
            // Documentation-range addresses that route to nobody, varying
            // the IP so an address-dependent NAT allocates per destination
            // too.
            let dst = SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(198, 51, 100, (i % 254 + 1) as u8),
                9000 + (i / 254) as u16,
            ));
            let _ = sock.send_to(b"x", dst).await;
        }
        drop(sock);
    }

    /// Jumps the lab allocation sequence to a fresh base once
    /// `allocations` mappings exist, like a router rebind that restarts
    /// the port walk. Applies to stepped [`Allocation::Increment`] walks
    /// (a step other than one); [`Allocation::Random`] and
    /// [`Allocation::Preserve`] ignore it.
    pub fn rebind_sequence_after(&self, allocations: u32) {
        *self.inner.rebind.lock().expect("rebind fault lock") = Some(allocations);
    }
}

impl UdpFactory for LabHost {
    type Socket = LabSocket;

    async fn bind(&self, addr: SocketAddr) -> io::Result<LabSocket> {
        if addr.is_ipv6() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the lab is IPv4 only",
            ));
        }
        // The private network behind the lab is loopback; any requested
        // IPv4 address maps onto it and the requested port survives.
        let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, addr.port())).await?;
        lab_socket(&self.inner, sock)
    }
}

/// Wraps one bound client socket into a lab socket framed for `inner`'s
/// gateway.
fn lab_socket(inner: &Arc<LabInner>, sock: UdpSocket) -> io::Result<LabSocket> {
    let gateway = inner.gateway.local_addr()?;
    let frame = || vec![0u8; FRAME_HEADER + MAX_DATAGRAM];
    Ok(LabSocket {
        sock,
        gateway,
        faults: Arc::clone(&inner.faults),
        send_wire: tokio::sync::Mutex::new(frame()),
        recv_wire: tokio::sync::Mutex::new(frame()),
    })
}

/// Binds one uplink client socket of the upstream lab at an explicit
/// port, as a nested lab's external side.
///
/// The OS keeps the port honest: a port the upstream host already holds
/// fails the bind, which moves the nested allocation on.
fn bind_uplink(uplink: &NatLab, port: u16) -> io::Result<LabSocket> {
    let sock = std::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))?;
    sock.set_nonblocking(true)?;
    lab_socket(&uplink.inner, UdpSocket::from_std(sock)?)
}

/// One client socket behind a lab NAT: a real loopback socket that frames
/// its datagrams for the gateway.
///
/// The frame buffers live on the heap, one per direction, so the async
/// methods stay small no matter how large a datagram the lab forwards.
pub struct LabSocket {
    sock: UdpSocket,
    gateway: SocketAddr,
    /// Uplink faults the socket consults before the gateway.
    faults: Arc<StdMutex<UplinkFaults>>,
    send_wire: tokio::sync::Mutex<Vec<u8>>,
    recv_wire: tokio::sync::Mutex<Vec<u8>>,
}

impl UdpIo for LabSocket {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        {
            let mut faults = self.faults.lock().expect("uplink fault lock");
            if faults.unreachable.contains(&target) {
                return Err(io::Error::new(
                    io::ErrorKind::NetworkUnreachable,
                    "lab uplink fault: destination unreachable",
                ));
            }
            if faults.drop_first.remove(&target) {
                // The datagram reports success and never reaches the NAT,
                // so the destination holds no mapping yet.
                return Ok(buf.len());
            }
        }
        // The gateway's receive buffer fits one framed data packet, so a
        // longer payload has no path through the lab.
        if buf.len() > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload over the lab frame cap",
            ));
        }
        let IpAddr::V4(ip) = target.ip() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the lab is IPv4 only",
            ));
        };
        let mut wire = self.send_wire.lock().await;
        write_header(&mut wire, TAG_OUT, SocketAddrV4::new(ip, target.port()));
        wire[FRAME_HEADER..FRAME_HEADER + buf.len()].copy_from_slice(buf);
        self.sock
            .send_to(&wire[..FRAME_HEADER + buf.len()], self.gateway)
            .await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut wire = self.recv_wire.lock().await;
        loop {
            let (len, _) = self.sock.recv_from(&mut wire).await?;
            // The gateway is the only sender here and sends only In
            // frames; anything else is skipped.
            if let Some((TAG_IN, Some(from), payload)) = parse_frame(&wire[..len]) {
                let len = payload.len().min(buf.len());
                buf[..len].copy_from_slice(&payload[..len]);
                return Ok((len, from));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }
}

impl Drop for LabSocket {
    fn drop(&mut self) {
        // Best effort from a sync context; a lost Bye only keeps the
        // mapping alive until the lab goes away, and a Bye after the lab
        // died fails to send and is ignored.
        let _ = self.sock.try_send_to(&[TAG_BYE], self.gateway);
    }
}

/// Writes the header of one addressed frame into `wire`.
fn write_header(wire: &mut [u8], tag: u8, addr: SocketAddrV4) {
    wire[0] = tag;
    wire[1..5].copy_from_slice(&addr.ip().octets());
    wire[5..7].copy_from_slice(&addr.port().to_le_bytes());
}

/// Splits one lab frame into its tag, address, and payload.
///
/// Bye carries no address, so it parses as `None` with an empty payload.
fn parse_frame(frame: &[u8]) -> Option<(u8, Option<SocketAddr>, &[u8])> {
    let (&tag, rest) = frame.split_first()?;
    if tag == TAG_BYE {
        return Some((tag, None, &[]));
    }
    if rest.len() < FRAME_HEADER - 1 {
        return None;
    }
    let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
    let port = u16::from_le_bytes([rest[4], rest[5]]);
    Some((
        tag,
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port))),
        &rest[FRAME_HEADER - 1..],
    ))
}

/// Whether an error reports a stray ICMP unreachable.
///
/// Loopback answers a send to a dead port with port-unreachable, which
/// Windows surfaces on a later operation of the same socket. The datagram
/// after the error still arrives, so the loops continue.
fn is_link_reset(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
    )
}

/// Binds one exclusive public socket for a mapping or a responder.
///
/// Plain binds, without the platform reuse options the punch path sets:
/// reuse would let two mappings share one port silently on Unix.
fn bind_public(ip: Ipv4Addr, port: u16) -> io::Result<UdpSocket> {
    let sock = std::net::UdpSocket::bind(SocketAddrV4::new(ip, port))?;
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock)
}

/// Widest port window discovery verifies, whatever the spec asks for.
///
/// A wide spec spans some 64k ports, and probing each costs one bind and
/// one close per spawn, so the scan verifies at most this many ports and
/// the window covers the first such run.
const MAX_WINDOW_PORTS: u32 = 1024;

/// Bind attempts one window discovery spends before falling back to the
/// longest run found, so a long OS-reserved stretch cannot stall a spawn.
const MAX_WINDOW_BINDS: u32 = 4096;

/// Finds the mapping port window on one public address.
///
/// Explicit binds fail on ports the OS excludes, Windows reserves chunks
/// machine-wide, and on ports another process holds. The scan takes the
/// first run of bindable ports at or after the requested start that fits
/// the window, so the window keeps its width and only its position moves.
/// Two caps keep the scan cheap: at most [`MAX_WINDOW_PORTS`] ports are
/// verified, and at most [`MAX_WINDOW_BINDS`] binds are attempted before
/// the scan falls back to the longest run found, which narrows the window
/// instead of failing the spawn. Every port of the returned window bound
/// during the scan.
fn discover_window(ip: Ipv4Addr, requested: &Range<u16>) -> io::Result<Range<u16>> {
    if requested.start >= requested.end {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "port range is empty",
        ));
    }
    // Port zero binds as a wildcard, which breaks explicit allocation.
    let first = requested.start.max(1);
    let width = u32::from(requested.end - requested.start);
    scan_window(first, width, |port| port_bindable(ip, port))
}

/// Scans upward from `first` for the first run of `width` bindable ports.
///
/// `width` caps at [`MAX_WINDOW_PORTS`], and the scan spends at most
/// [`MAX_WINDOW_BINDS`] bind attempts before returning the longest run
/// found.
fn scan_window(first: u16, width: u32, bindable: impl Fn(u16) -> bool) -> io::Result<Range<u16>> {
    let width = width.min(MAX_WINDOW_PORTS);
    // Longest bindable run so far, as (start, length).
    let mut best = (first, 0u32);
    let mut run_start = first;
    let mut run_len = 0u32;
    let mut budget = MAX_WINDOW_BINDS;
    for port in first..=u16::MAX {
        if budget == 0 {
            break;
        }
        budget -= 1;
        if bindable(port) {
            run_len += 1;
            if run_len >= width {
                // A u16 end cannot pass 65535, so a run touching the
                // last port loses it.
                let end = (u32::from(run_start) + width).min(u32::from(u16::MAX));
                return Ok(run_start..end as u16);
            }
        } else {
            if run_len > best.1 {
                best = (run_start, run_len);
            }
            run_len = 0;
            run_start = port.saturating_add(1);
        }
    }
    // The scan stopped on the budget or the last port; the trailing run
    // holds verified ports and competes with the best run.
    if run_len > best.1 {
        best = (run_start, run_len);
    }
    if best.1 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "no port of the range binds",
        ));
    }
    // A u16 range cannot express an end past 65535, so a run touching
    // the last port loses it.
    let end = (u32::from(best.0) + best.1).min(u32::from(u16::MAX));
    Ok(best.0..end as u16)
}

/// Whether one explicit bind on the public address succeeds.
fn port_bindable(ip: Ipv4Addr, port: u16) -> bool {
    std::net::UdpSocket::bind(SocketAddrV4::new(ip, port)).is_ok()
}

/// Derives the lab's randomness from the seed string, like `Net::seeded`.
fn seeded_rng(seed: &str) -> StdRng {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    StdRng::seed_from_u64(hasher.finish())
}

/// Handle of the lab STUN responder.
pub struct StunServer {
    /// `host:port` strings for `PunchConfig::stun_servers`.
    pub addrs: Vec<String>,
    /// Alternate-IP `host:port` strings the responder answers RFC 5780
    /// discovery requests from: the OTHER-ADDRESS targets.
    pub other_addrs: Vec<String>,
    /// Stops the responder loops.
    cancel: CancellationToken,
    /// Drawn addresses, returned to the registry on drop.
    ips: Vec<Ipv4Addr>,
}

impl Drop for StunServer {
    fn drop(&mut self) {
        self.cancel.cancel();
        release_stun_ips(&self.ips);
    }
}

/// Starts a STUN responder over two dedicated loopback addresses.
///
/// Four sockets, two ports on each of two addresses, form the RFC 5780
/// discovery grid: every socket answers binding requests with the v4
/// XOR-MAPPED address of the datagram's source plus RESPONSE-ORIGIN and
/// OTHER-ADDRESS, and a CHANGE-REQUEST reroutes the reply to the
/// flag-selected alternate socket. Four destinations is what
/// classification needs for a confident EasySym fit, and spanning two IPs
/// is what a cone reading needs before it counts as mapping-dimension
/// evidence.
pub fn stun_responder() -> io::Result<StunServer> {
    const PORTS: [u16; 2] = [3478, 3479];
    // Every port must bind on both addresses; a twin process that holds
    // one of them draws fresh addresses.
    for _ in 0..16 {
        let first = draw_stun_ip()?;
        let second = draw_stun_ip()?;
        let grid = Grid::new([first, second], &PORTS);
        let layout = grid.addrs();
        let mut sockets = Vec::with_capacity(layout.len());
        let mut refused = None;
        let bound = layout.iter().all(|&addr| {
            let SocketAddr::V4(v4) = addr else {
                return false;
            };
            match bind_public(*v4.ip(), v4.port()) {
                Ok(sock) => {
                    sockets.push(sock);
                    true
                },
                Err(e) => {
                    refused = Some((*v4.ip(), e));
                    false
                },
            }
        });
        if bound {
            let cancel = CancellationToken::new();
            let sockets: Arc<[Arc<UdpSocket>]> =
                sockets.into_iter().map(Arc::new).collect::<Vec<_>>().into();
            for sock in sockets.iter() {
                tokio::spawn(stun_loop(
                    Arc::clone(sock),
                    grid.clone(),
                    Arc::clone(&sockets),
                    cancel.clone(),
                ));
            }
            let split = layout.len() / 2;
            return Ok(StunServer {
                addrs: layout.iter().map(ToString::to_string).collect(),
                other_addrs: layout[split..].iter().map(ToString::to_string).collect(),
                cancel,
                ips: vec![first, second],
            });
        }
        // The failed draw never became a responder, so both addresses go
        // back for the next attempt. An address the host does not carry
        // fails every draw alike.
        drop(sockets);
        release_stun_ips(&[first, second]);
        if let Some((ip, e)) = refused
            && e.kind() == io::ErrorKind::AddrNotAvailable
        {
            return Err(missing_alias(ip));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no responder address binds",
    ))
}

/// Answers binding requests on one STUN socket until the server drops.
///
/// A CHANGE-REQUEST reply leaves the grid's flag-selected socket, so every
/// loop holds a handle on every socket of the grid.
async fn stun_loop(
    sock: Arc<UdpSocket>,
    grid: Grid,
    sockets: Arc<[Arc<UdpSocket>]>,
    cancel: CancellationToken,
) {
    let received = sock.local_addr().expect("bound socket reports its address");
    let mut buf = [0u8; 128];
    loop {
        let recv = sock.recv_from(&mut buf);
        tokio::select! {
            () = cancel.cancelled() => break,
            result = recv => match result {
                Ok((len, from)) => {
                    let Some(flags) = crate::stun::binding_request_flags(&buf[..len]) else {
                        continue;
                    };
                    let reply_src = grid.reply_source(received, flags);
                    let other = grid.other_address(received);
                    if let Some(reply) =
                        crate::stun::discovery_reply(&buf[..len], from, reply_src, other)
                    {
                        let at = grid.index_of(reply_src).expect("grid address");
                        let _ = sockets[at].send_to(&reply, from).await;
                    }
                },
                Err(e) if is_link_reset(&e) => {},
                Err(_) => break,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::{sim::MappingBehavior, socket::Family};

    /// A narrow-range spec, so window discovery stays instant.
    fn spec(mapping: MappingBehavior, filtering: FilterClass) -> NatSpec {
        NatSpec {
            mapping,
            allocation: Allocation::Increment { step: 1 },
            filtering,
            port_range: 30_000..30_040,
            hairpin: true,
        }
    }

    /// Binds one plain loopback socket as an off-NAT destination.
    async fn dest() -> UdpSocket {
        UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("destination binds")
    }

    /// Receives one datagram within two seconds, or panics.
    async fn recv(sock: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; 64];
        let (len, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .expect("datagram within 2s")
            .expect("socket alive");
        (buf[..len].to_vec(), from)
    }

    /// Waits until the lab holds `want` mappings, bounded by two seconds.
    ///
    /// A completed send only queued the gateway's work, so the mapping
    /// appears once the gateway task was polled.
    async fn wait_mappings(lab: &NatLab, want: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while lab.mapping_count() < want && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Waits until the counter reaches `want`, bounded by two seconds.
    async fn wait_counter(read: impl Fn() -> u32, want: u32) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while read() < want && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn frames_round_trip() {
        let dst = SocketAddrV4::new(Ipv4Addr::new(127, 9, 9, 9), 40_000);
        let mut wire = [0u8; FRAME_HEADER + 5];
        write_header(&mut wire, TAG_OUT, dst);
        wire[FRAME_HEADER..].copy_from_slice(b"hello");
        let (tag, addr, payload) = parse_frame(&wire).expect("out frame parses");
        assert_eq!(tag, TAG_OUT);
        assert_eq!(addr, Some(SocketAddr::V4(dst)));
        assert_eq!(payload, b"hello");

        let (tag, addr, payload) = parse_frame(&[TAG_BYE]).expect("bye frame parses");
        assert_eq!((tag, addr), (TAG_BYE, None));
        assert_eq!(payload, []);

        assert!(parse_frame(&[]).is_none());
        assert!(parse_frame(&[TAG_OUT, 1, 2, 3]).is_none());
    }

    #[test]
    fn window_scan_moves_past_a_conflict() {
        // Port 3 of the range fails, so the window starts after it and
        // keeps its width.
        let window = scan_window(1, 5, |port| port != 3).expect("a run fits");
        assert_eq!(window, 4..9);
    }

    #[test]
    fn window_scan_falls_back_to_the_longest_run() {
        // No run of five exists; the run 6..=9 wins over 1..=2.
        let bindable = |port: u16| (1..=2).contains(&port) || (6..=9).contains(&port);
        let window = scan_window(1, 5, bindable).expect("a run exists");
        assert_eq!(window, 6..10);
    }

    #[test]
    fn window_scan_caps_the_verified_width() {
        // A wide request verifies at most MAX_WINDOW_PORTS ports: the run
        // past the conflict at 3 closes at the capped width.
        let window = scan_window(1, u32::from(u16::MAX), |port| port != 3).expect("a run fits");
        assert_eq!(window, 4..4 + MAX_WINDOW_PORTS as u16);
    }

    #[test]
    fn window_scan_budget_falls_back_to_the_longest_run() {
        // The only bindable run holds 100 ports, and the budget runs out
        // long before any full-width run could exist, so the scan returns
        // the run it verified.
        let window = scan_window(1, MAX_WINDOW_PORTS, |port| port <= 100).expect("a run exists");
        assert_eq!(window, 1..101);
    }

    #[test]
    fn window_scan_clamps_a_run_touching_the_last_port() {
        // The longest run ends at 65535, which no u16 range end can
        // express, so the window ends at 65534.
        let window = scan_window(65_520, 10, |port| port >= 65_530).expect("a run exists");
        assert_eq!(window, 65_530..u16::MAX);
        assert!(scan_window(1, 2, |_| false).is_err());
    }

    #[test]
    fn narrow_pools_split_the_aliases_and_spare_the_foreign_address() {
        let labs: HashSet<Ipv4Addr> = (0..=u16::MAX)
            .map(|n| narrow_ip(NARROW_LAB_FIRST, n))
            .collect();
        let stuns: HashSet<Ipv4Addr> = (0..=u16::MAX)
            .map(|n| narrow_ip(NARROW_STUN_FIRST, n))
            .collect();
        assert_eq!(labs.len(), usize::from(NARROW_POOL));
        assert_eq!(stuns.len(), usize::from(NARROW_POOL));
        assert!(labs.is_disjoint(&stuns));
        let hosts: HashSet<u8> = labs.union(&stuns).map(|ip| ip.octets()[3]).collect();
        assert_eq!(hosts.len(), 2 * usize::from(NARROW_POOL));
        assert!(hosts.iter().all(|&host| (3..=254).contains(&host)));
    }

    /// A live lab holds its claim, so a twin's claim on the same address
    /// is refused and the twin redraws.
    #[tokio::test]
    async fn a_live_lab_refuses_a_twin_claim() {
        let lab = NatLab::spawn(
            "twin_claim",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("lab spawns");
        match claim_address(lab.public_ip()) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::AddrInUse),
            // A platform port exclusion refuses every claim alike.
            Ok(None) => {},
            Ok(Some(_)) => panic!("the lab holds no claim"),
        }
    }

    #[tokio::test]
    async fn cone_mapping_reuses_one_port_across_destinations() {
        let lab = NatLab::spawn(
            "cone_reuse",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("lab spawns");
        let client = lab
            .host()
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");
        let d1 = dest().await;
        let d2 = dest().await;

        client
            .send_to(b"one", d1.local_addr().expect("d1 addr"))
            .await
            .expect("first send");
        client
            .send_to(b"two", d2.local_addr().expect("d2 addr"))
            .await
            .expect("second send");

        let (payload, from1) = recv(&d1).await;
        assert_eq!(payload, b"one");
        let (payload, from2) = recv(&d2).await;
        assert_eq!(payload, b"two");
        // One mapping serves both destinations from one public port.
        assert_eq!(from1, from2);
        assert_eq!(from1.ip(), IpAddr::from(lab.public_ip()));
        assert_eq!(lab.mapping_count(), 1);
    }

    #[tokio::test]
    async fn sequential_mapping_walks_the_step_across_destinations() {
        let lab = NatLab::spawn(
            "seq_step",
            NatSpec::sequential(2).with_range(30_000..30_040),
        )
        .await
        .expect("lab spawns");
        let window = lab.port_window();
        let client = lab
            .host()
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");
        let d1 = dest().await;
        let d2 = dest().await;

        client
            .send_to(b"one", d1.local_addr().expect("d1 addr"))
            .await
            .expect("first send");
        client
            .send_to(b"two", d2.local_addr().expect("d2 addr"))
            .await
            .expect("second send");

        // The gateway allocates in arrival order: the first destination
        // reads the window start, the second the first step.
        let (_, from1) = recv(&d1).await;
        let (_, from2) = recv(&d2).await;
        assert_eq!(from1.port(), window.start);
        assert_eq!(from2.port(), window.start + 2);
        assert_eq!(lab.mapping_count(), 2);
    }

    #[tokio::test]
    async fn apdf_filter_drops_an_unsolicited_source() {
        let lab = NatLab::spawn(
            "apdf_drop",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::AddressPortDependent,
            ),
        )
        .await
        .expect("lab spawns");
        let client = lab
            .host()
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");
        let friend = dest().await;
        client
            .send_to(b"hi", friend.local_addr().expect("friend addr"))
            .await
            .expect("mapping opens");
        wait_mappings(&lab, 1).await;

        // The mapping's public address is the snapshot's second element.
        let ext = lab.mappings_snapshot()[0].1;
        let stranger = dest().await;
        stranger
            .send_to(b"evil", ext)
            .await
            .expect("unsolicited send");

        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buf))
                .await
                .is_err(),
            "the filtered datagram never reaches the client"
        );
        wait_counter(|| lab.dropped_by_filter(), 1).await;
        assert_eq!(lab.dropped_by_filter(), 1);

        // The mapped destination still passes.
        friend.send_to(b"ok", ext).await.expect("allowed send");
        let (len, from) = client.recv_from(&mut buf).await.expect("allowed through");
        assert_eq!(&buf[..len], b"ok");
        assert_eq!(from, friend.local_addr().expect("friend addr"));
    }

    #[tokio::test]
    async fn bye_drains_the_mappings_of_a_closed_socket() {
        let lab = NatLab::spawn(
            "bye_drain",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("lab spawns");
        let d = dest().await;
        {
            let client = lab
                .host()
                .bind(Family::V4.any_addr())
                .await
                .expect("client binds");
            client
                .send_to(b"x", d.local_addr().expect("dest addr"))
                .await
                .expect("mapping opens");
            wait_mappings(&lab, 1).await;
            assert_eq!(lab.mapping_count(), 1);
        }
        // The socket's Drop sent the Bye; zero expiry releases at once.
        lab.wait_mappings_drained().await;
        assert_eq!(lab.mapping_count(), 0);
        assert_eq!(lab.peak_mappings(), 1);
    }

    #[tokio::test]
    async fn delayed_release_spares_a_rebound_socket() {
        let lab = NatLab::spawn(
            "rebound",
            spec(
                MappingBehavior::AddressPortDependent,
                FilterClass::AddressDependent,
            ),
        )
        .await
        .expect("lab spawns");
        lab.set_mapping_expiry(Duration::from_millis(800));
        let d_old = dest().await;
        let d_new = dest().await;
        let private = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 31_111);
        {
            let client = lab.host().bind(private).await.expect("client binds");
            client
                .send_to(b"old", d_old.local_addr().expect("dest addr"))
                .await
                .expect("first send");
            wait_mappings(&lab, 1).await;
        }
        // The Bye reaches the gateway before the rebind, so the capture at
        // Bye time holds the first mapping only.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let client = {
            // The closed socket frees its port; a lingering hold clears
            // within moments.
            let host = lab.host();
            let mut tries = 0;
            loop {
                tries += 1;
                match host.bind(private).await {
                    Ok(sock) => break sock,
                    Err(e) if tries < 10 => {
                        assert_eq!(e.kind(), io::ErrorKind::AddrInUse, "rebind: {e}");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    },
                    Err(e) => panic!("rebind: {e}"),
                }
            }
        };
        client
            .send_to(b"new", d_new.local_addr().expect("dest addr"))
            .await
            .expect("second send");
        wait_mappings(&lab, 2).await;

        // The window passes: the mapping captured at Bye goes away and the
        // rebound socket's fresh mapping survives.
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert_eq!(lab.mapping_count(), 1);
        let window = lab.port_window();
        assert_eq!(
            lab.mappings_snapshot()[0].1.port(),
            window.start + 1,
            "the rebound socket's mapping survives"
        );
    }

    #[tokio::test]
    async fn idle_expiry_evicts_and_traffic_refreshes() {
        let lab = NatLab::spawn(
            "idle",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("lab spawns");
        lab.set_idle_expiry(Duration::from_millis(300));
        let d = dest().await;
        let client = lab
            .host()
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");
        let target = d.local_addr().expect("dest addr");

        // Periodic traffic keeps one mapping alive past several expiries.
        for _ in 0..8 {
            client.send_to(b"tick", target).await.expect("send");
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(lab.mapping_count(), 1, "traffic refreshes the timer");
            assert_eq!(lab.idled_mappings(), 0);
        }

        // With traffic stopped, the reaper evicts and counts.
        lab.wait_mappings_drained().await;
        assert_eq!(lab.mapping_count(), 0);
        assert_eq!(lab.idled_mappings(), 1);
    }

    #[tokio::test]
    async fn loss_drops_both_directions_and_counts_them() {
        let lab = NatLab::spawn(
            "loss",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("lab spawns");
        lab.set_loss(1000);
        let d = dest().await;
        let client = lab
            .host()
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");

        // Outbound: every datagram drops, and the mapping still opens.
        client
            .send_to(b"out", d.local_addr().expect("dest addr"))
            .await
            .expect("send");
        wait_counter(|| lab.dropped_by_loss(), 1).await;
        assert_eq!(lab.mapping_count(), 1);
        assert_eq!(lab.forwarded(), 0);

        // Inbound: the reply drops before the filter and never arrives.
        let ext = lab.mappings_snapshot()[0].1;
        d.send_to(b"in", ext).await.expect("reply send");
        wait_counter(|| lab.dropped_by_loss(), 2).await;
        assert_eq!(lab.forwarded(), 0);
        assert_eq!(lab.dropped_by_filter(), 0);

        let mut buf = [0u8; 16];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .is_err(),
            "no datagram survives a total loss uplink"
        );
    }

    #[tokio::test]
    async fn drop_first_send_holds_the_mapping_back() {
        let lab = NatLab::spawn(
            "drop_first",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("lab spawns");
        let host = lab.host();
        let d = dest().await;
        let target = d.local_addr().expect("dest addr");
        host.drop_first_send_to(target);
        let client = host
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");

        // The first datagram reports success and never reaches the NAT.
        client.send_to(b"one", target).await.expect("send");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(lab.mapping_count(), 0);

        // The retransmission crosses and opens the mapping.
        client.send_to(b"two", target).await.expect("send");
        let (payload, _) = recv(&d).await;
        assert_eq!(payload, b"two");
        wait_mappings(&lab, 1).await;
    }

    #[tokio::test]
    async fn fail_sends_to_reports_unreachable() {
        let lab = NatLab::spawn(
            "fail_sends",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("lab spawns");
        let host = lab.host();
        let d = dest().await;
        let target = d.local_addr().expect("dest addr");
        host.fail_sends_to(target);
        let client = host
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");

        let err = client
            .send_to(b"x", target)
            .await
            .expect_err("the send fails locally");
        assert_eq!(err.kind(), io::ErrorKind::NetworkUnreachable);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(lab.mapping_count(), 0);
    }

    #[tokio::test]
    async fn external_allocations_advance_the_walk() {
        let lab = NatLab::spawn(
            "ext_alloc",
            spec(
                MappingBehavior::AddressPortDependent,
                FilterClass::AddressDependent,
            ),
        )
        .await
        .expect("lab spawns");
        lab.host().external_allocations(3).await;
        let d = dest().await;
        let client = lab
            .host()
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");
        client
            .send_to(b"hi", d.local_addr().expect("dest addr"))
            .await
            .expect("send");

        // The scratch datagrams consumed the first three slots of the walk.
        let (_, from) = recv(&d).await;
        assert_eq!(from.port(), lab.port_window().start + 3);
    }

    #[tokio::test]
    async fn rebind_sequence_jumps_after_the_arming_count() {
        let lab = NatLab::spawn(
            "rebind_seq",
            NatSpec::sequential(2).with_range(30_000..30_040),
        )
        .await
        .expect("lab spawns");
        lab.host().rebind_sequence_after(2);
        let window = lab.port_window();
        let len = i64::from(window.end - window.start);
        // The jump draws from the lab's seeded generator, and this rebind
        // is its first draw.
        let jump = i64::from(seeded_rng("rebind_seq").random_range(3_000..4_000u32));
        let offset = |n: i64| (n * 2).rem_euclid(len) as u16;

        let mut dests = Vec::new();
        for _ in 0..4 {
            dests.push(dest().await);
        }
        let client = lab
            .host()
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");
        for d in &dests {
            client
                .send_to(b"x", d.local_addr().expect("dest addr"))
                .await
                .expect("send");
        }

        // The first two allocations walk as usual; the third crosses the
        // arming point and lands past the jump.
        let mut ports = Vec::new();
        for d in &dests {
            let (_, from) = recv(d).await;
            ports.push(from.port());
        }
        assert_eq!(ports[0], window.start);
        assert_eq!(ports[1], window.start + 2);
        assert_eq!(ports[2], window.start + offset(2 + jump));
        assert_eq!(ports[3], window.start + offset(3 + jump));
        assert_eq!(lab.mapping_count(), 4);
    }

    /// Crossings the test's tap recorded, as (direction, src, dst, payload).
    type Seen = Vec<(Direction, SocketAddr, SocketAddr, Vec<u8>)>;

    #[tokio::test]
    async fn tap_sees_and_shapes_both_directions() {
        let lab = NatLab::spawn(
            "tap",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("lab spawns");
        let seen: Arc<StdMutex<Seen>> = Arc::new(StdMutex::new(Vec::new()));
        let tap_seen = Arc::clone(&seen);
        lab.set_tap(Some(Arc::new(move |event: &TapEvent| {
            tap_seen.lock().expect("seen lock").push((
                event.direction,
                event.src,
                event.dst,
                event.payload.to_vec(),
            ));
            match event.direction {
                Direction::Out if event.payload == b"swap-me" => {
                    TapDecision::Replace(b"swapped".to_vec())
                },
                Direction::In if event.payload == b"blocked" => TapDecision::Drop,
                _ => TapDecision::Forward,
            }
        })));

        let d = dest().await;
        let client = lab
            .host()
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");
        let target = d.local_addr().expect("dest addr");
        let client_addr = client.local_addr().expect("client addr");

        // Outbound Replace: the destination reads the rewritten payload.
        client.send_to(b"swap-me", target).await.expect("send");
        let (payload, _) = recv(&d).await;
        assert_eq!(payload, b"swapped");
        wait_mappings(&lab, 1).await;
        let ext = lab.mappings_snapshot()[0].1;

        // Inbound Drop: the datagram never reaches the client.
        d.send_to(b"blocked", ext).await.expect("reply");
        let mut buf = [0u8; 16];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf))
                .await
                .is_err(),
            "the tap dropped the reply"
        );

        // Inbound Forward passes unchanged.
        d.send_to(b"pass", ext).await.expect("reply");
        let (len, from) = client.recv_from(&mut buf).await.expect("delivered");
        assert_eq!(&buf[..len], b"pass");
        assert_eq!(from, target);

        // Removing the tap restores the plain path, and the crossing goes
        // unrecorded.
        lab.set_tap(None);
        client.send_to(b"plain", target).await.expect("send");
        let (payload, _) = recv(&d).await;
        assert_eq!(payload, b"plain");

        assert_eq!(*seen.lock().expect("seen lock"), vec![
            (Direction::Out, client_addr, target, b"swap-me".to_vec()),
            (Direction::In, target, client_addr, b"blocked".to_vec()),
            (Direction::In, target, client_addr, b"pass".to_vec()),
        ]);
    }

    #[tokio::test]
    async fn dropping_the_lab_and_responder_frees_their_addresses() {
        let lab = NatLab::spawn(
            "lifecycle",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("lab spawns");
        let ip = lab.public_ip();
        assert!(LAB_IPS.lock().expect("address draw lock").contains(&ip));

        let stun = stun_responder().expect("responder spawns");
        assert_eq!(stun.addrs.len(), 4);
        assert_eq!(stun.other_addrs.len(), 2, "the other IP holds both ports");
        let stun_ips: HashSet<Ipv4Addr> = stun
            .addrs
            .iter()
            .filter_map(|addr| addr.split(':').next()?.parse().ok())
            .collect();
        assert_eq!(stun_ips.len(), 2);
        {
            let taken = STUN_IPS.lock().expect("address draw lock");
            for drawn in &stun_ips {
                assert!(taken.contains(drawn), "{drawn} never registered");
            }
        }

        // A mapping loop is live when the lab drops.
        let d = dest().await;
        let client = lab
            .host()
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");
        client
            .send_to(b"x", d.local_addr().expect("dest addr"))
            .await
            .expect("mapping opens");
        wait_mappings(&lab, 1).await;

        drop(lab);
        assert!(
            !LAB_IPS.lock().expect("address draw lock").contains(&ip),
            "the lab address returns to the draw"
        );
        drop(stun);
        let taken = STUN_IPS.lock().expect("address draw lock");
        for drawn in &stun_ips {
            assert!(!taken.contains(drawn), "{drawn} never freed");
        }

        // A socket outliving the lab drops without a panic.
        drop(client);
    }

    /// A nested lab's mapping rides an uplink client socket of the
    /// upstream lab: the outer mapping appears with the inner one, and
    /// releasing the inner one releases the outer through the closing
    /// uplink socket's Bye.
    #[tokio::test]
    async fn nested_mapping_release_travels_upstream() {
        let outer = NatLab::spawn(
            "nested_release_outer",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("outer spawns");
        let inner = NatLab::spawn_behind(
            &outer,
            "nested_release_inner",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("inner spawns");
        assert_eq!(inner.public_ip(), Ipv4Addr::UNSPECIFIED, "display label");
        let d = dest().await;
        {
            let client = inner
                .host()
                .bind(Family::V4.any_addr())
                .await
                .expect("client binds");
            client
                .send_to(b"x", d.local_addr().expect("dest addr"))
                .await
                .expect("send");
            wait_mappings(&inner, 1).await;
            wait_mappings(&outer, 1).await;
            assert_eq!(
                outer.mapping_count(),
                1,
                "the outer holds the uplink mapping"
            );
        }
        // The client's Bye releases the inner mapping; the closing uplink
        // socket's Bye releases the outer one.
        inner.wait_mappings_drained().await;
        outer.wait_mappings_drained().await;
        assert_eq!(outer.mapping_count(), 0, "the release traveled upstream");
    }

    /// Nested labs drop cleanly in either order: inner first sends the
    /// upstream the Byes, outer first leaves the inner's Byes nowhere to
    /// land.
    #[tokio::test]
    async fn nested_labs_drop_in_either_order() {
        let d = dest().await;
        // Inner before outer.
        let outer = NatLab::spawn(
            "drop_order_outer",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("outer spawns");
        let inner = NatLab::spawn_behind(
            &outer,
            "drop_order_inner",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("inner spawns");
        let client = inner
            .host()
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");
        client
            .send_to(b"x", d.local_addr().expect("dest addr"))
            .await
            .expect("send");
        wait_mappings(&outer, 1).await;
        drop(inner);
        outer.wait_mappings_drained().await;
        assert_eq!(outer.mapping_count(), 0);
        drop(client);
        drop(outer);

        // Outer before inner.
        let outer = NatLab::spawn(
            "drop_order_outer_2",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("outer spawns");
        let inner = NatLab::spawn_behind(
            &outer,
            "drop_order_inner_2",
            spec(
                MappingBehavior::EndpointIndependent,
                FilterClass::EndpointIndependent,
            ),
        )
        .await
        .expect("inner spawns");
        let client = inner
            .host()
            .bind(Family::V4.any_addr())
            .await
            .expect("client binds");
        client
            .send_to(b"x", d.local_addr().expect("dest addr"))
            .await
            .expect("send");
        wait_mappings(&inner, 1).await;
        drop(outer);
        drop(inner);
        drop(client);
    }
}
