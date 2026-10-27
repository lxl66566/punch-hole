//! Loopback NAT lab: one emulated NAT device over real OS sockets.
//!
//! Feature `test-util`. A `NatLab` is a userspace NAT forwarder that lives
//! on the 127.0.0.0/8 loopback space. Client sockets are real OS sockets;
//! every outbound datagram crosses a gateway task that applies the mapping
//! and filtering policy of a [`NatSpec`] and leaves through a per-mapping
//! public socket bound on the lab's dedicated loopback address. The
//! production path runs unmodified: real STUN probes, classification,
//! strategy, and punch all observe a translated address, which the pure
//! simulator covers only without the OS and the plain loopback smoke tests
//! cover only without a NAT.

use std::{
    collections::{HashMap, HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::Range,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use rand::{prelude::*, rngs::StdRng};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::{
    msg::MAX_DATA_PACKET,
    nat::FilterClass,
    sim::{Mapping, NatSpec},
    socket::{UdpFactory, UdpIo},
};

/// Lab addresses drawn in this process: 127.hi.lo.1.
static LAB_IPS: StdMutex<Vec<Ipv4Addr>> = StdMutex::new(Vec::new());
/// Responder addresses drawn in this process: 127.50.hi.lo.
static STUN_IPS: StdMutex<Vec<Ipv4Addr>> = StdMutex::new(Vec::new());

/// Draws one fresh address for this process from `taken`.
///
/// A process-global counter cannot keep test runners apart: cargo-nextest
/// runs every test in its own process, and all counters would start at the
/// same address. The draw reads OS entropy instead. A twin process that
/// holds the drawn address surfaces as a bind failure, which the callers
/// retry with a fresh draw.
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

/// One lab address. Octet one skips the responder space, and zero would
/// redraw the busy 127.0.0.1.
fn draw_lab_ip() -> io::Result<Ipv4Addr> {
    draw_ip(&LAB_IPS, |n| {
        (n != 0 && (n >> 8) != 50).then(|| Ipv4Addr::new(127, (n >> 8) as u8, (n & 0xff) as u8, 1))
    })
}

/// One responder address from the space no lab draws.
fn draw_stun_ip() -> io::Result<Ipv4Addr> {
    draw_ip(&STUN_IPS, |n| {
        Some(Ipv4Addr::new(127, 50, (n >> 8) as u8, (n & 0xff) as u8))
    })
}

/// Frame tag of a client datagram on its way out.
const TAG_OUT: u8 = 1;
/// Frame tag of a translated datagram on its way back to a client.
const TAG_IN: u8 = 2;
/// Frame tag of a client socket close notice.
const TAG_BYE: u8 = 3;
/// Frame bytes before the payload: one tag, four address, two port.
const FRAME_HEADER: usize = 7;

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
    /// Receives client frames; mapping tasks share it to deliver In frames.
    gateway: Arc<UdpSocket>,
    table: StdMutex<MappingTable>,
    rng: StdMutex<StdRng>,
    forwarded: AtomicU32,
    dropped_by_filter: AtomicU32,
    /// Delay between a socket close and its mappings going away.
    mapping_expiry: StdMutex<Duration>,
}

/// The mapping set of one lab, always behind one lock.
struct MappingTable {
    /// Cone mappings, keyed by client address.
    cone: HashMap<SocketAddr, Arc<LabMapping>>,
    /// Symmetric mappings, keyed by client and destination.
    sym: HashMap<(SocketAddr, SocketAddr), Arc<LabMapping>>,
    /// Allocation counter the sequential policies walk.
    next_alloc: u64,
    peak: usize,
}

impl MappingTable {
    /// Ports the live mappings hold.
    fn used_ports(&self) -> Vec<u16> {
        self.cone
            .values()
            .chain(self.sym.values())
            .map(|m| m.ext_port)
            .collect()
    }

    /// Records the concurrent mapping peak after one insert.
    fn note_count(&mut self) {
        let live = self.cone.len() + self.sym.len();
        self.peak = self.peak.max(live);
    }
}

/// One live NAT mapping: its public socket and bookkeeping.
struct LabMapping {
    client: SocketAddr,
    /// Kept beside the socket so snapshots need no syscall.
    ext_port: u16,
    ext: Arc<UdpSocket>,
    /// Destinations this mapping sent to, which inbound filtering checks.
    dests: Arc<StdMutex<HashSet<SocketAddr>>>,
    /// Fires when the mapping goes away; the task then drops the socket.
    cancel: CancellationToken,
}

impl NatLab {
    /// Creates one NAT device with policy `spec` and randomness from `seed`.
    ///
    /// The gateway binds and the port window settles before the call
    /// returns, so a failed spawn leaves nothing behind.
    pub async fn spawn(seed: &str, spec: NatSpec) -> io::Result<Self> {
        let (public_ip, window) = settle_address(&spec)?;
        let gateway = Arc::new(UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?);
        let inner = Arc::new(LabInner {
            spec,
            public_ip,
            window,
            table: StdMutex::new(MappingTable {
                cone: HashMap::new(),
                sym: HashMap::new(),
                next_alloc: 0,
                peak: 0,
            }),
            rng: StdMutex::new(seeded_rng(seed)),
            gateway,
            forwarded: AtomicU32::new(0),
            dropped_by_filter: AtomicU32::new(0),
            mapping_expiry: StdMutex::new(Duration::ZERO),
        });
        tokio::spawn(gateway_loop(Arc::clone(&inner)));
        Ok(Self { inner })
    }

    /// A cloneable factory that binds client sockets behind this NAT.
    #[must_use]
    pub fn host(&self) -> LabHost {
        LabHost {
            inner: Arc::clone(&self.inner),
        }
    }

    /// The public address every mapping of this lab sends from.
    #[must_use]
    pub fn public_ip(&self) -> Ipv4Addr {
        self.inner.public_ip
    }

    /// The port window the lab allocates from.
    ///
    /// Discovery moves the window past ports the OS excludes, so tests
    /// read port positions relative to this range.
    #[must_use]
    pub fn port_window(&self) -> Range<u16> {
        self.inner.window.clone()
    }

    /// Sets how long mappings survive the close of their socket.
    ///
    /// The default of zero releases mappings at close. A nonzero delay
    /// models the tens of seconds a real NAT keeps translating after the
    /// loser socket of a punch went away.
    pub fn set_mapping_expiry(&self, expiry: Duration) {
        *self.inner.mapping_expiry.lock().expect("expiry lock") = expiry;
    }

    /// Live mappings.
    #[must_use]
    pub fn mapping_count(&self) -> usize {
        let table = self.inner.table.lock().expect("mapping table lock");
        table.cone.len() + table.sym.len()
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

    /// Waits until every mapping is gone, bounded by five real seconds.
    pub async fn wait_mappings_drained(&self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while self.mapping_count() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Draws one lab address together with its bindable port window.
///
/// A twin process that squats the drawn address leaves no bindable port,
/// so discovery repeats over fresh addresses.
fn settle_address(spec: &NatSpec) -> io::Result<(Ipv4Addr, Range<u16>)> {
    let mut last = None;
    for _ in 0..8 {
        let ip = draw_lab_ip()?;
        match discover_window(ip, &spec.port_range) {
            Ok(window) => return Ok((ip, window)),
            Err(e) => last = Some(e),
        }
    }
    Err(last.expect("eight draws all failed"))
}

/// Collects (private, external) pairs of every live mapping.
fn snapshot(table: &MappingTable, public_ip: Ipv4Addr) -> Vec<(SocketAddr, SocketAddr)> {
    table
        .cone
        .values()
        .chain(table.sym.values())
        .map(|m| {
            (
                m.client,
                SocketAddr::V4(SocketAddrV4::new(public_ip, m.ext_port)),
            )
        })
        .collect()
}

/// The lab's forwarding core: one sequential receive loop.
///
/// Allocation order follows arrival order, and loopback preserves send
/// order per sender, so a probing socket reads the same allocation
/// sequence it would read behind a real NAT.
async fn gateway_loop(inner: Arc<LabInner>) {
    let mut buf = [0u8; FRAME_HEADER + MAX_DATA_PACKET];
    loop {
        let (len, from) = match inner.gateway.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) if is_link_reset(&e) => continue,
            Err(_) => break,
        };
        let Some((tag, addr, payload)) = parse_frame(&buf[..len]) else {
            continue;
        };
        match tag {
            TAG_OUT => {
                let Some(dst) = addr else { continue };
                // A bind failure means the window ran dry; the datagram is
                // lost, as a full NAT would lose it.
                let _ = outbound(&inner, from, dst, payload).await;
            },
            TAG_BYE => client_closed(&inner, from),
            // In frames travel to client sockets only.
            _ => {},
        }
    }
}

/// Translates one client datagram through its mapping and sends it out.
async fn outbound(
    inner: &Arc<LabInner>,
    client: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    let mapping = translate_outbound(inner, client, dst)?;
    mapping.ext.send_to(payload, dst).await?;
    inner.forwarded.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Finds or creates the mapping one outbound datagram uses.
///
/// The policy fixes the key: cone mappings follow the client, symmetric
/// mappings follow the destination, and an address-dependent NAT keys on
/// the destination address alone.
fn translate_outbound(
    inner: &Arc<LabInner>,
    client: SocketAddr,
    dst: SocketAddr,
) -> io::Result<Arc<LabMapping>> {
    let mut table = inner.table.lock().expect("mapping table lock");
    if matches!(inner.spec.mapping, Mapping::Cone) {
        if let Some(mapping) = table.cone.get(&client) {
            add_dest(mapping, dst);
            return Ok(Arc::clone(mapping));
        }
        let mapping = allocate_mapping(inner, &mut table, client)?;
        add_dest(&mapping, dst);
        table.cone.insert(client, Arc::clone(&mapping));
        table.note_count();
        Ok(mapping)
    } else {
        let key = match inner.spec.mapping {
            Mapping::AddressSequential { .. } => (client, SocketAddr::new(dst.ip(), 0)),
            _ => (client, dst),
        };
        if let Some(mapping) = table.sym.get(&key) {
            add_dest(mapping, dst);
            return Ok(Arc::clone(mapping));
        }
        let mapping = allocate_mapping(inner, &mut table, client)?;
        add_dest(&mapping, dst);
        table.sym.insert(key, Arc::clone(&mapping));
        table.note_count();
        Ok(mapping)
    }
}

/// Records one destination on its mapping for the inbound filter.
fn add_dest(mapping: &LabMapping, dst: SocketAddr) {
    mapping.dests.lock().expect("dests lock").insert(dst);
}

/// Binds the public socket of one fresh mapping under the port policy.
fn allocate_mapping(
    inner: &Arc<LabInner>,
    table: &mut MappingTable,
    client: SocketAddr,
) -> io::Result<Arc<LabMapping>> {
    let start = inner.window.start;
    let end = inner.window.end;
    let len = u64::from(end - start);
    // Candidates are tried until one binds, which covers a port stolen
    // after the window discovery.
    let mut budget = len as usize + 8;
    let ext = loop {
        if budget == 0 {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "no port of the window binds",
            ));
        }
        budget -= 1;
        let port = match inner.spec.mapping {
            Mapping::Cone
            | Mapping::Sequential { step: 1 }
            | Mapping::AddressSequential { step: 1 } => {
                let n = table.next_alloc;
                table.next_alloc += 1;
                start + (n % len) as u16
            },
            Mapping::Sequential { step } | Mapping::AddressSequential { step } => {
                let n = table.next_alloc as i64;
                table.next_alloc += 1;
                let offset = (n * i64::from(step)).rem_euclid(len as i64) as u16;
                start + offset
            },
            // A live mapping holds its port alone, so the draw comes from
            // the ports no live mapping holds, like the simulator's.
            Mapping::Random => {
                let used = table.used_ports();
                let mut rng = inner.rng.lock().expect("rng lock");
                if used.len() >= len as usize {
                    rng.random_range(start..end)
                } else {
                    let free: Vec<u16> = (start..end).filter(|p| !used.contains(p)).collect();
                    free[rng.random_range(0..free.len())]
                }
            },
        };
        if let Ok(sock) = bind_public(inner.public_ip, port) {
            break Arc::new(sock);
        }
    };
    let ext_port = ext
        .local_addr()
        .expect("bound socket reports its address")
        .port();
    let mapping = Arc::new(LabMapping {
        client,
        ext_port,
        ext,
        dests: Arc::new(StdMutex::new(HashSet::new())),
        cancel: CancellationToken::new(),
    });
    tokio::spawn(mapping_loop(Arc::clone(inner), Arc::clone(&mapping)));
    Ok(mapping)
}

/// Serves the public socket of one mapping.
///
/// Inbound datagrams pass the filter check and reach the client as In
/// frames through the gateway socket; filter failures count as drops.
async fn mapping_loop(inner: Arc<LabInner>, mapping: Arc<LabMapping>) {
    let mut buf = [0u8; MAX_DATA_PACKET];
    let mut wire = [0u8; FRAME_HEADER + MAX_DATA_PACKET];
    loop {
        let recv = mapping.ext.recv_from(&mut buf);
        tokio::select! {
            () = mapping.cancel.cancelled() => break,
            result = recv => match result {
                Ok((len, src)) => {
                    if !allows(inner.spec.filtering, &mapping.dests, src) {
                        inner.dropped_by_filter.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    // A v4 socket hears from v4 peers only.
                    let SocketAddr::V4(src_v4) = src else {
                        continue;
                    };
                    write_header(&mut wire, TAG_IN, src_v4);
                    wire[FRAME_HEADER..FRAME_HEADER + len].copy_from_slice(&buf[..len]);
                    // A failed delivery only loses this datagram, like a
                    // NAT whose client went away.
                    if inner
                        .gateway
                        .send_to(&wire[..FRAME_HEADER + len], mapping.client)
                        .await
                        .is_ok()
                    {
                        inner.forwarded.fetch_add(1, Ordering::Relaxed);
                    }
                },
                Err(e) if is_link_reset(&e) => {},
                Err(_) => break,
            },
        }
    }
}

/// One inbound filter decision, with the simulator's semantics.
fn allows(filtering: FilterClass, dests: &StdMutex<HashSet<SocketAddr>>, src: SocketAddr) -> bool {
    let dests = dests.lock().expect("dests lock");
    match filtering {
        FilterClass::EndpointIndependent | FilterClass::Unknown => true,
        FilterClass::AddressDependent => dests.iter().any(|d| d.ip() == src.ip()),
        FilterClass::AddressPortDependent => dests.contains(&src),
    }
}

/// Releases a closed client's mappings, honoring the expiry setting.
fn client_closed(inner: &Arc<LabInner>, client: SocketAddr) {
    let expiry = *inner.mapping_expiry.lock().expect("expiry lock");
    if expiry.is_zero() {
        forget_client(inner, client);
    } else {
        // The mappings keep translating for the expiry window, like a
        // router honoring its timer after the socket closed.
        let inner = Arc::clone(inner);
        tokio::spawn(async move {
            tokio::time::sleep(expiry).await;
            forget_client(&inner, client);
        });
    }
}

/// Removes every mapping of one client and closes its public sockets.
fn forget_client(inner: &LabInner, client: SocketAddr) {
    let mut table = inner.table.lock().expect("mapping table lock");
    let mut removed: Vec<Arc<LabMapping>> = Vec::new();
    if let Some(mapping) = table.cone.remove(&client) {
        removed.push(mapping);
    }
    table.sym.retain(|_, mapping| {
        if mapping.client == client {
            removed.push(Arc::clone(mapping));
            false
        } else {
            true
        }
    });
    // Each receive task owns one socket reference; the token releases it.
    for mapping in removed {
        mapping.cancel.cancel();
    }
}

/// Factory that binds client sockets behind one lab NAT.
#[derive(Clone)]
pub struct LabHost {
    inner: Arc<LabInner>,
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
        let gateway = self.inner.gateway.local_addr()?;
        Ok(LabSocket { sock, gateway })
    }
}

/// One client socket behind a lab NAT: a real loopback socket that frames
/// its datagrams for the gateway.
pub struct LabSocket {
    sock: UdpSocket,
    gateway: SocketAddr,
}

impl UdpIo for LabSocket {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        // The gateway's receive buffer fits one framed data packet, so a
        // longer payload has no path through the lab.
        if buf.len() > MAX_DATA_PACKET {
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
        let mut wire = [0u8; FRAME_HEADER + MAX_DATA_PACKET];
        write_header(&mut wire, TAG_OUT, SocketAddrV4::new(ip, target.port()));
        wire[FRAME_HEADER..FRAME_HEADER + buf.len()].copy_from_slice(buf);
        self.sock
            .send_to(&wire[..FRAME_HEADER + buf.len()], self.gateway)
            .await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut wire = [0u8; FRAME_HEADER + MAX_DATA_PACKET];
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
        // mapping alive until the lab goes away.
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

/// Finds the mapping port window on one public address.
///
/// Explicit binds fail on ports the OS excludes, Windows reserves chunks
/// machine-wide, and on ports another process holds. The scan takes the
/// first run of bindable ports at or after the requested start that fits
/// the whole window, so the window keeps its width and only its position
/// moves. When no full-width run exists the longest run wins, which
/// narrows the window instead of failing the spawn.
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
fn scan_window(first: u16, width: u32, bindable: impl Fn(u16) -> bool) -> io::Result<Range<u16>> {
    // Longest bindable run so far, as (start, length).
    let mut best = (first, 0u32);
    let mut run_start = first;
    let mut run_len = 0u32;
    for port in first..=u16::MAX {
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
}

/// Starts a STUN responder on a dedicated loopback address.
///
/// Four sockets on ports 3478 through 3481 answer binding requests with
/// the v4 XOR-MAPPED address of the datagram's source. Four destinations
/// is what classification needs for a confident EasySym fit.
pub fn stun_responder() -> io::Result<StunServer> {
    // Every port must bind; a twin process that holds one of them draws a
    // fresh address.
    for _ in 0..16 {
        let ip = draw_stun_ip()?;
        let mut sockets = Vec::with_capacity(4);
        let bound =
            (3478..=3481).all(|port| bind_public(ip, port).map(|s| sockets.push(s)).is_ok());
        if bound {
            for sock in sockets {
                tokio::spawn(stun_loop(sock));
            }
            let addrs = (3478..=3481).map(|port| format!("{ip}:{port}")).collect();
            return Ok(StunServer { addrs });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no responder address binds",
    ))
}

/// Answers binding requests on one STUN socket.
async fn stun_loop(sock: UdpSocket) {
    let mut buf = [0u8; 128];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, from)) => {
                if let Some(reply) = binding_reply(&buf[..len], from) {
                    let _ = sock.send_to(&reply, from).await;
                }
            },
            Err(e) if is_link_reset(&e) => {},
            Err(_) => break,
        }
    }
}

/// Minimal binding response, v4 XOR-MAPPED only.
fn binding_reply(request: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    const COOKIE: [u8; 4] = 0x2112_a442u32.to_be_bytes();
    if request.len() < 20
        || u16::from_be_bytes([request[0], request[1]]) != 0x0001
        || request[4..8] != COOKIE
    {
        return None;
    }
    let IpAddr::V4(ip) = from.ip() else {
        return None;
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
    out.extend_from_slice(&(from.port() ^ 0x2112).to_be_bytes());
    out.extend_from_slice(&xip);
    Some(out)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::socket::Family;

    /// A narrow-range spec, so window discovery stays instant.
    fn spec(mapping: Mapping, filtering: FilterClass) -> NatSpec {
        NatSpec {
            mapping,
            filtering,
            port_range: 30_000..30_040,
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
    fn window_scan_clamps_a_run_touching_the_last_port() {
        // The longest run ends at 65535, which no u16 range end can
        // express, so the window ends at 65534.
        let window = scan_window(1, 10, |port| port >= 65_530).expect("a run exists");
        assert_eq!(window, 65_530..u16::MAX);
        assert!(scan_window(1, 2, |_| false).is_err());
    }

    #[tokio::test]
    async fn cone_mapping_reuses_one_port_across_destinations() {
        let lab = NatLab::spawn(
            "cone_reuse",
            spec(Mapping::Cone, FilterClass::EndpointIndependent),
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
            spec(
                Mapping::Sequential { step: 2 },
                FilterClass::AddressDependent,
            ),
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
            spec(Mapping::Cone, FilterClass::AddressPortDependent),
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
            spec(Mapping::Cone, FilterClass::EndpointIndependent),
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
}
