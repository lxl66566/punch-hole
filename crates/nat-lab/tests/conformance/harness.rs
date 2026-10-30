//! The conformance suite's engine pair: one handle per engine that exposes
//! client sockets, public-side sockets, and the observation points the
//! behavior tests share.

#![allow(clippy::unused_async_trait_impl)]

use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::Range,
    sync::OnceLock,
    time::Duration,
};

use nat_lab::{
    Family, Host, LabSocket, NatLab, NatSpec, Net, SimSocket, StunServer, UdpFactory, UdpIo,
    stun_responder,
};
use tokio::net::UdpSocket;

/// One engine under test.
///
/// Both engines implement the same `NatSpec` behavior, so a behavior test
/// reads once against this surface and runs on both. The socket types stay
/// per-engine: the simulator hands out virtual sockets, the lab real ones.
pub trait Engine {
    /// Sockets bound behind the NAT.
    type Client: UdpIo;
    /// Sockets bound on the public side.
    type Public: UdpIo;

    /// Binds one client socket behind the NAT.
    async fn client(&self) -> io::Result<Self::Client>;

    /// Binds one public-side socket on the IP all destinations share.
    async fn public_socket(&self) -> io::Result<Self::Public>;

    /// Binds one public-side socket on an IP no destination uses.
    async fn foreign_socket(&self) -> io::Result<Self::Public>;

    /// Spawns a second engine whose NAT rides this engine's NAT upstream,
    /// building the NAT-behind-NAT chain. The returned engine shares the
    /// public side: its sockets, counters, and STUN responders all sit on
    /// the true public network.
    async fn spawn_nested(&self, seed: &'static str, spec: NatSpec) -> Self;

    /// The addresses of the engine's STUN responders.
    async fn stun_addrs(&self) -> Vec<SocketAddr>;

    /// The addresses of the engine's discovery alternates: the responder's
    /// other IP, where RFC 5780 OTHER-ADDRESS points.
    async fn stun_other_addrs(&self) -> Vec<SocketAddr>;

    /// Live mappings right now.
    fn mapping_count(&self) -> usize;

    /// Peak concurrent mappings since the engine started.
    fn peak_mappings(&self) -> usize;

    /// Every live mapping as (private, external) pairs.
    fn snapshot(&self) -> Vec<(SocketAddr, SocketAddr)>;

    /// The rejected-datagram counter, when the engine exposes one.
    fn filter_drops(&self) -> Option<u32>;

    /// The disabled-hairpin-drop counter, when the engine exposes one.
    fn hairpin_drops(&self) -> Option<u32>;

    /// Waits until the engine holds at least `want` mappings, bounded.
    async fn wait_mappings(&self, want: usize);

    /// Waits until at least `want` datagrams were rejected, bounded.
    async fn wait_filter_drops(&self, want: u32);

    /// Waits until at least `want` datagrams were dropped as disabled
    /// loops, bounded.
    async fn wait_hairpin_drops(&self, want: u32);

    /// Waits until every mapping is gone, bounded.
    async fn wait_drained(&self);

    /// The port range the NAT allocates external ports from.
    fn port_window(&self) -> Range<u16>;

    /// Sets how long mappings survive the close of their socket.
    fn set_expiry(&self, expiry: Duration);
}

/// Receives one datagram within two seconds, or panics.
///
/// The budget only bites on failure paths: a healthy engine answers in
/// microseconds, and paused time makes the simulator's budget free.
pub async fn recv_from<S: UdpIo>(sock: &S) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0u8; 2048];
    let (len, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .expect("datagram arrives within 2s")
        .expect("socket stays alive");
    (buf[..len].to_vec(), from)
}

/// Asserts that no datagram reaches `sock` within `budget`.
pub async fn assert_silent<S: UdpIo>(sock: &S, budget: Duration) {
    let mut buf = [0u8; 2048];
    assert!(
        tokio::time::timeout(budget, sock.recv_from(&mut buf))
            .await
            .is_err(),
        "a datagram arrived within {budget:?}"
    );
}

/// Waits until `done` holds, bounded by `budget`.
async fn wait_until(budget: Duration, done: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + budget;
    while !done() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Parses the engines' `ip:port` strings into socket addresses.
fn parse_addrs(addrs: &[String]) -> Vec<SocketAddr> {
    addrs
        .iter()
        .map(|addr| addr.parse().expect("engine address parses"))
        .collect()
}

/// A plain OS socket on the public side, so the lab's destinations and
/// strangers speak the same `UdpIo` surface as the simulator's.
pub struct Plain(pub UdpSocket);

impl UdpIo for Plain {
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

/// Binds one plain OS socket on `ip`.
async fn plain_at(ip: Ipv4Addr) -> io::Result<Plain> {
    Ok(Plain(UdpSocket::bind(SocketAddrV4::new(ip, 0)).await?))
}

/// Binds a plain OS socket on `addr`, which a released mapping must have
/// vacated. The bind retries until the previous owner's task dropped its
/// socket, bounded by two seconds.
pub async fn claim_released(addr: SocketAddrV4) -> Plain {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match UdpSocket::bind(addr).await {
            Ok(sock) => return Plain(sock),
            Err(err) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the released address never freed: {err}"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            },
        }
    }
}

/// The simulator engine: one seeded virtual network holding one NAT host
/// and one public host.
pub struct SimEng {
    net: Net,
    nat_host: Host,
    public_host: Host,
    spec: NatSpec,
    /// The one STUN server, created on first use so every accessor reads
    /// the same grid.
    stun: OnceLock<nat_lab::sim::StunServer>,
}

impl SimEng {
    /// Builds the engine behind one fresh NAT of `spec`. The seed names the
    /// test, so a failure reproduces from it.
    pub fn new(seed: &'static str, spec: NatSpec) -> Self {
        let net = Net::seeded(seed);
        let nat_host = net.host(spec.clone());
        let public_host = net.public_host();
        Self {
            net,
            nat_host,
            public_host,
            spec,
            stun: OnceLock::new(),
        }
    }

    /// The engine's STUN server, created on first use.
    fn stun(&self) -> &nat_lab::sim::StunServer {
        self.stun.get_or_init(|| self.net.stun_server())
    }
}

impl Engine for SimEng {
    type Client = SimSocket;
    type Public = SimSocket;

    async fn client(&self) -> io::Result<SimSocket> {
        self.nat_host.bind(Family::V4.any_addr()).await
    }

    async fn public_socket(&self) -> io::Result<SimSocket> {
        self.public_host.bind(Family::V4.any_addr()).await
    }

    async fn foreign_socket(&self) -> io::Result<SimSocket> {
        // A fresh public host draws a fresh IP.
        self.net.public_host().bind(Family::V4.any_addr()).await
    }

    async fn spawn_nested(&self, _seed: &'static str, spec: NatSpec) -> Self {
        // The seed only names the lab's generator; the simulator shares
        // this network's already-seeded one.
        SimEng {
            net: self.net.clone(),
            nat_host: self.net.host_behind(&self.nat_host, spec.clone()),
            public_host: self.public_host.clone(),
            spec,
            stun: OnceLock::new(),
        }
    }

    async fn stun_addrs(&self) -> Vec<SocketAddr> {
        parse_addrs(&self.stun().addrs)
    }

    async fn stun_other_addrs(&self) -> Vec<SocketAddr> {
        parse_addrs(&self.stun().other_addrs)
    }

    fn mapping_count(&self) -> usize {
        self.net.mapping_count()
    }

    fn peak_mappings(&self) -> usize {
        self.net.peak_mappings()
    }

    fn snapshot(&self) -> Vec<(SocketAddr, SocketAddr)> {
        self.net.mappings_snapshot()
    }

    fn filter_drops(&self) -> Option<u32> {
        Some(self.net.dropped_by_filter())
    }

    fn hairpin_drops(&self) -> Option<u32> {
        Some(self.net.dropped_by_hairpin())
    }

    async fn wait_mappings(&self, want: usize) {
        wait_until(Duration::from_secs(2), || self.mapping_count() >= want).await;
    }

    async fn wait_filter_drops(&self, want: u32) {
        wait_until(Duration::from_secs(2), || {
            self.filter_drops().unwrap_or(0) >= want
        })
        .await;
    }

    async fn wait_hairpin_drops(&self, want: u32) {
        wait_until(Duration::from_secs(2), || {
            self.hairpin_drops().unwrap_or(0) >= want
        })
        .await;
    }

    async fn wait_drained(&self) {
        self.net.wait_mappings_drained().await;
    }

    fn port_window(&self) -> Range<u16> {
        self.spec.port_range.clone()
    }

    fn set_expiry(&self, expiry: Duration) {
        self.net.set_mapping_expiry(expiry);
    }
}

/// The lab engine: one userspace NAT forwarder over real loopback sockets.
pub struct LabEng {
    lab: NatLab,
    /// The responder lives here, so its drop cannot stop the loops while a
    /// test still queries the addresses.
    stun: OnceLock<StunServer>,
}

impl LabEng {
    /// Spawns the engine behind one fresh NAT of `spec`.
    pub async fn new(seed: &'static str, spec: NatSpec) -> Self {
        Self {
            lab: NatLab::spawn(seed, spec).await.expect("lab spawns"),
            stun: OnceLock::new(),
        }
    }

    /// The public address every mapping of this lab sends from.
    pub fn public_ip(&self) -> Ipv4Addr {
        self.lab.public_ip()
    }

    /// The engine's STUN responder, spawned on first use.
    fn responder(&self) -> &StunServer {
        self.stun
            .get_or_init(|| stun_responder().expect("stun responder binds"))
    }

    /// Binds one client socket at an explicit local port, so a mapping can
    /// be observed past the close of its original socket.
    pub async fn client_at(&self, port: u16) -> LabSocket {
        self.lab
            .host()
            .bind(SocketAddr::from(([0, 0, 0, 0], port)))
            .await
            .expect("client socket rebinds")
    }
}

impl Engine for LabEng {
    type Client = LabSocket;
    type Public = Plain;

    async fn client(&self) -> io::Result<LabSocket> {
        self.lab.host().bind(Family::V4.any_addr()).await
    }

    async fn public_socket(&self) -> io::Result<Plain> {
        plain_at(Ipv4Addr::LOCALHOST).await
    }

    async fn foreign_socket(&self) -> io::Result<Plain> {
        // 127.0.0.2 sits in the loopback space no lab or responder draws.
        plain_at(Ipv4Addr::new(127, 0, 0, 2)).await
    }

    async fn spawn_nested(&self, seed: &'static str, spec: NatSpec) -> Self {
        Self {
            lab: NatLab::spawn_behind(&self.lab, seed, spec)
                .await
                .expect("nested lab spawns"),
            stun: OnceLock::new(),
        }
    }

    async fn stun_addrs(&self) -> Vec<SocketAddr> {
        parse_addrs(&self.responder().addrs)
    }

    async fn stun_other_addrs(&self) -> Vec<SocketAddr> {
        parse_addrs(&self.responder().other_addrs)
    }

    fn mapping_count(&self) -> usize {
        self.lab.mapping_count()
    }

    fn peak_mappings(&self) -> usize {
        self.lab.peak_mappings()
    }

    fn snapshot(&self) -> Vec<(SocketAddr, SocketAddr)> {
        self.lab.mappings_snapshot()
    }

    fn filter_drops(&self) -> Option<u32> {
        Some(self.lab.dropped_by_filter())
    }

    fn hairpin_drops(&self) -> Option<u32> {
        Some(self.lab.dropped_by_hairpin())
    }

    async fn wait_mappings(&self, want: usize) {
        wait_until(Duration::from_secs(2), || self.mapping_count() >= want).await;
    }

    async fn wait_filter_drops(&self, want: u32) {
        wait_until(Duration::from_secs(2), || {
            self.filter_drops().unwrap_or(0) >= want
        })
        .await;
    }

    async fn wait_hairpin_drops(&self, want: u32) {
        wait_until(Duration::from_secs(2), || {
            self.hairpin_drops().unwrap_or(0) >= want
        })
        .await;
    }

    async fn wait_drained(&self) {
        self.lab.wait_mappings_drained().await;
    }

    fn port_window(&self) -> Range<u16> {
        self.lab.port_window()
    }

    fn set_expiry(&self, expiry: Duration) {
        self.lab.set_mapping_expiry(expiry);
    }
}
