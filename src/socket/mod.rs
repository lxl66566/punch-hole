//! The socket seam and the pool that owns every session socket.
// Trait signatures stay async even when an implementation never yields.
#![allow(clippy::unused_async_trait_impl)]

pub(crate) mod rate;
pub(crate) mod sys;

use std::{
    collections::HashSet,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU32, Ordering},
    },
};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    config::PunchConfig,
    error::{Phase, PunchError},
    msg::MAX_DATA_PACKET,
};

/// One UDP socket. Implemented by tokio sockets and by the test simulator.
///
/// Methods take `&self` because a receive task and the sender share one
/// socket, so implementations need internal mutability.
pub trait UdpIo: Send + Sync + Sized + 'static {
    fn send_to(
        &self,
        buf: &[u8],
        target: SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send;
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    /// Prepares the winner for handover to the host; the pool calls this
    /// on the elected socket before returning it. Sockets that carry no
    /// punch-time options need nothing, hence the default.
    fn into_delivered(self) -> io::Result<Self> {
        Ok(self)
    }
}

/// Address family a pool group binds on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// The wildcard bind address the pool uses for this family.
    #[must_use]
    pub fn any_addr(self) -> SocketAddr {
        match self {
            Family::V4 => SocketAddr::from(([0, 0, 0, 0], 0)),
            Family::V6 => SocketAddr::from(([0u16; 8], 0)),
        }
    }

    /// This family's position in the pool's group array.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Family::V4 => 0,
            Family::V6 => 1,
        }
    }
}

/// Creates the sockets a session uses.
pub trait UdpFactory: Send + Sync + 'static {
    type Socket: UdpIo;
    fn bind(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::Socket>> + Send;
}

/// Default factory: plain tokio sockets with the platform options from `sys`.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioFactory;

impl UdpFactory for TokioFactory {
    type Socket = tokio::net::UdpSocket;

    async fn bind(&self, addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
        sys::bind(addr)
    }
}

impl UdpIo for tokio::net::UdpSocket {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        tokio::net::UdpSocket::send_to(self, buf, target).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        tokio::net::UdpSocket::recv_from(self, buf).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        tokio::net::UdpSocket::local_addr(self)
    }

    fn into_delivered(self) -> io::Result<Self> {
        // Windows binds exclusive sockets up front; Unix strips the
        // punch-time reuse options at handover.
        #[cfg(unix)]
        sys::clear_reuse(&self)?;
        Ok(self)
    }
}

/// One validated inbound datagram, tagged with the receiving pool index.
pub(crate) struct RecvEvent {
    pub family: Family,
    pub socket: u16,
    pub from: SocketAddr,
    pub len: usize,
    pub buf: [u8; MAX_DATA_PACKET],
}

/// Reserves one unit from a budget counter, or fails when it is empty.
///
/// The compare-and-swap loop makes the check and the decrement one atomic
/// step. A subtract-then-roll-back sequence reads as a huge wrapped value
/// between the two steps, which lets a concurrent caller overshoot a budget
/// that just ran out.
fn reserve(budget: &AtomicU32) -> bool {
    let mut current = budget.load(Ordering::Relaxed);
    loop {
        if current == 0 {
            return false;
        }
        match budget.compare_exchange_weak(
            current,
            current - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

/// Refresh queries one session may send. The strategy retries a query
/// four times per refresh and starts one refresh per session, so the quota
/// leaves headroom for a lossy path without touching the data-plane
/// budget.
const REFRESH_BUDGET: u32 = 16;

/// Why a destination cannot carry punch traffic.
///
/// Targets derive from peer-signaled data, so the pool rejects the
/// addresses that cannot be a punch peer: unspecified, port zero,
/// multicast, and the IPv4 broadcast. Loopback stays allowed; the smoke
/// tests and the NAT lab exercise the engine over real loopback sockets.
fn unusable_reason(target: SocketAddr) -> Option<&'static str> {
    if target.port() == 0 {
        return Some("port 0");
    }
    match target.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => Some("unspecified address"),
        IpAddr::V4(ip) if ip.is_multicast() => Some("multicast address"),
        IpAddr::V4(ip) if ip.is_broadcast() => Some("broadcast address"),
        IpAddr::V6(ip) if ip.is_unspecified() => Some("unspecified address"),
        IpAddr::V6(ip) if ip.is_multicast() => Some("multicast address"),
        _ => None,
    }
}

/// Owns every socket a session opens. Only the pool closes them.
///
/// Every outbound packet passes the rate limiter, and every data-plane
/// packet passes the session budget on top; the pool also bounds live
/// sockets times distinct destinations, which is the conntrack footprint
/// the session leaves on its NAT. Refresh queries share the rate grid and
/// draw from their own small quota instead of the data-plane budget.
pub(crate) struct SocketPool<S: UdpIo> {
    /// Live sockets per family, indexed by `Family::index`.
    groups: [Vec<Arc<S>>; 2],
    cancel: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    limiter: rate::RateLimiter,
    budget: AtomicU32,
    refresh_budget: AtomicU32,
    dests: RwLock<HashSet<SocketAddr>>,
    max_mappings: usize,
    sent: AtomicU32,
    /// The most recent bind failure, reported when no socket ever bound so
    /// the session names the real cause (for example descriptor exhaustion)
    /// instead of a generic stopped-stream error.
    last_bind_error: Option<io::Error>,
}

impl<S: UdpIo> SocketPool<S> {
    /// Binds `v4` and `v6` sockets and starts one receive task per socket.
    ///
    /// A family that cannot bind proceeds empty, which simply disables the
    /// stages that needed it. The returned receiver yields every inbound
    /// datagram, already tagged with its pool index.
    pub(crate) async fn bind<F: UdpFactory<Socket = S>>(
        factory: &F,
        cfg: &PunchConfig,
        v4: usize,
        v6: usize,
    ) -> Result<(Self, mpsc::Receiver<RecvEvent>), PunchError> {
        // The capacity must absorb one full sweep burst, so it scales with the pool.
        let capacity = usize::from(cfg.max_sockets).clamp(64, 1024);
        let (tx, rx) = mpsc::channel(capacity);
        let mut pool = Self {
            groups: [Vec::new(), Vec::new()],
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
            limiter: rate::RateLimiter::new(cfg.packets_per_sec),
            budget: AtomicU32::new(cfg.packet_budget),
            refresh_budget: AtomicU32::new(REFRESH_BUDGET),
            dests: RwLock::new(HashSet::new()),
            max_mappings: cfg.max_mappings,
            sent: AtomicU32::new(0),
            last_bind_error: None,
        };
        for (family, count) in [(Family::V4, v4), (Family::V6, v6)] {
            for _ in 0..count {
                // A family that cannot bind on this host stays empty.
                match factory.bind(family.any_addr()).await {
                    Ok(sock) => pool.push_socket(sock, family, &tx),
                    Err(e) => pool.last_bind_error = Some(e),
                }
            }
        }
        Ok((pool, rx))
    }

    /// Live sockets across both families.
    pub(crate) fn live_sockets(&self) -> usize {
        self.groups.iter().map(Vec::len).sum()
    }

    /// The most recent bind failure, kept for diagnosis when no socket
    /// ever bound.
    pub(crate) fn last_bind_error(&self) -> Option<&io::Error> {
        self.last_bind_error.as_ref()
    }

    fn push_socket(&mut self, sock: S, family: Family, tx: &mpsc::Sender<RecvEvent>) {
        let idx = self.group(family).len() as u16;
        let sock = Arc::new(sock);
        let recv_sock = Arc::clone(&sock);
        let cancel = self.cancel.clone();
        let tx = tx.clone();
        self.group(family).push(sock);
        self.tasks.push(tokio::spawn(async move {
            loop {
                let mut buf = [0u8; MAX_DATA_PACKET];
                tokio::select! {
                    () = cancel.cancelled() => break,
                    r = recv_sock.recv_from(&mut buf) => match r {
                        Ok((len, from)) => {
                            let event = RecvEvent { family, socket: idx, from, len, buf };
                            // A full or closed channel drops the event: every
                            // event is a handshake packet covered by
                            // retransmission, and blocking here would keep
                            // the task away from the cancel wait point.
                            let _ = tx.try_send(event);
                        }
                        Err(_) => break,
                    }
                }
            }
        }));
    }

    fn group(&mut self, family: Family) -> &mut Vec<Arc<S>> {
        &mut self.groups[family.index()]
    }

    fn group_ref(&self, family: Family) -> &[Arc<S>] {
        &self.groups[family.index()]
    }

    /// Number of sockets actually bound for one family.
    pub(crate) fn bound(&self, family: Family) -> usize {
        self.group_ref(family).len()
    }

    /// One pool socket, for reads such as the local address a refresh
    /// announces. Sends belong to `send` and `send_refresh`.
    pub(crate) fn socket(&self, family: Family, idx: u16) -> Option<Arc<S>> {
        self.group_ref(family).get(idx as usize).cloned()
    }

    /// Sends one packet, honoring the budget, the conntrack bound, and the
    /// global rate cap.
    pub(crate) async fn send(
        &self,
        family: Family,
        idx: u16,
        buf: &[u8],
        target: SocketAddr,
    ) -> Result<(), PunchError> {
        // The one choke point every outbound target crosses, because every
        // target list ultimately comes from peer-signaled data.
        if let Some(reason) = unusable_reason(target) {
            return Err(PunchError::Io {
                phase: Phase::Punch,
                source: io::Error::new(io::ErrorKind::InvalidInput, reason),
            });
        }
        if !self
            .dests
            .read()
            .expect("dest set read lock")
            .contains(&target)
        {
            let mut dests = self.dests.write().expect("dest set write lock");
            // Re-check: a racing sender may have inserted this destination.
            if !dests.contains(&target) {
                // A new destination costs one mapping per live socket, so
                // the bound scales the destination count with the pool. A
                // pool with no live socket carries no mapping at all, so it
                // admits no destination and the table stays bounded.
                let sockets =
                    self.groups[Family::V4.index()].len() + self.groups[Family::V6.index()].len();
                if sockets == 0 || sockets * (dests.len() + 1) > self.max_mappings {
                    return Err(PunchError::ConntrackExhausted);
                }
                // The destination joins the table before the limiter wait
                // below, so a send that fails or never drains has still
                // spent its conntrack slot: the footprint is counted, never
                // undercounted, which is the intended conservative bias.
                dests.insert(target);
            }
        }
        if !reserve(&self.budget) {
            return Err(PunchError::BudgetExhausted);
        }
        self.limiter.acquire().await;
        let sent = match self.group_ref(family).get(idx as usize) {
            Some(sock) => sock.send_to(buf, target).await,
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pool index out of range",
            )),
        };
        if let Err(err) = sent {
            // No packet left the host, so the reserved budget unit goes back.
            self.budget.fetch_add(1, Ordering::Relaxed);
            // The rate slot stays spent: a token cannot return to the limiter.
            return Err(PunchError::Io {
                phase: Phase::Punch,
                source: err,
            });
        }
        self.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Sends one STUN refresh query from a V4 pool socket.
    ///
    /// Refresh is control-plane traffic to a host-configured server, so it
    /// draws from a small dedicated quota instead of the data-plane budget
    /// and never enters the conntrack table: the answer is matched to the
    /// querying socket, not to a tracked destination. The shared rate grid
    /// still paces it, and it counts in `sent` like every outbound packet.
    pub(crate) async fn send_refresh(
        &self,
        idx: u16,
        buf: &[u8],
        server: SocketAddr,
    ) -> Result<(), PunchError> {
        if !reserve(&self.refresh_budget) {
            return Err(PunchError::BudgetExhausted);
        }
        self.limiter.acquire().await;
        let sent = match self.group_ref(Family::V4).get(idx as usize) {
            Some(sock) => sock.send_to(buf, server).await,
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pool index out of range",
            )),
        };
        match sent {
            Ok(_) => {
                self.sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            },
            Err(err) => {
                // No packet left the host, so the reserved quota unit goes
                // back.
                self.refresh_budget.fetch_add(1, Ordering::Relaxed);
                Err(PunchError::Io {
                    phase: Phase::Punch,
                    source: err,
                })
            },
        }
    }

    /// Packets the pool actually sent.
    pub(crate) fn sent(&self) -> u32 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Elects the winner: stops every task, closes the losers, strips the
    /// punch-time socket options, and hands out the winner as an owned
    /// socket. Both failure paths return only after the tasks are joined
    /// and the pool's sockets are dropped, so nothing outlives the session.
    pub(crate) async fn elect(mut self, family: Family, winner: u16) -> Result<S, PunchError> {
        self.cancel.cancel();
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        let group = self.group(family);
        if group.get(winner as usize).is_none() {
            return Err(PunchError::Io {
                phase: Phase::Punch,
                source: io::Error::new(io::ErrorKind::InvalidInput, "winner index out of range"),
            });
        }
        let sock = group.swap_remove(winner as usize);
        self.groups = [Vec::new(), Vec::new()];
        let sock = Arc::try_unwrap(sock).map_err(|_| PunchError::Io {
            phase: Phase::Punch,
            source: io::Error::other("winner socket still shared after election"),
        })?;
        sock.into_delivered().map_err(|source| PunchError::Io {
            phase: Phase::Punch,
            source,
        })
    }

    /// Stops every task and closes every socket on a failed session.
    pub(crate) async fn shutdown(mut self) {
        self.cancel.cancel();
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        self.groups = [Vec::new(), Vec::new()];
    }
}

impl<S: UdpIo> Drop for SocketPool<S> {
    /// Best-effort sync cleanup. Tasks observe the token and release their
    /// socket references on their next poll.
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests;
