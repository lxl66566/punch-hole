//! The socket seam and the pool that owns every session socket.
// Trait signatures stay async even when an implementation never yields.
#![allow(clippy::unused_async_trait_impl)]

pub(crate) mod rate;
pub(crate) mod sys;

use std::{
    collections::HashSet,
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{config::PunchConfig, error::PunchError, msg::MAX_DATA_PACKET};

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
}

/// One validated inbound datagram, tagged with the receiving pool index.
pub(crate) struct RecvEvent {
    pub family: Family,
    pub socket: u16,
    pub from: SocketAddr,
    pub len: usize,
    pub buf: [u8; MAX_DATA_PACKET],
}

/// Owns every socket a session opens. Only the pool closes them.
///
/// Every outbound packet passes the rate limiter and the session budget, and
/// the pool tracks distinct destinations to bound the conntrack footprint.
pub(crate) struct SocketPool<S: UdpIo> {
    groups: [Vec<Arc<S>>; 2],
    cancel: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    limiter: rate::RateLimiter,
    budget: AtomicU32,
    dests: Mutex<HashSet<SocketAddr>>,
    max_dests: usize,
    sent: AtomicU32,
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
        let (tx, rx) = mpsc::channel(64);
        let mut pool = Self {
            groups: [Vec::new(), Vec::new()],
            cancel: CancellationToken::new(),
            tasks: Vec::new(),
            limiter: rate::RateLimiter::new(cfg.packets_per_sec),
            budget: AtomicU32::new(cfg.packet_budget),
            dests: Mutex::new(HashSet::new()),
            max_dests: cfg.max_destinations,
            sent: AtomicU32::new(0),
        };
        for (family, count) in [(Family::V4, v4), (Family::V6, v6)] {
            for _ in 0..count {
                // A family that cannot bind on this host stays empty.
                let Ok(sock) = factory.bind(family.any_addr()).await else {
                    continue;
                };
                pool.push_socket(sock, family, &tx);
            }
        }
        Ok((pool, rx))
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
                            if tx.send(event).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }));
    }

    fn group(&mut self, family: Family) -> &mut Vec<Arc<S>> {
        match family {
            Family::V4 => &mut self.groups[0],
            Family::V6 => &mut self.groups[1],
        }
    }

    fn group_ref(&self, family: Family) -> &[Arc<S>] {
        match family {
            Family::V4 => &self.groups[0],
            Family::V6 => &self.groups[1],
        }
    }

    /// Number of sockets actually bound for one family.
    pub(crate) fn bound(&self, family: Family) -> usize {
        self.group_ref(family).len()
    }

    /// One pool socket, for sends that bypass the engine loop, such as the
    /// refresh STUN query.
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
        {
            let mut dests = self.dests.lock().expect("dest set lock");
            if !dests.contains(&target) {
                if dests.len() >= self.max_dests {
                    return Err(PunchError::ConntrackExhausted);
                }
                dests.insert(target);
            }
        }
        let mut remaining = self.budget.load(Ordering::Relaxed);
        loop {
            if remaining == 0 {
                return Err(PunchError::BudgetExhausted);
            }
            match self.budget.compare_exchange_weak(
                remaining,
                remaining - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => remaining = current,
            }
        }
        self.limiter.acquire().await;
        let sock = self.group_ref(family).get(idx as usize).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "pool index out of range")
        })?;
        sock.send_to(buf, target).await?;
        self.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Packets the pool actually sent.
    pub(crate) fn sent(&self) -> u32 {
        self.sent.load(Ordering::Relaxed)
    }

    /// Elects the winner: stops every task, closes the losers, and hands out
    /// the winner as an owned socket.
    pub(crate) async fn elect(mut self, family: Family, winner: u16) -> Result<S, PunchError> {
        self.cancel.cancel();
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        let group = self.group(family);
        if group.get(winner as usize).is_none() {
            return Err(PunchError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "winner index out of range",
            )));
        }
        let sock = group.swap_remove(winner as usize);
        self.groups = [Vec::new(), Vec::new()];
        Arc::try_unwrap(sock).map_err(|_| {
            PunchError::Io(io::Error::other(
                "winner socket still shared after election",
            ))
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
