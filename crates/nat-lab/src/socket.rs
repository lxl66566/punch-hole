//! The socket seam: the UDP surface a library writes against.
//!
//! Emulating a NAT requires intercepting every send and every receive, so
//! the lab cannot hand out plain `tokio::net::UdpSocket`s. A consumer library
//! defines its sockets against [`UdpIo`] and creates them through
//! [`UdpFactory`]; the two lab engines then plug in underneath. The trait
//! pair is deliberately four methods wide, so an adapter from any other
//! socket abstraction is a few lines.

// Trait signatures stay async even when an implementation never yields.
#![allow(clippy::unused_async_trait_impl)]

use std::{future::Future, io, net::SocketAddr};

/// One UDP socket.
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

/// Creates the sockets a consumer binds.
pub trait UdpFactory: Send + Sync + 'static {
    type Socket: UdpIo;
    fn bind(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::Socket>> + Send;
}

/// Address family a bind targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// The wildcard bind address for this family.
    #[must_use]
    pub fn any_addr(self) -> SocketAddr {
        match self {
            Family::V4 => SocketAddr::from(([0, 0, 0, 0], 0)),
            Family::V6 => SocketAddr::from(([0u16; 8], 0)),
        }
    }
}
