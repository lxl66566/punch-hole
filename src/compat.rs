//! Seam trait implementations for the [`nat-lab`] engines.
//!
//! The session engine is generic over this crate's own [`UdpFactory`] and
//! [`UdpIo`]. These impls bridge the two engines of the `nat-lab` crate onto
//! that seam, so a test can hand a simulated host or a loopback NAT host
//! straight to [`Puncher::with_factory`](crate::Puncher::with_factory).
//!
//! [`nat-lab`]: https://docs.rs/nat-lab

use crate::socket::{UdpFactory as SeamFactory, UdpIo as SeamIo};

macro_rules! bridge_factory {
    ($ty:ty, $sock:ty) => {
        impl SeamFactory for $ty {
            type Socket = $sock;

            async fn bind(&self, addr: std::net::SocketAddr) -> std::io::Result<Self::Socket> {
                nat_lab::UdpFactory::bind(self, addr).await
            }
        }
    };
}

bridge_factory!(nat_lab::sim::Host, nat_lab::sim::SimSocket);
bridge_factory!(nat_lab::lab::LabHost, nat_lab::lab::LabSocket);

macro_rules! bridge_socket {
    ($ty:ty) => {
        impl SeamIo for $ty {
            async fn send_to(
                &self,
                buf: &[u8],
                target: std::net::SocketAddr,
            ) -> std::io::Result<usize> {
                nat_lab::UdpIo::send_to(self, buf, target).await
            }

            async fn recv_from(
                &self,
                buf: &mut [u8],
            ) -> std::io::Result<(usize, std::net::SocketAddr)> {
                nat_lab::UdpIo::recv_from(self, buf).await
            }

            fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
                nat_lab::UdpIo::local_addr(self)
            }
        }
    };
}

bridge_socket!(nat_lab::sim::SimSocket);
bridge_socket!(nat_lab::lab::LabSocket);
