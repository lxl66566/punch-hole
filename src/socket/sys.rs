//! Platform socket setup for real sockets.

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
};

/// Binds a UDP socket with platform-appropriate options.
///
/// Unix allows address and port reuse, which speeds up rebinds between
/// attempts. Windows has no `SO_REUSEPORT`, and its `SO_REUSEADDR` lets two
/// sockets claim the same port with undefined delivery, so Windows binds
/// plain sockets and relies on distinct ephemeral ports.
pub(crate) fn bind(addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    #[cfg(unix)]
    {
        sock.set_reuse_address(true)?;
        sock.set_reuse_port(true)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    tokio::net::UdpSocket::from_std(sock.into())
}

/// The IPv4 address the OS would route through toward `peer`.
///
/// A connected UDP socket sends nothing; the kernel just picks the outgoing
/// interface. Probing uses this to tell a public host from a translated one.
pub(crate) fn routed_local_ip(peer: SocketAddr) -> io::Result<Option<Ipv4Addr>> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(peer),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.connect(&peer.into())?;
    Ok(match sock.local_addr()?.as_socket() {
        Some(SocketAddr::V4(a)) => Some(*a.ip()),
        _ => None,
    })
}
