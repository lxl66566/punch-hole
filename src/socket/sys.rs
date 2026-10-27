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
/// exclusive sockets and relies on distinct ephemeral ports.
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
    // The option must sit on the socket before bind, like SO_REUSEADDR.
    #[cfg(windows)]
    set_exclusive_addr_use(&sock)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    tokio::net::UdpSocket::from_std(sock.into())
}

/// Marks the socket with `SO_EXCLUSIVEADDRUSE`.
///
/// Without it, another local process can claim the bound port through its
/// own `SO_REUSEADDR` and receive a share of the traffic, which matters for
/// the long-lived business socket a finished punch hands over. socket2 0.6
/// carries no setter for the option, so the call goes to ws2_32, which the
/// standard library already links.
#[cfg(windows)]
// The crate denies unsafe code; this one ws2_32 call is the sole exemption.
#[expect(unsafe_code)]
fn set_exclusive_addr_use(sock: &socket2::Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;

    const SOL_SOCKET: i32 = 0xffff;
    // winsock2.h defines the option as !SO_REUSEADDR.
    const SO_EXCLUSIVEADDRUSE: i32 = !0x0004;
    const SOCKET_ERROR: i32 = -1;

    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(s: usize, level: i32, optname: i32, optval: *const i32, optlen: i32) -> i32;
    }

    let one: i32 = 1;
    // SAFETY: the handle belongs to `sock` for the call, and `optval` points
    // at a valid i32 for the call duration.
    let rc = unsafe {
        setsockopt(
            // Winsock SOCKET is UINT_PTR, so the raw handle widens to it.
            sock.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            &raw const one,
            size_of::<i32>() as i32,
        )
    };
    if rc == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A port bound by the punch path rejects a `SO_REUSEADDR` bind from
    /// another local process, the classic Windows UDP port hijack. The grab
    /// overlaps the wildcard with a specific address, the shape an exact
    /// rebind already refuses without any option.
    #[cfg(windows)]
    #[tokio::test]
    async fn exclusive_bind_rejects_a_reuseaddr_grab() {
        let bound = bind(SocketAddr::from(([0, 0, 0, 0], 0))).expect("punch socket binds");
        let addr = bound
            .local_addr()
            .expect("bound socket reports its address");
        let overlap = SocketAddr::from(([127, 0, 0, 1], addr.port()));
        let grabber = socket2::Socket::new(
            socket2::Domain::for_address(overlap),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("grabber socket creates");
        grabber.set_reuse_address(true).expect("reuse option sets");
        assert!(
            grabber.bind(&overlap.into()).is_err(),
            "a SO_REUSEADDR bind must not overlap an exclusive port"
        );
    }
}
