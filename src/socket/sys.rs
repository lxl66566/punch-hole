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

/// Clears the punch-time reuse options from a bound Unix socket.
///
/// The options speed up rebinds while the pool cycles through attempts, but
/// a delivered winner that still carries them lets any same-euid process
/// rebind its port and siphon its datagrams. Linux and the BSDs read the
/// flags of the sockets already on a port when a new bind is attempted, so
/// clearing them after bind still blocks every later grab.
#[cfg(unix)]
pub(crate) fn clear_reuse(sock: &tokio::net::UdpSocket) -> io::Result<()> {
    let sock = socket2::SockRef::from(sock);
    sock.set_reuse_address(false)?;
    sock.set_reuse_port(false)?;
    Ok(())
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

    /// The delivered winner must reject reuse grabs: after `clear_reuse`,
    /// neither a `SO_REUSEADDR` overlap bind nor a `SO_REUSEPORT` duplicate
    /// of the wildcard bind can claim the port. Linux and the BSDs demand
    /// the reuse options on the sockets already holding the port too, so an
    /// ordinary second socket in the same process is a faithful grabber.
    #[cfg(unix)]
    #[tokio::test]
    async fn cleared_winner_rejects_reuse_grabs() {
        let bound = bind(SocketAddr::from(([0, 0, 0, 0], 0))).expect("punch socket binds");
        clear_reuse(&bound).expect("reuse options clear on a bound socket");
        let port = bound
            .local_addr()
            .expect("bound socket reports its address")
            .port();

        // A SO_REUSEADDR bind overlapping the wildcard, the same shape the
        // Windows hardening rejects.
        let overlap = SocketAddr::from(([127, 0, 0, 1], port));
        let grabber = socket2::Socket::new(
            socket2::Domain::for_address(overlap),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("grabber socket creates");
        grabber.set_reuse_address(true).expect("reuse option sets");
        assert!(
            grabber.bind(&overlap.into()).is_err(),
            "a SO_REUSEADDR bind must not overlap the delivered port"
        );

        // A SO_REUSEPORT duplicate of the exact wildcard bind, the shape
        // that shares datagrams between same-euid processes on Linux.
        let twin = socket2::Socket::new(
            socket2::Domain::for_address(SocketAddr::from(([0, 0, 0, 0], port))),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("twin socket creates");
        twin.set_reuse_address(true).expect("reuse option sets");
        twin.set_reuse_port(true).expect("reuseport option sets");
        assert!(
            twin.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())
                .is_err(),
            "a SO_REUSEPORT bind must not share the delivered port"
        );
    }
}
