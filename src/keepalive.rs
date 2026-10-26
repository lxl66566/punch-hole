//! Optional heartbeat that holds the punched mapping open.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    msg::{DataPacket, Nonce, encode_packet},
    socket::UdpIo,
};

/// Default heartbeat interval, matching PROTOCOL.md.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Stops the heartbeat task when dropped.
#[must_use = "the heartbeat stops when the guard is dropped"]
pub struct KeepaliveGuard(tokio::task::JoinHandle<()>);

impl Drop for KeepaliveGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Lets an `Arc`-shared tokio socket flow into the generic [`spawn_io`].
impl UdpIo for Arc<tokio::net::UdpSocket> {
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        (**self).send_to(buf, target).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        (**self).recv_from(buf).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        (**self).local_addr()
    }
}

/// Sends the heartbeat on any UDP socket implementation at the default
/// interval, which covers the generic `Punched<F::Socket>` a session returns.
pub fn spawn_io<U: UdpIo>(socket: U, peer: SocketAddr, nonce: Nonce) -> KeepaliveGuard {
    spawn_io_with_interval(socket, peer, nonce, KEEPALIVE_INTERVAL)
}

/// `spawn_io` with a custom interval, which compressed-timer tests use.
pub fn spawn_io_with_interval<U: UdpIo>(
    socket: U,
    peer: SocketAddr,
    nonce: Nonce,
    interval: Duration,
) -> KeepaliveGuard {
    let packet = encode_packet(&DataPacket::Keepalive { nonce });
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if socket.send_to(&packet, peer).await.is_err() {
                break;
            }
        }
    });
    KeepaliveGuard(handle)
}

/// Sends the heartbeat on a shared socket at the default interval.
///
/// `tokio::net::UdpSocket` has no `Clone`, so the host shares it behind an
/// `Arc`. Hosts discard any datagram whose first byte is the data-plane magic
/// and whose length stays under the protocol limit.
pub fn spawn(socket: Arc<tokio::net::UdpSocket>, peer: SocketAddr, nonce: Nonce) -> KeepaliveGuard {
    spawn_with_interval(socket, peer, nonce, KEEPALIVE_INTERVAL)
}

/// `spawn` with a custom interval, which compressed-timer tests use.
pub fn spawn_with_interval(
    socket: Arc<tokio::net::UdpSocket>,
    peer: SocketAddr,
    nonce: Nonce,
    interval: Duration,
) -> KeepaliveGuard {
    spawn_io_with_interval(socket, peer, nonce, interval)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded beats: packet bytes and destination.
    type Sent = Arc<std::sync::Mutex<Vec<(Vec<u8>, SocketAddr)>>>;

    /// Records every send without touching the network.
    #[derive(Clone, Default)]
    struct Recorder {
        sent: Sent,
    }

    // The recorder body is fully synchronous.
    #[allow(clippy::unused_async_trait_impl)]
    impl UdpIo for Recorder {
        async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
            self.sent
                .lock()
                .expect("recorder lock")
                .push((buf.to_vec(), target));
            Ok(buf.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::other("the recorder never receives"))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn spawn_io_beats_on_any_udp_io() {
        let sock = Recorder::default();
        let peer = SocketAddr::from(([203, 0, 113, 9], 4500));
        let nonce = [7; 16];
        let guard = spawn_io_with_interval(sock.clone(), peer, nonce, Duration::from_millis(100));
        // The first interval tick fires immediately, so 350 ms holds four
        // beats: t = 0, 100, 200, 300.
        tokio::time::sleep(Duration::from_millis(350)).await;
        drop(guard);

        let sent = sock.sent.lock().expect("recorder lock").clone();
        assert_eq!(sent.len(), 4, "one beat per interval");
        for (buf, target) in sent {
            assert_eq!(target, peer);
            let decoded = crate::msg::decode_packet(&buf).expect("beat is a data packet");
            assert_eq!(decoded, DataPacket::Keepalive { nonce });
        }
    }
}
