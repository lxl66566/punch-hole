//! Optional heartbeat that holds the punched mapping open.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    msg::{DataPacket, Nonce, encode_packet},
    socket::UdpIo,
};

/// Default heartbeat interval.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Stops the heartbeat task when dropped.
#[must_use = "the heartbeat stops when the guard is dropped"]
pub struct KeepaliveGuard(tokio::task::JoinHandle<()>);

impl KeepaliveGuard {
    /// Whether the heartbeat task is still sending.
    ///
    /// The task ends when a heartbeat send fails, which usually means the
    /// socket is gone; the NAT mapping then ages out with no further
    /// signal from this side. A host that needs to notice polls this
    /// alongside its own socket health.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        !self.0.is_finished()
    }
}

impl Drop for KeepaliveGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Lets an `Arc`-shared tokio socket flow into the generic [`spawn_io`].
///
/// `tokio::net::UdpSocket` has no `Clone`, so hosts share the winner behind
/// an `Arc`. Hosts discard any datagram that satisfies
/// [`crate::msg::is_protocol_packet`], which covers these heartbeat beats
/// and any late handshake retransmissions.
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
/// interval, which covers an `Arc`-shared tokio socket and the generic
/// `Punched<F::Socket>` a session returns.
///
/// The task owns the socket value it receives: dropping the guard aborts
/// the task and releases that reference, so a host that moves its only
/// reference in closes the socket with it. Share the socket (`Arc::clone`)
/// when business traffic must outlive the heartbeat.
pub fn spawn_io<U: UdpIo>(socket: U, peer: SocketAddr, nonce: Nonce) -> KeepaliveGuard {
    spawn_io_with_interval(socket, peer, nonce, KEEPALIVE_INTERVAL)
}

/// `spawn_io` with a custom interval, which compressed-timer tests use.
///
/// A heartbeat that fails to send ends the task;
/// [`KeepaliveGuard::is_alive`] reports that.
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
            // The socket is usually the reason a beat fails, so the task
            // ends and the guard reports it instead of retrying blind.
            if socket.send_to(&packet, peer).await.is_err() {
                break;
            }
        }
    });
    KeepaliveGuard(handle)
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

    /// Succeeds on the first `ok` beats, then fails like a closed socket.
    struct FailsAfter {
        ok: std::sync::atomic::AtomicUsize,
    }

    // The failure injection is fully synchronous.
    #[allow(clippy::unused_async_trait_impl)]
    impl UdpIo for FailsAfter {
        async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> io::Result<usize> {
            if self.ok.fetch_sub(1, std::sync::atomic::Ordering::Relaxed) > 0 {
                Ok(buf.len())
            } else {
                Err(io::Error::other("socket gone"))
            }
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::other("the recorder never receives"))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_beat_ends_the_task_and_the_guard_reports_it() {
        let sock = FailsAfter {
            ok: std::sync::atomic::AtomicUsize::new(1),
        };
        let guard = spawn_io_with_interval(
            sock,
            SocketAddr::from(([203, 0, 113, 9], 4500)),
            [7; 16],
            Duration::from_millis(100),
        );
        assert!(guard.is_alive(), "the task starts alive");
        // The beat at t = 0 succeeds, the beat at t = 100 fails and ends
        // the task, so the mapping has an observable death instead of a
        // silent one.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!guard.is_alive(), "a failed beat ends the task");
    }
}
