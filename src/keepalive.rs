//! Optional heartbeat that holds the punched mapping open.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::msg::{DataPacket, Nonce, encode_packet};

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
