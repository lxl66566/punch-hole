//! The signaling bridge between the host transport and the session.

#[cfg(feature = "test-util")]
use std::sync::Arc;
use std::{collections::VecDeque, time::Duration};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::{
    error::PunchError,
    msg::{DecodeError, Frame, SigFrame, decode_sig, encode_sig},
};

/// Creates the two ends of one attempt's signaling channel.
///
/// One bridge serves exactly one attempt. Hosts that run parallel attempts
/// wrap the frames in their own envelope and route them to separate bridges.
#[must_use]
pub fn bridge(capacity: usize) -> (HostEnd, LibEnd) {
    let (to_peer_tx, to_peer_rx) = mpsc::channel(capacity);
    let (from_peer_tx, from_peer_rx) = mpsc::channel(capacity);
    (
        HostEnd {
            to_peer: to_peer_rx,
            from_peer: from_peer_tx,
        },
        LibEnd {
            out: to_peer_tx,
            inn: from_peer_rx,
        },
    )
}

/// The host side of one attempt's signaling channel.
pub struct HostEnd {
    /// Frames the host must deliver to the peer.
    pub to_peer: mpsc::Receiver<Bytes>,
    /// The host pushes frames that arrived from the peer through this sender.
    pub from_peer: mpsc::Sender<Bytes>,
}

/// The library side of the channel, consumed by `Puncher::with_signaling`.
pub struct LibEnd {
    pub(crate) out: mpsc::Sender<Bytes>,
    pub(crate) inn: mpsc::Receiver<Bytes>,
}

/// Session-side wrapper over the bridge with timestamp and RTT bookkeeping.
pub(crate) struct SigIo {
    out: mpsc::Sender<Bytes>,
    inn: mpsc::Receiver<Bytes>,
    epoch: tokio::time::Instant,
    last_peer_ts: u64,
    in_flight: VecDeque<(u64, tokio::time::Instant)>,
    rtt: Option<Duration>,
}

impl SigIo {
    pub(crate) fn new(end: LibEnd) -> Self {
        Self {
            out: end.out,
            inn: end.inn,
            epoch: tokio::time::Instant::now(),
            last_peer_ts: 0,
            in_flight: VecDeque::new(),
            rtt: None,
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Sends one frame, stamped with the local clock and the last peer
    /// timestamp as its echo, and returns the encoded bytes for later raw
    /// resends.
    pub(crate) async fn send(&mut self, body: Frame) -> Result<Bytes, PunchError> {
        // Timestamps count from one, so the zero echo slot stays reserved
        // for "no echo" and a frame sent in the first millisecond still
        // measures its RTT.
        let ts = self.now_ms() + 1;
        let raw = Bytes::from(encode_sig(&SigFrame {
            ts,
            echo: self.last_peer_ts,
            body,
        }));
        self.in_flight.push_back((ts, tokio::time::Instant::now()));
        // The queue holds the newest stamps only; older entries lose their
        // RTT relevance long before they leave through this cap.
        while self.in_flight.len() > 8 {
            self.in_flight.pop_front();
        }
        self.send_raw(raw.clone()).await?;
        Ok(raw)
    }

    /// Sends previously encoded bytes unchanged, which retransmissions use to
    /// skip a second encode.
    ///
    /// A raw resend carries the stamp of its original send, so an echo it
    /// triggers closes the RTT measurement against that original entry.
    pub(crate) async fn send_raw(&mut self, raw: Bytes) -> Result<(), PunchError> {
        self.out
            .send(raw)
            .await
            .map_err(|_| PunchError::SignalingClosed)
    }

    /// Receives the next frame from the host channel.
    ///
    /// A frame that echoes one of our in-flight timestamps closes an RTT
    /// measurement on the local clock. Undecodable frames are skipped, so a
    /// stray datagram on a shared host channel costs one frame and the
    /// session keeps receiving; a version mismatch stays fatal because no
    /// productive exchange can follow it.
    pub(crate) async fn recv(&mut self) -> Result<SigFrame, PunchError> {
        loop {
            let bytes = self.inn.recv().await.ok_or(PunchError::SignalingClosed)?;
            let frame = match decode_sig(&bytes) {
                Ok(frame) => frame,
                Err(DecodeError::BadFrame) => continue,
                Err(DecodeError::Version { local, peer }) => {
                    return Err(PunchError::VersionMismatch { local, peer })
                },
            };
            if frame.echo != 0
                && let Some(pos) = self.in_flight.iter().rposition(|(ts, _)| *ts == frame.echo)
            {
                let (_, sent) = self.in_flight.remove(pos).expect("position just found");
                self.rtt = Some(sent.elapsed());
            }
            self.last_peer_ts = frame.ts;
            return Ok(frame);
        }
    }

    /// The latest signaling round-trip estimate, or a small default before
    /// the first loop closes.
    pub(crate) fn rtt(&self) -> Duration {
        self.rtt.unwrap_or(Duration::from_millis(200))
    }
}

/// Wires two host ends together losslessly, acting as the host transport.
#[cfg(feature = "test-util")]
pub fn connect(a: HostEnd, b: HostEnd) {
    connect_with(a, b, |frame| Some(frame.to_vec()));
}

/// Wires two host ends through a per-frame tap.
///
/// The tap sees each frame as bytes; returning `None` drops it, and the
/// returned buffer replaces it. Loss, duplication, and version-mangling tests
/// build their taps on this hook.
#[cfg(feature = "test-util")]
pub fn connect_with(
    a: HostEnd,
    b: HostEnd,
    tap: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
) {
    let tap = Arc::new(tap);
    let mut a_to_b = a.to_peer;
    let b_from_a = b.from_peer;
    let forward_tap = Arc::clone(&tap);
    tokio::spawn(async move {
        while let Some(frame) = a_to_b.recv().await {
            if let Some(bytes) = forward_tap(&frame) {
                let _ = b_from_a.send(bytes.into()).await;
            }
        }
    });
    let mut b_to_a = b.to_peer;
    let a_from_b = a.from_peer;
    tokio::spawn(async move {
        while let Some(frame) = b_to_a.recv().await {
            if let Some(bytes) = tap(&frame) {
                let _ = a_from_b.send(bytes.into()).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_frame_timestamp_measures_rtt() {
        let (mut host, lib) = bridge(8);
        let mut sig = SigIo::new(lib);
        sig.send(Frame::Accept).await.expect("send");
        let bytes = host.to_peer.recv().await.expect("frame");
        let frame = decode_sig(&bytes).expect("decodes");
        // Timestamps count from one, so the zero echo slot stays reserved.
        assert!(frame.ts >= 1, "ts was {}", frame.ts);
        // The peer echoes the timestamp; a first-millisecond frame still
        // closes an RTT measurement instead of falling back to the default.
        host.from_peer
            .send(Bytes::from(encode_sig(&SigFrame {
                ts: 1,
                echo: frame.ts,
                body: Frame::Accept,
            })))
            .await
            .expect("echo send");
        let back = sig.recv().await.expect("recv");
        assert_eq!(back.echo, frame.ts);
        assert!(
            sig.rtt() < Duration::from_millis(200),
            "rtt stayed at the default"
        );
        drop(host);
    }
}
