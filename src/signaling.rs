//! The signaling bridge between the host transport and the session.

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
        let ts = self.now_ms();
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
    /// measurement on the local clock.
    pub(crate) async fn recv(&mut self) -> Result<SigFrame, PunchError> {
        let bytes = self.inn.recv().await.ok_or(PunchError::SignalingClosed)?;
        let frame = decode_sig(&bytes).map_err(|e| match e {
            DecodeError::Version { local, peer } => PunchError::VersionMismatch { local, peer },
            DecodeError::BadFrame => PunchError::BadFrame,
        })?;
        if frame.echo != 0 {
            if let Some(pos) = self.in_flight.iter().rposition(|(ts, _)| *ts == frame.echo) {
                let (_, sent) = self.in_flight.remove(pos).expect("position just found");
                self.rtt = Some(sent.elapsed());
            }
        }
        self.last_peer_ts = frame.ts;
        Ok(frame)
    }

    /// The latest signaling round-trip estimate, or a small default before
    /// the first loop closes.
    pub(crate) fn rtt(&self) -> Duration {
        self.rtt.unwrap_or(Duration::from_millis(200))
    }
}
