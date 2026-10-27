//! Wire messages for both planes and their codecs.
//!
//! The signaling plane wraps frames in a version byte, the data plane in a
//! magic byte plus a version byte. The book under `docs/` specifies both
//! planes; the struct definitions here are the source of truth.

#[cfg(test)]
use std::net::{SocketAddrV4, SocketAddrV6};

use serde::{Deserialize, Serialize};

use crate::nat::NatInfo;
#[cfg(test)]
use crate::nat::{FilterClass, NatClass};

/// Wire protocol version shared by both planes. Frames stamped with a
/// different version are rejected, so incompatible layouts never decode
/// halfway.
pub const VERSION: u8 = 2;
/// First byte of every data-plane packet.
pub const DATA_MAGIC: u8 = 0x70;
/// Signaling frames longer than this are rejected.
pub const MAX_SIG_FRAME: usize = 1024;
/// Data packets longer than this are dropped.
pub const MAX_DATA_PACKET: usize = 64;
/// Upper bound on `alloc_seq` entries.
pub const MAX_ALLOC_SEQ: usize = 64;
/// Upper bound on collected IPv6 addresses.
pub const MAX_V6_ADDRS: usize = 8;

/// Random 16 bytes drawn by the Initiator. Tags every packet of one attempt.
pub type Nonce = [u8; 16];

/// Draws a fresh nonce with the system random source.
#[must_use]
pub fn new_nonce() -> Nonce {
    rand::random()
}

/// The punching algorithm the Initiator picked for an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StrategyId {
    ConeExchange,
    SymProbe,
    PredictiveExchange,
    BirthdayBurst,
}

/// Why a side stopped the attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    Unpunchable,
    BudgetExhausted,
    Internal,
}

/// One signaling frame with its timestamp envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigFrame {
    /// Milliseconds on the sender's own monotonic clock.
    pub ts: u64,
    /// The ts field of the frame being answered, 0 when the frame answers none.
    pub echo: u64,
    pub body: Frame,
}

/// Signaling frame bodies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Frame {
    Hello(NatInfo),
    Offer(Offer),
    Accept,
    /// Fresh socket-0 ports of the sender, one slot per family it punches
    /// over. A family the plan leaves out carries None.
    PortUpdate {
        v4: Option<u16>,
        v6: Option<u16>,
    },
    /// The sender finished the handshake on its winning socket.
    Confirmed {
        socket: u16,
    },
    Abort(AbortReason),
}

/// The plan the Initiator derived from both `NatInfo` values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Offer {
    pub nonce: Nonce,
    pub strategy: StrategyId,
    /// Sockets the Initiator will open.
    pub local_sockets: u16,
    /// Sockets the Responder should open.
    pub peer_sockets: u16,
    /// Pulse start delay in milliseconds, counted from the Responder
    /// sending Accept.
    pub start_delay_ms: u32,
}

/// Data-plane packet bodies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DataPacket {
    Syn { nonce: Nonce, socket: u16 },
    SynAck { nonce: Nonce, socket: u16 },
    Ack { nonce: Nonce },
    Keepalive { nonce: Nonce },
}

impl DataPacket {
    /// The attempt every variant carries.
    #[must_use]
    pub fn nonce(&self) -> Nonce {
        match self {
            DataPacket::Syn { nonce, .. }
            | DataPacket::SynAck { nonce, .. }
            | DataPacket::Ack { nonce }
            | DataPacket::Keepalive { nonce } => *nonce,
        }
    }
}

/// Why a signaling frame could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("frame failed to decode")]
    BadFrame,
    #[error("version mismatch: local {local}, peer {peer}")]
    Version { local: u8, peer: u8 },
}

/// Encodes a signaling frame with its version prefix.
#[must_use]
pub fn encode_sig(frame: &SigFrame) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.push(VERSION);
    buf.extend_from_slice(&postcard::to_allocvec(frame).expect("SigFrame is serializable"));
    buf
}

/// Decodes a signaling frame. Garbage on this plane fails the session, so the
/// error distinguishes version mismatches from broken bytes. Peer-supplied
/// vectors are truncated to the wire limits on the way out.
pub fn decode_sig(bytes: &[u8]) -> Result<SigFrame, DecodeError> {
    if bytes.len() > MAX_SIG_FRAME || bytes.is_empty() {
        return Err(DecodeError::BadFrame);
    }
    if bytes[0] != VERSION {
        return Err(DecodeError::Version {
            local: VERSION,
            peer: bytes[0],
        });
    }
    let mut frame: SigFrame =
        postcard::from_bytes(&bytes[1..]).map_err(|_| DecodeError::BadFrame)?;
    if let Frame::Hello(info) = &mut frame.body
        && let Some(v4) = &mut info.v4
    {
        v4.alloc_seq.truncate(MAX_ALLOC_SEQ);
    }
    Ok(frame)
}

/// Encodes a data-plane packet with its magic and version prefix.
#[must_use]
pub fn encode_packet(packet: &DataPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    buf.push(DATA_MAGIC);
    buf.push(VERSION);
    buf.extend_from_slice(&postcard::to_allocvec(packet).expect("DataPacket is serializable"));
    buf
}

/// Decodes a data-plane packet. Garbage on this plane is dropped silently, so
/// callers only care whether decoding succeeded.
pub fn decode_packet(bytes: &[u8]) -> Result<DataPacket, DecodeError> {
    if bytes.len() > MAX_DATA_PACKET || bytes.len() < 3 || bytes[0] != DATA_MAGIC {
        return Err(DecodeError::BadFrame);
    }
    if bytes[1] != VERSION {
        return Err(DecodeError::Version {
            local: VERSION,
            peer: bytes[1],
        });
    }
    postcard::from_bytes(&bytes[2..]).map_err(|_| DecodeError::BadFrame)
}

#[cfg(test)]
fn sample_nat_info() -> NatInfo {
    NatInfo {
        v4: Some(crate::nat::V4Nat {
            class: NatClass::EasySym { step: 2 },
            reflexive: SocketAddrV4::new([203, 0, 113, 7].into(), 40001),
            alloc_seq: vec![40001, 40003, 40005, 40007],
            filtering: FilterClass::AddressPortDependent,
        }),
        v6: Some(crate::nat::V6Nat {
            addrs: vec![SocketAddrV6::new(
                [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into(),
                0,
                0,
                0,
            )],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sig_frames_round_trip() {
        let cases = vec![
            SigFrame {
                ts: 1,
                echo: 0,
                body: Frame::Hello(sample_nat_info()),
            },
            SigFrame {
                ts: 2,
                echo: 1,
                body: Frame::Offer(Offer {
                    nonce: [7; 16],
                    strategy: StrategyId::BirthdayBurst,
                    local_sockets: 16,
                    peer_sockets: 32,
                    start_delay_ms: 400,
                }),
            },
            SigFrame {
                ts: 3,
                echo: 2,
                body: Frame::Accept,
            },
            SigFrame {
                ts: 4,
                echo: 0,
                body: Frame::PortUpdate {
                    v4: Some(5000),
                    v6: None,
                },
            },
            SigFrame {
                ts: 5,
                echo: 0,
                body: Frame::Confirmed { socket: 3 },
            },
            SigFrame {
                ts: 6,
                echo: 0,
                body: Frame::Abort(AbortReason::BudgetExhausted),
            },
        ];
        for frame in cases {
            assert_eq!(decode_sig(&encode_sig(&frame)).unwrap(), frame);
        }
    }

    #[test]
    fn data_packets_round_trip() {
        let cases = vec![
            DataPacket::Syn {
                nonce: [1; 16],
                socket: 0,
            },
            DataPacket::SynAck {
                nonce: [2; 16],
                socket: 511,
            },
            DataPacket::Ack { nonce: [3; 16] },
            DataPacket::Keepalive { nonce: [4; 16] },
        ];
        for packet in cases {
            assert_eq!(decode_packet(&encode_packet(&packet)).unwrap(), packet);
        }
    }

    #[test]
    fn encoded_sizes_stay_under_limits() {
        let mut info = sample_nat_info();
        info.v4.as_mut().unwrap().alloc_seq =
            (0..MAX_ALLOC_SEQ as u16).map(|p| 30000 + p).collect();
        info.v6.as_mut().unwrap().addrs = (0..MAX_V6_ADDRS)
            .map(|_| SocketAddrV6::new([1; 8].into(), 0, 0, 0))
            .collect();
        let frame = SigFrame {
            ts: 0,
            echo: 0,
            body: Frame::Hello(info),
        };
        assert!(encode_sig(&frame).len() <= MAX_SIG_FRAME);
        assert!(
            encode_packet(&DataPacket::Syn {
                nonce: [0; 16],
                socket: 0
            })
            .len()
                <= MAX_DATA_PACKET
        );
    }

    #[test]
    fn garbage_signaling_bytes_rejected() {
        assert_eq!(decode_sig(&[]), Err(DecodeError::BadFrame));
        assert_eq!(
            decode_sig(&[VERSION, 0xff, 0xff]),
            Err(DecodeError::BadFrame)
        );
        assert_eq!(
            decode_sig(&[9, 1, 2, 3]),
            Err(DecodeError::Version {
                local: VERSION,
                peer: 9
            })
        );
        let long = vec![VERSION; MAX_SIG_FRAME + 1];
        assert_eq!(decode_sig(&long), Err(DecodeError::BadFrame));
    }

    #[test]
    fn garbage_data_bytes_rejected() {
        assert_eq!(decode_packet(&[]), Err(DecodeError::BadFrame));
        assert_eq!(
            decode_packet(&[DATA_MAGIC, VERSION, 0xfe]),
            Err(DecodeError::BadFrame)
        );
        // Wrong magic drops before the version check.
        assert_eq!(decode_packet(&[0x00, 9, 0x00]), Err(DecodeError::BadFrame));
        assert_eq!(
            decode_packet(&[DATA_MAGIC, 9, 0x00]),
            Err(DecodeError::Version {
                local: VERSION,
                peer: 9
            })
        );
    }

    #[test]
    fn oversized_peer_alloc_seq_is_truncated() {
        let mut info = sample_nat_info();
        info.v4.as_mut().unwrap().alloc_seq = vec![40001; MAX_ALLOC_SEQ * 3];
        let frame = SigFrame {
            ts: 0,
            echo: 0,
            body: Frame::Hello(info),
        };
        let decoded = decode_sig(&encode_sig(&frame)).expect("frame fits the size cap");
        let Frame::Hello(info) = decoded.body else {
            panic!("body survives the round trip");
        };
        // A peer that ignored the send-side cap cannot push an unbounded
        // sequence into the session.
        assert_eq!(info.v4.expect("v4 survives").alloc_seq.len(), MAX_ALLOC_SEQ);
    }
}
