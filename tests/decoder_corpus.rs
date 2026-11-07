//! Fixed decoder corpus for the two wire decoders.
//!
//! The property matches the cargo-fuzz targets in `fuzz/`: any byte string
//! decodes to a message or an error, never a panic or a hang. The corpus
//! here is deterministic, so plain `cargo test` covers a fixed slice of the
//! input space on every run.

use std::net::{SocketAddrV4, SocketAddrV6};

use punch_hole::{
    msg::{
        AbortReason, DATA_MAGIC, DataPacket, DecodeError, Frame, MAX_DATA_PACKET, MAX_LOCAL_ADDRS,
        MAX_SIG_FRAME, MAX_V6_ADDRS, Offer, SigFrame, StrategyId, VERSION, decode_packet,
        decode_sig, encode_packet, encode_sig,
    },
    nat::{FilterClass, NatClass, NatInfo, V4Nat, V6Nat},
};
use rand::{SeedableRng, prelude::*};

/// The largest signaling frame the protocol can build.
fn hello_frame() -> SigFrame {
    let info = NatInfo {
        v4: Some(V4Nat {
            class: NatClass::EasySym { step: 2 },
            reflexive: SocketAddrV4::new([203, 0, 113, 7].into(), 40001),
            // Every vector sits at its cap, so the encoding is maximal.
            alloc_seq: (0..64u16).map(|p| 30000 + p).collect(),
            distinct_probe_ips: 4,
            filtering: FilterClass::AddressPortDependent,
            hairpin: true,
        }),
        v6: Some(V6Nat {
            addrs: (0..8u16)
                .map(|i| SocketAddrV6::new([0x2001, i, 0, 0, 0, 0, 0, 1].into(), 5300 + i, 0, 0))
                .collect(),
        }),
        // Every vector sits at its cap, so the encoding is maximal.
        local: (0..8u8)
            .map(|i| std::net::Ipv4Addr::new(192, 168, i, 10))
            .collect(),
    };
    SigFrame {
        ts: 42,
        echo: 7,
        body: Frame::Hello(info),
    }
}

/// Every truncation and every single-byte corruption of one valid buffer.
fn mutations(valid: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = (0..=valid.len()).map(|i| valid[..i].to_vec()).collect();
    for i in 0..valid.len() {
        let mut flipped = valid.to_vec();
        flipped[i] ^= 0xff;
        out.push(flipped);
    }
    out
}

#[test]
fn decoders_survive_random_and_edge_inputs() {
    let mut rng = StdRng::seed_from_u64(0x5eed_c0de);
    let mut cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![VERSION],
        vec![DATA_MAGIC],
        vec![DATA_MAGIC, VERSION],
        vec![0x71, VERSION, 0x00],
        vec![VERSION, 0xff, 0xfe],
        vec![DATA_MAGIC, VERSION, 0xff],
        vec![9, 1, 2, 3],
    ];

    // Cap boundaries in both directions, with a plausible prefix.
    cases.push(vec![VERSION; MAX_SIG_FRAME]);
    cases.push(vec![VERSION; MAX_SIG_FRAME + 1]);
    let mut at_cap = vec![DATA_MAGIC, VERSION];
    at_cap.resize(MAX_DATA_PACKET, 0xee);
    cases.push(at_cap);
    let mut over_cap = vec![DATA_MAGIC, VERSION];
    over_cap.resize(MAX_DATA_PACKET + 1, 0xee);
    cases.push(over_cap);

    // A full-length frame with our magic and a foreign version names the
    // mismatch; a valid frame truncated one byte below the smallest legal
    // body stays garbage.
    let mut foreign_version = encode_packet(&DataPacket::Syn {
        nonce: [0x5a; 16],
        socket: 3,
    });
    foreign_version[1] = 9;
    let mut short = encode_packet(&DataPacket::Ack {
        nonce: [0x5a; 16],
        socket: 4,
    });
    short.truncate(short.len() - 1);
    assert_eq!(
        decode_packet(&foreign_version),
        Err(DecodeError::Version {
            local: VERSION,
            peer: 9
        })
    );
    assert_eq!(decode_packet(&short), Err(DecodeError::BadFrame));
    cases.push(foreign_version);
    cases.push(short);

    // Pseudo-random buffers of decoder-relevant sizes.
    for _ in 0..2048 {
        let len = rng.random_range(0..=80usize);
        cases.push((0..len).map(|_| rng.random::<u8>()).collect());
    }

    // Anchored mutations of real encodings, which random bytes rarely
    // resemble closely enough to reach deep parser states.
    let hello = encode_sig(&hello_frame());
    let offer = encode_sig(&SigFrame {
        ts: 1,
        echo: 0,
        body: Frame::Offer(Offer {
            nonce: [0xab; 16],
            strategy: StrategyId::BirthdayBurst,
            local_sockets: 16,
            peer_sockets: 32,
            start_delay_ms: 400,
        }),
    });
    // The appended variant encodes as the highest StrategyId index, so
    // its mutations walk a byte the mid-list variants never vary.
    let predictive = encode_sig(&SigFrame {
        ts: 2,
        echo: 1,
        body: Frame::Offer(Offer {
            nonce: [0x9e; 16],
            strategy: StrategyId::PredictiveBurst,
            local_sockets: 1,
            peer_sockets: 1,
            start_delay_ms: 350,
        }),
    });
    let syn = encode_packet(&DataPacket::Syn {
        nonce: [0xcd; 16],
        socket: 1023,
    });
    // Anchors for the remaining variants, so every parse path gets its own
    // mutation sweep: the short enum-only bodies (Accept, Abort), the
    // Option fields of PortUpdate, and the remaining data-plane ordinals.
    let accept = encode_sig(&SigFrame {
        ts: 3,
        echo: 2,
        body: Frame::Accept,
    });
    let port_update = encode_sig(&SigFrame {
        ts: 4,
        echo: 0,
        body: Frame::PortUpdate {
            v4: Some(5001),
            v6: Some(5301),
        },
    });
    let confirmed = encode_sig(&SigFrame {
        ts: 5,
        echo: 0,
        body: Frame::Confirmed { socket: 4095 },
    });
    let abort = encode_sig(&SigFrame {
        ts: 6,
        echo: 0,
        body: Frame::Abort(AbortReason::BudgetExhausted),
    });
    let synack = encode_packet(&DataPacket::SynAck {
        nonce: [0x66; 16],
        socket: 2047,
    });
    let ack = encode_packet(&DataPacket::Ack {
        nonce: [0x55; 16],
        socket: 2046,
    });
    let keepalive = encode_packet(&DataPacket::Keepalive { nonce: [0x44; 16] });
    // The anchors round-trip before mutation, so failures point at the
    // mutation and not at the corpus itself.
    assert!(decode_sig(&hello).is_ok());
    assert!(decode_sig(&offer).is_ok());
    assert!(decode_sig(&predictive).is_ok());
    assert!(decode_sig(&accept).is_ok());
    assert!(decode_sig(&port_update).is_ok());
    assert!(decode_sig(&confirmed).is_ok());
    assert!(decode_sig(&abort).is_ok());
    assert_eq!(decode_packet(&syn).unwrap(), DataPacket::Syn {
        nonce: [0xcd; 16],
        socket: 1023
    });
    assert_eq!(decode_packet(&synack).unwrap(), DataPacket::SynAck {
        nonce: [0x66; 16],
        socket: 2047
    });
    assert_eq!(decode_packet(&ack).unwrap(), DataPacket::Ack {
        nonce: [0x55; 16],
        socket: 2046
    });
    assert_eq!(decode_packet(&keepalive).unwrap(), DataPacket::Keepalive {
        nonce: [0x44; 16]
    });
    for valid in [
        &hello,
        &offer,
        &predictive,
        &syn,
        &accept,
        &port_update,
        &confirmed,
        &abort,
        &synack,
        &ack,
        &keepalive,
    ] {
        cases.extend(mutations(valid));
    }

    for bytes in &cases {
        let _ = decode_sig(bytes);
        let _ = decode_packet(bytes);
        // Both caps reject before any parsing runs.
        if bytes.len() > MAX_SIG_FRAME {
            assert_eq!(decode_sig(bytes), Err(DecodeError::BadFrame));
        }
        if let Some(&first) = bytes.first()
            && first != DATA_MAGIC
        {
            assert_eq!(decode_packet(bytes), Err(DecodeError::BadFrame));
        }
        // Any signaling-sized frame stamped with a foreign version names
        // the mismatch, which the session treats as fatal.
        if !bytes.is_empty() && bytes.len() <= MAX_SIG_FRAME && bytes[0] != VERSION {
            assert_eq!(
                decode_sig(bytes),
                Err(DecodeError::Version {
                    local: VERSION,
                    peer: bytes[0]
                })
            );
        }
    }
}

/// A peer that ignored the send-side IPv6 cap cannot push an oversized
/// address list into the session: decode truncates it to the wire limit
/// whatever the frame carries otherwise.
#[test]
fn oversized_peer_v6_list_is_truncated() {
    let addrs: Vec<_> = (0..u16::MAX)
        .take(MAX_V6_ADDRS * 3)
        .map(|i| SocketAddrV6::new([0x2001, 0xdb8, 0, i, 0, 0, 0, 1].into(), 5300 + i, 0, 0))
        .collect();
    let expected = addrs[..MAX_V6_ADDRS].to_vec();
    let frame = SigFrame {
        ts: 0,
        echo: 0,
        body: Frame::Hello(NatInfo {
            v4: None,
            v6: Some(V6Nat { addrs }),
            local: Vec::new(),
        }),
    };
    let bytes = encode_sig(&frame);
    assert!(
        bytes.len() <= MAX_SIG_FRAME,
        "the oversized list still fits the frame cap"
    );
    let Frame::Hello(decoded) = decode_sig(&bytes).expect("frame decodes").body else {
        panic!("hello body survives");
    };
    assert_eq!(decoded.v6.expect("v6 survives").addrs, expected);
}

/// A peer that ignored the send-side local-address cap cannot push an
/// oversized list into the session either: decode truncates it to the
/// wire limit whatever the frame carries otherwise.
#[test]
fn oversized_peer_local_list_is_truncated() {
    let count = u8::try_from(MAX_LOCAL_ADDRS * 3).expect("cap fits u8");
    let ips: Vec<_> = (1..=count)
        .map(|i| std::net::Ipv4Addr::new(192, 168, i, i))
        .collect();
    let expected = ips[..MAX_LOCAL_ADDRS].to_vec();
    let frame = SigFrame {
        ts: 0,
        echo: 0,
        body: Frame::Hello(NatInfo {
            v4: None,
            v6: None,
            local: ips,
        }),
    };
    let bytes = encode_sig(&frame);
    assert!(
        bytes.len() <= MAX_SIG_FRAME,
        "the oversized list still fits the frame cap"
    );
    let Frame::Hello(decoded) = decode_sig(&bytes).expect("frame decodes").body else {
        panic!("hello body survives");
    };
    assert_eq!(decoded.local, expected);
}
