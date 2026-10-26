//! Fixed decoder corpus for the two wire decoders.
//!
//! The property matches the cargo-fuzz targets in `fuzz/`: any byte string
//! decodes to a message or an error, never a panic or a hang. The corpus
//! here is deterministic, so plain `cargo test` covers a fixed slice of the
//! input space on every run.

use std::net::{SocketAddrV4, SocketAddrV6};

use punch_hole::{
    msg::{
        DATA_MAGIC, DataPacket, DecodeError, Frame, MAX_DATA_PACKET, MAX_SIG_FRAME, Offer,
        SigFrame, StrategyId, VERSION, decode_packet, decode_sig, encode_packet, encode_sig,
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
            pub_ips: (0..4u8).map(|i| [203, 0, 113, i].into()).collect(),
            alloc_seq: (0..64u16).map(|p| 30000 + p).collect(),
            filtering: FilterClass::AddressPortDependent,
        }),
        v6: Some(V6Nat {
            addrs: (0..8u16)
                .map(|i| SocketAddrV6::new([0x2001, i, 0, 0, 0, 0, 0, 1].into(), 5300 + i, 0, 0))
                .collect(),
        }),
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
    let syn = encode_packet(&DataPacket::Syn {
        nonce: [0xcd; 16],
        socket: 1023,
    });
    // The anchors round-trip before mutation, so failures point at the
    // mutation and not at the corpus itself.
    assert!(decode_sig(&hello).is_ok());
    assert!(decode_sig(&offer).is_ok());
    assert_eq!(decode_packet(&syn).unwrap(), DataPacket::Syn {
        nonce: [0xcd; 16],
        socket: 1023
    });
    for valid in [&hello, &offer, &syn] {
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
    }
}
