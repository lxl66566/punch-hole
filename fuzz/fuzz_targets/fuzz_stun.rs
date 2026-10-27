//! Fuzz target: the STUN binding response parser.
//!
//! The contract under fuzz: any datagram parses to an address or to None,
//! never a panic or a hang. The transaction id is taken from the datagram
//! header itself, so the fuzzed bytes exercise the attribute scan directly
//! instead of stopping at the header match.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let txid: [u8; 12] = data
        .get(8..20)
        .map(|s| s.try_into().expect("slice of length 12"))
        .unwrap_or([0; 12]);
    let _ = punch_hole::nat::parse_stun_response(data, &txid);
});
