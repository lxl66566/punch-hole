//! Fuzz target: the signaling decoder.
//!
//! The contract under fuzz: any byte string decodes to a frame or an error,
//! never a panic or a hang.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = punch_hole::msg::decode_sig(data);
});
