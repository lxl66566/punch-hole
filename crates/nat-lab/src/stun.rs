//! Minimal STUN binding responder shared by both engines.

use std::net::SocketAddr;

const COOKIE: [u8; 4] = 0x2112_a442u32.to_be_bytes();

/// Builds a STUN binding response for a valid binding request.
///
/// The reply carries the v4 XOR-MAPPED address of `from` and nothing else.
/// Anything that is not a binding request returns `None`.
pub(crate) fn binding_reply(request: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    if request.len() < 20
        || u16::from_be_bytes([request[0], request[1]]) != 0x0001
        || request[4..8] != COOKIE
    {
        return None;
    }
    let std::net::IpAddr::V4(ip) = from.ip() else {
        return None;
    };
    let port = from.port() ^ 0x2112;
    let xip: Vec<u8> = ip.octets().iter().zip(COOKIE).map(|(b, k)| b ^ k).collect();

    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&0x0101u16.to_be_bytes());
    out.extend_from_slice(&12u16.to_be_bytes());
    out.extend_from_slice(&COOKIE);
    out.extend_from_slice(&request[8..20]);
    out.extend_from_slice(&0x0020u16.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.push(0);
    out.push(0x01);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&xip);
    Some(out)
}
