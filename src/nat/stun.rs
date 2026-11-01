//! STUN binding codec.
//!
//! The wire subset is one binding request and one response, written
//! in-tree per the architecture notes: RFC 5389/8489 framing with the
//! XOR-MAPPED-ADDRESS reflexive address, plus the RFC 5780 discovery
//! attributes OTHER-ADDRESS and CHANGE-REQUEST.

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

const COOKIE: [u8; 4] = 0x2112_a442u32.to_be_bytes();
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_XOR_MAPPED: u16 = 0x0020;
/// OTHER-ADDRESS (RFC 5780 §3.4), the discovery capability marker.
const ATTR_OTHER_ADDRESS: u16 = 0x802c;
/// CHANGE-REQUEST (RFC 5780 §7.2) with its two flag bits.
const ATTR_CHANGE_REQUEST: u16 = 0x0003;
const CHANGE_IP: u32 = 0x0000_0004;
const CHANGE_PORT: u32 = 0x0000_0002;

pub(crate) fn binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&COOKIE);
    out.extend_from_slice(txid);
    out
}

/// A binding request that asks the server to answer from an alternate
/// source (RFC 5780 §4.4): `change_ip` moves the reply to the other IP,
/// `change_port` to the port partner on the same IP.
pub(super) fn change_request(txid: &[u8; 12], change_ip: bool, change_port: bool) -> Vec<u8> {
    let mut flags = 0u32;
    if change_ip {
        flags |= CHANGE_IP;
    }
    if change_port {
        flags |= CHANGE_PORT;
    }
    let mut out = binding_request(txid);
    out.extend_from_slice(&ATTR_CHANGE_REQUEST.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out
}

/// Whether `buf` is the binding request carrying `txid`.
pub(super) fn is_binding_request(buf: &[u8], txid: &[u8; 12]) -> bool {
    buf.len() >= 20
        && buf[0..2] == BINDING_REQUEST.to_be_bytes()
        && buf[4..8] == COOKIE
        && buf[8..20] == *txid
}

/// The addresses one binding response carries.
pub(crate) struct BindingAnswer {
    pub(crate) mapped: SocketAddr,
    /// OTHER-ADDRESS of an RFC 5780 discovery server, when present.
    pub(crate) other: Option<SocketAddrV4>,
}

/// Parses a binding response with a matching transaction id.
///
/// The wire subset is RFC 5389 and RFC 8489: the response must carry the
/// magic cookie, and the XOR-MAPPED-ADDRESS attribute yields the reflexive
/// address while a MAPPED-ADDRESS-shaped OTHER-ATTRIBUTE yields the
/// discovery server's alternate address. RFC 3489 servers — no cookie,
/// MAPPED-ADDRESS in the clear — are deliberately unsupported: 3489 is
/// historic and the servers a host configures speak 5389+, so a 3489-only
/// answer fails the cookie check and counts as silence.
pub(crate) fn parse_response(buf: &[u8], txid: &[u8; 12]) -> Option<BindingAnswer> {
    if buf.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_RESPONSE || buf[4..8] != COOKIE || buf[8..20] != *txid {
        return None;
    }
    // The message length bounds the attribute area; datagram bytes past it
    // belong to no attribute and are never scanned.
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = (20 + msg_len).min(buf.len());
    let mut i = 20;
    let mut mapped = None;
    let mut other = None;
    while i + 4 <= end {
        let attr = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        // An attribute overrunning the declared message ends the scan.
        if i + 4 + len > end {
            return None;
        }
        let body = &buf[i + 4..i + 4 + len];
        if attr == ATTR_XOR_MAPPED && mapped.is_none() {
            mapped = parse_xor_address(body, txid);
        } else if attr == ATTR_OTHER_ADDRESS && other.is_none() {
            other = parse_plain_v4(body);
        }
        i += 4 + len.div_ceil(4) * 4;
    }
    mapped.map(|mapped| BindingAnswer { mapped, other })
}

/// The XOR-MAPPED-ADDRESS body: an IPv4 or IPv6 reflexive address.
fn parse_xor_address(body: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if body.len() < 8 {
        return None;
    }
    let family = body[1];
    let xport = u16::from_be_bytes([body[2], body[3]]) ^ 0x2112;
    match family {
        0x01 if body.len() >= 8 => {
            let mut ip = [body[4], body[5], body[6], body[7]];
            for (b, k) in ip.iter_mut().zip(COOKIE) {
                *b ^= k;
            }
            Some(SocketAddr::V4(SocketAddrV4::new(ip.into(), xport)))
        },
        0x02 if body.len() >= 20 => {
            let mut ip = [0u8; 16];
            for (j, b) in ip.iter_mut().enumerate() {
                let key = if j < 4 { COOKIE[j] } else { txid[j - 4] };
                *b = body[4 + j] ^ key;
            }
            Some(SocketAddr::V6(SocketAddrV6::new(ip.into(), xport, 0, 0)))
        },
        _ => None,
    }
}

/// A clear-text MAPPED-ADDRESS-shaped body naming an IPv4 address.
fn parse_plain_v4(body: &[u8]) -> Option<SocketAddrV4> {
    if body.len() < 8 || body[1] != 0x01 {
        return None;
    }
    let port = u16::from_be_bytes([body[2], body[3]]);
    Some(SocketAddrV4::new(
        [body[4], body[5], body[6], body[7]].into(),
        port,
    ))
}

/// The reflexive address of one binding response.
pub(crate) fn parse_mapped(buf: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    parse_response(buf, txid).map(|answer| answer.mapped)
}

/// A binding response that reports `port` for the transaction `txid`; the
/// answer shape the probe flow tests feed their collectors.
#[cfg(test)]
pub(crate) fn binding_response(txid: &[u8; 12], port: u16) -> Vec<u8> {
    let ip: std::net::Ipv4Addr = [203, 0, 113, 7].into();
    let mut attr = vec![0x00, 0x01];
    attr.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
    let xip: Vec<u8> = ip.octets().iter().zip(COOKIE).map(|(b, k)| b ^ k).collect();
    attr.extend_from_slice(&xip);

    let mut resp = Vec::new();
    resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
    // Four attribute header bytes plus the eight-byte body.
    resp.extend_from_slice(&12u16.to_be_bytes());
    resp.extend_from_slice(&COOKIE);
    resp.extend_from_slice(txid);
    resp.extend_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
    resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    resp.extend_from_slice(&attr);
    resp
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn request_layout_follows_the_header_format() {
        let txid = [7u8; 12];
        let req = binding_request(&txid);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(&req[4..8], &COOKIE);
        assert_eq!(&req[8..], &txid);
    }

    #[test]
    fn response_parser_reads_xor_mapped_v4() {
        let txid = [1u8; 12];
        let ip: Ipv4Addr = [203, 0, 113, 9].into();
        let port: u16 = 34567;
        let mut attr = vec![0x00, 0x01];
        attr.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
        let xip: Vec<u8> = ip.octets().iter().zip(COOKIE).map(|(b, k)| b ^ k).collect();
        attr.extend_from_slice(&xip);

        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        // Four attribute header bytes plus the eight-byte body.
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&COOKIE);
        resp.extend_from_slice(&txid);
        resp.extend_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
        resp.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        resp.extend_from_slice(&attr);

        let parsed = parse_mapped(&resp, &txid).unwrap();
        assert_eq!(parsed, SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }

    #[test]
    fn mismatched_transaction_ids_are_rejected() {
        let resp = binding_request(&[0u8; 12]);
        assert!(parse_mapped(&resp, &[9u8; 12]).is_none());
    }

    /// A discovery response carries the alternate address in the clear.
    ///
    /// Builds a response the way `nat_lab`'s responders do:
    /// XOR-MAPPED-ADDRESS first, then RESPONSE-ORIGIN and OTHER-ADDRESS.
    fn discovery_response(txid: &[u8; 12], port: u16, other: (u16, [u8; 4])) -> Vec<u8> {
        let ip: Ipv4Addr = [203, 0, 113, 7].into();
        let attr = |ty: u16, body: Vec<u8>| {
            let mut out = ty.to_be_bytes().to_vec();
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
            out.extend_from_slice(&body);
            out
        };
        let mut xor = vec![0x00, 0x01];
        xor.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
        xor.extend(ip.octets().iter().zip(COOKIE).map(|(b, k)| b ^ k));
        let mut plain = vec![0x00, 0x01];
        plain.extend_from_slice(&other.0.to_be_bytes());
        plain.extend_from_slice(&other.1);

        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&COOKIE);
        resp.extend_from_slice(txid);
        for body in [attr(ATTR_XOR_MAPPED, xor), attr(ATTR_OTHER_ADDRESS, plain)] {
            resp.extend_from_slice(&body);
        }
        let msg_len = (resp.len() - 20) as u16;
        resp[2..4].copy_from_slice(&msg_len.to_be_bytes());
        resp
    }

    #[test]
    fn discovery_answers_carry_the_other_address() {
        let txid = [5u8; 12];
        let resp = discovery_response(&txid, 5010, (3479, [198, 51, 100, 9]));
        let answer = parse_response(&resp, &txid).expect("parses");
        assert_eq!(answer.mapped.port(), 5010);
        let other = answer.other.expect("discovery server");
        assert_eq!(other.ip().to_string(), "198.51.100.9");
        assert_eq!(other.port(), 3479);
        // A plain response keeps the field empty.
        let plain = binding_response(&txid, 5010);
        assert!(
            parse_response(&plain, &txid)
                .expect("parses")
                .other
                .is_none()
        );
    }

    #[test]
    fn change_requests_carry_their_flags() {
        let mut req = change_request(&[6u8; 12], true, false);
        assert_eq!(req.len(), 28);
        let bits = u32::from_be_bytes([req[24], req[25], req[26], req[27]]);
        assert_eq!(bits, CHANGE_IP);
        req = change_request(&[6u8; 12], false, true);
        let bits = u32::from_be_bytes([req[24], req[25], req[26], req[27]]);
        assert_eq!(bits, CHANGE_PORT);
    }

    #[test]
    fn attributes_past_the_declared_length_are_ignored() {
        let txid = [3u8; 12];
        let mapped = binding_response(&txid, 5010);
        // The message length declares one four-byte attribute only; the
        // XOR-MAPPED bytes appended after it belong to no attribute.
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&COOKIE);
        resp.extend_from_slice(&txid);
        resp.extend_from_slice(&0x8028u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&mapped[20..]);
        assert!(parse_mapped(&resp, &txid).is_none());
    }

    #[test]
    fn leading_server_attributes_still_parse() {
        // A server that prepends a padded 200-byte attribute keeps
        // XOR-MAPPED well past a minimal response.
        let txid = [4u8; 12];
        let mapped = binding_response(&txid, 5010);
        let mut resp = Vec::with_capacity(256);
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&COOKIE);
        resp.extend_from_slice(&txid);
        resp.extend_from_slice(&0x8028u16.to_be_bytes());
        resp.extend_from_slice(&200u16.to_be_bytes());
        resp.resize(resp.len() + 200, 0);
        resp.extend_from_slice(&mapped[20..]);
        let msg_len = (resp.len() - 20) as u16;
        resp[2..4].copy_from_slice(&msg_len.to_be_bytes());
        let parsed = parse_mapped(&resp, &txid).expect("trailing attribute parses");
        assert_eq!(parsed.port(), 5010);
    }
}
