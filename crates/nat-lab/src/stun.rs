//! Minimal STUN binding responder shared by both engines.
//!
//! The codec covers the subset RFC 5780 behavior discovery needs: a
//! binding request carrying CHANGE-REQUEST is answered with
//! XOR-MAPPED-ADDRESS, RESPONSE-ORIGIN, and OTHER-ADDRESS, and the reply
//! leaves the flag-selected socket of a two-IP, multi-port address grid.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

const COOKIE: [u8; 4] = 0x2112_a442u32.to_be_bytes();

/// Binding request (RFC 5389 §18.2.1).
const BINDING_REQUEST: u16 = 0x0001;
/// Binding success response (RFC 5389 §18.2.2).
const BINDING_RESPONSE: u16 = 0x0101;
/// XOR-MAPPED-ADDRESS (RFC 5389 §15.2).
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// CHANGE-REQUEST (RFC 5780 §7.2).
const ATTR_CHANGE_REQUEST: u16 = 0x0003;
/// RESPONSE-ORIGIN (RFC 5780 §3.3).
const ATTR_RESPONSE_ORIGIN: u16 = 0x802b;
/// OTHER-ADDRESS (RFC 5780 §3.4).
const ATTR_OTHER_ADDRESS: u16 = 0x802c;
/// CHANGE-REQUEST flag: respond from the alternate IP.
const CHANGE_IP: u32 = 0x0000_0004;
/// CHANGE-REQUEST flag: respond from the alternate port.
const CHANGE_PORT: u32 = 0x0000_0002;

/// The CHANGE-REQUEST flags of one binding request (RFC 5780 §7.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ChangeRequest {
    /// Respond from the alternate IP.
    pub(crate) change_ip: bool,
    /// Respond from the alternate port.
    pub(crate) change_port: bool,
}

/// Whether `request` is a binding request this codec answers.
fn is_binding_request(request: &[u8]) -> bool {
    request.len() >= 20
        && u16::from_be_bytes([request[0], request[1]]) == BINDING_REQUEST
        && request[4..8] == COOKIE
}

/// Parses a binding request and extracts its CHANGE-REQUEST flags.
///
/// Anything that is not a binding request returns `None`; a request
/// without CHANGE-REQUEST parses as both flags clear. Attributes are
/// bounds-checked, so a truncated or malformed tail never panics.
pub(crate) fn binding_request_flags(request: &[u8]) -> Option<ChangeRequest> {
    if !is_binding_request(request) {
        return None;
    }
    let mut flags = ChangeRequest::default();
    let mut at = 20;
    while request.len() >= at + 4 {
        let ty = u16::from_be_bytes([request[at], request[at + 1]]);
        let len = u16::from_be_bytes([request[at + 2], request[at + 3]]) as usize;
        let value_end = at + 4 + len;
        if value_end > request.len() {
            break;
        }
        if ty == ATTR_CHANGE_REQUEST && len == 4 {
            let bits = u32::from_be_bytes([
                request[at + 4],
                request[at + 5],
                request[at + 6],
                request[at + 7],
            ]);
            flags.change_ip = bits & CHANGE_IP != 0;
            flags.change_port = bits & CHANGE_PORT != 0;
        }
        // Attribute values pad to a four-byte boundary.
        at = value_end + (4 - len % 4) % 4;
    }
    Some(flags)
}

/// Builds an RFC 5780 binding response for a valid binding request.
///
/// The reply carries the v4 XOR-MAPPED address of `from`, the address the
/// reply leaves from, and the responder's OTHER-ADDRESS. Anything that is
/// not a binding request returns `None`.
pub(crate) fn discovery_reply(
    request: &[u8],
    from: SocketAddr,
    reply_src: SocketAddr,
    other: SocketAddr,
) -> Option<Vec<u8>> {
    if !is_binding_request(request) {
        return None;
    }
    let (SocketAddr::V4(from), SocketAddr::V4(reply_src), SocketAddr::V4(other)) =
        (from, reply_src, other)
    else {
        // The engines are IPv4 only.
        return None;
    };

    let mut out = Vec::with_capacity(20 + 3 * 12);
    out.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
    out.extend_from_slice(&(3 * 12u16).to_be_bytes());
    out.extend_from_slice(&COOKIE);
    out.extend_from_slice(&request[8..20]);
    push_address(&mut out, ATTR_XOR_MAPPED_ADDRESS, from, true);
    push_address(&mut out, ATTR_RESPONSE_ORIGIN, reply_src, false);
    push_address(&mut out, ATTR_OTHER_ADDRESS, other, false);
    Some(out)
}

/// Appends one MAPPED-ADDRESS-shaped attribute (RFC 5389 §15.1).
///
/// `xor` selects the XOR-MAPPED variant, which masks the port with the
/// cookie's high half and the address with the cookie itself.
fn push_address(out: &mut Vec<u8>, attr: u16, addr: SocketAddrV4, xor: bool) {
    out.extend_from_slice(&attr.to_be_bytes());
    out.extend_from_slice(&8u16.to_be_bytes());
    out.push(0);
    out.push(0x01); // IPv4
    let (port, ip) = if xor {
        (
            addr.port() ^ 0x2112,
            Ipv4Addr::from(u32::from(*addr.ip()) ^ u32::from_be_bytes(COOKIE)),
        )
    } else {
        (addr.port(), *addr.ip())
    };
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&ip.octets());
}

/// The address grid of one RFC 5780 discovery responder.
///
/// A discovery server answers on two IPs and, per IP, on two or more
/// ports. Every socket answers plain binding requests; a request carrying
/// CHANGE-REQUEST (RFC 5780 §4.3) is answered from the flag-selected
/// alternate: CHANGE-PORT moves to the port partner on the same IP,
/// CHANGE-IP to the same port on the other IP, both to their combination —
/// which is exactly the OTHER-ADDRESS every reply from that socket
/// advertises.
#[derive(Debug, Clone)]
pub(crate) struct Grid {
    ips: [Ipv4Addr; 2],
    ports: Vec<u16>,
}

impl Grid {
    /// Builds a grid over `ips` × `ports`.
    ///
    /// Both engines pass two IPs and a non-empty port list, so every
    /// partner lookup finds one.
    pub(crate) fn new(ips: [Ipv4Addr; 2], ports: &[u16]) -> Self {
        Self {
            ips,
            ports: ports.to_vec(),
        }
    }

    /// Every socket address, primary IP first, ports in order.
    pub(crate) fn addrs(&self) -> Vec<SocketAddr> {
        self.ips
            .iter()
            .flat_map(|ip| {
                self.ports
                    .iter()
                    .map(move |port| SocketAddr::from((*ip, *port)))
            })
            .collect()
    }

    /// The position of one grid address in [`Grid::addrs`].
    pub(crate) fn index_of(&self, addr: SocketAddr) -> Option<usize> {
        self.addrs().iter().position(|&a| a == addr)
    }

    /// The other IP of the pair.
    fn other_ip(&self, ip: Ipv4Addr) -> Ipv4Addr {
        if ip == self.ips[0] {
            self.ips[1]
        } else {
            self.ips[0]
        }
    }

    /// The port partner, rotating through the list.
    fn other_port(&self, port: u16) -> u16 {
        match self.ports.iter().position(|&p| p == port) {
            Some(at) => self.ports[(at + 1) % self.ports.len()],
            None => port,
        }
    }

    /// The socket a reply to one request received on `received` leaves
    /// from.
    pub(crate) fn reply_source(&self, received: SocketAddr, flags: ChangeRequest) -> SocketAddr {
        let SocketAddr::V4(received) = received else {
            // Not a grid address; the reply stays where it came from.
            return received;
        };
        let ip = if flags.change_ip {
            self.other_ip(*received.ip())
        } else {
            *received.ip()
        };
        let port = if flags.change_port {
            self.other_port(received.port())
        } else {
            received.port()
        };
        SocketAddr::from((ip, port))
    }

    /// The OTHER-ADDRESS a reply from `received` advertises: where a
    /// both-flags request from that socket would be answered from.
    pub(crate) fn other_address(&self, received: SocketAddr) -> SocketAddr {
        self.reply_source(received, ChangeRequest {
            change_ip: true,
            change_port: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal binding request with optional change flags.
    fn request(flags: Option<u32>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        match flags {
            Some(_) => out.extend_from_slice(&8u16.to_be_bytes()),
            None => out.extend_from_slice(&0u16.to_be_bytes()),
        }
        out.extend_from_slice(&COOKIE);
        out.extend_from_slice(&[0u8; 12]);
        if let Some(bits) = flags {
            out.extend_from_slice(&ATTR_CHANGE_REQUEST.to_be_bytes());
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&bits.to_be_bytes());
        }
        out
    }

    /// Decodes one MAPPED-ADDRESS-shaped attribute of a reply.
    fn attribute(reply: &[u8], attr: u16) -> Option<(u16, [u8; 4])> {
        let msg_len = u16::from_be_bytes([reply[2], reply[3]]) as usize;
        let mut at = 20;
        while at + 8 <= 20 + msg_len {
            let ty = u16::from_be_bytes([reply[at], reply[at + 1]]);
            let len = u16::from_be_bytes([reply[at + 2], reply[at + 3]]) as usize;
            if ty == attr && len == 8 {
                let v = at + 4;
                assert_eq!(reply[v + 1], 0x01, "the attribute names IPv4");
                let port = u16::from_be_bytes([reply[v + 2], reply[v + 3]]);
                return Some((port, [
                    reply[v + 4],
                    reply[v + 5],
                    reply[v + 6],
                    reply[v + 7],
                ]));
            }
            at += 4 + len;
        }
        None
    }

    #[test]
    fn plain_request_parses_without_flags() {
        assert_eq!(
            binding_request_flags(&request(None)),
            Some(ChangeRequest::default())
        );
    }

    #[test]
    fn change_request_flags_parse() {
        let flags = binding_request_flags(&request(Some(0x0000_0006))).expect("parses");
        assert!(flags.change_ip);
        assert!(flags.change_port);
        let flags = binding_request_flags(&request(Some(CHANGE_PORT))).expect("parses");
        assert!(!flags.change_ip);
        assert!(flags.change_port);
    }

    #[test]
    fn non_binding_frames_are_rejected() {
        assert_eq!(binding_request_flags(&[]), None);
        let mut bad_type = request(None);
        bad_type[0..2].copy_from_slice(&BINDING_RESPONSE.to_be_bytes());
        assert_eq!(binding_request_flags(&bad_type), None);
        let mut bad_cookie = request(None);
        bad_cookie[4..8].copy_from_slice(&[0; 4]);
        assert_eq!(binding_request_flags(&bad_cookie), None);
        let mut short = request(None);
        short.truncate(19);
        assert_eq!(binding_request_flags(&short), None);
    }

    #[test]
    fn truncated_attributes_do_not_panic() {
        let mut truncated = request(Some(0x0000_0006));
        truncated.truncate(24);
        assert_eq!(
            binding_request_flags(&truncated),
            Some(ChangeRequest::default()),
            "a truncated CHANGE-REQUEST is skipped, not honored"
        );
    }

    #[test]
    fn discovery_reply_carries_all_three_addresses() {
        let req = request(None);
        let from = SocketAddr::from(([203, 0, 113, 7], 45_000));
        let src = SocketAddr::from(([198, 51, 100, 9], 3479));
        let other = SocketAddr::from(([198, 51, 100, 9], 3478));
        let reply = discovery_reply(&req, from, src, other).expect("reply builds");

        // XOR-MAPPED masks with the cookie.
        let (port, ip) = attribute(&reply, ATTR_XOR_MAPPED_ADDRESS).expect("xor address present");
        assert_eq!(port ^ 0x2112, from.port());
        let cookie = u32::from_be_bytes(COOKIE);
        assert_eq!(
            Ipv4Addr::from(u32::from_be_bytes(ip) ^ cookie),
            from.ip(),
            "the mapped address is the datagram source"
        );
        // RESPONSE-ORIGIN and OTHER-ADDRESS stay in the clear.
        let (port, ip) = attribute(&reply, ATTR_RESPONSE_ORIGIN).expect("origin present");
        assert_eq!(Ipv4Addr::from(ip), src.ip());
        assert_eq!(port, src.port());
        let (port, ip) = attribute(&reply, ATTR_OTHER_ADDRESS).expect("other address present");
        assert_eq!(Ipv4Addr::from(ip), other.ip());
        assert_eq!(port, other.port());
    }

    #[test]
    fn grid_routes_change_requests_per_flags() {
        let grid = Grid::new([Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 1, 2, 1)], &[
            3478, 3479,
        ]);
        let primary = SocketAddr::from(([1, 1, 1, 1], 3478));
        assert_eq!(
            grid.reply_source(primary, ChangeRequest::default()),
            primary
        );
        assert_eq!(
            grid.reply_source(primary, ChangeRequest {
                change_ip: false,
                change_port: true
            }),
            SocketAddr::from(([1, 1, 1, 1], 3479))
        );
        assert_eq!(
            grid.reply_source(primary, ChangeRequest {
                change_ip: true,
                change_port: false
            }),
            SocketAddr::from(([1, 1, 2, 1], 3478))
        );
        let both = ChangeRequest {
            change_ip: true,
            change_port: true,
        };
        assert_eq!(
            grid.reply_source(primary, both),
            SocketAddr::from(([1, 1, 2, 1], 3479))
        );
        assert_eq!(
            grid.other_address(primary),
            grid.reply_source(primary, both)
        );
        assert_eq!(grid.addrs().len(), 4);
        assert_eq!(
            grid.index_of(SocketAddr::from(([1, 1, 2, 1], 3479))),
            Some(3)
        );
    }

    #[test]
    fn grid_rotates_the_port_partner_over_wide_lists() {
        let grid = Grid::new([Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 1, 2, 1)], &[
            3478, 3479, 3480, 3481,
        ]);
        assert_eq!(
            grid.other_address(SocketAddr::from(([1, 1, 1, 1], 3481))),
            SocketAddr::from(([1, 1, 2, 1], 3478)),
            "the partner wraps around the port list"
        );
        assert_eq!(
            grid.other_port(9999),
            9999,
            "a non-grid port maps to itself"
        );
    }
}
