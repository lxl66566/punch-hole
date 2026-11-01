//! The pairing relay: the demo's whole signaling plane.

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::{net::UdpSocket, time::timeout};

/// How long an unpaired slot waits for its peer before it frees, and how
/// long a pair stays silent before both slots free.
const SLOT_TTL: Duration = Duration::from_secs(60);
/// How long an unverified registration waits for its echo before it frees.
/// The pending cap is tiny, so stale entries must not squat on it.
const PENDING_TTL: Duration = Duration::from_secs(10);
/// Registrations allowed to wait for their echo at once.
const MAX_PENDING: usize = 4;

/// One verified address.
#[derive(Clone, Copy)]
struct Slot {
    addr: SocketAddr,
    joined: Instant,
    /// Last datagram from `addr`. Both sides of a pair falling silent for
    /// [`SLOT_TTL`] means the session ended, so the pair frees for the next.
    last_seen: Instant,
}

/// Forwards datagrams between the first two addresses that complete a
/// token-verified registration.
///
/// A registration is the byte `R`, answered with `A` plus a random token;
/// echoing the token back as `V` plus the same bytes proves the address
/// receives its own datagrams. A repeated `R` from a waiting address gets
/// its existing token again, so a retried registration on a lossy path
/// never races two tokens. Library frames never start with `R`, `A`, or
/// `V`, so the relay never mistakes a frame for control, and a verified
/// address's repeated `V` is swallowed rather than forwarded. An unpaired
/// slot frees [`SLOT_TTL`] after it joined, a pair once both sides have
/// been silent for [`SLOT_TTL`], and an unverified registration after
/// [`PENDING_TTL`], so nothing is held forever. This relay authenticates
/// nobody and must stay on a trusted network.
pub async fn run(bind: SocketAddr) -> anyhow::Result<()> {
    let sock = UdpSocket::bind(bind).await?;
    println!("relay listening on {}", sock.local_addr()?);
    println!("demo relay: unauthenticated, keep it on a trusted network");
    // Verified addresses; a filled pair forwards.
    let mut slots: [Option<Slot>; 2] = [None, None];
    // Tokens handed out, keyed by the address that asked.
    let mut pending: HashMap<SocketAddr, ([u8; 8], Instant)> = HashMap::new();
    let mut buf = [0u8; 2048];
    loop {
        let received = timeout(Duration::from_secs(1), sock.recv_from(&mut buf)).await;
        // The expiry sweep runs on every pass, not only when recv idles:
        // steady traffic must not keep a zombie slot or a stale pending
        // registration alive past its TTL.
        match (slots[0], slots[1]) {
            (Some(a), Some(b)) => {
                if a.last_seen.elapsed() >= SLOT_TTL && b.last_seen.elapsed() >= SLOT_TTL {
                    println!("pair: expired");
                    slots = [None, None];
                }
            },
            _ => {
                for (i, slot) in slots.iter_mut().enumerate() {
                    if slot.is_some_and(|s| s.joined.elapsed() >= SLOT_TTL) {
                        println!("slot {i}: expired");
                        *slot = None;
                    }
                }
            },
        }
        pending.retain(|_, (_, at)| at.elapsed() < PENDING_TTL);
        let (n, from) = match received {
            Ok(received) => received?,
            Err(_) => continue,
        };
        let member = slots.iter().position(|s| s.is_some_and(|s| s.addr == from));
        match member {
            Some(i) => {
                if let Some(slot) = slots[i].as_mut() {
                    slot.last_seen = Instant::now();
                }
                // A repeated echo from a verified address is control, not a
                // frame: forwarded, its first byte would read as a protocol
                // version and end the peer's session.
                if n == 9 && buf[0] == b'V' {
                    continue;
                }
                if let Some(peer) = slots[1 - i] {
                    // One failed forward must not kill the relay; only a
                    // broken receive socket is fatal for the process.
                    if let Err(e) = sock.send_to(&buf[..n], peer.addr).await {
                        println!("forward to {} failed: {e}", peer.addr);
                    }
                }
            },
            None if n == 1 && buf[0] == b'R' => {
                // The pending cap applies to new addresses only; a waiting
                // address asking again is answered with its own token.
                let token = match pending.get(&from) {
                    Some((token, _)) => *token,
                    None if pending.len() < MAX_PENDING => {
                        let token: [u8; 8] = rand::random();
                        pending.insert(from, (token, Instant::now()));
                        token
                    },
                    None => continue,
                };
                let mut ack = Vec::with_capacity(9);
                ack.push(b'A');
                ack.extend_from_slice(&token);
                sock.send_to(&ack, from).await?;
            },
            None if n == 9 && buf[0] == b'V' => {
                // The echo proves the token reached its address.
                if pending.get(&from).is_some_and(|(t, _)| *t == buf[1..9]) {
                    pending.remove(&from);
                    if let Some(free) = (0..2).find(|i| slots[*i].is_none()) {
                        let now = Instant::now();
                        slots[free] = Some(Slot {
                            addr: from,
                            joined: now,
                            last_seen: now,
                        });
                        println!("slot {free}: {from}");
                        if slots.iter().all(Option::is_some) {
                            println!("paired, forwarding between the two slots");
                        }
                    }
                }
            },
            None => {},
        }
    }
}
