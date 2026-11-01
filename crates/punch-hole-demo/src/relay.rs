//! The pairing relay: the demo's whole signaling plane.

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::{net::UdpSocket, time::timeout};

/// How long an unpaired slot waits for its peer before it frees.
const SLOT_TTL: Duration = Duration::from_secs(60);
/// How long an unverified registration waits for its echo before it frees.
/// The pending cap is tiny, so stale entries must not squat on it.
const PENDING_TTL: Duration = Duration::from_secs(10);
/// Registrations allowed to wait for their echo at once.
const MAX_PENDING: usize = 4;

/// Forwards datagrams between the first two addresses that complete a
/// token-verified registration.
///
/// A registration is the byte `R`, answered with `A` plus a random token;
/// echoing the token back as `V` plus the same bytes proves the address
/// receives its own datagrams. Library frames never start with `R`, `A`,
/// or `V`, so the relay never mistakes a frame for control. An unpaired
/// slot frees after [`SLOT_TTL`] and an unverified registration after
/// [`PENDING_TTL`], so neither can be held forever. This relay
/// authenticates nobody and must stay on a trusted network.
pub async fn run(bind: SocketAddr) -> anyhow::Result<()> {
    let sock = UdpSocket::bind(bind).await?;
    println!("relay listening on {}", sock.local_addr()?);
    println!("demo relay: unauthenticated, keep it on a trusted network");
    // Verified addresses with the instant they joined; a filled pair forwards.
    let mut slots: [Option<(SocketAddr, Instant)>; 2] = [None, None];
    // Tokens handed out, keyed by the address that asked.
    let mut pending: HashMap<SocketAddr, ([u8; 8], Instant)> = HashMap::new();
    let mut buf = [0u8; 2048];
    loop {
        let received = timeout(Duration::from_secs(1), sock.recv_from(&mut buf)).await;
        // The expiry sweep runs on every pass, not only when recv idles:
        // steady traffic must not keep a zombie slot or a stale pending
        // registration alive past its TTL.
        for i in 0..2 {
            // Only an unpaired slot ages out; a running pair stays.
            if slots[1 - i].is_none() && slots[i].is_some_and(|(_, at)| at.elapsed() >= SLOT_TTL) {
                println!("slot {i}: expired");
                slots[i] = None;
            }
        }
        pending.retain(|_, (_, at)| at.elapsed() < PENDING_TTL);
        let (n, from) = match received {
            Ok(received) => received?,
            Err(_) => continue,
        };
        let member = slots
            .iter()
            .position(|s| s.is_some_and(|(addr, _)| addr == from));
        match member {
            Some(i) => {
                if let Some((peer, _)) = &slots[1 - i] {
                    // One failed forward must not kill the relay; only a
                    // broken receive socket is fatal for the process.
                    if let Err(e) = sock.send_to(&buf[..n], peer).await {
                        println!("forward to {peer} failed: {e}");
                    }
                }
            },
            None if n == 1 && buf[0] == b'R' && pending.len() < MAX_PENDING => {
                let token: [u8; 8] = rand::random();
                pending.insert(from, (token, Instant::now()));
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
                        slots[free] = Some((from, Instant::now()));
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
