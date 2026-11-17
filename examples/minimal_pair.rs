//! The smallest complete session: both sides in one process.
//!
//! The library carries no signaling, so every session needs a transport
//! underneath. The smallest legal stand-in is two forwarding tasks between
//! the host ends of the bridges; a real host replaces them with its own
//! ordered, authenticated channel to the peer, which is the entire
//! integration surface the library asks for.
//!
//! ```sh
//! cargo run --example minimal_pair
//! ```

use bytes::Bytes;
use punch_hole::{PunchConfig, Puncher, msg};
use tokio::sync::mpsc;

/// Carries frames one way between two channel ends until either drops.
fn forward(mut from: mpsc::Receiver<Bytes>, to: mpsc::Sender<Bytes>) {
    tokio::spawn(async move {
        while let Some(frame) = from.recv().await {
            if to.send(frame).await.is_err() {
                break;
            }
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One bridge serves exactly one attempt, so a process hosting both
    // sides builds two.
    let (host_a, lib_a) = punch_hole::signaling::bridge(64);
    let (host_b, lib_b) = punch_hole::signaling::bridge(64);

    // The stand-in transport: each side's outbound frames become the other
    // side's inbound frames. Frames are opaque `Bytes`; the library never
    // looks past them, and the host never looks inside them.
    forward(host_a.to_peer, host_b.from_peer);
    forward(host_b.to_peer, host_a.from_peer);

    // The two roles run the same code with one method swapped. The
    // Initiator draws the nonce and picks the strategy; the Responder
    // agrees. Assign the role before either side dials: both sides calling
    // `initiator` abort each other.
    let initiator = tokio::spawn(async {
        Puncher::new(PunchConfig::default())
            .expect("the default config validates")
            .with_signaling(lib_a)
            .initiator()
            .await
    });
    let responder = tokio::spawn(async {
        Puncher::new(PunchConfig::default())
            .expect("the default config validates")
            .with_signaling(lib_b)
            .responder()
            .await
    });

    // Probe, Exchange, Negotiate, Punch, and Confirm all run inside these
    // two awaits. A failure returns `PunchFailure` fast, with the phase
    // error and the evidence collected so far.
    let a = initiator.await.expect("the initiator task joined")?;
    let b = responder.await.expect("the responder task joined")?;

    println!(
        "initiator: peer {} via {:?}",
        a.peer_addr, a.report.strategy
    );
    println!(
        "responder: peer {} via {:?}",
        b.peer_addr, b.report.strategy
    );

    // The winner is a plain unconnected `tokio::net::UdpSocket`; every
    // other socket the attempt opened is already closed. One datagram each
    // way proves the path. Late handshake retransmissions of this attempt
    // still arrive on the socket, so the reads skip packets tagged with the
    // attempt nonce.
    let echo = {
        let nonce = b.report.nonce;
        tokio::spawn(async move {
            let sock = b.socket;
            let mut buf = [0u8; 1500];
            loop {
                let (n, from) = sock.recv_from(&mut buf).await?;
                if msg::is_attempt_packet(&buf[..n], nonce) {
                    continue;
                }
                sock.send_to(&buf[..n], from).await?;
                return Ok::<(), std::io::Error>(());
            }
        })
    };
    a.socket
        .send_to(b"hello over the punched path", a.peer_addr)
        .await?;
    let mut buf = [0u8; 1500];
    loop {
        let (n, _from) = a.socket.recv_from(&mut buf).await?;
        if msg::is_attempt_packet(&buf[..n], a.report.nonce) {
            continue;
        }
        println!(
            "initiator heard back: {}",
            String::from_utf8_lossy(&buf[..n])
        );
        break;
    }
    echo.await??;
    Ok(())
}
