//! A full session between two processes, signaling over TCP.
//!
//! The bridge speaks frames, and any ordered transport can carry them.
//! Hosts usually already run a stream to a relay or to the peer
//! (WebSocket, TLS, gRPC), so this example shows the stream shape: each
//! frame goes out as a two-byte big-endian length followed by the frame
//! bytes, and one pump moves frames between the stream and the bridge in
//! both directions until either closes.
//!
//! The listener answers as the Responder and the dialer punches as the
//! Initiator, the natural role assignment when one side calls the other.
//!
//! ```sh
//! cargo run --example tcp_signaling_pair -- listen 127.0.0.1:9100
//! cargo run --example tcp_signaling_pair -- connect 127.0.0.1:9100
//! ```
//!
//! The signaling plane trusts whatever the transport delivers, so a
//! listener open to the world must sit behind authentication of its own;
//! loopback here keeps the example honest without needing any.

use std::{net::SocketAddr, sync::Arc, time::Instant};

use bytes::Bytes;
use punch_hole::{
    PunchConfig, Puncher, Role,
    keepalive::{KeepaliveGuard, spawn_io},
    msg,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// How the process joins the session.
enum Command {
    /// Bind, wait for the peer, answer as the Responder.
    Listen(SocketAddr),
    /// Dial the peer and punch as the Initiator.
    Connect(SocketAddr),
}

fn parse_args() -> Command {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "tcp_signaling_pair".into());
    match (args.next().as_deref(), args.next(), args.next()) {
        (Some("listen"), Some(addr), None) => {
            Command::Listen(addr.parse().expect("a socket address, like 127.0.0.1:9100"))
        },
        (Some("connect"), Some(addr), None) => {
            Command::Connect(addr.parse().expect("a socket address, like 127.0.0.1:9100"))
        },
        _ => {
            eprintln!("usage: {program} listen|connect <ip:port>");
            std::process::exit(2);
        },
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let (role, stream) = match parse_args() {
        Command::Listen(addr) => {
            let listener = TcpListener::bind(addr).await?;
            println!("listening on {addr}; run the other side with `connect`");
            let (stream, peer) = listener.accept().await?;
            println!(
                "peer {peer} dialed after {} ms",
                started.elapsed().as_millis()
            );
            (Role::Responder, stream)
        },
        Command::Connect(addr) => {
            let stream = TcpStream::connect(addr).await?;
            println!("dialed {addr}");
            (Role::Initiator, stream)
        },
    };

    let (host_end, lib_end) = punch_hole::signaling::bridge(64);
    pump(stream, host_end);

    let punched = match role {
        Role::Initiator => {
            Puncher::new(PunchConfig::default())?
                .with_signaling(lib_end)
                .initiator()
                .await?
        },
        Role::Responder => {
            Puncher::new(PunchConfig::default())?
                .with_signaling(lib_end)
                .responder()
                .await?
        },
    };
    let report = &punched.report;
    println!(
        "connected in {} ms: peer {} via {:?} ({} packets sent)",
        started.elapsed().as_millis(),
        punched.peer_addr,
        report.strategy,
        report.packets_sent
    );

    // The business layer owns the winner from here. Tokio sockets have no
    // `Clone`, so share it behind an `Arc`; the heartbeat keeps the NAT
    // mapping open while this side idles.
    let socket = Arc::new(punched.socket);
    let nonce = punched.report.nonce;
    let peer = punched.peer_addr;
    let _keepalive: KeepaliveGuard = spawn_io(Arc::clone(&socket), peer, nonce);

    // One datagram each way over the punched path. Handshake
    // retransmissions and heartbeat beats still arrive on this socket, so
    // the read loop drops packets tagged with the attempt nonce before it
    // parses its own traffic.
    socket
        .send_to(format!("hello from the {role:?}").as_bytes(), peer)
        .await?;
    let mut buf = [0u8; 1500];
    let (n, from) = loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        if msg::is_attempt_packet(&buf[..n], nonce) {
            continue;
        }
        break (n, from);
    };
    println!("[{from}] {}", String::from_utf8_lossy(&buf[..n]));
    // Answer once and leave on a send: a side that leaves right after a
    // receive closes its port while the peer may still be replying.
    socket.send_to(b"ack", from).await?;
    println!("done in {} ms", started.elapsed().as_millis());
    Ok(())
}

/// Moves frames between the bridge and the TCP stream until either closes.
///
/// A frame is opaque `Bytes` that stays under the protocol's signaling
/// size cap, so a two-byte length prefix is the whole framing. Loss and
/// reordering are stream problems the transport already solves; the
/// session's own retransmission covers the rest.
fn pump(stream: TcpStream, host: punch_hole::HostEnd) {
    let punch_hole::HostEnd { to_peer, from_peer } = host;
    tokio::spawn(async move {
        let (mut read, mut write) = stream.into_split();
        let mut to_peer = to_peer;
        let from_peer = from_peer;
        let mut prefix = [0u8; 2];
        let mut frame = [0u8; msg::MAX_SIG_FRAME];
        loop {
            tokio::select! {
                outbound = to_peer.recv() => {
                    let Some(outbound) = outbound else { break };
                    prefix = u16::try_from(outbound.len())
                        .expect("frames stay under the signaling size cap")
                        .to_be_bytes();
                    if write.write_all(&prefix).await.is_err()
                        || write.write_all(&outbound).await.is_err()
                    {
                        break;
                    }
                }
                inbound = read_frame(&mut read, &mut prefix, &mut frame) => {
                    match inbound {
                        Some(n) => {
                            let bytes = Bytes::copy_from_slice(&frame[..n]);
                            if from_peer.send(bytes).await.is_err() {
                                break;
                            }
                        },
                        None => break,
                    }
                }
            }
        }
    });
}

/// Reads one length-prefixed frame; `None` means the stream ended.
///
/// A length past the protocol's frame cap names a broken or hostile peer,
/// and the pump drops the connection instead of allocating for it.
async fn read_frame(
    read: &mut tokio::net::tcp::OwnedReadHalf,
    prefix: &mut [u8; 2],
    buf: &mut [u8; msg::MAX_SIG_FRAME],
) -> Option<usize> {
    read.read_exact(prefix).await.ok()?;
    let n = u16::from_be_bytes(*prefix) as usize;
    if n > buf.len() {
        return None;
    }
    read.read_exact(&mut buf[..n]).await.ok()?;
    Some(n)
}
