//! A two-terminal demo of one full punch session over real sockets.
//!
//! The library ships no signaling, so this binary carries the smallest
//! possible rendezvous: a `relay` subcommand that pairs the first two UDP
//! addresses that register and forwards every later datagram between them.
//! A registration is the single byte `R`. Library frames are never one byte,
//! so the relay never mistakes a frame for a registration.
//!
//! Three terminals, two of them on different networks for a real NAT path:
//!
//! ```text
//! punch-demo relay 0.0.0.0:9000
//! punch-demo punch --role initiator --relay 203.0.113.5:9000
//! punch-demo punch --role responder --relay 203.0.113.5:9000
//! ```
//!
//! STUN defaults to four public servers, pass `--stun` to override. Each
//! side prints its NAT class, the chosen strategy, and the estimate, then
//! exchanges one business datagram over the punched socket.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use punch_hole::{PunchConfig, Puncher};
use tokio::{net::UdpSocket, time::timeout};

const USAGE: &str = "usage:
  punch-demo relay <bind-addr>
  punch-demo punch --role <initiator|responder> --relay <addr> [--stun <host:port,...>] [--target \
                     <probability>]";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result: Result<(), Box<dyn std::error::Error>> = match args.first().map(String::as_str) {
        Some("relay") => match args.get(1) {
            Some(bind) => relay(bind).await,
            None => Err(format!("relay needs a bind address\n{USAGE}").into()),
        },
        Some("punch") => punch(&args[1..]).await,
        _ => Err(USAGE.to_owned().into()),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Forwards datagrams between the first two addresses that register.
///
/// A third address is ignored until a slot frees, which keeps a demo run
/// from pairing strangers.
async fn relay(bind: &str) -> Result<(), Box<dyn std::error::Error>> {
    let sock = UdpSocket::bind(bind).await?;
    println!("relay listening on {}", sock.local_addr()?);
    let mut slots: [Option<SocketAddr>; 2] = [None, None];
    let mut buf = [0u8; 2048];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        match slots.iter().position(|s| *s == Some(from)) {
            Some(i) => {
                if let Some(peer) = slots[1 - i] {
                    sock.send_to(&buf[..n], peer).await?;
                }
            },
            None if n == 1 && buf[0] == b'R' => {
                if let Some(free) = (0..2).find(|i| slots[*i].is_none()) {
                    slots[free] = Some(from);
                    println!("slot {free}: {from}");
                }
            },
            None => {},
        }
    }
}

struct Args {
    role: String,
    relay: SocketAddr,
    stun: Option<String>,
    target: Option<f64>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut role = None;
    let mut relay = None;
    let mut stun = None;
    let mut target = None;
    let mut i = 0;
    while i < args.len() {
        let take = |i: &mut usize| {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{} needs a value\n{USAGE}", args[*i - 1]))
        };
        match args[i].as_str() {
            "--role" => role = Some(take(&mut i)?),
            "--relay" => relay = Some(take(&mut i)?),
            "--stun" => stun = Some(take(&mut i)?),
            "--target" => {
                let raw = take(&mut i)?;
                target = Some(
                    raw.parse()
                        .map_err(|_| format!("--target is not a probability\n{USAGE}"))?,
                );
            },
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
        i += 1;
    }
    let role = role.ok_or_else(|| format!("--role is required\n{USAGE}"))?;
    if role != "initiator" && role != "responder" {
        return Err(format!("role must be initiator or responder\n{USAGE}"));
    }
    let relay = relay
        .ok_or_else(|| format!("--relay is required\n{USAGE}"))?
        .parse()
        .map_err(|_| format!("--relay is not an address\n{USAGE}"))?;
    Ok(Args {
        role,
        relay,
        stun,
        target,
    })
}

async fn punch(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let a = parse_args(args)?;
    let mut cfg = PunchConfig::default();
    if let Some(list) = &a.stun {
        cfg.stun_servers = list.split(',').map(|s| s.trim().to_owned()).collect();
    }
    if let Some(t) = a.target {
        cfg.target_success = t;
        cfg.min_success = cfg.min_success.min(t);
    }
    // Both terminals must join inside the exchange window, so the demo waits
    // longer than the default for the second side.
    cfg.exchange_timeout = Duration::from_secs(30);
    // A demo wants its attempt to land, so aim high by default; the model
    // sizes the burst for this rate.
    if a.target.is_none() {
        cfg.target_success = 0.9;
    }

    // Signaling transport: one UDP socket pointed at the relay. The pump
    // below moves frames between the bridge and this socket.
    let any = if a.relay.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(any).await?;
    sock.connect(a.relay).await?;
    // Register so the relay learns this address before frames flow.
    sock.send(b"R").await?;
    println!("signaling through {} from {}", a.relay, sock.local_addr()?);

    let (host_end, lib_end) = punch_hole::signaling::bridge(64);
    pump(Arc::new(sock), host_end);

    let session = Puncher::new(cfg)?.with_signaling(lib_end);
    let punched = if a.role == "initiator" {
        session.initiator().await?
    } else {
        session.responder().await?
    };

    let r = &punched.report;
    println!("local NAT  : {:?}", r.local_class);
    println!("peer NAT   : {:?}", r.peer_class);
    let estimate = r
        .success_estimate
        .map_or("-".to_owned(), |v| format!("{v:.2}"));
    println!("strategy   : {:?} (estimate {estimate})", r.strategy);
    println!(
        "path       : peer {} from local port {}",
        punched.peer_addr, r.winner_local_port
    );
    println!(
        "phases ms  : probe {} exchange {} negotiate {} punch {} confirm {}",
        r.phase_ms.probe_ms,
        r.phase_ms.exchange_ms,
        r.phase_ms.negotiate_ms,
        r.phase_ms.punch_ms,
        r.phase_ms.confirm_ms
    );

    demo_traffic(&punched.socket, punched.peer_addr, &a.role).await?;
    println!("business datagram exchanged over the direct path");
    Ok(())
}

/// Moves frames between the bridge and the signaling socket.
///
/// One datagram is one frame. Frames stay under the signaling size cap, so
/// no length prefix is needed. `connect` filters every source except the
/// relay, so whatever arrives here is a peer frame.
fn pump(sock: Arc<UdpSocket>, end: punch_hole::signaling::HostEnd) {
    let mut to_peer = end.to_peer;
    let from_peer = end.from_peer;
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            tokio::select! {
                frame = to_peer.recv() => {
                    let Some(frame) = frame else { break };
                    if sock.send(&frame).await.is_err() {
                        break;
                    }
                }
                received = sock.recv_from(&mut buf) => match received {
                    Ok((n, _)) => {
                        let frame = Bytes::copy_from_slice(&buf[..n]);
                        if from_peer.send(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
            }
        }
    });
}

/// One datagram each way over the winner socket proves the path.
async fn demo_traffic(
    sock: &UdpSocket,
    peer: SocketAddr,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 64];
    if role == "initiator" {
        sock.send_to(b"ping", peer).await?;
        let (n, _) = recv_with_deadline(sock, &mut buf).await?;
        if &buf[..n] != b"pong" {
            return Err("peer sent unexpected business data".into());
        }
    } else {
        let (n, from) = recv_with_deadline(sock, &mut buf).await?;
        if &buf[..n] != b"ping" {
            return Err("peer sent unexpected business data".into());
        }
        sock.send_to(b"pong", from).await?;
    }
    Ok(())
}

async fn recv_with_deadline(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> Result<(usize, SocketAddr), Box<dyn std::error::Error>> {
    let received = timeout(Duration::from_secs(10), sock.recv_from(buf))
        .await
        .map_err(|_| "no business datagram within 10 s")?;
    received.map_err(Into::into)
}
