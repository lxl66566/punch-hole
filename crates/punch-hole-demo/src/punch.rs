//! The client and server sides: register with the relay, punch, then chat.

use std::{
    io::BufRead,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use bytes::Bytes;
use punch_hole::{
    NatInfo, PunchConfig, Punched, Puncher, Role, SessionEvent, msg::Nonce, signaling::HostEnd,
};
use tokio::{net::UdpSocket, sync::mpsc, time::timeout};

use crate::PunchArgs;

/// Longest chat line sent as one datagram. Fits one unfragmented datagram
/// on a typical path.
const MAX_LINE: usize = 1400;

/// Registers with the relay, runs one session as `role`, and hands the
/// punched socket to the chat.
pub async fn run(role: Role, args: &PunchArgs) -> anyhow::Result<()> {
    let mut cfg = PunchConfig::default();
    if !args.stun.is_empty() {
        cfg.stun_servers = args.stun.iter().map(|s| s.trim().to_owned()).collect();
    }
    // A demo wants its attempt to land, so it aims high by default; the
    // model sizes the burst for this rate.
    cfg.target_success = args.target;
    cfg.min_success = cfg.min_success.min(args.target);
    // Both terminals must join inside the exchange window, so the demo waits
    // longer than the library default for the second side. The session wall
    // moves with it, so the phases after exchange keep the budget the
    // library default leaves them.
    let exchange = Duration::from_secs(args.exchange_timeout);
    cfg.overall_deadline = cfg.overall_deadline.saturating_sub(cfg.exchange_timeout) + exchange;
    cfg.exchange_timeout = exchange;

    let sock = register(args.relay).await?;
    println!(
        "{}: signaling through {} from {}",
        role_name(role),
        args.relay,
        sock.local_addr()?
    );

    let (host_end, lib_end) = punch_hole::signaling::bridge(64);
    pump(Arc::new(sock), host_end);

    let (events_tx, events_rx) = mpsc::channel(8);
    let printer = tokio::spawn(print_events(events_rx));
    let session = Puncher::new(cfg)?
        .with_events(events_tx)
        .with_signaling(lib_end);
    let result = match role {
        Role::Initiator => session.initiator().await,
        Role::Responder => session.responder().await,
    };
    // The finished session dropped its sender, so the printer drains the
    // last events and ends before the summary prints.
    let _ = printer.await;

    let punched = match result {
        Ok(punched) => punched,
        Err(failure) => {
            let d = &failure.diagnostics;
            println!("punch failed : {failure}");
            println!(
                "evidence     : local {:?} peer {:?} plan {:?}",
                d.local.as_ref().map(NatInfo::v4_class),
                d.peer.as_ref().map(NatInfo::v4_class),
                d.selection
            );
            return Err(failure.into());
        },
    };
    print_report(&punched);

    // The heartbeat holds the mapping open while neither user types.
    let socket = Arc::new(punched.socket);
    let _keepalive = punch_hole::keepalive::spawn_io(
        Arc::clone(&socket),
        punched.peer_addr,
        punched.report.nonce,
    );
    chat(&socket, punched.peer_addr, punched.report.nonce, role).await
}

/// Binds the signaling socket and completes the relay's registration.
///
/// The relay answers `R` with a random token, and echoing it back proves
/// this address receives its own datagrams. `connect` filters every source
/// except the relay, so whatever arrives later is a peer frame.
async fn register(relay: SocketAddr) -> anyhow::Result<UdpSocket> {
    let any = if relay.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let sock = UdpSocket::bind(any).await?;
    sock.connect(relay).await?;
    sock.send(b"R").await?;
    let mut ack = [0u8; 16];
    let n = timeout(Duration::from_secs(5), sock.recv(&mut ack))
        .await
        .context("no registration answer from the relay within 5 s")??;
    if n != 9 || ack[0] != b'A' {
        bail!("unexpected registration answer from the relay");
    }
    let mut verify = Vec::with_capacity(9);
    verify.push(b'V');
    verify.extend_from_slice(&ack[1..9]);
    sock.send(&verify).await?;
    Ok(sock)
}

/// Moves frames between the bridge and the signaling socket.
///
/// One datagram is one frame. Frames stay under the signaling size cap, so
/// no length prefix is needed. `connect` filters every source except the
/// relay, so whatever arrives here is a peer frame.
fn pump(sock: Arc<UdpSocket>, end: HostEnd) {
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

/// Prints each stage as the session completes it, stamped with the time
/// since the session began.
async fn print_events(mut rx: mpsc::Receiver<SessionEvent>) {
    let start = Instant::now();
    while let Some(event) = rx.recv().await {
        let ms = start.elapsed().as_millis();
        match event {
            SessionEvent::Probe(nat) => {
                println!("[{ms:>6} ms] probe     : local NAT {}", describe_nat(&nat));
                println!("[{ms:>6} ms] exchange  : waiting for the peer");
            },
            SessionEvent::Exchange(nat) => {
                println!("[{ms:>6} ms] exchange  : peer NAT {}", describe_nat(&nat));
            },
            SessionEvent::Negotiate(plan) => {
                println!(
                    "[{ms:>6} ms] negotiate : {:?}, {} initiator + {} responder sockets, estimate \
                     {}",
                    plan.strategy,
                    plan.initiator_sockets,
                    plan.responder_sockets,
                    estimate(plan.estimate)
                );
                println!("[{ms:>6} ms] punch     : running");
            },
            _ => {},
        }
    }
}

/// One line of NAT evidence: the IPv4 class and reflexive address with the
/// filtering reading, plus the global IPv6 count.
fn describe_nat(nat: &NatInfo) -> String {
    let v4 = match &nat.v4 {
        Some(v4) => format!(
            "{:?} via {} ({:?} filtering)",
            v4.class, v4.reflexive, v4.filtering
        ),
        None => "no IPv4 evidence".to_owned(),
    };
    match &nat.v6 {
        Some(v6) if !v6.addrs.is_empty() => format!("{v4}, {} global IPv6", v6.addrs.len()),
        _ => v4,
    }
}

fn estimate(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |v| format!("{v:.2}"))
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Initiator => "initiator",
        Role::Responder => "responder",
    }
}

/// The summary the session returned.
fn print_report(punched: &Punched) {
    let r = &punched.report;
    println!(
        "connected  : peer {} from local port {}",
        punched.peer_addr, r.winner_local_port
    );
    println!("local NAT  : {:?}", r.local_class);
    println!("peer NAT   : {:?}", r.peer_class);
    println!(
        "strategy   : {:?} (estimate {})",
        r.strategy,
        estimate(r.success_estimate)
    );
    println!(
        "phases ms  : probe {} exchange {} negotiate {} punch {} confirm {} total {}",
        r.phase_ms.probe_ms,
        r.phase_ms.exchange_ms,
        r.phase_ms.negotiate_ms,
        r.phase_ms.punch_ms,
        r.phase_ms.confirm_ms,
        r.phase_ms.total_ms
    );
    println!(
        "packets    : {} sent, {} stale",
        r.packets_sent, r.stale_packets
    );
}

/// Line-oriented chat over the punched socket.
///
/// Each stdin line is one datagram to the peer and each peer datagram
/// prints as one line. Late handshake retransmissions and keepalive beats
/// of this attempt still arrive on the handed-over socket, so the receive
/// side drops them by nonce before it prints.
async fn chat(sock: &UdpSocket, peer: SocketAddr, nonce: Nonce, role: Role) -> anyhow::Result<()> {
    println!("chat ready : every line goes to the peer; /quit or end of input closes");
    sock.send_to(
        format!("hello from the {}", role_name(role)).as_bytes(),
        peer,
    )
    .await?;
    let mut lines = stdin_lines();
    let mut buf = [0u8; 2048];
    loop {
        tokio::select! {
            line = lines.recv() => match line {
                None => break,
                Some(line) if line.trim() == "/quit" => break,
                Some(line) if line.is_empty() => {},
                Some(line) if line.len() > MAX_LINE => {
                    println!("line not sent: {} bytes, the cap is {MAX_LINE}", line.len());
                },
                Some(line) => {
                    sock.send_to(line.as_bytes(), peer).await?;
                },
            },
            received = sock.recv_from(&mut buf) => {
                let (n, from) = received?;
                if punch_hole::msg::is_attempt_packet(&buf[..n], nonce) {
                    continue;
                }
                println!("[{from}] {}", String::from_utf8_lossy(&buf[..n]));
            },
        }
    }
    println!("chat closed");
    Ok(())
}

/// Feeds stdin lines through a channel from a plain thread.
///
/// A blocking read on a tokio worker would hold the runtime open at exit
/// until the user presses Enter; a detached thread dies with the process.
fn stdin_lines() -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel(16);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if tx.blocking_send(line).is_err() {
                break;
            }
        }
    });
    rx
}
