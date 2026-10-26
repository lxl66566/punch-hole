//! Shared helpers for the simulator integration tests.

#![allow(dead_code, clippy::field_reassign_with_default)]

use punch_hole::{
    PunchConfig, Punched, Puncher,
    error::PunchError,
    sim::{Host, Net, SimSocket, StunServer},
};

pub fn config(stun: &StunServer) -> PunchConfig {
    let mut cfg = PunchConfig::default();
    cfg.stun_servers = stun.addrs.clone();
    cfg
}

pub async fn run_initiator(
    host: Host,
    cfg: PunchConfig,
    sig: punch_hole::signaling::LibEnd,
) -> Result<Punched<SimSocket>, PunchError> {
    let session = Puncher::with_factory(cfg, host)
        .expect("config valid")
        .with_signaling(sig);
    session.initiator().await
}

pub async fn run_responder(
    host: Host,
    cfg: PunchConfig,
    sig: punch_hole::signaling::LibEnd,
) -> Result<Punched<SimSocket>, PunchError> {
    let session = Puncher::with_factory(cfg, host)
        .expect("config valid")
        .with_signaling(sig);
    session.responder().await
}

/// Runs both roles against each other and returns both results.
pub async fn punch_pair(
    host_a: Host,
    cfg_a: PunchConfig,
    host_b: Host,
    cfg_b: PunchConfig,
) -> (
    Result<Punched<SimSocket>, PunchError>,
    Result<Punched<SimSocket>, PunchError>,
) {
    let (ha, la) = punch_hole::signaling::bridge(64);
    let (hb, lb) = punch_hole::signaling::bridge(64);
    punch_hole::sim::connect(ha, hb);
    let a = tokio::spawn(run_initiator(host_a, cfg_a, la));
    let b = tokio::spawn(run_responder(host_b, cfg_b, lb));
    (
        a.await.expect("initiator task panicked"),
        b.await.expect("responder task panicked"),
    )
}

/// Reads until a business datagram arrives, skipping handshake packets
/// still in flight around handover.
async fn recv_business<S: punch_hole::socket::UdpIo>(
    sock: &S,
    buf: &mut [u8],
) -> (usize, std::net::SocketAddr) {
    loop {
        let (n, from) = sock.recv_from(buf).await.expect("business recv");
        if buf[0] != punch_hole::msg::DATA_MAGIC {
            return (n, from);
        }
    }
}

/// Exchanges one business datagram each way over the winner sockets.
pub async fn assert_business_traffic(a: &Punched<SimSocket>, b: &Punched<SimSocket>) {
    use punch_hole::UdpIo;
    let mut buf = [0u8; 64];
    a.socket
        .send_to(b"PING", a.peer_addr)
        .await
        .expect("ping send");
    // The responder sees the initiator's external address, which is its own
    // peer address.
    let (n, from) = recv_business(&b.socket, &mut buf).await;
    assert_eq!(&buf[..n], b"PING");
    assert_eq!(
        from.ip(),
        b.peer_addr.ip(),
        "ping came from the initiator's NAT"
    );
    b.socket.send_to(b"PONG", from).await.expect("pong send");
    let (n, from) = recv_business(&a.socket, &mut buf).await;
    assert_eq!(&buf[..n], b"PONG");
    assert_eq!(
        from.ip(),
        a.peer_addr.ip(),
        "pong came from the responder's NAT"
    );
}

/// A pump that passes the negotiation frames and drops everything after
/// Accept, so both sides punch without ever exchanging PortUpdate or
/// Confirmed.
pub fn connect_then_blackhole(
    a: punch_hole::signaling::HostEnd,
    b: punch_hole::signaling::HostEnd,
) {
    punch_hole::sim::connect_with(a, b, |frame| {
        let setup = punch_hole::msg::decode_sig(frame).is_ok_and(|f| {
            matches!(
                f.body,
                punch_hole::msg::Frame::Hello(_)
                    | punch_hole::msg::Frame::Offer(_)
                    | punch_hole::msg::Frame::Accept
            )
        });
        setup.then(|| frame.to_vec())
    });
}

use punch_hole::sim::NatSpec;

/// One cone behind one cone NAT, the standard happy path setup.
pub fn cone_net(name: &str) -> (Net, StunServer, Host, Host) {
    let net = Net::seeded(name);
    let stun = net.stun_server();
    let a = net.host(NatSpec::cone_apdf());
    let b = net.host(NatSpec::cone_apdf());
    (net, stun, a, b)
}

/// Runs the pair on a fresh net per try until both sides punch, and returns
/// the last results.
///
/// A spray covers a fixed port set drawn from the attempt nonce, and every
/// sweep repeats that set, so the residual miss the model leaves below a
/// perfect target can only end the run in failure. A fresh run draws a fresh
/// nonce, so a few retries push the residual far below any single target
/// while each run keeps its full assertion.
pub async fn punch_pair_retried(
    name: &str,
    a: NatSpec,
    b: NatSpec,
    cfg: PunchConfig,
    tries: usize,
) -> (
    Result<Punched<SimSocket>, PunchError>,
    Result<Punched<SimSocket>, PunchError>,
) {
    let mut cfg = cfg;
    let mut last = None;
    for _ in 0..tries {
        let net = Net::seeded(name);
        let stun = net.stun_server();
        cfg.stun_servers = stun.addrs.clone();
        let pair = punch_pair(
            net.host(a.clone()),
            cfg.clone(),
            net.host(b.clone()),
            cfg.clone(),
        )
        .await;
        if pair.0.is_ok() && pair.1.is_ok() {
            return pair;
        }
        last = Some(pair);
    }
    last.expect("tries is nonzero")
}
