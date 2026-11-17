//! A full session through simulated NATs, with no network at all.
//!
//! The `test-util` feature wires the `nat-lab` simulator into the
//! library's socket seam, so a session runs against scripted NAT shapes on
//! a seeded virtual network. Hosts use this to test their integration
//! offline, and it makes the strategy matrix visible: each pair of NAT
//! shapes negotiates a different punching algorithm.
//!
//! ```sh
//! cargo run --example simulated_nat_pair --features test-util -- cone-cone
//! cargo run --example simulated_nat_pair --features test-util -- easy-easy
//! cargo run --example simulated_nat_pair --features test-util -- hard-cone
//! cargo run --example simulated_nat_pair --features test-util -- hard-hard
//! ```
//!
//! Without an argument the run walks every scenario.

use nat_lab::sim::{NatSpec, Net, SimSocket, StunServer};
use punch_hole::{PunchConfig, Punched, Puncher, msg, socket::UdpIo};

/// How many fresh tries a scenario gets. The probabilistic strategies can
/// miss a draw, and a fresh try draws a fresh nonce, the same retry a real
/// host owns.
const TRIES: usize = 5;

/// The NAT shape each side sits behind for one scenario.
enum Scenario {
    /// Cone against cone: one socket per side aimed at the other's
    /// reflexive address (`ConeExchange`).
    ConeCone,
    /// Sequential symmetric on both sides: each side continues the peer's
    /// port walk (`PredictiveExchange`).
    EasyEasy,
    /// Random symmetric dialer against a cone answerer: the symmetric side
    /// sprays while the cone side waits (`SymProbe`).
    HardCone,
    /// Random symmetric on both sides: a birthday attack over both port
    /// spaces (`BirthdayBurst`).
    HardHard,
}

fn parse_args() -> Vec<Scenario> {
    let names: Vec<String> = std::env::args().skip(1).collect();
    if names.is_empty() {
        return vec![
            Scenario::ConeCone,
            Scenario::EasyEasy,
            Scenario::HardCone,
            Scenario::HardHard,
        ];
    }
    let mut scenarios = Vec::new();
    for name in &names {
        let scenario = match name.as_str() {
            "cone-cone" => Scenario::ConeCone,
            "easy-easy" => Scenario::EasyEasy,
            "hard-cone" => Scenario::HardCone,
            "hard-hard" => Scenario::HardHard,
            _ => {
                eprintln!("unknown scenario {name}: cone-cone, easy-easy, hard-cone, hard-hard");
                std::process::exit(2);
            },
        };
        scenarios.push(scenario);
    }
    scenarios
}

/// The two NAT shapes one scenario runs.
fn specs(scenario: &Scenario) -> (NatSpec, NatSpec) {
    // A ten-thousand-port space keeps the model's estimate above
    // `min_success` under the default budget, so the scenario runs instead
    // of refusing the pair.
    let hard = || NatSpec::random(30_000..40_000);
    match scenario {
        Scenario::ConeCone => (NatSpec::cone_apdf(), NatSpec::cone_apdf()),
        Scenario::EasyEasy => (NatSpec::sequential(2), NatSpec::sequential(2)),
        Scenario::HardCone => (hard(), NatSpec::cone_apdf()),
        Scenario::HardHard => (hard(), hard()),
    }
}

#[tokio::main]
async fn main() {
    for scenario in parse_args() {
        println!("=== {} ===", scenario_name(&scenario));
        let Some((a, b)) = run_scenario(&scenario).await else {
            eprintln!(
                "{}: every try missed; raise `target_success` or the budget",
                scenario_name(&scenario)
            );
            std::process::exit(1);
        };
        print_report("initiator", &a);
        print_report("responder", &b);
        ping_pong(a, b).await;
    }
}

/// One try per fresh network; `None` means this try missed.
async fn run_once(
    scenario: &Scenario,
    try_no: usize,
) -> Option<(Punched<SimSocket>, Punched<SimSocket>)> {
    // A fresh seeded net per try, so each draw is its own network.
    let net = Net::seeded(&format!("{}-{try_no}", scenario_name(scenario)));
    // Two STUN servers feed the fan-out: a confident cone reading needs at
    // least two distinct server IPs behind it. No `other_addrs` means the
    // probe cannot measure inbound filtering, which reads as `Unknown`.
    let mut addrs = net.stun_server().addrs;
    addrs.extend(net.stun_server().addrs);
    let stun = StunServer {
        addrs,
        other_addrs: Vec::new(),
    };
    let config = PunchConfig {
        stun_servers: stun.addrs.clone(),
        ..PunchConfig::default()
    };

    let (spec_a, spec_b) = specs(scenario);
    let (host_a, lib_a) = punch_hole::signaling::bridge(64);
    let (host_b, lib_b) = punch_hole::signaling::bridge(64);
    // `connect` is the lossless wire `test-util` provides; a host writes
    // its own pump over its real transport, as the other examples do.
    punch_hole::signaling::connect(host_a, host_b);

    // The simulator hosts plug straight into the socket seam.
    let host_a = net.host(spec_a);
    let host_b = net.host(spec_b);
    let initiator = {
        let config = config.clone();
        tokio::spawn(async move {
            Puncher::with_factory(config, host_a)
                .expect("the scenario config validates")
                .with_signaling(lib_a)
                .initiator()
                .await
        })
    };
    let responder = tokio::spawn(async move {
        Puncher::with_factory(config, host_b)
            .expect("the scenario config validates")
            .with_signaling(lib_b)
            .responder()
            .await
    });

    let a = initiator.await.expect("the initiator task joined");
    let b = responder.await.expect("the responder task joined");
    match (a, b) {
        (Ok(a), Ok(b)) => Some((a, b)),
        (a, b) => {
            println!(
                "try {try_no}: initiator {}, responder {}",
                outcome(&a),
                outcome(&b)
            );
            None
        },
    }
}

/// Runs tries until both sides punch.
async fn run_scenario(scenario: &Scenario) -> Option<(Punched<SimSocket>, Punched<SimSocket>)> {
    for try_no in 1..=TRIES {
        if let Some(pair) = run_once(scenario, try_no).await {
            println!("try {try_no}: connected via {:?}", pair.0.report.strategy);
            return Some(pair);
        }
    }
    None
}

/// One datagram each way over the winner sockets, skipping the handshake
/// and heartbeat packets that still arrive around handover.
async fn ping_pong(a: Punched<SimSocket>, b: Punched<SimSocket>) {
    let replier = tokio::spawn(async move {
        let sock = b.socket;
        let nonce = b.report.nonce;
        let mut buf = [0u8; 64];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await.expect("sim receive");
            if msg::is_attempt_packet(&buf[..n], nonce) {
                continue;
            }
            sock.send_to(&buf[..n], from).await.expect("sim echo");
            return;
        }
    });
    a.socket
        .send_to(b"ping", a.peer_addr)
        .await
        .expect("sim send");
    let mut buf = [0u8; 64];
    loop {
        let (n, _from) = a.socket.recv_from(&mut buf).await.expect("sim receive");
        if msg::is_attempt_packet(&buf[..n], a.report.nonce) {
            continue;
        }
        println!(
            "business datagram round-tripped: {}",
            String::from_utf8_lossy(&buf[..n])
        );
        break;
    }
    replier.await.expect("the replier task joined");
}

fn scenario_name(scenario: &Scenario) -> &'static str {
    match scenario {
        Scenario::ConeCone => "cone-cone",
        Scenario::EasyEasy => "easy-easy",
        Scenario::HardCone => "hard-cone",
        Scenario::HardHard => "hard-hard",
    }
}

fn print_report(side: &str, punched: &Punched<SimSocket>) {
    let r = &punched.report;
    println!(
        "{side}: peer {} via {:?} (estimate {:?}, {} packets, {} ms)",
        punched.peer_addr, r.strategy, r.success_estimate, r.packets_sent, r.phase_ms.total_ms
    );
}

fn outcome(result: &Result<Punched<SimSocket>, punch_hole::PunchFailure>) -> String {
    match result {
        Ok(p) => format!("ok ({:?})", p.report.strategy),
        Err(f) => format!("{:?}", f.error),
    }
}
