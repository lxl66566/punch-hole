//! What NAT does this machine sit behind? Runs the Probe phase alone.
//!
//! `Puncher::probe` is the classification half of a session on its own: it
//! queries the configured STUN servers and returns the `NatInfo` a full
//! session would exchange with the peer. A host uses it to show the
//! network shape before dialing, to decide whether an attempt is worth its
//! budget, or to refresh a classification before feeding it back through
//! `Puncher::with_cached_nat`, which skips Probe on the next attempt.
//!
//! ```sh
//! cargo run --example nat_probe
//! cargo run --example nat_probe -- stun.example.com:3478
//! ```

use punch_hole::{FilterClass, NatClass, NatInfo, PunchConfig, Puncher};

#[tokio::main]
async fn main() -> Result<(), punch_hole::PunchError> {
    // The default STUN list carries four public servers; hosts behind a
    // restrictive network pass their own.
    let mut config = PunchConfig::default();
    let servers: Vec<String> = std::env::args().skip(1).collect();
    if !servers.is_empty() {
        config.stun_servers = servers;
    }

    let nat = Puncher::new(config)?.probe().await?;
    describe(&nat);
    Ok(())
}

/// Prints the classification with what each reading means for punching.
fn describe(nat: &NatInfo) {
    match &nat.v4 {
        Some(v4) => {
            let class = match v4.class {
                NatClass::Public => {
                    "public: the reflexive address is this host's own, no NAT in front".to_owned()
                },
                NatClass::Cone => {
                    "cone: one external port per socket, the friendliest shape".to_owned()
                },
                NatClass::EasySym { step } => format!(
                    "easy symmetric: a fresh port per destination, walking by {step}, so the next \
                     ports are predictable"
                ),
                NatClass::HardSym => {
                    "hard symmetric: a fresh unpredictable port per destination".to_owned()
                },
            };
            println!("IPv4 class    : {class}");
            println!(
                "IPv4 reflexive: {} (the address the internet sees)",
                v4.reflexive
            );
            println!(
                "port history  : {:?} (external ports the probe observed, in order)",
                v4.alloc_seq
            );
            let filtering = match v4.filtering {
                FilterClass::EndpointIndependent => {
                    "endpoint-independent: any source that learns the port can send in"
                },
                FilterClass::AddressDependent => {
                    "address-dependent: only hosts the socket already wrote to can send in"
                },
                FilterClass::AddressPortDependent => {
                    "address-and-port-dependent: only exact destinations already written to can \
                     answer"
                },
                FilterClass::Unknown => {
                    "unknown: no STUN server advertised a second address to test from"
                },
            };
            println!("filtering     : {filtering}");
            println!(
                "hairpin       : {} (whether two hosts behind this same NAT can loop through it)",
                if v4.hairpin { "yes" } else { "no" }
            );
        },
        None => println!("IPv4          : no evidence (no STUN server answered)"),
    }
    match &nat.v6 {
        Some(v6) if !v6.addrs.is_empty() => println!(
            "IPv6          : {} global address(es); a direct path that needs no punching",
            v6.addrs.len()
        ),
        _ => println!("IPv6          : none observed"),
    }
    println!(
        "\nA full session exchanges this reading with the peer and picks a strategy over the \
         pair; `with_cached_nat(nat)` reuses this reading to skip Probe."
    );
}
