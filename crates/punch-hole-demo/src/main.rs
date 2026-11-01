//! A two-terminal demo of one full punch session over real sockets.
//!
//! The library ships no signaling, so this binary carries the smallest
//! possible rendezvous: a `relay` subcommand that pairs the first two UDP
//! addresses that complete a registration and forwards every later datagram
//! between them. The `client` and `server` subcommands register with that
//! relay, punch as the session Initiator and Responder, print each stage as
//! it completes, and then chat over the punched socket line by line.
//!
//! Three terminals, two of them on different networks for a real NAT path:
//!
//! ```text
//! punch-demo relay 0.0.0.0:9000
//! punch-demo client --relay 203.0.113.5:9000
//! punch-demo server --relay 203.0.113.5:9000
//! ```
//!
//! STUN defaults to the library's public servers, pass `--stun` to override.
//! The relay authenticates nobody and belongs on a trusted network.

mod punch;
mod relay;

use std::net::SocketAddr;

use clap::{Args, Parser, Subcommand};
use punch_hole::Role;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Pair the first two registered addresses and forward datagrams between
    /// them.
    Relay {
        /// Address to listen on, for example 0.0.0.0:9000.
        bind: SocketAddr,
    },
    /// Punch as the session Initiator, then chat over the punched socket.
    Client(PunchArgs),
    /// Punch as the session Responder, then chat over the punched socket.
    Server(PunchArgs),
}

/// Options shared by the two punching sides.
#[derive(Args)]
pub struct PunchArgs {
    /// The relay both sides register with.
    #[arg(long)]
    pub relay: SocketAddr,
    /// STUN servers as host:port, comma separated. Defaults to the library's
    /// public set.
    #[arg(long, value_delimiter = ',')]
    pub stun: Vec<String>,
    /// Success rate the burst sizing aims for.
    #[arg(long, default_value_t = 0.9)]
    pub target: f64,
    /// Seconds the exchange waits for the peer to join.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    pub exchange_timeout: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Relay { bind } => relay::run(bind).await,
        Command::Client(args) => punch::run(Role::Initiator, &args).await,
        Command::Server(args) => punch::run(Role::Responder, &args).await,
    }
}
