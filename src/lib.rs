//! Signaling-agnostic UDP hole punching primitives.
//!
//! `punch-hole` establishes a direct UDP path between two peers behind NAT
//! devices. The host application owns peer discovery and the control channel:
//! it forwards the library's opaque frames to the peer and feeds peer frames
//! back. A successful session returns a plain `tokio::net::UdpSocket` with no
//! wrapper and no library state.
//!
//! The layers, the session lifecycle, and the strategy matrix are specified
//! in `ARCHITECTURE.md`; the wire formats live in `PROTOCOL.md`; the test
//! architecture lives in `TESTING.md`. A runnable two-terminal demo lives in
//! `examples/punch-demo.rs`.
//!
//! # Trust model
//!
//! The signaling plane carries no authentication of its own. The host must
//! authenticate the peer and reject replayed bytes on its own transport
//! before it pushes anything into `HostEnd::from_peer`; frames from the
//! authenticated peer are then trusted as peer input.
//!
//! The data plane tags every packet with the 128-bit attempt nonce, so a
//! third party cannot inject packets into a live attempt.
//!
//! Undecodable signaling frames are dropped and reception continues, which
//! keeps a stray datagram on a shared host channel from ending the session.
//! A signaling version mismatch aborts the session, because no productive
//! exchange can follow it.
//!
//! # Example
//!
//! One side of a session, with the host's own transport already in place:
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use punch_hole::{PunchConfig, PunchError, Puncher};
//!
//! async fn run_initiator_side() -> Result<(), PunchError> {
//!     let puncher = Puncher::new(PunchConfig::default())?;
//!
//!     let (host_end, lib_end) = punch_hole::signaling::bridge(64);
//!
//!     // The host pumps its own transport against the bridge: deliver
//!     // host_end.to_peer frames to the peer, and push frames that arrive
//!     // from the peer into host_end.from_peer.
//!
//!     let punched = puncher.with_signaling(lib_end).initiator().await?;
//!
//!     // The business layer owns the winner from here. Tokio sockets have
//!     // no Clone, so share it behind an Arc; the optional heartbeat keeps
//!     // the NAT mapping open while the host idles.
//!     let socket = Arc::new(punched.socket);
//!     let _guard = punch_hole::keepalive::spawn(
//!         Arc::clone(&socket),
//!         punched.peer_addr,
//!         punched.report.nonce,
//!     );
//!     let _ = socket; // send and receive business traffic
//!
//!     Ok(())
//! }
//! ```
//!
//! The Responder side runs the same code with `.responder()`.

// Port and packet arithmetic works on small fixed-width integers by design,
// and most public constructors return fresh values, so the corresponding
// pedantic lint families are noise here.
#![allow(
    clippy::must_use_candidate,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss
)]

pub mod config;
pub mod error;
pub mod keepalive;
pub mod msg;
pub mod nat;
pub mod report;
pub mod signaling;
pub mod socket;

#[cfg(feature = "test-util")]
pub mod natlab;

#[cfg(feature = "test-util")]
pub mod sim;

mod session;
mod strategy;

pub use config::PunchConfig;
pub use error::{Phase, PunchError};
pub use msg::{AbortReason, StrategyId};
pub use nat::{FilterClass, NatClass, NatInfo, PortPredictor};
pub use report::{PhaseDurations, PunchReport, Role};
pub use session::{PunchSession, Punched, Puncher};
pub use signaling::{HostEnd, LibEnd, bridge};
pub use socket::{Family, TokioFactory, UdpFactory, UdpIo};
