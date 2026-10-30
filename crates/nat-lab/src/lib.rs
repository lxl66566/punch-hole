//! Emulated NAT devices for testing UDP traversal code.
//!
//! Testing NAT traversal needs a NAT. This crate provides two engines that
//! share one specification, so a suite can run the same scenario twice:
//!
//! - [`sim`] is a deterministic virtual network. Hosts, NATs, and STUN servers attach to one router
//!   task; randomness flows through one seeded generator. It runs under paused tokio time and
//!   finishes in milliseconds.
//! - [`lab`] is a userspace NAT forwarder over real OS sockets on the 127.0.0.0/8 space. Client
//!   sockets are real sockets, so the OS bind rules, ICMP quirks, and real timing all apply, and
//!   the code under test runs unmodified.
//!
//! Both engines translate and filter datagrams according to a [`NatSpec`]:
//! a mapping behavior ([`MappingBehavior`], which destinations reuse a
//! mapping) and an allocation policy ([`Allocation`], how a fresh external
//! port is chosen) crossed with an inbound filtering class
//! ([`FilterClass`]) over a port range, plus a hairpinning switch: a
//! datagram a client sends to its own NAT's external address loops back to
//! the sibling behind the same NAT as if from outside (RFC 4787 §6), or —
//! with hairpinning off — drops with a counter, like the broken no-loopback
//! NATs a puncher must survive. Both engines also stack one NAT behind an
//! upstream one ([`Net::host_behind`], [`NatLab::spawn_behind`]) — the
//! shape a CGNAT gives every home router — where the upstream allocates
//! the externally visible address and the inner NAT's public address is a
//! display label. A suite that asserts mapping, allocation, filtering,
//! hairpinning, and stacking behavior can parameterize over the engine and
//! keep one set of expectations.
//!
//! # Example
//!
//! A virtual NAT, queried through the built-in STUN server:
//!
//! ```no_run
//! # async fn demo() -> std::io::Result<()> {
//! use nat_lab::UdpFactory as _;
//!
//! let net = nat_lab::Net::seeded("demo");
//! let stun = net.stun_server();
//! let host = net.host(nat_lab::NatSpec::cone_eif());
//! let sock = host.bind(nat_lab::Family::V4.any_addr()).await?;
//! let _ = (stun, sock); // send STUN binding requests through the NAT
//! //
//! # Ok(())
//! # }
//! ```
//!
//! A loopback NAT with real sockets, plus the matching STUN responder:
//!
//! ```no_run
//! # async fn demo() -> std::io::Result<()> {
//! use nat_lab::UdpFactory as _;
//!
//! let stun = nat_lab::stun_responder()?;
//! let nat = nat_lab::NatLab::spawn("demo", nat_lab::NatSpec::cone_eif()).await?;
//! let host = nat.host();
//! let sock = host.bind(nat_lab::Family::V4.any_addr()).await?;
//! let _ = (stun, sock); // real sockets behind a real forwarder
//! //
//! # Ok(())
//! # }
//! ```

// Port and packet arithmetic works on small fixed-width integers by design,
// and most public constructors return fresh values, so the corresponding
// pedantic lint families are noise here. The lab's frame buffers are one
// full-size datagram each, which trips the large-array and large-future
// lints on every async step of the forwarding path.
#![allow(
    clippy::must_use_candidate,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::large_futures,
    clippy::large_stack_arrays,
    clippy::large_stack_frames
)]

pub mod lab;
pub mod sim;
pub mod socket;

mod stun;

pub use lab::{
    Direction, LabHost, LabSocket, NatLab, StunServer, Tap, TapDecision, TapEvent, stun_responder,
};
pub use sim::{Allocation, FilterClass, Host, MappingBehavior, NatSpec, Net, SimSocket};
pub use socket::{Family, UdpFactory, UdpIo};

/// The largest UDP payload the loopback lab forwards: the IPv4 datagram
/// limit. The virtual network carries any payload size.
pub const MAX_DATAGRAM: usize = 65507;
