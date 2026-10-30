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
//! a mapping policy ([`Mapping`]) crossed with an inbound filtering class
//! ([`FilterClass`]) over a port range. A suite that asserts mapping and
//! filtering behavior can parameterize over the engine and keep one set of
//! expectations.
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

pub use lab::{LabHost, LabSocket, NatLab, StunServer, stun_responder};
pub use sim::{FilterClass, Host, Mapping, NatSpec, Net, SimSocket};
pub use socket::{Family, UdpFactory, UdpIo};

/// The largest UDP payload the loopback lab forwards: the IPv4 datagram
/// limit. The virtual network carries any payload size.
pub const MAX_DATAGRAM: usize = 65507;
