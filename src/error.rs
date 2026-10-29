//! Session errors and phase names.

use crate::{msg::AbortReason, nat::NatClass};

/// The phase a session was in when it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Probe,
    Exchange,
    Negotiate,
    Punch,
    Confirm,
}

/// Every way a punch session can fail.
#[derive(Debug, thiserror::Error)]
pub enum PunchError {
    /// A phase or the whole session ran out of time.
    #[error("phase {phase:?} ran out of time")]
    Timeout { phase: Phase },
    /// The NAT pair has no workable strategy under the current budget.
    #[error("NAT pair has no workable strategy: {local:?} vs {peer:?}")]
    Unpunchable { local: NatClass, peer: NatClass },
    /// The configured packet budget ran out.
    #[error("packet budget exhausted")]
    BudgetExhausted,
    /// The conntrack bound, sockets times distinct destinations, ran out.
    #[error("conntrack bound exhausted")]
    ConntrackExhausted,
    /// The host closed the signaling bridge.
    #[error("host closed the signaling bridge")]
    SignalingClosed,
    /// The peer sent an Abort frame with this reason.
    #[error("peer aborted: {0:?}")]
    PeerAborted(AbortReason),
    /// The peers run different protocol versions.
    #[error("protocol version mismatch: local {local}, peer {peer}")]
    VersionMismatch { local: u8, peer: u8 },
    /// The data-plane handshake never completed both directions.
    #[error("data-plane handshake never completed both directions")]
    ConfirmFailed,
    /// The configuration failed validation.
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
    /// Socket or STUN level failure in the phase that produced it.
    ///
    /// Only Probe and the punch engine construct these. The engine covers
    /// the Punch and Confirm windows as one phase, so failures from its
    /// post-handshake window still report `Phase::Punch`.
    #[error("phase {phase:?} io: {source}")]
    Io {
        phase: Phase,
        #[source]
        source: std::io::Error,
    },
}
