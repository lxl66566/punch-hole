//! Session errors and phase names.

use crate::{msg::AbortReason, nat::NatClass, report::SessionDiagnostics};

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
    /// No configured STUN server resolved to an IPv4 address, so the
    /// probe had no destination to query.
    #[error("no STUN server resolved to an IPv4 address")]
    NoStunDestination,
    /// Every socket the pool tried to bind failed, so the session has no
    /// socket to punch with. `source` is the last bind failure and names
    /// the real cause, such as descriptor exhaustion.
    #[error("every pool socket failed to bind: {source}")]
    BindFailed {
        #[source]
        source: std::io::Error,
    },
    /// The pool's receive tasks all stopped while the engine still ran.
    ///
    /// A receive task ends only by cancellation or a failed socket, and
    /// cancellation has not run at that point, so the pool lost its
    /// sockets to errors it does not attribute to one address.
    #[error("pool receive tasks stopped")]
    PoolStopped,
    /// A STUN refresh the plan depends on could not run: no server
    /// resolved or no IPv4 socket bound to query from.
    #[error("stun refresh unavailable: no server or bound socket")]
    RefreshUnavailable,
    /// A STUN refresh the plan depends on sent its retries and none
    /// answered before any handshake traffic arrived.
    #[error("stun refresh retries exhausted")]
    RefreshExhausted,
    /// A target derived from peer-signaled data cannot carry punch
    /// traffic: port zero, or an unspecified, multicast, or broadcast
    /// address. Loopback stays valid.
    #[error("unusable punch target {target}: {reason}")]
    UnusableTarget {
        target: std::net::SocketAddr,
        reason: &'static str,
    },
    /// A state this crate treats as unreachable: a bug, not a network
    /// condition. The detail names the invariant that broke.
    #[error("internal error: {0}")]
    Internal(&'static str),
    /// The configuration failed validation.
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
    /// A real socket error from the phase that produced it.
    ///
    /// Only Probe and the punch engine construct these, and the source is
    /// always an OS error; states the library derives itself carry
    /// dedicated variants. The engine covers the Punch and Confirm
    /// windows as one phase, so failures from its post-handshake window
    /// still report `Phase::Punch`.
    #[error("phase {phase:?} io: {source}")]
    Io {
        phase: Phase,
        #[source]
        source: std::io::Error,
    },
}

/// A failed session: the phase-level error plus the evidence the session
/// had collected when it stopped.
///
/// `PunchError` stays the match target; `diagnostics` answers why the
/// failed phase came to that end. The session assembles the failure at
/// its boundary, so the diagnostics always belong to the error they
/// travel with.
#[derive(Debug, thiserror::Error)]
#[error("punch session failed: {error}")]
pub struct PunchFailure {
    /// The phase-level failure. Match on this.
    #[source]
    pub error: PunchError,
    /// What the session had learned before it stopped.
    pub diagnostics: SessionDiagnostics,
}

impl From<PunchError> for PunchFailure {
    /// Wraps a failure from before the session ran, which by definition
    /// collected no evidence; `Puncher::new` failures land here.
    fn from(error: PunchError) -> Self {
        Self {
            error,
            diagnostics: SessionDiagnostics::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error chain names the phase error as the source, so generic
    /// host code that walks sources sees the real cause.
    #[test]
    fn failure_sources_the_phase_error() {
        let failure = PunchFailure::from(PunchError::BudgetExhausted);
        assert!(matches!(failure.error, PunchError::BudgetExhausted));
        let as_dyn: &dyn std::error::Error = &failure;
        let source = as_dyn.source().expect("failure names its source");
        assert!(matches!(
            source.downcast_ref::<PunchError>(),
            Some(PunchError::BudgetExhausted)
        ));
        // A pre-session failure carries no evidence.
        let SessionDiagnostics {
            local,
            peer,
            selection,
            nonce,
            phase_ms,
        } = failure.diagnostics;
        assert!(local.is_none() && peer.is_none() && selection.is_none());
        assert!(nonce.is_none());
        assert_eq!(phase_ms, crate::report::PhaseDurations::default());
    }
}
