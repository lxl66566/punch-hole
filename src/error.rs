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
