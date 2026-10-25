//! Session configuration.

use std::time::Duration;

use crate::error::PunchError;

/// Every knob a session reads. All limits are enforced by the socket pool.
#[derive(Debug, Clone)]
pub struct PunchConfig {
    /// STUN servers as `host:port` strings. Classification needs at least four
    /// distinct destinations for a confident EasySym fit.
    pub stun_servers: Vec<String>,
    /// Time one STUN server has to answer before the prober moves on.
    pub probe_timeout: Duration,
    /// Sockets the symmetric side opens in `SymProbe`.
    pub assistant_sockets: u16,
    /// Sockets each side opens in `PredictiveExchange`.
    pub predictive_sockets: u16,
    /// Hard cap on sockets one session opens on either family.
    pub max_sockets: u16,
    /// Global send rate cap across every pool socket.
    pub packets_per_sec: u32,
    /// Total packets one session may send on the data plane.
    pub packet_budget: u32,
    /// Cap on distinct destinations, which bounds the conntrack footprint.
    pub max_destinations: usize,
    pub signaling_retry: Duration,
    pub exchange_timeout: Duration,
    pub negotiate_timeout: Duration,
    /// Time the Punch and Confirm phases share.
    pub punch_timeout: Duration,
    pub confirm_retry: Duration,
    /// How long a confirmed side answers repeated handshake packets before
    /// handing the winner socket to the host.
    pub grace: Duration,
    /// Time the optional Direct stage gets before the matrix strategy runs.
    pub direct_window: Duration,
    /// Success rate the birthday model aims for when sizing a burst.
    pub target_success: f64,
    /// Success rates below this value fail Negotiate with `Unpunchable`.
    pub min_success: f64,
    /// Hard wall-clock limit for the whole session.
    pub overall_deadline: Duration,
    /// Whether to probe and punch over IPv6 when the peer reports addresses.
    pub ipv6: bool,
    /// Engine heartbeat; every retransmission and pulse decision is checked
    /// on this cadence.
    pub tick: Duration,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            stun_servers: [
                "stun.cloudflare.com:3478",
                "stun.l.google.com:19302",
                "stun1.l.google.com:19302",
                "global.stun.twilio.com:3478",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            probe_timeout: Duration::from_secs(3),
            assistant_sockets: 16,
            predictive_sockets: 8,
            max_sockets: 256,
            packets_per_sec: 400,
            packet_budget: 4096,
            max_destinations: 2048,
            signaling_retry: Duration::from_millis(500),
            exchange_timeout: Duration::from_secs(10),
            negotiate_timeout: Duration::from_secs(10),
            punch_timeout: Duration::from_secs(15),
            confirm_retry: Duration::from_millis(200),
            grace: Duration::from_secs(2),
            direct_window: Duration::from_secs(1),
            target_success: 0.5,
            min_success: 0.1,
            overall_deadline: Duration::from_secs(60),
            ipv6: true,
            tick: Duration::from_millis(50),
        }
    }
}

impl PunchConfig {
    /// Rejects configurations that could never complete a session.
    pub fn validate(&self) -> Result<(), PunchError> {
        use PunchError::InvalidConfig as bad;
        if self.stun_servers.is_empty() {
            return Err(bad("stun_servers must not be empty"));
        }
        if self.max_sockets == 0 || self.packets_per_sec == 0 || self.packet_budget == 0 {
            return Err(bad("socket counts, rate, and budget must be positive"));
        }
        if self.assistant_sockets == 0
            || self.assistant_sockets > self.max_sockets
            || self.predictive_sockets == 0
            || self.predictive_sockets > self.max_sockets
        {
            return Err(bad(
                "strategy socket counts must be between 1 and max_sockets"
            ));
        }
        if self.tick.is_zero()
            || self.probe_timeout.is_zero()
            || self.exchange_timeout.is_zero()
            || self.negotiate_timeout.is_zero()
            || self.punch_timeout.is_zero()
            || self.confirm_retry.is_zero()
            || self.grace.is_zero()
            || self.signaling_retry.is_zero()
            || self.overall_deadline.is_zero()
        {
            return Err(bad("durations must be positive"));
        }
        if !(0.0..=1.0).contains(&self.target_success) || !(0.0..=1.0).contains(&self.min_success) {
            return Err(bad("success targets must be probabilities"));
        }
        if self.min_success > self.target_success {
            return Err(bad("min_success must not exceed target_success"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(PunchConfig::default().validate().is_ok());
    }

    #[test]
    fn empty_stun_list_is_rejected() {
        let cfg = PunchConfig {
            stun_servers: Vec::new(),
            ..PunchConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(PunchError::InvalidConfig(_))));
    }

    #[test]
    fn zero_budget_is_rejected() {
        let cfg = PunchConfig {
            packet_budget: 0,
            ..PunchConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(PunchError::InvalidConfig(_))));
    }

    #[test]
    fn zero_sockets_are_rejected() {
        let cfg = PunchConfig {
            assistant_sockets: 0,
            ..PunchConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(PunchError::InvalidConfig(_))));
    }
}
