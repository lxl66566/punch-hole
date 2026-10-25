//! Send pacing shared by every pool socket.

use std::{sync::Mutex, time::Duration};

/// A spacing limiter that caps the global packet rate.
///
/// The first packet leaves immediately; every later packet waits for its own
/// slot on a fixed `1 / pps` grid.
pub(crate) struct RateLimiter {
    interval: Duration,
    next: Mutex<Option<tokio::time::Instant>>,
}

impl RateLimiter {
    pub(crate) fn new(pps: u32) -> Self {
        Self {
            interval: Duration::from_secs(1) / pps.max(1),
            next: Mutex::new(None),
        }
    }

    /// Reserves one send slot, sleeping until the slot is due.
    pub(crate) async fn acquire(&self) {
        let wait = {
            let mut next = self.next.lock().expect("rate limiter lock");
            let now = tokio::time::Instant::now();
            let slot = match *next {
                Some(reserved) if reserved > now => reserved,
                _ => now,
            };
            *next = Some(slot + self.interval);
            slot - now
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn ten_slots_at_ten_pps_span_nine_intervals() {
        let limiter = RateLimiter::new(10);
        let start = tokio::time::Instant::now();
        for _ in 0..10 {
            limiter.acquire().await;
        }
        assert_eq!(start.elapsed(), Duration::from_millis(900));
    }

    #[tokio::test(start_paused = true)]
    async fn first_packet_leaves_immediately() {
        let limiter = RateLimiter::new(1000);
        let start = tokio::time::Instant::now();
        limiter.acquire().await;
        assert_eq!(start.elapsed(), Duration::ZERO);
    }
}
