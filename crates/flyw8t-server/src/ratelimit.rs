//! Fixed-window rate limiting, in memory, per key. Good enough for a single server instance;
//! a multi-instance deployment needs a shared store (see docs/decisions/ADR-0009).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    windows: Mutex<HashMap<String, (Instant, u32)>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }
}

impl RateLimiter {
    /// Count one attempt against `key`; `false` when it exceeds `limit` per `window`.
    pub fn allow(&self, key: &str, limit: u32, window: Duration) -> bool {
        self.reserve(key, limit, window).is_some()
    }

    /// Like `allow`, returning the place taken so it can be given back with `refund`.
    /// Lets a caller budget only failures while reserving atomically before the work.
    pub fn reserve(&self, key: &str, limit: u32, window: Duration) -> Option<Reservation> {
        let now = Instant::now();
        let mut w = self.windows.lock().unwrap();
        if w.len() > 50_000 {
            w.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = w.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        (entry.1 <= limit).then(|| Reservation {
            key: key.to_string(),
            window_start: entry.0,
        })
    }

    /// Give back a place, but only to the window it was taken from: a refund that arrives
    /// after the window rolled over must not free a place in the new one.
    pub fn refund(&self, r: Reservation) {
        if let Some((start, n)) = self.windows.lock().unwrap().get_mut(&r.key) {
            if *start == r.window_start {
                *n = n.saturating_sub(1);
            }
        }
    }
}

/// One counted attempt, from `RateLimiter::reserve`.
#[derive(Debug)]
pub struct Reservation {
    key: String,
    window_start: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_key() {
        let r = RateLimiter::default();
        let w = Duration::from_secs(60);
        assert!((0..3).all(|_| r.allow("a", 3, w)));
        assert!(!r.allow("a", 3, w));
        assert!(r.allow("b", 3, w));
    }

    #[test]
    fn refunds_give_back_a_place_in_their_own_window_only() {
        let r = RateLimiter::default();
        let w = Duration::from_millis(200);
        let a = r.reserve("f", 2, w).unwrap();
        let b = r.reserve("f", 2, w).unwrap();
        assert!(
            r.reserve("f", 2, w).is_none(),
            "full, and the refused attempt counts too"
        );
        r.refund(a);
        r.refund(b);
        assert!(
            r.reserve("f", 2, w).is_some(),
            "two refunds free one place (three were counted)"
        );
        // A reservation from an earlier window gives nothing back to the next one.
        let old = r.reserve("g", 1, w).unwrap();
        std::thread::sleep(Duration::from_millis(250));
        assert!(r.reserve("g", 1, w).is_some(), "new window");
        r.refund(old);
        assert!(
            r.reserve("g", 1, w).is_none(),
            "a late refund freed a place in the new window"
        );
    }
}
