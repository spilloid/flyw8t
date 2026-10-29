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
        entry.1 <= limit
    }
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
}
