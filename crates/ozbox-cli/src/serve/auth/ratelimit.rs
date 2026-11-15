//! A sliding-window limiter for sign-in attempts. Keys are credential ids, identities or a global bucket, never an
//! address: behind a tunnel every request has the tunnel's address.

use std::collections::HashMap;

pub struct RateLimiter {
    window_ms: u64,
    hits: HashMap<String, Vec<u64>>,
}

impl RateLimiter {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window_ms,
            hits: HashMap::new(),
        }
    }

    /// Count an attempt. `false` means too many: the attempt must be refused.
    /// Count an attempt against this key's own limit. `false` means too many: refuse it.
    pub fn hit_n(&mut self, key: &str, now_ms: u64, max: usize) -> bool {
        if self.hits.len() > 4096 {
            let w = self.window_ms;
            self.hits
                .retain(|_, v| v.last().is_some_and(|t| now_ms.saturating_sub(*t) < w));
        }
        let v = self.hits.entry(key.to_string()).or_default();
        v.retain(|t| now_ms.saturating_sub(*t) < self.window_ms);
        if v.len() >= max {
            return false;
        }
        v.push(now_ms);
        true
    }

    /// Forget a key (after a success).
    pub fn clear(&mut self, key: &str) {
        self.hits.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_slides() {
        let mut r = RateLimiter::new(1000);
        assert!(r.hit_n("a", 0, 3) && r.hit_n("a", 1, 3) && r.hit_n("a", 2, 3));
        assert!(!r.hit_n("a", 3, 3));
        assert!(r.hit_n("b", 3, 3));
        assert!(r.hit_n("a", 1001, 3));
        r.clear("a");
        assert!(r.hit_n("a", 1002, 3));
    }
}
