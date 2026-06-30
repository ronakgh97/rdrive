use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Per-IP token bucket rate limiter.
///
/// Tokens refill at `refill_rate` per second up to `max_tokens`.
/// Each request consumes `cost` tokens (default 1).
/// Returns `true` if the request is allowed, `false` if rate-limited.
pub struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket with the given parameters.
    pub fn init(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    #[inline(always)]
    /// Try to consume `cost` tokens. Returns true if allowed.
    pub fn try_consume(&mut self, cost: f64) -> bool {
        self.refill();
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }

    #[inline]
    /// Refill tokens based on elapsed time since last refill.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }
}

/// Global per-IP rate limiter state.
pub struct RateLimiter {
    buckets: DashMap<IpAddr, TokenBucket>,
    max_tokens: f64,
    refill_rate: f64,
}

impl RateLimiter {
    /// Create a new rate limiter with the given parameters.
    pub fn init(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            buckets: DashMap::with_capacity(1024),
            max_tokens,
            refill_rate,
        }
    }

    #[inline(always)]
    /// Check if a request from `ip` is allowed. Consumes 1 token by default.
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        let mut entry = self
            .buckets
            .entry(*ip)
            .or_insert_with(|| TokenBucket::init(self.max_tokens, self.refill_rate));
        entry.try_consume(1.0)
    }

    #[inline(always)]
    /// Check if a request from `ip` is allowed, consuming `cost` tokens.
    pub fn is_allowed_cost(&self, ip: &IpAddr, cost: f64) -> bool {
        let mut entry = self
            .buckets
            .entry(*ip)
            .or_insert_with(|| TokenBucket::init(self.max_tokens, self.refill_rate));
        entry.try_consume(cost)
    }

    #[inline]
    /// Get current token count for an IP (for diagnostics).
    pub fn tokens_remaining(&self, ip: &IpAddr) -> f64 {
        self.buckets
            .get(ip)
            .map(|b| b.tokens)
            .unwrap_or(self.max_tokens)
    }

    /// Remove entries for IPs that haven't been seen recently.
    /// Call periodically to prevent unbounded growth.
    pub fn cleanup_stale(&self, max_age_secs: u64) {
        let now = Instant::now();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill).as_secs() < max_age_secs);
    }
}
