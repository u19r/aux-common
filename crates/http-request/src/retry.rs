use std::time::Duration;

use rand::RngExt as _;
use reqwest::Method;

use crate::constants::{
    DEFAULT_MAX_RETRIES, DEFAULT_RETRY_BASE_DELAY, DEFAULT_RETRY_MAX_DELAY, MAX_RETRY_EXPONENT,
};

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub retry_non_idempotent: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            base_delay: DEFAULT_RETRY_BASE_DELAY,
            max_delay: DEFAULT_RETRY_MAX_DELAY,
            retry_non_idempotent: false,
        }
    }
}

impl RetryConfig {
    #[must_use]
    pub fn should_retry_method(&self, method: &Method) -> bool {
        self.retry_non_idempotent || is_idempotent_method(method)
    }

    #[must_use]
    pub fn backoff_delay(&self, attempt: u32) -> Duration {
        jittered_backoff(self.base_delay, self.max_delay, attempt)
    }
}

fn jittered_backoff(base: Duration, max: Duration, attempt: u32) -> Duration {
    let base_ms = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    let max_ms = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);
    let shift = attempt.min(MAX_RETRY_EXPONENT);
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let exponential = base_ms.saturating_mul(factor);
    let mut rng = rand::rng();
    let jitter = rng.random_range(0..=base_ms);
    Duration::from_millis((exponential + jitter).min(max_ms))
}

fn is_idempotent_method(method: &Method) -> bool {
    matches!(
        method,
        &Method::GET | &Method::HEAD | &Method::PUT | &Method::DELETE | &Method::OPTIONS
    )
}
