use std::time::Duration;

use super::{Deadline, OperationId, TenantScope};
use crate::{constants::*, error::ConfigurationError};

/// Accounted buffer statistics passed to [`FlushPolicy`] without loading
/// payloads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BufferStats {
    items: usize,
    bytes: usize,
    oldest_age: Duration,
}

impl BufferStats {
    #[must_use]
    pub const fn new(items: usize, bytes: usize, oldest_age: Duration) -> Self {
        Self {
            items,
            bytes,
            oldest_age,
        }
    }

    #[must_use]
    pub const fn items(&self) -> usize {
        self.items
    }

    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Conservative upper age used for eligibility. Persisted future UTC
    /// timestamps have unknown age and report `Duration::MAX`.
    #[must_use]
    pub const fn oldest_age(&self) -> Duration {
        self.oldest_age
    }
}

/// Synchronous, side-effect-free flush eligibility decision.
pub trait FlushPolicy: Send + Sync {
    fn validate(&self) -> Result<(), ConfigurationError> {
        Ok(())
    }

    fn should_flush(&self, stats: &BufferStats) -> bool;
}

impl<F> FlushPolicy for F
where F: Fn(&BufferStats) -> bool + Send + Sync
{
    fn should_flush(&self, stats: &BufferStats) -> bool {
        self(stats)
    }
}

/// Built-in OR threshold flush policy (defaults: 200 ms age OR 25 items).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlushThresholds {
    max_age: Option<Duration>,
    max_items: Option<usize>,
    max_bytes: Option<usize>,
}

impl Default for FlushThresholds {
    fn default() -> Self {
        Self {
            max_age: Some(DEFAULT_FLUSH_MAX_AGE),
            max_items: Some(DEFAULT_FLUSH_MAX_ITEMS),
            max_bytes: None,
        }
    }
}

impl FlushThresholds {
    #[must_use]
    pub const fn max_age(mut self, age: Duration) -> Self {
        self.max_age = Some(age);
        self
    }

    #[must_use]
    pub const fn disable_max_age(mut self) -> Self {
        self.max_age = None;
        self
    }

    #[must_use]
    pub const fn max_items(mut self, items: usize) -> Self {
        self.max_items = Some(items);
        self
    }

    #[must_use]
    pub const fn disable_max_items(mut self) -> Self {
        self.max_items = None;
        self
    }

    #[must_use]
    pub const fn max_bytes(mut self, bytes: usize) -> Self {
        self.max_bytes = Some(bytes);
        self
    }

    #[must_use]
    pub const fn disable_max_bytes(mut self) -> Self {
        self.max_bytes = None;
        self
    }

    pub fn validate(&self) -> Result<(), ConfigurationError> {
        if self.max_items == Some(0) {
            return Err(ConfigurationError::ZeroCapacity {
                field: "flush_policy.max_items",
            });
        }
        if self.max_bytes == Some(0) {
            return Err(ConfigurationError::ZeroCapacity {
                field: "flush_policy.max_bytes",
            });
        }
        if self.max_age.is_some_and(|age| age.is_zero()) {
            return Err(ConfigurationError::ZeroCapacity {
                field: "flush_policy.max_age",
            });
        }
        Ok(())
    }
}

impl FlushPolicy for FlushThresholds {
    fn validate(&self) -> Result<(), ConfigurationError> {
        FlushThresholds::validate(self)
    }

    fn should_flush(&self, stats: &BufferStats) -> bool {
        stats.items() > 0
            && (self.max_age.is_some_and(|a| stats.oldest_age() >= a)
                || self.max_items.is_some_and(|i| stats.items() >= i)
                || self.max_bytes.is_some_and(|b| stats.bytes() >= b))
    }
}

/// Capacity backpressure behavior when admission reaches hard bounds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BackpressurePolicy {
    #[default]
    RejectFull,
    WaitUntilDeadline,
}

/// Hard buffer capacity limits (defaults: 25 items and 8 MiB).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferCapacity {
    max_items: usize,
    max_bytes: usize,
    backpressure: BackpressurePolicy,
}

impl Default for BufferCapacity {
    fn default() -> Self {
        Self {
            max_items: DEFAULT_BUFFER_MAX_ITEMS,
            max_bytes: DEFAULT_BUFFER_MAX_BYTES,
            backpressure: BackpressurePolicy::RejectFull,
        }
    }
}

impl BufferCapacity {
    #[must_use]
    pub const fn max_items(mut self, max_items: usize) -> Self {
        self.max_items = max_items;
        self
    }

    #[must_use]
    pub const fn max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    #[must_use]
    pub const fn backpressure(mut self, backpressure: BackpressurePolicy) -> Self {
        self.backpressure = backpressure;
        self
    }

    #[must_use]
    pub const fn item_limit(&self) -> usize {
        self.max_items
    }

    #[must_use]
    pub const fn byte_limit(&self) -> usize {
        self.max_bytes
    }

    #[must_use]
    pub const fn backpressure_policy(&self) -> BackpressurePolicy {
        self.backpressure
    }

    pub fn validate(&self) -> Result<(), ConfigurationError> {
        if self.max_items == 0 || self.max_bytes == 0 {
            return Err(ConfigurationError::ZeroCapacity {
                field: "buffer_capacity",
            });
        }
        Ok(())
    }
}

/// Engine delivery, retry, circuit-breaker, and replay-cutoff settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryPolicy {
    pub attempt_timeout: Duration,
    pub flush_budget: Duration,
    pub max_attempts_per_turn: u32,
    pub retry_base_delay: Duration,
    pub failure_threshold: u32,
    pub fallback_age: Duration,
    pub probe_initial_delay: Duration,
    pub probe_max_delay: Duration,
    pub recovery_success_threshold: u32,
    pub lease_duration: Duration,
    pub allow_queue_success: bool,
    pub receipt_retention: Option<Duration>,
    pub max_replay_age: Option<Duration>,
}

impl Default for DeliveryPolicy {
    fn default() -> Self {
        Self {
            attempt_timeout: DEFAULT_ATTEMPT_TIMEOUT,
            flush_budget: DEFAULT_FLUSH_BUDGET,
            max_attempts_per_turn: DEFAULT_MAX_ATTEMPTS_PER_TURN,
            retry_base_delay: DEFAULT_RETRY_BASE_DELAY,
            failure_threshold: DEFAULT_BREAKER_FAILURE_THRESHOLD,
            fallback_age: DEFAULT_FALLBACK_AGE_THRESHOLD,
            probe_initial_delay: DEFAULT_PROBE_INITIAL_DELAY,
            probe_max_delay: DEFAULT_PROBE_MAX_DELAY,
            recovery_success_threshold: DEFAULT_RECOVERY_SUCCESS_THRESHOLD,
            lease_duration: DEFAULT_LEASE_DURATION,
            allow_queue_success: false,
            receipt_retention: None,
            max_replay_age: None,
        }
    }
}

impl DeliveryPolicy {
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        if self.retry_base_delay.is_zero()
            || self.attempt_timeout.is_zero()
            || self.flush_budget.is_zero()
            || self.probe_initial_delay.is_zero()
            || self.probe_max_delay < self.probe_initial_delay
        {
            return Err(ConfigurationError::InvalidTimingRelationship {
                reason: "timeouts and retry delay must be positive and probe_max_delay >= \
                         probe_initial_delay",
            });
        }
        if self.max_attempts_per_turn == 0
            || self.failure_threshold == 0
            || self.recovery_success_threshold == 0
        {
            return Err(ConfigurationError::ZeroCapacity {
                field: "delivery_policy thresholds",
            });
        }
        if self.lease_duration
            <= self
                .attempt_timeout
                .saturating_add(DEFAULT_LEASE_SAFETY_MARGIN)
            || self.lease_duration <= self.flush_budget
        {
            return Err(ConfigurationError::InvalidTimingRelationship {
                reason: "lease must exceed the bounded flush and attempt budgets",
            });
        }
        if let Some(retention) = self.receipt_retention {
            let Some(max_replay_age) = self.max_replay_age else {
                return Err(ConfigurationError::IncompatibleRetentionAndReplay {
                    reason: "finite receipt_retention requires an explicit max_replay_age",
                });
            };
            if max_replay_age >= retention {
                return Err(ConfigurationError::IncompatibleRetentionAndReplay {
                    reason: "max_replay_age must be strictly shorter than receipt_retention",
                });
            }
        }
        Ok(())
    }
}

/// Optional per-add overrides for stable admission identity, scope, and
/// deadline.
#[derive(Clone, Debug, Default)]
pub struct WriteOptions {
    operation_id: Option<OperationId>,
    scope: Option<TenantScope>,
    deadline: Option<Deadline>,
}

impl WriteOptions {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            operation_id: None,
            scope: None,
            deadline: None,
        }
    }

    #[must_use]
    pub fn with_operation_id(mut self, operation_id: OperationId) -> Self {
        self.operation_id = Some(operation_id);
        self
    }

    #[must_use]
    pub fn with_scope(mut self, scope: TenantScope) -> Self {
        self.scope = Some(scope);
        self
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: impl Into<Deadline>) -> Self {
        self.deadline = Some(deadline.into());
        self
    }

    #[must_use]
    pub fn operation_id(&self) -> Option<&OperationId> {
        self.operation_id.as_ref()
    }

    #[must_use]
    pub fn scope(&self) -> Option<&TenantScope> {
        self.scope.as_ref()
    }

    #[must_use]
    pub const fn deadline(&self) -> Option<Deadline> {
        self.deadline
    }
}
