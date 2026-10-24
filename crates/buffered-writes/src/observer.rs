use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chrono::{DateTime, TimeZone as _, Utc};
use futures_util::future::BoxFuture;

use crate::configuration::{AdmissionStatus, BatchId, DurabilityClass, OperationId};

/// Injected monotonic and wall-clock time source.
pub trait Clock: Send + Sync + 'static {
    fn now_instant(&self) -> Instant;
    fn now_utc(&self) -> DateTime<Utc>;
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;
}

impl dyn Clock {
    pub(crate) async fn complete_before<F: std::future::Future>(
        &self,
        deadline: crate::Deadline,
        future: F,
    ) -> Option<F::Output> {
        let remaining = deadline.remaining_at(self.now_instant());
        if remaining.is_zero() {
            return None;
        }
        let timer = async { self.sleep(remaining).await };
        match futures_util::future::select(Box::pin(future), Box::pin(timer)).await {
            futures_util::future::Either::Left((output, _)) => Some(output),
            futures_util::future::Either::Right(_) => None,
        }
    }
}

/// Default production clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionClock;

impl Clock for ProductionClock {
    fn now_instant(&self) -> Instant {
        Instant::now()
    }

    fn now_utc(&self) -> DateTime<Utc> {
        Utc::now()
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            #[cfg(feature = "tokio")]
            {
                tokio::time::sleep(duration).await;
            }
            #[cfg(not(feature = "tokio"))]
            {
                futures_timer::Delay::new(duration).await;
            }
        })
    }
}

struct TestClockState {
    anchor: Instant,
    monotonic_offset: Duration,
    utc_millis: i64,
    auto_advance_on_sleep: bool,
}

/// Deterministic test clock supporting independent monotonic and UTC wall-clock
/// control.
#[derive(Clone)]
pub struct TestClock {
    state: Arc<Mutex<TestClockState>>,
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TestClock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TestClock")
    }
}

impl TestClock {
    #[must_use]
    pub fn new() -> Self {
        Self::with_utc_millis(1_761_000_000_000)
    }

    #[must_use]
    pub fn with_utc_millis(utc_millis: i64) -> Self {
        Self {
            state: Arc::new(Mutex::new(TestClockState {
                anchor: Instant::now(),
                monotonic_offset: Duration::ZERO,
                utc_millis,
                auto_advance_on_sleep: true,
            })),
        }
    }

    pub fn set_auto_advance_on_sleep(&self, enabled: bool) {
        if let Ok(mut guard) = self.state.lock() {
            guard.auto_advance_on_sleep = enabled;
        }
    }

    pub fn advance(&self, duration: Duration) {
        if let Ok(mut guard) = self.state.lock() {
            guard.monotonic_offset = guard.monotonic_offset.saturating_add(duration);
            let delta_ms = i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
            guard.utc_millis = guard.utc_millis.saturating_add(delta_ms);
        }
    }

    pub fn regress_wall_clock(&self, duration: Duration) {
        if let Ok(mut guard) = self.state.lock() {
            let delta_ms = i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
            guard.utc_millis = guard.utc_millis.saturating_sub(delta_ms);
        }
    }
}

impl Clock for TestClock {
    fn now_instant(&self) -> Instant {
        match self.state.lock() {
            Ok(guard) => guard
                .anchor
                .checked_add(guard.monotonic_offset)
                .unwrap_or(guard.anchor),
            Err(poisoned) => {
                let guard = poisoned.into_inner();
                guard
                    .anchor
                    .checked_add(guard.monotonic_offset)
                    .unwrap_or(guard.anchor)
            }
        }
    }

    fn now_utc(&self) -> DateTime<Utc> {
        let millis = match self.state.lock() {
            Ok(guard) => guard.utc_millis,
            Err(poisoned) => poisoned.into_inner().utc_millis,
        };
        Utc.timestamp_millis_opt(millis)
            .single()
            .unwrap_or_else(Utc::now)
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        let auto_advance = match self.state.lock() {
            Ok(guard) => guard.auto_advance_on_sleep,
            Err(poisoned) => poisoned.into_inner().auto_advance_on_sleep,
        };
        let clock = self.clone();
        Box::pin(async move {
            if auto_advance {
                clock.advance(duration);
            } else {
                ProductionClock.sleep(duration).await;
            }
        })
    }
}

/// Engine delivery mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DeliveryMode {
    #[default]
    Buffered,
    Synchronous,
    Draining,
    Stopped,
}

/// Sink circuit breaker health state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SinkHealth {
    #[default]
    Closed,
    Open,
    HalfOpen,
}

/// Safe classification for admission rejections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionRejectReason {
    Full,
    Closed,
    Oversized,
    IdentityConflict,
    InvalidInput,
    Unavailable,
    DeadlineExceeded,
}

/// Safe classification for sink failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkFailureKind {
    Retryable,
    Permanent,
    IdentityConflict,
    UnknownOutcome,
    InvalidOutcome,
    DeadlineExceeded,
}

/// Queue failure projection without transport reasons or receipt contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueFailureKind {
    Oversized,
    Unavailable,
    Permanent,
    UnknownOutcome,
    DeadlineExceeded,
    InvalidReceipt,
    PoisonEnvelope,
}

impl From<&crate::QueueError> for QueueFailureKind {
    fn from(error: &crate::QueueError) -> Self {
        match error {
            crate::QueueError::EnvelopeTooLarge { .. } => Self::Oversized,
            crate::QueueError::Unavailable { .. } => Self::Unavailable,
            crate::QueueError::Permanent { .. } => Self::Permanent,
            crate::QueueError::AmbiguousPublish => Self::UnknownOutcome,
            crate::QueueError::DeadlineExceeded => Self::DeadlineExceeded,
            crate::QueueError::InvalidReceipt => Self::InvalidReceipt,
            crate::QueueError::PoisonEnvelope { .. } => Self::PoisonEnvelope,
        }
    }
}

/// Safe classification for quarantined work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum QuarantineReason {
    OversizedSingleton,
    PermanentPrepareError,
    PermanentSinkFailure,
    IdentityConflict,
    PoisonReplayEnvelope,
    ExpiredReplayEnvelope,
    UncertainReplayAge,
    CorruptJournalFrame,
}

/// Safe classification for replay outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayObservation {
    Delivered,
    RetainedForRetry,
    Quarantined,
}

/// Safe, redacted observer event with fixed categories and no customer payload
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteEvent {
    /// A sample from an existing provider inspection; no extra read is
    /// required.
    BufferObserved {
        stats: crate::BufferStats,
        /// Inspection order assigned before the provider call begins.
        revision: u64,
    },
    /// The last known sample must remain stale, rather than being reported
    /// empty.
    BufferInspectionFailed {
        /// Inspection order assigned before the provider call begins.
        revision: u64,
    },
    LifecycleSourceFailed {
        error: crate::LifecycleError,
    },
    Admitted {
        status: AdmissionStatus,
        durability: DurabilityClass,
        bytes: usize,
    },
    AdmissionRejected {
        reason: AdmissionRejectReason,
    },
    BatchSealed {
        operations: usize,
        bytes: usize,
        oldest_age: Duration,
    },
    FlushAttempted {
        operations: usize,
        retry_attempt: u32,
    },
    FlushCompleted {
        operations: usize,
        elapsed: Duration,
    },
    FlushFailed {
        kind: SinkFailureKind,
        retrying: bool,
    },
    PartialProgress {
        completed: usize,
        remaining: usize,
    },
    ModeChanged {
        from: DeliveryMode,
        to: DeliveryMode,
        /// Monotonic mode-transition revision assigned under engine ownership.
        revision: u64,
    },
    HealthChanged {
        from: SinkHealth,
        to: SinkHealth,
        /// Monotonic health-transition revision assigned under engine
        /// ownership.
        revision: u64,
    },
    QueueFailed {
        kind: QueueFailureKind,
    },
    QueueHandoff {
        operations: usize,
        bytes: usize,
    },
    ReplayOutcome {
        outcome: ReplayObservation,
    },
    Quarantined {
        reason: QuarantineReason,
    },
    DrainCompleted {
        elapsed: Duration,
        unresolved_items: usize,
        unresolved_batches: usize,
        state_unknown: bool,
        clean: bool,
    },
    /// The driver guard was dropped before shutdown completed. Retained item
    /// ownership is unknown here; only a drain report can establish its count.
    GuardDroppedBeforeShutdown,
}

/// Observer for non-error and failure events across the buffered write engine.
pub trait WriteObserver: Send + Sync + 'static {
    fn observe(&self, event: WriteEvent);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopWriteObserver;

impl WriteObserver for NoopWriteObserver {
    fn observe(&self, _event: WriteEvent) {}
}

/// Recording observer for tests and diagnostics.
#[derive(Clone, Debug, Default)]
pub struct RecordingWriteObserver {
    events: Arc<Mutex<Vec<WriteEvent>>>,
}

impl RecordingWriteObserver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn events(&self) -> Vec<WriteEvent> {
        match self.events.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl WriteObserver for RecordingWriteObserver {
    fn observe(&self, event: WriteEvent) {
        if let Ok(mut guard) = self.events.lock() {
            guard.push(event);
        }
    }
}

/// Summary report returned by `after_response()` and `flush_writes()`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlushReport {
    pub batches_flushed: usize,
    pub items_settled: usize,
    pub batches_queued: usize,
    pub batches_failed: usize,
    pub partial_operations_completed: usize,
    pub unresolved_batches: Vec<BatchId>,
    pub quarantined_items: usize,
    pub mode: DeliveryMode,
    pub sink_health: SinkHealth,
    pub last_error: Option<SinkFailureKind>,
    pub buffer_error: Option<crate::BufferError>,
    pub queue_error: Option<crate::QueueError>,
}

impl FlushReport {
    #[must_use]
    pub const fn has_failures(&self) -> bool {
        self.batches_failed > 0
            || self.quarantined_items > 0
            || self.last_error.is_some()
            || self.buffer_error.is_some()
            || self.queue_error.is_some()
    }
}

/// Summary report returned by `shutdown(deadline)`.
///
/// When `state_unknown` is true, retained counts and batch IDs describe the
/// last successful drain inspection, if any. They are not proof of current
/// ownership or an empty buffer. Use [`Self::is_clean`] to establish a clean
/// drain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DrainReport {
    pub batches_flushed: usize,
    pub items_settled: usize,
    pub batches_queued: usize,
    pub unresolved_batches: Vec<BatchId>,
    /// Dispatched admissions with an unresolved acknowledgement or commit
    /// outcome.
    pub unresolved_admissions: Vec<OperationId>,
    /// Latest observed retained count; may be stale when `state_unknown` is
    /// true.
    pub unresolved_items: usize,
    /// Latest observed volatile count; may be stale when `state_unknown` is
    /// true.
    pub volatile_unresolved_items: usize,
    pub quarantined_items: usize,
    /// True when the provider could not establish the remaining ownership
    /// state.
    pub state_unknown: bool,
    pub completed_before_deadline: bool,
    pub elapsed: Duration,
}

impl DrainReport {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.completed_before_deadline
            && !self.state_unknown
            && self.quarantined_items == 0
            && self.unresolved_batches.is_empty()
            && self.unresolved_admissions.is_empty()
            && self.unresolved_items == 0
    }
}
