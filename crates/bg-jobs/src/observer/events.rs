use core::fmt;

use crate::{
    budget::DriveStopReason,
    ids::{JobKind, QueueName},
    model::EnqueueDisposition,
    policy::{EffectMode, OutcomeCode, Priority, RetryClass},
};

/// A bounded bucket for attempt counts in safe observer events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttemptBucket {
    First,
    Few,
    Many,
}

impl AttemptBucket {
    pub const fn from_attempt(attempt: u32) -> Self {
        match attempt {
            0 | 1 => Self::First,
            2..=4 => Self::Few,
            _ => Self::Many,
        }
    }
}

/// Closed error categories safe to forward to logs or metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SafeJobErrorKind {
    StoreUnavailable,
    StoreTimeout,
    UnknownCommit,
    LeaseLost,
    PayloadCorrupt,
    UnregisteredHandler,
    InvariantViolation,
    RepairConflict,
}

/// A typed error event with a closed error category and optional typed context.
///
/// Queue context remains available to typed observers, but [`Debug`] omits it:
/// queue names are caller-controlled and may contain customer data. Raw errors,
/// payloads, URLs, and other backend details are never part of this event.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SafeJobErrorEvent {
    pub kind: SafeJobErrorKind,
    pub queue: Option<QueueName>,
    pub effect_mode: Option<EffectMode>,
}

impl fmt::Debug for SafeJobErrorEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Queue names are caller-controlled and must not enter logs or metrics
        // through the public debug projection.
        formatter
            .debug_struct("SafeJobErrorEvent")
            .field("kind", &self.kind)
            .field("effect_mode", &self.effect_mode)
            .finish()
    }
}

/// Events emitted by the core observer boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobEvent {
    AttemptStarted {
        queue: QueueName,
        kind: JobKind,
        due_delay: std::time::Duration,
    },
    AttemptFinished {
        queue: QueueName,
        kind: JobKind,
        duration: std::time::Duration,
    },
    CapacityLimited {
        resource: super::CapacityResource,
    },
    StoreOperationsReserved {
        operations: u32,
    },
    StoreOperation {
        operation: super::StoreOperation,
    },
    Enqueued {
        queue: QueueName,
        disposition: EnqueueDisposition,
    },
    Claimed {
        queue: QueueName,
        priority: Priority,
        attempt: AttemptBucket,
    },
    Heartbeat {
        queue: QueueName,
        coalesced: bool,
    },
    RenewalLost {
        queue: QueueName,
    },
    Checkpoint {
        queue: QueueName,
        bytes: u32,
    },
    Completed {
        queue: QueueName,
        effect_mode: EffectMode,
    },
    Continued {
        queue: QueueName,
        kind: JobKind,
    },
    Retried {
        queue: QueueName,
        class: RetryClass,
        attempt: AttemptBucket,
    },
    DeadLettered {
        queue: QueueName,
        outcome: OutcomeCode,
    },
    CancellationRequested {
        queue: QueueName,
    },
    Cancelled {
        queue: QueueName,
    },
    Suspended {
        queue: QueueName,
    },
    Resumed {
        queue: QueueName,
    },
    Redriven {
        queue: QueueName,
        reused_execution: bool,
    },
    Repaired {
        queue: QueueName,
    },
    StoreError {
        kind: SafeJobErrorKind,
    },
    LeaseConflict {
        queue: QueueName,
    },
    DriveStopped {
        reason: DriveStopReason,
    },
}

/// Non-blocking observer for safe lifecycle telemetry.
pub trait JobObserver: Send + Sync + 'static {
    fn observe(&self, event: JobEvent);

    fn observe_error(&self, _event: SafeJobErrorEvent) {}
}

/// Default observer that deliberately discards events.
#[derive(Debug, Default)]
pub struct NoopObserver;

impl JobObserver for NoopObserver {
    fn observe(&self, _event: JobEvent) {}
}
