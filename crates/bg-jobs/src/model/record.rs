use core::fmt;
use std::{
    collections::HashSet,
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;

use crate::{
    error::ValidationError,
    ids::{
        ExecutionId, JobId, JobKind, LeaseToken, Namespace, OperationId, OrderingKey, OwnerId,
        QueueName,
    },
    model::constants::{
        MAX_CHECKPOINT_BYTES, MAX_COST_UNITS, MAX_INLINE_PAYLOAD_BYTES, PAYLOAD_DIGEST_BYTES,
    },
    policy::{
        Deduplication, EffectMode, FairnessClass, OutcomeCode, Priority, RetryClass, RetryPolicy,
        RetrySelection,
    },
    store::StoreKey,
    time::Timestamp,
};

/// A payload manifest persisted separately from immutable payload chunks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadManifest {
    pub total_length: u32,
    pub digest: [u8; PAYLOAD_DIGEST_BYTES],
    pub chunk_keys: Vec<StoreKey>,
}

impl PayloadManifest {
    /// Practical bound on persisted chunk references. The wire count remains
    /// `u16` for format compatibility, but decoding more than this many keys
    /// would permit unnecessary allocation and fetch work before validation.
    pub const MAX_CHUNKS: usize = 1_024;

    pub fn try_new(
        total_length: u32,
        digest: [u8; PAYLOAD_DIGEST_BYTES],
        chunk_keys: Vec<StoreKey>,
    ) -> Result<Self, ValidationError> {
        let manifest = Self {
            total_length,
            digest,
            chunk_keys,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.total_length as usize > MAX_INLINE_PAYLOAD_BYTES {
            return Err(ValidationError::TooLong {
                field: "payload",
                maximum: MAX_INLINE_PAYLOAD_BYTES,
                actual: self.total_length as usize,
            });
        }
        if self.chunk_keys.len() > Self::MAX_CHUNKS {
            return Err(ValidationError::TooLong {
                field: "payload chunks",
                maximum: Self::MAX_CHUNKS,
                actual: self.chunk_keys.len(),
            });
        }
        if self.total_length > 0 && self.chunk_keys.is_empty() {
            return Err(ValidationError::Empty {
                field: "payload chunks",
            });
        }
        if self.total_length == 0 && !self.chunk_keys.is_empty() {
            return Err(ValidationError::InvalidValue {
                field: "zero-length payload chunks",
            });
        }
        let duplicate = if self.chunk_keys.len() <= 8 {
            self.chunk_keys.iter().enumerate().any(|(index, key)| {
                self.chunk_keys[..index]
                    .iter()
                    .any(|previous| previous == key)
            })
        } else {
            let mut seen = HashSet::with_capacity(self.chunk_keys.len());
            self.chunk_keys.iter().any(|key| !seen.insert(key))
        };
        if duplicate {
            return Err(ValidationError::InvalidValue {
                field: "duplicate payload chunk",
            });
        }
        Ok(())
    }
}

/// Authoritative job state. Successful completion deletes the record instead of
/// retaining a state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobState {
    Scheduled,
    Leased(Lease),
    DeadLettered,
    Cancelled,
    Suspended,
}

/// Exact authority required for a lease-gated transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub owner: OwnerId,
    pub token: LeaseToken,
    pub fence: NonZeroU64,
    pub expires_at: Timestamp,
}

impl Lease {
    pub fn try_new(
        owner: OwnerId,
        token: LeaseToken,
        fence: NonZeroU64,
        expires_at: Timestamp,
    ) -> Result<Self, ValidationError> {
        if expires_at < Timestamp::ZERO {
            return Err(ValidationError::InvalidValue {
                field: "lease expiry",
            });
        }
        Ok(Self {
            owner,
            token,
            fence,
            expires_at,
        })
    }
}

/// Bounded attempt history persisted with a job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptHistory {
    pub attempts: NonZeroU32,
    pub first_attempt_at: Timestamp,
    pub last_attempt_at: Timestamp,
    pub last_outcome: Option<OutcomeCode>,
}

impl AttemptHistory {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.last_attempt_at < self.first_attempt_at {
            return Err(ValidationError::Ordering {
                field: "attempt chronology",
            });
        }
        Ok(())
    }
}

/// The complete v1 authoritative job value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobRecordV1 {
    pub job_id: JobId,
    pub namespace: Namespace,
    pub queue: QueueName,
    pub kind: JobKind,
    pub schema_version: NonZeroU16,
    pub generation: u32,
    pub execution_id: ExecutionId,
    pub payload: PayloadManifest,
    pub fairness: FairnessClass,
    pub ordering_key: Option<OrderingKey>,
    pub priority: Priority,
    pub created_at: Timestamp,
    pub scheduled_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub policy: JobPolicySnapshot,
    pub attempts: Option<AttemptHistory>,
    pub state: JobState,
    pub checkpoint: Option<Bytes>,
    pub retention_deadline: Timestamp,
    pub deduplication: Option<Deduplication>,
    pub revision: u64,
}

impl JobRecordV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.payload.validate()?;
        self.policy.validate()?;
        if let Some(attempts) = &self.attempts {
            attempts.validate()?;
        }
        self.validate_expiry_and_retention()?;
        self.validate_checkpoint_and_lease()
    }

    pub(crate) fn has_exhausted_attempts(&self) -> bool {
        self.attempts.as_ref().is_some_and(|attempts| {
            attempts.attempts.get() >= u32::from(self.policy.retry_policy.maximum_attempts().get())
        })
    }

    fn validate_expiry_and_retention(&self) -> Result<(), ValidationError> {
        if let Some(expiry) = self.expires_at
            && expiry < self.scheduled_at
        {
            return Err(ValidationError::Ordering {
                field: "job expiry",
            });
        }
        if self.retention_deadline < self.created_at {
            return Err(ValidationError::Ordering {
                field: "job retention",
            });
        }
        Ok(())
    }

    fn validate_checkpoint_and_lease(&self) -> Result<(), ValidationError> {
        if let Some(checkpoint) = &self.checkpoint
            && checkpoint.len() > MAX_CHECKPOINT_BYTES
        {
            return Err(ValidationError::TooLong {
                field: "checkpoint",
                maximum: MAX_CHECKPOINT_BYTES,
                actual: checkpoint.len(),
            });
        }
        if let JobState::Leased(lease) = &self.state
            && lease.expires_at < self.created_at
        {
            return Err(ValidationError::Ordering {
                field: "lease expiry",
            });
        }
        Ok(())
    }
}

/// Lowest-level enqueue input. Its immutable fields are used for idempotent
/// replay checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewJob {
    /// Raw/test-support-only immutable enqueue identity.
    pub job_id: JobId,
    /// Raw/test-support-only registered handler identity.
    pub kind: JobKind,
    /// Raw/test-support-only schema identity.
    pub schema_version: NonZeroU16,
    /// Raw/test-support-only encoded payload.
    pub payload: Bytes,
    /// Raw/test-support-only fairness lane.
    pub fairness: FairnessClass,
    /// Raw/test-support-only ordering group.
    pub ordering_key: Option<OrderingKey>,
    /// Raw/test-support-only priority lane.
    pub priority: Priority,
    /// Raw/test-support-only schedule timestamp.
    pub scheduled_at: Timestamp,
    /// Raw/test-support-only expiry timestamp.
    pub expires_at: Option<Timestamp>,
    /// Raw/test-support-only retry override.
    pub retry_override: Option<RetrySelection>,
    /// Raw/test-support-only deduplication policy.
    pub deduplication: Option<Deduplication>,
}

impl NewJob {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.payload.len() > MAX_INLINE_PAYLOAD_BYTES {
            return Err(ValidationError::TooLong {
                field: "payload",
                maximum: MAX_INLINE_PAYLOAD_BYTES,
                actual: self.payload.len(),
            });
        }
        if let Some(expiry) = self.expires_at
            && expiry < self.scheduled_at
        {
            return Err(ValidationError::Ordering {
                field: "job expiry",
            });
        }
        Ok(())
    }
}

/// Stable enqueue disposition for replaying an ambiguous producer request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EnqueueDisposition {
    Enqueued,
    AlreadyPresent,
    Deduplicated,
}

/// Enqueue response including an advisory wake repair hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnqueueResult {
    pub job_id: JobId,
    pub disposition: EnqueueDisposition,
    pub wake: crate::time::WakeHint,
}

/// Handler outcome after one claimed invocation.
///
/// Forward this decision to the runtime. Checking the handler's error with
/// `?` must not discard a retry or continuation and report completion instead.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use bg_jobs::{JobOutcome, OutcomeCode};
/// fn dispatch(outcome: Result<JobOutcome, ()>) -> Result<JobOutcome, ()> {
///     outcome?;
///     Ok(JobOutcome::Complete(OutcomeCode::try_new("finished").unwrap()))
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "return the handler's outcome; discarding it can lose a retry or continuation"]
pub enum JobOutcome {
    Complete(OutcomeCode),
    /// Commits a checkpoint and its next due time. The due time must be at
    /// least the context claim time; elapsed handler work may make it already
    /// due.
    Continue {
        not_before: Timestamp,
        checkpoint: Bytes,
    },
    Retry {
        class: RetryClass,
        not_before: Option<Timestamp>,
        code: OutcomeCode,
    },
    DeadLetter {
        code: OutcomeCode,
    },
    Cancelled,
}

/// Cooperative cancellation state shared by a claimed attempt and its context.
///
/// Clone the token from [`crate::ExecutionContext::cancellation`] when a
/// handler needs to propagate cancellation into a lower-level operation.
///
/// ```
/// use bg_jobs::CancellationToken;
///
/// let token = CancellationToken::new();
/// let operation = token.clone();
/// token.cancel();
/// assert!(operation.is_cancelled());
/// ```
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<CancellationState>);

struct CancellationState {
    cancelled: AtomicBool,
    waiter: Mutex<Option<Waker>>,
}

impl Default for CancellationState {
    fn default() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            waiter: Mutex::new(None),
        }
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        let waiter = self
            .0
            .waiter
            .lock()
            .ok()
            .and_then(|mut waiter| waiter.take());
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }

    // A handler may remain pending after cancellation. Retain its latest
    // executor so a subsequent shutdown request can wake that drive.
    pub(crate) fn poll_cancelled(&self, context: &mut Context<'_>) -> Poll<()> {
        let Ok(mut waiter) = self.0.waiter.lock() else {
            return Poll::Ready(());
        };
        *waiter = Some(context.waker().clone());
        if self.is_cancelled() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl JobOutcome {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let Self::Continue { checkpoint, .. } = self
            && checkpoint.len() > MAX_CHECKPOINT_BYTES
        {
            return Err(ValidationError::TooLong {
                field: "checkpoint",
                maximum: MAX_CHECKPOINT_BYTES,
                actual: checkpoint.len(),
            });
        }
        Ok(())
    }
}

fn validate_cost_units(field: &'static str, value: NonZeroU16) -> Result<(), ValidationError> {
    if value.get() > MAX_COST_UNITS {
        return Err(ValidationError::TooLong {
            field,
            maximum: MAX_COST_UNITS as usize,
            actual: value.get() as usize,
        });
    }
    Ok(())
}

fn validate_execution_timeout(
    field: &'static str,
    timeout: Option<Duration>,
) -> Result<(), ValidationError> {
    if let Some(timeout) = timeout {
        if timeout.is_zero() {
            return Err(ValidationError::InvalidValue { field });
        }
        if timeout.as_nanos() > u64::MAX as u128 {
            return Err(ValidationError::Overflow { field });
        }
    }
    Ok(())
}

/// Immutable registration policy captured by a persisted job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandlerDefinition<H> {
    /// Raw/test-support-only handler identity.
    pub kind: JobKind,
    /// Raw/test-support-only schema identity.
    pub schema_version: NonZeroU16,
    /// Raw/test-support-only queue.
    pub queue: QueueName,
    /// Raw/test-support-only effect authority.
    pub effect_mode: EffectMode,
    /// Raw/test-support-only cost.
    pub cost_units: NonZeroU16,
    /// Raw/test-support-only fairness policy.
    pub fairness_policy: crate::policy::FairnessPolicy,
    /// Raw/test-support-only retry policy.
    pub default_retry: RetrySelection,
    /// Raw/test-support-only execution timeout.
    pub default_timeout: std::time::Duration,
    /// Raw/test-support-only handler implementation.
    pub handler: H,
}

impl<H> HandlerDefinition<H> {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_cost_units("handler cost units", self.cost_units)?;
        validate_execution_timeout("handler timeout", Some(self.default_timeout))?;
        Ok(())
    }
}

/// Fixed policy values that are copied into a job record during
/// registration/enqueue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobPolicySnapshot {
    pub effect_mode: EffectMode,
    pub cost_units: NonZeroU16,
    pub execution_timeout: Option<Duration>,
    pub retry_policy: RetryPolicy,
}

impl JobPolicySnapshot {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_cost_units("job cost units", self.cost_units)?;
        validate_execution_timeout("execution timeout", self.execution_timeout)?;
        Ok(())
    }
}

/// A bounded protocol receipt retained after successful completion deletes the
/// live job. It is not an application audit record and contains no payload or
/// checkpoint data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationReceipt {
    /// Immutable enqueue definition, excluding mutable controller schedule.
    /// Legacy receipts lack this proof and cannot attest a stable seed replay.
    pub definition_digest: Option<[u8; 32]>,
    pub operation_id: OperationId,
    pub job_id: JobId,
    pub generation: u32,
    pub revision: u64,
    pub execution_id: ExecutionId,
    pub attempt_id: crate::ids::AttemptId,
    pub attempts: NonZeroU32,
    pub kind: JobKind,
    pub queue: QueueName,
    pub effect_mode: EffectMode,
    pub created_at: Timestamp,
    pub completed_at: Timestamp,
    pub owner: OwnerId,
    pub token: LeaseToken,
    pub fence: NonZeroU64,
    pub terminal: TerminalDisposition,
    pub outcome: OutcomeCode,
}

/// Terminal disposition recorded with a successful protocol transition.
///
/// This is lifecycle evidence, not an application audit record.  It contains
/// only the bounded identity, authority, and outcome fields needed to
/// reconcile an ambiguous commit after the live job has been deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TerminalDisposition {
    Completed,
}
