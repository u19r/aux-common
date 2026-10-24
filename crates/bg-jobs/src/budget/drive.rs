use std::num::{NonZeroU16, NonZeroU32, NonZeroUsize};

use crate::{
    error::ValidationError,
    ids::QueueName,
    policy::EffectMode,
    time::{MonotonicDeadline, Timestamp, WakeHint},
};

/// Selection of queues for one bounded drive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueSelection {
    kind: QueueSelectionKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum QueueSelectionKind {
    All,
    Only(Vec<QueueName>),
}

impl QueueSelection {
    pub const MAX_QUEUES: usize = 64;

    pub fn only(queues: Vec<QueueName>) -> Result<Self, ValidationError> {
        if queues.is_empty() {
            return Err(ValidationError::Empty {
                field: "queue selection",
            });
        }
        if queues.len() > Self::MAX_QUEUES {
            return Err(ValidationError::TooLong {
                field: "queue selection",
                maximum: Self::MAX_QUEUES,
                actual: queues.len(),
            });
        }
        Ok(Self {
            kind: QueueSelectionKind::Only(queues),
        })
    }

    pub const fn all() -> Self {
        Self {
            kind: QueueSelectionKind::All,
        }
    }

    /// Returns whether this selection includes every queue.
    pub const fn is_all(&self) -> bool {
        matches!(&self.kind, QueueSelectionKind::All)
    }

    /// Returns the selected queue names for an explicit selection. `None`
    /// means that the selection includes every queue.
    pub fn as_only(&self) -> Option<&[QueueName]> {
        match &self.kind {
            QueueSelectionKind::All => None,
            QueueSelectionKind::Only(queues) => Some(queues),
        }
    }

    /// Iterates explicit queue names without exposing mutable selection state.
    pub fn iter(&self) -> std::slice::Iter<'_, QueueName> {
        self.as_only().unwrap_or(&[]).iter()
    }
}

/// Bounded drive request. The constructor enforces receipt and deadline
/// invariants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveRequest {
    queues: QueueSelection,
    max_claims: NonZeroU32,
    max_concurrency: NonZeroU16,
    max_payload_bytes_in_flight: NonZeroUsize,
    max_completion_details: u32,
    max_store_operations: NonZeroU32,
    stop_claiming_at: MonotonicDeadline,
    finish_by: MonotonicDeadline,
}

/// Inputs for constructing a drive request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveRequestInput {
    pub queues: QueueSelection,
    pub max_claims: NonZeroU32,
    pub max_concurrency: NonZeroU16,
    pub max_payload_bytes_in_flight: NonZeroUsize,
    pub max_completion_details: u32,
    pub max_store_operations: NonZeroU32,
    pub stop_claiming_at: MonotonicDeadline,
    pub finish_by: MonotonicDeadline,
}

impl DriveRequest {
    fn try_from_input(input: DriveRequestInput) -> Result<Self, ValidationError> {
        if input.max_completion_details > input.max_claims.get() {
            return Err(ValidationError::InvalidValue {
                field: "max completion details",
            });
        }
        if input.finish_by.is_before(input.stop_claiming_at) {
            return Err(ValidationError::Ordering {
                field: "drive deadlines",
            });
        }
        Ok(Self {
            queues: input.queues,
            max_claims: input.max_claims,
            max_concurrency: input.max_concurrency,
            max_payload_bytes_in_flight: input.max_payload_bytes_in_flight,
            max_completion_details: input.max_completion_details,
            max_store_operations: input.max_store_operations,
            stop_claiming_at: input.stop_claiming_at,
            finish_by: input.finish_by,
        })
    }

    /// Returns the validated queue selection.
    pub const fn queues(&self) -> &QueueSelection {
        &self.queues
    }

    /// Returns the maximum number of claims this drive may report.
    pub const fn max_claims(&self) -> NonZeroU32 {
        self.max_claims
    }

    /// Returns the maximum number of handlers that may run concurrently.
    pub const fn max_concurrency(&self) -> NonZeroU16 {
        self.max_concurrency
    }

    /// Returns the aggregate in-flight payload byte budget.
    pub const fn max_payload_bytes_in_flight(&self) -> NonZeroUsize {
        self.max_payload_bytes_in_flight
    }

    /// Returns the maximum number of completion details to retain.
    pub const fn max_completion_details(&self) -> u32 {
        self.max_completion_details
    }

    /// Returns the maximum number of store operations permitted by this drive.
    pub const fn max_store_operations(&self) -> NonZeroU32 {
        self.max_store_operations
    }

    /// Returns the monotonic deadline after which claiming stops.
    pub const fn stop_claiming_at(&self) -> MonotonicDeadline {
        self.stop_claiming_at
    }

    /// Returns the monotonic deadline after which the drive must finish.
    pub const fn finish_by(&self) -> MonotonicDeadline {
        self.finish_by
    }
}

impl TryFrom<DriveRequestInput> for DriveRequest {
    type Error = ValidationError;

    fn try_from(input: DriveRequestInput) -> Result<Self, Self::Error> {
        Self::try_from_input(input)
    }
}

/// Closed reason for a bounded drive stopping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DriveStopReason {
    ClaimsExhausted,
    Deadline,
    Shutdown,
    NoVisibleWork,
    Capacity,
    StoreFailure,
}

/// Aggregate transition counts returned by a drive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriveCounts {
    pub claimed: u32,
    pub succeeded: u32,
    pub continued: u32,
    pub retried: u32,
    pub dead_lettered: u32,
    pub cancelled: u32,
    pub lease_conflicts: u32,
    pub capacity_deferrals: u32,
    pub repair_actions: u32,
}

/// A registration-safe terminal completion receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionDetails {
    pub job_id: crate::ids::JobId,
    pub execution_id: crate::ids::ExecutionId,
    pub generation: u32,
    pub kind: crate::ids::JobKind,
    pub queue: QueueName,
    pub effect_mode: EffectMode,
    pub created_at: Timestamp,
    pub completed_at: Timestamp,
    pub attempts: NonZeroU32,
    pub outcome: crate::policy::OutcomeCode,
}

/// Result of one bounded drive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveReport {
    pub counts: DriveCounts,
    pub completions: Vec<CompletionDetails>,
    pub completions_omitted: u32,
    pub has_immediately_visible_work: bool,
    pub next_wake: WakeHint,
    pub stop_reason: DriveStopReason,
}
