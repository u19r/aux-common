//! Results and authority values returned by checked recovery transitions.

use crate::{
    budget::CompletionDetails,
    ids::{ExecutionId, JobId, OperationId},
    policy::{OutcomeCode, RetryClass},
    time::Timestamp,
};

/// Result of one handler outcome after the lease-gated transition commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutcomeResult {
    Completed(CompletionDetails),
    Continued {
        not_before: Timestamp,
    },
    Retried {
        class: RetryClass,
        not_before: Timestamp,
    },
    DeadLettered {
        code: OutcomeCode,
    },
    Cancelled,
}

/// Result of a conditional lease heartbeat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenewalResult {
    Renewed { expires_at: Timestamp },
    Coalesced { expires_at: Timestamp },
}

/// Result of a bounded checkpoint write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointResult {
    pub bytes: u32,
}

/// Result of a cancellation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancellationResult {
    Requested,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryResult {
    Cancelled,
    DeadLettered,
    LeaseExpired,
    Unchanged,
}

/// Explicit execution identity policy for operator redrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RedriveExecution {
    ReuseExecutionId,
    NewExecutionId,
}

/// Expected authority and scheduling choice for one redrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedriveRequest {
    pub expected_revision: u64,
    pub expected_operation: OperationId,
    pub execution: RedriveExecution,
    pub scheduled_at: Timestamp,
}

impl RedriveRequest {
    pub const fn new(
        expected_revision: u64,
        expected_operation: OperationId,
        execution: RedriveExecution,
        scheduled_at: Timestamp,
    ) -> Self {
        Self {
            expected_revision,
            expected_operation,
            execution,
            scheduled_at,
        }
    }
}

/// Receipt returned only after the redrive transaction is known to have
/// committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedriveResult {
    pub job_id: JobId,
    pub generation: u32,
    pub execution_id: ExecutionId,
    pub reused_execution: bool,
}
