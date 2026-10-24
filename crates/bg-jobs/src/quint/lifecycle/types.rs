#![expect(
    clippy::enum_variant_names,
    reason = "Quint sum variants mirror the model vocabulary exactly"
)]

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum Node {
    NodeA,
    NodeB,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum JobId {
    JobA,
    JobB,
    JobC,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum JobState {
    Absent,
    Scheduled,
    Leased,
    RetryWaiting,
    DeadLettered,
    Cancelled,
    Suspended,
    Completed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum RecordKind {
    Valid,
    Missing,
    Corrupt,
    UnknownVersion,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum OperationId {
    OperationA,
    OperationB,
    OperationC,
    OperationD,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum StoreResult {
    Committed,
    Conflict,
    AuthorityChanged,
    Unknown,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum ResultClass {
    AppliedClass,
    RejectedClass,
    ConflictClass,
    UnknownClass,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum EnqueueDisposition {
    Inserted,
    AlreadyPresent,
    JobIdConflict,
    NotEnqueue,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum CompletionDetail {
    CompletionDetailReturned,
    CompletionDetailOmitted,
    NoCompletionDetail,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum HandlerResult {
    Success,
    Transient,
    Throttled,
    Permanent,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum LifecycleOutcome {
    Initialised,
    EnqueueCommitted,
    EnqueueFutureCommitted,
    EnqueueDedupeCommitted,
    EnqueueDedupeConflict,
    EnqueueRejected,
    EnqueueAlreadyPresent,
    EnqueueJobIdConflict,
    ClaimSelected,
    ClaimCommitted,
    ClaimConflict,
    Renewed,
    RenewRejected,
    CheckpointCommitted,
    CheckpointBoundRejected,
    CheckpointAuthorityRejected,
    CompletionDeleted,
    CompletionRejected,
    RetryTransient,
    RetryThrottled,
    RetryAmbiguous,
    PermanentDeadLetter,
    LeaseExpired,
    CancelCommitted,
    CancelRequested,
    LeasedCancelled,
    LeasedCancelRejected,
    Redriven,
    RedriveConflict,
    RedriveRejected,
    UnknownBeforeCommit,
    UnknownAfterCommit,
    UnknownReconciled,
    UnknownConflictReconciled,
    UnknownAuthorityChanged,
    StaleWriteRejected,
    RepairCommitted,
    RepairConflict,
    DedupeRegistered,
    DedupeReplayExisting,
    DedupeIdConflict,
    DedupeRetentionExpired,
    DedupeNotFound,
    QueuePaused,
    QueueResumed,
    PartialCommitRejected,
    CorruptQuarantined,
    UnknownVersionQuarantined,
    ScheduledExpired,
    TimeAdvanced,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum CancelPhase {
    CancelScheduled,
    RequestLeased,
    CommitLeased,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub state: JobState,
    pub node: Node,
    pub revision: i64,
    pub generation: i64,
    pub fence: i64,
    pub token: i64,
    pub lease_until: i64,
    pub due_at: i64,
    pub expires_at: i64,
    pub execution_id: i64,
    pub attempt_id: i64,
    pub attempts: i64,
    pub record: RecordKind,
    pub payload: bool,
    pub due_route: bool,
    pub lease_route: bool,
    pub fair_route: bool,
    pub wake_route: bool,
    pub checkpoint_bytes: i64,
    pub failure_recorded: bool,
    pub completion_receipt: bool,
    pub cancel_requested: bool,
    pub operation_id: OperationId,
    pub enqueue_fingerprint: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub now: i64,
    pub paused: bool,
    pub dedupe_active: bool,
    pub dedupe_job: JobId,
    pub dedupe_expired: bool,
    /// Connector-local finite labels for the next opaque lease token. The
    /// production lifecycle observation does not expose this value; it keeps
    /// token identity progression explicit without projecting a token onto a
    /// non-leased record.
    pub token_progression: BTreeMap<JobId, i64>,
    pub unknown_version_jobs: BTreeSet<JobId>,
    pub quarantine_snapshot: BTreeMap<JobId, Job>,
    pub quarantine_attempts: i64,
    pub unrelated_progress: i64,
    pub unknown_pending: bool,
    pub unknown_job: JobId,
    pub unknown_operation: OperationId,
    pub unknown_node: Node,
    pub unknown_revision: i64,
    pub unknown_generation: i64,
    pub unknown_fence: i64,
    pub unknown_token: i64,
    pub unknown_lease_until: i64,
    pub unknown_after_commit: bool,
    pub unknown_readback: StoreResult,
    pub completion_pending: bool,
    pub completion_job: JobId,
    pub completion_operation: OperationId,
    pub completion_revision: i64,
    pub completion_generation: i64,
    pub completion_detail: CompletionDetail,
    pub completion_detail_job: JobId,
    pub completion_omissions: i64,
    pub committed_terminal_jobs: BTreeSet<JobId>,
    pub claim_pending: bool,
    pub claim_job: JobId,
    pub claim_revision: i64,
    pub claim_reader: Node,
    pub last_attempt_revision: i64,
    pub last_attempt_applied: bool,
    pub last_attempt_operation: OperationId,
    pub last_attempt_job: JobId,
    pub completion_authority_recorded: bool,
    pub completion_authority_now: i64,
    pub completion_node: Node,
    pub completion_fence: i64,
    pub completion_token: i64,
    pub completion_lease_until: i64,
    pub completion_presented_node: Node,
    pub completion_presented_revision: i64,
    pub completion_presented_generation: i64,
    pub completion_presented_fence: i64,
    pub completion_presented_token: i64,
    pub completion_presented_lease_until: i64,
    pub completion_presented_operation: OperationId,
    pub presented_node: Node,
    pub presented_generation: i64,
    pub presented_fence: i64,
    pub presented_token: i64,
    pub presented_lease_until: i64,
    pub stale_node: Node,
    pub stale_revision: i64,
    pub stale_generation: i64,
    pub stale_fence: i64,
    pub stale_token: i64,
    pub stale_lease_until: i64,
    pub stale_operation: OperationId,
    pub last_enqueue_disposition: EnqueueDisposition,
    pub last_result: StoreResult,
    pub last_outcome: LifecycleOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityInput {
    pub job: JobId,
    pub node: Node,
    pub revision: i64,
    pub generation: i64,
    pub fence: i64,
    pub token: i64,
    pub lease_until: i64,
    pub operation: OperationId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "tag", content = "value")]
pub enum Command {
    LifecycleEnqueue {
        job: JobId,
        #[serde(rename = "dueAt")]
        due_at: i64,
        operation: OperationId,
        #[serde(rename = "withDedupe")]
        with_dedupe: bool,
        fingerprint: i64,
    },
    LifecycleSelectClaim {
        job: JobId,
        reader: Node,
        revision: i64,
    },
    LifecycleClaim {
        job: JobId,
        contender: Node,
        revision: i64,
    },
    LifecycleRenew(AuthorityInput),
    LifecycleCheckpoint {
        authority: AuthorityInput,
        bytes: i64,
    },
    LifecycleHandle {
        authority: AuthorityInput,
        handler: HandlerResult,
    },
    LifecycleComplete(AuthorityInput),
    LifecycleExpose {
        job: JobId,
        operation: OperationId,
        revision: i64,
        generation: i64,
    },
    LifecycleCancel {
        authority: AuthorityInput,
        phase: CancelPhase,
    },
    LifecycleAdvance {
        amount: i64,
    },
    LifecycleExpire {
        job: JobId,
        lease: bool,
    },
    LifecycleUnknown {
        authority: AuthorityInput,
        committed: bool,
    },
    LifecycleReconcile {
        job: JobId,
        operation: OperationId,
        observed: StoreResult,
    },
    LifecycleCorrupt {
        job: JobId,
        kind: RecordKind,
    },
    LifecycleRepair {
        job: JobId,
        revision: i64,
        operation: OperationId,
    },
    LifecycleRedrive {
        job: JobId,
        #[serde(rename = "expectedRevision")]
        expected_revision: i64,
        #[serde(rename = "expectedOperation")]
        expected_operation: OperationId,
        #[serde(rename = "reuseExecution")]
        reuse_execution: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LastTransition {
    pub command: Command,
    pub class: ResultClass,
    pub result: StoreResult,
    pub outcome: LifecycleOutcome,
    pub detail: CompletionDetail,
    pub enqueue: EnqueueDisposition,
    pub job: JobId,
    pub operation: OperationId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "tag", content = "value")]
pub enum CommandResult {
    LifecycleApplied(LastTransition),
    LifecycleRejected(LastTransition),
    LifecycleConflict(LastTransition),
    LifecycleUnknownResult(LastTransition),
    LifecycleDetailOmitted(LastTransition),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateProjection {
    pub jobs: BTreeMap<JobId, Job>,
    pub meta: Meta,
    #[serde(rename = "lastCommand")]
    pub command: Command,
    #[serde(rename = "lastTransition")]
    pub transition: LastTransition,
    #[serde(rename = "lastCommandResult")]
    pub result: CommandResult,
}

macro_rules! first_mismatch {
    ($path:expr, $expected:expr, $actual:expr) => {
        if $expected != $actual {
            return Some(format!(
                "{}: expected {:?}, actual {:?}",
                $path, $expected, $actual
            ));
        }
    };
}

fn first_job_difference(path: &str, expected: &Job, actual: &Job) -> Option<String> {
    first_mismatch!(format!("{path}.state"), &expected.state, &actual.state);
    first_mismatch!(format!("{path}.node"), &expected.node, &actual.node);
    first_mismatch!(
        format!("{path}.revision"),
        &expected.revision,
        &actual.revision
    );
    first_mismatch!(
        format!("{path}.generation"),
        &expected.generation,
        &actual.generation
    );
    first_mismatch!(format!("{path}.fence"), &expected.fence, &actual.fence);
    first_mismatch!(format!("{path}.token"), &expected.token, &actual.token);
    first_mismatch!(
        format!("{path}.lease_until"),
        &expected.lease_until,
        &actual.lease_until
    );
    first_mismatch!(format!("{path}.due_at"), &expected.due_at, &actual.due_at);
    first_mismatch!(
        format!("{path}.expires_at"),
        &expected.expires_at,
        &actual.expires_at
    );
    first_mismatch!(
        format!("{path}.execution_id"),
        &expected.execution_id,
        &actual.execution_id
    );
    first_mismatch!(
        format!("{path}.attempt_id"),
        &expected.attempt_id,
        &actual.attempt_id
    );
    first_mismatch!(
        format!("{path}.attempts"),
        &expected.attempts,
        &actual.attempts
    );
    first_mismatch!(format!("{path}.record"), &expected.record, &actual.record);
    first_mismatch!(
        format!("{path}.payload"),
        &expected.payload,
        &actual.payload
    );
    first_mismatch!(
        format!("{path}.due_route"),
        &expected.due_route,
        &actual.due_route
    );
    first_mismatch!(
        format!("{path}.lease_route"),
        &expected.lease_route,
        &actual.lease_route
    );
    first_mismatch!(
        format!("{path}.fair_route"),
        &expected.fair_route,
        &actual.fair_route
    );
    first_mismatch!(
        format!("{path}.wake_route"),
        &expected.wake_route,
        &actual.wake_route
    );
    first_mismatch!(
        format!("{path}.checkpoint_bytes"),
        &expected.checkpoint_bytes,
        &actual.checkpoint_bytes
    );
    first_mismatch!(
        format!("{path}.failure_recorded"),
        &expected.failure_recorded,
        &actual.failure_recorded
    );
    first_mismatch!(
        format!("{path}.completion_receipt"),
        &expected.completion_receipt,
        &actual.completion_receipt
    );
    first_mismatch!(
        format!("{path}.cancel_requested"),
        &expected.cancel_requested,
        &actual.cancel_requested
    );
    first_mismatch!(
        format!("{path}.operation_id"),
        &expected.operation_id,
        &actual.operation_id
    );
    first_mismatch!(
        format!("{path}.enqueue_fingerprint"),
        &expected.enqueue_fingerprint,
        &actual.enqueue_fingerprint
    );
    None
}

fn first_jobs_difference(
    path: &str,
    expected: &BTreeMap<JobId, Job>,
    actual: &BTreeMap<JobId, Job>,
) -> Option<String> {
    for job in [JobId::JobA, JobId::JobB, JobId::JobC] {
        match (expected.get(&job), actual.get(&job)) {
            (Some(expected), Some(actual)) => {
                if let Some(difference) =
                    first_job_difference(&format!("{path}.{job:?}"), expected, actual)
                {
                    return Some(difference);
                }
            }
            (None, Some(actual)) => {
                return Some(format!(
                    "{path}.{job:?}: expected missing job, actual {:?}",
                    actual
                ));
            }
            (Some(expected), None) => {
                return Some(format!(
                    "{path}.{job:?}: expected {:?}, actual missing job",
                    expected
                ));
            }
            (None, None) => {}
        }
    }
    if expected.len() != actual.len() {
        return Some(format!(
            "{path}: expected {} jobs, actual {} jobs",
            expected.len(),
            actual.len()
        ));
    }
    None
}

fn first_meta_difference(path: &str, expected: &Meta, actual: &Meta) -> Option<String> {
    first_mismatch!(format!("{path}.now"), &expected.now, &actual.now);
    first_mismatch!(format!("{path}.paused"), &expected.paused, &actual.paused);
    first_mismatch!(
        format!("{path}.dedupe_active"),
        &expected.dedupe_active,
        &actual.dedupe_active
    );
    first_mismatch!(
        format!("{path}.dedupe_job"),
        &expected.dedupe_job,
        &actual.dedupe_job
    );
    first_mismatch!(
        format!("{path}.dedupe_expired"),
        &expected.dedupe_expired,
        &actual.dedupe_expired
    );
    first_mismatch!(
        format!("{path}.unknown_version_jobs"),
        &expected.unknown_version_jobs,
        &actual.unknown_version_jobs
    );
    if let Some(difference) = first_jobs_difference(
        &format!("{path}.quarantine_snapshot"),
        &expected.quarantine_snapshot,
        &actual.quarantine_snapshot,
    ) {
        return Some(difference);
    }
    first_mismatch!(
        format!("{path}.quarantine_attempts"),
        &expected.quarantine_attempts,
        &actual.quarantine_attempts
    );
    first_mismatch!(
        format!("{path}.unrelated_progress"),
        &expected.unrelated_progress,
        &actual.unrelated_progress
    );
    first_mismatch!(
        format!("{path}.unknown_pending"),
        &expected.unknown_pending,
        &actual.unknown_pending
    );
    first_mismatch!(
        format!("{path}.unknown_job"),
        &expected.unknown_job,
        &actual.unknown_job
    );
    first_mismatch!(
        format!("{path}.unknown_operation"),
        &expected.unknown_operation,
        &actual.unknown_operation
    );
    first_mismatch!(
        format!("{path}.unknown_node"),
        &expected.unknown_node,
        &actual.unknown_node
    );
    first_mismatch!(
        format!("{path}.unknown_revision"),
        &expected.unknown_revision,
        &actual.unknown_revision
    );
    first_mismatch!(
        format!("{path}.unknown_generation"),
        &expected.unknown_generation,
        &actual.unknown_generation
    );
    first_mismatch!(
        format!("{path}.unknown_fence"),
        &expected.unknown_fence,
        &actual.unknown_fence
    );
    first_mismatch!(
        format!("{path}.unknown_token"),
        &expected.unknown_token,
        &actual.unknown_token
    );
    first_mismatch!(
        format!("{path}.unknown_lease_until"),
        &expected.unknown_lease_until,
        &actual.unknown_lease_until
    );
    first_mismatch!(
        format!("{path}.unknown_after_commit"),
        &expected.unknown_after_commit,
        &actual.unknown_after_commit
    );
    first_mismatch!(
        format!("{path}.unknown_readback"),
        &expected.unknown_readback,
        &actual.unknown_readback
    );
    first_mismatch!(
        format!("{path}.completion_pending"),
        &expected.completion_pending,
        &actual.completion_pending
    );
    first_mismatch!(
        format!("{path}.completion_job"),
        &expected.completion_job,
        &actual.completion_job
    );
    first_mismatch!(
        format!("{path}.completion_operation"),
        &expected.completion_operation,
        &actual.completion_operation
    );
    first_mismatch!(
        format!("{path}.completion_revision"),
        &expected.completion_revision,
        &actual.completion_revision
    );
    first_mismatch!(
        format!("{path}.completion_generation"),
        &expected.completion_generation,
        &actual.completion_generation
    );
    first_mismatch!(
        format!("{path}.completion_detail"),
        &expected.completion_detail,
        &actual.completion_detail
    );
    first_mismatch!(
        format!("{path}.completion_detail_job"),
        &expected.completion_detail_job,
        &actual.completion_detail_job
    );
    first_mismatch!(
        format!("{path}.completion_omissions"),
        &expected.completion_omissions,
        &actual.completion_omissions
    );
    first_mismatch!(
        format!("{path}.committed_terminal_jobs"),
        &expected.committed_terminal_jobs,
        &actual.committed_terminal_jobs
    );
    first_mismatch!(
        format!("{path}.claim_pending"),
        &expected.claim_pending,
        &actual.claim_pending
    );
    first_mismatch!(
        format!("{path}.claim_job"),
        &expected.claim_job,
        &actual.claim_job
    );
    first_mismatch!(
        format!("{path}.claim_revision"),
        &expected.claim_revision,
        &actual.claim_revision
    );
    first_mismatch!(
        format!("{path}.claim_reader"),
        &expected.claim_reader,
        &actual.claim_reader
    );
    first_mismatch!(
        format!("{path}.last_attempt_revision"),
        &expected.last_attempt_revision,
        &actual.last_attempt_revision
    );
    first_mismatch!(
        format!("{path}.last_attempt_applied"),
        &expected.last_attempt_applied,
        &actual.last_attempt_applied
    );
    first_mismatch!(
        format!("{path}.last_attempt_operation"),
        &expected.last_attempt_operation,
        &actual.last_attempt_operation
    );
    first_mismatch!(
        format!("{path}.last_attempt_job"),
        &expected.last_attempt_job,
        &actual.last_attempt_job
    );
    first_mismatch!(
        format!("{path}.completion_authority_recorded"),
        &expected.completion_authority_recorded,
        &actual.completion_authority_recorded
    );
    first_mismatch!(
        format!("{path}.completion_authority_now"),
        &expected.completion_authority_now,
        &actual.completion_authority_now
    );
    first_mismatch!(
        format!("{path}.completion_node"),
        &expected.completion_node,
        &actual.completion_node
    );
    first_mismatch!(
        format!("{path}.completion_fence"),
        &expected.completion_fence,
        &actual.completion_fence
    );
    first_mismatch!(
        format!("{path}.completion_token"),
        &expected.completion_token,
        &actual.completion_token
    );
    first_mismatch!(
        format!("{path}.completion_lease_until"),
        &expected.completion_lease_until,
        &actual.completion_lease_until
    );
    first_mismatch!(
        format!("{path}.completion_presented_node"),
        &expected.completion_presented_node,
        &actual.completion_presented_node
    );
    first_mismatch!(
        format!("{path}.completion_presented_revision"),
        &expected.completion_presented_revision,
        &actual.completion_presented_revision
    );
    first_mismatch!(
        format!("{path}.completion_presented_generation"),
        &expected.completion_presented_generation,
        &actual.completion_presented_generation
    );
    first_mismatch!(
        format!("{path}.completion_presented_fence"),
        &expected.completion_presented_fence,
        &actual.completion_presented_fence
    );
    first_mismatch!(
        format!("{path}.completion_presented_token"),
        &expected.completion_presented_token,
        &actual.completion_presented_token
    );
    first_mismatch!(
        format!("{path}.completion_presented_lease_until"),
        &expected.completion_presented_lease_until,
        &actual.completion_presented_lease_until
    );
    first_mismatch!(
        format!("{path}.completion_presented_operation"),
        &expected.completion_presented_operation,
        &actual.completion_presented_operation
    );
    first_mismatch!(
        format!("{path}.presented_node"),
        &expected.presented_node,
        &actual.presented_node
    );
    first_mismatch!(
        format!("{path}.presented_generation"),
        &expected.presented_generation,
        &actual.presented_generation
    );
    first_mismatch!(
        format!("{path}.presented_fence"),
        &expected.presented_fence,
        &actual.presented_fence
    );
    first_mismatch!(
        format!("{path}.presented_token"),
        &expected.presented_token,
        &actual.presented_token
    );
    first_mismatch!(
        format!("{path}.presented_lease_until"),
        &expected.presented_lease_until,
        &actual.presented_lease_until
    );
    first_mismatch!(
        format!("{path}.stale_node"),
        &expected.stale_node,
        &actual.stale_node
    );
    first_mismatch!(
        format!("{path}.stale_revision"),
        &expected.stale_revision,
        &actual.stale_revision
    );
    first_mismatch!(
        format!("{path}.stale_generation"),
        &expected.stale_generation,
        &actual.stale_generation
    );
    first_mismatch!(
        format!("{path}.stale_fence"),
        &expected.stale_fence,
        &actual.stale_fence
    );
    first_mismatch!(
        format!("{path}.stale_token"),
        &expected.stale_token,
        &actual.stale_token
    );
    first_mismatch!(
        format!("{path}.stale_lease_until"),
        &expected.stale_lease_until,
        &actual.stale_lease_until
    );
    first_mismatch!(
        format!("{path}.stale_operation"),
        &expected.stale_operation,
        &actual.stale_operation
    );
    first_mismatch!(
        format!("{path}.last_enqueue_disposition"),
        &expected.last_enqueue_disposition,
        &actual.last_enqueue_disposition
    );
    first_mismatch!(
        format!("{path}.last_result"),
        &expected.last_result,
        &actual.last_result
    );
    first_mismatch!(
        format!("{path}.last_outcome"),
        &expected.last_outcome,
        &actual.last_outcome
    );
    None
}

impl PartialEq for StateProjection {
    fn eq(&self, other: &Self) -> bool {
        let difference = first_jobs_difference("jobs", &self.jobs, &other.jobs)
            .or_else(|| first_meta_difference("meta", &self.meta, &other.meta))
            .or_else(|| {
                (self.command != other.command).then(|| {
                    format!(
                        "command: expected {:?}, actual {:?}",
                        self.command, other.command
                    )
                })
            })
            .or_else(|| {
                (self.transition != other.transition).then(|| {
                    format!(
                        "transition: expected {:?}, actual {:?}",
                        self.transition, other.transition
                    )
                })
            })
            .or_else(|| {
                (self.result != other.result).then(|| {
                    format!(
                        "result: expected {:?}, actual {:?}",
                        self.result, other.result
                    )
                })
            });
        difference.is_none()
    }
}

impl Eq for StateProjection {}
