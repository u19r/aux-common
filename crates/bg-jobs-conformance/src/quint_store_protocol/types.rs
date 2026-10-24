#![allow(clippy::enum_variant_names)]

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
pub enum StoreOutcome {
    Initialised,
    AtomicEnqueue,
    ConflictNoMutation,
    CompletionDeletedAllKeys,
    UnknownCommitRequiresReconcile,
    ReconciledCommitted,
    ReconciledConflict,
    ReconciledAuthorityChanged,
    CorruptQuarantined,
    UnknownVersionQuarantined,
    MissingIndexDiscovered,
    DanglingRecordCreated,
    DanglingIndexPurged,
    RepairCommitted,
    RepairRevisionConflict,
    PartialTransactionRejected,
    PayloadRejected,
    ClaimSelected,
    ClaimAtomicCommit,
    ClaimConflictNoMutation,
    LeaseRenewed,
    LeaseRenewConflict,
    LeaseExpiredToReady,
    TimeAdvanced,
    EnqueueAlreadyPresent,
    EnqueueJobIdConflict,
    HandlerDeadLetter,
    RedriveCommitted,
    RedriveConflict,
    RedriveRejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub exists: bool,
    pub state: JobState,
    pub kind: RecordKind,
    pub revision: i64,
    pub node: Node,
    pub generation: i64,
    pub fence: i64,
    pub token: i64,
    pub leased: bool,
    pub lease_until: i64,
    pub expires_at: i64,
    pub operation_id: OperationId,
    pub enqueue_fingerprint: i64,
    pub execution_id: i64,
    pub attempt_id: i64,
    pub attempts: i64,
    pub payload_bytes: i64,
    pub manifest_bytes: i64,
    pub chunk_bytes: i64,
    pub digest_bytes: i64,
    pub checkpoint_bytes: i64,
    pub payload: bool,
    pub failure_recorded: bool,
    pub dlq_route: bool,
    pub due_route: bool,
    pub fair_route: bool,
    pub lease_route: bool,
    pub wake_route: bool,
    pub permit_held: bool,
    pub rate_held: bool,
    pub in_flight: i64,
    pub dangling: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub wake_watermark: bool,
    pub now: i64,
    pub unknown_pending: bool,
    pub unknown_job: JobId,
    pub unknown_operation: OperationId,
    pub unknown_node: Node,
    pub unknown_revision: i64,
    pub unknown_generation: i64,
    pub unknown_fence: i64,
    pub unknown_token: i64,
    pub unknown_lease_until: i64,
    pub unknown_readback: StoreResult,
    pub unknown_version_jobs: BTreeSet<JobId>,
    pub quarantine_snapshot: BTreeMap<JobId, Record>,
    pub quarantine_attempts: i64,
    pub last_enqueue_disposition: EnqueueDisposition,
    pub last_result: StoreResult,
    pub last_outcome: StoreOutcome,
    pub transaction_checks: i64,
    pub transaction_mutations: i64,
    pub transaction_bytes: i64,
    pub repair_steps: i64,
    pub unrelated_progress: i64,
    pub completion_receipts: i64,
    pub completion_detail: CompletionDetail,
    pub last_detail: CompletionDetail,
    pub completion_detail_job: JobId,
    pub committed_terminal_jobs: BTreeSet<JobId>,
    pub claim_pending: bool,
    pub claim_job: JobId,
    pub claim_revision: i64,
    pub claim_reader: Node,
    pub last_authority_node: Node,
    pub last_authority_revision: i64,
    pub last_authority_generation: i64,
    pub last_authority_fence: i64,
    pub last_authority_token: i64,
    pub last_authority_lease_until: i64,
    pub last_authority_operation: OperationId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct AuthorityInput {
    pub job: JobId,
    pub node: Node,
    pub revision: i64,
    pub generation: i64,
    pub fence: i64,
    pub token: i64,
    #[serde(rename = "leaseUntil")]
    pub lease_until: i64,
    pub operation: OperationId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ResourceInput {
    #[serde(rename = "payloadBytes")]
    pub payload_bytes: i64,
    #[serde(rename = "manifestBytes")]
    pub manifest_bytes: i64,
    #[serde(rename = "chunkBytes")]
    pub chunk_bytes: i64,
    #[serde(rename = "digestBytes")]
    pub digest_bytes: i64,
    #[serde(rename = "checkpointBytes")]
    pub checkpoint_bytes: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "tag", content = "value")]
pub enum Command {
    StoreEnqueue {
        job: JobId,
        operation: OperationId,
        resources: ResourceInput,
        fingerprint: i64,
    },
    StoreSelectClaim {
        job: JobId,
        reader: Node,
        revision: i64,
    },
    StoreClaim {
        job: JobId,
        contender: Node,
        revision: i64,
    },
    StoreRenew(AuthorityInput),
    StoreComplete(AuthorityInput),
    StoreDeadLetter {
        authority: AuthorityInput,
        handler: HandlerResult,
    },
    StoreRedrive {
        job: JobId,
        revision: i64,
        operation: OperationId,
        #[serde(rename = "reuseExecution")]
        reuse_execution: bool,
    },
    StoreUnknown {
        authority: AuthorityInput,
        committed: bool,
    },
    StoreReconcile {
        job: JobId,
        operation: OperationId,
        observed: StoreResult,
    },
    StoreCorrupt {
        job: JobId,
        kind: RecordKind,
    },
    StoreDropRoute {
        job: JobId,
        due: bool,
        fair: bool,
        lease: bool,
        wake: bool,
    },
    StoreRepair {
        job: JobId,
        revision: i64,
        operation: OperationId,
    },
    StorePurge {
        job: JobId,
        revision: i64,
    },
    StoreAdvance {
        amount: i64,
    },
    StoreExpire {
        job: JobId,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LastTransition {
    pub command: Command,
    pub class: ResultClass,
    pub result: StoreResult,
    pub outcome: StoreOutcome,
    pub detail: CompletionDetail,
    pub enqueue: EnqueueDisposition,
    pub job: JobId,
    pub operation: OperationId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "tag", content = "value")]
pub enum CommandResult {
    StoreApplied(LastTransition),
    StoreRejected(LastTransition),
    StoreConflictResult(LastTransition),
    StoreUnknownResult(LastTransition),
    StoreDetailOmitted(LastTransition),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StateProjection {
    pub records: BTreeMap<JobId, Record>,
    pub meta: Meta,
    #[serde(rename = "lastCommand")]
    pub command: Command,
    #[serde(rename = "lastTransition")]
    pub transition: LastTransition,
    #[serde(rename = "lastCommandResult")]
    pub result: CommandResult,
}
