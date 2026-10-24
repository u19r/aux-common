#![allow(clippy::enum_variant_names)]

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum JobId {
    JobA,
    JobB,
    JobC,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum Priority {
    Critical,
    Default,
    Bulk,
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
pub enum Scope {
    ScopeA,
    ScopeB,
    ScopeA1,
    ScopeA2,
    ScopeB1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum OrderingGroup {
    OrderA,
    OrderB,
    OrderC,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum BlockReason {
    Unblocked,
    LeasedHead,
    CorruptHead,
    OversizedHead,
    PoisonHead,
    RateLimitedHead,
    CapacityBlockedHead,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum VolumeMode {
    ScopedVolume,
    LowVolume,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum HandlerKind {
    HandlerA,
    HandlerB,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum BatchKey {
    BatchA,
    BatchB,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum AuthConfigId {
    AuthConfigA,
    AuthConfigB,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum EffectModeModel {
    ReadOnlyEffect,
    IdempotentEffect,
    AtLeastOnceEffect,
    FencedEffect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum RetryPolicyModel {
    InteractiveRetry,
    NetworkRetry,
    MaintenanceRetry,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum TimeoutPolicyModel {
    ShortTimeout,
    LongTimeout,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum BatchResult {
    ItemSuccess,
    ItemRetry,
    ItemDeadLetter,
    ItemMissing,
    ItemDuplicate,
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
pub enum FairOutcome {
    Initialised,
    HeadReady,
    SelectionServed,
    SelectionRejected,
    BulkForced,
    QuietTick,
    HeadBlocked,
    HolEscaped,
    RateBlocked,
    CapacityBlocked,
    PermitBlocked,
    LowVolumeRejected,
    BatchPartial,
    ScratchCleared,
    ScratchShrunk,
    ServiceErrorRecorded,
    ClaimReleased,
    ScopeRefilled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FairJob {
    pub state: JobState,
    pub record: RecordKind,
    pub payload: bool,
    pub due_route: bool,
    pub fair_route: bool,
    pub due_at: i64,
    pub scope: Scope,
    pub priority: Priority,
    pub ordering: OrderingGroup,
    pub order: i64,
    pub order_head: i64,
    pub cost: i64,
    pub block: BlockReason,
    pub payload_bytes: i64,
    pub handler_kind: HandlerKind,
    pub schema_version: i64,
    pub batch_key: BatchKey,
    pub auth_config: AuthConfigId,
    pub effect_mode: EffectModeModel,
    pub retry_policy: RetryPolicyModel,
    pub timeout_policy: TimeoutPolicyModel,
    pub service_transitions: i64,
    pub enqueued_at: i64,
    pub batch_deadline: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScopeState {
    pub primary: Scope,
    pub secondary: bool,
    pub share: i64,
    pub mode: VolumeMode,
    pub ready: bool,
    pub priority: Priority,
    pub candidates: BTreeSet<JobId>,
    pub head: i64,
    pub order: i64,
    pub cost: i64,
    pub block: BlockReason,
    pub in_flight: i64,
    pub permits: i64,
    pub rate: i64,
    pub quiet_dwell: i64,
    pub served: i64,
    pub served_cost: i64,
    pub errors: i64,
    pub acquisitions: i64,
    pub releases: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OrderState {
    pub head: i64,
    pub in_flight: bool,
    pub owner: JobId,
    pub acquisitions: i64,
    pub releases: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub cycle: i64,
    pub critical_served: i64,
    pub default_served: i64,
    pub bulk_served: i64,
    pub critical_window: i64,
    pub default_window: i64,
    pub bulk_window: i64,
    pub hol_escapes: i64,
    pub batch_active: bool,
    pub batch_scope: Scope,
    pub batch_auth_config: AuthConfigId,
    pub batch_members: BTreeSet<JobId>,
    pub batch_results: BTreeMap<JobId, BatchResult>,
    pub scratch_size: i64,
    pub scratch_capacity: i64,
    pub batch_payload_bytes: i64,
    pub batch_formed_at: i64,
    pub batch_deadline: i64,
    pub selected_scope: Scope,
    pub selected_job: JobId,
    pub selected_cost: i64,
    pub service_transitions: i64,
    pub last_outcome: FairOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CandidateInput {
    pub job: JobId,
    pub scope: Scope,
    pub primary: Scope,
    pub priority: Priority,
    pub cost: i64,
    pub ordering: OrderingGroup,
    pub order: i64,
    pub order_head: i64,
    pub order_in_flight: bool,
    pub permits: i64,
    pub rate: i64,
    pub in_flight: i64,
    pub primary_permits: i64,
    pub primary_rate: i64,
    pub primary_in_flight: i64,
    pub payload_bytes: i64,
    pub handler_kind: HandlerKind,
    pub schema_version: i64,
    pub batch_key: BatchKey,
    pub auth_config: AuthConfigId,
    pub effect_mode: EffectModeModel,
    pub retry_policy: RetryPolicyModel,
    pub timeout_policy: TimeoutPolicyModel,
    pub enqueued_at: i64,
    pub batch_deadline: i64,
    pub mode: VolumeMode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SelectInput {
    pub candidate: CandidateInput,
    pub now: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "tag", content = "value")]
pub enum Command {
    FairSeed {
        job: JobId,
        priority: Priority,
    },
    FairBatchCandidate(CandidateInput),
    FairSelect(SelectInput),
    FairRelease {
        candidate: CandidateInput,
        result: BatchResult,
    },
    FairTick {
        cycle: i64,
    },
    FairBlock {
        job: JobId,
        reason: BlockReason,
    },
    FairHolEscape {
        blocked: JobId,
        candidate: CandidateInput,
    },
    FairRefill {
        scope: Scope,
        primary: Scope,
    },
    FairLowVolume(CandidateInput),
    FairBatchStart {
        first: CandidateInput,
        second: CandidateInput,
        capacity: i64,
    },
    FairBatchItem {
        job: JobId,
        result: BatchResult,
    },
    FairScratch {
        clear: bool,
        capacity: i64,
    },
    FairService {
        candidate: CandidateInput,
        #[serde(rename = "refillRate")]
        refill_rate: bool,
    },
    FairResetWindow {
        critical: i64,
        default: i64,
        bulk: i64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LastTransition {
    pub command: Command,
    pub class: ResultClass,
    pub outcome: FairOutcome,
    pub job: JobId,
    pub scope: Scope,
    pub priority: Priority,
    pub registered_cost: i64,
    pub reason: BlockReason,
    pub handler_kind: HandlerKind,
    pub schema_version: i64,
    pub batch_key: BatchKey,
    pub auth_config: AuthConfigId,
    pub effect_mode: EffectModeModel,
    pub retry_policy: RetryPolicyModel,
    pub timeout_policy: TimeoutPolicyModel,
    pub payload_bytes: i64,
    pub enqueued_at: i64,
    pub batch_deadline: i64,
    pub permits: i64,
    pub rate: i64,
    pub in_flight: i64,
    pub primary_permits: i64,
    pub primary_rate: i64,
    pub primary_in_flight: i64,
    pub scratch_capacity: i64,
    pub batch_active: bool,
    pub members: BTreeSet<JobId>,
    pub results: BTreeMap<JobId, BatchResult>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "tag", content = "value")]
pub enum CommandResult {
    FairApplied {
        transition: LastTransition,
        #[serde(rename = "batchResults")]
        batch_results: BTreeMap<JobId, BatchResult>,
    },
    FairRejected(LastTransition),
    FairBlockedResult {
        transition: LastTransition,
        reason: BlockReason,
    },
    FairBatchResult {
        transition: LastTransition,
        members: BTreeSet<JobId>,
        results: BTreeMap<JobId, BatchResult>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StateProjection {
    pub scopes: BTreeMap<Scope, ScopeState>,
    pub jobs: BTreeMap<JobId, FairJob>,
    pub orders: BTreeMap<OrderingGroup, OrderState>,
    pub meta: Meta,
    #[serde(rename = "lastCommand")]
    pub command: Command,
    #[serde(rename = "lastTransition")]
    pub transition: LastTransition,
    #[serde(rename = "lastCommandResult")]
    pub result: CommandResult,
}
