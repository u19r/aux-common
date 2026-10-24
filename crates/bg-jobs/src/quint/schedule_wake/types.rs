#![expect(
    clippy::enum_variant_names,
    reason = "Quint sum variants mirror the model vocabulary exactly"
)]

use std::collections::BTreeMap;

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
pub enum Occurrence {
    Occ1,
    Occ2,
    Occ3,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum Misfire {
    Skip,
    FireOnce,
    CatchUp,
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
pub enum Priority {
    Critical,
    Default,
    Bulk,
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
pub enum DriveResult {
    DriveRecurrence,
    DriveMaterialized,
    DriveClaimed,
    DriveTerminal,
    DriveConflict,
    DrivePaused,
    DriveBudgetExhausted,
    DriveFuture,
    DriveNoWork,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum DriveKernelBranch {
    KernelRecurrence,
    KernelMaterialize,
    KernelClaim,
    KernelTerminal,
    KernelConflict,
    KernelPaused,
    KernelBudget,
    KernelFuture,
    KernelNoWork,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum DriveWork {
    DriveRecurrenceWork,
    DriveMaterializeWork,
    DriveClaimWork,
    DriveTerminalWork,
    DriveConflictWork,
    DriveNoImmediateWork,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum DriveStopReason {
    ContinuePulse,
    StopConflict,
    StopPaused,
    StopBudget,
    StopFuture,
    StopNoWork,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum ScheduleOutcome {
    Initialised,
    Skipped,
    FireOnceEmitted,
    CatchUpEmitted,
    MaterializeSelected,
    Materialized,
    MaterializeConflict,
    ScheduleCompleted,
    CompletionConflict,
    WakeSet,
    WakeLost,
    WakeDuplicate,
    WakeStale,
    PauseChanged,
    ScheduleEnabledChanged,
    PulseStarted,
    PulseExited,
    DriveClaimCommitted,
    CronRejected,
    CronAccepted,
    TimeAdvanced,
    NotDue,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum ResultClass {
    AppliedClass,
    RejectedClass,
    ConflictClass,
    UnknownClass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleState {
    pub enabled: bool,
    pub paused: bool,
    pub overlap: bool,
    pub misfire: Misfire,
    pub now: i64,
    pub next_due: i64,
    pub watermark: i64,
    pub revision: i64,
    pub last_materialize_node: Node,
    pub emitted: BTreeMap<Occurrence, bool>,
    pub emission_count: i64,
    pub last_backlog: i64,
    pub skipped_remainder: i64,
    pub last_evaluation_now: i64,
    pub occurrence_identity: BTreeMap<Occurrence, i64>,
    pub previous_identity: BTreeMap<Occurrence, i64>,
    pub occurrence_job: BTreeMap<Occurrence, JobId>,
    pub materialized: BTreeMap<Occurrence, bool>,
    pub completed: BTreeMap<Occurrence, bool>,
    pub job_state: BTreeMap<JobId, JobState>,
    pub job_revision: BTreeMap<JobId, i64>,
    pub job_generation: BTreeMap<JobId, i64>,
    pub job_fence: BTreeMap<JobId, i64>,
    pub job_token: BTreeMap<JobId, i64>,
    pub job_lease_until: BTreeMap<JobId, i64>,
    pub job_node: BTreeMap<JobId, Node>,
    pub job_due_route: BTreeMap<JobId, bool>,
    pub job_fair_route: BTreeMap<JobId, bool>,
    pub job_lease_route: BTreeMap<JobId, bool>,
    pub job_wake_route: BTreeMap<JobId, bool>,
    pub job_attempts: BTreeMap<JobId, i64>,
    pub job_attempt_id: BTreeMap<JobId, i64>,
    pub job_execution_id: BTreeMap<JobId, i64>,
    pub durable_route: BTreeMap<Occurrence, bool>,
    pub materialize_pending: bool,
    pub materialize_occurrence: Occurrence,
    pub materialize_revision: i64,
    pub materialize_reader: Node,
    pub materialize_other_reader: Node,
    pub materialize_winner: Node,
    pub materialize_committed: bool,
    pub wake_pending: bool,
    pub wake_revision: i64,
    pub wake_token: i64,
    pub wake_at: i64,
    pub catch_up_limit: i64,
    pub active_pulses: i64,
    pub pulse_actions: i64,
    pub pulse_exited: bool,
    pub cron_accepted: bool,
    pub fair_ready: BTreeMap<JobId, bool>,
    pub fair_scope: BTreeMap<JobId, Scope>,
    pub fair_priority: BTreeMap<JobId, Priority>,
    pub fair_cost: BTreeMap<JobId, i64>,
    pub fair_weight: BTreeMap<JobId, i64>,
    pub fair_permits: BTreeMap<JobId, i64>,
    pub fair_rate: BTreeMap<JobId, i64>,
    pub fair_in_flight: BTreeMap<JobId, i64>,
    pub fair_served: BTreeMap<JobId, i64>,
    pub fair_ordering: BTreeMap<JobId, OrderingGroup>,
    pub fair_order: BTreeMap<JobId, i64>,
    pub order_head: BTreeMap<OrderingGroup, i64>,
    pub order_in_flight: BTreeMap<OrderingGroup, bool>,
    pub order_owner: BTreeMap<OrderingGroup, JobId>,
    pub fair_critical: i64,
    pub fair_default: i64,
    pub fair_bulk: i64,
    pub fair_cycle: i64,
    pub last_claim_node: Node,
    pub last_drive: DriveResult,
    pub last_drive_branch: DriveKernelBranch,
    pub last_drive_work: DriveWork,
    pub last_drive_stop: DriveStopReason,
    pub progress_counter: i64,
    pub drive_progress_before: i64,
    pub drive_progress_after: i64,
    pub last_outcome: ScheduleOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "tag", content = "value")]
pub enum Command {
    ScheduleAdvance {
        amount: i64,
    },
    ScheduleEvaluate {
        mode: Misfire,
        #[serde(rename = "catchUpLimit")]
        catch_up_limit: i64,
        now: i64,
        #[serde(rename = "nextDue")]
        next_due: i64,
    },
    ScheduleSelectMaterialize {
        occurrence: Occurrence,
        reader: Node,
        revision: i64,
    },
    ScheduleMaterialize {
        occurrence: Occurrence,
        contender: Node,
        revision: i64,
    },
    ScheduleComplete {
        occurrence: Occurrence,
        job: JobId,
        revision: i64,
    },
    ScheduleWake {
        revision: i64,
        token: i64,
        lose: bool,
        duplicate: bool,
    },
    SchedulePolicy {
        enabled: bool,
        paused: bool,
        overlap: bool,
    },
    ScheduleCron {
        form: CronForm,
    },
    SchedulePulse {
        active: i64,
        actions: i64,
    },
    ScheduleDrive {
        node: Node,
        active: i64,
        actions: i64,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(tag = "tag", content = "value")]
pub enum CronForm {
    PortableFiveField,
    SecondsField,
    YearField,
    AliasForm,
    TimezoneForm,
    ProviderExtension,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DriveResultRecord {
    pub command: Command,
    pub class: ResultClass,
    pub outcome: ScheduleOutcome,
    pub occurrence: Occurrence,
    pub drive: DriveResult,
    pub branch: DriveKernelBranch,
    pub work: DriveWork,
    pub stop: DriveStopReason,
    pub progress_before: i64,
    pub progress_after: i64,
    pub emission_count: i64,
    pub skipped: i64,
    pub next_due: i64,
    pub post: ScheduleState,
}

pub type LastTransition = DriveResultRecord;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "tag", content = "value")]
pub enum CommandResult {
    ScheduleApplied(LastTransition),
    ScheduleRejected(LastTransition),
    ScheduleConflictResult(LastTransition),
    ScheduleFuture(LastTransition),
    ScheduleNoWork(LastTransition),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct StateProjection {
    pub state: ScheduleState,
    #[serde(rename = "lastCommand")]
    pub last_command: Command,
    #[serde(rename = "lastTransition")]
    pub last_transition: LastTransition,
    #[serde(rename = "lastCommandResult")]
    pub last_command_result: CommandResult,
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

pub fn initial_state() -> ScheduleState {
    let occurrences = || {
        BTreeMap::from([
            (Occurrence::Occ1, false),
            (Occurrence::Occ2, false),
            (Occurrence::Occ3, false),
        ])
    };
    let identities = || {
        BTreeMap::from([
            (Occurrence::Occ1, 0),
            (Occurrence::Occ2, 0),
            (Occurrence::Occ3, 0),
        ])
    };
    let jobs = BTreeMap::from([
        (Occurrence::Occ1, JobId::JobA),
        (Occurrence::Occ2, JobId::JobB),
        (Occurrence::Occ3, JobId::JobC),
    ]);
    let job_states = BTreeMap::from([
        (JobId::JobA, JobState::Absent),
        (JobId::JobB, JobState::Absent),
        (JobId::JobC, JobState::Absent),
    ]);
    let revisions = BTreeMap::from([(JobId::JobA, 0), (JobId::JobB, 0), (JobId::JobC, 0)]);
    let zeros = || BTreeMap::from([(JobId::JobA, 0), (JobId::JobB, 0), (JobId::JobC, 0)]);
    let nodes = || {
        BTreeMap::from([
            (JobId::JobA, Node::NodeA),
            (JobId::JobB, Node::NodeA),
            (JobId::JobC, Node::NodeA),
        ])
    };
    let routes = || {
        BTreeMap::from([
            (JobId::JobA, false),
            (JobId::JobB, false),
            (JobId::JobC, false),
        ])
    };
    let scopes = BTreeMap::from([
        (JobId::JobA, Scope::ScopeA),
        (JobId::JobB, Scope::ScopeB),
        (JobId::JobC, Scope::ScopeA1),
    ]);
    let priorities = BTreeMap::from([
        (JobId::JobA, Priority::Critical),
        (JobId::JobB, Priority::Default),
        (JobId::JobC, Priority::Bulk),
    ]);
    let costs = BTreeMap::from([(JobId::JobA, 2), (JobId::JobB, 1), (JobId::JobC, 1)]);
    let weights = BTreeMap::from([(JobId::JobA, 1), (JobId::JobB, 1), (JobId::JobC, 1)]);
    let permits = BTreeMap::from([(JobId::JobA, 2), (JobId::JobB, 2), (JobId::JobC, 2)]);
    let rates = BTreeMap::from([(JobId::JobA, 3), (JobId::JobB, 3), (JobId::JobC, 3)]);
    let ordering = BTreeMap::from([
        (JobId::JobA, OrderingGroup::OrderA),
        (JobId::JobB, OrderingGroup::OrderB),
        (JobId::JobC, OrderingGroup::OrderB),
    ]);
    let order = BTreeMap::from([(JobId::JobA, 1), (JobId::JobB, 1), (JobId::JobC, 1)]);
    ScheduleState {
        enabled: true,
        paused: false,
        overlap: false,
        misfire: Misfire::FireOnce,
        now: 0,
        next_due: 5,
        watermark: 0,
        revision: 0,
        last_materialize_node: Node::NodeA,
        emitted: occurrences(),
        emission_count: 0,
        last_backlog: 0,
        skipped_remainder: 0,
        last_evaluation_now: 0,
        occurrence_identity: identities(),
        previous_identity: identities(),
        occurrence_job: jobs,
        materialized: occurrences(),
        completed: occurrences(),
        job_state: job_states,
        job_revision: revisions,
        job_generation: zeros(),
        job_fence: zeros(),
        job_token: zeros(),
        job_lease_until: zeros(),
        job_node: nodes(),
        job_due_route: routes(),
        job_fair_route: routes(),
        job_lease_route: routes(),
        job_wake_route: routes(),
        job_attempts: zeros(),
        job_attempt_id: zeros(),
        job_execution_id: BTreeMap::from([(JobId::JobA, 1), (JobId::JobB, 2), (JobId::JobC, 3)]),
        durable_route: occurrences(),
        materialize_pending: false,
        materialize_occurrence: Occurrence::Occ1,
        materialize_revision: 0,
        materialize_reader: Node::NodeA,
        materialize_other_reader: Node::NodeB,
        materialize_winner: Node::NodeA,
        materialize_committed: false,
        wake_pending: false,
        wake_revision: 0,
        wake_token: 0,
        wake_at: 5,
        catch_up_limit: 3,
        active_pulses: 0,
        pulse_actions: 0,
        pulse_exited: false,
        cron_accepted: true,
        fair_ready: routes(),
        fair_scope: scopes,
        fair_priority: priorities,
        fair_cost: costs,
        fair_weight: weights,
        fair_permits: permits,
        fair_rate: rates,
        fair_in_flight: zeros(),
        fair_served: zeros(),
        fair_ordering: ordering,
        fair_order: order,
        order_head: BTreeMap::from([
            (OrderingGroup::OrderA, 1),
            (OrderingGroup::OrderB, 1),
            (OrderingGroup::OrderC, 1),
        ]),
        order_in_flight: BTreeMap::from([
            (OrderingGroup::OrderA, false),
            (OrderingGroup::OrderB, false),
            (OrderingGroup::OrderC, false),
        ]),
        order_owner: BTreeMap::from([
            (OrderingGroup::OrderA, JobId::JobA),
            (OrderingGroup::OrderB, JobId::JobB),
            (OrderingGroup::OrderC, JobId::JobC),
        ]),
        fair_critical: 0,
        fair_default: 0,
        fair_bulk: 0,
        fair_cycle: 0,
        last_claim_node: Node::NodeA,
        last_drive: DriveResult::DriveNoWork,
        last_drive_branch: DriveKernelBranch::KernelNoWork,
        last_drive_work: DriveWork::DriveNoImmediateWork,
        last_drive_stop: DriveStopReason::StopNoWork,
        progress_counter: 0,
        drive_progress_before: 0,
        drive_progress_after: 0,
        last_outcome: ScheduleOutcome::Initialised,
    }
}

pub fn initial_transition() -> LastTransition {
    let command = Command::ScheduleAdvance { amount: 0 };
    LastTransition {
        command,
        class: ResultClass::AppliedClass,
        outcome: ScheduleOutcome::Initialised,
        occurrence: Occurrence::Occ1,
        drive: DriveResult::DriveNoWork,
        branch: DriveKernelBranch::KernelNoWork,
        work: DriveWork::DriveNoImmediateWork,
        stop: DriveStopReason::StopNoWork,
        progress_before: 0,
        progress_after: 0,
        emission_count: 0,
        skipped: 0,
        next_due: 5,
        post: initial_state(),
    }
}

pub fn initial_projection() -> StateProjection {
    let transition = initial_transition();
    StateProjection {
        state: initial_state(),
        last_command: transition.command.clone(),
        last_transition: transition.clone(),
        last_command_result: CommandResult::ScheduleApplied(transition),
    }
}
