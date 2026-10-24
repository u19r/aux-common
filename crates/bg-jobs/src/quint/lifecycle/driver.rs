use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroU32},
    time::Duration,
};

use bytes::Bytes;
use quint_connect::{Driver, Result, State, Step};
use quint_rendered_parser::{RenderedValue, parse as parse_rendered};
use serde::Deserialize;
use sha2::Digest;

use super::{
    constants::{ALL_COMMAND_FAMILIES, MAX_COMPLETION_RECEIPTS, MAX_UNRELATED_PROGRESS},
    types::{
        self, Command, CommandResult, CompletionDetail, EnqueueDisposition, HandlerResult, Job,
        JobId as MJobId, JobState as MJobState, LastTransition, LifecycleOutcome, Meta, Node,
        OperationId as MOperationId, RecordKind, ResultClass, StateProjection, StoreResult,
    },
};
use crate::{
    JobSystem,
    codec::{DecodedOperation, ValueCodec, ValueTag, decode_operation, encode_job_record},
    ids::{ExecutionId, JobId, JobKind, LeaseToken, Namespace, OperationId, OwnerId},
    model::{
        AttemptHistory, HandlerDefinition, JobOutcome, JobPolicySnapshot, JobRecordV1, JobState,
        LifecycleObservation, OperationReceipt, PayloadManifest,
    },
    policy::{
        BackoffMultiplier, FairnessClass, Priority, RetryPolicy, RetryPolicyInput, RetrySelection,
    },
    registry::HandlerRegistry,
    store::JobStore,
    test_helper::{CompletingHandler, FakeStore, FakeStoreError},
    time::Timestamp,
};

fn decode_marker_operation(encoded: &[u8]) -> Option<OperationId> {
    match decode_operation(encoded).ok()? {
        DecodedOperation::Live(authority) => authority.operation_id(),
        DecodedOperation::Receipt(_) => None,
    }
}

#[derive(Clone, Copy)]
struct CompletionAuthority {
    node: Node,
    revision: i64,
    generation: i64,
    fence: i64,
    token: i64,
    lease_until: i64,
    operation: MOperationId,
}

struct QuarantineObservation {
    observation: LifecycleObservation,
    operation_label: MOperationId,
}

struct CurrentProjectionInput {
    model_job: MJobId,
    record: crate::model::LifecycleRecord,
    operation_id: Option<OperationId>,
    routes: crate::model::LifecycleRoutes,
    cancellation_requested: bool,
    status: crate::model::LifecycleRecordStatus,
    include_fence_high_water: bool,
    operation_label: MOperationId,
}

impl CompletionAuthority {
    fn into_input(self, job: MJobId) -> types::AuthorityInput {
        types::AuthorityInput {
            job,
            node: self.node,
            revision: self.revision,
            generation: self.generation,
            fence: self.fence,
            token: self.token,
            lease_until: self.lease_until,
            operation: self.operation,
        }
    }
}

struct FixtureRecordInput {
    job_id: JobId,
    namespace: Namespace,
    queue: crate::QueueName,
    kind: JobKind,
    policy: JobPolicySnapshot,
    state: JobState,
    execution: u8,
    revision: u64,
    checkpoint: Option<Bytes>,
}

#[derive(Debug)]
pub(crate) enum ProjectionError {
    Store(crate::FakeStoreError),
    Data(crate::error::StoreDataError),
    Observation(String),
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "store projection failed: {error}"),
            Self::Data(error) => write!(formatter, "stored data projection failed: {error}"),
            Self::Observation(error) => write!(formatter, "lifecycle observation failed: {error}"),
        }
    }
}

impl std::error::Error for ProjectionError {}

impl From<crate::FakeStoreError> for ProjectionError {
    fn from(error: crate::FakeStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<crate::error::StoreDataError> for ProjectionError {
    fn from(error: crate::error::StoreDataError) -> Self {
        Self::Data(error)
    }
}

/// Full-state lifecycle connector. Persisted jobs, routes, leases, and
/// operations are read through the public lifecycle observation boundary after
/// every action. Retained state is limited to opaque claim/permit handles and
/// command-result metadata that has no persisted representation.
pub(crate) struct LifecycleDriver {
    system_a: JobSystem<FakeStore>,
    system_b: JobSystem<FakeStore>,
    store: FakeStore,
    now: i64,
    /// Bijections from opaque persisted identities to finite model labels.
    /// Labels are assigned in first-seen order and never from an ID byte, so
    /// equality and inequality of the production identities are preserved.
    execution_labels: BTreeMap<ExecutionId, i64>,
    next_execution_label: i64,
    /// Per-job finite labels for the model-visible operation identity.
    /// Production operation markers are opaque; the model observes only the
    /// fresh identity assigned by a successful redrive.
    operation_labels: BTreeMap<MJobId, MOperationId>,
    /// Lease tokens are opaque and scoped to a logical job. Keep a connector
    /// local raw-identity map so projection fails closed for unknown tokens
    /// without deriving model values from identifier bytes or generation.
    lease_token_labels: BTreeMap<(MJobId, LeaseToken), i64>,
    next_lease_token_labels: BTreeMap<MJobId, i64>,
    claims: BTreeMap<MJobId, crate::ClaimedJob>,
    fair_permits: BTreeMap<MJobId, crate::fairness::FairPermit>,
    /// Public observations captured at initialization and when the model
    /// quarantines an unknown-version record. This trace evidence is used
    /// only to project `quarantineSnapshot`; command transitions always read
    /// the live store through `observe_job`.
    trace_quarantine_observations: BTreeMap<MJobId, QuarantineObservation>,
    quarantine_attempts: i64,
    unrelated_progress: i64,
    unknown_pending: bool,
    unknown_job: MJobId,
    unknown_operation: MOperationId,
    unknown_node: Node,
    unknown_revision: i64,
    unknown_generation: i64,
    unknown_fence: i64,
    unknown_token: i64,
    unknown_lease_until: i64,
    unknown_after_commit: bool,
    unknown_readback: StoreResult,
    completion_pending: bool,
    completion_job: MJobId,
    completion_operation: MOperationId,
    completion_revision: i64,
    completion_generation: i64,
    completion_detail: CompletionDetail,
    completion_detail_job: MJobId,
    completion_omissions: i64,
    completion_receipt_jobs: BTreeSet<MJobId>,
    claim_pending: bool,
    claim_job: MJobId,
    claim_revision: i64,
    claim_reader: Node,
    last_attempt_revision: i64,
    last_attempt_applied: bool,
    last_attempt_operation: MOperationId,
    last_attempt_job: MJobId,
    completion_authority_recorded: bool,
    completion_authority_now: i64,
    completion_node: Node,
    completion_fence: i64,
    completion_token: i64,
    completion_lease_until: i64,
    completion_presented_node: Node,
    completion_presented_revision: i64,
    completion_presented_generation: i64,
    completion_presented_fence: i64,
    completion_presented_token: i64,
    completion_presented_lease_until: i64,
    completion_presented_operation: MOperationId,
    presented_node: Node,
    presented_generation: i64,
    presented_fence: i64,
    presented_token: i64,
    presented_lease_until: i64,
    stale_node: Node,
    stale_revision: i64,
    stale_generation: i64,
    stale_fence: i64,
    stale_token: i64,
    stale_lease_until: i64,
    stale_operation: MOperationId,
    last_enqueue_disposition: EnqueueDisposition,
    last_result: StoreResult,
    last_outcome: LifecycleOutcome,
    command: Command,
    transition: LastTransition,
    result: CommandResult,
    command_counts: BTreeMap<&'static str, usize>,
    require_command_coverage: bool,
    require_complete_command_coverage: bool,
}

impl State<LifecycleDriver> for StateProjection {
    fn from_driver(driver: &LifecycleDriver) -> Result<Self> {
        driver.projection().map_err(Into::into)
    }
}

impl Default for LifecycleDriver {
    fn default() -> Self {
        Self::try_default().unwrap_or_else(|error| panic!("lifecycle connector setup: {error}"))
    }
}

impl LifecycleDriver {
    fn try_default() -> Result<Self> {
        let store = FakeStore::distributed();
        seed_fixture(&store)?;
        let system_a = test_system(store.clone(), 1)?;
        let system_b = test_system(store.clone(), 2)?;
        let command = Command::LifecycleAdvance { amount: 0 };
        let transition = initial_transition(command.clone());
        let mut driver = Self {
            system_a,
            system_b,
            store,
            now: 0,
            execution_labels: BTreeMap::new(),
            next_execution_label: 1,
            operation_labels: BTreeMap::new(),
            lease_token_labels: BTreeMap::new(),
            next_lease_token_labels: BTreeMap::new(),
            claims: BTreeMap::new(),
            fair_permits: BTreeMap::new(),
            trace_quarantine_observations: BTreeMap::new(),
            quarantine_attempts: 0,
            unrelated_progress: 0,
            unknown_pending: false,
            unknown_job: MJobId::JobA,
            unknown_operation: MOperationId::OperationA,
            unknown_node: Node::NodeA,
            unknown_revision: 0,
            unknown_generation: 0,
            unknown_fence: 0,
            unknown_token: 0,
            unknown_lease_until: 0,
            unknown_after_commit: false,
            unknown_readback: StoreResult::Rejected,
            completion_pending: false,
            completion_job: MJobId::JobA,
            completion_operation: MOperationId::OperationA,
            completion_revision: 0,
            completion_generation: 0,
            completion_detail: CompletionDetail::NoCompletionDetail,
            completion_detail_job: MJobId::JobA,
            completion_omissions: 0,
            completion_receipt_jobs: BTreeSet::new(),
            claim_pending: false,
            claim_job: MJobId::JobA,
            claim_revision: 1,
            claim_reader: Node::NodeA,
            last_attempt_revision: 0,
            last_attempt_applied: false,
            last_attempt_operation: MOperationId::OperationA,
            last_attempt_job: MJobId::JobA,
            completion_authority_recorded: false,
            completion_authority_now: 0,
            completion_node: Node::NodeA,
            completion_fence: 0,
            completion_token: 0,
            completion_lease_until: 0,
            completion_presented_node: Node::NodeA,
            completion_presented_revision: 0,
            completion_presented_generation: 0,
            completion_presented_fence: 0,
            completion_presented_token: 0,
            completion_presented_lease_until: 0,
            completion_presented_operation: MOperationId::OperationA,
            presented_node: Node::NodeA,
            presented_generation: 0,
            presented_fence: 0,
            presented_token: 0,
            presented_lease_until: 0,
            stale_node: Node::NodeA,
            stale_revision: 0,
            stale_generation: 0,
            stale_fence: 0,
            stale_token: 0,
            stale_lease_until: 0,
            stale_operation: MOperationId::OperationA,
            last_enqueue_disposition: EnqueueDisposition::NotEnqueue,
            last_result: StoreResult::Committed,
            last_outcome: LifecycleOutcome::Initialised,
            command,
            transition: transition.clone(),
            result: CommandResult::LifecycleApplied(transition),
            command_counts: BTreeMap::new(),
            require_command_coverage: false,
            require_complete_command_coverage: false,
        };
        // Establish the model's first execution label from the seeded public
        // record before the leased fixture introduces JobB's opaque claim.
        driver.sync_execution_id(MJobId::JobA)?;
        // JobB starts with a live claim owned by the public lifecycle API.
        // Build that state through enqueue/claim so every later completion,
        // retry, and unknown-commit path carries the real opaque handle.
        let input = driver.enqueue_input(MJobId::JobB, 0, false)?;
        crate::test_helper::block_on(driver.system_a.enqueue_raw(input, driver.now_timestamp()))?;
        let claim = crate::test_helper::block_on(
            driver
                .system_a
                .claim(actual_job_id(MJobId::JobB), driver.now_timestamp()),
        )?;
        driver.register_claim_handle(MJobId::JobB, &claim);
        driver.claims.insert(MJobId::JobB, claim);
        driver.sync_execution_id(MJobId::JobB)?;
        driver.capture_initial_quarantine_observations()?;
        Ok(driver)
    }

    pub(crate) fn for_command_coverage() -> Self {
        let mut driver = Self::try_default()
            .unwrap_or_else(|error| panic!("lifecycle connector setup: {error}"));
        driver.require_command_coverage = true;
        driver
    }

    pub(crate) fn for_deterministic_command_coverage() -> Self {
        let mut driver = Self::try_default()
            .unwrap_or_else(|error| panic!("lifecycle connector setup: {error}"));
        driver.require_command_coverage = true;
        driver.require_complete_command_coverage = true;
        driver
    }

    fn reset_for_trace(&mut self) -> Result<()> {
        let command_counts = std::mem::take(&mut self.command_counts);
        let require_command_coverage = self.require_command_coverage;
        let require_complete_command_coverage = self.require_complete_command_coverage;
        let mut fresh = Self::try_default()?;
        fresh.command_counts = command_counts;
        fresh.require_command_coverage = require_command_coverage;
        fresh.require_complete_command_coverage = require_complete_command_coverage;
        self.require_command_coverage = false;
        self.require_complete_command_coverage = false;
        std::mem::swap(self, &mut fresh);
        Ok(())
    }

    fn projection(&self) -> std::result::Result<StateProjection, ProjectionError> {
        let observations = self.observe_jobs()?;
        let jobs = self.project_jobs_from_observations(&observations)?;
        let meta = self.project_meta(&observations)?;
        Ok(StateProjection {
            meta,
            jobs,
            command: self.command.clone(),
            transition: self.transition.clone(),
            result: self.result.clone(),
        })
    }

    fn project_jobs(&self) -> std::result::Result<BTreeMap<MJobId, Job>, ProjectionError> {
        let observations = self.observe_jobs()?;
        self.project_jobs_from_observations(&observations)
    }

    fn observe_jobs(
        &self,
    ) -> std::result::Result<[(MJobId, LifecycleObservation); 3], ProjectionError> {
        Ok([
            (MJobId::JobA, self.observe_job(MJobId::JobA)?),
            (MJobId::JobB, self.observe_job(MJobId::JobB)?),
            (MJobId::JobC, self.observe_job(MJobId::JobC)?),
        ])
    }

    fn project_jobs_from_observations(
        &self,
        observations: &[(MJobId, LifecycleObservation)],
    ) -> std::result::Result<BTreeMap<MJobId, Job>, ProjectionError> {
        observations
            .iter()
            .map(|(job, observation)| {
                Ok((
                    *job,
                    self.project_observation(
                        *job,
                        observation.clone(),
                        true,
                        self.model_operation(*job),
                    )?,
                ))
            })
            .collect()
    }

    fn observe_job(
        &self,
        model_job: MJobId,
    ) -> std::result::Result<LifecycleObservation, ProjectionError> {
        crate::test_helper::block_on(self.system_a.observe_lifecycle(actual_job_id(model_job)))
            .map_err(|error| ProjectionError::Observation(format!("{model_job:?}: {error}")))
    }

    fn observed_operation_id(&self, model_job: MJobId) -> Result<OperationId> {
        match self.observe_job(model_job)? {
            LifecycleObservation::Current {
                operation_id: Some(operation_id),
                ..
            }
            | LifecycleObservation::Terminal(OperationReceipt { operation_id, .. }) => {
                Ok(operation_id)
            }
            LifecycleObservation::Current {
                operation_id: None, ..
            }
            | LifecycleObservation::Invalid { .. }
            | LifecycleObservation::Missing => Err(std::io::Error::other(format!(
                "{model_job:?} has no public operation authority for reconciliation"
            ))
            .into()),
        }
    }

    fn repair_operation_id(
        &self,
        model_job: MJobId,
        requested: MOperationId,
    ) -> Result<OperationId> {
        let fallback = operation(requested);
        let observation = self.observe_job(model_job)?;
        match observation {
            LifecycleObservation::Current {
                operation_id: Some(operation_id),
                ..
            }
            | LifecycleObservation::Terminal(OperationReceipt { operation_id, .. }) => {
                Ok(operation_id)
            }
            // A corrupt record is still repairable when its operation marker
            // is intact.  Lifecycle observation intentionally does not expose
            // that marker for an invalid record, so recover the opaque value
            // through the same consumer-provided store boundary used by the
            // repair transition.  Missing or malformed markers remain a
            // deliberate conflict input via the typed fallback.
            LifecycleObservation::Current {
                operation_id: None, ..
            }
            | LifecycleObservation::Invalid { .. }
            | LifecycleObservation::Missing => {
                let operation_key = crate::keys::operation_key(
                    self.system_a.namespace(),
                    &actual_job_id(model_job),
                )?;
                let encoded =
                    crate::test_helper::block_on(self.system_a.store().get(operation_key))?;
                Ok(encoded
                    .as_deref()
                    .and_then(decode_marker_operation)
                    .unwrap_or(fallback))
            }
        }
    }

    fn register_observed_identifiers(&mut self, observation: &LifecycleObservation) {
        let execution_id = match observation {
            LifecycleObservation::Current { record, .. } => Some(record.execution_id),
            LifecycleObservation::Terminal(receipt) => Some(receipt.execution_id),
            LifecycleObservation::Invalid {
                record: Some(record),
                ..
            } => Some(record.execution_id),
            LifecycleObservation::Invalid { record: None, .. } | LifecycleObservation::Missing => {
                None
            }
        };
        if let Some(execution_id) = execution_id {
            self.normalize_execution_id(execution_id);
        }
    }

    fn capture_initial_quarantine_observations(&mut self) -> Result<()> {
        for job in [MJobId::JobA, MJobId::JobB, MJobId::JobC] {
            let observation = self.observe_job(job)?;
            self.register_observed_identifiers(&observation);
            self.trace_quarantine_observations.insert(
                job,
                QuarantineObservation {
                    observation,
                    operation_label: self.model_operation(job),
                },
            );
        }
        Ok(())
    }

    /// Execution identifiers are deliberately opaque at the public boundary.
    /// Keep a connector-local bijection so the finite Quint model can compare
    /// identity equality without depending on random identifier bytes.
    fn normalize_execution_id(&mut self, execution_id: ExecutionId) -> i64 {
        if let Some(label) = self.execution_labels.get(&execution_id) {
            return *label;
        }
        let label = self.next_execution_label;
        self.next_execution_label = self.next_execution_label.saturating_add(1);
        self.execution_labels.insert(execution_id, label);
        label
    }

    fn execution_label(
        &self,
        execution_id: ExecutionId,
    ) -> std::result::Result<i64, ProjectionError> {
        self.execution_labels
            .get(&execution_id)
            .copied()
            .ok_or_else(|| {
                ProjectionError::Observation("unregistered opaque execution identifier".to_owned())
            })
    }

    fn register_lease_token(&mut self, job: MJobId, token: LeaseToken) {
        if self.lease_token_labels.contains_key(&(job, token)) {
            return;
        }
        let label = self.next_lease_token_labels.get(&job).copied().unwrap_or(3);
        self.lease_token_labels.insert((job, token), label);
        self.next_lease_token_labels
            .insert(job, label.saturating_add(3));
    }

    fn reset_lease_token_labels(&mut self, job: MJobId) {
        self.next_lease_token_labels.insert(job, 3);
    }

    fn lease_token_label(
        &self,
        job: MJobId,
        token: LeaseToken,
    ) -> std::result::Result<i64, ProjectionError> {
        self.lease_token_labels
            .get(&(job, token))
            .copied()
            .ok_or_else(|| {
                ProjectionError::Observation("unregistered opaque lease token".to_owned())
            })
    }

    fn lease_token_progression(&self, job: MJobId) -> i64 {
        self.next_lease_token_labels
            .get(&job)
            .copied()
            .unwrap_or(3)
            .saturating_sub(3)
    }

    fn register_claim_handle(&mut self, job: MJobId, claim: &crate::ClaimedJob) {
        self.normalize_execution_id(claim.record().execution_id);
        if let JobState::Leased(lease) = &claim.record().state {
            self.register_lease_token(job, lease.token);
        }
    }

    fn sync_execution_id(&mut self, job: MJobId) -> Result<()> {
        let observation = self.observe_job(job)?;
        self.register_observed_identifiers(&observation);
        Ok(())
    }

    fn observed_record_kind(&self, job: MJobId) -> Result<RecordKind> {
        Ok(match self.observe_job(job)? {
            LifecycleObservation::Current { status, .. }
            | LifecycleObservation::Invalid { status, .. } => match status {
                crate::model::LifecycleRecordStatus::Valid => RecordKind::Valid,
                crate::model::LifecycleRecordStatus::Corrupt => RecordKind::Corrupt,
                crate::model::LifecycleRecordStatus::UnknownVersion => RecordKind::UnknownVersion,
            },
            LifecycleObservation::Terminal(_) => RecordKind::Valid,
            LifecycleObservation::Missing => RecordKind::Missing,
        })
    }

    fn is_unknown_version(&self, job: MJobId) -> Result<bool> {
        Ok(self.observed_record_kind(job)? == RecordKind::UnknownVersion)
    }

    fn model_operation(&self, model_job: MJobId) -> MOperationId {
        self.operation_labels
            .get(&model_job)
            .copied()
            .unwrap_or(MOperationId::OperationA)
    }

    fn project_observation(
        &self,
        model_job: MJobId,
        observation: LifecycleObservation,
        include_fence_high_water: bool,
        operation_label: MOperationId,
    ) -> std::result::Result<Job, ProjectionError> {
        match observation {
            LifecycleObservation::Current {
                record,
                operation_id,
                routes,
                cancellation_requested,
                status,
            } => self.project_current(CurrentProjectionInput {
                model_job,
                record,
                operation_id,
                routes,
                cancellation_requested,
                status,
                include_fence_high_water,
                operation_label,
            }),
            LifecycleObservation::Terminal(receipt) => {
                self.project_terminal(model_job, receipt, operation_label)
            }
            LifecycleObservation::Invalid {
                status,
                routes,
                record: Some(record),
            } => self.project_current(CurrentProjectionInput {
                model_job,
                record,
                operation_id: None,
                routes,
                cancellation_requested: false,
                status,
                include_fence_high_water,
                operation_label,
            }),
            LifecycleObservation::Invalid {
                status,
                routes,
                record: None,
            } => Err(ProjectionError::Observation(format!(
                "{model_job:?}: invalid persisted lifecycle state ({status:?}, routes={routes:?})"
            ))),
            LifecycleObservation::Missing => Ok(missing_job()),
        }
    }

    fn project_quarantine_snapshot(
        &self,
    ) -> std::result::Result<BTreeMap<MJobId, Job>, ProjectionError> {
        self.trace_quarantine_observations
            .iter()
            .map(|(job, quarantine)| {
                // This is an immutable observation captured before a record
                // entered quarantine. Its operation key may legitimately be
                // a later receipt, so never consult current marker state when
                // projecting this historical snapshot.
                Ok((
                    *job,
                    self.project_observation(
                        *job,
                        quarantine.observation.clone(),
                        false,
                        quarantine.operation_label,
                    )?,
                ))
            })
            .collect()
    }

    fn project_current(
        &self,
        input: CurrentProjectionInput,
    ) -> std::result::Result<Job, ProjectionError> {
        let CurrentProjectionInput {
            model_job,
            record,
            operation_id,
            routes,
            cancellation_requested,
            status,
            include_fence_high_water,
            operation_label,
        } = input;
        let persisted_fence = if include_fence_high_water {
            self.persisted_fence_high_water(model_job, status, operation_id)?
        } else {
            0
        };
        let record_kind = match status {
            crate::model::LifecycleRecordStatus::UnknownVersion => RecordKind::Valid,
            crate::model::LifecycleRecordStatus::Corrupt => RecordKind::Corrupt,
            crate::model::LifecycleRecordStatus::Valid
                if routes_match_state(&record.state, routes) =>
            {
                RecordKind::Valid
            }
            crate::model::LifecycleRecordStatus::Valid => RecordKind::Corrupt,
        };
        let state = match &record.state {
            JobState::Scheduled if record.attempts.is_some() => MJobState::RetryWaiting,
            JobState::Scheduled => MJobState::Scheduled,
            JobState::Leased(_) => MJobState::Leased,
            JobState::DeadLettered => MJobState::DeadLettered,
            JobState::Cancelled => MJobState::Cancelled,
            JobState::Suspended => MJobState::Suspended,
        };
        let (node, fence, token, lease_until) = match &record.state {
            JobState::Leased(lease) => (
                model_node(lease.owner.as_bytes()[0]),
                i64::try_from(lease.fence.get()).unwrap_or(i64::MAX),
                self.lease_token_label(model_job, lease.token)?,
                timestamp_tick(lease.expires_at),
            ),
            _ => (Node::NodeA, persisted_fence, 0, 0),
        };
        let attempts = record
            .attempts
            .as_ref()
            .map_or(0, |attempts| i64::from(attempts.attempts.get()));
        Ok(Job {
            state,
            node,
            revision: i64::try_from(record.revision).unwrap_or(i64::MAX),
            generation: i64::from(record.generation),
            fence,
            token,
            lease_until,
            due_at: timestamp_tick(record.scheduled_at),
            expires_at: record.expires_at.map_or(0, timestamp_tick),
            execution_id: self.execution_label(record.execution_id)?,
            // Attempt identity is intentionally opaque and not persisted in
            // a live record. The model's observable abstraction is the
            // persisted attempt number, so it remains equal to `attempts`.
            attempt_id: attempts,
            attempts,
            record: record_kind,
            payload: record.payload.complete,
            due_route: routes.due,
            lease_route: routes.lease,
            fair_route: routes.fair,
            wake_route: routes.wake,
            checkpoint_bytes: i64::try_from(record.checkpoint_bytes).unwrap_or(i64::MAX),
            failure_recorded: matches!(record.state, JobState::DeadLettered),
            completion_receipt: false,
            cancel_requested: cancellation_requested,
            // The marker is opaque and may be absent for an invalid record;
            // retain the model label established by prior redrives.
            operation_id: operation_label,
            // Enqueue fingerprints are caller inputs, not part of the
            // persisted job record or lifecycle receipt.
            enqueue_fingerprint: 0,
        })
    }

    fn persisted_fence_high_water(
        &self,
        model_job: MJobId,
        status: crate::model::LifecycleRecordStatus,
        _operation_id: Option<OperationId>,
    ) -> std::result::Result<i64, ProjectionError> {
        if status != crate::model::LifecycleRecordStatus::Valid {
            return Ok(0);
        }
        let job_id = actual_job_id(model_job);
        let operation_key = crate::keys::operation_key(self.system_a.namespace(), &job_id)?;
        let Some(encoded) = self
            .store
            .snapshot()?
            .into_iter()
            .find(|(key, _)| key == &operation_key)
            .map(|(_, value)| value)
        else {
            return Ok(0);
        };
        match decode_operation(&encoded)? {
            DecodedOperation::Live(authority) if authority.matches_job(job_id) => {
                Ok(i64::try_from(authority.fence_high_water()).unwrap_or(i64::MAX))
            }
            DecodedOperation::Live(_) => Err(ProjectionError::Observation(format!(
                "{model_job:?}: operation marker identity mismatch"
            ))),
            DecodedOperation::Receipt(receipt) => Err(ProjectionError::Observation(format!(
                "{model_job:?}: terminal receipt on a live record (receipt revision={}, receipt \
                 job={:?})",
                receipt.revision, receipt.job_id,
            ))),
        }
    }

    fn project_terminal(
        &self,
        model_job: MJobId,
        receipt: OperationReceipt,
        operation_label: MOperationId,
    ) -> std::result::Result<Job, ProjectionError> {
        let attempts = i64::from(receipt.attempts.get());
        Ok(Job {
            state: MJobState::Absent,
            node: model_node(receipt.owner.as_bytes()[0]),
            revision: i64::try_from(receipt.revision).unwrap_or(i64::MAX),
            generation: i64::from(receipt.generation),
            fence: i64::try_from(receipt.fence.get()).unwrap_or(i64::MAX),
            token: self.lease_token_label(model_job, receipt.token)?,
            lease_until: 0,
            due_at: 0,
            expires_at: 0,
            execution_id: self.execution_label(receipt.execution_id)?,
            // The receipt preserves opaque identities; the model exposes the
            // connector's finite operation and attempt labels.
            attempt_id: attempts,
            attempts,
            record: RecordKind::Valid,
            payload: false,
            due_route: false,
            lease_route: false,
            fair_route: false,
            wake_route: false,
            checkpoint_bytes: 0,
            failure_recorded: false,
            completion_receipt: self.completion_receipt_jobs.contains(&model_job),
            cancel_requested: false,
            operation_id: operation_label,
            enqueue_fingerprint: 0,
        })
    }

    fn project_meta(
        &self,
        observations: &[(MJobId, LifecycleObservation)],
    ) -> std::result::Result<Meta, ProjectionError> {
        // Terminal membership is a durable public observation, not a
        // connector-side history flag. A receipt projects as an absent job,
        // so derive this set directly from the observations shared with the
        // live-job projection.
        let committed_terminal_jobs = observations
            .iter()
            .filter_map(|(job, observation)| {
                let committed = match observation {
                    LifecycleObservation::Terminal(_) => true,
                    LifecycleObservation::Current { record, .. } => {
                        matches!(
                            record.state,
                            JobState::DeadLettered | JobState::Cancelled | JobState::Suspended
                        )
                    }
                    LifecycleObservation::Invalid { .. } | LifecycleObservation::Missing => false,
                };
                committed.then_some(*job)
            })
            .collect();
        let unknown_version_jobs = observations
            .iter()
            .filter_map(|(job, observation)| {
                matches!(
                    observation,
                    LifecycleObservation::Current {
                        status: crate::model::LifecycleRecordStatus::UnknownVersion,
                        ..
                    } | LifecycleObservation::Invalid {
                        status: crate::model::LifecycleRecordStatus::UnknownVersion,
                        ..
                    }
                )
                .then_some(*job)
            })
            .collect();
        let quarantine_snapshot = self.project_quarantine_snapshot()?;
        Ok(Meta {
            now: self.now,
            paused: false,
            dedupe_active: false,
            dedupe_job: MJobId::JobA,
            dedupe_expired: false,
            token_progression: [MJobId::JobA, MJobId::JobB, MJobId::JobC]
                .into_iter()
                .map(|job| (job, self.lease_token_progression(job)))
                .collect(),
            unknown_version_jobs,
            quarantine_snapshot,
            quarantine_attempts: self.quarantine_attempts,
            unrelated_progress: self.unrelated_progress,
            unknown_pending: self.unknown_pending,
            unknown_job: self.unknown_job,
            unknown_operation: self.unknown_operation,
            unknown_node: self.unknown_node,
            unknown_revision: self.unknown_revision,
            unknown_generation: self.unknown_generation,
            unknown_fence: self.unknown_fence,
            unknown_token: self.unknown_token,
            unknown_lease_until: self.unknown_lease_until,
            unknown_after_commit: self.unknown_after_commit,
            unknown_readback: self.unknown_readback,
            completion_pending: self.completion_pending,
            completion_job: self.completion_job,
            completion_operation: self.completion_operation,
            completion_revision: self.completion_revision,
            completion_generation: self.completion_generation,
            completion_detail: self.completion_detail,
            completion_detail_job: self.completion_detail_job,
            completion_omissions: self.completion_omissions,
            committed_terminal_jobs,
            claim_pending: self.claim_pending,
            claim_job: self.claim_job,
            claim_revision: self.claim_revision,
            claim_reader: self.claim_reader,
            last_attempt_revision: self.last_attempt_revision,
            last_attempt_applied: self.last_attempt_applied,
            last_attempt_operation: self.last_attempt_operation,
            last_attempt_job: self.last_attempt_job,
            completion_authority_recorded: self.completion_authority_recorded,
            completion_authority_now: self.completion_authority_now,
            completion_node: self.completion_node,
            completion_fence: self.completion_fence,
            completion_token: self.completion_token,
            completion_lease_until: self.completion_lease_until,
            completion_presented_node: self.completion_presented_node,
            completion_presented_revision: self.completion_presented_revision,
            completion_presented_generation: self.completion_presented_generation,
            completion_presented_fence: self.completion_presented_fence,
            completion_presented_token: self.completion_presented_token,
            completion_presented_lease_until: self.completion_presented_lease_until,
            completion_presented_operation: self.completion_presented_operation,
            presented_node: self.presented_node,
            presented_generation: self.presented_generation,
            presented_fence: self.presented_fence,
            presented_token: self.presented_token,
            presented_lease_until: self.presented_lease_until,
            stale_node: self.stale_node,
            stale_revision: self.stale_revision,
            stale_generation: self.stale_generation,
            stale_fence: self.stale_fence,
            stale_token: self.stale_token,
            stale_lease_until: self.stale_lease_until,
            stale_operation: self.stale_operation,
            last_enqueue_disposition: self.last_enqueue_disposition,
            last_result: self.last_result,
            last_outcome: self.last_outcome,
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "The connector preserves the model's fixed transition fields explicitly"
    )]
    fn finish(
        &mut self,
        command: Command,
        class: ResultClass,
        result: StoreResult,
        outcome: LifecycleOutcome,
        detail: CompletionDetail,
        enqueue: EnqueueDisposition,
        job: MJobId,
        operation: MOperationId,
    ) {
        self.command = command.clone();
        self.last_result = result;
        self.last_outcome = outcome;
        self.last_enqueue_disposition = enqueue;
        self.completion_detail = detail;
        let transition = LastTransition {
            command,
            class,
            result,
            outcome,
            detail,
            enqueue,
            job,
            operation,
        };
        self.transition = transition.clone();
        self.result = match detail {
            CompletionDetail::CompletionDetailOmitted => {
                CommandResult::LifecycleDetailOmitted(transition)
            }
            _ => match class {
                ResultClass::AppliedClass => CommandResult::LifecycleApplied(transition),
                ResultClass::RejectedClass => CommandResult::LifecycleRejected(transition),
                ResultClass::ConflictClass => CommandResult::LifecycleConflict(transition),
                ResultClass::UnknownClass => CommandResult::LifecycleUnknownResult(transition),
            },
        };
    }

    fn now_timestamp(&self) -> Timestamp {
        Timestamp::from_millis(self.now.saturating_mul(1_000))
    }

    fn job_record(&self, job: MJobId) -> Result<JobRecordV1> {
        let key = crate::keys::job_key(self.system_a.namespace(), &actual_job_id(job))?;
        let value = self
            .store
            .snapshot()?
            .into_iter()
            .find(|(candidate, _)| candidate == &key)
            .map(|(_, value)| value)
            .ok_or_else(|| std::io::Error::other(format!("missing persisted {job:?}")))?;
        Ok(crate::codec::decode_job_record(&value)?)
    }

    fn completion_authority(
        &self,
        job: MJobId,
        claim: &crate::ClaimedJob,
    ) -> Result<CompletionAuthority> {
        let JobState::Leased(lease) = &claim.record().state else {
            return Err(std::io::Error::other("completion requires a leased record").into());
        };
        Ok(CompletionAuthority {
            node: model_node(lease.owner.as_bytes()[0]),
            revision: i64::try_from(claim.record().revision).unwrap_or(i64::MAX),
            generation: i64::from(claim.record().generation),
            fence: i64::try_from(lease.fence.get()).unwrap_or(i64::MAX),
            token: self.lease_token_label(job, lease.token)?,
            lease_until: timestamp_tick(lease.expires_at),
            operation: self.model_operation(job),
        })
    }

    fn system_for_node(&self, node: Node) -> &JobSystem<FakeStore> {
        match node {
            Node::NodeA => &self.system_a,
            Node::NodeB => &self.system_b,
        }
    }

    fn leased_owner(&self, job: MJobId) -> Result<Node> {
        let record = self.job_record(job)?;
        let JobState::Leased(lease) = record.state else {
            return Err(std::io::Error::other("lifecycle command requires a lease").into());
        };
        Ok(model_node(lease.owner.as_bytes()[0]))
    }

    fn ensure_claim_handle(&mut self, job: MJobId) -> Result<()> {
        if self.claims.contains_key(&job) {
            return Ok(());
        }
        if self
            .project_jobs()?
            .get(&job)
            .is_some_and(|value| value.state != MJobState::Leased)
        {
            return Err(crate::error::JobSystemError::<FakeStoreError>::LeaseConflict.into());
        }
        let _ = self.leased_owner(job)?;
        Err(crate::error::JobSystemError::<FakeStoreError>::LeaseConflict.into())
    }

    fn take_completion_claim(
        &mut self,
        input: &types::AuthorityInput,
    ) -> Result<(crate::ClaimedJob, CompletionAuthority, Node)> {
        self.ensure_claim_handle(input.job)?;
        let claim = self
            .claims
            .get(&input.job)
            .ok_or_else(|| std::io::Error::other("completion claim missing"))?;
        let authority = self.completion_authority(input.job, claim)?;
        let owner = self.claim_owner(input.job, input.node);
        let claim = self
            .claims
            .remove(&input.job)
            .ok_or_else(|| std::io::Error::other("completion claim missing"))?;
        Ok((claim, authority, owner))
    }

    fn has_claim_handle_or_lease(&self, job: MJobId) -> Result<bool> {
        Ok(self.claims.contains_key(&job)
            || self
                .project_jobs()?
                .get(&job)
                .is_some_and(|value| value.state == MJobState::Leased))
    }

    fn has_exact_authority(&self, input: &types::AuthorityInput) -> Result<bool> {
        let jobs = self.project_jobs()?;
        let Some(current) = jobs.get(&input.job) else {
            return Ok(false);
        };
        Ok(current.state == MJobState::Leased
            && !current.cancel_requested
            && current.node == input.node
            && current.revision == input.revision
            && current.generation == input.generation
            && current.fence == input.fence
            && current.token == input.token
            && current.lease_until == input.lease_until
            && current.operation_id == input.operation
            && self.now < current.lease_until)
    }

    fn has_exact_completion_authority(&self, input: &types::AuthorityInput) -> Result<bool> {
        if self.unknown_pending && self.unknown_job == input.job {
            return Ok(false);
        }
        if self.is_unknown_version(input.job)? {
            return Ok(false);
        }
        self.has_exact_authority(input)
    }

    fn has_exact_unknown_authority(&self, input: &types::AuthorityInput) -> Result<bool> {
        if self.unknown_pending {
            return Ok(false);
        }
        self.has_exact_authority(input)
    }

    fn validate_unknown_completion_result<T>(
        committed: bool,
        result: &std::result::Result<T, crate::error::JobSystemError<FakeStoreError>>,
    ) -> Result<()> {
        match (committed, result) {
            (true, Ok(_)) | (false, Err(crate::error::JobSystemError::UnknownCommit)) => Ok(()),
            (true, Err(error)) => Err(std::io::Error::other(format!(
                "unknown-after completion expected Ok(_), got {error}"
            ))
            .into()),
            (false, Ok(_)) => Err(std::io::Error::other(
                "unknown-before completion expected Err(UnknownCommit), got Ok(_)",
            )
            .into()),
            (false, Err(error)) => Err(std::io::Error::other(format!(
                "unknown-before completion expected Err(UnknownCommit), got {error}"
            ))
            .into()),
        }
    }

    fn claim_owner(&self, job: MJobId, fallback: Node) -> Node {
        self.claims
            .get(&job)
            .and_then(|claim| match &claim.record().state {
                JobState::Leased(lease) => Some(model_node(lease.owner.as_bytes()[0])),
                _ => None,
            })
            .unwrap_or(fallback)
    }

    fn settle_fair_permit(
        &mut self,
        job: MJobId,
        release: crate::fairness::FairRelease,
    ) -> Result<()> {
        let Some(permit) = self.fair_permits.remove(&job) else {
            return Ok(());
        };
        let Some(mut owner) =
            crate::test_helper::block_on(crate::fairness::FairDispatchOwner::load(&self.system_a))?
        else {
            return Err(std::io::Error::other("selected fair permit owner disappeared").into());
        };
        owner
            .release(permit, release)
            .map_err(|error| std::io::Error::other(format!("fair permit release: {error:?}")))?;
        crate::test_helper::block_on(owner.save(&self.system_a))?;
        Ok(())
    }

    fn set_completion_authority(
        &mut self,
        job: MJobId,
        input: &types::AuthorityInput,
        authority: &CompletionAuthority,
        operation: MOperationId,
    ) -> Result<()> {
        self.completion_pending = true;
        self.completion_job = job;
        self.completion_operation = operation;
        self.completion_revision = authority.revision.saturating_add(1);
        self.completion_generation = authority.generation;
        self.completion_detail = CompletionDetail::NoCompletionDetail;
        self.completion_authority_recorded = true;
        self.completion_authority_now = self.now;
        self.completion_node = authority.node;
        self.completion_fence = authority.fence;
        self.completion_token = authority.token;
        self.completion_lease_until = authority.lease_until;
        self.completion_presented_node = input.node;
        self.completion_presented_revision = input.revision;
        self.completion_presented_generation = input.generation;
        self.completion_presented_fence = input.fence;
        self.completion_presented_token = input.token;
        self.completion_presented_lease_until = input.lease_until;
        self.completion_presented_operation = operation;
        self.stale_node = authority.node;
        self.stale_revision = authority.revision;
        self.stale_generation = authority.generation;
        self.stale_fence = authority.fence;
        self.stale_token = authority.token;
        self.stale_lease_until = authority.lease_until;
        self.stale_operation = authority.operation;
        self.presented_node = input.node;
        self.presented_generation = input.generation;
        self.presented_fence = input.fence;
        self.presented_token = input.token;
        self.presented_lease_until = input.lease_until;
        self.last_attempt_revision = input.revision;
        self.last_attempt_operation = operation;
        Ok(())
    }

    fn record_completion(
        &mut self,
        job: MJobId,
        input: &types::AuthorityInput,
        authority: CompletionAuthority,
    ) -> Result<()> {
        self.set_completion_authority(job, input, &authority, input.operation)?;
        self.settle_fair_permit(job, crate::fairness::FairRelease::Complete)
    }

    fn clear_claim_pending(&mut self) {
        self.claim_pending = false;
    }

    fn dynamic_error_class(
        error: &crate::error::JobSystemError<FakeStoreError>,
    ) -> (ResultClass, StoreResult) {
        match error {
            crate::error::JobSystemError::UnknownCommit => {
                (ResultClass::UnknownClass, StoreResult::Unknown)
            }
            crate::error::JobSystemError::JobIdConflict
            | crate::error::JobSystemError::Validation(_)
            | crate::error::JobSystemError::UnregisteredHandler => {
                (ResultClass::RejectedClass, StoreResult::Rejected)
            }
            _ => (ResultClass::ConflictClass, StoreResult::Conflict),
        }
    }

    fn redrive_error_transition(
        &self,
        job: MJobId,
        expected_revision: i64,
        expected_operation: MOperationId,
        error: &crate::error::JobSystemError<FakeStoreError>,
    ) -> Result<(ResultClass, StoreResult, LifecycleOutcome)> {
        let (class, result) = match error {
            crate::error::JobSystemError::LeaseConflict
            | crate::error::JobSystemError::LeaseLost => {
                let current = self.project_jobs()?.get(&job).cloned().ok_or_else(|| {
                    std::io::Error::other(format!("redrive projection missing {job:?}"))
                })?;
                if current.revision != expected_revision
                    || current.operation_id != expected_operation
                {
                    (ResultClass::ConflictClass, StoreResult::Conflict)
                } else {
                    (ResultClass::RejectedClass, StoreResult::Rejected)
                }
            }
            crate::error::JobSystemError::UnknownCommit => {
                (ResultClass::UnknownClass, StoreResult::Unknown)
            }
            crate::error::JobSystemError::JobIdConflict
            | crate::error::JobSystemError::Validation(_)
            | crate::error::JobSystemError::UnregisteredHandler
            | crate::error::JobSystemError::NotFound
            | crate::error::JobSystemError::PayloadCorrupt => {
                (ResultClass::RejectedClass, StoreResult::Rejected)
            }
            _ => Self::dynamic_error_class(error),
        };
        let outcome = if class == ResultClass::ConflictClass {
            LifecycleOutcome::RedriveConflict
        } else {
            LifecycleOutcome::RedriveRejected
        };
        Ok((class, result, outcome))
    }

    fn enqueue_input(&self, job: MJobId, due_at: i64, with_dedupe: bool) -> Result<crate::NewJob> {
        let now = self.now_timestamp();
        let deduplication = with_dedupe.then(|| {
            crate::Deduplication::try_new(
                crate::DeduplicationKey::try_new(format!("quint-{job:?}").as_bytes())
                    .expect("static lifecycle dedupe key"),
                now.checked_add(Duration::from_secs(12))
                    .expect("fixture age"),
            )
            .expect("fixture dedupe retention")
        });
        Ok(crate::NewJob {
            job_id: actual_job_id(job),
            kind: JobKind::try_new("email")?,
            schema_version: NonZeroU16::MIN,
            payload: Bytes::from_static(b"c"),
            fairness: FairnessClass::LowVolume,
            ordering_key: None,
            priority: Priority::Default,
            scheduled_at: Timestamp::from_millis(due_at.saturating_mul(1_000)),
            expires_at: Some(now.checked_add(Duration::from_secs(12))?),
            retry_override: Some(RetrySelection::Custom(retry_policy()?)),
            deduplication,
        })
    }

    fn select_fair_candidate(&mut self, job: MJobId) -> Result<crate::fairness::FairPermit> {
        let record = self.job_record(job)?;
        let mut budget = crate::fairness::FairnessBudget::tiny();
        // This bounded chain selects C, its retry, and redriven B. Keep the
        // real fair-owner admission path while allowing those three attempts.
        budget.max_low_volume_service = NonZeroU32::new(4)
            .ok_or_else(|| std::io::Error::other("invalid connector fair budget"))?;
        let mut owner =
            crate::test_helper::block_on(crate::fairness::FairDispatchOwner::load(&self.system_a))?
                .unwrap_or(crate::fairness::FairDispatchOwner::try_new(budget)?);
        owner.ensure_candidate(
            crate::fairness::FairCandidateInput {
                job_id: record.job_id,
                fairness: record.fairness.clone(),
                priority: record.priority,
                cost_units: record.policy.cost_units,
                scheduled_at: record.scheduled_at,
                payload_bytes: record.payload.total_length as usize,
                ordering_key: record.ordering_key.clone(),
                ordering_position: 1,
                block: None,
            },
            crate::fairness::FairCandidateMetadata::for_record(&record),
        )?;
        let permit = owner.select(record.job_id).map_err(|error| {
            std::io::Error::other(format!("fair candidate selection: {error:?}"))
        })?;
        crate::test_helper::block_on(owner.save(&self.system_a))?;
        Ok(permit)
    }

    /// `mbtDispatchNondet` nests `mbtStep` in an `any` action.  Quint Connect
    /// therefore reports the inner action name and no nondeterministic pick;
    /// the selected command is still serialized in the next-state
    /// `lastCommand`.  Decode that complete command instead of choosing a
    /// connector-owned default.  This keeps generated inputs authoritative,
    /// including stale authorities and the selected unknown-commit branch.
    fn command_from_step(&self, step: &Step) -> Result<Command> {
        let rendered = step.to_string();
        let line = rendered
            .lines()
            .find(|line| line.contains("+ lastCommand: "))
            .ok_or_else(|| std::io::Error::other("lifecycle step has no serialized command"))?;
        let (_, value) = line
            .split_once("+ lastCommand: ")
            .ok_or_else(|| std::io::Error::other("lifecycle step command is missing"))?;
        parse_command(value.trim()).map_err(|error| {
            std::io::Error::other(format!(
                "cannot decode lifecycle command {value:?}: {error}"
            ))
            .into()
        })
    }

    fn apply_dynamic(&mut self, command: Command) -> Result<()> {
        let family = command_family(&command);
        if self.require_command_coverage {
            *self.command_counts.entry(family).or_default() += 1;
        }
        match command {
            Command::LifecycleEnqueue {
                job,
                due_at,
                operation,
                with_dedupe,
                fingerprint,
            } => {
                let input = self.enqueue_input(job, due_at, with_dedupe)?;
                let result = crate::test_helper::block_on(
                    self.system_a.enqueue_raw(input, self.now_timestamp()),
                );
                match result {
                    Ok(receipt) => {
                        // EnqueueResult intentionally exposes only the job
                        // identity. Observe the committed record at the
                        // public lifecycle boundary before the next state
                        // projection so a newly generated opaque execution
                        // ID receives the next bijective model label.
                        if receipt.disposition == crate::EnqueueDisposition::Enqueued {
                            self.operation_labels.insert(job, MOperationId::OperationA);
                        }
                        self.sync_execution_id(job)?;
                        self.finish(
                            Command::LifecycleEnqueue {
                                job,
                                due_at,
                                operation,
                                with_dedupe,
                                fingerprint,
                            },
                            ResultClass::AppliedClass,
                            StoreResult::Committed,
                            if receipt.disposition == crate::EnqueueDisposition::AlreadyPresent {
                                LifecycleOutcome::EnqueueAlreadyPresent
                            } else if receipt.disposition == crate::EnqueueDisposition::Deduplicated
                            {
                                LifecycleOutcome::EnqueueDedupeCommitted
                            } else if due_at > self.now {
                                if with_dedupe {
                                    LifecycleOutcome::EnqueueDedupeCommitted
                                } else {
                                    LifecycleOutcome::EnqueueFutureCommitted
                                }
                            } else {
                                LifecycleOutcome::EnqueueCommitted
                            },
                            CompletionDetail::NoCompletionDetail,
                            if receipt.disposition == crate::EnqueueDisposition::AlreadyPresent {
                                EnqueueDisposition::AlreadyPresent
                            } else {
                                EnqueueDisposition::Inserted
                            },
                            job,
                            operation,
                        );
                    }
                    Err(crate::error::JobSystemError::JobIdConflict) => self.finish(
                        Command::LifecycleEnqueue {
                            job,
                            due_at,
                            operation,
                            with_dedupe,
                            fingerprint,
                        },
                        ResultClass::RejectedClass,
                        StoreResult::Rejected,
                        LifecycleOutcome::EnqueueJobIdConflict,
                        CompletionDetail::NoCompletionDetail,
                        EnqueueDisposition::JobIdConflict,
                        job,
                        operation,
                    ),
                    Err(error) => {
                        let (class, result) = Self::dynamic_error_class(&error);
                        self.finish(
                            Command::LifecycleEnqueue {
                                job,
                                due_at,
                                operation,
                                with_dedupe,
                                fingerprint,
                            },
                            class,
                            result,
                            LifecycleOutcome::EnqueueRejected,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            job,
                            operation,
                        );
                    }
                }
                Ok(())
            }
            Command::LifecycleSelectClaim {
                job,
                reader,
                revision,
            } => {
                if self.fair_permits.contains_key(&job) {
                    self.claim_pending = true;
                    self.claim_job = job;
                    self.claim_revision = revision;
                    self.claim_reader = reader;
                    self.finish(
                        Command::LifecycleSelectClaim {
                            job,
                            reader,
                            revision,
                        },
                        ResultClass::AppliedClass,
                        StoreResult::Committed,
                        LifecycleOutcome::ClaimSelected,
                        CompletionDetail::NoCompletionDetail,
                        EnqueueDisposition::NotEnqueue,
                        job,
                        MOperationId::OperationA,
                    );
                    return Ok(());
                }
                let permit = self.select_fair_candidate(job)?;
                self.fair_permits.insert(job, permit);
                self.claim_pending = true;
                self.claim_job = job;
                self.claim_revision = revision;
                self.claim_reader = reader;
                self.finish(
                    Command::LifecycleSelectClaim {
                        job,
                        reader,
                        revision,
                    },
                    ResultClass::AppliedClass,
                    StoreResult::Committed,
                    LifecycleOutcome::ClaimSelected,
                    CompletionDetail::NoCompletionDetail,
                    EnqueueDisposition::NotEnqueue,
                    job,
                    MOperationId::OperationA,
                );
                Ok(())
            }
            Command::LifecycleClaim {
                job,
                contender,
                revision,
            } => {
                let command = Command::LifecycleClaim {
                    job,
                    contender,
                    revision,
                };
                let result = if self.fair_permits.contains_key(&job) {
                    let system = self.system_for_node(contender);
                    Some(crate::test_helper::block_on(
                        system.claim(actual_job_id(job), self.now_timestamp()),
                    ))
                } else {
                    // Exercise the canonical owner planner for an unselected
                    // claim, but release its probe immediately so an invalid
                    // model command cannot claim outside SelectClaim.
                    if let Some(mut owner) = crate::test_helper::block_on(
                        crate::fairness::FairDispatchOwner::load(&self.system_a),
                    )? && let Ok(permit) = owner.select(actual_job_id(job))
                    {
                        let _ = owner.release(permit, crate::fairness::FairRelease::Conflict);
                        crate::test_helper::block_on(owner.save(&self.system_a))?;
                    }
                    None
                };
                match result {
                    Some(Ok(claim)) => {
                        self.register_claim_handle(job, &claim);
                        self.claims.insert(job, claim);
                        self.clear_claim_pending();
                        self.finish(
                            command,
                            ResultClass::AppliedClass,
                            StoreResult::Committed,
                            LifecycleOutcome::ClaimCommitted,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            job,
                            MOperationId::OperationA,
                        );
                    }
                    Some(Err(_)) | None => {
                        self.clear_claim_pending();
                        self.settle_fair_permit(job, crate::fairness::FairRelease::Conflict)?;
                        self.finish(
                            command,
                            ResultClass::ConflictClass,
                            StoreResult::Conflict,
                            LifecycleOutcome::ClaimConflict,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            job,
                            MOperationId::OperationA,
                        );
                    }
                }
                Ok(())
            }
            Command::LifecycleRenew(input) => {
                if !self.has_claim_handle_or_lease(input.job)? {
                    self.finish(
                        Command::LifecycleRenew(input.clone()),
                        ResultClass::ConflictClass,
                        StoreResult::Conflict,
                        LifecycleOutcome::RenewRejected,
                        CompletionDetail::NoCompletionDetail,
                        EnqueueDisposition::NotEnqueue,
                        input.job,
                        input.operation,
                    );
                    return Ok(());
                }
                self.ensure_claim_handle(input.job)?;
                // A stale completion handle is still a real authority witness,
                // but its job record has intentionally been deleted.  Keep
                // routing the public renewal boundary from that handle so an
                // expected authority conflict is observable instead of
                // turning projection absence into a connector error.
                let owner = self.claim_owner(input.job, input.node);
                let now = self.now_timestamp();
                let result = {
                    let claim = self
                        .claims
                        .get_mut(&input.job)
                        .ok_or_else(|| std::io::Error::other("renew claim missing"))?;
                    claim
                        .last_heartbeat()
                        .store(i64::MIN, std::sync::atomic::Ordering::Release);
                    let system = match owner {
                        Node::NodeA => &self.system_a,
                        Node::NodeB => &self.system_b,
                    };
                    crate::test_helper::block_on(system.renew(claim, now))
                };
                match result {
                    Ok(_) => self.finish(
                        Command::LifecycleRenew(input.clone()),
                        ResultClass::AppliedClass,
                        StoreResult::Committed,
                        LifecycleOutcome::Renewed,
                        CompletionDetail::NoCompletionDetail,
                        EnqueueDisposition::NotEnqueue,
                        input.job,
                        input.operation,
                    ),
                    Err(_) => self.finish(
                        Command::LifecycleRenew(input.clone()),
                        ResultClass::ConflictClass,
                        StoreResult::Conflict,
                        LifecycleOutcome::RenewRejected,
                        CompletionDetail::NoCompletionDetail,
                        EnqueueDisposition::NotEnqueue,
                        input.job,
                        input.operation,
                    ),
                }
                Ok(())
            }
            Command::LifecycleCheckpoint {
                authority: input,
                bytes,
            } => {
                if !self.has_claim_handle_or_lease(input.job)? {
                    self.finish(
                        Command::LifecycleCheckpoint {
                            authority: input.clone(),
                            bytes,
                        },
                        ResultClass::ConflictClass,
                        StoreResult::Conflict,
                        if bytes
                            > i64::try_from(crate::model::MAX_CHECKPOINT_BYTES).unwrap_or(i64::MAX)
                        {
                            LifecycleOutcome::CheckpointBoundRejected
                        } else {
                            LifecycleOutcome::CheckpointAuthorityRejected
                        },
                        CompletionDetail::NoCompletionDetail,
                        EnqueueDisposition::NotEnqueue,
                        input.job,
                        input.operation,
                    );
                    return Ok(());
                }
                self.ensure_claim_handle(input.job)?;
                // See renewal above: an absent terminal record can still have
                // a retained stale handle for the generated conflict case.
                let owner = self.claim_owner(input.job, input.node);
                let now = self.now_timestamp();
                let result = {
                    let claim = self
                        .claims
                        .get_mut(&input.job)
                        .ok_or_else(|| std::io::Error::other("checkpoint claim missing"))?;
                    let system = match owner {
                        Node::NodeA => &self.system_a,
                        Node::NodeB => &self.system_b,
                    };
                    crate::test_helper::block_on(system.checkpoint(
                        claim,
                        Bytes::from(vec![0; usize::try_from(bytes.max(0)).unwrap_or(usize::MAX)]),
                        now,
                    ))
                };
                let outcome = match &result {
                    Ok(_) => LifecycleOutcome::CheckpointCommitted,
                    Err(crate::error::JobSystemError::Validation(_)) => {
                        LifecycleOutcome::CheckpointBoundRejected
                    }
                    Err(_) => LifecycleOutcome::CheckpointAuthorityRejected,
                };
                let (class, store_result) = if result.is_ok() {
                    (ResultClass::AppliedClass, StoreResult::Committed)
                } else {
                    (ResultClass::ConflictClass, StoreResult::Conflict)
                };
                self.finish(
                    Command::LifecycleCheckpoint {
                        authority: input.clone(),
                        bytes,
                    },
                    class,
                    store_result,
                    outcome,
                    CompletionDetail::NoCompletionDetail,
                    EnqueueDisposition::NotEnqueue,
                    input.job,
                    input.operation,
                );
                Ok(())
            }
            Command::LifecycleHandle {
                authority: input,
                handler,
            } => {
                let command = Command::LifecycleHandle {
                    authority: input.clone(),
                    handler,
                };
                if !self.claims.contains_key(&input.job)
                    || !self.has_exact_completion_authority(&input)?
                {
                    self.finish(
                        command,
                        ResultClass::ConflictClass,
                        StoreResult::Conflict,
                        LifecycleOutcome::CompletionRejected,
                        CompletionDetail::NoCompletionDetail,
                        EnqueueDisposition::NotEnqueue,
                        input.job,
                        input.operation,
                    );
                    return Ok(());
                }
                let (claim, authority, owner) = self.take_completion_claim(&input)?;
                let outcome = match handler {
                    HandlerResult::Success => {
                        JobOutcome::Complete(crate::OutcomeCode::try_new("completed")?)
                    }
                    HandlerResult::Transient => JobOutcome::Retry {
                        class: crate::RetryClass::Transient,
                        not_before: Some(self.now_timestamp().checked_add(Duration::from_secs(1))?),
                        code: crate::OutcomeCode::try_new("transient")?,
                    },
                    HandlerResult::Throttled => JobOutcome::Retry {
                        class: crate::RetryClass::Throttled,
                        not_before: Some(self.now_timestamp().checked_add(Duration::from_secs(1))?),
                        code: crate::OutcomeCode::try_new("throttled")?,
                    },
                    HandlerResult::Ambiguous => JobOutcome::Retry {
                        class: crate::RetryClass::AmbiguousEffect,
                        not_before: Some(self.now_timestamp().checked_add(Duration::from_secs(1))?),
                        code: crate::OutcomeCode::try_new("ambiguous")?,
                    },
                    HandlerResult::Permanent => JobOutcome::DeadLetter {
                        code: crate::OutcomeCode::try_new("permanent")?,
                    },
                };
                let now = self.now_timestamp();
                let system = self.system_for_node(owner);
                let result =
                    crate::test_helper::block_on(system.apply_outcome(claim, outcome, now));
                match result {
                    Ok(crate::OutcomeResult::Completed(_)) => {
                        self.record_completion(input.job, &input, authority)?;
                        // Handler completion records the attempted job in the
                        // model; direct Complete intentionally leaves the
                        // previous stale-attempt job untouched.
                        self.last_attempt_job = input.job;
                        self.finish(
                            command,
                            ResultClass::AppliedClass,
                            StoreResult::Committed,
                            LifecycleOutcome::CompletionDeleted,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            input.job,
                            input.operation,
                        );
                    }
                    Ok(crate::OutcomeResult::Retried { class, .. }) => {
                        // Handler retry clears the model token. The next
                        // successful claim therefore starts a fresh model
                        // label sequence, unlike lease-expiry retry below
                        // which deliberately preserves the cleared token's
                        // progression.
                        self.reset_lease_token_labels(input.job);
                        self.settle_fair_permit(input.job, crate::fairness::FairRelease::Retry)?;
                        let lifecycle = match class {
                            crate::RetryClass::Transient => LifecycleOutcome::RetryTransient,
                            crate::RetryClass::Throttled => LifecycleOutcome::RetryThrottled,
                            crate::RetryClass::AmbiguousEffect => LifecycleOutcome::RetryAmbiguous,
                        };
                        self.finish(
                            command,
                            ResultClass::AppliedClass,
                            StoreResult::Committed,
                            lifecycle,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            input.job,
                            input.operation,
                        );
                    }
                    Ok(crate::OutcomeResult::DeadLettered { .. }) => {
                        self.reset_lease_token_labels(input.job);
                        self.settle_fair_permit(
                            input.job,
                            crate::fairness::FairRelease::DeadLetter,
                        )?;
                        self.finish(
                            command,
                            ResultClass::AppliedClass,
                            StoreResult::Committed,
                            LifecycleOutcome::PermanentDeadLetter,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            input.job,
                            input.operation,
                        );
                    }
                    Ok(other) => {
                        return Err(std::io::Error::other(format!(
                            "unexpected handler outcome: {other:?}"
                        ))
                        .into());
                    }
                    Err(error) => {
                        let (class, store_result) = Self::dynamic_error_class(&error);
                        if self.project_jobs()?[&input.job].state == MJobState::Leased {
                            self.ensure_claim_handle(input.job)?;
                        }
                        self.finish(
                            command,
                            class,
                            store_result,
                            LifecycleOutcome::CompletionRejected,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            input.job,
                            input.operation,
                        );
                    }
                }
                Ok(())
            }
            Command::LifecycleComplete(input) => {
                if !self.claims.contains_key(&input.job)
                    || !self.has_exact_completion_authority(&input)?
                {
                    self.finish(
                        Command::LifecycleComplete(input.clone()),
                        ResultClass::ConflictClass,
                        StoreResult::Conflict,
                        LifecycleOutcome::CompletionRejected,
                        CompletionDetail::NoCompletionDetail,
                        EnqueueDisposition::NotEnqueue,
                        input.job,
                        input.operation,
                    );
                    return Ok(());
                }
                let (claim, authority, owner) = self.take_completion_claim(&input)?;
                let result = {
                    let system = self.system_for_node(owner);
                    crate::test_helper::block_on(system.complete(
                        claim,
                        JobOutcome::Complete(crate::OutcomeCode::try_new("completed")?),
                        self.now_timestamp(),
                    ))
                };
                match result {
                    Ok(_) => {
                        self.record_completion(input.job, &input, authority)?;
                        self.finish(
                            Command::LifecycleComplete(input.clone()),
                            ResultClass::AppliedClass,
                            StoreResult::Committed,
                            LifecycleOutcome::CompletionDeleted,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            input.job,
                            input.operation,
                        );
                    }
                    Err(error) => {
                        let (class, store_result) = Self::dynamic_error_class(&error);
                        self.finish(
                            Command::LifecycleComplete(input.clone()),
                            class,
                            store_result,
                            LifecycleOutcome::CompletionRejected,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            input.job,
                            input.operation,
                        );
                    }
                }
                Ok(())
            }
            Command::LifecycleExpose {
                job,
                operation,
                revision,
                generation,
            } => {
                let current = self.project_jobs()?[&job].clone();
                let allowed = self.completion_pending
                    && !self.unknown_pending
                    && job == self.completion_job
                    && operation == self.completion_operation
                    && revision == self.completion_revision
                    && generation == self.completion_generation
                    && current.state == MJobState::Absent
                    && current.operation_id == operation
                    && current.revision == revision
                    && current.generation == generation;
                // Completion detail exposure is not persisted after terminal
                // deletion. Track only the model's bounded exposure bit; the
                // terminal receipt itself is always read from the public
                // observation boundary.
                let detail = if allowed {
                    if self.completion_receipt_jobs.len() < MAX_COMPLETION_RECEIPTS {
                        self.completion_receipt_jobs.insert(job);
                        CompletionDetail::CompletionDetailReturned
                    } else {
                        self.completion_omissions = self.completion_omissions.saturating_add(1);
                        CompletionDetail::CompletionDetailOmitted
                    }
                } else {
                    CompletionDetail::NoCompletionDetail
                };
                if allowed {
                    self.completion_pending = false;
                    self.completion_detail = detail;
                }
                self.completion_detail_job = job;
                self.finish(
                    Command::LifecycleExpose {
                        job,
                        operation,
                        revision,
                        generation,
                    },
                    if allowed {
                        ResultClass::AppliedClass
                    } else {
                        ResultClass::ConflictClass
                    },
                    if allowed {
                        StoreResult::Committed
                    } else {
                        StoreResult::Conflict
                    },
                    if allowed {
                        LifecycleOutcome::CompletionDeleted
                    } else {
                        LifecycleOutcome::CompletionRejected
                    },
                    detail,
                    EnqueueDisposition::NotEnqueue,
                    job,
                    operation,
                );
                Ok(())
            }
            Command::LifecycleCancel {
                authority: input,
                phase,
            } => {
                let command = Command::LifecycleCancel {
                    authority: input.clone(),
                    phase,
                };
                match phase {
                    types::CancelPhase::CancelScheduled => {
                        let result = crate::test_helper::block_on(
                            self.system_a
                                .cancel_job(actual_job_id(input.job), self.now_timestamp()),
                        );
                        match result {
                            Ok(crate::CancellationResult::Cancelled) => self.finish(
                                command,
                                ResultClass::AppliedClass,
                                StoreResult::Committed,
                                LifecycleOutcome::CancelCommitted,
                                CompletionDetail::NoCompletionDetail,
                                EnqueueDisposition::NotEnqueue,
                                input.job,
                                input.operation,
                            ),
                            Err(error) => {
                                let (class, store_result) = Self::dynamic_error_class(&error);
                                self.finish(
                                    command,
                                    class,
                                    store_result,
                                    LifecycleOutcome::CompletionRejected,
                                    CompletionDetail::NoCompletionDetail,
                                    EnqueueDisposition::NotEnqueue,
                                    input.job,
                                    input.operation,
                                );
                            }
                            Ok(crate::CancellationResult::Requested) => {
                                return Err(std::io::Error::other(
                                    "scheduled cancellation returned request",
                                )
                                .into());
                            }
                        }
                    }
                    types::CancelPhase::RequestLeased => {
                        if !self.has_claim_handle_or_lease(input.job)? {
                            self.finish(
                                command,
                                ResultClass::ConflictClass,
                                StoreResult::Conflict,
                                LifecycleOutcome::CompletionRejected,
                                CompletionDetail::NoCompletionDetail,
                                EnqueueDisposition::NotEnqueue,
                                input.job,
                                input.operation,
                            );
                            return Ok(());
                        }
                        self.ensure_claim_handle(input.job)?;
                        let owner = self.claim_owner(input.job, input.node);
                        let system = self.system_for_node(owner);
                        let result = {
                            let claim = self
                                .claims
                                .get(&input.job)
                                .ok_or_else(|| std::io::Error::other("cancel claim missing"))?;
                            crate::test_helper::block_on(
                                system.request_job_cancellation(claim, self.now_timestamp()),
                            )
                        };
                        match result {
                            Ok(crate::CancellationResult::Requested) => {
                                self.finish(
                                    command,
                                    ResultClass::AppliedClass,
                                    StoreResult::Committed,
                                    LifecycleOutcome::CancelRequested,
                                    CompletionDetail::NoCompletionDetail,
                                    EnqueueDisposition::NotEnqueue,
                                    input.job,
                                    input.operation,
                                );
                            }
                            Err(error) => {
                                let (class, store_result) = Self::dynamic_error_class(&error);
                                self.finish(
                                    command,
                                    class,
                                    store_result,
                                    LifecycleOutcome::CompletionRejected,
                                    CompletionDetail::NoCompletionDetail,
                                    EnqueueDisposition::NotEnqueue,
                                    input.job,
                                    input.operation,
                                );
                            }
                            Ok(crate::CancellationResult::Cancelled) => {
                                return Err(std::io::Error::other(
                                    "request cancellation committed terminal state",
                                )
                                .into());
                            }
                        }
                    }
                    types::CancelPhase::CommitLeased => {
                        if !self.has_claim_handle_or_lease(input.job)? {
                            self.finish(
                                command,
                                ResultClass::ConflictClass,
                                StoreResult::Conflict,
                                LifecycleOutcome::LeasedCancelRejected,
                                CompletionDetail::NoCompletionDetail,
                                EnqueueDisposition::NotEnqueue,
                                input.job,
                                input.operation,
                            );
                            return Ok(());
                        }
                        self.ensure_claim_handle(input.job)?;
                        let owner = self.claim_owner(input.job, input.node);
                        let claim = self
                            .claims
                            .remove(&input.job)
                            .ok_or_else(|| std::io::Error::other("cancel claim missing"))?;
                        let result = {
                            let system = self.system_for_node(owner);
                            crate::test_helper::block_on(
                                system.cancel_claim(claim, self.now_timestamp()),
                            )
                        };
                        match result {
                            Ok(crate::CancellationResult::Cancelled) => {
                                self.settle_fair_permit(
                                    input.job,
                                    crate::fairness::FairRelease::Cancelled,
                                )?;
                                self.finish(
                                    command,
                                    ResultClass::AppliedClass,
                                    StoreResult::Committed,
                                    LifecycleOutcome::LeasedCancelled,
                                    CompletionDetail::NoCompletionDetail,
                                    EnqueueDisposition::NotEnqueue,
                                    input.job,
                                    input.operation,
                                );
                            }
                            Err(error) => {
                                let (class, store_result) = Self::dynamic_error_class(&error);
                                if self.project_jobs()?[&input.job].state == MJobState::Leased {
                                    self.ensure_claim_handle(input.job)?;
                                }
                                self.finish(
                                    command,
                                    class,
                                    store_result,
                                    LifecycleOutcome::LeasedCancelRejected,
                                    CompletionDetail::NoCompletionDetail,
                                    EnqueueDisposition::NotEnqueue,
                                    input.job,
                                    input.operation,
                                );
                            }
                            Ok(crate::CancellationResult::Requested) => {
                                return Err(std::io::Error::other(
                                    "leased cancellation returned request",
                                )
                                .into());
                            }
                        }
                    }
                }
                Ok(())
            }
            Command::LifecycleAdvance { amount } => self.advance(amount),
            Command::LifecycleExpire { job, lease } => {
                let result = crate::test_helper::block_on(
                    self.system_a
                        .expire_job(actual_job_id(job), self.now_timestamp()),
                );
                match result {
                    Ok(crate::ExpiryResult::Cancelled) => {
                        self.reset_lease_token_labels(job);
                        self.claims.remove(&job);
                        self.settle_fair_permit(job, crate::fairness::FairRelease::Cancelled)?;
                        self.finish(
                            Command::LifecycleExpire { job, lease },
                            ResultClass::AppliedClass,
                            StoreResult::Committed,
                            LifecycleOutcome::LeasedCancelled,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            job,
                            MOperationId::OperationA,
                        );
                    }
                    Ok(crate::ExpiryResult::LeaseExpired) => {
                        self.claims.remove(&job);
                        self.settle_fair_permit(job, crate::fairness::FairRelease::Retry)?;
                        self.finish(
                            Command::LifecycleExpire { job, lease },
                            ResultClass::AppliedClass,
                            StoreResult::Committed,
                            LifecycleOutcome::LeaseExpired,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            job,
                            MOperationId::OperationA,
                        );
                    }
                    Ok(crate::ExpiryResult::DeadLettered) => {
                        self.reset_lease_token_labels(job);
                        self.claims.remove(&job);
                        self.settle_fair_permit(job, crate::fairness::FairRelease::DeadLetter)?;
                        self.finish(
                            Command::LifecycleExpire { job, lease },
                            ResultClass::AppliedClass,
                            StoreResult::Committed,
                            if lease {
                                LifecycleOutcome::PermanentDeadLetter
                            } else {
                                LifecycleOutcome::ScheduledExpired
                            },
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            job,
                            MOperationId::OperationA,
                        );
                    }
                    Ok(crate::ExpiryResult::Unchanged) => self.finish(
                        Command::LifecycleExpire { job, lease },
                        ResultClass::ConflictClass,
                        StoreResult::Conflict,
                        LifecycleOutcome::CompletionRejected,
                        CompletionDetail::NoCompletionDetail,
                        EnqueueDisposition::NotEnqueue,
                        job,
                        MOperationId::OperationA,
                    ),
                    Err(error) => {
                        let (class, store_result) = Self::dynamic_error_class(&error);
                        self.finish(
                            Command::LifecycleExpire { job, lease },
                            class,
                            store_result,
                            LifecycleOutcome::CompletionRejected,
                            CompletionDetail::NoCompletionDetail,
                            EnqueueDisposition::NotEnqueue,
                            job,
                            MOperationId::OperationA,
                        );
                    }
                }
                Ok(())
            }
            Command::LifecycleUnknown {
                authority: input,
                committed,
            } => {
                if !self.has_claim_handle_or_lease(input.job)?
                    || !self.has_exact_unknown_authority(&input)?
                {
                    self.finish(
                        Command::LifecycleUnknown {
                            authority: input.clone(),
                            committed,
                        },
                        ResultClass::ConflictClass,
                        StoreResult::Conflict,
                        LifecycleOutcome::CompletionRejected,
                        CompletionDetail::NoCompletionDetail,
                        EnqueueDisposition::NotEnqueue,
                        input.job,
                        input.operation,
                    );
                    return Ok(());
                }
                self.ensure_claim_handle(input.job)?;
                let owner = self.claim_owner(input.job, input.node);
                if committed {
                    self.store.queue_unknown_after_commit()?;
                } else {
                    self.store.queue_unknown_before_commit()?;
                    self.store.queue_unknown_before_commit()?;
                }
                let claim = self
                    .claims
                    .remove(&input.job)
                    .ok_or_else(|| std::io::Error::other("unknown claim missing"))?;
                let result = {
                    let system = self.system_for_node(owner);
                    crate::test_helper::block_on(system.complete(
                        claim,
                        JobOutcome::Complete(crate::OutcomeCode::try_new("completed")?),
                        self.now_timestamp(),
                    ))
                };
                Self::validate_unknown_completion_result(committed, &result)?;
                let observed = self.project_jobs()?[&input.job].clone();
                let after_commit = observed.state == MJobState::Absent;
                // An unknown completion has already consumed the local claim
                // handle.  The live observation and operation marker are the
                // only safe reconciliation evidence; rebuilding a claim here
                // would replay handler authority and can fail with
                // LeaseConflict while the original lease is still visible.
                if after_commit {
                    self.completion_receipt_jobs.insert(input.job);
                    self.settle_fair_permit(input.job, crate::fairness::FairRelease::Complete)?;
                }
                let unknown_result = if after_commit {
                    StoreResult::Committed
                } else {
                    StoreResult::Conflict
                };
                self.unknown_pending = true;
                self.unknown_job = input.job;
                self.unknown_operation = input.operation;
                self.unknown_node = input.node;
                self.unknown_revision = input.revision;
                self.unknown_generation = input.generation;
                self.unknown_fence = input.fence;
                self.unknown_token = input.token;
                self.unknown_lease_until = input.lease_until;
                self.unknown_after_commit = after_commit;
                self.unknown_readback = unknown_result;
                self.completion_detail = CompletionDetail::NoCompletionDetail;
                self.completion_detail_job = input.job;
                self.finish(
                    Command::LifecycleUnknown {
                        authority: input.clone(),
                        committed,
                    },
                    ResultClass::UnknownClass,
                    StoreResult::Unknown,
                    if after_commit {
                        LifecycleOutcome::UnknownAfterCommit
                    } else {
                        LifecycleOutcome::UnknownBeforeCommit
                    },
                    CompletionDetail::NoCompletionDetail,
                    EnqueueDisposition::NotEnqueue,
                    input.job,
                    input.operation,
                );
                Ok(())
            }
            Command::LifecycleReconcile {
                job,
                operation: operation_id,
                observed,
            } => {
                let exact_request = self.unknown_pending
                    && job == self.unknown_job
                    && operation_id == self.unknown_operation
                    && observed == self.unknown_readback;
                // Generated operation IDs are opaque.  For the exact
                // reconciliation command, use the ID read from the durable
                // operation receipt/marker rather than manufacturing bytes
                // from the finite model label.  Deliberately wrong commands
                // retain their synthetic ID so the public API can reject
                // them.
                let reconcile_operation = if exact_request {
                    self.observed_operation_id(job)?
                } else {
                    operation(operation_id)
                };
                let result = crate::test_helper::block_on(
                    self.system_a
                        .reconcile(actual_job_id(job), reconcile_operation),
                );
                let exact = exact_request;
                let outcome = match result {
                    Ok(crate::ReconciliationOutcome::AlreadyCommitted)
                        if exact && observed == StoreResult::Committed =>
                    {
                        let terminal = matches!(
                            self.observe_job(job)?,
                            LifecycleObservation::Terminal(OperationReceipt {
                                operation_id,
                                job_id,
                                ..
                            }) if operation_id == reconcile_operation
                                && job_id == actual_job_id(job)
                        );
                        if !terminal {
                            (
                                ResultClass::ConflictClass,
                                StoreResult::Conflict,
                                LifecycleOutcome::CompletionRejected,
                                CompletionDetail::NoCompletionDetail,
                            )
                        } else {
                            // The receipt is a durable public observation.
                            // Reconciliation may expose its detail only while
                            // the model's bounded exposure budget has room.
                            let detail =
                                if self.completion_receipt_jobs.len() < MAX_COMPLETION_RECEIPTS {
                                    self.completion_receipt_jobs.insert(job);
                                    CompletionDetail::CompletionDetailReturned
                                } else {
                                    self.completion_omissions =
                                        self.completion_omissions.saturating_add(1);
                                    CompletionDetail::CompletionDetailOmitted
                                };
                            self.unknown_pending = false;
                            self.completion_pending = false;
                            self.completion_job = job;
                            self.completion_operation = self.unknown_operation;
                            self.completion_revision = self.unknown_revision.saturating_add(1);
                            self.completion_generation = self.unknown_generation;
                            self.completion_detail = detail;
                            self.completion_detail_job = job;
                            (
                                ResultClass::AppliedClass,
                                StoreResult::Committed,
                                LifecycleOutcome::UnknownReconciled,
                                detail,
                            )
                        }
                    }
                    Ok(crate::ReconciliationOutcome::RetryCommit)
                        if exact && observed == StoreResult::Conflict =>
                    {
                        self.unknown_pending = false;
                        (
                            ResultClass::AppliedClass,
                            StoreResult::Committed,
                            LifecycleOutcome::UnknownConflictReconciled,
                            CompletionDetail::NoCompletionDetail,
                        )
                    }
                    Ok(crate::ReconciliationOutcome::LeaseLost) if exact => {
                        self.unknown_pending = false;
                        (
                            ResultClass::AppliedClass,
                            StoreResult::Committed,
                            LifecycleOutcome::UnknownAuthorityChanged,
                            CompletionDetail::NoCompletionDetail,
                        )
                    }
                    Ok(crate::ReconciliationOutcome::Conflict) | Err(_) => (
                        ResultClass::ConflictClass,
                        StoreResult::Conflict,
                        LifecycleOutcome::CompletionRejected,
                        CompletionDetail::NoCompletionDetail,
                    ),
                    _ => (
                        ResultClass::ConflictClass,
                        StoreResult::Conflict,
                        LifecycleOutcome::CompletionRejected,
                        CompletionDetail::NoCompletionDetail,
                    ),
                };
                self.finish(
                    Command::LifecycleReconcile {
                        job,
                        operation: operation_id,
                        observed,
                    },
                    outcome.0,
                    outcome.1,
                    outcome.2,
                    outcome.3,
                    EnqueueDisposition::NotEnqueue,
                    job,
                    operation_id,
                );
                Ok(())
            }
            Command::LifecycleCorrupt { job, kind } => self.corrupt(job, kind),
            Command::LifecycleRepair {
                job,
                revision,
                operation: operation_id,
            } => self.repair(job, revision, operation_id),
            Command::LifecycleRedrive {
                job,
                expected_revision,
                expected_operation,
                reuse_execution,
            } => {
                if job == MJobId::JobB {
                    self.redrive_b(expected_revision, expected_operation, reuse_execution)
                } else {
                    self.redrive_a(expected_revision, expected_operation)
                }
            }
        }
    }

    fn adopt_b(&mut self) -> Result<crate::ClaimedJob> {
        self.ensure_claim_handle(MJobId::JobB)?;
        self.claims
            .remove(&MJobId::JobB)
            .ok_or_else(|| std::io::Error::other("missing public claim handle").into())
    }

    fn complete_conflict(&mut self) -> Result<()> {
        let mut claim = self.adopt_b()?;
        let mut wrong = claim.record().clone();
        if let JobState::Leased(lease) = &mut wrong.state {
            lease.token = LeaseToken::from([4; 16]);
        }
        claim.replace_encoded_authority(
            encode_job_record(&wrong)?,
            operation(MOperationId::OperationA),
        );
        let command = Command::LifecycleComplete(types::AuthorityInput {
            job: MJobId::JobB,
            node: Node::NodeA,
            revision: 1,
            generation: 1,
            fence: 1,
            token: 4,
            lease_until: 3,
            operation: MOperationId::OperationA,
        });
        let result = crate::test_helper::block_on(self.system_a.complete(
            claim,
            JobOutcome::Complete(crate::OutcomeCode::try_new("completed")?),
            self.now_timestamp(),
        ));
        if result.is_ok() {
            return Err(std::io::Error::other("stale completion unexpectedly committed").into());
        }
        self.finish(
            command,
            ResultClass::ConflictClass,
            StoreResult::Conflict,
            LifecycleOutcome::CompletionRejected,
            CompletionDetail::NoCompletionDetail,
            EnqueueDisposition::NotEnqueue,
            MJobId::JobB,
            MOperationId::OperationA,
        );
        Ok(())
    }

    fn unknown_before(&mut self) -> Result<()> {
        self.apply_dynamic(Command::LifecycleUnknown {
            authority: self.unknown_command_authority()?,
            committed: false,
        })
    }

    fn unknown_after(&mut self) -> Result<()> {
        self.apply_dynamic(Command::LifecycleUnknown {
            authority: self.unknown_command_authority()?,
            committed: true,
        })
    }

    fn unknown_command_authority(&self) -> Result<types::AuthorityInput> {
        if self.unknown_pending {
            return Ok(CompletionAuthority {
                node: self.unknown_node,
                revision: self.unknown_revision,
                generation: self.unknown_generation,
                fence: self.unknown_fence,
                token: self.unknown_token,
                lease_until: self.unknown_lease_until,
                operation: self.unknown_operation,
            }
            .into_input(self.unknown_job));
        }
        let claim = self
            .claims
            .get(&MJobId::JobB)
            .ok_or_else(|| std::io::Error::other("unknown claim missing"))?;
        Ok(self
            .completion_authority(MJobId::JobB, claim)?
            .into_input(MJobId::JobB))
    }

    fn corrupt(&mut self, job: MJobId, kind: RecordKind) -> Result<()> {
        let command = Command::LifecycleCorrupt { job, kind };
        if kind == RecordKind::UnknownVersion {
            // The Quint reducer captures the pre-quarantine value while the
            // record is still publicly observable. Retain only that public
            // observation for later projection; transitions continue to read
            // the live store and never consult this trace evidence.
            let observation = self.observe_job(job)?;
            self.register_observed_identifiers(&observation);
            self.trace_quarantine_observations.insert(
                job,
                QuarantineObservation {
                    observation,
                    operation_label: self.model_operation(job),
                },
            );
            let key = crate::keys::operation_key(self.system_a.namespace(), &actual_job_id(job))?;
            self.store
                .put_raw(key.clone(), Bytes::from_static(&[0x7f]))?;
            if decode_operation(&Bytes::from_static(&[0x7f])).is_ok() {
                return Err(std::io::Error::other("unknown operation was decoded").into());
            }
            self.finish(
                command,
                ResultClass::RejectedClass,
                StoreResult::Rejected,
                LifecycleOutcome::UnknownVersionQuarantined,
                CompletionDetail::NoCompletionDetail,
                EnqueueDisposition::NotEnqueue,
                job,
                MOperationId::OperationA,
            );
            return Ok(());
        }
        let record = self.job_record(job)?;
        let due = crate::keys::due_key(
            self.system_a.namespace(),
            &record.queue,
            record.scheduled_at,
            &record.job_id,
        )?;
        let mut next = record.clone();
        next.revision = next.revision.saturating_add(1);
        self.store.put_raw(
            crate::keys::job_key(self.system_a.namespace(), &record.job_id)?,
            encode_job_record(&next)?,
        )?;
        self.store.delete_raw(&due)?;
        self.store.delete_raw(&crate::keys::fair_key(
            self.system_a.namespace(),
            &record.queue,
            &record.job_id,
        )?)?;
        self.finish(
            command,
            ResultClass::AppliedClass,
            StoreResult::Committed,
            LifecycleOutcome::CorruptQuarantined,
            CompletionDetail::NoCompletionDetail,
            EnqueueDisposition::NotEnqueue,
            job,
            MOperationId::OperationA,
        );
        Ok(())
    }

    fn repair(&mut self, job: MJobId, revision: i64, operation_id: MOperationId) -> Result<()> {
        let command = Command::LifecycleRepair {
            job,
            revision,
            operation: operation_id,
        };
        let public_operation = self.repair_operation_id(job, operation_id)?;
        let result = crate::test_helper::block_on(self.system_a.repair_job(
            actual_job_id(job),
            u64::try_from(revision.max(0)).unwrap_or(u64::MAX),
            public_operation,
        ));
        let allowed = result.is_ok();
        if allowed {
            if self.unknown_pending && self.unknown_job != job {
                self.unrelated_progress = self
                    .unrelated_progress
                    .saturating_add(1)
                    .min(MAX_UNRELATED_PROGRESS);
            }
        } else if self.is_unknown_version(job)? {
            self.quarantine_attempts = self.quarantine_attempts.saturating_add(1);
        }
        self.finish(
            command,
            if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::ConflictClass
            },
            if allowed {
                StoreResult::Committed
            } else {
                StoreResult::Conflict
            },
            if allowed {
                LifecycleOutcome::RepairCommitted
            } else {
                LifecycleOutcome::RepairConflict
            },
            CompletionDetail::NoCompletionDetail,
            EnqueueDisposition::NotEnqueue,
            job,
            operation_id,
        );
        Ok(())
    }

    fn handle_permanent(&mut self) -> Result<()> {
        let claim = self.adopt_b()?;
        let authority = self.completion_authority(MJobId::JobB, &claim)?;
        let command = Command::LifecycleHandle {
            authority: types::AuthorityInput {
                job: MJobId::JobB,
                node: authority.node,
                revision: authority.revision,
                generation: authority.generation,
                fence: authority.fence,
                token: authority.token,
                lease_until: authority.lease_until,
                operation: authority.operation,
            },
            handler: HandlerResult::Permanent,
        };
        let result = crate::test_helper::block_on(self.system_a.apply_outcome(
            claim,
            JobOutcome::DeadLetter {
                code: crate::OutcomeCode::try_new("permanent")?,
            },
            self.now_timestamp(),
        ))?;
        if !matches!(result, crate::OutcomeResult::DeadLettered { .. }) {
            return Err(std::io::Error::other("permanent handler did not dead-letter").into());
        }
        self.finish(
            command,
            ResultClass::AppliedClass,
            StoreResult::Committed,
            LifecycleOutcome::PermanentDeadLetter,
            CompletionDetail::NoCompletionDetail,
            EnqueueDisposition::NotEnqueue,
            MJobId::JobB,
            MOperationId::OperationA,
        );
        Ok(())
    }

    fn redrive_b(
        &mut self,
        expected_revision: i64,
        expected_operation: MOperationId,
        reuse: bool,
    ) -> Result<()> {
        let command = Command::LifecycleRedrive {
            job: MJobId::JobB,
            expected_revision,
            expected_operation,
            reuse_execution: reuse,
        };
        let current_operation = self.model_operation(MJobId::JobB);
        let public_operation = if expected_operation == current_operation {
            self.observed_operation_id(MJobId::JobB)?
        } else {
            operation(expected_operation)
        };
        let result = crate::test_helper::block_on(self.system_a.redrive_job(
            actual_job_id(MJobId::JobB),
            crate::RedriveRequest::new(
                u64::try_from(expected_revision.max(0)).unwrap_or(u64::MAX),
                public_operation,
                if reuse {
                    crate::RedriveExecution::ReuseExecutionId
                } else {
                    crate::RedriveExecution::NewExecutionId
                },
                self.now_timestamp(),
            ),
        ));
        match result {
            Ok(redrive) => {
                self.operation_labels
                    .insert(MJobId::JobB, next_model_operation(current_operation));
                // RedriveResult is the first public operation boundary that
                // exposes a rotated execution identity. Register it before
                // projecting the post-operation lifecycle state; reused
                // identities remain mapped to their existing label.
                self.reset_lease_token_labels(MJobId::JobB);
                self.normalize_execution_id(redrive.execution_id);
                if self.completion_job == MJobId::JobB {
                    self.completion_pending = false;
                    self.completion_authority_recorded = false;
                }
                self.completion_detail = CompletionDetail::NoCompletionDetail;
                self.completion_detail_job = MJobId::JobB;
                self.finish(
                    command,
                    ResultClass::AppliedClass,
                    StoreResult::Committed,
                    LifecycleOutcome::Redriven,
                    CompletionDetail::NoCompletionDetail,
                    EnqueueDisposition::NotEnqueue,
                    MJobId::JobB,
                    expected_operation,
                );
            }
            Err(error) => {
                let (class, store_result, outcome) = self.redrive_error_transition(
                    MJobId::JobB,
                    expected_revision,
                    expected_operation,
                    &error,
                )?;
                self.finish(
                    command,
                    class,
                    store_result,
                    outcome,
                    CompletionDetail::NoCompletionDetail,
                    EnqueueDisposition::NotEnqueue,
                    MJobId::JobB,
                    expected_operation,
                );
            }
        }
        Ok(())
    }

    fn redrive_a(
        &mut self,
        expected_revision: i64,
        expected_operation: MOperationId,
    ) -> Result<()> {
        let command = Command::LifecycleRedrive {
            job: MJobId::JobA,
            expected_revision,
            expected_operation,
            reuse_execution: false,
        };
        let result = crate::test_helper::block_on(self.system_a.redrive_job(
            actual_job_id(MJobId::JobA),
            crate::RedriveRequest::new(
                u64::try_from(expected_revision.max(0)).unwrap_or(u64::MAX),
                operation(expected_operation),
                crate::RedriveExecution::NewExecutionId,
                self.now_timestamp(),
            ),
        ));
        let (class, store_result, outcome) = match result {
            Ok(_) => {
                return Err(std::io::Error::other(
                    "non-dead-letter redrive unexpectedly committed",
                )
                .into());
            }
            Err(error) => self.redrive_error_transition(
                MJobId::JobA,
                expected_revision,
                expected_operation,
                &error,
            )?,
        };
        self.finish(
            command,
            class,
            store_result,
            outcome,
            CompletionDetail::NoCompletionDetail,
            EnqueueDisposition::NotEnqueue,
            MJobId::JobA,
            expected_operation,
        );
        Ok(())
    }

    fn advance(&mut self, amount: i64) -> Result<()> {
        self.now = self.now.saturating_add(amount.max(0));
        self.finish(
            Command::LifecycleAdvance { amount },
            ResultClass::AppliedClass,
            StoreResult::Committed,
            LifecycleOutcome::TimeAdvanced,
            CompletionDetail::NoCompletionDetail,
            EnqueueDisposition::NotEnqueue,
            MJobId::JobA,
            MOperationId::OperationA,
        );
        Ok(())
    }

    fn fixed_retry_reclaim(&mut self) -> Result<()> {
        let current = self.project_jobs()?[&MJobId::JobB].clone();
        if current.state == MJobState::Leased {
            let claim = self
                .claims
                .get(&MJobId::JobB)
                .ok_or_else(|| std::io::Error::other("handler retry fixed trace claim missing"))?;
            let authority = self.completion_authority(MJobId::JobB, claim)?;
            return self.apply_dynamic(Command::LifecycleHandle {
                authority: types::AuthorityInput {
                    job: MJobId::JobB,
                    node: authority.node,
                    revision: authority.revision,
                    generation: authority.generation,
                    fence: authority.fence,
                    token: authority.token,
                    lease_until: authority.lease_until,
                    operation: authority.operation,
                },
                handler: HandlerResult::Transient,
            });
        }
        if current.state == MJobState::RetryWaiting && current.due_at > self.now {
            return self.advance(current.due_at - self.now);
        }
        if self.command_family() == "LifecycleAdvance" {
            return self.apply_dynamic(Command::LifecycleSelectClaim {
                job: MJobId::JobB,
                reader: Node::NodeA,
                revision: current.revision,
            });
        }
        if self.command_family() == "LifecycleSelectClaim" {
            return self.apply_dynamic(Command::LifecycleClaim {
                job: MJobId::JobB,
                contender: Node::NodeA,
                revision: current.revision,
            });
        }
        self.advance(0)
    }

    fn fixed_expiry_reclaim(&mut self) -> Result<()> {
        let current = self.project_jobs()?[&MJobId::JobB].clone();
        if current.state == MJobState::Leased && current.lease_until > self.now {
            return self.advance(current.lease_until - self.now);
        }
        if self.command_family() == "LifecycleAdvance" && current.state == MJobState::Leased {
            return self.apply_dynamic(Command::LifecycleExpire {
                job: MJobId::JobB,
                lease: true,
            });
        }
        if current.state == MJobState::RetryWaiting
            && self.command_family() != "LifecycleSelectClaim"
        {
            return self.apply_dynamic(Command::LifecycleSelectClaim {
                job: MJobId::JobB,
                reader: Node::NodeA,
                revision: current.revision,
            });
        }
        if self.command_family() == "LifecycleSelectClaim" {
            return self.apply_dynamic(Command::LifecycleClaim {
                job: MJobId::JobB,
                contender: Node::NodeA,
                revision: current.revision,
            });
        }
        self.advance(0)
    }

    fn command_family(&self) -> &'static str {
        command_family(&self.command)
    }

    fn fixed_cancellation_expiry(&mut self) -> Result<()> {
        let current = self.project_jobs()?[&MJobId::JobB].clone();
        if current.state == MJobState::Leased && !current.cancel_requested {
            return self.apply_dynamic(Command::LifecycleCancel {
                authority: types::AuthorityInput {
                    job: MJobId::JobB,
                    node: current.node,
                    revision: current.revision,
                    generation: current.generation,
                    fence: current.fence,
                    token: current.token,
                    lease_until: current.lease_until,
                    operation: current.operation_id,
                },
                phase: types::CancelPhase::RequestLeased,
            });
        }
        self.claims.remove(&MJobId::JobB);
        if current.state == MJobState::Leased && current.lease_until > self.now {
            return self.advance(current.lease_until - self.now);
        }
        if current.state == MJobState::Leased {
            return self.apply_dynamic(Command::LifecycleExpire {
                job: MJobId::JobB,
                lease: true,
            });
        }
        self.advance(0)
    }

    fn apply_fixed(&mut self, action: &str) -> Result<()> {
        match action {
            "fixedZeroAdvanceTrace" | "fixedZeroAdvance" => self.advance(0),
            "fixedConflictTrace" | "fixedConflictCommand" => self.complete_conflict(),
            "fixedUnknownTrace" | "fixedUnknownCommand" => self.unknown_before(),
            "fixedUnknownAfterTrace" | "fixedUnknownAfterCommand" => self.unknown_after(),
            "fixedLifecycleRetryReclaimTrace" | "fixedLifecycleRetryReclaimChain" => {
                self.fixed_retry_reclaim()
            }
            "fixedLifecycleExpiryReclaimTrace" | "fixedLifecycleExpiryReclaimChain" => {
                self.fixed_expiry_reclaim()
            }
            "fixedCancellationExpiryTrace" | "fixedCancellationExpiryChain" => {
                self.fixed_cancellation_expiry()
            }
            "fixedUnknownReconcileTrace" | "fixedUnknownReconcileChain" => {
                if self.unknown_pending {
                    self.apply_dynamic(Command::LifecycleReconcile {
                        job: self.unknown_job,
                        operation: self.unknown_operation,
                        observed: self.unknown_readback,
                    })
                } else {
                    let claim = self.claims.get(&MJobId::JobB).ok_or_else(|| {
                        std::io::Error::other("unknown-before fixed trace claim missing")
                    })?;
                    let authority = self.completion_authority(MJobId::JobB, claim)?;
                    self.apply_dynamic(Command::LifecycleUnknown {
                        authority: types::AuthorityInput {
                            job: MJobId::JobB,
                            node: authority.node,
                            revision: authority.revision,
                            generation: authority.generation,
                            fence: authority.fence,
                            token: authority.token,
                            lease_until: authority.lease_until,
                            operation: authority.operation,
                        },
                        committed: false,
                    })
                }
            }
            "fixedScopedRepairTrace" | "fixedScopedRepair" => {
                if self.project_jobs()?[&MJobId::JobA].record == RecordKind::Valid {
                    self.corrupt(MJobId::JobA, RecordKind::Corrupt)
                } else if !self.unknown_pending {
                    self.unknown_before()
                } else {
                    let revision = self.project_jobs()?[&MJobId::JobA].revision;
                    self.repair(MJobId::JobA, revision, MOperationId::OperationA)
                }
            }
            "fixedQuarantinedRepairTrace" | "fixedQuarantinedRepair" => {
                if self.project_jobs()?[&MJobId::JobC].state == MJobState::Absent {
                    self.apply_dynamic(Command::LifecycleEnqueue {
                        job: MJobId::JobC,
                        due_at: self.now,
                        operation: MOperationId::OperationA,
                        with_dedupe: false,
                        fingerprint: 3,
                    })
                } else if !self.is_unknown_version(MJobId::JobC)? {
                    self.corrupt(MJobId::JobC, RecordKind::UnknownVersion)
                } else {
                    let revision = self.project_jobs()?[&MJobId::JobC].revision;
                    self.repair(MJobId::JobC, revision, MOperationId::OperationA)
                }
            }
            "fixedStaleRepairTrace" | "fixedStaleRepair" => {
                if self.project_jobs()?[&MJobId::JobC].state == MJobState::Absent {
                    self.apply_dynamic(Command::LifecycleEnqueue {
                        job: MJobId::JobC,
                        due_at: self.now,
                        operation: MOperationId::OperationA,
                        with_dedupe: false,
                        fingerprint: 3,
                    })
                } else if self.project_jobs()?[&MJobId::JobC].record == RecordKind::Valid {
                    self.corrupt(MJobId::JobC, RecordKind::Corrupt)
                } else {
                    let revision = self.project_jobs()?[&MJobId::JobC].revision;
                    self.repair(
                        MJobId::JobC,
                        revision.saturating_sub(1),
                        MOperationId::OperationA,
                    )
                }
            }
            "fixedLifecycleRedriveTrace" | "fixedLifecycleRedriveChain" => {
                let current = self.project_jobs()?[&MJobId::JobB].clone();
                if current.state == MJobState::Leased {
                    self.handle_permanent()
                } else {
                    self.redrive_b(current.revision, current.operation_id, false)
                }
            }
            "fixedLifecycleStaleRedriveTrace" | "fixedLifecycleStaleRedriveChain" => {
                if self.project_jobs()?[&MJobId::JobB].state == MJobState::Leased {
                    self.handle_permanent()
                } else {
                    self.redrive_b(1, MOperationId::OperationA, false)
                }
            }
            "fixedLifecycleWrongOperationRedriveTrace"
            | "fixedLifecycleWrongOperationRedriveChain" => {
                if self.project_jobs()?[&MJobId::JobB].state == MJobState::Leased {
                    self.handle_permanent()
                } else {
                    self.redrive_b(2, MOperationId::OperationB, false)
                }
            }
            "fixedLifecycleDuplicateRedriveTrace" | "fixedLifecycleDuplicateRedriveChain" => {
                let current = self.project_jobs()?[&MJobId::JobB].clone();
                match current.state {
                    MJobState::Leased => self.handle_permanent(),
                    MJobState::DeadLettered => {
                        self.redrive_b(current.revision, current.operation_id, false)
                    }
                    _ => self.redrive_b(
                        current.revision.saturating_sub(1),
                        current.operation_id,
                        false,
                    ),
                }
            }
            "fixedLifecycleNonterminalRedriveTrace" => {
                let current = self.project_jobs()?[&MJobId::JobA].clone();
                self.redrive_a(current.revision, current.operation_id)
            }
            "fixedLifecycleQuarantinedRedriveTrace" | "fixedLifecycleQuarantinedRedriveChain" => {
                if !self.is_unknown_version(MJobId::JobA)? {
                    self.corrupt(MJobId::JobA, RecordKind::UnknownVersion)
                } else {
                    let revision = self.project_jobs()?[&MJobId::JobA].revision;
                    self.redrive_a(revision, MOperationId::OperationA)
                }
            }
            "fixedLifecycleCorruptRedriveTrace" | "fixedLifecycleCorruptRedriveChain" => {
                if self.project_jobs()?[&MJobId::JobA].record == RecordKind::Valid {
                    self.corrupt(MJobId::JobA, RecordKind::Corrupt)
                } else {
                    self.redrive_a(2, MOperationId::OperationA)
                }
            }
            "mbtObserve" => Ok(()),
            action => Err(std::io::Error::other(format!(
                "lifecycle action not implemented: {action}"
            ))
            .into()),
        }
    }
}

fn parse_command(input: &str) -> Result<Command> {
    let value = parse_rendered(input)?;
    let RenderedValue::Variant(name, payload) = value else {
        return Err(std::io::Error::other("serialized lifecycle command is not a variant").into());
    };
    match name.as_str() {
        "LifecycleEnqueue" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleEnqueue {
                job: job_id(field(fields, "job")?)?,
                due_at: integer(field(fields, "dueAt")?)?,
                operation: operation_id(field(fields, "operation")?)?,
                with_dedupe: boolean(field(fields, "withDedupe")?)?,
                fingerprint: integer(field(fields, "fingerprint")?)?,
            })
        }
        "LifecycleSelectClaim" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleSelectClaim {
                job: job_id(field(fields, "job")?)?,
                reader: node(field(fields, "reader")?)?,
                revision: integer(field(fields, "revision")?)?,
            })
        }
        "LifecycleClaim" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleClaim {
                job: job_id(field(fields, "job")?)?,
                contender: node(field(fields, "contender")?)?,
                revision: integer(field(fields, "revision")?)?,
            })
        }
        "LifecycleRenew" | "LifecycleComplete" => {
            let authority = authority(&payload)?;
            if name == "LifecycleRenew" {
                Ok(Command::LifecycleRenew(authority))
            } else {
                Ok(Command::LifecycleComplete(authority))
            }
        }
        "LifecycleCheckpoint" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleCheckpoint {
                authority: authority(field(fields, "authority")?)?,
                bytes: integer(field(fields, "bytes")?)?,
            })
        }
        "LifecycleHandle" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleHandle {
                authority: authority(field(fields, "authority")?)?,
                handler: handler(field(fields, "handler")?)?,
            })
        }
        "LifecycleExpose" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleExpose {
                job: job_id(field(fields, "job")?)?,
                operation: operation_id(field(fields, "operation")?)?,
                revision: integer(field(fields, "revision")?)?,
                generation: integer(field(fields, "generation")?)?,
            })
        }
        "LifecycleCancel" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleCancel {
                authority: authority(field(fields, "authority")?)?,
                phase: cancel_phase(field(fields, "phase")?)?,
            })
        }
        "LifecycleAdvance" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleAdvance {
                amount: integer(field(fields, "amount")?)?,
            })
        }
        "LifecycleExpire" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleExpire {
                job: job_id(field(fields, "job")?)?,
                lease: boolean(field(fields, "lease")?)?,
            })
        }
        "LifecycleUnknown" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleUnknown {
                authority: authority(field(fields, "authority")?)?,
                committed: boolean(field(fields, "committed")?)?,
            })
        }
        "LifecycleReconcile" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleReconcile {
                job: job_id(field(fields, "job")?)?,
                operation: operation_id(field(fields, "operation")?)?,
                observed: store_result(field(fields, "observed")?)?,
            })
        }
        "LifecycleCorrupt" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleCorrupt {
                job: job_id(field(fields, "job")?)?,
                kind: record_kind(field(fields, "kind")?)?,
            })
        }
        "LifecycleRepair" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleRepair {
                job: job_id(field(fields, "job")?)?,
                revision: integer(field(fields, "revision")?)?,
                operation: operation_id(field(fields, "operation")?)?,
            })
        }
        "LifecycleRedrive" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::LifecycleRedrive {
                job: job_id(field(fields, "job")?)?,
                expected_revision: integer(field(fields, "expectedRevision")?)?,
                expected_operation: operation_id(field(fields, "expectedOperation")?)?,
                reuse_execution: boolean(field(fields, "reuseExecution")?)?,
            })
        }
        other => Err(std::io::Error::other(format!(
            "unsupported serialized lifecycle command {other}"
        ))
        .into()),
    }
}

fn record_fields<'a>(
    value: &'a RenderedValue,
    name: &str,
) -> Result<&'a BTreeMap<String, RenderedValue>> {
    match value {
        RenderedValue::Record(fields) => Ok(fields),
        _ => Err(std::io::Error::other(format!(
            "lifecycle command {name} does not contain a record payload"
        ))
        .into()),
    }
}

fn field<'a>(fields: &'a BTreeMap<String, RenderedValue>, name: &str) -> Result<&'a RenderedValue> {
    fields.get(name).ok_or_else(|| {
        std::io::Error::other(format!("serialized lifecycle command is missing {name}")).into()
    })
}

fn integer(value: &RenderedValue) -> Result<i64> {
    match value {
        RenderedValue::Integer(value) => Ok(*value),
        _ => {
            Err(std::io::Error::other(format!("expected lifecycle integer, got {value:?}")).into())
        }
    }
}

fn boolean(value: &RenderedValue) -> Result<bool> {
    match value {
        RenderedValue::Bool(value) => Ok(*value),
        _ => {
            Err(std::io::Error::other(format!("expected lifecycle boolean, got {value:?}")).into())
        }
    }
}

fn node(value: &RenderedValue) -> Result<Node> {
    if matches!(value, RenderedValue::Atom(value) if value == "NodeA") {
        Ok(Node::NodeA)
    } else if matches!(value, RenderedValue::Atom(value) if value == "NodeB") {
        Ok(Node::NodeB)
    } else {
        Err(std::io::Error::other(format!("expected lifecycle node, got {value:?}")).into())
    }
}

fn job_id(value: &RenderedValue) -> Result<MJobId> {
    for (name, job) in [
        ("JobA", MJobId::JobA),
        ("JobB", MJobId::JobB),
        ("JobC", MJobId::JobC),
    ] {
        if matches!(value, RenderedValue::Atom(actual) if actual == name) {
            return Ok(job);
        }
    }
    Err(std::io::Error::other(format!("expected lifecycle job, got {value:?}")).into())
}

fn operation_id(value: &RenderedValue) -> Result<MOperationId> {
    for (name, operation) in [
        ("OperationA", MOperationId::OperationA),
        ("OperationB", MOperationId::OperationB),
        ("OperationC", MOperationId::OperationC),
        ("OperationD", MOperationId::OperationD),
    ] {
        if matches!(value, RenderedValue::Atom(actual) if actual == name) {
            return Ok(operation);
        }
    }
    Err(std::io::Error::other(format!("expected lifecycle operation, got {value:?}")).into())
}

fn handler(value: &RenderedValue) -> Result<HandlerResult> {
    for (name, handler) in [
        ("Success", HandlerResult::Success),
        ("Transient", HandlerResult::Transient),
        ("Throttled", HandlerResult::Throttled),
        ("Permanent", HandlerResult::Permanent),
        ("Ambiguous", HandlerResult::Ambiguous),
    ] {
        if matches!(value, RenderedValue::Atom(actual) if actual == name) {
            return Ok(handler);
        }
    }
    Err(std::io::Error::other(format!("expected lifecycle handler, got {value:?}")).into())
}

fn cancel_phase(value: &RenderedValue) -> Result<types::CancelPhase> {
    for (name, phase) in [
        ("CancelScheduled", types::CancelPhase::CancelScheduled),
        ("RequestLeased", types::CancelPhase::RequestLeased),
        ("CommitLeased", types::CancelPhase::CommitLeased),
    ] {
        if matches!(value, RenderedValue::Atom(actual) if actual == name) {
            return Ok(phase);
        }
    }
    Err(std::io::Error::other(format!("expected lifecycle cancel phase, got {value:?}")).into())
}

fn store_result(value: &RenderedValue) -> Result<StoreResult> {
    for (name, result) in [
        ("Committed", StoreResult::Committed),
        ("Conflict", StoreResult::Conflict),
        ("AuthorityChanged", StoreResult::AuthorityChanged),
        ("Unknown", StoreResult::Unknown),
        ("Rejected", StoreResult::Rejected),
    ] {
        if matches!(value, RenderedValue::Atom(actual) if actual == name) {
            return Ok(result);
        }
    }
    Err(std::io::Error::other(format!("expected lifecycle store result, got {value:?}")).into())
}

fn routes_match_state(
    state: &crate::model::JobState,
    routes: crate::model::LifecycleRoutes,
) -> bool {
    match state {
        crate::model::JobState::Scheduled => {
            routes.due && routes.fair && routes.wake && !routes.lease
        }
        crate::model::JobState::Leased(_) => {
            routes.lease && !routes.due && !routes.fair && !routes.wake
        }
        crate::model::JobState::DeadLettered
        | crate::model::JobState::Cancelled
        | crate::model::JobState::Suspended => {
            !routes.due && !routes.lease && !routes.fair && !routes.wake
        }
    }
}

fn record_kind(value: &RenderedValue) -> Result<RecordKind> {
    for (name, kind) in [
        ("Valid", RecordKind::Valid),
        ("Missing", RecordKind::Missing),
        ("Corrupt", RecordKind::Corrupt),
        ("UnknownVersion", RecordKind::UnknownVersion),
    ] {
        if matches!(value, RenderedValue::Atom(actual) if actual == name) {
            return Ok(kind);
        }
    }
    Err(std::io::Error::other(format!("expected lifecycle record kind, got {value:?}")).into())
}

fn authority(value: &RenderedValue) -> Result<types::AuthorityInput> {
    let fields = record_fields(value, "authority")?;
    Ok(types::AuthorityInput {
        job: job_id(field(fields, "job")?)?,
        node: node(field(fields, "node")?)?,
        revision: integer(field(fields, "revision")?)?,
        generation: integer(field(fields, "generation")?)?,
        fence: integer(field(fields, "fence")?)?,
        token: integer(field(fields, "token")?)?,
        lease_until: integer(field(fields, "leaseUntil")?)?,
        operation: operation_id(field(fields, "operation")?)?,
    })
}

impl Driver for LifecycleDriver {
    type State = StateProjection;

    fn step(&mut self, step: &Step) -> Result {
        match step.action_taken.as_str() {
            "mbtInit" => self.reset_for_trace(),
            "mbtObserve" => Ok(()),
            "fixedCommandCoverageTrace" | "fixedCommandCoverageChain" => {
                let command = self.command_from_step(step)?;
                let command_debug = format!("{command:?}");
                self.apply_dynamic(command).map_err(|error| {
                    std::io::Error::other(format!(
                        "lifecycle command {command_debug} failed: {error}"
                    ))
                    .into()
                })
            }
            "mbtNondetStep" | "mbtStep" => {
                let command = match step.nondet_picks.get("command") {
                    Some(value) => Command::deserialize(value.clone())?,
                    None => self.command_from_step(step)?,
                };
                let command_debug = format!("{command:?}");
                self.apply_dynamic(command).map_err(|error| {
                    std::io::Error::other(format!(
                        "lifecycle command {command_debug} failed: {error}"
                    ))
                    .into()
                })
            }
            action => self.apply_fixed(action),
        }
    }
}

impl Drop for LifecycleDriver {
    fn drop(&mut self) {
        if self.require_command_coverage && self.require_complete_command_coverage {
            let missing = ALL_COMMAND_FAMILIES
                .into_iter()
                .filter(|family| !self.command_counts.contains_key(family))
                .collect::<Vec<_>>();
            if !missing.is_empty() && !std::thread::panicking() {
                panic!("lifecycle command coverage trace missed command families: {missing:?}");
            }
        }
    }
}

fn command_family(command: &Command) -> &'static str {
    match command {
        Command::LifecycleEnqueue { .. } => "LifecycleEnqueue",
        Command::LifecycleSelectClaim { .. } => "LifecycleSelectClaim",
        Command::LifecycleClaim { .. } => "LifecycleClaim",
        Command::LifecycleRenew(_) => "LifecycleRenew",
        Command::LifecycleCheckpoint { .. } => "LifecycleCheckpoint",
        Command::LifecycleHandle { .. } => "LifecycleHandle",
        Command::LifecycleComplete(_) => "LifecycleComplete",
        Command::LifecycleExpose { .. } => "LifecycleExpose",
        Command::LifecycleCancel { .. } => "LifecycleCancel",
        Command::LifecycleAdvance { .. } => "LifecycleAdvance",
        Command::LifecycleExpire { .. } => "LifecycleExpire",
        Command::LifecycleUnknown { .. } => "LifecycleUnknown",
        Command::LifecycleReconcile { .. } => "LifecycleReconcile",
        Command::LifecycleCorrupt { .. } => "LifecycleCorrupt",
        Command::LifecycleRepair { .. } => "LifecycleRepair",
        Command::LifecycleRedrive { .. } => "LifecycleRedrive",
    }
}

fn test_system(store: FakeStore, owner: u8) -> Result<JobSystem<FakeStore>> {
    let mut registry = HandlerRegistry::new();
    registry.register(HandlerDefinition {
        kind: JobKind::try_new("email")?,
        schema_version: NonZeroU16::MIN,
        queue: crate::QueueName::try_new("default")?,
        effect_mode: crate::EffectMode::Idempotent,
        cost_units: NonZeroU16::MIN,
        fairness_policy: crate::FairnessPolicy::low_volume(),
        default_retry: RetrySelection::Custom(retry_policy()?),
        default_timeout: Duration::from_secs(3),
        handler: CompletingHandler,
    })?;
    Ok(JobSystem::new(
        store,
        crate::JobCatalog::from_registry(registry),
        Namespace::try_new(b"jobs")?,
        OwnerId::from([owner; 16]),
        crate::test_helper::wake_scheduler(),
    ))
}

fn retry_policy() -> Result<RetryPolicy> {
    Ok(RetryPolicy::try_from(RetryPolicyInput {
        maximum_attempts: NonZeroU16::new(3).ok_or_else(|| std::io::Error::other("attempts"))?,
        maximum_age: Duration::from_secs(12),
        minimum_backoff: Duration::from_secs(1),
        maximum_backoff: Duration::from_secs(1),
        multiplier: BackoffMultiplier::try_from(1)?,
    })?)
}

fn seed_fixture(store: &FakeStore) -> Result<()> {
    let namespace = Namespace::try_new(b"jobs")?;
    let queue = crate::QueueName::try_new("default")?;
    let kind = JobKind::try_new("email")?;
    let policy = JobPolicySnapshot {
        effect_mode: crate::EffectMode::Idempotent,
        cost_units: NonZeroU16::MIN,
        execution_timeout: Some(Duration::from_secs(3)),
        retry_policy: retry_policy()?,
    };
    let a = fixture_record(FixtureRecordInput {
        job_id: JobId::from([1; 16]),
        namespace: namespace.clone(),
        queue: queue.clone(),
        kind: kind.clone(),
        policy,
        state: JobState::Scheduled,
        execution: 2,
        revision: 1,
        checkpoint: None,
    })?;
    put_record(store, &namespace, &queue, &a, true)?;
    Ok(())
}

fn fixture_record(input: FixtureRecordInput) -> Result<JobRecordV1> {
    let FixtureRecordInput {
        job_id,
        namespace,
        queue,
        kind,
        policy,
        state,
        execution,
        revision,
        checkpoint,
    } = input;
    let payload_bytes = match job_id.as_bytes()[0] {
        1 => Bytes::from_static(b"a"),
        2 => Bytes::from_static(b"b"),
        _ => Bytes::new(),
    };
    let chunk_keys = if payload_bytes.is_empty() {
        Vec::new()
    } else {
        vec![crate::keys::payload_key(&namespace, &job_id, 0)?]
    };
    let digest: [u8; 32] = if payload_bytes.is_empty() {
        [0; 32]
    } else {
        sha2::Sha256::digest(&payload_bytes).into()
    };
    Ok(JobRecordV1 {
        job_id,
        namespace,
        queue,
        kind,
        schema_version: NonZeroU16::MIN,
        generation: if matches!(state, JobState::Leased(_)) {
            1
        } else {
            0
        },
        execution_id: ExecutionId::from([execution; 16]),
        payload: PayloadManifest::try_new(payload_bytes.len() as u32, digest, chunk_keys)?,
        fairness: FairnessClass::LowVolume,
        ordering_key: None,
        priority: Priority::Default,
        created_at: Timestamp::ZERO,
        scheduled_at: Timestamp::ZERO,
        expires_at: Some(Timestamp::from_millis(12_000)),
        policy,
        attempts: NonZeroU32::new(if matches!(state, JobState::Leased(_)) {
            1
        } else {
            0
        })
        .map(|attempts| AttemptHistory {
            attempts,
            first_attempt_at: Timestamp::ZERO,
            last_attempt_at: Timestamp::ZERO,
            last_outcome: None,
        }),
        state,
        checkpoint,
        retention_deadline: Timestamp::from_millis(12_000),
        deduplication: None,
        revision,
    })
}

fn put_record(
    store: &FakeStore,
    namespace: &Namespace,
    queue: &crate::QueueName,
    record: &JobRecordV1,
    scheduled: bool,
) -> Result<()> {
    store.put_raw(
        crate::keys::job_key(namespace, &record.job_id)?,
        encode_job_record(record)?,
    )?;
    let operation = operation(MOperationId::OperationA);
    let fence_high_water = match &record.state {
        JobState::Leased(lease) => lease.fence.get(),
        _ => 0,
    };
    store.put_raw(
        crate::keys::operation_key(namespace, &record.job_id)?,
        crate::keys::operation_value(&record.job_id, &operation, fence_high_water)?,
    )?;
    for key in &record.payload.chunk_keys {
        let body = if record.job_id.as_bytes()[0] == 1 {
            b"a"
        } else {
            b"b"
        };
        store.put_raw(
            key.clone(),
            ValueCodec::encode(ValueTag::PayloadChunk, body)?,
        )?;
    }
    if scheduled {
        store.put_raw(
            crate::keys::due_key(namespace, queue, record.scheduled_at, &record.job_id)?,
            crate::keys::due_value(record.scheduled_at)?,
        )?;
        store.put_raw(
            crate::keys::fair_key(namespace, queue, &record.job_id)?,
            crate::keys::fair_value(&record.job_id)?,
        )?;
        store.put_raw(
            crate::keys::wake_key(namespace, queue)?,
            crate::keys::wake_value(record.scheduled_at)?,
        )?;
    }
    if let JobState::Leased(_) = &record.state {
        store.put_raw(
            crate::keys::lease_key(namespace, &record.queue, &record.job_id)?,
            crate::keys::lease_value(&record.job_id)?,
        )?;
    }
    Ok(())
}

fn initial_transition(command: Command) -> LastTransition {
    LastTransition {
        command,
        class: ResultClass::AppliedClass,
        result: StoreResult::Committed,
        outcome: LifecycleOutcome::Initialised,
        detail: CompletionDetail::NoCompletionDetail,
        enqueue: EnqueueDisposition::NotEnqueue,
        job: MJobId::JobA,
        operation: MOperationId::OperationA,
    }
}

fn operation(operation: MOperationId) -> OperationId {
    OperationId::from(
        [match operation {
            MOperationId::OperationA => 1,
            MOperationId::OperationB => 2,
            MOperationId::OperationC => 3,
            MOperationId::OperationD => 4,
        }; 16],
    )
}

fn next_model_operation(operation: MOperationId) -> MOperationId {
    match operation {
        MOperationId::OperationA => MOperationId::OperationB,
        MOperationId::OperationB => MOperationId::OperationC,
        MOperationId::OperationC => MOperationId::OperationD,
        MOperationId::OperationD => MOperationId::OperationA,
    }
}

fn actual_job_id(job: MJobId) -> JobId {
    JobId::from(
        [match job {
            MJobId::JobA => 1,
            MJobId::JobB => 2,
            MJobId::JobC => 3,
        }; 16],
    )
}

fn missing_job() -> Job {
    Job {
        state: MJobState::Absent,
        node: Node::NodeA,
        revision: 0,
        generation: 0,
        fence: 0,
        token: 0,
        lease_until: 0,
        due_at: 0,
        expires_at: 0,
        execution_id: 0,
        attempt_id: 0,
        attempts: 0,
        record: RecordKind::Missing,
        payload: false,
        due_route: false,
        lease_route: false,
        fair_route: false,
        wake_route: false,
        checkpoint_bytes: 0,
        failure_recorded: false,
        completion_receipt: false,
        cancel_requested: false,
        operation_id: MOperationId::OperationA,
        enqueue_fingerprint: 0,
    }
}

fn model_node(value: u8) -> Node {
    if value == 2 { Node::NodeB } else { Node::NodeA }
}

fn timestamp_tick(timestamp: Timestamp) -> i64 {
    timestamp.as_millis().div_euclid(1_000)
}
