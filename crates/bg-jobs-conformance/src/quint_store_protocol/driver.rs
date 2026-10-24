use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU32, NonZeroU64},
};

use bg_jobs::{
    ExecutionId, Namespace, QueueName, Timestamp,
    store::{
        Check, CommitOperationId, CommitOutcome, JobStore, Mutation, StoreKey, StoreTransaction,
        StoreTransactionInput, TransactionLimits,
    },
    test_support::{
        FakeStore,
        codec::{KeyCodec, KeyTag, ValueCodec, ValueTag, encode_job_record},
        raw::{AttemptHistory, Lease},
    },
};
use quint_connect::{Driver, Result, State, Step};
use quint_rendered_parser::{RenderedValue, parse as parse_rendered};
use types::{
    AuthorityInput, Command, CommandResult, CompletionDetail, EnqueueDisposition, HandlerResult,
    JobId, JobState, LastTransition, Meta, Node, OperationId, Record, RecordKind, ResourceInput,
    ResultClass, StateProjection, StoreOutcome, StoreResult,
};

use super::{
    constants::{
        ALL_COMMAND_FAMILIES, MAX_CHECKPOINT_BYTES, MAX_CHUNK_BYTES, MAX_COMPLETION_RECEIPTS,
        MAX_DIGEST_BYTES, MAX_INLINE_PAYLOAD_BYTES, MAX_MANIFEST_BYTES,
    },
    persist, types,
};

/// Non-authoritative observation state for the connector test harness. Durable
/// lifecycle, route, fault, claim, and reconciliation state is always read
/// from `FakeStore`; this state only records the logical test clock and the
/// result metadata exposed by the model's observation surface.
#[derive(Clone, Debug)]
struct TraceState {
    now: i64,
    quarantine_attempts: i64,
    last_enqueue_disposition: EnqueueDisposition,
    last_result: StoreResult,
    last_outcome: StoreOutcome,
    transaction_checks: i64,
    transaction_mutations: i64,
    transaction_bytes: i64,
    repair_steps: i64,
    unrelated_progress: i64,
    completion_receipts: i64,
    completion_detail: CompletionDetail,
    last_detail: CompletionDetail,
    completion_detail_job: JobId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
enum PayloadChange {
    #[default]
    Keep,
    Write(i64),
    Delete,
}

#[derive(Clone, Debug, Default)]
struct StateChange {
    payload: PayloadChange,
    unknown: Option<Option<persist::UnknownState>>,
    claim: Option<Option<persist::ClaimState>>,
}

impl State<StoreProtocolDriver> for StateProjection {
    fn from_driver(driver: &StoreProtocolDriver) -> Result<Self> {
        driver.projection()
    }
}

/// Store-protocol connector backed by the public `FakeStore` contract.
///
/// The driver has no model-record shadow map. It persists a versioned
/// connector receipt beside each real `JobRecordV1`, then decodes the receipt,
/// job value, and route value on every projection. The small in-memory `Meta`
/// value is operation-result evidence (unknown readback, claim selection, and
/// completion detail) rather than an alternate record reducer.
#[derive(Clone)]
pub(super) struct StoreProtocolDriver {
    pub(super) store: FakeStore,
    pub(super) namespace: Namespace,
    queue: QueueName,
    trace: TraceState,
    command: Command,
    transition: LastTransition,
    result: CommandResult,
    covered_commands: BTreeSet<&'static str>,
    command_counts: BTreeMap<&'static str, usize>,
    require_command_coverage: bool,
}

impl Default for StoreProtocolDriver {
    fn default() -> Self {
        Self::try_default().unwrap_or_else(|error| panic!("store connector setup: {error}"))
    }
}

impl StoreProtocolDriver {
    pub(super) fn try_default() -> Result<Self> {
        let namespace = Namespace::try_new(b"quint-store-protocol")?;
        let queue = QueueName::try_new("default")?;
        let store = FakeStore::distributed();
        let initial = initial_records();
        persist::write_initial(&store, &namespace, &queue, &initial)
            .map_err(std::io::Error::other)?;
        let trace = initial_trace();
        let command = advance_command(0);
        let transition = initial_transition(command.clone());
        Ok(Self {
            store,
            namespace,
            queue,
            trace,
            command,
            transition: transition.clone(),
            result: CommandResult::StoreApplied(transition),
            covered_commands: BTreeSet::new(),
            command_counts: BTreeMap::new(),
            require_command_coverage: false,
        })
    }

    pub(super) fn for_command_coverage() -> Self {
        let mut driver =
            Self::try_default().unwrap_or_else(|error| panic!("store connector setup: {error}"));
        driver.require_command_coverage = true;
        driver
    }

    fn reset_for_trace(&mut self) -> Result<()> {
        let fresh = Self::try_default()?;
        self.store = fresh.store.clone();
        self.namespace = fresh.namespace.clone();
        self.queue = fresh.queue.clone();
        self.trace = fresh.trace.clone();
        self.command = fresh.command.clone();
        self.transition = fresh.transition.clone();
        self.result = fresh.result.clone();
        Ok(())
    }

    pub(super) fn projection(&self) -> Result<StateProjection> {
        let records = self.project_records()?;
        let meta = self.derived_meta(&records)?;
        Ok(StateProjection {
            records,
            meta,
            command: self.command.clone(),
            transition: self.transition.clone(),
            result: self.result.clone(),
        })
    }

    fn derived_meta(&self, records: &BTreeMap<JobId, Record>) -> Result<Meta> {
        let unknown =
            persist::read_unknown(&self.store, &self.namespace).map_err(std::io::Error::other)?;
        let claim =
            persist::read_claim(&self.store, &self.namespace).map_err(std::io::Error::other)?;
        let unknown_version_jobs = self.unknown_versions()?;
        let committed_terminal_jobs = self.committed_terminal_jobs(records)?;
        let quarantine_snapshot = unknown_version_jobs
            .iter()
            .filter_map(|job| records.get(job).cloned().map(|record| (*job, record)))
            .collect();
        let (
            unknown_job,
            unknown_operation,
            unknown_node,
            unknown_revision,
            unknown_generation,
            unknown_fence,
            unknown_token,
            unknown_lease_until,
            unknown_readback,
        ) = unknown.map_or(
            (
                JobId::JobA,
                OperationId::OperationA,
                Node::NodeA,
                0,
                0,
                0,
                0,
                0,
                StoreResult::Rejected,
            ),
            |value| {
                (
                    value.job,
                    value.operation,
                    value.node,
                    value.revision,
                    value.generation,
                    value.fence,
                    value.token,
                    value.lease_until,
                    value.readback,
                )
            },
        );
        let (claim_pending, claim_job, claim_revision, claim_reader) = claim
            .map_or((false, JobId::JobA, 1, Node::NodeA), |value| {
                (true, value.job, value.revision, value.reader)
            });
        Ok(Meta {
            wake_watermark: records.values().any(|record| {
                record.exists
                    && record.kind == RecordKind::Valid
                    && (record.due_route
                        || record.fair_route
                        || record.lease_route
                        || record.wake_route)
            }),
            now: self.trace.now,
            unknown_pending: unknown.is_some(),
            unknown_job,
            unknown_operation,
            unknown_node,
            unknown_revision,
            unknown_generation,
            unknown_fence,
            unknown_token,
            unknown_lease_until,
            unknown_readback,
            unknown_version_jobs,
            quarantine_snapshot,
            quarantine_attempts: self.trace.quarantine_attempts,
            last_enqueue_disposition: self.trace.last_enqueue_disposition,
            last_result: self.trace.last_result,
            last_outcome: self.trace.last_outcome,
            transaction_checks: self.trace.transaction_checks,
            transaction_mutations: self.trace.transaction_mutations,
            transaction_bytes: self.trace.transaction_bytes,
            repair_steps: self.trace.repair_steps,
            unrelated_progress: self.trace.unrelated_progress,
            completion_receipts: self.trace.completion_receipts,
            completion_detail: self.trace.completion_detail,
            last_detail: self.trace.last_detail,
            completion_detail_job: self.trace.completion_detail_job,
            committed_terminal_jobs,
            claim_pending,
            claim_job,
            claim_revision,
            claim_reader,
            last_authority_node: Node::NodeA,
            last_authority_revision: 0,
            last_authority_generation: 0,
            last_authority_fence: 0,
            last_authority_token: 0,
            last_authority_lease_until: 0,
            last_authority_operation: OperationId::OperationA,
        })
    }

    fn project_records(&self) -> Result<BTreeMap<JobId, Record>> {
        [JobId::JobA, JobId::JobB, JobId::JobC]
            .into_iter()
            .map(|job| Ok((job, self.project_record(job)?)))
            .collect()
    }

    fn committed_terminal_jobs(
        &self,
        records: &BTreeMap<JobId, Record>,
    ) -> Result<BTreeSet<JobId>> {
        let mut jobs = BTreeSet::new();
        for job in [JobId::JobA, JobId::JobB, JobId::JobC] {
            let terminal_receipt = persist::read_operation(&self.store, &self.namespace, &job)
                .map_err(std::io::Error::other)?
                .is_some_and(|operation| operation.terminal.is_some());
            let dead_lettered = records
                .get(&job)
                .is_some_and(|record| record.state == JobState::DeadLettered);
            if terminal_receipt || dead_lettered {
                jobs.insert(job);
            }
        }
        Ok(jobs)
    }

    fn project_record(&self, job: JobId) -> Result<Record> {
        let state = persist::StoredState::read(&self.store, &self.namespace, &job)
            .map_err(std::io::Error::other)?;
        let persist::StoredState {
            core,
            operation,
            route,
            fault,
            ..
        } = state;
        // Unknown schema markers block transitions but do not replace the
        // authoritative record projection; the live value remains decodable.
        let kind = fault.map_or(RecordKind::Valid, |fault| {
            if fault.kind == RecordKind::UnknownVersion {
                RecordKind::Valid
            } else {
                fault.kind
            }
        });
        let dangling = fault.is_some_and(|fault| fault.dangling);

        let Some(core) = core else {
            let terminal = operation.terminal;
            return Ok(Record {
                exists: false,
                state: JobState::Absent,
                kind,
                revision: terminal.map_or(0, |value| value.revision),
                node: terminal.map_or(Node::NodeA, |value| value.node),
                generation: terminal.map_or(0, |value| value.generation),
                fence: terminal.map_or(operation.fence_high_water, |value| value.fence),
                token: terminal.map_or(0, |value| value.token),
                leased: false,
                lease_until: terminal.map_or(0, |value| value.lease_until),
                expires_at: terminal.map_or(0, |value| value.expires_at),
                operation_id: operation.operation_id,
                enqueue_fingerprint: operation.enqueue_fingerprint,
                execution_id: terminal.map_or(0, |value| value.execution_id),
                attempt_id: terminal.map_or(operation.attempt_id, |value| value.attempt_id),
                attempts: terminal.map_or(0, |value| value.attempts),
                payload_bytes: 0,
                manifest_bytes: operation.manifest_bytes,
                chunk_bytes: operation.chunk_bytes,
                digest_bytes: operation.digest_bytes,
                checkpoint_bytes: terminal.map_or(0, |value| value.checkpoint_bytes),
                payload: operation.payload,
                failure_recorded: false,
                dlq_route: false,
                due_route: route.due,
                fair_route: route.fair,
                lease_route: route.lease,
                wake_route: route.wake,
                permit_held: route.permit,
                rate_held: route.rate,
                in_flight: 0,
                dangling,
            });
        };
        if core.job_id != persist::actual_job_id(job) {
            return Err(std::io::Error::other("stored job ID does not match connector job").into());
        }
        let (state, leased, core_node, core_fence, core_token, core_lease_until) = match &core.state
        {
            bg_jobs::JobState::Scheduled => (
                if route.retry_waiting {
                    JobState::RetryWaiting
                } else {
                    JobState::Scheduled
                },
                false,
                Node::NodeA,
                operation.fence_high_water,
                0,
                0,
            ),
            bg_jobs::JobState::DeadLettered => (
                JobState::DeadLettered,
                false,
                Node::NodeA,
                operation.fence_high_water,
                0,
                0,
            ),
            bg_jobs::JobState::Cancelled => (
                JobState::Cancelled,
                false,
                Node::NodeA,
                operation.fence_high_water,
                0,
                0,
            ),
            // The store-protocol model has no suspend commands and no
            // Suspended state, so this arm is currently unreachable in
            // conformance traces. Project as a non-leased, non-terminal
            // record with its actual (empty) routes rather than inventing
            // terminal semantics.
            bg_jobs::JobState::Suspended => (
                JobState::Scheduled,
                false,
                Node::NodeA,
                operation.fence_high_water,
                0,
                0,
            ),
            bg_jobs::JobState::Leased(lease) => {
                let node = if lease.owner.as_bytes()[0] == 2 {
                    Node::NodeB
                } else {
                    Node::NodeA
                };
                let fence = i64::try_from(lease.fence.get())
                    .map_err(|_| std::io::Error::other("lease fence exceeds model range"))?;
                (
                    JobState::Leased,
                    true,
                    node,
                    fence,
                    number_from_bytes(lease.token.as_bytes()),
                    lease.expires_at.as_millis() / 1_000,
                )
            }
        };
        let mut record = Record {
            exists: true,
            state,
            kind,
            revision: i64::try_from(core.revision)
                .map_err(|_| std::io::Error::other("stored revision exceeds model range"))?,
            node: core_node,
            generation: i64::from(core.generation),
            fence: core_fence,
            token: core_token,
            leased,
            lease_until: core_lease_until,
            expires_at: core.expires_at.map_or(0, |value| value.as_millis() / 1_000),
            operation_id: operation.operation_id,
            enqueue_fingerprint: operation.enqueue_fingerprint,
            execution_id: number_from_bytes(core.execution_id.as_bytes()),
            attempt_id: operation.attempt_id,
            attempts: core
                .attempts
                .as_ref()
                .map_or(0, |value| i64::from(value.attempts.get())),
            payload_bytes: i64::from(core.payload.total_length),
            manifest_bytes: operation.manifest_bytes,
            chunk_bytes: operation.chunk_bytes,
            digest_bytes: operation.digest_bytes,
            checkpoint_bytes: core
                .checkpoint
                .as_ref()
                .map_or(0, |value| i64::try_from(value.len()).unwrap_or(i64::MAX)),
            payload: operation.payload,
            failure_recorded: matches!(core.state, bg_jobs::JobState::DeadLettered),
            dlq_route: matches!(core.state, bg_jobs::JobState::DeadLettered),
            due_route: route.due,
            fair_route: route.fair,
            lease_route: route.lease,
            wake_route: route.wake,
            permit_held: route.permit,
            rate_held: route.rate,
            in_flight: if leased { 1 } else { 0 },
            dangling,
        };
        if !record.payload {
            record.payload_bytes = 0;
        }
        Ok(record)
    }

    fn unknown_versions(&self) -> Result<BTreeSet<JobId>> {
        let mut jobs = BTreeSet::new();
        for job in [JobId::JobA, JobId::JobB, JobId::JobC] {
            if persist::read_fault(&self.store, &self.namespace, &job)
                .map_err(std::io::Error::other)?
                .is_some_and(|fault| fault.kind == RecordKind::UnknownVersion)
            {
                jobs.insert(job);
            }
        }
        Ok(jobs)
    }

    fn command_from_step(&self, step: &Step) -> Result<Command> {
        let rendered = step.to_string();
        let value = rendered
            .lines()
            .find_map(|line| line.trim_start().strip_prefix("+ lastCommand: "))
            .ok_or_else(|| std::io::Error::other("store step has no serialized command"))?;
        parse_command(value.trim()).map_err(|error| {
            std::io::Error::other(format!("cannot decode store command {value:?}: {error}")).into()
        })
    }

    fn apply_command(&mut self, command: Command) -> Result<()> {
        let family = command_family(&command);
        self.covered_commands.insert(family);
        *self.command_counts.entry(family).or_default() += 1;
        match command {
            Command::StoreEnqueue {
                job,
                operation,
                resources,
                fingerprint,
            } => self.enqueue(job, operation, resources, fingerprint),
            Command::StoreSelectClaim {
                job,
                reader,
                revision,
            } => self.select_claim(job, reader, revision),
            Command::StoreClaim {
                job,
                contender,
                revision,
            } => self.claim(job, contender, revision),
            Command::StoreRenew(authority) => self.renew(authority),
            Command::StoreComplete(authority) => self.complete(authority),
            Command::StoreDeadLetter { authority, handler } => self.dead_letter(authority, handler),
            Command::StoreRedrive {
                job,
                revision,
                operation,
                reuse_execution,
            } => self.redrive(job, revision, operation, reuse_execution),
            Command::StoreUnknown {
                authority,
                committed,
            } => self.unknown(authority, committed),
            Command::StoreReconcile {
                job,
                operation,
                observed,
            } => self.reconcile(job, operation, observed),
            Command::StoreCorrupt { job, kind } => self.corrupt(job, kind),
            Command::StoreDropRoute {
                job,
                due,
                fair,
                lease,
                wake,
            } => self.drop_route(job, due, fair, lease, wake),
            Command::StoreRepair {
                job,
                revision,
                operation,
            } => self.repair(job, revision, operation),
            Command::StorePurge { job, revision } => self.purge(job, revision),
            Command::StoreAdvance { amount } => self.advance(amount),
            Command::StoreExpire { job } => self.expire(job),
        }
    }

    fn enqueue(
        &mut self,
        job: JobId,
        operation: OperationId,
        resources: ResourceInput,
        fingerprint: i64,
    ) -> Result<()> {
        let current = self.project_record(job)?;
        let within = resources.payload_bytes >= 0
            && resources.payload_bytes <= MAX_INLINE_PAYLOAD_BYTES
            && resources.manifest_bytes >= 0
            && resources.manifest_bytes <= MAX_MANIFEST_BYTES
            && resources.chunk_bytes >= 0
            && resources.chunk_bytes <= MAX_CHUNK_BYTES
            && resources.digest_bytes >= 0
            && resources.digest_bytes <= MAX_DIGEST_BYTES
            && resources.checkpoint_bytes >= 0
            && resources.checkpoint_bytes <= MAX_CHECKPOINT_BYTES;
        let blocked = self.blocked(job)?;
        let present = current.enqueue_fingerprint != 0;
        let same = present && current.enqueue_fingerprint == fingerprint;
        let inserted = within && fingerprint > 0 && !blocked && !present;
        let replay = within && !blocked && same;
        let conflict = within && !blocked && present && !same;
        let disposition = if inserted {
            EnqueueDisposition::Inserted
        } else if replay {
            EnqueueDisposition::AlreadyPresent
        } else if conflict {
            EnqueueDisposition::JobIdConflict
        } else {
            EnqueueDisposition::NotEnqueue
        };
        if inserted {
            let revision = current.revision.saturating_add(1);
            let expires_at = self.trace.now.saturating_add(12);
            self.commit_state(job, |state| {
                state.core = Some(
                    persist::new_scheduled_core(persist::NewScheduledCoreInput {
                        namespace: &self.namespace,
                        queue: &self.queue,
                        job,
                        payload_bytes: resources.payload_bytes,
                        checkpoint_bytes: resources.checkpoint_bytes,
                        expires_at,
                        revision,
                        execution_id: current.execution_id.max(1),
                    })
                    .map_err(std::io::Error::other)?,
                );
                state.operation = persist::OperationState {
                    operation_id: operation,
                    fence_high_water: current.fence,
                    enqueue_fingerprint: fingerprint,
                    payload: true,
                    manifest_bytes: resources.manifest_bytes,
                    chunk_bytes: resources.chunk_bytes,
                    digest_bytes: resources.digest_bytes,
                    attempt_id: 0,
                    terminal: None,
                };
                state.route = persist::RouteState {
                    due: true,
                    fair: true,
                    lease: false,
                    wake: true,
                    permit: false,
                    rate: false,
                    retry_waiting: false,
                };
                state.fault = None;
                Ok(StateChange {
                    payload: PayloadChange::Write(resources.payload_bytes),
                    ..StateChange::default()
                })
            })?;
        } else {
            self.check_state(job)?;
        }
        self.trace.transaction_checks = 1;
        self.trace.transaction_mutations = if inserted { 6 } else { 0 };
        self.trace.transaction_bytes = if inserted { 6 } else { 0 };
        self.trace.quarantine_attempts = if self.unknown_versions()?.contains(&job) {
            self.trace.quarantine_attempts.saturating_add(1)
        } else {
            self.trace.quarantine_attempts
        };
        let outcome = if inserted {
            StoreOutcome::AtomicEnqueue
        } else if replay {
            StoreOutcome::EnqueueAlreadyPresent
        } else if conflict {
            StoreOutcome::EnqueueJobIdConflict
        } else if blocked {
            StoreOutcome::ConflictNoMutation
        } else {
            StoreOutcome::PayloadRejected
        };
        let result = if inserted || replay {
            StoreResult::Committed
        } else if conflict || !within {
            StoreResult::Rejected
        } else {
            StoreResult::Conflict
        };
        self.finish(LastTransition {
            command: Command::StoreEnqueue {
                job,
                operation,
                resources,
                fingerprint,
            },
            class: if inserted || replay {
                ResultClass::AppliedClass
            } else if conflict || !within {
                ResultClass::RejectedClass
            } else {
                ResultClass::ConflictClass
            },
            result,
            outcome,
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: disposition,
            job,
            operation,
        });
        Ok(())
    }

    fn select_claim(&mut self, job: JobId, reader: Node, revision: i64) -> Result<()> {
        let current = self.project_record(job)?;
        let allowed = self.claimable(job, &current)? && revision == current.revision;
        if allowed {
            self.commit_state(job, |_state| {
                Ok(StateChange {
                    claim: Some(Some(persist::ClaimState {
                        job,
                        reader,
                        revision,
                    })),
                    ..StateChange::default()
                })
            })?;
        } else {
            self.check_state(job)?;
        }
        self.finish(LastTransition {
            command: Command::StoreSelectClaim {
                job,
                reader,
                revision,
            },
            class: ResultClass::AppliedClass,
            result: StoreResult::Committed,
            outcome: StoreOutcome::ClaimSelected,
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job,
            operation: OperationId::OperationA,
        });
        Ok(())
    }

    fn claim(&mut self, job: JobId, contender: Node, revision: i64) -> Result<()> {
        let current = self.project_record(job)?;
        let claim =
            persist::read_claim(&self.store, &self.namespace).map_err(std::io::Error::other)?;
        let same_read = claim.is_some_and(|claim| claim.job == job && revision == claim.revision);
        let allowed = !self.blocked(job)?
            && same_read
            && claim.is_some_and(|claim| contender == claim.reader)
            && current.exists
            && current.kind == RecordKind::Valid
            && current.payload
            && current.due_route
            && !current.leased
            && self.trace.now < current.expires_at
            && revision == current.revision;
        let competing = !self.blocked(job)?
            && claim.is_some_and(|claim| revision == claim.revision)
            && contender != current.node
            && (!same_read || current.revision != revision || current.leased);
        if allowed {
            let lease_until = self.trace.now.saturating_add(3);
            self.commit_state(job, |state| {
                let core = state
                    .core
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("claim requires live core"))?;
                let fence = current.fence.saturating_add(1);
                let token = current.token.saturating_add(3);
                core.state = bg_jobs::JobState::Leased(
                    Lease::try_new(
                        persist::owner_id(contender),
                        persist::lease_token(token),
                        NonZeroU64::new(fence.max(1) as u64)
                            .ok_or_else(|| std::io::Error::other("zero lease fence"))?,
                        Timestamp::from_millis(lease_until.saturating_mul(1_000)),
                    )
                    .map_err(std::io::Error::other)?,
                );
                core.revision = u64::try_from(current.revision.saturating_add(1))
                    .map_err(|_| std::io::Error::other("revision overflow"))?;
                core.generation = u32::try_from(current.generation.saturating_add(1))
                    .map_err(|_| std::io::Error::other("generation overflow"))?;
                core.attempts =
                    NonZeroU32::new(current.attempts.saturating_add(1) as u32).map(|attempts| {
                        AttemptHistory {
                            attempts,
                            first_attempt_at: Timestamp::ZERO,
                            last_attempt_at: Timestamp::ZERO,
                            last_outcome: None,
                        }
                    });
                state.operation.attempt_id = current.attempt_id.saturating_add(1);
                state.operation.fence_high_water = fence;
                state.operation.terminal = None;
                state.route.due = false;
                state.route.fair = false;
                state.route.lease = true;
                state.route.wake = false;
                state.route.permit = true;
                state.route.rate = true;
                state.route.retry_waiting = false;
                state.fault = None;
                Ok(StateChange {
                    claim: Some(None),
                    ..StateChange::default()
                })
            })?;
        } else if competing {
            self.commit_state(job, |_state| {
                Ok(StateChange {
                    claim: Some(None),
                    ..StateChange::default()
                })
            })?;
        } else {
            self.check_state(job)?;
        }
        self.trace.transaction_checks = 1;
        self.trace.transaction_mutations = if allowed { 3 } else { 0 };
        self.trace.transaction_bytes = if allowed { 3 } else { 0 };
        self.finish(LastTransition {
            command: Command::StoreClaim {
                job,
                contender,
                revision,
            },
            class: if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::ConflictClass
            },
            result: if allowed || competing {
                StoreResult::Committed
            } else {
                StoreResult::Conflict
            },
            outcome: if allowed {
                StoreOutcome::ClaimAtomicCommit
            } else {
                StoreOutcome::ClaimConflictNoMutation
            },
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job,
            operation: OperationId::OperationA,
        });
        Ok(())
    }

    fn renew(&mut self, authority: AuthorityInput) -> Result<()> {
        let current = self.project_record(authority.job)?;
        let exact = self.exact_authority(&current, &authority)?;
        if exact {
            let lease_until = self.trace.now.saturating_add(3);
            self.commit_state(authority.job, |state| {
                let core = state
                    .core
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("renew requires live core"))?;
                if let bg_jobs::JobState::Leased(lease) = &mut core.state {
                    lease.expires_at = Timestamp::from_millis(lease_until.saturating_mul(1_000));
                } else {
                    return Err(std::io::Error::other("renew requires leased core").into());
                }
                core.revision = u64::try_from(current.revision.saturating_add(1))
                    .map_err(|_| std::io::Error::other("revision overflow"))?;
                state.operation.terminal = None;
                Ok(StateChange::default())
            })?;
        } else {
            self.check_state(authority.job)?;
        }
        self.finish(LastTransition {
            command: Command::StoreRenew(authority.clone()),
            class: if exact {
                ResultClass::AppliedClass
            } else {
                ResultClass::ConflictClass
            },
            result: if exact {
                StoreResult::Committed
            } else {
                StoreResult::Conflict
            },
            outcome: if exact {
                StoreOutcome::LeaseRenewed
            } else {
                StoreOutcome::LeaseRenewConflict
            },
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job: authority.job,
            operation: authority.operation,
        });
        Ok(())
    }

    fn complete(&mut self, authority: AuthorityInput) -> Result<()> {
        let current = self.project_record(authority.job)?;
        let exact = self.exact_authority(&current, &authority)?;
        let detail = if exact {
            detail_at(self.trace.completion_receipts)
        } else {
            CompletionDetail::NoCompletionDetail
        };
        if exact {
            let clear_claim = persist::read_claim(&self.store, &self.namespace)
                .map_err(std::io::Error::other)?
                .is_some_and(|claim| claim.job == authority.job);
            self.commit_state(authority.job, |state| {
                let core = state
                    .core
                    .take()
                    .ok_or_else(|| std::io::Error::other("completion requires live core"))?;
                let mut terminal =
                    persist::terminal_from_core(&core).map_err(std::io::Error::other)?;
                terminal.revision = authority.revision.saturating_add(1);
                terminal.lease_until = 0;
                terminal.checkpoint_bytes = 0;
                terminal.attempt_id = state.operation.attempt_id;
                state.operation.fence_high_water = terminal.fence;
                state.operation.payload = false;
                state.operation.manifest_bytes = 0;
                state.operation.chunk_bytes = 0;
                state.operation.digest_bytes = 0;
                state.operation.attempt_id = 0;
                state.operation.terminal = Some(terminal);
                state.route.due = false;
                state.route.fair = false;
                state.route.lease = false;
                state.route.wake = false;
                state.route.permit = false;
                state.route.rate = false;
                state.route.retry_waiting = false;
                state.fault = None;
                Ok(StateChange {
                    payload: PayloadChange::Delete,
                    claim: clear_claim.then_some(None),
                    ..StateChange::default()
                })
            })?;
            self.trace.completion_receipts =
                (self.trace.completion_receipts + 1).min(MAX_COMPLETION_RECEIPTS);
            self.trace.completion_detail = detail;
            self.trace.last_detail = detail;
            self.trace.completion_detail_job = authority.job;
        } else {
            self.check_state(authority.job)?;
            self.trace.completion_detail = CompletionDetail::NoCompletionDetail;
            self.trace.last_detail = CompletionDetail::NoCompletionDetail;
        }
        self.trace.completion_detail_job = authority.job;
        self.trace.transaction_checks = 1;
        self.trace.transaction_mutations = if exact { 7 } else { 0 };
        self.trace.transaction_bytes = if exact { 7 } else { 0 };
        self.finish(LastTransition {
            command: Command::StoreComplete(authority.clone()),
            class: if exact {
                ResultClass::AppliedClass
            } else {
                ResultClass::ConflictClass
            },
            result: if exact {
                StoreResult::Committed
            } else {
                StoreResult::Conflict
            },
            outcome: if exact {
                StoreOutcome::CompletionDeletedAllKeys
            } else {
                StoreOutcome::ConflictNoMutation
            },
            detail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job: authority.job,
            operation: authority.operation,
        });
        Ok(())
    }

    fn dead_letter(&mut self, authority: AuthorityInput, handler: HandlerResult) -> Result<()> {
        let current = self.project_record(authority.job)?;
        let authority_matches = self.exact_authority(&current, &authority)?;
        let retryable = matches!(
            handler,
            HandlerResult::Transient | HandlerResult::Throttled | HandlerResult::Ambiguous
        );
        let terminal = authority_matches
            && current.leased
            && current.kind == RecordKind::Valid
            && (matches!(handler, HandlerResult::Permanent)
                || (retryable && current.attempts >= 3));
        if terminal {
            let clear_claim = persist::read_claim(&self.store, &self.namespace)
                .map_err(std::io::Error::other)?
                .is_some_and(|claim| claim.job == authority.job);
            self.commit_state(authority.job, |state| {
                let core = state
                    .core
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("dead-letter requires live core"))?;
                core.state = bg_jobs::JobState::DeadLettered;
                core.revision = u64::try_from(current.revision.saturating_add(1))
                    .map_err(|_| std::io::Error::other("revision overflow"))?;
                state.operation.fence_high_water = current.fence;
                state.operation.terminal = None;
                state.route.due = false;
                state.route.fair = false;
                state.route.lease = false;
                state.route.wake = false;
                state.route.permit = false;
                state.route.rate = false;
                state.route.retry_waiting = false;
                state.fault = None;
                Ok(StateChange {
                    claim: clear_claim.then_some(None),
                    ..StateChange::default()
                })
            })?;
        } else {
            self.check_state(authority.job)?;
        }
        self.trace.transaction_checks = 1;
        self.trace.transaction_mutations = if terminal { 7 } else { 0 };
        self.trace.transaction_bytes = if terminal { 7 } else { 0 };
        let result = if terminal {
            StoreResult::Committed
        } else if authority_matches {
            StoreResult::Rejected
        } else {
            StoreResult::Conflict
        };
        self.finish(LastTransition {
            command: Command::StoreDeadLetter {
                authority: authority.clone(),
                handler,
            },
            class: if terminal {
                ResultClass::AppliedClass
            } else if authority_matches {
                ResultClass::RejectedClass
            } else {
                ResultClass::ConflictClass
            },
            result,
            outcome: if terminal {
                StoreOutcome::HandlerDeadLetter
            } else {
                StoreOutcome::ConflictNoMutation
            },
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job: authority.job,
            operation: authority.operation,
        });
        Ok(())
    }

    fn redrive(
        &mut self,
        job: JobId,
        revision: i64,
        operation: OperationId,
        reuse_execution: bool,
    ) -> Result<()> {
        let current = self.project_record(job)?;
        let authority_conflict = revision != current.revision || operation != current.operation_id;
        let allowed = !self.blocked(job)?
            && current.state == JobState::DeadLettered
            && current.kind == RecordKind::Valid
            && current.failure_recorded
            && current.dlq_route
            && !authority_conflict;
        if allowed {
            let clear_claim = persist::read_claim(&self.store, &self.namespace)
                .map_err(std::io::Error::other)?
                .is_some_and(|claim| claim.job == job);
            let expires_at = self.trace.now.saturating_add(12);
            self.commit_state(job, |state| {
                let core = state
                    .core
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("redrive requires live core"))?;
                core.state = bg_jobs::JobState::Scheduled;
                core.revision = u64::try_from(current.revision.saturating_add(1))
                    .map_err(|_| std::io::Error::other("revision overflow"))?;
                core.generation = u32::try_from(current.generation.saturating_add(1))
                    .map_err(|_| std::io::Error::other("generation overflow"))?;
                core.execution_id = if reuse_execution {
                    core.execution_id
                } else {
                    ExecutionId::from(number_bytes(current.execution_id.saturating_add(1)))
                };
                core.checkpoint = None;
                core.expires_at = Some(Timestamp::from_millis(expires_at.saturating_mul(1_000)));
                core.retention_deadline = Timestamp::from_millis(expires_at.saturating_mul(1_000));
                core.attempts = None;
                state.operation.attempt_id = 0;
                state.operation.operation_id = next_operation_id(current.operation_id);
                state.operation.terminal = None;
                state.route.due = true;
                state.route.fair = true;
                state.route.lease = false;
                state.route.wake = true;
                state.route.permit = false;
                state.route.rate = false;
                state.route.retry_waiting = false;
                state.fault = None;
                Ok(StateChange {
                    claim: clear_claim.then_some(None),
                    ..StateChange::default()
                })
            })?;
            self.trace.completion_detail = CompletionDetail::NoCompletionDetail;
            self.trace.last_detail = CompletionDetail::NoCompletionDetail;
            self.trace.completion_detail_job = job;
        } else {
            self.check_state(job)?;
        }
        self.trace.transaction_checks = 1;
        self.trace.transaction_mutations = if allowed { 7 } else { 0 };
        self.trace.transaction_bytes = if allowed { 7 } else { 0 };
        let result = if allowed {
            StoreResult::Committed
        } else if authority_conflict {
            StoreResult::Conflict
        } else {
            StoreResult::Rejected
        };
        self.finish(LastTransition {
            command: Command::StoreRedrive {
                job,
                revision,
                operation,
                reuse_execution,
            },
            class: if allowed {
                ResultClass::AppliedClass
            } else if authority_conflict {
                ResultClass::ConflictClass
            } else {
                ResultClass::RejectedClass
            },
            result,
            outcome: if allowed {
                StoreOutcome::RedriveCommitted
            } else if authority_conflict {
                StoreOutcome::RedriveConflict
            } else {
                StoreOutcome::RedriveRejected
            },
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job,
            operation,
        });
        Ok(())
    }

    fn unknown(&mut self, authority: AuthorityInput, committed: bool) -> Result<()> {
        let current = self.project_record(authority.job)?;
        let unknown_before =
            persist::read_unknown(&self.store, &self.namespace).map_err(std::io::Error::other)?;
        let exact = unknown_before.is_none() && self.exact_authority(&current, &authority)?;
        if exact {
            let readback = if committed {
                StoreResult::Committed
            } else {
                StoreResult::Conflict
            };
            let clear_claim = persist::read_claim(&self.store, &self.namespace)
                .map_err(std::io::Error::other)?
                .is_some_and(|claim| claim.job == authority.job);
            if committed {
                self.store
                    .queue_unknown_after_commit()
                    .map_err(std::io::Error::other)?;
            }
            self.commit_state_allow_unknown(authority.job, committed, |state| {
                if committed {
                    let core = state.core.take().ok_or_else(|| {
                        std::io::Error::other("unknown commit requires live core")
                    })?;
                    let mut terminal =
                        persist::terminal_from_core(&core).map_err(std::io::Error::other)?;
                    terminal.revision = authority.revision.saturating_add(1);
                    terminal.lease_until = 0;
                    terminal.attempt_id = state.operation.attempt_id;
                    state.operation.fence_high_water = terminal.fence;
                    state.operation.payload = false;
                    state.operation.manifest_bytes = 0;
                    state.operation.chunk_bytes = 0;
                    state.operation.digest_bytes = 0;
                    state.operation.attempt_id = 0;
                    state.operation.terminal = Some(terminal);
                    state.route.due = false;
                    state.route.fair = false;
                    state.route.lease = false;
                    state.route.wake = false;
                    state.route.permit = false;
                    state.route.rate = false;
                    state.route.retry_waiting = false;
                    state.fault = None;
                }
                Ok(StateChange {
                    payload: if committed {
                        PayloadChange::Delete
                    } else {
                        PayloadChange::Keep
                    },
                    unknown: Some(Some(persist::UnknownState {
                        job: authority.job,
                        operation: authority.operation,
                        node: authority.node,
                        revision: authority.revision,
                        generation: authority.generation,
                        fence: authority.fence,
                        token: authority.token,
                        lease_until: authority.lease_until,
                        readback,
                    })),
                    claim: clear_claim.then_some(None),
                })
            })?;
            self.trace.completion_detail = CompletionDetail::NoCompletionDetail;
            self.trace.last_detail = CompletionDetail::NoCompletionDetail;
            self.trace.completion_detail_job = authority.job;
        } else {
            self.check_state(authority.job)?;
        }
        self.finish(LastTransition {
            command: Command::StoreUnknown {
                authority: authority.clone(),
                committed,
            },
            class: if exact {
                ResultClass::UnknownClass
            } else {
                ResultClass::ConflictClass
            },
            result: if exact {
                StoreResult::Unknown
            } else {
                StoreResult::Conflict
            },
            outcome: if exact {
                StoreOutcome::UnknownCommitRequiresReconcile
            } else {
                StoreOutcome::ConflictNoMutation
            },
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job: authority.job,
            operation: authority.operation,
        });
        Ok(())
    }

    fn reconcile(
        &mut self,
        job: JobId,
        operation: OperationId,
        observed: StoreResult,
    ) -> Result<()> {
        let current = self.project_record(job)?;
        let unknown =
            persist::read_unknown(&self.store, &self.namespace).map_err(std::io::Error::other)?;
        let identity = unknown.is_some_and(|unknown| {
            current.operation_id == unknown.operation
                && current.node == unknown.node
                && current.generation == unknown.generation
                && current.fence == unknown.fence
                && current.token == unknown.token
                && if observed == StoreResult::Committed {
                    !current.exists
                        && current.revision == unknown.revision.saturating_add(1)
                        && current.lease_until == 0
                        && !current.permit_held
                        && !current.rate_held
                        && current.in_flight == 0
                } else {
                    current.exists
                        && current.leased
                        && current.revision == unknown.revision
                        && current.lease_until == unknown.lease_until
                        && current.permit_held
                        && current.rate_held
                        && current.in_flight == 1
                }
        });
        let authority_changed = unknown.is_some_and(|unknown| {
            current.revision != unknown.revision
                && current.revision != unknown.revision.saturating_add(1)
        });
        let exact = unknown.is_some_and(|unknown| {
            job == unknown.job
                && operation == unknown.operation
                && observed == unknown.readback
                && if observed == StoreResult::AuthorityChanged {
                    authority_changed
                } else {
                    identity
                }
        });
        let committed_exact = exact && observed == StoreResult::Committed;
        let completion_detail = if committed_exact {
            detail_at(self.trace.completion_receipts)
        } else {
            CompletionDetail::NoCompletionDetail
        };
        if exact {
            self.commit_state(job, |_state| {
                Ok(StateChange {
                    unknown: Some(None),
                    ..StateChange::default()
                })
            })?;
            if committed_exact {
                self.trace.completion_receipts =
                    (self.trace.completion_receipts + 1).min(MAX_COMPLETION_RECEIPTS);
                self.trace.completion_detail = completion_detail;
                self.trace.last_detail = completion_detail;
            } else {
                self.trace.completion_detail = CompletionDetail::NoCompletionDetail;
                self.trace.last_detail = CompletionDetail::NoCompletionDetail;
            }
            self.trace.completion_detail_job = job;
        } else {
            self.check_state(job)?;
        }
        self.finish(LastTransition {
            command: Command::StoreReconcile {
                job,
                operation,
                observed,
            },
            class: if exact {
                ResultClass::AppliedClass
            } else {
                ResultClass::ConflictClass
            },
            result: if exact {
                StoreResult::Committed
            } else {
                StoreResult::Conflict
            },
            outcome: if !exact {
                StoreOutcome::ConflictNoMutation
            } else if observed == StoreResult::Committed {
                StoreOutcome::ReconciledCommitted
            } else if observed == StoreResult::Conflict {
                StoreOutcome::ReconciledConflict
            } else {
                StoreOutcome::ReconciledAuthorityChanged
            },
            detail: completion_detail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job,
            operation,
        });
        Ok(())
    }

    fn corrupt(&mut self, job: JobId, kind: RecordKind) -> Result<()> {
        let current = self.project_record(job)?;
        let understood = kind != RecordKind::UnknownVersion;
        if understood {
            let clear_claim = persist::read_claim(&self.store, &self.namespace)
                .map_err(std::io::Error::other)?
                .is_some_and(|claim| claim.job == job);
            self.commit_state(job, |state| {
                let revision = current.revision.saturating_add(1);
                if let Some(core) = state.core.as_mut() {
                    core.revision = u64::try_from(revision)
                        .map_err(|_| std::io::Error::other("revision overflow"))?;
                } else if let Some(terminal) = state.operation.terminal.as_mut() {
                    terminal.revision = revision;
                }
                state.route.due = false;
                state.route.fair = false;
                state.route.lease = false;
                state.route.wake = false;
                state.route.permit = false;
                state.route.rate = false;
                state.route.retry_waiting = false;
                state.fault = Some(persist::FaultState {
                    kind,
                    dangling: state.core.is_none(),
                });
                Ok(StateChange {
                    claim: clear_claim.then_some(None),
                    ..StateChange::default()
                })
            })?;
            self.trace.transaction_checks = 1;
            self.trace.transaction_mutations = 1;
            self.trace.transaction_bytes = 1;
        } else {
            self.commit_state(job, |state| {
                state.fault = Some(persist::FaultState {
                    kind: RecordKind::UnknownVersion,
                    dangling: state.core.is_none(),
                });
                Ok(StateChange {
                    ..StateChange::default()
                })
            })?;
            self.trace.quarantine_attempts = 0;
        }
        self.finish(LastTransition {
            command: Command::StoreCorrupt { job, kind },
            class: if understood {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
            result: if understood {
                StoreResult::Committed
            } else {
                StoreResult::Rejected
            },
            outcome: if !understood {
                StoreOutcome::UnknownVersionQuarantined
            } else if kind == RecordKind::Missing {
                StoreOutcome::MissingIndexDiscovered
            } else {
                StoreOutcome::CorruptQuarantined
            },
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job,
            operation: OperationId::OperationA,
        });
        Ok(())
    }

    fn drop_route(
        &mut self,
        job: JobId,
        due: bool,
        fair: bool,
        lease: bool,
        wake: bool,
    ) -> Result<()> {
        let current = self.project_record(job)?;
        let allowed = (due || fair || lease || wake)
            && !self.blocked(job)?
            && current.kind == RecordKind::Valid
            && !current.leased
            && matches!(current.state, JobState::Scheduled | JobState::RetryWaiting);
        if allowed {
            self.commit_state(job, |state| {
                let revision = current.revision.saturating_add(1);
                if let Some(core) = state.core.as_mut() {
                    core.revision = u64::try_from(revision)
                        .map_err(|_| std::io::Error::other("revision overflow"))?;
                } else if let Some(terminal) = state.operation.terminal.as_mut() {
                    terminal.revision = revision;
                }
                state.route.due = false;
                state.route.fair = false;
                state.route.lease = false;
                state.route.wake = false;
                state.route.permit = false;
                state.route.rate = false;
                state.route.retry_waiting = false;
                state.fault = Some(persist::FaultState {
                    kind: RecordKind::Corrupt,
                    dangling: state.core.is_none(),
                });
                Ok(StateChange {
                    claim: Some(None),
                    ..StateChange::default()
                })
            })?;
        } else {
            self.check_state(job)?;
        }
        self.trace.transaction_checks = 1;
        self.trace.transaction_mutations = if allowed { 1 } else { 0 };
        self.trace.transaction_bytes = 1;
        self.finish(LastTransition {
            command: Command::StoreDropRoute {
                job,
                due,
                fair,
                lease,
                wake,
            },
            class: if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::ConflictClass
            },
            result: if allowed {
                StoreResult::Committed
            } else {
                StoreResult::Conflict
            },
            outcome: if !allowed {
                StoreOutcome::ConflictNoMutation
            } else if current.exists {
                StoreOutcome::MissingIndexDiscovered
            } else {
                StoreOutcome::DanglingRecordCreated
            },
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job,
            operation: OperationId::OperationA,
        });
        Ok(())
    }

    fn repair(&mut self, job: JobId, revision: i64, operation: OperationId) -> Result<()> {
        let current = self.project_record(job)?;
        let allowed = !self.blocked(job)?
            && current.exists
            && matches!(current.state, JobState::Scheduled | JobState::RetryWaiting)
            && current.kind == RecordKind::Corrupt
            && revision == current.revision
            && operation == current.operation_id
            && !self.unknown_versions()?.contains(&job);
        if allowed {
            let clear_claim = persist::read_claim(&self.store, &self.namespace)
                .map_err(std::io::Error::other)?
                .is_some_and(|claim| claim.job == job);
            self.commit_state(job, |state| {
                let core = state
                    .core
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("repair requires live core"))?;
                core.revision = u64::try_from(current.revision.saturating_add(1))
                    .map_err(|_| std::io::Error::other("revision overflow"))?;
                state.route.due = true;
                state.route.fair = true;
                state.route.wake = true;
                state.route.lease = false;
                state.route.permit = false;
                state.route.rate = false;
                state.route.retry_waiting = current.state == JobState::RetryWaiting;
                state.fault = None;
                Ok(StateChange {
                    claim: clear_claim.then_some(None),
                    ..StateChange::default()
                })
            })?;
            self.trace.repair_steps = 1;
        } else {
            self.check_state(job)?;
            self.trace.repair_steps = 0;
        }
        self.trace.transaction_checks = 1;
        self.trace.transaction_mutations = if allowed { 6 } else { 0 };
        self.trace.transaction_bytes = if allowed { 6 } else { 0 };
        self.finish(LastTransition {
            command: Command::StoreRepair {
                job,
                revision,
                operation,
            },
            class: if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::ConflictClass
            },
            result: if allowed {
                StoreResult::Committed
            } else {
                StoreResult::Conflict
            },
            outcome: if allowed {
                StoreOutcome::RepairCommitted
            } else {
                StoreOutcome::RepairRevisionConflict
            },
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job,
            operation,
        });
        Ok(())
    }

    fn purge(&mut self, job: JobId, revision: i64) -> Result<()> {
        let current = self.project_record(job)?;
        let allowed = !self.blocked(job)?
            && !current.exists
            && (current.due_route
                || current.fair_route
                || current.lease_route
                || current.wake_route)
            && revision == current.revision;
        if allowed {
            let clear_claim = persist::read_claim(&self.store, &self.namespace)
                .map_err(std::io::Error::other)?
                .is_some_and(|claim| claim.job == job);
            self.commit_state(job, |state| {
                if let Some(terminal) = state.operation.terminal.as_mut() {
                    terminal.revision = current.revision.saturating_add(1);
                }
                state.route.due = false;
                state.route.fair = false;
                state.route.lease = false;
                state.route.wake = false;
                state.route.permit = false;
                state.route.rate = false;
                state.route.retry_waiting = false;
                state.fault = None;
                Ok(StateChange {
                    claim: clear_claim.then_some(None),
                    ..StateChange::default()
                })
            })?;
            self.trace.repair_steps = 1;
            self.trace.unrelated_progress = (self.trace.unrelated_progress + 1).min(4);
        } else {
            self.check_state(job)?;
            self.trace.repair_steps = 0;
        }
        self.finish(LastTransition {
            command: Command::StorePurge { job, revision },
            class: if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::ConflictClass
            },
            result: if allowed {
                StoreResult::Committed
            } else {
                StoreResult::Conflict
            },
            outcome: if allowed {
                StoreOutcome::DanglingIndexPurged
            } else {
                StoreOutcome::ConflictNoMutation
            },
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job,
            operation: OperationId::OperationA,
        });
        Ok(())
    }

    fn advance(&mut self, amount: i64) -> Result<()> {
        self.trace.now = self.trace.now.saturating_add(amount.max(0));
        self.finish(LastTransition {
            command: advance_command(amount),
            class: ResultClass::AppliedClass,
            result: StoreResult::Committed,
            outcome: StoreOutcome::TimeAdvanced,
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job: JobId::JobA,
            operation: OperationId::OperationA,
        });
        Ok(())
    }

    fn expire(&mut self, job: JobId) -> Result<()> {
        let current = self.project_record(job)?;
        let eligible =
            current.leased && current.lease_until <= self.trace.now && !self.blocked(job)?;
        if eligible {
            let age_expired = current.expires_at <= self.trace.now;
            self.commit_state(job, |state| {
                let core = state
                    .core
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("expiration requires live core"))?;
                core.revision = u64::try_from(current.revision.saturating_add(1))
                    .map_err(|_| std::io::Error::other("revision overflow"))?;
                state.route.permit = false;
                state.route.rate = false;
                state.route.lease = false;
                state.operation.fence_high_water = current.fence;
                state.operation.terminal = None;
                if age_expired {
                    core.state = bg_jobs::JobState::DeadLettered;
                    state.route.due = false;
                    state.route.fair = false;
                    state.route.wake = false;
                    state.route.retry_waiting = false;
                } else {
                    core.state = bg_jobs::JobState::Scheduled;
                    state.route.due = true;
                    state.route.fair = true;
                    state.route.wake = true;
                    state.route.retry_waiting = true;
                }
                state.fault = None;
                Ok(StateChange::default())
            })?;
        } else {
            self.check_state(job)?;
        }
        self.finish(LastTransition {
            command: Command::StoreExpire { job },
            class: ResultClass::AppliedClass,
            result: StoreResult::Committed,
            outcome: if current.expires_at <= self.trace.now {
                StoreOutcome::HandlerDeadLetter
            } else {
                StoreOutcome::LeaseExpiredToReady
            },
            detail: CompletionDetail::NoCompletionDetail,
            enqueue: EnqueueDisposition::NotEnqueue,
            job,
            operation: OperationId::OperationA,
        });
        Ok(())
    }

    fn finish(&mut self, transition: LastTransition) {
        self.trace.last_result = transition.result;
        self.trace.last_outcome = transition.outcome;
        self.trace.last_enqueue_disposition = transition.enqueue;
        self.trace.last_detail = transition.detail;
        self.command = transition.command.clone();
        self.transition = transition.clone();
        self.result = if transition.detail == CompletionDetail::CompletionDetailOmitted {
            CommandResult::StoreDetailOmitted(transition)
        } else {
            match self.transition.class {
                ResultClass::AppliedClass => CommandResult::StoreApplied(self.transition.clone()),
                ResultClass::RejectedClass => CommandResult::StoreRejected(self.transition.clone()),
                ResultClass::ConflictClass => {
                    CommandResult::StoreConflictResult(self.transition.clone())
                }
                ResultClass::UnknownClass => {
                    CommandResult::StoreUnknownResult(self.transition.clone())
                }
            }
        };
    }

    fn exact_authority(&self, current: &Record, authority: &AuthorityInput) -> Result<bool> {
        Ok(!self.blocked(authority.job)?
            && current.leased
            && current.kind == RecordKind::Valid
            && current.node == authority.node
            && current.revision == authority.revision
            && current.generation == authority.generation
            && current.fence == authority.fence
            && current.token == authority.token
            && current.lease_until == authority.lease_until
            && current.operation_id == authority.operation
            && self.trace.now < current.lease_until)
    }

    fn claimable(&self, job: JobId, current: &Record) -> Result<bool> {
        Ok(!self.blocked(job)?
            && current.exists
            && current.kind == RecordKind::Valid
            && matches!(current.state, JobState::Scheduled | JobState::RetryWaiting)
            && current.payload
            && current.due_route
            && !current.leased
            && self.trace.now < current.expires_at)
    }

    fn blocked(&self, job: JobId) -> Result<bool> {
        let unknown =
            persist::read_unknown(&self.store, &self.namespace).map_err(std::io::Error::other)?;
        let unknown_version = persist::read_fault(&self.store, &self.namespace, &job)
            .map_err(std::io::Error::other)?
            .is_some_and(|fault| fault.kind == RecordKind::UnknownVersion);
        Ok(unknown.is_some_and(|unknown| unknown.job == job) || unknown_version)
    }

    fn commit_state<F>(&self, job: JobId, update: F) -> Result<()>
    where F: FnOnce(&mut persist::StoredState) -> Result<StateChange> {
        self.commit_state_allow_unknown(job, false, update)
    }

    fn commit_state_allow_unknown<F>(
        &self,
        job: JobId,
        allow_unknown: bool,
        update: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut persist::StoredState) -> Result<StateChange>,
    {
        let before = persist::StoredState::read(&self.store, &self.namespace, &job)
            .map_err(std::io::Error::other)?;
        let unknown_before =
            persist::read_unknown(&self.store, &self.namespace).map_err(std::io::Error::other)?;
        let claim_before =
            persist::read_claim(&self.store, &self.namespace).map_err(std::io::Error::other)?;
        let mut after = before.clone();
        let change = update(&mut after)?;
        let operation_key =
            persist::operation_key(&self.namespace, &job).map_err(std::io::Error::other)?;
        let core_key = KeyCodec::job(&self.namespace, &persist::actual_job_id(job))?;
        let route_key = persist::route_key(&self.namespace, &job).map_err(std::io::Error::other)?;
        let fault_key = persist::fault_key(&self.namespace, &job).map_err(std::io::Error::other)?;
        let unknown_key = persist::unknown_key(&self.namespace).map_err(std::io::Error::other)?;
        let claim_key = persist::claim_key(&self.namespace).map_err(std::io::Error::other)?;

        let mut checks = Vec::with_capacity(6);
        checks.push(if before.operation_present {
            Check::Value(
                operation_key.clone(),
                before.operation.encode().map_err(std::io::Error::other)?,
            )
        } else {
            Check::Absent(operation_key.clone())
        });
        checks.push(if let Some(core) = &before.core {
            Check::Value(core_key.clone(), encode_job_record(core)?)
        } else {
            Check::Absent(core_key.clone())
        });
        checks.push(if before.route_present {
            Check::Value(
                route_key.clone(),
                ValueCodec::encode(ValueTag::Operation, &before.route.encode())?,
            )
        } else {
            Check::Absent(route_key.clone())
        });
        checks.push(if before.fault_present {
            Check::Value(
                fault_key.clone(),
                before
                    .fault
                    .ok_or_else(|| std::io::Error::other("missing decoded fault state"))?
                    .encode()
                    .map_err(std::io::Error::other)?,
            )
        } else {
            Check::Absent(fault_key.clone())
        });
        checks.push(if let Some(unknown) = unknown_before {
            Check::Value(
                unknown_key.clone(),
                unknown.encode().map_err(std::io::Error::other)?,
            )
        } else {
            Check::Absent(unknown_key.clone())
        });
        checks.push(if let Some(claim) = claim_before {
            Check::Value(
                claim_key.clone(),
                claim.encode().map_err(std::io::Error::other)?,
            )
        } else {
            Check::Absent(claim_key.clone())
        });

        let mut mutations = vec![Mutation::Put(
            operation_key,
            after.operation.encode().map_err(std::io::Error::other)?,
        )];
        if after.route.has_state() {
            mutations.push(Mutation::Put(
                route_key,
                ValueCodec::encode(ValueTag::Operation, &after.route.encode())?,
            ));
        } else {
            mutations.push(Mutation::Delete(route_key));
        }
        if let Some(fault) = after.fault {
            mutations.push(Mutation::Put(
                fault_key,
                fault.encode().map_err(std::io::Error::other)?,
            ));
        } else {
            mutations.push(Mutation::Delete(fault_key));
        }
        if let Some(core) = after.core {
            mutations.push(Mutation::Put(core_key, encode_job_record(&core)?));
        } else {
            mutations.push(Mutation::Delete(core_key));
        }
        match change.payload {
            PayloadChange::Keep => {}
            PayloadChange::Write(length) => {
                let payload_key = payload_key(&self.namespace, job)?;
                let length = usize::try_from(length)
                    .map_err(|_| std::io::Error::other("payload length exceeds capacity"))?;
                mutations.push(Mutation::Put(
                    payload_key,
                    ValueCodec::encode(ValueTag::PayloadChunk, &vec![0; length])?,
                ));
            }
            PayloadChange::Delete => {
                mutations.push(Mutation::Delete(payload_key(&self.namespace, job)?));
            }
        }
        if let Some(next_unknown) = change.unknown {
            if let Some(unknown) = next_unknown {
                mutations.push(Mutation::Put(
                    unknown_key,
                    unknown.encode().map_err(std::io::Error::other)?,
                ));
            } else {
                mutations.push(Mutation::Delete(unknown_key));
            }
        }
        if let Some(next_claim) = change.claim {
            if let Some(claim) = next_claim {
                mutations.push(Mutation::Put(
                    claim_key,
                    claim.encode().map_err(std::io::Error::other)?,
                ));
            } else {
                mutations.push(Mutation::Delete(claim_key));
            }
        }
        let transaction = StoreTransaction::try_from(StoreTransactionInput {
            operation_id: CommitOperationId::generate().map_err(std::io::Error::other)?,
            checks,
            mutations,
            limits: transaction_limits(self.store.capabilities()),
        })?;
        match persist::block_on(self.store.commit(&transaction))? {
            CommitOutcome::Committed => Ok(()),
            CommitOutcome::Conflict => {
                Err(std::io::Error::other("connector raw-state commit conflicted").into())
            }
            CommitOutcome::Unknown if allow_unknown => Ok(()),
            CommitOutcome::Unknown => {
                Err(std::io::Error::other("connector raw-state commit was ambiguous").into())
            }
        }
    }

    fn check_state(&self, job: JobId) -> Result<()> {
        let state = persist::StoredState::read(&self.store, &self.namespace, &job)
            .map_err(std::io::Error::other)?;
        let unknown =
            persist::read_unknown(&self.store, &self.namespace).map_err(std::io::Error::other)?;
        let claim =
            persist::read_claim(&self.store, &self.namespace).map_err(std::io::Error::other)?;
        let operation_key =
            persist::operation_key(&self.namespace, &job).map_err(std::io::Error::other)?;
        let core_key = KeyCodec::job(&self.namespace, &persist::actual_job_id(job))?;
        let route_key = persist::route_key(&self.namespace, &job).map_err(std::io::Error::other)?;
        let fault_key = persist::fault_key(&self.namespace, &job).map_err(std::io::Error::other)?;
        let unknown_key = persist::unknown_key(&self.namespace).map_err(std::io::Error::other)?;
        let claim_key = persist::claim_key(&self.namespace).map_err(std::io::Error::other)?;
        let checks = vec![
            if state.operation_present {
                Check::Value(
                    operation_key,
                    state.operation.encode().map_err(std::io::Error::other)?,
                )
            } else {
                Check::Absent(operation_key)
            },
            if let Some(core) = state.core {
                Check::Value(core_key, encode_job_record(&core)?)
            } else {
                Check::Absent(core_key)
            },
            if state.route_present {
                Check::Value(
                    route_key,
                    ValueCodec::encode(ValueTag::Operation, &state.route.encode())?,
                )
            } else {
                Check::Absent(route_key)
            },
            if state.fault_present {
                Check::Value(
                    fault_key,
                    state
                        .fault
                        .ok_or_else(|| std::io::Error::other("missing decoded fault state"))?
                        .encode()
                        .map_err(std::io::Error::other)?,
                )
            } else {
                Check::Absent(fault_key)
            },
            if let Some(unknown) = unknown {
                Check::Value(
                    unknown_key,
                    unknown.encode().map_err(std::io::Error::other)?,
                )
            } else {
                Check::Absent(unknown_key)
            },
            if let Some(claim) = claim {
                Check::Value(claim_key, claim.encode().map_err(std::io::Error::other)?)
            } else {
                Check::Absent(claim_key)
            },
        ];
        let transaction = StoreTransaction::try_from(StoreTransactionInput {
            operation_id: CommitOperationId::generate().map_err(std::io::Error::other)?,
            checks,
            mutations: Vec::new(),
            limits: transaction_limits(self.store.capabilities()),
        })?;
        match persist::block_on(self.store.commit(&transaction))? {
            CommitOutcome::Committed => Ok(()),
            CommitOutcome::Conflict => {
                Err(std::io::Error::other("connector raw-state check conflicted").into())
            }
            CommitOutcome::Unknown => {
                Err(std::io::Error::other("connector raw-state check was ambiguous").into())
            }
        }
    }
}

impl Driver for StoreProtocolDriver {
    type State = StateProjection;

    fn step(&mut self, step: &Step) -> Result {
        match step.action_taken.as_str() {
            "mbtInit" => self.reset_for_trace()?,
            "mbtObserve" => {}
            "mbtNondetStep" | "mbtStep" => {
                let command = self.command_from_step(step)?;
                self.apply_command(command)?;
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "unsupported store connector action: {other}"
                ))
                .into());
            }
        }
        Ok(())
    }
}

impl Drop for StoreProtocolDriver {
    fn drop(&mut self) {
        if self.require_command_coverage {
            let missing = ALL_COMMAND_FAMILIES
                .into_iter()
                .filter(|family| !self.covered_commands.contains(family))
                .collect::<Vec<_>>();
            assert!(
                missing.is_empty(),
                "bounded store command campaign missed command families: {missing:?}"
            );
        }
    }
}

fn command_family(command: &Command) -> &'static str {
    match command {
        Command::StoreEnqueue { .. } => "StoreEnqueue",
        Command::StoreSelectClaim { .. } => "StoreSelectClaim",
        Command::StoreClaim { .. } => "StoreClaim",
        Command::StoreRenew(_) => "StoreRenew",
        Command::StoreComplete(_) => "StoreComplete",
        Command::StoreDeadLetter { .. } => "StoreDeadLetter",
        Command::StoreRedrive { .. } => "StoreRedrive",
        Command::StoreUnknown { .. } => "StoreUnknown",
        Command::StoreReconcile { .. } => "StoreReconcile",
        Command::StoreCorrupt { .. } => "StoreCorrupt",
        Command::StoreDropRoute { .. } => "StoreDropRoute",
        Command::StoreRepair { .. } => "StoreRepair",
        Command::StorePurge { .. } => "StorePurge",
        Command::StoreAdvance { .. } => "StoreAdvance",
        Command::StoreExpire { .. } => "StoreExpire",
    }
}

fn payload_key(namespace: &Namespace, job: JobId) -> Result<StoreKey> {
    KeyCodec::encode(
        namespace,
        KeyTag::PayloadChunk,
        &[persist::actual_job_id(job).as_bytes(), &0_u32.to_be_bytes()],
    )
    .map_err(Into::into)
}

fn transaction_limits(capabilities: bg_jobs::store::StoreCapabilities) -> TransactionLimits {
    TransactionLimits {
        max_checks: capabilities.max_transaction_keys(),
        max_mutations: capabilities.max_transaction_keys(),
        max_bytes: capabilities.max_transaction_bytes(),
    }
}

fn number_from_bytes(bytes: &[u8; 16]) -> i64 {
    let mut tail = [0; 8];
    tail.copy_from_slice(&bytes[8..]);
    i64::from_be_bytes(tail)
}

fn number_bytes(value: i64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn advance_command(amount: i64) -> Command {
    Command::StoreAdvance { amount }
}

fn initial_transition(command: Command) -> LastTransition {
    LastTransition {
        command,
        class: ResultClass::AppliedClass,
        result: StoreResult::Committed,
        outcome: StoreOutcome::Initialised,
        detail: CompletionDetail::NoCompletionDetail,
        enqueue: EnqueueDisposition::NotEnqueue,
        job: JobId::JobA,
        operation: OperationId::OperationA,
    }
}

fn initial_records() -> Vec<(JobId, Record)> {
    vec![
        (
            JobId::JobA,
            base_record(
                true,
                RecordKind::Valid,
                1,
                false,
                true,
                true,
                true,
                false,
                true,
            ),
        ),
        (
            JobId::JobB,
            Record {
                enqueue_fingerprint: 11,
                payload_bytes: 12,
                manifest_bytes: 13,
                chunk_bytes: 14,
                digest_bytes: 15,
                checkpoint_bytes: 16,
                ..base_record(
                    true,
                    RecordKind::Valid,
                    1,
                    true,
                    true,
                    false,
                    false,
                    true,
                    false,
                )
            },
        ),
        (
            JobId::JobC,
            base_record(
                false,
                RecordKind::Valid,
                0,
                false,
                false,
                false,
                false,
                false,
                false,
            ),
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn base_record(
    exists: bool,
    kind: RecordKind,
    revision: i64,
    leased: bool,
    payload: bool,
    due_route: bool,
    fair_route: bool,
    lease_route: bool,
    wake_route: bool,
) -> Record {
    Record {
        exists,
        state: if !exists {
            JobState::Absent
        } else if leased {
            JobState::Leased
        } else {
            JobState::Scheduled
        },
        kind,
        revision,
        node: Node::NodeA,
        generation: if leased { 1 } else { 0 },
        fence: if leased { 1 } else { 0 },
        token: if leased { 3 } else { 0 },
        leased,
        lease_until: if leased { 3 } else { 0 },
        expires_at: 12,
        operation_id: OperationId::OperationA,
        enqueue_fingerprint: if exists { revision } else { 0 },
        execution_id: 1,
        attempt_id: if leased { 1 } else { 0 },
        attempts: if leased { 1 } else { 0 },
        payload_bytes: if payload { MAX_INLINE_PAYLOAD_BYTES } else { 0 },
        manifest_bytes: if payload { MAX_MANIFEST_BYTES } else { 0 },
        chunk_bytes: if payload { MAX_CHUNK_BYTES } else { 0 },
        digest_bytes: if payload { MAX_DIGEST_BYTES } else { 0 },
        checkpoint_bytes: 0,
        payload,
        failure_recorded: false,
        dlq_route: false,
        due_route,
        fair_route,
        lease_route,
        wake_route,
        permit_held: leased,
        rate_held: leased,
        in_flight: if leased { 1 } else { 0 },
        dangling: false,
    }
}

fn initial_trace() -> TraceState {
    TraceState {
        now: 0,
        quarantine_attempts: 0,
        last_enqueue_disposition: EnqueueDisposition::NotEnqueue,
        last_result: StoreResult::Committed,
        last_outcome: StoreOutcome::Initialised,
        transaction_checks: 0,
        transaction_mutations: 0,
        transaction_bytes: 0,
        repair_steps: 0,
        unrelated_progress: 0,
        completion_receipts: 0,
        completion_detail: CompletionDetail::NoCompletionDetail,
        last_detail: CompletionDetail::NoCompletionDetail,
        completion_detail_job: JobId::JobA,
    }
}

fn detail_at(receipts: i64) -> CompletionDetail {
    if receipts >= MAX_COMPLETION_RECEIPTS {
        CompletionDetail::CompletionDetailOmitted
    } else {
        CompletionDetail::CompletionDetailReturned
    }
}

/// Quint Connect exposes the selected inner action but not the nested ITF
/// value when `mbtDispatchNondet` wraps `mbtStep`.  Parse the serialized
pub(super) fn parse_command(input: &str) -> Result<Command> {
    let value = parse_rendered(input)?;
    let RenderedValue::Variant(name, payload) = value else {
        return Err(std::io::Error::other("serialized store command is not a variant").into());
    };
    match name.as_str() {
        "StoreEnqueue" => {
            let fields = record_fields(&payload, &name)?;
            let resources = record_fields(field(fields, "resources")?, "resources")?;
            Ok(Command::StoreEnqueue {
                job: job_id(field(fields, "job")?)?,
                operation: operation_id(field(fields, "operation")?)?,
                resources: ResourceInput {
                    payload_bytes: integer(field(resources, "payloadBytes")?)?,
                    manifest_bytes: integer(field(resources, "manifestBytes")?)?,
                    chunk_bytes: integer(field(resources, "chunkBytes")?)?,
                    digest_bytes: integer(field(resources, "digestBytes")?)?,
                    checkpoint_bytes: integer(field(resources, "checkpointBytes")?)?,
                },
                fingerprint: integer(field(fields, "fingerprint")?)?,
            })
        }
        "StoreSelectClaim" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StoreSelectClaim {
                job: job_id(field(fields, "job")?)?,
                reader: node(field(fields, "reader")?)?,
                revision: integer(field(fields, "revision")?)?,
            })
        }
        "StoreClaim" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StoreClaim {
                job: job_id(field(fields, "job")?)?,
                contender: node(field(fields, "contender")?)?,
                revision: integer(field(fields, "revision")?)?,
            })
        }
        "StoreRenew" | "StoreComplete" => {
            let authority = authority(&payload)?;
            if name == "StoreRenew" {
                Ok(Command::StoreRenew(authority))
            } else {
                Ok(Command::StoreComplete(authority))
            }
        }
        "StoreDeadLetter" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StoreDeadLetter {
                authority: authority(field(fields, "authority")?)?,
                handler: handler(field(fields, "handler")?)?,
            })
        }
        "StoreRedrive" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StoreRedrive {
                job: job_id(field(fields, "job")?)?,
                revision: integer(field(fields, "revision")?)?,
                operation: operation_id(field(fields, "operation")?)?,
                reuse_execution: boolean(field(fields, "reuseExecution")?)?,
            })
        }
        "StoreUnknown" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StoreUnknown {
                authority: authority(field(fields, "authority")?)?,
                committed: boolean(field(fields, "committed")?)?,
            })
        }
        "StoreReconcile" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StoreReconcile {
                job: job_id(field(fields, "job")?)?,
                operation: operation_id(field(fields, "operation")?)?,
                observed: store_result(field(fields, "observed")?)?,
            })
        }
        "StoreCorrupt" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StoreCorrupt {
                job: job_id(field(fields, "job")?)?,
                kind: record_kind(field(fields, "kind")?)?,
            })
        }
        "StoreDropRoute" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StoreDropRoute {
                job: job_id(field(fields, "job")?)?,
                due: boolean(field(fields, "due")?)?,
                fair: boolean(field(fields, "fair")?)?,
                lease: boolean(field(fields, "lease")?)?,
                wake: boolean(field(fields, "wake")?)?,
            })
        }
        "StoreRepair" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StoreRepair {
                job: job_id(field(fields, "job")?)?,
                revision: integer(field(fields, "revision")?)?,
                operation: operation_id(field(fields, "operation")?)?,
            })
        }
        "StorePurge" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StorePurge {
                job: job_id(field(fields, "job")?)?,
                revision: integer(field(fields, "revision")?)?,
            })
        }
        "StoreAdvance" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StoreAdvance {
                amount: integer(field(fields, "amount")?)?,
            })
        }
        "StoreExpire" => {
            let fields = record_fields(&payload, &name)?;
            Ok(Command::StoreExpire {
                job: job_id(field(fields, "job")?)?,
            })
        }
        other => Err(std::io::Error::other(format!(
            "unsupported serialized store command {other}"
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
            "store command {name} does not contain a record payload"
        ))
        .into()),
    }
}

fn field<'a>(fields: &'a BTreeMap<String, RenderedValue>, name: &str) -> Result<&'a RenderedValue> {
    fields.get(name).ok_or_else(|| {
        std::io::Error::other(format!("serialized store command is missing {name}")).into()
    })
}

fn integer(value: &RenderedValue) -> Result<i64> {
    match value {
        RenderedValue::Integer(value) => Ok(*value),
        _ => Err(std::io::Error::other(format!("expected store integer, got {value:?}")).into()),
    }
}

fn boolean(value: &RenderedValue) -> Result<bool> {
    match value {
        RenderedValue::Bool(value) => Ok(*value),
        _ => Err(std::io::Error::other(format!("expected store boolean, got {value:?}")).into()),
    }
}

fn atom<'a>(value: &'a RenderedValue, kind: &str) -> Result<&'a str> {
    match value {
        RenderedValue::Atom(value) => Ok(value),
        _ => Err(std::io::Error::other(format!("expected store {kind}, got {value:?}")).into()),
    }
}

fn node(value: &RenderedValue) -> Result<Node> {
    match atom(value, "node")? {
        "NodeA" => Ok(Node::NodeA),
        "NodeB" => Ok(Node::NodeB),
        _ => Err(std::io::Error::other(format!("expected store node, got {value:?}")).into()),
    }
}

fn job_id(value: &RenderedValue) -> Result<JobId> {
    match atom(value, "job")? {
        "JobA" => Ok(JobId::JobA),
        "JobB" => Ok(JobId::JobB),
        "JobC" => Ok(JobId::JobC),
        _ => Err(std::io::Error::other(format!("expected store job, got {value:?}")).into()),
    }
}

fn operation_id(value: &RenderedValue) -> Result<OperationId> {
    match atom(value, "operation")? {
        "OperationA" => Ok(OperationId::OperationA),
        "OperationB" => Ok(OperationId::OperationB),
        "OperationC" => Ok(OperationId::OperationC),
        "OperationD" => Ok(OperationId::OperationD),
        _ => Err(std::io::Error::other(format!("expected store operation, got {value:?}")).into()),
    }
}

fn next_operation_id(operation: OperationId) -> OperationId {
    match operation {
        OperationId::OperationA => OperationId::OperationB,
        OperationId::OperationB => OperationId::OperationC,
        OperationId::OperationC => OperationId::OperationD,
        OperationId::OperationD => OperationId::OperationA,
    }
}

fn store_result(value: &RenderedValue) -> Result<StoreResult> {
    match atom(value, "result")? {
        "Committed" => Ok(StoreResult::Committed),
        "Conflict" => Ok(StoreResult::Conflict),
        "AuthorityChanged" => Ok(StoreResult::AuthorityChanged),
        "Unknown" => Ok(StoreResult::Unknown),
        "Rejected" => Ok(StoreResult::Rejected),
        _ => Err(std::io::Error::other(format!("expected store result, got {value:?}")).into()),
    }
}

fn record_kind(value: &RenderedValue) -> Result<RecordKind> {
    match atom(value, "record kind")? {
        "Valid" => Ok(RecordKind::Valid),
        "Missing" => Ok(RecordKind::Missing),
        "Corrupt" => Ok(RecordKind::Corrupt),
        "UnknownVersion" => Ok(RecordKind::UnknownVersion),
        _ => {
            Err(std::io::Error::other(format!("expected store record kind, got {value:?}")).into())
        }
    }
}

fn handler(value: &RenderedValue) -> Result<HandlerResult> {
    match atom(value, "handler")? {
        "Success" => Ok(HandlerResult::Success),
        "Transient" => Ok(HandlerResult::Transient),
        "Throttled" => Ok(HandlerResult::Throttled),
        "Permanent" => Ok(HandlerResult::Permanent),
        "Ambiguous" => Ok(HandlerResult::Ambiguous),
        _ => Err(std::io::Error::other(format!("expected store handler, got {value:?}")).into()),
    }
}

fn authority(value: &RenderedValue) -> Result<AuthorityInput> {
    let fields = record_fields(value, "authority")?;
    Ok(AuthorityInput {
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
