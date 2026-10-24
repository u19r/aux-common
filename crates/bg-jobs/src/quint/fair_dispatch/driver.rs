//! Real-store adapter for the fair-dispatch MBT boundary.
//!
//! The driver deliberately keeps only opaque-id adaptation and the last
//! observed command result.  Candidate, scope, order, permit, batch, and job
//! values are read back from the durable `JobSystem`/`FakeStore` owner after
//! every command.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU16,
    time::Duration,
};

use bytes::Bytes;
use quint_connect::{Driver, Result, State, Step};
use serde::de::DeserializeOwned;

use super::{
    constants::{FAIR_RETRY_DUE_NOW_MILLIS, FAIR_RETRY_DUE_TICK, FAIR_RETRY_NOT_DUE_TICK},
    types::{
        self, AuthConfigId, BatchKey, BatchResult, BlockReason, CandidateInput, Command,
        CommandResult, EffectModeModel, FairJob, FairOutcome, HandlerKind, JobId, JobState,
        LastTransition, Meta, OrderState, OrderingGroup, Priority, RecordKind, ResultClass,
        RetryPolicyModel, Scope, ScopeState, SelectInput, StateProjection, TimeoutPolicyModel,
        VolumeMode,
    },
};
use crate::{
    FairnessPolicy, FakeStore, JobSystem,
    batch::{Batch, BatchResult as DurableBatchResult},
    codec::decode_job_record,
    drive::{
        FairDispatchCandidateSpec, fair_dispatch_batch_item, fair_dispatch_batch_start,
        fair_dispatch_configure, fair_dispatch_hol_escape, fair_dispatch_low_volume,
        fair_dispatch_release, fair_dispatch_scratch, fair_dispatch_select, fair_dispatch_service,
    },
    fairness::{
        CandidateBlock, FairBatchItemState, FairCandidateMetadata, FairCandidateSnapshot,
        FairDispatchOwner, FairPermit, FairScope,
    },
    ids::{FairnessKey, JobId as DurableJobId, JobKind, OrderingKey},
    keys,
    model::JobOutcome,
    policy::{
        EffectMode, FairnessClass, FairnessPath, Priority as DurablePriority, RetryClass,
        RetryPolicy, RetryPreset,
    },
    store::JobStore,
    test_helper::block_on,
    time::Timestamp,
};

struct ActiveClaim {
    permit: FairPermit,
    claim: crate::lifecycle::ClaimedJob,
}

pub(crate) struct FairDispatchDriver {
    system: JobSystem<FakeStore>,
    claims: BTreeMap<JobId, ActiveClaim>,
    batch: Option<Batch>,
    projection: StateProjection,
    last_command: Command,
    last_outcome: FairOutcome,
    last_class: ResultClass,
}

impl State<FairDispatchDriver> for StateProjection {
    fn from_driver(driver: &FairDispatchDriver) -> Result<Self> {
        Ok(driver.projection.clone())
    }
}

impl Default for FairDispatchDriver {
    fn default() -> Self {
        Self::try_default().unwrap_or_else(|error| panic!("fair connector setup: {error}"))
    }
}

impl FairDispatchDriver {
    #[cfg(test)]
    pub(crate) fn apply_action_for_test(&mut self, action: &str) -> Result<()> {
        self.apply_trace_action(action)
    }

    #[cfg(test)]
    pub(crate) fn projection_for_test(&self) -> &StateProjection {
        &self.projection
    }

    fn try_default() -> Result<Self> {
        let system = crate::test_helper::system(
            FakeStore::distributed(),
            FairnessPolicy::from(NonZeroU16::MIN),
            61,
        );
        let mut driver = Self {
            system,
            claims: BTreeMap::new(),
            batch: None,
            projection: initial_projection(),
            last_command: initial_command(),
            last_outcome: FairOutcome::Initialised,
            last_class: ResultClass::AppliedClass,
        };
        driver.configure(
            JobId::JobA,
            Scope::ScopeA,
            Priority::Critical,
            AuthConfigId::AuthConfigA,
            2,
            OrderingGroup::OrderA,
        )?;
        driver.configure(
            JobId::JobB,
            Scope::ScopeB,
            Priority::Default,
            AuthConfigId::AuthConfigA,
            2,
            OrderingGroup::OrderB,
        )?;
        driver.refresh(
            initial_command(),
            FairOutcome::Initialised,
            ResultClass::AppliedClass,
        )?;
        Ok(driver)
    }

    fn configure(
        &mut self,
        job: JobId,
        scope: Scope,
        priority: Priority,
        auth_config: AuthConfigId,
        cost: u16,
        ordering: OrderingGroup,
    ) -> Result<()> {
        let spec = candidate_spec(job, scope, priority, auth_config, cost, ordering)?;
        block_on(fair_dispatch_configure(&self.system, spec, Timestamp::ZERO))?;
        Ok(())
    }

    fn refresh(
        &mut self,
        command: Command,
        outcome: FairOutcome,
        class: ResultClass,
    ) -> Result<()> {
        let previous_selected_cost = self.projection.meta.selected_cost;
        let owner = block_on(FairDispatchOwner::load(&self.system))?.ok_or_else(|| {
            std::io::Error::other("fair owner was not persisted after connector action")
        })?;
        let job = command_job(&command);
        let candidate = owner.candidate_snapshot(durable_id(job));
        let transition =
            transition_from_actual(&owner, command.clone(), outcome, class, candidate)?;
        let result = match class {
            ResultClass::RejectedClass => CommandResult::FairRejected(transition.clone()),
            ResultClass::AppliedClass | ResultClass::ConflictClass | ResultClass::UnknownClass => {
                if matches!(
                    outcome,
                    FairOutcome::HeadBlocked
                        | FairOutcome::RateBlocked
                        | FairOutcome::CapacityBlocked
                ) {
                    CommandResult::FairBlockedResult {
                        transition: transition.clone(),
                        reason: transition.reason,
                    }
                } else if matches!(outcome, FairOutcome::BatchPartial) {
                    CommandResult::FairBatchResult {
                        transition: transition.clone(),
                        members: transition.members.clone(),
                        results: transition.results.clone(),
                    }
                } else {
                    CommandResult::FairApplied {
                        transition: transition.clone(),
                        batch_results: transition.results.clone(),
                    }
                }
            }
        };
        self.last_command = command;
        self.last_outcome = outcome;
        self.last_class = class;
        self.projection = project_actual(
            &self.system,
            &owner,
            self.last_command.clone(),
            transition,
            result,
            previous_selected_cost,
        )?;
        Ok(())
    }

    fn apply_trace_action(&mut self, action: &str) -> Result<()> {
        match action {
            "mbtInit" => *self = Self::try_default()?,
            "fixedBulkSeedTrace" | "fixedBulkSeed" => {
                self.fair_seed(JobId::JobC, Priority::Bulk)?
            }
            "fixedPrimaryBatchTrace" => self.primary_batch_step()?,
            "fixedSecondaryBatchTrace" => self.secondary_batch_step()?,
            "fixedBatchRejectionTrace" => self.rejected_batch_step()?,
            "fixedLiveAuthorityCandidateTrace" => self.live_authority_step()?,
            "fixedRetryDueTrace" => self.retry_due_step()?,
            "mbtObserve" => {
                let command = self.last_command.clone();
                self.refresh(command, self.last_outcome, self.last_class)?;
            }
            "FairSeed" | "FairBatchCandidate" | "FairSelect" | "FairRelease" | "FairTick"
            | "FairBlock" | "FairHolEscape" | "FairRefill" | "FairLowVolume" | "FairBatchStart"
            | "FairBatchItem" | "FairScratch" | "FairService" | "FairResetWindow" => {
                self.generic_action(action)?
            }
            action => {
                return Err(std::io::Error::other(format!(
                    "fair connector action not implemented: {action}"
                ))
                .into());
            }
        }
        Ok(())
    }

    fn fair_seed(&mut self, job: JobId, priority: Priority) -> Result<()> {
        let already_registered = block_on(FairDispatchOwner::load(&self.system))?
            .and_then(|owner| owner.candidate_state(durable_id(job)))
            .is_some();
        if already_registered {
            return self.refresh(
                Command::FairSeed { job, priority },
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        }
        let (scope, auth, cost, ordering) = match job {
            JobId::JobC => (
                Scope::ScopeA1,
                AuthConfigId::AuthConfigA,
                1,
                OrderingGroup::OrderB,
            ),
            JobId::JobA => (
                Scope::ScopeA,
                AuthConfigId::AuthConfigA,
                2,
                OrderingGroup::OrderA,
            ),
            JobId::JobB => (
                Scope::ScopeB,
                AuthConfigId::AuthConfigA,
                2,
                OrderingGroup::OrderB,
            ),
        };
        let spec = candidate_spec(job, scope, priority, auth, cost, ordering)?;
        let outcome = block_on(fair_dispatch_configure(&self.system, spec, Timestamp::ZERO));
        self.refresh(
            Command::FairSeed { job, priority },
            if outcome.is_ok() {
                FairOutcome::HeadReady
            } else {
                FairOutcome::SelectionRejected
            },
            if outcome.is_ok() {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
        )
    }

    fn fair_batch_candidate(&mut self, input: CandidateInput) -> Result<()> {
        let command = Command::FairBatchCandidate(input.clone());
        let already_configured = block_on(FairDispatchOwner::load(&self.system))?
            .as_ref()
            .and_then(|owner| owner.candidate_snapshot(durable_id(input.job)))
            .is_some_and(|candidate| candidate.state.has_ready_route())
            && self.candidate_matches(&input);
        if already_configured {
            return self.refresh(command, FairOutcome::HeadReady, ResultClass::AppliedClass);
        }
        let result: Result<()> = candidate_spec_from_input(&input).and_then(|spec| {
            block_on(fair_dispatch_configure(&self.system, spec, Timestamp::ZERO))
                .map_err(Into::into)
        });
        self.refresh(
            command,
            if result.is_ok() {
                FairOutcome::HeadReady
            } else {
                FairOutcome::SelectionRejected
            },
            if result.is_ok() {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
        )
    }

    fn fair_select(&mut self, input: CandidateInput) -> Result<()> {
        self.fair_select_at(input, 0)
    }

    fn fair_select_at(&mut self, input: CandidateInput, now: i64) -> Result<()> {
        let command = Command::FairSelect(SelectInput {
            candidate: input.clone(),
            now,
        });
        if !self.candidate_matches(&input) {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        }
        let now_timestamp = model_now(now);
        if self.durable_job_is_future(input.job, now_timestamp)? {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        }
        let result = block_on(fair_dispatch_select(
            &self.system,
            durable_id(input.job),
            now_timestamp,
        ));
        match result {
            Ok((permit, claim)) => {
                self.claims.insert(input.job, ActiveClaim { permit, claim });
                self.refresh(
                    command,
                    FairOutcome::SelectionServed,
                    ResultClass::AppliedClass,
                )
            }
            Err(_) => self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            ),
        }
    }

    fn fair_release(&mut self, input: CandidateInput, result: BatchResult) -> Result<()> {
        let command = Command::FairRelease {
            candidate: input.clone(),
            result,
        };
        if !self.candidate_matches(&input) {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        }
        let Some(active) = self.claims.remove(&input.job) else {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        };
        let outcome = model_job_outcome(result)?;
        let durable = DurableBatchResult {
            attempt_id: active.claim.attempt_id(),
            outcome,
        };
        let result = block_on(fair_dispatch_release(
            &self.system,
            active.permit,
            active.claim,
            durable,
            Timestamp::ZERO,
        ));
        self.refresh(
            command,
            if result.is_ok() {
                FairOutcome::ClaimReleased
            } else {
                FairOutcome::SelectionRejected
            },
            if result.is_ok() {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
        )
    }

    fn fair_tick(&mut self, cycle: i64) -> Result<()> {
        let command = Command::FairTick { cycle };
        let Some(mut owner) = block_on(FairDispatchOwner::load(&self.system))? else {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        };
        let allowed = cycle >= 0
            && i64::from(owner.priority_deficit().cycle()) == cycle
            && owner.tick_allowed(Timestamp::ZERO);
        if allowed {
            owner.tick();
            block_on(owner.save(&self.system))?;
        }
        self.refresh(
            command,
            if allowed {
                FairOutcome::QuietTick
            } else {
                FairOutcome::SelectionRejected
            },
            if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
        )
    }

    fn fair_block(&mut self, job: JobId, reason: BlockReason) -> Result<()> {
        let command = Command::FairBlock { job, reason };
        let Some(mut owner) = block_on(FairDispatchOwner::load(&self.system))? else {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        };
        let Some(block) = candidate_block(reason) else {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        };
        let allowed = owner.block_candidate(durable_id(job), block);
        if allowed {
            block_on(owner.save(&self.system))?;
        }
        self.refresh(
            command,
            if allowed {
                block_outcome(reason)
            } else {
                FairOutcome::SelectionRejected
            },
            if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
        )
    }

    fn fair_hol_escape(&mut self, blocked: JobId, input: CandidateInput) -> Result<()> {
        let command = Command::FairHolEscape {
            blocked,
            candidate: input.clone(),
        };
        let blocked_ready = self.projection.jobs.get(&blocked).is_some_and(|job| {
            job.state == JobState::Scheduled && job.block != BlockReason::Unblocked
        });
        let different_order = self
            .projection
            .jobs
            .get(&blocked)
            .zip(self.projection.jobs.get(&input.job))
            .is_some_and(|(blocked, candidate)| blocked.ordering != candidate.ordering);
        if !blocked_ready || !different_order || !self.candidate_matches(&input) {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        }
        let result = block_on(fair_dispatch_hol_escape(
            &self.system,
            durable_id(input.job),
            Timestamp::ZERO,
        ));
        match result {
            Ok((permit, claim)) => {
                self.claims.insert(input.job, ActiveClaim { permit, claim });
                self.refresh(command, FairOutcome::HolEscaped, ResultClass::AppliedClass)
            }
            Err(_) => self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            ),
        }
    }

    fn fair_refill(&mut self, scope: Scope, primary: Scope) -> Result<()> {
        let command = Command::FairRefill { scope, primary };
        let expected_primary = self
            .projection
            .scopes
            .get(&scope)
            .map(|value| value.primary);
        if expected_primary != Some(primary) {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        }
        let Some(mut owner) = block_on(FairDispatchOwner::load(&self.system))? else {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        };
        let allowed = owner.refill(&fair_scope(scope)?);
        if allowed {
            block_on(owner.save(&self.system))?;
        }
        self.refresh(
            command,
            if allowed {
                FairOutcome::ScopeRefilled
            } else {
                FairOutcome::SelectionRejected
            },
            if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
        )
    }

    fn fair_low_volume(&mut self, input: CandidateInput) -> Result<()> {
        let command = Command::FairLowVolume(input.clone());
        if input.mode != VolumeMode::LowVolume || !self.candidate_matches(&input) {
            return self.refresh(
                command,
                FairOutcome::LowVolumeRejected,
                ResultClass::RejectedClass,
            );
        }
        let result = block_on(fair_dispatch_low_volume(
            &self.system,
            durable_id(input.job),
            Timestamp::ZERO,
        ));
        match result {
            Ok((permit, claim)) => {
                self.claims.insert(input.job, ActiveClaim { permit, claim });
                self.refresh(
                    command,
                    FairOutcome::SelectionServed,
                    ResultClass::AppliedClass,
                )
            }
            Err(_) => self.refresh(
                command,
                FairOutcome::LowVolumeRejected,
                ResultClass::RejectedClass,
            ),
        }
    }

    fn fair_batch_start(
        &mut self,
        first: CandidateInput,
        second: CandidateInput,
        capacity: i64,
    ) -> Result<()> {
        let command = Command::FairBatchStart {
            first,
            second,
            capacity,
        };
        let (first, second, capacity) = match &command {
            Command::FairBatchStart {
                first,
                second,
                capacity,
            } => (first, second, *capacity),
            _ => unreachable!(),
        };
        if !self.candidate_matches(first) || !self.candidate_matches(second) {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        }
        let capacity = u16::try_from(capacity).unwrap_or(0);
        let formed = block_on(fair_dispatch_batch_start(
            &self.system,
            durable_id(first.job),
            durable_id(second.job),
            capacity,
            Timestamp::ZERO,
        ));
        match formed {
            Ok(formed) => {
                for (permit, claim) in formed.claims {
                    self.claims.insert(
                        model_id(claim.record().job_id),
                        ActiveClaim { permit, claim },
                    );
                }
                self.batch = Some(formed.batch);
                self.refresh(
                    command,
                    FairOutcome::BatchPartial,
                    ResultClass::AppliedClass,
                )
            }
            Err(_) => self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            ),
        }
    }

    fn fair_batch_item(&mut self, job: JobId, result: BatchResult) -> Result<()> {
        let command = Command::FairBatchItem { job, result };
        match self.submit_batch_item(job, result) {
            Ok(()) => Ok(()),
            Err(_) => self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            ),
        }
    }

    fn fair_scratch(&mut self, clear: bool, capacity: i64) -> Result<()> {
        let command = Command::FairScratch { clear, capacity };
        let capacity = usize::try_from(capacity).unwrap_or(0);
        let result = block_on(fair_dispatch_scratch(&self.system, clear, capacity));
        if result.is_ok() && clear {
            self.batch = None;
        }
        self.refresh(
            command,
            if result.is_ok() {
                if clear {
                    FairOutcome::ScratchCleared
                } else {
                    FairOutcome::ScratchShrunk
                }
            } else {
                FairOutcome::SelectionRejected
            },
            if result.is_ok() {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
        )
    }

    fn fair_service(&mut self, input: CandidateInput, refill_rate: bool) -> Result<()> {
        let command = Command::FairService {
            candidate: input.clone(),
            refill_rate,
        };
        if !self.candidate_matches(&input) {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        }
        if self.durable_job_is_future(input.job, Timestamp::ZERO)? {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        }
        let forced_bulk = block_on(FairDispatchOwner::load(&self.system))?
            .is_some_and(|owner| owner.service_forces_bulk(durable_id(input.job), Timestamp::ZERO));
        let result = block_on(fair_dispatch_service(
            &self.system,
            durable_id(input.job),
            refill_rate,
            Timestamp::ZERO,
        ));
        self.refresh(
            command,
            if result.is_ok() {
                if forced_bulk {
                    FairOutcome::BulkForced
                } else {
                    FairOutcome::SelectionServed
                }
            } else {
                FairOutcome::SelectionRejected
            },
            if result.is_ok() {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
        )
    }

    fn fair_reset_from_step(&mut self, step: &Step) -> Result<()> {
        let critical = pick::<i64>(step, "critical")?.unwrap_or(0);
        let default_window = pick::<i64>(step, "default")?.unwrap_or(0);
        let bulk = pick::<i64>(step, "bulk")?.unwrap_or(0);
        self.fair_reset_window(critical, default_window, bulk)
    }

    fn fair_reset_window(&mut self, critical: i64, default_window: i64, bulk: i64) -> Result<()> {
        let command = Command::FairResetWindow {
            critical,
            default: default_window,
            bulk,
        };
        let Some(mut owner) = block_on(FairDispatchOwner::load(&self.system))? else {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        };
        let current = owner.priority_deficit();
        let allowed = critical == i64::from(current.critical_window())
            && default_window == i64::from(current.default_window())
            && bulk == i64::from(current.bulk_window())
            && current.critical_window() == 8
            && current.default_window() == 4
            && current.bulk_window() == 1;
        if allowed {
            owner.reset_priority_window();
            block_on(owner.save(&self.system))?;
        }
        self.refresh(
            command,
            if allowed {
                FairOutcome::HeadReady
            } else {
                FairOutcome::SelectionRejected
            },
            if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
        )
    }

    fn actual_candidate(&self, job: JobId) -> Result<CandidateInput> {
        let value = self
            .projection
            .jobs
            .get(&job)
            .ok_or_else(|| std::io::Error::other("fair connector candidate is absent"))?;
        let scope = self
            .projection
            .scopes
            .get(&value.scope)
            .ok_or_else(|| std::io::Error::other("fair connector scope is absent"))?;
        let primary = self
            .projection
            .scopes
            .get(&scope.primary)
            .ok_or_else(|| std::io::Error::other("fair connector primary scope is absent"))?;
        let order = self
            .projection
            .orders
            .get(&value.ordering)
            .ok_or_else(|| std::io::Error::other("fair connector ordering state is absent"))?;
        Ok(CandidateInput {
            job,
            scope: value.scope,
            primary: scope.primary,
            priority: value.priority,
            cost: value.cost,
            ordering: value.ordering,
            order: value.order,
            order_head: order.head,
            order_in_flight: order.in_flight,
            permits: scope.permits,
            rate: scope.rate,
            in_flight: scope.in_flight,
            primary_permits: primary.permits,
            primary_rate: primary.rate,
            primary_in_flight: primary.in_flight,
            payload_bytes: value.payload_bytes,
            handler_kind: value.handler_kind,
            schema_version: value.schema_version,
            batch_key: value.batch_key,
            auth_config: value.auth_config,
            effect_mode: value.effect_mode,
            retry_policy: value.retry_policy,
            timeout_policy: value.timeout_policy,
            enqueued_at: value.enqueued_at,
            batch_deadline: value.batch_deadline,
            mode: scope.mode,
        })
    }

    fn candidate_matches(&self, input: &CandidateInput) -> bool {
        self.actual_candidate(input.job)
            .is_ok_and(|actual| actual == *input)
    }

    fn durable_job_is_future(&self, job: JobId, now: Timestamp) -> Result<bool> {
        let key = keys::job_key(self.system.namespace(), &durable_id(job))?;
        let Some(encoded) = block_on(self.system.store().get(key))? else {
            return Ok(false);
        };
        let record = decode_job_record(&encoded)?;
        Ok(record.scheduled_at > now)
    }

    fn fair_service_error(&mut self, job: JobId) -> Result<()> {
        let command = self.last_command.clone();
        let Some(mut owner) = block_on(FairDispatchOwner::load(&self.system))? else {
            return self.refresh(
                command,
                FairOutcome::SelectionRejected,
                ResultClass::RejectedClass,
            );
        };
        let allowed = owner.record_service_error(durable_id(job), Timestamp::ZERO);
        if allowed {
            block_on(owner.save(&self.system))?;
        }
        self.refresh(
            command,
            if allowed {
                FairOutcome::ServiceErrorRecorded
            } else {
                FairOutcome::SelectionRejected
            },
            if allowed {
                ResultClass::AppliedClass
            } else {
                ResultClass::RejectedClass
            },
        )
    }

    fn fair_priority_witness_step(&mut self) -> Result<()> {
        if self
            .projection
            .jobs
            .get(&JobId::JobC)
            .is_some_and(|job| job.state == JobState::Absent)
        {
            return self.fair_seed(JobId::JobC, Priority::Bulk);
        }
        let job = match self.projection.meta.service_transitions {
            0 | 2 | 4 | 6 => JobId::JobA,
            8 => JobId::JobC,
            _ => JobId::JobB,
        };
        self.fair_service(self.actual_candidate(job)?, true)
    }

    fn fair_compatible_batch_witness_step(&mut self) -> Result<()> {
        let first = self.actual_candidate(JobId::JobA)?;
        let second = self.actual_candidate(JobId::JobB)?;
        self.fair_batch_start(first, second, self.projection.meta.scratch_capacity)
    }

    fn fair_resolved_batch_clear_witness_step(&mut self) -> Result<()> {
        if !self.projection.meta.batch_active {
            return self.fair_compatible_batch_witness_step();
        }
        if self.projection.meta.batch_results.get(&JobId::JobA) == Some(&BatchResult::ItemMissing) {
            return self.fair_batch_item(JobId::JobA, BatchResult::ItemSuccess);
        }
        if self.projection.meta.batch_results.get(&JobId::JobB) == Some(&BatchResult::ItemMissing) {
            return self.fair_batch_item(JobId::JobB, BatchResult::ItemSuccess);
        }
        self.fair_scratch(true, self.projection.meta.scratch_capacity)
    }

    fn apply_generated_step(&mut self, step: &Step) -> Result<()> {
        if let Some(command) = pick::<Command>(step, "command")? {
            return self.apply_model_command(command);
        }
        let candidate = pick::<CandidateInput>(step, "candidate")?;
        let input = pick::<CandidateInput>(step, "input")?;
        let result = pick::<BatchResult>(step, "result")?;
        if let (Some(input), Some(now)) = (input.clone(), pick::<i64>(step, "now")?) {
            return self.fair_select_at(input, now);
        }
        if let (Some(first), Some(second), Some(capacity)) = (
            pick::<CandidateInput>(step, "first")?,
            pick::<CandidateInput>(step, "second")?,
            pick::<i64>(step, "capacity")?,
        ) {
            return self.fair_batch_start(first, second, capacity);
        }
        if let (Some(blocked), Some(candidate)) =
            (pick::<JobId>(step, "blocked")?, candidate.clone())
        {
            return self.fair_hol_escape(blocked, candidate);
        }
        if let (Some(scope), Some(primary)) = (
            pick::<Scope>(step, "scope")?,
            pick::<Scope>(step, "primary")?,
        ) {
            return self.fair_refill(scope, primary);
        }
        if let (Some(clear), Some(capacity)) =
            (pick::<bool>(step, "clear")?, pick::<i64>(step, "capacity")?)
        {
            return self.fair_scratch(clear, capacity);
        }
        if let (Some(candidate), Some(refill_rate)) =
            (candidate.clone(), pick::<bool>(step, "refillRate")?)
        {
            return self.fair_service(candidate, refill_rate);
        }
        if let (Some(candidate), Some(result)) = (candidate.clone(), result) {
            return self.fair_release(candidate, result);
        }
        if let (Some(job), Some(result)) = (pick::<JobId>(step, "job")?, result) {
            return self.fair_batch_item(job, result);
        }
        if let (Some(job), Some(reason)) = (
            pick::<JobId>(step, "job")?,
            pick::<BlockReason>(step, "reason")?,
        ) {
            return self.fair_block(job, reason);
        }
        if let Some(cycle) = pick::<i64>(step, "cycle")? {
            return self.fair_tick(cycle);
        }
        if let (Some(critical), Some(default_window), Some(bulk)) = (
            pick::<i64>(step, "critical")?,
            pick::<i64>(step, "default")?,
            pick::<i64>(step, "bulk")?,
        ) {
            return self.fair_reset_window(critical, default_window, bulk);
        }
        if let (Some(job), Some(priority)) = (
            pick::<JobId>(step, "job")?,
            pick::<Priority>(step, "priority")?,
        ) {
            return self.fair_seed(job, priority);
        }
        if let Some(input) = input {
            let owner = block_on(FairDispatchOwner::load(&self.system))?;
            let use_low_volume = input.mode == VolumeMode::LowVolume;
            let configured = owner
                .as_ref()
                .and_then(|owner| owner.candidate_snapshot(durable_id(input.job)));
            if use_low_volume
                || configured.is_some_and(|candidate| candidate.state.has_ready_route())
            {
                if use_low_volume {
                    return self.fair_low_volume(input);
                }
                return self.fair_select(input);
            }
            return self.fair_batch_candidate(input);
        }
        if let Some(candidate) = candidate {
            let owner = block_on(FairDispatchOwner::load(&self.system))?;
            let configured = owner
                .as_ref()
                .and_then(|owner| owner.candidate_snapshot(durable_id(candidate.job)));
            if configured.is_some_and(|candidate| candidate.state.has_ready_route()) {
                return self.fair_select(candidate);
            }
            return self.fair_batch_candidate(candidate);
        }
        self.apply_model_command(self.command_from_step(step)?)
    }

    /// `mbtDispatchNondet` wraps each typed command in `mbtStep`.  Quint
    /// Connect exposes the inner action name but, for this wrapper shape,
    /// does not expose the command argument as a nondeterministic pick.  The
    /// next-state projection does retain `lastCommand`; recover only its
    /// variant tag and derive the input from the actual pre-step projection.
    /// Direct `mbtStep` traces with a command pick take the deserialization
    /// path above.
    fn command_from_step(&self, step: &Step) -> Result<Command> {
        let rendered = step.to_string();
        let line = rendered
            .lines()
            .find(|line| line.starts_with("+ lastCommand: "))
            .ok_or_else(|| std::io::Error::other("fair step has no serialized command"))?;
        let name = line
            .strip_prefix("+ lastCommand: ")
            .and_then(|value| value.split(['(', '{']).next())
            .map(str::trim)
            .ok_or_else(|| std::io::Error::other("fair command tag is missing"))?;
        let meta = &self.projection.meta;
        let candidate = |job| self.actual_candidate(job);
        let command = match name {
            "FairSeed" => Command::FairSeed {
                job: JobId::JobC,
                priority: Priority::Bulk,
            },
            "FairBatchCandidate" => Command::FairBatchCandidate(candidate(JobId::JobA)?),
            "FairSelect" => Command::FairSelect(SelectInput {
                candidate: candidate(meta.selected_job)?,
                now: 0,
            }),
            "FairRelease" => Command::FairRelease {
                candidate: candidate(meta.selected_job)?,
                result: BatchResult::ItemRetry,
            },
            "FairTick" => Command::FairTick { cycle: meta.cycle },
            "FairBlock" => Command::FairBlock {
                job: JobId::JobA,
                reason: BlockReason::RateLimitedHead,
            },
            "FairHolEscape" => Command::FairHolEscape {
                blocked: JobId::JobA,
                candidate: candidate(JobId::JobB)?,
            },
            "FairRefill" => {
                let scope = meta.selected_scope;
                Command::FairRefill {
                    scope,
                    primary: self
                        .projection
                        .scopes
                        .get(&scope)
                        .ok_or_else(|| std::io::Error::other("fair scope is absent"))?
                        .primary,
                }
            }
            "FairLowVolume" => Command::FairLowVolume(candidate(JobId::JobC)?),
            "FairBatchStart" => Command::FairBatchStart {
                first: candidate(JobId::JobB)?,
                second: candidate(JobId::JobC)?,
                capacity: meta.scratch_capacity,
            },
            "FairBatchItem" => Command::FairBatchItem {
                job: meta.selected_job,
                result: BatchResult::ItemSuccess,
            },
            "FairScratch" => Command::FairScratch {
                clear: true,
                capacity: meta.scratch_capacity,
            },
            "FairService" => Command::FairService {
                candidate: candidate(meta.selected_job)?,
                refill_rate: true,
            },
            "FairResetWindow" => Command::FairResetWindow {
                critical: meta.critical_window,
                default: meta.default_window,
                bulk: meta.bulk_window,
            },
            other => {
                return Err(
                    std::io::Error::other(format!("unknown fair command tag: {other}")).into(),
                );
            }
        };
        Ok(command)
    }

    fn apply_model_command(&mut self, command: Command) -> Result<()> {
        match command {
            Command::FairSeed { job, priority } => self.fair_seed(job, priority),
            Command::FairBatchCandidate(input) => self.fair_batch_candidate(input),
            Command::FairSelect(input) => self.fair_select_at(input.candidate, input.now),
            Command::FairRelease { candidate, result } => self.fair_release(candidate, result),
            Command::FairTick { cycle } => self.fair_tick(cycle),
            Command::FairBlock { job, reason } => self.fair_block(job, reason),
            Command::FairHolEscape { blocked, candidate } => {
                self.fair_hol_escape(blocked, candidate)
            }
            Command::FairRefill { scope, primary } => self.fair_refill(scope, primary),
            Command::FairLowVolume(input) => self.fair_low_volume(input),
            Command::FairBatchStart {
                first,
                second,
                capacity,
            } => self.fair_batch_start(first, second, capacity),
            Command::FairBatchItem { job, result } => self.fair_batch_item(job, result),
            Command::FairScratch { clear, capacity } => self.fair_scratch(clear, capacity),
            Command::FairService {
                candidate,
                refill_rate,
            } => self.fair_service(candidate, refill_rate),
            Command::FairResetWindow {
                critical,
                default,
                bulk,
            } => self.fair_reset_window(critical, default, bulk),
        }
    }

    fn generic_action(&mut self, action: &str) -> Result<()> {
        match action {
            "FairSeed" => {
                if !is_configured(
                    &self.system,
                    JobId::JobC,
                    Scope::ScopeA1,
                    Priority::Bulk,
                    AuthConfigId::AuthConfigA,
                )? {
                    self.configure(
                        JobId::JobC,
                        Scope::ScopeA1,
                        Priority::Bulk,
                        AuthConfigId::AuthConfigA,
                        1,
                        OrderingGroup::OrderB,
                    )?;
                }
                self.refresh(
                    Command::FairSeed {
                        job: JobId::JobC,
                        priority: Priority::Bulk,
                    },
                    FairOutcome::HeadReady,
                    ResultClass::AppliedClass,
                )
            }
            "FairBatchCandidate" => {
                let (job, scope, priority, auth, cost, ordering) = if !is_configured(
                    &self.system,
                    JobId::JobA,
                    Scope::ScopeA,
                    Priority::Critical,
                    AuthConfigId::AuthConfigA,
                )? {
                    (
                        JobId::JobA,
                        Scope::ScopeA,
                        Priority::Critical,
                        AuthConfigId::AuthConfigA,
                        2,
                        OrderingGroup::OrderA,
                    )
                } else {
                    (
                        JobId::JobB,
                        Scope::ScopeA,
                        Priority::Critical,
                        AuthConfigId::AuthConfigA,
                        2,
                        OrderingGroup::OrderB,
                    )
                };
                self.configure(job, scope, priority, auth, cost, ordering)?;
                self.refresh_candidate_action(job, scope, priority, auth, ordering)
            }
            "FairSelect" => {
                let owner = block_on(FairDispatchOwner::load(&self.system))?.ok_or_else(|| {
                    std::io::Error::other("fair owner is absent before selection")
                })?;
                let job = [JobId::JobA, JobId::JobB, JobId::JobC]
                    .into_iter()
                    .find(|job| {
                        owner
                            .candidate_snapshot(durable_id(*job))
                            .is_some_and(|candidate| candidate.state.has_ready_route())
                    })
                    .ok_or_else(|| std::io::Error::other("no ready candidate before selection"))?;
                let (permit, claim) = block_on(fair_dispatch_select(
                    &self.system,
                    durable_id(job),
                    Timestamp::ZERO,
                ))?;
                self.claims.insert(job, ActiveClaim { permit, claim });
                let (scope, priority, auth, cost, ordering) = default_candidate_for(job);
                self.refresh(
                    Command::FairSelect(SelectInput {
                        candidate: candidate_input(job, scope, priority, auth, ordering, cost)?,
                        now: 0,
                    }),
                    FairOutcome::SelectionServed,
                    ResultClass::AppliedClass,
                )
            }
            "FairRelease" => {
                let (job, active) = self
                    .claims
                    .pop_first()
                    .ok_or_else(|| std::io::Error::other("no claim before release"))?;
                let attempt_id = active.claim.attempt_id();
                let outcome =
                    JobOutcome::Complete(crate::policy::OutcomeCode::try_new("fair_complete")?);
                block_on(fair_dispatch_release(
                    &self.system,
                    active.permit,
                    active.claim,
                    DurableBatchResult {
                        attempt_id,
                        outcome,
                    },
                    Timestamp::ZERO,
                ))?;
                let (scope, priority, auth, cost, ordering) = default_candidate_for(job);
                self.refresh(
                    Command::FairRelease {
                        candidate: candidate_input(job, scope, priority, auth, ordering, cost)?,
                        result: BatchResult::ItemSuccess,
                    },
                    FairOutcome::ClaimReleased,
                    ResultClass::AppliedClass,
                )
            }
            "FairTick" => {
                let owner = block_on(FairDispatchOwner::load(&self.system))?
                    .ok_or_else(|| std::io::Error::other("fair owner is absent before tick"))?;
                let cycle = owner.priority_deficit().cycle();
                drop(owner);
                self.fair_tick(i64::from(cycle))
            }
            "FairBlock" => {
                let owner = block_on(FairDispatchOwner::load(&self.system))?
                    .ok_or_else(|| std::io::Error::other("fair owner is absent before block"))?;
                let job = [JobId::JobA, JobId::JobB, JobId::JobC]
                    .into_iter()
                    .find(|job| {
                        owner
                            .candidate_snapshot(durable_id(*job))
                            .is_some_and(|candidate| candidate.state.has_ready_route())
                    })
                    .ok_or_else(|| std::io::Error::other("no ready candidate before block"))?;
                self.fair_block(job, BlockReason::RateLimitedHead)
            }
            "FairHolEscape" => {
                let job = JobId::JobB;
                let (permit, claim) = block_on(fair_dispatch_hol_escape(
                    &self.system,
                    durable_id(job),
                    Timestamp::ZERO,
                ))?;
                self.claims.insert(job, ActiveClaim { permit, claim });
                let (scope, priority, auth, cost, ordering) = default_candidate_for(job);
                self.refresh(
                    Command::FairHolEscape {
                        blocked: JobId::JobA,
                        candidate: candidate_input(job, scope, priority, auth, ordering, cost)?,
                    },
                    FairOutcome::HolEscaped,
                    ResultClass::AppliedClass,
                )
            }
            "FairRefill" => self.fair_refill(Scope::ScopeA, Scope::ScopeA),
            "FairLowVolume" => {
                if !is_configured(
                    &self.system,
                    JobId::JobC,
                    Scope::ScopeA1,
                    Priority::Bulk,
                    AuthConfigId::AuthConfigA,
                )? {
                    self.configure(
                        JobId::JobC,
                        Scope::ScopeA1,
                        Priority::Bulk,
                        AuthConfigId::AuthConfigA,
                        1,
                        OrderingGroup::OrderB,
                    )?;
                }
                let (permit, claim) = block_on(fair_dispatch_low_volume(
                    &self.system,
                    durable_id(JobId::JobC),
                    Timestamp::ZERO,
                ))?;
                self.claims
                    .insert(JobId::JobC, ActiveClaim { permit, claim });
                self.refresh(
                    Command::FairLowVolume(candidate_input(
                        JobId::JobC,
                        Scope::ScopeA1,
                        Priority::Bulk,
                        AuthConfigId::AuthConfigA,
                        OrderingGroup::OrderB,
                        1,
                    )?),
                    FairOutcome::SelectionServed,
                    ResultClass::AppliedClass,
                )
            }
            "FairBatchStart" => {
                let formed = block_on(fair_dispatch_batch_start(
                    &self.system,
                    durable_id(JobId::JobA),
                    durable_id(JobId::JobB),
                    3,
                    Timestamp::ZERO,
                ));
                match formed {
                    Ok(formed) => {
                        for (permit, claim) in formed.claims {
                            self.claims.insert(
                                model_id(claim.record().job_id),
                                ActiveClaim { permit, claim },
                            );
                        }
                        self.batch = Some(formed.batch);
                        self.refresh(
                            Command::FairBatchStart {
                                first: candidate_input(
                                    JobId::JobA,
                                    Scope::ScopeA,
                                    Priority::Critical,
                                    AuthConfigId::AuthConfigA,
                                    OrderingGroup::OrderA,
                                    2,
                                )?,
                                second: candidate_input(
                                    JobId::JobB,
                                    Scope::ScopeA,
                                    Priority::Critical,
                                    AuthConfigId::AuthConfigA,
                                    OrderingGroup::OrderB,
                                    2,
                                )?,
                                capacity: 3,
                            },
                            FairOutcome::BatchPartial,
                            ResultClass::AppliedClass,
                        )
                    }
                    Err(_) => self.refresh(
                        Command::FairBatchStart {
                            first: candidate_input(
                                JobId::JobA,
                                Scope::ScopeA,
                                Priority::Critical,
                                AuthConfigId::AuthConfigA,
                                OrderingGroup::OrderA,
                                2,
                            )?,
                            second: candidate_input(
                                JobId::JobB,
                                Scope::ScopeA,
                                Priority::Critical,
                                AuthConfigId::AuthConfigA,
                                OrderingGroup::OrderB,
                                2,
                            )?,
                            capacity: 3,
                        },
                        FairOutcome::SelectionRejected,
                        ResultClass::RejectedClass,
                    ),
                }
            }
            "FairBatchItem" => {
                let job = if self.claims.contains_key(&JobId::JobA) {
                    JobId::JobA
                } else {
                    JobId::JobB
                };
                self.fair_batch_item(job, BatchResult::ItemSuccess)
            }
            "FairScratch" => self.fair_scratch(self.batch.is_some(), 3),
            "FairService" => self.fair_service(self.actual_candidate(JobId::JobA)?, true),
            "FairResetWindow" => {
                self.fair_reset_window(
                    self.projection.meta.critical_window,
                    self.projection.meta.default_window,
                    self.projection.meta.bulk_window,
                )?;
                Ok(())
            }
            _ => Err(std::io::Error::other("unknown fair action").into()),
        }
    }

    fn primary_batch_step(&mut self) -> Result<()> {
        if self.batch.is_none()
            && !is_configured(
                &self.system,
                JobId::JobA,
                Scope::ScopeA,
                Priority::Critical,
                AuthConfigId::AuthConfigA,
            )?
        {
            self.configure(
                JobId::JobA,
                Scope::ScopeA,
                Priority::Critical,
                AuthConfigId::AuthConfigA,
                2,
                OrderingGroup::OrderA,
            )?;
            return self.refresh_candidate_action(
                JobId::JobA,
                Scope::ScopeA,
                Priority::Critical,
                AuthConfigId::AuthConfigA,
                OrderingGroup::OrderA,
            );
        }
        if self.batch.is_none()
            && !is_configured(
                &self.system,
                JobId::JobB,
                Scope::ScopeA,
                Priority::Critical,
                AuthConfigId::AuthConfigA,
            )?
        {
            self.configure(
                JobId::JobB,
                Scope::ScopeA,
                Priority::Critical,
                AuthConfigId::AuthConfigA,
                2,
                OrderingGroup::OrderB,
            )?;
            return self.refresh_candidate_action(
                JobId::JobB,
                Scope::ScopeA,
                Priority::Critical,
                AuthConfigId::AuthConfigA,
                OrderingGroup::OrderB,
            );
        }
        if self.batch.is_none() {
            let formed = block_on(fair_dispatch_batch_start(
                &self.system,
                durable_id(JobId::JobA),
                durable_id(JobId::JobB),
                3,
                Timestamp::ZERO,
            ));
            match formed {
                Ok(batch) => {
                    for (permit, claim) in batch.claims {
                        self.claims.insert(
                            model_id(claim.record().job_id),
                            ActiveClaim { permit, claim },
                        );
                    }
                    self.batch = Some(batch.batch);
                    self.refresh(
                        Command::FairBatchStart {
                            first: candidate_input(
                                JobId::JobA,
                                Scope::ScopeA,
                                Priority::Critical,
                                AuthConfigId::AuthConfigA,
                                OrderingGroup::OrderA,
                                2,
                            )?,
                            second: candidate_input(
                                JobId::JobB,
                                Scope::ScopeA,
                                Priority::Critical,
                                AuthConfigId::AuthConfigA,
                                OrderingGroup::OrderB,
                                2,
                            )?,
                            capacity: 3,
                        },
                        FairOutcome::BatchPartial,
                        ResultClass::AppliedClass,
                    )?;
                }
                Err(_) => {
                    self.refresh(
                        Command::FairBatchStart {
                            first: candidate_input(
                                JobId::JobA,
                                Scope::ScopeA,
                                Priority::Critical,
                                AuthConfigId::AuthConfigA,
                                OrderingGroup::OrderA,
                                2,
                            )?,
                            second: candidate_input(
                                JobId::JobB,
                                Scope::ScopeA,
                                Priority::Critical,
                                AuthConfigId::AuthConfigA,
                                OrderingGroup::OrderB,
                                2,
                            )?,
                            capacity: 3,
                        },
                        FairOutcome::SelectionRejected,
                        ResultClass::RejectedClass,
                    )?;
                }
            }
            return Ok(());
        }
        if self.batch.as_ref().is_some_and(|_| {
            self.projection.meta.batch_results.get(&JobId::JobA) == Some(&BatchResult::ItemMissing)
        }) {
            self.submit_batch_item(JobId::JobA, BatchResult::ItemSuccess)?;
            return Ok(());
        }
        if self.batch.as_ref().is_some_and(|_| {
            self.projection.meta.batch_results.get(&JobId::JobB) == Some(&BatchResult::ItemMissing)
        }) {
            self.submit_batch_item(JobId::JobB, BatchResult::ItemDeadLetter)?;
            return Ok(());
        }
        block_on(fair_dispatch_scratch(&self.system, true, 3))?;
        self.batch = None;
        self.refresh(
            Command::FairScratch {
                clear: true,
                capacity: 3,
            },
            FairOutcome::ScratchCleared,
            ResultClass::AppliedClass,
        )
    }

    fn secondary_batch_step(&mut self) -> Result<()> {
        if !is_configured(
            &self.system,
            JobId::JobA,
            Scope::ScopeA2,
            Priority::Default,
            AuthConfigId::AuthConfigA,
        )? {
            self.configure(
                JobId::JobA,
                Scope::ScopeA2,
                Priority::Default,
                AuthConfigId::AuthConfigA,
                1,
                OrderingGroup::OrderA,
            )?;
            return self.refresh_candidate_action(
                JobId::JobA,
                Scope::ScopeA2,
                Priority::Default,
                AuthConfigId::AuthConfigA,
                OrderingGroup::OrderA,
            );
        }
        if !is_configured(
            &self.system,
            JobId::JobB,
            Scope::ScopeA2,
            Priority::Default,
            AuthConfigId::AuthConfigA,
        )? {
            self.configure(
                JobId::JobB,
                Scope::ScopeA2,
                Priority::Default,
                AuthConfigId::AuthConfigA,
                1,
                OrderingGroup::OrderB,
            )?;
            return self.refresh_candidate_action(
                JobId::JobB,
                Scope::ScopeA2,
                Priority::Default,
                AuthConfigId::AuthConfigA,
                OrderingGroup::OrderB,
            );
        }
        let formed = block_on(fair_dispatch_batch_start(
            &self.system,
            durable_id(JobId::JobA),
            durable_id(JobId::JobB),
            3,
            Timestamp::ZERO,
        ))
        .map_err(|error| std::io::Error::other(format!("secondary batch start: {error}")))?;
        for (permit, claim) in formed.claims {
            self.claims.insert(
                model_id(claim.record().job_id),
                ActiveClaim { permit, claim },
            );
        }
        self.batch = Some(formed.batch);
        self.refresh(
            Command::FairBatchStart {
                first: candidate_input(
                    JobId::JobA,
                    Scope::ScopeA2,
                    Priority::Default,
                    AuthConfigId::AuthConfigA,
                    OrderingGroup::OrderA,
                    1,
                )?,
                second: candidate_input(
                    JobId::JobB,
                    Scope::ScopeA2,
                    Priority::Default,
                    AuthConfigId::AuthConfigA,
                    OrderingGroup::OrderB,
                    1,
                )?,
                capacity: 3,
            },
            FairOutcome::BatchPartial,
            ResultClass::AppliedClass,
        )
    }

    fn rejected_batch_step(&mut self) -> Result<()> {
        if !is_configured(
            &self.system,
            JobId::JobA,
            Scope::ScopeA,
            Priority::Critical,
            AuthConfigId::AuthConfigA,
        )? {
            self.configure(
                JobId::JobA,
                Scope::ScopeA,
                Priority::Critical,
                AuthConfigId::AuthConfigA,
                2,
                OrderingGroup::OrderA,
            )?;
            return self.refresh_candidate_action(
                JobId::JobA,
                Scope::ScopeA,
                Priority::Critical,
                AuthConfigId::AuthConfigA,
                OrderingGroup::OrderA,
            );
        }
        if !is_configured(
            &self.system,
            JobId::JobB,
            Scope::ScopeA,
            Priority::Critical,
            AuthConfigId::AuthConfigB,
        )? {
            self.configure(
                JobId::JobB,
                Scope::ScopeA,
                Priority::Critical,
                AuthConfigId::AuthConfigB,
                2,
                OrderingGroup::OrderB,
            )?;
            return self.refresh_candidate_action(
                JobId::JobB,
                Scope::ScopeA,
                Priority::Critical,
                AuthConfigId::AuthConfigB,
                OrderingGroup::OrderB,
            );
        }
        let first = candidate_input(
            JobId::JobA,
            Scope::ScopeA,
            Priority::Critical,
            AuthConfigId::AuthConfigA,
            OrderingGroup::OrderA,
            2,
        )?;
        let second = candidate_input(
            JobId::JobB,
            Scope::ScopeA,
            Priority::Critical,
            AuthConfigId::AuthConfigB,
            OrderingGroup::OrderB,
            2,
        )?;
        let _ = block_on(fair_dispatch_batch_start(
            &self.system,
            durable_id(JobId::JobA),
            durable_id(JobId::JobB),
            3,
            Timestamp::ZERO,
        ));
        self.refresh(
            Command::FairBatchStart {
                first,
                second,
                capacity: 3,
            },
            FairOutcome::SelectionRejected,
            ResultClass::RejectedClass,
        )
    }

    fn live_authority_step(&mut self) -> Result<()> {
        if !self.claims.contains_key(&JobId::JobA) {
            let (permit, claim) = block_on(fair_dispatch_select(
                &self.system,
                durable_id(JobId::JobA),
                Timestamp::ZERO,
            ))?;
            self.claims
                .insert(JobId::JobA, ActiveClaim { permit, claim });
            self.refresh(
                Command::FairSelect(SelectInput {
                    candidate: candidate_input(
                        JobId::JobA,
                        Scope::ScopeA,
                        Priority::Critical,
                        AuthConfigId::AuthConfigA,
                        OrderingGroup::OrderA,
                        2,
                    )?,
                    now: 0,
                }),
                FairOutcome::SelectionServed,
                ResultClass::AppliedClass,
            )?;
            return Ok(());
        }
        let spec = candidate_spec(
            JobId::JobB,
            Scope::ScopeA,
            Priority::Critical,
            AuthConfigId::AuthConfigA,
            2,
            OrderingGroup::OrderB,
        )?;
        let result = block_on(fair_dispatch_configure(&self.system, spec, Timestamp::ZERO));
        if result.is_ok() {
            return Err(std::io::Error::other(
                "leased fair authority accepted a candidate replacement",
            )
            .into());
        }
        self.refresh(
            Command::FairBatchCandidate(candidate_input(
                JobId::JobB,
                Scope::ScopeA,
                Priority::Critical,
                AuthConfigId::AuthConfigA,
                OrderingGroup::OrderB,
                2,
            )?),
            FairOutcome::SelectionRejected,
            ResultClass::RejectedClass,
        )
    }

    fn retry_due_step(&mut self) -> Result<()> {
        let state = self.projection.jobs.get(&JobId::JobA).map(|job| job.state);
        match state {
            Some(JobState::Scheduled) => self.fair_select(self.actual_candidate(JobId::JobA)?),
            Some(JobState::Leased) => {
                self.fair_release(self.actual_candidate(JobId::JobA)?, BatchResult::ItemRetry)
            }
            Some(JobState::RetryWaiting) => {
                self.fair_select_at(self.actual_candidate(JobId::JobA)?, FAIR_RETRY_DUE_TICK)
            }
            _ => Err(std::io::Error::other(
                "retry timing witness requires a scheduled, leased, or retry-waiting JobA",
            )
            .into()),
        }
    }

    fn refresh_candidate_action(
        &mut self,
        job: JobId,
        scope: Scope,
        priority: Priority,
        auth_config: AuthConfigId,
        ordering: OrderingGroup,
    ) -> Result<()> {
        self.refresh(
            Command::FairBatchCandidate(candidate_input(
                job,
                scope,
                priority,
                auth_config,
                ordering,
                if matches!(priority, Priority::Bulk | Priority::Default) {
                    1
                } else {
                    2
                },
            )?),
            FairOutcome::HeadReady,
            ResultClass::AppliedClass,
        )
    }

    fn submit_batch_item(&mut self, job: JobId, result: BatchResult) -> Result<()> {
        let active = self
            .claims
            .remove(&job)
            .ok_or_else(|| std::io::Error::other("missing batch claim"))?;
        let outcome = match result {
            BatchResult::ItemSuccess => {
                JobOutcome::Complete(crate::policy::OutcomeCode::try_new("batch_success")?)
            }
            BatchResult::ItemDeadLetter => JobOutcome::DeadLetter {
                code: crate::policy::OutcomeCode::try_new("batch_dead_letter")?,
            },
            BatchResult::ItemRetry | BatchResult::ItemMissing | BatchResult::ItemDuplicate => {
                JobOutcome::Retry {
                    class: RetryClass::Transient,
                    not_before: Some(Timestamp::ZERO),
                    code: crate::policy::OutcomeCode::try_new("batch_retry")?,
                }
            }
        };
        let batch = self
            .batch
            .as_ref()
            .ok_or_else(|| std::io::Error::other("missing active batch"))?;
        let durable = DurableBatchResult {
            attempt_id: active.claim.attempt_id(),
            outcome,
        };
        block_on(fair_dispatch_batch_item(
            &self.system,
            batch,
            active.permit,
            active.claim,
            durable,
            Timestamp::ZERO,
        ))?;
        self.refresh(
            Command::FairBatchItem { job, result },
            FairOutcome::BatchPartial,
            ResultClass::AppliedClass,
        )
    }
}

impl Driver for FairDispatchDriver {
    type State = StateProjection;

    fn step(&mut self, step: &Step) -> Result {
        match step.action_taken.as_str() {
            "mbtInit" => *self = Self::try_default()?,
            "mbtObserve" => {
                let command = self.last_command.clone();
                self.refresh(command, self.last_outcome, self.last_class)?;
            }
            "mbtNondetStep" | "mbtStep" => self.apply_generated_step(step)?,
            "fixedBulkSeed" | "fixedBulkSeedTrace" => {
                self.apply_trace_action("fixedBulkSeedTrace")?
            }
            "fixedPrimaryBatchTrace" => self.apply_trace_action("fixedPrimaryBatchTrace")?,
            "fixedSecondaryBatchTrace" => self.apply_trace_action("fixedSecondaryBatchTrace")?,
            "fixedBatchRejectionTrace" => self.apply_trace_action("fixedBatchRejectionTrace")?,
            "fixedLiveAuthorityCandidateTrace" => {
                self.apply_trace_action("fixedLiveAuthorityCandidateTrace")?
            }
            "fixedRetryDueTrace" => self.apply_trace_action("fixedRetryDueTrace")?,
            "FairSeed" => self.fair_seed(
                required_pick(step, "job")?,
                required_pick(step, "priority")?,
            )?,
            "FairBatchCandidate" => self.fair_batch_candidate(required_pick(step, "input")?)?,
            "FairSelect" => {
                let input = if let Some(input) = pick::<CandidateInput>(step, "input")? {
                    Some(input)
                } else {
                    pick::<CandidateInput>(step, "candidate")?
                }
                .ok_or_else(|| std::io::Error::other("fair selection candidate is absent"))?;
                let now = pick::<i64>(step, "now")?.unwrap_or(0);
                self.fair_select_at(input, now)?;
            }
            "FairRelease" => self.fair_release(
                required_pick(step, "candidate")?,
                required_pick(step, "result")?,
            )?,
            "FairTick" => self.fair_tick(required_pick(step, "cycle")?)?,
            "FairBlock" => {
                self.fair_block(required_pick(step, "job")?, required_pick(step, "reason")?)?
            }
            "FairHolEscape" => self.fair_hol_escape(
                required_pick(step, "blocked")?,
                required_pick(step, "candidate")?,
            )?,
            "FairRefill" => self.fair_refill(
                required_pick(step, "scope")?,
                required_pick(step, "primary")?,
            )?,
            "FairLowVolume" => self.fair_low_volume(required_pick(step, "input")?)?,
            "FairBatchStart" => self.fair_batch_start(
                required_pick(step, "first")?,
                required_pick(step, "second")?,
                required_pick(step, "capacity")?,
            )?,
            "FairBatchItem" => {
                self.fair_batch_item(required_pick(step, "job")?, required_pick(step, "result")?)?
            }
            "FairScratch" => self.fair_scratch(
                required_pick(step, "clear")?,
                required_pick(step, "capacity")?,
            )?,
            "FairService" => self.fair_service(
                required_pick(step, "candidate")?,
                required_pick(step, "refillRate")?,
            )?,
            "FairResetWindow" => self.fair_reset_from_step(step)?,
            "SeedReady" => self.fair_seed(
                required_pick(step, "job")?,
                required_pick(step, "priority")?,
            )?,
            "Select" => {
                let job = required_pick(step, "job")?;
                self.fair_select(self.actual_candidate(job)?)?;
            }
            "Release" => {
                let job = required_pick(step, "job")?;
                self.fair_release(
                    self.actual_candidate(job)?,
                    required_pick(step, "itemResult")?,
                )?;
            }
            "Tick" => self.fair_tick(self.projection.meta.cycle)?,
            "BlockHead" => {
                self.fair_block(required_pick(step, "job")?, required_pick(step, "reason")?)?
            }
            "HolEscape" => {
                let blocked = required_pick(step, "blockedJob")?;
                let job = required_pick(step, "job")?;
                self.fair_hol_escape(blocked, self.actual_candidate(job)?)?;
            }
            "Refill" => {
                let scope = required_pick(step, "scope")?;
                self.fair_refill(scope, primary_scope(scope))?;
            }
            "LowVolumeAttempt" => {
                let job = required_pick(step, "job")?;
                self.fair_low_volume(self.actual_candidate(job)?)?;
            }
            "StartBatch" => {
                let first = required_pick(step, "first")?;
                let second = required_pick(step, "second")?;
                self.fair_batch_start(
                    self.actual_candidate(first)?,
                    self.actual_candidate(second)?,
                    self.projection.meta.scratch_capacity,
                )?;
            }
            "SubmitPartialBatch" => self.fair_batch_item(
                required_pick(step, "batchItem")?,
                required_pick(step, "itemResult")?,
            )?,
            "ClearScratch" => self.fair_scratch(true, self.projection.meta.scratch_capacity)?,
            "ShrinkScratch" => self.fair_scratch(false, self.projection.meta.scratch_capacity)?,
            "RecordServiceError" => self.fair_service_error(required_pick(step, "job")?)?,
            "ResetPriorityWindow" => self.fair_reset_window(
                self.projection.meta.critical_window,
                self.projection.meta.default_window,
                self.projection.meta.bulk_window,
            )?,
            "ServiceUnit" => {
                let job = required_pick(step, "job")?;
                self.fair_service(
                    self.actual_candidate(job)?,
                    required_pick(step, "refillRate")?,
                )?;
            }
            "PriorityWindowWitnessStep" => self.fair_priority_witness_step()?,
            "CompatibleBatchWitnessStep" => self.fair_compatible_batch_witness_step()?,
            "ResolvedBatchClearWitnessStep" => self.fair_resolved_batch_clear_witness_step()?,
            "step" => self.apply_generated_step(step)?,
            action => self.apply_trace_action(action)?,
        }
        Ok(())
    }
}

fn initial_command() -> Command {
    Command::FairTick { cycle: 0 }
}

fn model_now(now: i64) -> Timestamp {
    if now <= 0 {
        Timestamp::ZERO
    } else {
        Timestamp::from_millis(FAIR_RETRY_DUE_NOW_MILLIS)
    }
}

fn initial_projection() -> StateProjection {
    let transition = LastTransition {
        command: initial_command(),
        class: ResultClass::AppliedClass,
        outcome: FairOutcome::Initialised,
        job: JobId::JobA,
        scope: Scope::ScopeA,
        priority: Priority::Critical,
        registered_cost: 2,
        reason: BlockReason::Unblocked,
        handler_kind: HandlerKind::HandlerA,
        schema_version: 1,
        batch_key: BatchKey::BatchA,
        auth_config: AuthConfigId::AuthConfigA,
        effect_mode: EffectModeModel::IdempotentEffect,
        retry_policy: RetryPolicyModel::NetworkRetry,
        timeout_policy: TimeoutPolicyModel::ShortTimeout,
        payload_bytes: 1,
        enqueued_at: 0,
        batch_deadline: 4,
        permits: 2,
        rate: 3,
        in_flight: 0,
        primary_permits: 2,
        primary_rate: 3,
        primary_in_flight: 0,
        scratch_capacity: 3,
        batch_active: false,
        members: BTreeSet::new(),
        results: BTreeMap::new(),
    };
    StateProjection {
        scopes: BTreeMap::new(),
        jobs: BTreeMap::new(),
        orders: BTreeMap::new(),
        meta: default_meta(),
        command: initial_command(),
        transition: transition.clone(),
        result: CommandResult::FairApplied {
            transition,
            batch_results: BTreeMap::new(),
        },
    }
}

fn default_meta() -> Meta {
    Meta {
        cycle: 0,
        critical_served: 0,
        default_served: 0,
        bulk_served: 0,
        critical_window: 0,
        default_window: 0,
        bulk_window: 0,
        hol_escapes: 0,
        batch_active: false,
        batch_scope: Scope::ScopeA,
        batch_auth_config: AuthConfigId::AuthConfigA,
        batch_members: BTreeSet::new(),
        batch_results: BTreeMap::new(),
        scratch_size: 0,
        scratch_capacity: 3,
        batch_payload_bytes: 0,
        batch_formed_at: 0,
        batch_deadline: 0,
        selected_scope: Scope::ScopeA,
        selected_job: JobId::JobA,
        selected_cost: 0,
        service_transitions: 0,
        last_outcome: FairOutcome::Initialised,
    }
}

fn candidate_spec(
    job: JobId,
    scope: Scope,
    priority: Priority,
    auth_config: AuthConfigId,
    cost: u16,
    ordering: OrderingGroup,
) -> Result<FairDispatchCandidateSpec> {
    let durable_priority = durable_priority(priority);
    let volume_mode = if matches!(scope, Scope::ScopeA1 | Scope::ScopeB1) {
        crate::fairness::FairVolumeMode::LowVolume
    } else {
        crate::fairness::FairVolumeMode::Scoped
    };
    let metadata = FairCandidateMetadata {
        handler_kind: JobKind::try_new("email")?,
        schema_version: NonZeroU16::MIN,
        batch_key: crate::batch::BatchKey::new(1),
        auth_config: crate::batch::AuthConfigId::new(match auth_config {
            AuthConfigId::AuthConfigA => 1,
            AuthConfigId::AuthConfigB => 2,
        }),
        effect_mode: EffectMode::Idempotent,
        retry_policy: RetryPolicy::preset(RetryPreset::Network),
        timeout: Duration::from_secs(1),
        enqueued_at: Timestamp::ZERO,
        batch_deadline: Timestamp::from_millis(4),
    };
    Ok(FairDispatchCandidateSpec {
        job_id: durable_id(job),
        payload: Bytes::from_static(b"x"),
        fairness: fairness_class(scope)?,
        volume_mode,
        priority: durable_priority,
        cost_units: NonZeroU16::new(cost).ok_or_else(|| std::io::Error::other("cost is zero"))?,
        scheduled_at: Timestamp::ZERO,
        ordering_key: Some(ordering_key(ordering)?),
        ordering_position: 1,
        metadata,
    })
}

fn candidate_spec_from_input(input: &CandidateInput) -> Result<FairDispatchCandidateSpec> {
    let cost = u16::try_from(input.cost)
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or_else(|| std::io::Error::other("candidate cost must be positive and bounded"))?;
    let schema_version = u16::try_from(input.schema_version)
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or_else(|| std::io::Error::other("candidate schema version must be positive"))?;
    let payload_bytes = usize::try_from(input.payload_bytes)
        .map_err(|_| std::io::Error::other("candidate payload size is negative"))?;
    let ordering_position = u64::try_from(input.order)
        .map_err(|_| std::io::Error::other("candidate ordering position is negative"))?;
    let metadata = FairCandidateMetadata {
        handler_kind: JobKind::try_new(match input.handler_kind {
            HandlerKind::HandlerA => "email",
            HandlerKind::HandlerB => "webhook",
        })?,
        schema_version,
        batch_key: crate::batch::BatchKey::new(match input.batch_key {
            BatchKey::BatchA => 1,
            BatchKey::BatchB => 2,
        }),
        auth_config: crate::batch::AuthConfigId::new(match input.auth_config {
            AuthConfigId::AuthConfigA => 1,
            AuthConfigId::AuthConfigB => 2,
        }),
        effect_mode: model_effect_mode(input.effect_mode),
        retry_policy: model_retry_policy(input.retry_policy),
        timeout: model_timeout(input.timeout_policy),
        enqueued_at: Timestamp::from_millis(input.enqueued_at),
        batch_deadline: Timestamp::from_millis(input.batch_deadline),
    };
    Ok(FairDispatchCandidateSpec {
        job_id: durable_id(input.job),
        payload: Bytes::from(vec![b'x'; payload_bytes]),
        fairness: fairness_class(input.scope)?,
        volume_mode: match input.mode {
            VolumeMode::ScopedVolume => crate::fairness::FairVolumeMode::Scoped,
            VolumeMode::LowVolume => crate::fairness::FairVolumeMode::LowVolume,
        },
        priority: durable_priority(input.priority),
        cost_units: cost,
        scheduled_at: Timestamp::from_millis(input.enqueued_at),
        ordering_key: Some(ordering_key(input.ordering)?),
        ordering_position,
        metadata,
    })
}

fn model_effect_mode(mode: EffectModeModel) -> EffectMode {
    match mode {
        EffectModeModel::ReadOnlyEffect => EffectMode::ReadOnly,
        EffectModeModel::IdempotentEffect => EffectMode::Idempotent,
        EffectModeModel::AtLeastOnceEffect => EffectMode::AtLeastOnce,
        EffectModeModel::FencedEffect => EffectMode::Fenced,
    }
}

fn model_retry_policy(policy: RetryPolicyModel) -> RetryPolicy {
    RetryPolicy::preset(match policy {
        RetryPolicyModel::InteractiveRetry => RetryPreset::Interactive,
        RetryPolicyModel::NetworkRetry => RetryPreset::Network,
        RetryPolicyModel::MaintenanceRetry => RetryPreset::Maintenance,
    })
}

fn model_timeout(policy: TimeoutPolicyModel) -> Duration {
    match policy {
        TimeoutPolicyModel::ShortTimeout => Duration::from_secs(1),
        TimeoutPolicyModel::LongTimeout => Duration::from_secs(30),
    }
}

fn model_job_outcome(result: BatchResult) -> Result<JobOutcome> {
    Ok(match result {
        BatchResult::ItemSuccess => {
            JobOutcome::Complete(crate::policy::OutcomeCode::try_new("fair_complete")?)
        }
        BatchResult::ItemDeadLetter => JobOutcome::DeadLetter {
            code: crate::policy::OutcomeCode::try_new("fair_dead_letter")?,
        },
        BatchResult::ItemRetry | BatchResult::ItemMissing | BatchResult::ItemDuplicate => {
            JobOutcome::Retry {
                class: RetryClass::Transient,
                not_before: Some(Timestamp::ZERO),
                code: crate::policy::OutcomeCode::try_new("fair_retry")?,
            }
        }
    })
}

fn candidate_block(reason: BlockReason) -> Option<CandidateBlock> {
    match reason {
        BlockReason::LeasedHead => Some(CandidateBlock::Leased),
        BlockReason::CorruptHead => Some(CandidateBlock::Corrupt),
        BlockReason::OversizedHead => Some(CandidateBlock::Oversized),
        BlockReason::PoisonHead => Some(CandidateBlock::Poison),
        BlockReason::RateLimitedHead => Some(CandidateBlock::RateLimited),
        BlockReason::CapacityBlockedHead => Some(CandidateBlock::Capacity),
        BlockReason::Unblocked => None,
    }
}

fn block_outcome(reason: BlockReason) -> FairOutcome {
    match reason {
        BlockReason::RateLimitedHead => FairOutcome::RateBlocked,
        BlockReason::CapacityBlockedHead => FairOutcome::CapacityBlocked,
        _ => FairOutcome::HeadBlocked,
    }
}

fn pick<T: DeserializeOwned>(step: &Step, name: &str) -> Result<Option<T>> {
    step.nondet_picks
        .get(name)
        .map(|value| T::deserialize(value.clone()))
        .transpose()
        .map_err(Into::into)
}

fn required_pick<T: DeserializeOwned>(step: &Step, name: &str) -> Result<T> {
    pick(step, name)?.ok_or_else(|| {
        std::io::Error::other(format!(
            "fair connector action is missing nondet pick {name}"
        ))
        .into()
    })
}

fn candidate_input(
    job: JobId,
    scope: Scope,
    priority: Priority,
    auth_config: AuthConfigId,
    ordering: OrderingGroup,
    cost: u16,
) -> Result<types::CandidateInput> {
    Ok(types::CandidateInput {
        job,
        scope,
        primary: primary_scope(scope),
        priority,
        cost: i64::from(cost),
        ordering,
        order: 1,
        order_head: 1,
        order_in_flight: false,
        permits: 2,
        rate: 3,
        in_flight: 0,
        primary_permits: 2,
        primary_rate: 3,
        primary_in_flight: 0,
        payload_bytes: 1,
        handler_kind: HandlerKind::HandlerA,
        schema_version: 1,
        batch_key: BatchKey::BatchA,
        auth_config,
        effect_mode: EffectModeModel::IdempotentEffect,
        retry_policy: RetryPolicyModel::NetworkRetry,
        timeout_policy: TimeoutPolicyModel::ShortTimeout,
        enqueued_at: 0,
        batch_deadline: 4,
        mode: if matches!(scope, Scope::ScopeA1 | Scope::ScopeB1) {
            VolumeMode::LowVolume
        } else {
            VolumeMode::ScopedVolume
        },
    })
}

fn default_candidate_for(job: JobId) -> (Scope, Priority, AuthConfigId, u16, OrderingGroup) {
    match job {
        JobId::JobA => (
            Scope::ScopeA,
            Priority::Critical,
            AuthConfigId::AuthConfigA,
            2,
            OrderingGroup::OrderA,
        ),
        JobId::JobB => (
            Scope::ScopeB,
            Priority::Default,
            AuthConfigId::AuthConfigA,
            2,
            OrderingGroup::OrderB,
        ),
        JobId::JobC => (
            Scope::ScopeA1,
            Priority::Bulk,
            AuthConfigId::AuthConfigA,
            1,
            OrderingGroup::OrderB,
        ),
    }
}

fn is_configured(
    system: &JobSystem<FakeStore>,
    job: JobId,
    scope: Scope,
    priority: Priority,
    auth_config: AuthConfigId,
) -> Result<bool> {
    let owner = block_on(FairDispatchOwner::load(system))?;
    let Some(owner) = owner else { return Ok(false) };
    let Some(candidate) = owner.candidate_snapshot(durable_id(job)) else {
        return Ok(false);
    };
    let Some(metadata) = owner.metadata(durable_id(job)) else {
        return Ok(false);
    };
    Ok(candidate.scope == fair_scope(scope)?
        && candidate.priority == durable_priority(priority)
        && metadata.auth_config.get()
            == match auth_config {
                AuthConfigId::AuthConfigA => 1,
                AuthConfigId::AuthConfigB => 2,
            })
}

fn transition_from_actual(
    owner: &FairDispatchOwner,
    command: Command,
    outcome: FairOutcome,
    class: ResultClass,
    candidate: Option<FairCandidateSnapshot>,
) -> Result<LastTransition> {
    let job = command_job(&command);
    let candidate = candidate.or_else(|| owner.candidate_snapshot(durable_id(job)));
    let scope = candidate
        .as_ref()
        .map(|value| model_scope(&value.scope))
        .transpose()?
        .unwrap_or(Scope::ScopeA);
    let priority = candidate
        .as_ref()
        .map(|value| model_priority(value.priority));
    let priority = priority.unwrap_or(Priority::Critical);
    let metadata = owner.metadata(durable_id(job));
    let auth_config = metadata
        .map(|value| model_auth(value.auth_config))
        .unwrap_or(AuthConfigId::AuthConfigA);
    let handler_kind = metadata
        .map(|value| model_handler_kind(&value.handler_kind))
        .unwrap_or(HandlerKind::HandlerA);
    let batch_key = metadata
        .map(|value| model_batch_key(value.batch_key))
        .unwrap_or(BatchKey::BatchA);
    let effect_mode = metadata
        .map(|value| model_effect_mode_actual(value.effect_mode))
        .unwrap_or(EffectModeModel::IdempotentEffect);
    let retry_policy = metadata
        .map(|value| model_retry_policy_actual(value.retry_policy))
        .unwrap_or(RetryPolicyModel::NetworkRetry);
    let timeout_policy = metadata
        .map(|value| model_timeout_actual(value.timeout))
        .unwrap_or(TimeoutPolicyModel::ShortTimeout);
    let batch = owner.batch();
    let results = batch
        .results
        .iter()
        .map(|(job, state)| (model_id(*job), model_batch_result(*state)))
        .collect();
    let members = batch.members.iter().copied().map(model_id).collect();
    let scope_snapshot = owner.ledger().scope_snapshot(
        &candidate
            .as_ref()
            .map(|value| value.scope.clone())
            .unwrap_or(FairScope::LowVolume),
    );
    let primary_snapshot = candidate
        .as_ref()
        .and_then(|value| owner.ledger().scope_snapshot(&value.scope.primary_scope()));
    Ok(LastTransition {
        command,
        class,
        outcome,
        job,
        scope,
        priority,
        registered_cost: candidate
            .as_ref()
            .map_or(2, |value| i64::from(value.cost_units.get())),
        reason: candidate
            .as_ref()
            .and_then(|value| value.block)
            .map(model_block)
            .unwrap_or(BlockReason::Unblocked),
        handler_kind,
        schema_version: i64::from(metadata.map_or(1, |value| value.schema_version.get())),
        batch_key,
        auth_config,
        effect_mode,
        retry_policy,
        timeout_policy,
        payload_bytes: candidate.as_ref().map_or(1, |value| {
            i64::try_from(value.payload_bytes).unwrap_or(i64::MAX)
        }),
        enqueued_at: metadata.map_or(0, |value| value.enqueued_at.as_millis()),
        batch_deadline: metadata.map_or(4, |value| value.batch_deadline.as_millis()),
        permits: scope_snapshot
            .as_ref()
            .map_or(2, |value| i64::from(value.permits)),
        rate: scope_snapshot
            .as_ref()
            .map_or(3, |value| i64::from(value.rate)),
        in_flight: scope_snapshot
            .as_ref()
            .map_or(0, |value| i64::from(value.in_flight)),
        primary_permits: primary_snapshot
            .as_ref()
            .map_or(2, |value| i64::from(value.permits)),
        primary_rate: primary_snapshot
            .as_ref()
            .map_or(3, |value| i64::from(value.rate)),
        primary_in_flight: primary_snapshot
            .as_ref()
            .map_or(0, |value| i64::from(value.in_flight)),
        scratch_capacity: i64::try_from(batch.scratch_capacity).unwrap_or(i64::MAX),
        batch_active: batch.active,
        members,
        results,
    })
}

fn project_actual(
    system: &JobSystem<FakeStore>,
    owner: &FairDispatchOwner,
    command: Command,
    transition: LastTransition,
    result: CommandResult,
    previous_selected_cost: i64,
) -> Result<StateProjection> {
    let mut jobs = BTreeMap::new();
    for job in [JobId::JobA, JobId::JobB, JobId::JobC] {
        jobs.insert(job, project_job(system, owner, job)?);
    }
    let scopes = project_scopes(owner)?;
    let orders = project_orders(owner)?;
    let deficit = owner.priority_deficit();
    let batch = owner.batch();
    let mut meta = default_meta();
    meta.critical_served = i64::try_from(deficit.critical_served()).unwrap_or(i64::MAX);
    meta.default_served = i64::try_from(deficit.default_served()).unwrap_or(i64::MAX);
    meta.bulk_served = i64::try_from(deficit.bulk_served()).unwrap_or(i64::MAX);
    meta.critical_window = i64::from(deficit.critical_window());
    meta.default_window = i64::from(deficit.default_window());
    meta.bulk_window = i64::from(deficit.bulk_window());
    meta.cycle = i64::from(deficit.cycle());
    meta.hol_escapes = i64::try_from(owner.hol_escapes()).unwrap_or(i64::MAX);
    meta.service_transitions = jobs
        .values()
        .map(|job| job.service_transitions)
        .fold(0_i64, |total, units| total.saturating_add(units));
    meta.batch_active = batch.active;
    meta.batch_scope = model_scope(&batch.scope)?;
    meta.batch_auth_config = model_auth(batch.auth_config);
    meta.batch_members = batch.members.iter().copied().map(model_id).collect();
    meta.batch_results = batch
        .results
        .iter()
        .map(|(job, state)| (model_id(*job), model_batch_result(*state)))
        .collect();
    meta.scratch_size = i64::try_from(batch.scratch_size).unwrap_or(i64::MAX);
    meta.scratch_capacity = i64::try_from(batch.scratch_capacity).unwrap_or(i64::MAX);
    meta.batch_payload_bytes = i64::try_from(batch.payload_bytes).unwrap_or(i64::MAX);
    meta.batch_formed_at = batch.formed_at.as_millis();
    meta.batch_deadline = batch.deadline.as_millis();
    let selected = owner.selected();
    meta.selected_job = model_id(selected.job_id);
    meta.selected_scope = model_scope(&selected.scope)?;
    // Selection cost is command metadata, not a live candidate attribute.
    // Rejected SelectInput writes zero, while later Tick/observation commands
    // leave that value unchanged even though the durable owner still retains
    // the last successful candidate cost.
    meta.selected_cost = match (&command, transition.outcome) {
        (Command::FairSelect(_), FairOutcome::SelectionRejected)
        | (Command::FairHolEscape { .. }, FairOutcome::SelectionRejected) => 0,
        (Command::FairLowVolume(_), FairOutcome::SelectionRejected)
        | (Command::FairBatchStart { .. }, FairOutcome::SelectionRejected)
        | (Command::FairService { .. }, FairOutcome::SelectionRejected)
        | (Command::FairResetWindow { .. }, FairOutcome::SelectionRejected) => {
            previous_selected_cost
        }
        (Command::FairResetWindow { .. }, FairOutcome::HeadReady) => 0,
        (Command::FairSelect(_), _)
        | (Command::FairHolEscape { .. }, _)
        | (Command::FairLowVolume(_), _)
        | (Command::FairBatchStart { .. }, _)
        | (Command::FairService { .. }, _) => i64::from(selected.cost_units),
        _ => previous_selected_cost,
    };
    meta.last_outcome = transition.outcome;
    Ok(StateProjection {
        scopes,
        jobs,
        orders,
        meta,
        command,
        transition,
        result,
    })
}

fn project_job(
    system: &JobSystem<FakeStore>,
    owner: &FairDispatchOwner,
    job: JobId,
) -> Result<FairJob> {
    let durable = durable_id(job);
    let candidate = owner.candidate_snapshot(durable);
    let metadata = owner.metadata(durable);
    let record = block_on(
        system
            .store()
            .get(crate::keys::job_key(system.namespace(), &durable)?),
    )?
    .map(|value| decode_job_record(&value))
    .transpose()?;
    let state = match candidate.as_ref().map(|value| value.state) {
        Some(crate::fairness::FairCandidateState::Leased) => JobState::Leased,
        Some(crate::fairness::FairCandidateState::RetryWaiting) => JobState::RetryWaiting,
        Some(crate::fairness::FairCandidateState::DeadLettered) => JobState::DeadLettered,
        Some(crate::fairness::FairCandidateState::Cancelled) => JobState::Cancelled,
        Some(crate::fairness::FairCandidateState::Absent) | None => {
            record
                .as_ref()
                .map_or(JobState::Absent, |record| match record.state {
                    crate::model::JobState::Scheduled => JobState::Scheduled,
                    crate::model::JobState::Leased(_) => JobState::Leased,
                    crate::model::JobState::DeadLettered => JobState::DeadLettered,
                    crate::model::JobState::Cancelled => JobState::Cancelled,
                    crate::model::JobState::Suspended => JobState::Suspended,
                })
        }
        Some(crate::fairness::FairCandidateState::Scheduled) => JobState::Scheduled,
    };
    let scope = candidate
        .as_ref()
        .map(|value| model_scope(&value.scope))
        .transpose()?
        .unwrap_or(match job {
            JobId::JobC => Scope::ScopeA1,
            _ => {
                if job == JobId::JobA {
                    Scope::ScopeA
                } else {
                    Scope::ScopeB
                }
            }
        });
    let priority = candidate
        .as_ref()
        .map(|value| model_priority(value.priority))
        .unwrap_or(match job {
            JobId::JobA => Priority::Critical,
            JobId::JobB => Priority::Default,
            JobId::JobC => Priority::Bulk,
        });
    let ordering = candidate
        .as_ref()
        .and_then(|value| value.ordering_key.as_ref())
        .map(model_ordering)
        .transpose()?
        .unwrap_or(match job {
            JobId::JobA => OrderingGroup::OrderA,
            JobId::JobB => OrderingGroup::OrderB,
            JobId::JobC => OrderingGroup::OrderB,
        });
    let order_head = candidate
        .as_ref()
        .and_then(|value| value.ordering_key.as_ref())
        .and_then(|key| owner.order_snapshot(key))
        .map_or(1, |value| i64::try_from(value.head).unwrap_or(i64::MAX));
    let metadata = metadata.cloned();
    let handler_kind = metadata
        .as_ref()
        .map(|value| model_handler_kind(&value.handler_kind))
        .or_else(|| record.as_ref().map(|value| model_handler_kind(&value.kind)))
        .unwrap_or(HandlerKind::HandlerA);
    let batch_key = metadata
        .as_ref()
        .map(|value| model_batch_key(value.batch_key))
        .unwrap_or(BatchKey::BatchA);
    let auth_config = metadata
        .as_ref()
        .map_or(AuthConfigId::AuthConfigA, |value| {
            model_auth(value.auth_config)
        });
    let effect_mode = metadata
        .as_ref()
        .map(|value| model_effect_mode_actual(value.effect_mode))
        .or_else(|| {
            record
                .as_ref()
                .map(|value| model_effect_mode_actual(value.policy.effect_mode))
        })
        .unwrap_or(EffectModeModel::IdempotentEffect);
    let retry_policy = metadata
        .as_ref()
        .map(|value| model_retry_policy_actual(value.retry_policy))
        .or_else(|| {
            record
                .as_ref()
                .map(|value| model_retry_policy_actual(value.policy.retry_policy))
        })
        .unwrap_or(RetryPolicyModel::NetworkRetry);
    let timeout_policy = metadata
        .as_ref()
        .map(|value| model_timeout_actual(value.timeout))
        .or_else(|| {
            record
                .as_ref()
                .and_then(|value| value.policy.execution_timeout.map(model_timeout_actual))
        })
        .unwrap_or(TimeoutPolicyModel::ShortTimeout);
    Ok(FairJob {
        state,
        record: RecordKind::Valid,
        payload: record.is_some(),
        due_route: candidate
            .as_ref()
            .is_some_and(|value| value.state.has_ready_route()),
        fair_route: candidate
            .as_ref()
            .is_some_and(|value| value.state.has_ready_route()),
        // The durable job record owns retry timing. The fair-owner candidate
        // can still contain its pre-retry timestamp while the lifecycle
        // transition has persisted a jittered `scheduled_at`; projecting the
        // owner value here would recreate the seed-0x3d mismatch. Keep the
        // Quint value finite while preserving the durable due/not-due bit.
        due_at: record.as_ref().map_or(0, |value| {
            if value.scheduled_at > Timestamp::ZERO {
                FAIR_RETRY_NOT_DUE_TICK
            } else {
                0
            }
        }),
        scope,
        priority,
        ordering,
        order: candidate.as_ref().map_or(1, |value| {
            i64::try_from(value.ordering_position).unwrap_or(i64::MAX)
        }),
        order_head,
        cost: candidate.as_ref().map_or(
            match job {
                JobId::JobC => 1,
                _ => 2,
            },
            |value| i64::from(value.cost_units.get()),
        ),
        block: candidate
            .as_ref()
            .and_then(|value| value.block)
            .map(model_block)
            .unwrap_or(BlockReason::Unblocked),
        payload_bytes: candidate.as_ref().map_or(1, |value| {
            i64::try_from(value.payload_bytes).unwrap_or(i64::MAX)
        }),
        handler_kind,
        schema_version: i64::from(
            metadata
                .as_ref()
                .map_or(1, |value| value.schema_version.get()),
        ),
        batch_key,
        auth_config,
        effect_mode,
        retry_policy,
        timeout_policy,
        service_transitions: candidate.as_ref().map_or(0, |value| {
            i64::try_from(value.service_transitions).unwrap_or(i64::MAX)
        }),
        enqueued_at: metadata
            .as_ref()
            .map_or(0, |value| value.enqueued_at.as_millis()),
        batch_deadline: metadata
            .as_ref()
            .map_or(4, |value| value.batch_deadline.as_millis()),
    })
}

fn project_scopes(owner: &FairDispatchOwner) -> Result<BTreeMap<Scope, ScopeState>> {
    let mut scopes = BTreeMap::new();
    for scope in [
        Scope::ScopeA,
        Scope::ScopeB,
        Scope::ScopeA1,
        Scope::ScopeA2,
        Scope::ScopeB1,
    ] {
        let fair = fair_scope(scope)?;
        let snapshot = owner.ledger().scope_snapshot(&fair);
        let candidates = owner
            .candidate_ids()
            .filter_map(|job_id| {
                let candidate = owner.candidate_snapshot(job_id)?;
                (candidate.scope == fair && candidate.state.has_ready_route())
                    .then_some(model_id(job_id))
            })
            .collect::<BTreeSet<_>>();
        let priority = candidates
            .iter()
            .find_map(|job| {
                owner
                    .candidate_snapshot(durable_id(*job))
                    .map(|value| model_priority(value.priority))
            })
            .unwrap_or(match scope {
                Scope::ScopeA => Priority::Critical,
                Scope::ScopeB => Priority::Default,
                Scope::ScopeA1 | Scope::ScopeB1 => Priority::Bulk,
                Scope::ScopeA2 => Priority::Default,
            });
        let (primary, secondary) = match scope {
            Scope::ScopeA | Scope::ScopeB => (scope, false),
            Scope::ScopeA1 | Scope::ScopeA2 => (Scope::ScopeA, true),
            Scope::ScopeB1 => (Scope::ScopeB, true),
        };
        scopes.insert(
            scope,
            ScopeState {
                primary,
                secondary,
                share: 1,
                mode: snapshot.as_ref().map_or(
                    if matches!(scope, Scope::ScopeA1 | Scope::ScopeB1) {
                        VolumeMode::LowVolume
                    } else {
                        VolumeMode::ScopedVolume
                    },
                    |value| match value.mode {
                        crate::FairVolumeMode::Scoped => VolumeMode::ScopedVolume,
                        crate::FairVolumeMode::LowVolume => VolumeMode::LowVolume,
                    },
                ),
                ready: !candidates.is_empty(),
                priority,
                candidates,
                head: snapshot
                    .as_ref()
                    .map_or(if secondary { 0 } else { 1 }, |value| {
                        i64::try_from(value.head).unwrap_or(i64::MAX)
                    }),
                order: snapshot
                    .as_ref()
                    .map_or(if secondary { 0 } else { 1 }, |value| {
                        i64::try_from(value.order).unwrap_or(i64::MAX)
                    }),
                cost: snapshot
                    .as_ref()
                    .map_or(if secondary { 1 } else { 2 }, |value| {
                        i64::from(value.cost.get())
                    }),
                block: snapshot
                    .as_ref()
                    .and_then(|value| value.block)
                    .map(model_block)
                    .unwrap_or(BlockReason::Unblocked),
                in_flight: snapshot
                    .as_ref()
                    .map_or(0, |value| i64::from(value.in_flight)),
                permits: snapshot
                    .as_ref()
                    .map_or(2, |value| i64::from(value.permits)),
                rate: snapshot.as_ref().map_or(3, |value| i64::from(value.rate)),
                quiet_dwell: snapshot
                    .as_ref()
                    .map_or(0, |value| i64::from(value.quiet_dwell)),
                served: snapshot
                    .as_ref()
                    .map_or(0, |value| i64::try_from(value.served).unwrap_or(i64::MAX)),
                served_cost: snapshot.as_ref().map_or(0, |value| {
                    i64::try_from(value.served_cost).unwrap_or(i64::MAX)
                }),
                errors: snapshot
                    .as_ref()
                    .map_or(0, |value| i64::try_from(value.errors).unwrap_or(i64::MAX)),
                acquisitions: snapshot.as_ref().map_or(0, |value| {
                    i64::try_from(value.acquisitions).unwrap_or(i64::MAX)
                }),
                releases: snapshot
                    .as_ref()
                    .map_or(0, |value| i64::try_from(value.releases).unwrap_or(i64::MAX)),
            },
        );
    }
    Ok(scopes)
}

fn project_orders(owner: &FairDispatchOwner) -> Result<BTreeMap<OrderingGroup, OrderState>> {
    let mut orders = BTreeMap::new();
    for group in [
        OrderingGroup::OrderA,
        OrderingGroup::OrderB,
        OrderingGroup::OrderC,
    ] {
        let key = ordering_key(group)?;
        if let Some(value) = owner.order_snapshot(&key) {
            orders.insert(
                group,
                OrderState {
                    head: i64::try_from(value.head).unwrap_or(i64::MAX),
                    in_flight: value.in_flight,
                    owner: model_id(value.owner),
                    acquisitions: i64::try_from(value.acquisitions).unwrap_or(i64::MAX),
                    releases: i64::try_from(value.releases).unwrap_or(i64::MAX),
                },
            );
        } else {
            orders.insert(
                group,
                OrderState {
                    head: 1,
                    in_flight: false,
                    owner: match group {
                        OrderingGroup::OrderA => JobId::JobA,
                        OrderingGroup::OrderB => JobId::JobB,
                        OrderingGroup::OrderC => JobId::JobC,
                    },
                    acquisitions: 0,
                    releases: 0,
                },
            );
        }
    }
    Ok(orders)
}

fn command_job(command: &Command) -> JobId {
    match command {
        Command::FairSeed { job, .. }
        | Command::FairBatchCandidate(types::CandidateInput { job, .. })
        | Command::FairSelect(types::SelectInput {
            candidate: types::CandidateInput { job, .. },
            ..
        })
        | Command::FairRelease {
            candidate: types::CandidateInput { job, .. },
            ..
        }
        | Command::FairBlock { job, .. }
        | Command::FairLowVolume(types::CandidateInput { job, .. })
        | Command::FairBatchItem { job, .. }
        | Command::FairService {
            candidate: types::CandidateInput { job, .. },
            ..
        } => *job,
        Command::FairTick { .. }
        | Command::FairRefill { .. }
        | Command::FairScratch { .. }
        | Command::FairResetWindow { .. } => JobId::JobA,
        Command::FairHolEscape { candidate, .. } => candidate.job,
        Command::FairBatchStart { second, .. } => second.job,
    }
}

fn durable_id(job: JobId) -> DurableJobId {
    DurableJobId::from(match job {
        JobId::JobA => [1; 16],
        JobId::JobB => [2; 16],
        JobId::JobC => [3; 16],
    })
}

fn model_id(job: DurableJobId) -> JobId {
    match job.as_bytes()[0] {
        1 => JobId::JobA,
        2 => JobId::JobB,
        _ => JobId::JobC,
    }
}

fn fairness_class(scope: Scope) -> Result<FairnessClass> {
    Ok(match scope {
        Scope::ScopeA => FairnessClass::from(FairnessPath::new(FairnessKey::try_new(b"a")?, None)),
        Scope::ScopeB => FairnessClass::from(FairnessPath::new(FairnessKey::try_new(b"b")?, None)),
        Scope::ScopeA1 => FairnessClass::from(FairnessPath::new(
            FairnessKey::try_new(b"a")?,
            Some(FairnessKey::try_new(b"a1")?),
        )),
        Scope::ScopeA2 => FairnessClass::from(FairnessPath::new(
            FairnessKey::try_new(b"a")?,
            Some(FairnessKey::try_new(b"a2")?),
        )),
        Scope::ScopeB1 => FairnessClass::from(FairnessPath::new(
            FairnessKey::try_new(b"b")?,
            Some(FairnessKey::try_new(b"b1")?),
        )),
    })
}

fn fair_scope(scope: Scope) -> Result<FairScope> {
    Ok(FairScope::from(fairness_class(scope)?))
}

fn ordering_key(group: OrderingGroup) -> Result<OrderingKey> {
    Ok(OrderingKey::try_new(match group {
        OrderingGroup::OrderA => b"order-a".as_slice(),
        OrderingGroup::OrderB => b"order-b".as_slice(),
        OrderingGroup::OrderC => b"order-c".as_slice(),
    })?)
}

fn primary_scope(scope: Scope) -> Scope {
    match scope {
        Scope::ScopeA1 | Scope::ScopeA2 => Scope::ScopeA,
        Scope::ScopeB1 => Scope::ScopeB,
        other => other,
    }
}
fn durable_priority(priority: Priority) -> DurablePriority {
    match priority {
        Priority::Critical => DurablePriority::Critical,
        Priority::Default => DurablePriority::Default,
        Priority::Bulk => DurablePriority::Bulk,
    }
}
fn model_priority(priority: DurablePriority) -> Priority {
    match priority {
        DurablePriority::Critical => Priority::Critical,
        DurablePriority::Default => Priority::Default,
        DurablePriority::Bulk => Priority::Bulk,
    }
}
fn model_scope(scope: &FairScope) -> Result<Scope> {
    match scope {
        FairScope::LowVolume => Ok(Scope::ScopeA1),
        FairScope::Scoped { primary, secondary } => match (
            primary.as_bytes(),
            secondary.as_ref().map(FairnessKey::as_bytes),
        ) {
            (b"a", None) => Ok(Scope::ScopeA),
            (b"b", None) => Ok(Scope::ScopeB),
            (b"a", Some(b"a1")) => Ok(Scope::ScopeA1),
            (b"a", Some(b"a2")) => Ok(Scope::ScopeA2),
            (b"b", Some(b"b1")) => Ok(Scope::ScopeB1),
            _ => Err(std::io::Error::other("unknown fair scope").into()),
        },
    }
}
fn model_ordering(key: &OrderingKey) -> Result<OrderingGroup> {
    match key.as_bytes() {
        b"order-a" => Ok(OrderingGroup::OrderA),
        b"order-b" => Ok(OrderingGroup::OrderB),
        b"order-c" => Ok(OrderingGroup::OrderC),
        _ => Err(std::io::Error::other("unknown ordering key").into()),
    }
}
fn model_block(block: CandidateBlock) -> BlockReason {
    match block {
        CandidateBlock::Leased => BlockReason::LeasedHead,
        CandidateBlock::Missing => BlockReason::CorruptHead,
        CandidateBlock::Corrupt => BlockReason::CorruptHead,
        CandidateBlock::Oversized => BlockReason::OversizedHead,
        CandidateBlock::Poison => BlockReason::PoisonHead,
        CandidateBlock::RateLimited => BlockReason::RateLimitedHead,
        CandidateBlock::Capacity => BlockReason::CapacityBlockedHead,
    }
}
fn model_auth(auth: crate::batch::AuthConfigId) -> AuthConfigId {
    if auth.get() == 2 {
        AuthConfigId::AuthConfigB
    } else {
        AuthConfigId::AuthConfigA
    }
}
fn model_handler_kind(kind: &JobKind) -> HandlerKind {
    if kind.as_str() == "webhook" {
        HandlerKind::HandlerB
    } else {
        HandlerKind::HandlerA
    }
}
fn model_batch_key(key: crate::batch::BatchKey) -> BatchKey {
    if key.get() == 2 {
        BatchKey::BatchB
    } else {
        BatchKey::BatchA
    }
}
fn model_effect_mode_actual(mode: EffectMode) -> EffectModeModel {
    match mode {
        EffectMode::ReadOnly => EffectModeModel::ReadOnlyEffect,
        EffectMode::Idempotent => EffectModeModel::IdempotentEffect,
        EffectMode::AtLeastOnce => EffectModeModel::AtLeastOnceEffect,
        EffectMode::Fenced => EffectModeModel::FencedEffect,
    }
}
fn model_retry_policy_actual(policy: RetryPolicy) -> RetryPolicyModel {
    if policy == RetryPolicy::preset(RetryPreset::Interactive) {
        RetryPolicyModel::InteractiveRetry
    } else if policy == RetryPolicy::preset(RetryPreset::Maintenance) {
        RetryPolicyModel::MaintenanceRetry
    } else {
        RetryPolicyModel::NetworkRetry
    }
}
fn model_timeout_actual(timeout: Duration) -> TimeoutPolicyModel {
    if timeout >= Duration::from_secs(30) {
        TimeoutPolicyModel::LongTimeout
    } else {
        TimeoutPolicyModel::ShortTimeout
    }
}
fn model_batch_result(result: FairBatchItemState) -> BatchResult {
    match result {
        FairBatchItemState::Missing => BatchResult::ItemMissing,
        FairBatchItemState::Success => BatchResult::ItemSuccess,
        FairBatchItemState::Retry => BatchResult::ItemRetry,
        FairBatchItemState::DeadLetter => BatchResult::ItemDeadLetter,
        FairBatchItemState::Duplicate => BatchResult::ItemDuplicate,
    }
}
