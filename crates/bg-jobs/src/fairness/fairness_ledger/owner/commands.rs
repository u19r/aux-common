//! Fair-owner commands and accounting transitions.

#[cfg(test)]
use std::cell::Cell;
use std::{collections::BTreeSet, num::NonZeroU16};

#[cfg(all(test, not(target_family = "wasm")))]
use super::state::{FairBatchItemState, FairSelectionSnapshot};
use super::state::{FairCandidateMetadata, FairDispatchOwner};
#[cfg(all(test, not(target_family = "wasm")))]
use super::state::{FairCandidateSnapshot, FairOrderSnapshot};
#[cfg(all(test, not(target_family = "wasm")))]
use crate::{fairness::FairVolumeMode, ids::OrderingKey, policy::Priority};
use crate::{
    fairness::{
        FairCandidateInput, FairCandidateState, FairPermit, FairRelease, FairScope,
        FairnessRejection,
    },
    ids::JobId,
    time::Timestamp,
};

#[cfg(test)]
thread_local! {
    static SELECTION_PASSES: Cell<usize> = const { Cell::new(0) };
}

impl FairDispatchOwner {
    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn observe_selection_attempt(&mut self, job_id: JobId, served: bool) -> bool {
        let Some(record) = self.ledger.candidates.get(&job_id) else {
            return false;
        };
        self.selected = FairSelectionSnapshot {
            job_id,
            scope: record.candidate.scope.clone(),
            cost_units: if served {
                record.candidate.cost_units.get()
            } else {
                0
            },
        };
        true
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn observe_permit(&mut self, permit: &FairPermit) {
        self.selected = FairSelectionSnapshot {
            job_id: permit.job_id(),
            scope: permit.scope().clone(),
            cost_units: permit.cost_units().get(),
        };
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn clear_selected_cost(&mut self) {
        self.selected.cost_units = 0;
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn record_hol_escape(&mut self) {
        self.hol_escapes = self.hol_escapes.saturating_add(1);
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn scratch_capacity(&self) -> usize {
        self.batch.scratch_capacity
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn batch_clearable(&self) -> bool {
        self.batch.active
            && self
                .batch
                .results
                .values()
                .all(|result| !matches!(result, FairBatchItemState::Missing))
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn scratch_shrinkable(&self) -> bool {
        !self.batch.active && self.batch.scratch_size == 0 && self.batch.scratch_capacity > 0
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn start_batch(
        &mut self,
        scope: FairScope,
        auth_config: crate::batch::AuthConfigId,
        members: BTreeSet<JobId>,
        payload_bytes: usize,
        formed_at: Timestamp,
        deadline: Timestamp,
    ) {
        let results = members
            .iter()
            .copied()
            .map(|job_id| (job_id, FairBatchItemState::Missing))
            .collect();
        self.batch = super::state::FairBatchState {
            active: true,
            scope,
            auth_config,
            scratch_size: members.len(),
            scratch_capacity: self.batch.scratch_capacity,
            members,
            results,
            payload_bytes,
            formed_at,
            deadline,
        };
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn record_batch_result(
        &mut self,
        job_id: JobId,
        result: FairBatchItemState,
    ) -> bool {
        if !self.batch.active || !self.batch.members.contains(&job_id) {
            return false;
        }
        self.batch.results.insert(job_id, result);
        true
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn clear_batch(&mut self) {
        self.batch.active = false;
        self.batch.members.clear();
        self.batch.results.clear();
        self.batch.scratch_size = 0;
        self.batch.payload_bytes = 0;
        self.batch.formed_at = Timestamp::ZERO;
        self.batch.deadline = Timestamp::ZERO;
        self.batch.auth_config = crate::batch::AuthConfigId::new(1);
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn shrink_scratch(&mut self) {
        self.batch.scratch_capacity = 0;
    }

    /// Registers a candidate discovered from the authoritative job record.
    /// Existing leased accounting is never replaced by a stale discovery
    /// page; scheduled/retry candidates may be refreshed when immutable fair
    /// input changed through an enqueue replay or connector configuration.
    pub(crate) fn ensure_candidate(
        &mut self,
        input: FairCandidateInput,
        metadata: FairCandidateMetadata,
    ) -> Result<(), crate::error::ValidationError> {
        let job_id = input.job_id;
        let state = self.ledger.candidate_state(job_id);
        match state {
            None => self.ledger.add_candidate(input)?,
            Some(
                FairCandidateState::Absent
                | FairCandidateState::Scheduled
                | FairCandidateState::RetryWaiting
                | FairCandidateState::DeadLettered
                | FairCandidateState::Cancelled,
            ) => self.ledger.upsert_candidate(input)?,
            Some(FairCandidateState::Leased) => {}
        }
        self.metadata.insert(job_id, metadata);
        Ok(())
    }

    pub(crate) fn set_scope_weight(&mut self, scope: &FairScope, weight: NonZeroU16) -> bool {
        self.ledger.set_scope_weight(scope, weight)
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn set_scope_mode(&mut self, scope: &FairScope, mode: FairVolumeMode) -> bool {
        self.ledger.set_scope_mode(scope, mode)
    }

    pub(crate) fn select_next_due_in(
        &mut self,
        now: Timestamp,
        eligible: &BTreeSet<JobId>,
    ) -> Result<Option<FairPermit>, FairnessRejection> {
        #[cfg(test)]
        SELECTION_PASSES.with(|passes| passes.set(passes.get().saturating_add(1)));
        self.ledger.select_next_due_in(now, eligible)
    }

    #[cfg(test)]
    pub(crate) fn reset_selection_passes() {
        SELECTION_PASSES.with(|passes| passes.set(0));
    }

    #[cfg(test)]
    pub(crate) fn selection_passes() -> usize {
        SELECTION_PASSES.with(Cell::get)
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn select(&mut self, job_id: JobId) -> Result<FairPermit, FairnessRejection> {
        self.ledger.select(job_id)
    }

    pub(crate) fn release(
        &mut self,
        permit: FairPermit,
        release: FairRelease,
    ) -> Result<(), FairnessRejection> {
        self.ledger.release(permit, release)
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn settle_service(
        &mut self,
        permit: &FairPermit,
        refill_rate: bool,
    ) -> Result<(), FairnessRejection> {
        self.ledger.settle_service(permit, refill_rate)
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn record_selection(&mut self, permit: &FairPermit) -> bool {
        let recorded = self
            .ledger
            .record_service_units(permit.job_id(), u64::from(permit.cost_units().get()));
        if recorded {
            self.observe_permit(permit);
        }
        recorded
    }

    pub(crate) fn record_service_units(&mut self, job_id: JobId, units: u64) -> bool {
        self.ledger.record_service_units(job_id, units)
    }

    /// Records the observed normalized service error for an eligible candidate
    /// scope without consuming a permit.
    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn record_service_error(&mut self, job_id: JobId, now: Timestamp) -> bool {
        let Some(scope) = self.service_error_scope(job_id, now) else {
            return false;
        };
        if !self.service_error_is_admissible(job_id, now) {
            return false;
        }
        let Some(error) = self.service_error_value(&scope) else {
            return false;
        };
        let bound = u128::from(self.budget().normalized_error_bound())
            .saturating_mul(u128::from(crate::fairness::NORMALIZATION_SCALE));
        if error > bound {
            return false;
        }
        let Some(scope_state) = self.ledger.scopes.get_mut(&scope) else {
            return false;
        };
        scope_state.errors = error;
        true
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    fn service_error_scope(&self, job_id: JobId, now: Timestamp) -> Option<FairScope> {
        let record = self.ledger.candidates.get(&job_id)?;
        if record.candidate.scheduled_at() > now || !record.state.has_ready_route() {
            return None;
        }
        Some(record.candidate.scope.clone())
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    fn service_error_is_admissible(&self, job_id: JobId, now: Timestamp) -> bool {
        let mut probe = self.ledger.clone();
        if probe.select(job_id).is_err() {
            return false;
        }
        let bulk_ready = self.has_eligible_bulk(now);
        u64::from(self.ledger.priority_deficit().cycle()) < self.budget().normalized_error_bound()
            || !bulk_ready
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    fn service_error_value(&self, scope: &FairScope) -> Option<u128> {
        let primary = scope.primary_scope();
        let primary_state = self.ledger.scopes.get(&primary)?;
        let other_state = self
            .ledger
            .scopes
            .iter()
            .find(|(candidate, _)| {
                matches!(
                    candidate,
                    FairScope::Scoped {
                        secondary: None,
                        ..
                    }
                ) && **candidate != primary
            })
            .map(|(_, state)| state)?;
        Some(
            primary_state
                .service
                .position(primary_state.weight, self.ledger.service_clock)
                .abs_diff(
                    other_state
                        .service
                        .position(other_state.weight, self.ledger.service_clock),
                ),
        )
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn block_candidate(
        &mut self,
        job_id: JobId,
        reason: crate::fairness::CandidateBlock,
    ) -> bool {
        let Some(record) = self.ledger.candidates.get(&job_id) else {
            return false;
        };
        match record.state {
            FairCandidateState::Scheduled | FairCandidateState::RetryWaiting => {}
            FairCandidateState::Absent
            | FairCandidateState::Leased
            | FairCandidateState::DeadLettered
            | FairCandidateState::Cancelled => return false,
        }
        if record.candidate.block.is_some() {
            return false;
        }
        let scope = record.candidate.scope.clone();
        let Some(record) = self.ledger.candidates.get_mut(&job_id) else {
            return false;
        };
        record.candidate.block = Some(reason);
        self.ledger.block(&scope, reason)
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn refill(&mut self, scope: &FairScope) -> bool {
        self.ledger.refill(scope)
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn tick(&mut self) {
        self.ledger.tick();
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn tick_allowed(&self, now: Timestamp) -> bool {
        let bound = self.budget().normalized_error_bound();
        let bulk_ready = self.has_eligible_bulk(now);
        !(u64::from(self.ledger.priority_deficit().cycle()) >= bound && bulk_ready)
            && self
                .ledger
                .scope_snapshots()
                .all(|(_, snapshot)| !snapshot.ready || u64::from(snapshot.quiet_dwell) < bound)
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn service_forces_bulk(&self, job_id: JobId, now: Timestamp) -> bool {
        let Some(candidate) = self.ledger.candidates.get(&job_id) else {
            return false;
        };
        let bulk_ready = self.has_eligible_bulk(now);
        bulk_ready
            && u64::from(self.ledger.priority_deficit().cycle())
                .saturating_add(u64::from(candidate.candidate.cost_units().get()))
                >= self.budget().normalized_error_bound()
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    fn has_eligible_bulk(&self, now: Timestamp) -> bool {
        self.ledger.candidates.values().any(|record| {
            record.candidate.priority() == Priority::Bulk
                && record.candidate.scheduled_at() <= now
                && record.state.has_ready_route()
                && {
                    let mut probe = self.ledger.clone();
                    probe.select(record.candidate.job_id()).is_ok()
                }
        })
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn reset_priority_window(&mut self) {
        self.ledger.reset_priority_window();
        self.clear_selected_cost();
    }

    pub(crate) fn defer_candidate(&mut self, job_id: JobId, scheduled_at: Timestamp) {
        self.ledger.defer_candidate(job_id, scheduled_at);
    }

    pub(crate) fn reconcile_leased_candidate(
        &mut self,
        job_id: JobId,
        scheduled_at: Timestamp,
    ) -> bool {
        self.ledger.reconcile_leased(job_id, scheduled_at)
    }

    pub(crate) fn candidate_ids(&self) -> impl Iterator<Item = JobId> + '_ {
        self.ledger.candidates.keys().copied()
    }

    pub(crate) fn remove_candidate(&mut self, job_id: JobId) {
        self.ledger.remove_candidate(job_id);
    }

    /// Drops terminal and absent projections after their durable lifecycle
    /// transition has been committed. The owner is an accounting cache, not a
    /// terminal history store.
    pub(crate) fn compact_terminal_candidates(&mut self) {
        let job_ids: Vec<_> = self.ledger.terminal_or_absent_candidates().collect();
        for job_id in job_ids {
            if self.ledger.compact_candidate(job_id) {
                self.metadata.remove(&job_id);
            }
        }
        self.ledger.compact_empty_scopes();
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn candidate_state(&self, job_id: JobId) -> Option<FairCandidateState> {
        self.ledger.candidate_state(job_id)
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn candidate_snapshot(&self, job_id: JobId) -> Option<FairCandidateSnapshot> {
        self.ledger.candidates.get(&job_id).map(|record| {
            let candidate = &record.candidate;
            FairCandidateSnapshot {
                job_id,
                scope: candidate.scope.clone(),
                priority: candidate.priority,
                cost_units: candidate.cost_units,
                scheduled_at: candidate.scheduled_at,
                payload_bytes: candidate.payload_bytes,
                ordering_key: candidate.ordering_key.clone(),
                ordering_position: candidate.ordering_position,
                block: candidate.block,
                state: record.state,
                service_transitions: record.service_transitions,
            }
        })
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn order_snapshot(&self, ordering_key: &OrderingKey) -> Option<FairOrderSnapshot> {
        self.ledger
            .orders
            .get(ordering_key)
            .map(|order| FairOrderSnapshot {
                head: order.head,
                owner: order.owner,
                in_flight: order.in_flight,
                acquisitions: order.acquisitions,
                releases: order.releases,
            })
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn has_leased_candidate(&self) -> bool {
        self.ledger
            .candidates
            .values()
            .any(|record| record.state == FairCandidateState::Leased)
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn priority_deficit(&self) -> crate::fairness::PriorityDeficit {
        self.ledger.priority_deficit()
    }
}
