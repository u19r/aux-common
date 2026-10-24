//! Admission predicates for a prepared fair-candidate selection.

use super::{
    super::super::state::FairnessLedger,
    state::{CandidatePreparation, PreparedCandidate, SelectionPass},
};
use crate::{
    fairness::{FairCandidate, FairScope, FairnessRejection},
    ids::JobId,
    policy::Priority,
};

impl FairnessLedger {
    pub(super) fn selection_score(
        job_id: JobId,
        preparation: &CandidatePreparation,
    ) -> super::SelectionScore {
        let facts = preparation.facts;
        let metrics = &preparation.metrics;
        let priority = match facts.priority {
            Priority::Critical => 0,
            Priority::Default => 1,
            Priority::Bulk => 2,
        };
        (
            metrics.primary_service,
            metrics.primary_candidate_count,
            metrics.child_service_lag,
            priority,
            facts.scheduled_at,
            job_id,
        )
    }

    pub(super) fn check_selection<'a>(
        &self,
        prepared: &'a PreparedCandidate,
        bulk_ready: bool,
    ) -> Result<&'a CandidatePreparation, FairnessRejection> {
        let preparation = prepared.preparation.as_ref().map_err(|reason| *reason)?;
        let facts = preparation.facts;
        if facts.cost_units > self.budget.max_cost_units() {
            return Err(FairnessRejection::ScopeCapacity);
        }
        self.check_priority(facts.priority, facts.cost_units.get(), bulk_ready)?;
        Ok(preparation)
    }

    pub(super) fn validate_candidate(
        &self,
        job_id: JobId,
    ) -> Result<super::state::ValidatedCandidate<'_>, FairnessRejection> {
        let record = self
            .candidates
            .get(&job_id)
            .ok_or(FairnessRejection::UnknownScope)?;
        let candidate = &record.candidate;
        if !record.state.has_ready_route() {
            return Err(FairnessRejection::OrderingHead);
        }
        if let Some(block) = candidate.block() {
            return Err(FairnessRejection::Blocked(block));
        }
        if candidate.payload_bytes() > self.budget.max_payload_bytes().get() {
            return Err(FairnessRejection::PayloadCapacity);
        }
        let acquisition_generation =
            super::state::next_permit_generation(record.acquisition_generation)?;
        self.check_scope(candidate.scope(), candidate.cost_units().get())?;
        if candidate.scope().is_secondary() {
            let primary = candidate.scope().primary_scope();
            self.check_scope(&primary, candidate.cost_units().get())?;
        }
        self.check_order(candidate)?;
        Ok(super::state::ValidatedCandidate {
            candidate,
            acquisition_generation,
        })
    }

    fn check_scope(&self, scope: &FairScope, cost: u16) -> Result<(), FairnessRejection> {
        let Some(state) = self.scopes.get(scope) else {
            return Err(FairnessRejection::UnknownScope);
        };
        if let Some(block) = state.block {
            return Err(FairnessRejection::Blocked(block));
        }
        if state.service.cost.checked_add(u64::from(cost)).is_none()
            || state.in_flight >= self.budget.max_concurrency_per_scope().get()
            || state.permits == 0
        {
            return Err(FairnessRejection::ScopeCapacity);
        }
        if state.rate == 0 {
            return Err(FairnessRejection::RateCapacity);
        }
        if state.mode == crate::FairVolumeMode::LowVolume
            && state.served >= u64::from(self.budget.max_low_volume_service().get())
        {
            return Err(FairnessRejection::LowVolumeCapacity);
        }
        Ok(())
    }

    fn check_order(&self, candidate: &FairCandidate) -> Result<(), FairnessRejection> {
        let Some(key) = candidate.ordering_key() else {
            return Ok(());
        };
        let Some(order) = self.orders.get(key) else {
            return Err(FairnessRejection::OrderingHead);
        };
        if order.in_flight || candidate.ordering_position() != order.head {
            return Err(FairnessRejection::OrderingHead);
        }
        Ok(())
    }

    fn check_priority(
        &self,
        priority: Priority,
        cost: u16,
        bulk_ready: bool,
    ) -> Result<(), FairnessRejection> {
        let bound = self
            .budget
            .normalized_error_bound()
            .min(u64::from(u32::MAX)) as u32;
        if self
            .priority
            .allows(priority, u32::from(cost), bulk_ready, bound)
        {
            Ok(())
        } else {
            Err(FairnessRejection::PriorityDeficit)
        }
    }

    pub(super) fn check_normalized_admission(
        &self,
        preparation: &CandidatePreparation,
        pass: &SelectionPass,
    ) -> Result<(), FairnessRejection> {
        if preparation.facts.low_volume {
            return Ok(());
        }
        let bound = u128::from(self.budget.normalized_error_bound())
            .saturating_mul(u128::from(crate::NORMALIZATION_SCALE));
        if !pass.service_extrema.allows(
            preparation.metrics.primary_index,
            preparation.metrics.admission_service,
            bound,
        ) {
            return Err(FairnessRejection::NormalizedServiceBound);
        }
        Ok(())
    }

    /// Returns true only for a bulk candidate that could actually be selected
    /// in this admission snapshot. Future, blocked, oversized, or
    /// fairness-ineligible entries must not suppress other priorities.
    pub(super) fn has_admissible_bulk(&self, pass: &SelectionPass) -> bool {
        pass.candidates.iter().any(|prepared| {
            #[cfg(test)]
            super::record_selection_scan_visit();
            prepared.ready
                && prepared.due
                && prepared.preparation.as_ref().is_ok_and(|preparation| {
                    preparation.facts.priority == Priority::Bulk
                        && self
                            .check_priority(
                                preparation.facts.priority,
                                preparation.facts.cost_units.get(),
                                true,
                            )
                            .is_ok()
                        && self.check_normalized_admission(preparation, pass).is_ok()
                })
        })
    }
}
