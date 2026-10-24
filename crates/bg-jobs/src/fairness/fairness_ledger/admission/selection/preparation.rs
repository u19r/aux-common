//! Build the immutable snapshot used by fair-candidate admission.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    super::super::state::FairnessLedger,
    state::{
        CandidateFacts, CandidatePreparation, CandidateSelection, PreparedCandidate, PrimaryStats,
        SelectionMetrics, SelectionPass, ServiceExtrema,
    },
};
use crate::{
    fairness::{FairScope, FairnessRejection},
    ids::JobId,
    time::Timestamp,
};

impl FairnessLedger {
    pub(super) fn prepare_selection_pass(
        &self,
        now: Option<Timestamp>,
        eligible: Option<&BTreeSet<JobId>>,
    ) -> SelectionPass {
        let primary_indices = self.primary_indices();
        let mut primary_stats = self.prepare_primary_stats(&primary_indices);
        let candidates =
            self.prepare_candidates(now, eligible, &primary_indices, &mut primary_stats);
        let service_extrema = Self::build_service_extrema(&primary_stats);
        let candidates = Self::attach_candidate_counts(candidates, &primary_stats);
        SelectionPass {
            candidates,
            service_extrema,
        }
    }

    fn prepare_primary_stats(
        &self,
        primary_indices: &BTreeMap<FairScope, usize>,
    ) -> Vec<PrimaryStats> {
        let mut primary_stats: Vec<PrimaryStats> = (0..primary_indices.len())
            .map(|_| PrimaryStats::default())
            .collect();
        for (scope, &primary_index) in primary_indices {
            #[cfg(test)]
            super::record_selection_scope_visit();
            if let Some(state) = self.scopes.get(scope) {
                primary_stats[primary_index].normalized_service =
                    if matches!(scope, FairScope::LowVolume) {
                        0
                    } else {
                        state.service.position(state.weight, self.service_clock)
                    };
            }
        }
        primary_stats
    }

    fn prepare_candidates(
        &self,
        now: Option<Timestamp>,
        eligible: Option<&BTreeSet<JobId>>,
        primary_indices: &BTreeMap<FairScope, usize>,
        primary_stats: &mut [PrimaryStats],
    ) -> Vec<PreparedCandidate> {
        let mut candidates = Vec::with_capacity(self.candidates.len());
        for record in self.candidates.values() {
            #[cfg(test)]
            super::record_selection_scan_visit();
            candidates.push(self.prepare_candidate_entry(
                &record.candidate,
                record.state.has_ready_route(),
                now,
                eligible,
                primary_indices,
                primary_stats,
            ));
        }
        candidates
    }

    fn prepare_candidate_entry(
        &self,
        candidate: &crate::fairness::FairCandidate,
        has_ready_route: bool,
        now: Option<Timestamp>,
        eligible: Option<&BTreeSet<JobId>>,
        primary_indices: &BTreeMap<FairScope, usize>,
        primary_stats: &mut [PrimaryStats],
    ) -> PreparedCandidate {
        let job_id = candidate.job_id();
        let in_scope = eligible.is_none_or(|ids| ids.contains(&job_id));
        let ready = in_scope && has_ready_route;
        self.record_ready_candidate(candidate, ready, primary_indices, primary_stats);
        let due = in_scope && now.is_none_or(|now| candidate.scheduled_at() <= now);
        let selection = if in_scope {
            self.prepare_candidate_for_pass(job_id, primary_indices, primary_stats)
        } else {
            Err(FairnessRejection::UnknownScope)
        };
        self.mark_eligible_candidate(ready, due, &selection, primary_stats);
        PreparedCandidate {
            job_id,
            ready,
            due,
            preparation: selection,
        }
    }

    fn record_ready_candidate(
        &self,
        candidate: &crate::fairness::FairCandidate,
        ready: bool,
        primary_indices: &BTreeMap<FairScope, usize>,
        primary_stats: &mut [PrimaryStats],
    ) {
        if !ready {
            return;
        }
        let primary = candidate.scope().primary_scope();
        if let Some(&primary_index) = primary_indices.get(&primary) {
            primary_stats[primary_index].candidate_count = primary_stats[primary_index]
                .candidate_count
                .saturating_add(1);
        }
    }

    fn mark_eligible_candidate(
        &self,
        ready: bool,
        due: bool,
        selection: &Result<CandidatePreparation, FairnessRejection>,
        primary_stats: &mut [PrimaryStats],
    ) {
        if ready
            && due
            && let Ok(preparation) = selection
            && !preparation.facts.low_volume
            && preparation.facts.cost_units <= self.budget.max_cost_units()
        {
            let stats = &mut primary_stats[preparation.metrics.primary_index];
            stats.eligible = true;
            let service = preparation.metrics.child_service;
            stats.child_minimum = Some(
                stats
                    .child_minimum
                    .map_or(service, |minimum| minimum.min(service)),
            );
        }
    }

    fn build_service_extrema(primary_stats: &[PrimaryStats]) -> ServiceExtrema {
        let mut service_extrema = ServiceExtrema::default();
        for (primary_index, stats) in primary_stats.iter().enumerate() {
            if stats.eligible {
                service_extrema.insert(primary_index, stats.normalized_service);
            }
        }
        service_extrema
    }

    fn attach_candidate_counts(
        mut candidates: Vec<PreparedCandidate>,
        primary_stats: &[PrimaryStats],
    ) -> Vec<PreparedCandidate> {
        for prepared in &mut candidates {
            if let Ok(preparation) = &mut prepared.preparation {
                let stats = &primary_stats[preparation.metrics.primary_index];
                preparation.metrics.primary_candidate_count = stats.candidate_count;
                preparation.metrics.child_service_lag = stats.child_minimum.map_or(0, |minimum| {
                    preparation.metrics.child_service.saturating_sub(minimum)
                });
            }
        }
        candidates
    }

    fn primary_indices(&self) -> BTreeMap<FairScope, usize> {
        let mut indices = BTreeMap::new();
        for scope in self.scopes.keys() {
            #[cfg(test)]
            super::record_selection_scope_visit();
            if !scope.is_secondary() {
                let index = indices.len();
                indices.insert(scope.clone(), index);
            }
        }
        indices
    }

    fn prepare_candidate_for_pass(
        &self,
        job_id: JobId,
        primary_indices: &BTreeMap<FairScope, usize>,
        primary_stats: &[PrimaryStats],
    ) -> Result<CandidatePreparation, FairnessRejection> {
        let validated = self.validate_candidate(job_id)?;
        let candidate = validated.candidate;
        let (primary_index, primary_service, admission_service, child_service) =
            self.candidate_service_metrics(candidate, primary_indices, primary_stats)?;
        let scope = candidate.scope();
        Ok(CandidatePreparation {
            facts: CandidateFacts {
                scheduled_at: candidate.scheduled_at(),
                priority: candidate.priority(),
                cost_units: candidate.cost_units(),
                low_volume: matches!(scope, FairScope::LowVolume),
            },
            metrics: SelectionMetrics {
                primary_index,
                primary_service,
                admission_service,
                child_service,
                child_service_lag: 0,
                primary_candidate_count: 0,
            },
        })
    }

    fn candidate_service_metrics(
        &self,
        candidate: &crate::fairness::FairCandidate,
        primary_indices: &BTreeMap<FairScope, usize>,
        primary_stats: &[PrimaryStats],
    ) -> Result<(usize, u128, u128, u128), FairnessRejection> {
        let scope = candidate.scope();
        let primary_scope = scope.is_secondary().then(|| scope.primary_scope());
        let primary_index = match primary_scope.as_ref() {
            Some(primary) => primary_indices.get(primary),
            None => primary_indices.get(scope),
        }
        .copied()
        .ok_or(FairnessRejection::UnknownScope)?;
        let primary_state = match primary_scope.as_ref() {
            Some(primary) => self.scopes.get(primary),
            None => self.scopes.get(scope),
        }
        .ok_or(FairnessRejection::UnknownScope)?;
        let primary_service = primary_stats
            .get(primary_index)
            .map(|stats| stats.normalized_service)
            .ok_or(FairnessRejection::UnknownScope)?;
        let child_state = self
            .scopes
            .get(scope)
            .ok_or(FairnessRejection::UnknownScope)?;
        let admission_service = primary_state
            .service
            .position(primary_state.weight, self.service_clock)
            .saturating_add(
                primary_state
                    .service
                    .cost_delta(primary_state.weight, candidate.cost_units().get()),
            );
        let child_service = if matches!(scope, FairScope::LowVolume) {
            0
        } else if scope.is_secondary() {
            child_state
                .service
                .position(child_state.weight, primary_state.child_service_clock)
        } else {
            primary_state
                .own_service
                .position(primary_state.weight, primary_state.child_service_clock)
        };
        Ok((
            primary_index,
            primary_service,
            admission_service,
            child_service,
        ))
    }

    pub(super) fn prepare_candidate(
        &self,
        job_id: JobId,
    ) -> Result<CandidateSelection, FairnessRejection> {
        let validated = self.validate_candidate(job_id)?;
        let candidate = validated.candidate;
        let scope = candidate.scope().clone();
        let primary = scope.is_secondary().then(|| scope.primary_scope());
        Ok(CandidateSelection {
            job_id: candidate.job_id(),
            scope,
            primary,
            priority: candidate.priority(),
            cost_units: candidate.cost_units(),
            ordering_key: candidate.ordering_key().cloned(),
            ordering_position: candidate.ordering_position(),
            acquisition_generation: validated.acquisition_generation,
        })
    }
}
