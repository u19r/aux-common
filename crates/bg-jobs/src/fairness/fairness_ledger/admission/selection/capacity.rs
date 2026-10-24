//! Capacity settlement and priority-window transitions for fair selection.

use super::{
    super::super::{
        index::{CandidateRoute, IndexRefresh},
        state::FairnessLedger,
    },
    state::{CandidatePreparation, CandidateSelection, SelectionPass},
};
use crate::{
    fairness::{FairCandidateState, FairPermit, FairScope},
    policy::Priority,
};

impl FairnessLedger {
    /// A priority window is an epoch over the lanes that can currently make
    /// progress. If all such lanes have consumed their configured share, a
    /// new epoch is required even when an unavailable lane cannot contribute
    /// its share.
    pub(super) fn reset_exhausted_priority_window(&mut self, pass: &SelectionPass) -> bool {
        let mut active = [false; 3];
        for prepared in &pass.candidates {
            if !prepared.ready || !prepared.due {
                continue;
            }
            let Ok(preparation) = &prepared.preparation else {
                continue;
            };
            if preparation.facts.cost_units > self.budget.max_cost_units() {
                continue;
            }
            if self.check_normalized_admission(preparation, pass).is_err() {
                continue;
            }
            let lane = match preparation.facts.priority {
                Priority::Critical => 0,
                Priority::Default => 1,
                Priority::Bulk => 2,
            };
            active[lane] = true;
        }
        if !active.into_iter().any(|available| available) {
            return false;
        }
        let priority = self.priority;
        let complete = (!active[0] || priority.critical_window() >= 8)
            && (!active[1] || priority.default_window() >= 4)
            && (!active[2] || priority.bulk_window() >= 1);
        if !complete {
            return false;
        }
        self.reset_priority_window();
        true
    }

    fn advance_service_clocks(
        &mut self,
        selection: &CandidateSelection,
        preparation: &CandidatePreparation,
        pass: &SelectionPass,
    ) {
        if matches!(selection.scope, FairScope::LowVolume) {
            return;
        }
        let child_minimum = preparation
            .metrics
            .child_service
            .saturating_sub(preparation.metrics.child_service_lag);
        let primary = selection.primary.as_ref().unwrap_or(&selection.scope);
        if let Some(state) = self.scopes.get_mut(primary) {
            state.child_service_clock = state.child_service_clock.max(child_minimum);
        }
        if let Some((_, minimum)) = pass.service_extrema.min {
            self.service_clock = self.service_clock.max(minimum);
        }
    }

    pub(super) fn settle_selection(
        &mut self,
        selection: CandidateSelection,
        preparation: &CandidatePreparation,
        pass: &SelectionPass,
    ) -> FairPermit {
        self.advance_service_clocks(&selection, preparation, pass);
        let old_route = self
            .candidates
            .get(&selection.job_id)
            .map(CandidateRoute::from_record);
        self.charge_selection(&selection);
        self.priority
            .charge(selection.priority, selection.cost_units.get() as u32);
        if let Some(record) = self.candidates.get_mut(&selection.job_id) {
            record.state = FairCandidateState::Leased;
            record.acquisition_generation = Some(selection.acquisition_generation);
        }
        let new_route = self
            .candidates
            .get(&selection.job_id)
            .map(CandidateRoute::from_record);
        self.replace_candidate_route(
            old_route.as_ref(),
            new_route.as_ref(),
            IndexRefresh::PreserveOrder,
        );
        FairPermit {
            job_id: selection.job_id,
            scope: selection.scope,
            primary: selection.primary,
            priority: selection.priority,
            cost_units: selection.cost_units,
            ordering_key: selection.ordering_key,
            ordering_position: selection.ordering_position,
            acquisition_generation: selection.acquisition_generation,
        }
    }
}
