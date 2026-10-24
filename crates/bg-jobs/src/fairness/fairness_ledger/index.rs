//! Rebuilding the advisory ready index from authoritative candidate state.

use std::collections::btree_map::Entry;

use super::state::FairnessLedger;
use crate::fairness::{FairScope, FairVolumeMode, ScopeState};

#[derive(Clone, Copy)]
pub(super) enum IndexRefresh {
    PreserveOrder,
    AdvanceOrder,
}

#[derive(Clone)]
pub(super) struct CandidateRoute {
    pub(super) scope: FairScope,
    pub(super) ready: bool,
    pub(super) ordering_position: u64,
}

impl CandidateRoute {
    pub(super) fn from_record(record: &super::state::CandidateRecord) -> Self {
        Self {
            scope: record.candidate.scope.clone(),
            ready: record.state.has_ready_route(),
            ordering_position: record.candidate.ordering_position,
        }
    }
}

impl FairnessLedger {
    pub(super) fn ensure_scope(&mut self, scope: &FairScope, cost: std::num::NonZeroU16) {
        let mode = if matches!(scope, FairScope::LowVolume) {
            FairVolumeMode::LowVolume
        } else {
            FairVolumeMode::Scoped
        };
        let budget = self.budget;
        match self.scopes.entry(scope.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(ScopeState::new(scope, cost, mode, budget));
            }
            Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                state.cost = state.cost.max(cost);
            }
        }
    }

    pub(crate) fn set_scope_weight(
        &mut self,
        scope: &FairScope,
        weight: std::num::NonZeroU16,
    ) -> bool {
        let Some(state) = self.scopes.get_mut(scope) else {
            return false;
        };
        if state.weight != weight {
            state.service.reweight(state.weight);
            state.own_service.reweight(state.weight);
            state.weight = weight;
        }
        true
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(super) fn set_scope_mode(&mut self, scope: &FairScope, mode: FairVolumeMode) -> bool {
        let Some(state) = self.scopes.get_mut(scope) else {
            return false;
        };
        state.mode = mode;
        true
    }

    pub(super) fn replace_candidate_route(
        &mut self,
        old: Option<&CandidateRoute>,
        new: Option<&CandidateRoute>,
        refresh: IndexRefresh,
    ) {
        if let Some(route) = old {
            self.adjust_ready_count(&route.scope, route.ready, false);
        }
        if let Some(route) = new {
            self.adjust_ready_count(&route.scope, route.ready, true);
            if route.ready
                && matches!(refresh, IndexRefresh::AdvanceOrder)
                && let Some(state) = self.scopes.get_mut(&route.scope)
            {
                state.order = state.order.max(route.ordering_position);
                if state.head == 0 || route.ordering_position < state.head {
                    state.head = route.ordering_position;
                }
            }
        }
    }

    pub(super) fn rebuild_ready_counts(&mut self) {
        for state in self.scopes.values_mut() {
            state.ready_count = 0;
        }
        let ready_scopes: Vec<_> = self
            .candidates
            .values()
            .filter(|record| record.state.has_ready_route())
            .map(|record| record.candidate.scope.clone())
            .collect();
        for scope in ready_scopes {
            self.adjust_ready_count(&scope, true, true);
        }
    }

    fn adjust_ready_count(&mut self, scope: &FairScope, ready: bool, add: bool) {
        if !ready {
            return;
        }
        if let Some(state) = self.scopes.get_mut(scope) {
            state.ready_count = if add {
                state.ready_count.saturating_add(1)
            } else {
                state.ready_count.saturating_sub(1)
            };
        }
    }
}
