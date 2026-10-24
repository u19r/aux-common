//! Scope capacity acquisition and release for fair admission.

use super::super::state::FairnessLedger;
use crate::fairness::{FairPermit, FairScope};

#[derive(Clone, Copy)]
pub(super) enum ScopeCharge {
    Service,
    ParentCapacity,
}

#[derive(Clone, Copy)]
pub(in crate::fairness::fairness_ledger) enum CapacityRelease {
    RestoreRate,
    #[cfg(any(test, feature = "test-support"))]
    PreserveRate,
    UndoService,
}

impl FairnessLedger {
    pub(in crate::fairness::fairness_ledger) fn release_capacity(
        &mut self,
        permit: &FairPermit,
        release: CapacityRelease,
    ) {
        self.release_scope(
            &permit.scope,
            release,
            permit.cost_units.get(),
            ScopeCharge::Service,
        );
        if let Some(primary) = permit.primary.as_ref() {
            self.release_scope(
                primary,
                release,
                permit.cost_units.get(),
                ScopeCharge::ParentCapacity,
            );
        }
        if let Some(key) = &permit.ordering_key
            && let Some(order) = self.orders.get_mut(key)
        {
            order.in_flight = false;
            order.releases = order.releases.saturating_add(1);
        }
    }

    pub(in crate::fairness::fairness_ledger) fn restore_reconciled_low_volume_service(
        &mut self,
        permit: &FairPermit,
    ) {
        if !matches!(&permit.scope, FairScope::LowVolume) {
            return;
        }
        if let Some(state) = self.scopes.get_mut(&permit.scope) {
            state.served = state.served.saturating_sub(1);
            state.service.undo(permit.cost_units.get());
        }
    }

    pub(super) fn acquire_scope(&mut self, scope: &FairScope, cost: u16, charge: ScopeCharge) {
        if let Some(state) = self.scopes.get_mut(scope) {
            state.permits = state.permits.saturating_sub(1);
            state.rate = state.rate.saturating_sub(1);
            state.in_flight = state.in_flight.saturating_add(1);
            if matches!(charge, ScopeCharge::Service) {
                state.served = state.served.saturating_add(1);
            }
            state.service.charge(cost);
            if matches!(charge, ScopeCharge::Service)
                && matches!(
                    scope,
                    FairScope::Scoped {
                        secondary: None,
                        ..
                    }
                )
            {
                state.own_service.charge(cost);
            }
            state.acquisitions = state.acquisitions.saturating_add(1);
        }
    }

    pub(super) fn charge_selection(
        &mut self,
        selection: &super::selection::state::CandidateSelection,
    ) {
        self.align_selection_service(selection);
        self.acquire_scope(
            &selection.scope,
            selection.cost_units.get(),
            ScopeCharge::Service,
        );
        if let Some(primary) = &selection.primary {
            self.acquire_scope(
                primary,
                selection.cost_units.get(),
                ScopeCharge::ParentCapacity,
            );
        }
        if let Some(key) = &selection.ordering_key
            && let Some(order) = self.orders.get_mut(key)
        {
            order.owner = selection.job_id;
            order.in_flight = true;
            order.acquisitions = order.acquisitions.saturating_add(1);
        }
    }

    fn align_selection_service(&mut self, selection: &super::selection::state::CandidateSelection) {
        if matches!(selection.scope, FairScope::LowVolume) {
            return;
        }
        let primary = selection.primary.as_ref().unwrap_or(&selection.scope);
        let child_floor = self
            .scopes
            .get(primary)
            .map_or(0, |state| state.child_service_clock);
        if let Some(state) = self.scopes.get_mut(&selection.scope) {
            let floor = if selection.primary.is_some() {
                child_floor
            } else {
                self.service_clock
            };
            state.service.align(state.weight, floor);
            if selection.primary.is_none() {
                state.own_service.align(state.weight, child_floor);
            }
        }
        if let Some(primary) = selection.primary.as_ref()
            && let Some(state) = self.scopes.get_mut(primary)
        {
            state.service.align(state.weight, self.service_clock);
        }
    }

    fn release_scope(
        &mut self,
        scope: &FairScope,
        release: CapacityRelease,
        cost: u16,
        charge: ScopeCharge,
    ) {
        let max_concurrency = self.budget.max_concurrency_per_scope().get();
        let max_rate = self.budget.max_rate_per_scope().get();
        if let Some(state) = self.scopes.get_mut(scope) {
            state.in_flight = state.in_flight.saturating_sub(1);
            state.permits = state.permits.saturating_add(1).min(max_concurrency);
            if matches!(
                release,
                CapacityRelease::RestoreRate | CapacityRelease::UndoService
            ) {
                state.rate = state.rate.saturating_add(1).min(max_rate);
            }
            if matches!(release, CapacityRelease::UndoService) {
                state.service.undo(cost);
                if matches!(charge, ScopeCharge::Service) {
                    state.served = state.served.saturating_sub(1);
                    if matches!(
                        scope,
                        FairScope::Scoped {
                            secondary: None,
                            ..
                        }
                    ) {
                        state.own_service.undo(cost);
                    }
                }
            }
            state.releases = state.releases.saturating_add(1);
        }
    }
}
