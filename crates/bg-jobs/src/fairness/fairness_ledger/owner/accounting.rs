//! Cross-scope invariants of persisted service accounting.

use std::collections::BTreeMap;

use super::state::FairDispatchOwner;
use crate::{error::StoreDataError, fairness::FairScope};

impl FairDispatchOwner {
    pub(super) fn validate_service_accounting(&self) -> Result<(), StoreDataError> {
        let mut retained_costs = BTreeMap::<FairScope, u64>::new();
        for (scope, state) in &self.ledger.scopes {
            if matches!(
                scope,
                FairScope::Scoped {
                    secondary: None,
                    ..
                }
            ) {
                let cost = retained_costs.entry(scope.clone()).or_default();
                *cost = cost
                    .checked_add(state.own_service.cost)
                    .ok_or(StoreDataError::Malformed("fair owner aggregate service"))?;
                continue;
            }
            if state.own_service.cost != 0
                || state.own_service.origin != 0
                || state.own_service.base_cost != 0
                || state.child_service_clock != 0
            {
                return Err(StoreDataError::Malformed("fair owner non-primary service"));
            }
            if scope.is_secondary() {
                let cost = retained_costs.entry(scope.primary_scope()).or_default();
                *cost = cost
                    .checked_add(state.service.cost)
                    .ok_or(StoreDataError::Malformed("fair owner aggregate service"))?;
            }
        }
        for (primary, minimum) in retained_costs {
            let state = self
                .ledger
                .scopes
                .get(&primary)
                .ok_or(StoreDataError::Malformed(
                    "fair owner missing primary service",
                ))?;
            // Compaction can delete historical children while retaining their
            // parent's cost.
            if state.service.cost < minimum {
                return Err(StoreDataError::Malformed("fair owner aggregate service"));
            }
        }
        Ok(())
    }
}
