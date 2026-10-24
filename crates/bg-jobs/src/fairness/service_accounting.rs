//! Actual work cost and its position in a virtual service era.

use std::num::NonZeroU16;

#[derive(Clone, Debug, Default)]
pub(crate) struct ServiceAccounting {
    pub(super) cost: u64,
    pub(super) origin: u128,
    pub(super) base_cost: u64,
}

impl ServiceAccounting {
    pub(super) fn position(&self, weight: NonZeroU16, floor: u128) -> u128 {
        self.origin
            .saturating_add(super::normalized_service(
                self.cost.saturating_sub(self.base_cost),
                weight,
            ))
            .max(floor)
    }

    pub(super) fn align(&mut self, weight: NonZeroU16, floor: u128) {
        if self.position(weight, 0) < floor {
            self.origin = floor;
            self.base_cost = self.cost;
        }
    }

    pub(super) fn reweight(&mut self, previous_weight: NonZeroU16) {
        self.origin = self.position(previous_weight, 0);
        self.base_cost = self.cost;
    }

    pub(super) fn cost_delta(&self, weight: NonZeroU16, cost: u16) -> u128 {
        let current = self.cost.saturating_sub(self.base_cost);
        super::normalized_service(current.saturating_add(u64::from(cost)), weight)
            .saturating_sub(super::normalized_service(current, weight))
    }

    pub(super) fn charge(&mut self, cost: u16) {
        self.cost = self.cost.saturating_add(u64::from(cost));
    }

    pub(super) fn undo(&mut self, cost: u16) {
        self.cost = self.cost.saturating_sub(u64::from(cost));
        self.base_cost = self.base_cost.min(self.cost);
    }
}
