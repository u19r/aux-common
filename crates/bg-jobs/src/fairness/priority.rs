//! Priority deficit accounting and normalized service helpers.

use std::num::NonZeroU16;

use super::constants::{BULK_WEIGHT, CRITICAL_WEIGHT, DEFAULT_WEIGHT, NORMALIZATION_SCALE};
use crate::policy::Priority;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PriorityDeficit {
    critical_served: u64,
    default_served: u64,
    bulk_served: u64,
    critical_window: u32,
    default_window: u32,
    bulk_window: u32,
    cycle: u32,
}

impl PriorityDeficit {
    pub(crate) const fn from_parts(
        critical_served: u64,
        default_served: u64,
        bulk_served: u64,
        critical_window: u32,
        default_window: u32,
        bulk_window: u32,
        cycle: u32,
    ) -> Self {
        Self {
            critical_served,
            default_served,
            bulk_served,
            critical_window,
            default_window,
            bulk_window,
            cycle,
        }
    }

    pub const fn critical_served(self) -> u64 {
        self.critical_served
    }
    pub const fn default_served(self) -> u64 {
        self.default_served
    }
    pub const fn bulk_served(self) -> u64 {
        self.bulk_served
    }
    pub const fn critical_window(self) -> u32 {
        self.critical_window
    }
    pub const fn default_window(self) -> u32 {
        self.default_window
    }
    pub const fn bulk_window(self) -> u32 {
        self.bulk_window
    }
    pub const fn cycle(self) -> u32 {
        self.cycle
    }

    pub(crate) fn allows(
        self,
        priority: Priority,
        cost: u32,
        bulk_ready: bool,
        bound: u32,
    ) -> bool {
        if cost == 0
            || (bulk_ready
                && self.cycle.saturating_add(cost) >= bound
                && priority != Priority::Bulk)
            || !self.window_allows(priority, cost)
        {
            return false;
        }
        match priority {
            Priority::Critical => {
                self.critical_served.saturating_add(u64::from(cost))
                    <= 8_u64.saturating_mul(self.bulk_served.saturating_add(1))
            }
            Priority::Default => {
                self.default_served.saturating_add(u64::from(cost))
                    <= 4_u64.saturating_mul(self.bulk_served.saturating_add(1))
            }
            Priority::Bulk => true,
        }
    }

    fn window_allows(self, priority: Priority, cost: u32) -> bool {
        match priority {
            Priority::Critical => self.critical_window.saturating_add(cost) <= CRITICAL_WEIGHT,
            Priority::Default => self.default_window.saturating_add(cost) <= DEFAULT_WEIGHT,
            Priority::Bulk => self.bulk_window.saturating_add(cost) <= BULK_WEIGHT,
        }
    }

    pub(crate) fn charge(&mut self, priority: Priority, cost: u32) {
        let value = u64::from(cost);
        match priority {
            Priority::Critical => {
                self.critical_served = self.critical_served.saturating_add(value);
                self.critical_window = self.critical_window.saturating_add(cost);
                self.cycle = self.cycle.saturating_add(cost);
            }
            Priority::Default => {
                self.default_served = self.default_served.saturating_add(value);
                self.default_window = self.default_window.saturating_add(cost);
                self.cycle = self.cycle.saturating_add(cost);
            }
            Priority::Bulk => {
                self.bulk_served = self.bulk_served.saturating_add(value);
                self.bulk_window = self.bulk_window.saturating_add(cost);
                self.cycle = 0;
            }
        }
        if self.critical_window >= 8 && self.default_window >= 4 && self.bulk_window >= 1 {
            self.critical_window = 0;
            self.default_window = 0;
            self.bulk_window = 0;
        }
    }
}

pub fn normalized_service(served_cost: u64, weight: NonZeroU16) -> u128 {
    u128::from(served_cost).saturating_mul(u128::from(NORMALIZATION_SCALE))
        / u128::from(weight.get())
}

#[cfg(feature = "test-support")]
pub fn normalized_service_error(left: u64, right: u64, weight: NonZeroU16) -> u128 {
    normalized_service(left, weight).abs_diff(normalized_service(right, weight))
}
