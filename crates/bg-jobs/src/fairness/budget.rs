//! Bounded fair-dispatch budget values.

use std::num::{NonZeroU16, NonZeroU32, NonZeroUsize};

use crate::{error::ValidationError, model::MAX_COST_UNITS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FairnessBudgetInput {
    pub candidate_window: NonZeroU32,
    pub max_concurrency_per_scope: NonZeroU32,
    pub max_rate_per_scope: NonZeroU32,
    pub max_low_volume_service: NonZeroU32,
    pub max_payload_bytes: NonZeroUsize,
    pub max_cost_units: NonZeroU16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FairnessBudget {
    pub(crate) candidate_window: NonZeroU32,
    pub(crate) max_concurrency_per_scope: NonZeroU32,
    pub(crate) max_rate_per_scope: NonZeroU32,
    pub(crate) max_low_volume_service: NonZeroU32,
    pub(crate) max_payload_bytes: NonZeroUsize,
    pub(crate) max_cost_units: NonZeroU16,
}

impl FairnessBudget {
    pub fn try_new(input: FairnessBudgetInput) -> Result<Self, ValidationError> {
        if input.max_cost_units.get() > MAX_COST_UNITS {
            return Err(ValidationError::TooLong {
                field: "fairness budget cost units",
                maximum: MAX_COST_UNITS as usize,
                actual: input.max_cost_units.get() as usize,
            });
        }
        Ok(Self {
            candidate_window: input.candidate_window,
            max_concurrency_per_scope: input.max_concurrency_per_scope,
            max_rate_per_scope: input.max_rate_per_scope,
            max_low_volume_service: input.max_low_volume_service,
            max_payload_bytes: input.max_payload_bytes,
            max_cost_units: input.max_cost_units,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn tiny() -> Self {
        Self {
            candidate_window: NonZeroU32::new(4).unwrap_or(NonZeroU32::MIN),
            max_concurrency_per_scope: NonZeroU32::MIN,
            max_rate_per_scope: NonZeroU32::new(4).unwrap_or(NonZeroU32::MIN),
            max_low_volume_service: NonZeroU32::MIN,
            max_payload_bytes: NonZeroUsize::new(crate::policy::TINY_MAX_PAYLOAD_BYTES_IN_FLIGHT)
                .unwrap_or(NonZeroUsize::MIN),
            max_cost_units: NonZeroU16::new(MAX_COST_UNITS).unwrap_or(NonZeroU16::MIN),
        }
    }

    pub const fn max_concurrency_per_scope(self) -> NonZeroU32 {
        self.max_concurrency_per_scope
    }

    pub const fn max_rate_per_scope(self) -> NonZeroU32 {
        self.max_rate_per_scope
    }

    pub const fn max_low_volume_service(self) -> NonZeroU32 {
        self.max_low_volume_service
    }

    pub const fn max_payload_bytes(self) -> NonZeroUsize {
        self.max_payload_bytes
    }

    pub const fn max_cost_units(self) -> NonZeroU16 {
        self.max_cost_units
    }

    /// `E = C * (W + N)`, the bounded normalized service error.
    pub fn normalized_error_bound(self) -> u64 {
        u64::from(self.max_cost_units.get()).saturating_mul(
            u64::from(self.candidate_window.get())
                .saturating_add(u64::from(self.max_concurrency_per_scope.get())),
        )
    }
}
