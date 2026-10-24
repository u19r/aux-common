//! Mutable and observable fair-dispatch scope state.

use std::num::NonZeroU16;

use super::{
    budget::FairnessBudget, candidate::CandidateBlock, service_accounting::ServiceAccounting,
};
use crate::{
    ids::FairnessKey,
    policy::{FairnessClass, FairnessPath},
};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum FairScope {
    /// A primary scope plus an optional child. Children never become
    /// independent top-level service domains.
    Scoped {
        primary: FairnessKey,
        secondary: Option<FairnessKey>,
    },
    LowVolume,
}

impl FairScope {
    pub fn primary_scope(&self) -> Self {
        match self {
            Self::Scoped { primary, .. } => Self::Scoped {
                primary: primary.clone(),
                secondary: None,
            },
            Self::LowVolume => Self::LowVolume,
        }
    }

    pub const fn is_secondary(&self) -> bool {
        matches!(
            self,
            Self::Scoped {
                secondary: Some(_),
                ..
            }
        )
    }
}

impl From<FairnessClass> for FairScope {
    fn from(class: FairnessClass) -> Self {
        match class {
            FairnessClass::Scoped(path) => {
                let FairnessPath { primary, secondary } = path;
                Self::Scoped { primary, secondary }
            }
            FairnessClass::LowVolume => Self::LowVolume,
        }
    }
}

impl From<&FairnessClass> for FairScope {
    fn from(class: &FairnessClass) -> Self {
        Self::from(class.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FairVolumeMode {
    Scoped,
    LowVolume,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeSnapshot {
    pub primary: Option<FairnessKey>,
    pub secondary: Option<FairnessKey>,
    pub mode: FairVolumeMode,
    /// True when an authoritative candidate in this scope has a ready route.
    pub ready: bool,
    pub head: u64,
    pub order: u64,
    pub cost: NonZeroU16,
    pub block: Option<CandidateBlock>,
    pub weight: NonZeroU16,
    pub served: u64,
    pub served_cost: u64,
    pub in_flight: u32,
    pub permits: u32,
    pub rate: u32,
    pub quiet_dwell: u32,
    pub errors: u128,
    pub acquisitions: u64,
    pub releases: u64,
}

#[cfg(any(test, feature = "test-support"))]
impl ScopeSnapshot {
    pub(crate) fn from_state(scope: &FairScope, state: &ScopeState) -> Self {
        let (primary, secondary) = match scope {
            FairScope::Scoped { primary, secondary } => (Some(primary.clone()), secondary.clone()),
            FairScope::LowVolume => (None, None),
        };
        Self {
            primary,
            secondary,
            mode: state.mode,
            ready: state.is_ready(),
            head: state.head,
            order: state.order,
            cost: state.cost,
            block: state.block,
            weight: state.weight,
            served: state.served,
            served_cost: state.service.cost,
            in_flight: state.in_flight,
            permits: state.permits,
            rate: state.rate,
            quiet_dwell: state.quiet_dwell,
            errors: state.errors,
            acquisitions: state.acquisitions,
            releases: state.releases,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ScopeState {
    pub(crate) mode: FairVolumeMode,
    pub(crate) ready_count: u32,
    pub(crate) head: u64,
    pub(crate) order: u64,
    pub(crate) cost: NonZeroU16,
    pub(crate) block: Option<CandidateBlock>,
    pub(crate) weight: NonZeroU16,
    pub(crate) served: u64,
    pub(crate) service: ServiceAccounting,
    pub(crate) own_service: ServiceAccounting,
    pub(crate) child_service_clock: u128,
    pub(crate) in_flight: u32,
    pub(crate) permits: u32,
    pub(crate) rate: u32,
    pub(crate) quiet_dwell: u32,
    pub(crate) errors: u128,
    pub(crate) acquisitions: u64,
    pub(crate) releases: u64,
}

impl ScopeState {
    pub(crate) fn new(
        scope: &FairScope,
        cost: NonZeroU16,
        mode: FairVolumeMode,
        budget: FairnessBudget,
    ) -> Self {
        let initial_order = if matches!(
            scope,
            FairScope::Scoped {
                secondary: None,
                ..
            } | FairScope::LowVolume
        ) {
            1
        } else {
            0
        };
        Self {
            mode,
            ready_count: 0,
            head: initial_order,
            order: initial_order,
            cost,
            block: None,
            weight: NonZeroU16::MIN,
            served: 0,
            service: ServiceAccounting::default(),
            own_service: ServiceAccounting::default(),
            child_service_clock: 0,
            in_flight: 0,
            permits: budget.max_concurrency_per_scope.get(),
            rate: budget.max_rate_per_scope.get(),
            quiet_dwell: 0,
            errors: 0,
            acquisitions: 0,
            releases: 0,
        }
    }

    pub(crate) const fn is_ready(&self) -> bool {
        self.ready_count != 0
    }
}
