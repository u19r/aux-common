//! Fair-dispatch candidates, permits, and rejection values.

use std::num::{NonZeroU16, NonZeroU64};

use super::scope::FairScope;
use crate::{
    error::ValidationError,
    ids::{JobId, OrderingKey},
    model::MAX_COST_UNITS,
    policy::{FairnessClass, Priority},
    time::Timestamp,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum CandidateBlock {
    Leased,
    Missing,
    Corrupt,
    Oversized,
    Poison,
    RateLimited,
    Capacity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FairCandidateInput {
    pub job_id: JobId,
    pub fairness: FairnessClass,
    pub priority: Priority,
    pub cost_units: NonZeroU16,
    pub scheduled_at: Timestamp,
    pub payload_bytes: usize,
    pub ordering_key: Option<OrderingKey>,
    pub ordering_position: u64,
    pub block: Option<CandidateBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FairCandidate {
    pub(crate) job_id: JobId,
    pub(crate) scope: FairScope,
    pub(crate) priority: Priority,
    pub(crate) cost_units: NonZeroU16,
    pub(crate) scheduled_at: Timestamp,
    pub(crate) payload_bytes: usize,
    pub(crate) ordering_key: Option<OrderingKey>,
    pub(crate) ordering_position: u64,
    pub(crate) block: Option<CandidateBlock>,
}

impl FairCandidate {
    fn try_from_input(input: FairCandidateInput) -> Result<Self, ValidationError> {
        if input.cost_units.get() > MAX_COST_UNITS {
            return Err(ValidationError::TooLong {
                field: "fair candidate cost units",
                maximum: MAX_COST_UNITS as usize,
                actual: input.cost_units.get() as usize,
            });
        }
        Ok(Self {
            job_id: input.job_id,
            scope: FairScope::from(input.fairness),
            priority: input.priority,
            cost_units: input.cost_units,
            scheduled_at: input.scheduled_at,
            payload_bytes: input.payload_bytes,
            ordering_key: input.ordering_key,
            ordering_position: input.ordering_position,
            block: input.block,
        })
    }

    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    pub const fn priority(&self) -> Priority {
        self.priority
    }

    pub const fn cost_units(&self) -> NonZeroU16 {
        self.cost_units
    }

    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    pub fn scope(&self) -> &FairScope {
        &self.scope
    }

    pub const fn scheduled_at(&self) -> Timestamp {
        self.scheduled_at
    }

    pub fn ordering_key(&self) -> Option<&OrderingKey> {
        self.ordering_key.as_ref()
    }

    pub const fn ordering_position(&self) -> u64 {
        self.ordering_position
    }

    pub const fn block(&self) -> Option<CandidateBlock> {
        self.block
    }
}

impl TryFrom<FairCandidateInput> for FairCandidate {
    type Error = ValidationError;

    fn try_from(input: FairCandidateInput) -> Result<Self, Self::Error> {
        Self::try_from_input(input)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FairCandidateState {
    Absent,
    Scheduled,
    Leased,
    RetryWaiting,
    DeadLettered,
    Cancelled,
}

impl FairCandidateState {
    pub const fn has_ready_route(self) -> bool {
        match self {
            Self::Scheduled | Self::RetryWaiting => true,
            Self::Absent | Self::Leased | Self::DeadLettered | Self::Cancelled => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::fairness) struct FairPermitGeneration(NonZeroU64);

impl FairPermitGeneration {
    pub(in crate::fairness) const FIRST: Self = Self(NonZeroU64::MIN);

    pub(in crate::fairness) fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    pub(in crate::fairness) const fn get(self) -> u64 {
        self.0.get()
    }

    pub(in crate::fairness) fn from_u64(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self)
    }
}

/// A lease-scoped fair-dispatch authority. The generation is retained in the
/// ledger so a retained permit from an earlier acquisition cannot settle a
/// later acquisition.
#[derive(Debug, PartialEq, Eq)]
pub struct FairPermit {
    pub(crate) job_id: JobId,
    pub(crate) scope: FairScope,
    pub(crate) primary: Option<FairScope>,
    pub(crate) priority: Priority,
    pub(crate) cost_units: NonZeroU16,
    pub(crate) ordering_key: Option<OrderingKey>,
    pub(crate) ordering_position: u64,
    pub(in crate::fairness) acquisition_generation: FairPermitGeneration,
}

impl FairPermit {
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn scope(&self) -> &FairScope {
        &self.scope
    }

    #[cfg(any(test, feature = "test-support"))]
    pub const fn priority(&self) -> Priority {
        self.priority
    }

    pub const fn cost_units(&self) -> NonZeroU16 {
        self.cost_units
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FairnessRejection {
    Blocked(CandidateBlock),
    PayloadCapacity,
    ScopeCapacity,
    RateCapacity,
    LowVolumeCapacity,
    OrderingHead,
    PriorityDeficit,
    NormalizedServiceBound,
    UnknownScope,
    PermitGenerationExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FairRelease {
    Complete,
    Retry,
    #[cfg(any(test, feature = "test-support"))]
    DeadLetter,
    #[cfg(any(test, feature = "test-support"))]
    Cancelled,
    Conflict,
}

impl FairRelease {
    #[cfg(any(test, feature = "test-support"))]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::DeadLetter | Self::Cancelled)
    }

    #[cfg(not(any(test, feature = "test-support")))]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete)
    }
}
