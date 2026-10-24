//! Runtime-neutral bounded fair-dispatch contracts.
//!
//! The fair-ready index is advisory; a store claim remains authoritative.

mod budget;
mod candidate;
mod constants;
mod fairness_ledger;
mod permits;
#[cfg(test)]
mod permits_tests;
mod priority;
mod scope;
#[cfg(test)]
mod scope_tests;

pub use budget::{FairnessBudget, FairnessBudgetInput};
pub(in crate::fairness) use candidate::FairPermitGeneration;
pub use candidate::{
    CandidateBlock, FairCandidate, FairCandidateInput, FairCandidateState, FairPermit, FairRelease,
    FairnessRejection,
};
#[cfg(not(feature = "test-support"))]
pub(crate) use constants::NORMALIZATION_SCALE;
#[cfg(feature = "test-support")]
pub use constants::NORMALIZATION_SCALE;
pub use fairness_ledger::FairnessLedger;
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) use fairness_ledger::{FairBatchItemState, FairCandidateSnapshot};
pub(crate) use fairness_ledger::{FairCandidateMetadata, FairDispatchOwner};
pub(crate) use permits::{
    find_available_permit_keys, find_owned_permit_keys, find_reclaimable_permit_keys,
    permit_read_operation_bound,
};
#[cfg(feature = "test-support")]
pub use priority::normalized_service_error;
pub use priority::{PriorityDeficit, normalized_service};
#[cfg(any(test, feature = "test-support"))]
pub use scope::ScopeSnapshot;
pub(crate) use scope::ScopeState;
pub use scope::{FairScope, FairVolumeMode};

mod service_accounting;
