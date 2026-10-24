//! Canonical fair-dispatch ledger wiring.

mod admission;
mod index;
mod lifecycle;
mod owner;
mod state;

#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) use owner::FairBatchItemState;
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) use owner::FairCandidateSnapshot;
pub(crate) use owner::{FairCandidateMetadata, FairDispatchOwner};
pub use state::FairnessLedger;
