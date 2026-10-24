//! The durable fair-dispatch owner and its command, persistence, and codec
//! layers.

mod accounting;
#[cfg(test)]
mod accounting_tests;
mod codec;
mod commands;
mod constants;
mod discovery;
mod persistence;
mod state;

#[cfg(test)]
mod state_tests;

#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) use state::{FairBatchItemState, FairCandidateSnapshot};
pub(crate) use state::{FairCandidateMetadata, FairDispatchOwner};
