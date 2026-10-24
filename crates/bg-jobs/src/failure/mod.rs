//! Checked recovery transitions owned by the runtime-neutral job engine.

mod constants;
mod lease;
mod operation;
mod result;
mod retry;
mod terminal;
#[cfg(test)]
mod terminal_tests;

#[cfg(test)]
mod lease_tests;
#[cfg(test)]
mod retry_tests;

pub(crate) use lease::{checkpoint, renew};
pub(crate) use operation::apply_outcome;
pub use result::{
    CancellationResult, CheckpointResult, ExpiryResult, OutcomeResult, RedriveExecution,
    RedriveRequest, RedriveResult, RenewalResult,
};
pub(crate) use retry::{continue_claim, retry_claim};
pub(crate) use terminal::{
    cancel_claim, cancel_claim_commit, dead_letter_by_id, dead_letter_claim,
};
