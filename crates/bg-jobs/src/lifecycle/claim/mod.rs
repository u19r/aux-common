//! Claim authority, record state, and claim-side lifecycle orchestration.

mod authority;
mod flow;
#[cfg(test)]
mod flow_tests;
mod publication;
#[cfg(test)]
mod publication_tests;
mod transaction;
mod types;
#[cfg(test)]
mod types_tests;
#[cfg(test)]
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) use flow::claim_with_capacity;
pub(crate) use flow::{claim, claim_record_with_capacity};
pub use types::ClaimedJob;
pub(crate) use types::{ClaimDeadline, ClaimRecordInput, ClaimRoute};
