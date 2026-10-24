//! Lease-gated lifecycle operations grouped by claim, completion, payload, and
//! identity ownership.

mod claim;
mod completion;
#[cfg(test)]
mod completion_tests;
mod identity;
mod observation;
mod payload;
mod terminal_projection;

#[cfg(test)]
mod observation_tests;
#[cfg(test)]
mod payload_tests;

pub use claim::ClaimedJob;
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) use claim::claim_with_capacity;
pub(crate) use claim::{
    ClaimDeadline, ClaimRecordInput, ClaimRoute, claim, claim_record_with_capacity,
};
pub(crate) use completion::complete;
pub(crate) use identity::validate_persisted_identity;
pub(crate) use observation::observe;
pub(crate) use payload::scan_payload;
