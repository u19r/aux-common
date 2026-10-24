//! Checked job transitions grouped by authority, transactions, commits, wake,
//! and due work.

mod authority;
mod commit;
mod constants;
mod due;
mod transaction;
mod wake;

#[cfg(test)]
mod commit_tests;

pub use authority::{ReconciliationOutcome, TransitionAuthority};
pub(crate) use commit::{
    TransitionConflict, checked_transaction, commit_marker, commit_record,
    commit_record_without_claim, commit_transition, reconcile,
};
pub(crate) use constants::{MAX_INDEX_RANGE_BYTES, MAX_INDEX_RANGE_ITEMS};
pub(crate) use due::{RangeLimits, bounded_range_limits};
pub(crate) use transaction::{
    TerminalTransition, authority_checks, code, current_lease, fresh_operation, jitter_duration,
    lease_record_transaction, next_revision, scheduled_transaction, terminal_transaction,
};
pub(crate) use wake::wake_mutation;
