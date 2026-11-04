//! Shared operational bounds for the drive scheduler and discovery lanes.

use std::time::Duration;

// Reserve the entire journal path before a handler starts: admission, checked
// application, exact unknown replay, one wake refresh, and retirement.
// Additional fair-permit batches are reserved from advertised store limits.
pub(super) const CLAIM_INPUT_STORE_OPERATIONS: u32 = 4;
pub(super) const UNKNOWN_TRANSITION_STORE_OPERATIONS: u32 =
    crate::journal::COMMIT_WORST_CASE_STORE_OPERATIONS;
pub(super) const PAYLOAD_READ_STORE_OPERATIONS: u32 = 1;
pub(super) const CANCELLATION_READ_STORE_OPERATIONS: u32 = 1;
// Outcome preparation reads the catalog, fair owner, wake, and one bounded due
// page.
pub(super) const WAKE_RECONCILIATION_STORE_OPERATIONS: u32 = 4;
// The journal allowance already includes the one permitted wake retry.
pub(super) const WAKE_TRANSITION_STORE_OPERATIONS: u32 = UNKNOWN_TRANSITION_STORE_OPERATIONS;
pub(super) const CANDIDATE_WORST_CASE_STORE_OPERATIONS: u32 = CLAIM_INPUT_STORE_OPERATIONS
    .saturating_add(UNKNOWN_TRANSITION_STORE_OPERATIONS)
    .saturating_add(PAYLOAD_READ_STORE_OPERATIONS)
    .saturating_add(CANCELLATION_READ_STORE_OPERATIONS)
    .saturating_add(WAKE_RECONCILIATION_STORE_OPERATIONS)
    .saturating_add(WAKE_TRANSITION_STORE_OPERATIONS);
// Owner load is one read; save uses the same bounded journal as lifecycle
// mutations, including recovery of unknown acknowledgements.
pub(super) const OWNER_LOAD_STORE_OPERATIONS: u32 = 1;
pub(super) const OWNER_SAVE_WORST_CASE_STORE_OPERATIONS: u32 =
    crate::journal::COMMIT_WORST_CASE_STORE_OPERATIONS;
pub(super) const MAX_DISCOVERY_ITEMS: usize = crate::transition::MAX_INDEX_RANGE_ITEMS;
pub(super) const MAX_DISCOVERY_BYTES: usize = crate::transition::MAX_INDEX_RANGE_BYTES;
pub(super) const SHUTDOWN_GRACE: Duration = Duration::from_millis(50);
