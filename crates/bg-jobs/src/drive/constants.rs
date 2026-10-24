//! Shared operational bounds for the drive scheduler and discovery lanes.

use std::time::Duration;

// The scheduler reserves a complete candidate path before starting its
// handler.  Claim preparation reads the job, route, fence marker, and fair
// first fair-permit batch; the scheduler reserves any additional batches from
// the store's advertised limits. Its checked commit may consume two
// reconciliation reads and a retry commit after Unknown. Payload loading is
// one native bulk read.
pub(super) const CLAIM_INPUT_STORE_OPERATIONS: u32 = 4;
pub(super) const UNKNOWN_TRANSITION_STORE_OPERATIONS: u32 = 4;
pub(super) const PAYLOAD_READ_STORE_OPERATIONS: u32 = 1;
pub(super) const CANCELLATION_READ_STORE_OPERATIONS: u32 = 1;
// Outcome preparation reads the wake record and one bounded due page.
pub(super) const WAKE_RECONCILIATION_STORE_OPERATIONS: u32 = 2;
// A known conflict can follow Unknown + probe + replay (three calls).
// Reading the changed wake and reconciling one fresh commit adds five more.
// Reserve both identities before effects; each Unknown still replays exactly.
pub(super) const WAKE_TRANSITION_STORE_OPERATIONS: u32 =
    UNKNOWN_TRANSITION_STORE_OPERATIONS.saturating_mul(2);
pub(super) const CANDIDATE_WORST_CASE_STORE_OPERATIONS: u32 = CLAIM_INPUT_STORE_OPERATIONS
    .saturating_add(UNKNOWN_TRANSITION_STORE_OPERATIONS)
    .saturating_add(PAYLOAD_READ_STORE_OPERATIONS)
    .saturating_add(CANCELLATION_READ_STORE_OPERATIONS)
    .saturating_add(WAKE_RECONCILIATION_STORE_OPERATIONS)
    .saturating_add(WAKE_TRANSITION_STORE_OPERATIONS);
// A load is one get.  A checked owner save is get + commit, with each of the
// two possible Unknown acknowledgements requiring a reconciliation get before
// the next commit (or final UnknownCommit).  Reserve the full five-call
// sequence before any handler effect starts.
pub(super) const OWNER_LOAD_STORE_OPERATIONS: u32 = 1;
pub(super) const OWNER_SAVE_WORST_CASE_STORE_OPERATIONS: u32 = 5;
pub(super) const MAX_DISCOVERY_ITEMS: usize = crate::transition::MAX_INDEX_RANGE_ITEMS;
pub(super) const MAX_DISCOVERY_BYTES: usize = crate::transition::MAX_INDEX_RANGE_BYTES;
pub(super) const SHUTDOWN_GRACE: Duration = Duration::from_millis(50);

pub(super) struct OperationBudget {
    pub(super) remaining: u32,
    observer: std::sync::Arc<dyn crate::observer::JobObserver>,
}

impl OperationBudget {
    pub(super) fn new(
        limit: u32,
        observer: std::sync::Arc<dyn crate::observer::JobObserver>,
    ) -> Self {
        Self {
            remaining: limit,
            observer,
        }
    }

    pub(super) fn reserve(&mut self, operations: u32) -> bool {
        if operations > self.remaining {
            self.observer
                .observe(crate::observer::JobEvent::CapacityLimited {
                    resource: crate::observer::CapacityResource::StoreOperations,
                });
            return false;
        }
        self.observer
            .observe(crate::observer::JobEvent::StoreOperationsReserved { operations });
        self.remaining -= operations;
        true
    }
}

pub(crate) fn initial_completion_capacity(max_completion_details: u32) -> usize {
    (max_completion_details as usize).min(MAX_DISCOVERY_ITEMS)
}
