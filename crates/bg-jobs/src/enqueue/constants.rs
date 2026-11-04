pub(super) const EXPIRED_DEDUPE_PAGE_ITEMS: u32 = 8;
pub(super) const MAX_DEDUPE_RANGE_BYTES: usize = 16 * 1024;

// One point read and one native conditional deletion; the expiry index owns
// retry input.
pub(super) const EXPIRED_DEDUPE_RETIRE_STORE_OPERATIONS: u32 = 2;
