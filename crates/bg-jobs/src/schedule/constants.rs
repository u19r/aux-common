pub(crate) const ENQUEUE_WORST_CASE_STORE_OPERATIONS: usize =
    crate::journal::COMMIT_WORST_CASE_STORE_OPERATIONS as usize + 4;
pub(crate) const MAX_OCCURRENCE_SCAN: u16 = u16::MAX;

pub(crate) const CATALOG_CURSOR_BYTES: usize = 42;
