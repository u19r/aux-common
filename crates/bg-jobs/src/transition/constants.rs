//! Shared bounds for checked transition range work.

/// Maximum number of index entries considered by one transition-side scan.
pub(crate) const MAX_INDEX_RANGE_ITEMS: usize = 4_096;
/// Maximum bytes considered by one transition-side scan.
pub(crate) const MAX_INDEX_RANGE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_DUE_RANGE_PAGES: usize = 1;
