pub(super) const CATALOG_VERSION: u8 = 1;
pub(super) const MAX_CATALOG_ATTEMPTS: usize = 4;
pub(super) const CATALOG_HEADER_BYTES: usize = 17;
pub(super) const MAX_SEED_PROGRESS_BYTES: usize = 49;
pub(super) const MAX_SCHEDULE_PROGRESS_BYTES: usize = 49 + crate::schedule::CATALOG_CURSOR_BYTES;
