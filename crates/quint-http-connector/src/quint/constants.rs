//! Bounds shared by the Quint HTTP connector driver.

pub(super) const MAX_ATTEMPTS: i64 = 3;
pub(super) const MAX_RETRY_AFTER_TICKS: i64 = 4;
pub(super) const RETRY_AFTER_FALLBACK_TICKS: i64 = 1;
