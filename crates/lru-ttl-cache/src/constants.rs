use std::time::Duration;

pub const DEFAULT_TTL_MS: u64 = 5_000;
pub const DEFAULT_CAPACITY: usize = 128;

pub const COMMON_TTL_SHORT: Duration = Duration::from_secs(2);
pub const COMMON_TTL_STANDARD: Duration = Duration::from_secs(5);
pub const COMMON_TTL_LONG: Duration = Duration::from_secs(60);
pub const COMMON_TTL_EXTRA_LONG: Duration = Duration::from_secs(5 * 60);
pub const COMMON_TTL_EXTRA_EXTRA_LONG: Duration = Duration::from_secs(30 * 60);

pub(super) const MAX_LOAD_KEYS: usize = 128;
pub(super) const MAX_LOAD_WAITERS: usize = 4096;

pub(super) const DEFAULT_REFRESH_BYTES: usize = 4 * 1024 * 1024;
pub(super) const DEFAULT_REFRESH_BATCH_BYTES: usize = 1024 * 1024;
pub(super) const DEFAULT_REFRESH_BATCH_KEYS: usize = 100;

pub(super) const DEFAULT_REFRESH_BATCHES: usize = 2;

pub(super) const REFRESH_EXECUTOR_WORKERS: usize = 8;
pub(super) const REFRESH_JOB_OVERHEAD_BYTES: usize = 1024;

pub(super) const REFRESH_KEY_COPY_CHARGE: usize = 6;
