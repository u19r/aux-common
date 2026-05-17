use std::time::Duration;

pub const DEFAULT_TTL_MS: u64 = 5_000;
pub const DEFAULT_CAPACITY: usize = 128;

pub const COMMON_TTL_VERY_SHORT: Duration = Duration::from_secs(2);
pub const COMMON_TTL_SHORT: Duration = Duration::from_secs(5);
pub const COMMON_TTL_REGULAR: Duration = Duration::from_secs(10);
pub const COMMON_TTL_LONG: Duration = Duration::from_secs(30);
pub const COMMON_TTL_EXTRA_LONG: Duration = Duration::from_secs(60);
pub const COMMON_TTL_EXTENDED: Duration = Duration::from_secs(5 * 60);
pub const COMMON_TTL_COLD: Duration = Duration::from_secs(30 * 60);
pub const COMMON_TTL_STATIC: Duration = Duration::from_secs(60 * 60 * 24);
