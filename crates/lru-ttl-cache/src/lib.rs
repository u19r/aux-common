//! Internal LRU/TTL cache utilities used by aux-storage.
//!
//! This crate is not a supported downstream API.
#![doc(hidden)]

mod cache;
mod cache_entry;
mod cache_load;
mod cache_loader;
mod common_ttls;
mod config;
mod constants;
mod core;
mod error;
mod fetch;
mod shared_load;
mod singleflight;
mod template;

pub use core::CacheStats;

pub use cache::{CacheRead, FetchingLruTtlCache, LruTtlCache};
pub use common_ttls::{CommonCacheTtl, CommonCacheTtlOverrides};
pub use config::{CacheConfig, FetchingCacheConfig};
pub use error::{LoadUnavailable, SharedCause};
pub use fetch::{FetchFn, FetchFuture, arc_fetch_fn};
pub use shared_load::{SharedLoad, SharedLoadError, SharedLoadStats};
pub use singleflight::{KeyedSingleflight, KeyedSingleflightGuard};
pub use template::CacheTemplate;

#[cfg(test)]
mod cache_tests;
#[cfg(test)]
mod common_ttls_tests;
#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod singleflight_tests;

#[cfg(test)]
mod shared_load_tests;

mod load_lease;
mod refresh_batch;
mod refresh_queue;
mod refresh_queue_core;
mod refresh_queue_limits;
mod refresh_queue_state;
mod refresh_ticket;

pub use refresh_batch::{RefreshBatch, RefreshJob};
pub use refresh_queue::{RefreshQueue, RefreshQueueStats};
pub use refresh_queue_limits::{RefreshBudget, RefreshQueueConfigError, RefreshQueueLimits};
pub use refresh_ticket::{RefreshAdmission, RefreshDemand, RefreshTicket, RefreshWork};

#[cfg(test)]
mod refresh_queue_tests;

#[cfg(test)]
mod source_drop_test_support;

mod refresh_cancellation;
mod refresh_executor;
mod refresh_job;
pub use refresh_executor::{RefreshExecutor, RefreshExecutorStats};

#[cfg(test)]
mod refresh_executor_tests;

mod refresh_priority;
pub use refresh_priority::RefreshPriority;

#[cfg(test)]
mod cache_loader_tests;
