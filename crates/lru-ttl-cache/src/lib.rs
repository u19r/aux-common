//! Internal LRU/TTL cache utilities used by aux-storage.
//!
//! This crate is not a supported downstream API.
#![doc(hidden)]

pub mod cache;
pub mod common_ttls;
pub mod config;
pub mod constants;
mod core;
pub mod fetch;
mod template;

pub use core::CacheStats;

pub use cache::{FetchingLruTtlCache, LruTtlCache};
pub use common_ttls::{CommonCacheTtl, CommonCacheTtlOverrides};
pub use config::{CacheConfig, FetchingCacheConfig};
pub use fetch::{FetchFn, FetchFuture, arc_fetch_fn};
pub use template::CacheTemplate;

#[cfg(test)]
mod cache_tests;
#[cfg(test)]
mod common_ttls_tests;
#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod lib_tests;
