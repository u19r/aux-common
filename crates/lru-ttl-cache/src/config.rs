use std::{fmt, marker::PhantomData, time::Duration};

use crate::{
    constants::{DEFAULT_CAPACITY, DEFAULT_TTL_MS},
    fetch::FetchFn,
};

#[derive(Clone, Copy)]
#[must_use]
pub struct CacheConfig<K, V> {
    pub(crate) capacity: usize,
    pub(crate) ttl: Duration,
    marker: PhantomData<(K, V)>,
}

#[derive(Clone)]
#[must_use]
pub struct FetchingCacheConfig<K, V, E> {
    pub(crate) base: CacheConfig<K, V>,
    pub(crate) refresh_ttl: Option<Duration>,
    pub(crate) fetch: FetchFn<K, V, E>,
}

impl<K, V> CacheConfig<K, V> {
    pub fn new() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            ttl: Duration::from_millis(DEFAULT_TTL_MS),
            marker: PhantomData,
        }
    }

    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn with_fetch<E>(self, fetch: FetchFn<K, V, E>) -> FetchingCacheConfig<K, V, E> {
        FetchingCacheConfig {
            base: self,
            refresh_ttl: None,
            fetch,
        }
    }
}

impl<K, V, E> FetchingCacheConfig<K, V, E> {
    pub fn with_refresh_ttl(mut self, refresh_ttl: Duration) -> Self {
        self.refresh_ttl = Some(refresh_ttl);
        self
    }
}

impl<K, V> Default for CacheConfig<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> fmt::Debug for CacheConfig<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheConfig")
            .field("capacity", &self.capacity)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl<K, V, E> fmt::Debug for FetchingCacheConfig<K, V, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchingCacheConfig")
            .field("capacity", &self.base.capacity)
            .field("ttl", &self.base.ttl)
            .field("refresh_ttl", &self.refresh_ttl)
            .finish_non_exhaustive()
    }
}
