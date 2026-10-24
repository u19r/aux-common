use std::{fmt, marker::PhantomData, sync::Arc, time::Duration};

use crate::{
    constants::{DEFAULT_CAPACITY, DEFAULT_TTL_MS},
    fetch::FetchFn,
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum CacheExpiration {
    Ttl(Duration),
    Never,
}

impl CacheExpiration {
    pub(crate) fn ttl(self) -> Duration {
        match self {
            Self::Ttl(ttl) => ttl,
            // Keep the existing duration-shaped `ttl` API while the cache
            // core uses the typed `Never` variant for its expiry checks.
            Self::Never => Duration::MAX,
        }
    }
}

#[derive(Clone, Copy)]
#[must_use]
pub struct CacheConfig<K, V> {
    pub(crate) capacity: usize,
    pub(crate) expiration: CacheExpiration,
    marker: PhantomData<(K, V)>,
}

pub(crate) type InvalidationFn<K> = Arc<dyn Fn(&K) + Send + Sync>;

#[derive(Clone)]
#[must_use]
pub struct FetchingCacheConfig<K, V, E> {
    pub(crate) base: CacheConfig<K, V>,
    pub(crate) fetch: FetchFn<K, V, E>,
    pub(crate) refresh: Option<RefreshPolicy<K>>,
    pub(crate) invalidation: Option<InvalidationFn<K>>,
}

#[derive(Clone)]
pub(crate) struct RefreshPolicy<K> {
    pub(crate) ttl: Duration,
    pub(crate) executor: Arc<crate::RefreshExecutor>,
    pub(crate) key_bytes: fn(&K) -> usize,
}

impl<K, V> CacheConfig<K, V> {
    pub fn new() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            expiration: CacheExpiration::Ttl(Duration::from_millis(DEFAULT_TTL_MS)),
            marker: PhantomData,
        }
    }

    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.expiration = CacheExpiration::Ttl(ttl);
        self
    }

    pub fn without_expiration(mut self) -> Self {
        self.expiration = CacheExpiration::Never;
        self
    }

    pub(crate) fn ttl(&self) -> Duration {
        self.expiration.ttl()
    }

    pub fn with_fetch<E>(self, fetch: FetchFn<K, V, E>) -> FetchingCacheConfig<K, V, E> {
        FetchingCacheConfig {
            base: self,
            fetch,
            refresh: None,
            invalidation: None,
        }
    }
}

impl<K, V, E> FetchingCacheConfig<K, V, E> {
    /// Fence shared source work before explicit removal, replacement or
    /// eviction. Runs under the cache mutex: callbacks must be synchronous,
    /// nonblocking and nonreentrant, and must not acquire any cache mutex.
    pub fn with_invalidation(mut self, invalidate: impl Fn(&K) + Send + Sync + 'static) -> Self {
        self.invalidation = Some(Arc::new(invalidate));
        self
    }

    /// Enable bounded refresh using an executor shared with related caches.
    /// Declare the heap bytes of one cloned key; the executor charges all
    /// framework key copies, inline future state, and scheduling overhead.
    pub fn with_refresh(
        mut self,
        ttl: Duration,
        executor: Arc<crate::RefreshExecutor>,
        key_bytes: fn(&K) -> usize,
    ) -> Self {
        self.refresh = Some(RefreshPolicy {
            ttl,
            executor,
            key_bytes,
        });
        self
    }

    pub fn with_refresh_ttl(self, ttl: Duration, key_bytes: fn(&K) -> usize) -> Self {
        self.with_refresh(ttl, Arc::new(crate::RefreshExecutor::new()), key_bytes)
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
            .field("ttl", &self.ttl())
            .finish()
    }
}

impl<K, V, E> fmt::Debug for FetchingCacheConfig<K, V, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchingCacheConfig")
            .field("capacity", &self.base.capacity)
            .field("ttl", &self.base.ttl())
            .field(
                "refresh_ttl",
                &self.refresh.as_ref().map(|policy| policy.ttl),
            )
            .finish_non_exhaustive()
    }
}
