use std::{fmt, hash::Hash, time::Duration};

use crate::{CacheConfig, FetchFn, FetchingLruTtlCache};

#[derive(Clone)]
pub struct CacheTemplate {
    capacity: usize,
    ttl: Duration,
    refresh_ttl: Option<Duration>,
}

impl CacheTemplate {
    #[must_use]
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity: capacity.max(1),
            ttl,
            refresh_ttl: None,
        }
    }

    #[must_use]
    pub fn with_refresh_ttl(mut self, refresh_ttl: Duration) -> Self {
        self.refresh_ttl = Some(refresh_ttl);
        self
    }

    pub fn fetching<K, V, E>(&self, fetch: FetchFn<K, V, E>) -> FetchingLruTtlCache<K, V, E>
    where
        K: Eq + Hash + Clone + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
        E: Send + 'static,
    {
        let mut config = CacheConfig::new()
            .with_capacity(self.capacity)
            .with_ttl(self.ttl)
            .with_fetch(fetch);
        if let Some(refresh_ttl) = self.refresh_ttl {
            config = config.with_refresh_ttl(refresh_ttl);
        }
        FetchingLruTtlCache::new(config)
    }
}

impl fmt::Debug for CacheTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheTemplate")
            .field("capacity", &self.capacity)
            .field("ttl", &self.ttl)
            .field("refresh_ttl", &self.refresh_ttl)
            .finish()
    }
}
