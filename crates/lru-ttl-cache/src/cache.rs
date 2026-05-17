use std::{
    fmt::Debug,
    hash::Hash,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use tracing::warn;

use crate::{
    config::{CacheConfig, FetchingCacheConfig},
    core::{CacheCore, CacheEntry, CacheStats, EntryState},
    fetch::FetchFn,
};

pub struct LruTtlCache<K, V> {
    core: CacheCore<K, V>,
}

pub struct FetchingLruTtlCache<K, V, E> {
    core: CacheCore<K, V>,
    refresh_ttl: Option<Duration>,
    fetch: FetchFn<K, V, E>,
}

impl<K, V> Clone for LruTtlCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
        }
    }
}

impl<K, V, E> Clone for FetchingLruTtlCache<K, V, E>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    E: Debug + Send + 'static,
{
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
            refresh_ttl: self.refresh_ttl,
            fetch: Arc::clone(&self.fetch),
        }
    }
}

impl<K, V> LruTtlCache<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(config: CacheConfig<K, V>) -> Self {
        Self {
            core: CacheCore::new(config.capacity, config.ttl),
        }
    }

    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.core.ttl()
    }

    pub fn insert(&self, key: K, value: V) {
        self.core.insert(key, value);
    }

    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        self.core.insert_with_ttl(key, value, ttl);
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        self.core.remove(key)
    }

    pub fn cached(&self, key: &K) -> Option<V> {
        match self.core.inspect_entry(key) {
            EntryState::Fresh(entry) => Some(entry.value().clone()),
            EntryState::Expired | EntryState::Missing | EntryState::Stale(_) => None,
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.cached(key)
    }

    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.core.stats()
    }
}

impl<K, V, E> FetchingLruTtlCache<K, V, E>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    E: Debug + Send + 'static,
{
    #[must_use]
    pub fn new(config: FetchingCacheConfig<K, V, E>) -> Self {
        Self {
            core: CacheCore::new(config.base.capacity, config.base.ttl),
            refresh_ttl: config.refresh_ttl,
            fetch: config.fetch,
        }
    }

    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.core.ttl()
    }

    pub fn insert(&self, key: K, value: V) {
        self.core.insert(key, value);
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        self.core.remove(key)
    }

    pub fn cached(&self, key: &K) -> Option<V> {
        match self.core.inspect_entry(key) {
            EntryState::Fresh(entry) => {
                let value = entry.value().clone();
                self.maybe_spawn_refresh(key, entry);
                Some(value)
            }
            EntryState::Expired | EntryState::Missing | EntryState::Stale(_) => None,
        }
    }

    pub async fn get_or_fetch(&self, key: &K) -> Result<Option<V>, E> {
        match self.core.inspect_entry(key) {
            EntryState::Fresh(entry) => {
                let value = entry.value().clone();
                self.maybe_spawn_refresh(key, entry);
                Ok(Some(value))
            }
            EntryState::Expired | EntryState::Missing | EntryState::Stale(_) => {
                self.fetch_and_store(key).await
            }
        }
    }

    pub async fn get_or_fetch_stale_on_error(
        &self,
        key: &K,
        stale_ttl: Duration,
    ) -> Result<Option<V>, E> {
        match self.core.inspect_entry_with_stale(key, stale_ttl) {
            EntryState::Fresh(entry) => {
                let value = entry.value().clone();
                self.maybe_spawn_refresh(key, entry);
                Ok(Some(value))
            }
            EntryState::Stale(entry) => match self.fetch_and_store(key).await {
                Ok(value) => Ok(value),
                Err(err) => {
                    self.core.refresh_errors().fetch_add(1, Ordering::Relaxed);
                    warn!(error = ?err, "cache_fetch_failed_serving_stale");
                    Ok(Some(entry.value().clone()))
                }
            },
            EntryState::Expired | EntryState::Missing => self.fetch_and_store(key).await,
        }
    }

    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.core.stats()
    }

    fn fetch_clone(&self) -> FetchFn<K, V, E> {
        Arc::clone(&self.fetch)
    }

    async fn fetch_and_store(&self, key: &K) -> Result<Option<V>, E> {
        let fetcher = self.fetch_clone();
        let key_clone = key.clone();
        let result = fetcher(key_clone.clone()).await?;
        if self.core.is_disabled() {
            return Ok(result);
        }
        if let Some(value) = result {
            self.core.insert(key_clone, value.clone());
            Ok(Some(value))
        } else {
            self.core.remove(&key_clone);
            Ok(None)
        }
    }

    fn maybe_spawn_refresh(&self, key: &K, entry: CacheEntry<V>) {
        if self.core.is_disabled() {
            return;
        }
        let Some(refresh_ttl) = self.refresh_ttl else {
            return;
        };
        if refresh_ttl.is_zero() {
            return;
        }
        if !entry.should_refresh(refresh_ttl) {
            return;
        }
        if !entry.begin_refresh() {
            return;
        }

        self.core.record_refresh_spawn();
        let cache_core = self.core.clone();
        let refresh_errors = self.core.refresh_errors();
        let fetcher = self.fetch_clone();
        let refresh_key = key.clone();
        tokio::spawn(async move {
            let result = fetcher(refresh_key.clone()).await;
            match result {
                Ok(Some(value)) => cache_core.insert(refresh_key.clone(), value),
                Ok(None) => {
                    cache_core.remove(&refresh_key);
                }
                Err(err) => {
                    refresh_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(error = ?err, "cache_refresh_failed");
                }
            }
            entry.finish_refresh();
        });
    }
}
