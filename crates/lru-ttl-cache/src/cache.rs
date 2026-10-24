use std::{borrow::Borrow, hash::Hash, ops::Deref, sync::atomic::Ordering, time::Duration};

use tracing::warn;

use crate::{
    LoadUnavailable,
    cache_entry::CacheEntry,
    cache_load::LoadIntent,
    cache_loader::CacheLoader,
    config::{CacheConfig, FetchingCacheConfig, RefreshPolicy},
    core::{CacheCore, CacheStats, EntryState},
};

pub struct LruTtlCache<K, V> {
    core: CacheCore<K, V>,
}

pub struct FetchingLruTtlCache<K, V, E> {
    loader: CacheLoader<K, V, E>,
    refresh: Option<RefreshPolicy<K>>,
}

#[must_use]
pub struct CacheRead<V>(CacheEntry<V>);

impl<V> Deref for CacheRead<V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        self.0.value()
    }
}

struct RefreshGuard<V>(CacheEntry<V>);

impl<V> Drop for RefreshGuard<V> {
    fn drop(&mut self) {
        self.0.finish_refresh();
    }
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
    E: Send + 'static,
{
    fn clone(&self) -> Self {
        Self {
            loader: self.loader.clone(),
            refresh: self.refresh.clone(),
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
            core: CacheCore::new(config.capacity, config.expiration, None),
        }
    }

    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.core.ttl()
    }

    pub fn insert(&self, key: K, value: V) {
        self.core.insert(key, value);
    }

    /// Insert a value and retain an owning read handle to the inserted entry.
    ///
    /// The handle shares the cache entry's allocation, so callers can use the
    /// value without a second lookup or a `V` clone. `None` means this cache is
    /// disabled or the insertion used a zero TTL and did not retain the value.
    pub fn insert_ref(&self, key: K, value: V) -> Option<CacheRead<V>> {
        self.core.insert_ref(key, value).map(CacheRead)
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

    /// Read a fresh entry without triggering any refresh side effect.
    pub fn peek(&self, key: &K) -> Option<V> {
        self.cached(key)
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.cached(key)
    }

    /// Read a fresh value through an owning handle without cloning `V`.
    ///
    /// The handle keeps the cache entry alive after eviction and does not hold
    /// the cache mutex while the caller uses the borrowed value.
    pub fn get_ref<Q>(&self, key: &Q) -> Option<CacheRead<V>>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        match self.core.inspect_entry(key) {
            EntryState::Fresh(entry) => Some(CacheRead(entry)),
            EntryState::Expired | EntryState::Missing | EntryState::Stale(_) => None,
        }
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
    E: Clone + From<LoadUnavailable> + Send + Sync + 'static,
{
    #[must_use]
    pub fn new(config: FetchingCacheConfig<K, V, E>) -> Self {
        Self {
            loader: CacheLoader::new(config.base, config.fetch, config.invalidation),
            refresh: config.refresh,
        }
    }

    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.loader.core.ttl()
    }

    pub fn insert(&self, key: K, value: V) {
        self.loader.core.insert(key, value);
    }

    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        self.loader.core.insert_with_ttl(key, value, ttl);
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        self.loader.core.remove(key)
    }

    pub fn cached(&self, key: &K) -> Option<V> {
        match self.loader.core.inspect_entry(key) {
            EntryState::Fresh(entry) => {
                let value = entry.value().clone();
                self.schedule_refresh(key, entry);
                Some(value)
            }
            EntryState::Expired | EntryState::Missing | EntryState::Stale(_) => None,
        }
    }

    /// Read a fresh entry without triggering a background refresh.
    ///
    /// This is useful for callers which must prove that the fast path performs
    /// no provider work before deciding whether to acquire a provider permit.
    pub fn peek(&self, key: &K) -> Option<V> {
        match self.loader.core.inspect_entry(key) {
            EntryState::Fresh(entry) => Some(entry.value().clone()),
            EntryState::Expired | EntryState::Missing | EntryState::Stale(_) => None,
        }
    }

    pub async fn get_or_fetch(&self, key: &K) -> Result<Option<V>, E> {
        match self.loader.core.inspect_entry(key) {
            EntryState::Fresh(entry) => {
                let value = entry.value().clone();
                self.schedule_refresh(key, entry);
                Ok(Some(value))
            }
            EntryState::Expired | EntryState::Missing | EntryState::Stale(_) => {
                self.loader.fetch_and_store(key).await
            }
        }
    }

    pub async fn get_or_fetch_stale_on_error(
        &self,
        key: &K,
        stale_ttl: Duration,
    ) -> Result<Option<V>, E> {
        // The stale window is evaluated at request time by
        // `inspect_entry_with_stale`. A `Stale` entry was within `stale_ttl`
        // of expiry when this call started, so a failing fetch serves it
        // without re-checking the clock: otherwise the fetch's own retry
        // budget would eat a short window and make the opt-in silently inert.
        match self.loader.core.inspect_entry_with_stale(key, stale_ttl) {
            EntryState::Fresh(entry) => {
                let value = entry.value().clone();
                self.schedule_refresh(key, entry);
                Ok(Some(value))
            }
            EntryState::Stale(entry) => match self.loader.fetch_and_store(key).await {
                Ok(value) => Ok(value),
                Err(_) if self.loader.core.is_current_entry(key, &entry) => {
                    self.loader
                        .core
                        .refresh_errors()
                        .fetch_add(1, Ordering::Relaxed);
                    warn!("cache_fetch_failed_serving_stale");
                    Ok(Some(entry.value().clone()))
                }
                Err(error) => Err(error),
            },
            EntryState::Expired | EntryState::Missing => self.loader.fetch_and_store(key).await,
        }
    }

    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let mut stats = self.loader.core.stats();
        let loads = self.loader.loads.stats();
        stats.active_loads = loads.active_keys;
        stats.load_subscribers = loads.subscribers;
        stats
    }

    fn schedule_refresh(&self, key: &K, entry: CacheEntry<V>) {
        if self.loader.core.is_disabled() {
            return;
        }
        let Some(policy) = &self.refresh else {
            return;
        };
        if policy.ttl.is_zero() {
            return;
        }
        if !entry.should_refresh(policy.ttl) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if !entry.begin_refresh() {
            return;
        }

        self.dispatch_refresh(key, entry, policy, &runtime);
    }

    fn dispatch_refresh(
        &self,
        key: &K,
        entry: CacheEntry<V>,
        policy: &RefreshPolicy<K>,
        runtime: &tokio::runtime::Handle,
    ) {
        let loader = self.loader.clone();
        let refresh_errors = self.loader.core.refresh_errors();
        let refresh_guard = RefreshGuard(entry.clone());
        let build = || {
            let refresh_key = key.clone();
            async move {
                if loader
                    .fetch_shared(&refresh_key, LoadIntent::Refresh(refresh_guard.0.clone()))
                    .await
                    .is_err()
                {
                    refresh_errors.fetch_add(1, Ordering::Relaxed);
                    warn!("cache_refresh_failed");
                }
                drop(refresh_guard);
            }
        };
        match policy
            .executor
            .try_submit(runtime, (policy.key_bytes)(key), build)
        {
            Ok(handle) => {
                self.loader.core.record_refresh();
                entry.install_refresh_handle(handle);
            }
            Err(_) => {
                self.loader
                    .core
                    .refresh_errors()
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
