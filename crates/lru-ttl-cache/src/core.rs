use std::{
    borrow::Borrow,
    collections::{BTreeMap, HashMap, hash_map::RandomState},
    hash::Hash,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use hashlink::LinkedHashMap;

use crate::{
    cache_entry::{CacheEntry, EntryIdentity},
    cache_load::{CacheLoad, LoadIntent, LoadPreparation, LoadPublication},
    config::{CacheExpiration, InvalidationFn},
    load_lease::LoadLease,
};

#[derive(Clone)]
pub(super) struct CacheCore<K, V> {
    inner: Arc<Mutex<CacheInner<K, V>>>,
    capacity: usize,
    disabled: bool,
    expiration: CacheExpiration,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    refreshes: Arc<AtomicU64>,
    refresh_errors: Arc<AtomicU64>,
}

impl<K, V> CacheCore<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    // Cache contract:
    // - Value/source: Callers supply process-local values; their authoritative
    //   source remains outside this cache.
    // - Stale result: A non-zero TTL can return an older value after a source
    //   write until local expiry or eviction.
    // - Inconsistent result: Each process stores entries independently, so
    //   calls can observe A -> B -> A across nodes and must not join results
    //   without an explicit revision/snapshot.
    // - Likelihood: Medium during writes with load-balanced callers; none for
    //   unchanged values.
    // - Appropriateness: Duration::ZERO disables storage while preserving fetch
    //   behavior; every non-zero TTL is bounded and process-local, so durable
    //   writes and strong reads remain authoritative.
    pub(super) fn new(
        capacity: usize,
        expiration: CacheExpiration,
        invalidation: Option<InvalidationFn<K>>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CacheInner::new(capacity, invalidation))),
            capacity,
            disabled: matches!(expiration, CacheExpiration::Ttl(ttl) if ttl.is_zero()),
            expiration,
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            refreshes: Arc::new(AtomicU64::new(0)),
            refresh_errors: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(super) fn ttl(&self) -> Duration {
        self.expiration.ttl()
    }

    pub(super) fn is_disabled(&self) -> bool {
        self.disabled
    }

    pub(super) fn insert(&self, key: K, value: V) {
        let _ = self.insert_ref(key, value);
    }

    pub(super) fn insert_ref(&self, key: K, value: V) -> Option<CacheEntry<V>> {
        self.insert_with_expiration(key, value, self.expiration)
    }

    pub(super) fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        let _ = self.insert_with_expiration(key, value, CacheExpiration::Ttl(ttl));
    }

    fn insert_with_expiration(
        &self,
        key: K,
        value: V,
        expiration: CacheExpiration,
    ) -> Option<CacheEntry<V>> {
        let mut inner = self.lock_inner();
        inner.invalidate_key(&key);
        if self.disabled || matches!(expiration, CacheExpiration::Ttl(ttl) if ttl.is_zero()) {
            if let Some(entry) = inner.remove(&key) {
                entry.cancel_refresh();
            }
            return None;
        }
        inner.evict_if_needed(&key, self.capacity);
        let entry = CacheEntry::new(value, expiration);
        if let Some(entry) = inner.insert(key, entry.clone()) {
            entry.cancel_refresh();
        }
        Some(entry)
    }

    pub(super) fn remove(&self, key: &K) -> Option<V> {
        let mut inner = self.lock_inner();
        inner.invalidate_key(key);
        let entry = inner.remove(key);
        entry.map(|entry| {
            entry.cancel_refresh();
            entry.value().clone()
        })
    }

    pub(super) fn prepare_load(&self, key: &K, intent: LoadIntent<V>) -> LoadPreparation<K, V> {
        let mut inner = self.lock_inner();
        match &intent {
            LoadIntent::Cold => {
                if let Some(entry) = inner.entries.to_back(key)
                    && !entry.is_expired_at(Instant::now())
                {
                    return LoadPreparation::Cached(entry.value().clone());
                }
            }
            LoadIntent::Refresh(expected) => {
                if !inner.entries.get(key).is_some_and(|entry| {
                    entry.is_same_entry(expected) && !entry.is_expired_at(Instant::now())
                }) {
                    return LoadPreparation::Cancelled;
                }
            }
        }
        let lease = LoadLease::new();
        let previous = inner.loads.insert(key.clone(), lease.clone());
        debug_assert!(
            previous.is_none(),
            "SharedLoad owns each active key exclusively"
        );
        LoadPreparation::Fetch(CacheLoad::new(self.clone(), key.clone(), intent, lease))
    }

    pub(super) fn publish_load(
        &self,
        key: &K,
        lease: &LoadLease,
        intent: &LoadIntent<V>,
        value: Option<V>,
    ) -> LoadPublication {
        let mut inner = self.lock_inner();
        if !inner.is_current_load(key, lease) {
            return LoadPublication::Cancelled;
        }
        let expiration = match intent {
            LoadIntent::Cold => self.expiration,
            LoadIntent::Refresh(expected) => {
                let Some(current) = inner.entries.get(key) else {
                    return LoadPublication::Cancelled;
                };
                if !current.is_same_entry(expected) {
                    return LoadPublication::Cancelled;
                }
                // A successful read can satisfy cold subscribers without
                // renewing an expired entry. Replacement/removal still cancels
                // the cohort.
                if value.is_some() && current.is_expired_at(Instant::now()) {
                    return LoadPublication::NotRetained;
                }
                current.expiration()
            }
        };
        match value {
            Some(value) => {
                inner.evict_if_needed(key, self.capacity);
                inner.insert(key.clone(), CacheEntry::new(value, expiration));
            }
            None => {
                inner.remove(key);
            }
        }
        LoadPublication::Stored
    }

    pub(super) fn is_current_entry(&self, key: &K, expected: &CacheEntry<V>) -> bool {
        self.lock_inner()
            .entries
            .get(key)
            .is_some_and(|entry| entry.is_same_entry(expected))
    }

    pub(super) fn inspect_entry<Q>(&self, key: &Q) -> EntryState<V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        if self.disabled {
            self.record_miss();
            return EntryState::Missing;
        }

        let mut inner = self.lock_inner();
        let Some(entry_ref) = inner.entries.to_back(key) else {
            self.record_miss();
            return EntryState::Missing;
        };
        let entry = entry_ref.clone();
        if entry.is_expired_at(Instant::now()) {
            inner.discard_expired(key);
            self.record_miss();
            return EntryState::Expired;
        }

        self.hits.fetch_add(1, Ordering::Relaxed);
        EntryState::Fresh(entry)
    }

    pub(super) fn inspect_entry_with_stale(&self, key: &K, stale_ttl: Duration) -> EntryState<V> {
        if self.disabled {
            self.record_miss();
            return EntryState::Missing;
        }

        let mut inner = self.lock_inner();
        let Some(entry_ref) = inner.entries.to_back(key) else {
            self.record_miss();
            return EntryState::Missing;
        };
        let entry = entry_ref.clone();
        let now = Instant::now();
        if !entry.is_expired_at(now) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return EntryState::Fresh(entry);
        }

        if entry.is_stale_at(now, stale_ttl) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return EntryState::Stale(entry);
        }

        inner.discard_expired(key);
        self.record_miss();
        EntryState::Expired
    }

    pub(super) fn stats(&self) -> CacheStats {
        CacheStats {
            active_loads: 0,
            load_subscribers: 0,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            refreshes: self.refreshes.load(Ordering::Relaxed),
            refresh_errors: self.refresh_errors.load(Ordering::Relaxed),
        }
    }

    pub(super) fn record_refresh(&self) {
        self.refreshes.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn refresh_errors(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.refresh_errors)
    }

    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }
}

impl<K, V> CacheCore<K, V> {
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, CacheInner<K, V>> {
        self.inner.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl<K: Eq + Hash, V> CacheCore<K, V> {
    pub(super) fn finish_load(&self, key: &K, lease: &LoadLease) {
        let mut inner = self.lock_inner();
        if inner
            .loads
            .get(key)
            .is_some_and(|current| current.is_same(lease))
        {
            inner.loads.remove(key);
        }
    }
}

struct CacheInner<K, V> {
    invalidation: Option<InvalidationFn<K>>,
    loads: HashMap<K, LoadLease>,
    entries: LinkedHashMap<K, CacheEntry<V>, RandomState>,
    expirations: BTreeMap<(Instant, EntryIdentity), K>,
}

impl<K, V> CacheInner<K, V>
where K: Eq + Hash + Clone
{
    fn new(capacity: usize, invalidation: Option<InvalidationFn<K>>) -> Self {
        Self {
            invalidation,
            entries: LinkedHashMap::with_capacity_and_hasher(capacity, RandomState::new()),
            expirations: BTreeMap::new(),
            loads: HashMap::new(),
        }
    }

    fn invalidate_key(&self, key: &K) {
        if let Some(invalidate) = &self.invalidation {
            invalidate(key);
        }
    }

    fn is_current_load(&self, key: &K, lease: &LoadLease) -> bool {
        !lease.is_cancelled()
            && self
                .loads
                .get(key)
                .is_some_and(|current| current.is_same(lease))
    }

    fn insert(&mut self, key: K, entry: CacheEntry<V>) -> Option<CacheEntry<V>> {
        let previous = self.remove(&key);
        if let Some(expiration) = entry.expiration_key() {
            self.expirations.insert(expiration, key.clone());
        }
        self.entries.insert(key, entry);
        previous
    }

    fn remove<Q>(&mut self, key: &Q) -> Option<CacheEntry<V>>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        if let Some(lease) = self.loads.get(key) {
            lease.cancel();
        }
        let entry = self.entries.remove(key)?;
        if let Some(expiration) = entry.expiration_key() {
            self.expirations.remove(&expiration);
        }
        Some(entry)
    }

    fn discard_expired<Q>(&mut self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        // Expiry removes residence, not an in-flight read's identity. A cold
        // caller must be able to join/promote it without renewing old data.
        if self.loads.contains_key(key) {
            return;
        }
        if let Some(entry) = self.remove(key) {
            entry.cancel_refresh();
        }
    }

    fn evict_if_needed(&mut self, incoming_key: &K, capacity: usize) {
        if self.entries.len() < capacity || self.entries.contains_key(incoming_key) {
            return;
        }
        let expired = self
            .expirations
            .first_key_value()
            .filter(|((deadline, _), _)| *deadline <= Instant::now())
            .map(|(_, key)| key.clone());
        let victim = expired.or_else(|| self.entries.front().map(|(key, _)| key.clone()));
        if let Some(key) = victim {
            self.invalidate_key(&key);
            if let Some(entry) = self.remove(&key) {
                entry.cancel_refresh();
            }
        }
    }
}

pub(super) enum EntryState<V> {
    Missing,
    Expired,
    Fresh(CacheEntry<V>),
    Stale(CacheEntry<V>),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Reserved leader slots, including sources whose destruction is pending.
    pub active_loads: usize,
    /// Admitted leaders plus waiting followers; plain caches report zero.
    pub load_subscribers: usize,
    pub hits: u64,
    pub misses: u64,
    pub refreshes: u64,
    pub refresh_errors: u64,
}
