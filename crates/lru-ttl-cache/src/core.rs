use std::{
    collections::HashMap,
    hash::Hash,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
pub(super) struct CacheCore<K, V> {
    inner: Arc<Mutex<CacheInner<K, V>>>,
    capacity: usize,
    disabled: bool,
    ttl: Duration,
    access_counter: Arc<AtomicU64>,
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
    pub(super) fn new(capacity: usize, ttl: Duration) -> Self {
        let total_capacity = capacity.max(1);
        Self {
            inner: Arc::new(Mutex::new(CacheInner::new(total_capacity))),
            capacity: total_capacity,
            disabled: ttl.is_zero(),
            ttl,
            access_counter: Arc::new(AtomicU64::new(0)),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            refreshes: Arc::new(AtomicU64::new(0)),
            refresh_errors: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(super) fn ttl(&self) -> Duration {
        self.ttl
    }

    pub(super) fn is_disabled(&self) -> bool {
        self.disabled
    }

    pub(super) fn insert(&self, key: K, value: V) {
        self.insert_with_ttl(key, value, self.ttl);
    }

    pub(super) fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        let mut inner = self.lock_inner();
        if self.disabled || ttl.is_zero() {
            inner.entries.remove(&key);
            return;
        }
        inner.evict_if_needed(&key, self.capacity);
        let access_order = self.next_access_order();
        inner
            .entries
            .insert(key, CacheEntry::new(value, ttl, access_order));
    }

    pub(super) fn remove(&self, key: &K) -> Option<V> {
        self.lock_inner()
            .entries
            .remove(key)
            .map(|entry| entry.value().clone())
    }

    pub(super) fn apply_refresh_if_current(
        &self,
        key: &K,
        expected: &CacheEntry<V>,
        value: Option<V>,
    ) -> bool {
        let mut inner = self.lock_inner();
        let Some(current) = inner.entries.get(key) else {
            return false;
        };
        if !current.is_same_entry(expected) {
            return false;
        }

        match value {
            Some(value) => {
                let access_order = self.next_access_order();
                inner
                    .entries
                    .insert(key.clone(), CacheEntry::new(value, self.ttl, access_order));
            }
            None => {
                inner.entries.remove(key);
            }
        }
        true
    }

    pub(super) fn inspect_entry(&self, key: &K) -> EntryState<V> {
        if self.disabled {
            self.record_miss();
            return EntryState::Missing;
        }

        let mut inner = self.lock_inner();
        let Some(entry_ref) = inner.entries.get(key) else {
            self.record_miss();
            return EntryState::Missing;
        };
        let entry = entry_ref.clone();
        if entry.is_expired_at(Instant::now()) {
            inner.entries.remove(key);
            self.record_miss();
            return EntryState::Expired;
        }

        entry.touch(self.next_access_order());
        self.hits.fetch_add(1, Ordering::Relaxed);
        EntryState::Fresh(entry)
    }

    pub(super) fn fresh_entry_untracked(&self, key: &K) -> Option<CacheEntry<V>> {
        if self.disabled {
            return None;
        }

        let mut inner = self.lock_inner();
        let entry = inner.entries.get(key)?.clone();
        if entry.is_expired_at(Instant::now()) {
            inner.entries.remove(key);
            return None;
        }
        entry.touch(self.next_access_order());
        Some(entry)
    }

    pub(super) fn inspect_entry_with_stale(&self, key: &K, stale_ttl: Duration) -> EntryState<V> {
        if self.disabled {
            self.record_miss();
            return EntryState::Missing;
        }

        let mut inner = self.lock_inner();
        let Some(entry_ref) = inner.entries.get(key) else {
            self.record_miss();
            return EntryState::Missing;
        };
        let entry = entry_ref.clone();
        let now = Instant::now();
        if !entry.is_expired_at(now) {
            entry.touch(self.next_access_order());
            self.hits.fetch_add(1, Ordering::Relaxed);
            return EntryState::Fresh(entry);
        }

        if entry.is_stale_at(now, stale_ttl) {
            entry.touch(self.next_access_order());
            self.hits.fetch_add(1, Ordering::Relaxed);
            return EntryState::Stale(entry);
        }

        inner.entries.remove(key);
        self.record_miss();
        EntryState::Expired
    }

    pub(super) fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            refreshes: self.refreshes.load(Ordering::Relaxed),
            refresh_errors: self.refresh_errors.load(Ordering::Relaxed),
        }
    }

    pub(super) fn record_refresh_spawn(&self) {
        self.refreshes.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn refresh_errors(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.refresh_errors)
    }

    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    fn next_access_order(&self) -> u64 {
        self.access_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, CacheInner<K, V>> {
        match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

struct CacheInner<K, V> {
    entries: HashMap<K, CacheEntry<V>>,
}

impl<K, V> CacheInner<K, V>
where K: Eq + Hash + Clone
{
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
        }
    }

    fn evict_if_needed(&mut self, incoming_key: &K, capacity: usize) {
        if self.entries.len() < capacity || self.entries.contains_key(incoming_key) {
            return;
        }

        let now = Instant::now();
        let key_to_remove = self
            .entries
            .iter()
            .find(|(_, entry)| entry.is_expired_at(now))
            .or_else(|| {
                self.entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_access_order())
            })
            .map(|(key, _)| key.clone());

        if let Some(key) = key_to_remove {
            self.entries.remove(&key);
        }
    }
}

#[derive(Clone)]
pub(super) struct CacheEntry<V> {
    inner: Arc<EntryInner<V>>,
}

struct EntryInner<V> {
    value: V,
    inserted_at: Instant,
    expires_at: Instant,
    last_access_order: AtomicU64,
    refreshing: AtomicBool,
}

impl<V> CacheEntry<V> {
    fn new(value: V, ttl: Duration, access_order: u64) -> Self {
        let inserted_at = Instant::now();
        let expires_at = inserted_at.checked_add(ttl).unwrap_or(inserted_at);
        Self {
            inner: Arc::new(EntryInner {
                value,
                inserted_at,
                expires_at,
                last_access_order: AtomicU64::new(access_order),
                refreshing: AtomicBool::new(false),
            }),
        }
    }

    fn is_expired_at(&self, now: Instant) -> bool {
        now >= self.inner.expires_at
    }

    fn is_stale_at(&self, now: Instant, stale_ttl: Duration) -> bool {
        if stale_ttl.is_zero() {
            return false;
        }
        self.inner
            .expires_at
            .checked_add(stale_ttl)
            .is_some_and(|stale_until| now < stale_until)
    }

    fn touch(&self, access_order: u64) {
        self.inner
            .last_access_order
            .store(access_order, Ordering::Relaxed);
    }

    fn last_access_order(&self) -> u64 {
        self.inner.last_access_order.load(Ordering::Relaxed)
    }

    pub(super) fn should_refresh(&self, refresh_ttl: Duration) -> bool {
        self.inner.inserted_at.elapsed() >= refresh_ttl
    }

    pub(super) fn begin_refresh(&self) -> bool {
        self.inner
            .refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(super) fn finish_refresh(&self) {
        self.inner.refreshing.store(false, Ordering::Release);
    }

    fn is_same_entry(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub(super) fn value(&self) -> &V {
        &self.inner.value
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
    pub hits: u64,
    pub misses: u64,
    pub refreshes: u64,
    pub refresh_errors: u64,
}
