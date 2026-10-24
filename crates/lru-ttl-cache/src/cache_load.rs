use std::hash::Hash;

use crate::{cache_entry::CacheEntry, core::CacheCore, load_lease::LoadLease};

pub(super) enum LoadIntent<V> {
    Cold,
    Refresh(CacheEntry<V>),
}

pub(super) enum LoadPublication {
    Stored,
    NotRetained,
    Cancelled,
}

pub(super) enum LoadPreparation<K: Eq + Hash, V> {
    Cached(V),
    Fetch(CacheLoad<K, V>),
    Cancelled,
}

/// Owns publication identity until the source future has exited. The outer
/// SharedLoad leader retains admission capacity for the guard's entire life.
pub(super) struct CacheLoad<K: Eq + Hash, V> {
    core: CacheCore<K, V>,
    key: K,
    intent: LoadIntent<V>,
    lease: LoadLease,
}

impl<K: Eq + Hash, V> CacheLoad<K, V> {
    pub(super) fn new(
        core: CacheCore<K, V>,
        key: K,
        intent: LoadIntent<V>,
        lease: LoadLease,
    ) -> Self {
        Self {
            core,
            key,
            intent,
            lease,
        }
    }

    pub(super) async fn cancelled(&self) {
        self.lease.cancelled().await;
    }
}

impl<K, V> CacheLoad<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub(super) fn publish(&self, value: Option<V>) -> LoadPublication {
        self.core
            .publish_load(&self.key, &self.lease, &self.intent, value)
    }
}

impl<K: Eq + Hash, V> Drop for CacheLoad<K, V> {
    fn drop(&mut self) {
        self.core.finish_load(&self.key, &self.lease);
    }
}
