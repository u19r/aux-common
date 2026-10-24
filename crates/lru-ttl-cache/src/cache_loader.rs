use std::{hash::Hash, sync::Arc};

use crate::{
    LoadUnavailable, SharedLoad, SharedLoadError,
    cache_load::{LoadIntent, LoadPreparation, LoadPublication},
    config::{CacheConfig, InvalidationFn},
    constants::{MAX_LOAD_KEYS, MAX_LOAD_WAITERS},
    core::CacheCore,
    fetch::FetchFn,
};

// Refresh jobs retain loading/publication state, never their execution owner.
pub(super) struct CacheLoader<K, V, E> {
    pub(super) core: CacheCore<K, V>,
    pub(super) fetch: FetchFn<K, V, E>,
    pub(super) loads: Arc<SharedLoad<K, Option<V>, E>>,
}

impl<K, V, E> Clone for CacheLoader<K, V, E>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    E: Send + 'static,
{
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
            fetch: Arc::clone(&self.fetch),
            loads: Arc::clone(&self.loads),
        }
    }
}

impl<K, V, E> CacheLoader<K, V, E>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    E: Clone + From<LoadUnavailable> + Send + Sync + 'static,
{
    pub(super) fn new(
        config: CacheConfig<K, V>,
        fetch: FetchFn<K, V, E>,
        invalidation: Option<InvalidationFn<K>>,
    ) -> Self {
        Self {
            core: CacheCore::new(config.capacity, config.expiration, invalidation),
            fetch,
            loads: Arc::new(SharedLoad::new(
                config.capacity.min(MAX_LOAD_KEYS),
                MAX_LOAD_WAITERS,
            )),
        }
    }
    pub(super) async fn fetch_and_store(&self, key: &K) -> Result<Option<V>, E> {
        if self.core.is_disabled() {
            return (self.fetch)(key.clone()).await;
        }
        self.fetch_shared(key, LoadIntent::Cold).await
    }

    pub(super) async fn fetch_shared(
        &self,
        key: &K,
        intent: LoadIntent<V>,
    ) -> Result<Option<V>, E> {
        self.loads
            .fetch(key, || async {
                let load = match self.core.prepare_load(key, intent) {
                    LoadPreparation::Cached(value) => return Ok(Some(value)),
                    LoadPreparation::Cancelled => return Err(LoadUnavailable::Cancelled.into()),
                    LoadPreparation::Fetch(load) => load,
                };
                let result = tokio::select! {
                    biased;
                    _ = load.cancelled() => return Err(LoadUnavailable::Cancelled.into()),
                    result = (self.fetch)(key.clone()) => result?,
                };
                match load.publish(result.clone()) {
                    LoadPublication::Stored | LoadPublication::NotRetained => Ok(result),
                    LoadPublication::Cancelled => Err(LoadUnavailable::Cancelled.into()),
                }
            })
            .await
            .map_err(SharedLoadError::into_owned)
    }
}
