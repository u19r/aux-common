use std::{future::Future, pin::Pin, sync::Arc};

// Fetching caches accept caller-owned async loaders, but the cache has to store
// those loaders behind one stable type that can be cloned, moved into refresh
// tasks, and called without naming every closure's unique future type. These
// aliases erase the concrete future into a boxed `Send` future and wrap the
// loader in `Arc`, keeping the public cache type small while preserving typed
// keys, values, and errors.

/// Boxed async result returned by fetch functions.
pub type FetchFuture<V, E> = Pin<Box<dyn Future<Output = Result<Option<V>, E>> + Send + 'static>>;

/// Shared async fetch function signature used by [`crate::cache::LruTtlCache`].
pub type FetchFn<K, V, E> = Arc<dyn Fn(K) -> FetchFuture<V, E> + Send + Sync + 'static>;

/// Helper to wrap an async function or closure into a [`FetchFn`].
pub fn arc_fetch_fn<K, V, E, F, Fut>(func: F) -> FetchFn<K, V, E>
where
    F: Fn(K) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Option<V>, E>> + Send + 'static,
    K: 'static,
    V: 'static,
    E: 'static,
{
    Arc::new(move |key| {
        let fut = func(key);
        Box::pin(fut)
    })
}
