use std::{
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::Mutex;

use crate::{
    cache::{FetchingLruTtlCache, LruTtlCache},
    config::CacheConfig,
    fetch::{FetchFn, arc_fetch_fn},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetches_value_when_missing() {
    let state = Arc::new(Mutex::new(0usize));
    let fetch: FetchFn<String, usize, ()> = {
        let state = Arc::clone(&state);
        arc_fetch_fn(move |_key: String| {
            let state = Arc::clone(&state);
            async move {
                let mut guard = state.lock().await;
                *guard += 1;
                Ok(Some(*guard))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_millis(50))
            .with_fetch(fetch.clone()),
    );

    let key = "user#1".to_string();
    let value = cache
        .get_or_fetch(&key)
        .await
        .expect("fetch should succeed")
        .expect("value expected");
    assert_eq!(1, value);

    let cached = cache
        .get_or_fetch(&key)
        .await
        .expect("cache hit should succeed")
        .expect("value expected");
    assert_eq!(1, cached);

    let guard = state.lock().await;
    assert_eq!(1, *guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn triggers_background_refresh() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let call_count = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, ()> = {
        let call_count = Arc::clone(&call_count);
        arc_fetch_fn(move |_key: String| {
            let call_count = Arc::clone(&call_count);
            async move {
                let next = call_count.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(Some(next))
            }
        })
    };

    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_millis(100))
            .with_fetch(fetch.clone())
            .with_refresh_ttl(Duration::from_millis(5)),
    );

    let key = "tenant#123".to_string();
    let value = cache
        .get_or_fetch(&key)
        .await
        .expect("initial fetch succeeds")
        .expect("value expected");
    assert_eq!(1, value);

    tokio::time::sleep(Duration::from_millis(10)).await;
    let cached = cache
        .get_or_fetch(&key)
        .await
        .expect("cache hit succeeds")
        .expect("value expected");
    assert_eq!(1, cached);

    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(call_count.load(Ordering::SeqCst) >= 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expires_entries() {
    let fetch: FetchFn<String, i32, ()> =
        arc_fetch_fn(move |_key: String| async move { Ok::<_, ()>(Some(99)) });
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, i32>::new()
            .with_ttl(Duration::from_millis(5))
            .with_fetch(fetch.clone()),
    );
    let key = "expiring".to_string();
    cache
        .get_or_fetch(&key)
        .await
        .expect("initial fetch succeeds")
        .expect("value expected");

    tokio::time::sleep(Duration::from_millis(10)).await;
    let second = cache
        .get_or_fetch(&key)
        .await
        .expect("second fetch succeeds")
        .expect("value expected");
    assert_eq!(99, second);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supports_per_entry_ttl() {
    let cache =
        LruTtlCache::new(CacheConfig::<String, i32>::new().with_ttl(Duration::from_millis(5)));
    let default_ttl_key = "default".to_string();
    let custom_ttl_key = "custom".to_string();

    cache.insert(default_ttl_key.clone(), 1);
    cache.insert_with_ttl(custom_ttl_key.clone(), 2, Duration::from_millis(50));

    tokio::time::sleep(Duration::from_millis(10)).await;

    assert_eq!(None, cache.get(&default_ttl_key));
    assert_eq!(Some(2), cache.get(&custom_ttl_key));

    tokio::time::sleep(Duration::from_millis(45)).await;
    assert_eq!(None, cache.get(&custom_ttl_key));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_ttl_disables_plain_cache() {
    let cache = LruTtlCache::new(CacheConfig::<String, i32>::new().with_ttl(Duration::ZERO));
    let key = "disabled".to_string();

    cache.insert(key.clone(), 7);

    assert_eq!(None, cache.get(&key));
    assert_eq!(
        cache.stats(),
        crate::CacheStats {
            hits: 0,
            misses: 1,
            refreshes: 0,
            refresh_errors: 0,
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_ttl_disables_fetching_cache_storage() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, ()> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                let next = calls.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(Some(next))
            }
        })
    };

    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::ZERO)
            .with_fetch(fetch),
    );
    let key = "disabled".to_string();

    let first = cache
        .get_or_fetch(&key)
        .await
        .expect("first fetch succeeds")
        .expect("value expected");
    let second = cache
        .get_or_fetch(&key)
        .await
        .expect("second fetch succeeds")
        .expect("value expected");

    assert_eq!(1, first);
    assert_eq!(2, second);
    assert_eq!(2, calls.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_does_not_clone_keys_on_cache_hits() {
    let clone_count = Arc::new(AtomicUsize::new(0));
    let key = CloneCountingKey::new("hot-table", Arc::clone(&clone_count));
    let cache = LruTtlCache::new(
        CacheConfig::<CloneCountingKey, i32>::new()
            .with_capacity(16)
            .with_ttl(Duration::from_secs(60)),
    );

    cache.insert(key.clone(), 1);
    clone_count.store(0, Ordering::SeqCst);

    for _ in 0..100 {
        assert_eq!(Some(1), cache.get(&key));
    }

    assert_eq!(0, clone_count.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evicts_least_recently_accessed_entry_when_capacity_is_full() {
    let cache = LruTtlCache::new(
        CacheConfig::<String, i32>::new()
            .with_capacity(2)
            .with_ttl(Duration::from_secs(60)),
    );
    let first = "first".to_string();
    let second = "second".to_string();
    let third = "third".to_string();

    cache.insert(first.clone(), 1);
    cache.insert(second.clone(), 2);
    assert_eq!(Some(1), cache.get(&first));

    cache.insert(third.clone(), 3);

    assert_eq!(Some(1), cache.get(&first));
    assert_eq!(None, cache.get(&second));
    assert_eq!(Some(3), cache.get(&third));
}

#[derive(Debug)]
struct CloneCountingKey {
    value: &'static str,
    clone_count: Arc<AtomicUsize>,
}

impl CloneCountingKey {
    fn new(value: &'static str, clone_count: Arc<AtomicUsize>) -> Self {
        Self { value, clone_count }
    }
}

impl Clone for CloneCountingKey {
    fn clone(&self) -> Self {
        self.clone_count.fetch_add(1, Ordering::SeqCst);
        Self {
            value: self.value,
            clone_count: Arc::clone(&self.clone_count),
        }
    }
}

impl PartialEq for CloneCountingKey {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for CloneCountingKey {}

impl Hash for CloneCountingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}
