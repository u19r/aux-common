use std::{sync::Arc, time::Duration};

use tokio::sync::Mutex;

use super::{CacheConfig, FetchFn, FetchingLruTtlCache, arc_fetch_fn};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetches_value_when_missing() {
    let state = Arc::new(Mutex::new(0usize));
    let fetch: FetchFn<String, usize, ()> = {
        let state = state.clone();
        arc_fetch_fn(move |_key: String| {
            let state = state.clone();
            async move {
                let mut guard = state.lock().await;
                *guard += 1;
                Ok(Some(*guard))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::new()
            .with_ttl(Duration::from_millis(50))
            .with_fetch(fetch),
    );

    let key = "user#1".to_string();
    let value = cache
        .get_or_fetch(&key)
        .await
        .expect("fetch should succeed")
        .expect("value expected");
    assert_eq!(1, value);

    // Second call should hit the cache without invoking the fetcher again.
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
        let call_count = call_count.clone();
        arc_fetch_fn(move |_key: String| {
            let call_count = call_count.clone();
            async move {
                let next = call_count.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(Some(next))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::new()
            .with_ttl(Duration::from_millis(100))
            .with_fetch(fetch)
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
    // Allow background refresh to complete and verify that it invoked the fetcher.
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(call_count.load(Ordering::SeqCst) >= 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expires_entries() {
    let fetch: FetchFn<String, i32, ()> =
        arc_fetch_fn(move |_key: String| async move { Ok::<_, ()>(Some(99)) });
    let cache = FetchingLruTtlCache::new(
        CacheConfig::new()
            .with_ttl(Duration::from_millis(5))
            .with_fetch(fetch),
    );
    let key = "expiring".to_string();
    cache
        .get_or_fetch(&key)
        .await
        .expect("initial fetch succeeds");

    tokio::time::sleep(Duration::from_millis(10)).await;
    let second = cache
        .get_or_fetch(&key)
        .await
        .expect("second fetch succeeds")
        .expect("value expected");
    assert_eq!(99, second);
}
