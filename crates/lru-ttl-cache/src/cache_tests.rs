use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    fmt::{self, Write as _},
    hash::{Hash, Hasher},
    hint::black_box,
    sync::{
        Arc, Mutex as StdMutex, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use tokio::sync::{Barrier, Mutex, Notify};
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};

use crate::{
    cache::{FetchingLruTtlCache, LruTtlCache},
    config::CacheConfig,
    fetch::{FetchFn, arc_fetch_fn},
    source_drop_test_support::{SourceDropGate, SourceDropRelease},
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

#[tokio::test]
async fn peek_reads_a_fresh_value_without_starting_refresh() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, ()> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(Some(1))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_millis(100))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::ZERO, String::len),
    );
    let key = "peek".to_string();
    assert_eq!(
        cache.get_or_fetch(&key).await.expect("initial fetch"),
        Some(1)
    );
    assert_eq!(cache.peek(&key), Some(1));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
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
            .with_refresh_ttl(Duration::from_millis(5), String::len),
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
async fn background_refresh_panic_does_not_disable_future_refreshes() {
    let call_count = Arc::new(AtomicUsize::new(0));
    let refresh_started = Arc::new(Notify::new());
    let fetch: FetchFn<String, usize, ()> = {
        let call_count = Arc::clone(&call_count);
        let refresh_started = Arc::clone(&refresh_started);
        arc_fetch_fn(move |_key: String| {
            let call_count = Arc::clone(&call_count);
            let refresh_started = Arc::clone(&refresh_started);
            async move {
                match call_count.fetch_add(1, Ordering::SeqCst) + 1 {
                    1 => Ok(Some(1)),
                    2 => {
                        refresh_started.notify_one();
                        panic!("simulated refresh panic");
                    }
                    _ => Ok(Some(3)),
                }
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_millis(5), String::len),
    );
    let key = "refresh-panic".to_string();

    assert_eq!(
        Some(1),
        cache.get_or_fetch(&key).await.expect("initial fetch")
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        Some(1),
        cache
            .get_or_fetch(&key)
            .await
            .expect("first refresh trigger")
    );
    refresh_started.notified().await;
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert_eq!(
        Some(1),
        cache
            .get_or_fetch(&key)
            .await
            .expect("second refresh trigger")
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while call_count.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("future refresh should run after a panic");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_refresh_does_not_overwrite_newer_insert() {
    use tokio::sync::Notify;

    let call_count = Arc::new(AtomicUsize::new(0));
    let refresh_started = Arc::new(Notify::new());
    let release_refresh = Arc::new(Notify::new());
    let fetch: FetchFn<String, usize, ()> = {
        let call_count = Arc::clone(&call_count);
        let refresh_started = Arc::clone(&refresh_started);
        let release_refresh = Arc::clone(&release_refresh);
        arc_fetch_fn(move |_key: String| {
            let call_count = Arc::clone(&call_count);
            let refresh_started = Arc::clone(&refresh_started);
            let release_refresh = Arc::clone(&release_refresh);
            async move {
                let call = call_count.fetch_add(1, Ordering::SeqCst) + 1;
                if call == 1 {
                    return Ok(Some(1));
                }
                refresh_started.notify_one();
                release_refresh.notified().await;
                Ok(Some(2))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_millis(1), String::len),
    );
    let key = "refresh-race".to_string();

    assert_eq!(
        Some(1),
        cache.get_or_fetch(&key).await.expect("initial fetch")
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(Some(1), cache.get_or_fetch(&key).await.expect("cache hit"));
    refresh_started.notified().await;

    cache.insert(key.clone(), 99);
    release_refresh.notify_one();
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert_eq!(Some(99), cache.cached(&key));
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
async fn serves_bounded_stale_value_when_refresh_fails() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, &'static str> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                let next = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if next == 1 {
                    return Ok(Some(7));
                }
                Err("fetch failed")
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_millis(5))
            .with_fetch(fetch),
    );
    let key = "stale".to_string();

    assert_eq!(
        Some(7),
        cache
            .get_or_fetch_stale_on_error(&key, Duration::from_millis(50))
            .await
            .expect("initial fetch succeeds")
    );
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert_eq!(
        Some(7),
        cache
            .get_or_fetch_stale_on_error(&key, Duration::from_millis(50))
            .await
            .expect("stale value served after refresh failure")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_stale_on_error_calls_keep_the_value_during_stale_window() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, &'static str> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(Some(7))
                } else {
                    Err("fetch failed")
                }
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_millis(5))
            .with_fetch(fetch),
    );
    let key = "repeated-stale".to_string();
    assert_eq!(
        Some(7),
        cache.get_or_fetch(&key).await.expect("initial fetch")
    );
    tokio::time::sleep(Duration::from_millis(10)).await;

    for _ in 0..2 {
        assert_eq!(
            Some(7),
            cache
                .get_or_fetch_stale_on_error(&key, Duration::from_millis(50))
                .await
                .expect("stale value should remain available")
        );
    }
}

#[test]
fn synchronous_cache_hit_without_runtime_does_not_spawn_refresh() {
    let fetch: FetchFn<String, usize, ()> =
        arc_fetch_fn(move |_key: String| async move { Ok(Some(2)) });
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_millis(1), String::len),
    );
    cache.insert("no-runtime".to_string(), 1);
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(Some(1), cache.cached(&"no-runtime".to_string()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evicting_entry_cancels_its_background_refresh() {
    struct ActiveGuard(Arc<AtomicUsize>);
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    let active = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let refresh_started = Arc::new(Notify::new());
    let fetch: FetchFn<String, usize, ()> = {
        let active = Arc::clone(&active);
        let calls = Arc::clone(&calls);
        let refresh_started = Arc::clone(&refresh_started);
        arc_fetch_fn(move |key: String| {
            let active = Arc::clone(&active);
            let calls = Arc::clone(&calls);
            let refresh_started = Arc::clone(&refresh_started);
            async move {
                if key == "A" && calls.fetch_add(1, Ordering::SeqCst) > 0 {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _guard = ActiveGuard(Arc::clone(&active));
                    refresh_started.notify_one();
                    std::future::pending::<()>().await;
                }
                Ok(Some(1))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_capacity(1)
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_millis(1), String::len),
    );
    cache
        .get_or_fetch(&"A".to_string())
        .await
        .expect("initial fetch");
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(Some(1), cache.cached(&"A".to_string()));
    refresh_started.notified().await;

    cache.insert("B".to_string(), 2);
    tokio::time::timeout(Duration::from_secs(1), async {
        while active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("eviction should cancel the refresh task");
}

#[derive(Clone)]
struct SecretError;

impl From<crate::LoadUnavailable> for SecretError {
    fn from(_: crate::LoadUnavailable) -> Self {
        Self
    }
}

impl fmt::Debug for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("token=super-secret")
    }
}

#[derive(Clone)]
struct CapturingSubscriber {
    events: Arc<StdMutex<Vec<String>>>,
}

impl Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = EventVisitor(String::new());
        event.record(&mut visitor);
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(visitor.0);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

struct EventVisitor(String);

impl Visit for EventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let _ = write!(self.0, "{}={value:?};", field.name());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn fetch_error_logs_do_not_include_error_debug_payload() {
    let fetch: FetchFn<String, usize, SecretError> =
        arc_fetch_fn(move |_key: String| async move { Err(SecretError) });
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_millis(5))
            .with_fetch(fetch),
    );
    let key = "secret".to_string();
    cache.insert(key.clone(), 7);
    tokio::time::sleep(Duration::from_millis(10)).await;

    let events = Arc::new(StdMutex::new(Vec::new()));
    let _subscriber = tracing::subscriber::set_default(CapturingSubscriber {
        events: Arc::clone(&events),
    });
    assert_eq!(
        Some(7),
        cache
            .get_or_fetch_stale_on_error(&key, Duration::from_millis(50))
            .await
            .expect("stale value is returned")
    );
    drop(_subscriber);

    let events = events
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .join("\n");
    assert!(
        !events.contains("super-secret"),
        "secret-bearing error debug payload was logged: {events}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_stale_value_after_stale_ttl() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, &'static str> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                let next = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if next == 1 {
                    return Ok(Some(7));
                }
                Err("fetch failed")
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_millis(5))
            .with_fetch(fetch),
    );
    let key = "stale-expired".to_string();

    cache
        .get_or_fetch_stale_on_error(&key, Duration::from_millis(5))
        .await
        .expect("initial fetch succeeds");
    tokio::time::sleep(Duration::from_millis(20)).await;

    assert_eq!(
        Err("fetch failed"),
        cache
            .get_or_fetch_stale_on_error(&key, Duration::from_millis(5))
            .await
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_stale_value_when_slow_fetch_exceeds_stale_ttl() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, &'static str> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Ok(Some(7));
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                Err("fetch failed")
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_millis(50))
            .with_fetch(fetch),
    );
    let key = "stale-fetch-too-slow".to_string();

    cache
        .get_or_fetch_stale_on_error(&key, Duration::from_millis(100))
        .await
        .expect("initial fetch succeeds");
    tokio::time::sleep(Duration::from_millis(60)).await;

    assert_eq!(
        Some(7),
        cache
            .get_or_fetch_stale_on_error(&key, Duration::from_millis(100))
            .await
            .expect("stale window is measured at request time so retry budget cannot eat it"),
    );
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

#[tokio::test]
async fn given_prefetched_value_when_inserted_with_shorter_ttl_then_fetching_cache_expires_on_time()
{
    let fetch: FetchFn<String, usize, ()> = arc_fetch_fn(|_key: String| async { Ok(Some(9)) });
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch),
    );
    let key = "prefetched".to_string();
    cache.insert_with_ttl(key.clone(), 3, Duration::from_millis(20));
    assert_eq!(cache.peek(&key), Some(3));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(cache.peek(&key), None);
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
            active_loads: 0,
            load_subscribers: 0,
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

#[test]
fn given_plain_cache_when_reading_metadata_and_removing_then_entry_is_removed() {
    let ttl = Duration::from_secs(17);
    let cache = LruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_capacity(2)
            .with_ttl(ttl),
    );
    let key = "plain-api".to_string();

    assert_eq!(ttl, cache.ttl());
    assert_eq!(None, cache.peek(&key));

    cache.insert(key.clone(), 7);
    let cloned = cache.clone();
    assert_eq!(Some(7), cloned.peek(&key));
    assert_eq!(Some(7), cache.peek(&key));
    assert_eq!(Some(7), cache.remove(&key));
    assert_eq!(None, cache.remove(&key));
    assert_eq!(None, cache.peek(&key));
}

#[tokio::test]
async fn given_fetching_cache_when_reading_metadata_and_removing_then_entry_is_not_fetched() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, ()> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(Some(11))
            }
        })
    };
    let ttl = Duration::from_secs(17);
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_capacity(2)
            .with_ttl(ttl)
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_secs(1), String::len),
    );
    let key = "fetching-api".to_string();
    cache.insert(key.clone(), 11);

    assert_eq!(ttl, cache.ttl());
    assert_eq!(Some(11), cache.cached(&key));
    assert_eq!(Some(11), cache.peek(&key));
    assert_eq!(Some(11), cache.remove(&key));
    assert_eq!(None, cache.remove(&key));
    assert_eq!(None, cache.cached(&key));
    assert_eq!(0, calls.load(Ordering::SeqCst));
    assert_eq!(0, cache.stats().refreshes);
}

#[tokio::test]
async fn given_fresh_entry_when_stale_on_error_lookup_runs_then_cache_value_wins() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, ()> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(Some(99))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::ZERO, String::len),
    );
    let key = "fresh-stale-lookup".to_string();
    cache.insert(key.clone(), 7);

    assert_eq!(
        Some(7),
        cache
            .get_or_fetch_stale_on_error(&key, Duration::from_secs(1))
            .await
            .expect("fresh entry should be returned")
    );
    assert_eq!(0, calls.load(Ordering::SeqCst));
    assert_eq!(0, cache.stats().refreshes);
}

#[tokio::test]
async fn given_stale_entry_when_refresh_fetch_succeeds_then_new_value_is_returned_and_cached() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, ()> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                Ok(Some(if call == 0 { 1 } else { 2 }))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_millis(5))
            .with_fetch(fetch),
    );
    let key = "stale-success".to_string();
    assert_eq!(
        Some(1),
        cache
            .get_or_fetch_stale_on_error(&key, Duration::from_secs(1))
            .await
            .expect("initial fetch should succeed")
    );

    tokio::time::sleep(Duration::from_millis(15)).await;
    assert_eq!(
        Some(2),
        cache
            .get_or_fetch_stale_on_error(&key, Duration::from_secs(1))
            .await
            .expect("stale fetch should succeed")
    );
    assert_eq!(Some(2), cache.peek(&key));
    assert_eq!(2, calls.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_refresh_in_flight_when_entry_is_read_again_then_no_second_refresh_spawns() {
    let calls = Arc::new(AtomicUsize::new(0));
    let refresh_started = Arc::new(Notify::new());
    let release_refresh = Arc::new(Notify::new());
    let fetch: FetchFn<String, usize, ()> = {
        let calls = Arc::clone(&calls);
        let refresh_started = Arc::clone(&refresh_started);
        let release_refresh = Arc::clone(&release_refresh);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            let refresh_started = Arc::clone(&refresh_started);
            let release_refresh = Arc::clone(&release_refresh);
            async move {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                if call == 1 {
                    refresh_started.notify_one();
                    release_refresh.notified().await;
                }
                Ok(Some(call + 1))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(60))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_millis(1), String::len),
    );
    let key = "refresh-in-flight".to_string();
    assert_eq!(
        Some(1),
        cache
            .get_or_fetch(&key)
            .await
            .expect("initial fetch should succeed")
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(Some(1), cache.cached(&key));
    tokio::time::timeout(Duration::from_secs(1), refresh_started.notified())
        .await
        .expect("refresh should start");
    assert_eq!(Some(1), cache.cached(&key));
    assert_eq!(2, calls.load(Ordering::SeqCst));

    release_refresh.notify_one();
    tokio::time::timeout(Duration::from_secs(1), async {
        while cache.peek(&key) != Some(2) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refresh should eventually replace the entry");
    assert_eq!(1, cache.stats().refreshes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_refresh_fetch_returns_none_when_task_finishes_then_entry_is_removed() {
    let calls = Arc::new(AtomicUsize::new(0));
    let refresh_started = Arc::new(Notify::new());
    let release_refresh = Arc::new(Notify::new());
    let fetch: FetchFn<String, usize, ()> = {
        let calls = Arc::clone(&calls);
        let refresh_started = Arc::clone(&refresh_started);
        let release_refresh = Arc::clone(&release_refresh);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            let refresh_started = Arc::clone(&refresh_started);
            let release_refresh = Arc::clone(&release_refresh);
            async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Ok(Some(1));
                }
                refresh_started.notify_one();
                release_refresh.notified().await;
                Ok(None)
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(60))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_millis(1), String::len),
    );
    let key = "refresh-none".to_string();
    assert_eq!(
        Some(1),
        cache.get_or_fetch(&key).await.expect("initial fetch")
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(Some(1), cache.cached(&key));
    tokio::time::timeout(Duration::from_secs(1), refresh_started.notified())
        .await
        .expect("refresh should start");
    release_refresh.notify_one();

    tokio::time::timeout(Duration::from_secs(1), async {
        while cache.peek(&key).is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("None refresh result should remove the entry");
    assert_eq!(1, cache.stats().refreshes);
    assert_eq!(0, cache.stats().refresh_errors);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_refresh_fetch_returns_error_when_task_finishes_then_value_and_error_stat_remain() {
    let calls = Arc::new(AtomicUsize::new(0));
    let refresh_started = Arc::new(Notify::new());
    let release_refresh = Arc::new(Notify::new());
    let fetch: FetchFn<String, usize, &'static str> = {
        let calls = Arc::clone(&calls);
        let refresh_started = Arc::clone(&refresh_started);
        let release_refresh = Arc::clone(&release_refresh);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            let refresh_started = Arc::clone(&refresh_started);
            let release_refresh = Arc::clone(&release_refresh);
            async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Ok(Some(1));
                }
                refresh_started.notify_one();
                release_refresh.notified().await;
                Err("refresh failed")
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(60))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_millis(1), String::len),
    );
    let key = "refresh-error".to_string();
    assert_eq!(
        Some(1),
        cache.get_or_fetch(&key).await.expect("initial fetch")
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(Some(1), cache.cached(&key));
    tokio::time::timeout(Duration::from_secs(1), refresh_started.notified())
        .await
        .expect("refresh should start");
    release_refresh.notify_one();

    tokio::time::timeout(Duration::from_secs(1), async {
        while cache.stats().refresh_errors == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refresh error should be recorded");
    assert_eq!(Some(1), cache.peek(&key));
    assert_eq!(1, cache.stats().refreshes);
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

#[test]
fn borrowed_read_does_not_clone_values_and_survives_eviction() {
    let clone_count = Arc::new(AtomicUsize::new(0));
    let cache = LruTtlCache::new(
        CacheConfig::<String, CloneCountingValue>::new()
            .with_capacity(2)
            .without_expiration(),
    );
    let first = "first".to_string();
    let second = "second".to_string();
    let third = "third".to_string();
    cache.insert(
        first.clone(),
        CloneCountingValue::new(1, Arc::clone(&clone_count)),
    );
    cache.insert(
        second.clone(),
        CloneCountingValue::new(2, Arc::clone(&clone_count)),
    );
    clone_count.store(0, Ordering::SeqCst);

    let retained = cache.get_ref(first.as_str()).expect("borrowed cache hit");
    assert_eq!(1, retained.value);
    assert_eq!(0, clone_count.load(Ordering::SeqCst));
    let _ = cache.get_ref(second.as_str()).expect("second cache hit");

    cache.insert(third, CloneCountingValue::new(3, Arc::clone(&clone_count)));
    assert!(cache.get_ref("first").is_none());
    assert_eq!(1, retained.value);
    assert_eq!(0, clone_count.load(Ordering::SeqCst));
}

#[test]
fn borrowed_read_accepts_str_for_a_live_string_key() {
    let cache = LruTtlCache::new(CacheConfig::<String, i32>::new().without_expiration());
    cache.insert("borrowed-live".to_owned(), 7);

    assert_eq!(Some(7), cache.get_ref("borrowed-live").map(|value| *value));
}

#[test]
fn insertion_handle_reuses_entry_without_cloning_values() {
    let clone_count = Arc::new(AtomicUsize::new(0));
    let cache = LruTtlCache::new(
        CacheConfig::<String, CloneCountingValue>::new()
            .with_capacity(2)
            .without_expiration(),
    );
    let key = "insert-handle".to_string();
    let retained = cache
        .insert_ref(
            key.clone(),
            CloneCountingValue::new(7, Arc::clone(&clone_count)),
        )
        .expect("non-expiring cache retains inserted value");

    assert_eq!(7, retained.value);
    assert_eq!(0, clone_count.load(Ordering::SeqCst));
    assert_eq!(
        7,
        cache.get_ref(&key).expect("inserted value is cached").value
    );
    assert_eq!(0, clone_count.load(Ordering::SeqCst));
}

#[test]
fn borrowed_read_honors_expiration() {
    let cache =
        LruTtlCache::new(CacheConfig::<String, i32>::new().with_ttl(Duration::from_millis(5)));
    let key = "expiring-borrowed".to_string();
    cache.insert(key.clone(), 7);
    assert_eq!(Some(7), cache.get_ref(key.as_str()).map(|value| *value));

    std::thread::sleep(Duration::from_millis(10));

    assert!(cache.get_ref("expiring-borrowed").is_none());
}

#[test]
fn borrowed_read_hit_does_not_clone_key_or_value() {
    let clone_count = Arc::new(AtomicUsize::new(0));
    let cache =
        LruTtlCache::new(CacheConfig::<String, CloneCountingValue>::new().without_expiration());
    cache.insert(
        "borrowed-hit".to_owned(),
        CloneCountingValue::new(11, Arc::clone(&clone_count)),
    );
    clone_count.store(0, Ordering::SeqCst);

    let allocations = count_test_thread_allocations(|| {
        let value = cache.get_ref("borrowed-hit").expect("borrowed cache hit");

        assert_eq!(11, value.value);
    });

    assert_eq!(0, allocations);
    assert_eq!(0, clone_count.load(Ordering::SeqCst));
}

#[test]
fn borrowed_read_without_expiration_remains_fresh() {
    let cache = LruTtlCache::new(
        CacheConfig::<String, i32>::new()
            .with_ttl(Duration::from_millis(1))
            .without_expiration(),
    );
    let key = "non-expiring-borrowed".to_string();
    cache.insert(key.clone(), 7);

    std::thread::sleep(Duration::from_millis(10));

    assert_eq!(Some(7), cache.get_ref(&key).map(|value| *value));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_misses_for_one_key_share_one_fetch() {
    const CALLERS: usize = 32;

    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, ()> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(Some(7))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch),
    );
    let start = Arc::new(Barrier::new(CALLERS + 1));
    let key = "shared".to_string();
    let mut tasks = Vec::with_capacity(CALLERS);
    for _ in 0..CALLERS {
        let cache = cache.clone();
        let start = Arc::clone(&start);
        let key = key.clone();
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            cache.get_or_fetch(&key).await
        }));
    }

    start.wait().await;
    for task in tasks {
        assert_eq!(Some(7), task.await.expect("task").expect("fetch"));
    }
    assert_eq!(1, calls.load(Ordering::SeqCst));
    assert_eq!(0, cache.stats().active_loads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_negative_misses_share_one_fetch_without_negative_caching() {
    const CALLERS: usize = 16;

    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, ()> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(None)
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch),
    );
    let start = Arc::new(Barrier::new(CALLERS + 1));
    let key = "absent".to_string();
    let mut tasks = Vec::with_capacity(CALLERS);
    for _ in 0..CALLERS {
        let cache = cache.clone();
        let start = Arc::clone(&start);
        let key = key.clone();
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            cache.get_or_fetch(&key).await
        }));
    }

    start.wait().await;
    for task in tasks {
        assert_eq!(None, task.await.expect("task").expect("fetch"));
    }
    assert_eq!(1, calls.load(Ordering::SeqCst));
    assert_eq!(None, cache.get_or_fetch(&key).await.expect("next fetch"));
    assert_eq!(2, calls.load(Ordering::SeqCst));
    assert_eq!(0, cache.stats().active_loads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn given_cancelled_leader_when_followers_wait_then_they_fail_and_a_later_call_retries() {
    let calls = Arc::new(AtomicUsize::new(0));
    let first_started = Arc::new(Notify::new());
    let fetch: FetchFn<String, usize, ()> = {
        let calls = Arc::clone(&calls);
        let first_started = Arc::clone(&first_started);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            let first_started = Arc::clone(&first_started);
            async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    first_started.notify_one();
                    std::future::pending().await
                } else {
                    Ok(Some(9))
                }
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch),
    );
    let key = "cancelled".to_string();
    let leader = {
        let cache = cache.clone();
        let key = key.clone();
        tokio::spawn(async move { cache.get_or_fetch(&key).await })
    };
    first_started.notified().await;
    let follower = {
        let cache = cache.clone();
        let key = key.clone();
        tokio::spawn(async move { cache.get_or_fetch(&key).await })
    };
    await_load_subscribers(&cache, 2).await;
    leader.abort();

    assert_eq!(
        Err(()),
        tokio::time::timeout(Duration::from_secs(1), follower)
            .await
            .expect("follower unblocked")
            .expect("follower task")
    );
    assert_eq!(1, calls.load(Ordering::SeqCst));
    assert_eq!(Ok(Some(9)), cache.get_or_fetch(&key).await);
    assert_eq!(2, calls.load(Ordering::SeqCst));
    assert_eq!(0, cache.stats().active_loads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn given_source_error_when_followers_wait_then_they_share_it_without_retrying() {
    let calls = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let first_started = Arc::new(Notify::new());
    let release_first = Arc::new(Notify::new());
    let fetch: FetchFn<String, usize, &'static str> = {
        let calls = Arc::clone(&calls);
        let active = Arc::clone(&active);
        let maximum = Arc::clone(&maximum);
        let first_started = Arc::clone(&first_started);
        let release_first = Arc::clone(&release_first);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            let first_started = Arc::clone(&first_started);
            let release_first = Arc::clone(&release_first);
            async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(current, Ordering::SeqCst);
                let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                if first {
                    first_started.notify_one();
                    release_first.notified().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Err("first fetch failed")
                } else {
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(Some(11))
                }
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch),
    );
    let key = "failed".to_string();
    let leader = {
        let cache = cache.clone();
        let key = key.clone();
        tokio::spawn(async move { cache.get_or_fetch(&key).await })
    };
    first_started.notified().await;
    let follower = {
        let cache = cache.clone();
        let key = key.clone();
        tokio::spawn(async move { cache.get_or_fetch(&key).await })
    };
    await_load_subscribers(&cache, 2).await;
    release_first.notify_one();

    assert_eq!(
        Err("first fetch failed"),
        leader.await.expect("leader task")
    );
    assert_eq!(
        Err("first fetch failed"),
        follower.await.expect("follower task")
    );
    assert_eq!(1, calls.load(Ordering::SeqCst));
    assert_eq!(Ok(Some(11)), cache.get_or_fetch(&key).await);
    assert_eq!(2, calls.load(Ordering::SeqCst));
    assert_eq!(1, maximum.load(Ordering::SeqCst));
    assert_eq!(0, cache.stats().active_loads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn given_panicking_leader_when_followers_wait_then_they_fail_and_a_later_call_retries() {
    let calls = Arc::new(AtomicUsize::new(0));
    let first_started = Arc::new(Notify::new());
    let release_first = Arc::new(Notify::new());
    let fetch: FetchFn<String, usize, ()> = {
        let calls = Arc::clone(&calls);
        let first_started = Arc::clone(&first_started);
        let release_first = Arc::clone(&release_first);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            let first_started = Arc::clone(&first_started);
            let release_first = Arc::clone(&release_first);
            async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    first_started.notify_one();
                    release_first.notified().await;
                    panic!("simulated fetch panic");
                }
                Ok(Some(13))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch),
    );
    let key = "panicked".to_string();
    let leader = {
        let cache = cache.clone();
        let key = key.clone();
        tokio::spawn(async move { cache.get_or_fetch(&key).await })
    };
    first_started.notified().await;
    let follower = {
        let cache = cache.clone();
        let key = key.clone();
        tokio::spawn(async move { cache.get_or_fetch(&key).await })
    };
    await_load_subscribers(&cache, 2).await;
    release_first.notify_one();

    assert!(leader.await.expect_err("leader must panic").is_panic());
    assert_eq!(Err(()), follower.await.expect("follower task"));
    assert_eq!(1, calls.load(Ordering::SeqCst));
    assert_eq!(Ok(Some(13)), cache.get_or_fetch(&key).await);
    assert_eq!(2, calls.load(Ordering::SeqCst));
    assert_eq!(0, cache.stats().active_loads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn different_keys_fetch_concurrently() {
    let active = Arc::new(AtomicUsize::new(0));
    let maximum_active = Arc::new(AtomicUsize::new(0));
    let both_started = Arc::new(Barrier::new(2));
    let fetch: FetchFn<String, usize, ()> = {
        let active = Arc::clone(&active);
        let maximum_active = Arc::clone(&maximum_active);
        let both_started = Arc::clone(&both_started);
        arc_fetch_fn(move |_key: String| {
            let active = Arc::clone(&active);
            let maximum_active = Arc::clone(&maximum_active);
            let both_started = Arc::clone(&both_started);
            async move {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum_active.fetch_max(current, Ordering::SeqCst);
                both_started.wait().await;
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(Some(1))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch),
    );
    let first = {
        let cache = cache.clone();
        tokio::spawn(async move { cache.get_or_fetch(&"first".to_string()).await })
    };
    let second = {
        let cache = cache.clone();
        tokio::spawn(async move { cache.get_or_fetch(&"second".to_string()).await })
    };

    let (first, second) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(first, second)
    })
    .await
    .expect("different keys must not share one fetch lock");
    assert_eq!(Some(1), first.expect("first task").expect("first fetch"));
    assert_eq!(Some(1), second.expect("second task").expect("second fetch"));
    assert_eq!(2, maximum_active.load(Ordering::SeqCst));
    assert_eq!(0, cache.stats().active_loads);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn given_full_load_capacity_when_other_keys_arrive_then_no_uncoordinated_fetch_starts() {
    let first_started = Arc::new(Notify::new());
    let release_first = Arc::new(Notify::new());
    let fetch: FetchFn<String, usize, ()> = {
        let first_started = Arc::clone(&first_started);
        let release_first = Arc::clone(&release_first);
        arc_fetch_fn(move |key: String| {
            let first_started = Arc::clone(&first_started);
            let release_first = Arc::clone(&release_first);
            async move {
                if key == "first" {
                    first_started.notify_one();
                    release_first.notified().await;
                }
                Ok(Some(1))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_capacity(1)
            .with_ttl(Duration::from_secs(1))
            .with_fetch(fetch),
    );

    let first = {
        let cache = cache.clone();
        tokio::spawn(async move { cache.get_or_fetch(&"first".to_string()).await })
    };
    first_started.notified().await;

    let mut other_tasks = Vec::new();
    for index in 0..32 {
        let cache = cache.clone();
        other_tasks.push(tokio::spawn(async move {
            cache.get_or_fetch(&format!("other-{index}")).await
        }));
    }
    for task in other_tasks {
        assert_eq!(Err(()), task.await.expect("rejected request"));
    }
    assert_eq!(1, cache.stats().active_loads);

    release_first.notify_one();
    assert_eq!(
        Some(1),
        first.await.expect("first fetch task").expect("first fetch")
    );
    assert_eq!(0, cache.stats().active_loads);
}

fn profile_hit_lock(thread_count: usize, reads_per_thread: usize, read_concurrent: bool) -> u128 {
    let values = (0..64)
        .map(|key| (key, key))
        .collect::<std::collections::HashMap<_, _>>();
    let start = Arc::new(std::sync::Barrier::new(thread_count + 1));
    let started = std::time::Instant::now();

    if read_concurrent {
        let values = Arc::new(RwLock::new(values));
        let handles = (0..thread_count)
            .map(|thread_index| {
                let values = Arc::clone(&values);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    for read_index in 0..reads_per_thread {
                        let key = (thread_index + read_index) % 64;
                        let values = values
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        black_box(values.get(&key).copied());
                    }
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        for handle in handles {
            handle.join().expect("reader");
        }
    } else {
        let values = Arc::new(StdMutex::new(values));
        let handles = (0..thread_count)
            .map(|thread_index| {
                let values = Arc::clone(&values);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    for read_index in 0..reads_per_thread {
                        let key = (thread_index + read_index) % 64;
                        let values = values
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        black_box(values.get(&key).copied());
                    }
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        for handle in handles {
            handle.join().expect("reader");
        }
    }

    started.elapsed().as_nanos()
}

#[test]
#[ignore = "P2-030a single-core and available-parallelism lock profile"]
fn cache_hit_read_lock_profile() {
    const READS_PER_THREAD: usize = 100_000;

    let parallelism = thread::available_parallelism()
        .map_or(1, usize::from)
        .clamp(1, 96);
    for thread_count in [1, parallelism] {
        let mut mutex_best_ns = u128::MAX;
        let mut rwlock_best_ns = u128::MAX;
        for iteration in 0..6 {
            if iteration % 2 == 0 {
                rwlock_best_ns =
                    rwlock_best_ns.min(profile_hit_lock(thread_count, READS_PER_THREAD, true));
                mutex_best_ns =
                    mutex_best_ns.min(profile_hit_lock(thread_count, READS_PER_THREAD, false));
            } else {
                mutex_best_ns =
                    mutex_best_ns.min(profile_hit_lock(thread_count, READS_PER_THREAD, false));
                rwlock_best_ns =
                    rwlock_best_ns.min(profile_hit_lock(thread_count, READS_PER_THREAD, true));
            }
        }
        eprintln!(
            "p2_030a_cache_hit_lock_profile|threads={thread_count}|reads_per_thread={READS_PER_THREAD}|mutex_best_ns={mutex_best_ns}|rwlock_best_ns={rwlock_best_ns}"
        );
    }
}

#[derive(Debug)]
struct CloneCountingKey {
    value: &'static str,
    clone_count: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct CloneCountingValue {
    value: usize,
    clone_count: Arc<AtomicUsize>,
}

thread_local! {
    static TEST_THREAD_ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
    static TEST_THREAD_ALLOCATION_TRACKING: Cell<bool> = const { Cell::new(false) };
}

struct TestCountingAllocator;

#[global_allocator]
static TEST_GLOBAL_ALLOCATOR: TestCountingAllocator = TestCountingAllocator;

// SAFETY: Each operation delegates to the standard system allocator with the
// same arguments and only records successful allocations on the current test
// thread.
unsafe impl GlobalAlloc for TestCountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies a valid layout for the allocation.
        let pointer = unsafe { System.alloc(layout) };
        record_test_thread_allocation(pointer);
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies a valid layout for the allocation.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        record_test_thread_allocation(pointer);
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The pointer and layout are those previously returned by this
        // allocator.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: The pointer and layout are those previously returned by this
        // allocator, and the requested size is supplied by the caller.
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        record_test_thread_allocation(new_pointer);
        new_pointer
    }
}

fn record_test_thread_allocation(pointer: *mut u8) {
    if pointer.is_null() {
        return;
    }

    TEST_THREAD_ALLOCATION_TRACKING.with(|tracking| {
        if tracking.get() {
            TEST_THREAD_ALLOCATION_COUNT.with(|count| count.set(count.get() + 1));
        }
    });
}

struct TestAllocationGuard;

impl TestAllocationGuard {
    fn start() -> Self {
        TEST_THREAD_ALLOCATION_COUNT.with(|count| count.set(0));
        TEST_THREAD_ALLOCATION_TRACKING.with(|tracking| tracking.set(true));
        Self
    }

    fn finish(self) -> usize {
        let count = TEST_THREAD_ALLOCATION_COUNT.with(Cell::get);
        drop(self);
        count
    }
}

impl Drop for TestAllocationGuard {
    fn drop(&mut self) {
        TEST_THREAD_ALLOCATION_TRACKING.with(|tracking| tracking.set(false));
    }
}

fn count_test_thread_allocations(action: impl FnOnce()) -> usize {
    let guard = TestAllocationGuard::start();
    action();
    guard.finish()
}

impl CloneCountingValue {
    fn new(value: usize, clone_count: Arc<AtomicUsize>) -> Self {
        Self { value, clone_count }
    }
}

impl Clone for CloneCountingValue {
    fn clone(&self) -> Self {
        self.clone_count.fetch_add(1, Ordering::SeqCst);
        Self {
            value: self.value,
            clone_count: Arc::clone(&self.clone_count),
        }
    }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetching_cache_fetches_value_when_missing() {
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
async fn fetching_cache_triggers_background_refresh() {
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
            .with_refresh_ttl(Duration::from_millis(5), String::len),
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
    // Allow background refresh to complete and verify that it invoked the
    // fetcher.
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(call_count.load(Ordering::SeqCst) >= 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetching_cache_expires_entries() {
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

#[tokio::test]
async fn given_expired_most_recent_entry_when_capacity_is_full_then_live_lru_is_retained() {
    let cache = LruTtlCache::new(CacheConfig::new().with_capacity(2));
    cache.insert_with_ttl("live", 1, Duration::from_secs(60));
    cache.insert_with_ttl("expired", 2, Duration::from_millis(1));
    tokio::time::sleep(Duration::from_millis(5)).await;
    cache.insert("incoming", 3);
    assert_eq!(Some(1), cache.get(&"live"));
    assert_eq!(None, cache.get(&"expired"));
    assert_eq!(Some(3), cache.get(&"incoming"));
}

#[tokio::test]
async fn given_replaced_expiry_when_capacity_is_full_then_only_current_expiry_can_evict() {
    let cache = LruTtlCache::new(CacheConfig::new().with_capacity(2));
    cache.insert_with_ttl("replaced", 1, Duration::from_millis(1));
    cache.insert_with_ttl("lru", 2, Duration::from_secs(60));
    cache.insert_with_ttl("replaced", 3, Duration::from_secs(60));
    tokio::time::sleep(Duration::from_millis(5)).await;
    cache.insert("incoming", 4);
    assert_eq!(Some(3), cache.get(&"replaced"));
    assert_eq!(None, cache.get(&"lru"));
    assert_eq!(Some(4), cache.get(&"incoming"));
}

#[tokio::test]
async fn given_removed_expiry_when_capacity_is_full_then_removal_does_not_hide_live_eviction() {
    let cache = LruTtlCache::new(CacheConfig::new().with_capacity(2));
    cache.insert_with_ttl("removed", 1, Duration::from_millis(1));
    assert_eq!(Some(1), cache.remove(&"removed"));
    cache.insert("lru", 2);
    cache.insert("recent", 3);
    tokio::time::sleep(Duration::from_millis(5)).await;
    cache.insert("incoming", 4);
    assert_eq!(None, cache.get(&"removed"));
    assert_eq!(None, cache.get(&"lru"));
    assert_eq!(Some(3), cache.get(&"recent"));
    assert_eq!(Some(4), cache.get(&"incoming"));
}

#[tokio::test]
async fn given_refresh_exceeds_entry_deadline_when_source_completes_then_expired_value_is_not_renewed()
 {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let completed = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch = arc_fetch_fn({
        let (started, release, completed, calls) = (
            Arc::clone(&started),
            Arc::clone(&release),
            Arc::clone(&completed),
            Arc::clone(&calls),
        );
        move |_: String| {
            let (started, release, completed, calls) = (
                Arc::clone(&started),
                Arc::clone(&release),
                Arc::clone(&completed),
                Arc::clone(&calls),
            );
            async move {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    started.notify_one();
                    release.notified().await;
                    completed.notify_one();
                }
                Ok::<_, &'static str>(Some(call + 2))
            }
        }
    });
    let cache = FetchingLruTtlCache::new(
        CacheConfig::new()
            .with_ttl(Duration::from_millis(40))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_millis(1), String::len),
    );
    let key = "refresh-deadline".to_owned();
    cache.insert(key.clone(), 1);
    tokio::time::sleep(Duration::from_millis(2)).await;
    assert_eq!(cache.cached(&key), Some(1));
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("refresh started");
    tokio::time::sleep(Duration::from_millis(50)).await;
    release.notify_one();
    // This current-thread runtime polls the callback and synchronous
    // publication to completion before it can resume this waiter.
    tokio::time::timeout(Duration::from_secs(1), completed.notified())
        .await
        .expect("refresh completed");
    assert_eq!(
        cache.peek(&key),
        None,
        "late refresh must not renew expired residence"
    );
    assert_eq!(
        cache.get_or_fetch(&key).await.expect("new source load"),
        Some(3)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn given_stale_read_when_invalidated_during_source_failure_then_old_entry_is_not_returned() {
    for replacement in [None, Some(2)] {
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let fetch = arc_fetch_fn({
            let (started, release) = (Arc::clone(&started), Arc::clone(&release));
            move |_: String| {
                let (started, release) = (Arc::clone(&started), Arc::clone(&release));
                async move {
                    started.notify_one();
                    release.notified().await;
                    Err::<Option<usize>, _>("source unavailable")
                }
            }
        });
        let cache = FetchingLruTtlCache::new(
            CacheConfig::new()
                .with_ttl(Duration::from_millis(100))
                .with_fetch(fetch),
        );
        let key = "stale-invalidation".to_owned();
        cache.insert(key.clone(), 1);
        tokio::time::sleep(Duration::from_millis(120)).await;
        let reader = {
            let (cache, key) = (cache.clone(), key.clone());
            tokio::spawn(async move {
                cache
                    .get_or_fetch_stale_on_error(&key, Duration::from_secs(10))
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("source started");
        cache.remove(&key);
        if let Some(value) = replacement {
            cache.insert(key.clone(), value);
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), reader)
                .await
                .expect("invalidation cancels without waiting for provider release")
                .expect("reader"),
            Err("cache load cancelled")
        );
        assert_eq!(cache.peek(&key), replacement);
    }
}

#[tokio::test]
async fn given_refresh_reports_absence_after_deadline_when_next_fetch_fails_then_old_value_is_not_served_stale()
 {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let completed = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch = arc_fetch_fn({
        let (started, release, completed, calls) = (
            Arc::clone(&started),
            Arc::clone(&release),
            Arc::clone(&completed),
            Arc::clone(&calls),
        );
        move |_: String| {
            let (started, release, completed, calls) = (
                Arc::clone(&started),
                Arc::clone(&release),
                Arc::clone(&completed),
                Arc::clone(&calls),
            );
            async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    started.notify_one();
                    release.notified().await;
                    completed.notify_one();
                    Ok(None)
                } else {
                    Err("source unavailable")
                }
            }
        }
    });
    let cache = FetchingLruTtlCache::new(
        CacheConfig::new()
            .with_ttl(Duration::from_millis(40))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_millis(1), String::len),
    );
    let key = "late-refresh-absence".to_owned();
    cache.insert(key.clone(), 1);
    tokio::time::sleep(Duration::from_millis(2)).await;
    assert_eq!(cache.cached(&key), Some(1));
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .expect("refresh started");
    tokio::time::sleep(Duration::from_millis(50)).await;
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), completed.notified())
        .await
        .expect("refresh completed");
    assert_eq!(
        cache
            .get_or_fetch_stale_on_error(&key, Duration::from_secs(10))
            .await,
        Err("source unavailable"),
        "authoritative absence must prevent stale fallback",
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn given_cold_load_when_removed_or_replaced_then_late_completion_cannot_restore_old_data() {
    for replacement in [None, Some(17)] {
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let fetch = {
            let (started, release) = (Arc::clone(&started), Arc::clone(&release));
            arc_fetch_fn(move |_: u64| {
                let (started, release) = (Arc::clone(&started), Arc::clone(&release));
                async move {
                    started.notify_one();
                    release.notified().await;
                    Ok::<_, &'static str>(Some(7))
                }
            })
        };
        let cache = FetchingLruTtlCache::new(CacheConfig::new().with_fetch(fetch));
        let request = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.get_or_fetch(&1).await })
        };
        started.notified().await;
        match replacement {
            Some(value) => cache.insert(1, value),
            None => {
                cache.remove(&1);
            }
        }
        release.notify_one();
        let result = request.await.expect("request task");
        assert_eq!(
            cache.peek(&1),
            replacement,
            "late publication replaced current state"
        );
        assert!(result.is_err(), "invalidated load must fail closed");
    }
}

async fn await_load_subscribers<E>(cache: &FetchingLruTtlCache<String, usize, E>, expected: usize)
where E: Clone + From<crate::LoadUnavailable> + Send + Sync + 'static {
    tokio::time::timeout(Duration::from_secs(2), async {
        while cache.stats().load_subscribers != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("subscriber admission deadline");
}

struct OpaqueSource;

#[derive(Debug, Clone)]
enum CacheFailure {
    Source(crate::SharedCause<OpaqueSource>),
    Unavailable(crate::LoadUnavailable),
}

impl From<crate::LoadUnavailable> for CacheFailure {
    fn from(reason: crate::LoadUnavailable) -> Self {
        Self::Unavailable(reason)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn given_many_cold_callers_when_source_fails_then_one_original_opaque_cause_reaches_every_caller()
 {
    let cause = crate::SharedCause::from(OpaqueSource);
    let calls = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let fetch = {
        let (cause, calls, release) = (cause.clone(), Arc::clone(&calls), Arc::clone(&release));
        arc_fetch_fn(move |_: String| {
            let (cause, calls, release) = (cause.clone(), Arc::clone(&calls), Arc::clone(&release));
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                release.notified().await;
                Err::<Option<usize>, _>(CacheFailure::Source(cause))
            }
        })
    };
    let cache = FetchingLruTtlCache::new(CacheConfig::new().with_fetch(fetch));
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let cache = cache.clone();
        tasks.push(tokio::spawn(async move {
            cache.get_or_fetch(&"same".to_owned()).await
        }));
    }
    await_load_subscribers(&cache, 64).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release.notify_one();
    for task in tasks {
        let Err(CacheFailure::Source(shared)) = task.await.expect("caller") else {
            panic!("original source category was lost");
        };
        assert!(std::ptr::eq(cause.as_ref(), shared.as_ref()));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(cache.stats().active_loads, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_invalidated_source_when_drop_is_pending_then_capacity_remains_reserved_until_drop_completes()
 {
    let started = Arc::new(Notify::new());
    let dropping = Arc::new(Notify::new());
    let release = Arc::new((StdMutex::new(false), std::sync::Condvar::new()));
    let _cleanup = SourceDropRelease(Arc::clone(&release));
    let fetch = {
        let (started, dropping, release) = (
            Arc::clone(&started),
            Arc::clone(&dropping),
            Arc::clone(&release),
        );
        arc_fetch_fn(move |key: String| {
            let (started, dropping, release) = (
                Arc::clone(&started),
                Arc::clone(&dropping),
                Arc::clone(&release),
            );
            async move {
                if key == "new" {
                    return Ok(Some(42));
                }
                let _guard = SourceDropGate { dropping, release };
                started.notify_one();
                std::future::pending::<Result<Option<usize>, CacheFailure>>().await
            }
        })
    };
    let cache = FetchingLruTtlCache::new(CacheConfig::new().with_capacity(1).with_fetch(fetch));
    let request = {
        let cache = cache.clone();
        tokio::spawn(async move { cache.get_or_fetch(&"old".to_owned()).await })
    };
    started.notified().await;
    cache.remove(&"old".to_owned());
    tokio::time::timeout(Duration::from_secs(2), dropping.notified())
        .await
        .expect("source drop started");
    let rejected = cache.get_or_fetch(&"new".to_owned()).await;
    let active = cache.stats().active_loads;
    {
        let (mutex, condition) = release.as_ref();
        *mutex.lock().expect("release gate") = true;
        condition.notify_all();
    }
    assert!(matches!(
        rejected,
        Err(CacheFailure::Unavailable(crate::LoadUnavailable::Full))
    ));
    assert_eq!(active, 1);
    assert!(matches!(
        request.await.expect("cancelled caller"),
        Err(CacheFailure::Unavailable(crate::LoadUnavailable::Cancelled))
    ));
    assert_eq!(cache.stats().active_loads, 0);
    assert!(matches!(
        cache.get_or_fetch(&"new".to_owned()).await,
        Ok(Some(42))
    ));
}

#[tokio::test]
async fn given_background_refresh_and_stale_reader_when_source_fails_then_they_share_one_load() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch = {
        let (started, release, calls) = (
            Arc::clone(&started),
            Arc::clone(&release),
            Arc::clone(&calls),
        );
        arc_fetch_fn(move |_: String| {
            let (started, release, calls) = (
                Arc::clone(&started),
                Arc::clone(&release),
                Arc::clone(&calls),
            );
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                started.notify_one();
                release.notified().await;
                Err::<Option<usize>, _>("provider failed")
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::new()
            .with_ttl(Duration::from_millis(40))
            .with_fetch(fetch)
            .with_refresh_ttl(Duration::from_millis(1), String::len),
    );
    let key = "refresh".to_owned();
    cache.insert(key.clone(), 7);
    tokio::time::sleep(Duration::from_millis(2)).await;
    assert_eq!(cache.cached(&key), Some(7));
    started.notified().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let reader = {
        let (cache, key) = (cache.clone(), key.clone());
        tokio::spawn(async move {
            cache
                .get_or_fetch_stale_on_error(&key, Duration::from_secs(5))
                .await
        })
    };
    await_load_subscribers(&cache, 2).await;
    release.notify_one();
    assert_eq!(reader.await.expect("stale reader"), Ok(Some(7)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(cache.stats().active_loads, 0);
}
