use std::{
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
            .with_refresh_ttl(Duration::ZERO),
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
            .with_refresh_ttl(Duration::from_millis(5)),
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
            .with_refresh_ttl(Duration::from_millis(1)),
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
            .with_refresh_ttl(Duration::from_millis(1)),
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
            .with_refresh_ttl(Duration::from_millis(1)),
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

struct SecretError;

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
async fn refuses_stale_value_if_fetch_finishes_after_stale_ttl() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fetch: FetchFn<String, usize, &'static str> = {
        let calls = Arc::clone(&calls);
        arc_fetch_fn(move |_key: String| {
            let calls = Arc::clone(&calls);
            async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Ok(Some(7));
                }
                tokio::time::sleep(Duration::from_millis(40)).await;
                Err("fetch failed")
            }
        })
    };
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, usize>::new()
            .with_ttl(Duration::from_millis(5))
            .with_fetch(fetch),
    );
    let key = "stale-fetch-too-slow".to_string();

    cache
        .get_or_fetch_stale_on_error(&key, Duration::from_millis(10))
        .await
        .expect("initial fetch succeeds");
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert_eq!(
        Err("fetch failed"),
        cache
            .get_or_fetch_stale_on_error(&key, Duration::from_millis(10))
            .await,
        "a stale value must not be resurrected after its stale deadline"
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
    assert_eq!(0, cache.in_flight_count());
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
    assert_eq!(0, cache.in_flight_count());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_releases_same_key_followers() {
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
    tokio::task::yield_now().await;
    leader.abort();

    assert_eq!(
        Some(9),
        tokio::time::timeout(Duration::from_secs(1), follower)
            .await
            .expect("follower unblocked")
            .expect("follower task")
            .expect("retry fetch")
    );
    assert_eq!(2, calls.load(Ordering::SeqCst));
    assert_eq!(0, cache.in_flight_count());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_error_releases_same_key_followers_for_retry() {
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
    tokio::task::yield_now().await;
    release_first.notify_one();

    assert_eq!(
        Err("first fetch failed"),
        leader.await.expect("leader task")
    );
    assert_eq!(
        Some(11),
        follower.await.expect("follower task").expect("retry fetch")
    );
    assert_eq!(2, calls.load(Ordering::SeqCst));
    assert_eq!(1, maximum.load(Ordering::SeqCst));
    assert_eq!(0, cache.in_flight_count());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_panic_releases_same_key_followers_for_retry() {
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
    tokio::task::yield_now().await;
    release_first.notify_one();

    assert!(leader.await.expect_err("leader must panic").is_panic());
    assert_eq!(
        Some(13),
        follower.await.expect("follower task").expect("retry fetch")
    );
    assert_eq!(2, calls.load(Ordering::SeqCst));
    assert_eq!(0, cache.in_flight_count());
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
    assert_eq!(0, cache.in_flight_count());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn distinct_key_fetch_coordination_is_bounded_by_cache_capacity() {
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
    tokio::task::yield_now().await;
    assert_eq!(1, cache.in_flight_count());

    release_first.notify_one();
    assert_eq!(
        Some(1),
        first.await.expect("first fetch task").expect("first fetch")
    );
    for task in other_tasks {
        assert_eq!(
            Some(1),
            task.await.expect("other fetch task").expect("other fetch")
        );
    }
    assert_eq!(0, cache.in_flight_count());
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
