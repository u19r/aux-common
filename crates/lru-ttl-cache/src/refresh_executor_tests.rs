use std::{future::pending, sync::Arc, time::Duration};

use tokio::sync::oneshot;

use crate::{
    LoadUnavailable, RefreshExecutor,
    constants::{DEFAULT_REFRESH_BYTES, MAX_LOAD_KEYS},
};

async fn wait_empty(executor: &RefreshExecutor) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while executor.stats().jobs != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("refresh work should drain");
}

#[tokio::test]
async fn given_full_executor_when_another_job_arrives_then_admission_is_rejected() {
    let executor = RefreshExecutor::new();
    let handles: Vec<_> = (0..MAX_LOAD_KEYS)
        .map(|_| {
            executor
                .try_submit(&tokio::runtime::Handle::current(), 0, pending)
                .expect("admitted")
        })
        .collect();
    assert_eq!(executor.stats().jobs, MAX_LOAD_KEYS);
    assert!(matches!(
        executor.try_submit(&tokio::runtime::Handle::current(), 0, || { pending() }),
        Err(LoadUnavailable::Full)
    ));
    assert_eq!(executor.stats().workers, 8);
    assert!(executor.stats().charged_bytes <= DEFAULT_REFRESH_BYTES);
    for handle in handles {
        handle.abort();
    }
    wait_empty(&executor).await;
    assert_eq!(executor.stats().charged_bytes, 0);
}

#[tokio::test]
async fn given_oversized_job_when_submitted_then_no_worker_or_budget_is_retained() {
    let executor = RefreshExecutor::new();
    let built = std::sync::atomic::AtomicBool::new(false);
    assert!(matches!(
        executor.try_submit(
            &tokio::runtime::Handle::current(),
            DEFAULT_REFRESH_BYTES,
            || {
                built.store(true, std::sync::atomic::Ordering::Relaxed);
                pending()
            }
        ),
        Err(LoadUnavailable::Full)
    ));
    assert!(
        !built.load(std::sync::atomic::Ordering::Relaxed),
        "rejected work is not constructed"
    );
    assert_eq!(executor.stats().jobs, 0);
    assert_eq!(executor.stats().charged_bytes, 0);
    assert_eq!(executor.stats().workers, 0);
    assert!(matches!(
        executor.try_submit(&tokio::runtime::Handle::current(), usize::MAX, || {
            pending()
        }),
        Err(LoadUnavailable::Full)
    ));
}

#[tokio::test]
async fn given_panicking_callbacks_when_following_jobs_arrive_then_workers_continue() {
    let executor = RefreshExecutor::new();
    let mut handles = Vec::new();
    for _ in 0..16 {
        handles.push(
            executor
                .try_submit(&tokio::runtime::Handle::current(), 0, || async {
                    panic!("callback panic");
                })
                .expect("admitted"),
        );
    }
    wait_empty(&executor).await;
    let (sender, receiver) = oneshot::channel();
    handles.push(
        executor
            .try_submit(&tokio::runtime::Handle::current(), 0, || async move {
                let _ = sender.send(());
            })
            .expect("admitted"),
    );
    tokio::time::timeout(Duration::from_secs(2), receiver)
        .await
        .expect("fixed workers survive")
        .expect("job completed");
    wait_empty(&executor).await;
}

#[test]
fn given_live_sender_when_runtime_stops_then_all_queued_futures_are_destroyed() {
    let executor = RefreshExecutor::new();
    let owner = Arc::new(());
    let weak = Arc::downgrade(&owner);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let handles = runtime.block_on(async {
        (0..32)
            .map(|_| {
                let owner = Arc::clone(&owner);
                executor
                    .try_submit(&tokio::runtime::Handle::current(), 0, || async move {
                        let _owner = owner;
                        pending::<()>().await;
                    })
                    .expect("admitted")
            })
            .collect::<Vec<_>>()
    });
    drop(owner);
    assert!(weak.upgrade().is_some());
    drop(runtime);
    assert!(weak.upgrade().is_none());
    assert_eq!(executor.stats().jobs, 0);
    assert_eq!(executor.stats().charged_bytes, 0);
    drop(handles);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_cancelled_job_when_its_future_is_dropping_then_admission_stays_reserved() {
    use std::sync::Mutex;

    use tokio::sync::Notify;

    use crate::source_drop_test_support::{SourceDropGate, SourceDropRelease};
    let executor = RefreshExecutor::new();
    let dropping = Arc::new(Notify::new());
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let _release = SourceDropRelease(Arc::clone(&release));
    let guard = SourceDropGate {
        dropping: Arc::clone(&dropping),
        release: Arc::clone(&release),
    };
    let handle = executor
        .try_submit(&tokio::runtime::Handle::current(), 0, || async move {
            let _guard = guard;
            pending::<()>().await;
        })
        .expect("admitted");
    handle.abort();
    tokio::time::timeout(Duration::from_secs(2), dropping.notified())
        .await
        .expect("future dropping");
    assert_eq!(executor.stats().jobs, 1);
    assert!(executor.stats().charged_bytes > 0);
    drop(_release);
    wait_empty(&executor).await;
    assert_eq!(executor.stats().charged_bytes, 0);
}

#[tokio::test]
async fn given_related_caches_when_refreshes_fill_shared_executor_then_hits_stay_available() {
    use crate::{CacheConfig, FetchingLruTtlCache, arc_fetch_fn};
    let executor = Arc::new(RefreshExecutor::new());
    let build = || {
        FetchingLruTtlCache::new(
            CacheConfig::<u64, u64>::new()
                .with_capacity(128)
                .with_ttl(Duration::from_secs(10))
                .with_fetch(arc_fetch_fn(|_: u64| async {
                    pending::<Result<Option<u64>, LoadUnavailable>>().await
                }))
                .with_refresh(Duration::from_nanos(1), Arc::clone(&executor), |_| 0),
        )
    };
    let first = build();
    let second = build();
    for key in 0..128 {
        first.insert(key, key);
        second.insert(key, key);
    }
    for key in 0..128 {
        assert_eq!(first.cached(&key), Some(key));
        assert_eq!(second.cached(&key), Some(key));
    }
    assert_eq!(executor.stats().jobs, 128);
    assert_eq!(executor.stats().rejected, 128);
    for key in 0..128 {
        first.remove(&key);
        second.remove(&key);
    }
    wait_empty(&executor).await;
    assert_eq!(first.peek(&0), None);
    assert_eq!(second.peek(&0), None);
}

#[tokio::test]
async fn given_pending_cache_refresh_when_last_owner_drops_then_provider_is_released() {
    use crate::{CacheConfig, FetchingLruTtlCache, arc_fetch_fn};
    let provider = Arc::new(());
    let weak = Arc::downgrade(&provider);
    let (started, observed) = tokio::sync::watch::channel(false);
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<u64, u64>::new()
            .with_fetch(arc_fetch_fn(move |_: u64| {
                let provider = Arc::clone(&provider);
                let started = started.clone();
                async move {
                    let _provider = provider;
                    started.send_replace(true);
                    pending::<Result<Option<u64>, LoadUnavailable>>().await
                }
            }))
            .with_refresh_ttl(Duration::from_nanos(1), |_| 0),
    );
    cache.insert(1, 1);
    assert_eq!(cache.cached(&1), Some(1));
    let mut observed = observed;
    tokio::time::timeout(
        Duration::from_secs(2),
        observed.wait_for(|started| *started),
    )
    .await
    .expect("refresh starts")
    .expect("sender lives");
    drop(cache);
    tokio::time::timeout(Duration::from_secs(2), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("last owner drop releases pending refresh and provider");
}

#[tokio::test]
async fn given_large_heap_key_when_refresh_is_requested_then_default_admission_rejects_it() {
    use crate::{CacheConfig, FetchingLruTtlCache, arc_fetch_fn};
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let fetched = Arc::clone(&calls);
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<String, u64>::new()
            .with_fetch(arc_fetch_fn(move |_: String| {
                fetched.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async { Ok::<_, LoadUnavailable>(Some(2)) }
            }))
            .with_refresh_ttl(Duration::from_nanos(1), String::len),
    );
    let key = "x".repeat(DEFAULT_REFRESH_BYTES);
    cache.insert(key.clone(), 1);
    assert_eq!(cache.cached(&key), Some(1));
    tokio::task::yield_now().await;
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(cache.stats().refresh_errors, 1);
}

#[tokio::test]
async fn given_refresh_waits_past_expiry_when_worker_frees_then_source_is_not_called() {
    use crate::{CacheConfig, FetchingLruTtlCache, arc_fetch_fn};
    let executor = Arc::new(RefreshExecutor::new());
    let mut blockers = Vec::new();
    for _ in 0..8 {
        blockers.push(
            executor
                .try_submit(&tokio::runtime::Handle::current(), 0, pending)
                .expect("block workers"),
        );
    }
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let fetched = Arc::clone(&calls);
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<u64, u64>::new()
            .with_ttl(Duration::from_millis(20))
            .with_fetch(arc_fetch_fn(move |_: u64| {
                fetched.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async { Ok::<_, LoadUnavailable>(Some(2)) }
            }))
            .with_refresh(Duration::from_nanos(1), Arc::clone(&executor), |_| 0),
    );
    cache.insert(1, 1);
    assert_eq!(cache.cached(&1), Some(1));
    tokio::time::sleep(Duration::from_millis(30)).await;
    for blocker in blockers {
        blocker.abort();
    }
    wait_empty(&executor).await;
    assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(cache.peek(&1), None);
}
