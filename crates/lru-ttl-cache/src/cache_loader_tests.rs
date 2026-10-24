use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::{Notify, oneshot};

use crate::{CacheConfig, FetchingLruTtlCache, LoadUnavailable, RefreshPriority, arc_fetch_fn};

#[tokio::test]
async fn given_cache_invalidation_hook_when_loads_and_explicit_transitions_run_then_only_transitions_fence_sources()
 {
    let invalidated = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&invalidated);
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<u64, u64>::new()
            .with_capacity(1)
            .with_fetch(arc_fetch_fn(|key: u64| async move {
                Ok::<_, LoadUnavailable>(Some(key))
            }))
            .with_invalidation(move |key| observed.lock().unwrap().push(*key)),
    );
    assert_eq!(cache.get_or_fetch(&1).await.unwrap(), Some(1));
    assert!(invalidated.lock().unwrap().is_empty());
    cache.insert(1, 10);
    cache.insert(2, 20);
    cache.remove(&2);
    cache.remove(&99);
    assert_eq!(*invalidated.lock().unwrap(), vec![1, 2, 1, 2, 99]);
}

async fn check_expired_join(stale: bool) {
    let calls = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let (started, observed) = oneshot::channel();
    let started = Arc::new(Mutex::new(Some(started)));
    let fetch_calls = Arc::clone(&calls);
    let fetch_release = Arc::clone(&release);
    let cache = FetchingLruTtlCache::new(
        CacheConfig::<u64, usize>::new()
            .with_ttl(Duration::from_millis(20))
            .with_fetch(arc_fetch_fn(move |_: u64| {
                let calls = Arc::clone(&fetch_calls);
                let release = Arc::clone(&fetch_release);
                let started = Arc::clone(&started);
                async move {
                    let call = calls.fetch_add(1, Ordering::SeqCst);
                    if call == 0 {
                        started
                            .lock()
                            .expect("test sender")
                            .take()
                            .expect("first read")
                            .send(RefreshPriority::current())
                            .ok();
                        release.notified().await;
                    }
                    Ok::<_, LoadUnavailable>(Some(call + 2))
                }
            }))
            .with_refresh_ttl(Duration::from_nanos(1), |_| 0),
    );
    cache.insert(1, 1);
    assert_eq!(cache.cached(&1), Some(1));
    let priority = observed.await.expect("refresh started");
    tokio::time::sleep(Duration::from_millis(30)).await;
    let cold_cache = cache.clone();
    let cold = tokio::spawn(async move {
        if stale {
            cold_cache
                .get_or_fetch_stale_on_error(&1, Duration::ZERO)
                .await
        } else {
            cold_cache.get_or_fetch(&1).await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), priority.promoted())
        .await
        .expect("cold cache caller promotes active refresh");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release.notify_one();
    assert_eq!(
        cold.await
            .expect("cold task")
            .expect("shared source success"),
        Some(2)
    );
    assert_eq!(
        cache.peek(&1),
        None,
        "expiry still prevents renewed residence"
    );
    assert_eq!(
        cache.get_or_fetch(&1).await.expect("new cold source"),
        Some(3)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn given_expired_entry_with_refresh_when_cold_read_joins_then_it_promotes_without_renewing_residence()
 {
    check_expired_join(false).await;
}

#[tokio::test]
async fn given_hard_expired_stale_entry_with_refresh_when_cold_read_joins_then_it_promotes_without_renewing_residence()
 {
    check_expired_join(true).await;
}
