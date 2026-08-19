use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use super::KeyedSingleflight;

#[tokio::test]
async fn same_key_serializes_while_different_keys_remain_concurrent_and_cleanup() {
    let singleflight = KeyedSingleflight::default();
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    for key in ["same", "same", "other"] {
        let singleflight = singleflight.clone();
        let active = Arc::clone(&active);
        let maximum = Arc::clone(&maximum);
        tasks.spawn(async move {
            let _guard = singleflight.lock(&key).await;
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            maximum.fetch_max(current, Ordering::SeqCst);
            tokio::task::yield_now().await;
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.expect("singleflight task");
    }

    assert_eq!(maximum.load(Ordering::SeqCst), 2);
    assert_eq!(singleflight.active_key_count(), 0);
}
