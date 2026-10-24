use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::Semaphore;

use crate::{SharedLoad, SharedLoadError};

#[derive(Debug)]
struct Failure(String);

type Probe = SharedLoad<u64, Option<Arc<u64>>, Failure>;

async fn await_subscribers(probe: &Probe, expected: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while probe.stats().subscribers != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("subscriber admission deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn given_64_same_key_callers_when_fetching_then_success_absence_and_errors_are_shared() {
    for outcome in 0..3 {
        let probe = Arc::new(Probe::new(4, 64));
        let release = Arc::new(Semaphore::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..64 {
            let (probe, release, calls) =
                (Arc::clone(&probe), Arc::clone(&release), Arc::clone(&calls));
            tasks.push(tokio::spawn(async move {
                probe
                    .fetch(&1, || async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        release.acquire().await.expect("release").forget();
                        match outcome {
                            0 => Ok(Some(Arc::new(42))),
                            1 => Ok(None),
                            _ => Err(Failure("private source bytes".to_owned())),
                        }
                    })
                    .await
            }));
        }
        await_subscribers(&probe, 64).await;
        assert_eq!(probe.stats().active_keys, 1);
        release.add_permits(1);
        let mut value = None;
        let mut error = None;
        for task in tasks {
            match (outcome, task.await.expect("task")) {
                (0, Ok(Some(current))) => {
                    assert_eq!(*current, 42);
                    assert!(
                        value
                            .as_ref()
                            .is_none_or(|previous| Arc::ptr_eq(previous, &current))
                    );
                    value = Some(current);
                }
                (1, Ok(None)) => {}
                (2, Err(SharedLoadError::Source(current))) => {
                    assert_eq!(current.0, "private source bytes");
                    assert!(
                        error
                            .as_ref()
                            .is_none_or(|previous| Arc::ptr_eq(previous, &current))
                    );
                    error = Some(current);
                }
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(probe.stats().active_keys, 0);
        assert_eq!(probe.stats().subscribers, 0);
    }
}

#[tokio::test]
async fn given_full_key_or_subscriber_capacity_when_fetching_then_no_extra_source_starts() {
    let probe = Arc::new(Probe::new(1, 1));
    let leader = {
        let probe = Arc::clone(&probe);
        tokio::spawn(async move { probe.fetch(&1, std::future::pending).await })
    };
    await_subscribers(&probe, 1).await;
    assert!(matches!(
        probe
            .fetch(&2, || async { panic!("full key started source") })
            .await,
        Err(SharedLoadError::Full)
    ));
    let follower = {
        let probe = Arc::clone(&probe);
        tokio::spawn(async move {
            probe
                .fetch(&1, || async { panic!("follower started source") })
                .await
        })
    };
    await_subscribers(&probe, 2).await;
    assert!(matches!(
        probe
            .fetch(&1, || async { panic!("full subscriber started source") })
            .await,
        Err(SharedLoadError::Full)
    ));
    leader.abort();
    assert!(leader.await.expect_err("leader cancelled").is_cancelled());
    assert!(matches!(
        follower.await.expect("follower"),
        Err(SharedLoadError::Cancelled)
    ));
    assert_eq!(probe.stats().active_keys, 0);
    assert_eq!(probe.stats().subscribers, 0);
    assert_eq!(
        *probe
            .fetch(&1, || async { Ok(Some(Arc::new(7))) })
            .await
            .expect("retry")
            .expect("value"),
        7
    );
}

#[tokio::test]
async fn given_cancelled_subscriber_when_leader_completes_then_other_subscribers_succeed() {
    let probe = Arc::new(Probe::new(1, 3));
    let release = Arc::new(Semaphore::new(0));
    let leader = {
        let (probe, release) = (Arc::clone(&probe), Arc::clone(&release));
        tokio::spawn(async move {
            probe
                .fetch(&1, || async {
                    release.acquire().await.expect("release").forget();
                    Ok(Some(Arc::new(9)))
                })
                .await
        })
    };
    await_subscribers(&probe, 1).await;
    let follower = {
        let probe = Arc::clone(&probe);
        tokio::spawn(async move { probe.fetch(&1, std::future::pending).await })
    };
    await_subscribers(&probe, 2).await;
    follower.abort();
    assert!(follower.await.expect_err("cancelled").is_cancelled());
    await_subscribers(&probe, 1).await;
    release.add_permits(1);
    assert_eq!(
        *leader
            .await
            .expect("leader")
            .expect("fetch")
            .expect("value"),
        9
    );
    assert_eq!(probe.stats().active_keys, 0);
}

#[test]
fn given_sensitive_source_error_when_formatting_then_public_diagnostics_are_fixed_categories() {
    let error = SharedLoadError::Source(Arc::new(Failure("secret source bytes".to_owned())));
    assert_eq!(format!("{error}"), "shared fetch failed");
    assert_eq!(format!("{error:?}"), "shared fetch failed");
}

#[tokio::test]
async fn given_saturated_hot_key_waiters_when_another_key_arrives_then_reserved_leader_capacity_remains()
 {
    let probe = Arc::new(Probe::new(2, 1));
    let leader = {
        let probe = Arc::clone(&probe);
        tokio::spawn(async move { probe.fetch(&1, std::future::pending).await })
    };
    await_subscribers(&probe, 1).await;
    let follower = {
        let probe = Arc::clone(&probe);
        tokio::spawn(async move { probe.fetch(&1, std::future::pending).await })
    };
    await_subscribers(&probe, 2).await;
    assert!(matches!(
        probe
            .fetch(&1, || async { panic!("overflow started source") })
            .await,
        Err(SharedLoadError::Full)
    ));
    let calls = AtomicUsize::new(0);
    let other = probe
        .fetch(&2, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(Arc::new(12)))
        })
        .await
        .expect("independent key admitted")
        .expect("value");
    assert_eq!(*other, 12);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    leader.abort();
    assert!(leader.await.expect_err("cancelled").is_cancelled());
    assert!(matches!(
        follower.await.expect("follower"),
        Err(SharedLoadError::Cancelled)
    ));
    assert_eq!(probe.stats().subscribers, 0);
}
