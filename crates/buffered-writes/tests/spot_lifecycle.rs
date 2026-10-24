#![cfg(feature = "tokio")]

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use buffered_writes::{
    InjectedSpotSource, LifecycleEvents, LifecycleTrigger, SpotActionKind, SpotInstanceAction,
    SpotLifecycle,
};
use chrono::Utc;

#[tokio::test]
async fn given_expired_or_unknown_spot_deadline_when_forwarded_then_no_fresh_shutdown_window() {
    for time in [
        None,
        Some("invalid timestamp".into()),
        Some((Utc::now() - chrono::Duration::seconds(1)).to_rfc3339()),
    ] {
        for action in [SpotActionKind::Terminate, SpotActionKind::Stop] {
            let lifecycle = SpotLifecycle::new(InjectedSpotSource::new());
            lifecycle.forward_spot_notice(&SpotInstanceAction {
                action,
                time: time.clone(),
            });
            let Some(LifecycleTrigger::Shutdown { deadline }) = lifecycle.next_event().await else {
                panic!("expected a shutdown event");
            };
            assert!(
                deadline.is_expired_at(Instant::now()),
                "unknown or expired notice cannot promise more time"
            );
        }
    }
}

#[tokio::test]
async fn given_hibernation_notice_when_forwarded_then_no_invented_grace_period() {
    let source = InjectedSpotSource::new();
    source.inject_notice(SpotInstanceAction {
        action: SpotActionKind::Hibernate,
        time: Some((Utc::now() + chrono::Duration::minutes(2)).to_rfc3339()),
    });
    let lifecycle = SpotLifecycle::new(source);
    let Some(LifecycleTrigger::Shutdown { deadline }) = lifecycle.next_event().await else {
        panic!("expected shutdown");
    };
    assert!(deadline.is_expired_at(Instant::now()));
}

#[tokio::test]
async fn given_delayed_notice_when_polled_then_remaining_budget_is_capped_by_action_time_and_host_limit()
 {
    for seconds in [10, 300] {
        let source = InjectedSpotSource::new();
        source.inject_notice(SpotInstanceAction {
            action: SpotActionKind::Terminate,
            time: Some((Utc::now() + chrono::Duration::seconds(seconds)).to_rfc3339()),
        });
        let lifecycle = SpotLifecycle::new(source).with_terminate_grace(Duration::from_secs(30));
        let Some(LifecycleTrigger::Shutdown { deadline }) = lifecycle.next_event().await else {
            panic!("expected shutdown");
        };
        assert!(
            deadline.remaining_at(Instant::now()) <= Duration::from_secs(seconds.min(30) as u64)
        );
    }
}

struct FailedSource(Arc<tokio::sync::Notify>);
impl buffered_writes::SpotActionSource for FailedSource {
    fn poll_spot_action(
        &self,
    ) -> futures_util::future::BoxFuture<
        'static,
        Result<Option<SpotInstanceAction>, buffered_writes::LifecycleError>,
    > {
        let polled = self.0.clone();
        Box::pin(async move {
            polled.notify_one();
            Err(buffered_writes::LifecycleError::SourceUnavailable {
                reason: "metadata unavailable",
            })
        })
    }
}

#[tokio::test]
async fn given_failed_spot_source_when_host_shutdown_arrives_then_observe_failure_without_blocking_host()
 {
    let polled = Arc::new(tokio::sync::Notify::new());
    let observer = buffered_writes::RecordingWriteObserver::new();
    let lifecycle =
        SpotLifecycle::new(FailedSource(polled.clone())).with_observer(observer.clone());
    let task = tokio::spawn(lifecycle.next_event());
    polled.notified().await;
    let deadline = buffered_writes::Deadline::after(Duration::from_secs(1));
    lifecycle.notify_shutdown(deadline);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap(),
        Some(LifecycleTrigger::Shutdown { deadline })
    );
    assert!(observer.events().iter().any(|event| matches!(
        event,
        buffered_writes::WriteEvent::LifecycleSourceFailed { .. }
    )));
    assert!(
        !format!(
            "{:?}",
            SpotInstanceAction {
                action: SpotActionKind::Stop,
                time: Some("PRIVATE-DATA".into())
            }
        )
        .contains("PRIVATE-DATA")
    );
}

struct CountedSource {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    polled: Arc<tokio::sync::Notify>,
    release: Option<Arc<tokio::sync::Notify>>,
    dropped: Arc<std::sync::atomic::AtomicUsize>,
}
struct PollDrop(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for PollDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
impl buffered_writes::SpotActionSource for CountedSource {
    fn poll_spot_action(
        &self,
    ) -> futures_util::future::BoxFuture<
        'static,
        Result<Option<SpotInstanceAction>, buffered_writes::LifecycleError>,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let polled = self.polled.clone();
        let release = self.release.clone();
        let dropped = self.dropped.clone();
        Box::pin(async move {
            let _guard = PollDrop(dropped);
            polled.notify_one();
            if let Some(release) = release {
                release.notified().await;
                Ok(Some(SpotInstanceAction {
                    action: SpotActionKind::Stop,
                    time: Some((Utc::now() + chrono::Duration::seconds(60)).to_rfc3339()),
                }))
            } else {
                Ok(None)
            }
        })
    }
}

#[tokio::test(start_paused = true)]
async fn given_frequent_responses_when_spot_poll_is_scheduled_then_do_not_restart_poll_interval() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let polled = Arc::new(tokio::sync::Notify::new());
    let lifecycle = SpotLifecycle::new(CountedSource {
        calls: calls.clone(),
        polled: polled.clone(),
        release: None,
        dropped: Arc::new(AtomicUsize::new(0)),
    });
    let task = tokio::spawn(lifecycle.next_event());
    polled.notified().await;
    lifecycle.notify_response_completed();
    assert_eq!(
        task.await.unwrap(),
        Some(LifecycleTrigger::ResponseCompleted)
    );
    for _ in 0..50 {
        lifecycle.notify_response_completed();
        assert_eq!(
            lifecycle.next_event().await,
            Some(LifecycleTrigger::ResponseCompleted)
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "host response rate must not become metadata poll rate"
    );
    let task = tokio::spawn(lifecycle.next_event());
    tokio::time::advance(Duration::from_secs(5)).await;
    polled.notified().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the next scheduled poll must still run"
    );
    lifecycle.close();
    assert_eq!(task.await.unwrap(), None);
}

#[tokio::test]
async fn given_pending_spot_poll_when_responses_complete_then_resume_same_poll_until_notice_arrives()
 {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let polled = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let dropped = Arc::new(AtomicUsize::new(0));
    let lifecycle = SpotLifecycle::new(CountedSource {
        calls: calls.clone(),
        polled: polled.clone(),
        release: Some(release.clone()),
        dropped: dropped.clone(),
    });
    let task = tokio::spawn(lifecycle.next_event());
    polled.notified().await;
    lifecycle.notify_response_completed();
    assert_eq!(
        task.await.unwrap(),
        Some(LifecycleTrigger::ResponseCompleted)
    );
    for _ in 0..10 {
        lifecycle.notify_response_completed();
        assert_eq!(
            lifecycle.next_event().await,
            Some(LifecycleTrigger::ResponseCompleted)
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "response completion cannot cancel discovery"
    );
    release.notify_one();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), lifecycle.next_event())
            .await
            .unwrap(),
        Some(LifecycleTrigger::Shutdown { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn given_pending_spot_poll_when_host_closes_or_waiter_aborts_then_cancel_discovery_with_handle_retained()
 {
    use std::sync::atomic::{AtomicUsize, Ordering};
    enum Teardown {
        Abort,
        Shutdown,
        Close,
    }
    for teardown in [Teardown::Abort, Teardown::Shutdown, Teardown::Close] {
        let calls = Arc::new(AtomicUsize::new(0));
        let polled = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        let lifecycle = SpotLifecycle::new(CountedSource {
            calls: calls.clone(),
            polled: polled.clone(),
            release: Some(Arc::new(tokio::sync::Notify::new())),
            dropped: dropped.clone(),
        });
        let task = tokio::spawn(lifecycle.next_event());
        polled.notified().await;
        match teardown {
            Teardown::Abort => {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            }
            Teardown::Shutdown => {
                let deadline = buffered_writes::Deadline::after(Duration::ZERO);
                lifecycle.notify_shutdown(deadline);
                assert_eq!(
                    task.await.unwrap(),
                    Some(LifecycleTrigger::Shutdown { deadline })
                );
            }
            Teardown::Close => {
                lifecycle.close();
                assert_eq!(task.await.unwrap(), None);
            }
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        lifecycle.close();
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(lifecycle.next_event().await, None);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "closed adapters cannot restart discovery"
        );
    }
}

#[test]
fn given_invalid_poll_interval_when_configuring_then_reject_instead_of_clamping_or_overflowing() {
    for interval in [Duration::ZERO, Duration::from_millis(1), Duration::MAX] {
        assert!(
            SpotLifecycle::new(InjectedSpotSource::new())
                .try_with_poll_interval(interval)
                .is_err()
        );
    }
    assert!(
        SpotLifecycle::new(InjectedSpotSource::new())
            .try_with_poll_interval(Duration::from_secs(10))
            .is_ok()
    );
}

#[tokio::test]
async fn given_shared_pending_spot_poll_when_one_waiter_aborts_then_other_waiter_keeps_discovery_owned()
 {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let polled = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let lifecycle = SpotLifecycle::new(CountedSource {
        calls: calls.clone(),
        polled: polled.clone(),
        release: Some(release.clone()),
        dropped: dropped.clone(),
    });
    let task = tokio::spawn(lifecycle.next_event());
    polled.notified().await;
    let mut other = Box::pin(lifecycle.next_event());
    assert!(futures_util::poll!(&mut other).is_pending());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        0,
        "the remaining waiter owns the poll"
    );
    release.notify_one();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), other)
            .await
            .unwrap(),
        Some(LifecycleTrigger::Shutdown { .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn given_two_pending_spot_waiters_when_close_or_shutdown_then_both_return_and_release_source()
{
    use std::sync::atomic::{AtomicUsize, Ordering};
    for shutdown in [false, true] {
        let polled = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        let lifecycle = SpotLifecycle::new(CountedSource {
            calls: Arc::new(AtomicUsize::new(0)),
            polled: polled.clone(),
            release: Some(Arc::new(tokio::sync::Notify::new())),
            dropped: dropped.clone(),
        });
        let mut first = Box::pin(lifecycle.next_event());
        assert!(futures_util::poll!(&mut first).is_pending());
        polled.notified().await;
        let mut second = Box::pin(lifecycle.next_event());
        assert!(futures_util::poll!(&mut second).is_pending());
        if shutdown {
            lifecycle.notify_shutdown(Duration::ZERO);
        } else {
            lifecycle.close();
        }
        let results = tokio::time::timeout(Duration::from_millis(100), async {
            tokio::join!(first, second)
        })
        .await
        .expect("every waiter must release after termination");
        if shutdown {
            assert!(
                matches!(results.0, Some(LifecycleTrigger::Shutdown { .. }))
                    || matches!(results.1, Some(LifecycleTrigger::Shutdown { .. }))
            );
        } else {
            assert_eq!(results, (None, None));
        }
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}
