use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use buffered_writes::{
    BufferedWrites, DeliveryMode, DeliveryPolicy, InMemoryQueue, OperationStatus, PartialSink,
    QueueConfig, SinkError, SinkHealth, SinkLimits, TestClock, WriteAttempt, WriteOutcome,
};

#[derive(Clone, Copy)]
enum PartialFailure {
    Retryable,
    Unknown,
    Omitted,
}

#[tokio::test]
async fn given_incomplete_partial_failure_when_outage_age_is_reached_then_open_breaker_and_transfer_original_batch()
 {
    for failure in [
        PartialFailure::Retryable,
        PartialFailure::Unknown,
        PartialFailure::Omitted,
    ] {
        let identities = Arc::new(Mutex::new(Vec::new()));
        let captured = identities.clone();
        let committed = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let observed = committed.clone();
        let sink =
            PartialSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
                let mut identities = captured.lock().unwrap();
                identities.push((attempt.batch_id(), *attempt.digest()));
                if identities.len() > 1 {
                    observed
                        .lock()
                        .unwrap()
                        .extend(attempt.pending_operation_ids().iter().cloned());
                    return std::future::ready(Ok::<_, SinkError>(WriteOutcome::Complete));
                }
                observed
                    .lock()
                    .unwrap()
                    .insert(attempt.pending_operation_ids()[0].clone());
                let ids = attempt.pending_operation_ids();
                let mut outcomes = BTreeMap::from([(ids[0].clone(), OperationStatus::Completed)]);
                match failure {
                    PartialFailure::Retryable => {
                        outcomes.insert(
                            ids[1].clone(),
                            OperationStatus::Retryable { reason: "outage" },
                        );
                    }
                    PartialFailure::Unknown => {
                        outcomes.insert(ids[1].clone(), OperationStatus::Unknown);
                    }
                    PartialFailure::Omitted => {}
                }
                std::future::ready(Ok::<_, SinkError>(WriteOutcome::Partial(outcomes)))
            })
            .unwrap();
        let clock = TestClock::new();
        let queue = InMemoryQueue::default();
        let writer = BufferedWrites::builder("partial-outage/v1", sink.clone())
            .with_clock(clock.clone())
            .fallback(QueueConfig::custom(queue.clone()))
            .delivery_policy(DeliveryPolicy {
                failure_threshold: 1,
                max_attempts_per_turn: 1,
                ..DeliveryPolicy::default()
            })
            .build()
            .unwrap();
        writer.add_write_item(1).await.unwrap();
        writer.add_write_item(2).await.unwrap();
        clock.advance(Duration::from_secs(31));
        let report = writer.after_response().await;
        assert!(
            report.has_failures(),
            "an incomplete partial response must report destination failure"
        );
        assert_eq!(report.partial_operations_completed, 1);
        assert_eq!(report.batches_queued, 1);
        assert_eq!(queue.queued_len(), 1);
        assert_eq!(
            writer.mode_and_health(),
            (DeliveryMode::Synchronous, SinkHealth::Open)
        );
        assert_eq!(identities.lock().unwrap().len(), 1);
        assert_eq!(committed.lock().unwrap().len(), 1);
        let replay =
            buffered_writes::ReplayWorker::builder("partial-outage/v1", queue.clone(), sink)
                .with_clock(clock.clone())
                .build()
                .unwrap();
        let deadline = buffered_writes::Deadline::from_anchor(
            buffered_writes::Clock::now_instant(&clock),
            Duration::from_secs(1),
        );
        assert_eq!(
            replay
                .replay_once(1, deadline)
                .await
                .unwrap()
                .batches_delivered,
            1
        );
        assert_eq!(queue.acknowledged_count(), 1);
        assert_eq!(queue.queued_len(), 0);
        assert_eq!(committed.lock().unwrap().len(), 2);
        let identities = identities.lock().unwrap();
        assert_eq!(identities.len(), 2);
        assert_eq!(identities[0], identities[1]);
    }
}

#[tokio::test]
async fn given_young_incomplete_partial_failure_when_flushed_then_open_breaker_without_claiming_success()
 {
    let sink = PartialSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<_, SinkError>(WriteOutcome::Partial(BTreeMap::new()))
    })
    .unwrap();
    let writer = BufferedWrites::builder("young-partial/v1", sink)
        .with_clock(TestClock::new())
        .delivery_policy(DeliveryPolicy {
            failure_threshold: 1,
            max_attempts_per_turn: 1,
            ..DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let report = writer.flush_writes().await;
    assert!(report.has_failures());
    assert_eq!(report.items_settled, 0);
    assert_eq!(
        writer.mode_and_health(),
        (DeliveryMode::Buffered, SinkHealth::Open)
    );
}

#[tokio::test]
async fn given_open_breaker_when_concurrent_flushes_probe_then_one_probe_requires_real_canary_successes()
 {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use buffered_writes::AtomicSink;
    let calls = Arc::new(AtomicUsize::new(0));
    let probes = Arc::new(AtomicUsize::new(0));
    let probe_entered = Arc::new(tokio::sync::Notify::new());
    let probe_release = Arc::new(tokio::sync::Notify::new());
    let canary_entered = Arc::new(tokio::sync::Notify::new());
    let canary_release = Arc::new(tokio::sync::Notify::new());
    let (observed, entered, release) = (
        calls.clone(),
        canary_entered.clone(),
        canary_release.clone(),
    );
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        let call = observed.fetch_add(1, Ordering::SeqCst);
        let (entered, release) = (entered.clone(), release.clone());
        async move {
            match call {
                0 => Err(SinkError::retryable("outage")),
                1 => {
                    entered.notify_one();
                    release.notified().await;
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    })
    .unwrap();
    let (observed, entered, release) =
        (probes.clone(), probe_entered.clone(), probe_release.clone());
    let sink = sink.with_probe(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        let (entered, release) = (entered.clone(), release.clone());
        async move {
            entered.notify_one();
            release.notified().await;
            Ok(())
        }
    });
    let clock = TestClock::new();
    clock.set_auto_advance_on_sleep(false);
    let writer = BufferedWrites::builder("concurrent-probe/v1", sink)
        .with_clock(clock.clone())
        .delivery_policy(DeliveryPolicy {
            failure_threshold: 1,
            max_attempts_per_turn: 1,
            recovery_success_threshold: 2,
            ..DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_secs(31));
    assert!(writer.flush_writes().await.has_failures());
    assert_eq!(
        writer.mode_and_health(),
        (DeliveryMode::Synchronous, SinkHealth::Open)
    );
    let accepted = writer.add_write_item(2).await.unwrap_err();
    assert!(!accepted.is_definitely_rejected());
    clock.advance(Duration::from_secs(6));
    let first_writer = writer.clone();
    let first = tokio::spawn(async move { first_writer.flush_writes().await });
    probe_entered.notified().await;
    let second_writer = writer.clone();
    let second = tokio::spawn(async move { second_writer.flush_writes().await });
    tokio::task::yield_now().await;
    assert_eq!(probes.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    probe_release.notify_one();
    canary_entered.notified().await;
    assert_eq!(
        writer.mode_and_health(),
        (DeliveryMode::Synchronous, SinkHealth::HalfOpen)
    );
    canary_release.notify_one();
    let (first, second) = tokio::join!(first, second);
    assert_eq!(
        first.unwrap().items_settled + second.unwrap().items_settled,
        2
    );
    assert_eq!(probes.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        writer.mode_and_health(),
        (DeliveryMode::Buffered, SinkHealth::Closed)
    );
}

#[tokio::test]
async fn given_cancelled_probe_when_lease_expires_then_retry_probe_without_synthetic_writes() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use buffered_writes::AtomicSink;
    let calls = Arc::new(AtomicUsize::new(0));
    let probes = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let identities = Arc::new(Mutex::new(Vec::new()));
    let (observed, captured) = (calls.clone(), identities.clone());
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        captured.lock().unwrap().push(attempt.batch_id());
        let call = observed.fetch_add(1, Ordering::SeqCst);
        async move {
            if call == 0 {
                Err(SinkError::retryable("outage"))
            } else {
                Ok(())
            }
        }
    })
    .unwrap();
    let (observed, started) = (probes.clone(), entered.clone());
    let sink = sink.with_probe(move |_| {
        let call = observed.fetch_add(1, Ordering::SeqCst);
        let started = started.clone();
        async move {
            if call == 0 {
                started.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(())
        }
    });
    let clock = TestClock::new();
    clock.set_auto_advance_on_sleep(false);
    let writer = BufferedWrites::builder("cancel-probe/v1", sink)
        .with_clock(clock.clone())
        .delivery_policy(DeliveryPolicy {
            failure_threshold: 1,
            max_attempts_per_turn: 1,
            recovery_success_threshold: 1,
            ..DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    assert!(writer.flush_writes().await.has_failures());
    clock.advance(Duration::from_secs(6));
    let pending_writer = writer.clone();
    let pending = tokio::spawn(async move { pending_writer.flush_writes().await });
    entered.notified().await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    assert_eq!(writer.mode_and_health().1, SinkHealth::Open);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    clock.advance(Duration::from_secs(6));
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(probes.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        writer.mode_and_health(),
        (DeliveryMode::Buffered, SinkHealth::Closed)
    );
    let identities = identities.lock().unwrap();
    assert_eq!(identities.len(), 2);
    assert_eq!(identities[0], identities[1]);
}

#[tokio::test]
async fn given_default_failure_threshold_when_old_batch_is_queued_then_remain_synchronous_until_recovery()
 {
    let sink =
        buffered_writes::AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
            Err::<(), _>(SinkError::retryable("outage"))
        })
        .unwrap();
    let clock = TestClock::new();
    let queue = InMemoryQueue::default();
    let writer = BufferedWrites::builder("aged-outage/v1", sink)
        .with_clock(clock.clone())
        .fallback(QueueConfig::custom(queue.clone()))
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_secs(31));
    assert_eq!(writer.after_response().await.batches_queued, 1);
    assert_eq!(queue.queued_len(), 1);
    assert_eq!(
        writer.mode_and_health(),
        (DeliveryMode::Synchronous, SinkHealth::Open)
    );
}

#[derive(Clone, Copy)]
enum QueueFault {
    Unavailable,
    LoseFirstAcknowledgement,
}

type RecordedBatchIdentities = Arc<Mutex<Vec<(buffered_writes::BatchId, [u8; 32])>>>;

#[derive(Clone)]
struct FaultQueue {
    inner: InMemoryQueue,
    fault: QueueFault,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    identities: RecordedBatchIdentities,
}

impl FaultQueue {
    fn new(fault: QueueFault) -> Self {
        Self {
            inner: InMemoryQueue::default(),
            fault,
            calls: Arc::default(),
            identities: Arc::default(),
        }
    }
}

impl buffered_writes::WriteQueue for FaultQueue {
    fn limits(&self) -> &buffered_writes::QueueLimits {
        buffered_writes::WriteQueue::limits(&self.inner)
    }
    fn publish(
        &self,
        batch: buffered_writes::SealedBatch,
        deadline: buffered_writes::Deadline,
    ) -> futures_util::future::BoxFuture<
        'static,
        Result<buffered_writes::QueueReceipt, buffered_writes::QueueError>,
    > {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.identities
            .lock()
            .unwrap()
            .push((batch.batch_id(), *batch.digest()));
        match self.fault {
            QueueFault::Unavailable => Box::pin(async {
                Err(buffered_writes::QueueError::Unavailable {
                    reason: "queue outage",
                })
            }),
            QueueFault::LoseFirstAcknowledgement => {
                let publish = buffered_writes::WriteQueue::publish(&self.inner, batch, deadline);
                Box::pin(async move {
                    let receipt = publish.await?;
                    if call == 0 {
                        Err(buffered_writes::QueueError::AmbiguousPublish)
                    } else {
                        Ok(receipt)
                    }
                })
            }
        }
    }
}

#[tokio::test]
async fn given_open_breaker_and_unavailable_queue_when_flush_is_retried_then_report_failure_and_keep_capacity()
 {
    let sink =
        buffered_writes::AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
            Err::<(), _>(SinkError::retryable("outage"))
        })
        .unwrap();
    let clock = TestClock::new();
    let queue = FaultQueue::new(QueueFault::Unavailable);
    let observer = buffered_writes::RecordingWriteObserver::default();
    let writer = BufferedWrites::builder("both-outages/v1", sink)
        .with_observer(observer.clone())
        .with_clock(clock.clone())
        .fallback(QueueConfig::custom(queue.clone()))
        .delivery_policy(DeliveryPolicy {
            failure_threshold: 1,
            ..DeliveryPolicy::default()
        })
        .buffer_capacity(buffered_writes::BufferCapacity::default().max_items(2))
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_secs(31));
    assert!(writer.flush_writes().await.has_failures());
    clock.advance(Duration::from_millis(100));
    let report = writer.flush_writes().await;
    assert!(
        report.has_failures(),
        "open circuit and failed fallback cannot report a successful turn"
    );
    assert!(matches!(
        report.queue_error,
        Some(buffered_writes::QueueError::Unavailable { .. })
    ));
    assert_eq!(report.items_settled, 0);
    assert_eq!(report.batches_queued, 0);
    assert_eq!(queue.inner.queued_len(), 0);
    assert!(observer.events().iter().any(|event| matches!(
        event,
        buffered_writes::WriteEvent::QueueFailed {
            kind: buffered_writes::QueueFailureKind::Unavailable
        }
    )));
    let error = writer.add_write_item(2).await.unwrap_err();
    assert!(!error.is_definitely_rejected());
    let calls = std::sync::atomic::AtomicUsize::new(0);
    assert!(matches!(
        writer
            .add_write_item_with(|| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(3)
            })
            .await,
        Err(buffered_writes::WriteError::Full)
    ));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_lost_queue_ack_when_republished_then_preserve_batch_and_deduplicate_replay_effects()
{
    let sink =
        buffered_writes::AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
            Err::<(), _>(SinkError::retryable("outage"))
        })
        .unwrap();
    let clock = TestClock::new();
    let queue = FaultQueue::new(QueueFault::LoseFirstAcknowledgement);
    let writer = BufferedWrites::builder("lost-queue-ack/v1", sink)
        .with_clock(clock.clone())
        .fallback(QueueConfig::custom(queue.clone()))
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_secs(31));
    let first = writer.flush_writes().await;
    assert_eq!(
        first.queue_error,
        Some(buffered_writes::QueueError::AmbiguousPublish)
    );
    assert_eq!(first.items_settled, 0);
    assert_eq!(first.batches_queued, 0);
    assert_eq!(queue.inner.queued_len(), 1);
    clock.advance(Duration::from_millis(100));
    assert_eq!(writer.flush_writes().await.batches_queued, 1);
    assert_eq!(queue.inner.queued_len(), 2);
    let ids = queue.identities.lock().unwrap().clone();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], ids[1]);
    let committed = Arc::new(Mutex::new(BTreeMap::new()));
    let observed = committed.clone();
    let sink = buffered_writes::AtomicSink::try_new(
        SinkLimits::default(),
        move |attempt: WriteAttempt<u32>| {
            let mut commits = observed.lock().unwrap();
            let status = match commits.entry(attempt.batch_id()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(*attempt.digest());
                    buffered_writes::AtomicWriteStatus::Applied
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    assert_eq!(entry.get(), attempt.digest());
                    buffered_writes::AtomicWriteStatus::AlreadyApplied
                }
            };
            std::future::ready(Ok::<_, SinkError>(status))
        },
    )
    .unwrap();
    let replay =
        buffered_writes::ReplayWorker::builder("lost-queue-ack/v1", queue.inner.clone(), sink)
            .with_clock(clock.clone())
            .build()
            .unwrap();
    let deadline = buffered_writes::Deadline::from_anchor(
        buffered_writes::Clock::now_instant(&clock),
        Duration::from_secs(1),
    );
    assert_eq!(
        replay
            .replay_once(2, deadline)
            .await
            .unwrap()
            .batches_delivered,
        2
    );
    assert_eq!(queue.inner.acknowledged_count(), 2);
    assert_eq!(committed.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn given_sink_commit_with_lost_ack_when_retried_then_confirm_original_batch_without_duplicate_effect()
 {
    let committed = Arc::new(Mutex::new(None));
    let observed = committed.clone();
    let sink = buffered_writes::AtomicSink::try_new(
        SinkLimits::default(),
        move |attempt: WriteAttempt<u32>| {
            let identity = (attempt.batch_id(), *attempt.digest());
            let mut state = observed.lock().unwrap();
            let result = if let Some(original) = *state {
                assert_eq!(identity, original);
                Ok(buffered_writes::AtomicWriteStatus::AlreadyApplied)
            } else {
                *state = Some(identity);
                Err(SinkError::unknown_outcome(
                    "commit acknowledged after caller lost response",
                ))
            };
            std::future::ready(result)
        },
    )
    .unwrap();
    let clock = TestClock::new();
    let writer = BufferedWrites::builder("unknown-sink/v1", sink)
        .with_clock(clock.clone())
        .delivery_policy(DeliveryPolicy {
            failure_threshold: 1,
            max_attempts_per_turn: 1,
            recovery_success_threshold: 1,
            ..DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let first = writer.flush_writes().await;
    assert_eq!(
        first.last_error,
        Some(buffered_writes::SinkFailureKind::UnknownOutcome)
    );
    assert_eq!(first.items_settled, 0);
    clock.advance(Duration::from_secs(6));
    let second = writer.flush_writes().await;
    assert_eq!(second.items_settled, 1);
    assert!(!second.has_failures(), "{second:?}");
    assert_eq!(
        writer.mode_and_health(),
        (DeliveryMode::Buffered, SinkHealth::Closed)
    );
    assert!(committed.lock().unwrap().is_some());
}

#[tokio::test]
async fn given_partial_permanent_outcome_when_flushed_then_quarantine_with_confirmed_progress() {
    let sink = PartialSink::try_new(SinkLimits::default(), |attempt: WriteAttempt<u32>| {
        let ids = attempt.pending_operation_ids();
        std::future::ready(Ok::<_, SinkError>(WriteOutcome::Partial(BTreeMap::from([
            (ids[0].clone(), OperationStatus::Completed),
            (
                ids[1].clone(),
                OperationStatus::Permanent {
                    reason: "invalid effect",
                },
            ),
        ]))))
    })
    .unwrap();
    let writer = BufferedWrites::builder("partial-permanent/v1", sink)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    writer.add_write_item(2).await.unwrap();
    let report = writer.flush_writes().await;
    assert_eq!(report.partial_operations_completed, 1);
    assert_eq!(report.quarantined_items, 2);
    assert_eq!(
        report.last_error,
        Some(buffered_writes::SinkFailureKind::Permanent)
    );
    assert_eq!(report.items_settled, 0);
    assert!(report.buffer_error.is_none(), "{report:?}");
    assert!(!writer.shutdown(Duration::from_secs(1)).await.is_clean());
}

#[tokio::test]
async fn given_successful_probe_when_real_canary_fails_then_reopen_and_require_fresh_recovery_successes()
 {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let probes = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let sink =
        buffered_writes::AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
            let call = observed.fetch_add(1, Ordering::SeqCst);
            std::future::ready(if call < 2 {
                Err::<(), _>(SinkError::retryable("outage"))
            } else {
                Ok(())
            })
        })
        .unwrap();
    let observed = probes.clone();
    let sink = sink.with_probe(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(()))
    });
    let clock = TestClock::new();
    clock.set_auto_advance_on_sleep(false);
    let writer = BufferedWrites::builder("failed-canary/v1", sink)
        .with_clock(clock.clone())
        .delivery_policy(DeliveryPolicy {
            failure_threshold: 1,
            max_attempts_per_turn: 1,
            recovery_success_threshold: 2,
            ..DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_secs(31));
    assert!(writer.flush_writes().await.has_failures());
    clock.advance(Duration::from_secs(6));
    assert!(writer.flush_writes().await.has_failures());
    assert_eq!(probes.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        writer.mode_and_health(),
        (DeliveryMode::Synchronous, SinkHealth::Open)
    );
    assert!(
        !writer
            .add_write_item(2)
            .await
            .unwrap_err()
            .is_definitely_rejected()
    );
    clock.advance(Duration::from_secs(6));
    assert_eq!(writer.flush_writes().await.items_settled, 2);
    assert_eq!(probes.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(
        writer.mode_and_health(),
        (DeliveryMode::Buffered, SinkHealth::Closed)
    );
}

#[tokio::test]
async fn given_old_item_when_utc_regresses_before_failure_then_fallback_does_not_wait_for_wall_clock_catchup()
 {
    let sink =
        buffered_writes::AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
            Err::<(), _>(SinkError::retryable("outage"))
        })
        .unwrap();
    let clock = TestClock::new();
    let queue = InMemoryQueue::default();
    let writer = BufferedWrites::builder("rollback-outage/v1", sink)
        .with_clock(clock.clone())
        .fallback(QueueConfig::custom(queue.clone()))
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_secs(31));
    clock.regress_wall_clock(Duration::from_secs(3_600));
    let report = writer.after_response().await;
    assert_eq!(
        report.batches_queued, 1,
        "uncertain UTC age cannot postpone outage transfer indefinitely"
    );
    assert_eq!(queue.queued_len(), 1);
    assert_eq!(
        writer.mode_and_health(),
        (DeliveryMode::Synchronous, SinkHealth::Open)
    );
}

#[tokio::test]
async fn given_failed_sealed_batch_when_utc_regresses_then_normal_response_retries_without_wall_clock_catchup()
 {
    let sink =
        buffered_writes::AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
            Err::<(), _>(SinkError::retryable("outage"))
        })
        .unwrap();
    let clock = TestClock::new();
    let queue = InMemoryQueue::default();
    let writer = BufferedWrites::builder("sealed-rollback/v1", sink)
        .with_clock(clock.clone())
        .delivery_policy(DeliveryPolicy {
            max_attempts_per_turn: 1,
            ..DeliveryPolicy::default()
        })
        .fallback(QueueConfig::custom(queue.clone()))
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_millis(250));
    assert_eq!(writer.after_response().await.batches_failed, 1);
    assert_eq!(queue.queued_len(), 0);
    clock.regress_wall_clock(Duration::from_secs(3_600));
    let report = writer.after_response().await;
    assert_eq!(report.batches_queued, 1);
    assert_eq!(queue.queued_len(), 1);
}

#[tokio::test]
async fn given_old_failed_batch_when_utc_rolls_back_within_its_lifetime_then_retry_without_waiting_for_prior_attempt_time()
 {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let sink =
        buffered_writes::AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(Err::<(), _>(SinkError::retryable("outage")))
        })
        .unwrap();
    let clock = TestClock::new();
    let writer = BufferedWrites::builder("old-retry-clock/v1", sink)
        .with_clock(clock.clone())
        .delivery_policy(DeliveryPolicy {
            max_attempts_per_turn: 1,
            fallback_age: Duration::from_secs(86_400),
            ..DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_secs(7_200));
    assert_eq!(writer.after_response().await.batches_failed, 1);
    clock.regress_wall_clock(Duration::from_secs(3_600));
    assert_eq!(writer.after_response().await.batches_failed, 1);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}
