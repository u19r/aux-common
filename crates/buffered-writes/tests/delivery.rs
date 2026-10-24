use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use buffered_writes::{
    AtomicSink, BufferCapacity, BufferStats, BufferedWrites, DeliveryPolicy, FlushThresholds,
    OperationId, PartialSink, PreparedWrites, SinkError, SinkLimits, TestClock, WriteAttempt,
    WriteError, WriteOptions,
};

type Attempts = Arc<Mutex<Vec<(buffered_writes::BatchId, Vec<u32>)>>>;

fn recording_sink() -> (AtomicSink<u32>, Attempts) {
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let recorded = attempts.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let recorded = recorded.clone();
        async move {
            recorded
                .lock()
                .unwrap()
                .push((attempt.batch_id(), attempt.items().to_vec()));
            Ok::<(), SinkError>(())
        }
    })
    .unwrap();
    (sink, attempts)
}

#[tokio::test]
async fn given_defaults_when_responses_reach_age_then_flush_at_200ms() {
    let (sink, attempts) = recording_sink();
    let clock = TestClock::new();
    let writer = BufferedWrites::builder("age/v1", sink)
        .with_clock(clock.clone())
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_millis(199));
    assert_eq!(writer.after_response().await.batches_flushed, 0);
    clock.advance(Duration::from_millis(1));
    assert_eq!(writer.after_response().await.items_settled, 1);
    assert_eq!(attempts.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn given_defaults_when_25_items_arrive_then_defer_flush_until_response_completion() {
    let (sink, attempts) = recording_sink();
    let writer = BufferedWrites::builder("count/v1", sink)
        .with_clock(TestClock::new())
        .build()
        .unwrap();
    for item in 0..24 {
        writer.add_write_item(item).await.unwrap();
    }
    assert!(attempts.lock().unwrap().is_empty());
    writer.add_write_item(24).await.unwrap();
    assert!(
        attempts.lock().unwrap().is_empty(),
        "buffered admission must not deliver"
    );
    let factories = AtomicUsize::new(0);
    assert!(matches!(
        writer
            .add_write_item_with(|| {
                factories.fetch_add(1, Ordering::SeqCst);
                Ok(25)
            })
            .await,
        Err(WriteError::Full)
    ));
    assert_eq!(factories.load(Ordering::SeqCst), 0);
    assert_eq!(writer.after_response().await.items_settled, 25);
    assert_eq!(attempts.lock().unwrap()[0].1.len(), 25);
}

#[tokio::test]
async fn given_custom_policy_when_age_exceeds_default_then_only_predicate_controls_flush() {
    let (sink, attempts) = recording_sink();
    let clock = TestClock::new();
    let writer = BufferedWrites::builder("custom/v1", sink)
        .with_clock(clock.clone())
        .flush_policy(|stats: &BufferStats| stats.items() >= 3)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_secs(1));
    writer.after_response().await;
    assert!(attempts.lock().unwrap().is_empty());
    writer.add_write_item(2).await.unwrap();
    writer.add_write_item(3).await.unwrap();
    assert_eq!(writer.after_response().await.items_settled, 3);
}

#[tokio::test]
async fn given_overridden_thresholds_when_500ms_reached_then_default_age_does_not_apply() {
    let (sink, _) = recording_sink();
    let clock = TestClock::new();
    let writer = BufferedWrites::builder("overrides/v1", sink)
        .with_clock(clock.clone())
        .buffer_capacity(BufferCapacity::default().max_items(500))
        .flush_policy(
            FlushThresholds::default()
                .max_age(Duration::from_millis(500))
                .max_items(100),
        )
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_millis(499));
    assert_eq!(writer.after_response().await.items_settled, 0);
    clock.advance(Duration::from_millis(1));
    assert_eq!(writer.after_response().await.items_settled, 1);
}

#[tokio::test]
async fn given_false_predicate_when_capacity_is_full_then_reject_without_eviction() {
    let (sink, attempts) = recording_sink();
    let writer = BufferedWrites::builder("full/v1", sink)
        .flush_policy(|_: &BufferStats| false)
        .build()
        .unwrap();
    for item in 0..25 {
        writer.add_write_item(item).await.unwrap();
    }
    assert!(matches!(
        writer.add_write_item(26).await,
        Err(WriteError::Full)
    ));
    assert_eq!(writer.flush_writes().await.items_settled, 25);
    assert_eq!(attempts.lock().unwrap()[0].1, (0..25).collect::<Vec<_>>());
}

#[tokio::test]
async fn given_stable_admission_identity_when_retried_then_deduplicate_and_reject_changed_bytes() {
    let (sink, attempts) = recording_sink();
    let writer = BufferedWrites::builder("identity/v1", sink)
        .build()
        .unwrap();
    let options = WriteOptions::new().with_operation_id(OperationId::try_new("request-1").unwrap());
    writer
        .add_write_item_with_options(1, options.clone())
        .await
        .unwrap();
    writer
        .add_write_item_with_options(1, options.clone())
        .await
        .unwrap();
    assert!(matches!(
        writer.add_write_item_with_options(2, options).await,
        Err(WriteError::IdentityConflict { .. })
    ));
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(attempts.lock().unwrap()[0].1, vec![1]);
}

#[tokio::test]
async fn given_partial_success_when_retried_then_retry_only_pending_operations() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let sink = PartialSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let calls = recorded.clone();
        async move {
            let mut calls = calls.lock().unwrap();
            calls.push(
                attempt
                    .pending_items()
                    .iter()
                    .map(|item| *item.item())
                    .collect::<Vec<_>>(),
            );
            if calls.len() == 1 {
                attempt.complete_except([attempt.pending_operation_ids()[1].clone()])
            } else {
                attempt.complete()
            }
        }
    })
    .unwrap();
    let writer = BufferedWrites::builder("partial/v1", sink)
        .with_clock(TestClock::new())
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    writer.add_write_item(2).await.unwrap();
    let report = writer.flush_writes().await;
    assert_eq!(*calls.lock().unwrap(), vec![vec![1, 2], vec![2]]);
    assert!(report.buffer_error.is_none(), "{report:?}");
    assert_eq!(report.batches_flushed, 1);
    assert_eq!(report.items_settled, 2);
}

#[tokio::test]
async fn given_packed_preparation_when_flushed_then_deliver_one_combined_value() {
    let totals = Arc::new(Mutex::new(Vec::new()));
    let recorded = totals.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let totals = recorded.clone();
        async move {
            totals
                .lock()
                .unwrap()
                .push(attempt.decode_packed::<u32>().unwrap());
            Ok::<(), SinkError>(())
        }
    })
    .unwrap();
    let writer = BufferedWrites::builder("packed/v1", sink)
        .prepare_with("sum/v1", |batch| {
            PreparedWrites::packed(&batch, &batch.items().iter().sum::<u32>())
        })
        .build()
        .unwrap();
    writer.add_write_item(3).await.unwrap();
    writer.add_write_item(7).await.unwrap();
    assert_eq!(writer.flush_writes().await.batches_flushed, 1);
    assert_eq!(*totals.lock().unwrap(), vec![10]);
}

#[tokio::test]
async fn given_full_buffer_when_factory_is_submitted_then_do_not_invoke_factory() {
    let (sink, _) = recording_sink();
    let writer = BufferedWrites::builder("staging/v1", sink)
        .flush_policy(|_: &BufferStats| false)
        .buffer_capacity(BufferCapacity::default().max_items(1))
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let invoked = calls.clone();
    assert!(matches!(
        writer
            .add_write_item_with(move || {
                invoked.fetch_add(1, Ordering::SeqCst);
                Ok(2)
            })
            .await,
        Err(WriteError::Full)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_hung_sink_when_shutdown_deadline_expires_then_return_unresolved_report() {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        std::future::pending::<Result<(), SinkError>>().await
    })
    .unwrap();
    let policy = DeliveryPolicy {
        attempt_timeout: Duration::from_millis(10),
        flush_budget: Duration::from_millis(20),
        ..DeliveryPolicy::default()
    };
    let writer = BufferedWrites::builder("deadline/v1", sink)
        .delivery_policy(policy)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let report = tokio::time::timeout(
        Duration::from_millis(100),
        writer.shutdown(Duration::from_millis(30)),
    )
    .await
    .expect("shutdown must enforce the host deadline on hung sink I/O");
    assert_eq!(report.unresolved_items, 1);
    assert!(!report.is_clean());
}

#[test]
fn given_zero_default_threshold_override_when_built_then_reject_configuration() {
    let (sink, _) = recording_sink();
    assert!(
        BufferedWrites::builder("invalid/v1", sink)
            .flush_policy(FlushThresholds::default().max_items(0))
            .build()
            .is_err()
    );
}

#[tokio::test]
async fn given_inflight_flush_when_shutdown_starts_then_lock_wait_is_bounded_by_host_deadline() {
    let started = Arc::new(tokio::sync::Notify::new());
    let observed = started.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        let observed = observed.clone();
        async move {
            observed.notify_one();
            std::future::pending::<Result<(), SinkError>>().await
        }
    })
    .unwrap();
    let writer = BufferedWrites::builder("concurrent-drain/v1", sink)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let concurrent_writer = writer.clone();
    let flushing = tokio::spawn(async move { concurrent_writer.flush_writes().await });
    started.notified().await;
    let drain = tokio::time::timeout(
        Duration::from_millis(100),
        writer.shutdown(Duration::from_millis(30)),
    )
    .await;
    flushing.abort();
    assert_eq!(
        drain
            .expect("drain must bound waiting for another flush")
            .unresolved_items,
        1
    );
}

#[tokio::test]
async fn given_old_backlog_when_sync_turn_expires_after_old_write_then_never_acknowledge_new_item()
{
    let clock = TestClock::new();
    let observed_clock = clock.clone();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(1, 64 * 1024).unwrap(),
        move |attempt: WriteAttempt<u32>| {
            let observed = observed.clone();
            let clock = observed_clock.clone();
            async move {
                let mut calls = observed.lock().unwrap();
                calls.push(attempt.items().to_vec());
                if calls.len() == 1 {
                    return Err::<(), SinkError>(SinkError::retryable("outage"));
                }
                clock.advance(Duration::from_secs(3));
                Ok(())
            }
        },
    )
    .unwrap();
    let policy = DeliveryPolicy {
        failure_threshold: 1,
        ..DeliveryPolicy::default()
    };
    let writer = BufferedWrites::builder("sync-ownership/v1", sink)
        .with_clock(clock.clone())
        .delivery_policy(policy)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_secs(31));
    assert!(writer.flush_writes().await.has_failures());
    clock.advance(Duration::from_secs(6));
    let admission = writer.add_write_item(2).await;
    assert!(
        admission.is_err(),
        "settling old backlog cannot acknowledge a different pending write: {admission:?}"
    );
    assert_eq!(*calls.lock().unwrap(), vec![vec![1], vec![1]]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_constructing_item_when_competing_factory_runs_then_reject_before_invocation() {
    let (sink, _) = recording_sink();
    let writer = BufferedWrites::builder("factory-race/v1", sink)
        .buffer_capacity(BufferCapacity::default().max_items(1))
        .flush_policy(|_: &BufferStats| false)
        .build()
        .unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let first_writer = writer.clone();
    let first_entered = entered.clone();
    let first_release = release.clone();
    let first = tokio::spawn(async move {
        first_writer
            .add_write_item_with(|| {
                first_entered.notify_one();
                let (lock, condition) = &*first_release;
                let ready = lock.lock().unwrap();
                drop(condition.wait_while(ready, |ready| !*ready).unwrap());
                Ok(1)
            })
            .await
    });
    entered.notified().await;
    let calls = AtomicUsize::new(0);
    let second = writer
        .add_write_item_with(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(2)
        })
        .await;
    let (lock, condition) = &*release;
    *lock.lock().unwrap() = true;
    condition.notify_one();
    let first = first.await.unwrap();
    assert!(first.is_ok());
    assert!(matches!(second, Err(WriteError::Full)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_full_buffer_when_stable_admission_retries_then_preserve_deduplication() {
    let (sink, attempts) = recording_sink();
    let writer = BufferedWrites::builder("full-retry/v1", sink)
        .buffer_capacity(BufferCapacity::default().max_items(1))
        .flush_policy(|_: &BufferStats| false)
        .build()
        .unwrap();
    let options = WriteOptions::new().with_operation_id(OperationId::generate_v7());
    writer
        .add_write_item_with_options(1, options.clone())
        .await
        .unwrap();
    writer
        .add_write_item_with_options(1, options.clone())
        .await
        .unwrap();
    assert!(matches!(
        writer.add_write_item_with_options(2, options).await,
        Err(WriteError::IdentityConflict { .. })
    ));
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(attempts.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn given_failed_factory_when_next_item_arrives_then_release_staging_capacity() {
    let (sink, _) = recording_sink();
    let writer = BufferedWrites::builder("factory-failure/v1", sink)
        .buffer_capacity(BufferCapacity::default().max_items(1))
        .flush_policy(|_: &BufferStats| false)
        .build()
        .unwrap();
    let failed = writer
        .add_write_item_with(|| {
            Err(buffered_writes::EncodeError::invalid_input(
                "test factory failure",
            ))
        })
        .await;
    assert!(matches!(failed, Err(WriteError::Encode(_))));
    writer.add_write_item(1).await.unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
}

#[tokio::test]
async fn given_young_failed_buffer_when_breaker_opens_then_keep_buffered_mode_until_age_threshold()
{
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Err::<(), _>(SinkError::retryable("outage"))
    })
    .unwrap();
    let writer = BufferedWrites::builder("breaker-age/v1", sink)
        .with_clock(TestClock::new())
        .delivery_policy(DeliveryPolicy {
            failure_threshold: 1,
            ..DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    writer.flush_writes().await;
    assert_eq!(
        writer.mode_and_health(),
        (
            buffered_writes::DeliveryMode::Buffered,
            buffered_writes::SinkHealth::Open
        )
    );
}

#[tokio::test]
async fn given_open_breaker_when_forced_flush_precedes_probe_then_skip_normal_sink_attempt() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.fetch_add(1, Ordering::SeqCst);
        async { Err::<(), _>(SinkError::retryable("outage")) }
    })
    .unwrap();
    let clock = TestClock::new();
    let writer = BufferedWrites::builder("breaker-permit/v1", sink)
        .with_clock(clock.clone())
        .delivery_policy(DeliveryPolicy {
            failure_threshold: 1,
            probe_initial_delay: Duration::from_secs(10),
            ..DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    writer.flush_writes().await;
    clock.advance(Duration::from_secs(6));
    writer.flush_writes().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn given_open_breaker_when_real_canaries_succeed_then_recover_after_configured_count() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        let attempt = observed.fetch_add(1, Ordering::SeqCst);
        async move {
            if attempt == 0 {
                Err(SinkError::retryable("outage"))
            } else {
                Ok(())
            }
        }
    })
    .unwrap();
    let clock = TestClock::new();
    let writer = BufferedWrites::builder("breaker-recovery/v1", sink)
        .with_clock(clock.clone())
        .delivery_policy(DeliveryPolicy {
            failure_threshold: 1,
            ..DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    writer.flush_writes().await;
    clock.advance(Duration::from_secs(6));
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(
        writer.mode_and_health().1,
        buffered_writes::SinkHealth::HalfOpen
    );
    for item in [2, 3] {
        writer.add_write_item(item).await.unwrap();
        assert_eq!(writer.flush_writes().await.items_settled, 1);
    }
    assert_eq!(
        writer.mode_and_health(),
        (
            buffered_writes::DeliveryMode::Buffered,
            buffered_writes::SinkHealth::Closed
        )
    );
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn given_active_shutdown_when_earlier_deadline_arrives_then_shorten_inflight_attempt() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let observed = entered.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.notify_one();
        std::future::pending::<Result<(), SinkError>>()
    })
    .unwrap();
    let writer = BufferedWrites::builder("shortened-shutdown/v1", sink)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let first_writer = writer.clone();
    let first = tokio::spawn(async move { first_writer.shutdown(Duration::from_secs(2)).await });
    entered.notified().await;
    let second = writer.shutdown(Duration::from_millis(30));
    let (first, second) = tokio::join!(
        tokio::time::timeout(Duration::from_millis(150), first),
        tokio::time::timeout(Duration::from_millis(150), second),
    );
    assert!(
        first.is_ok(),
        "the active attempt kept its original longer deadline"
    );
    assert!(!first.unwrap().unwrap().is_clean());
    assert!(!second.unwrap().is_clean());
}

#[tokio::test]
async fn given_waiting_backpressure_when_full_then_flush_before_constructing_next_item() {
    let (sink, attempts) = recording_sink();
    let writer = BufferedWrites::builder("waiting-capacity/v1", sink)
        .buffer_capacity(
            BufferCapacity::default()
                .max_items(1)
                .backpressure(buffered_writes::BackpressurePolicy::WaitUntilDeadline),
        )
        .flush_policy(|_: &BufferStats| false)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let pending = writer.add_write_item_with(|| {
        assert_eq!(attempts.lock().unwrap().len(), 1);
        Ok(2)
    });
    let response = async {
        tokio::task::yield_now().await;
        writer.after_response().await
    };
    let (admission, response) = tokio::join!(pending, response);
    admission.unwrap();
    assert_eq!(response.items_settled, 1);
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    let values = attempts
        .lock()
        .unwrap()
        .iter()
        .map(|(_, items)| items.clone())
        .collect::<Vec<_>>();
    assert_eq!(values, vec![vec![1], vec![2]]);
}

#[tokio::test]
async fn given_waiting_backpressure_without_execution_window_when_full_then_bound_wait_and_skip_factory()
 {
    let sink_calls = Arc::new(AtomicUsize::new(0));
    let observed = sink_calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<Result<(), SinkError>>()
    })
    .unwrap();
    let writer = BufferedWrites::builder("waiting-deadline/v1", sink)
        .buffer_capacity(
            BufferCapacity::default()
                .max_items(1)
                .backpressure(buffered_writes::BackpressurePolicy::WaitUntilDeadline),
        )
        .flush_policy(|_: &BufferStats| false)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let calls = AtomicUsize::new(0);
    let result = tokio::time::timeout(
        Duration::from_millis(150),
        writer.add_write_item_with_and_options(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(2)
            },
            WriteOptions::new().with_deadline(Duration::from_millis(30)),
        ),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    assert!(result.unwrap_err().is_definitely_rejected());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(sink_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_successful_capacity_wait_when_observed_then_do_not_report_rejected_admission() {
    let (sink, _) = recording_sink();
    let observer = buffered_writes::RecordingWriteObserver::default();
    let writer = BufferedWrites::builder("waiting-observations/v1", sink)
        .buffer_capacity(
            BufferCapacity::default()
                .max_items(1)
                .backpressure(buffered_writes::BackpressurePolicy::WaitUntilDeadline),
        )
        .flush_policy(|_: &BufferStats| false)
        .with_observer(observer.clone())
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let response = async {
        tokio::task::yield_now().await;
        writer.after_response().await
    };
    let (admission, _) = tokio::join!(writer.add_write_item(2), response);
    admission.unwrap();
    assert!(
        !observer
            .events()
            .iter()
            .any(|event| matches!(event, buffered_writes::WriteEvent::AdmissionRejected { .. }))
    );
}

#[test]
fn given_zero_capacity_retry_delay_when_configured_then_reject_busy_retry_policy() {
    let (sink, _) = recording_sink();
    assert!(
        BufferedWrites::builder("zero-retry/v1", sink)
            .delivery_policy(DeliveryPolicy {
                retry_base_delay: Duration::ZERO,
                ..DeliveryPolicy::default()
            })
            .build()
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_constructing_admission_when_shutdown_starts_then_wait_and_drain_owned_item() {
    let (sink, attempts) = recording_sink();
    let writer = BufferedWrites::builder("factory-drain/v1", sink)
        .build()
        .unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let admitted = writer.clone();
    let observed = entered.clone();
    let unblock = release.clone();
    let admission = tokio::spawn(async move {
        admitted
            .add_write_item_with(|| {
                observed.notify_one();
                let (lock, condition) = &*unblock;
                drop(
                    condition
                        .wait_while(lock.lock().unwrap(), |ready| !*ready)
                        .unwrap(),
                );
                Ok(1)
            })
            .await
    });
    entered.notified().await;
    let release_thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        let (lock, condition) = &*release;
        *lock.lock().unwrap() = true;
        condition.notify_one();
    });
    let report = writer.shutdown(Duration::from_secs(2)).await;
    release_thread.join().unwrap();
    assert!(admission.await.unwrap().is_ok());
    assert_eq!(report.items_settled, 1);
    assert!(report.is_clean());
    assert_eq!(attempts.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn given_delivery_is_pending_when_submission_capacity_is_reached_then_reject_excess_callers()
{
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let (started, resume, observed) = (entered.clone(), release.clone(), calls.clone());
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        let (started, resume) = (started.clone(), resume.clone());
        let first = observed.fetch_add(1, Ordering::SeqCst) == 0;
        async move {
            if first {
                started.notify_one();
                resume.notified().await;
            }
            Ok::<(), SinkError>(())
        }
    })
    .unwrap();
    let writer = BufferedWrites::builder("submission-slots/v1", sink)
        .flush_policy(FlushThresholds::default().max_items(1))
        .buffer_capacity(
            BufferCapacity::default()
                .max_items(1)
                .backpressure(buffered_writes::BackpressurePolicy::WaitUntilDeadline),
        )
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let pending = writer.clone();
    let flushing = tokio::spawn(async move { pending.flush_writes().await });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    let waiting = writer.clone();
    let first = tokio::spawn(async move { waiting.add_write_item(2).await });
    tokio::task::yield_now().await;
    let extra = tokio::time::timeout(Duration::from_millis(20), writer.add_write_item(3)).await;
    assert!(matches!(extra, Ok(Err(WriteError::Full))));
    release.notify_one();
    first.await.unwrap().unwrap();
    flushing.await.unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
