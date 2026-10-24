use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use buffered_writes::{
    AtomicSink, BufferedWrites, Deadline, InMemoryQueue, OperationStatus, PartialSink, QueueError,
    QueueLimits, QueueReceipt, ReceivedEnvelope, ReplayQueue, ReplayWorker, SealedBatch, SinkError,
    SinkLimits, WriteAttempt, WriteOutcome, WriteQueue,
};
use bytes::Bytes;
use futures_util::future::BoxFuture;

async fn envelope() -> Bytes {
    let captured = Arc::new(Mutex::new(None));
    let observed = captured.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        *observed.lock().unwrap() = Some(attempt.sealed_batch().clone());
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let writer = BufferedWrites::builder("replay/v1", sink).build().unwrap();
    writer.add_write_item(1).await.unwrap();
    writer.add_write_item(2).await.unwrap();
    writer.flush_writes().await;
    captured
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .to_envelope_bytes()
        .unwrap()
}

#[derive(Clone)]
struct HungQueue {
    inner: InMemoryQueue,
    stage: u8,
    quarantines: Arc<Mutex<Vec<Bytes>>>,
    receives: Arc<std::sync::atomic::AtomicUsize>,
}

impl WriteQueue for HungQueue {
    fn limits(&self) -> &QueueLimits {
        self.inner.limits()
    }
    fn publish(
        &self,
        batch: SealedBatch,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<QueueReceipt, QueueError>> {
        self.inner.publish(batch, deadline)
    }
}
impl ReplayQueue for HungQueue {
    fn receive(
        &self,
        max: usize,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<Vec<ReceivedEnvelope>, QueueError>> {
        self.receives
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.stage == 1 {
            return Box::pin(std::future::pending());
        }
        self.inner.receive(max, deadline)
    }
    fn renew_visibility(
        &self,
        receipt: &str,
        extension: Duration,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>> {
        if self.stage == 2 {
            return Box::pin(std::future::pending());
        }
        self.inner.renew_visibility(receipt, extension, deadline)
    }
    fn acknowledge(
        &self,
        receipt: &str,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>> {
        if self.stage == 3 {
            return Box::pin(std::future::pending());
        }
        self.inner.acknowledge(receipt, deadline)
    }
    fn quarantine(
        &self,
        receipt: &str,
        bytes: Bytes,
        reason: &'static str,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>> {
        self.quarantines.lock().unwrap().push(bytes.clone());
        if self.stage == 4 {
            return Box::pin(std::future::pending());
        }
        self.inner.quarantine(receipt, bytes, reason, deadline)
    }
}

#[tokio::test]
async fn given_hung_replay_boundary_when_deadline_expires_then_return_without_acknowledgement() {
    let bytes = envelope().await;
    for stage in 1..=5 {
        let queue = InMemoryQueue::default();
        queue.inject_raw_envelope(if stage == 4 {
            Bytes::from_static(b"invalid")
        } else {
            bytes.clone()
        });
        let sink = AtomicSink::try_new(
            SinkLimits::default(),
            move |_: WriteAttempt<u32>| async move {
                if stage == 5 {
                    std::future::pending::<()>().await;
                }
                Ok::<(), SinkError>(())
            },
        )
        .unwrap();
        let worker = ReplayWorker::builder(
            "replay/v1",
            HungQueue {
                inner: queue.clone(),
                stage,
                quarantines: Arc::default(),
                receives: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            },
            sink,
        )
        .build()
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(150),
            worker.replay_once(1, Instant::now() + Duration::from_millis(30)),
        )
        .await;
        assert!(result.is_ok(), "boundary {stage} ignored its deadline");
        assert_eq!(queue.acknowledged_count(), 0);
        assert_eq!(queue.queued_len(), 1);
    }
}

#[tokio::test]
async fn given_incomplete_partial_result_when_replayed_then_keep_message_for_retry() {
    let queue = InMemoryQueue::default();
    queue.inject_raw_envelope(envelope().await);
    let sink = PartialSink::try_new(
        SinkLimits::default(),
        |attempt: WriteAttempt<u32>| async move {
            Ok::<_, SinkError>(WriteOutcome::Partial(
                [(
                    attempt.pending_operation_ids()[0].clone(),
                    OperationStatus::Completed,
                )]
                .into(),
            ))
        },
    )
    .unwrap();
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), sink)
        .build()
        .unwrap();
    let report = worker
        .replay_once(1, Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(report.batches_delivered, 0);
    assert_eq!(report.batches_retained, 1);
    assert_eq!(queue.acknowledged_count(), 0);
    assert_eq!(queue.queued_len(), 1);
}

#[tokio::test]
async fn given_partial_outcome_when_expected_identities_match_then_acknowledge_only_complete_set() {
    for unexpected in [false, true] {
        let queue = InMemoryQueue::default();
        queue.inject_raw_envelope(envelope().await);
        let sink = PartialSink::try_new(
            SinkLimits::default(),
            move |attempt: WriteAttempt<u32>| async move {
                let mut outcomes: std::collections::BTreeMap<_, _> = attempt
                    .pending_operation_ids()
                    .iter()
                    .cloned()
                    .map(|id| (id, OperationStatus::Completed))
                    .collect();
                if unexpected {
                    outcomes.insert(
                        buffered_writes::OperationId::generate_v7(),
                        OperationStatus::Completed,
                    );
                }
                Ok::<_, SinkError>(WriteOutcome::Partial(outcomes))
            },
        )
        .unwrap();
        let worker = ReplayWorker::builder("replay/v1", queue.clone(), sink)
            .build()
            .unwrap();
        let report = worker
            .replay_once(1, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(queue.acknowledged_count(), usize::from(!unexpected));
        assert_eq!(report.batches_retained, usize::from(unexpected));
        assert_eq!(queue.visibility_renewals(), 1);
    }
}

#[tokio::test]
async fn given_incompatible_replay_when_validated_then_quarantine_before_sink_effects() {
    let bytes = envelope().await;
    let batch = SealedBatch::from_envelope_bytes(&bytes).unwrap();
    for incompatible_strategy in [false, true] {
        let queue = InMemoryQueue::default();
        queue.inject_raw_envelope(bytes.clone());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Ok::<(), SinkError>(()) }
        })
        .unwrap();
        let clock =
            buffered_writes::TestClock::with_utc_millis(batch.first_item_time_ms() + 31_000);
        let mut builder = ReplayWorker::builder("replay/v1", queue.clone(), sink)
            .with_clock(clock)
            .delivery_policy(buffered_writes::DeliveryPolicy {
                max_replay_age: Some(Duration::from_secs(30)),
                ..buffered_writes::DeliveryPolicy::default()
            });
        if incompatible_strategy {
            builder = builder.strategy_version("unknown/v1");
        }
        let worker = builder.build().unwrap();
        let report = worker
            .replay_once(1, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(report.batches_quarantined, 1);
        assert_eq!(queue.quarantined_len(), 1);
        assert_eq!(queue.acknowledged_count(), 0);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn given_unknown_commit_when_original_envelope_replays_then_keep_identity_and_apply_once() {
    let queue = InMemoryQueue::default();
    queue.inject_raw_envelope(envelope().await);
    let committed = Arc::new(Mutex::new(None));
    let observed = committed.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let observed = observed.clone();
        async move {
            let mut state = observed.lock().unwrap();
            let identity = (
                attempt.batch_id(),
                *attempt.digest(),
                attempt.operation_ids().to_vec(),
            );
            if let Some(original) = state.as_ref() {
                assert_eq!(original, &identity);
                return Ok(buffered_writes::AtomicWriteStatus::AlreadyApplied);
            }
            *state = Some(identity);
            Err(SinkError::unknown_outcome(
                "commit succeeded but acknowledgement was lost",
            ))
        }
    })
    .unwrap();
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), sink)
        .build()
        .unwrap();
    let first = worker
        .replay_once(1, Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(first.batches_retained, 1);
    assert_eq!(queue.acknowledged_count(), 0);
    queue.expire_all_in_flight_visibilities();
    let second = worker
        .replay_once(1, Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(second.batches_delivered, 1);
    assert_eq!(queue.acknowledged_count(), 1);
    assert_eq!(queue.queued_len(), 0);
}

#[tokio::test]
async fn given_expired_replay_deadline_when_called_then_never_invoke_queue_transport() {
    let receives = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let queue = HungQueue {
        inner: InMemoryQueue::default(),
        stage: 0,
        quarantines: Arc::default(),
        receives: receives.clone(),
    };
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let worker = ReplayWorker::builder("replay/v1", queue, sink)
        .build()
        .unwrap();
    let result = worker
        .replay_once(1, Instant::now() - Duration::from_millis(1))
        .await;
    assert!(matches!(result, Err(QueueError::DeadlineExceeded)));
    assert_eq!(receives.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_extreme_persisted_age_when_replayed_then_expire_without_sink_effects() {
    let mut input: buffered_writes::SealedBatchInput =
        serde_json::from_slice(&envelope().await).unwrap();
    input.first_item_time_ms = i64::MIN;
    for record in Arc::make_mut(&mut input.records) {
        record.admitted_at_utc_ms = i64::MIN;
    }
    let batch = SealedBatch::try_new(input).unwrap();
    let queue = InMemoryQueue::default();
    queue.inject_raw_envelope(batch.to_envelope_bytes().unwrap());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), sink)
        .delivery_policy(buffered_writes::DeliveryPolicy {
            max_replay_age: Some(Duration::from_secs(30)),
            ..buffered_writes::DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    let report = worker
        .replay_once(1, Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(report.batches_quarantined, 1);
    assert_eq!(queue.acknowledged_count(), 0);
}

#[tokio::test]
async fn given_future_persisted_time_when_finite_replay_window_is_required_then_quarantine_before_sink_effects()
 {
    let bytes = envelope().await;
    let batch = SealedBatch::from_envelope_bytes(&bytes).unwrap();
    let queue = InMemoryQueue::default();
    queue.inject_raw_envelope(bytes);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::ready(Ok::<(), SinkError>(()))
    })
    .unwrap();
    let observer = buffered_writes::RecordingWriteObserver::default();
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), sink)
        .with_observer(observer.clone())
        .with_clock(buffered_writes::TestClock::with_utc_millis(
            batch.first_item_time_ms() - 1_000,
        ))
        .delivery_policy(buffered_writes::DeliveryPolicy {
            max_replay_age: Some(Duration::from_secs(30)),
            ..buffered_writes::DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    let report = worker.replay_once(1, Duration::from_secs(1)).await.unwrap();
    assert_eq!(
        report.batches_quarantined, 1,
        "unknown age cannot extend a finite replay contract"
    );
    assert!(observer.events().iter().any(|event| matches!(
        event,
        buffered_writes::WriteEvent::Quarantined {
            reason: buffered_writes::QuarantineReason::UncertainReplayAge
        }
    )));
    assert_eq!(queue.acknowledged_count(), 0);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_permanent_partial_replay_when_quarantined_then_preserve_original_envelope_and_known_progress()
 {
    use base64::Engine as _;
    let bytes = envelope().await;
    let batch = SealedBatch::from_envelope_bytes(&bytes).unwrap();
    let completed = batch.operation_ids()[0].clone();
    let sink = PartialSink::try_new(
        SinkLimits::default(),
        |attempt: WriteAttempt<u32>| async move {
            let ids = attempt.pending_operation_ids();
            Ok::<_, SinkError>(WriteOutcome::Partial(BTreeMap::from([
                (ids[0].clone(), OperationStatus::Completed),
                (
                    ids[1].clone(),
                    OperationStatus::Permanent { reason: "rejected" },
                ),
            ])))
        },
    )
    .unwrap();
    let queue = HungQueue {
        inner: InMemoryQueue::default(),
        stage: 0,
        receives: Arc::default(),
        quarantines: Arc::default(),
    };
    queue.inner.inject_raw_envelope(bytes.clone());
    let observer = buffered_writes::RecordingWriteObserver::default();
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), sink)
        .with_observer(observer.clone())
        .build()
        .unwrap();
    let report = worker
        .replay_once(1, Deadline::after(Duration::from_secs(1)))
        .await
        .unwrap();
    assert_eq!(report.partial_operations_completed, 1);
    assert_eq!(report.batches_quarantined, 1);
    assert_eq!(report.batches_delivered, 0);
    assert_eq!(queue.inner.queued_len(), 0);
    let records = queue.quarantines.lock().unwrap();
    let record: serde_json::Value = serde_json::from_slice(&records[0]).unwrap();
    assert_eq!(record["version"], 1);
    assert_eq!(record["reason"], "PermanentSinkFailure");
    let original = base64::engine::general_purpose::STANDARD
        .decode(record["envelope_base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(original, bytes);
    assert_eq!(
        record["completed_operation_ids"],
        serde_json::to_value(vec![completed]).unwrap()
    );
    assert!(
        observer
            .events()
            .contains(&buffered_writes::WriteEvent::PartialProgress {
                completed: 1,
                remaining: 1
            })
    );
}
