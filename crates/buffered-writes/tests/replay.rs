use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use buffered_writes::{
    AtomicSink, BufferedWrites, Deadline, EnvelopeKey, InMemoryQueue, OperationStatus, PartialSink,
    QueueEnvelope, QueueError, QueueLimits, QueueReceipt, ReceivedEnvelope, ReplayQueue,
    ReplayWorker, SealedBatch, SinkError, SinkLimits, WriteAttempt, WriteOutcome, WriteQueue,
};
use bytes::Bytes;
use futures_util::future::BoxFuture;

fn envelope_key() -> EnvelopeKey {
    EnvelopeKey::try_new([7; 32]).unwrap()
}

fn seal(batch: &SealedBatch) -> Bytes {
    envelope_key().seal(batch.clone()).unwrap().bytes().clone()
}

fn batch_input(envelope: &[u8]) -> buffered_writes::SealedBatchInput {
    let value: serde_json::Value = serde_json::from_slice(envelope).unwrap();
    serde_json::from_value(value["batch"].clone()).unwrap()
}

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
    seal(captured.lock().unwrap().as_ref().unwrap())
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
        envelope: QueueEnvelope,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<QueueReceipt, QueueError>> {
        self.inner.publish(envelope, deadline)
    }
}
impl ReplayQueue for HungQueue {
    fn has_quarantine_target(&self) -> bool {
        self.inner.has_quarantine_target()
    }
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
        if self.stage == 6 {
            return Box::pin(async {
                Err(QueueError::Permanent {
                    reason: "quarantine destination rejected the record",
                })
            });
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
            envelope_key(),
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
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), envelope_key(), sink)
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
        let worker = ReplayWorker::builder("replay/v1", queue.clone(), envelope_key(), sink)
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
    let batch = envelope_key().open(&bytes).unwrap();
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
        let mut builder = ReplayWorker::builder("replay/v1", queue.clone(), envelope_key(), sink)
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
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), envelope_key(), sink)
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
    let worker = ReplayWorker::builder("replay/v1", queue, envelope_key(), sink)
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
    let mut input = batch_input(&envelope().await);
    input.first_item_time_ms = i64::MIN;
    for record in Arc::make_mut(&mut input.records) {
        record.admitted_at_utc_ms = i64::MIN;
    }
    let batch = SealedBatch::try_new(input).unwrap();
    let queue = InMemoryQueue::default();
    queue.inject_raw_envelope(seal(&batch));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), envelope_key(), sink)
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
    let batch = envelope_key().open(&bytes).unwrap();
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
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), envelope_key(), sink)
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
    let batch = envelope_key().open(&bytes).unwrap();
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
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), envelope_key(), sink)
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
    assert_eq!(record["version"], 2);
    assert_eq!(record["reason"], "PermanentSinkFailure");
    assert_eq!(record["truncated"], false);
    assert_eq!(record["envelope_bytes"], bytes.len());
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

#[tokio::test]
async fn given_forged_envelope_with_recomputed_digest_for_another_scope_when_replayed_then_quarantine_without_sink_effects()
 {
    let bytes = envelope().await;
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut input = batch_input(&bytes);
    input.batch_id = buffered_writes::BatchId::generate_v7();
    input.scope = buffered_writes::TenantScope::try_new("victim-tenant").unwrap();
    let forged = SealedBatch::try_new(input).unwrap();
    let queue = InMemoryQueue::default();
    // A recomputed digest with the original tag, then a tag from another key.
    queue.inject_raw_envelope(
        serde_json::to_vec(&serde_json::json!({"mac": original["mac"], "batch": forged})).unwrap(),
    );
    queue.inject_raw_envelope(
        EnvelopeKey::try_new([9; 32])
            .unwrap()
            .seal(forged)
            .unwrap()
            .bytes()
            .clone(),
    );
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), envelope_key(), sink)
        .build()
        .unwrap();

    let report = worker
        .replay_once(2, Deadline::after(Duration::from_secs(1)))
        .await
        .unwrap();

    assert_eq!(report.batches_quarantined, 2);
    assert_eq!(report.batches_delivered, 0);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_poison_envelope_whose_quarantine_fails_when_replayed_then_later_envelopes_are_still_delivered()
 {
    let queue = HungQueue {
        inner: InMemoryQueue::default(),
        stage: 6,
        quarantines: Arc::default(),
        receives: Arc::default(),
    };
    queue.inner.inject_raw_envelope(Bytes::from_static(b"{}"));
    queue.inner.inject_raw_envelope(envelope().await);
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let worker = ReplayWorker::builder("replay/v1", queue.clone(), envelope_key(), sink)
        .build()
        .unwrap();

    let report = worker
        .replay_once(2, Deadline::after(Duration::from_secs(1)))
        .await
        .unwrap();

    assert_eq!(report.envelopes_failed, 1);
    assert_eq!(report.batches_delivered, 1);
    assert_eq!(queue.inner.acknowledged_count(), 1);
}
