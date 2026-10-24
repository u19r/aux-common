use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use buffered_writes::{
    AtomicSink, BufferedWrites, Deadline, InMemoryQueue, PreparedWrites, ReplayWorker, SealedBatch,
    SinkError, SinkLimits, WriteAttempt,
};

async fn batch(packed: bool) -> SealedBatch {
    let captured = Arc::new(Mutex::new(None));
    let observed = captured.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        *observed.lock().unwrap() = Some(attempt.sealed_batch().clone());
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let mut builder = BufferedWrites::builder("quotas/v1", sink);
    if packed {
        builder = builder.prepare_with("packed/v1", |batch| PreparedWrites::packed(&batch, &1));
    }
    let writer = builder.build().unwrap();
    writer.add_write_item(1).await.unwrap();
    writer.add_write_item(2).await.unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 2);
    captured.lock().unwrap().take().unwrap()
}

async fn replay(batch: SealedBatch, limits: SinkLimits) -> (buffered_writes::ReplayReport, usize) {
    let queue = InMemoryQueue::default();
    queue.inject_raw_envelope(batch.to_envelope_bytes().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(limits, move |_: WriteAttempt<u32>| {
        observed.fetch_add(1, Ordering::SeqCst);
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let worker = ReplayWorker::builder("quotas/v1", queue, sink)
        .strategy_version(batch.strategy_version())
        .build()
        .unwrap();
    let report = worker
        .replay_once(1, Deadline::after(Duration::from_secs(1)))
        .await
        .unwrap();
    (report, calls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn given_exact_native_payload_limit_when_replayed_then_exclude_retention_metadata() {
    for packed in [false, true] {
        let limit = if packed { 1 } else { 2 };
        let (report, calls) =
            replay(batch(packed).await, SinkLimits::try_new(25, limit).unwrap()).await;
        assert_eq!(report.batches_delivered, 1, "packed={packed}");
        assert_eq!(report.batches_quarantined, 0);
        assert_eq!(calls, 1);
    }
}

#[tokio::test]
async fn given_expanded_effects_exceed_quota_when_replayed_then_quarantine_without_sink_call() {
    let limits = SinkLimits::try_new(25, 1000)
        .unwrap()
        .with_effect_expansion_factor(1000);
    let (report, calls) = replay(batch(false).await, limits).await;
    assert_eq!(report.batches_quarantined, 1);
    assert_eq!(report.batches_delivered, 0);
    assert_eq!(calls, 0);
}

#[tokio::test]
async fn given_exact_expanded_payload_and_receipt_when_replayed_then_deliver_at_boundary() {
    let limits = SinkLimits::try_new(25, 7)
        .unwrap()
        .with_effect_expansion_factor(2)
        .with_receipt_overhead_bytes(3);
    let (report, calls) = replay(batch(false).await, limits).await;
    assert_eq!(report.batches_delivered, 1);
    assert_eq!(calls, 1);
}
