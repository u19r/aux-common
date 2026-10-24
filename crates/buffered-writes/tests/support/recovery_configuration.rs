use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use buffered_writes::{
    AtomicSink, BufferCapacity, BufferError, BufferInspectRequest, BufferedWrites,
    ConfigurationError, Deadline, SinkError, SinkLimits, WriteAttempt, WriteBuffer, WriteError,
};

fn recording_sink(values: Arc<Mutex<Vec<u32>>>) -> AtomicSink<u32> {
    AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let values = values.clone();
        async move {
            values.lock().unwrap().extend_from_slice(attempt.items());
            Ok::<(), SinkError>(())
        }
    })
    .unwrap()
}

async fn inspect(buffer: &impl WriteBuffer) -> buffered_writes::BufferSnapshot {
    buffer
        .inspect(BufferInspectRequest {
            operation_id: None,
            now_utc_ms: chrono::Utc::now().timestamp_millis(),
            now_instant: Instant::now(),
            deadline: Deadline::after(Duration::from_secs(1)),
        })
        .await
        .unwrap()
}

pub(crate) async fn verify_lower_capacity<B, F, Fut>(buffer: B, reopen: F, capacity: BufferCapacity)
where
    B: WriteBuffer + Clone,
    F: FnOnce(B) -> Fut,
    Fut: Future<Output = B>,
{
    let namespace = buffer.namespace().as_str().to_owned();
    let values = Arc::new(Mutex::new(Vec::new()));
    {
        let original = BufferedWrites::builder(&namespace, recording_sink(values.clone()))
            .with_buffer_provider(buffer.clone())
            .buffer_capacity(BufferCapacity::default().max_bytes(4000))
            .build()
            .unwrap();
        original.add_write_item(1).await.unwrap();
        original.add_write_item(2).await.unwrap();
    }
    let buffer = reopen(buffer).await;
    let before = inspect(&buffer).await;
    assert!(
        before.stats.bytes() - before.reclaimable_bytes > capacity.byte_limit()
            || before.stats.items() > capacity.item_limit()
    );
    let smaller = BufferedWrites::builder(&namespace, recording_sink(values.clone()))
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(capacity)
        .build()
        .unwrap();
    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = called.clone();
    let result = smaller
        .add_write_item_with(move || {
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(3)
        })
        .await;
    assert!(
        matches!(
            result,
            Err(WriteError::Configuration(
                ConfigurationError::InsufficientRecoveryCapacity {
                    retained_items: 2,
                    ..
                }
            ))
        ),
        "{result:?}"
    );
    assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    let report = smaller.flush_writes().await;
    assert!(
        matches!(
            report.buffer_error,
            Some(BufferError::Configuration(
                ConfigurationError::InsufficientRecoveryCapacity { .. }
            ))
        ),
        "{report:?}"
    );
    assert_eq!(report.items_settled, 0);
    let after = inspect(&buffer).await;
    assert_eq!(after.unsettled_items, 2);
    assert_eq!(after.quarantined_items, 0);
    assert!(values.lock().unwrap().is_empty());
    let draining = BufferedWrites::builder(&namespace, recording_sink(values.clone()))
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(capacity)
        .build()
        .unwrap();
    let drain = draining.shutdown(Duration::from_secs(1)).await;
    assert_eq!(drain.unresolved_items, 2);
    assert!(!drain.state_unknown);
    assert!(!drain.is_clean());
    let restored = BufferedWrites::builder(&namespace, recording_sink(values.clone()))
        .with_buffer_provider(buffer)
        .buffer_capacity(BufferCapacity::default().max_bytes(4000))
        .build()
        .unwrap();
    assert_eq!(restored.flush_writes().await.items_settled, 2);
    assert_eq!(*values.lock().unwrap(), vec![1, 2]);
    smaller.add_write_item(3).await.unwrap();
    assert_eq!(smaller.flush_writes().await.items_settled, 1);
}

pub(crate) async fn verify_changed_preparation<B, F, Fut>(buffer: B, reopen: F)
where
    B: WriteBuffer + Clone,
    F: FnOnce(B) -> Fut,
    Fut: Future<Output = B>,
{
    let namespace = buffer.namespace().as_str().to_owned();
    let values = Arc::new(Mutex::new(Vec::new()));
    {
        let original = BufferedWrites::builder(&namespace, recording_sink(values.clone()))
            .with_buffer_provider(buffer.clone())
            .buffer_capacity(BufferCapacity::default().max_bytes(8000))
            .build()
            .unwrap();
        original.add_write_item(7).await.unwrap();
    }
    let buffer = reopen(buffer).await;
    let effects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = effects.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(1, 3000).unwrap(),
        move |_: WriteAttempt<u32>| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Ok::<(), SinkError>(()) }
        },
    )
    .unwrap();
    let prepared = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = prepared.clone();
    let changed = BufferedWrites::builder(&namespace, sink)
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(BufferCapacity::default().max_bytes(8000))
        .prepare_with("larger-packed/v1", move |batch| {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            buffered_writes::PreparedWrites::packed(&batch, &"x".repeat(1500))
        })
        .build()
        .unwrap();
    let report = changed.flush_writes().await;
    assert_eq!(report.quarantined_items, 0, "{report:?}");
    assert!(
        matches!(
            report.buffer_error,
            Some(BufferError::Configuration(
                ConfigurationError::InsufficientPreparationCredit { .. }
            ))
        ),
        "{report:?}"
    );
    assert_eq!(prepared.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 0);
    let retained = inspect(&buffer).await;
    assert_eq!(retained.unsettled_items, 1);
    assert_eq!(retained.quarantined_items, 0);
    let restored = BufferedWrites::builder(&namespace, recording_sink(values.clone()))
        .with_buffer_provider(buffer)
        .buffer_capacity(BufferCapacity::default().max_bytes(8000))
        .build()
        .unwrap();
    assert_eq!(restored.flush_writes().await.items_settled, 1);
    assert_eq!(*values.lock().unwrap(), vec![7]);
    changed.add_write_item(8).await.unwrap();
    assert_eq!(changed.flush_writes().await.items_settled, 1);
    assert_eq!(effects.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(prepared.load(std::sync::atomic::Ordering::SeqCst), 1);
}
