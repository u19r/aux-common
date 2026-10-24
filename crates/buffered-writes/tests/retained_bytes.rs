use std::time::{Duration, Instant};

use buffered_writes::{
    AtomicSink, BufferCapacity, BufferInspectRequest, BufferedWrites, Deadline, DeliveryPolicy,
    MemoryBuffer, OperationId, PreparedWrites, SerdeJsonCodec, SinkError, SinkLimits, TenantScope,
    WriteAttempt, WriteBuffer, WriteError, WriteOptions,
};

fn sink() -> AtomicSink<u32> {
    AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap()
}
async fn inspect(buffer: &MemoryBuffer) -> buffered_writes::BufferSnapshot {
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
#[tokio::test]
async fn given_completed_write_when_inspected_then_charge_retained_receipt_metadata() {
    let buffer = MemoryBuffer::new(buffered_writes::Namespace::try_from("bytes/v1").unwrap());
    let writer = BufferedWrites::builder("bytes/v1", sink())
        .with_buffer_provider(buffer.clone())
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    let snapshot = inspect(&buffer).await;
    assert_eq!(snapshot.unsettled_items, 0);
    assert!(
        snapshot.stats.bytes() > 0,
        "retained receipts have an uncharged allocation"
    );
}
#[tokio::test]
async fn given_completed_receipt_pressure_when_admitting_then_reclaim_cache_within_capacity() {
    let buffer = MemoryBuffer::new(buffered_writes::Namespace::try_from("bytes/v1").unwrap());
    let writer = BufferedWrites::builder("bytes/v1", sink())
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(BufferCapacity::default().max_bytes(1024))
        .build()
        .unwrap();
    for item in 0..100 {
        writer.add_write_item(item).await.unwrap();
        assert!(inspect(&buffer).await.stats.bytes() <= 1024);
        assert_eq!(writer.flush_writes().await.items_settled, 1);
        assert!(inspect(&buffer).await.stats.bytes() <= 1024);
    }
}
#[tokio::test]
async fn given_large_record_metadata_when_admitted_then_reject_before_retaining_it() {
    let buffer = MemoryBuffer::new(buffered_writes::Namespace::try_from("bytes/v1").unwrap());
    let writer = BufferedWrites::builder("bytes/v1", sink())
        .with_buffer_provider(buffer.clone())
        .codec(SerdeJsonCodec::with_version("v".repeat(128)).unwrap())
        .buffer_capacity(BufferCapacity::default().max_bytes(700))
        .build()
        .unwrap();
    let options = WriteOptions::new()
        .with_scope(TenantScope::try_from("s".repeat(256)).unwrap())
        .with_operation_id(OperationId::try_from("i".repeat(256)).unwrap());
    assert!(matches!(
        writer.add_write_item_with_options(1, options).await,
        Err(WriteError::OversizedItem { .. })
    ));
    assert_eq!(inspect(&buffer).await.unsettled_items, 0);
}

#[tokio::test]
async fn given_active_receipt_when_byte_pressure_rejects_another_item_then_preserve_retry_identity()
{
    let buffer = MemoryBuffer::new(buffered_writes::Namespace::try_from("bytes/v1").unwrap());
    let writer = BufferedWrites::builder("bytes/v1", sink())
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(BufferCapacity::default().max_bytes(1024))
        .build()
        .unwrap();
    let id = OperationId::generate_v7();
    let options = WriteOptions::new().with_operation_id(id.clone());
    writer
        .add_write_item_with_options(7, options.clone())
        .await
        .unwrap();
    assert!(matches!(
        writer.add_write_item(8).await,
        Err(WriteError::Full)
    ));
    let receipt = writer
        .add_write_item_with_options(7, options)
        .await
        .unwrap();
    assert_eq!(receipt.operation_id(), &id);
    assert_eq!(inspect(&buffer).await.unsettled_items, 1);
    assert_eq!(writer.flush_writes().await.items_settled, 1);
}

#[tokio::test]
async fn given_full_buffer_when_preparation_expands_writes_then_retain_within_capacity_and_progress()
 {
    let buffer =
        MemoryBuffer::new(buffered_writes::Namespace::try_from("expanded-retention/v1").unwrap());
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(1, 1000).unwrap(),
        |_: WriteAttempt<u32>| async {
            Err::<(), _>(SinkError::unknown_outcome("lost acknowledgement"))
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("expanded-retention/v1", sink)
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(BufferCapacity::default().max_bytes(1800))
        .delivery_policy(DeliveryPolicy {
            max_attempts_per_turn: 1,
            ..Default::default()
        })
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .prepare_with("packed/v1", |batch| {
            PreparedWrites::packed(&batch, &"x".repeat(400))
        })
        .build()
        .unwrap();
    let mut accepted = 0;
    for item in 0..25 {
        match writer.add_write_item(item).await {
            Ok(_) => accepted += 1,
            Err(WriteError::Full) => break,
            Err(error) => panic!("unexpected admission error: {error:?}"),
        }
    }
    assert!(accepted > 0);
    assert!(inspect(&buffer).await.stats.bytes() <= 1800);
    let report = writer.flush_writes().await;
    assert_eq!(report.quarantined_items, 0);
    assert_eq!(report.batches_failed, 1);
    let snapshot = inspect(&buffer).await;
    assert_eq!(snapshot.unsettled_items, accepted);
    assert_eq!(snapshot.unresolved_batch_ids.len(), 1);
    assert!(snapshot.stats.bytes() <= 1800, "{snapshot:?}");
}

#[tokio::test]
async fn given_oversized_seal_when_provider_checks_capacity_then_preserve_claim_and_original_payload()
 {
    use buffered_writes::{
        BatchId, BufferClaimRequest, BufferError, BufferSealAction, BufferSealRequest, ClaimedWork,
        Namespace, PreparedOperation, PreparedPayload, SealedBatch, SealedBatchInput,
    };
    let buffer = MemoryBuffer::new(buffered_writes::Namespace::try_from("guard/v1").unwrap());
    let capacity = BufferCapacity::default().max_bytes(1800);
    let writer = BufferedWrites::builder("guard/v1", sink())
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(capacity)
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .build()
        .unwrap();
    writer.add_write_item(7).await.unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let ClaimedWork::OpenCandidate(candidate) = buffer
        .claim(BufferClaimRequest {
            max_watermark: None,
            allow_open_claim: true,
            force_all_ages: true,
            max_items: 25,
            max_bytes: 65536,
            lease_duration: Duration::from_secs(5),
            now_utc_ms: now,
            now_instant: Instant::now(),
            deadline: Deadline::after(Duration::from_secs(1)),
        })
        .await
        .unwrap()
    else {
        panic!("expected open candidate")
    };
    let first = &candidate.records[0];
    let id = OperationId::generate_v7();
    let oversized = SealedBatch::try_new(SealedBatchInput {
        batch_id: BatchId::generate_v7(),
        namespace: Namespace::try_from("guard/v1").unwrap(),
        scope: first.scope.clone(),
        codec_version: first.codec_version.clone(),
        strategy_version: "packed/v1".to_owned(),
        first_item_time_ms: first.admitted_at_utc_ms,
        records: candidate
            .records
            .iter()
            .map(|record| record.to_persisted())
            .collect(),
        prepared: PreparedPayload::CustomOperations(
            vec![PreparedOperation {
                operation_id: id.clone(),
                payload: bytes::Bytes::from(vec![0; 4096]),
            }]
            .into(),
        ),
        operation_ids: vec![id].into(),
    })
    .unwrap();
    let before = inspect(&buffer).await;
    let request = BufferSealRequest {
        fencing_token: candidate.fencing_token,
        action: BufferSealAction::InstallBatch(oversized),
        capacity,
        lease_duration: Duration::from_secs(5),
        now_utc_ms: now,
        deadline: Deadline::after(Duration::from_secs(1)),
    };
    assert!(matches!(
        buffer.seal(request.clone()).await,
        Err(BufferError::Full)
    ));
    let after = inspect(&buffer).await;
    assert_eq!(after.stats.bytes(), before.stats.bytes());
    assert_eq!(after.unsettled_items, 1);
    assert_eq!(after.claimable_open_items, 0);
    assert!(after.unresolved_batch_ids.is_empty());
    buffer
        .seal(BufferSealRequest {
            action: BufferSealAction::ReleaseCandidate,
            ..request
        })
        .await
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
}

#[tokio::test]
async fn given_custom_preparation_exceeds_budget_when_flushed_then_quarantine_within_reserved_bytes()
 {
    let buffer = MemoryBuffer::new(
        buffered_writes::Namespace::try_from("unchecked-preparation/v1").unwrap(),
    );
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(1, 5000).unwrap(),
        |_: WriteAttempt<u32>| -> std::future::Ready<Result<(), SinkError>> {
            panic!("oversized prepared data reached the sink")
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("unchecked-preparation/v1", sink)
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(BufferCapacity::default().max_bytes(1800))
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .prepare_with("unchecked/v1", |batch| {
            PreparedWrites::packed(&batch, &"x".repeat(4000))
        })
        .build()
        .unwrap();
    writer.add_write_item(7).await.unwrap();
    let reserved = inspect(&buffer).await.stats.bytes();
    assert!(reserved <= 1800);
    let report = writer.flush_writes().await;
    assert_eq!(report.quarantined_items, 1);
    assert!(report.buffer_error.is_none());
    let snapshot = inspect(&buffer).await;
    assert_eq!(snapshot.quarantined_items, 1);
    assert_eq!(snapshot.unsettled_items, 1);
    assert!(snapshot.unresolved_batch_ids.is_empty());
    assert!(snapshot.stats.bytes() <= reserved);
}
