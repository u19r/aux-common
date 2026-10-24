use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use buffered_writes::{
    BatchId, BufferInspectRequest, BufferedWrites, Deadline, DeliveryPolicy, MemoryBuffer,
    Namespace, OperationId, PartialSink, PersistedRecord, PreparedOperation, PreparedPayload,
    SealedBatch, SealedBatchInput, SinkError, SinkLimits, TenantScope, TestClock, WriteAttempt,
    WriteBuffer,
};
use bytes::Bytes;

fn batch(length: usize, custom: bool) -> SealedBatch {
    let record_id = OperationId::try_from("r".repeat(length)).unwrap();
    let operation_id = if custom {
        OperationId::try_from("o".repeat(length)).unwrap()
    } else {
        record_id.clone()
    };
    let prepared = if custom {
        PreparedPayload::CustomOperations(
            vec![PreparedOperation {
                operation_id: operation_id.clone(),
                payload: Bytes::from_static(b"1"),
            }]
            .into(),
        )
    } else {
        PreparedPayload::SharedRecords
    };
    SealedBatch::try_new(SealedBatchInput {
        batch_id: BatchId::generate_v7(),
        namespace: Namespace::try_from("n".repeat(length)).unwrap(),
        scope: TenantScope::try_from("s".repeat(length)).unwrap(),
        codec_version: "c".repeat(length),
        strategy_version: "v".repeat(length),
        first_item_time_ms: 1,
        records: vec![PersistedRecord {
            operation_id: record_id,
            admitted_at_utc_ms: 1,
            payload: Bytes::from_static(b"7"),
        }]
        .into(),
        prepared,
        operation_ids: vec![operation_id].into(),
    })
    .unwrap()
}

#[test]
fn given_larger_sealed_metadata_when_accounted_then_charge_headers_and_all_identity_copies() {
    for custom in [false, true] {
        let small = batch(1, custom).accounted_bytes();
        let large = batch(128, custom).accounted_bytes();
        let copies = if custom { 7 } else { 6 };
        assert!(
            large >= small + 127 * copies,
            "custom={custom}: small={small}, large={large}"
        );
    }
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

fn partial_sink(stage: Arc<AtomicU8>) -> PartialSink<u32> {
    PartialSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let phase = stage.load(Ordering::SeqCst);
        async move {
            match phase {
                0 => Err(SinkError::unknown_outcome("lost acknowledgement")),
                1 => attempt.complete_except([attempt
                    .pending_operation_ids()
                    .last()
                    .unwrap()
                    .clone()]),
                _ => Err(SinkError::permanent("quarantine")),
            }
        }
    })
    .unwrap()
}

struct RetainedPartialBatch {
    writer: BufferedWrites<u32>,
    buffer: MemoryBuffer,
    clock: TestClock,
    stage: Arc<AtomicU8>,
}
impl RetainedPartialBatch {
    async fn new() -> Self {
        let stage = Arc::new(AtomicU8::new(0));
        let clock = TestClock::new();
        clock.set_auto_advance_on_sleep(false);
        let buffer =
            MemoryBuffer::new(buffered_writes::Namespace::try_from("sealed-bytes/v1").unwrap());
        let writer = BufferedWrites::builder("sealed-bytes/v1", partial_sink(stage.clone()))
            .with_buffer_provider(buffer.clone())
            .with_clock(clock.clone())
            .delivery_policy(DeliveryPolicy {
                max_attempts_per_turn: 1,
                ..Default::default()
            })
            .build()
            .unwrap();
        writer.add_write_item(1).await.unwrap();
        writer.add_write_item(2).await.unwrap();
        assert_eq!(writer.flush_writes().await.items_settled, 0);
        Self {
            writer,
            buffer,
            clock,
            stage,
        }
    }
}

#[tokio::test]
async fn given_sealed_batch_when_partial_progress_then_use_reserved_completion_bytes_in_quarantine()
{
    let fixture = RetainedPartialBatch::new().await;
    let before = inspect(&fixture.buffer).await.stats.bytes();
    fixture.clock.advance(Duration::from_secs(1));
    fixture.stage.store(1, Ordering::SeqCst);
    let report = fixture.writer.flush_writes().await;
    assert_eq!(report.partial_operations_completed, 1);
    assert!(report.buffer_error.is_none(), "{report:?}");
    let after = inspect(&fixture.buffer).await.stats.bytes();
    assert_eq!(
        after, before,
        "completion metadata must be reserved at sealing"
    );
    fixture.clock.advance(Duration::from_secs(1));
    fixture.stage.store(2, Ordering::SeqCst);
    assert_eq!(fixture.writer.flush_writes().await.quarantined_items, 2);
    assert_eq!(inspect(&fixture.buffer).await.stats.bytes(), after);
}

impl RetainedPartialBatch {
    async fn claim(&self) -> buffered_writes::LeasedSealedBatch {
        use buffered_writes::{BufferClaimRequest, ClaimedWork, Clock};
        self.clock.advance(Duration::from_secs(1));
        let work = self
            .buffer
            .claim(BufferClaimRequest {
                max_watermark: None,
                allow_open_claim: false,
                force_all_ages: true,
                max_items: 25,
                max_bytes: 65536,
                lease_duration: Duration::from_secs(5),
                now_utc_ms: self.clock.now_utc().timestamp_millis(),
                now_instant: self.clock.now_instant(),
                deadline: Deadline::after(Duration::from_secs(1)),
            })
            .await
            .unwrap();
        let ClaimedWork::ExistingSealed(leased) = work else {
            panic!("expected sealed batch");
        };
        leased
    }

    async fn assert_rejected_settlement(
        &self,
        leased: &buffered_writes::LeasedSealedBatch,
        disposition: buffered_writes::SettleDisposition,
    ) {
        use buffered_writes::{BufferError, BufferSettleRequest, Clock};
        let before = inspect(&self.buffer).await.stats.bytes();
        let result = self
            .buffer
            .settle(BufferSettleRequest {
                batch_id: leased.batch.batch_id(),
                fencing_token: leased.fencing_token,
                disposition,
                now_utc_ms: self.clock.now_utc().timestamp_millis(),
                deadline: Deadline::after(Duration::from_secs(1)),
            })
            .await;
        assert!(matches!(result, Err(BufferError::InvalidRequest { .. })));
        let snapshot = inspect(&self.buffer).await;
        assert_eq!(snapshot.quarantined_items, 0);
        assert_eq!(snapshot.unsettled_items, 2);
        assert_eq!(snapshot.stats.bytes(), before);
    }
}

#[tokio::test]
async fn given_foreign_completion_identity_when_settled_then_reject_without_changing_retained_state()
 {
    use buffered_writes::{QuarantineReason, SettleDisposition};
    let fixture = RetainedPartialBatch::new().await;
    let leased = fixture.claim().await;
    for quarantine in [false, true] {
        let completed_ids = vec![OperationId::generate_v7()];
        let disposition = if quarantine {
            SettleDisposition::Quarantine {
                reason: QuarantineReason::PermanentSinkFailure,
                completed_ids,
            }
        } else {
            SettleDisposition::PartialProgress {
                completed_ids,
                retry_delay: Duration::ZERO,
            }
        };
        fixture
            .assert_rejected_settlement(&leased, disposition)
            .await;
    }
}
