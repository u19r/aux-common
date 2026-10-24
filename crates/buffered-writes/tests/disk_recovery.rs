#![cfg(feature = "disk")]

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use buffered_writes::{
    AtomicSink, BufferedWrites, DiskBuffer, OperationId, SinkError, SinkLimits, TestClock,
    WriteAttempt, WriteOptions,
};

struct JournalDirectory(PathBuf);
impl JournalDirectory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("buffered-writes-{}", uuid::Uuid::now_v7())))
    }
}
impl Drop for JournalDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn reserved_writer(buffer: DiskBuffer) -> BufferedWrites<u32> {
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(1, 1000).unwrap(),
        |_: WriteAttempt<u32>| async { Err::<(), _>(SinkError::unknown_outcome("unknown commit")) },
    )
    .unwrap();
    BufferedWrites::builder("reserved-disk/v1", sink)
        .with_buffer_provider(buffer)
        .buffer_capacity(buffered_writes::BufferCapacity::default().max_bytes(1800))
        .delivery_policy(buffered_writes::DeliveryPolicy {
            max_attempts_per_turn: 1,
            ..Default::default()
        })
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .prepare_with("packed/v1", |batch| {
            buffered_writes::PreparedWrites::packed(&batch, &"x".repeat(400))
        })
        .build()
        .unwrap()
}

#[tokio::test]
async fn given_reserved_open_write_when_disk_reopens_then_keep_budget_and_seal_without_exceeding_it()
 {
    use buffered_writes::{BufferInspectRequest, Deadline, WriteBuffer, WriteError};
    let directory = JournalDirectory::new();
    let id = OperationId::generate_v7();
    let inspect = || BufferInspectRequest {
        operation_id: Some(id.clone()),
        now_utc_ms: chrono::Utc::now().timestamp_millis(),
        now_instant: std::time::Instant::now(),
        deadline: Deadline::after(Duration::from_secs(1)),
    };
    let reserved;
    let receipt;
    {
        let buffer = DiskBuffer::open(
            buffered_writes::Namespace::try_from("reserved-disk/v1").unwrap(),
            &directory.0,
        )
        .unwrap();
        let writer = reserved_writer(buffer.clone());
        writer
            .add_write_item_with_options(1, WriteOptions::new().with_operation_id(id.clone()))
            .await
            .unwrap();
        assert!(matches!(
            writer.add_write_item(2).await,
            Err(WriteError::Full)
        ));
        let snapshot = buffer.inspect(inspect()).await.unwrap();
        reserved = snapshot.stats.bytes();
        receipt = snapshot.admission.unwrap();
        assert_eq!(receipt.status, buffered_writes::AdmissionStatus::Buffered);
        assert!(reserved <= 1800);
        buffer.compact_now().unwrap();
    }
    let buffer = DiskBuffer::open(
        buffered_writes::Namespace::try_from("reserved-disk/v1").unwrap(),
        &directory.0,
    )
    .unwrap();
    assert_eq!(
        buffer.inspect(inspect()).await.unwrap().stats.bytes(),
        reserved
    );
    assert_eq!(
        buffer.inspect(inspect()).await.unwrap().admission,
        Some(receipt)
    );
    let writer = reserved_writer(buffer.clone());
    let report = writer.flush_writes().await;
    assert_eq!(report.batches_failed, 1);
    assert_eq!(report.quarantined_items, 0);
    let snapshot = buffer.inspect(inspect()).await.unwrap();
    assert_eq!(snapshot.admission, Some(receipt));
    assert_eq!(snapshot.unsettled_items, 1);
    assert_eq!(snapshot.unresolved_batch_ids.len(), 1);
    assert!(snapshot.stats.bytes() <= reserved);
}

#[tokio::test]
async fn given_synced_admission_when_writer_reopens_then_recover_and_deliver() {
    let directory = JournalDirectory::new();
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let calls = delivered.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let calls = calls.clone();
        async move {
            calls.lock().unwrap().extend_from_slice(attempt.items());
            Ok::<(), SinkError>(())
        }
    })
    .unwrap();
    {
        let buffer = DiskBuffer::open(
            buffered_writes::Namespace::try_from("recovery/v1").unwrap(),
            &directory.0,
        )
        .unwrap();
        let writer = BufferedWrites::builder("recovery/v1", sink.clone())
            .with_buffer_provider(buffer)
            .build()
            .unwrap();
        writer.add_write_item(42).await.unwrap();
    }
    let buffer = DiskBuffer::open(
        buffered_writes::Namespace::try_from("recovery/v1").unwrap(),
        &directory.0,
    )
    .unwrap();
    let writer = BufferedWrites::builder("recovery/v1", sink)
        .with_buffer_provider(buffer)
        .build()
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(*delivered.lock().unwrap(), vec![42]);
}

#[tokio::test]
async fn given_failed_disk_append_when_same_identity_retries_then_no_false_duplicate_acknowledgement()
 {
    let directory = JournalDirectory::new();
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let buffer = DiskBuffer::open(
        buffered_writes::Namespace::try_from("disk-full/v1").unwrap(),
        &directory.0,
    )
    .unwrap();
    let writer = BufferedWrites::builder("disk-full/v1", sink.clone())
        .with_buffer_provider(buffer.clone())
        .build()
        .unwrap();
    let options =
        WriteOptions::new().with_operation_id(OperationId::try_new("same-write").unwrap());
    let journal = directory.0.join("journal.bin");
    let backup = directory.0.join("journal.backup");
    std::fs::rename(&journal, &backup).unwrap();
    std::fs::create_dir(&journal).unwrap();
    assert!(
        writer
            .add_write_item_with_options(9, options.clone())
            .await
            .is_err()
    );
    assert!(
        writer.add_write_item(10).await.is_err(),
        "failed commit requires reopen"
    );
    drop(writer);
    drop(buffer);
    std::fs::remove_dir(&journal).unwrap();
    std::fs::rename(&backup, &journal).unwrap();
    let buffer = DiskBuffer::open(
        buffered_writes::Namespace::try_from("disk-full/v1").unwrap(),
        &directory.0,
    )
    .unwrap();
    let writer = BufferedWrites::builder("disk-full/v1", sink)
        .with_buffer_provider(buffer)
        .build()
        .unwrap();
    writer
        .add_write_item_with_options(9, options)
        .await
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
}

#[tokio::test]
async fn given_unknown_disk_batch_commit_when_reopened_then_preserve_sealed_identity() {
    let directory = JournalDirectory::new();
    let ids = Arc::new(Mutex::new(Vec::new()));
    let clock = TestClock::new();
    clock.set_auto_advance_on_sleep(false);
    {
        let recorded = ids.clone();
        let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
            let recorded = recorded.clone();
            async move {
                recorded
                    .lock()
                    .unwrap()
                    .push((attempt.batch_id(), *attempt.digest()));
                Err::<(), SinkError>(SinkError::unknown_outcome("lost acknowledgement"))
            }
        })
        .unwrap();
        let buffer = DiskBuffer::open(
            buffered_writes::Namespace::try_from("unknown/v1").unwrap(),
            &directory.0,
        )
        .unwrap();
        let writer = BufferedWrites::builder("unknown/v1", sink)
            .with_clock(clock.clone())
            .with_buffer_provider(buffer)
            .build()
            .unwrap();
        writer.add_write_item(1).await.unwrap();
        assert!(writer.flush_writes().await.has_failures());
    }
    clock.advance(Duration::from_secs(10));
    let recorded = ids.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let recorded = recorded.clone();
        async move {
            recorded
                .lock()
                .unwrap()
                .push((attempt.batch_id(), *attempt.digest()));
            Ok::<(), SinkError>(())
        }
    })
    .unwrap();
    let buffer = DiskBuffer::open(
        buffered_writes::Namespace::try_from("unknown/v1").unwrap(),
        &directory.0,
    )
    .unwrap();
    let writer = BufferedWrites::builder("unknown/v1", sink)
        .with_clock(clock)
        .with_buffer_provider(buffer)
        .build()
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    let ids = ids.lock().unwrap();
    assert!(ids.len() >= 2);
    assert!(ids.iter().all(|id| *id == ids[0]));
}

#[tokio::test]
async fn given_quarantined_item_when_compacted_and_reopened_then_keep_payload_and_capacity() {
    let directory = JournalDirectory::new();
    {
        let calls = Arc::new(Mutex::new(0usize));
        let recorded = calls.clone();
        let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<String>| {
            let calls = recorded.clone();
            async move {
                *calls.lock().unwrap() += 1;
                Ok::<(), SinkError>(())
            }
        })
        .unwrap();
        let buffer = DiskBuffer::open(
            buffered_writes::Namespace::try_from("quarantine/v1").unwrap(),
            &directory.0,
        )
        .unwrap();
        let writer = BufferedWrites::builder("quarantine/v1", sink)
            .with_buffer_provider(buffer.clone())
            .prepare_with("reject/v1", |_| {
                Err(buffered_writes::PrepareError::InvalidOperationId)
            })
            .build()
            .unwrap();
        writer
            .add_write_item("retained-payload".to_owned())
            .await
            .unwrap();
        assert_eq!(writer.flush_writes().await.quarantined_items, 1);
        assert_eq!(*calls.lock().unwrap(), 0);
        buffer.compact_now().unwrap();
        let bytes = std::fs::read(directory.0.join("journal.bin")).unwrap();
        let length = u32::from_le_bytes(bytes[11..15].try_into().unwrap()) as usize;
        let checkpoint: serde_json::Value =
            serde_json::from_slice(&bytes[23..23 + length]).unwrap();
        let records = checkpoint["Snapshot"]["state"]["quarantined_items"]
            .as_object()
            .unwrap();
        let payload: Vec<u8> =
            serde_json::from_value(records.values().next().unwrap()["payload"].clone()).unwrap();
        assert_eq!(payload, serde_json::to_vec("retained-payload").unwrap());
    }
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<String>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let buffer = DiskBuffer::open(
        buffered_writes::Namespace::try_from("quarantine/v1").unwrap(),
        &directory.0,
    )
    .unwrap();
    let writer = BufferedWrites::builder("quarantine/v1", sink)
        .with_buffer_provider(buffer)
        .build()
        .unwrap();
    let report = writer.shutdown(Duration::from_secs(1)).await;
    assert_eq!(report.quarantined_items, 1);
    assert_eq!(report.unresolved_items, 1);
    assert!(!report.is_clean());
}

#[tokio::test]
async fn given_completed_admission_when_compacted_and_reopened_then_preserve_dedup_receipt() {
    let directory = JournalDirectory::new();
    let options =
        WriteOptions::new().with_operation_id(OperationId::try_new("completed-request").unwrap());
    for turn in 0..2 {
        let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
            Ok::<(), SinkError>(())
        })
        .unwrap();
        let buffer = DiskBuffer::open(
            buffered_writes::Namespace::try_from("receipts/v1").unwrap(),
            &directory.0,
        )
        .unwrap();
        let writer = BufferedWrites::builder("receipts/v1", sink)
            .with_buffer_provider(buffer.clone())
            .build()
            .unwrap();
        writer
            .add_write_item_with_options(9, options.clone())
            .await
            .unwrap();
        assert_eq!(
            writer.flush_writes().await.items_settled,
            usize::from(turn == 0)
        );
        buffer.compact_now().unwrap();
    }
}

#[test]
fn given_previous_journal_version_when_opened_then_reject_without_rewriting_data() {
    let directory = JournalDirectory::new();
    std::fs::create_dir_all(&directory.0).unwrap();
    let journal = directory.0.join("journal.bin");
    for version in [3_u16, 4, 5, 6, 7] {
        let previous = [b"AUXBWJ01".as_slice(), &version.to_le_bytes()].concat();
        std::fs::write(&journal, &previous).unwrap();
        assert!(matches!(
            DiskBuffer::open(
                buffered_writes::Namespace::try_from("version-recovery/v1").unwrap(),
                &directory.0
            ),
            Err(buffered_writes::ConfigurationError::InvalidDiskPath {
                reason: "unsupported disk journal version"
            })
        ));
        assert_eq!(std::fs::read(&journal).unwrap(), previous);
    }
}

#[tokio::test]
async fn given_recovered_format_or_namespace_mismatch_when_used_then_reject_before_sink_effects() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for (sealed, change) in [(false, 0), (true, 0), (true, 1), (true, 2)] {
        let directory = JournalDirectory::new();
        let clock = TestClock::new();
        clock.set_auto_advance_on_sleep(false);
        {
            let buffer = DiskBuffer::open(
                buffered_writes::Namespace::try_from("version-recovery/v1").unwrap(),
                &directory.0,
            )
            .unwrap();
            let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
                Err::<(), SinkError>(SinkError::unknown_outcome("lost acknowledgement"))
            })
            .unwrap();
            let writer = BufferedWrites::builder("version-recovery/v1", sink)
                .with_buffer_provider(buffer)
                .with_clock(clock.clone())
                .delivery_policy(buffered_writes::DeliveryPolicy {
                    max_attempts_per_turn: 1,
                    ..Default::default()
                })
                .build()
                .unwrap();
            writer.add_write_item(7).await.unwrap();
            if sealed {
                assert_eq!(writer.flush_writes().await.items_settled, 0);
            }
        }
        clock.advance(Duration::from_secs(1));
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok::<(), SinkError>(()) }
        })
        .unwrap();
        let buffer = DiskBuffer::open(
            buffered_writes::Namespace::try_from("version-recovery/v1").unwrap(),
            &directory.0,
        )
        .unwrap();
        let decodes = Arc::new(AtomicUsize::new(0));
        let version = if change == 0 {
            "serde-json/v2"
        } else {
            "serde-json/v1"
        };
        let namespace = if change == 2 {
            "different/v1"
        } else {
            "version-recovery/v1"
        };
        let mut builder = BufferedWrites::builder(namespace, sink)
            .with_buffer_provider(buffer)
            .with_clock(clock)
            .codec(TrackingCodec {
                version,
                decodes: decodes.clone(),
            });
        if change == 1 {
            builder = builder.prepare_with("changed/v1", |batch| {
                buffered_writes::PreparedWrites::default_items(&batch)
            });
        }
        let built = builder.build();
        if change == 2 {
            assert!(matches!(
                built,
                Err(buffered_writes::ConfigurationError::NamespaceMismatch)
            ));
            assert_eq!(decodes.load(Ordering::SeqCst), 0);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            continue;
        }
        let writer = built.unwrap();
        let report = writer.flush_writes().await;
        assert_eq!(
            decodes.load(Ordering::SeqCst),
            0,
            "recovery invoked an incompatible decoder"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "recovery reinterpreted old data"
        );
        assert_eq!(report.items_settled, 0);
        assert_eq!(report.quarantined_items, 1);
    }
}

struct TrackingCodec {
    version: &'static str,
    decodes: Arc<std::sync::atomic::AtomicUsize>,
}
impl buffered_writes::RecordCodec<u32> for TrackingCodec {
    fn version(&self) -> &str {
        self.version
    }
    fn encode(
        &self,
        item: &u32,
        max_bytes: usize,
    ) -> Result<bytes::Bytes, buffered_writes::EncodeError> {
        buffered_writes::RecordCodec::encode(
            &buffered_writes::SerdeJsonCodec::default(),
            item,
            max_bytes,
        )
    }
    fn decode(&self, bytes: &[u8]) -> Result<u32, buffered_writes::EncodeError> {
        self.decodes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        serde_json::from_slice(bytes)
            .map_err(|_| buffered_writes::EncodeError::DeserializationFailed)
    }
}

impl JournalDirectory {
    async fn persist_quota_batch(&self, clock: TestClock) {
        let buffer = DiskBuffer::open(
            buffered_writes::Namespace::try_from("native-quotas/v1").unwrap(),
            &self.0,
        )
        .unwrap();
        let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
            Err::<(), SinkError>(SinkError::unknown_outcome("lost acknowledgement"))
        })
        .unwrap();
        let writer = BufferedWrites::builder("native-quotas/v1", sink)
            .with_buffer_provider(buffer)
            .with_clock(clock)
            .delivery_policy(buffered_writes::DeliveryPolicy {
                max_attempts_per_turn: 1,
                ..Default::default()
            })
            .build()
            .unwrap();
        writer.add_write_item(1).await.unwrap();
        writer.add_write_item(2).await.unwrap();
        assert_eq!(writer.flush_writes().await.items_settled, 0);
    }

    async fn assert_quota_rejection(&self, limits: SinkLimits, clock: TestClock) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let sink = AtomicSink::try_new(limits, move |_: WriteAttempt<u32>| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Ok::<(), SinkError>(()) }
        })
        .unwrap();
        let decodes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let buffer = DiskBuffer::open(
            buffered_writes::Namespace::try_from("native-quotas/v1").unwrap(),
            &self.0,
        )
        .unwrap();
        let writer = BufferedWrites::builder("native-quotas/v1", sink)
            .with_buffer_provider(buffer)
            .with_clock(clock)
            .codec(TrackingCodec {
                version: "serde-json/v1",
                decodes: decodes.clone(),
            })
            .build()
            .unwrap();
        let report = writer.flush_writes().await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(decodes.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(report.items_settled, 0);
        assert_eq!(report.quarantined_items, 2);
    }
}

#[tokio::test]
async fn given_recovered_batch_exceeds_new_native_limits_when_flushed_then_quarantine_before_decode()
 {
    for limits in [
        SinkLimits::try_new(1, 1024).unwrap(),
        SinkLimits::try_new(25, 1).unwrap(),
        SinkLimits::try_new(25, 1000)
            .unwrap()
            .with_effect_expansion_factor(1000),
    ] {
        let directory = JournalDirectory::new();
        let clock = TestClock::new();
        clock.set_auto_advance_on_sleep(false);
        directory.persist_quota_batch(clock.clone()).await;
        clock.advance(Duration::from_secs(1));
        directory.assert_quota_rejection(limits, clock).await;
    }
}

#[tokio::test]
async fn given_foreign_persisted_completion_when_disk_recovers_then_block_mutation_and_preserve_bytes()
 {
    use buffered_writes::{BufferClaimRequest, BufferError, Deadline, WriteBuffer};
    use sha2::{Digest, Sha256};
    for quarantined in [false, true] {
        let directory = JournalDirectory::new();
        {
            let buffer = DiskBuffer::open(
                buffered_writes::Namespace::try_from("reserved-disk/v1").unwrap(),
                &directory.0,
            )
            .unwrap();
            let writer = reserved_writer(buffer.clone());
            writer.add_write_item(1).await.unwrap();
            assert_eq!(writer.flush_writes().await.items_settled, 0);
            buffer.compact_now().unwrap();
        }
        let path = directory.0.join("journal.bin");
        let before = std::fs::read(&path).unwrap();
        let mut checkpoint: serde_json::Value = serde_json::from_slice(&before[23..]).unwrap();
        let state = &mut checkpoint["Snapshot"]["state"];
        let entries = state["sealed_batches"].as_object_mut().unwrap();
        let key = entries.keys().next().unwrap().clone();
        entries[&key]["completed_operations"] = serde_json::json!([OperationId::generate_v7()]);
        if quarantined {
            state["quarantined_batches"] = state["sealed_batches"].take();
            state["sealed_batches"] = serde_json::json!({});
        }
        let payload = serde_json::to_vec(&checkpoint).unwrap();
        let mut hasher = Sha256::new();
        hasher.update([before[10]]);
        hasher.update((payload.len() as u32).to_le_bytes());
        hasher.update(&payload);
        let digest = hasher.finalize();
        let mut corrupt = before[..11].to_vec();
        corrupt.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        corrupt.extend_from_slice(&digest[..4]);
        let header_digest = Sha256::digest(&corrupt[10..]);
        corrupt.extend_from_slice(&header_digest[..4]);
        corrupt.extend_from_slice(&payload);
        std::fs::write(&path, &corrupt).unwrap();
        let recovered = DiskBuffer::open(
            buffered_writes::Namespace::try_from("reserved-disk/v1").unwrap(),
            &directory.0,
        )
        .unwrap();
        assert!(
            recovered.has_interior_corruption(),
            "foreign completion was trusted"
        );
        let result = recovered
            .claim(BufferClaimRequest {
                max_watermark: None,
                allow_open_claim: true,
                force_all_ages: true,
                max_items: 25,
                max_bytes: 64 * 1024,
                lease_duration: Duration::from_secs(5),
                now_utc_ms: chrono::Utc::now().timestamp_millis(),
                now_instant: std::time::Instant::now(),
                deadline: Deadline::after(Duration::from_secs(1)),
            })
            .await;
        assert!(
            matches!(result, Err(BufferError::StorageUnavailable { .. })),
            "{result:?}"
        );
        assert_eq!(std::fs::read(path).unwrap(), corrupt);
    }
}
