use std::sync::{Arc, Mutex};

use buffered_writes::{
    AtomicSink, BufferCapacity, BufferedWrites, PreparedWrites, RecordCodec, SerdeJsonCodec,
    SinkError, SinkLimits, WriteAttempt,
};

struct InputBudgets(Arc<Mutex<Vec<usize>>>);
impl<T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static> RecordCodec<T>
    for InputBudgets
{
    fn version(&self) -> &str {
        "budget-json/v1"
    }
    fn encode(
        &self,
        item: &T,
        max_bytes: usize,
    ) -> Result<bytes::Bytes, buffered_writes::EncodeError> {
        self.0.lock().unwrap().push(max_bytes);
        SerdeJsonCodec::<T>::default().encode(item, max_bytes)
    }
    fn decode(&self, bytes: &[u8]) -> Result<T, buffered_writes::EncodeError> {
        SerdeJsonCodec::<T>::default().decode(bytes)
    }
}

#[tokio::test]
async fn given_factory_exceeds_deadline_when_it_returns_then_skip_encoding_and_reject_before_dispatch()
 {
    let budgets = Arc::new(Mutex::new(Vec::new()));
    let clock = buffered_writes::TestClock::new();
    clock.set_auto_advance_on_sleep(false);
    let sink = AtomicSink::try_new(
        SinkLimits::default(),
        |_: WriteAttempt<u32>| -> std::future::Ready<Result<(), SinkError>> {
            panic!("expired admission reached sink")
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("expired-factory/v1", sink)
        .codec(InputBudgets(budgets.clone()))
        .with_clock(clock.clone())
        .build()
        .unwrap();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let result = writer
        .add_write_item_with_and_options(
            || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                clock.advance(std::time::Duration::from_millis(100));
                Ok(1)
            },
            buffered_writes::WriteOptions::new()
                .with_deadline(std::time::Duration::from_millis(20)),
        )
        .await;
    assert!(matches!(
        result,
        Err(buffered_writes::WriteError::DeadlineExceeded {
            accepted: false,
            ..
        })
    ));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(budgets.lock().unwrap().is_empty());
    assert!(
        writer
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .is_clean()
    );
}

#[tokio::test]
async fn given_one_native_operation_when_packing_then_group_25_canonical_items() {
    let groups = Arc::new(Mutex::new(Vec::new()));
    let observed = groups.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(1, 64).unwrap(),
        move |attempt: WriteAttempt<u32>| {
            observed
                .lock()
                .unwrap()
                .push(attempt.decode_packed::<usize>().unwrap());
            async { Ok::<(), SinkError>(()) }
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("packed-count/v1", sink)
        .prepare_with("count/v1", |batch| {
            PreparedWrites::packed(&batch, &batch.items().len())
        })
        .build()
        .unwrap();
    for item in 0..25 {
        writer.add_write_item(item).await.unwrap();
    }
    writer.flush_writes().await;
    assert_eq!(*groups.lock().unwrap(), vec![25]);
}

#[tokio::test]
async fn given_large_canonical_input_when_packed_to_small_output_then_use_separate_byte_limits() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let observed = received.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(1, 1).unwrap(),
        move |attempt: WriteAttempt<String>| {
            observed.lock().unwrap().push(attempt.items()[0].len());
            async { Ok::<(), SinkError>(()) }
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("packed-bytes/v1", sink)
        .prepare_with("constant/v1", |batch| PreparedWrites::packed(&batch, &1_u8))
        .build()
        .unwrap();
    writer.add_write_item("x".repeat(512)).await.unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(*received.lock().unwrap(), vec![512]);
}

#[tokio::test]
async fn given_two_input_slots_when_each_item_produces_four_writes_then_allow_eight_native_operations()
 {
    let operations = Arc::new(Mutex::new(Vec::new()));
    let observed = operations.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(10, 1024).unwrap(),
        move |attempt: WriteAttempt<u32>| {
            observed
                .lock()
                .unwrap()
                .push(attempt.pending_operations().len());
            async { Ok::<(), SinkError>(()) }
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("many-writes/v1", sink)
        .buffer_capacity(BufferCapacity::default().max_items(2))
        .prepare_with("four/v1", |batch| {
            let writes = batch
                .items()
                .iter()
                .flat_map(|item| std::iter::repeat_n(*item, 4));
            PreparedWrites::operations(&batch, writes)
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    writer.add_write_item(2).await.unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 2);
    assert_eq!(*operations.lock().unwrap(), vec![8]);
}

struct MisdeclaredRecords;
impl buffered_writes::WriteBatch<u32> for MisdeclaredRecords {
    fn strategy_version(&self) -> &str {
        "misdeclared/v1"
    }
    fn layout(&self) -> buffered_writes::PreparationLayout {
        buffered_writes::PreparationLayout::Records
    }
    fn prepare(
        &self,
        batch: buffered_writes::BatchItems<'_, u32>,
    ) -> Result<PreparedWrites, buffered_writes::PrepareError> {
        PreparedWrites::packed(&batch, &1_u8)
    }
}

#[tokio::test]
async fn given_record_layout_when_commands_are_returned_then_quarantine_without_sink_effects() {
    let calls = Arc::new(Mutex::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        *observed.lock().unwrap() += 1;
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let writer = BufferedWrites::builder("layout/v1", sink)
        .with_batch_strategy(MisdeclaredRecords)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let report = writer.flush_writes().await;
    assert_eq!(report.items_settled, 0);
    assert_eq!(report.quarantined_items, 1);
    assert_eq!(*calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn given_custom_preparation_when_canonical_input_exceeds_retention_budget_then_reject_before_admission()
 {
    let budgets = Arc::new(Mutex::new(Vec::new()));
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(1, 1).unwrap(),
        |_: WriteAttempt<String>| async { Ok::<(), SinkError>(()) },
    )
    .unwrap();
    let writer = BufferedWrites::builder("input-bytes/v1", sink)
        .codec(InputBudgets(budgets.clone()))
        .buffer_capacity(BufferCapacity::default().max_bytes(1024))
        .prepare_with("constant/v1", |batch| PreparedWrites::packed(&batch, &1_u8))
        .build()
        .unwrap();
    let error = writer.add_write_item("x".repeat(4096)).await.unwrap_err();
    let seen = budgets.lock().unwrap().clone();
    let [budget] = seen.as_slice() else {
        panic!("expected one bounded encoding")
    };
    assert!(
        *budget > 1 && *budget < 1024,
        "metadata must share the configured byte capacity"
    );
    assert!(
        matches!(error, buffered_writes::WriteError::OversizedItem { size, limit }
        if limit == *budget && size > limit)
    );
    let report = writer.flush_writes().await;
    assert_eq!(report.items_settled, 0);
    assert_eq!(report.quarantined_items, 0);
    assert!(report.buffer_error.is_none());
}

#[tokio::test]
async fn given_partial_byte_budget_when_factory_runs_then_bound_encoding_and_preserve_factory_ownership()
 {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use buffered_writes::{BackpressurePolicy, MemoryBuffer, WriteError};
    for policy in [
        BackpressurePolicy::RejectFull,
        BackpressurePolicy::WaitUntilDeadline,
    ] {
        let budgets = Arc::new(Mutex::new(Vec::new()));
        let effects = Arc::new(Mutex::new(Vec::new()));
        let observed = effects.clone();
        let sink = AtomicSink::try_new(
            SinkLimits::default(),
            move |attempt: WriteAttempt<String>| {
                observed.lock().unwrap().extend_from_slice(attempt.items());
                async { Ok::<(), SinkError>(()) }
            },
        )
        .unwrap();
        let writer = BufferedWrites::builder("staging-budget/v1", sink)
            .with_buffer_provider(MemoryBuffer::new(
                buffered_writes::Namespace::try_from("staging-budget/v1").unwrap(),
            ))
            .codec(InputBudgets(budgets.clone()))
            .buffer_capacity(
                BufferCapacity::default()
                    .max_bytes(1800)
                    .backpressure(policy),
            )
            .flush_policy(|_: &buffered_writes::BufferStats| false)
            .build()
            .unwrap();
        writer.add_write_item("first".to_owned()).await.unwrap();
        let calls = AtomicUsize::new(0);
        let owned = "x".repeat(600);
        let admission = writer.add_write_item_with(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(owned)
        });
        let result = if policy == BackpressurePolicy::WaitUntilDeadline {
            let completion = async {
                tokio::task::yield_now().await;
                writer.after_response().await
            };
            let (result, response) = tokio::join!(admission, completion);
            assert_eq!(response.items_settled, 1);
            result
        } else {
            admission.await
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let limits = budgets.lock().unwrap().clone();
        assert!(limits[1] < limits[0], "{limits:?}");
        if policy == BackpressurePolicy::RejectFull {
            assert!(matches!(result, Err(WriteError::Full)), "{result:?}");
            assert_eq!(limits.len(), 2);
            assert!(effects.lock().unwrap().is_empty());
        } else {
            result.unwrap();
            assert_eq!(limits.len(), 3);
            assert!(limits[2] > limits[1]);
            assert_eq!(*effects.lock().unwrap(), vec!["first"]);
        }
        assert_eq!(writer.flush_writes().await.items_settled, 1);
        assert!(
            writer
                .shutdown(std::time::Duration::from_secs(1))
                .await
                .is_clean()
        );
    }
}

#[tokio::test]
async fn given_many_tiny_commands_when_metadata_budget_exhausts_then_stop_iterator_early() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let visited = Arc::new(AtomicUsize::new(0));
    let observed = visited.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(1_000_000, 1_000_000).unwrap(),
        |_: WriteAttempt<u32>| async { Ok::<(), SinkError>(()) },
    )
    .unwrap();
    let writer = BufferedWrites::builder("command-metadata/v1", sink)
        .buffer_capacity(BufferCapacity::default().max_bytes(16_384))
        .prepare_with("many/v1", move |batch| {
            let visited = observed.clone();
            let commands = (0..1_000_000_u32).inspect(move |_| {
                visited.fetch_add(1, Ordering::SeqCst);
            });
            PreparedWrites::operations(&batch, commands)
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    assert_eq!(writer.flush_writes().await.quarantined_items, 1);
    assert!(
        visited.load(Ordering::SeqCst) < 1000,
        "command metadata escaped the byte budget"
    );
}
