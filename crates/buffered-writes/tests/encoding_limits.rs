use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use buffered_writes::{
    AtomicSink, BufferedWrites, PreparedWrites, SinkError, SinkLimits, WriteAttempt,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq as _};

#[derive(Clone)]
struct SerializationProbe {
    count: usize,
    visited: Arc<AtomicUsize>,
}

impl Serialize for SerializationProbe {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.count))?;
        for _ in 0..self.count {
            self.visited.fetch_add(1, Ordering::SeqCst);
            sequence.serialize_element(&0_u8)?;
        }
        sequence.end()
    }
}
impl<'de> Deserialize<'de> for SerializationProbe {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self {
            count: Vec::<u8>::deserialize(deserializer)?.len(),
            visited: Arc::default(),
        })
    }
}

#[tokio::test]
async fn given_oversized_serializable_item_when_admitted_then_stop_at_byte_limit() {
    let visited = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(25, 128).unwrap(),
        move |_: WriteAttempt<SerializationProbe>| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok::<(), SinkError>(()) }
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("encoding/limit/v1", sink)
        .build()
        .unwrap();
    assert!(
        writer
            .add_write_item(SerializationProbe {
                count: 100_000,
                visited: visited.clone()
            })
            .await
            .is_err()
    );
    assert!(
        visited.load(Ordering::SeqCst) < 1_000,
        "serialization consumed the oversized input"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_too_many_prepared_commands_when_prepared_then_stop_at_operation_limit() {
    let visited = Arc::new(AtomicUsize::new(0));
    let observed = visited.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(2, 1024).unwrap(),
        |_: WriteAttempt<u32>| async { Ok::<(), SinkError>(()) },
    )
    .unwrap();
    let writer = BufferedWrites::builder("commands/limit/v1", sink)
        .prepare_with("expansion/v1", move |batch| {
            let observed = observed.clone();
            let commands = (0..100_000).inspect(move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
            });
            PreparedWrites::operations(&batch, commands)
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    assert_eq!(writer.flush_writes().await.quarantined_items, 1);
    assert!(
        visited.load(Ordering::SeqCst) <= 3,
        "preparation consumed the entire command iterator"
    );
}

#[tokio::test]
async fn given_exact_json_budget_when_admitted_then_decode_and_deliver() {
    let count = Arc::new(AtomicUsize::new(0));
    let observed = count.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(25, 129).unwrap(),
        move |attempt: WriteAttempt<SerializationProbe>| {
            observed.fetch_add(attempt.items()[0].count, Ordering::SeqCst);
            async { Ok::<(), SinkError>(()) }
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("encoding/exact/v1", sink)
        .build()
        .unwrap();
    writer
        .add_write_item(SerializationProbe {
            count: 64,
            visited: Arc::default(),
        })
        .await
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(count.load(Ordering::SeqCst), 64);
}

#[tokio::test]
async fn given_large_packed_command_when_prepared_then_stop_encoding_before_quarantine() {
    let visited = Arc::new(AtomicUsize::new(0));
    let observed = visited.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(25, 128).unwrap(),
        |_: WriteAttempt<u32>| async { Ok::<(), SinkError>(()) },
    )
    .unwrap();
    let writer = BufferedWrites::builder("encoding/packed/v1", sink)
        .prepare_with("packed/v1", move |batch| {
            PreparedWrites::packed(
                &batch,
                &SerializationProbe {
                    count: 100_000,
                    visited: observed.clone(),
                },
            )
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    assert_eq!(writer.flush_writes().await.quarantined_items, 1);
    assert!(visited.load(Ordering::SeqCst) < 1_000);
}

#[tokio::test]
async fn given_cumulative_command_bytes_when_prepared_then_stop_the_iterator_at_budget() {
    let visited = Arc::new(AtomicUsize::new(0));
    let observed = visited.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(100, 128).unwrap(),
        |_: WriteAttempt<u32>| async { Ok::<(), SinkError>(()) },
    )
    .unwrap();
    let writer = BufferedWrites::builder("encoding/cumulative/v1", sink)
        .prepare_with("commands/v1", move |batch| {
            let observed = observed.clone();
            let commands = (0..100_000).map(move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                "x".repeat(20)
            });
            PreparedWrites::operations(&batch, commands)
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    assert_eq!(writer.flush_writes().await.quarantined_items, 1);
    assert!(visited.load(Ordering::SeqCst) < 10);
}

#[test]
fn given_admitted_record_when_debugged_then_omit_customer_payload_bytes() {
    let record = buffered_writes::AdmittedRecord {
        operation_id: buffered_writes::OperationId::generate_v7(),
        scope: buffered_writes::TenantScope::try_new("scope").unwrap(),
        codec_version: "v1".to_owned(),
        admitted_at_utc_ms: 0,
        admitted_at_mono: std::time::Instant::now(),
        payload: bytes::Bytes::from_static(b"private-payload"),
    };
    let output = format!("{record:?}");
    assert!(!output.contains("private-payload"));
    assert!(output.contains("payload_len"));
}

struct CustomJsonCodec;
impl buffered_writes::RecordCodec<SerializationProbe> for CustomJsonCodec {
    fn version(&self) -> &str {
        "custom-json/v1"
    }
    fn encode(
        &self,
        item: &SerializationProbe,
        max_bytes: usize,
    ) -> Result<bytes::Bytes, buffered_writes::EncodeError> {
        buffered_writes::RecordCodec::encode(
            &buffered_writes::SerdeJsonCodec::default(),
            item,
            max_bytes,
        )
    }
    fn decode(&self, bytes: &[u8]) -> Result<SerializationProbe, buffered_writes::EncodeError> {
        buffered_writes::RecordCodec::decode(&buffered_writes::SerdeJsonCodec::default(), bytes)
    }
}

#[tokio::test]
async fn given_custom_codec_when_reusing_json_encoder_then_stop_at_supplied_budget() {
    let visited = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(25, 128).unwrap(),
        move |_: WriteAttempt<SerializationProbe>| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok::<(), SinkError>(()) }
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("custom-codec/v1", sink)
        .codec(CustomJsonCodec)
        .build()
        .unwrap();
    assert!(
        writer
            .add_write_item(SerializationProbe {
                count: 100_000,
                visited: visited.clone()
            })
            .await
            .is_err()
    );
    assert!(visited.load(Ordering::SeqCst) < 1_000);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_decoded_items_when_delivered_then_pending_views_share_the_same_item() {
    let sink = AtomicSink::try_new(
        SinkLimits::default(),
        |attempt: WriteAttempt<String>| async move {
            assert!(std::ptr::eq(
                attempt.items().first().unwrap(),
                attempt.pending_items()[0].item()
            ));
            for pending in attempt.pending_items() {
                assert_eq!(
                    pending,
                    &buffered_writes::PendingItem::new(
                        pending.operation_id().clone(),
                        pending.item().clone(),
                    )
                );
            }
            Ok::<(), SinkError>(())
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("shared-items/v1", sink)
        .build()
        .unwrap();
    writer
        .add_write_item("private-item".to_owned())
        .await
        .unwrap();
    writer
        .add_write_item("second-item".to_owned())
        .await
        .unwrap();
    writer.flush_writes().await;
}

#[tokio::test]
async fn given_customer_item_when_attempt_formatted_then_omit_customer_payload() {
    let sink = AtomicSink::try_new(
        SinkLimits::default(),
        |attempt: WriteAttempt<String>| async move {
            assert!(!format!("{attempt:?}").contains("private-item"));
            assert!(!format!("{:?}", attempt.pending_items()[0]).contains("private-item"));
            Ok::<(), SinkError>(())
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("safe-attempt/v1", sink)
        .build()
        .unwrap();
    writer
        .add_write_item("private-item".to_owned())
        .await
        .unwrap();
    writer.flush_writes().await;
}
