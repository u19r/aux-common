use buffered_writes::{
    AtomicSink, BatchItems, BufferCapacity, BufferConfig, BufferedWrites, ConfigurationError,
    DefaultItemGrouping, EncodeError, InMemoryQueue, PreparedWrites, RecordCodec, ReplayWorker,
    SerdeJsonCodec, SinkError, SinkLimits, WriteAttempt, WriteBatch, WriteError,
};
use bytes::Bytes;

struct VersionCodec(String);
impl RecordCodec<u32> for VersionCodec {
    fn version(&self) -> &str {
        &self.0
    }
    fn encode(&self, item: &u32, _: usize) -> Result<Bytes, EncodeError> {
        // Deliberately violate the budget contract to exercise boundary
        // validation.
        Ok(Bytes::from(item.to_string()))
    }
    fn decode(&self, bytes: &[u8]) -> Result<u32, EncodeError> {
        serde_json::from_slice(bytes).map_err(|_| EncodeError::DeserializationFailed)
    }
}
struct VersionStrategy(String);
impl WriteBatch<u32> for VersionStrategy {
    fn strategy_version(&self) -> &str {
        &self.0
    }
    fn prepare(
        &self,
        batch: BatchItems<'_, u32>,
    ) -> Result<PreparedWrites, buffered_writes::PrepareError> {
        PreparedWrites::default_items(&batch)
    }
}
fn sink(limits: SinkLimits) -> AtomicSink<u32> {
    AtomicSink::try_new(limits, |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap()
}

#[test]
fn given_invalid_versions_when_configured_then_reject_before_opening_retention() {
    for invalid in [
        "".to_owned(),
        "bad\nversion".to_owned(),
        " padded ".to_owned(),
        "x".repeat(129),
    ] {
        let directory =
            std::env::temp_dir().join(format!("buffered-config-{}", uuid::Uuid::now_v7()));
        let result = BufferedWrites::builder("configuration/v1", sink(SinkLimits::default()))
            .codec(VersionCodec(invalid.clone()))
            .buffer(BufferConfig::Disk {
                directory: directory.clone(),
            })
            .build();
        assert!(matches!(result, Err(ConfigurationError::InvalidVersion)));
        assert!(!directory.exists());
        assert!(SerdeJsonCodec::<u32>::with_version(invalid.clone()).is_err());
        assert!(
            BufferedWrites::builder("configuration/v1", sink(SinkLimits::default()))
                .prepare_with(invalid.clone(), |batch| PreparedWrites::default_items(
                    &batch
                ))
                .build()
                .is_err()
        );
        assert!(
            BufferedWrites::builder("configuration/v1", sink(SinkLimits::default()))
                .with_batch_strategy(VersionStrategy(invalid.clone()))
                .build()
                .is_err()
        );
        assert!(
            ReplayWorker::builder(
                "configuration/v1",
                InMemoryQueue::default(),
                sink(SinkLimits::default())
            )
            .strategy_version(invalid.clone())
            .build()
            .is_err()
        );
        assert!(
            ReplayWorker::builder(
                "configuration/v1",
                InMemoryQueue::default(),
                sink(SinkLimits::default())
            )
            .with_codec(VersionCodec(invalid))
            .build()
            .is_err()
        );
    }
}

#[test]
fn given_replaced_invalid_strategy_when_built_then_use_only_the_final_choice() {
    let writer = BufferedWrites::builder("configuration/v1", sink(SinkLimits::default()))
        .prepare_with("", |batch| PreparedWrites::default_items(&batch))
        .prepare_with("valid/v1", |batch| PreparedWrites::default_items(&batch))
        .build();
    assert!(writer.is_ok());
    let writer = BufferedWrites::builder("configuration/v1", sink(SinkLimits::default()))
        .prepare_with("", |batch| PreparedWrites::default_items(&batch))
        .with_batch_strategy(DefaultItemGrouping)
        .build();
    assert!(writer.is_ok());
}

#[test]
fn given_receipt_larger_than_effective_capacity_when_built_then_reject_configuration() {
    let limits = SinkLimits::try_new(25, 1024)
        .unwrap()
        .with_receipt_overhead_bytes(128);
    let result = BufferedWrites::builder("configuration/v1", sink(limits))
        .buffer_capacity(BufferCapacity::default().max_bytes(64))
        .build();
    assert!(matches!(
        result,
        Err(ConfigurationError::InvalidSinkLimits { .. })
    ));
}

#[tokio::test]
async fn given_codec_ignores_budget_when_admitted_then_reject_oversized_output() {
    let writer = BufferedWrites::builder(
        "configuration/v1",
        sink(SinkLimits::try_new(25, 1).unwrap()),
    )
    .codec(VersionCodec("valid/v1".to_owned()))
    .build()
    .unwrap();
    assert!(matches!(
        writer.add_write_item(123).await,
        Err(WriteError::OversizedItem { size: 3, limit: 1 })
    ));
}

#[test]
fn given_credential_and_endpoint_secrets_when_debugged_then_keep_only_configuration_facts() {
    let credentials = buffered_writes::ValkeyCredentials::new("private-password")
        .with_username("private-username")
        .with_tls_ca_pem(b"private-certificate".to_vec());
    let debug = format!("{credentials:?}");
    for secret in [
        "private-password",
        "private-username",
        "private-certificate",
    ] {
        assert!(!debug.contains(secret));
    }
    let buffer = buffered_writes::BufferConfig::valkey(
        "rediss://user:private-password@private-host/",
        credentials,
    );
    assert_eq!(format!("{buffer:?}"), "Valkey");
}
