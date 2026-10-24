use std::sync::{Arc, Mutex};

use buffered_writes::{
    AtomicSink, BufferedWrites, SealedBatch, SinkError, SinkLimits, WriteAttempt,
};

async fn envelope() -> serde_json::Value {
    let captured = Arc::new(Mutex::new(None));
    let observed = captured.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let observed = observed.clone();
        async move {
            *observed.lock().unwrap() = Some(attempt.sealed_batch().clone());
            Ok::<(), SinkError>(())
        }
    })
    .unwrap();
    let writer = BufferedWrites::builder("envelope/v1", sink)
        .build()
        .unwrap();
    writer.add_write_item(7).await.unwrap();
    writer.flush_writes().await;
    serde_json::to_value(captured.lock().unwrap().as_ref().unwrap()).unwrap()
}

#[tokio::test]
async fn given_sealed_envelope_when_batch_identity_changes_then_reject_digest() {
    let mut value = envelope().await;
    value["batch_id"] = serde_json::json!(uuid::Uuid::now_v7());
    assert!(SealedBatch::from_envelope_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[tokio::test]
async fn given_sealed_envelope_when_replay_age_changes_then_reject_digest() {
    let mut value = envelope().await;
    value["first_item_time_ms"] = serde_json::json!(0);
    assert!(SealedBatch::from_envelope_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[tokio::test]
async fn given_sealed_envelope_when_record_time_changes_then_reject_digest() {
    let mut value = envelope().await;
    value["records"][0]["admitted_at_utc_ms"] = serde_json::json!(0);
    assert!(SealedBatch::from_envelope_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[tokio::test]
async fn given_corrupt_digest_when_deserialized_directly_then_reject_invalid_batch() {
    let mut value = envelope().await;
    value["digest"] = serde_json::json!(vec![0_u8; 32]);
    assert!(serde_json::from_value::<SealedBatch>(value).is_err());
}

#[test]
fn given_invalid_identifiers_when_deserialized_then_preserve_constructor_validation() {
    assert!(serde_json::from_value::<buffered_writes::Namespace>(serde_json::json!("")).is_err());
    assert!(
        serde_json::from_value::<buffered_writes::TenantScope>(serde_json::json!("invalid scope"))
            .is_err()
    );
    assert!(
        serde_json::from_value::<buffered_writes::OperationId>(serde_json::json!("\n")).is_err()
    );
    assert!(
        serde_json::from_value::<buffered_writes::BatchId>(serde_json::json!(uuid::Uuid::new_v4()))
            .is_err()
    );
}

#[tokio::test]
async fn given_valid_envelope_when_round_tripped_then_preserve_identity_and_digest() {
    let original: SealedBatch = serde_json::from_value(envelope().await).unwrap();
    let restored =
        SealedBatch::from_envelope_bytes(&original.to_envelope_bytes().unwrap()).unwrap();
    assert_eq!(original, restored);
    assert!(restored.verify_digest());
    assert_eq!(restored.batch_id().as_uuid().get_version_num(), 7);
}

#[tokio::test]
async fn given_invalid_membership_when_constructed_then_reject_before_sealing() {
    use buffered_writes::{OperationId, PreparedOperation, PreparedPayload, SealedBatchInput};
    let value = envelope().await;
    let input = || serde_json::from_value::<SealedBatchInput>(value.clone()).unwrap();
    let mut empty = input();
    empty.records = Arc::from([]);
    assert!(SealedBatch::try_new(empty).is_err());
    let mut duplicate = input();
    duplicate.records = vec![duplicate.records[0].clone(); 2].into();
    assert!(SealedBatch::try_new(duplicate).is_err());
    let mut missing = input();
    missing.operation_ids = Arc::from([]);
    assert!(SealedBatch::try_new(missing).is_err());
    let mut mismatch = input();
    mismatch.operation_ids = vec![OperationId::try_new("other").unwrap()].into();
    assert!(SealedBatch::try_new(mismatch).is_err());
    let mut custom = input();
    custom.prepared = PreparedPayload::CustomOperations(
        vec![PreparedOperation {
            operation_id: OperationId::try_new("other").unwrap(),
            payload: bytes::Bytes::from_static(b"7"),
        }]
        .into(),
    );
    assert!(SealedBatch::try_new(custom).is_err());
    let mut age = input();
    age.first_item_time_ms = age.first_item_time_ms.saturating_sub(1);
    assert!(SealedBatch::try_new(age).is_err());
}

#[tokio::test]
async fn given_invalid_versions_when_constructed_then_reject_before_sealing() {
    use buffered_writes::SealedBatchInput;
    let value = envelope().await;
    for version in [
        "".to_owned(),
        "x".repeat(129),
        "x\ny".to_owned(),
        " padded ".to_owned(),
    ] {
        let mut codec: SealedBatchInput = serde_json::from_value(value.clone()).unwrap();
        codec.codec_version = version.clone();
        assert!(SealedBatch::try_new(codec).is_err());
        let mut strategy: SealedBatchInput = serde_json::from_value(value.clone()).unwrap();
        strategy.strategy_version = version;
        assert!(SealedBatch::try_new(strategy).is_err());
    }
}

#[tokio::test]
async fn given_identical_operations_when_representation_changes_then_digest_changes() {
    use buffered_writes::{PreparedOperation, PreparedPayload, SealedBatchInput};
    let value = envelope().await;
    let shared: SealedBatch = serde_json::from_value(value.clone()).unwrap();
    let mut input: SealedBatchInput = serde_json::from_value(value).unwrap();
    input.prepared = PreparedPayload::CustomOperations(
        vec![PreparedOperation {
            operation_id: input.records[0].operation_id.clone(),
            payload: input.records[0].payload.clone(),
        }]
        .into(),
    );
    let custom = SealedBatch::try_new(input).unwrap();
    assert_ne!(shared.digest(), custom.digest());
    assert_eq!(
        custom,
        SealedBatch::from_envelope_bytes(&custom.to_envelope_bytes().unwrap()).unwrap()
    );
}
