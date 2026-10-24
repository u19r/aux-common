//! Job-record encoder and input-validation tests.

use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    time::Duration,
};

use bytes::Bytes;

use crate::{
    codec::encode_job_record,
    error::ValidationError,
    ids::{ExecutionId, JobId, JobKind, Namespace, QueueName},
    model::{
        AttemptHistory, JobPolicySnapshot, JobRecordV1, JobState, MAX_CHECKPOINT_BYTES,
        MAX_INLINE_PAYLOAD_BYTES, NewJob, PayloadManifest,
    },
    policy::{EffectMode, FairnessClass, Priority, RetryPreset},
    store::StoreKey,
    time::Timestamp,
};

fn valid_record() -> JobRecordV1 {
    JobRecordV1 {
        job_id: JobId::from([1; 16]),
        namespace: Namespace::try_new(b"jobs").expect("namespace is valid"),
        queue: QueueName::try_new("default").expect("queue is valid"),
        kind: JobKind::try_new("example").expect("kind is valid"),
        schema_version: NonZeroU16::new(1).expect("schema version is non-zero"),
        generation: 0,
        execution_id: ExecutionId::from([2; 16]),
        payload: PayloadManifest::try_new(0, [0; crate::model::PAYLOAD_DIGEST_BYTES], Vec::new())
            .expect("empty payload has no chunks"),
        fairness: FairnessClass::low_volume(),
        ordering_key: None,
        priority: Priority::Default,
        created_at: Timestamp::from_millis(10),
        scheduled_at: Timestamp::from_millis(10),
        expires_at: Some(Timestamp::from_millis(20)),
        policy: JobPolicySnapshot {
            effect_mode: EffectMode::Idempotent,
            cost_units: NonZeroU16::new(1).expect("cost is non-zero"),
            execution_timeout: Some(Duration::from_secs(1)),
            // The v1 vector encodes this explicit policy, independent of preset
            // defaults.
            retry_policy: RetryPreset::Interactive
                .with_limits(NonZeroU16::new(3).unwrap(), Duration::from_secs(5))
                .unwrap()
                .into(),
        },
        attempts: None,
        state: JobState::Scheduled,
        checkpoint: None,
        retention_deadline: Timestamp::from_millis(30),
        deduplication: None,
        revision: 1,
    }
}

// Hand-maintained v1 bytes. Field groups keep the persisted body reviewable
// without deriving the expected data from the encoder under test.
const JOB_RECORD_VALUE: &str = concat!(
    "014a000000c5",                     // version, tag, body length
    "01010101010101010101010101010101", // job_id
    "000000046a6f6273",                 // namespace
    "0000000764656661756c74",           // queue
    "000000076578616d706c65",           // kind
    "000100000000",                     // schema_version, generation
    "02020202020202020202020202020202", // execution_id
    "0000000000000000000000000000000000000000000000000000000000000000000000000000", // payload
    "000001",                           // low-volume fairness, no ordering key, default priority
    "000000000000000a000000000000000a", // created_at, scheduled_at
    "010000000000000014",               // expires_at
    "01000101000000003b9aca00",         // effect, cost, timeout
    "00030000001bf08eb0000000000005f5e100000000012a05f2000000000201", // retry policy
    "000000000000000000001e000000000000000001", // mutable fields
);

fn hex_bytes(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "hex literal has odd length");
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                .expect("hex digit")
        })
        .collect()
}

#[test]
fn given_a_valid_job_record_when_encoding_then_hand_maintained_bytes_are_stable() {
    let expected = hex_bytes(JOB_RECORD_VALUE);
    assert_eq!(
        encode_job_record(&valid_record())
            .expect("job record encodes")
            .as_ref(),
        expected.as_slice()
    );
}

#[test]
fn given_malformed_job_record_components_when_validating_then_public_constructors_reject_them() {
    let duplicate_key = StoreKey::try_from(&b"chunk"[..]).expect("chunk key is valid");
    assert!(matches!(
        PayloadManifest::try_new(
            1,
            [0; crate::model::PAYLOAD_DIGEST_BYTES],
            vec![duplicate_key.clone(), duplicate_key,]
        ),
        Err(ValidationError::InvalidValue {
            field: "duplicate payload chunk"
        })
    ));
    let too_many_chunks = (0..=PayloadManifest::MAX_CHUNKS)
        .map(|index| {
            StoreKey::try_from(format!("chunk-{index}").into_bytes()).expect("key is valid")
        })
        .collect();
    assert!(matches!(
        PayloadManifest::try_new(
            1,
            [0; crate::model::PAYLOAD_DIGEST_BYTES],
            too_many_chunks,
        ),
        Err(ValidationError::TooLong {
            field: "payload chunks",
            maximum: PayloadManifest::MAX_CHUNKS,
            actual,
        }) if actual == PayloadManifest::MAX_CHUNKS + 1
    ));
    assert!(matches!(
        PayloadManifest::try_new(
            0,
            [0; crate::model::PAYLOAD_DIGEST_BYTES],
            vec![StoreKey::try_from(&b"orphan"[..]).expect("key is valid"),]
        ),
        Err(ValidationError::InvalidValue {
            field: "zero-length payload chunks"
        })
    ));

    let mut record = valid_record();
    record.checkpoint = Some(Bytes::from(vec![0; MAX_CHECKPOINT_BYTES + 1]));
    assert!(matches!(
        record.validate(),
        Err(ValidationError::TooLong {
            field: "checkpoint",
            maximum: MAX_CHECKPOINT_BYTES,
            ..
        })
    ));

    let history = AttemptHistory {
        attempts: NonZeroU32::new(1).expect("attempt count is non-zero"),
        first_attempt_at: Timestamp::from_millis(20),
        last_attempt_at: Timestamp::from_millis(10),
        last_outcome: None,
    };
    assert!(matches!(
        history.validate(),
        Err(ValidationError::Ordering {
            field: "attempt chronology"
        })
    ));
    assert!(NonZeroU64::new(0).is_none());
}

#[test]
fn given_an_oversized_or_reversed_new_job_when_validating_then_the_enqueue_shape_is_rejected() {
    let mut job = NewJob {
        job_id: JobId::from([3; 16]),
        kind: JobKind::try_new("example").expect("kind is valid"),
        schema_version: NonZeroU16::new(1).expect("schema is non-zero"),
        payload: Bytes::from(vec![0; MAX_INLINE_PAYLOAD_BYTES + 1]),
        fairness: FairnessClass::low_volume(),
        ordering_key: None,
        priority: Priority::Default,
        scheduled_at: Timestamp::from_millis(20),
        expires_at: Some(Timestamp::from_millis(10)),
        retry_override: None,
        deduplication: None,
    };
    assert!(matches!(
        job.validate(),
        Err(ValidationError::TooLong {
            field: "payload",
            maximum: MAX_INLINE_PAYLOAD_BYTES,
            ..
        })
    ));

    job.payload = Bytes::new();
    assert!(matches!(
        job.validate(),
        Err(ValidationError::Ordering {
            field: "job expiry"
        })
    ));
}

#[test]
fn given_a_version_one_definition_when_hashed_then_terminal_identity_is_stable() {
    let record = valid_record();
    // SHA-256 of the independently maintained v1 immutable fields in
    // JOB_RECORD_VALUE, prefixed with definition version 1. Mutable fields
    // and payload chunk addresses are omitted.
    let expected = hex_bytes("f0aa3b82f3ebd57ee6a82a53fa4a7c26cc787f2b5139669a4c5a2b2eba1bf1e6");
    let digest =
        crate::codec::job_definition_digest(&crate::model::JobDefinition::from(&record)).unwrap();
    assert_eq!(digest.as_slice(), expected);

    let mut continued = record.clone();
    continued.scheduled_at = Timestamp::from_millis(19);
    continued.execution_id = ExecutionId::from([3; 16]);
    continued.generation = 4;
    continued.revision = 5;
    continued.checkpoint = Some(Bytes::from_static(b"next-page"));
    continued.state = JobState::Cancelled;
    assert_eq!(
        crate::codec::job_definition_digest(&crate::model::JobDefinition::from(&continued))
            .unwrap(),
        digest
    );
    continued.schema_version = NonZeroU16::new(2).unwrap();
    assert_ne!(
        crate::codec::job_definition_digest(&crate::model::JobDefinition::from(&continued))
            .unwrap(),
        digest
    );
}
