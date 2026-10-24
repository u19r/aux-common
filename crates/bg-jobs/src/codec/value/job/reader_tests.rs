//! Job-record decoder and persisted-byte tests.

use std::{num::NonZeroU16, time::Duration};

use crate::{
    codec::{decode_job_record, encode_job_record},
    error::StoreDataError,
    ids::{ExecutionId, JobId, JobKind, Namespace, QueueName},
    model::{JobPolicySnapshot, JobRecordV1, JobState, PayloadManifest},
    policy::{EffectMode, FairnessClass, Priority, RetryPreset},
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
// without deriving the expected data from the decoder under test.
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

const JOB_EFFECT_MODE_OFFSET: usize = 6 + 134;
const JOB_PAYLOAD_CHUNK_COUNT_OFFSET: usize =
    6 + 16 + (4 + 4) + (4 + 7) + (4 + 7) + (2 + 4) + 16 + 4 + crate::model::PAYLOAD_DIGEST_BYTES;

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
fn given_hand_maintained_job_record_vector_when_decoding_then_body_is_stable() {
    let expected = hex_bytes(JOB_RECORD_VALUE);
    let decoded = decode_job_record(&expected).expect("literal job record decodes");

    assert_eq!(decoded, valid_record());
}

#[test]
fn given_unknown_job_effect_mode_bytes_when_decoding_then_the_codec_fails_closed() {
    let mut encoded = hex_bytes(JOB_RECORD_VALUE);
    encoded[JOB_EFFECT_MODE_OFFSET] = 0xff;
    assert!(matches!(
        decode_job_record(&encoded),
        Err(StoreDataError::Malformed("effect mode"))
    ));
}

#[test]
fn given_an_oversized_payload_chunk_count_when_decoding_then_keys_are_not_read() {
    let mut encoded = hex_bytes(JOB_RECORD_VALUE);
    let count = u16::try_from(PayloadManifest::MAX_CHUNKS + 1).expect("bound fits wire count");
    encoded[JOB_PAYLOAD_CHUNK_COUNT_OFFSET..JOB_PAYLOAD_CHUNK_COUNT_OFFSET + 2]
        .copy_from_slice(&count.to_be_bytes());

    assert_eq!(
        decode_job_record(&encoded),
        Err(StoreDataError::InvalidLength {
            field: "payload chunks",
            actual: PayloadManifest::MAX_CHUNKS + 1,
            maximum: PayloadManifest::MAX_CHUNKS,
        })
    );
}

#[test]
fn given_each_job_effect_mode_byte_when_round_tripping_then_the_mapping_is_stable() {
    for (byte, mode) in [
        (0, EffectMode::ReadOnly),
        (1, EffectMode::Idempotent),
        (2, EffectMode::AtLeastOnce),
        (3, EffectMode::Fenced),
    ] {
        let mut job = hex_bytes(JOB_RECORD_VALUE);
        job[JOB_EFFECT_MODE_OFFSET] = byte;
        let decoded_job = decode_job_record(&job).expect("job effect mode decodes");
        assert_eq!(decoded_job.policy.effect_mode, mode);
        assert_eq!(
            encode_job_record(&decoded_job)
                .expect("job re-encodes")
                .as_ref(),
            job
        );
    }
}
