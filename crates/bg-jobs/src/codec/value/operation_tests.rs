//! Operation marker, watermark, and receipt codec tests.

use std::num::{NonZeroU32, NonZeroU64};

use crate::{
    codec::{DecodedOperation, ValueCodec, ValueTag, decode_operation, encode_operation_receipt},
    error::StoreDataError,
    ids::{AttemptId, ExecutionId, JobId, JobKind, LeaseToken, OperationId, OwnerId, QueueName},
    model::{OperationReceipt, TerminalDisposition},
    policy::{EffectMode, OutcomeCode},
    time::Timestamp,
};

const OPERATION_VALUE: &str = concat!(
    "014f00000029",                     // version, tag, body length
    "00",                               // marker kind
    "01010101010101010101010101010101", // job_id
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // operation_id
    "0000000000000000",                 // fence high-water
);
const OPERATION_WATERMARK_VALUE: &str = concat!(
    "014f00000019",                     // version, tag, body length
    "02",                               // watermark kind
    "01010101010101010101010101010101", // job_id
    "0000000000000007",                 // fence high-water
);
const OPERATION_RECEIPT_VALUE: &str = concat!(
    "014f000000a2",                     // version, tag, body length
    "01",                               // receipt kind
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // operation_id
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", // job_id
    "00000007",                         // generation
    "0000000000000008",                 // revision
    "cccccccccccccccccccccccccccccccc", // execution_id
    "dddddddddddddddddddddddddddddddd", // attempt_id
    "00000002",                         // attempts
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", // owner
    "ffffffffffffffffffffffffffffffff", // token
    "0000000000000003",                 // fence
    "02",                               // AtLeastOnce effect mode
    "000000000000000b",                 // created_at
    "000000000000000c",                 // completed_at
    "00",                               // Completed terminal disposition
    "000000046b696e64",                 // kind
    "000000057175657565",               // queue
    "000000026f6b",                     // outcome
);

const OPERATION_EFFECT_MODE_OFFSET: usize = 6 + 121;

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

fn valid_operation_receipt() -> OperationReceipt {
    OperationReceipt {
        definition_digest: None,
        operation_id: OperationId::from([0xaa; 16]),
        job_id: JobId::from([0xbb; 16]),
        generation: 7,
        revision: 8,
        execution_id: ExecutionId::from([0xcc; 16]),
        attempt_id: AttemptId::from([0xdd; 16]),
        attempts: NonZeroU32::new(2).expect("attempt count is non-zero"),
        kind: JobKind::try_new("kind").expect("kind is valid"),
        queue: QueueName::try_new("queue").expect("queue is valid"),
        effect_mode: EffectMode::AtLeastOnce,
        created_at: Timestamp::from_millis(11),
        completed_at: Timestamp::from_millis(12),
        owner: OwnerId::from([0xee; 16]),
        token: LeaseToken::from([0xff; 16]),
        fence: NonZeroU64::new(3).expect("fence is non-zero"),
        terminal: TerminalDisposition::Completed,
        outcome: OutcomeCode::try_new("ok").expect("outcome is valid"),
    }
}

#[test]
fn given_a_hand_maintained_operation_marker_vector_when_decoding_then_framing_and_bytes_are_stable()
{
    let expected = hex_bytes(OPERATION_VALUE);
    let decoded = ValueCodec::decode(&expected).expect("literal operation decodes");
    assert_eq!(decoded.tag, ValueTag::Operation);
    assert_eq!(
        ValueCodec::encode(decoded.tag, decoded.body.as_ref())
            .expect("operation re-encodes")
            .as_ref(),
        expected.as_slice()
    );

    let operation = OperationId::from([0xaa; 16]);
    let marker_job = JobId::from([1; 16]);
    let operation_value =
        crate::keys::operation_value(&marker_job, &operation, 0).expect("operation value");
    assert_eq!(operation_value.as_ref(), expected.as_slice());
}

#[test]
fn given_hand_maintained_operation_receipt_vector_when_decoding_then_effect_mode_and_bytes_are_stable()
 {
    let expected = hex_bytes(OPERATION_RECEIPT_VALUE);
    let decoded = decode_operation(&expected).expect("literal operation receipt decodes");
    let receipt = match decoded {
        DecodedOperation::Receipt(receipt) => receipt,
        DecodedOperation::Live(_) => panic!("receipt vector decoded as live authority"),
    };

    assert_eq!(receipt, valid_operation_receipt());
    assert_eq!(
        encode_operation_receipt(&receipt)
            .expect("operation receipt re-encodes")
            .as_ref(),
        expected.as_slice()
    );
}

#[test]
fn given_an_operation_marker_for_another_job_when_validating_then_identity_is_rejected() {
    let marker_job = JobId::from([0x11; 16]);
    let other_job = JobId::from([0x22; 16]);
    let operation = OperationId::from([0xaa; 16]);
    let encoded =
        crate::keys::operation_value(&marker_job, &operation, 7).expect("operation marker encodes");

    let authority = crate::keys::decode_operation_authority(&encoded, &marker_job)
        .expect("active operation decodes");
    assert_eq!(authority.job_id(), marker_job);
    assert_eq!(authority.operation_id(), Some(operation));
    assert_eq!(authority.fence_high_water(), 7);
    assert!(matches!(
        crate::keys::decode_operation_authority(&encoded, &other_job),
        Err(StoreDataError::Malformed("operation job identity"))
    ));
}

#[test]
fn given_an_operation_watermark_when_decoding_then_it_preserves_fence_without_operation_id() {
    let job = JobId::from([1; 16]);
    let other_job = JobId::from([2; 16]);
    let encoded =
        crate::keys::operation_watermark_value(&job, 7).expect("operation watermark encodes");

    assert_eq!(
        encoded.as_ref(),
        hex_bytes(OPERATION_WATERMARK_VALUE).as_slice()
    );
    match decode_operation(&encoded).expect("operation watermark decodes") {
        DecodedOperation::Live(authority) => {
            assert_eq!(authority.job_id(), job);
            assert_eq!(authority.fence_high_water(), 7);
            assert_eq!(authority.operation_id(), None);
        }
        DecodedOperation::Receipt(_) => panic!("watermark decoded as receipt"),
    }
    assert_eq!(
        crate::keys::decode_operation_fence_high_water(&encoded, &job),
        Ok(7)
    );
    assert!(matches!(
        crate::keys::decode_operation_fence_high_water(&encoded, &other_job),
        Err(StoreDataError::Malformed("operation job identity"))
    ));
    assert!(matches!(
        crate::keys::decode_active_operation(&encoded, &job),
        Err(StoreDataError::Malformed("operation marker"))
    ));
}

#[test]
fn given_unknown_operation_effect_mode_bytes_when_decoding_then_the_codec_fails_closed() {
    let mut encoded = hex_bytes(OPERATION_RECEIPT_VALUE);
    encoded[OPERATION_EFFECT_MODE_OFFSET] = 0xff;
    assert!(matches!(
        decode_operation(&encoded),
        Err(StoreDataError::Malformed("effect mode"))
    ));
}

#[test]
fn given_each_operation_effect_mode_byte_when_round_tripping_then_the_mapping_is_stable() {
    for (byte, mode) in [
        (0, EffectMode::ReadOnly),
        (1, EffectMode::Idempotent),
        (2, EffectMode::AtLeastOnce),
        (3, EffectMode::Fenced),
    ] {
        let mut operation = hex_bytes(OPERATION_RECEIPT_VALUE);
        operation[OPERATION_EFFECT_MODE_OFFSET] = byte;
        let decoded_operation =
            decode_operation(&operation).expect("operation effect mode decodes");
        let receipt = match decoded_operation {
            DecodedOperation::Receipt(receipt) => receipt,
            DecodedOperation::Live(_) => panic!("receipt vector decoded as live authority"),
        };
        assert_eq!(receipt.effect_mode, mode);
        assert_eq!(
            encode_operation_receipt(&receipt)
                .expect("operation re-encodes")
                .as_ref(),
            operation
        );
    }
}

#[test]
fn given_a_defined_receipt_when_encoding_then_new_framing_round_trips_and_legacy_bytes_stay_readable()
 {
    let mut receipt = valid_operation_receipt();
    receipt.definition_digest = Some([0x55; 32]);
    let mut expected = hex_bytes(OPERATION_RECEIPT_VALUE);
    expected[2..6].copy_from_slice(&194_u32.to_be_bytes());
    expected[6] = 3;
    expected.extend_from_slice(&[0x55; 32]);
    assert_eq!(
        encode_operation_receipt(&receipt).unwrap().as_ref(),
        expected
    );
    match decode_operation(&expected).unwrap() {
        DecodedOperation::Receipt(decoded) => assert_eq!(decoded, receipt),
        DecodedOperation::Live(_) => panic!("terminal receipt"),
    }
    match decode_operation(&hex_bytes(OPERATION_RECEIPT_VALUE)).unwrap() {
        DecodedOperation::Receipt(decoded) => assert_eq!(decoded.definition_digest, None),
        DecodedOperation::Live(_) => panic!("legacy terminal receipt"),
    }
    let truncated =
        ValueCodec::encode(ValueTag::Operation, &expected[6..expected.len() - 1]).unwrap();
    assert!(matches!(
        decode_operation(&truncated),
        Err(StoreDataError::Truncated)
    ));
}
