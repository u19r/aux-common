use crate::{
    codec::{ValueCodec, ValueTag, decode_operation},
    ids::{JobId, OperationId},
};

#[test]
fn given_a_current_operation_when_encoded_then_identity_and_fence_round_trip() {
    let job = JobId::from([1; 16]);
    let operation = OperationId::from([2; 16]);
    let encoded = crate::keys::operation_value(&job, &operation, 7).unwrap();
    let mut body = vec![1; 16];
    body.extend_from_slice(&[2; 16]);
    body.extend_from_slice(&7_u64.to_be_bytes());
    assert_eq!(
        encoded,
        ValueCodec::encode(ValueTag::Operation, &body).unwrap()
    );
    let authority = crate::keys::decode_operation_authority(&encoded, &job).unwrap();
    assert_eq!(authority.job_id(), job);
    assert_eq!(authority.operation_id(), operation);
    assert_eq!(authority.fence_high_water(), 7);
    assert!(crate::keys::decode_operation_authority(&encoded, &JobId::from([3; 16])).is_err());
}

#[test]
fn given_malformed_operation_values_when_decoding_then_they_are_rejected() {
    for length in [0, 16, 32, 39, 41, 200] {
        let encoded = ValueCodec::encode(ValueTag::Operation, &vec![0; length]).unwrap();
        assert!(decode_operation(&encoded).is_err());
    }
    let encoded = ValueCodec::encode(ValueTag::PayloadChunk, &[0; 40]).unwrap();
    assert!(decode_operation(&encoded).is_err());
}
