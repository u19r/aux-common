//! Value-envelope framing and persisted-byte tests.

use crate::{
    codec::{ValueCodec, ValueTag},
    error::StoreDataError,
};

const PAYLOAD_VALUE: &str = "0150000000077061796c6f6164";
const CANCELLATION_VALUE: &str = "014300000000";

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
fn given_hand_maintained_payload_and_cancellation_vectors_when_decoding_then_framing_and_mutations_are_stable()
 {
    let expected = hex_bytes(PAYLOAD_VALUE);
    let decoded = ValueCodec::decode(&expected).expect("literal payload decodes");
    assert_eq!(decoded.tag, ValueTag::PayloadChunk);
    assert_eq!(decoded.body.as_ref(), b"payload");
    assert_eq!(
        ValueCodec::encode(decoded.tag, decoded.body.as_ref())
            .expect("payload re-encodes")
            .as_ref(),
        expected.as_slice()
    );

    let cancellation_value = crate::keys::cancellation_value().expect("cancellation value");
    let expected = hex_bytes(CANCELLATION_VALUE);
    let decoded = ValueCodec::decode(&expected).expect("literal cancellation decodes");
    assert_eq!(decoded.tag, ValueTag::Cancellation);
    assert_eq!(decoded.body.as_ref(), b"");
    assert_eq!(
        ValueCodec::encode(decoded.tag, decoded.body.as_ref())
            .expect("cancellation re-encodes")
            .as_ref(),
        expected.as_slice()
    );
    assert_eq!(cancellation_value.as_ref(), expected.as_slice());

    let assert_error = |mut bytes: Vec<u8>, offset: usize, replacement: &[u8], expected| {
        bytes[offset..offset + replacement.len()].copy_from_slice(replacement);
        assert_eq!(ValueCodec::decode(&bytes), Err(expected));
    };
    let payload = hex_bytes(PAYLOAD_VALUE);
    assert_error(
        payload.clone(),
        0,
        &[0x7f],
        StoreDataError::UnknownVersion(0x7f),
    );
    assert_error(payload.clone(), 1, b"?", StoreDataError::UnknownTag(b'?'));
    assert_error(
        payload.clone(),
        2,
        &u32::MAX.to_be_bytes(),
        StoreDataError::InvalidLength {
            field: "value body",
            actual: u32::MAX as usize,
            maximum: 1_048_576,
        },
    );
    assert_eq!(
        ValueCodec::decode(&payload[..payload.len() - 1]),
        Err(StoreDataError::Truncated)
    );
}

#[test]
fn given_unknown_value_versions_or_tags_when_decoding_then_the_codec_fails_closed() {
    let encoded = ValueCodec::encode(ValueTag::Job, b"payload").expect("value encodes");

    let mut unknown_version = encoded.to_vec();
    unknown_version[0] = 0x7f;
    assert!(matches!(
        ValueCodec::decode(&unknown_version),
        Err(StoreDataError::UnknownVersion(0x7f))
    ));

    let mut unknown_tag = encoded.to_vec();
    unknown_tag[1] = b'?';
    assert!(matches!(
        ValueCodec::decode(&unknown_tag),
        Err(StoreDataError::UnknownTag(b'?'))
    ));
}

#[test]
fn given_truncated_or_malformed_value_envelopes_when_decoding_then_no_partial_value_is_returned() {
    let encoded = ValueCodec::encode(ValueTag::Job, b"payload").expect("value encodes");

    assert!(matches!(
        ValueCodec::decode(&[]),
        Err(StoreDataError::Truncated)
    ));
    for length in 1..encoded.len() {
        assert!(
            ValueCodec::decode(&encoded[..length]).is_err(),
            "length {length}"
        );
    }

    let mut declared_too_long = encoded.to_vec();
    declared_too_long[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        ValueCodec::decode(&declared_too_long),
        Err(StoreDataError::InvalidLength {
            field: "value body",
            ..
        }) | Err(StoreDataError::Truncated)
    ));

    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(matches!(
        ValueCodec::decode(&trailing),
        Err(StoreDataError::TrailingBytes)
    ));
}

#[test]
fn given_malformed_envelopes_when_decoding_through_each_entrypoint_then_errors_have_one_precedence()
{
    const HEADER_BYTES: usize = 6;
    const MAX_BODY_BYTES: usize = 1_048_576;

    let encoded = ValueCodec::encode(ValueTag::Job, b"payload").expect("value encodes");
    let mut unknown_version = encoded.to_vec();
    unknown_version[0] = 0x7f;
    assert_envelope_error_parity(&unknown_version, StoreDataError::UnknownVersion(0x7f));

    for length in 0..=HEADER_BYTES - 1 {
        assert_envelope_error_parity(&encoded[..length], StoreDataError::Truncated);
    }

    let mut unknown_tag = encoded.to_vec();
    unknown_tag[1] = b'?';
    assert_envelope_error_parity(&unknown_tag, StoreDataError::UnknownTag(b'?'));

    let mut declared_too_long = encoded.to_vec();
    declared_too_long[2..HEADER_BYTES].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_envelope_error_parity(
        &declared_too_long,
        StoreDataError::InvalidLength {
            field: "value body",
            actual: u32::MAX as usize,
            maximum: MAX_BODY_BYTES,
        },
    );

    let mut truncated_body = encoded.to_vec();
    truncated_body[2..HEADER_BYTES].copy_from_slice(&8_u32.to_be_bytes());
    assert_envelope_error_parity(&truncated_body, StoreDataError::Truncated);

    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_envelope_error_parity(&trailing, StoreDataError::TrailingBytes);
}

#[test]
fn given_a_valid_envelope_when_reading_its_body_then_the_body_borrows_the_input() {
    let encoded = ValueCodec::encode(ValueTag::Job, b"payload").expect("value encodes");

    let (tag, body) = ValueCodec::decode_body(&encoded).expect("body decodes");

    assert_eq!(tag, ValueTag::Job);
    assert_eq!(body, b"payload");
    assert_eq!(body.as_ptr(), encoded[6..].as_ptr());
}

fn assert_envelope_error_parity(encoded: &[u8], expected: StoreDataError) {
    assert_eq!(ValueCodec::decode(encoded), Err(expected.clone()));
    assert_eq!(ValueCodec::decode_body(encoded), Err(expected.clone()));
    assert_eq!(
        ValueCodec::decode_timestamp(encoded, ValueTag::Due),
        Err(expected)
    );
}
