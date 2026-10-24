use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::{JwsAlgorithm, ProtectedHeader};
use crate::JoseError;

#[test]
fn given_header_when_encoding_then_fields_are_canonical_and_roundtrip() {
    let header = ProtectedHeader::new(JwsAlgorithm::EdDsa, "key-1", Some("JWT")).expect("header");
    let encoded = header.encode().expect("encoding");
    assert_eq!(ProtectedHeader::decode(&encoded).expect("decode"), header);
}

#[test]
fn given_duplicate_or_unknown_header_members_when_decoding_then_reject() {
    let duplicate = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"a","kid":"b"}"#);
    assert!(ProtectedHeader::decode(&duplicate).is_err());
    let unknown = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"a","extra":true}"#);
    assert!(ProtectedHeader::decode(&unknown).is_err());
}

#[test]
fn given_out_of_profile_header_values_when_decoding_then_reject() {
    // Given headers with empty or oversized identifiers and with
    // undecodable or disallowed algorithms.
    assert!(matches!(
        ProtectedHeader::new(JwsAlgorithm::EdDsa, "", None::<String>),
        Err(JoseError::EmptyKeyId)
    ));
    assert!(ProtectedHeader::new(JwsAlgorithm::EdDsa, "k".repeat(257), None::<String>).is_err());
    assert!(ProtectedHeader::new(JwsAlgorithm::EdDsa, "key-1", Some("t".repeat(65))).is_err());
    for header in [
        r#"{"alg":"none","kid":"a"}"#,
        r#"{"alg":"HS256","kid":"a"}"#,
        r#"{"alg":"EdDsa","kid":"a"}"#,
        r#"{"alg":"ES256K","kid":"a"}"#,
        r#"{"kid":"a"}"#,
        r#"{"alg":256,"kid":"a"}"#,
    ] {
        // When each header reaches the decoder.
        let encoded = URL_SAFE_NO_PAD.encode(header);

        // Then values outside the closed asymmetric profile fail before use.
        assert!(
            ProtectedHeader::decode(&encoded).is_err(),
            "out-of-profile header was accepted: {header}"
        );
    }
}
