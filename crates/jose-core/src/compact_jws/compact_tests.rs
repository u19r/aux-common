use super::CompactJws;
use crate::{JwsAlgorithm, ProtectedHeader};

#[test]
fn given_compact_jws_when_preparing_then_only_canonical_three_part_shape_is_emitted() {
    let header =
        ProtectedHeader::new(JwsAlgorithm::EdDsa, "key-1", None::<String>).expect("header");
    let prepared = CompactJws::prepare(&header, br#"{"sub":"user"}"#).expect("prepare");
    let compact = prepared.finish(&[1, 2, 3]);
    let decoded = CompactJws::decode(&compact).expect("decode");
    assert_eq!(decoded.payload, br#"{"sub":"user"}"#);
    assert_eq!(decoded.signature, vec![1, 2, 3]);
}

#[test]
fn given_noncanonical_compact_shape_when_decoding_then_reject() {
    // Given a valid compact JWS and systematic shape violations.
    let header =
        ProtectedHeader::new(JwsAlgorithm::EdDsa, "key-1", None::<String>).expect("header");
    let compact = CompactJws::prepare(&header, br#"{"sub":"user"}"#)
        .expect("prepare")
        .finish(&[1, 2, 3]);
    let mut parts = compact.split('.');
    let (header_segment, payload_segment, signature_segment) = (
        parts.next().expect("header"),
        parts.next().expect("payload"),
        parts.next().expect("signature"),
    );
    let candidates = [
        // Padded base64 is not canonical URL_SAFE_NO_PAD.
        format!("{header_segment}={payload_segment}.{payload_segment}.{signature_segment}"),
        // Segment-count violations.
        format!("{header_segment}.{payload_segment}"),
        format!("{compact}.e30"),
        String::new(),
        // Non-alphabet bytes in the header segment.
        format!("{header_segment}!{payload_segment}.{signature_segment}"),
    ];

    // When each candidate reaches the decoder.
    for candidate in candidates {
        // Then non-canonical shapes fail before any cryptographic work.
        assert!(
            CompactJws::decode(&candidate).is_err(),
            "non-canonical compact JWS was accepted: {candidate:?}"
        );
    }
}
