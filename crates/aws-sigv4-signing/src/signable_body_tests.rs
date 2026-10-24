use crate::SignableBody;

#[test]
fn given_body_material_when_debugged_then_omit_payload_and_precomputed_hash() {
    let bytes = SignableBody::Bytes(b"sentinel-private-body");
    let precomputed = SignableBody::Precomputed("sentinel-private-hash".to_owned());
    assert_eq!(format!("{bytes:?}"), "Bytes([REDACTED])");
    assert_eq!(format!("{precomputed:?}"), "Precomputed([REDACTED])");
}

#[test]
fn given_malformed_precomputed_hash_when_signing_then_reject_it() {
    for value in ["", "not-hex", &"F".repeat(64), &"0".repeat(63)] {
        assert!(
            SignableBody::Precomputed(value.to_owned())
                .payload_hash()
                .is_err()
        );
    }
}
