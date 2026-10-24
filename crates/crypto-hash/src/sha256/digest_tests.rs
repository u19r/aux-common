use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::{content_digest_header_value, digest_base64, hmac_sha256};

#[test]
fn given_known_input_when_hashing_sha256_then_vectors_match() {
    assert_eq!(
        digest_base64(b"abc"),
        "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        content_digest_header_value(b"hello"),
        "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:"
    );
}

#[test]
fn given_rfc_hmac_vector_when_hashing_then_tag_matches() {
    let tag = hmac_sha256(&[0x0b; 20], b"Hi There");
    assert_eq!(
        STANDARD.encode(tag),
        "sDRMYdjbOFNcqK/OrwvxK4gdwgDJgz2nJuk3bC4yz/c="
    );
}

#[test]
fn given_short_key_rfc_vector_when_hashing_then_tag_matches() {
    let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        STANDARD.encode(tag),
        "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM="
    );
}

#[test]
fn given_long_key_rfc_vector_when_hashing_then_key_is_hashed_first() {
    let tag = hmac_sha256(
        &[0xaa; 131],
        b"Test Using Larger Than Block-Sized Key - Hash Key First",
    );
    assert_eq!(
        STANDARD.encode(tag),
        "rUd2PCkoTpOZ/qtR4OecnFhpzQZhfRT+afCvGf+9Uc0="
    );
}

#[test]
fn given_empty_key_and_data_when_hashing_then_tag_matches_reference() {
    let tag = hmac_sha256(b"", b"");
    assert_eq!(
        STANDARD.encode(tag),
        "thNnmggU2ex3L5XXeMNfxf8Wl8STcVZTxscSFEKSxa0="
    );
}
