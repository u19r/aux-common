use super::{hash_api_key_secret, try_derive_api_key_public_id, verify_api_key_secret};
use crate::constants::API_KEY_HASH_ALGO;

#[test]
fn given_secret_when_hashing_api_key_then_verification_is_constant_time_and_roundtrips() {
    let hash = hash_api_key_secret(b"secret-token");
    assert!(verify_api_key_secret(
        b"secret-token",
        hash.algo(),
        hash.salt_b64(),
        hash.hash_b64()
    ));
    assert!(!verify_api_key_secret(
        b"wrong",
        hash.algo(),
        hash.salt_b64(),
        hash.hash_b64()
    ));
    assert!(!verify_api_key_secret(
        b"secret-token",
        "sha256",
        hash.salt_b64(),
        hash.hash_b64()
    ));
}

#[test]
fn given_oversized_encoded_api_key_parts_when_verifying_then_reject_without_decoding() {
    assert!(!verify_api_key_secret(
        b"secret",
        API_KEY_HASH_ALGO,
        &"A".repeat(1 << 20),
        "AQ"
    ));
    assert!(!verify_api_key_secret(
        b"secret",
        API_KEY_HASH_ALGO,
        "AQ",
        &"A".repeat(1 << 20)
    ));
}

#[test]
fn given_noncanonical_api_key_encoding_when_verifying_then_reject() {
    let hash = hash_api_key_secret(b"secret");
    let mut salt = hash.salt_b64().to_owned();
    salt.pop();
    salt.push('B');
    assert!(!verify_api_key_secret(
        b"secret",
        hash.algo(),
        &salt,
        hash.hash_b64()
    ));
}

#[test]
fn given_api_key_hash_when_debugging_then_verifier_material_is_redacted() {
    let hash = hash_api_key_secret(b"secret-token");
    let debug = format!("{hash:?}");
    assert!(!debug.contains(hash.salt_b64()));
    assert!(!debug.contains(hash.hash_b64()));
}

#[test]
fn given_hmac_key_when_deriving_public_id_then_output_is_stable_and_bounded() {
    let first = try_derive_api_key_public_id(b"secret", b"tenant-key", 12).expect("valid HMAC key");
    let second =
        try_derive_api_key_public_id(b"secret", b"tenant-key", 12).expect("valid HMAC key");
    assert_eq!(first, second);
    assert_eq!(first.len(), 12);
    assert!(try_derive_api_key_public_id(b"secret", b"tenant-key", 0).is_err());
}
