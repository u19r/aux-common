use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::{Argon2Policy, api_key::*, password, sha256};

#[test]
fn given_known_input_when_hashing_sha256_then_vectors_match() {
    assert_eq!(
        sha256::digest_base64(b"abc"),
        "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
    );
    assert_eq!(
        sha256::content_digest_header_value(b"hello"),
        "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:"
    );
}

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

#[test]
fn given_rfc_hmac_vector_when_hashing_then_tag_matches() {
    let tag = sha256::hmac_sha256(&[0x0b; 20], b"Hi There");
    assert_eq!(
        STANDARD.encode(tag),
        "sDRMYdjbOFNcqK/OrwvxK4gdwgDJgz2nJuk3bC4yz/c="
    );
}

#[test]
fn given_password_when_hashing_then_strict_policy_roundtrips() {
    let hash = password::hash_password(b"secret").expect("hash");
    assert!(password::verify_password(b"secret", &hash).expect("verify"));
    assert!(!password::verify_password(b"wrong", &hash).expect("verify"));
    assert_eq!(Argon2Policy::strict().parallelism(), 1);
}

#[test]
fn given_legacy_parallelism_when_verifying_strictly_then_policy_rejects_it() {
    let legacy = "$argon2id$v=19$m=19456,t=3,p=8$Lud2zb0Z6RvFEWl1YiQ12A$pK/4X7HO3sxc5hykR/\
                  yvTqghqQOfzU10DLem+o9tlA8";
    assert_eq!(
        password::verify_password(b"auxfn-dummy-password-verification-only", legacy),
        Err(crate::HashError::PasswordPolicy)
    );
    assert!(
        password::verify_password_with_policy(
            b"auxfn-dummy-password-verification-only",
            legacy,
            Argon2Policy::bounded_legacy()
        )
        .expect("legacy verify")
    );
}

#[test]
fn given_oversized_password_hash_when_verifying_then_reject_before_argon2() {
    let oversized = "$argon2id$v=19$m=19456,t=3,p=1$".to_owned() + &"A".repeat(2 * 1024);
    assert_eq!(
        password::verify_password(b"secret", &oversized),
        Err(crate::HashError::InvalidPasswordHash)
    );
}
