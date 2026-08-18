use std::panic::{AssertUnwindSafe, catch_unwind};

use ciborium::value::Value;
use p256::ecdsa::SigningKey;
use webauthn_core::{
    AssertionInput, AttestationInput, CrossOriginPolicy, RpPolicy, UserVerification,
    parse_client_data, parse_cose_key, verify_assertion, verify_none_attestation,
};

#[test]
fn adversarial_deterministic_arbitrary_bytes_never_panic() {
    let policy = policy();
    let mut state = 0x5eed_u64;

    for _ in 0..256 {
        let length = (next_byte(&mut state) as usize) * 8;
        let bytes = (0..length)
            .map(|_| next_byte(&mut state))
            .collect::<Vec<_>>();
        let parse_result = catch_unwind(AssertUnwindSafe(|| parse_cose_key(&bytes)));
        assert!(
            parse_result.is_ok(),
            "COSE parser panicked for {length} bytes"
        );

        let client_result = catch_unwind(AssertUnwindSafe(|| {
            parse_client_data(&bytes, "webauthn.get", &policy)
        }));
        assert!(
            client_result.is_ok(),
            "client-data parser panicked for {length} bytes"
        );

        let attestation_result = catch_unwind(AssertUnwindSafe(|| {
            verify_none_attestation(AttestationInput {
                client_data_json: &bytes,
                attestation_object: &bytes,
                policy: &policy,
            })
        }));
        assert!(
            attestation_result.is_ok(),
            "attestation parser panicked for {length} bytes"
        );

        let assertion_result = catch_unwind(AssertUnwindSafe(|| {
            verify_assertion(AssertionInput {
                client_data_json: &bytes,
                authenticator_data: &bytes,
                signature: &bytes,
                credential_public_key_cose: &bytes,
                credential_id: b"credential",
                previous_sign_count: 0,
                policy: &policy,
            })
        }));
        assert!(
            assertion_result.is_ok(),
            "assertion parser panicked for {length} bytes"
        );
    }
}

#[test]
fn adversarial_single_byte_mutations_never_panic() {
    let valid = valid_cose_key();

    for index in 0..valid.len() {
        for mask in [1_u8, 0x80] {
            let mut mutated = valid.clone();
            mutated[index] ^= mask;
            let result = catch_unwind(AssertUnwindSafe(|| parse_cose_key(&mutated)));
            assert!(
                result.is_ok(),
                "COSE parser panicked after mutating byte {index} with {mask:#x}"
            );
        }
    }
}

fn policy() -> RpPolicy {
    RpPolicy::try_new(
        "AAAAAAAAAAAAAAAAAAAAAA",
        "https://example.test",
        [0; 32],
        UserVerification::Preferred,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid policy")
}

fn next_byte(state: &mut u64) -> u8 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1);
    (*state >> 32) as u8
}

fn valid_cose_key() -> Vec<u8> {
    let signing_key = SigningKey::from_bytes((&[42_u8; 32]).into()).expect("signing key");
    let point = signing_key.verifying_key().to_sec1_point(false);
    let value = Value::Map(vec![
        (Value::Integer(1_i64.into()), Value::Integer(2_i64.into())),
        (
            Value::Integer(3_i64.into()),
            Value::Integer((-7_i64).into()),
        ),
        (
            Value::Integer((-1_i64).into()),
            Value::Integer(1_i64.into()),
        ),
        (
            Value::Integer((-2_i64).into()),
            Value::Bytes(point.x().expect("x coordinate").to_vec()),
        ),
        (
            Value::Integer((-3_i64).into()),
            Value::Bytes(point.y().expect("y coordinate").to_vec()),
        ),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).expect("encode COSE key");
    encoded
}
