use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use sha2::{Digest as _, Sha256};

use super::verify_assertion;
use crate::{
    AssertionInput, CrossOriginPolicy, RpPolicy, UserVerification, WebAuthnError,
    assertion::{CHALLENGE_B64, assertion_fixture, assertion_policy, cose_key, nested_array_value},
    parse_cose_key,
};

#[test]
fn given_valid_assertion_when_verifying_then_signature_and_counter_are_returned() {
    let signing_key = SigningKey::from_bytes((&[42_u8; 32]).into()).expect("signing key");
    let point = signing_key.verifying_key().to_sec1_point(false);
    let x = point.x().expect("x");
    let y = point.y().expect("y");
    let cose = cose_key(x, y);
    let client_data = br#"{"origin":"https://example.test","crossOrigin":false,"challenge":"AAAAAAAAAAAAAAAAAAAAAA","type":"webauthn.get"}"#;
    let rp_hash: [u8; 32] = Sha256::digest(b"example.test").into();
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_hash);
    auth_data.extend_from_slice(&[0x01, 0, 0, 0, 5]);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(client_data));
    let signature: Signature = signing_key.sign(&signed);
    let assertion_policy = RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        rp_hash,
        UserVerification::Preferred,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid policy");
    let result = verify_assertion(AssertionInput {
        client_data_json: client_data,
        authenticator_data: &auth_data,
        signature: signature.to_der().as_bytes(),
        credential_public_key_cose: &cose,
        credential_id: b"credential",
        previous_sign_count: 4,
        policy: &assertion_policy,
        user_handle: None,
    })
    .expect("valid assertion");
    assert_eq!(result.sign_count, 5);
}

#[test]
fn given_signature_with_trailing_der_bytes_when_verifying_then_reject() {
    let fixture = assertion_fixture();
    let mut signature = fixture.signature.clone();
    signature.push(0);
    let policy = assertion_policy(&fixture);

    assert!(matches!(
        verify_assertion(AssertionInput {
            client_data_json: &fixture.client_data,
            authenticator_data: &fixture.authenticator_data,
            signature: &signature,
            credential_public_key_cose: &fixture.cose,
            credential_id: b"credential",
            previous_sign_count: 0,
            policy: &policy,
            user_handle: None,
        }),
        Err(WebAuthnError::InvalidSignature)
    ));
}

#[test]
fn given_signature_for_different_client_data_when_verifying_then_reject() {
    let fixture = assertion_fixture();
    let mut altered_client_data = fixture.client_data[..fixture.client_data.len() - 1].to_vec();
    altered_client_data.extend_from_slice(br#","extra":0}"#);
    let policy = assertion_policy(&fixture);

    assert!(matches!(
        verify_assertion(AssertionInput {
            client_data_json: &altered_client_data,
            authenticator_data: &fixture.authenticator_data,
            signature: &fixture.signature,
            credential_public_key_cose: &fixture.cose,
            credential_id: b"credential",
            previous_sign_count: 0,
            policy: &policy,
            user_handle: None,
        }),
        Err(WebAuthnError::InvalidSignature)
    ));
}

#[test]
fn given_authenticator_data_for_different_rp_when_verifying_then_reject() {
    let fixture = assertion_fixture();
    let mut altered_authenticator_data = fixture.authenticator_data.clone();
    altered_authenticator_data[0] ^= 1;
    let policy = assertion_policy(&fixture);

    assert!(matches!(
        verify_assertion(AssertionInput {
            client_data_json: &fixture.client_data,
            authenticator_data: &altered_authenticator_data,
            signature: &fixture.signature,
            credential_public_key_cose: &fixture.cose,
            credential_id: b"credential",
            previous_sign_count: 0,
            policy: &policy,
            user_handle: None,
        }),
        Err(WebAuthnError::RpIdHashMismatch)
    ));
}

#[test]
fn given_unknown_authenticator_flag_when_verifying_then_reject() {
    let fixture = assertion_fixture();
    let mut altered_authenticator_data = fixture.authenticator_data.clone();
    altered_authenticator_data[32] |= 0x02;
    let policy = assertion_policy(&fixture);

    assert!(matches!(
        verify_assertion(AssertionInput {
            client_data_json: &fixture.client_data,
            authenticator_data: &altered_authenticator_data,
            signature: &fixture.signature,
            credential_public_key_cose: &fixture.cose,
            credential_id: b"credential",
            previous_sign_count: 0,
            policy: &policy,
            user_handle: None,
        }),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_user_verification_required_without_uv_flag_when_verifying_then_reject() {
    let fixture = assertion_fixture();
    let policy = RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        fixture.rp_id_hash,
        UserVerification::Required,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid policy");

    assert!(matches!(
        verify_assertion(AssertionInput {
            client_data_json: &fixture.client_data,
            authenticator_data: &fixture.authenticator_data,
            signature: &fixture.signature,
            credential_public_key_cose: &fixture.cose,
            credential_id: b"credential",
            previous_sign_count: 0,
            policy: &policy,
            user_handle: None,
        }),
        Err(WebAuthnError::UserVerificationRequired)
    ));
}

#[test]
fn given_attested_data_in_assertion_when_verifying_then_reject() {
    let fixture = assertion_fixture();
    let mut altered_authenticator_data = fixture.authenticator_data.clone();
    altered_authenticator_data[32] |= 0x40;
    let policy = assertion_policy(&fixture);

    assert!(matches!(
        verify_assertion(AssertionInput {
            client_data_json: &fixture.client_data,
            authenticator_data: &altered_authenticator_data,
            signature: &fixture.signature,
            credential_public_key_cose: &fixture.cose,
            credential_id: b"credential",
            previous_sign_count: 0,
            policy: &policy,
            user_handle: None,
        }),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_oversized_credential_id_when_verifying_then_reject_before_signature_work() {
    let fixture = assertion_fixture();
    let policy = assertion_policy(&fixture);
    let credential_id = vec![0_u8; 1024];

    assert!(matches!(
        verify_assertion(AssertionInput {
            client_data_json: &fixture.client_data,
            authenticator_data: &fixture.authenticator_data,
            signature: &fixture.signature,
            credential_public_key_cose: &fixture.cose,
            credential_id: &credential_id,
            previous_sign_count: 0,
            policy: &policy,
            user_handle: None,
        }),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_deeply_nested_cose_value_when_parsing_then_reject_before_recursive_decode() {
    use ciborium::value::Value;

    let nested = nested_array_value(20);
    let value = Value::Map(vec![
        (Value::Integer(1_i64.into()), Value::Integer(2_i64.into())),
        (
            Value::Integer(3_i64.into()),
            Value::Integer((-7_i64).into()),
        ),
        (Value::Integer(4_i64.into()), nested),
        (
            Value::Integer((-1_i64).into()),
            Value::Integer(1_i64.into()),
        ),
        (Value::Integer((-2_i64).into()), Value::Bytes(vec![1; 32])),
        (Value::Integer((-3_i64).into()), Value::Bytes(vec![2; 32])),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).expect("encode nested COSE value");

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_broad_cose_array_when_parsing_then_reject_before_allocating_all_items() {
    // A definite array with 257 scalar members is tiny on the wire but exceeds
    // the parser's total-value budget.
    let mut encoded = vec![0x99, 0x01, 0x01];
    encoded.extend(std::iter::repeat_n(0_u8, 257));

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_trailing_assertion_authenticator_bytes_when_verifying_then_reject() {
    let mut bytes = vec![0; 38];
    bytes[32] = 0x01;
    assert!(matches!(
        super::parse_authenticator_data(&bytes, &[0; 32], false, UserVerification::Preferred),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_missing_user_presence_when_parsing_authenticator_data_then_reject() {
    assert!(matches!(
        super::parse_authenticator_data(&[0; 37], &[0; 32], false, UserVerification::Preferred,),
        Err(WebAuthnError::UserPresenceMissing)
    ));
}

#[test]
fn given_backup_state_without_backup_eligibility_when_parsing_then_reject() {
    let mut bytes = vec![0_u8; 37];
    bytes[32] = 0x11;

    assert!(matches!(
        super::parse_authenticator_data(&bytes, &[0; 32], false, UserVerification::Preferred,),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_counter_pairs_when_classifying_then_return_documented_status() {
    assert_eq!(
        super::classify_counter(0, 0),
        crate::SignCountStatus::ZeroCounter
    );
    assert_eq!(
        super::classify_counter(0, 4),
        crate::SignCountStatus::Initial { value: 4 }
    );
    assert_eq!(
        super::classify_counter(4, 5),
        crate::SignCountStatus::Increased {
            previous: 4,
            current: 5,
        }
    );
    assert_eq!(
        super::classify_counter(4, 4),
        crate::SignCountStatus::Unchanged { value: 4 }
    );
    assert_eq!(
        super::classify_counter(5, 4),
        crate::SignCountStatus::Regression {
            previous: 5,
            current: 4,
        }
    );
}

#[test]
fn given_raw_signature_when_verifying_then_reject() {
    let fixture = assertion_fixture();
    let policy = assertion_policy(&fixture);
    let raw_signature = vec![0_u8; 64];

    assert!(matches!(
        verify_assertion(AssertionInput {
            client_data_json: &fixture.client_data,
            authenticator_data: &fixture.authenticator_data,
            signature: &raw_signature,
            credential_public_key_cose: &fixture.cose,
            credential_id: b"credential",
            previous_sign_count: 0,
            policy: &policy,
            user_handle: None,
        }),
        Err(WebAuthnError::InvalidSignature)
    ));
}

#[test]
fn given_mutated_ceremony_bytes_when_verifying_then_decision_oracle_holds() {
    // Given a valid fixture. This is the deterministic twin of the
    // `webauthn_ceremony` fuzz oracle: only byte-identical inputs may
    // reproduce the seed result.
    let fixture = assertion_fixture();
    let policy = assertion_policy(&fixture);
    let seed_result = verify_assertion(AssertionInput {
        client_data_json: &fixture.client_data,
        authenticator_data: &fixture.authenticator_data,
        signature: &fixture.signature,
        credential_public_key_cose: &fixture.cose,
        credential_id: b"credential",
        previous_sign_count: 0,
        policy: &policy,
        user_handle: None,
    })
    .expect("seed must verify");
    let verify = |client_data: &[u8],
                  authenticator_data: &[u8],
                  signature: &[u8],
                  cose: &[u8],
                  credential_id: &[u8]| {
        verify_assertion(AssertionInput {
            client_data_json: client_data,
            authenticator_data,
            signature,
            credential_public_key_cose: cose,
            credential_id,
            previous_sign_count: 0,
            policy: &policy,
            user_handle: None,
        })
    };
    let flipped_client_data = flip_byte(&fixture.client_data, 10);
    let flipped_auth_data = flip_byte(&fixture.authenticator_data, 0);
    let flipped_signature = flip_byte(&fixture.signature, 8);
    let flipped_cose = flip_byte(&fixture.cose, 20);
    let substituted_origin = fixture
        .client_data
        .windows(b"example.test".len())
        .position(|window| window == b"example.test")
        .map(|position| {
            let mut substituted = fixture.client_data.clone();
            substituted[position..position + b"example.test".len()]
                .copy_from_slice(b"evil.test!!!");
            substituted
        })
        .expect("origin present");
    let duplicated_member = String::from_utf8(fixture.client_data.clone())
        .expect("client data is UTF-8")
        .replacen("\"crossOrigin\"", "\"crossOrigin\":true,\"crossOrigin\"", 1)
        .into_bytes();
    let mutated: Vec<Vec<u8>> = vec![
        flipped_client_data,
        flipped_auth_data,
        flipped_signature,
        flipped_cose,
        substituted_origin,
        duplicated_member,
        fixture.authenticator_data[..20].to_vec(),
    ];

    // When each mutated ceremony reaches the verifier.
    for bytes in [0, 1, 2, 3, 4, 5, 6] {
        let candidate = &mutated[bytes];
        let result = match bytes {
            0 | 4 | 5 => verify(
                candidate,
                &fixture.authenticator_data,
                &fixture.signature,
                &fixture.cose,
                b"credential",
            ),
            1 | 6 => verify(
                &fixture.client_data,
                candidate,
                &fixture.signature,
                &fixture.cose,
                b"credential",
            ),
            2 => verify(
                &fixture.client_data,
                &fixture.authenticator_data,
                candidate,
                &fixture.cose,
                b"credential",
            ),
            _ => verify(
                &fixture.client_data,
                &fixture.authenticator_data,
                &fixture.signature,
                candidate,
                b"credential",
            ),
        };

        // Then every mutation fails closed or yields a different result than
        // the seed, never an equal result for different inputs.
        assert!(
            result.is_err() || result.expect("checked") != seed_result,
            "mutated ceremony reproduced the seed result"
        );
    }
}

fn flip_byte(bytes: &[u8], position: usize) -> Vec<u8> {
    let mut flipped = bytes.to_vec();
    let index = position % flipped.len();
    flipped[index] ^= 0x01;
    flipped
}

#[test]
fn given_expected_user_handle_when_asserting_then_binding_is_enforced() {
    let fixture = assertion_fixture();
    let policy = assertion_policy(&fixture)
        .with_expected_user_handle(b"alice")
        .expect("expected user policy");
    let verify_with = |user_handle: Option<&[u8]>| {
        verify_assertion(AssertionInput {
            client_data_json: &fixture.client_data,
            authenticator_data: &fixture.authenticator_data,
            signature: &fixture.signature,
            credential_public_key_cose: &fixture.cose,
            credential_id: b"credential",
            previous_sign_count: 0,
            policy: &policy,
            user_handle,
        })
    };

    let matching = verify_with(Some(b"alice")).expect("matching handle verifies");
    assert_eq!(matching.user_handle.as_deref(), Some(b"alice".as_slice()));
    assert!(matches!(
        verify_with(Some(b"mallory")),
        Err(WebAuthnError::UserHandleMismatch)
    ));
    assert!(matches!(
        verify_with(None),
        Err(WebAuthnError::UserHandleMismatch)
    ));
}

#[test]
fn given_no_expected_user_handle_when_asserting_then_handle_is_reported_without_enforcement() {
    let fixture = assertion_fixture();
    let policy = assertion_policy(&fixture);
    let verify_with = |user_handle: Option<&[u8]>| {
        verify_assertion(AssertionInput {
            client_data_json: &fixture.client_data,
            authenticator_data: &fixture.authenticator_data,
            signature: &fixture.signature,
            credential_public_key_cose: &fixture.cose,
            credential_id: b"credential",
            previous_sign_count: 0,
            policy: &policy,
            user_handle,
        })
    };

    let alice = verify_with(Some(b"alice")).expect("alice handle reports");
    assert_eq!(alice.user_handle.as_deref(), Some(b"alice".as_slice()));
    let mallory = verify_with(Some(b"mallory")).expect("mallory handle reports");
    assert_eq!(mallory.user_handle.as_deref(), Some(b"mallory".as_slice()));
    let absent = verify_with(None).expect("absent handle reports");
    assert_eq!(absent.user_handle, None);
}

#[test]
fn given_oversized_user_handle_when_asserting_then_rejects_malformed() {
    let fixture = assertion_fixture();
    let policy = assertion_policy(&fixture);
    let oversized = vec![7_u8; 65];

    assert!(matches!(
        verify_assertion(AssertionInput {
            client_data_json: &fixture.client_data,
            authenticator_data: &fixture.authenticator_data,
            signature: &fixture.signature,
            credential_public_key_cose: &fixture.cose,
            credential_id: b"credential",
            previous_sign_count: 0,
            policy: &policy,
            user_handle: Some(&oversized),
        }),
        Err(WebAuthnError::Malformed)
    ));
    assert!(policy.with_expected_user_handle(&oversized).is_err());
}
