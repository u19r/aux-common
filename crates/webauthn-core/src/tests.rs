use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use sha2::{Digest as _, Sha256};

use super::{
    AssertionInput, AttestationInput, CrossOriginPolicy, RpPolicy, UserVerification, WebAuthnError,
    parse_client_data, parse_cose_key, verify_assertion, verify_none_attestation,
};

const CHALLENGE_B64: &str = "AAAAAAAAAAAAAAAAAAAAAA";

fn policy() -> RpPolicy {
    RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        [0; 32],
        UserVerification::Preferred,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid policy")
}

#[test]
fn given_trailing_cbor_when_parsing_cose_then_reject() {
    let mut input = vec![0xa4, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    input.extend_from_slice(&[0; 32]);
    input.push(0);
    assert!(matches!(
        parse_cose_key(&input),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_indefinite_cbor_container_when_parsing_cose_then_reject() {
    assert!(matches!(
        parse_cose_key(&[0x9f, 0xff]),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_truncated_cbor_length_when_parsing_cose_then_reject() {
    assert!(matches!(
        parse_cose_key(&[0x58]),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_noncanonical_integer_encoding_when_parsing_cose_then_reject() {
    // The map itself is canonical; label 1 is deliberately encoded with an
    // unnecessarily wide integer argument.
    let mut encoded = vec![
        0xa5, 0x18, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20,
    ];
    encoded.extend_from_slice(&[1; 32]);
    encoded.push(0x22);
    encoded.push(0x58);
    encoded.push(0x20);
    encoded.extend_from_slice(&[2; 32]);

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_tagged_cose_value_when_parsing_then_reject() {
    let mut encoded = vec![
        0xd8, 0x18, 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20,
    ];
    encoded.extend_from_slice(&[1; 32]);
    encoded.extend_from_slice(&[0x22, 0x58, 0x20]);
    encoded.extend_from_slice(&[2; 32]);

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::UnsupportedCoseKey | WebAuthnError::Malformed)
    ));
}

#[test]
fn given_oversized_cose_input_when_parsing_then_reject_before_decode() {
    let input = vec![0_u8; super::cbor::MAX_COSE_KEY_BYTES + 1];

    assert!(matches!(
        parse_cose_key(&input),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_non_integer_or_unknown_cose_label_when_parsing_then_reject() {
    use ciborium::value::Value;

    for key in [Value::Text("kty".into()), Value::Integer(4_i64.into())] {
        let value = Value::Map(vec![
            (key, Value::Integer(2_i64.into())),
            (
                Value::Integer(3_i64.into()),
                Value::Integer((-7_i64).into()),
            ),
            (
                Value::Integer((-1_i64).into()),
                Value::Integer(1_i64.into()),
            ),
            (Value::Integer((-2_i64).into()), Value::Bytes(vec![1; 32])),
            (Value::Integer((-3_i64).into()), Value::Bytes(vec![2; 32])),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).expect("encode unsupported COSE label");

        assert!(matches!(
            parse_cose_key(&encoded),
            Err(WebAuthnError::UnsupportedCoseKey | WebAuthnError::Malformed)
        ));
    }
}

#[test]
fn given_invalid_es256_profile_when_parsing_then_reject() {
    use ciborium::value::Value;

    for (kty, alg, curve) in [(3_i64, -7_i64, 1_i64), (2, -8, 1), (2, -7, 2)] {
        let value = Value::Map(vec![
            (Value::Integer(1_i64.into()), Value::Integer(kty.into())),
            (Value::Integer(3_i64.into()), Value::Integer(alg.into())),
            (
                Value::Integer((-1_i64).into()),
                Value::Integer(curve.into()),
            ),
            (Value::Integer((-2_i64).into()), Value::Bytes(vec![1; 32])),
            (Value::Integer((-3_i64).into()), Value::Bytes(vec![2; 32])),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).expect("encode unsupported COSE profile");

        assert!(matches!(
            parse_cose_key(&encoded),
            Err(WebAuthnError::UnsupportedCoseKey)
        ));
    }
}

#[test]
fn given_off_curve_coordinates_when_parsing_then_reject() {
    let input = cose_key(&[0; 32], &[0; 32]);

    assert!(matches!(
        parse_cose_key(&input),
        Err(WebAuthnError::UnsupportedCoseKey)
    ));
}

#[test]
fn given_deeply_nested_cbor_tags_when_parsing_cose_then_reject() {
    let mut encoded = vec![0xc1; 20];
    encoded.push(0);

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_wrong_curve_or_coordinate_size_when_parsing_cose_then_reject() {
    let value = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x02, 0x21, 0x58, 0x20];
    assert!(parse_cose_key(&value).is_err());
}

#[test]
fn given_duplicate_cose_member_when_parsing_then_reject() {
    use ciborium::value::Value;

    let value = Value::Map(vec![
        (Value::Integer(1_i64.into()), Value::Integer(2_i64.into())),
        (Value::Integer(1_i64.into()), Value::Integer(2_i64.into())),
        (
            Value::Integer(3_i64.into()),
            Value::Integer((-7_i64).into()),
        ),
        (
            Value::Integer((-1_i64).into()),
            Value::Integer(1_i64.into()),
        ),
        (Value::Integer((-2_i64).into()), Value::Bytes(vec![1; 32])),
        (Value::Integer((-3_i64).into()), Value::Bytes(vec![2; 32])),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).expect("encode duplicate COSE key");

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_noncanonical_cose_member_order_when_parsing_then_reject() {
    use ciborium::value::Value;

    let value = Value::Map(vec![
        (Value::Integer((-3_i64).into()), Value::Bytes(vec![2; 32])),
        (Value::Integer((-2_i64).into()), Value::Bytes(vec![1; 32])),
        (
            Value::Integer((-1_i64).into()),
            Value::Integer(1_i64.into()),
        ),
        (
            Value::Integer(3_i64.into()),
            Value::Integer((-7_i64).into()),
        ),
        (Value::Integer(1_i64.into()), Value::Integer(2_i64.into())),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).expect("encode noncanonical COSE key");

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_ctap_major_type_order_when_validating_map_then_accept_and_reject_inverse() {
    use ciborium::value::Value;

    let canonical = vec![
        (Value::Integer(24_i64.into()), Value::Null),
        (Value::Text(String::new()), Value::Null),
    ];
    assert!(super::cbor::validate_canonical_map_order(&canonical).is_ok());

    let noncanonical = vec![
        (Value::Text(String::new()), Value::Null),
        (Value::Integer(24_i64.into()), Value::Null),
    ];
    assert!(matches!(
        super::cbor::validate_canonical_map_order(&noncanonical),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_oversized_unknown_cose_member_when_parsing_then_reject_before_decoding_it() {
    use ciborium::value::Value;

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
        (Value::Integer((-2_i64).into()), Value::Bytes(vec![1; 32])),
        (Value::Integer((-3_i64).into()), Value::Bytes(vec![2; 32])),
        (Value::Integer(4_i64.into()), Value::Bytes(vec![0; 1024])),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).expect("encode COSE key");
    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_policy_when_constructing_then_expected_origin_is_caller_owned() {
    assert_eq!(policy().expected_origin(), "https://example.test");
}

#[test]
fn given_non_loopback_http_origin_when_constructing_policy_then_reject() {
    assert!(matches!(
        RpPolicy::try_new(
            CHALLENGE_B64,
            "http://attacker.example",
            [0; 32],
            UserVerification::Preferred,
            CrossOriginPolicy::Disallowed,
        ),
        Err(WebAuthnError::InvalidPolicy)
    ));
}

#[test]
fn given_loopback_http_origin_when_constructing_policy_then_accept() {
    for origin in [
        "http://localhost",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://[::1]:3000",
    ] {
        assert!(
            RpPolicy::try_new(
                CHALLENGE_B64,
                origin,
                [0; 32],
                UserVerification::Preferred,
                CrossOriginPolicy::Disallowed,
            )
            .is_ok(),
            "loopback origin should be accepted: {origin}"
        );
    }
}

#[test]
fn given_private_or_non_loopback_http_origin_when_constructing_policy_then_reject() {
    for origin in [
        "http://10.0.0.1",
        "http://192.168.1.1",
        "http://169.254.169.254",
        "http://0.0.0.0",
        "http://[::ffff:127.0.0.1]",
        "http://localhost.attacker.example",
    ] {
        assert!(
            RpPolicy::try_new(
                CHALLENGE_B64,
                origin,
                [0; 32],
                UserVerification::Preferred,
                CrossOriginPolicy::Disallowed,
            )
            .is_err(),
            "non-loopback HTTP origin should be rejected: {origin}"
        );
    }
}

#[test]
fn given_short_challenge_when_constructing_policy_then_reject() {
    // Fifteen zero bytes is canonical base64url but below WebAuthn's
    // required 16-byte challenge minimum.
    assert!(matches!(
        RpPolicy::try_new(
            "AAAAAAAAAAAAAAAAAAAA",
            "https://example.test",
            [0; 32],
            UserVerification::Preferred,
            CrossOriginPolicy::Disallowed,
        ),
        Err(WebAuthnError::InvalidPolicy)
    ));
}

#[test]
fn given_duplicate_client_data_members_when_parsing_then_reject() {
    let json = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.test","crossOrigin":false}"#;
    assert!(matches!(
        parse_client_data(json, "webauthn.get", &policy()),
        Err(WebAuthnError::ClientData)
    ));
}

#[test]
fn given_cross_origin_client_data_when_top_origin_is_not_allowlisted_then_reject() {
    let json = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.test","crossOrigin":true,"topOrigin":"https://parent.test"}"#;
    assert!(matches!(
        parse_client_data(json, "webauthn.get", &policy()),
        Err(WebAuthnError::OriginMismatch)
    ));
}

#[test]
fn given_allowlisted_cross_origin_client_data_then_normalize_top_origin() {
    let policy = RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        [0; 32],
        UserVerification::Preferred,
        CrossOriginPolicy::AllowedOrigins(vec!["https://PARENT.test/".to_string()]),
    )
    .expect("valid cross-origin policy");
    let json = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://EXAMPLE.test/","crossOrigin":true,"topOrigin":"https://PARENT.test/"}"#;
    let client_data = parse_client_data(json, "webauthn.get", &policy).expect("client data");
    assert_eq!(client_data.origin, "https://example.test");
    assert_eq!(
        client_data.top_origin.as_deref(),
        Some("https://parent.test")
    );
}

#[test]
fn given_cross_origin_client_data_with_same_top_origin_then_reject() {
    let policy = RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        [0; 32],
        UserVerification::Preferred,
        CrossOriginPolicy::AllowedOrigins(vec!["https://example.test".to_string()]),
    )
    .expect("valid cross-origin policy");
    let json = br#"{"origin":"https://example.test","crossOrigin":true,"challenge":"AAAAAAAAAAAAAAAAAAAAAA","type":"webauthn.get","topOrigin":"https://example.test"}"#;

    assert!(matches!(
        parse_client_data(json, "webauthn.get", &policy),
        Err(WebAuthnError::OriginMismatch)
    ));
}

#[test]
fn given_remote_http_client_data_when_policy_is_secure_then_reject() {
    let json = br#"{"origin":"http://attacker.example","crossOrigin":false,"challenge":"AAAAAAAAAAAAAAAAAAAAAA","type":"webauthn.get"}"#;

    assert!(matches!(
        parse_client_data(json, "webauthn.get", &policy()),
        Err(WebAuthnError::OriginMismatch)
    ));
}

#[test]
fn given_loopback_http_client_data_when_policy_matches_then_accept() {
    let loopback_policy = RpPolicy::try_new(
        CHALLENGE_B64,
        "http://LOCALHOST:3000/",
        [0; 32],
        UserVerification::Preferred,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid loopback policy");
    let json = br#"{"origin":"http://localhost:3000/","crossOrigin":false,"challenge":"AAAAAAAAAAAAAAAAAAAAAA","type":"webauthn.get"}"#;

    let parsed = parse_client_data(json, "webauthn.get", &loopback_policy)
        .expect("loopback client data should be accepted");
    assert_eq!(parsed.origin, "http://localhost:3000");
}

#[test]
fn given_oversized_expected_challenge_when_constructing_policy_then_reject_before_decode() {
    assert!(matches!(
        RpPolicy::try_new(
            "A".repeat(1 << 20),
            "https://example.test",
            [0; 32],
            UserVerification::Preferred,
            CrossOriginPolicy::Disallowed,
        ),
        Err(WebAuthnError::InvalidPolicy)
    ));
}

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
fn given_valid_none_attestation_when_verifying_then_return_credential_material() {
    let fixture = attestation_fixture();
    let policy = attestation_policy(&fixture);

    let result = verify_none_attestation(AttestationInput {
        client_data_json: &fixture.client_data,
        attestation_object: &fixture.attestation_object,
        policy: &policy,
    })
    .expect("valid none attestation");

    assert_eq!(result.credential_id, b"credential");
    assert_eq!(result.public_key.algorithm, -7);
    assert_eq!(result.public_key.curve, 1);
}

#[test]
fn given_attestation_with_unknown_root_member_when_verifying_then_reject() {
    use ciborium::value::Value;

    let fixture = attestation_fixture();
    let mut value: Value =
        ciborium::de::from_reader(fixture.attestation_object.as_slice()).expect("decode fixture");
    let Value::Map(entries) = &mut value else {
        panic!("fixture root must be a map");
    };
    entries.insert(2, (Value::Text("unknown".into()), Value::Null));
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).expect("encode unknown-member fixture");
    let policy = attestation_policy(&fixture);

    assert!(matches!(
        verify_none_attestation(AttestationInput {
            client_data_json: &fixture.client_data,
            attestation_object: &encoded,
            policy: &policy,
        }),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_duplicate_attestation_root_member_when_verifying_then_reject() {
    use ciborium::value::Value;

    let fixture = attestation_fixture();
    let value: Value =
        ciborium::de::from_reader(fixture.attestation_object.as_slice()).expect("decode fixture");
    let Value::Map(mut entries) = value else {
        panic!("fixture root must be a map");
    };
    entries.push((Value::Text("fmt".into()), Value::Text("none".into())));
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut encoded)
        .expect("encode duplicate-member fixture");
    let policy = attestation_policy(&fixture);

    assert!(matches!(
        verify_none_attestation(AttestationInput {
            client_data_json: &fixture.client_data,
            attestation_object: &encoded,
            policy: &policy,
        }),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_attestation_with_trailing_cbor_when_verifying_then_reject() {
    let fixture = attestation_fixture();
    let mut encoded = fixture.attestation_object.clone();
    encoded.push(0);
    let policy = attestation_policy(&fixture);

    assert!(matches!(
        verify_none_attestation(AttestationInput {
            client_data_json: &fixture.client_data,
            attestation_object: &encoded,
            policy: &policy,
        }),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_deeply_nested_attestation_cbor_when_verifying_then_reject() {
    let fixture = attestation_fixture();
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&nested_array_value(20), &mut encoded)
        .expect("encode nested attestation");
    let policy = attestation_policy(&fixture);

    assert!(matches!(
        verify_none_attestation(AttestationInput {
            client_data_json: &fixture.client_data,
            attestation_object: &encoded,
            policy: &policy,
        }),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_attestation_without_required_user_verification_when_verifying_then_reject() {
    let fixture = attestation_fixture();
    let policy = RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        fixture.rp_id_hash,
        UserVerification::Required,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid policy");

    assert!(matches!(
        verify_none_attestation(AttestationInput {
            client_data_json: &fixture.client_data,
            attestation_object: &fixture.attestation_object,
            policy: &policy,
        }),
        Err(WebAuthnError::UserVerificationRequired)
    ));
}

#[test]
fn given_trailing_assertion_authenticator_bytes_when_verifying_then_reject() {
    let mut bytes = vec![0; 38];
    bytes[32] = 0x01;
    assert!(matches!(
        super::assertion::parse_authenticator_data(
            &bytes,
            &[0; 32],
            false,
            UserVerification::Preferred
        ),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_missing_user_presence_when_parsing_authenticator_data_then_reject() {
    assert!(matches!(
        super::assertion::parse_authenticator_data(
            &[0; 37],
            &[0; 32],
            false,
            UserVerification::Preferred,
        ),
        Err(WebAuthnError::UserPresenceMissing)
    ));
}

#[test]
fn given_backup_state_without_backup_eligibility_when_parsing_then_reject() {
    let mut bytes = vec![0_u8; 37];
    bytes[32] = 0x11;

    assert!(matches!(
        super::assertion::parse_authenticator_data(
            &bytes,
            &[0; 32],
            false,
            UserVerification::Preferred,
        ),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_counter_pairs_when_classifying_then_return_documented_status() {
    assert_eq!(
        super::assertion::classify_counter(0, 4),
        super::SignCountStatus::Initial { value: 4 }
    );
    assert_eq!(
        super::assertion::classify_counter(4, 5),
        super::SignCountStatus::Increased {
            previous: 4,
            current: 5,
        }
    );
    assert_eq!(
        super::assertion::classify_counter(4, 4),
        super::SignCountStatus::Unchanged { value: 4 }
    );
    assert_eq!(
        super::assertion::classify_counter(5, 4),
        super::SignCountStatus::Regression {
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
        }),
        Err(WebAuthnError::InvalidSignature)
    ));
}

#[test]
fn given_arbitrary_short_bytes_when_parsing_cose_then_never_panic() {
    for length in 0..=64 {
        let input = (0..length).map(|value| value as u8).collect::<Vec<_>>();
        let result = std::panic::catch_unwind(|| parse_cose_key(&input));

        assert!(result.is_ok(), "parser panicked for length {length}");
    }
}

fn cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    use ciborium::value::Value;
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
        (Value::Integer((-2_i64).into()), Value::Bytes(x.to_vec())),
        (Value::Integer((-3_i64).into()), Value::Bytes(y.to_vec())),
    ]);
    let mut output = Vec::new();
    ciborium::ser::into_writer(&value, &mut output).expect("encode COSE key");
    output
}

fn nested_array_value(depth: usize) -> ciborium::value::Value {
    if depth == 0 {
        ciborium::value::Value::Integer(0_i64.into())
    } else {
        ciborium::value::Value::Array(vec![nested_array_value(depth - 1)])
    }
}

struct AssertionFixture {
    client_data: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
    cose: Vec<u8>,
    rp_id_hash: [u8; 32],
}

fn assertion_fixture() -> AssertionFixture {
    let signing_key = SigningKey::from_bytes((&[42_u8; 32]).into()).expect("signing key");
    let point = signing_key.verifying_key().to_sec1_point(false);
    let x = point.x().expect("x");
    let y = point.y().expect("y");
    let cose = cose_key(x, y);
    let client_data =
        br#"{"origin":"https://example.test","crossOrigin":false,"challenge":"AAAAAAAAAAAAAAAAAAAAAA","type":"webauthn.get"}"#
            .to_vec();
    let rp_id_hash: [u8; 32] = Sha256::digest(b"example.test").into();
    let mut authenticator_data = Vec::new();
    authenticator_data.extend_from_slice(&rp_id_hash);
    authenticator_data.extend_from_slice(&[0x01, 0, 0, 0, 5]);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let signature: Signature = signing_key.sign(&signed);

    AssertionFixture {
        client_data,
        authenticator_data,
        signature: signature.to_der().as_bytes().to_vec(),
        cose,
        rp_id_hash,
    }
}

fn assertion_policy(fixture: &AssertionFixture) -> RpPolicy {
    RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        fixture.rp_id_hash,
        UserVerification::Preferred,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid policy")
}

struct AttestationFixture {
    client_data: Vec<u8>,
    attestation_object: Vec<u8>,
    rp_id_hash: [u8; 32],
}

fn attestation_fixture() -> AttestationFixture {
    use ciborium::value::Value;

    let signing_key = SigningKey::from_bytes((&[42_u8; 32]).into()).expect("signing key");
    let point = signing_key.verifying_key().to_sec1_point(false);
    let x = point.x().expect("x");
    let y = point.y().expect("y");
    let cose = cose_key(x, y);
    let rp_id_hash: [u8; 32] = Sha256::digest(b"example.test").into();
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.extend_from_slice(&[0x41, 0, 0, 0, 0]);
    auth_data.extend_from_slice(&[0_u8; 16]);
    auth_data.extend_from_slice(&(10_u16.to_be_bytes()));
    auth_data.extend_from_slice(b"credential");
    auth_data.extend_from_slice(&cose);
    let attestation = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(Vec::new())),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]);
    let mut attestation_object = Vec::new();
    ciborium::ser::into_writer(&attestation, &mut attestation_object).expect("encode attestation");
    let client_data = br#"{"origin":"https://example.test","crossOrigin":false,"challenge":"AAAAAAAAAAAAAAAAAAAAAA","type":"webauthn.create"}"#
        .to_vec();

    AttestationFixture {
        client_data,
        attestation_object,
        rp_id_hash,
    }
}

fn attestation_policy(fixture: &AttestationFixture) -> RpPolicy {
    RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        fixture.rp_id_hash,
        UserVerification::Preferred,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid policy")
}
