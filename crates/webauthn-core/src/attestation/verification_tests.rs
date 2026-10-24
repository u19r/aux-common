use super::verify_none_attestation;
use crate::{
    AttestationInput, CrossOriginPolicy, RpPolicy, UserVerification, WebAuthnError,
    assertion::{CHALLENGE_B64, attestation_fixture, attestation_policy, nested_array_value},
};

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
