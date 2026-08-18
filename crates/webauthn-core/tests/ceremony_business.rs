use ciborium::value::Value;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use sha2::{Digest as _, Sha256};
use webauthn_core::{
    AssertionInput, AttestationInput, CrossOriginPolicy, RpPolicy, SignCountStatus,
    UserVerification, WebAuthnError, parse_client_data, parse_cose_key, verify_assertion,
    verify_none_attestation,
};

const CHALLENGE_B64: &str = "AAAAAAAAAAAAAAAAAAAAAA";

// Given a canonical none-attestation with a valid ES256 credential and the
// expected RP/origin policy
//
// When registration verification runs
//
// Then the credential public key and parsed authenticator data are returned
#[test]
fn given_valid_none_attestation_when_registering_then_return_credential_material() {
    let fixture = CeremonyFixture::new();
    let policy = fixture.policy(UserVerification::Preferred, CrossOriginPolicy::Disallowed);

    let result = verify_none_attestation(AttestationInput {
        client_data_json: &fixture.registration_client_data,
        attestation_object: &fixture.attestation_object,
        policy: &policy,
    })
    .expect("valid registration");

    assert_eq!(result.credential_id, b"credential");
    assert_eq!(result.public_key.algorithm, -7);
    assert_eq!(result.public_key.curve, 1);
    assert_eq!(result.aaguid, [0; 16]);
    assert_eq!(result.sign_count, 0);
    assert!(!result.user_verified);
}

// Given an attestation object with an unsupported format
//
// When registration verification runs
//
// Then registration fails without partial success
#[test]
fn given_unsupported_attestation_format_when_registering_then_reject() {
    let fixture = CeremonyFixture::new();
    let policy = fixture.policy(UserVerification::Preferred, CrossOriginPolicy::Disallowed);
    let unsupported = fixture.attestation_object_with_format("packed");

    assert!(matches!(
        verify_none_attestation(AttestationInput {
            client_data_json: &fixture.registration_client_data,
            attestation_object: &unsupported,
            policy: &policy,
        }),
        Err(WebAuthnError::UnsupportedAttestation)
    ));
}

// Given registration flags without user verification while UV is required
//
// When registration verification runs
//
// Then the ceremony is rejected by policy
#[test]
fn given_uv_required_without_uv_when_registering_then_reject() {
    let fixture = CeremonyFixture::new();
    let policy = fixture.policy(UserVerification::Required, CrossOriginPolicy::Disallowed);

    assert!(matches!(
        verify_none_attestation(AttestationInput {
            client_data_json: &fixture.registration_client_data,
            attestation_object: &fixture.attestation_object,
            policy: &policy,
        }),
        Err(WebAuthnError::UserVerificationRequired)
    ));
}

// Given valid client data, RP-bound authenticator data, a DER signature, and a
// caller-supplied key
//
// When assertion verification runs
//
// Then it returns a successful assertion result and counter status
#[test]
fn given_valid_assertion_when_verifying_then_return_result_and_counter() {
    let fixture = CeremonyFixture::new();
    let policy = fixture.policy(UserVerification::Preferred, CrossOriginPolicy::Disallowed);

    let result = verify_assertion(AssertionInput {
        client_data_json: fixture.assertion_client_data.as_bytes(),
        authenticator_data: &fixture.assertion_authenticator_data,
        signature: &fixture.assertion_signature,
        credential_public_key_cose: &fixture.cose_key,
        credential_id: b"credential",
        previous_sign_count: 4,
        policy: &policy,
    })
    .expect("valid assertion");

    assert_eq!(result.credential_id, b"credential");
    assert_eq!(result.sign_count, 5);
    assert_eq!(
        result.sign_count_status,
        SignCountStatus::Increased {
            previous: 4,
            current: 5,
        }
    );
    assert!(!result.user_verified);
}

// Given assertion client data with a changed challenge
//
// When assertion verification runs
//
// Then it rejects the ceremony without returning success
#[test]
fn given_changed_challenge_when_asserting_then_reject_without_success() {
    let fixture = CeremonyFixture::new();
    let policy = fixture.policy(UserVerification::Preferred, CrossOriginPolicy::Disallowed);
    let changed_client_data = fixture
        .assertion_client_data
        .replace(CHALLENGE_B64, "AQAAAAAAAAAAAAAAAAAAAA");

    assert!(matches!(
        verify_assertion(AssertionInput {
            client_data_json: changed_client_data.as_bytes(),
            authenticator_data: &fixture.assertion_authenticator_data,
            signature: &fixture.assertion_signature,
            credential_public_key_cose: &fixture.cose_key,
            credential_id: b"credential",
            previous_sign_count: 4,
            policy: &policy,
        }),
        Err(WebAuthnError::ChallengeMismatch)
    ));
}

// Given each prior/current sign-count pair
//
// When assertion verification runs
//
// Then it returns Initial, Increased, Unchanged, or Regression exactly as
// documented
#[test]
fn given_each_counter_transition_when_asserting_then_return_status() {
    let fixture = CeremonyFixture::new();
    let policy = fixture.policy(UserVerification::Preferred, CrossOriginPolicy::Disallowed);
    for (previous, expected) in [
        (0, SignCountStatus::Initial { value: 5 }),
        (
            4,
            SignCountStatus::Increased {
                previous: 4,
                current: 5,
            },
        ),
        (5, SignCountStatus::Unchanged { value: 5 }),
        (
            6,
            SignCountStatus::Regression {
                previous: 6,
                current: 5,
            },
        ),
    ] {
        let result = verify_assertion(AssertionInput {
            client_data_json: fixture.assertion_client_data.as_bytes(),
            authenticator_data: &fixture.assertion_authenticator_data,
            signature: &fixture.assertion_signature,
            credential_public_key_cose: &fixture.cose_key,
            credential_id: b"credential",
            previous_sign_count: previous,
            policy: &policy,
        })
        .expect("valid assertion counter transition");
        assert_eq!(result.sign_count_status, expected);
    }
}

// Given same-origin client data and a disallowed cross-origin policy
//
// When client data is parsed
//
// Then it is accepted
#[test]
fn given_same_origin_when_parsing_client_data_then_accept() {
    let fixture = CeremonyFixture::new();
    let policy = fixture.policy(UserVerification::Preferred, CrossOriginPolicy::Disallowed);

    let client_data = parse_client_data(
        fixture.assertion_client_data.as_bytes(),
        "webauthn.get",
        &policy,
    )
    .expect("same-origin client data");

    assert_eq!(client_data.origin, "https://example.test");
    assert!(!client_data.cross_origin);
    assert_eq!(client_data.top_origin, None);
}

// Given cross-origin client data and a disallowed cross-origin policy
//
// When client data is parsed
//
// Then it is rejected
#[test]
fn given_cross_origin_when_disallowed_then_reject() {
    let fixture = CeremonyFixture::new();
    let policy = fixture.policy(UserVerification::Preferred, CrossOriginPolicy::Disallowed);
    let client_data = client_data_json("https://example.test", true, Some("https://parent.test"));

    assert!(matches!(
        parse_client_data(client_data.as_bytes(), "webauthn.get", &policy),
        Err(WebAuthnError::OriginMismatch)
    ));
}

// Given cross-origin client data and a normalized allowlist containing the top
// origin
//
// When client data is parsed
//
// Then it is accepted with normalized origins
#[test]
fn given_allowlisted_cross_origin_when_normalized_then_accept() {
    let fixture = CeremonyFixture::new();
    let policy = fixture.policy(
        UserVerification::Preferred,
        CrossOriginPolicy::AllowedOrigins(vec!["https://PARENT.test/".to_string()]),
    );
    let client_data = client_data_json("https://EXAMPLE.test/", true, Some("https://PARENT.test/"));

    let parsed = parse_client_data(client_data.as_bytes(), "webauthn.get", &policy)
        .expect("allowlisted cross-origin client data");

    assert_eq!(parsed.origin, "https://example.test");
    assert_eq!(parsed.top_origin.as_deref(), Some("https://parent.test"));
}

// Given a COSE input larger than the configured byte budget
//
// When the public parser is called
//
// Then it rejects before unbounded recursive allocation
#[test]
fn given_oversized_cose_input_when_verifying_then_reject_within_budget() {
    let oversized = vec![0_u8; 1025];

    assert!(matches!(
        parse_cose_key(&oversized),
        Err(WebAuthnError::Malformed)
    ));
}

struct CeremonyFixture {
    cose_key: Vec<u8>,
    registration_client_data: Vec<u8>,
    assertion_client_data: String,
    assertion_authenticator_data: Vec<u8>,
    assertion_signature: Vec<u8>,
    attestation_object: Vec<u8>,
    rp_id_hash: [u8; 32],
}

impl CeremonyFixture {
    fn new() -> Self {
        let signing_key = SigningKey::from_bytes((&[42_u8; 32]).into()).expect("signing key");
        let point = signing_key.verifying_key().to_sec1_point(false);
        let cose_key = cose_key(
            point.x().expect("x coordinate"),
            point.y().expect("y coordinate"),
        );
        let rp_id_hash: [u8; 32] = Sha256::digest(b"example.test").into();
        let assertion_client_data = client_data_json("https://example.test", false, None);
        let mut assertion_authenticator_data = rp_id_hash.to_vec();
        assertion_authenticator_data.extend_from_slice(&[0x01, 0, 0, 0, 5]);
        let mut signed = assertion_authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(assertion_client_data.as_bytes()));
        let signature: Signature = signing_key.sign(&signed);
        let registration_client_data = client_data_json("https://example.test", false, None)
            .replace("webauthn.get", "webauthn.create")
            .into_bytes();
        let auth_data = attested_authenticator_data(rp_id_hash, &cose_key);
        let attestation_object = attestation_object("none", auth_data);

        Self {
            cose_key,
            registration_client_data,
            assertion_client_data,
            assertion_authenticator_data,
            assertion_signature: signature.to_der().as_bytes().to_vec(),
            attestation_object,
            rp_id_hash,
        }
    }

    fn policy(
        &self,
        user_verification: UserVerification,
        cross_origin: CrossOriginPolicy,
    ) -> RpPolicy {
        RpPolicy::try_new(
            CHALLENGE_B64,
            "https://example.test",
            self.rp_id_hash,
            user_verification,
            cross_origin,
        )
        .expect("valid relying-party policy")
    }

    fn attestation_object_with_format(&self, format: &str) -> Vec<u8> {
        let Value::Map(mut entries) =
            ciborium::de::from_reader(self.attestation_object.as_slice()).expect("decode object")
        else {
            panic!("fixture object must be a map");
        };
        let Some((_, value)) = entries
            .iter_mut()
            .find(|(key, _)| matches!(key, Value::Text(key) if key == "fmt"))
        else {
            panic!("fixture object must contain fmt");
        };
        *value = Value::Text(format.to_string());
        let mut output = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut output).expect("encode object");
        output
    }
}

fn client_data_json(origin: &str, cross_origin: bool, top_origin: Option<&str>) -> String {
    let mut json = format!(
        r#"{{"origin":"{origin}","crossOrigin":{cross_origin},"challenge":"{CHALLENGE_B64}","type":"webauthn.get""#
    );
    if let Some(top_origin) = top_origin {
        json.push_str(&format!(r#","topOrigin":"{top_origin}"}}"#));
    } else {
        json.push('}');
    }
    json
}

fn cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
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

fn attested_authenticator_data(rp_id_hash: [u8; 32], cose_key: &[u8]) -> Vec<u8> {
    let mut auth_data = rp_id_hash.to_vec();
    auth_data.extend_from_slice(&[0x41, 0, 0, 0, 0]);
    auth_data.extend_from_slice(&[0; 16]);
    auth_data.extend_from_slice(&(10_u16.to_be_bytes()));
    auth_data.extend_from_slice(b"credential");
    auth_data.extend_from_slice(cose_key);
    auth_data
}

fn attestation_object(format: &str, auth_data: Vec<u8>) -> Vec<u8> {
    let value = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text(format.to_string())),
        (Value::Text("attStmt".into()), Value::Map(Vec::new())),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]);
    let mut output = Vec::new();
    ciborium::ser::into_writer(&value, &mut output).expect("encode attestation object");
    output
}
