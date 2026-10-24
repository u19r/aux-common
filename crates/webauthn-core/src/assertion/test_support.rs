use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use sha2::{Digest as _, Sha256};

use crate::{CrossOriginPolicy, RpPolicy, UserVerification};

pub(crate) const CHALLENGE_B64: &str = "AAAAAAAAAAAAAAAAAAAAAA";

pub(crate) fn policy() -> RpPolicy {
    RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        [0; 32],
        UserVerification::Preferred,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid policy")
}
pub(crate) fn cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
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

pub(crate) fn nested_array_value(depth: usize) -> ciborium::value::Value {
    if depth == 0 {
        ciborium::value::Value::Integer(0_i64.into())
    } else {
        ciborium::value::Value::Array(vec![nested_array_value(depth - 1)])
    }
}

pub(crate) struct AssertionFixture {
    pub(crate) client_data: Vec<u8>,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) cose: Vec<u8>,
    pub(crate) rp_id_hash: [u8; 32],
}

pub(crate) fn assertion_fixture() -> AssertionFixture {
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

pub(crate) fn assertion_policy(fixture: &AssertionFixture) -> RpPolicy {
    RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        fixture.rp_id_hash,
        UserVerification::Preferred,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid policy")
}

pub(crate) struct AttestationFixture {
    pub(crate) client_data: Vec<u8>,
    pub(crate) attestation_object: Vec<u8>,
    pub(crate) rp_id_hash: [u8; 32],
}

pub(crate) fn attestation_fixture() -> AttestationFixture {
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

pub(crate) fn attestation_policy(fixture: &AttestationFixture) -> RpPolicy {
    RpPolicy::try_new(
        CHALLENGE_B64,
        "https://example.test",
        fixture.rp_id_hash,
        UserVerification::Preferred,
        CrossOriginPolicy::Disallowed,
    )
    .expect("valid policy")
}
