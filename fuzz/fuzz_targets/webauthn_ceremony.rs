#![no_main]

use libfuzzer_sys::fuzz_target;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use sha2::{Digest as _, Sha256};
use webauthn_core::{
    AssertionInput, AttestationInput, CrossOriginPolicy, RpPolicy, UserVerification,
    parse_client_data, verify_assertion, verify_none_attestation,
};

// Structured decision oracle for WebAuthn ceremonies.
//
// Seeds are fully valid assertion and `none`-attestation ceremonies minted
// with a fixed test key through the same cryptographic steps a real
// authenticator performs. Every byte-driven edit models an attacker move:
// origin, challenge, or type substitution, flag manipulation, counter games,
// credential and key tampering, CBOR smuggling, and truncation. The oracle:
// verification may only reproduce the seed result when every non-client-data
// input is byte-identical and the client data keeps its security semantics
// (type, challenge, cross-origin posture). Origin spellings erased by WHATWG
// URL normalization are accepted as equivalent, exactly as browsers parse
// them; any other equal-result verification is ceremony confusion.
const CHALLENGE_B64: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const ORIGIN: &str = "https://example.test";
const RP_ID: &[u8] = b"example.test";
const CREDENTIAL_ID: &[u8] = b"credential";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes((&[42_u8; 32]).into()).expect("test signing key")
}

fn cose_key() -> Vec<u8> {
    use ciborium::value::Value;
    let key = signing_key();
    let point = key.verifying_key().to_sec1_point(false);
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
            Value::Bytes(point.x().expect("x").to_vec()),
        ),
        (
            Value::Integer((-3_i64).into()),
            Value::Bytes(point.y().expect("y").to_vec()),
        ),
    ]);
    let mut output = Vec::new();
    ciborium::ser::into_writer(&value, &mut output).expect("encode COSE key");
    output
}

fn rp_id_hash() -> [u8; 32] {
    Sha256::digest(RP_ID).into()
}

fn policy() -> RpPolicy {
    RpPolicy::try_new(
        CHALLENGE_B64,
        ORIGIN,
        rp_id_hash(),
        UserVerification::Preferred,
        CrossOriginPolicy::Disallowed,
    )
    .expect("policy builds")
}

struct AssertionSeed {
    client_data: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
    cose: Vec<u8>,
    credential_id: Vec<u8>,
}

fn assertion_seed() -> AssertionSeed {
    let client_data =
        br#"{"origin":"https://example.test","crossOrigin":false,"challenge":"AAAAAAAAAAAAAAAAAAAAAA","type":"webauthn.get"}"#
            .to_vec();
    let mut authenticator_data = Vec::new();
    authenticator_data.extend_from_slice(&rp_id_hash());
    authenticator_data.extend_from_slice(&[0x01, 0, 0, 0, 5]);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let signature: Signature = signing_key().sign(&signed);
    let signature = signature.to_der().as_bytes().to_vec();
    AssertionSeed {
        client_data,
        authenticator_data,
        signature,
        cose: cose_key(),
        credential_id: CREDENTIAL_ID.to_vec(),
    }
}

struct AttestationSeed {
    client_data: Vec<u8>,
    attestation_object: Vec<u8>,
}

fn attestation_seed() -> AttestationSeed {
    use ciborium::value::Value;
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&rp_id_hash());
    auth_data.extend_from_slice(&[0x41, 0, 0, 0, 0]);
    auth_data.extend_from_slice(&[0_u8; 16]);
    auth_data.extend_from_slice(&10_u16.to_be_bytes());
    auth_data.extend_from_slice(CREDENTIAL_ID);
    auth_data.extend_from_slice(&cose_key());
    let attestation = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(Vec::new())),
        (Value::Text("authData".into()), Value::Bytes(auth_data)),
    ]);
    let mut attestation_object = Vec::new();
    ciborium::ser::into_writer(&attestation, &mut attestation_object).expect("encode attestation");
    let client_data =
        br#"{"origin":"https://example.test","crossOrigin":false,"challenge":"AAAAAAAAAAAAAAAAAAAAAA","type":"webauthn.create"}"#
            .to_vec();
    AttestationSeed {
        client_data,
        attestation_object,
    }
}

fn flip_byte(vector: &mut [u8], position: usize, argument: u8) {
    if vector.is_empty() {
        return;
    }
    let index = position % vector.len();
    vector[index] ^= argument | 1;
}

fn truncate_vector(vector: &mut Vec<u8>, position: usize) {
    vector.truncate(position % (vector.len() + 1));
}

fn substitute(vector: &mut Vec<u8>, from: &[u8], to: &[u8]) {
    if let Some(position) = find_subslice(vector, from) {
        vector.splice(position..position + from.len(), to.iter().copied());
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Security-relevant client-data semantics, compared through the public
/// parser. The origin spelling is deliberately exempt: WHATWG URL
/// normalization erases distinctions such as `/` versus `\`, so two
/// spellings can verify identically without confusing ceremonies. Origin
/// *mismatch* (different normalized origins) still fails closed inside
/// verification, and the deterministic suite pins rejection of wrong,
/// remote, and non-allowlisted origins.
fn client_data_semantics_equal(
    mutated: &[u8],
    seed: &[u8],
    expected_type: &str,
    policy: &RpPolicy,
) -> bool {
    match (
        parse_client_data(mutated, expected_type, policy),
        parse_client_data(seed, expected_type, policy),
    ) {
        (Ok(current), Ok(expected)) => {
            current.ceremony_type == expected.ceremony_type
                && current.challenge == expected.challenge
                && current.cross_origin == expected.cross_origin
                && current.top_origin == expected.top_origin
        }
        _ => false,
    }
}

fn apply_assertion_edit(seed: &mut AssertionSeed, op: u8, position: usize, argument: u8) {
    match op % 10 {
        0 => flip_byte(&mut seed.client_data, position, argument),
        1 => flip_byte(&mut seed.authenticator_data, position, argument),
        2 => flip_byte(&mut seed.signature, position, argument),
        3 => flip_byte(&mut seed.cose, position, argument),
        4 => flip_byte(&mut seed.credential_id, position, argument),
        5 => {
            // Same-length origin, type, and challenge substitutions.
            substitute(&mut seed.client_data, b"example.test", b"evil.test!!!");
            substitute(&mut seed.client_data, b"webauthn.get", b"webauthn.pay");
            substitute(&mut seed.client_data, b"AAAA", b"BBBB");
        }
        6 => {
            // Authenticator flag and counter games.
            if seed.authenticator_data.len() > 33 {
                seed.authenticator_data[32] ^= argument | 1;
            }
            if seed.authenticator_data.len() >= 37 {
                seed.authenticator_data[33..37].copy_from_slice(&u32::MAX.to_be_bytes());
            }
        }
        7 => {
            // Duplicate a client-data member, probing duplicate-key handling.
            if let Some(position) = find_subslice(&seed.client_data, b"\"crossOrigin\"") {
                let injection = b"\"crossOrigin\":true,".to_vec();
                seed.client_data.splice(position..position, injection);
            }
        }
        8 => truncate_vector(&mut seed.client_data, position),
        _ => truncate_vector(&mut seed.authenticator_data, position),
    }
}

fn apply_attestation_edit(seed: &mut AttestationSeed, op: u8, position: usize, argument: u8) {
    match op % 6 {
        0 => flip_byte(&mut seed.client_data, position, argument),
        1 => flip_byte(&mut seed.attestation_object, position, argument),
        2 => {
            substitute(&mut seed.client_data, b"example.test", b"evil.test!!!");
            substitute(
                &mut seed.client_data,
                b"webauthn.create",
                b"webauthn.delete",
            );
        }
        3 => truncate_vector(&mut seed.client_data, position),
        4 => truncate_vector(&mut seed.attestation_object, position),
        _ => seed.attestation_object.clear(),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let policy = policy();
    if data[0].is_multiple_of(2) {
        let seed = assertion_seed();
        let seed_result = verify_assertion(AssertionInput {
            client_data_json: &seed.client_data,
            authenticator_data: &seed.authenticator_data,
            signature: &seed.signature,
            credential_public_key_cose: &seed.cose,
            credential_id: &seed.credential_id,
            previous_sign_count: 0,
            policy: &policy,
            user_handle: None,
        })
        .expect("seed assertion must verify");
        let mut mutated = assertion_seed();
        let mut cursor = 1;
        let mut edits = 0;
        while edits < 8 && cursor + 4 <= data.len() {
            let position = u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
            apply_assertion_edit(&mut mutated, data[cursor], position, data[cursor + 3]);
            cursor += 4;
            edits += 1;
        }
        if mutated.client_data == seed.client_data
            && mutated.authenticator_data == seed.authenticator_data
            && mutated.signature == seed.signature
            && mutated.cose == seed.cose
            && mutated.credential_id == seed.credential_id
        {
            return;
        }
        let result = verify_assertion(AssertionInput {
            client_data_json: &mutated.client_data,
            authenticator_data: &mutated.authenticator_data,
            signature: &mutated.signature,
            credential_public_key_cose: &mutated.cose,
            credential_id: &mutated.credential_id,
            previous_sign_count: 0,
            policy: &policy,
            user_handle: None,
        });
        match result {
            Err(_) => {}
            Ok(current) if current != seed_result => {}
            Ok(_) => {
                let hard_inputs_unchanged = mutated.authenticator_data == seed.authenticator_data
                    && mutated.signature == seed.signature
                    && mutated.cose == seed.cose
                    && mutated.credential_id == seed.credential_id;
                assert!(
                    hard_inputs_unchanged
                        && client_data_semantics_equal(
                            &mutated.client_data,
                            &seed.client_data,
                            "webauthn.get",
                            &policy
                        ),
                    "ceremony confusion: mutated assertion verified like the seed"
                );
            }
        }
    } else {
        let seed = attestation_seed();
        let seed_result = verify_none_attestation(AttestationInput {
            client_data_json: &seed.client_data,
            attestation_object: &seed.attestation_object,
            policy: &policy,
        })
        .expect("seed attestation must verify");
        let mut mutated = attestation_seed();
        let mut cursor = 1;
        let mut edits = 0;
        while edits < 8 && cursor + 4 <= data.len() {
            let position = u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
            apply_attestation_edit(&mut mutated, data[cursor], position, data[cursor + 3]);
            cursor += 4;
            edits += 1;
        }
        if mutated.client_data == seed.client_data
            && mutated.attestation_object == seed.attestation_object
        {
            return;
        }
        let result = verify_none_attestation(AttestationInput {
            client_data_json: &mutated.client_data,
            attestation_object: &mutated.attestation_object,
            policy: &policy,
        });
        match result {
            Err(_) => {}
            Ok(current) if current != seed_result => {}
            Ok(_) => {
                assert!(
                    mutated.attestation_object == seed.attestation_object
                        && client_data_semantics_equal(
                            &mutated.client_data,
                            &seed.client_data,
                            "webauthn.create",
                            &policy
                        ),
                    "ceremony confusion: mutated attestation verified like the seed"
                );
            }
        }
    }
});
