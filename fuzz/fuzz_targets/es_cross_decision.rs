#![no_main]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libfuzzer_sys::fuzz_target;
use p256::ecdsa::{SigningKey, signature::Signer as _};

// Cross-library differential oracle on one ES256 compact token.
//
// `jose_core::CompactJws` and `jwt_decode::JwtVerifier` are independent
// verification implementations in this workspace (strict canonical header
// shape vs policy-driven key/claim gates). The seed is a valid token under
// both; every byte-driven edit must be rejected by both stacks. The
// differential keeps either implementation from silently dropping its
// bytes-identity invariant: jose_core's strict shape would otherwise accept
// tokens jwt_decode rejects for missing gates, and a bug in either stack is
// visible as a disagreement.
//
// Mutated SPKIs and JWKS documents never panic; the JWKS path still accepts
// the pure byte-identical seed.
const ISSUER: &str = "https://issuer.example";
const AUDIENCE: &str = "fuzz-api";
const KEY: [u8; 32] = *b"es256-cross-api-key-entropy-0123";

fn sec1_public_coordinates(key: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let signing = SigningKey::from_slice(key).expect("fuzz test key");
    let point = signing.verifying_key().to_sec1_point(false);
    (
        point.x().expect("x").to_vec(),
        point.y().expect("y").to_vec(),
    )
}

fn sec1_public_point(key: &[u8; 32]) -> p256::PublicKey {
    p256::PublicKey::from_sec1_bytes(&[
        &[0x04][..],
        &sec1_public_coordinates(key).0,
        &sec1_public_coordinates(key).1,
    ]
    .concat())
    .expect("point on curve")
}

fn encoded_sec1(key: &[u8; 32]) -> [String; 2] {
    let (x, y) = sec1_public_coordinates(key);
    [URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y)]
}

fn jws_sign(key: &[u8; 32], header: &[u8], payload: &[u8]) -> String {
    let signing = SigningKey::from_slice(key).expect("fuzz test key");
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature: p256::ecdsa::Signature = signing.sign(message.as_bytes());
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn seed_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock moves forward")
        .as_secs() as i64;
    let header = serde_json::json!({"alg":"ES256","kid":"es-cross-key","typ":"at+jwt"});
    let claims = serde_json::json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "subject",
        "exp": now + 300,
        "iat": now - 10
    });
    jws_sign(
        &KEY,
        serde_json::to_vec(&header).unwrap().as_slice(),
        serde_json::to_vec(&claims).unwrap().as_slice(),
    )
}

fn seed_jwks() -> String {
    let [x, y] = encoded_sec1(&KEY);
    format!(
        r#"{{"keys":[{{"kty":"EC","kid":"es-cross-key","crv":"P-256","alg":"ES256","use":"sig","x":"{x}","y":"{y}"}}]}}"#
    )
}

fn decoded_verifier() -> (jwt_decode::JwtVerifier, jwt_decode::VerificationPolicy) {
    let policy = jwt_decode::VerificationPolicy::generic_jwt()
        .issuer(ISSUER)
        .expect("issuer")
        .audience(AUDIENCE)
        .expect("audience")
        .build()
        .expect("policy builds");
    let verifier = jwt_decode::JwtVerifier::builder()
        .jwks_source(jwt_decode::JwksSource::json_string(&seed_jwks()).expect("seed jwks parses"))
        .allowed_algorithms(
            jwt_decode::AllowedAlgorithms::asymmetric([jwt_decode::SignatureAlgorithm::ES256])
                .expect("asymmetric allowlist"),
        )
        .build()
        .expect("jwt verifier builds");
    (verifier, policy)
}

fn jose_core_verifier() -> jose_core::PreparedVerifier {
    let spki = p256::pkcs8::EncodePublicKey::to_public_key_der(&sec1_public_point(&KEY))
        .map_err(|error| panic!("spki encode failed: {error}"))
        .unwrap();
    jose_core::PreparedVerifier::try_new(
        jose_core::JwsAlgorithm::Es256,
        spki.as_ref(),
    )
    .expect("verifier builds")
}

fn jose_core_verifies(token: &str, verifier: &jose_core::PreparedVerifier) -> bool {
    jose_core::CompactJws::decode(token)
        .and_then(|decoded| decoded.verify(verifier))
        .is_ok()
}

fn jwt_decode_verifies(
    token: &str,
    verifier: &jwt_decode::JwtVerifier,
    policy: &jwt_decode::VerificationPolicy,
) -> bool {
    verifier
        .verify_static_json_claims_only(token, policy)
        .is_ok()
}

// Confusion variants that model real JOSE attack shapes. Each must stay
// rejected by both stacks (bytes-identity invariant breaks).
const CONFUSION_HEADER_JSONS: [&str; 6] = [
    r#"{"alg":"none","kid":"es-cross-key","typ":"at+jwt"}"#,
    r#"{"alg":"ES256","kid":"other-key","typ":"at+jwt"}"#,
    r#"{"alg":"ES256","typ":"at+jwt"}"#,
    r#"{"alg":"HS256","kid":"es-cross-key","typ":"at+jwt"}"#,
    r#"{"alg":"ES256","kid":"es-cross-key","typ":"at+jwt","jku":"https://attacker.invalid/jwks.json"}"#,
    r#"{"alg":"ES256","kid":"es-cross-key","typ":"at+jwt","crit":["b64"],"b64":false}"#,
];

fn apply_edit(token: &mut String, op: u8, position: usize, argument: u8) {
    if token.is_empty() {
        return;
    }
    match op % 8 {
        0 => {
            let mut characters: Vec<char> = token.chars().collect();
            let index = position % characters.len();
            characters[index] =
                char::from_u32(characters[index] as u32 ^ u32::from(argument) ^ 1).unwrap_or('?');
            *token = characters.into_iter().collect();
        }
        1 => {
            if let Some(dot) = token.find('.') {
                *token = format!(
                    "{}.{}",
                    URL_SAFE_NO_PAD.encode(
                        CONFUSION_HEADER_JSONS[(argument % 6) as usize].as_bytes()
                    ),
                    &token[dot + 1..]
                );
            }
        }
        2 => {
            if let Some(dot) = token.rfind('.') {
                token.truncate(dot + 1);
            }
        }
        3 => {
            if let Some((_, rest)) = token.split_once('.')
                && let Some((_, signature)) = rest.split_once('.')
            {
                *token = format!(
                    "{}.{}.{}",
                    &token[..token.find('.').expect("split ok") + 1],
                    URL_SAFE_NO_PAD.encode(
                        serde_json::json!({"iss":"https://attacker.invalid",
                                           "aud":AUDIENCE,
                                           "sub":"sub"})
                        .to_string()
                        .as_bytes()
                    ),
                    signature
                );
            }
        }
        4 => {
            token.truncate(token.floor_char_boundary(position % (token.len() + 1)));
        }
        5 => {
            token.push_str(".e30");
        }
        6 => {
            if let Some(first_dot) = token.find('.') {
                token.truncate(first_dot);
            }
        }
        _ => {
            // Pad the header segment with '=': a canonical-base64 violation.
            if let Some(dot) = token.find('.') {
                token.insert(dot, '=');
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let seed = seed_token();
    let jose_verifier = jose_core_verifier();
    let (verifier, policy) = decoded_verifier();

    assert!(
        jose_core_verifies(&seed, &jose_verifier),
        "seed must verify in jose_core"
    );
    if let Err(error) = verifier.verify_static_json_claims_only(&seed, &policy) {
        panic!("seed must verify in jwt_decode: {error:?}");
    }

    let mut token = seed.clone();
    let mut cursor = 0;
    let mut edits = 0;
    while edits < 8 && cursor + 4 <= data.len() {
        let position = u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        apply_edit(&mut token, data[cursor], position, data[cursor + 3]);
        cursor += 4;
        edits += 1;
    }
    if token != seed {
        assert!(
            !jose_core_verifies(&token, &jose_verifier),
            "jose_core bypass: mutated token verified"
        );
        // jwt_decode on the same token: a bypass here is important, but only
        // reported as an assertion to make the differential visible.
        assert!(
            !jwt_decode_verifies(&token, &verifier, &policy),
            "jwt_decode bypass: mutated token verified"
        );
    }

    // Hostile JWKS documents never panic and hostile SPKIs never panic.
    let mut jwks = seed_jwks();
    if !jwks.is_empty() {
        let index = usize::from(data.get(1).copied().unwrap_or(0)) % jwks.len();
        let flipped = jwks.chars().nth(index).unwrap_or('X');
        let mutated = format!(
            "{}{}",
            &jwks[..index],
            char::from_u32(u32::from(flipped) ^ 1).unwrap_or(flip_remaining_diff(flipped)),
        );
        let _ = jwt_decode::JwksSource::json_string(&mutated);
    }

    // SPKI mutations: no panic, and a full curve/keykind mismatch must
    // reject (the seed SPKI is still fine).
    let spki = p256::pkcs8::EncodePublicKey::to_public_key_der(&sec1_public_point(&KEY))
        .map_err(|error| panic!("spki encode failed: {error}"))
        .unwrap();
    let mut spki_bytes = spki.as_ref().to_vec();
    if !spki_bytes.is_empty() {
        let index = usize::from(data.get(2).copied().unwrap_or(0)) % spki_bytes.len();
        spki_bytes[index] ^= 1;
        let _ = jose_core::PreparedVerifier::try_new(
            jose_core::JwsAlgorithm::Es256,
            &spki_bytes,
        );
    }
});

/// Fallback when an xor flip is unrepresentable for the source character.
fn flip_remaining_diff(character: char) -> char {
    if character == 'X' {
        'Y'
    } else {
        'X'
    }
}
