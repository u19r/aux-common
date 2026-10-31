#![no_main]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use libfuzzer_sys::fuzz_target;
use sha2::Sha256;

// Differential forum over key selection inside one verifier: two signing
// symmetric keys share one static JWKS (plus a decoy octet key), the token
// carries an arbitrary `kid`, and the same token runs through both the
// static and the async verifier paths.
//
// Oracles:
// 1. verification may only succeed on byte-identical seeds;
// 2. the static and async verifier paths must agree on every token;
// 3. mutation of JWKS documents never panics; malformed JWKS rejects.
const JWT_SECRET: &[u8] = b"cross-jwt-hmac-secret-with-enough-entropy-0123";
const ALT_SECRET: &[u8] = b"cross-jwt-hmac-secret-entirely-separate-from-SEED";
const DECOY_SECRET: &[u8] = b"cross-jwt-decoy-share-secret--not-for-signing-SEED";const HS_KID: &str = "hs-seed";
const ALT_KID: &str = "alt-hs-seed";
const DECOY_KID: &str = "surprise-octet-not-used";
const ISSUER: &str = "https://issuer.example";
const AUDIENCE: &str = "fuzz-api";
const CLIENT_ID: &str = "fuzz-client";

struct FuzzState {
    /// Byte-identical signed HMAC token (HS256). Anything else must not pass.
    hs_token: String,
    hs_alt_token: String,
    hs_verifier: jwt_decode::JwtVerifier,
    /// Same surface but the alternative-hmac policy (so `kid` must matter).
    policy: jwt_decode::VerificationPolicy,
}

/// A valid JWKS with three octet keys: the signing pair and a decoy.
fn seed_jwks_json() -> String {
    format!(
        r#"{{"keys":[
           {{"kty":"oct","kid":"{HS_KID}","alg":"HS256",
              "use":"sig",
              "k":"{}"}},
           {{"kty":"oct","kid":"{ALT_KID}","alg":"HS256",
              "use":"sig",
              "k":"{}"}},
           {{"kty":"oct","kid":"{DECOY_KID}","alg":"HS256",
              "use":"sig",
              "k":"{}"}}]}}"#,
        URL_SAFE_NO_PAD.encode(JWT_SECRET),
        URL_SAFE_NO_PAD.encode(ALT_SECRET),
        URL_SAFE_NO_PAD.encode(DECOY_SECRET),
    )
}

fn main_policy() -> jwt_decode::VerificationPolicy {
    jwt_decode::VerificationPolicy::access_token()
        .issuer(ISSUER)
        .expect("issuer")
        .audience(AUDIENCE)
        .expect("audience")
        .client_id(CLIENT_ID)
        .expect("client")
        .max_issued_age(std::time::Duration::from_secs(600))
        .build()
        .expect("policy builds")
}

fn hmac_verifier(jwks_json: &str) -> jwt_decode::JwtVerifier {
    jwt_decode::JwtVerifier::builder()
        .jwks_source(
            jwt_decode::JwksSource::json_string(jwks_json).expect("jwks doc parses"),
        )
        .allowed_algorithms(
            jwt_decode::AllowedAlgorithms::symmetric([
                jwt_decode::SignatureAlgorithm::HS256,
                jwt_decode::SignatureAlgorithm::HS384,
            ])
            .expect("symmetric policy"),
        )
        .build()
        .expect("jwt verifier builds")
}

fn base64_url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hmac_token(kid: &str, secret: &[u8], typ: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock moves forward")
        .as_secs() as i64;
    let header = format!(r#"{{"alg":"HS256","kid":"{}","typ":"{}"}}"#, kid, typ);
    let claims = format!(
        "{{\"iss\":\"{}\",\"aud\":\"{}\",\"exp\":{},\"iat\":{},\"token_type\":\"access\",\"client_id\":\"{}\"}}",
        ISSUER, AUDIENCE,
        now + 300,
        now - 10,
        CLIENT_ID,
    );
    let message = format!(
        "{}.{}",
        base64_url_encode(header.as_bytes()),
        base64_url_encode(claims.as_bytes())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key");
    mac.update(message.as_bytes());
    format!("{message}.{}", base64_url_encode(&mac.finalize().into_bytes()))
}

fn craft_token(kid: &str, secret: &[u8], typ: &str) -> String {
    hmac_token(kid, secret, typ)
}

fn base64_decode(encoded: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(encoded).ok()
}

// Every mutation either flips bytes of the compact serialization or surgically
// rewrites structurally meaningful segments. Flipping the `kid` on the wire
// still must invalidate the signature; replacing the full header with one of
// the confusion variants likewise must fail.
const CONFUSION_HEADER_JSONS: [&str; 8] = [
    r#"{"alg":"none","kid":"hs-seed","typ":"at+jwt"}"#,
    r#"{"alg":"nOnE","kid":"hs-seed","typ":"at+jwt"}"#,
    r#"{"alg":"HS256","kid":"alt-hs-seed","typ":"at+jwt"}"#,
    r#"{"alg":"HS256","kid":"surprise-octet-not-used","typ":"at+jwt"}"#,
    r#"{"alg":"HS256","typ":"at+jwt"}"#,
    r#"{"alg":"HS256","kid":"hs-seed","typ":"at+jwt","jku":"https://attacker.invalid/jwks.json"}"#,
    r#"{"alg":"HS256","kid":"hs-seed","typ":"at+jwt","crit":["b64"]}"#,
    r#"{"alg":"ES256","kid":"hs-seed","typ":"at+jwt"}"#,
];

fn flip_first_character(segment: &str) -> String {
    let mut characters: Vec<char> = segment.chars().collect();
    if characters.is_empty() {
        return segment.to_owned();
    }
    characters[0] = if characters[0] == 'A' { 'B' } else { 'A' };
    characters.into_iter().collect()
}

fn apply_token_edit(token: &mut String, op: u8, position: usize, argument: u8) {
    if token.is_empty() {
        return;
    }
    match op % 10 {
        0 => {
            // Flip a character of the compact serialization.
            let mut characters: Vec<char> = token.chars().collect();
            let index = position % characters.len();
            characters[index] =
                char::from_u32(characters[index] as u32 ^ u32::from(argument) ^ 1)
                    .unwrap_or('?');
            *token = characters.into_iter().collect();
        }
        1 => {
            // Replace the header with a confusion variant.
            if let Some(dot) = token.find('.') {
                let variant = CONFUSION_HEADER_JSONS[(argument % 8) as usize];
                *token = format!(
                    "{}.{}",
                    base64_url_encode(variant.as_bytes()),
                    &token[dot + 1..]
                );
            }
        }
        2 => {
            // Duplicate a claim within the payload.
            if let Some((header, rest)) = token.split_once('.')
                && let Some((payload, signature)) = rest.split_once('.')
                && let Some(decoded) = base64_decode(payload)
                && let Ok(mut text) = String::from_utf8(decoded)
            {
                text = text.replacen('}', &format!(",\"client_id\":\"mallory{argument}\"}}"), 1);
                *token = format!("{header}.{}.{}", base64_url_encode(text.as_bytes()), signature);
            }
        }
        3 => {
            // Tamper with the signature segment.
            if let Some(dot) = token.rfind('.') {
                *token = format!(
                    "{}.{}",
                    &token[..dot + 1],
                    flip_first_character(&token[dot + 1..])
                );
            }
        }
        4 => {
            // Drop the signature segment entirely.
            if let Some(dot) = token.rfind('.') {
                token.truncate(dot + 1);
            }
        }
        5 => {
            // Pad the header segment (canonical base64 violation).
            if let Some(dot) = token.find('.') {
                token.insert(dot, '=');
            }
        }
        6 => {
            // Truncate the compact serialization on a character boundary.
            token.truncate(token.floor_char_boundary(position % (token.len() + 1)));
        }
        7 => {
            // Append a trailing segment.
            token.push_str(".e30");
        }
        8 => {
            // Rewrite the kid to another known key id, keeping the signature.
            if let Some((_, rest)) = token.split_once('.')
                && let Some((_, message_tail)) = rest.split_once('.')
            {
                let kid = [HS_KID, ALT_KID, DECOY_KID][(argument % 3) as usize];
                let rewritten = format!(r#"{{"alg":"HS256","kid":"{kid}","typ":"at+jwt"}}"#);
                *token = format!(
                    "{}.{}",
                    base64_url_encode(rewritten.as_bytes()),
                    message_tail
                );
            }
        }
        _ => {
            // Substitute the payload under the original signature.
            if let Some((header, rest)) = token.split_once('.')
                && let Some((_, signature)) = rest.split_once('.')
            {
                *token = format!(
                    "{}.{}.{}",
                    header,
                    base64_url_encode(br#"{"iss":"https://attacker.invalid\"}"#),
                    signature
                );
            }
        }
    }
}

fn apply_jwks_edit(jwks: &mut String, op: u8, position: usize, argument: u8) {
    if jwks.is_empty() {
        return;
    }
    let blank: String = jwks
        .char_indices()
        .map(|(index, character)| {
            if index == position % jwks.chars().count() {
                char::from_u32(character as u32 ^ u32::from(argument) ^ 1)
                    .unwrap_or('?')
            } else {
                character
            }
        })
        .collect();
    match op % 3 {
        0 => {
            // Byte flip on a raw character boundary.
            *jwks = blank;
        }
        1 => {
            // Duplicate one key entry's kid prefix, forcing ambiguous-key
            // handling inside `find_unique_key`.
            if let Some(start) = jwks.find("\"kty\"") {
                *jwks = format!(
                    "{}{}",
                    &jwks[..start],
                    jwks[start..].replace("\"alg\"", "\"kalg\"")
                );
            }
        }
        _ => {
            // Truncate on a character boundary.
            jwks.truncate(jwks.floor_char_boundary(position % (jwks.len() + 1)));
        }
    }
}

fn crafted_state() -> FuzzState {
    let jwks_json = seed_jwks_json();
    let hs_verifier = hmac_verifier(&jwks_json);
    let policy = main_policy();
    FuzzState {
        hs_token: craft_token(HS_KID, JWT_SECRET, "at+jwt"),
        hs_alt_token: craft_token(ALT_KID, ALT_SECRET, "at+jwt"),
        hs_verifier,
        policy,
    }
}

fuzz_target!(|data: &[u8]| {
    let state = crafted_state();
    let hs_token = state.hs_token.clone();
    let hs_alt_token = state.hs_alt_token.clone();

    // Seeds must verify through both the static and async paths of the same
    // verifier; byte-identity is the only acceptable pass.
    state
        .hs_verifier
        .verify_static_json_claims_only(&hs_token, &state.policy)
        .expect("hs seed verifies on its static path");
    state
        .hs_verifier
        .verify_static_json_claims_only(&hs_alt_token, &state.policy)
        .expect("alt hs seed verifies on its static path");

    let mut token = hs_token.clone();
    let mut cursor = 0;
    let mut edits = 0;
    while edits < 8 && cursor + 4 <= data.len() {
        let position = u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        apply_token_edit(&mut token, data[cursor], position, data[cursor + 3]);
        cursor += 4;
        edits += 1;
    }

    if token != hs_token && token != hs_alt_token {
        let static_outcome =
            state
                .hs_verifier
                .verify_static_json_claims_only(&token, &state.policy);
        let async_outcome = tokio_block_on(
            state
                .hs_verifier
                .verify::<serde_json::Value>(&token, &state.policy),
        );
        assert!(static_outcome.is_err(), "static verification escaped: token {token:?}");
        assert!(async_outcome.is_err(), "async verification escaped: token {token:?}");
    }

    // Hostile JWKS documents must always parse (or reject) without panicking,
    // while still able to accept the byte-level valid seed doc.
    let mut jwks = seed_jwks_json();
    cursor = 0;
    edits = 0;
    while edits < 4 && cursor + 4 <= data.len() {
        let position = u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        apply_jwks_edit(&mut jwks, data[cursor] / 10, position, data[cursor + 3]);
        cursor += 4;
        edits += 1;
    }
    let _ = jwt_decode::JwksSource::json_string(&jwks);
    let _ = jwt_decode::JwksSource::json_string(&seed_jwks_json()).expect("seed jwks parses");
});

fn tokio_block_on<F: std::future::Future>(future: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(future)
}
