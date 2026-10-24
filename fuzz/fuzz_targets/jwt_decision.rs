#![no_main]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use libfuzzer_sys::fuzz_target;
use sha2::Sha256;

// Structured decision oracle for JWT verification.
//
// The seed is a valid HS256 access token minted and verified through the
// production `JwtVerifier` with a static symmetric key, an explicit
// symmetric-only algorithm policy, and a full access-token policy. Every
// byte-driven edit models a real bypass shape: algorithm confusion (`none`,
// asymmetric labels), unknown or missing key IDs, header-injected key URLs,
// wrong token types, duplicated claims, expired lifetimes, tampered or
// missing signatures, segment swaps, truncation, and trailing segments. The
// oracle: verification may only succeed on the byte-identical seed. Any
// other `Ok` is an authentication bypass.
const SECRET: &[u8] = b"fuzz-harness-hmac-secret-with-enough-entropy-0123";
const ISSUER: &str = "https://issuer.example";
const AUDIENCE: &str = "fuzz-api";
const CLIENT_ID: &str = "fuzz-client";

fn base64_url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hmac_tag(secret: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac accepts any key");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn timestamps() -> (i64, i64) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock moves forward")
        .as_secs() as i64;
    (now + 300, now - 10)
}

fn seed_token() -> (
    String,
    jwt_decode::VerificationPolicy,
    jwt_decode::JwtVerifier,
) {
    let (expiration, issued_at) = timestamps();
    let header = r#"{"alg":"HS256","kid":"fuzz-key","typ":"at+jwt"}"#;
    let claims = format!(
        "{{\"iss\":\"{ISSUER}\",\"aud\":\"{AUDIENCE}\",\"exp\":{expiration},\"iat\":{issued_at},\"\
         token_type\":\"access\",\"client_id\":\"{CLIENT_ID}\"}}"
    );
    let message = format!(
        "{}.{}",
        base64_url_encode(header.as_bytes()),
        base64_url_encode(claims.as_bytes())
    );
    let token = format!(
        "{message}.{}",
        base64_url_encode(&hmac_tag(SECRET, message.as_bytes()))
    );
    let verifier = jwt_decode::JwtVerifier::builder()
        .jwks_source(
            jwt_decode::JwksSource::local_symmetric_key("fuzz-key", SECRET.to_vec())
                .expect("symmetric key source"),
        )
        .allowed_algorithms(
            jwt_decode::AllowedAlgorithms::symmetric([jwt_decode::SignatureAlgorithm::HS256])
                .expect("symmetric policy"),
        )
        .build()
        .expect("verifier builds");
    let policy = jwt_decode::VerificationPolicy::access_token()
        .issuer(ISSUER)
        .expect("issuer")
        .audience(AUDIENCE)
        .expect("audience")
        .client_id(CLIENT_ID)
        .expect("client")
        .max_issued_age(std::time::Duration::from_secs(600))
        .build()
        .expect("policy builds");
    (token, policy, verifier)
}

fn crafted_header(variant: u8) -> &'static str {
    match variant % 7 {
        0 => r#"{"alg":"none","kid":"fuzz-key","typ":"at+jwt"}"#,
        1 => r#"{"alg":"nOnE","kid":"fuzz-key","typ":"at+jwt"}"#,
        2 => r#"{"alg":"RS256","kid":"fuzz-key","typ":"at+jwt"}"#,
        3 => r#"{"alg":"HS256","kid":"unknown-key","typ":"at+jwt"}"#,
        4 => {
            r#"{"alg":"HS256","kid":"fuzz-key","typ":"at+jwt","jku":"https://attacker.invalid/jwks.json"}"#
        }
        5 => r#"{"alg":"HS256","kid":"fuzz-key","typ":"JWT"}"#,
        _ => r#"{"alg":"HS256","typ":"at+jwt"}"#,
    }
}

fn flip_first_character(segment: &str) -> String {
    let mut characters: Vec<char> = segment.chars().collect();
    if characters.is_empty() {
        return segment.to_owned();
    }
    characters[0] = if characters[0] == 'A' { 'B' } else { 'A' };
    characters.into_iter().collect()
}

fn apply_edit(token: &mut String, op: u8, position: usize, argument: u8) {
    if token.is_empty() {
        return;
    }
    // All edits stay on character boundaries: flipping bytes can introduce
    // multi-byte scalars, and byte-indexed truncation must never split them.
    match op % 8 {
        0 => {
            // Flip a character of the compact serialization.
            let mut characters: Vec<char> = token.chars().collect();
            let index = position % characters.len();
            characters[index] =
                char::from_u32(characters[index] as u32 ^ u32::from(argument) ^ 1).unwrap_or('?');
            *token = characters.into_iter().collect();
        }
        1 => {
            // Swap the header for a confusion variant.
            if let Some(dot) = token.find('.') {
                *token = format!(
                    "{}.{}",
                    base64_url_encode(crafted_header(argument).as_bytes()),
                    &token[dot + 1..]
                );
            }
        }
        2 => {
            // Duplicate a claim inside the payload.
            if let Some((header, rest)) = token.split_once('.')
                && let Some((payload, signature)) = rest.split_once('.')
                && let Ok(decoded) = URL_SAFE_NO_PAD.decode(payload)
                && let Ok(mut text) = String::from_utf8(decoded)
            {
                text = text.replacen('}', &format!(",\"client_id\":\"mallory{argument}\"}}"), 1);
                *token = format!(
                    "{header}.{}.{}",
                    base64_url_encode(text.as_bytes()),
                    signature
                );
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
            // Expire the lifetime while keeping the original signature.
            if let Some((header, rest)) = token.split_once('.')
                && let Some((payload, signature)) = rest.split_once('.')
                && let Ok(decoded) = URL_SAFE_NO_PAD.decode(payload)
                && let Ok(text) = String::from_utf8(decoded)
            {
                let (expiration, _) = timestamps();
                let expired = text.replace(&format!("\"exp\":{expiration}"), "\"exp\":1000");
                *token = format!(
                    "{header}.{}.{}",
                    base64_url_encode(expired.as_bytes()),
                    signature
                );
            }
        }
        6 => {
            // Truncate the compact serialization on a character boundary.
            token.truncate(token.floor_char_boundary(position % (token.len() + 1)));
        }
        _ => {
            // Append a trailing segment.
            token.push_str(".e30");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let (seed, policy, verifier) = seed_token();
    verifier
        .verify_static_json_claims_only(&seed, &policy)
        .expect("seed must verify");
    let mut token = seed.clone();
    let mut cursor = 0;
    let mut edits = 0;
    while edits < 8 && cursor + 4 <= data.len() {
        let position = u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        apply_edit(&mut token, data[cursor], position, data[cursor + 3]);
        cursor += 4;
        edits += 1;
    }
    if token == seed {
        return;
    }
    assert!(
        verifier
            .verify_static_json_claims_only(&token, &policy)
            .is_err(),
        "authentication bypass: mutated token verified"
    );
});
