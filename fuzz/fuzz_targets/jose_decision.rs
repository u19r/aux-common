#![no_main]

use std::sync::OnceLock;

use aws_lc_rs::{
    encoding::AsDer as _,
    rand::SystemRandom,
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{KeyPair as _, RSA_PKCS1_SHA256},
};
use jose_core::{CompactJws, JwsAlgorithm, PreparedVerifier, ProtectedHeader};
use libfuzzer_sys::fuzz_target;

// Structured decision oracle for strict asymmetric JWS verification.
//
// The seed is a valid RS256 compact JWS minted with a fixed test key. Every
// byte-driven edit models a signature-bypass shape: algorithm confusion
// (`none`, symmetric labels, cross-asymmetric labels), key-id removal,
// smuggled key URLs and certificates, critical extensions, base64
// canonicalization abuse, segment surgery, payload substitution, and
// signature tampering or truncation. The oracle: decoding plus verification
// may only succeed on the byte-identical seed. Any other `Ok` confuses one
// algorithm, key, or message for another.
struct Seed {
    token: String,
    spki: Vec<u8>,
}

fn seed() -> &'static Seed {
    static SEED: OnceLock<Seed> = OnceLock::new();
    SEED.get_or_init(|| {
        let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("test key");
        let spki = key_pair
            .public_key()
            .as_der()
            .expect("encode public key")
            .as_ref()
            .to_vec();
        let header = ProtectedHeader::new(JwsAlgorithm::Rs256, "fuzz-key", None::<String>)
            .expect("seed header");
        let prepared =
            CompactJws::prepare(&header, br#"{"sub":"subject"}"#).expect("seed prepared");
        let mut signature = vec![0_u8; key_pair.public_modulus_len()];
        key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                prepared.as_str().as_bytes(),
                &mut signature,
            )
            .expect("seed signature");
        let token = prepared.finish(&signature);
        let verifier =
            PreparedVerifier::try_new(JwsAlgorithm::Rs256, &spki).expect("seed verifier");
        CompactJws::decode(&token)
            .expect("seed decodes")
            .verify(&verifier)
            .expect("seed must verify");
        Seed { token, spki }
    })
}

fn crafted_header(variant: u8) -> &'static str {
    match variant % 8 {
        0 => r#"{"alg":"none","kid":"fuzz-key"}"#,
        1 => r#"{"alg":"nOnE","kid":"fuzz-key"}"#,
        2 => r#"{"alg":"HS256","kid":"fuzz-key"}"#,
        3 => r#"{"alg":"ES256","kid":"fuzz-key"}"#,
        4 => r#"{"alg":"RS256"}"#,
        5 => r#"{"alg":"RS256","kid":"fuzz-key","jku":"https://attacker.invalid/jwks.json"}"#,
        6 => r#"{"alg":"RS256","kid":"fuzz-key","crit":["exp"]}"#,
        _ => r#"{"alg":"RS256","kid":"fuzz-key","x5u":"https://attacker.invalid/cert.pem"}"#,
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
    match op % 9 {
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
            // Pad the header segment, breaking canonical base64.
            if let Some(dot) = token.find('.') {
                token.insert(dot, '=');
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
            // Substitute the payload while keeping the original signature.
            if let Some((header, rest)) = token.split_once('.')
                && let Some((_, signature)) = rest.split_once('.')
            {
                *token = format!(
                    "{}.{}.{}",
                    header,
                    base64_url_encode(br#"{"sub":"mallory","role":"admin"}"#),
                    signature
                );
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
        _ => {
            // Collapse to two segments.
            if let Some(dot) = token.find('.') {
                token.truncate(dot);
            }
        }
    }
}

fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(bytes)
}

fuzz_target!(|data: &[u8]| {
    let seed = seed();
    let verifier =
        PreparedVerifier::try_new(JwsAlgorithm::Rs256, &seed.spki).expect("seed verifier");
    let mut token = seed.token.clone();
    let mut cursor = 0;
    let mut edits = 0;
    while edits < 8 && cursor + 4 <= data.len() {
        let position = u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        apply_edit(&mut token, data[cursor], position, data[cursor + 3]);
        cursor += 4;
        edits += 1;
    }
    if token == seed.token {
        return;
    }
    let verified =
        CompactJws::decode(&token).and_then(|decoded| decoded.verify(&verifier).map(|()| decoded));
    assert!(verified.is_err(), "signature bypass: mutated JWS verified");
});
