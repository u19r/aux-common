use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode, jwk::Jwk};

use super::verify;
use crate::{JwtDecodeErrorKind, SignatureAlgorithm, jwks::PRIVATE_KEY};

const P256_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWTFfCGljY6aw3Hrt
kHmPRiazukxPLb6ilpRAewjW8nihRANCAATDskChT+Altkm9X7MI69T3IUmrQU0L
950IxEzvw/x5BMEINRMrXLBJhqzO9Bm+d6JbqA21YQmd1Kt4RzLJR1W+
-----END PRIVATE KEY-----";

const P384_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/p
E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZz
MIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw
8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
-----END PRIVATE KEY-----";

const ED25519_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGrD/e7uKYqSY4twDEsRfMMuLSrODf14dpTiTK6K1YI0
-----END PRIVATE KEY-----";

const HMAC_KEY: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn given_rsa_tokens_when_wasm_backend_verifies_then_all_rsa_algorithms_pass() {
    for algorithm in [
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
    ] {
        let key = EncodingKey::from_rsa_pem(PRIVATE_KEY).expect("valid RSA test key");
        assert_asymmetric_verifies(algorithm, key);
    }
}

#[test]
fn given_elliptic_curve_tokens_when_wasm_backend_verifies_then_supported_algorithms_pass() {
    let p256 = EncodingKey::from_ec_pem(P256_PRIVATE_KEY).expect("valid P-256 test key");
    assert_asymmetric_verifies(Algorithm::ES256, p256);

    let p384 = EncodingKey::from_ec_pem(P384_PRIVATE_KEY).expect("valid P-384 test key");
    assert_asymmetric_verifies(Algorithm::ES384, p384);

    let ed25519 = EncodingKey::from_ed_pem(ED25519_PRIVATE_KEY).expect("valid Ed25519 test key");
    assert_asymmetric_verifies(Algorithm::EdDSA, ed25519);
}

#[test]
fn given_hmac_tokens_when_wasm_backend_verifies_then_supported_algorithms_pass() {
    for algorithm in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
        let encoding_key = EncodingKey::from_secret(HMAC_KEY);
        let token = token(algorithm, &encoding_key);
        let decoding_key = DecodingKey::from_secret(HMAC_KEY);
        assert_token_verifies(&token, &decoding_key, algorithm);
    }
}

#[test]
fn given_tampered_signature_when_wasm_backend_verifies_then_signature_is_rejected() {
    let encoding_key = EncodingKey::from_rsa_pem(PRIVATE_KEY).expect("valid RSA test key");
    let token = token(Algorithm::RS256, &encoding_key);
    let (message, encoded_signature) = token.rsplit_once('.').expect("compact token");
    let mut signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .expect("base64 signature");
    signature[0] ^= 1;
    let tampered = URL_SAFE_NO_PAD.encode(signature);
    let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).expect("RSA JWK");
    let decoding_key = DecodingKey::from_jwk(&jwk).expect("RSA decoding key");

    let error = verify(
        &tampered,
        message.as_bytes(),
        &decoding_key,
        SignatureAlgorithm::RS256,
    )
    .expect_err("tampered signature must fail");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::SignatureInvalid);
}

fn assert_asymmetric_verifies(algorithm: Algorithm, encoding_key: EncodingKey) {
    let token = token(algorithm, &encoding_key);
    let jwk = Jwk::from_encoding_key(&encoding_key, algorithm).expect("public JWK");
    let decoding_key = DecodingKey::from_jwk(&jwk).expect("public decoding key");
    assert_token_verifies(&token, &decoding_key, algorithm);
}

fn assert_token_verifies(token: &str, key: &DecodingKey, algorithm: Algorithm) {
    let (message, signature) = token.rsplit_once('.').expect("compact token");
    let algorithm = SignatureAlgorithm::try_from(algorithm).expect("supported algorithm");
    verify(signature, message.as_bytes(), key, algorithm).expect("signature should verify");
}

fn token(algorithm: Algorithm, key: &EncodingKey) -> String {
    let mut header = Header::new(algorithm);
    header.kid = Some("test-key".to_owned());
    encode(&header, &serde_json::json!({ "sub": "subject" }), key).expect("signed token")
}

#[test]
fn given_native_and_wasm_backends_when_verifying_then_verdicts_agree() {
    // Given every supported algorithm with a matching key pair. The native
    // backend is `aws-lc-rs` through `jsonwebtoken`; the WASM backend is the
    // hand-dispatched `purecrypto`/`p256`/`p384`/`ed25519-dalek` path. A
    // verdict split between them would let a token verify on one platform
    // and fail on the other, so agreement is the security property.
    let rsa = EncodingKey::from_rsa_pem(PRIVATE_KEY).expect("valid RSA test key");
    let p256 = EncodingKey::from_ec_pem(P256_PRIVATE_KEY).expect("valid P-256 test key");
    let p384 = EncodingKey::from_ec_pem(P384_PRIVATE_KEY).expect("valid P-384 test key");
    let ed25519 = EncodingKey::from_ed_pem(ED25519_PRIVATE_KEY).expect("valid Ed25519 test key");
    let hmac = EncodingKey::from_secret(HMAC_KEY);
    let cases = [
        (Algorithm::RS256, rsa.clone()),
        (Algorithm::RS384, rsa.clone()),
        (Algorithm::RS512, rsa.clone()),
        (Algorithm::PS256, rsa.clone()),
        (Algorithm::PS384, rsa.clone()),
        (Algorithm::PS512, rsa.clone()),
        (Algorithm::ES256, p256),
        (Algorithm::ES384, p384),
        (Algorithm::EdDSA, ed25519),
        (Algorithm::HS256, hmac.clone()),
        (Algorithm::HS384, hmac.clone()),
        (Algorithm::HS512, hmac),
    ];
    // When each backend verifies valid, tampered, wrong-key, truncated,
    // empty, and non-base64 signatures.
    for (algorithm, encoding_key) in cases {
        let token = token(algorithm, &encoding_key);
        let (message, signature) = token.rsplit_once('.').expect("compact token");
        let decoding_key = if algorithm == Algorithm::HS256
            || algorithm == Algorithm::HS384
            || algorithm == Algorithm::HS512
        {
            DecodingKey::from_secret(HMAC_KEY)
        } else {
            let jwk = Jwk::from_encoding_key(&encoding_key, algorithm).expect("public JWK");
            DecodingKey::from_jwk(&jwk).expect("public decoding key")
        };
        let wrong_key = DecodingKey::from_secret(b"wrong-key-with-enough-entropy-000000");
        let mut tampered = URL_SAFE_NO_PAD.decode(signature).expect("base64 signature");
        tampered[0] ^= 1;
        let variants = [
            signature.to_string(),
            URL_SAFE_NO_PAD.encode(&tampered),
            String::new(),
            "not-base64!".to_string(),
            signature
                .get(..signature.len() / 2)
                .expect("base64url is ASCII")
                .to_string(),
        ];
        for variant in variants {
            let native = jsonwebtoken::crypto::verify(
                &variant,
                message.as_bytes(),
                &decoding_key,
                algorithm,
            )
            .is_ok_and(|verified| verified);
            let wasm = verify(
                &variant,
                message.as_bytes(),
                &decoding_key,
                SignatureAlgorithm::try_from(algorithm).expect("supported algorithm"),
            )
            .is_ok();
            assert_eq!(
                native, wasm,
                "backend split for {algorithm:?} signature {variant:?}"
            );
        }
        let native_wrong =
            jsonwebtoken::crypto::verify(signature, message.as_bytes(), &wrong_key, algorithm)
                .is_ok_and(|verified| verified);
        let wasm_wrong = verify(
            signature,
            message.as_bytes(),
            &wrong_key,
            SignatureAlgorithm::try_from(algorithm).expect("supported algorithm"),
        )
        .is_ok();
        assert_eq!(native_wrong, wasm_wrong, "backend split on wrong key");
    }
}
