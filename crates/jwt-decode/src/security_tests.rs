use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(not(target_arch = "wasm32"))]
use http_request::HttpClientBuilder;
use jsonwebtoken::{
    Algorithm, Header,
    jwk::{KeyAlgorithm, PublicKeyUse},
};

use crate::{
    AllowedAlgorithms, JwksCachePolicy, JwksSource, JwksUrl, JwtDecodeErrorKind, JwtVerifier,
    RemoteJwksSource, SignatureAlgorithm,
    test_support::{
        Claims, CountingTransport, FixedClock, build_hmac_verifier, build_verifier, hmac_token,
        jwk, policy, signed_token, token, valid_claims,
    },
};

#[tokio::test]
async fn given_explicit_local_hmac_source_when_verifying_hs256_then_accepts() {
    let verified = build_hmac_verifier()
        .verify::<Claims>(&hmac_token(valid_claims()), &policy())
        .await
        .unwrap();

    assert_eq!(verified.algorithm, SignatureAlgorithm::HS256);
    assert_eq!(verified.key_id, "hmac-key");
}

#[tokio::test]
async fn given_default_asymmetric_policy_when_verifying_hs256_then_rejects_algorithm() {
    let error = build_verifier()
        .verify::<Claims>(&hmac_token(valid_claims()), &policy())
        .await
        .unwrap_err();

    assert_eq!(
        error.kind(),
        &JwtDecodeErrorKind::UnsupportedAlgorithm(SignatureAlgorithm::HS256)
    );
}

#[tokio::test]
async fn given_oct_key_in_jwks_with_symmetric_allowlist_when_verifying_hs256_then_accepts() {
    let jwks = hmac_jwks();
    let verifier = JwtVerifier::builder()
        .jwks_source(JwksSource::json_string(jwks.to_string()).unwrap())
        .allowed_algorithms(AllowedAlgorithms::symmetric([SignatureAlgorithm::HS256]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .unwrap();

    let verified = verifier
        .verify::<Claims>(&hmac_token(valid_claims()), &policy())
        .await
        .unwrap();

    assert_eq!(verified.algorithm, SignatureAlgorithm::HS256);
    assert_eq!(verified.key_id, "hmac-key");
}

#[tokio::test]
async fn given_oct_key_in_jwks_with_asymmetric_allowlist_when_verifying_hs256_then_rejects_algorithm()
 {
    let jwks = hmac_jwks();
    let verifier = JwtVerifier::builder()
        .jwks_source(JwksSource::json_string(jwks.to_string()).unwrap())
        .allowed_algorithms(AllowedAlgorithms::asymmetric([SignatureAlgorithm::RS256]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .unwrap();

    let error = verifier
        .verify::<Claims>(&hmac_token(valid_claims()), &policy())
        .await
        .unwrap_err();

    assert_eq!(
        error.kind(),
        &JwtDecodeErrorKind::UnsupportedAlgorithm(SignatureAlgorithm::HS256)
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn given_remote_oct_key_when_symmetric_policy_is_enabled_then_rejects_key() {
    let transport = CountingTransport::from_bodies(vec![hmac_jwks().to_string()]);
    let client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .expect("build test HTTP client");
    let source = RemoteJwksSource::new(
        JwksUrl::parse_https("https://issuer.example/jwks.json").expect("JWKS URL"),
        JwksCachePolicy::default(),
        client,
    );
    let verifier = JwtVerifier::builder()
        .jwks_source(JwksSource::Url(Box::new(source)))
        .allowed_algorithms(AllowedAlgorithms::symmetric([SignatureAlgorithm::HS256]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .unwrap();

    let error = verifier
        .verify::<Claims>(&hmac_token(valid_claims()), &policy())
        .await
        .expect_err("remote JWKS material must never become an HMAC secret");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

#[tokio::test]
async fn given_low_order_ed25519_jwk_when_verifying_forged_signature_then_rejects_key() {
    let mut point = [0_u8; 32];
    point[0] = 1;
    let jwks = serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "kid": "ed-key",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(point)
        }]
    });
    let verifier = JwtVerifier::builder()
        .jwks_source(JwksSource::json_string(jwks.to_string()).expect("JWKS"))
        .allowed_algorithms(AllowedAlgorithms::asymmetric([SignatureAlgorithm::EdDSA]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .unwrap();

    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"ed-key","typ":"at+jwt"}"#);
    let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&valid_claims()).unwrap());
    let mut forged_signature = [0_u8; 64];
    forged_signature[0] = 1;
    let token = format!(
        "{header}.{claims}.{}",
        URL_SAFE_NO_PAD.encode(forged_signature)
    );

    let error = verifier
        .verify::<Claims>(&token, &policy())
        .await
        .expect_err("the verifier must reject low-order Ed25519 JWKs before backend verification");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

fn hmac_jwks() -> serde_json::Value {
    let jwks = serde_json::json!({
        "keys": [{
            "kty": "oct",
            "kid": "hmac-key",
            "alg": "HS256",
            "k": "bG9jYWwgdGVzdCBobWFjIHNlY3JldCB3aXRoIGVub3VnaCBlbnRyb3B5"
        }]
    });
    jwks
}

#[tokio::test]
async fn given_wrong_signature_when_verifying_then_rejects_signature() {
    let token = token(valid_claims());
    let mut parts = token.split('.').collect::<Vec<_>>();
    let mut signature = parts[2].to_owned();
    let replacement = if signature.starts_with('a') { "b" } else { "a" };
    signature.replace_range(0..1, replacement);
    parts[2] = &signature;
    let token = parts.join(".");

    let error = build_verifier()
        .verify::<Claims>(&token, &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::SignatureInvalid);
}

#[tokio::test]
async fn given_key_algorithm_conflict_when_verifying_then_rejects_key() {
    let mut jwk = jwk();
    jwk.common.key_id = Some("test-key".to_owned());
    jwk.common.key_algorithm = Some(KeyAlgorithm::RS384);
    let verifier = verifier_for_jwk(jwk);

    let error = verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

#[tokio::test]
async fn given_encryption_key_use_when_verifying_then_rejects_key() {
    let mut jwk = jwk();
    jwk.common.key_id = Some("test-key".to_owned());
    jwk.common.public_key_use = Some(PublicKeyUse::Encryption);
    let verifier = verifier_for_jwk(jwk);

    let error = verifier
        .verify::<Claims>(&token(valid_claims()), &policy())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

#[tokio::test]
async fn given_ps256_header_with_rs256_allowlist_when_verifying_then_rejects_algorithm() {
    let mut header = Header::new(Algorithm::PS256);
    header.kid = Some("test-key".to_owned());
    header.typ = Some("at+jwt".to_owned());

    let error = build_verifier()
        .verify::<Claims>(&signed_token(header, valid_claims()), &policy())
        .await
        .unwrap_err();

    assert_eq!(
        error.kind(),
        &JwtDecodeErrorKind::UnsupportedAlgorithm(SignatureAlgorithm::PS256)
    );
}

fn verifier_for_jwk(jwk: jsonwebtoken::jwk::Jwk) -> JwtVerifier {
    let jwks = serde_json::json!({ "keys": [jwk] }).to_string();
    JwtVerifier::builder()
        .jwks_source(JwksSource::json_string(jwks).unwrap())
        .allowed_algorithms(AllowedAlgorithms::asymmetric([SignatureAlgorithm::RS256]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .unwrap()
}
